package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Var is one config line: a name and an optional replacement.
type Var struct{ Name, Replacement string }

// Config holds the two sections. Values: variables whose assigned value the agent
// must not see (Name may be a glob like *_TOKEN). Names: words renamed themselves.
type Config struct{ Values, Names []Var }

func isGlob(name string) bool { return strings.ContainsAny(name, "*?[") }

const configTemplate = `# slopproxy config. The agent never sees this file.

# Hide the value assigned to a variable, anywhere in the project.
#   NAME = replacement   the agent sees the replacement (8+ characters)
#   NAME                 the agent sees [[SECRET:NAME]]
#   *_SECRET             every variable whose name matches
[values]

# Rename a word itself (methods, parameters, hostnames), as a whole word.
#   realName = nameTheAgentSees
[names]
`

// configPath picks -config, else the project's file, else the shared fallback.
func configPath(dir, cwd, flagPath string) (path string, explicit bool) {
	if flagPath != "" {
		return flagPath, true
	}
	p := projectConfig(dir, cwd)
	if _, err := os.Stat(p); err == nil {
		return p, false
	}
	return filepath.Join(dir, "config"), false
}

// ponytail: keyed by folder name, so two projects called "api" share one; use -config to split them.
func projectConfig(dir, cwd string) string {
	return filepath.Join(dir, "projects", filepath.Base(cwd))
}

func loadConfig(path string, explicit bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseConfig(path, data)
}

func parseConfig(path string, data []byte) (*Config, error) {
	cfg := &Config{}
	var section *[]Var
	seen := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, i+1)
		switch {
		case line == "[values]":
			section = &cfg.Values
			continue
		case line == "[names]":
			section = &cfg.Names
			continue
		case line[0] == '[':
			return nil, fmt.Errorf("%s: unknown section %s; use [values] or [names]", where, line)
		case section == nil:
			return nil, fmt.Errorf("%s: line is outside a section; put it under [values] (hide a value) or [names] (rename a word)", where)
		}
		if a := strings.Index(line, "->"); a >= 0 && !strings.Contains(line[:a], "=") {
			return nil, fmt.Errorf("%s: -> is no longer used; write NAME = new_name under [names]", where)
		}
		name, repl, _ := strings.Cut(line, "=")
		x := Var{strings.TrimSpace(name), strings.Trim(strings.TrimSpace(repl), `"'`)}
		names := section == &cfg.Names
		switch {
		case x.Name == "" || strings.ContainsAny(x.Name, " \t"):
			return nil, fmt.Errorf("%s: expected NAME or NAME = replacement", where)
		case names && isGlob(x.Name):
			return nil, fmt.Errorf("%s: patterns like %s only work under [values]", where, x.Name)
		case names && x.Replacement == "":
			return nil, fmt.Errorf("%s: [names] lines need NAME = new_name", where)
		case !names && x.Replacement != "" && isGlob(x.Name):
			return nil, fmt.Errorf("%s: pattern %s can't have a replacement", where, x.Name)
		case !names && x.Replacement != "" && len(x.Replacement) < 8:
			// The replacement is swapped back wherever the agent writes it, so "x" would be a disaster.
			return nil, fmt.Errorf("%s: replacement %q must be distinctive, at least 8 characters", where, x.Replacement)
		case x.Replacement != "" && seen[x.Replacement] != "":
			return nil, fmt.Errorf("%s: %s and %s have the same replacement", where, seen[x.Replacement], x.Name)
		}
		if names && len(x.Name) < 4 {
			log.Printf("warning: %s: every whole word %q the agent sees is renamed, including in its own instructions", where, x.Name)
		}
		if x.Replacement != "" {
			seen[x.Replacement] = x.Name
		}
		*section = append(*section, x)
	}
	return cfg, nil
}

func match(vars []Var, name string) (Var, bool) {
	var hit Var
	found := false
	for _, x := range vars {
		if strings.EqualFold(x.Name, name) {
			return x, true
		}
		if ok, _ := filepath.Match(strings.ToUpper(x.Name), strings.ToUpper(name)); ok && !found {
			hit, found = x, true
		}
	}
	return hit, found
}

// assignRe finds NAME = value, NAME: value, "NAME": "value", NAME := value, NAME => value.
// Unquoted values must end the statement, so NAME = os.getenv("NAME") is not a value.
var assignRe = regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)["']?[ \t]*(?::=|=>|=|:)[ \t]*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'#,;(){}\[\]]+)[ \t\r]*(?:$|[#,;}]))`)

// ponytail: 1MB cap skips lockfiles and dumps; raise it if secrets live in huge files.
const maxFileSize = 1 << 20

// loadSecrets collects the values of configured variables from the environment and
// from assignments in every text file under the current directory. Every file is
// also scanned for well-known token formats.
func loadSecrets(cfg *Config, configPath string, v *Vault) error {
	found := map[string]bool{}
	add := func(x Var, name, value, source string) {
		switch {
		case value == "" || strings.HasPrefix(value, "$") || strings.Contains(value, "${"):
			// empty or a reference to another variable, not a value
		case len(value) < 8:
			// ponytail: 8-char floor; masking "test" everywhere would wreck the agent's view
			if !isGlob(x.Name) {
				log.Printf("warning: %s in %s is shorter than 8 characters, not masked", name, source)
			}
		default:
			found[x.Name] = true
			if e := v.Add(name, value, x.Replacement, source); x.Replacement != "" && e.Token != x.Replacement {
				log.Printf("warning: %s has more than one value; the one in %s is shown as %s", name, source, e.Token)
			}
		}
	}

	for _, x := range cfg.Names {
		v.AddRename(x.Name, x.Replacement)
	}
	for _, x := range cfg.Values {
		if !isGlob(x.Name) {
			add(x, x.Name, os.Getenv(x.Name), "env")
		}
	}

	cfgInfo, _ := os.Stat(configPath)
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != "." && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize || (cfgInfo != nil && os.SameFile(info, cfgInfo)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			return nil
		}
		for _, m := range assignRe.FindAllSubmatch(data, -1) {
			if x, ok := match(cfg.Values, string(m[1])); ok {
				add(x, string(m[1]), string(m[2])+string(m[3])+string(m[4]), path)
			}
		}
		v.Detect(data, path, false)
		for _, x := range slices.Concat(cfg.Values, cfg.Names) {
			if x.Replacement != "" && bytes.Contains(data, []byte(x.Replacement)) {
				log.Printf("warning: replacement for %s appears in %s; if the agent writes it, it becomes the real value", x.Name, path)
			}
		}
		return nil
	})
	for _, x := range cfg.Values {
		if !isGlob(x.Name) && x.Replacement != "" && !found[x.Name] {
			log.Printf("warning: no value assigned to %s found; to rename %s itself, move it to [names]", x.Name, x.Name)
		}
	}
	return err
}

// configDir holds the config and the HMAC key, outside any project the agent can browse.
func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	return filepath.Join(dir, "slopproxy"), err
}

// loadKey returns the persistent HMAC key, so tokens survive restarts.
func loadKey() ([]byte, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "key")
	if k, err := os.ReadFile(path); err == nil && len(k) >= 32 {
		return k, nil
	}
	k := make([]byte, 32)
	rand.Read(k)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, k, 0o600)
}
