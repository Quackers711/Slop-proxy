package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Var is one config line: a name and an optional replacement.
type Var struct{ Name, Replacement string }

// Config holds the sections. Values: variables whose assigned value the agent
// must not see (Name may be a glob like *_TOKEN). Names: words renamed themselves.
// Files: where to read Values from, besides the environment and defaultFiles.
// Hosts: remote services the agent reaches, and sees, as localhost ones.
type Config struct {
	Values, Names []Var
	Files         []string
	Hosts         []*Host
}

func isGlob(name string) bool { return strings.ContainsAny(name, "*?[") }

// defaultFiles are read for [values] without being listed under [files].
var defaultFiles = []string{".env"}

const configTemplate = `# slopproxy config. The agent never sees this file.

# Hide the value assigned to a variable. Values are read from the environment,
# .env and the files under [files]; nothing else in the project is read.
#   NAME = replacement   the agent sees the replacement (8+ characters)
#   NAME                 the agent sees [[SECRET:NAME]]
#   *_SECRET             every variable whose name matches
[values]

# More files to read [values] from, relative to the project (.env always is).
# ` + "`slopproxy scan -all`" + ` searches the whole project and lists files to add.
#   config/secrets.yml
#   .env.*
[files]

# Rename a word itself (methods, parameters, hostnames), as a whole word.
# Matches in any case and keeps the casing: banana = apple turns Banana into Apple.
# Works for any literal string, such as a secret you paste here.
#   realName = nameTheAgentSees
[names]

# Cloak a remote service as a localhost one. slopproxy serves it on
# localhost:PORT, and the agent sees http://localhost:PORT wherever the real
# address appears. Option lines below a host change its traffic:
#   https://api.example.com = 9001
#     strip-cf                                    drop Cloudflare headers both ways
#     request Authorization: Bearer $API_TOKEN    set a request header ($VAR from env or .env)
#     request -X-Forwarded-For                    remove one (cf-* removes a prefix)
#     response -Server                            the same for responses
#     insecure                                    don't verify the target's certificate
[hosts]
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
	inFiles, inHosts := false, false
	var host *Host                   // the [hosts] entry option lines belong to
	seen := map[string]string{}      // replacement -> the line's name
	seenFold := map[string]string{}  // the same, lowercased
	namesFold := map[string]string{} // lowercased [names] replacement -> name
	namesFrom := map[string]string{} // lowercased [names] word -> word
	for i, line := range strings.Split(string(data), "\n") {
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, i+1)
		switch {
		case line == "[values]":
			section, inFiles, inHosts = &cfg.Values, false, false
			continue
		case line == "[names]":
			section, inFiles, inHosts = &cfg.Names, false, false
			continue
		case line == "[files]":
			section, inFiles, inHosts = nil, true, false
			continue
		case line == "[hosts]":
			section, inFiles, inHosts, host = nil, false, true, nil
			continue
		case line[0] == '[':
			return nil, fmt.Errorf("%s: unknown section %s; use [values], [files], [names] or [hosts]", where, line)
		case inHosts && (indented || isHostOption(line)):
			if host == nil {
				return nil, fmt.Errorf("%s: %s comes before any host; put it below a line like https://real.host = PORT", where, line)
			}
			if err := host.parseOption(line, where); err != nil {
				return nil, err
			}
			continue
		case inHosts:
			h, err := parseHostLine(line, where)
			if err != nil {
				return nil, err
			}
			for _, o := range cfg.Hosts {
				switch {
				case o.Port == h.Port:
					return nil, fmt.Errorf("%s: port %d is already used by %s", where, h.Port, o.Target)
				case strings.EqualFold(o.Target.Hostname(), h.Target.Hostname()):
					return nil, fmt.Errorf("%s: %s is already cloaked (as %s)", where, h.Target.Hostname(), o.Local())
				}
			}
			cfg.Hosts = append(cfg.Hosts, h)
			host = h
			continue
		case inFiles:
			if _, err := filepath.Match(line, ""); err != nil {
				return nil, fmt.Errorf("%s: bad file pattern %s", where, line)
			}
			cfg.Files = append(cfg.Files, line)
			continue
		case section == nil:
			return nil, fmt.Errorf("%s: line is outside a section; put it under [values] (hide a value) or [names] (rename a word)", where)
		}
		if a := strings.Index(line, "->"); a >= 0 && !strings.Contains(line[:a], "=") {
			return nil, fmt.Errorf("%s: -> is no longer used; write NAME = new_name under [names]", where)
		}
		// " = " splits first, so a literal ending in "=" (base64) can be renamed;
		// lines without it split at the first "=", as they always did.
		sep := "="
		if strings.Contains(line, " = ") {
			sep = " = "
		}
		name, repl, _ := strings.Cut(line, sep)
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
		// [names] match in any case, so their words and replacements must differ in more than case.
		case x.Replacement != "" && (names && seenFold[strings.ToLower(x.Replacement)] != "" || namesFold[strings.ToLower(x.Replacement)] != ""):
			return nil, fmt.Errorf("%s: %s and %s have the same replacement, ignoring case", where, seenFold[strings.ToLower(x.Replacement)], x.Name)
		case names && namesFrom[strings.ToLower(x.Name)] != "":
			return nil, fmt.Errorf("%s: %s is already renamed (as %s); [names] ignore case", where, x.Name, namesFrom[strings.ToLower(x.Name)])
		}
		if names && len(x.Name) < 4 {
			log.Printf("warning: %s: every whole word %q the agent sees is renamed, in any case, including in its own instructions", where, x.Name)
		}
		if x.Replacement != "" {
			seen[x.Replacement] = x.Name
			seenFold[strings.ToLower(x.Replacement)] = x.Name
		}
		if names {
			namesFold[strings.ToLower(x.Replacement)] = x.Name
			namesFrom[strings.ToLower(x.Name)] = x.Name
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
// from assignments in .env and the files under [files]. It reads nothing else, so
// startup is quick in any repo; all reads every project file instead (scan -all).
// Every file read is also scanned for well-known token formats.
func loadSecrets(cfg *Config, configPath string, v *Vault, all bool) error {
	found := map[string]bool{}
	add := func(x Var, name, value, source string) {
		switch {
		case value == "" || strings.HasPrefix(value, "$") || strings.Contains(value, "${"):
			// empty or a reference to another variable, not a value
		case len(value) < 8:
			found[x.Name] = true
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
	for _, h := range cfg.Hosts {
		v.AddHost(h)
	}
	for _, x := range cfg.Values {
		if !isGlob(x.Name) {
			add(x, x.Name, os.Getenv(x.Name), "env")
		}
	}

	files := listedFiles(cfg.Files)
	if all {
		var err error
		if files, err = projectFiles(); err != nil {
			return err
		}
	}
	cfgInfo, _ := os.Stat(configPath)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || (cfgInfo != nil && os.SameFile(info, cfgInfo)) {
			continue
		}
		if info.Size() > maxFileSize {
			if !all {
				log.Printf("warning: %s is larger than 1MB, not read", path)
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			continue
		}
		for _, m := range assignRe.FindAllSubmatch(data, -1) {
			if x, ok := match(cfg.Values, string(m[1])); ok {
				add(x, string(m[1]), string(m[2])+string(m[3])+string(m[4]), path)
			}
		}
		v.Detect(data, path, false)
		lower := bytes.ToLower(data) // [names] are swapped back in any case
		for i, x := range slices.Concat(cfg.Values, cfg.Names) {
			names := i >= len(cfg.Values)
			if x.Replacement != "" && (!names && bytes.Contains(data, []byte(x.Replacement)) || names && bytes.Contains(lower, bytes.ToLower([]byte(x.Replacement)))) {
				log.Printf("warning: replacement for %s appears in %s; if the agent writes it, it becomes the real value", x.Name, path)
			}
		}
		for _, h := range cfg.Hosts {
			if bytes.Contains(data, []byte(h.Local())) {
				log.Printf("warning: %s appears in %s; if the agent edits it, it becomes %s", h.Local(), path, h.Target.Host)
			}
		}
	}

	where, hint := "the environment, .env or [files]", "; `slopproxy scan -all` shows where it is assigned"
	if all {
		where, hint = "the environment or any project file", ""
	}
	for _, x := range cfg.Values {
		switch {
		case found[x.Name]:
		case isGlob(x.Name):
			log.Printf("warning: %s matches no variable in %s", x.Name, where)
		case x.Replacement != "":
			log.Printf("warning: no value for %s found in %s, so it is not masked%s; to rename %s itself, move it to [names]", x.Name, where, hint, x.Name)
		default:
			log.Printf("warning: no value for %s found in %s, so it is not masked%s", x.Name, where, hint)
		}
	}
	return nil
}

// listedFiles expands defaultFiles and the [files] patterns, relative to the
// current directory. A listed pattern that matches nothing gets a warning; a
// project without .env does not.
func listedFiles(patterns []string) []string {
	var out []string
	seen := map[string]bool{}
	for i, p := range slices.Concat(defaultFiles, patterns) {
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, rest)
			}
		}
		matches, _ := filepath.Glob(p) // parseConfig rejected bad patterns
		if len(matches) == 0 && i >= len(defaultFiles) {
			log.Printf("warning: [files] %s matches no file", p)
		}
		for _, m := range matches {
			if m = filepath.Clean(m); !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// projectFiles lists every file git sees under the current directory, plus
// ignored files but not ignored directories (node_modules, target/), because
// secret files like .env.local are usually ignored. Outside git it walks the tree.
func projectFiles() ([]string, error) {
	files, err := gitFiles("--cached", "--others", "--exclude-standard")
	if err != nil {
		return walkFiles()
	}
	ignored, err := gitFiles("--others", "--ignored", "--exclude-standard", "--directory")
	return append(files, ignored...), err
}

func gitFiles(args ...string) ([]string, error) {
	out, err := exec.Command("git", append([]string{"ls-files", "-z"}, args...)...).Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" && !strings.HasSuffix(f, "/") {
			files = append(files, f)
		}
	}
	return files, nil
}

func walkFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
		case d.IsDir() && path != "." && (d.Name() == ".git" || d.Name() == "node_modules"):
			return filepath.SkipDir
		case !d.IsDir():
			files = append(files, path)
		}
		return nil
	})
	return files, err
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
