package main

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Claude Code reads ANTHROPIC_BASE_URL from the env section of its settings
// files as well as from its environment, and the settings files win. Both
// matter here: they say where requests would have gone without the proxy (the
// upstream), and they would route Claude around the proxy (see claudeArgs).

const anthropicAPI = "https://api.anthropic.com"

// claudeSettingsFiles lists the settings files Claude Code reads in cwd, most
// important first. --settings on the command line ranks below managed settings
// and above the rest.
func claudeSettingsFiles(cwd string) []string {
	managed := "/etc/claude-code/managed-settings.json"
	switch runtime.GOOS {
	case "darwin":
		managed = "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		managed = `C:\Program Files\ClaudeCode\managed-settings.json`
	}
	user := os.Getenv("CLAUDE_CONFIG_DIR")
	if user == "" {
		home, _ := os.UserHomeDir()
		user = filepath.Join(home, ".claude")
	}
	return []string{
		managed,
		filepath.Join(cwd, ".claude", "settings.local.json"),
		filepath.Join(cwd, ".claude", "settings.json"),
		filepath.Join(user, "settings.json"),
	}
}

func settingsBaseURL(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var s struct {
		Env map[string]any `json:"env"`
	}
	json.Unmarshal(data, &s)
	u, _ := s.Env["ANTHROPIC_BASE_URL"].(string)
	return strings.TrimSpace(u)
}

// defaultUpstream returns where Claude Code in cwd would send requests without
// the proxy, and where that came from ("" for the Anthropic API). An address
// that is the proxy's own (self, for serve) is skipped, so it can't loop.
func defaultUpstream(cwd, self string) (upstream, from string) {
	for _, f := range claudeSettingsFiles(cwd) {
		if u := settingsBaseURL(f); u != "" && !isAddr(u, self) {
			return u, f
		}
	}
	if u := os.Getenv("ANTHROPIC_BASE_URL"); u != "" && !isAddr(u, self) {
		return u, "ANTHROPIC_BASE_URL"
	}
	return anthropicAPI, ""
}

// isAddr reports whether URL u points at the local listen address addr.
func isAddr(u, addr string) bool {
	if addr == "" {
		return false
	}
	p, err := url.Parse(u)
	host, port, err2 := net.SplitHostPort(addr)
	if err != nil || err2 != nil || p.Port() != port {
		return false
	}
	loopback := func(h string) bool {
		ip := net.ParseIP(h)
		return h == "localhost" || ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
	}
	return p.Hostname() == host || loopback(p.Hostname()) && loopback(host)
}

// claudeArgs makes a claude command use the proxy even when a settings file
// sets ANTHROPIC_BASE_URL: the environment variable alone loses to those, a
// --settings argument doesn't. Other commands are returned unchanged.
func claudeArgs(args []string, base string) []string {
	if !isClaude(args[0]) {
		return args
	}
	s, _ := json.Marshal(map[string]any{"env": map[string]string{"ANTHROPIC_BASE_URL": base}})
	return slices.Concat(args[:1], []string{"--settings", string(s)}, args[1:])
}

func isClaude(cmd string) bool {
	return strings.TrimSuffix(filepath.Base(cmd), filepath.Ext(cmd)) == "claude"
}
