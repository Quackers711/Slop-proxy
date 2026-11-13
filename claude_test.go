package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultUpstream(t *testing.T) {
	if settingsBaseURL(claudeSettingsFiles("")[0]) != "" {
		t.Skip("managed settings on this machine set ANTHROPIC_BASE_URL")
	}
	user, proj := t.TempDir(), t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", user)
	t.Setenv("ANTHROPIC_BASE_URL", "")
	write := func(path, url string) {
		os.MkdirAll(filepath.Dir(path), 0o700)
		os.WriteFile(path, []byte(`{"env": {"ANTHROPIC_BASE_URL": "`+url+`"}}`), 0o600)
	}
	check := func(what, self, want, wantFrom string) {
		t.Helper()
		if got, from := defaultUpstream(proj, self); got != want || from != wantFrom {
			t.Errorf("%s: got %s from %q, want %s from %q", what, got, from, want, wantFrom)
		}
	}

	check("nothing set", "", anthropicAPI, "")
	t.Setenv("ANTHROPIC_BASE_URL", "https://env.example")
	check("environment", "", "https://env.example", "ANTHROPIC_BASE_URL")
	write(filepath.Join(user, "settings.json"), "https://user.example:8317")
	check("user settings beat the environment", "", "https://user.example:8317", filepath.Join(user, "settings.json"))
	local := filepath.Join(proj, ".claude", "settings.local.json")
	write(local, "http://localhost:8787")
	check("project settings beat user settings", "", "http://localhost:8787", local)
	check("serve skips its own address", "127.0.0.1:8787", "https://user.example:8317", filepath.Join(user, "settings.json"))
}

func TestClaudeArgs(t *testing.T) {
	args := claudeArgs([]string{"/Users/x/.local/bin/claude", "-p", "hi"}, "http://127.0.0.1:5000")
	if len(args) != 5 || args[1] != "--settings" || args[3] != "-p" || args[4] != "hi" {
		t.Fatalf("args = %q", args)
	}
	var s struct{ Env map[string]string }
	if err := json.Unmarshal([]byte(args[2]), &s); err != nil || s.Env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:5000" {
		t.Errorf("settings = %s (%v)", args[2], err)
	}
	if got := claudeArgs([]string{"aider", "--yes"}, "x"); len(got) != 2 {
		t.Errorf("other commands should be left alone: %q", got)
	}
}
