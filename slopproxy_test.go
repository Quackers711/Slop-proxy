package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	password = `pa"ss\word-123`
	stripe   = "sk_live_abcdefghijklmnop1234"
	ghToken  = "ghp_0123456789abcdefghijABCDEFGHIJ012345"
	pwToken  = "[[SECRET:DB_PASSWORD]]"
	fakeKey  = "sk_live_not-the-real-key"
)

func testVault() *Vault {
	v := NewVault([]byte("test-key"))
	v.Add("DB_PASSWORD", password, "", "test")
	v.Add("STRIPE_KEY", stripe, fakeKey, "test")
	return v
}

func TestMaskRoundTrip(t *testing.T) {
	v := testVault()
	body, _ := json.Marshal(map[string]any{"messages": []any{map[string]string{
		"role": "user", "content": "pw=" + password + " key=" + stripe + " gh=" + ghToken,
	}}})
	v.Detect(body, "request", true)
	out, err := v.Mask(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{jsonEscape(password), stripe, ghToken} {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("secret %q leaked: %s", s, out)
		}
	}
	if !bytes.Contains(out, []byte(pwToken)) || !bytes.Contains(out, []byte(fakeKey)) {
		t.Errorf("missing token or replacement: %s", out)
	}
	if got := v.UnmaskJSON(string(out)); got != string(body) {
		t.Errorf("round trip:\n got %s\nwant %s", got, body)
	}

	v.Add("PIN", "12345678", "", "test")
	if _, err := v.Mask([]byte(`{"n":12345678}`)); err == nil {
		t.Error("expected error when masking breaks JSON")
	}
}

func TestUnmaskStream(t *testing.T) {
	v := testVault()
	var in strings.Builder
	ev := func(m map[string]any) {
		b, _ := json.Marshal(m)
		fmt.Fprintf(&in, "event: %s\ndata: %s\n\n", m["type"], b)
	}
	delta := func(i int, d map[string]any) {
		ev(map[string]any{"type": "content_block_delta", "index": i, "delta": d})
	}

	ev(map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
	delta(0, map[string]any{"type": "text_delta", "text": "pw is " + pwToken[:5]})
	delta(0, map[string]any{"type": "text_delta", "text": pwToken[5:] + " ok"})
	ev(map[string]any{"type": "content_block_stop", "index": 0})
	ev(map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "tool_use", "input": map[string]any{}}})
	input := `{"command":"echo ` + pwToken + `"}`
	delta(1, map[string]any{"type": "input_json_delta", "partial_json": input[:20]})
	delta(1, map[string]any{"type": "input_json_delta", "partial_json": input[20:]})
	ev(map[string]any{"type": "content_block_stop", "index": 1})
	delta(2, map[string]any{"type": "thinking_delta", "thinking": "token " + pwToken})

	var out bytes.Buffer
	if err := unmaskStream(v, strings.NewReader(in.String()), &out); err != nil {
		t.Fatal(err)
	}
	var text, tool, thinking string
	for _, e := range strings.Split(out.String(), "\n\n") {
		var d struct {
			Delta struct {
				Text, Thinking string
				PartialJSON    string `json:"partial_json"`
			}
		}
		json.Unmarshal(sseData([]byte(e)), &d)
		text += d.Delta.Text
		tool += d.Delta.PartialJSON
		thinking += d.Delta.Thinking
	}
	if text != "pw is "+pwToken+" ok" {
		t.Errorf("text should stay as the agent wrote it: %q", text)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(tool), &args); err != nil || args["command"] != "echo "+password {
		t.Errorf("tool input = %q (%v)", tool, err)
	}
	if thinking != "token "+pwToken {
		t.Errorf("thinking was modified: %q", thinking)
	}
}

func TestProxyEndToEnd(t *testing.T) {
	v := testVault()
	var seen []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content":[{"type":"text","text":"use `+pwToken+`"},{"type":"tool_use","input":{"cmd":"echo `+pwToken+`"}}]}`)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	px := httptest.NewServer(newProxy(v, u))
	defer px.Close()

	body, _ := json.Marshal(map[string]string{"content": password + " " + ghToken})
	resp, err := http.Post(px.URL+"/v1/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if bytes.Contains(seen, []byte("word-123")) || bytes.Contains(seen, []byte(ghToken)) {
		t.Errorf("upstream saw a secret: %s", seen)
	}
	var r struct {
		Content []struct {
			Text  string
			Input struct{ Cmd string }
		}
	}
	if err := json.Unmarshal(got, &r); err != nil || len(r.Content) != 2 || r.Content[0].Text != "use "+pwToken || r.Content[1].Input.Cmd != "echo "+password {
		t.Errorf("response = %s (%v)", got, err)
	}
}

func TestLoadSecrets(t *testing.T) {
	t.Chdir(t.TempDir())
	files := map[string]string{
		"slop.conf":  "# comment\n[values]\nDB_PASSWORD = not-the-real-password\nAPI_KEY\n*_SECRET # pattern\n\n[names]\nsomeMethod = flagChecker\n",
		".env":       "DB_PASSWORD=hunter2-horse\nPORT=3000\n",
		"config.yml": "db:\n  db_password: 'hunter2-horse'\n  api_key: abcdefgh12345 # inline\n",
		"app.json":   `{"JWT_SECRET": "s3cr3t-jwt-value", "API_KEY": "${API_KEY}"}`,
		"app.py":     "API_KEY = os.getenv(\"API_KEY\")\nkey = \"" + ghToken + "\"\n",
	}
	for name, body := range files {
		os.WriteFile(name, []byte(body), 0o600)
	}
	cfg, err := loadConfig("slop.conf", true)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVault([]byte("k"))
	if err := loadSecrets(cfg, "slop.conf", v); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range v.Entries() {
		got[e.Value] = e.Token
	}
	want := map[string]string{
		"hunter2-horse":    "not-the-real-password",
		"abcdefgh12345":    "[[SECRET:api_key]]",
		"s3cr3t-jwt-value": "[[SECRET:JWT_SECRET]]",
	}
	for val, tok := range want {
		if got[val] != tok {
			t.Errorf("%s: got token %q, want %q", val, got[val], tok)
		}
	}
	if !strings.HasPrefix(got[ghToken], "[[SECRET:github-token-") {
		t.Errorf("github token not detected: %v", got)
	}
	if len(got) != 4 {
		t.Errorf("unexpected entries: %v", got)
	}
	if r := v.Renames(); r["someMethod"] != "flagChecker" || len(r) != 1 {
		t.Errorf("renames = %v", r)
	}

	for _, bad := range []string{
		"A = outside-any-section",
		"[secrets]\nA",
		"[values]\nA = short",
		"[values]\n*_KEY = some-replacement",
		"[values]\nA = same-value-x\n[names]\nB = same-value-x",
		"[names]\nkey",
		"[names]\n*_KEY = something",
		"[values]\nkey -> flagValue",
	} {
		os.WriteFile("bad", []byte(bad), 0o600)
		if _, err := loadConfig("bad", true); err == nil {
			t.Errorf("config %q should be rejected", bad)
		}
	}
}

func TestRename(t *testing.T) {
	v := testVault()
	v.AddRename("someMethodNameHere", "flagChecker")
	v.AddRename("key", "flagValue")
	code := "def someMethodNameHere(key: str):\n    return key == \"VALID_KEY\"  # keyboard"
	body, _ := json.Marshal(map[string]any{"messages": []any{
		map[string]any{"role": "user", "content": code + " pw=" + password},
		map[string]any{"type": "thinking", "thinking": "the key idea", "signature": "sig"},
	}, "key": "json keys stay"})
	out, err := v.Mask(body)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Messages []map[string]string
		Key      string
	}
	json.Unmarshal(out, &got)
	want := "def flagChecker(flagValue: str):\n    return flagValue == \"VALID_KEY\"  # keyboard pw=" + pwToken
	if got.Messages[0]["content"] != want {
		t.Errorf("content = %q", got.Messages[0]["content"])
	}
	if got.Messages[1]["thinking"] != "the key idea" || got.Key != "json keys stay" {
		t.Errorf("thinking or JSON key changed: %s", out)
	}

	in := v.UnmaskInput(`{"old_string":"def flagChecker(flagValue","new_string":"x = ` + pwToken + `"}`)
	var args map[string]string
	json.Unmarshal([]byte(in), &args)
	if args["old_string"] != "def someMethodNameHere(key" || args["new_string"] != "x = "+password {
		t.Errorf("unmask input = %s", in)
	}
}

func TestConfigPath(t *testing.T) {
	dir := t.TempDir()
	if p, explicit := configPath(dir, "/x/myproj", "custom.conf"); p != "custom.conf" || !explicit {
		t.Errorf("flag: got %s %v", p, explicit)
	}
	if p, _ := configPath(dir, "/x/myproj", ""); p != filepath.Join(dir, "config") {
		t.Errorf("fallback: got %s", p)
	}
	proj := filepath.Join(dir, "projects", "myproj")
	os.MkdirAll(filepath.Dir(proj), 0o700)
	os.WriteFile(proj, nil, 0o600)
	if p, explicit := configPath(dir, "/x/myproj", ""); p != proj || explicit {
		t.Errorf("project: got %s %v", p, explicit)
	}
}
