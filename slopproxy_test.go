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
	"os/exec"
	"path/filepath"
	"slices"
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
	v.AddRename("widgetco", "gizmoco")
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
	delta(0, map[string]any{"type": "text_delta", "text": pwToken[5:] + " ok, see Gizmo"})
	delta(0, map[string]any{"type": "text_delta", "text": "co.dk"})
	ev(map[string]any{"type": "content_block_stop", "index": 0})
	ev(map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "tool_use", "input": map[string]any{}}})
	input := `{"command":"echo ` + pwToken + `"}`
	delta(1, map[string]any{"type": "input_json_delta", "partial_json": input[:20]})
	delta(1, map[string]any{"type": "input_json_delta", "partial_json": input[20:]})
	ev(map[string]any{"type": "content_block_stop", "index": 1})
	delta(2, map[string]any{"type": "thinking_delta", "thinking": "token " + pwToken + " gizmoco"})

	var out bytes.Buffer
	if err := unmaskStream(v, strings.NewReader(in.String()), &out, nil); err != nil {
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
	// Stand-ins split across deltas are still restored, in the original casing.
	if text != "pw is "+password+" ok, see Widgetco.dk" {
		t.Errorf("text = %q", text)
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(tool), &args); err != nil || args["command"] != "echo "+password {
		t.Errorf("tool input = %q (%v)", tool, err)
	}
	if thinking != "token "+pwToken+" gizmoco" { // signed, so never touched
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
	px := httptest.NewServer(newProxy(v, u, nil))
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
	if err := json.Unmarshal(got, &r); err != nil || len(r.Content) != 2 || r.Content[0].Text != "use "+password || r.Content[1].Input.Cmd != "echo "+password {
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
	load := func(conf string, all bool) (map[string]string, *Vault) {
		t.Helper()
		os.WriteFile("slop.conf", []byte(conf), 0o600)
		cfg, err := loadConfig("slop.conf", true)
		if err != nil {
			t.Fatal(err)
		}
		v := NewVault([]byte("k"))
		if err := loadSecrets(cfg, "slop.conf", v, all); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, e := range v.Entries() {
			got[e.Value] = e.Token
		}
		return got, v
	}
	want := map[string]string{
		"hunter2-horse":    "not-the-real-password",
		"abcdefgh12345":    "[[SECRET:api_key]]",
		"s3cr3t-jwt-value": "[[SECRET:JWT_SECRET]]",
	}
	check := func(what string, got map[string]string) {
		t.Helper()
		for val, tok := range want {
			if got[val] != tok {
				t.Errorf("%s: %s: got token %q, want %q", what, val, got[val], tok)
			}
		}
		if !strings.HasPrefix(got[ghToken], "[[SECRET:github-token-") {
			t.Errorf("%s: github token not detected: %v", what, got)
		}
		if len(got) != 4 {
			t.Errorf("%s: unexpected entries: %v", what, got)
		}
	}

	// By default only .env is read: an old config keeps working, it just reads less.
	conf := files["slop.conf"]
	got, v := load(conf, false)
	if len(got) != 1 || got["hunter2-horse"] != "not-the-real-password" {
		t.Errorf("default: want only the .env value, got %v", got)
	}
	if r := v.Renames(); r["someMethod"] != "flagChecker" || len(r) != 1 {
		t.Errorf("renames = %v", r)
	}

	got, _ = load(conf+"[files]\nconfig.yml\napp.* # globs work\n", false)
	check("[files]", got)

	got, _ = load(conf, true) // not a git repo: walks the tree
	check("scan -all", got)

	for _, bad := range []string{
		"A = outside-any-section",
		"[secrets]\nA",
		"[values]\nA = short",
		"[values]\n*_KEY = some-replacement",
		"[values]\nA = same-value-x\n[names]\nB = same-value-x",
		"[names]\nkey",
		"[names]\n*_KEY = something",
		"[values]\nkey -> flagValue",
		"[files]\nconfig/[bad",
	} {
		os.WriteFile("bad", []byte(bad), 0o600)
		if _, err := loadConfig("bad", true); err == nil {
			t.Errorf("config %q should be rejected", bad)
		}
	}
}

func TestParseEquals(t *testing.T) {
	if _, err := parseConfig("template", []byte(configTemplate)); err != nil {
		t.Errorf("init template: %v", err)
	}
	cfg, err := parseConfig("c", []byte("[values]\nDB_PASSWORD=not-the-real-password\n[names]\nc2VjcmV0LXZhbHVl== = fake-value-here\nold=style\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Var{{"c2VjcmV0LXZhbHVl==", "fake-value-here"}, {"old", "style"}}
	if cfg.Values[0] != (Var{"DB_PASSWORD", "not-the-real-password"}) || len(cfg.Names) != 2 || cfg.Names[0] != want[0] || cfg.Names[1] != want[1] {
		t.Errorf("values = %v, names = %v", cfg.Values, cfg.Names)
	}
}

// scan -all reads what git sees plus ignored files like .env.local, but not
// ignored directories like node_modules.
func TestProjectFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	t.Chdir(t.TempDir())
	if err := exec.Command("git", "init", "-q").Run(); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll("node_modules/pkg", 0o700)
	for name, body := range map[string]string{
		".gitignore":            "node_modules/\n.env.local\n",
		"config.yml":            "x",
		".env.local":            "x",
		"node_modules/pkg/a.js": "x",
	} {
		os.WriteFile(name, []byte(body), 0o600)
	}
	files, err := projectFiles()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	if want := []string{".env.local", ".gitignore", "config.yml"}; !slices.Equal(files, want) {
		t.Errorf("files = %v, want %v", files, want)
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

func TestRenameCase(t *testing.T) {
	for _, c := range []struct{ from, to, match, want string }{
		{"banana", "apple", "banana", "apple"},
		{"banana", "apple", "Banana", "Apple"},
		{"banana", "apple", "BANANA", "APPLE"},
		{"some", "tobe", "SoMe", "ToBe"},
		{"some", "tobe", "sOmE", "tObE"},
		{"calculateRiskScore", "scoreThing", "calculateRiskScore", "scoreThing"},
		{"calculateRiskScore", "scoreThing", "CalculateRiskScore", "ScoreThing"},
		{"calculateRiskScore", "scoreThing", "CALCULATERISKSCORE", "SCORETHING"},
		{"calculateRiskScore", "scoreThing", "calculateriskscore", "scorething"},
		{"ab", "wxyz", "aB", "wXYZ"}, // extra letters follow the last one
		{"acme", "Initech", "acme", "Initech"},
	} {
		if got := matchCase(c.match, c.from, c.to); got != c.want {
			t.Errorf("%s=%s on %q: got %q, want %q", c.from, c.to, c.match, got, c.want)
		}
	}

	// Through the proxy and back: the agent sees each casing mapped, and what it
	// writes in a tool call comes back in the original casing.
	v := NewVault([]byte("k"))
	v.AddRename("banana", "apple")
	v.AddRename("some", "tobe")
	v.AddRename("calculateRiskScore", "scoreThing")
	text := "Banana BANANA banana SoMe CalculateRiskScore(calculateRiskScore) bananas"
	body, _ := json.Marshal(map[string]string{"content": text})
	out, err := v.Mask(body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	json.Unmarshal(out, &got)
	if want := "Apple APPLE apple ToBe ScoreThing(scoreThing) bananas"; got["content"] != want {
		t.Errorf("masked = %q, want %q", got["content"], want)
	}
	back, _ := json.Marshal(map[string]string{"content": got["content"]})
	json.Unmarshal([]byte(v.UnmaskInput(string(back))), &got)
	if got["content"] != text {
		t.Errorf("round trip = %q, want %q", got["content"], text)
	}

	for _, bad := range []string{
		"[names]\nBanana = apple\nbanana = pear",
		"[names]\nbanana = Apple\ncherry = apple",
		"[values]\nA = fake-value-x\n[names]\nB = FAKE-VALUE-X",
	} {
		if _, err := parseConfig("bad", []byte(bad)); err == nil {
			t.Errorf("config %q should be rejected", bad)
		}
	}
}
