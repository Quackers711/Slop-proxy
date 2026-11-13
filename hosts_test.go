package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	cfg, err := parseConfig("cfg", []byte(`
[hosts]
https://API.acme.com:443 = 9001
  strip-cf
  request Authorization: Bearer $ACME_TOKEN   # comment
  request -X-Debug
  response -x-trace-*
api.other.io = localhost:9002
http://plain.example:8080 = 9003
	insecure
[names]
foo = barbaz
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 3 || len(cfg.Names) != 1 {
		t.Fatalf("got %d hosts, %d names", len(cfg.Hosts), len(cfg.Names))
	}
	a, b, c := cfg.Hosts[0], cfg.Hosts[1], cfg.Hosts[2]
	if a.Target.String() != "https://api.acme.com" || a.Port != 9001 || !a.StripCF {
		t.Errorf("first host: %+v", a)
	}
	want := []HeaderRule{{Name: "Authorization", Value: "Bearer $ACME_TOKEN"}, {Name: "X-Debug", Remove: true}}
	if len(a.Request) != 2 || a.Request[0] != want[0] || a.Request[1] != want[1] {
		t.Errorf("request rules: %+v", a.Request)
	}
	if len(a.Response) != 1 || a.Response[0] != (HeaderRule{Name: "x-trace-*", Remove: true}) {
		t.Errorf("response rules: %+v", a.Response)
	}
	if b.Target.String() != "https://api.other.io" || b.Port != 9002 {
		t.Errorf("second host: %+v", b)
	}
	if c.Target.String() != "http://plain.example:8080" || !c.Insecure {
		t.Errorf("third host: %+v", c)
	}

	for _, bad := range []string{
		"[hosts]\nhttps://a.com = 9001\nhttps://b.com = 9001",
		"[hosts]\nhttps://a.com = 9001\nhttps://A.com = 9002",
		"[hosts]\nhttps://a.com/path = 9001",
		"[hosts]\nftp://a.com = 9001",
		"[hosts]\nhttps://a.com = nope",
		"[hosts]\nhttp://localhost:3000 = 9001",
		"[hosts]\n  strip-cf",
		"[hosts]\nstrip-cf",
		"[hosts]\nhttps://a.com = 9001\nstrip-cff",
		"[hosts]\nhttps://a.com = 9001\n  request Bad Header: x",
		"[hosts]\nhttps://a.com = 9001\n  bogus",
	} {
		if _, err := parseConfig("cfg", []byte(bad)); err == nil {
			t.Errorf("no error for %q", bad)
		}
	}
}

func TestHostOptionsUnindented(t *testing.T) {
	cfg, err := parseConfig("cfg", []byte("[names]\nwidgetco = gizmoco\n\n[hosts]\nhttps://widgetco.dk = 9001\nstrip-cf\nrequest X-A: b\nhttps://b.dk = 9002\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 2 || !cfg.Hosts[0].StripCF || len(cfg.Hosts[0].Request) != 1 || cfg.Hosts[1].StripCF {
		t.Fatalf("hosts: %+v %+v", cfg.Hosts[0], cfg.Hosts[1])
	}
}

func cloakVault(t *testing.T) *Vault {
	t.Helper()
	cfg, err := parseConfig("cfg", []byte("[hosts]\nhttps://api.acme.com = 9001\nhttps://acme.com = 9002\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := NewVault(make([]byte, 32))
	for _, h := range cfg.Hosts {
		v.AddHost(h)
	}
	return v
}

func TestMaskHosts(t *testing.T) {
	v := cloakVault(t)
	body := `{"messages":[{"role":"user","content":"GET https://api.acme.com/v1 or HTTPS://API.ACME.COM:443/x, wss://api.acme.com/ws, cdn.api.acme.com, see acme.com and notacme.com, mail me@acme.com"},` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"https://api.acme.com","signature":"s"}]}]}`
	out, trace, err := v.MaskTrace([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Messages []struct {
			Content json.RawMessage
		}
	}
	json.Unmarshal(out, &doc)
	var text string
	json.Unmarshal(doc.Messages[0].Content, &text)
	want := "GET http://localhost:9001/v1 or http://localhost:9001/x, ws://localhost:9001/ws, cdn.localhost:9001, see localhost:9002 and notacme.com, mail me@localhost:9002"
	if text != want {
		t.Errorf("masked:\n got %s\nwant %s", text, want)
	}
	if !strings.Contains(string(doc.Messages[1].Content), "https://api.acme.com") {
		t.Errorf("thinking was changed: %s", doc.Messages[1].Content)
	}
	if len(trace) == 0 || trace[0].Kind != "host" {
		t.Errorf("trace: %+v", trace)
	}

	edit := `{"file_path":"a.go","old_string":"http://localhost:9001/v1","new_string":"ws://localhost:9001 cdn.localhost:9001"}`
	var got map[string]string
	json.Unmarshal([]byte(v.UnmaskToolInput("Edit", edit, nil)), &got)
	if got["old_string"] != "https://api.acme.com/v1" || got["new_string"] != "wss://api.acme.com cdn.api.acme.com" {
		t.Errorf("Edit restored to %v", got)
	}
	cmd := `{"command":"curl http://localhost:9001/v1"}`
	if out := v.UnmaskToolInput("Bash", cmd, nil); out != cmd {
		t.Errorf("Bash input changed to %s", out)
	}
	if s := v.UnmaskText("Served at http://localhost:9002."); s != "Served at https://acme.com." {
		t.Errorf("reply text: %s", s)
	}
}

func TestStreamKeepsLocalForBash(t *testing.T) {
	v := cloakVault(t)
	stream := "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"curl http://localhost:9001\\\"}\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Write\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"content\\\":\\\"url = http://localhost:9001\\\"}\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
	var out bytes.Buffer
	if err := unmaskStream(v, strings.NewReader(stream), &out, nil); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, `curl http://localhost:9001`) {
		t.Errorf("Bash input lost its local address:\n%s", s)
	}
	if !strings.Contains(s, `url = https://api.acme.com`) {
		t.Errorf("Write input not restored:\n%s", s)
	}
}

func TestCloakHandler(t *testing.T) {
	var got *http.Request
	var gotBody string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		self := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", self+"/next")
		w.Header().Set("Set-Cookie", "s=1; Domain="+r.Host+"; Path=/")
		w.Header().Set("CF-Ray", "abc")
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("X-Trace-Id", "t")
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		io.WriteString(w, `{"next":"`+self+`/page/2"}`)
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	h := &Host{Target: target, Port: 9001, StripCF: true, Insecure: true,
		Request:  []HeaderRule{{Name: "Authorization", Value: "Bearer real"}, {Name: "X-Debug", Remove: true}},
		Response: []HeaderRule{{Name: "x-trace-*", Remove: true}, {Name: "X-Cloaked", Value: "1"}},
	}
	px := httptest.NewServer(cloakHandler(h))
	defer px.Close()

	req, _ := http.NewRequest("POST", px.URL+"/v1?cb=http%3A%2F%2Flocalhost%3A9001%2Fdone", strings.NewReader(`{"callback":"http://localhost:9001/hook"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.Header.Set("CDN-Loop", "cloudflare")
	req.Header.Set("X-Debug", "1")
	req.Header.Set("Origin", "http://localhost:9001")
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if got.Host != target.Host || got.Header.Get("Authorization") != "Bearer real" {
		t.Errorf("upstream got Host %s, Authorization %q", got.Host, got.Header.Get("Authorization"))
	}
	for _, k := range []string{"CF-Connecting-IP", "CDN-Loop", "X-Debug"} {
		if got.Header.Get(k) != "" {
			t.Errorf("upstream got %s", k)
		}
	}
	if o := got.Header.Get("Origin"); o != up.URL {
		t.Errorf("Origin = %s", o)
	}
	if cb := got.URL.Query().Get("cb"); cb != up.URL+"/done" {
		t.Errorf("query cb = %s", cb)
	}
	if gotBody != `{"callback":"`+up.URL+`/hook"}` {
		t.Errorf("upstream body = %s", gotBody)
	}

	local := "http://localhost:9001"
	if l := resp.Header.Get("Location"); l != local+"/next" {
		t.Errorf("Location = %s", l)
	}
	if c := resp.Header.Get("Set-Cookie"); strings.Contains(strings.ToLower(c), "domain") {
		t.Errorf("Set-Cookie = %s", c)
	}
	for _, k := range []string{"CF-Ray", "Server", "X-Trace-Id", "Strict-Transport-Security"} {
		if resp.Header.Get(k) != "" {
			t.Errorf("response kept %s", k)
		}
	}
	if resp.Header.Get("X-Cloaked") != "1" {
		t.Error("response header not set")
	}
	if string(body) != `{"next":"`+local+`/page/2"}` {
		t.Errorf("response body = %s", body)
	}
}

func TestExpandHeaders(t *testing.T) {
	t.Setenv("CLOAK_TEST_TOKEN", "env-token-123456")
	v := NewVault(make([]byte, 32))
	v.Add("FILE_TOKEN", "file-token-123456", "", ".env")
	h := &Host{Request: []HeaderRule{{Name: "Authorization", Value: "Bearer $CLOAK_TEST_TOKEN"}, {Name: "X-Key", Value: "${file_token}"}}}
	expandHeaders([]*Host{h}, v)
	if h.Request[0].Value != "Bearer env-token-123456" || h.Request[1].Value != "file-token-123456" {
		t.Errorf("expanded to %+v", h.Request)
	}
	masked, _ := v.Mask([]byte(`{"x":"env-token-123456"}`))
	if strings.Contains(string(masked), "env-token") {
		t.Errorf("header value not masked: %s", masked)
	}
}
