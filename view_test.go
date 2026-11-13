package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A streamed exchange through the proxy with -view on: the record holds what
// went upstream, what was hidden, the raw response, and the restored tool input.
func TestRecorder(t *testing.T) {
	v := testVault()
	v.AddRename("banana", "apple")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		input, _ := json.Marshal(`{"command":"echo ` + pwToken + ` Apple"}`)
		fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{}}}\n\n")
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":%s}}\n\n", input)
		fmt.Fprintf(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	rec := &Recorder{}
	px := httptest.NewServer(newProxy(v, u, rec))
	defer px.Close()

	body, _ := json.Marshal(map[string]string{"model": "claude-test", "content": password + " and Banana and " + password})
	req, _ := http.NewRequest("POST", px.URL+"/v1/messages?beta=true", bytes.NewReader(body))
	req.Header.Set("x-api-key", "sk-ant-api03-not-a-real-key-but-long-enough")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.list) != 1 {
		t.Fatalf("recorded %d exchanges", len(rec.list))
	}
	ex := rec.list[0]
	if !ex.done || ex.status != 200 || ex.model != "claude-test" || ex.uri != "/v1/messages?beta=true" {
		t.Errorf("summary = %+v", ex.summary())
	}
	if bytes.Contains(ex.sent, []byte("word-123")) || !bytes.Contains(ex.sent, []byte(pwToken)) || !bytes.Contains(ex.sent, []byte("Apple")) {
		t.Errorf("sent = %s", ex.sent)
	}
	want := map[string]Rewrite{
		"DB_PASSWORD": {Kind: "secret", Name: "DB_PASSWORD", Real: password, Shown: pwToken, Source: "test", Count: 2},
		"banana":      {Kind: "rename", Name: "banana", Real: "Banana", Shown: "Apple", Count: 1},
	}
	if len(ex.rewrites) != len(want) {
		t.Errorf("rewrites = %+v", ex.rewrites)
	}
	for _, r := range ex.rewrites {
		if want[r.Name] != r {
			t.Errorf("rewrite %+v, want %+v", r, want[r.Name])
		}
	}
	if ex.reqHeaders["X-Api-Key"] != "(hidden)" {
		t.Errorf("api key recorded: %q", ex.reqHeaders["X-Api-Key"])
	}
	if !bytes.Contains(ex.response, []byte(pwToken)) || bytes.Contains(ex.response, []byte("word-123")) {
		t.Errorf("response should be recorded as received: %s", ex.response)
	}
	if len(ex.restores) != 1 || len(ex.restores[0].Rewrites) != 2 || !strings.Contains(ex.restores[0].Agent, "Banana") || !strings.Contains(ex.restores[0].Model, pwToken) {
		t.Errorf("restores = %+v", ex.restores)
	}
}

func TestRecorderEvicts(t *testing.T) {
	rec := &Recorder{}
	for range viewMaxExchanges + 5 {
		ex, _ := rec.start(httptest.NewRequest("POST", "/v1/messages", nil))
		rec.sent(ex, []byte(`{}`), nil)
	}
	if len(rec.list) != viewMaxExchanges || rec.list[0].id != 6 {
		t.Errorf("kept %d, oldest #%d", len(rec.list), rec.list[0].id)
	}
}

// The view shows real values, so it needs the token from the printed link.
func TestViewNeedsToken(t *testing.T) {
	srv := httptest.NewServer((&Recorder{}).handler("secret-token", "slopproxy_view_test"))
	defer srv.Close()
	for _, path := range []string{"/", "/api/list", "/app.js", "/?token=wrong"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s without the token: %d", path, resp.StatusCode)
		}
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(srv.URL + "/?token=secret-token")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(page, []byte("slopproxy")) || resp.Request.URL.RawQuery != "" {
		t.Errorf("with the token: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	resp, err = c.Get(srv.URL + "/api/list")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("api with the cookie: %d", resp.StatusCode)
	}
}
