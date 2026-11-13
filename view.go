package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The traffic view (-view) records what passes through the proxy, in memory
// only, and shows it on a local web page: each request as sent to the API, the
// response as received, and every value hidden or restored on the way.

//go:embed view
var viewFiles embed.FS

// ponytail: keeps the newest 100 exchanges and 64MB of bodies; one long
// conversation is resent whole each turn, so bodies add up fast.
const (
	viewMaxExchanges = 100
	viewMaxBytes     = 64 << 20
	viewMaxBody      = 8 << 20
)

// Exchange is one request through the proxy and its response.
type Exchange struct {
	id          int
	start, end  time.Time
	method, uri string
	model       string
	status      int
	done        bool
	err         string
	reqHeaders  map[string]string
	respHeaders map[string]string
	sent        []byte // the request body as it went upstream (masked)
	sentCut     bool
	rewrites    []Rewrite // what was hidden on the way out
	response    []byte    // the response as it came from upstream (still masked)
	responseCut bool
	restores    []restore // tool inputs that went back to the agent
	evicted     bool
}

type restore struct {
	Index    int       `json:"index"`
	Model    string    `json:"model"` // the tool input as the model wrote it
	Agent    string    `json:"agent"` // and as the agent received it
	Rewrites []Rewrite `json:"rewrites"`
}

// Recorder holds the recent exchanges. A nil *Recorder records nothing, so the
// proxy calls it unconditionally.
type Recorder struct {
	mu     sync.Mutex
	nextID int
	list   []*Exchange
	size   int
}

type exchangeKey struct{}

func exchangeFrom(ctx context.Context) *Exchange {
	ex, _ := ctx.Value(exchangeKey{}).(*Exchange)
	return ex
}

// start records a new request and returns r carrying it in its context.
func (rc *Recorder) start(r *http.Request) (*Exchange, *http.Request) {
	if rc == nil {
		return nil, r
	}
	ex := &Exchange{start: time.Now(), method: r.Method, uri: r.URL.RequestURI(), reqHeaders: redactHeaders(r.Header)}
	rc.mu.Lock()
	rc.nextID++
	ex.id = rc.nextID
	rc.list = append(rc.list, ex)
	rc.evict()
	rc.mu.Unlock()
	return ex, r.WithContext(context.WithValue(r.Context(), exchangeKey{}, ex))
}

// evict drops the oldest exchanges over the limits; mu must be held.
func (rc *Recorder) evict() {
	for len(rc.list) > 1 && (len(rc.list) > viewMaxExchanges || rc.size > viewMaxBytes) {
		old := rc.list[0]
		old.evicted = true
		rc.size -= len(old.sent) + len(old.response)
		rc.list = rc.list[1:]
	}
}

func (rc *Recorder) update(ex *Exchange, f func(*Exchange)) {
	if rc == nil || ex == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	f(ex)
}

func (rc *Recorder) sent(ex *Exchange, body []byte, rewrites []Rewrite) {
	var m struct{ Model string }
	json.Unmarshal(body, &m)
	rc.update(ex, func(ex *Exchange) {
		ex.model, ex.rewrites = m.Model, rewrites
		ex.sent, ex.sentCut = capped(nil, body)
		if !ex.evicted {
			rc.size += len(ex.sent)
			rc.evict()
		}
	})
}

func (rc *Recorder) response(ex *Exchange, resp *http.Response) {
	rc.update(ex, func(ex *Exchange) {
		ex.status, ex.respHeaders = resp.StatusCode, redactHeaders(resp.Header)
	})
}

func (rc *Recorder) finish(ex *Exchange, status int, err string) {
	rc.update(ex, func(ex *Exchange) {
		if ex.done {
			return
		}
		if status != 0 {
			ex.status = status
		}
		ex.done, ex.end, ex.err = true, time.Now(), err
	})
}

// restorer returns the callback that records restored tool inputs, or nil.
func (rc *Recorder) restorer(ex *Exchange) onRestore {
	if rc == nil || ex == nil {
		return nil
	}
	return func(index int, model, agent string, trace []Rewrite) {
		rc.update(ex, func(ex *Exchange) {
			ex.restores = append(ex.restores, restore{index, model, agent, trace})
		})
	}
}

// tee records the upstream response body as it is read, and finishes the
// exchange when it ends.
func (rc *Recorder) tee(ex *Exchange, body io.ReadCloser) io.ReadCloser {
	if rc == nil || ex == nil {
		return body
	}
	return &teeBody{body, rc, ex}
}

type teeBody struct {
	io.ReadCloser
	rc *Recorder
	ex *Exchange
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if n > 0 {
		t.rc.update(t.ex, func(ex *Exchange) {
			before := len(ex.response)
			ex.response, ex.responseCut = capped(ex.response, p[:n])
			if !ex.evicted {
				t.rc.size += len(ex.response) - before
				t.rc.evict()
			}
		})
	}
	switch {
	case err == io.EOF:
		t.rc.finish(t.ex, 0, "")
	case err != nil:
		t.rc.finish(t.ex, 0, err.Error())
	}
	return n, err
}

func (t *teeBody) Close() error {
	t.rc.finish(t.ex, 0, "")
	return t.ReadCloser.Close()
}

// capped appends b to dst up to viewMaxBody, and says whether it had to cut.
func capped(dst, b []byte) ([]byte, bool) {
	room := viewMaxBody - len(dst)
	if len(b) <= room {
		return append(dst, b...), false
	}
	return append(dst, b[:max(room, 0)]...), true
}

// redactHeaders flattens headers for display, hiding credentials.
func redactHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		switch strings.ToLower(k) {
		case "authorization", "x-api-key", "proxy-authorization", "cookie", "set-cookie":
			out[k] = "(hidden)"
		default:
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}

type summary struct {
	ID       int       `json:"id"`
	Start    time.Time `json:"start"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Model    string    `json:"model,omitempty"`
	Status   int       `json:"status"`
	Ms       int64     `json:"ms"`
	Done     bool      `json:"done"`
	Error    string    `json:"error,omitempty"`
	Hidden   int       `json:"hidden"`   // places a value was hidden in the request
	Restored int       `json:"restored"` // tool inputs that got real values back
	Size     int       `json:"size"`
}

// summary must be called with mu held.
func (ex *Exchange) summary() summary {
	s := summary{ID: ex.id, Start: ex.start, Method: ex.method, URI: ex.uri, Model: ex.model,
		Status: ex.status, Done: ex.done, Error: ex.err, Size: len(ex.sent)}
	end := ex.end
	if !ex.done {
		end = time.Now()
	}
	s.Ms = end.Sub(ex.start).Milliseconds()
	for _, r := range ex.rewrites {
		s.Hidden += r.Count
	}
	for _, r := range ex.restores {
		if len(r.Rewrites) > 0 {
			s.Restored++
		}
	}
	return s
}

// handler serves the view. cookie names the login cookie; browsers share
// cookies across ports, so each instance needs its own name.
func (rc *Recorder) handler(token, cookie string) http.Handler {
	static, _ := fs.Sub(viewFiles, "view")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/list", func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		out := make([]summary, 0, len(rc.list))
		for i := len(rc.list) - 1; i >= 0; i-- {
			out = append(out, rc.list[i].summary())
		}
		rc.mu.Unlock()
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /api/exchange/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		rc.mu.Lock()
		var out any
		for _, ex := range rc.list {
			if ex.id == id {
				out = struct {
					summary
					ReqHeaders  map[string]string `json:"reqHeaders"`
					RespHeaders map[string]string `json:"respHeaders"`
					Sent        string            `json:"sent"`
					SentCut     bool              `json:"sentCut"`
					Rewrites    []Rewrite         `json:"rewrites"`
					Response    string            `json:"response"`
					ResponseCut bool              `json:"responseCut"`
					Restores    []restore         `json:"restores"`
				}{ex.summary(), ex.reqHeaders, ex.respHeaders, string(ex.sent), ex.sentCut, ex.rewrites,
					string(ex.response), ex.responseCut, ex.restores}
			}
		}
		rc.mu.Unlock()
		if out == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /api/clear", func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		for _, ex := range rc.list {
			ex.evicted = true
		}
		rc.list, rc.size = nil, 0
		rc.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// The page shows real secret values, and the agent can reach localhost
		// too, so it needs the token from the link printed on the terminal.
		if t := r.URL.Query().Get("token"); t != "" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) != 1 {
				http.Error(w, "wrong token", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie(cookie); err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) != 1 {
			http.Error(w, "Open the traffic view with the link slopproxy printed in your terminal.", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

// startView serves the traffic view on a free local port and returns its link.
func startView(rc *Recorder) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	go http.Serve(ln, rc.handler(token, fmt.Sprintf("slopproxy_view_%d", ln.Addr().(*net.TCPAddr).Port)))
	return fmt.Sprintf("http://%s/?token=%s", ln.Addr(), token), nil
}

// openBrowser opens url in the default browser, if there is one.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd.Start() == nil {
		go cmd.Wait()
	}
}
