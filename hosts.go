package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// A cloaked host is a remote service the agent only knows as a localhost one.
// slopproxy listens on localhost:PORT and forwards to the real address, and in
// everything the model sees, the real address reads as http://localhost:PORT.
//
//	[hosts]
//	https://api.acme.com = 9001
//	  strip-cf                                    # drop Cloudflare headers both ways
//	  request Authorization: Bearer $ACME_TOKEN   # set a request header
//	  request -X-Debug                            # remove one (x-trace-* removes a prefix)
//	  response -Server                            # the same for responses
//	  insecure                                    # don't verify the target's certificate

// Host is one [hosts] entry.
type Host struct {
	Target            *url.URL // scheme://host[:port], nothing else
	Port              int      // listens on 127.0.0.1:Port (and [::1]:Port)
	StripCF           bool
	Insecure          bool
	Request, Response []HeaderRule
	where             string // config file:line, for errors
}

// HeaderRule sets a header, or removes it when Remove is set. Name may end in
// "*" to remove every header with that prefix.
type HeaderRule struct {
	Name, Value string
	Remove      bool
}

// Local is the address the agent uses instead of the real one.
func (h *Host) Local() string { return "localhost:" + strconv.Itoa(h.Port) }

// parseHostLine reads "TARGET = PORT"; TARGET without a scheme means https.
func parseHostLine(line, where string) (*Host, error) {
	target, port, ok := strings.Cut(line, "=")
	target, port = strings.TrimSpace(target), strings.TrimSpace(port)
	if !ok || target == "" || port == "" {
		return nil, fmt.Errorf("%s: %q is neither a host (https://real.host = PORT) nor an option (strip-cf, insecure, request, response)", where, line)
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	switch {
	case err != nil || u.Host == "" || u.Hostname() == "":
		return nil, fmt.Errorf("%s: %s is not a host name or URL", where, target)
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("%s: %s: only http:// and https:// hosts can be cloaked", where, target)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return nil, fmt.Errorf("%s: %s: give the host only (scheme://host[:port]), no path or query", where, target)
	}
	port = strings.TrimPrefix(strings.TrimPrefix(port, "localhost:"), "127.0.0.1:")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%s: %q is not a port; write %s = 9001 to use localhost:9001", where, port, target)
	}
	u.Host = strings.ToLower(u.Host)
	if p := u.Port(); p == "443" && u.Scheme == "https" || p == "80" && u.Scheme == "http" {
		u.Host = u.Hostname()
	}
	if strings.EqualFold(u.Hostname(), "localhost") || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback() {
		return nil, fmt.Errorf("%s: %s is already local; [hosts] cloaks remote hosts", where, target)
	}
	return &Host{Target: &url.URL{Scheme: u.Scheme, Host: u.Host}, Port: n, where: where}, nil
}

// isHostOption reports whether a [hosts] line is an option for the host above
// it rather than a new host. Indenting options is optional.
func isHostOption(line string) bool {
	word, _, _ := strings.Cut(line, " ")
	switch strings.ToLower(word) {
	case "strip-cf", "insecure", "request", "response":
		return true
	}
	return false
}

// parseOption reads one option line under a host.
func (h *Host) parseOption(line, where string) error {
	word, rest, _ := strings.Cut(line, " ")
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(word) {
	case "strip-cf":
		h.StripCF = true
	case "insecure":
		h.Insecure = true
	case "request", "response":
		r, err := parseHeaderRule(rest)
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		if word == "request" {
			h.Request = append(h.Request, r)
		} else {
			h.Response = append(h.Response, r)
		}
	default:
		return fmt.Errorf("%s: unknown host option %q; use strip-cf, insecure, request or response", where, word)
	}
	return nil
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'+.^_|~-]+\*?$`)

func parseHeaderRule(s string) (HeaderRule, error) {
	if name, ok := strings.CutPrefix(s, "-"); ok {
		name = strings.TrimSpace(name)
		if !headerNameRe.MatchString(name) {
			return HeaderRule{}, fmt.Errorf("expected -Header-Name, got %q", s)
		}
		return HeaderRule{Name: name, Remove: true}, nil
	}
	name, value, ok := strings.Cut(s, ":")
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if !ok || !headerNameRe.MatchString(name) || strings.HasSuffix(name, "*") {
		return HeaderRule{}, fmt.Errorf("expected Header-Name: value or -Header-Name, got %q", s)
	}
	return HeaderRule{Name: name, Value: value}, nil
}

// expandHeaders fills $VAR and ${VAR} in header values from the environment,
// else from the [values] found in .env and [files]. Each value used is masked
// like a secret, so a credential the cloak adds never reaches the model.
func expandHeaders(hosts []*Host, v *Vault) {
	known := map[string]string{}
	for _, e := range v.Entries() {
		known[strings.ToUpper(e.Name)] = e.Value
	}
	for _, h := range hosts {
		for _, rules := range [][]HeaderRule{h.Request, h.Response} {
			for i, r := range rules {
				if r.Remove {
					continue
				}
				rules[i].Value = os.Expand(r.Value, func(name string) string {
					val, ok := os.LookupEnv(name)
					if !ok {
						val, ok = known[strings.ToUpper(name)]
					}
					switch {
					case !ok:
						log.Printf("warning: %s: $%s is not in the environment, .env or [files], so header %s gets an empty value there", h.where, name, r.Name)
					case len(val) >= 8:
						v.Add(name, val, "", "env")
					}
					return val
				})
			}
		}
	}
}

// hostReplacer maps the target's URLs to the local address (toLocal) or back.
// Only scheme-qualified and //-anchored forms, so e-mail addresses and
// subdomains are left alone; the vault masks every other mention for the model.
func (h *Host) replacer(toLocal bool) *strings.Replacer {
	t, l := h.Target.Host, h.Local()
	ws := "ws"
	if h.Target.Scheme == "https" {
		ws = "wss"
	}
	pairs := [][2]string{
		{h.Target.Scheme + "://" + t, "http://" + l},
		{ws + "://" + t, "ws://" + l},
		{h.Target.Scheme + `:\/\/` + t, `http:\/\/` + l},
		{url.QueryEscape(h.Target.Scheme + "://" + t), url.QueryEscape("http://" + l)},
		{"//" + t, "//" + l},
	}
	var args []string
	for _, p := range pairs {
		if toLocal {
			args = append(args, p[0], p[1])
		} else {
			args = append(args, p[1], p[0])
		}
	}
	return strings.NewReplacer(args...)
}

// cfRequestHeaders are added by Cloudflare in front of a client: they carry its
// IP, country and the hop. cf-* on responses exist only because the target is
// behind Cloudflare; cfValueHeaders go only when they point at Cloudflare.
var (
	cfRequestHeaders = []string{"cf-*", "cdn-loop", "true-client-ip"}
	cfValueHeaders   = []string{"Server", "NEL", "Report-To", "Reporting-Endpoints", "Speculation-Rules", "Expect-CT"}
)

func removeHeaders(h http.Header, pattern string) {
	p := strings.ToLower(pattern)
	prefix, isPrefix := strings.CutSuffix(p, "*")
	for k := range h {
		if lk := strings.ToLower(k); lk == p || isPrefix && strings.HasPrefix(lk, prefix) {
			delete(h, k)
		}
	}
}

func applyRules(h http.Header, rules []HeaderRule) {
	for _, r := range rules {
		if r.Remove {
			removeHeaders(h, r.Name)
		} else {
			h.Set(r.Name, r.Value)
		}
	}
}

func stripCloudflareResponse(h http.Header) {
	removeHeaders(h, "cf-*")
	for _, k := range cfValueHeaders {
		for _, v := range h.Values(k) {
			if lv := strings.ToLower(v); strings.Contains(lv, "cloudflare") || strings.Contains(lv, "cf-nel") || strings.Contains(lv, "/cdn-cgi/") {
				h.Del(k)
				break
			}
		}
	}
}

// stripCookieDomain drops the Domain attribute so the cookie binds to localhost.
func stripCookieDomain(c string) string {
	parts := strings.Split(c, ";")
	kept := parts[:0]
	for _, p := range parts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "domain=") {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ";")
}

// ponytail: bodies are rewritten whole, up to this size; bigger ones (and
// streams) pass through with the real host's URLs in them.
const maxRewriteBody = 8 << 20

func isText(h http.Header) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	for _, s := range []string{"json", "xml", "javascript", "x-www-form-urlencoded", "graphql", "yaml"} {
		if strings.Contains(ct, s) {
			return true
		}
	}
	return false
}

// rewriteBody replaces URLs in a text body of at most maxRewriteBody bytes;
// anything larger or unreadable is passed on as it came.
func rewriteBody(body io.ReadCloser, r *strings.Replacer) (io.ReadCloser, int64, bool) {
	head, err := io.ReadAll(io.LimitReader(body, maxRewriteBody+1))
	if err != nil || len(head) > maxRewriteBody {
		return struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), body), body}, -1, false
	}
	body.Close()
	out := []byte(r.Replace(string(head)))
	return io.NopCloser(bytes.NewReader(out)), int64(len(out)), true
}

// cloakHandler forwards localhost:PORT to the real host.
func cloakHandler(h *Host) http.Handler {
	toReal, toLocal := h.replacer(false), h.replacer(true)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: h.Insecure}
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			pr.SetURL(h.Target) // the Host header becomes the target's
			out.URL.RawQuery = toReal.Replace(out.URL.RawQuery)
			for _, vs := range out.Header {
				for i, v := range vs {
					vs[i] = toReal.Replace(v)
				}
			}
			// The transport negotiates gzip and decodes it, so bodies can be rewritten.
			out.Header.Del("Accept-Encoding")
			if h.StripCF {
				for _, p := range cfRequestHeaders {
					removeHeaders(out.Header, p)
				}
			}
			applyRules(out.Header, h.Request)
			if out.Body != nil && out.Body != http.NoBody && out.Header.Get("Content-Encoding") == "" && isText(out.Header) {
				var n int64
				var ok bool
				if out.Body, n, ok = rewriteBody(out.Body, toReal); ok {
					out.ContentLength = n
					out.Header.Set("Content-Length", strconv.FormatInt(n, 10))
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			hd := resp.Header
			for k, vs := range hd {
				for i, v := range vs {
					if k == "Set-Cookie" {
						v = stripCookieDomain(v)
					}
					vs[i] = toLocal.Replace(v)
				}
			}
			hd.Del("Strict-Transport-Security")
			hd.Del("Alt-Svc")
			if h.StripCF {
				stripCloudflareResponse(hd)
			}
			applyRules(hd, h.Response)
			if resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
				hd.Get("Content-Encoding") != "" || !isText(hd) {
				return nil
			}
			if body, n, ok := rewriteBody(resp.Body, toLocal); ok {
				resp.Body, resp.ContentLength = body, n
				hd.Set("Content-Length", strconv.FormatInt(n, 10))
				hd.Del("ETag")
			} else {
				resp.Body = body
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				log.Printf("host %s: %s %s: %v", h.Local(), r.Method, r.URL.RequestURI(), err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// startHosts listens for every cloaked host, on 127.0.0.1 and, when it can,
// [::1], since "localhost" may resolve to either.
func startHosts(hosts []*Host) error {
	for _, h := range hosts {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.Port)))
		if err != nil {
			return fmt.Errorf("%s: can't cloak %s as %s: %w", h.where, h.Target, h.Local(), err)
		}
		srv := &http.Server{Handler: cloakHandler(h), ErrorLog: log.Default()}
		go srv.Serve(ln)
		// Not every machine has IPv6 loopback; 127.0.0.1 is enough there.
		if ln6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(h.Port))); err == nil {
			go srv.Serve(ln6)
		}
	}
	return nil
}

// hostMask is how the vault shows a cloaked host to the model, and back.
type hostMask struct {
	host         *Host
	mask, unmask *regexp.Regexp
}

// Both match a host name with an optional scheme and port, as a whole name: a
// preceding letter, digit, "_" or "-" means a longer name. A preceding "." is a
// subdomain, which is masked too (cdn.api.acme.com reads cdn.localhost:9001).
const hostStart = `(^|[^A-Za-z0-9_-])((?:https?|wss?)://)?`

func newHostMask(h *Host) hostMask {
	return hostMask{
		host:   h,
		mask:   regexp.MustCompile(`(?i)` + hostStart + regexp.QuoteMeta(h.Target.Hostname()) + `(?::\d+)?\b`),
		unmask: regexp.MustCompile(`(?i)` + hostStart + `(?:localhost|127\.0\.0\.1):` + strconv.Itoa(h.Port) + `\b`),
	}
}

// apply replaces each match in s; inverse goes from the local address to the
// real one. count gets the text replaced and what it became.
func (m hostMask) apply(s string, inverse bool, count func(from, to string)) string {
	re := m.mask
	if inverse {
		re = m.unmask
	}
	idx := re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, x := range idx {
		start := x[3] // after the boundary character
		scheme := ""
		if x[4] >= 0 {
			scheme = strings.ToLower(s[x[4]:x[5]])
		}
		to := m.replacement(scheme, inverse)
		b.WriteString(s[last:start])
		b.WriteString(to)
		if count != nil {
			count(s[start:x[1]], to)
		}
		last = x[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func (m hostMask) replacement(scheme string, inverse bool) string {
	ws := strings.HasPrefix(scheme, "ws")
	if !inverse {
		switch {
		case scheme == "":
			return m.host.Local()
		case ws:
			return "ws://" + m.host.Local()
		}
		return "http://" + m.host.Local()
	}
	t := m.host.Target
	switch {
	case scheme == "":
		return t.Host
	case ws && t.Scheme == "https":
		return "wss://" + t.Host
	case ws:
		return "ws://" + t.Host
	}
	return t.Scheme + "://" + t.Host
}

// keepsLocalAddress lists tools whose input reaches the network: they keep the
// localhost address the model wrote, so their requests go through the cloak
// (its headers, Cloudflare stripping). Every other tool (Edit, Write, Grep, ...)
// gets the real address back, so it matches what is on disk.
func keepsLocalAddress(tool string) bool {
	switch tool {
	case "Bash", "PowerShell", "Monitor", "WebFetch":
		return true
	}
	return false
}
