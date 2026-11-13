package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
)

const usage = `slopproxy keeps secrets out of what a coding agent sends to the Claude API.
Secret values are replaced on the way out and swapped back on the way in, so
files on disk keep their real values.

Usage:
  slopproxy [flags] init           create this project's config and print its path
  slopproxy [flags] run -- CMD...  run CMD (e.g. claude) through a private proxy
  slopproxy [flags] serve          serve on -listen; point ANTHROPIC_BASE_URL at it

Add -view (before run or serve) to watch the traffic live in your browser:
what is sent, what comes back, and everything hidden or restored.
  slopproxy [flags] scan [-all]    list what will be masked (never prints values);
                                   -all searches the whole project for [values]

Config lives outside the project so the agent doesn't stumble on it:
-config FILE, else ~/.config/slopproxy/projects/<folder name>, else
~/.config/slopproxy/config.

  [values]                          # hide the value assigned to these
  DB_PASSWORD = not-the-real-db-password
  GITHUB_TOKEN                      # agent sees [[SECRET:GITHUB_TOKEN]]
  *_SECRET                          # every matching variable

  [files]                           # read [values] from these too (.env always)
  config/secrets.yml

  [names]                           # rename these words themselves
  calculateRiskScore = scoreThing

  [hosts]                           # serve a remote host as a localhost one
  https://api.acme.com = 9001       # the agent sees http://localhost:9001
    strip-cf                        # drop Cloudflare headers both ways
    request Authorization: Bearer $ACME_TOKEN
    response -Server

[values] are read from the environment, .env and [files] (NAME=x, NAME: x,
"NAME": "x", ...); nothing else in the project is read.
[names] entries are renamed wherever they appear as a whole word, in any case,
keeping its casing (banana = apple turns Banana into Apple, BANANA into APPLE).
Well-known token formats (sk-ant-, ghp_, AKIA, JWTs, ...) are always masked.

Flags:
`

func main() {
	configFlag := flag.String("config", "", "config file (default: this project's file, else ~/.config/slopproxy/config)")
	listen := flag.String("listen", "127.0.0.1:8787", "address for serve")
	upstreamURL := flag.String("upstream", "", "API base URL to forward to (default: the ANTHROPIC_BASE_URL Claude Code would use, else "+anthropicAPI+")")
	logPath := flag.String("log", "", "log file (default: stderr for serve, discarded for run)")
	view := flag.Bool("view", false, "open a live view of the traffic in the browser: what is sent, received and rewritten")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage); flag.PrintDefaults() }
	flag.Parse()

	dir, err := configDir()
	if err != nil {
		log.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	if flag.Arg(0) == "init" {
		initConfig(projectConfig(dir, cwd))
		return
	}
	args := flag.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	scanAll := false
	if cmd == "scan" {
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		all := fs.Bool("all", false, "search every project file for [values], not just .env and [files]")
		fs.Parse(args)
		scanAll = *all
	}
	path, explicit := configPath(dir, cwd, *configFlag)
	cfg, err := loadConfig(path, explicit)
	if err != nil {
		log.Fatal(err)
	}
	upstreamFrom := "-upstream"
	if *upstreamURL == "" {
		self := ""
		if cmd == "serve" {
			self = *listen
		}
		*upstreamURL, upstreamFrom = defaultUpstream(cwd, self)
	}
	upstream, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatal(err)
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		log.Fatalf("upstream %q (from %s) is not an http(s) URL", *upstreamURL, upstreamFrom)
	}
	forwarding := upstream.String()
	if upstreamFrom != "" {
		forwarding += " (from " + upstreamFrom + ")"
	}
	key, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}
	v := NewVault(key)
	if err := loadSecrets(cfg, path, v, scanAll); err != nil {
		log.Fatal(err)
	}
	expandHeaders(cfg.Hosts, v)
	if cmd == "run" || cmd == "serve" {
		if err := startHosts(cfg.Hosts); err != nil {
			log.Fatal(err)
		}
	}
	var rec *Recorder
	if *view && (cmd == "run" || cmd == "serve") {
		rec = &Recorder{}
		link, err := startView(rec)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "slopproxy: traffic view at %s\n", link)
		openBrowser(link)
	}
	h := newProxy(v, upstream, rec)

	switch cmd {
	case "scan":
		fmt.Fprintf(os.Stderr, "config: %s\n", path)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tFOUND IN\tAGENT SEES")
		for _, e := range v.Entries() {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Source, e.Token)
		}
		for from, to := range v.Renames() {
			fmt.Fprintf(tw, "%s\t(rename)\t%s\n", from, to)
		}
		for _, h := range cfg.Hosts {
			fmt.Fprintf(tw, "%s\t(host)\thttp://%s\n", h.Target, h.Local())
		}
		tw.Flush()
		if scanAll {
			if add := unlistedSources(cfg, v); len(add) > 0 {
				fmt.Printf("\nThese files hold [values] but aren't read on a normal start. Add them under [files] in %s:\n  %s\n", path, strings.Join(add, "\n  "))
			}
		}
	case "serve":
		setLog(*logPath, os.Stderr)
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("listening on http://%s -> %s (%d secrets); set ANTHROPIC_BASE_URL=http://%s", ln.Addr(), forwarding, len(v.Entries()), ln.Addr())
		for _, h := range cfg.Hosts {
			log.Printf("cloaking %s as http://%s", h.Target, h.Local())
		}
		log.Fatal(http.Serve(ln, h))
	case "run":
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			flag.Usage()
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "slopproxy: protecting %d secrets, %d renames, config %s\nslopproxy: forwarding to %s\n", len(v.Entries()), len(v.Renames()), path, forwarding)
		for _, h := range cfg.Hosts {
			fmt.Fprintf(os.Stderr, "slopproxy: cloaking %s as http://%s\n", h.Target, h.Local())
		}
		warnBypass(cwd, args)
		setLog(*logPath, io.Discard)
		os.Exit(run(h, args))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func initConfig(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Println(path, "(already exists)")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(configTemplate), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)
}

// unlistedSources lists the files [values] were found in that a normal start
// doesn't read. Well-known tokens are left out: they are caught in every request.
func unlistedSources(cfg *Config, v *Vault) []string {
	listed := map[string]bool{}
	for _, f := range listedFiles(cfg.Files) {
		listed[f] = true
	}
	var out []string
	for _, e := range v.Entries() {
		if _, ok := match(cfg.Values, e.Name); ok && e.Source != "env" && !listed[filepath.Clean(e.Source)] && !slices.Contains(out, e.Source) {
			out = append(out, e.Source)
		}
	}
	return out
}

func setLog(path string, def io.Writer) {
	if path == "" {
		log.SetOutput(def)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(f)
}

// warnBypass says when claude may still go around the proxy: managed settings
// and the user's own --settings outrank the --settings run adds.
func warnBypass(cwd string, args []string) {
	if !isClaude(args[0]) {
		return
	}
	if m := claudeSettingsFiles(cwd)[0]; settingsBaseURL(m) != "" {
		fmt.Fprintf(os.Stderr, "slopproxy: WARNING: %s sets ANTHROPIC_BASE_URL, which overrides slopproxy; requests will NOT be masked\n", m)
	}
	for _, a := range args[1:] {
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			fmt.Fprintln(os.Stderr, "slopproxy: WARNING: your --settings may override the proxy address; make sure it doesn't set ANTHROPIC_BASE_URL")
		}
	}
}

func run(h http.Handler, args []string) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, h)

	base := "http://" + ln.Addr().String()
	args = claudeArgs(args, base)
	c := exec.Command(args[0], args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), "ANTHROPIC_BASE_URL="+base)
	// Ctrl-C belongs to the child; catching (not ignoring) it keeps the child's default handler.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	err = c.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "slopproxy:", err)
		return 1
	}
	return 0
}

// newProxy masks requests and restores tool inputs in responses. rec, when not
// nil, records each exchange for the traffic view.
func newProxy(v *Vault, upstream *url.URL, rec *Recorder) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			// Let the transport negotiate and transparently decode gzip so we see plain bytes.
			r.Out.Header.Del("Accept-Encoding")
		},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			ex := exchangeFrom(resp.Request.Context())
			rec.response(ex, resp)
			resp.Body = rec.tee(ex, resp.Body)
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Body = unmaskSSE(v, resp.Body, rec.restorer(ex))
				return nil
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			b = unmaskToolInputs(v, b, rec.restorer(ex))
			resp.Body = io.NopCloser(bytes.NewReader(b))
			resp.ContentLength = int64(len(b))
			resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return nil
		},
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %s %s: %v", r.Method, r.URL.Path, err)
		rec.finish(exchangeFrom(r.Context()), http.StatusBadGateway, err.Error())
		w.WriteHeader(http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ex, r := rec.start(r)
		refuse := func(status int, msg string) {
			rec.finish(ex, status, msg)
			http.Error(w, "slopproxy: "+msg, status)
		}
		// Fail closed: anything we can't read must not go upstream unmasked.
		if r.Header.Get("Content-Encoding") != "" {
			refuse(http.StatusUnsupportedMediaType, "compressed request bodies are not supported")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			refuse(http.StatusBadRequest, err.Error())
			return
		}
		for _, e := range v.Detect(body, "request", true) {
			log.Printf("detected new secret %s", e.Name)
		}
		var masked []byte
		var rewrites []Rewrite
		if rec != nil {
			masked, rewrites, err = v.MaskTrace(body)
		} else {
			masked, err = v.Mask(body)
		}
		if err != nil {
			log.Printf("refusing %s %s: %v", r.Method, r.URL.Path, err)
			refuse(http.StatusBadGateway, err.Error())
			return
		}
		rec.sent(ex, masked, rewrites)
		r.Body = io.NopCloser(bytes.NewReader(masked))
		r.ContentLength = int64(len(masked))
		rp.ServeHTTP(w, r)
	})
}
