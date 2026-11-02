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
  slopproxy [flags] scan           list what will be masked (never prints values)

Config lives outside the project so the agent doesn't stumble on it:
-config FILE, else ~/.config/slopproxy/projects/<folder name>, else
~/.config/slopproxy/config.

  [values]                          # hide the value assigned to these
  DB_PASSWORD = not-the-real-db-password
  GITHUB_TOKEN                      # agent sees [[SECRET:GITHUB_TOKEN]]
  *_SECRET                          # every matching variable

  [names]                           # rename these words themselves
  calculateRiskScore = scoreThing

Every text file in the project is searched for assignments to [values] names
(NAME=x, NAME: x, "NAME": "x", ...) and the environment is checked too.
[names] entries are renamed wherever they appear as a whole word.
Well-known token formats (sk-ant-, ghp_, AKIA, JWTs, ...) are always masked.

Flags:
`

func main() {
	configFlag := flag.String("config", "", "config file (default: this project's file, else ~/.config/slopproxy/config)")
	listen := flag.String("listen", "127.0.0.1:8787", "address for serve")
	upstreamURL := flag.String("upstream", "https://api.anthropic.com", "Claude API base URL")
	logPath := flag.String("log", "", "log file (default: stderr for serve, discarded for run)")
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
	path, explicit := configPath(dir, cwd, *configFlag)
	cfg, err := loadConfig(path, explicit)
	if err != nil {
		log.Fatal(err)
	}
	upstream, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatal(err)
	}
	key, err := loadKey()
	if err != nil {
		log.Fatal(err)
	}
	v := NewVault(key)
	if err := loadSecrets(cfg, path, v); err != nil {
		log.Fatal(err)
	}
	h := newProxy(v, upstream)

	args := flag.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
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
		tw.Flush()
	case "serve":
		setLog(*logPath, os.Stderr)
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("listening on http://%s -> %s (%d secrets); set ANTHROPIC_BASE_URL=http://%s", ln.Addr(), upstream, len(v.Entries()), ln.Addr())
		log.Fatal(http.Serve(ln, h))
	case "run":
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			flag.Usage()
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "slopproxy: protecting %d secrets, %d renames, config %s\n", len(v.Entries()), len(v.Renames()), path)
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

func run(h http.Handler, args []string) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, h)

	c := exec.Command(args[0], args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(os.Environ(), "ANTHROPIC_BASE_URL=http://"+ln.Addr().String())
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

func newProxy(v *Vault, upstream *url.URL) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			// Let the transport negotiate and transparently decode gzip so we see plain bytes.
			r.Out.Header.Del("Accept-Encoding")
		},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				resp.Body = unmaskSSE(v, resp.Body)
				return nil
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			b = unmaskToolInputs(v, b)
			resp.Body = io.NopCloser(bytes.NewReader(b))
			resp.ContentLength = int64(len(b))
			resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail closed: anything we can't read must not go upstream unmasked.
		if r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "slopproxy: compressed request bodies are not supported", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "slopproxy: "+err.Error(), http.StatusBadRequest)
			return
		}
		for _, e := range v.Detect(body, "request", true) {
			log.Printf("detected new secret %s", e.Name)
		}
		masked, err := v.Mask(body)
		if err != nil {
			log.Printf("refusing %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(w, "slopproxy: "+err.Error(), http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(masked))
		r.ContentLength = int64(len(masked))
		rp.ServeHTTP(w, r)
	})
}
