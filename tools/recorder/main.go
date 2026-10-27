// Command recorder is a recording reverse proxy used to capture golden fixtures
// of the Hydra login/consent protocol from a running stack. Each leg listens on
// its own address and forwards to one upstream; every exchange is written as a
// JSON file into the output directory, numbered in arrival order across legs.
//
//	recorder -out ./captures \
//	  -leg front=:8080=http://hydra-dispatcher:80 \
//	  -leg hydra=:8081=http://hydra:4445
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const maxBody = 10 << 20

type leg struct {
	name     string
	listen   string
	upstream *url.URL
}

func parseLeg(s string) (leg, error) {
	parts := strings.SplitN(s, "=", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return leg{}, fmt.Errorf("leg %q: want name=listen=upstream", s)
	}
	u, err := url.Parse(parts[2])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return leg{}, fmt.Errorf("leg %q: invalid upstream URL", s)
	}
	return leg{name: parts[0], listen: parts[1], upstream: u}, nil
}

type message struct {
	Method  string          `json:"method,omitempty"`
	Host    string          `json:"host,omitempty"`
	URI     string          `json:"uri,omitempty"`
	Status  int             `json:"status,omitempty"`
	Headers http.Header     `json:"headers"`
	Body    json.RawMessage `json:"body,omitempty"`
}

type exchange struct {
	Seq        int64     `json:"seq"`
	Leg        string    `json:"leg"`
	Time       time.Time `json:"time"`
	DurationMS int64     `json:"duration_ms"`
	Request    message   `json:"request"`
	Response   message   `json:"response"`
}

type recorder struct {
	dir    string
	skip   *regexp.Regexp
	seq    atomic.Int64
	logger *slog.Logger
}

// newRecorder continues the numbering of files already in dir, so a restart
// never overwrites earlier captures.
func newRecorder(dir string, skip *regexp.Regexp, logger *slog.Logger) (*recorder, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rec := &recorder{dir: dir, skip: skip, logger: logger}
	for _, e := range entries {
		prefix, _, _ := strings.Cut(e.Name(), "-")
		if n, err := strconv.ParseInt(prefix, 10, 64); err == nil && n > rec.seq.Load() {
			rec.seq.Store(n)
		}
	}
	return rec, nil
}

// exchangeKey carries the exchange being recorded on the outbound request.
type exchangeKey struct{}

func (rec *recorder) handler(l leg) http.Handler {
	// The incoming Host is kept: the Symfony dispatcher only answers to its
	// own server name.
	proxy := httputil.NewSingleHostReverseProxy(l.upstream)
	// The upstream response is read in full before it is relayed, so it is
	// recorded whole even when the client hangs up early.
	proxy.ModifyResponse = func(resp *http.Response) error {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if ex, ok := resp.Request.Context().Value(exchangeKey{}).(*exchange); ok {
			ex.Response = message{Status: resp.StatusCode, Headers: resp.Header.Clone(), Body: bodyJSON(body)}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if ex, ok := r.Context().Value(exchangeKey{}).(*exchange); ok {
			ex.Response = message{Status: http.StatusBadGateway, Body: bodyJSON([]byte("recorder: " + err.Error()))}
		}
		w.WriteHeader(http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec.skip != nil && rec.skip.MatchString(r.URL.Path) {
			proxy.ServeHTTP(w, r)
			return
		}
		reqBody, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "recorder: read body: "+err.Error(), http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		ex := &exchange{
			Seq:  rec.seq.Add(1),
			Leg:  l.name,
			Time: time.Now().UTC(),
			Request: message{
				Method:  r.Method,
				Host:    r.Host,
				URI:     r.URL.RequestURI(),
				Headers: r.Header.Clone(),
				Body:    bodyJSON(reqBody),
			},
		}
		// Keep recorded response bodies readable.
		r.Header.Del("Accept-Encoding")

		// Some clients (hydra-passwordless) hang up as soon as they have
		// decoded the JSON: the upstream call must outlive them, and the
		// proxy's ErrAbortHandler panic must not skip the recording.
		defer func() {
			ex.DurationMS = time.Since(ex.Time).Milliseconds()
			if err := rec.save(*ex); err != nil {
				rec.logger.Error("save", "seq", ex.Seq, "err", err)
			}
			if p := recover(); p != nil {
				panic(p)
			}
		}()
		ctx := context.WithValue(context.WithoutCancel(r.Context()), exchangeKey{}, ex)
		proxy.ServeHTTP(noCloseNotify{w}, r.WithContext(ctx))
	})
}

// noCloseNotify hides http.CloseNotifier, which the proxy falls back to for
// cancelling the upstream call when the request context cannot be cancelled.
type noCloseNotify struct{ http.ResponseWriter }

func (w noCloseNotify) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (rec *recorder) save(ex exchange) error {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetEscapeHTML(false) // recorded pages stay readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(ex); err != nil {
		return err
	}
	name := fmt.Sprintf("%04d-%s-%s-%s.json", ex.Seq, ex.Leg, ex.Request.Method, slug(ex.Request.URI))
	if err := os.WriteFile(filepath.Join(rec.dir, name), data.Bytes(), 0o644); err != nil {
		return err
	}
	rec.logger.Info("recorded", "file", name, "status", ex.Response.Status)
	return nil
}

var nonSlug = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// slug turns a request path into a file name fragment: /oauth2/auth/requests/login → oauth2_auth_requests_login.
func slug(uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	s := strings.Trim(nonSlug.ReplaceAllString(path, "_"), "_")
	if s == "" {
		return "root"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// bodyJSON embeds a JSON body as is, anything else as a JSON string.
func bodyJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return b
	}
	var s bytes.Buffer
	enc := json.NewEncoder(&s)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(string(b))
	return bytes.TrimSuffix(s.Bytes(), []byte("\n"))
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("out", "", "directory receiving one JSON file per exchange")
	skip := flag.String("skip", `\.(css|js|svg|png|jpg|ico|woff2?|map)$|^/_(wdt|profiler)/`, "paths proxied but not recorded (regexp)")
	var legs []leg
	flag.Func("leg", "name=listen=upstream, repeatable", func(s string) error {
		l, err := parseLeg(s)
		legs = append(legs, l)
		return err
	})
	flag.Parse()
	if *out == "" || len(legs) == 0 {
		flag.Usage()
		return errors.New("-out and at least one -leg are required")
	}
	skipRe, err := regexp.Compile(*skip)
	if err != nil {
		return fmt.Errorf("-skip: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	rec, err := newRecorder(*out, skipRe, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(legs))
	servers := make([]*http.Server, 0, len(legs))
	for _, l := range legs {
		srv := &http.Server{Addr: l.listen, Handler: rec.handler(l), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() {
			logger.Info("listening", "leg", l.name, "addr", l.listen, "upstream", l.upstream.String())
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("leg %s: %w", l.name, err)
			}
		}()
	}

	select {
	case err = <-errCh:
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return err
}
