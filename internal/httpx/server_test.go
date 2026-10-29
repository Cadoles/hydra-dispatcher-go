package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReady(t *testing.T) {
	ok := func(context.Context) error { return nil }
	failing := func(context.Context) error { return errors.New("dial tcp hydra:4445: connection refused") }
	slow := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	deaf := func(context.Context) error { time.Sleep(time.Second); return nil } // ignores its deadline
	panicking := func(context.Context) error { panic("kaboom") }

	tests := []struct {
		name       string
		checks     map[string]Check
		wantStatus int
		wantBody   map[string]any
		wantLog    string
	}{
		{"all ok", map[string]Check{"hydra": ok, "state": ok}, 200,
			map[string]any{"status": "ready", "checks": map[string]any{"hydra": "ok", "state": "ok"}}, ""},
		{"one failing", map[string]Check{"hydra": failing, "state": ok}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable", "state": "ok"}}, "connection refused"},
		{"one too slow", map[string]Check{"hydra": slow}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable"}}, "deadline exceeded"},
		{"one ignoring its deadline", map[string]Check{"hydra": deaf, "state": ok}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable", "state": "ok"}}, "no answer within 50ms"},
		// Out of Recover's reach: the check fails, not the process.
		{"one panicking", map[string]Check{"hydra": panicking}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable"}}, "http.panic"},
		{"no check", nil, 200, map[string]any{"status": "ready", "checks": map[string]any{}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			w := httptest.NewRecorder()
			start := time.Now()
			Ready(tt.checks, 50*time.Millisecond, slog.New(slog.NewJSONHandler(&logs, nil))).
				ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if d := time.Since(start); d > 500*time.Millisecond {
				t.Errorf("answered in %s, want within the timeout", d)
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tt.wantStatus || !jsonEqual(body, tt.wantBody) {
				t.Errorf("got %d %v, want %d %v", w.Code, body, tt.wantStatus, tt.wantBody)
			}
			// Error details stay in the log: /ready is public.
			if strings.Contains(w.Body.String(), "connection refused") || strings.Contains(w.Body.String(), "kaboom") {
				t.Error("the error detail reached the /ready body")
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs = %s, want %q", logs.String(), tt.wantLog)
			}
		})
	}
}

// A check is logged when it starts failing and when it recovers, not on
// every probe: /ready is open to anyone, who may call it in a loop.
func TestReadyLogsChanges(t *testing.T) {
	var logs bytes.Buffer
	var fail atomic.Bool
	check := func(context.Context) error {
		if fail.Load() {
			return errors.New("connection refused")
		}
		return nil
	}
	ready := Ready(map[string]Check{"hydra": check}, time.Second, slog.New(slog.NewJSONHandler(&logs, nil)))
	probe := func() { ready.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ready", nil)) }

	probe() // ok from the start: nothing to say
	fail.Store(true)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(probe)
	}
	wg.Wait()
	fail.Store(false)
	probe()
	probe()
	// A client gone before the answer changes nothing.
	fail.Store(true)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	ready.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ready", nil).WithContext(gone))

	var msgs []any
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var line map[string]any
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		msgs = append(msgs, line["msg"])
	}
	if want := []any{"ready.check_failed", "ready.check_recovered"}; !slices.Equal(msgs, want) {
		t.Errorf("logged %v, want %v", msgs, want)
	}
}

func jsonEqual(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

func TestServeGracefulShutdown(t *testing.T) {
	released := make(chan struct{})
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-released
		_, _ = w.Write([]byte("done"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, NewServer(mux, slog.New(slog.DiscardHandler)), ln, time.Second) }()

	got := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			got <- err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		got <- string(b)
	}()

	<-started
	cancel() // SIGTERM while a request is in flight
	// Released once Shutdown has closed the listener: the request is then
	// in flight during the shutdown, not finished before it starts.
	for {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			break
		}
		_ = c.Close()
		time.Sleep(time.Millisecond)
	}
	close(released)

	if body := <-got; body != "done" {
		t.Errorf("in-flight request = %q, want it to finish", body)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve = %v, want nil after a graceful shutdown", err)
	}
}

func TestServeListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if err := Serve(context.Background(), NewServer(http.NewServeMux(), slog.New(slog.DiscardHandler)), ln, time.Second); err == nil {
		t.Error("Serve on a closed listener: want an error")
	}
}

// Past the grace, in-flight requests are cut rather than left to SIGKILL.
func TestServeShutdownTimeout(t *testing.T) {
	started := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stuck", func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done() // until the connection is cut
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, NewServer(mux, slog.New(slog.DiscardHandler)), ln, 50*time.Millisecond) }()

	got := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/stuck")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		got <- err
	}()
	<-started
	cancel()
	if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Serve = %v, want the grace exceeded", err)
	}
	if err := <-got; err == nil {
		t.Error("the stuck request ended normally, want it cut")
	}
}

func TestInFlight(t *testing.T) {
	var f InFlight
	if n, err := f.Wait(context.Background()); n != 0 || err != nil {
		t.Fatalf("Wait with no request = %d, %v", n, err)
	}
	release := map[string]chan struct{}{"/a": make(chan struct{}), "/b": make(chan struct{})}
	started := make(chan struct{})
	h := f.Track(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release[r.URL.Path]
	}))
	served := make(chan struct{})
	for _, path := range []string{"/a", "/b"} {
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
			served <- struct{}{}
		}()
		<-started
	}
	waitFor := func(d time.Duration) (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		return f.Wait(ctx)
	}
	if n, err := waitFor(10 * time.Millisecond); n != 2 || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait with two requests = %d, %v; want 2, the deadline", n, err)
	}
	close(release["/a"])
	<-served
	if n, err := waitFor(10 * time.Millisecond); n != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait with one request = %d, %v; want 1, the deadline", n, err)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := f.Wait(context.Background())
		waited <- err
	}()
	// Blocked on the running request: what follows wakes it, not the path
	// of a Wait that finds none.
	select {
	case err := <-waited:
		t.Fatalf("Wait = %v with a request running", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(release["/b"])
	<-served
	if err := <-waited; err != nil {
		t.Errorf("Wait = %v once the last request ended", err)
	}

	// A panic that goes through Track still ends its count.
	p := f.Track(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	func() {
		defer func() { _ = recover() }()
		p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	if n, err := f.Wait(context.Background()); n != 0 || err != nil {
		t.Errorf("Wait after a panic = %d, %v", n, err)
	}
}

// What InFlight is for: past the grace, Serve returns while the handler of a
// cut request still runs.
func TestInFlightAfterShutdownTimeout(t *testing.T) {
	var f InFlight
	started, release := make(chan struct{}), make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /deaf", func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release // deaf to the request's context
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- Serve(ctx, NewServer(f.Track(mux), slog.New(slog.DiscardHandler)), ln, 50*time.Millisecond)
	}()
	go func() {
		if resp, err := http.Get("http://" + ln.Addr().String() + "/deaf"); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	cancel()
	if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve = %v, want the grace exceeded", err)
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if n, err := f.Wait(waitCtx); n != 1 || err == nil {
		t.Errorf("Wait after Serve = %d, %v; want the cut handler still counted", n, err)
	}
	close(release)
	if n, err := f.Wait(context.Background()); n != 0 || err != nil {
		t.Errorf("Wait once released = %d, %v", n, err)
	}
}

// net/http's own messages are error records with a stable name.
func TestServerErrorLog(t *testing.T) {
	var logs bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /twice", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.WriteHeader(http.StatusTeapot)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	go func() { served <- Serve(ctx, NewServer(mux, logger), ln, time.Second) }()
	resp, err := http.Get("http://" + ln.Addr().String() + "/twice")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cancel()
	if err := <-served; err != nil {
		t.Fatal(err)
	}

	var line map[string]any
	if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
		t.Fatalf("%q: %v", logs.String(), err)
	}
	if line["level"] != "ERROR" || line["msg"] != "http.server_error" || !strings.Contains(line["detail"].(string), "superfluous response.WriteHeader") {
		t.Errorf("line = %v", line)
	}
}
