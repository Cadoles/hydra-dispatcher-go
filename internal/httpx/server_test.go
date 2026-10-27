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
	"strings"
	"testing"
	"time"
)

func TestReady(t *testing.T) {
	ok := func(context.Context) error { return nil }
	failing := func(context.Context) error { return errors.New("dial tcp hydra:4445: connection refused") }
	slow := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

	tests := []struct {
		name       string
		checks     map[string]Check
		wantStatus int
		wantBody   map[string]any
	}{
		{"all ok", map[string]Check{"hydra": ok, "state": ok}, 200,
			map[string]any{"status": "ready", "checks": map[string]any{"hydra": "ok", "state": "ok"}}},
		{"one failing", map[string]Check{"hydra": failing, "state": ok}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable", "state": "ok"}}},
		{"one too slow", map[string]Check{"hydra": slow}, 503,
			map[string]any{"status": "unavailable", "checks": map[string]any{"hydra": "unavailable"}}},
		{"no check", nil, 200, map[string]any{"status": "ready", "checks": map[string]any{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			w := httptest.NewRecorder()
			Ready(tt.checks, 50*time.Millisecond, slog.New(slog.NewJSONHandler(&logs, nil))).
				ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != tt.wantStatus || !jsonEqual(body, tt.wantBody) {
				t.Errorf("got %d %v, want %d %v", w.Code, body, tt.wantStatus, tt.wantBody)
			}
			// Error details stay in the log: /ready is public.
			if strings.Contains(w.Body.String(), "connection refused") {
				t.Error("the error detail reached the /ready body")
			}
			if tt.name == "one failing" && !strings.Contains(logs.String(), "connection refused") {
				t.Errorf("the failure was not logged: %s", logs.String())
			}
		})
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
	go func() { served <- Serve(ctx, NewServer(mux), ln) }()

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
	time.Sleep(50 * time.Millisecond)
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
	if err := Serve(context.Background(), NewServer(http.NewServeMux()), ln); err == nil {
		t.Error("Serve on a closed listener: want an error")
	}
}
