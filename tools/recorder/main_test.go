package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecorder(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"host":"` + r.Host + `","echo":` + string(body) + `}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	// A file from an earlier run: numbering must continue after it.
	if err := os.WriteFile(filepath.Join(dir, "0041-front-GET-root.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := newRecorder(dir, regexp.MustCompile(`\.css$`), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(rec.handler(leg{name: "front", upstream: u}))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPut, front.URL+"/oauth2/auth/requests/login/accept?login_challenge=abc", strings.NewReader(`{"subject":"alice"}`))
	req.Host = "dispatcher.hydra.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || !strings.Contains(string(got), `"host":"dispatcher.hydra.test"`) {
		t.Fatalf("proxied response = %d %s, want 201 with the original Host", resp.StatusCode, got)
	}

	resp, err = http.Get(front.URL + "/build/app.css")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 2 {
		t.Fatalf("files = %v, want the old one plus one recording (css skipped)", files)
	}
	data, err := os.ReadFile(filepath.Join(dir, "0042-front-PUT-oauth2_auth_requests_login_accept.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ex exchange
	if err := json.Unmarshal(data, &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Request.URI != "/oauth2/auth/requests/login/accept?login_challenge=abc" ||
		compact(t, ex.Request.Body) != `{"subject":"alice"}` ||
		ex.Response.Status != http.StatusCreated ||
		!strings.Contains(compact(t, ex.Response.Body), `"echo":{"subject":"alice"}`) {
		t.Errorf("recorded exchange = %s", data)
	}
}

// hydra-passwordless hangs up once it has decoded the JSON: the exchange must
// still be recorded with the full upstream response.
func TestRecorderClientHangsUp(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenge":"abc"}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	rec, err := newRecorder(dir, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(rec.handler(leg{name: "front", upstream: u}))
	defer front.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+"/oauth2/auth/requests/login", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("client was expected to give up before the upstream answered")
	}

	file := filepath.Join(dir, "0001-front-GET-oauth2_auth_requests_login.json")
	var data []byte
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if data, err = os.ReadFile(file); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("exchange not recorded: %v", err)
	}
	var ex exchange
	if err := json.Unmarshal(data, &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Response.Status != http.StatusOK || compact(t, ex.Response.Body) != `{"challenge":"abc"}` {
		t.Errorf("recorded response = %d %s, want 200 with the full body", ex.Response.Status, ex.Response.Body)
	}
}

// An upstream that never answers is given up after the timeout: the client gets
// a 504 and the exchange is still recorded.
func TestRecorderUpstreamTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	dir := t.TempDir()
	rec, err := newRecorder(dir, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	rec.timeout = 100 * time.Millisecond
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(rec.handler(leg{name: "front", upstream: u}))
	defer front.Close()

	resp, err := http.Get(front.URL + "/consent")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", resp.StatusCode)
	}
	data, err := os.ReadFile(filepath.Join(dir, "0001-front-GET-consent.json"))
	if err != nil {
		t.Fatalf("exchange not recorded: %v", err)
	}
	var ex exchange
	if err := json.Unmarshal(data, &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Response.Status != http.StatusGatewayTimeout || !strings.Contains(string(ex.Response.Body), "deadline exceeded") {
		t.Errorf("recorded response = %d %s, want 504 with the cause", ex.Response.Status, ex.Response.Body)
	}
}

// A body over maxBody is refused, never relayed or recorded truncated.
func TestRecorderBodyLimit(t *testing.T) {
	var called atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		// Chunked: a truncated body would reach the client without an error.
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	rec, err := newRecorder(dir, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(upstream.URL)
	front := httptest.NewServer(rec.handler(leg{name: "front", upstream: u}))
	defer front.Close()

	resp, err := http.Post(front.URL+"/upload", "text/plain", bytes.NewReader(make([]byte, maxBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || called.Load() {
		t.Errorf("request over maxBody = %d, upstream called %v; want 413, not forwarded", resp.StatusCode, called.Load())
	}

	resp, err = http.Get(front.URL + "/page")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || len(got) != 0 {
		t.Errorf("response over maxBody = %d with %d bytes, want 502 and no body", resp.StatusCode, len(got))
	}
	data, err := os.ReadFile(filepath.Join(dir, "0001-front-GET-page.json"))
	if err != nil {
		t.Fatalf("exchange not recorded: %v", err)
	}
	var ex exchange
	if err := json.Unmarshal(data, &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Response.Status != http.StatusBadGateway || !strings.Contains(string(ex.Response.Body), "over") {
		t.Errorf("recorded response = %d %.80s, want 502 with the cause", ex.Response.Status, ex.Response.Body)
	}
}

// compact undoes the indentation the recorder applies to embedded JSON bodies.
func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestBodyJSON(t *testing.T) {
	if got := string(bodyJSON([]byte(`<html>`))); got != `"<html>"` {
		t.Errorf("non-JSON body = %s, want a JSON string", got)
	}
	if bodyJSON(nil) != nil {
		t.Error("empty body must be omitted")
	}
}

func TestParseLeg(t *testing.T) {
	if _, err := parseLeg("front=:8080=http://hydra-dispatcher:80"); err != nil {
		t.Errorf("valid leg: %v", err)
	}
	for _, s := range []string{"front", "front=:8080", "front=:8080=not-a-url", "=:8080=http://x"} {
		if _, err := parseLeg(s); err == nil {
			t.Errorf("parseLeg(%q): want an error", s)
		}
	}
}
