package httpx

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var trustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}

func TestRealIP(t *testing.T) {
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct client", "203.0.113.7:4321", nil, "203.0.113.7"},
		{"untrusted remote ignores X-Forwarded-For", "203.0.113.7:4321", []string{"198.51.100.1"}, "203.0.113.7"},
		{"trusted proxy", "10.0.5.5:80", []string{"198.51.100.1"}, "198.51.100.1"},
		{"first untrusted hop from the right", "10.0.5.5:80", []string{"192.0.2.66, 198.51.100.1, 10.1.2.3"}, "198.51.100.1"},
		{"several headers", "10.0.5.5:80", []string{"192.0.2.66", "198.51.100.1"}, "198.51.100.1"},
		{"trusted hop in a header of its own", "10.0.5.5:80", []string{"192.0.2.66, 198.51.100.1", "10.1.2.3"}, "198.51.100.1"},
		{"empty header right of the client", "10.0.5.5:80", []string{"198.51.100.1", ""}, "invalid IP"},
		{"only trusted hops", "10.0.5.5:80", []string{"10.9.9.9, 10.1.1.1"}, "10.9.9.9"},
		{"trusted proxy without header", "10.0.5.5:80", nil, "10.0.5.5"},
		{"IPv6 proxy", "[fd00::1]:80", []string{"2001:db8::42"}, "2001:db8::42"},
		{"IPv4-mapped remote", "[::ffff:10.0.5.5]:80", []string{"198.51.100.1"}, "198.51.100.1"},
		{"zoned proxy", "[fd00::1%eth0]:80", []string{"2001:db8::42"}, "2001:db8::42"},
		{"unreadable remote", "@", []string{"198.51.100.1"}, "invalid IP"},
		// Forms some load balancers write.
		{"hop with a port", "10.0.5.5:80", []string{"198.51.100.1:4321"}, "198.51.100.1"},
		{"bracketed IPv6 hop", "10.0.5.5:80", []string{"[2001:db8::42]"}, "2001:db8::42"},
		{"bracketed IPv6 hop with a port", "10.0.5.5:80", []string{"[2001:db8::42]:4321"}, "2001:db8::42"},
		{"zone dropped", "10.0.5.5:80", []string{"fe80::1%eth0"}, "fe80::1"},
		// Unknown, never the proxy: the allowlists may hold its address.
		{"malformed hop", "10.0.5.5:80", []string{"198.51.100.1, garbage, 10.1.1.1"}, "invalid IP"},
		{"unknown hop", "10.0.5.5:80", []string{"unknown"}, "invalid IP"},
		{"empty hop", "10.0.5.5:80", []string{"198.51.100.1,"}, "invalid IP"},
		{"empty header", "10.0.5.5:80", []string{""}, "invalid IP"},
		// What the client writes left of its own address is never read: it can
		// make itself neither trusted nor unknown.
		{"malformed hop left of the client", "10.0.5.5:80", []string{"garbage, 198.51.100.1"}, "198.51.100.1"},
		{"malformed line left of the client", "10.0.5.5:80", []string{"garbage", "198.51.100.1, 10.1.2.3"}, "198.51.100.1"},
		{"trusted address left of the client", "10.0.5.5:80", []string{"10.3.0.7, 198.51.100.1"}, "198.51.100.1"},
		{"IPv4-mapped trusted hop", "10.0.5.5:80", []string{"198.51.100.1, ::ffff:10.1.2.3"}, "198.51.100.1"},
		{"IPv6 proxy chain", "[fd00::1]:80", []string{"2001:db8::42, fd00::2, [fd00::3]:443"}, "2001:db8::42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			var got netip.Addr
			RealIP(trustedProxies)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = ClientIP(r.Context())
			})).ServeHTTP(httptest.NewRecorder(), r)
			if got.String() != tt.want {
				t.Errorf("client IP = %s, want %s", got, tt.want)
			}
		})
	}
}

// Left of its address, the client writes as many entries as it likes: they
// are neither read nor split, so they cost nothing.
func TestRealIPLongHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.5.5:80"
	r.Header.Set("X-Forwarded-For", strings.Repeat(",", 60000)+"198.51.100.1")
	const runs = 100
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		if got := clientIP(r, trustedProxies); got != netip.MustParseAddr("198.51.100.1") {
			t.Fatalf("client IP = %s", got)
		}
	}
	runtime.ReadMemStats(&after)
	if perRun := (after.TotalAlloc - before.TotalAlloc) / runs; perRun > 1<<10 {
		t.Errorf("%d bytes allocated per request, want none for the entries left of the client", perRun)
	}
}

func TestTrace(t *testing.T) {
	const parentTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	traceparent := "00-" + parentTrace + "-00f067aa0ba902b7-01"
	tests := []struct {
		name, remote string
		headers      map[string]string
		want         string // "" means a freshly generated id
	}{
		{"traceparent from a trusted network", "10.0.0.9:1", map[string]string{"Traceparent": traceparent}, parentTrace},
		{"traceparent from the Internet is ignored", "203.0.113.7:1", map[string]string{"Traceparent": traceparent}, ""},
		{"traceparent from a login app behind the proxy", "10.0.0.9:1", map[string]string{"X-Forwarded-For": "10.3.0.7", "Traceparent": traceparent}, parentTrace},
		{"traceparent from the Internet behind the proxy is ignored", "10.0.0.9:1", map[string]string{"X-Forwarded-For": "203.0.113.7", "Traceparent": traceparent}, ""},
		{"traceparent behind an unreadable hop is ignored", "10.0.0.9:1", map[string]string{"X-Forwarded-For": "unknown", "Traceparent": traceparent}, ""},
		{"zero trace id", "10.0.0.9:1", map[string]string{"Traceparent": "00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01"}, ""},
		{"zero parent id", "10.0.0.9:1", map[string]string{"Traceparent": "00-" + parentTrace + "-" + strings.Repeat("0", 16) + "-01"}, ""},
		{"uppercase traceparent", "10.0.0.9:1", map[string]string{"Traceparent": strings.ToUpper(traceparent)}, ""},
		{"traceparent of another version", "10.0.0.9:1", map[string]string{"Traceparent": "01" + traceparent[2:]}, ""},
		{"X-Trace-ID from a trusted network", "10.0.0.9:1", map[string]string{"X-Trace-ID": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"}, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"},
		{"X-Trace-ID from a login app behind the proxy", "10.0.0.9:1", map[string]string{"X-Forwarded-For": "10.3.0.7", "X-Trace-ID": "0123456789abcdef"}, "0123456789abcdef"},
		// Never an id of the client's choosing (another user's) in the logs.
		{"X-Trace-ID from the Internet is ignored", "203.0.113.7:1", map[string]string{"X-Trace-ID": "0123456789abcdef"}, ""},
		{"X-Trace-ID from the Internet behind the proxy is ignored", "10.0.0.9:1", map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Trace-ID": "0123456789abcdef"}, ""},
		{"X-Trace-ID of 16 characters", "10.0.0.9:1", map[string]string{"X-Trace-ID": strings.Repeat("a", 16)}, strings.Repeat("a", 16)},
		{"X-Trace-ID of 64 characters", "10.0.0.9:1", map[string]string{"X-Trace-ID": strings.Repeat("a", 64)}, strings.Repeat("a", 64)},
		{"X-Trace-ID of 15 characters", "10.0.0.9:1", map[string]string{"X-Trace-ID": strings.Repeat("a", 15)}, ""},
		{"X-Trace-ID of 65 characters", "10.0.0.9:1", map[string]string{"X-Trace-ID": strings.Repeat("a", 65)}, ""},
		{"traceparent wins over X-Trace-ID", "10.0.0.9:1", map[string]string{"Traceparent": traceparent, "X-Trace-ID": "0123456789abcdef"}, parentTrace},
		{"malformed X-Trace-ID", "10.0.0.9:1", map[string]string{"X-Trace-ID": "<script>alert(1)</script>"}, ""},
		{"nothing", "203.0.113.7:1", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			var got string
			w := httptest.NewRecorder()
			Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = TraceID(r.Context())
			}), RealIP(trustedProxies), Trace(trustedProxies)).ServeHTTP(w, r)

			if tt.want != "" && got != tt.want {
				t.Errorf("trace id = %q, want %q", got, tt.want)
			}
			if tt.want == "" && (len(got) != 32 || got == parentTrace || strings.Trim(got, "0123456789abcdef") != "") {
				t.Errorf("trace id = %q, want a new 32-hex id", got)
			}
			if w.Header().Get("X-Trace-ID") != got {
				t.Errorf("X-Trace-ID response header = %q, want %q", w.Header().Get("X-Trace-ID"), got)
			}
		})
	}

	// Without RealIP, the client is unknown: no traceparent is trusted.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.9:1"
	r.Header.Set("Traceparent", traceparent)
	var got string
	Trace(trustedProxies)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = TraceID(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), r)
	if len(got) != 32 || got == parentTrace {
		t.Errorf("trace id without RealIP = %q, want a new one", got)
	}
}

// stack builds the chain serve uses, logging into a buffer.
func stack(mux *http.ServeMux, sample float64, logIP string) (http.Handler, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(LogHandler(slog.NewJSONHandler(&buf, nil)))
	return Chain(Routes(mux),
		RealIP(trustedProxies),
		Trace(trustedProxies),
		AccessLog(logger.With("log_type", "access"), sample, logIP),
		Recover(logger),
	), &buf
}

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func TestAccessLog(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /things/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})
	mux.Handle("GET /health", Health())
	h, buf := stack(mux, 1, "truncated")

	r := httptest.NewRequest(http.MethodGet, "/things/42?login_challenge=secret-challenge", nil)
	r.RemoteAddr = "10.0.5.5:80"
	r.Header.Set("X-Forwarded-For", "198.51.100.77")
	r.Header.Set("User-Agent", strings.Repeat("u", 300))
	h.ServeHTTP(httptest.NewRecorder(), r)

	health := httptest.NewRequest(http.MethodGet, "/health", nil)
	h.ServeHTTP(httptest.NewRecorder(), health)

	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("log lines = %v, want only the /things request (/health is never logged)", lines)
	}
	l := lines[0]
	for k, want := range map[string]any{
		"msg": "http.request", "log_type": "access", "method": "GET", "path": "/things/42",
		"route": "GET /things/{id}", "status": float64(200), "bytes": float64(5), "ip": "198.51.100.0/24",
	} {
		if l[k] != want {
			t.Errorf("%s = %v, want %v", k, l[k], want)
		}
	}
	if len(l["user_agent"].(string)) != 256 || len(l["trace_id"].(string)) != 32 {
		t.Errorf("user_agent or trace_id malformed: %v", l)
	}
	// Once each, though LogHandler wraps the access logger too.
	if n := strings.Count(buf.String(), `"trace_id"`); n != 1 {
		t.Errorf("trace_id written %d times: %s", n, buf.String())
	}
	if strings.Contains(buf.String(), "secret-challenge") {
		t.Error("the query string reached the access log")
	}
}

func TestAccessLogSamplingAndIP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /fail", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })

	for _, tt := range []struct {
		logIP, remote, xff, want string
	}{
		{"none", "203.0.113.7:1", "", ""},
		{"full", "203.0.113.7:1", "", "203.0.113.7"},
		{"truncated", "[2001:db8:1:2::42]:1", "", "2001:db8:1::/48"},
		// Unreadable X-Forwarded-For: shown, never mistaken for none.
		{"truncated", "10.0.5.5:80", "unknown", "unknown"},
		{"full", "10.0.5.5:80", "unknown", "unknown"},
		{"none", "10.0.5.5:80", "unknown", ""},
	} {
		h, buf := stack(mux, 0, tt.logIP)
		for _, path := range []string{"/ok", "/fail", "/nowhere"} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
		}
		lines := logLines(t, buf)
		// Sample 0: the success is dropped, errors are always written.
		if len(lines) != 2 || lines[0]["path"] != "/fail" || lines[1]["route"] != "unmatched" {
			t.Fatalf("log_ip %s: lines = %v", tt.logIP, lines)
		}
		if got, _ := lines[0]["ip"].(string); got != tt.want {
			t.Errorf("log_ip %s, X-Forwarded-For %q: ip = %q, want %q", tt.logIP, tt.xff, got, tt.want)
		}
	}
}

// Probes are read (GET, HEAD); another method on their paths is written.
func TestAccessLogQuietPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /ready", Health())
	h, buf := stack(mux, 1, "none")
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(m, "/ready", nil))
	}
	lines := logLines(t, buf)
	if len(lines) != 2 || lines[0]["method"] != "POST" || lines[1]["method"] != "DELETE" || lines[0]["status"] != float64(405) {
		t.Errorf("log lines = %v, want POST and DELETE only, in 405", lines)
	}
}

// The mux names the trailing-slash redirect of a CONNECT by the path received:
// the route is then unmatched, never that path.
func TestRoutesConnect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/files/{id}/", func(http.ResponseWriter, *http.Request) {})
	h, buf := stack(mux, 1, "none")
	for _, m := range []string{http.MethodGet, http.MethodConnect} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(m, "/files/client-chosen", nil))
	}
	lines := logLines(t, buf)
	if len(lines) != 2 || lines[0]["route"] != "/files/{id}/" || lines[1]["route"] != "unmatched" {
		t.Errorf("log lines = %v, want the pattern for GET, unmatched for CONNECT", lines)
	}
}

// Errors are never sampled: what a client sends must be bounded.
func TestAccessLogBounds(t *testing.T) {
	h, buf := stack(http.NewServeMux(), 0, "none")
	// 1023 bytes, then a 2-byte character across the 1024-byte limit.
	path := "/" + strings.Repeat("a", 1022) + "%C3%A9" + strings.Repeat("b", 50000)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(strings.Repeat("M", 40), path, nil))

	l := logLines(t, buf)[0]
	if p := l["path"].(string); len(p) != 1023 || !utf8.ValidString(p) {
		t.Errorf("path of %d bytes (valid UTF-8: %v), want 1023", len(p), utf8.ValidString(p))
	}
	if m := l["method"].(string); m != strings.Repeat("M", 16) {
		t.Errorf("method = %q, want 16 characters", m)
	}

	// Not UTF-8: cut at the limit, not back to the last character ("/a").
	// The encoder writes each invalid byte as U+FFFD.
	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/a"+strings.Repeat("%80", 2000), nil))
	if p := logLines(t, buf)[0]["path"].(string); p != "/a"+strings.Repeat("�", 1022) {
		t.Errorf("path of invalid bytes = %q, want /a then 1022 replacement characters", p)
	}
}

func TestStatusWriter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hints", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusTeapot)
	})
	mux.HandleFunc("GET /flush", func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the middlewares: %v", err)
		}
	})
	h, buf := stack(mux, 1, "none")
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hints", nil))
	flushed := httptest.NewRecorder()
	h.ServeHTTP(flushed, httptest.NewRequest(http.MethodGet, "/flush", nil))

	if l := logLines(t, buf)[0]; l["status"] != float64(http.StatusTeapot) {
		t.Errorf("status = %v, want the final 418, not the 103", l["status"])
	}
	if !flushed.Flushed {
		t.Error("the flush did not reach the connection")
	}

	// 101 Switching Protocols is final, unlike the other 1xx.
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw.WriteHeader(http.StatusSwitchingProtocols)
	if sw.status != http.StatusSwitchingProtocols {
		t.Errorf("status after a 101 = %d", sw.status)
	}
}

// http.ServeContent copies by ReadFrom, which statusWriter keeps for the
// sendfile of net/http, and counts.
func TestStatusWriterReadFrom(t *testing.T) {
	path := filepath.Join(t.TempDir(), "theme.css")
	content := strings.Repeat("body{}", 5000)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /theme.css", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(io.ReaderFrom); !ok {
			t.Error("statusWriter hides io.ReaderFrom")
		}
		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = f.Close() }()
		http.ServeContent(w, r, "theme.css", time.Time{}, f)
	})
	h, buf := stack(mux, 1, "none")
	srv := httptest.NewServer(h)
	resp, err := http.Get(srv.URL + "/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	srv.Close()
	if string(b) != content {
		t.Errorf("body of %d bytes, want %d", len(b), len(content))
	}
	if l := logLines(t, buf)[0]; l["status"] != float64(200) || l["bytes"] != float64(len(content)) {
		t.Errorf("status = %v, bytes = %v, want 200 and %d", l["status"], l["bytes"], len(content))
	}
}

func TestRecover(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	h, buf := stack(mux, 1, "full")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))
	traceID := w.Header().Get("X-Trace-ID")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), traceID) {
		t.Errorf("response = %d %q, want 500 with the trace id", w.Code, w.Body.String())
	}
	lines := logLines(t, buf)
	if len(lines) != 2 || lines[0]["msg"] != "http.panic" || lines[0]["trace_id"] != traceID || lines[1]["status"] != float64(500) {
		t.Errorf("log lines = %v, want the panic then the 500 access line", lines)
	}

	abort := http.NewServeMux()
	abort.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	h, buf = stack(abort, 1, "full")
	func() {
		defer func() {
			if p := recover(); p != http.ErrAbortHandler {
				t.Errorf("recovered %v, want http.ErrAbortHandler to go through", p)
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
	}()
	if lines := logLines(t, buf); len(lines) != 1 || lines[0]["aborted"] != true || lines[0]["status"] != float64(500) {
		t.Errorf("log lines = %v, want the aborted request in the access log", lines)
	}
}

// The 500 drops what the handler had set, and keeps the outer headers.
func TestRecoverHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "dispatcher_remember", Value: "sentinel"})
		w.Header().Set("Location", "https://elsewhere.example")
		panic("kaboom")
	})
	h, _ := stack(mux, 1, "none")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if w.Code != http.StatusInternalServerError || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
		t.Errorf("response = %d %v, want a 500 without the handler's headers", w.Code, w.Header())
	}
	if w.Header().Get("X-Trace-ID") == "" {
		t.Error("the 500 lost the trace id header")
	}
}

// A response already started is cut, never completed by the error message:
// by a write, by a flush (the headers are gone), or by a status alone.
func TestRecoverStartedResponse(t *testing.T) {
	for _, tt := range []struct {
		name   string
		start  func(http.ResponseWriter)
		status float64
	}{
		{"written", func(w http.ResponseWriter) { _, _ = w.Write([]byte("partial page ")) }, 200},
		{"copied", func(w http.ResponseWriter) {
			_, _ = io.Copy(w, io.LimitReader(strings.NewReader("partial page "), 100))
		}, 200},
		{"flushed", func(w http.ResponseWriter) { _ = http.NewResponseController(w).Flush() }, 200},
		{"status set", func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.example")
			w.WriteHeader(http.StatusFound)
		}, 302},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /half", func(w http.ResponseWriter, _ *http.Request) {
				tt.start(w)
				panic("kaboom")
			})
			h, buf := stack(mux, 0, "none")
			srv := httptest.NewServer(h)
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Get(srv.URL + "/half")
			if err == nil {
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr == nil {
					t.Errorf("response = %d %q, want the connection cut", resp.StatusCode, b)
				}
			}
			srv.Close() // waits for the handler, hence for its log lines

			lines := logLines(t, buf)
			if len(lines) != 2 || lines[0]["msg"] != "http.panic" || lines[1]["aborted"] != true || lines[1]["status"] != tt.status {
				t.Errorf("log lines = %v, want the panic, then the aborted request (sampling or not)", lines)
			}
		})
	}
}

// A panic before any final status gets the 500: after a 103, on an invalid
// status (net/http panics before sending it), after copying nothing, and on a
// path the access log skips, where Recover tracks the response itself.
func TestRecoverBeforeStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hints", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		panic("kaboom")
	})
	mux.HandleFunc("GET /invalid", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(1000) })
	mux.HandleFunc("GET /nothing-copied", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(strings.NewReader(""), 1))
		panic("kaboom")
	})
	mux.HandleFunc("GET /ready", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	h, buf := stack(mux, 1, "none")
	srv := httptest.NewServer(h)
	for _, path := range []string{"/hints", "/invalid", "/nothing-copied", "/ready"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if traceID := resp.Header.Get("X-Trace-ID"); resp.StatusCode != http.StatusInternalServerError || traceID == "" || !strings.Contains(string(b), traceID) {
			t.Errorf("%s: response = %d %q, want 500 with the trace id", path, resp.StatusCode, b)
		}
	}
	srv.Close()

	count := map[any]int{}
	for _, l := range logLines(t, buf) {
		count[l["msg"]]++
	}
	if count["http.panic"] != 4 || count["http.request"] != 3 {
		t.Errorf("log lines = %v, want 4 panics and 3 access lines (none for /ready)", count)
	}
}
