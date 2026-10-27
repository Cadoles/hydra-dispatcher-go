package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
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
		{"only trusted hops", "10.0.5.5:80", []string{"10.9.9.9, 10.1.1.1"}, "10.9.9.9"},
		{"malformed hop stops the walk", "10.0.5.5:80", []string{"198.51.100.1, garbage, 10.1.1.1"}, "10.1.1.1"},
		{"trusted proxy without header", "10.0.5.5:80", nil, "10.0.5.5"},
		{"IPv6 proxy", "[fd00::1]:80", []string{"2001:db8::42"}, "2001:db8::42"},
		{"IPv4-mapped remote", "[::ffff:10.0.5.5]:80", []string{"198.51.100.1"}, "198.51.100.1"},
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
		{"zero trace id", "10.0.0.9:1", map[string]string{"Traceparent": "00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01"}, ""},
		{"X-Trace-ID from anyone", "203.0.113.7:1", map[string]string{"X-Trace-ID": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"}, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"},
		{"traceparent wins over X-Trace-ID", "10.0.0.9:1", map[string]string{"Traceparent": traceparent, "X-Trace-ID": "0123456789abcdef"}, parentTrace},
		{"malformed X-Trace-ID", "203.0.113.7:1", map[string]string{"X-Trace-ID": "<script>alert(1)</script>"}, ""},
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
		logIP, remote, want string
	}{
		{"none", "203.0.113.7:1", ""},
		{"full", "203.0.113.7:1", "203.0.113.7"},
		{"truncated", "[2001:db8:1:2::42]:1", "2001:db8:1::/48"},
	} {
		h, buf := stack(mux, 0, tt.logIP)
		for _, path := range []string{"/ok", "/fail", "/nowhere"} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.RemoteAddr = tt.remote
			h.ServeHTTP(httptest.NewRecorder(), r)
		}
		lines := logLines(t, buf)
		// Sample 0: the success is dropped, errors are always written.
		if len(lines) != 2 || lines[0]["path"] != "/fail" || lines[1]["route"] != "unmatched" {
			t.Fatalf("log_ip %s: lines = %v", tt.logIP, lines)
		}
		if got, _ := lines[0]["ip"].(string); got != tt.want {
			t.Errorf("log_ip %s: ip = %q, want %q", tt.logIP, got, tt.want)
		}
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
	h, _ = stack(abort, 1, "full")
	defer func() {
		if p := recover(); p != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler to go through", p)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
}
