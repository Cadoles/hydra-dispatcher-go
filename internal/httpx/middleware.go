package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"
)

type Middleware func(http.Handler) http.Handler

// Chain wraps h in the middlewares, the first one outermost.
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// RealIP stores the client address: the remote address, or, when the remote
// is a trusted proxy, the first untrusted hop of X-Forwarded-For read from
// the right. Forwarded headers from anyone else are ignored. A hop that does
// not read as an address leaves the client unknown (the zero Addr, which no
// allowlist holds), never the proxy's address, which the allowlists may hold.
func RealIP(trusted []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inf := &requestInfo{clientIP: clientIP(r, trusted)}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), infoKey{}, inf)))
		})
	}
}

func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := remote.Addr().Unmap().WithZone("")
	forwarded := r.Header.Values("X-Forwarded-For")
	if !contains(trusted, ip) || len(forwarded) == 0 {
		return ip
	}
	// From the right, without splitting: left of its address, the client
	// writes as many entries as it likes, which are never read.
	for i := len(forwarded) - 1; i >= 0; i-- {
		rest := forwarded[i]
		for {
			comma := strings.LastIndexByte(rest, ',')
			hop, ok := parseHop(rest[comma+1:])
			if !ok {
				return netip.Addr{}
			}
			if ip = hop; !contains(trusted, ip) {
				return ip
			}
			if comma < 0 {
				break
			}
			rest = rest[:comma]
		}
	}
	return ip
}

// parseHop reads an X-Forwarded-For entry: an address, bracketed or not,
// with or without the port some load balancers add (203.0.113.7:4321,
// [2001:db8::1]:4321). A zone means nothing outside its host: it is dropped.
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		a = ap.Addr()
	}
	return a.Unmap().WithZone(""), true
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	traceparent = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$`)
	xTraceID    = regexp.MustCompile(`^[0-9a-fA-F-]{16,64}$`)
)

// Trace picks the request's trace id. A client in parentNetworks (proxies,
// login apps) may give it, by a W3C traceparent, else by a well-formed
// X-Trace-ID; anyone else gets a new one, so outsiders can neither steer
// tracing nor put an id of their choosing (another user's) in the logs and
// the audit. It is returned in X-Trace-ID on every response.
func Trace(parentNetworks []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inf := infoFrom(r.Context())
			if inf == nil {
				inf = &requestInfo{}
				r = r.WithContext(context.WithValue(r.Context(), infoKey{}, inf))
			}
			trusted := contains(parentNetworks, inf.clientIP)
			// W3C: an all-zero trace id or parent id voids the header.
			if m := traceparent.FindStringSubmatch(r.Header.Get("Traceparent")); trusted && m != nil &&
				m[1] != strings.Repeat("0", 32) && m[2] != strings.Repeat("0", 16) {
				inf.traceID = m[1]
			} else if id := r.Header.Get("X-Trace-ID"); trusted && xTraceID.MatchString(id) {
				inf.traceID = id
			} else {
				inf.traceID = newTraceID()
			}
			w.Header().Set("X-Trace-ID", inf.traceID)
			next.ServeHTTP(w, r)
		})
	}
}

// newTraceID returns a W3C trace id: 16 random bytes in lowercase hex.
func newTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return hex.EncodeToString(b)
}

// Routes serves mux and records the matched pattern ("GET /admin/v1/flows/{id}")
// for the logs, "unmatched" when none matches. It never records the real path:
// the mux names the trailing-slash redirect of a CONNECT by the path received,
// so CONNECT, which the dispatcher does not serve, is unmatched.
func Routes(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inf := infoFrom(r.Context()); inf != nil {
			inf.route = "unmatched"
			if _, pattern := mux.Handler(r); pattern != "" && r.Method != http.MethodConnect {
				inf.route = pattern
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// quietPaths are probes and scrapes, never written to the access log when
// read (GET or HEAD). Another method is no probe: it is written.
var quietPaths = map[string]bool{"/health": true, "/ready": true, "/metrics": true}

// AccessLog writes one line per request. Successful requests are sampled at
// sample (0 to 1); errors and aborted requests are always written. The query
// string, which carries the challenges, is never logged; logIP is truncated,
// full or none.
func AccessLog(logger *slog.Logger, sample float64, logIP string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if quietPaths[r.URL.Path] && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			// Deferred without recover: a request aborted by a panic
			// (http.ErrAbortHandler) is logged, and the panic goes on.
			aborted := true
			defer func() {
				status := sw.status
				switch {
				case status == 0 && aborted:
					status = http.StatusInternalServerError
				case status == 0:
					status = http.StatusOK
				}
				if aborted || status >= 400 || mathrand.Float64() < sample {
					logRequest(logger, r, start, sw, status, aborted, logIP)
				}
			}()
			next.ServeHTTP(sw, r)
			aborted = false
		})
	}
}

func logRequest(logger *slog.Logger, r *http.Request, start time.Time, sw *statusWriter, status int, aborted bool, logIP string) {
	var traceID, route string
	if inf := infoFrom(r.Context()); inf != nil {
		traceID, route = inf.traceID, inf.route
	}
	// Errors are never sampled: what a client sends is bounded here.
	attrs := []slog.Attr{
		slog.String("trace_id", traceID),
		slog.String("method", truncate(r.Method, 16)),
		slog.String("route", route),
		slog.String("path", truncate(r.URL.Path, 1024)),
		slog.Int("status", status),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.Int64("bytes", sw.bytes),
		slog.String("user_agent", truncate(r.UserAgent(), 256)),
	}
	if aborted {
		attrs = append(attrs, slog.Bool("aborted", true))
	}
	if ip := formatIP(ClientIP(r.Context()), logIP); ip != "" {
		attrs = append(attrs, slog.String("ip", ip))
	}
	logger.LogAttrs(r.Context(), slog.LevelInfo, "http.request", attrs...)
}

// formatIP applies observability.log_ip: truncated keeps the /24 (IPv4) or
// /48 (IPv6) network. A client RealIP could not tell (X-Forwarded-For
// unreadable) is "unknown", so that it shows, unlike with none.
func formatIP(ip netip.Addr, mode string) string {
	switch {
	case mode == "none":
		return ""
	case !ip.IsValid():
		return "unknown"
	case mode == "full":
		return ip.String()
	}
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

// truncate cuts s to at most n bytes, on a character boundary. Where s is
// not UTF-8, it cuts at n: walking back further would empty a path of
// invalid bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > n-utf8.UTFMax && i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return s[:n]
}

// statusWriter records what the handler wrote, for the access log and
// Recover. It hides http.Flusher and http.Hijacker from type assertions:
// handlers reach them through http.NewResponseController, which unwraps it.
// A flush is recorded, since it sends the headers; a hijack is not. It keeps
// io.ReaderFrom, for the sendfile of http.ServeContent.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	// Called first: it panics on an invalid code, and nothing is sent then.
	w.ResponseWriter.WriteHeader(status)
	// A 1xx (103 Early Hints) is informational: the final status follows.
	// 101 Switching Protocols is final.
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
}

// FlushError is what http.ResponseController calls before unwrapping: a
// flush sends the headers, with a 200 unless the handler set a status. Not
// being http.Flusher, it leaves statusWriter opaque to type assertions.
func (w *statusWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if w.status == 0 && !errors.Is(err, http.ErrNotSupported) {
		w.status = http.StatusOK
	}
	return err
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// ReadFrom copies through the ReadFrom of net/http, which sends a file by
// sendfile. Nothing read, nothing is sent: the status stays unset.
func (w *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(w.ResponseWriter, src)
	if n > 0 && w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Recover turns a panic into a 500 carrying the trace id, and logs it with
// its stack. The 500 keeps the headers of the outer middlewares only, not a
// cookie or a redirection the handler had set. A response already started
// (written or flushed) is cut instead (http.ErrAbortHandler): the error
// appended to it would be served with its status. http.ErrAbortHandler keeps
// its meaning: abort without a log.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw, ok := w.(*statusWriter)
			if !ok {
				sw = &statusWriter{ResponseWriter: w}
			}
			outer := w.Header().Clone()
			defer func() {
				p := recover()
				if p == nil {
					return
				}
				if p == http.ErrAbortHandler {
					panic(p)
				}
				logger.ErrorContext(r.Context(), "http.panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				if sw.status != 0 {
					panic(http.ErrAbortHandler)
				}
				h := w.Header()
				clear(h)
				maps.Copy(h, outer)
				http.Error(sw, "internal error, trace id "+TraceID(r.Context()), http.StatusInternalServerError)
			}()
			next.ServeHTTP(sw, r)
		})
	}
}
