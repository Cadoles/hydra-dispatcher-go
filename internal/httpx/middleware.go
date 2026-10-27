package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
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
// the right. Forwarded headers from anyone else are ignored.
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
	ip := remote.Addr().Unmap()
	if !contains(trusted, ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // a malformed hop: do not trust anything left of it
		}
		ip = hop.Unmap()
		if !contains(trusted, ip) {
			break
		}
	}
	return ip
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
	traceparent = regexp.MustCompile(`^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)
	xTraceID    = regexp.MustCompile(`^[0-9a-fA-F-]{16,64}$`)
)

// Trace picks the request's trace id: from a W3C traceparent sent by a client
// in parentNetworks (proxies, login apps), else from a well-formed
// X-Trace-ID, else a new one. It is returned in X-Trace-ID on every response.
// A traceparent from elsewhere is ignored, so outsiders cannot steer tracing.
func Trace(parentNetworks []netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inf := infoFrom(r.Context())
			if inf == nil {
				inf = &requestInfo{}
				r = r.WithContext(context.WithValue(r.Context(), infoKey{}, inf))
			}
			if m := traceparent.FindStringSubmatch(r.Header.Get("Traceparent")); m != nil &&
				m[1] != strings.Repeat("0", 32) && contains(parentNetworks, inf.clientIP) {
				inf.traceID = m[1]
			} else if id := r.Header.Get("X-Trace-ID"); xTraceID.MatchString(id) {
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
// for the logs, "unmatched" when none matches. It never records the real path.
func Routes(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inf := infoFrom(r.Context()); inf != nil {
			if _, pattern := mux.Handler(r); pattern != "" {
				inf.route = pattern
			} else {
				inf.route = "unmatched"
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// quietPaths are probes and scrapes, never written to the access log.
var quietPaths = map[string]bool{"/health": true, "/ready": true, "/metrics": true}

// AccessLog writes one line per request. Successful requests are sampled at
// sample (0 to 1), errors always written. The query string, which carries the
// challenges, is never logged; logIP is truncated, full or none.
func AccessLog(logger *slog.Logger, sample float64, logIP string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if quietPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)

			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			if status < 400 && mathrand.Float64() >= sample {
				return
			}
			var traceID, route string
			if inf := infoFrom(r.Context()); inf != nil {
				traceID, route = inf.traceID, inf.route
			}
			attrs := []slog.Attr{
				slog.String("trace_id", traceID),
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.Int64("bytes", sw.bytes),
				slog.String("user_agent", truncate(r.UserAgent(), 256)),
			}
			if ip := formatIP(ClientIP(r.Context()), logIP); ip != "" {
				attrs = append(attrs, slog.String("ip", ip))
			}
			logger.LogAttrs(r.Context(), slog.LevelInfo, "http.request", attrs...)
		})
	}
}

// formatIP applies observability.log_ip: truncated keeps the /24 (IPv4) or
// /48 (IPv6) network.
func formatIP(ip netip.Addr, mode string) string {
	if !ip.IsValid() {
		return ""
	}
	switch mode {
	case "full":
		return ip.String()
	case "none":
		return ""
	}
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// statusWriter records what the handler wrote, for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Recover turns a panic into a 500 carrying the trace id, and logs it with
// its stack. http.ErrAbortHandler keeps its meaning: abort without a log.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				p := recover()
				if p == nil {
					return
				}
				if p == http.ErrAbortHandler {
					panic(p)
				}
				logger.ErrorContext(r.Context(), "http.panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				http.Error(w, "internal error, trace id "+TraceID(r.Context()), http.StatusInternalServerError)
			}()
			next.ServeHTTP(w, r)
		})
	}
}
