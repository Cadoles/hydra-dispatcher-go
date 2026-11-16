// Package httpx holds what every HTTP surface of the dispatcher shares: the
// server and its timeouts, the middleware chain (real client IP, trace id,
// access log, panic recovery), the readiness endpoint, and the slog handler
// that stamps each log line with the request's trace id.
package httpx

import (
	"context"
	"net/netip"
)

type infoKey struct{}

// requestInfo is shared by the middlewares of a request through a pointer in
// the context, so values set deeper (the matched route) reach the outer ones.
// Each field is written once, before the handlers that read it run.
type requestInfo struct {
	traceID   string
	clientIP  netip.Addr
	userAgent string
	// acceptLanguage and clientHints are signals of the browser a pre-check
	// of a step may send (phase 4).
	acceptLanguage string
	clientHints    map[string]string
	route          string
	// trustedTrace tells that the client may give the trace: a parent's traceparent.
	trustedTrace bool
}

func infoFrom(ctx context.Context) *requestInfo {
	inf, _ := ctx.Value(infoKey{}).(*requestInfo)
	return inf
}

// WithTraceID returns a context carrying traceID, for work outside an HTTP
// request (background jobs, tests).
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, infoKey{}, &requestInfo{traceID: traceID})
}

// TraceID returns the trace id of the request ctx belongs to, or "".
func TraceID(ctx context.Context) string {
	if inf := infoFrom(ctx); inf != nil {
		return inf.traceID
	}
	return ""
}

// ClientIP returns the real client address of the request ctx belongs to.
func ClientIP(ctx context.Context) netip.Addr {
	if inf := infoFrom(ctx); inf != nil {
		return inf.clientIP
	}
	return netip.Addr{}
}

// TrustedTrace tells whether the client of the request ctx belongs to may give its trace:
// a proxy of server.trusted_proxies, or a login app within its sources.
func TrustedTrace(ctx context.Context) bool {
	if inf := infoFrom(ctx); inf != nil {
		return inf.trustedTrace
	}
	return false
}

// Route returns the route of the request ctx belongs to, once matched: the pattern of
// its mux, unmatched for none, "" before Routes ran.
func Route(ctx context.Context) string {
	if inf := infoFrom(ctx); inf != nil {
		return inf.route
	}
	return ""
}

// UserAgent returns the User-Agent of the request ctx belongs to, or "".
func UserAgent(ctx context.Context) string {
	if inf := infoFrom(ctx); inf != nil {
		return inf.userAgent
	}
	return ""
}

// clientHintHeaders are the client hints a pre-check may send: the brands,
// the platform, mobile or not.
var clientHintHeaders = []string{"Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile"}

// AcceptLanguage returns the Accept-Language of the request ctx belongs to,
// or "".
func AcceptLanguage(ctx context.Context) string {
	if inf := infoFrom(ctx); inf != nil {
		return inf.acceptLanguage
	}
	return ""
}

// ClientHints returns the client hints of the request ctx belongs to, by
// header, nil for none.
func ClientHints(ctx context.Context) map[string]string {
	if inf := infoFrom(ctx); inf != nil {
		return inf.clientHints
	}
	return nil
}
