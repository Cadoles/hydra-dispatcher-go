package httpx

import (
	"context"
	"log/slog"
)

// LogHandler adds the trace id and route of the request to every record
// logged with its context (slog.InfoContext(ctx, ...)), so code outside this
// package never passes them around. A record that already has them (the
// access log) keeps its own.
func LogHandler(h slog.Handler) slog.Handler { return logHandler{h} }

type logHandler struct{ slog.Handler }

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	if inf := infoFrom(ctx); inf != nil {
		hasTrace, hasRoute := false, false
		r.Attrs(func(a slog.Attr) bool {
			hasTrace = hasTrace || a.Key == "trace_id"
			hasRoute = hasRoute || a.Key == "route"
			return true
		})
		if inf.traceID != "" && !hasTrace {
			r.AddAttrs(slog.String("trace_id", inf.traceID))
		}
		if inf.route != "" && !hasRoute {
			r.AddAttrs(slog.String("route", inf.route))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return logHandler{h.Handler.WithAttrs(attrs)}
}

func (h logHandler) WithGroup(name string) slog.Handler {
	return logHandler{h.Handler.WithGroup(name)}
}
