package httpx

import (
	"context"
	"log/slog"
	"slices"
)

// LogHandler adds the trace id and route of the request to every record
// logged with its context (slog.InfoContext(ctx, ...)), so code outside this
// package never passes them around. They stay at the top level of the line,
// out of the groups of WithGroup, where the collector looks for them. A
// logger or record that already has them (the access log) keeps its own.
func LogHandler(h slog.Handler) slog.Handler { return logHandler{h: h} }

type logHandler struct {
	h slog.Handler
	// What WithGroup and WithAttrs added from the first group on, applied to
	// each record under the trace id and route instead of being given to h.
	nested             []groupOrAttrs
	hasTrace, hasRoute bool // given to h by WithAttrs
}

type groupOrAttrs struct {
	group string
	attrs []slog.Attr
}

func (h logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.h.Enabled(ctx, level)
}

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	inf := infoFrom(ctx)
	if len(h.nested) == 0 {
		if inf != nil {
			hasTrace, hasRoute := h.hasTrace, h.hasRoute
			r.Attrs(func(a slog.Attr) bool {
				trace, route := requestKeys(a)
				hasTrace, hasRoute = hasTrace || trace, hasRoute || route
				return true
			})
			addRequestAttrs(&r, inf, hasTrace, hasRoute)
		}
		return h.h.Handle(ctx, r)
	}
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	for _, n := range slices.Backward(h.nested) {
		if n.group != "" {
			attrs = []slog.Attr{{Key: n.group, Value: slog.GroupValue(attrs...)}}
		} else {
			attrs = append(slices.Clip(n.attrs), attrs...)
		}
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if inf != nil {
		addRequestAttrs(&out, inf, h.hasTrace, h.hasRoute)
	}
	out.AddAttrs(attrs...)
	return h.h.Handle(ctx, out)
}

// requestKeys reports whether a sets the trace id or the route at the level
// it is logged at: by its key, or inside a group without a key, which slog
// inlines.
func requestKeys(a slog.Attr) (trace, route bool) {
	if a.Key == "" && a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			t, r := requestKeys(g)
			trace, route = trace || t, route || r
		}
		return trace, route
	}
	return a.Key == "trace_id", a.Key == "route"
}

func addRequestAttrs(r *slog.Record, inf *requestInfo, hasTrace, hasRoute bool) {
	if inf.traceID != "" && !hasTrace {
		r.AddAttrs(slog.String("trace_id", inf.traceID))
	}
	if inf.route != "" && !hasRoute {
		r.AddAttrs(slog.String("route", inf.route))
	}
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(h.nested) > 0 {
		h.nested = append(slices.Clip(h.nested), groupOrAttrs{attrs: attrs})
		return h
	}
	for _, a := range attrs {
		trace, route := requestKeys(a)
		h.hasTrace, h.hasRoute = h.hasTrace || trace, h.hasRoute || route
	}
	h.h = h.h.WithAttrs(attrs)
	return h
}

func (h logHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h.nested = append(slices.Clip(h.nested), groupOrAttrs{group: name})
	return h
}
