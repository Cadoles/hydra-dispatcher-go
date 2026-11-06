package httpx

import (
	"context"
	"log/slog"
	"slices"

	"go.opentelemetry.io/otel/trace"
)

// LogHandler adds the trace id and route of the request to every record
// logged with its context (slog.InfoContext(ctx, ...)), so code outside this
// package never passes them around. They stay at the top level of the line,
// out of the groups of WithGroup, where the collector looks for them. A
// logger or record that already has them (the access log) keeps its own.
//
// A key appears once at the top level: an attribute that repeats one already
// there (time, level, msg, a log_type given by With) is renamed attr_<key>,
// so that no collector takes it for the line's own, nor rejects the line.
func LogHandler(h slog.Handler) slog.Handler { return logHandler{h: h, keys: builtinKeys} }

// builtinKeys are written by the slog handlers themselves.
var builtinKeys = []string{slog.TimeKey, slog.LevelKey, slog.MessageKey, slog.SourceKey}

type logHandler struct {
	h slog.Handler
	// What WithGroup and WithAttrs added from the first group on, applied to
	// each record under the trace id and route instead of being given to h.
	nested []groupOrAttrs
	// The top-level keys of a line before its record's: the built-in ones,
	// then those given to h by WithAttrs. Shared between handlers: appended
	// to only after slices.Clip.
	keys []string
}

type groupOrAttrs struct {
	group string
	attrs []slog.Attr
}

func (h logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.h.Enabled(ctx, level)
}

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs()+2)
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
	attrs, keys := topLevel(attrs, h.keys)
	if inf := infoFrom(ctx); inf != nil {
		if inf.traceID != "" && !slices.Contains(keys, "trace_id") {
			attrs = append(attrs, slog.String("trace_id", inf.traceID))
		}
		if inf.route != "" && !slices.Contains(keys, "route") {
			attrs = append(attrs, slog.String("route", inf.route))
		}
	}
	if sc := trace.SpanContextFromContext(ctx); sc.HasSpanID() && !slices.Contains(keys, "span_id") {
		attrs = append(attrs, slog.String("span_id", sc.SpanID().String()))
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	out.AddAttrs(attrs...)
	return h.h.Handle(ctx, out)
}

// topLevel returns attrs as written at the top level of a line that already
// has keys, and the keys of the line after them. A group without a key is
// flattened, as slog inlines it (a LogValuer is resolved to find out); a key
// already there is renamed attr_<key>.
func topLevel(attrs []slog.Attr, keys []string) ([]slog.Attr, []string) {
	out := make([]slog.Attr, 0, len(attrs))
	keys = slices.Clip(keys)
	var add func(a slog.Attr)
	add = func(a slog.Attr) {
		if a.Key == "" {
			if a.Value = a.Value.Resolve(); a.Value.Kind() == slog.KindGroup {
				for _, g := range a.Value.Group() {
					add(g)
				}
				return
			}
			out = append(out, a) // what slog does of it is its business
			return
		}
		for slices.Contains(keys, a.Key) {
			a.Key = "attr_" + a.Key
		}
		keys = append(keys, a.Key)
		out = append(out, a)
	}
	for _, a := range attrs {
		add(a)
	}
	return out, keys
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(h.nested) > 0 {
		h.nested = append(slices.Clip(h.nested), groupOrAttrs{attrs: attrs})
		return h
	}
	attrs, h.keys = topLevel(attrs, h.keys)
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
