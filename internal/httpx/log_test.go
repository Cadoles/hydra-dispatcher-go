package httpx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogHandler(t *testing.T) {
	const trace = "4bf92f3577b34da6a3ce929d0e0e4736"
	ctx := context.WithValue(context.Background(), infoKey{}, &requestInfo{traceID: trace, route: "GET /x"})
	request := `"trace_id":"` + trace + `","route":"GET /x"`

	tests := []struct {
		name string
		log  func(*slog.Logger)
		want string // the line, without its time
	}{
		{"plain", func(l *slog.Logger) { l.InfoContext(ctx, "e", "a", 1) },
			`{"level":"INFO","msg":"e","a":1,` + request + `}`},
		{"no request", func(l *slog.Logger) { l.InfoContext(context.Background(), "e", "a", 1) },
			`{"level":"INFO","msg":"e","a":1}`},
		// The collector looks for the trace id at the top level, never in a group.
		{"group", func(l *slog.Logger) { l.WithGroup("g").InfoContext(ctx, "e", "a", 1) },
			`{"level":"INFO","msg":"e","g":{"a":1},` + request + `}`},
		{"groups and attributes", func(l *slog.Logger) {
			l.With("top", 0).WithGroup("g").With("b", 2).WithGroup("h").InfoContext(ctx, "e", "a", 1)
		}, `{"level":"INFO","msg":"e","top":0,"g":{"b":2,"h":{"a":1}},` + request + `}`},
		{"empty group", func(l *slog.Logger) { l.WithGroup("g").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e",` + request + `}`},
		{"group without request", func(l *slog.Logger) { l.WithGroup("g").Info("e", "a", 1) },
			`{"level":"INFO","msg":"e","g":{"a":1}}`},
		{"trace id given by With", func(l *slog.Logger) { l.With("trace_id", "mine").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"trace id given by the record", func(l *slog.Logger) { l.InfoContext(ctx, "e", "trace_id", "mine") },
			`{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"trace id in a group is not the line's", func(l *slog.Logger) { l.WithGroup("g").With("trace_id", "mine").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e","g":{"trace_id":"mine"},` + request + `}`},
		// slog inlines a group without a key: its attributes are the line's.
		{"trace id in an inline group", func(l *slog.Logger) {
			l.InfoContext(ctx, "e", slog.Group("", slog.String("trace_id", "mine")))
		}, `{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"route in an inline group given by With", func(l *slog.Logger) {
			l.With(slog.Group("", slog.String("route", "mine"))).InfoContext(ctx, "e")
		}, `{"level":"INFO","msg":"e","route":"mine","trace_id":"` + trace + `"}`},
		// A LogValuer under an empty key that turns into a group is inlined too.
		{"trace id in an inline LogValuer", func(l *slog.Logger) {
			l.InfoContext(ctx, "e", slog.Any("", groupValuer{slog.String("trace_id", "mine")}))
		}, `{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},

		// A key appears once at the top level: a repeated one is renamed, the
		// line's own (built-in, given by With) staying where collectors look.
		{"built-in keys given by the record", func(l *slog.Logger) {
			l.InfoContext(ctx, "e", "time", "12:00", "level", "debug", "msg", "other", "source", "x")
		}, `{"level":"INFO","msg":"e","attr_time":"12:00","attr_level":"debug","attr_msg":"other","attr_source":"x",` + request + `}`},
		{"built-in key given by With", func(l *slog.Logger) { l.With("msg", "other").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e","attr_msg":"other",` + request + `}`},
		{"log_type given by With and the record", func(l *slog.Logger) {
			l.With("log_type", "app").InfoContext(ctx, "e", "log_type", "audit")
		}, `{"level":"INFO","msg":"e","log_type":"app","attr_log_type":"audit",` + request + `}`},
		{"trace id given by With and the record", func(l *slog.Logger) {
			l.With("trace_id", "first").InfoContext(ctx, "e", "trace_id", "second")
		}, `{"level":"INFO","msg":"e","trace_id":"first","attr_trace_id":"second","route":"GET /x"}`},
		{"key repeated in the record", func(l *slog.Logger) { l.InfoContext(ctx, "e", "a", 1, "a", 2, "attr_a", 3) },
			`{"level":"INFO","msg":"e","a":1,"attr_a":2,"attr_attr_a":3,` + request + `}`},
		{"key repeated by an inline group", func(l *slog.Logger) {
			l.With("a", 0).InfoContext(ctx, "e", slog.Group("", slog.Int("a", 1)))
		}, `{"level":"INFO","msg":"e","a":0,"attr_a":1,` + request + `}`},
		// Left to slog as it is, without a key to compare.
		{"empty key", func(l *slog.Logger) { l.InfoContext(ctx, "e", slog.String("", "x")) },
			`{"level":"INFO","msg":"e","":"x",` + request + `}`},
		{"group without a name", func(l *slog.Logger) { l.WithGroup("").InfoContext(ctx, "e", "a", 1) },
			`{"level":"INFO","msg":"e","a":1,` + request + `}`},
		{"group named like a built-in key", func(l *slog.Logger) { l.WithGroup("level").InfoContext(ctx, "e", "a", 1) },
			`{"level":"INFO","msg":"e","attr_level":{"a":1},` + request + `}`},
		{"keys of a group are its own", func(l *slog.Logger) { l.WithGroup("g").InfoContext(ctx, "e", "level", "x", "a", 1) },
			`{"level":"INFO","msg":"e","g":{"level":"x","a":1},` + request + `}`},
		{"siblings keep their keys", func(l *slog.Logger) {
			base := l.With("a", 0)
			base.With("b", 1).InfoContext(ctx, "e")
			base.InfoContext(ctx, "e", "b", 2)
		}, `{"level":"INFO","msg":"e","a":0,"b":1,` + request + `}` + "\n" + `{"level":"INFO","msg":"e","a":0,"b":2,` + request + `}`},
	}
	noTime := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		return a
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tt.log(slog.New(LogHandler(slog.NewJSONHandler(&buf, noTime))))
			if got := strings.TrimSpace(buf.String()); got != tt.want {
				t.Errorf("line = %s\nwant   %s", got, tt.want)
			}
		})
	}
}

type groupValuer []slog.Attr

func (g groupValuer) LogValue() slog.Value { return slog.GroupValue(g...) }
