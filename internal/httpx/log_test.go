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
			`{"level":"INFO","msg":"e",` + request + `,"g":{"a":1}}`},
		{"groups and attributes", func(l *slog.Logger) {
			l.With("top", 0).WithGroup("g").With("b", 2).WithGroup("h").InfoContext(ctx, "e", "a", 1)
		}, `{"level":"INFO","msg":"e","top":0,` + request + `,"g":{"b":2,"h":{"a":1}}}`},
		{"empty group", func(l *slog.Logger) { l.WithGroup("g").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e",` + request + `}`},
		{"group without request", func(l *slog.Logger) { l.WithGroup("g").Info("e", "a", 1) },
			`{"level":"INFO","msg":"e","g":{"a":1}}`},
		{"trace id given by With", func(l *slog.Logger) { l.With("trace_id", "mine").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"trace id given by the record", func(l *slog.Logger) { l.InfoContext(ctx, "e", "trace_id", "mine") },
			`{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"trace id in a group is not the line's", func(l *slog.Logger) { l.WithGroup("g").With("trace_id", "mine").InfoContext(ctx, "e") },
			`{"level":"INFO","msg":"e",` + request + `,"g":{"trace_id":"mine"}}`},
		// slog inlines a group without a key: its attributes are the line's.
		{"trace id in an inline group", func(l *slog.Logger) {
			l.InfoContext(ctx, "e", slog.Group("", slog.String("trace_id", "mine")))
		}, `{"level":"INFO","msg":"e","trace_id":"mine","route":"GET /x"}`},
		{"route in an inline group given by With", func(l *slog.Logger) {
			l.With(slog.Group("", slog.String("route", "mine"))).InfoContext(ctx, "e")
		}, `{"level":"INFO","msg":"e","route":"mine","trace_id":"` + trace + `"}`},
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
