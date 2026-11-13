package loglevel

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

// syncBuffer is a buffer the timer of a window writes to beside the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// levelFor returns a level configured at configured, its clock now, the lines
// it lets pass in lines and its notices in notices.
func levelFor(configured slog.Level, now *time.Time) (*Level, *slog.Logger, *bytes.Buffer, *syncBuffer) {
	var lines bytes.Buffer
	notices := &syncBuffer{}
	l := New(configured, slog.New(slog.NewJSONHandler(notices, nil)))
	l.now = func() time.Time { return *now }
	logger := slog.New(l.Handler(slog.NewJSONHandler(&lines, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return l, logger, &lines, notices
}

// The lines below the configured level pass in a window, those of its scope
// alone, until its end.
func TestHandler(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	trace := "4bf92f3577b34da6a3ce929d0e0e4736"
	traced := httpx.WithTraceID(context.Background(), trace)
	other := httpx.WithTraceID(context.Background(), "00f067aa0ba902b700f067aa0ba902b7")
	type line struct {
		name   string
		ctx    context.Context
		level  slog.Level
		logger func(*slog.Logger) *slog.Logger
		args   []any
	}
	lines := []line{
		{name: "info", level: slog.LevelInfo},
		{name: "debug", level: slog.LevelDebug},
		{name: "debug-main", level: slog.LevelDebug, args: []any{"flow", "main"}},
		{name: "debug-other-flow", level: slog.LevelDebug, args: []any{"flow", "other"}},
		{name: "debug-sql", level: slog.LevelDebug, args: []any{"flow", "main", "app", "sql"}},
		{name: "debug-with-main", level: slog.LevelDebug, logger: func(l *slog.Logger) *slog.Logger { return l.With("flow", "main") }},
		{name: "debug-grouped-main", level: slog.LevelDebug, logger: func(l *slog.Logger) *slog.Logger { return l.WithGroup("g").With("flow", "main") }},
		{name: "debug-grouped-attr", level: slog.LevelDebug, logger: func(l *slog.Logger) *slog.Logger { return l.WithGroup("g") }, args: []any{"flow", "main"}},
		{name: "debug-traced", ctx: traced, level: slog.LevelDebug},
		{name: "debug-other-trace", ctx: other, level: slog.LevelDebug},
		{name: "debug-traced-main", ctx: traced, level: slog.LevelDebug, args: []any{"flow", "main"}},
	}
	for _, c := range []struct {
		name       string
		configured slog.Level
		window     *Window
		want       []string
	}{
		{name: "no window", configured: slog.LevelInfo, want: []string{"info"}},
		{name: "every line", configured: slog.LevelInfo, window: &Window{Until: now.Add(time.Minute)},
			want: []string{"info", "debug", "debug-main", "debug-other-flow", "debug-sql", "debug-with-main", "debug-grouped-main", "debug-grouped-attr", "debug-traced", "debug-other-trace", "debug-traced-main"}},
		{name: "ended", configured: slog.LevelInfo, window: &Window{Until: now}, want: []string{"info"}},
		{name: "a flow", configured: slog.LevelInfo, window: &Window{Until: now.Add(time.Minute), Flow: "main"},
			want: []string{"info", "debug-main", "debug-sql", "debug-with-main", "debug-traced-main"}},
		{name: "a flow and an app", configured: slog.LevelInfo, window: &Window{Until: now.Add(time.Minute), Flow: "main", App: "sql"},
			want: []string{"info", "debug-sql"}},
		{name: "a trace", configured: slog.LevelInfo, window: &Window{Until: now.Add(time.Minute), TraceID: trace},
			want: []string{"info", "debug-traced", "debug-traced-main"}},
		{name: "a trace and a flow", configured: slog.LevelInfo, window: &Window{Until: now.Add(time.Minute), TraceID: trace, Flow: "main"},
			want: []string{"info", "debug-traced-main"}},
		{name: "warn, no window", configured: slog.LevelWarn, want: nil},
		// The window lets the info lines of its scope pass too.
		{name: "warn, a window", configured: slog.LevelWarn, window: &Window{Until: now.Add(time.Minute), Flow: "main"},
			want: []string{"debug-main", "debug-sql", "debug-with-main", "debug-traced-main"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			at := now
			l, logger, out, _ := levelFor(c.configured, &at)
			if c.window != nil {
				// Seen before its end, as a snapshot gives it.
				at = c.window.Until.Add(-time.Second)
				l.Set(c.window)
				at = now
			}
			for _, x := range lines {
				ctx := x.ctx
				if ctx == nil {
					ctx = context.Background()
				}
				lg := logger
				if x.logger != nil {
					lg = x.logger(lg)
				}
				lg.Log(ctx, x.level, x.name, x.args...)
			}
			var got []string
			for s := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
				for _, x := range lines {
					if strings.Contains(s, `"msg":"`+x.name+`"`) {
						got = append(got, x.name)
					}
				}
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("passed %q, want %q", got, c.want)
			}
		})
	}
}

// Handle filters by itself, Enabled skipped as a wrapper may skip it, or as a
// window may change between the two.
func TestHandleAlone(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	l, logger, out, _ := levelFor(slog.LevelInfo, &now)
	l.Set(&Window{Until: now.Add(time.Minute), TraceID: "4bf92f3577b34da6a3ce929d0e0e4736"})
	h := logger.Handler()
	for _, c := range []struct {
		ctx  context.Context
		pass bool
	}{
		{httpx.WithTraceID(context.Background(), "00f067aa0ba902b700f067aa0ba902b7"), false},
		{context.Background(), false},
		{httpx.WithTraceID(context.Background(), "4bf92f3577b34da6a3ce929d0e0e4736"), true},
	} {
		out.Reset()
		if err := h.Handle(c.ctx, slog.NewRecord(now, slog.LevelDebug, "line", 0)); err != nil {
			t.Fatal(err)
		}
		if (out.Len() > 0) != c.pass {
			t.Errorf("%s: %q", httpx.TraceID(c.ctx), out)
		}
	}
	l.Set(nil)
	out.Reset()
	_ = h.Handle(httpx.WithTraceID(context.Background(), "4bf92f3577b34da6a3ce929d0e0e4736"), slog.NewRecord(now, slog.LevelDebug, "line", 0))
	if out.Len() > 0 {
		t.Errorf("closed: %q", out)
	}
}

// Each instance tells of a window it sees, and of its end: closed, or past
// its time.
func TestNotices(t *testing.T) {
	now := time.Now()
	l, _, _, notices := levelFor(slog.LevelInfo, &now)
	w := &Window{Until: now.Add(time.Hour), Flow: "main", UpdatedBy: "admin:alice"}
	l.Set(w)
	l.Set(&Window{Until: w.Until, Flow: "main", UpdatedBy: "admin:bob"}) // the same, another snapshot
	if got := notices.String(); strings.Count(got, "log.debug_started") != 1 || !strings.Contains(got, `"scope_flow":"main"`) ||
		strings.Contains(got, "scope_app") || strings.Contains(got, "alice") || !strings.Contains(got, `"until":"`+w.Until.UTC().Format(time.RFC3339)+`"`) {
		t.Fatalf("started: %s", got)
	}
	if l.Window() == nil {
		t.Fatal("no window")
	}
	l.Set(nil)
	if got := notices.String(); !strings.Contains(got, `"msg":"log.debug_ended","reason":"closed"`) || l.Window() != nil {
		t.Fatalf("closed: %s", got)
	}
	l.Set(nil)
	if strings.Count(notices.String(), "log.debug_ended") != 1 {
		t.Errorf("closed twice: %s", notices.String())
	}
	// Past its end, it ends by itself.
	l.now = time.Now
	l.Set(&Window{Until: time.Now().Add(50 * time.Millisecond)})
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(notices.String(), `"reason":"expired"`) {
		if time.Now().After(deadline) {
			t.Fatalf("never expired: %s", notices.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if l.Window() != nil {
		t.Error("expired, still open")
	}
	// A snapshot that still holds it, past its end: nothing more.
	l.Set(&Window{Until: time.Now().Add(-time.Second)})
	if strings.Count(notices.String(), "log.debug_ended") != 2 || strings.Count(notices.String(), "log.debug_started") != 2 {
		t.Errorf("after its end: %s", notices.String())
	}
}
