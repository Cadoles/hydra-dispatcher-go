// Package loglevel is the level of the application log: the configured one,
// observability.log_level, and the window of debug of the configuration (P25,
// Q131), during which the lines below that level pass too, those in its scope.
package loglevel

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
)

// Window is a window of debug.
type Window = domain.DebugWindow

// Level is the level of the application log of an instance.
type Level struct {
	configured slog.Level
	// notices writes log.debug_started and log.debug_ended whatever the
	// level, as config.warning.
	notices *slog.Logger
	now     func() time.Time
	// window is the window open, nil for none: read by every line below the
	// configured level.
	window atomic.Pointer[Window]

	// mu orders Set and the end of a window.
	mu    sync.Mutex
	timer *time.Timer
}

// New returns the level configured, without a window; notices, nil for none,
// tells of the windows.
func New(configured slog.Level, notices *slog.Logger) *Level {
	return &Level{configured: configured, notices: notices, now: time.Now}
}

// Configured is observability.log_level.
func (l *Level) Configured() slog.Level { return l.configured }

// Window is the window open now, nil for none.
func (l *Level) Window() *Window {
	if w := l.window.Load(); w.Open(l.now()) {
		return w
	}
	return nil
}

// Set gives the window of the configuration, nil for none: at each snapshot.
// A window past its end is none.
func (l *Level) Set(w *Window) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !w.Open(now) {
		w = nil
	}
	old := l.window.Load()
	if same(old, w) {
		return
	}
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	l.window.Store(w)
	switch {
	case w != nil:
		// Its scope apart from the flow and the app of a line: this line is
		// of none.
		args := []any{"until", w.Until.UTC().Format(time.RFC3339)}
		for _, f := range []struct{ key, value string }{{"scope_flow", w.Flow}, {"scope_app", w.App}, {"scope_trace_id", w.TraceID}} {
			if f.value != "" {
				args = append(args, f.key, f.value)
			}
		}
		l.notice("log.debug_started", args...)
		l.timer = time.AfterFunc(w.Until.Sub(now), func() { l.end(w) })
	case old.Open(now):
		l.notice("log.debug_ended", "reason", "closed")
	default:
		l.notice("log.debug_ended", "reason", "expired")
	}
}

// end ends w, still open past its end.
func (l *Level) end(w *Window) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.window.Load() != w {
		return
	}
	l.window.Store(nil)
	l.timer = nil
	l.notice("log.debug_ended", "reason", "expired")
}

func (l *Level) notice(msg string, args ...any) {
	if l.notices != nil {
		l.notices.Info(msg, args...)
	}
}

// same tells whether a and b are the same window, by their fields.
func same(a, b *Window) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Until.Equal(b.Until) && a.Flow == b.Flow && a.App == b.App && a.TraceID == b.TraceID
}

// scopeKey carries the flow and the app of a request in its context.
type scopeKey struct{}

type scope struct{ flow, app string }

// WithScope returns ctx carrying the flow and the app its request is about:
// a window in their scope lets its lines pass, and the lines of debug of the
// calls it makes name them (Q132).
func WithScope(ctx context.Context, flow, app string) context.Context {
	return context.WithValue(ctx, scopeKey{}, scope{flow, app})
}

// Scope gives the flow and the app ctx carries, "" for none.
func Scope(ctx context.Context) (flow, app string) {
	s, _ := ctx.Value(scopeKey{}).(scope)
	return s.flow, s.app
}

// ScopeAttrs are the flow and the app ctx carries, as the attributes of a
// line: those it has.
func ScopeAttrs(ctx context.Context) []any {
	flow, app := Scope(ctx)
	var attrs []any
	if flow != "" {
		attrs = append(attrs, "flow", flow)
	}
	if app != "" {
		attrs = append(attrs, "app", app)
	}
	return attrs
}

// Handler is h, which takes every level, filtered: a line at the configured
// level or above passes; one below it only while a window is open, and in
// its scope.
func (l *Level) Handler(h slog.Handler) slog.Handler { return handler{l: l, h: h} }

type handler struct {
	l *Level
	h slog.Handler
	// flow and app are those the logger was given (With), top level.
	flow, app string
	// grouped: the attributes given after are in a group, none at the top.
	grouped bool
}

func (h handler) Enabled(ctx context.Context, level slog.Level) bool {
	if level >= h.l.configured {
		return h.h.Enabled(ctx, level)
	}
	w := h.l.window.Load()
	if !w.Open(h.l.now()) || w.TraceID != "" && httpx.TraceID(ctx) != w.TraceID {
		return false
	}
	return h.h.Enabled(ctx, level)
}

func (h handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.l.configured {
		return h.h.Handle(ctx, r)
	}
	w := h.l.window.Load()
	if !w.Open(h.l.now()) || !h.within(ctx, r, w) {
		return nil
	}
	return h.h.Handle(ctx, r)
}

// within tells whether the line r is in the scope of w: each field of the
// scope held by the line, its attributes (those of the logger, then its own)
// or its request's.
func (h handler) within(ctx context.Context, r slog.Record, w *Window) bool {
	if w.TraceID != "" && httpx.TraceID(ctx) != w.TraceID {
		return false
	}
	if w.Flow == "" && w.App == "" {
		return true
	}
	flow, app := Scope(ctx)
	if h.flow != "" {
		flow = h.flow
	}
	if h.app != "" {
		app = h.app
	}
	if !h.grouped {
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "flow":
				flow = a.Value.String()
			case "app":
				app = a.Value.String()
			}
			return true
		})
	}
	return (w.Flow == "" || flow == w.Flow) && (w.App == "" || app == w.App)
}

func (h handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if !h.grouped {
		for _, a := range attrs {
			switch a.Key {
			case "flow":
				h.flow = a.Value.String()
			case "app":
				h.app = a.Value.String()
			}
		}
	}
	h.h = h.h.WithAttrs(attrs)
	return h
}

func (h handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h.grouped = true
	h.h = h.h.WithGroup(name)
	return h
}
