// Package sentrylog sends to Sentry what demands an action, and only that: the internal
// errors, Hydra, a webhook or the state store failing, a panic, an error in the logs. One
// event by request, grouped by code and operation, so that an outage of Hydra is one
// issue, not thousands. Nothing personal leaves: no subject, claim, challenge, cookie or
// query string (doc, Sentry). Sending is asynchronous: a slow Sentry never slows an
// authentication.
package sentrylog

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getsentry/sentry-go"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
)

const (
	// flushTimeout bounds what the stop of serve waits for, and sendTimeout one send.
	flushTimeout = 2 * time.Second
	sendTimeout  = 2 * time.Second
	// maxBreadcrumbs is the doc's, by event.
	maxBreadcrumbs = 30
	// decryptEvery is how often a failure to decrypt goes: one alert is enough to say a
	// secret is missing.
	decryptEvery = 10 * time.Minute
)

// Options are observability.sentry, and what tags each event.
type Options struct {
	DSN                string
	Environment        string
	Release            string
	SampleRate         float64
	TracesSampleRate   float64
	MaxEventsPerMinute int
	// HydraMode is decrypt or fallback, StateBackend memory or redis.
	HydraMode    string
	StateBackend string
	// Transport replaces the sending, for the tests.
	Transport sentry.Transport
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// Tracker is Sentry for one instance; nil without a DSN, and then does nothing.
type Tracker struct {
	opts   Options
	client *sentry.Client
	hub    *sentry.Hub

	mu     sync.Mutex
	minute time.Time
	sent   int

	lastDecrypt atomic.Int64
}

// New opens Sentry, nil without a DSN.
func New(o Options) (*Tracker, error) {
	if o.DSN == "" {
		return nil, nil
	}
	t := &Tracker{opts: o}
	// SendDefaultPII and DataCollection left at their zero values: no IP, cookie, header
	// or body is collected, and beforeSend checks it.
	options := sentry.ClientOptions{
		Dsn:              o.DSN,
		Environment:      o.Environment,
		Release:          o.Release,
		TracesSampleRate: o.TracesSampleRate,
		MaxBreadcrumbs:   maxBreadcrumbs,
		SampleRate:       o.SampleRate,
		BeforeSend:       t.beforeSend,
		BeforeBreadcrumb: beforeBreadcrumb,
		Transport:        o.Transport,
	}
	if options.Transport == nil {
		transport := sentry.NewHTTPTransport()
		transport.Timeout = sendTimeout
		options.Transport = transport
	}
	client, err := sentry.NewClient(options)
	if err != nil {
		return nil, err
	}
	t.client, t.hub = client, sentry.NewHub(client, sentry.NewScope())
	return t, nil
}

// Flush waits for what is being sent, at most 2 s.
func (t *Tracker) Flush() {
	if t != nil {
		t.client.Flush(flushTimeout)
	}
}

func (t *Tracker) now() time.Time {
	if t.opts.Now != nil {
		return t.opts.Now()
	}
	return time.Now()
}

// allowed applies observability.sentry.max_events_per_minute, and a sample_rate of 0,
// which the SDK would read as its default of 1.
func (t *Tracker) allowed() bool {
	if t.opts.SampleRate == 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().Truncate(time.Minute)
	if !now.Equal(t.minute) {
		t.minute, t.sent = now, 0
	}
	if t.opts.MaxEventsPerMinute > 0 && t.sent >= t.opts.MaxEventsPerMinute {
		return false
	}
	t.sent++
	return true
}

// hubOf is the request's hub, set by Middleware, else the instance's.
func (t *Tracker) hubOf(ctx context.Context) *sentry.Hub {
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		return hub
	}
	return t.hub
}

// Middleware gives each request its hub, whose breadcrumbs are its own, and captures a
// panic before Recover, outside it, answers. It takes neither the URL nor the headers of
// the request, unlike sentryhttp: nothing to scrub, and no trace chosen by a client.
func (t *Tracker) Middleware(next http.Handler) http.Handler {
	if t == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub := t.hub.Clone()
		ctx := sentry.SetHubOnContext(r.Context(), hub)
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p != http.ErrAbortHandler {
				hub.WithScope(func(scope *sentry.Scope) {
					t.tag(ctx, scope, "")
					hub.RecoverWithContext(ctx, p)
				})
			}
			panic(p)
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tag sets what every event carries (doc, Contexte de chaque événement).
func (t *Tracker) tag(ctx context.Context, scope *sentry.Scope, code string) {
	if id := httpx.TraceID(ctx); id != "" {
		scope.SetTag("trace_id", id)
	}
	if route := httpx.Route(ctx); route != "" {
		scope.SetTag("route", route)
	}
	if t.opts.HydraMode != "" {
		scope.SetTag("hydra_mode", t.opts.HydraMode)
	}
	if code != "" {
		scope.SetTag("error_code", code)
	}
}

// send captures one event of level, grouped by fingerprint.
func (t *Tracker) send(ctx context.Context, level sentry.Level, message string, fingerprint []string, tags map[string]string, contexts map[string]sentry.Context) {
	hub := t.hubOf(ctx)
	hub.WithScope(func(scope *sentry.Scope) {
		code := tags["error_code"]
		t.tag(ctx, scope, code)
		for k, v := range tags {
			if v != "" {
				scope.SetTag(k, v)
			}
		}
		event := sentry.NewEvent()
		event.Level, event.Message, event.Fingerprint = level, message, fingerprint
		event.Contexts = contexts
		hub.CaptureEvent(event)
	})
}

// Observe is flow.Observer: at most one event by request, flow.error first, which the
// reports of the request explain (revue R26): a conflict and its E1007 are one issue.
func (t *Tracker) Observe(ctx context.Context, o flow.Observation) {
	if t == nil {
		return
	}
	var main, failed, hook, state, conflict, decrypt *flow.Report
	for i := range o.Reports {
		r := &o.Reports[i]
		switch r.Event {
		case "flow.error":
			main = r
		case "hydra.request_failed":
			if failed == nil {
				failed = r
			}
		case "webhook.failed":
			hook = r
		case "state.error":
			state = r
		case "state.conflict":
			if r.Sentry {
				conflict = r
			}
		case "hydra.decrypt_fallback":
			decrypt = r
		}
	}
	if decrypt != nil {
		t.decryptFailed(ctx, o)
	}
	tags := tagsOf(o)
	contexts := map[string]sentry.Context{}
	if failed != nil {
		contexts["hydra"] = sentry.Context{"operation": failed.Operation, "status": failed.Status}
	}
	if hook != nil {
		contexts["webhook"] = sentry.Context{"kind": hook.Kind, "host": hook.Host, "status": hook.Status, "duration_ms": hook.Elapsed.Milliseconds()}
	}
	switch {
	case main != nil:
		tags["error_code"] = main.Detail
		fingerprint := []string{main.Detail}
		switch {
		case state != nil:
			fingerprint = append(fingerprint, "state", t.opts.StateBackend)
		case main.Detail == string(flow.E1004) && failed != nil:
			fingerprint = append(fingerprint, failed.Operation)
		case main.Detail == string(flow.E1006) && hook != nil:
			fingerprint = append(fingerprint, hook.Kind)
		}
		t.send(ctx, sentry.LevelError, main.Detail, fingerprint, tags, contexts)
	case state != nil:
		// The answer stands without the store (SKP-8, DEP-6, SUI-3): no page says so.
		t.send(ctx, sentry.LevelError, state.Event, []string{"state", t.opts.StateBackend}, tags, contexts)
	case conflict != nil:
		// A fact of Hydra on a finished flow (ECR-9), whose page may be a redirection.
		t.send(ctx, sentry.LevelError, conflict.Event, []string{conflict.Event}, tags, contexts)
	}
}

// decryptFailed sends a failure to decrypt, at most once by interval.
func (t *Tracker) decryptFailed(ctx context.Context, o flow.Observation) {
	now := t.now().Unix()
	last := t.lastDecrypt.Load()
	if last != 0 && now-last < int64(decryptEvery/time.Second) {
		return
	}
	if !t.lastDecrypt.CompareAndSwap(last, now) {
		return
	}
	t.send(ctx, sentry.LevelWarning, "hydra.decrypt_fallback", []string{"hydra.decrypt_fallback"}, tagsOf(o), nil)
}

// tagsOf are the tags of the flow: its id, the app of its step, the surface.
func tagsOf(o flow.Observation) map[string]string {
	tags := map[string]string{"surface": o.Surface}
	for _, f := range []*flow.Flow{o.After, o.Before} {
		if f == nil {
			continue
		}
		if tags["flow"] == "" {
			tags["flow"] = f.FlowID
		}
		if tags["step"] == "" && f.Current >= 1 && f.Current <= len(f.Steps) {
			tags["step"] = f.Steps[f.Current-1].App
		}
	}
	return tags
}

// observed are the error lines of the log that Observe or Middleware send already, or
// that flow.error accompanies (Q61, Q64).
var observed = []string{"flow.error", "state.error", "state.conflict", "hydra.request_failed", "webhook.failed", "http.panic"}

// breadcrumbAttrs are what a line of the log gives its breadcrumb: closed names, whose
// values name no one; never its detail, a free text.
var breadcrumbAttrs = []string{"surface", "kind", "reason", "result", "app", "operation", "status", "duration_ms", "host", "rp_initiated", "apps"}

// Handler bridges a log to Sentry: an error line is an event, by its name alone, the
// details staying in the log; info and warn lines the breadcrumbs of their request.
func (t *Tracker) Handler(next slog.Handler) slog.Handler {
	if t == nil {
		return next
	}
	return bridge{next, t}
}

type bridge struct {
	next slog.Handler
	t    *Tracker
}

func (b bridge) Enabled(ctx context.Context, l slog.Level) bool { return b.next.Enabled(ctx, l) }

func (b bridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	return bridge{b.next.WithAttrs(attrs), b.t}
}

func (b bridge) WithGroup(name string) slog.Handler {
	return bridge{b.next.WithGroup(name), b.t}
}

func (b bridge) Handle(ctx context.Context, r slog.Record) error {
	err := b.next.Handle(ctx, r)
	switch {
	case r.Level >= slog.LevelError:
		if !slices.Contains(observed, r.Message) {
			b.t.send(ctx, sentry.LevelError, r.Message, []string{r.Message}, nil, nil)
		}
	case r.Level >= slog.LevelInfo:
		hub := sentry.GetHubFromContext(ctx)
		if hub == nil {
			break // no request: no event for it to explain
		}
		level := sentry.LevelInfo
		if r.Level >= slog.LevelWarn {
			level = sentry.LevelWarning
		}
		data := map[string]any{}
		r.Attrs(func(a slog.Attr) bool {
			if slices.Contains(breadcrumbAttrs, a.Key) {
				data[a.Key] = a.Value.Any()
			}
			return true
		})
		hub.AddBreadcrumb(&sentry.Breadcrumb{Category: "log", Message: r.Message, Level: level, Data: data, Timestamp: r.Time}, nil)
	}
	return err
}

// forbidden are the names of what never leaves, wherever the SDK or a future field puts
// them.
var forbidden = []string{"subject", "context", "claims", "id_token", "access_token", "secret", "password", "token"}

// query finds a query string in a text: it may hold a challenge.
var query = regexp.MustCompile(`\?\S*`)

func scrubMap[V any](m map[string]V) {
	for _, name := range forbidden {
		delete(m, name)
	}
}

// beforeSend is the last check of an event, whatever built it, and the plafond.
func (t *Tracker) beforeSend(e *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if !t.allowed() {
		return nil
	}
	e.User = sentry.User{}
	e.Request = nil
	e.Message = query.ReplaceAllString(e.Message, "")
	for i := range e.Exception {
		e.Exception[i].Value = query.ReplaceAllString(e.Exception[i].Value, "")
	}
	scrubMap(e.Tags)
	scrubMap(e.Contexts)
	for _, c := range e.Contexts {
		scrubMap(c)
	}
	for _, b := range e.Breadcrumbs {
		scrubBreadcrumb(b)
	}
	return e
}

func beforeBreadcrumb(b *sentry.Breadcrumb, _ *sentry.BreadcrumbHint) *sentry.Breadcrumb {
	scrubBreadcrumb(b)
	return b
}

func scrubBreadcrumb(b *sentry.Breadcrumb) {
	b.Message = query.ReplaceAllString(b.Message, "")
	scrubMap(b.Data)
	for k, v := range b.Data {
		if s, ok := v.(string); ok {
			b.Data[k] = query.ReplaceAllString(s, "")
		}
	}
}
