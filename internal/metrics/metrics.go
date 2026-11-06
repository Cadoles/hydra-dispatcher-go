// Package metrics holds the Prometheus catalogue of the dispatcher, in the memory of
// the instance, read by scrape: incrementing never touches the network, and a scrape
// neither Redis nor the database (doc, Prometheus). Every label is a Go enumeration or a
// value of the configuration, bounded, so that the budget of series holds.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/trace"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const namespace = "hydra_dispatcher"

// The values a label takes outside its enumeration.
const (
	// LabelNone is a flow or an app before the choice.
	LabelNone = "none"
	// LabelOther is a value the configuration does not hold, or over the budget.
	LabelOther = "other"
	// labelUnmatched is the route of a request no route matched.
	labelUnmatched = "unmatched"
)

var (
	// shortBuckets are those of the calls and the requests, durationBuckets those of
	// an authentication.
	shortBuckets    = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 5}
	durationBuckets = []float64{2, 5, 10, 20, 30, 60, 120, 300, 600, 1200, 1800}
)

// Metrics is the catalogue of one instance.
type Metrics struct {
	registry *prometheus.Registry
	log      *slog.Logger

	logins, consents, hydraErrors *prometheus.CounterVec
	flowStarts, stepRequests      *prometheus.CounterVec
	skips, resubmits              *prometheus.CounterVec
	authDuration                  *prometheus.HistogramVec
	hydraRequests                 *prometheus.CounterVec
	hydraDuration                 *prometheus.HistogramVec
	hydraRejected                 *prometheus.CounterVec
	validations                   *prometheus.CounterVec
	stateDuration                 *prometheus.HistogramVec
	stateErrors                   *prometheus.CounterVec
	stateConflicts                prometheus.Counter
	webhookDuration               *prometheus.HistogramVec
	httpRequests                  *prometheus.CounterVec
	httpDuration                  *prometheus.HistogramVec
	httpInFlight                  prometheus.Gauge
	ipRejections                  *prometheus.CounterVec
	configLastRefresh             prometheus.Gauge
	configRefreshErrors           prometheus.Counter
	buildInfo                     *prometheus.GaugeVec
	propagations                  *prometheus.CounterVec

	flows, apps, routes bounded
}

// New registers the catalogue and the Go and process collectors, and at most
// maxLabelValues values for each of the labels flow, app and route; log hears when a
// label goes over.
func New(maxLabelValues int, log *slog.Logger) *Metrics {
	reg := prometheus.NewRegistry()
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help}, labels)
		reg.MustRegister(c)
		return c
	}
	histogram := func(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
		h := prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: namespace, Name: name, Help: help, Buckets: buckets}, labels)
		reg.MustRegister(h)
		return h
	}
	single := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help})
		reg.MustRegister(c)
		return c
	}
	gauge := func(name, help string) prometheus.Gauge {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help})
		reg.MustRegister(g)
		return g
	}
	m := &Metrics{
		registry:            reg,
		log:                 log,
		logins:              counter("login_requests_total", "Login requests, by outcome and flow.", "outcome", "flow"),
		consents:            counter("consent_requests_total", "Consent requests, by outcome and flow.", "outcome", "flow"),
		hydraErrors:         counter("hydra_errors_total", "Calls to Hydra that failed a page, by operation and flow.", "operation", "flow"),
		flowStarts:          counter("flow_starts_total", "Flows started, by flow and trigger.", "flow", "trigger"),
		stepRequests:        counter("step_requests_total", "Traffic of the login apps.", "app", "kind", "outcome"),
		skips:               counter("skip_total", "Skips honoured or not.", "kind", "result"),
		resubmits:           counter("consent_resubmits_total", "Returns on /consent of a flow its consent finished.", "result"),
		authDuration:        histogram("auth_duration_seconds", "From the start of a flow to the login accept at Hydra.", durationBuckets, "outcome"),
		hydraRequests:       counter("hydra_requests_total", "Calls to Hydra's admin API.", "operation", "status_class"),
		hydraDuration:       histogram("hydra_request_duration_seconds", "Latency of the calls to Hydra.", shortBuckets, "operation"),
		hydraRejected:       counter("hydra_rejected_total", "Calls to Hydra refused by back-pressure or past their delay.", "reason"),
		validations:         counter("challenge_validations_total", "Validation of Hydra's challenges.", "mode", "result"),
		stateDuration:       histogram("state_operation_duration_seconds", "Latency of the state store.", shortBuckets, "op"),
		stateErrors:         counter("state_errors_total", "Errors of the state store.", "op"),
		stateConflicts:      single("state_conflicts_total", "Conditional writes replayed."),
		webhookDuration:     histogram("webhook_duration_seconds", "Latency of the webhooks.", shortBuckets, "kind", "outcome"),
		httpRequests:        counter("http_requests_total", "HTTP traffic, by route.", "route", "method", "status_class"),
		httpDuration:        histogram("http_request_duration_seconds", "HTTP latency, by route.", shortBuckets, "route"),
		httpInFlight:        gauge("http_requests_in_flight", "Requests in flight."),
		ipRejections:        counter("ip_filter_rejections_total", "Refusals of the IP filters.", "surface"),
		configLastRefresh:   gauge("config_last_refresh_timestamp_seconds", "Last successful refresh of the configuration."),
		configRefreshErrors: single("config_refresh_errors_total", "Refreshes of the configuration that failed."),
		propagations:        counter("logout_propagations_total", "Propagation of the logout to the login apps.", "app", "result"),
		buildInfo: func() *prometheus.GaugeVec {
			g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: "build_info", Help: "The instance deployed."}, []string{"version", "go_version", "state_backend", "hydra_mode"})
			reg.MustRegister(g)
			return g
		}(),
		flows:  bounded{name: "flow", max: maxLabelValues, log: log},
		apps:   bounded{name: "app", max: maxLabelValues, log: log},
		routes: bounded{name: "route", max: maxLabelValues, log: log},
	}
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// bounded keeps the distinct values of a label under max: past it, the new ones count
// as other, and the log says so once.
type bounded struct {
	name   string
	max    int
	log    *slog.Logger
	seen   sync.Map
	count  atomic.Int64
	warned atomic.Bool
}

func (b *bounded) value(v string) string {
	if _, ok := b.seen.Load(v); ok {
		return v
	}
	if b.count.Add(1) > int64(b.max) {
		b.count.Add(-1)
		if b.warned.CompareAndSwap(false, true) && b.log != nil {
			b.log.Warn("metrics.label_overflow", "label", b.name, "max", b.max)
		}
		return LabelOther
	}
	if _, loaded := b.seen.LoadOrStore(v, true); loaded {
		b.count.Add(-1)
	}
	return v
}

// SetBuild tells what the instance runs.
func (m *Metrics) SetBuild(version, stateBackend, hydraMode string) {
	m.buildInfo.WithLabelValues(version, runtime.Version(), stateBackend, hydraMode).Set(1)
}

// WatchHydraInFlight exposes the calls in flight to Hydra.
func (m *Metrics) WatchHydraInFlight(inFlight func() int) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: namespace, Name: "hydra_in_flight", Help: "Calls to Hydra in flight."},
		func() float64 { return float64(inFlight()) }))
}

// Handler serves the catalogue, in OpenMetrics when the collector asks for it.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

// Filtered is Handler behind security.metrics_authorized_hosts. A refusal is logged and
// counted, the access log keeping silent on a GET of /metrics, and given to refused, nil
// for none: the audit log.
func (m *Metrics) Filtered(hosts []netip.Prefix, logIP string, refused func(context.Context)) http.Handler {
	next := m.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r.Context())
		if !httpx.Within(hosts, ip) {
			m.Refused("metrics")
			if m.log != nil {
				m.log.WarnContext(r.Context(), "security.ip_rejected", "surface", "metrics", "ip", httpx.FormatIP(ip, logIP))
			}
			if refused != nil {
				refused(r.Context())
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Refused counts a refusal of an IP filter on surface: admin, emulated or metrics.
func (m *Metrics) Refused(surface string) { m.ipRejections.WithLabelValues(surface).Inc() }

// SkipUnavailable counts a memory of the skip too big to write (WRT-2).
func (m *Metrics) SkipUnavailable() { m.skips.WithLabelValues("login", "unavailable").Inc() }

// ConfigRefreshed tells of a refresh of the configuration that ended.
func (m *Metrics) ConfigRefreshed(err error) {
	if err != nil {
		m.configRefreshErrors.Inc()
		return
	}
	m.configLastRefresh.SetToCurrentTime()
}

// operation is the name a call has in the catalogue: Symfony's, kept in
// hydra_errors_total, where the client names its reads otherwise.
func operation(op string) string {
	switch op {
	case "get_login_request":
		return "get_login"
	case "get_consent_request":
		return "get_consent"
	case "get_logout_request":
		return "get_logout"
	}
	return op
}

// HydraCall is hydra.Observer.
func (m *Metrics) HydraCall(ctx context.Context, op, statusClass string, elapsed time.Duration) {
	op = operation(op)
	m.hydraRequests.WithLabelValues(op, statusClass).Inc()
	observe(ctx, m.hydraDuration.WithLabelValues(op), elapsed.Seconds())
}

// observe records v, with the trace_id of a request sampled by OpenTelemetry as its
// exemplar: from a peak of latency to a precise trace, at no cost in series.
func observe(ctx context.Context, o prometheus.Observer, v float64) {
	if sc := trace.SpanContextFromContext(ctx); sc.IsSampled() {
		if e, ok := o.(prometheus.ExemplarObserver); ok {
			e.ObserveWithExemplar(v, prometheus.Labels{"trace_id": sc.TraceID().String()})
			return
		}
	}
	o.Observe(v)
}

// HydraRejected is hydra.Observer.
func (m *Metrics) HydraRejected(reason string) { m.hydraRejected.WithLabelValues(reason).Inc() }

var _ hydra.Observer = (*Metrics)(nil)

// States is the state store, its operations timed and its errors counted: not a key
// absent, a conflict (a replay, counted apart) nor a client gone.
func (m *Metrics) States(s state.StateStore) state.StateStore { return &states{StateStore: s, m: m} }

type states struct {
	state.StateStore
	m *Metrics
}

func (s *states) done(ctx context.Context, op string, start time.Time, err error) {
	observe(ctx, s.m.stateDuration.WithLabelValues(op), time.Since(start).Seconds())
	switch {
	case err == nil, errors.Is(err, state.ErrNotFound), errors.Is(err, context.Canceled):
	case errors.Is(err, state.ErrConflict):
		s.m.stateConflicts.Inc()
	default:
		s.m.stateErrors.WithLabelValues(op).Inc()
	}
}

func (s *states) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	start := time.Now()
	val, version, err := s.StateStore.Get(ctx, key)
	s.done(ctx, "get", start, err)
	return val, version, err
}

func (s *states) Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error {
	start := time.Now()
	err := s.StateStore.Put(ctx, key, val, ttl, ifVersion)
	s.done(ctx, "put", start, err)
	return err
}

func (s *states) Delete(ctx context.Context, key string) error {
	start := time.Now()
	err := s.StateStore.Delete(ctx, key)
	s.done(ctx, "delete", start, err)
	return err
}

// Webhooks is w, its calls timed: not those a client gone cancelled, which say nothing
// of the webhook.
func (m *Metrics) Webhooks(w flow.Webhooks) flow.Webhooks { return webhooks{w, m} }

type webhooks struct {
	next flow.Webhooks
	m    *Metrics
}

func (w webhooks) done(ctx context.Context, kind string, start time.Time, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	observe(ctx, w.m.webhookDuration.WithLabelValues(kind, outcome), time.Since(start).Seconds())
}

func (w webhooks) Login(ctx context.Context, call flow.Call) flow.LoginHookAnswer {
	start := time.Now()
	a := w.next.Login(ctx, call)
	w.done(ctx, "login", start, a.Err)
	return a
}

func (w webhooks) Consent(ctx context.Context, call flow.Call) flow.ConsentHookAnswer {
	start := time.Now()
	a := w.next.Consent(ctx, call)
	w.done(ctx, "consent", start, a.Err)
	return a
}

// knownMethods bound the label method: a client chooses what it sends.
var knownMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true}

// HTTP counts the requests by route, the pattern of the mux without its method, never
// the path received; httpx.Routes must run inside it, and RealIP outside.
func (m *Metrics) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()
		rec := &statusWriter{ResponseWriter: w}
		defer func() {
			route := httpx.Route(r.Context())
			if _, pattern, ok := strings.Cut(route, " "); ok {
				route = pattern
			}
			if route == "" {
				route = labelUnmatched
			}
			route = m.routes.value(route)
			method := r.Method
			if !knownMethods[method] {
				method = LabelOther
			}
			m.httpRequests.WithLabelValues(route, method, statusClassOf(rec.status())).Inc()
			observe(r.Context(), m.httpDuration.WithLabelValues(route), time.Since(start).Seconds())
		}()
		next.ServeHTTP(rec, r)
	})
}

func statusClassOf(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	}
	return "1xx"
}

// statusWriter keeps the status of a response, 200 when none was set.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// flowLabel is the flow of an observation: none before the choice, other for a flow the
// configuration no longer holds.
func (m *Metrics) flowLabel(o flow.Observation) string {
	var id string
	for _, f := range []*flow.Flow{o.After, o.Before} {
		if f != nil && f.FlowID != "" {
			id = f.FlowID
			break
		}
	}
	return m.flowValue(o, id)
}

// flowValue is the label of the flow id.
func (m *Metrics) flowValue(o flow.Observation, id string) string {
	if id == "" {
		return LabelNone
	}
	if o.Config != nil {
		if _, ok := flowOf(o.Config, id); !ok {
			return LabelOther
		}
	}
	return m.flows.value(id)
}

func flowOf(s *store.Snapshot, id string) (store.Flow, bool) {
	for _, f := range s.Flows {
		if f.ID == id {
			return f, true
		}
	}
	return store.Flow{}, false
}

// appLabel is an app of the configuration, other otherwise.
func (m *Metrics) appLabel(o flow.Observation, id string) string {
	if id == "" {
		return LabelNone
	}
	if o.Config != nil {
		if _, ok := o.Config.App(id); !ok {
			return LabelOther
		}
	}
	return m.apps.value(id)
}

// currentApp is the app of the current step of f, "" without one.
func currentApp(f *flow.Flow) string {
	if f == nil || f.Current < 1 || f.Current > len(f.Steps) {
		return ""
	}
	return f.Steps[f.Current-1].App
}

// knownTriggers bound the label trigger.
var knownTriggers = map[string]bool{"choice": true, "auto_select": true, "acr": true}

// Observe is flow.Observer: a request's result, as the catalogue counts it.
func (m *Metrics) Observe(ctx context.Context, o flow.Observation) {
	label := m.flowLabel(o)
	consent, login := false, false
	post := false
	switch ev := o.Event.(type) {
	case flow.Entry, flow.Choose, flow.Loop:
		login = true
	case flow.Consent:
		consent, post = true, ev.Post
	}
	code := o.Response.Code
	switch {
	case login && o.Response.Kind == flow.ChoicePage:
		m.logins.WithLabelValues("displayed", label).Inc()
	case login && code == flow.E1001:
		m.logins.WithLabelValues("invalid_challenge", label).Inc()
	case login && code == flow.E1002:
		m.logins.WithLabelValues("session_missing", label).Inc()
	case consent && o.Response.Kind == flow.ConsentPage:
		m.consents.WithLabelValues("displayed", label).Inc()
	case consent && code == flow.E1001:
		m.consents.WithLabelValues("invalid_challenge", label).Inc()
	case consent && code == flow.E1002:
		m.consents.WithLabelValues("session_missing", label).Inc()
	}
	for _, v := range o.Validations {
		m.validations.WithLabelValues(v.Mode, v.Result).Inc()
	}
	for _, r := range o.Reports {
		switch r.Event {
		case "hydra.login_accepted":
			of := label
			if r.Flow != "" {
				of = m.flowValue(o, r.Flow) // a skip's, from the cookie
			}
			m.logins.WithLabelValues("accepted", of).Inc()
			m.authEnded(ctx, o, "accepted")
		case "hydra.consent_accepted":
			outcome := "skip_accepted"
			if post {
				outcome = "accepted"
			}
			of := label
			if r.Flow != "" {
				of = m.flowValue(o, r.Flow) // a consent without a flow, from the cookie
			}
			m.consents.WithLabelValues(outcome, of).Inc()
		case "flow.rejected":
			m.rejected(ctx, o, r, label, consent)
		case "hydra.request_failed":
			m.hydraErrors.WithLabelValues(operation(r.Operation), label).Inc()
		case "flow.started":
			trigger := r.Detail
			if !knownTriggers[trigger] {
				trigger = LabelOther
			}
			m.flowStarts.WithLabelValues(label, trigger).Inc()
		case "step.login_accepted":
			m.stepRequests.WithLabelValues(m.appLabel(o, r.Detail), "login", "accepted").Inc()
		case "step.consent_accepted":
			m.stepRequests.WithLabelValues(m.appLabel(o, r.Detail), "consent", "accepted").Inc()
		case "skip.accepted":
			m.skips.WithLabelValues(r.Kind, "accepted").Inc()
		case "skip.ignored":
			m.skips.WithLabelValues(r.Kind, "ignored").Inc()
		case "consent.resubmitted":
			m.resubmits.WithLabelValues(r.Result).Inc()
		case "security.ip_rejected":
			m.Refused("emulated")
		case "logout.propagated":
			m.propagations.WithLabelValues(m.appLabel(o, r.App), r.Result).Inc()
		}
	}
}

// rejected counts a reject made: of a consent, its outcome; of an app on its step, its
// traffic; of a login not yet accepted, the end of an authentication.
func (m *Metrics) rejected(ctx context.Context, o flow.Observation, r flow.Report, label string, consent bool) {
	reason, _, _ := strings.Cut(r.Detail, ":")
	if consent {
		outcome := "rejected"
		// Symfony's: a consent without the session of a login in progress.
		if reason == flow.ReasonNoRef.String() || reason == flow.ReasonMemory.String() {
			outcome = "session_missing"
		}
		m.consents.WithLabelValues(outcome, label).Inc()
		return
	}
	expired := reason == flow.ReasonExpired.String()
	if call, ok := o.Event.(flow.AppCall); ok && (expired || reason == flow.ReasonApp.String() || reason == flow.ReasonSubject.String()) {
		kind, outcome := "login", "rejected"
		if call.Op.Consent() {
			kind = "consent"
		}
		if expired {
			outcome = "expired"
		}
		m.stepRequests.WithLabelValues(m.appLabel(o, currentApp(o.Before)), kind, outcome).Inc()
	}
	if expired {
		m.authEnded(ctx, o, "expired")
	} else {
		m.authEnded(ctx, o, "rejected")
	}
}

// authEnded observes an authentication that ended, from the start of its flow: not a
// skip, nor a reject of a login already accepted, the consent's.
func (m *Metrics) authEnded(ctx context.Context, o flow.Observation, outcome string) {
	f := o.Before
	if f == nil || f.StartedAt == 0 {
		return
	}
	if outcome != "accepted" && f.HydraRedirect != "" {
		return
	}
	observe(ctx, m.authDuration.WithLabelValues(outcome), o.Now.Sub(time.UnixMilli(f.StartedAt)).Seconds())
}
