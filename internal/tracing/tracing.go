// Package tracing holds the OpenTelemetry of the dispatcher: an authentication followed
// from the client OIDC to Hydra, the dispatcher and the webhooks, in any tool that reads
// OTLP. The instrumentation is always compiled, and costs almost nothing while the export
// is off. Its spans are written here rather than by otelhttp, which records the URL of a
// request, its challenge in the query string; redisotel the keys and the values of the
// flows. No subject, claim, challenge, cookie or query string in an attribute (doc,
// OpenTelemetry).
package tracing

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	sentryotlp "github.com/getsentry/sentry-go/otel/otlp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/state"
)

const (
	tracerName = "forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/tracing"
	// shutdownTimeout is what the stop of serve gives the exporters.
	shutdownTimeout = 2 * time.Second
)

func tracer() trace.Tracer { return otel.Tracer(tracerName) }

// Options are observability.tracing, with what names the instance, and the part of
// Sentry: with SentryRatio above 0, its spans go there too.
type Options struct {
	Enabled      bool
	Endpoint     string
	Protocol     string
	SamplerRatio float64
	Version      string
	Environment  string
	Instance     string
	SentryDSN    string
	SentryRatio  float64
}

// Setup installs the exporters, the sampler and the W3C propagation, and returns what
// stops them. Nothing asks for traces: nothing is installed, the spans are empty
// operations and no traceparent leaves. OTEL_* variables win over the options, as the
// doc says.
func Setup(ctx context.Context, o Options) (func(), error) {
	wantsSentry := o.SentryDSN != "" && o.SentryRatio > 0
	if !o.Enabled && !wantsSentry {
		return func() {}, nil
	}
	providerOptions := []sdktrace.TracerProviderOption{sdktrace.WithIDGenerator(ids{})}
	if o.Enabled {
		exporter, err := newExporter(ctx, o)
		if err != nil {
			return nil, fmt.Errorf("observability.tracing: %w", err)
		}
		providerOptions = append(providerOptions, sdktrace.WithBatcher(exporter))
	}
	ratio := 0.0
	if o.Enabled {
		ratio = o.SamplerRatio
	}
	if wantsSentry {
		exporter, err := sentryotlp.NewTraceExporter(ctx, o.SentryDSN)
		if err != nil {
			return nil, fmt.Errorf("observability.sentry: %w", err)
		}
		providerOptions = append(providerOptions, sdktrace.WithBatcher(exporter))
		// One sampler for the provider: the higher of the two asked for.
		ratio = max(ratio, o.SentryRatio)
	}
	if os.Getenv("OTEL_TRACES_SAMPLER") == "" {
		providerOptions = append(providerOptions, sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))))
	}
	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", "hydra-dispatcher"),
		attribute.String("service.version", o.Version),
		attribute.String("deployment.environment", o.Environment),
		attribute.String("service.instance.id", o.Instance),
	), resource.WithFromEnv(), resource.WithTelemetrySDK())
	if err != nil && !errors.Is(err, resource.ErrPartialResource) && !errors.Is(err, resource.ErrSchemaURLConflict) {
		return nil, fmt.Errorf("observability.tracing: %w", err)
	}
	provider := sdktrace.NewTracerProvider(append(providerOptions, sdktrace.WithResource(res))...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = provider.Shutdown(ctx)
	}, nil
}

// newExporter is the OTLP exporter of the protocol, batched and asynchronous by the SDK:
// its queue is bounded, and spans are dropped rather than slow a request. An endpoint in
// the environment wins.
func newExporter(ctx context.Context, o Options) (sdktrace.SpanExporter, error) {
	endpoint := o.Endpoint
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" {
		endpoint = ""
	}
	protocol := o.Protocol
	for _, name := range []string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL"} {
		if v := os.Getenv(name); v != "" {
			protocol = v
			break
		}
	}
	if protocol == "http/protobuf" {
		var options []otlptracehttp.Option
		if endpoint != "" {
			options = append(options, otlptracehttp.WithEndpointURL(endpoint))
		}
		return otlptracehttp.New(ctx, options...)
	}
	var options []otlptracegrpc.Option
	if endpoint != "" {
		options = append(options, otlptracegrpc.WithEndpointURL(endpoint))
	}
	return otlptracegrpc.New(ctx, options...)
}

// ids draws the ids of the spans, a new trace taking the trace_id the logs and the error
// page already give the request (httpx.Trace): a client given its trace id finds its trace.
type ids struct{}

// IDs is that generator, for a provider a test installs.
func IDs() sdktrace.IDGenerator { return ids{} }

func (ids) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	var t trace.TraceID
	if parsed, err := trace.TraceIDFromHex(httpx.TraceID(ctx)); err == nil {
		t = parsed
	} else {
		_, _ = rand.Read(t[:])
	}
	return t, ids{}.NewSpanID(ctx, t)
}

func (ids) NewSpanID(context.Context, trace.TraceID) trace.SpanID {
	var s trace.SpanID
	_, _ = rand.Read(s[:])
	return s
}

// knownMethods bound the name of a span: a client chooses what it sends.
var knownMethods = map[string]bool{http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true}

// HTTP makes a span of each request, named by its route once matched, never the path
// received. Must run after httpx.TraceFrom, and httpx.Routes inside it. A traceparent is
// its parent from a trusted client alone; from any other, the trace starts over, and what
// it said is only a link: it cannot impose the sampling.
func HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		method := r.Method
		if !knownMethods[method] {
			method = "OTHER"
		}
		carrier := propagation.HeaderCarrier(r.Header)
		options := []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindServer)}
		if httpx.TrustedTrace(ctx) {
			ctx = otel.GetTextMapPropagator().Extract(ctx, carrier)
		} else if sc := trace.SpanContextFromContext(otel.GetTextMapPropagator().Extract(context.Background(), carrier)); sc.IsValid() {
			options = append(options, trace.WithLinks(trace.Link{SpanContext: sc}))
		}
		ctx, span := tracer().Start(ctx, "HTTP "+method, options...)
		defer span.End()
		if !span.IsRecording() {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		span.SetAttributes(attribute.String("http.request.method", method))
		rec := &statusWriter{ResponseWriter: w}
		defer func() {
			route := httpx.Route(ctx)
			if _, pattern, ok := strings.Cut(route, " "); ok {
				route = pattern
			}
			if route == "" {
				route = "unmatched"
			}
			span.SetName(method + " " + route)
			span.SetAttributes(attribute.String("http.route", route), attribute.Int("http.response.status_code", rec.status()))
			if rec.status() >= 500 {
				span.SetStatus(codes.Error, "")
			}
		}()
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}

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

// Observer tells the span of a request what it decided: the flow, its step, the error
// page, and the events of its reports, by name and closed fields; and links it to the
// span that created the flow, which gathers a whole authentication though the browser's
// redirections carry no header. HydraMode is decrypt or fallback.
type Observer struct{ HydraMode string }

// detailed are the events whose detail is a closed value: others hold a free text.
var detailed = map[string]bool{"flow.started": true, "flow.rejected": true, "challenge.invalid": true, "flow.error": true}

// Observe is flow.Observer.
func (t Observer) Observe(ctx context.Context, o flow.Observation) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("dispatcher.surface", o.Surface), attribute.String("dispatcher.hydra_mode", t.HydraMode)}
	if id := flowOf(o); id != "" {
		attrs = append(attrs, attribute.String("dispatcher.flow", id))
	}
	if app := stepOf(o); app != "" {
		attrs = append(attrs, attribute.String("dispatcher.step", app))
	}
	if code := o.Response.Code; code != "" {
		attrs = append(attrs, attribute.String("dispatcher.error_code", string(code)))
	}
	span.SetAttributes(attrs...)
	for _, r := range o.Reports {
		var fields []attribute.KeyValue
		if detailed[r.Event] {
			fields = append(fields, attribute.String("detail", r.Detail))
		}
		if r.Kind != "" {
			fields = append(fields, attribute.String("kind", r.Kind))
		}
		if r.Result != "" {
			fields = append(fields, attribute.String("result", r.Result))
		}
		if r.Operation != "" {
			fields = append(fields, attribute.String("operation", r.Operation))
		}
		span.AddEvent(r.Event, trace.WithAttributes(fields...))
	}
	if o.Before != nil {
		if sc, ok := parseOrigin(o.Before.Trace); ok && sc.TraceID() != span.SpanContext().TraceID() {
			span.AddLink(trace.Link{SpanContext: sc, Attributes: []attribute.KeyValue{attribute.String("dispatcher.link", "flow.start")}})
		}
	}
}

func flowOf(o flow.Observation) string {
	for _, f := range []*flow.Flow{o.After, o.Before} {
		if f != nil && f.FlowID != "" {
			return f.FlowID
		}
	}
	return ""
}

func stepOf(o flow.Observation) string {
	for _, f := range []*flow.Flow{o.Before, o.After} {
		if f != nil && f.Current >= 1 && f.Current <= len(f.Steps) {
			return f.Steps[f.Current-1].App
		}
	}
	return ""
}

// parseOrigin reads a Flow.Trace: "<trace id>-<span id>".
func parseOrigin(origin string) (trace.SpanContext, bool) {
	traceHex, spanHex, ok := strings.Cut(origin, "-")
	if !ok {
		return trace.SpanContext{}, false
	}
	t, err := trace.TraceIDFromHex(traceHex)
	if err != nil {
		return trace.SpanContext{}, false
	}
	s, err := trace.SpanIDFromHex(spanHex)
	if err != nil {
		return trace.SpanContext{}, false
	}
	return trace.NewSpanContext(trace.SpanContextConfig{TraceID: t, SpanID: s, Remote: true}), true
}

// States is s, a span by operation: never its key nor its value.
func States(s state.StateStore, backend string) state.StateStore {
	return &states{StateStore: s, backend: backend}
}

type states struct {
	state.StateStore
	backend string
}

func (s *states) start(ctx context.Context, op string) (context.Context, trace.Span) {
	return tracer().Start(ctx, "state."+op, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("db.system.name", s.backend), attribute.String("db.operation.name", op)))
}

func failed(span trace.Span, err error) {
	if err != nil && !errors.Is(err, state.ErrNotFound) && !errors.Is(err, state.ErrConflict) {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

func (s *states) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	ctx, span := s.start(ctx, "get")
	val, version, err := s.StateStore.Get(ctx, key)
	failed(span, err)
	return val, version, err
}

func (s *states) Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error {
	ctx, span := s.start(ctx, "put")
	err := s.StateStore.Put(ctx, key, val, ttl, ifVersion)
	failed(span, err)
	return err
}

func (s *states) Delete(ctx context.Context, key string) error {
	ctx, span := s.start(ctx, "delete")
	err := s.StateStore.Delete(ctx, key)
	failed(span, err)
	return err
}
