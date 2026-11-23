package tracing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/state"
)

// recording installs a provider that keeps its spans, and its sampler.
func recording(t *testing.T, sampler sdktrace.Sampler) *tracetest.InMemoryExporter {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sampler), sdktrace.WithIDGenerator(ids{}))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
		_ = provider.Shutdown(context.Background())
	})
	return exporter
}

const (
	trustedAddr   = "10.0.0.1:1000"
	untrustedAddr = "203.0.113.9:1000"
	parentTrace   = "4bf92f3577b34da6a3ce929d0e0e4736"
	parentSpan    = "00f067aa0ba902b7"
)

// served plays one request from remote through the chain, returning the response.
func served(t *testing.T, remote string, header map[string]string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var traceID string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		traceID = trace.SpanContextFromContext(r.Context()).TraceID().String()
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(trusted), HTTP)
	target := "/oauth2/auth?login_challenge=sentinel-challenge"
	if header["path"] != "" {
		target = header["path"]
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	for k, v := range header {
		if k != "path" {
			r.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, traceID
}

func attrs(s tracetest.SpanStub) map[string]string {
	out := map[string]string{}
	for _, kv := range s.Attributes {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// A span by request, named by its route, the trace_id of the logs and the response; the
// URL received is nowhere.
func TestHTTPSpan(t *testing.T) {
	exporter := recording(t, sdktrace.AlwaysSample())
	rec, id := served(t, untrustedAddr, nil)
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("%d spans", len(spans))
	}
	s := spans[0]
	if s.Name != "GET /oauth2/auth" || s.SpanKind != trace.SpanKindServer {
		t.Errorf("span %s, kind %v", s.Name, s.SpanKind)
	}
	a := attrs(s)
	if a["http.route"] != "/oauth2/auth" || a["http.request.method"] != "GET" || a["http.response.status_code"] != "303" {
		t.Errorf("attributes %v", a)
	}
	if got := rec.Header().Get("X-Trace-ID"); got != id || got != s.SpanContext.TraceID().String() {
		t.Errorf("X-Trace-ID %s, span %s, context %s", got, s.SpanContext.TraceID(), id)
	}
	data, _ := json.Marshal(s.Attributes)
	if strings.Contains(string(data), "sentinel-challenge") || strings.Contains(s.Name, "sentinel") {
		t.Errorf("the query string in the span: %s %s", s.Name, data)
	}
}

// A status of the server marks the span; a path no route matches is unmatched.
func TestHTTPSpanStatus(t *testing.T) {
	exporter := recording(t, sdktrace.AlwaysSample())
	served(t, untrustedAddr, map[string]string{"path": "/boom"})
	served(t, untrustedAddr, map[string]string{"path": "/secret-path-of-the-client"})
	spans := exporter.GetSpans()
	if spans[0].Status.Code.String() != "Error" {
		t.Errorf("status %v", spans[0].Status)
	}
	if spans[1].Name != "GET unmatched" {
		t.Errorf("name %s", spans[1].Name)
	}
}

// A traceparent from a parent of confidence: the trace goes on, its sampling respected.
// From Internet: a new trace, and the id received only a link: a client neither imposes
// the sampling nor chooses the id of the logs (doc, Propagation).
func TestParent(t *testing.T) {
	header := func(flags string) map[string]string {
		return map[string]string{"Traceparent": "00-" + parentTrace + "-" + parentSpan + "-" + flags}
	}
	t.Run("trusted", func(t *testing.T) {
		exporter := recording(t, sdktrace.ParentBased(sdktrace.NeverSample()))
		rec, _ := served(t, trustedAddr, header("01"))
		spans := exporter.GetSpans()
		if len(spans) != 1 {
			t.Fatalf("the parent's sampling not respected: %d spans", len(spans))
		}
		if spans[0].SpanContext.TraceID().String() != parentTrace || spans[0].Parent.SpanID().String() != parentSpan || rec.Header().Get("X-Trace-ID") != parentTrace {
			t.Errorf("span %+v", spans[0].SpanContext)
		}
	})
	t.Run("trusted, not sampled", func(t *testing.T) {
		exporter := recording(t, sdktrace.ParentBased(sdktrace.AlwaysSample()))
		served(t, trustedAddr, header("00"))
		if n := len(exporter.GetSpans()); n != 0 {
			t.Errorf("%d spans", n)
		}
	})
	t.Run("from Internet", func(t *testing.T) {
		exporter := recording(t, sdktrace.ParentBased(sdktrace.AlwaysSample()))
		rec, _ := served(t, untrustedAddr, header("00"))
		spans := exporter.GetSpans()
		if len(spans) != 1 {
			t.Fatalf("a client imposed the sampling: %d spans", len(spans))
		}
		s := spans[0]
		if s.SpanContext.TraceID().String() == parentTrace || s.Parent.IsValid() || rec.Header().Get("X-Trace-ID") == parentTrace {
			t.Errorf("a client chose the trace: %+v", s.SpanContext)
		}
		if len(s.Links) != 1 || s.Links[0].SpanContext.TraceID().String() != parentTrace {
			t.Errorf("links %+v", s.Links)
		}
	})
	t.Run("from Internet, sampled by it: the sampler decides", func(t *testing.T) {
		exporter := recording(t, sdktrace.ParentBased(sdktrace.NeverSample()))
		served(t, untrustedAddr, header("01"))
		if n := len(exporter.GetSpans()); n != 0 {
			t.Errorf("%d spans", n)
		}
	})
}

// What the span of a request is told: the flow, its step, the page, the events, a link to
// the span that created the flow; never a value.
func TestObserver(t *testing.T) {
	const sentinel = "sentinel-value"
	exporter := recording(t, sdktrace.AlwaysSample())
	ctx, span := tracer().Start(context.Background(), "request")
	origin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb"
	f := &flow.Flow{FlowID: "hydra-sql", Subject: sentinel, LoginChallenge: sentinel, Current: 1, Trace: origin, Steps: []flow.Step{{App: "sql"}}}
	Observer{HydraMode: "decrypt"}.Observe(ctx, flow.Observation{Surface: "front", Before: f, After: f, Response: flow.Response{Code: flow.E1004}, Reports: []flow.Report{
		{Event: "flow.error", Detail: "E1004"},
		{Event: "hydra.request_failed", Operation: "accept_login", Status: 502, Detail: sentinel},
		{Event: "hydra.login_accepted", Detail: sentinel},
		{Event: "webhook.failed", Kind: "login", Host: sentinel, Detail: sentinel},
		{Event: "state.error", Detail: sentinel},
	}})
	span.End()
	s := exporter.GetSpans()[0]
	a := attrs(s)
	for k, v := range map[string]string{"dispatcher.flow": "hydra-sql", "dispatcher.step": "sql", "dispatcher.surface": "front", "dispatcher.hydra_mode": "decrypt", "dispatcher.error_code": "E1004"} {
		if a[k] != v {
			t.Errorf("%s = %q, want %q", k, a[k], v)
		}
	}
	if len(s.Events) != 5 {
		t.Errorf("events %+v", s.Events)
	}
	if len(s.Links) != 1 || s.Links[0].SpanContext.TraceID().String() != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || s.Links[0].SpanContext.SpanID().String() != "bbbbbbbbbbbbbbbb" {
		t.Errorf("links %+v", s.Links)
	}
	data, err := json.Marshal(struct {
		A, E, L any
	}{s.Attributes, s.Events, s.Links})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), sentinel) {
		t.Errorf("a value in the span: %s", data)
	}
}

// The flow's own trace needs no link to itself; a malformed origin none either.
func TestNoLink(t *testing.T) {
	exporter := recording(t, sdktrace.AlwaysSample())
	ctx, span := tracer().Start(context.Background(), "request")
	own := span.SpanContext().TraceID().String() + "-" + span.SpanContext().SpanID().String()
	Observer{}.Observe(ctx, flow.Observation{Before: &flow.Flow{Trace: own}})
	Observer{}.Observe(ctx, flow.Observation{Before: &flow.Flow{Trace: "not-an-origin"}})
	span.End()
	if n := len(exporter.GetSpans()[0].Links); n != 0 {
		t.Errorf("%d links", n)
	}
}

// A span by operation of the store, without its key or value; a key absent and a replay
// are no errors.
func TestStates(t *testing.T) {
	exporter := recording(t, sdktrace.AlwaysSample())
	mem := state.NewMemory()
	defer mem.Close()
	s := States(mem, "redis")
	ctx := context.Background()
	const key, value = "flow:sentinel-key", "sentinel-value"
	_, _, _ = s.Get(ctx, key)
	_ = s.Put(ctx, key, []byte(value), time.Minute, 0)
	_ = s.Put(ctx, key, []byte(value), time.Minute, 0)
	_ = s.Delete(ctx, key)
	mem.Close()
	_, _, _ = s.Get(ctx, key)
	spans := exporter.GetSpans()
	if len(spans) != 5 {
		t.Fatalf("%d spans", len(spans))
	}
	for i, want := range []string{"state.get", "state.put", "state.put", "state.delete", "state.get"} {
		if spans[i].Name != want {
			t.Errorf("span %d: %s, want %s", i, spans[i].Name, want)
		}
	}
	for i := range 4 {
		if spans[i].Status.Code.String() == "Error" {
			t.Errorf("span %d marked an error", i)
		}
	}
	if spans[4].Status.Code.String() != "Error" {
		t.Errorf("a closed store: %v", spans[4].Status)
	}
	data, _ := json.Marshal(spans[1].Attributes)
	if strings.Contains(string(data), "sentinel") {
		t.Errorf("the key in the span: %s", data)
	}
	if attrs(spans[1])["db.system.name"] != "redis" {
		t.Errorf("attributes %s", data)
	}
}

// IDs: a new trace takes the trace_id of the logs; one that is no W3C id, random.
func TestIDs(t *testing.T) {
	ctx := httpx.WithTraceID(context.Background(), parentTrace)
	got, span := ids{}.NewIDs(ctx)
	if got.String() != parentTrace || !span.IsValid() {
		t.Errorf("ids %s %s", got, span)
	}
	got, _ = ids{}.NewIDs(httpx.WithTraceID(context.Background(), "not-hexadecimal-trace-id"))
	if !got.IsValid() {
		t.Errorf("no id for another form: %s", got)
	}
}

// Nothing asks for traces: nothing installed, no traceparent leaves.
func TestSetupOff(t *testing.T) {
	before := otel.GetTracerProvider()
	stop, err := Setup(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if otel.GetTracerProvider() != before {
		t.Error("a provider installed")
	}
	ctx, span := tracer().Start(context.Background(), "x")
	defer span.End()
	if span.IsRecording() {
		t.Error("a span records")
	}
	carrier := propagation.HeaderCarrier(http.Header{})
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if len(carrier.Keys()) != 0 {
		t.Errorf("headers %v", carrier.Keys())
	}
}

// collector stands in for an OTLP receiver, or Sentry's.
func collector(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var hits atomic.Int32
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		path.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &path
}

func restore(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
}

// The real export, over OTLP/HTTP: at the stop of serve, within its 2 s, W3C propagation
// on; the ratio applied, a span sampled reaching the collector.
func TestSetupExports(t *testing.T) {
	restore(t)
	srv, hits, path := collector(t)
	stop, err := Setup(context.Background(), Options{Enabled: true, Endpoint: srv.URL + "/v1/traces", Protocol: "http/protobuf", SamplerRatio: 1, Version: "v1", Instance: "i"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := tracer().Start(context.Background(), "x")
	if !span.SpanContext().IsSampled() {
		t.Error("ratio 1 not sampled")
	}
	carrier := propagation.HeaderCarrier(http.Header{})
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if carrier.Get("Traceparent") == "" {
		t.Errorf("no traceparent: %v", carrier.Keys())
	}
	span.End()
	start := time.Now()
	stop()
	if hits.Load() == 0 || path.Load() != "/v1/traces" {
		t.Errorf("%d calls, path %v", hits.Load(), path.Load())
	}
	if took := time.Since(start); took > shutdownTimeout+time.Second {
		t.Errorf("stopped in %v", took)
	}
}

// A collector down costs no request: spans are dropped, the stop bounded.
func TestCollectorDown(t *testing.T) {
	restore(t)
	stop, err := Setup(context.Background(), Options{Enabled: true, Endpoint: "http://127.0.0.1:1/v1/traces", Protocol: "http/protobuf", SamplerRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, span := tracer().Start(context.Background(), "x")
	span.End()
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("a span took %v", took)
	}
	stop()
	if took := time.Since(start); took > shutdownTimeout+time.Second {
		t.Errorf("stopped in %v", took)
	}
}

// With traces_sample_rate, the spans go to Sentry's OTLP endpoint; 0 sends none there.
func TestSetupSentry(t *testing.T) {
	restore(t)
	srv, hits, path := collector(t)
	stop, err := Setup(context.Background(), Options{SentryDSN: strings.Replace(srv.URL, "http://", "http://key@", 1) + "/1", SentryRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, span := tracer().Start(context.Background(), "x", trace.WithAttributes(attribute.String("a", "b")))
	span.End()
	stop()
	if hits.Load() == 0 || !strings.Contains(path.Load().(string), "otlp") {
		t.Errorf("%d calls, path %v", hits.Load(), path.Load())
	}
	before := otel.GetTracerProvider()
	stop, err = Setup(context.Background(), Options{SentryDSN: strings.Replace(srv.URL, "http://", "http://key@", 1) + "/1"})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if otel.GetTracerProvider() != before {
		t.Error("a provider installed for traces_sample_rate 0")
	}
}

// OTEL_TRACES_SAMPLER wins over the options, as the doc says.
func TestEnvironmentWins(t *testing.T) {
	restore(t)
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	srv, _, _ := collector(t)
	stop, err := Setup(context.Background(), Options{Enabled: true, Endpoint: srv.URL, Protocol: "http/protobuf", SamplerRatio: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	_, span := tracer().Start(context.Background(), "x")
	defer span.End()
	if span.SpanContext().IsSampled() {
		t.Error("the environment lost")
	}
}
