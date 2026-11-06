package front

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/tracing"
)

// The tree of spans of a flow of two steps, through the pages: a trace by request of the
// browser, its calls under it, each later one linked to the span that created the flow;
// the trace id of the logs is the span's; no value in any span (doc, OpenTelemetry, Tests).
func TestSpansOfAFlowOfTwoSteps(t *testing.T) {
	const subject = "sentinel.subject@example.org"
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithIDGenerator(tracing.IDs()))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
		_ = provider.Shutdown(context.Background())
	})
	w := newWorld(t)
	var logs bytes.Buffer
	w.o.Log = slog.New(httpx.LogHandler(slog.NewJSONHandler(&logs, nil)))
	w.o.Observers = []flow.Observer{tracing.Observer{HydraMode: "fallback"}}
	w.o.Store = tracing.States(w.o.Store, "memory")
	mux := http.NewServeMux()
	w.front.Register(mux)
	w.h = httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil), tracing.HTTP)

	step := w.choose("hydra-sql-2fa")
	w.app(step, subject, `{"email":"sentinel-claim"}`)
	step = location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	w.app(step, subject, `{}`)
	location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther)

	spans := exporter.GetSpans()
	byName := map[string]int{}
	var origin string
	for _, s := range spans {
		byName[s.Name]++
		if s.Name == "hydra.login_request" && origin == "" {
			origin = s.SpanContext.TraceID().String()
		}
	}
	for name, min := range map[string]int{"hydra.login_request": 1, "hydra.accept_login": 1, "hydra.consent_request": 1, "hydra.accept_consent": 1, "state.get": 1, "state.put": 1, "GET /{$}": 1, "POST /{$}": 1, "GET /oauth2/auth": 2, "GET /consent": 1} {
		if byName[name] < min {
			t.Errorf("%d spans %s, want %d at least, in %v", byName[name], name, min, byName)
		}
	}
	// A call is a child of its request's span.
	servers := map[string]tracetest.SpanStub{}
	for _, s := range spans {
		servers[s.SpanContext.SpanID().String()] = s
	}
	links := 0
	for _, s := range spans {
		switch {
		case strings.HasPrefix(s.Name, "hydra."):
			parent, ok := servers[s.Parent.SpanID().String()]
			if !ok || parent.SpanContext.TraceID() != s.SpanContext.TraceID() {
				t.Errorf("%s has no parent: %+v", s.Name, s.Parent)
			}
		case s.Name == "GET /oauth2/auth" || s.Name == "GET /consent":
			if len(s.Links) > 0 && s.Links[0].SpanContext.TraceID().String() == origin {
				links++
			}
		}
	}
	if links < 3 {
		t.Errorf("%d later requests linked to the flow's start", links)
	}
	data, err := json.Marshal(func() (out []any) {
		for _, s := range spans {
			out = append(out, []any{s.Name, s.Attributes, s.Events, s.Links})
		}
		return out
	}())
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{subject, "sentinel-claim", hydraL, hydraC, w.cookies["dispatcher_flow_csrf"]} {
		if sentinel != "" && strings.Contains(string(data), sentinel) {
			t.Errorf("%q in a span", sentinel)
		}
	}
	// The logs of a request carry the trace id and the span id of its span.
	found := false
	for line := range strings.Lines(logs.String()) {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if m["msg"] == "hydra.login_accepted" {
			found = true
			if s, ok := servers[m["span_id"].(string)]; !ok || s.SpanContext.TraceID().String() != m["trace_id"] {
				t.Errorf("line %s", line)
			}
		}
	}
	if !found {
		t.Errorf("no line: %s", logs.String())
	}
}
