package front

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/metrics"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/sentrylog"
)

func scrapeOf(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// A whole authentication through the pages, then a skip, counted by the real catalogue:
// the engine's reports reach the labels of the doc.
func TestMetricsThroughThePages(t *testing.T) {
	w := newWorld(t)
	m := metrics.New(200, nil)
	w.o.Observers = []flow.Observer{m}
	w.o.Store = m.States(w.o.Store)
	w.remembered(`{"email":"alice@example.org"}`)
	w.hydra.skip, w.hydra.consentSkip = true, true
	if u := location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("SKP-1: %s", u)
	}
	if u := location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther); u.String() != callbackURL {
		t.Fatalf("SKC-1: %s", u)
	}
	location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther)
	body := scrapeOf(t, m)
	for _, want := range []string{
		`hydra_dispatcher_login_requests_total{flow="none",outcome="displayed"} 1`,
		`hydra_dispatcher_login_requests_total{flow="hydra-sql",outcome="accepted"} 2`,
		`hydra_dispatcher_flow_starts_total{flow="hydra-sql",trigger="choice"} 1`,
		`hydra_dispatcher_step_requests_total{app="sql",kind="login",outcome="accepted"} 1`,
		`hydra_dispatcher_step_requests_total{app="sql",kind="consent",outcome="accepted"} 1`,
		`hydra_dispatcher_consent_requests_total{flow="hydra-sql",outcome="skip_accepted"} 3`,
		`hydra_dispatcher_skip_total{kind="login",result="accepted"} 1`,
		`hydra_dispatcher_skip_total{kind="consent",result="accepted"} 2`,
		`hydra_dispatcher_auth_duration_seconds_count{outcome="accepted"} 1`,
		`hydra_dispatcher_challenge_validations_total{mode="fallback",result="ok"}`,
		`hydra_dispatcher_state_operation_duration_seconds_count{op="put"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("no %s in:\n%s", want, body)
		}
	}
}

// WRT-2: a memory of the skip too big to write is counted.
func TestMetricsSkipUnavailable(t *testing.T) {
	heard := 0
	w := newWorld(t)
	w.front.o.SkipUnavailable = func() { heard++ }
	b := make([]byte, 6000)
	_, _ = rand.Read(b)
	w.remembered(`{"blob":"` + base64.RawURLEncoding.EncodeToString(b) + `"}`)
	if heard != 1 {
		t.Errorf("heard %d", heard)
	}
}

// fakeSentry keeps what Sentry would get.
type fakeSentry struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (f *fakeSentry) Flush(time.Duration) bool              { return true }
func (f *fakeSentry) FlushWithContext(context.Context) bool { return true }
func (f *fakeSentry) Configure(sentry.ClientOptions)        {}
func (f *fakeSentry) Close()                                {}
func (f *fakeSentry) SendEvent(e *sentry.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

// The pages through a real tracker: an event for E1004, by its operation, none for
// E1001; the doc's test (Sentry, Tests).
func TestSentryThroughThePages(t *testing.T) {
	f := &fakeSentry{}
	tracker, err := sentrylog.New(sentrylog.Options{DSN: "https://key@sentry.example/1", SampleRate: 1, Transport: f})
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	w.o.Observers = []flow.Observer{tracker}
	w.h = tracker.Middleware(w.h)
	w.hydra.errs["get_login"] = &hydra.RequestError{Op: "get_login_request", Status: http.StatusNotFound, Body: []byte(`{"error":"not_found"}`)}
	if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Fatalf("E1001: %d", resp.StatusCode)
	}
	if len(f.events) != 0 {
		t.Fatalf("E1001 sent: %+v", f.events[0])
	}
	w.hydra.errs["get_login"] = &hydra.UnavailableError{Op: "get_login_request", Status: http.StatusBadGateway}
	if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("E1004: %d", resp.StatusCode)
	}
	if len(f.events) != 1 || !slices.Equal(f.events[0].Fingerprint, []string{"E1004", "get_login_request"}) || f.events[0].Tags["surface"] != "front" {
		t.Fatalf("events %+v", f.events)
	}
}
