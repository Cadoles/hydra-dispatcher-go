package sentrylog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/httpx"
)

// fakeTransport keeps what would leave.
type fakeTransport struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (f *fakeTransport) Flush(time.Duration) bool              { return true }
func (f *fakeTransport) FlushWithContext(context.Context) bool { return true }
func (f *fakeTransport) Configure(sentry.ClientOptions)        {}
func (f *fakeTransport) Close()                                {}
func (f *fakeTransport) SendEvent(e *sentry.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeTransport) sent() []*sentry.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

func newTracker(t *testing.T, mod ...func(*Options)) (*Tracker, *fakeTransport) {
	t.Helper()
	f := &fakeTransport{}
	o := Options{DSN: "https://key@sentry.example/1", SampleRate: 1, MaxEventsPerMinute: 60, HydraMode: "decrypt", StateBackend: "redis", Transport: f}
	for _, m := range mod {
		m(&o)
	}
	tr, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return tr, f
}

func TestNoDSN(t *testing.T) {
	tr, err := New(Options{})
	if err != nil || tr != nil {
		t.Fatalf("tracker %v, err %v", tr, err)
	}
	tr.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1004"}}})
	tr.Flush()
	called := false
	tr.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(nil, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("the middleware of no tracker stops the request")
	}
	if h := slog.DiscardHandler; tr.Handler(h) != h {
		t.Error("the handler of no tracker wraps")
	}
}

// What goes: the codes of the doc, grouped by code and what failed; what does not: the
// expected answers (doc, Sentry).
func TestWhatIsSent(t *testing.T) {
	failedAccept := flow.Report{Event: "hydra.request_failed", Operation: "accept_login", Status: 502}
	for name, tc := range map[string]struct {
		reports     []flow.Report
		level       sentry.Level
		fingerprint []string
	}{
		"E1000":                                  {[]flow.Report{{Event: "flow.error", Detail: "E1000", Sentry: true}}, sentry.LevelError, []string{"E1000"}},
		"E1005":                                  {[]flow.Report{{Event: "flow.error", Detail: "E1005", Sentry: true}}, sentry.LevelError, []string{"E1005"}},
		"E1007":                                  {[]flow.Report{{Event: "flow.error", Detail: "E1007", Sentry: true}}, sentry.LevelError, []string{"E1007"}},
		"E1004, by its operation":                {[]flow.Report{{Event: "flow.error", Detail: "E1004", Sentry: true}, failedAccept}, sentry.LevelError, []string{"E1004", "accept_login"}},
		"E1006, by its hook":                     {[]flow.Report{{Event: "flow.error", Detail: "E1006", Sentry: true}, {Event: "webhook.failed", Kind: "login", Host: "hooks", Status: 500}}, sentry.LevelError, []string{"E1006", "login"}},
		"the store, by its backend":              {[]flow.Report{{Event: "flow.error", Detail: "E1000", Sentry: true}, {Event: "state.error", Detail: "down", Sentry: true}}, sentry.LevelError, []string{"E1000", "state", "redis"}},
		"the store under an answer that stands":  {[]flow.Report{{Event: "state.error", Detail: "down", Sentry: true}}, sentry.LevelError, []string{"state", "redis"}},
		"a conflict and its E1007 are one event": {[]flow.Report{{Event: "state.conflict", Detail: "replayed", Sentry: true}, {Event: "flow.error", Detail: "E1007", Sentry: true}}, sentry.LevelError, []string{"E1007"}},
		"ECR-9, a fact on a finished flow":       {[]flow.Report{{Event: "state.conflict", Detail: "finished meanwhile", Sentry: true}}, sentry.LevelError, []string{"state.conflict"}},
	} {
		t.Run(name, func(t *testing.T) {
			tr, f := newTracker(t)
			tr.Observe(context.Background(), flow.Observation{Surface: "front", Reports: tc.reports})
			events := f.sent()
			if len(events) != 1 {
				t.Fatalf("%d events", len(events))
			}
			if e := events[0]; e.Level != tc.level || !slices.Equal(e.Fingerprint, tc.fingerprint) {
				t.Errorf("level %s, fingerprint %v", e.Level, e.Fingerprint)
			}
		})
	}
	for name, reports := range map[string][]flow.Report{
		"E1001, a forged challenge":   {{Event: "challenge.invalid", Detail: "forged"}},
		"an expired one":              {{Event: "challenge.invalid", Detail: "expired"}},
		"a reject":                    {{Event: "flow.rejected", Detail: "user"}},
		"an A3 reject, for the audit": {{Event: "flow.rejected", Detail: "not_ours:login", Audit: true}},
		"a replay":                    {{Event: "state.conflict", Detail: "replay"}},
		"a client gone":               {{Event: "hydra.request_abandoned", Operation: "accept_login"}, {Event: "webhook.abandoned", Kind: "login"}},
		"a skip":                      {{Event: "skip.ignored", Kind: "login"}},
	} {
		t.Run("nothing for "+name, func(t *testing.T) {
			tr, f := newTracker(t)
			tr.Observe(context.Background(), flow.Observation{Reports: reports, Response: flow.Response{Code: flow.E1001}})
			if events := f.sent(); len(events) != 0 {
				t.Errorf("%d events: %s", len(events), events[0].Message)
			}
		})
	}
}

// requestContext is the context of a request, its trace id and route.
func requestContext(t *testing.T, tr *Tracker) (ctx context.Context) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/auth", func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil), tr.Middleware)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil))
	return ctx
}

// The tags and contexts of the doc.
func TestContext(t *testing.T) {
	tr, f := newTracker(t)
	ctx := requestContext(t, tr)
	tr.Observe(ctx, flow.Observation{Surface: "front", Before: &flow.Flow{FlowID: "hydra-sql", Current: 1, Steps: []flow.Step{{App: "sql"}}},
		Reports: []flow.Report{{Event: "flow.error", Detail: "E1004", Sentry: true}, {Event: "hydra.request_failed", Operation: "accept_login", Status: 502},
			{Event: "webhook.failed", Kind: "consent", Host: "hooks", Status: 500, Elapsed: time.Second}}})
	events := f.sent()
	if len(events) != 1 {
		t.Fatalf("%d events", len(events))
	}
	e := events[0]
	for k, v := range map[string]string{"flow": "hydra-sql", "step": "sql", "route": "GET /oauth2/auth", "surface": "front", "hydra_mode": "decrypt", "error_code": "E1004", "trace_id": httpx.TraceID(ctx)} {
		if e.Tags[k] != v || v == "" {
			t.Errorf("tag %s = %q, want %q", k, e.Tags[k], v)
		}
	}
	if e.Contexts["hydra"]["operation"] != "accept_login" || e.Contexts["webhook"]["host"] != "hooks" || e.Contexts["webhook"]["kind"] != "consent" {
		t.Errorf("contexts %+v", e.Contexts)
	}
}

// The plafond by minute of an instance, and a sample_rate of 0 sends nothing.
func TestLimits(t *testing.T) {
	now := time.Unix(6000, 0)
	tr, f := newTracker(t, func(o *Options) { o.MaxEventsPerMinute, o.Now = 2, func() time.Time { return now } })
	send := func() {
		tr.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1000"}}})
	}
	send()
	send()
	send()
	if n := len(f.sent()); n != 2 {
		t.Errorf("%d events", n)
	}
	now = now.Add(time.Minute)
	send()
	if n := len(f.sent()); n != 3 {
		t.Errorf("%d events the next minute", n)
	}
	tr, f = newTracker(t, func(o *Options) { o.SampleRate = 0 })
	tr.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1000"}}})
	if n := len(f.sent()); n != 0 {
		t.Errorf("sample_rate 0: %d events", n)
	}
}

// A failure to decrypt goes once by interval, as a warning.
func TestDecrypt(t *testing.T) {
	now := time.Unix(6000, 0)
	tr, f := newTracker(t, func(o *Options) { o.Now = func() time.Time { return now } })
	fail := func() {
		tr.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "hydra.decrypt_fallback", Detail: "flowcodec: format"}}})
	}
	fail()
	fail()
	events := f.sent()
	if len(events) != 1 || events[0].Level != sentry.LevelWarning || !slices.Equal(events[0].Fingerprint, []string{"hydra.decrypt_fallback"}) {
		t.Fatalf("events %+v", events)
	}
	now = now.Add(decryptEvery)
	fail()
	if n := len(f.sent()); n != 2 {
		t.Errorf("%d events past the interval", n)
	}
}

// A panic is one fatal event, the panic going on to Recover, which answers; the abort of
// net/http is none.
func TestPanic(t *testing.T) {
	tr, f := newTracker(t)
	var logs bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic(errors.New("boom ?login_challenge=secret")) })
	mux.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	logger := slog.New(tr.Handler(slog.NewJSONHandler(&logs, nil)))
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil), httpx.Recover(logger), tr.Middleware)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
	events := f.sent()
	if len(events) != 1 || events[0].Level != sentry.LevelFatal || events[0].Tags["route"] != "GET /boom" || events[0].Tags["trace_id"] == "" {
		t.Fatalf("events %+v", events)
	}
	data, _ := json.Marshal(events[0])
	if strings.Contains(string(data), "secret") {
		t.Errorf("a query string left: %s", data)
	}
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
	}()
	if n := len(f.sent()); n != 1 {
		t.Errorf("%d events after an abort", n)
	}
}

// An error line is an event, by its name alone; those a request's observation sends are
// not sent twice; info and warn lines are the breadcrumbs of their request.
func TestBridge(t *testing.T) {
	tr, f := newTracker(t)
	var logs bytes.Buffer
	logger := slog.New(tr.Handler(slog.NewJSONHandler(&logs, nil))).With("log_type", "app")
	ctx := requestContext(t, tr)
	logger.ErrorContext(ctx, "config.refresh_failed", "cause", "dsn postgres://user:secret@db")
	for _, name := range observed {
		logger.ErrorContext(ctx, name, "detail", "x")
	}
	events := f.sent()
	if len(events) != 1 || events[0].Message != "config.refresh_failed" || !slices.Equal(events[0].Fingerprint, []string{"config.refresh_failed"}) {
		t.Fatalf("events %+v", events)
	}
	data, _ := json.Marshal(events[0])
	if strings.Contains(string(data), "secret") {
		t.Errorf("the details of the line left: %s", data)
	}
	if !strings.Contains(logs.String(), `"log_type":"app"`) || !strings.Contains(logs.String(), "secret") {
		t.Errorf("the log itself lost: %s", logs.String())
	}

	logger.InfoContext(ctx, "flow.started", "detail", "free text of alice", "kind", "login", "surface", "front")
	logger.WarnContext(ctx, "challenge.invalid", "detail", "forged", "ip", "203.0.113.9")
	logger.DebugContext(ctx, "not.a.crumb")
	tr.Observe(ctx, flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1000"}}})
	events = f.sent()
	last := events[len(events)-1]
	if len(last.Breadcrumbs) < 2 {
		t.Fatalf("breadcrumbs %+v", last.Breadcrumbs)
	}
	crumbs, _ := json.Marshal(last.Breadcrumbs)
	for _, want := range []string{`"message":"flow.started"`, `"message":"challenge.invalid"`, `"kind":"login"`, `"level":"warning"`} {
		if !strings.Contains(string(crumbs), want) {
			t.Errorf("no %s in %s", want, crumbs)
		}
	}
	for _, not := range []string{"alice", "203.0.113.9", "not.a.crumb"} {
		if strings.Contains(string(crumbs), not) {
			t.Errorf("%s in %s", not, crumbs)
		}
	}
	// Another request has its own.
	other := requestContext(t, tr)
	tr.Observe(other, flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1000"}}})
	events = f.sent()
	if n := len(events[len(events)-1].Breadcrumbs); n != 0 {
		t.Errorf("%d breadcrumbs of another request", n)
	}
}

// A failed flow full of sentinels: none is in the payload, whatever built the event, and
// the hooks scrub what the SDK or a future field would add (doc, Données personnelles).
func TestNothingPersonalLeaves(t *testing.T) {
	const sentinel = "sentinel-value"
	tr, f := newTracker(t)
	ctx := requestContext(t, tr)
	logger := slog.New(tr.Handler(slog.DiscardHandler))
	logger.InfoContext(ctx, "hydra.login_accepted", "detail", sentinel, "subject", sentinel, "context", sentinel, "token", sentinel)
	flowFull := &flow.Flow{FlowID: "f", Subject: sentinel, LoginChallenge: sentinel, CSRF: sentinel,
		Sent: &flow.SentLogin{Subject: sentinel, ACR: sentinel, Context: flow.Object{"email": json.RawMessage(`"` + sentinel + `"`)}}}
	tr.Observe(ctx, flow.Observation{Surface: "front", Before: flowFull, After: flowFull, Reports: []flow.Report{
		{Event: "flow.error", Detail: "E1004", Sentry: true},
		{Event: "hydra.request_failed", Operation: "accept_login", Status: 502, Detail: sentinel},
	}})
	events := f.sent()
	if len(events) != 1 {
		t.Fatalf("%d events", len(events))
	}
	data, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), sentinel) {
		t.Errorf("a value left:\n%s", data)
	}

	e := sentry.NewEvent()
	e.Message = "see /consent?consent_challenge=" + sentinel
	e.User = sentry.User{Email: sentinel, IPAddress: "203.0.113.9"}
	e.Request = &sentry.Request{URL: "http://x/?login_challenge=" + sentinel, Cookies: sentinel, Headers: map[string]string{"Authorization": sentinel}}
	e.Exception = []sentry.Exception{{Value: "GET /?login_challenge=" + sentinel}}
	e.Tags = map[string]string{"token": sentinel}
	e.Contexts = map[string]sentry.Context{"id_token": {"a": sentinel}, "hydra": {"secret": sentinel, "operation": "x"}}
	e.Breadcrumbs = []*sentry.Breadcrumb{{Message: "GET /?logout_challenge=" + sentinel, Data: map[string]any{"password": sentinel, "url": "/?a=" + sentinel}}}
	out := tr.beforeSend(e, nil)
	data, _ = json.Marshal(out)
	if strings.Contains(string(data), sentinel) || strings.Contains(string(data), "203.0.113.9") {
		t.Errorf("the hook left a value:\n%s", data)
	}
	if out.Contexts["hydra"]["operation"] != "x" {
		t.Errorf("the hook took too much: %+v", out)
	}
}

// The real transport, on a server standing in for Sentry: the envelope goes on Flush,
// and a Sentry that hangs costs the request nothing.
func TestRealTransport(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var bodies bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		bodies.Write(data)
	}))
	defer srv.Close()
	tr, err := New(Options{DSN: strings.Replace(srv.URL, "http://", "http://key@", 1) + "/1", SampleRate: 1, MaxEventsPerMinute: 60, Release: "hydra-dispatcher@v1"})
	if err != nil {
		t.Fatal(err)
	}
	tr.Observe(context.Background(), flow.Observation{Before: &flow.Flow{Subject: "sentinel-value"}, Reports: []flow.Report{{Event: "flow.error", Detail: "E1004"}}})
	tr.Flush()
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/api/1/envelope/" {
		t.Fatalf("paths %v", paths)
	}
	if !strings.Contains(bodies.String(), "E1004") || !strings.Contains(bodies.String(), "hydra-dispatcher@v1") || strings.Contains(bodies.String(), "sentinel-value") {
		t.Errorf("envelope %s", bodies.String())
	}
}

func TestSendDoesNotWait(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	tr, err := New(Options{DSN: strings.Replace(srv.URL, "http://", "http://key@", 1) + "/1", SampleRate: 1})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	tr.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "flow.error", Detail: "E1004"}}})
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("the request waited %v", took)
	}
}
