package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Cadoles/hydra-dispatcher-go/internal/audit"
	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"github.com/Cadoles/hydra-dispatcher-go/internal/metrics"
	"github.com/Cadoles/hydra-dispatcher-go/internal/sentrylog"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
	"github.com/Cadoles/hydra-dispatcher-go/internal/tracing"
)

// The bench of revue R29, rebuilt (P12d): the whole handler of newHandler, before a
// fake Hydra over HTTP and the two webhooks, signed, with Sentry and the traces exported
// to servers that keep what they get, and the three streams. A login through the pages
// and the emulated API, a skip, a webhook and Hydra failing, a logout and a panic: no
// sentinel leaves by the logs, Sentry, the spans, /metrics, nor the headers sent to
// Hydra and to the webhooks.

// The sentinels: what may never leave, but where it belongs.
const (
	benchSubject   = "sentinel.subject@example.org"
	benchClaim     = "sentinel-claim-value"
	benchHydraBody = "sentinel-hydra-body"
	benchHookBody  = "sentinel-webhook-body"
	benchBaggage   = "sentinel-baggage"
	benchSID       = "5e771e7a-5e55-4e55-8e55-5e771e7a5e55"
)

// The challenges of Hydra, one by scenario, and the consent and logout ones.
const (
	benchLogin    = "11c34aaee066148adbc0251024fee9bb"
	benchSkip     = "22c34aaee066148adbc0251024fee9bb"
	benchHookFail = "33c34aaee066148adbc0251024fee9bb"
	benchDown     = "44c34aaee066148adbc0251024fee9bb"
	benchPanic    = "55c34aaee066148adbc0251024fee9bb"
	benchConsent  = "66c34aaee066148adbc0251024fee9bb"
	benchConsent2 = "77c34aaee066148adbc0251024fee9bb"
	benchLogout   = "88c34aaee066148adbc0251024fee9bb"
)

const benchRequestURL = "http://public.hydra.test/oauth2/auth?client_id=c1&scope=openid+email&state=abcdefghijklmnopqrstuvwxyz"

// httpHydra is Hydra's admin API over HTTP: it keeps the login accepted by challenge,
// whose consent request carries the subject and the context, and every header received.
type httpHydra struct {
	t        *testing.T
	mu       sync.Mutex
	headers  []http.Header
	accepted map[string]ory.AcceptOAuth2LoginRequest
	// loginOf is the login challenge of a consent challenge.
	loginOf map[string]string
	// skip are the login challenges of a session Hydra holds, down those it fails.
	skip, down map[string]bool
}

func (h *httpHydra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.headers = append(h.headers, r.Header.Clone())
	q := r.URL.Query()
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	redirect := func(to string) { reply(ory.OAuth2RedirectTo{RedirectTo: to}) }
	switch r.Method + " " + r.URL.Path {
	case "GET /health/ready":
		reply(map[string]string{"status": "ok"})
	case "GET /admin/oauth2/auth/requests/login":
		c := q.Get("login_challenge")
		if h.down[c] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"server_error","error_description":"`+benchHydraBody+` for `+benchSubject+`"}`)
			return
		}
		req := ory.OAuth2LoginRequest{Challenge: c, Client: ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Client")},
			RequestUrl: benchRequestURL, RequestedScope: []string{"openid", "email"}, RequestedAccessTokenAudience: []string{},
			SessionId: ory.PtrString(benchSID)}
		if h.skip[c] {
			req.Skip, req.Subject = true, benchSubject
		}
		reply(req)
	case "PUT /admin/oauth2/auth/requests/login/accept":
		var body ory.AcceptOAuth2LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.t.Error(err)
		}
		h.accepted[q.Get("login_challenge")] = body
		redirect("http://public.hydra.test/oauth2/auth?login_verifier=v")
	case "GET /admin/oauth2/auth/requests/consent":
		c := q.Get("consent_challenge")
		login := h.accepted[h.loginOf[c]]
		ctx, _ := json.Marshal(login.Context)
		amr := login.Amr
		if amr == nil {
			amr = []string{}
		}
		reply(ory.OAuth2ConsentRequest{Challenge: c, LoginChallenge: ory.PtrString(h.loginOf[c]), Subject: ory.PtrString(login.Subject),
			LoginSessionId: ory.PtrString(benchSID), Acr: ory.PtrString(login.GetAcr()), Amr: amr, RequestUrl: ory.PtrString(benchRequestURL),
			Context: json.RawMessage(ctx), RequestedScope: []string{"openid", "email"}, RequestedAccessTokenAudience: []string{},
			Client: &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Client")}, Skip: ory.PtrBool(true)})
	case "PUT /admin/oauth2/auth/requests/consent/accept":
		_, _ = io.Copy(io.Discard, r.Body)
		redirect("http://client.test/callback?code=c")
	case "PUT /admin/oauth2/auth/requests/login/reject", "PUT /admin/oauth2/auth/requests/consent/reject":
		_, _ = io.Copy(io.Discard, r.Body)
		redirect("http://client.test/callback?error=access_denied")
	case "GET /admin/oauth2/auth/requests/logout":
		reply(ory.OAuth2LogoutRequest{Challenge: ory.PtrString(q.Get("logout_challenge")), Subject: ory.PtrString(benchSubject), Sid: ory.PtrString(benchSID),
			RequestUrl: ory.PtrString("http://public.hydra.test/oauth2/sessions/logout"), RpInitiated: ory.PtrBool(true),
			Client: &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Client")}})
	case "PUT /admin/oauth2/auth/requests/logout/accept":
		redirect("http://public.hydra.test/oauth2/sessions/logout?logout_verifier=v")
	case "PUT /admin/oauth2/auth/requests/logout/reject", "DELETE /admin/oauth2/auth/sessions/login":
		w.WriteHeader(http.StatusNoContent)
	default:
		h.t.Errorf("Hydra: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// keeper keeps what a server receives: the headers and the bodies.
type keeper struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  bytes.Buffer
	// fail answers 500 with a sentinel, for the webhooks.
	fail atomic.Bool
	// reply is the answer of a webhook.
	reply string
}

func (k *keeper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	k.mu.Lock()
	k.headers = append(k.headers, r.Header.Clone())
	if r.Header.Get("Content-Encoding") == "" {
		k.bodies.Write(data)
	}
	k.mu.Unlock()
	switch {
	case k.fail.Load():
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"`+benchHookBody+` for `+benchSubject+`"}`)
	case k.reply != "":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, k.reply)
	}
}

func (k *keeper) received() (headers, bodies string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	h, _ := json.Marshal(k.headers)
	return string(h), k.bodies.String()
}

// switching is the configuration of the moment, which says nothing once: the panic.
type switching struct {
	s     *store.Snapshot
	panic atomic.Bool
}

func (s *switching) Snapshot() *store.Snapshot {
	if s.panic.Load() {
		return nil
	}
	return s.s
}

// browser plays a browser of the Internet on h, its cookies kept, a Baggage of its own
// on every request.
type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]string
}

func (b *browser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	r.RemoteAddr = "198.51.100.66:4321"
	r.Header.Set("Baggage", benchBaggage+"=1")
	r.Header.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for name, value := range b.cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
			continue
		}
		b.cookies[c.Name] = c.Value
	}
	return rec
}

// app is the login app on the emulated API, from its source.
func app(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "10.0.1.7:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, target, rec.Code, rec.Body.String())
	}
	return rec
}

func redirected(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirection: %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSentinelsOnTheWholeHandler(t *testing.T) {
	hydra := &httpHydra{t: t, accepted: map[string]ory.AcceptOAuth2LoginRequest{},
		loginOf: map[string]string{benchConsent: benchLogin, benchConsent2: benchSkip},
		skip:    map[string]bool{benchSkip: true, benchHookFail: true}, down: map[string]bool{benchDown: true}}
	hydraSrv := httptest.NewServer(hydra)
	defer hydraSrv.Close()
	loginHook := &keeper{reply: `{"subject":"` + benchSubject + `"}`}
	consentHook := &keeper{reply: `{}`}
	hooks := http.NewServeMux()
	hooks.Handle("/login", loginHook)
	hooks.Handle("/consent", consentHook)
	hookSrv := httptest.NewServer(hooks)
	defer hookSrv.Close()
	sentry, collector := &keeper{}, &keeper{}
	sentrySrv, collectorSrv := httptest.NewServer(sentry), httptest.NewServer(collector)
	defer sentrySrv.Close()
	defer collectorSrv.Close()

	cfg := testConfig(t, hydraSrv.URL)
	cfg.TLS.AllowHTTP = true
	cfg.Secrets.WebhookSigningKey = []byte("0123456789abcdef0123456789abcdef")
	dsn := strings.Replace(sentrySrv.URL, "http://", "http://key@", 1) + "/1"
	tracker, err := sentrylog.New(sentrylog.Options{DSN: dsn, SampleRate: 1, TracesSampleRate: 1, MaxEventsPerMinute: 600,
		Release: "hydra-dispatcher@bench", HydraMode: "fallback", StateBackend: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	stopTracing, err := tracing.Setup(context.Background(), tracing.Options{Enabled: true, Endpoint: collectorSrv.URL + "/v1/traces",
		Protocol: "http/protobuf", SamplerRatio: 1, SentryDSN: dsn, SentryRatio: 1, Version: "bench"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})

	var appLog, accessLog, auditLog syncBuffer
	logger := slog.New(tracker.Handler(newLogHandler(&appLog, "json", slog.LevelDebug))).With("log_type", "app")
	accessLogger := slog.New(newLogHandler(&accessLog, "json", slog.LevelInfo)).With("log_type", "access")
	auditLogger := slog.New(newLogHandler(&auditLog, "json", slog.LevelInfo)).With("log_type", "audit")
	services := testServices(t, func(context.Context) error { return nil })
	services.metrics = metrics.New(200, logger)
	services.audit = audit.New(auditLogger, []byte("audit-key-audit-key-audit-key-32"), false)
	services.sentry = tracker
	settings := store.DefaultSettings()
	settings.LoginAcceptWebhookURL, settings.ConsentAcceptWebhookURL = hookSrv.URL+"/login", hookSrv.URL+"/consent"
	sql := store.App{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", AuthMode: "network",
		AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.0.1.7/32")}}
	flows := []store.Flow{{ID: "a", Enabled: true, Title: map[string]string{"en": "A"}, Steps: []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}}}}
	snapshots := &switching{s: store.NewSnapshot([]store.App{sql}, flows, settings)}
	services.config = snapshots
	h, err := newHandler(cfg, logger, accessLogger, services)
	if err != nil {
		t.Fatal(err)
	}
	b := &browser{t: t, h: h, cookies: map[string]string{}}

	// A login: the choice, the app, the webhooks, the consent.
	if rec := b.do(http.MethodGet, "/?login_challenge="+benchLogin, nil); rec.Code != http.StatusOK {
		t.Fatalf("choice page: %d %s", rec.Code, rec.Body.String())
	}
	step := redirected(t, b.do(http.MethodPost, "/", url.Values{"flow": {"a"}, "login_challenge": {benchLogin}, "csrf_token": {b.cookies["dispatcher_flow_csrf"]}}))
	sc := step.Query().Get("login_challenge")
	app(t, h, http.MethodGet, "/admin/oauth2/auth/requests/login?login_challenge="+sc, "")
	app(t, h, http.MethodPut, "/admin/oauth2/auth/requests/login/accept?login_challenge="+sc, `{"subject":"`+benchSubject+`","context":{"email":"`+benchSubject+`"}}`)
	consent := redirected(t, b.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(benchLogin), nil))
	cc := consent.Query().Get("consent_challenge")
	app(t, h, http.MethodGet, "/admin/oauth2/auth/requests/consent?consent_challenge="+cc, "")
	app(t, h, http.MethodPut, "/admin/oauth2/auth/requests/consent/accept?consent_challenge="+cc, `{"session":{"id_token":{"email":"`+benchClaim+`"}}}`)
	if u := redirected(t, b.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(benchLogin), nil)); !strings.Contains(u.String(), "login_verifier") {
		t.Fatalf("final accept: %s", u)
	}
	if u := redirected(t, b.do(http.MethodGet, "/consent?consent_challenge="+benchConsent, nil)); u.Host != "client.test" {
		t.Fatalf("consent: %s", u)
	}
	if b.cookies["dispatcher_remember"] == "" {
		t.Fatal("no remember cookie")
	}

	// A skip, honoured from the remember cookie, the webhooks called again.
	if u := redirected(t, b.do(http.MethodGet, "/?login_challenge="+benchSkip, nil)); !strings.Contains(u.String(), "login_verifier") {
		t.Fatalf("skip: %s", u)
	}
	if u := redirected(t, b.do(http.MethodGet, "/consent?consent_challenge="+benchConsent2, nil)); u.Host != "client.test" {
		t.Fatalf("consent of the skip: %s", u)
	}

	// A webhook that fails, at a skip: E1006, with the way out (Q88).
	loginHook.fail.Store(true)
	if rec := b.do(http.MethodGet, "/?login_challenge="+benchHookFail, nil); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "E1006") ||
		!strings.Contains(rec.Body.String(), "http://public.hydra.test/oauth2/sessions/logout") {
		t.Errorf("webhook failed: %d %s", rec.Code, rec.Body.String())
	}
	loginHook.fail.Store(false)

	// Hydra failing: E1004.
	if rec := b.do(http.MethodGet, "/?login_challenge="+benchDown, nil); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "E1004") {
		t.Errorf("Hydra failing: %d", rec.Code)
	}

	// A logout of a client, for the session of the remember cookie.
	if rec := b.do(http.MethodGet, "/logout?logout_challenge="+benchLogout, nil); rec.Code >= 500 {
		t.Errorf("logout: %d %s", rec.Code, rec.Body.String())
	}

	// A panic: the page answers 500 with its trace_id, Sentry hears of it.
	snapshots.panic.Store(true)
	if rec := b.do(http.MethodGet, "/?login_challenge="+benchPanic, nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("panic: %d", rec.Code)
	}
	snapshots.panic.Store(false)

	scrape := httptest.NewRecorder()
	services.metrics.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	tracker.Flush()
	stopTracing()

	sentinels := []string{benchSubject, benchClaim, benchHydraBody, benchHookBody, benchBaggage,
		benchLogin, benchSkip, benchHookFail, benchDown, benchPanic, benchConsent, benchConsent2, benchLogout, sc, cc,
		strings.Repeat("ab", 32), strings.Repeat("cd", 32), "0123456789abcdef0123456789abcdef", "audit-key-audit-key-audit-key-32"}
	for name, value := range b.cookies {
		if len(value) >= 16 {
			sentinels = append(sentinels, value)
		} else {
			t.Logf("cookie %s too short to be a sentinel: %q", name, value)
		}
	}
	hydraHeaders, _ := json.Marshal(hydra.headers)
	loginHeaders, _ := loginHook.received()
	consentHeaders, _ := consentHook.received()
	_, sentryBodies := sentry.received()
	_, spans := collector.received()
	for name, stream := range map[string]string{
		"the application log": appLog.String(), "the access log": accessLog.String(), "the audit log": auditLog.String(),
		"Sentry": sentryBodies, "the spans": spans, "/metrics": scrape.Body.String(),
		"the headers to Hydra": string(hydraHeaders), "the headers to the login webhook": loginHeaders,
		"the headers to the consent webhook": consentHeaders,
	} {
		if stream == "" || stream == "null" {
			t.Errorf("%s: nothing", name)
		}
		t.Logf("%s: %d bytes", name, len(stream))
		for _, s := range sentinels {
			if strings.Contains(stream, s) {
				t.Errorf("%s holds %q", name, s)
			}
		}
	}
	// What the bench played, seen where it should be.
	for _, want := range []struct{ where, stream, what string }{
		{"the application log", appLog.String(), `"msg":"webhook.failed"`},
		{"the application log", appLog.String(), `"msg":"hydra.request_failed"`},
		{"the application log", appLog.String(), `"msg":"http.panic"`},
		{"the application log", appLog.String(), `"msg":"skip.accepted"`},
		{"the application log", appLog.String(), `"msg":"logout.started"`},
		// The lines of debug (Q132), the sentinels not among them.
		{"the application log", appLog.String(), `"log_type":"app","event":"choice","step_before":0,"step_after":1,"outcome":"redirect","flow":"a","app":"sql"`},
		{"the application log", appLog.String(), `"log_type":"app","operation":"accept_login","status":200,`},
		{"the application log", appLog.String(), `"log_type":"app","kind":"consent","host":"127.0.0.1:`},
		{"the application log", appLog.String(), `"log_type":"app","id_token":["email"],"access_token":[],"conflicts":[],"flow":"a"`},
		{"the application log", appLog.String(), `"log_type":"app","id_token":["email"],"access_token":[],"dropped":[],"flow":"a"`},
		{"the audit log", auditLog.String(), `"msg":"auth.succeeded"`},
		{"Sentry", sentryBodies, "E1004"},
		{"Sentry", sentryBodies, "E1006"},
		{"the spans", spans, "webhook.call"},
		{"the headers to Hydra", string(hydraHeaders), "Traceparent"},
		{"the headers to the login webhook", loginHeaders, "X-Dispatcher-Signature"},
	} {
		if !strings.Contains(want.stream, want.what) {
			t.Errorf("no %s in %s", want.what, want.where)
		}
	}
}

// syncBuffer is a log the handlers write while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
