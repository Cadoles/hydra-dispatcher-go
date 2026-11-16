package front

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/remember"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/web"
)

const (
	base        = "http://dispatcher.hydra.test"
	hydraL      = "0c34aaee066148adbc0251024fee9bb4"
	hydraC      = "5f1d1b2c3a4e4f60a1b2c3d4e5f60718"
	logoutU     = "8a1d1b2c3a4e4f60a1b2c3d4e5f60718"
	sessionID   = "ba1ce6e4-e93b-401c-b6af-62703fe39df7"
	verifierURL = "http://public.hydra.test/oauth2/auth?login_verifier=v1"
	callbackURL = "http://oidc.client.test/auth/callback?code=c"
	rejectedURL = "http://oidc.client.test/auth/callback?error=access_denied"
	loggedOut   = "http://public.hydra.test/oauth2/sessions/logout?logout_verifier=v"
)

// fakeHydra is an admin API that keeps what it accepted: the consent request
// it serves carries the final login accept's subject and context.
type fakeHydra struct {
	mu          sync.Mutex
	consentSkip bool
	calls       []string
	errs        map[string]error
	accepted    *ory.AcceptOAuth2LoginRequest
	consent     *ory.AcceptOAuth2ConsentRequest
	// client replaces the client of the login and consent requests.
	client *ory.OAuth2Client
	// noLogoutRedirect accepts the logout without a redirect_to; rpInitiated
	// serves a logout request of a client.
	noLogoutRedirect bool
	rpInitiated      bool
	// login is the last login challenge read, which the consent request
	// names, as Hydra 2.1 does (Q34).
	login string
	// skip is Hydra's skip on the login requests, for alice.
	skip bool
}

func (h *fakeHydra) called(op string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, op)
	return h.errs[op]
}

func (h *fakeHydra) LoginRequest(_ context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	if err := h.called("get_login"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.login = challenge
	h.mu.Unlock()
	r := &ory.OAuth2LoginRequest{
		Challenge:      challenge,
		Client:         ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client"), ClientUri: ory.PtrString("http://oidc.client.test/")},
		RequestUrl:     "http://public.hydra.test/oauth2/auth?client_id=c1",
		RequestedScope: []string{"openid", "profile", "email", "groups"},
		SessionId:      ory.PtrString(sessionID),
	}
	if h.skip {
		r.Skip, r.Subject = true, "alice"
	}
	if h.client != nil {
		r.Client = *h.client
	}
	return r, nil
}

func (h *fakeHydra) AcceptLogin(_ context.Context, _ string, body ory.AcceptOAuth2LoginRequest) (string, error) {
	if err := h.called("accept_login"); err != nil {
		return "", err
	}
	h.accepted = &body
	return verifierURL, nil
}

func (h *fakeHydra) RejectLogin(context.Context, string, ory.RejectOAuth2Request) (string, error) {
	return rejectedURL, h.called("reject_login")
}

func (h *fakeHydra) ConsentRequest(_ context.Context, challenge string) (*ory.OAuth2ConsentRequest, error) {
	if err := h.called("get_consent"); err != nil {
		return nil, err
	}
	ctx, _ := json.Marshal(h.accepted.Context)
	client := &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client")}
	if h.client != nil {
		client = h.client
	}
	h.mu.Lock()
	login := h.login
	h.mu.Unlock()
	amr := h.accepted.Amr
	if amr == nil {
		amr = []string{}
	}
	return &ory.OAuth2ConsentRequest{
		Challenge:      challenge,
		LoginChallenge: ory.PtrString(login),
		Subject:        ory.PtrString(h.accepted.Subject),
		LoginSessionId: ory.PtrString(sessionID),
		Acr:            ory.PtrString(h.accepted.GetAcr()),
		Amr:            amr,
		RequestUrl:     ory.PtrString("http://public.hydra.test/oauth2/auth?client_id=c1"),
		Context:        json.RawMessage(ctx),
		RequestedScope: []string{"openid", "profile", "email", "groups"},
		Client:         client,
		Skip:           ory.PtrBool(h.consentSkip),
		OidcContext:    &ory.OAuth2ConsentRequestOpenIDConnectContext{UiLocales: []string{"en-GB"}},
	}, nil
}

func (h *fakeHydra) AcceptConsent(_ context.Context, _ string, body ory.AcceptOAuth2ConsentRequest) (string, error) {
	if err := h.called("accept_consent"); err != nil {
		return "", err
	}
	h.consent = &body
	return callbackURL, nil
}

func (h *fakeHydra) RejectConsent(context.Context, string, ory.RejectOAuth2Request) (string, error) {
	return rejectedURL, h.called("reject_consent")
}

func (h *fakeHydra) LogoutRequest(_ context.Context, challenge string) (*ory.OAuth2LogoutRequest, error) {
	if err := h.called("get_logout"); err != nil {
		return nil, err
	}
	r := &ory.OAuth2LogoutRequest{Challenge: ory.PtrString(challenge), Subject: ory.PtrString("alice"), Sid: ory.PtrString(sessionID), RequestUrl: ory.PtrString("/oauth2/sessions/logout"), RpInitiated: ory.PtrBool(h.rpInitiated)}
	if h.rpInitiated {
		r.Client = &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client")}
	}
	return r, nil
}

func (h *fakeHydra) AcceptLogout(context.Context, string) (string, error) {
	if h.noLogoutRedirect {
		return "", h.called("accept_logout")
	}
	return loggedOut, h.called("accept_logout")
}

func (h *fakeHydra) RejectLogout(context.Context, string) error { return h.called("reject_logout") }

func (h *fakeHydra) RevokeLoginSession(context.Context, string) error {
	return h.called("revoke_session")
}

type snapshots struct{ s *store.Snapshot }

func (s snapshots) Snapshot() *store.Snapshot { return s.s }

func testSnapshot() *store.Snapshot {
	apps := []store.App{
		{ID: "sql", LoginURL: "http://sql.hydra.test/login", ConsentURL: "http://sql.hydra.test/consent", Method: "pwd"},
		{ID: "2fa", LoginURL: "http://2fa.hydra.test/login", ConsentURL: "http://2fa.hydra.test/consent", Method: "otp"},
	}
	flows := []store.Flow{
		{ID: "hydra-sql", Enabled: true, Title: map[string]string{"fr": "Mot de passe", "en": "Password"},
			Description: map[string]string{"fr": "Identifiant et mot de passe"},
			Steps:       []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}}},
		{ID: "hydra-sql-2fa", Enabled: true, Title: map[string]string{"en": "Two factors"},
			Steps: []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}, {AppID: "2fa", Position: 2, SubjectCheck: "equal"}}},
	}
	return store.NewSnapshot(apps, flows, store.DefaultSettings())
}

// world is the dispatcher's pages over the engine, a browser and the apps.
type world struct {
	t       *testing.T
	h       http.Handler
	front   *Handler
	o       *flow.Orchestrator
	hydra   *fakeHydra
	cookies map[string]string
	logs    bytes.Buffer
}

type worldOptions struct {
	base       string
	showValues bool
	// snapshot replaces testSnapshot.
	snapshot *store.Snapshot
	// path is server.cookie_path, / when "".
	path string
	// lastFlow is ui.remember_last_flow, guard the failure limiter.
	lastFlow bool
	guard    func(http.Handler) http.Handler
	// theme is that of ui.theme_dir, nil for the embedded one; reload is
	// ui.reload.
	theme  *Theme
	reload bool
}

func (o worldOptions) cookiePath() string {
	if o.path == "" {
		return "/"
	}
	return o.path
}

func newWorld(t *testing.T, opts ...worldOptions) *world {
	t.Helper()
	opt := worldOptions{base: base}
	if len(opts) > 0 {
		opt = opts[0]
	}
	w := &world{t: t, hydra: &fakeHydra{consentSkip: true, errs: map[string]error{}}, cookies: map[string]string{}}
	mem := state.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	cfg := snapshots{testSnapshot()}
	if opt.snapshot != nil {
		cfg = snapshots{opt.snapshot}
	}
	w.o = &flow.Orchestrator{
		Store: mem, Config: cfg, Source: flow.Fallback{Hydra: w.hydra}, Hydra: w.hydra, Webhooks: flow.StubWebhooks{},
		BaseURL: opt.base, LoginConsentTTL: 30 * time.Minute, Keys: flow.Keys{[]byte("0123456789abcdef0123456789abcdef")},
	}
	logger := slog.New(httpx.LogHandler(slog.NewJSONHandler(&w.logs, nil)))
	memories, err := remember.New([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{RememberLastFlow: opt.lastFlow, Guard: opt.guard, Engine: w.o, Config: cfg, Remember: memories, BaseURL: opt.base, CookiePath: opt.cookiePath(), ShowValues: opt.showValues, Logger: logger,
		Theme: opt.theme, Reload: opt.reload})
	if err != nil {
		t.Fatal(err)
	}
	w.front = h
	mux := http.NewServeMux()
	h.Register(mux)
	w.h = httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), httpx.Trace(nil),
		httpx.SecurityHeaders(httpx.CSP(nil), strings.HasPrefix(opt.base, "https:"), false))
	return w
}

// do sends a request with the browser's cookies, and keeps those it sets.
// header holds name, value pairs.
func (w *world) do(method, target string, form url.Values, header ...string) *http.Response {
	w.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for name, value := range w.cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(w.cookies, c.Name)
			continue
		}
		w.cookies[c.Name] = c.Value
	}
	return resp
}

func (w *world) csrf() string { return w.cookies["dispatcher_flow_csrf"] }

func text(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func location(t *testing.T, resp *http.Response, status int) *url.URL {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", resp.StatusCode, status, text(t, resp))
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// app plays a login app on its step through the engine: read, accept, and
// the same for its consent once the browser is back, claims in its id_token.
func (w *world) app(login *url.URL, subject, claims string) {
	w.t.Helper()
	w.appSession(login, subject, `{"id_token":`+claims+`}`)
}

// appSession is app with the consent's whole session.
func (w *world) appSession(login *url.URL, subject, session string) {
	w.t.Helper()
	ctx := context.Background()
	anyApp := func(store.App) bool { return true }
	c := login.Query().Get("login_challenge")
	for _, call := range []flow.AppCall{
		{Op: flow.AppGetLogin, Challenge: c, Caller: anyApp},
		{Op: flow.AppAcceptLogin, Challenge: c, Caller: anyApp, Body: json.RawMessage(`{"subject":"` + subject + `","context":{"email":"` + subject + `"}}`)},
	} {
		if r := w.o.Handle(ctx, call).Response; r.Status != http.StatusOK {
			w.t.Fatalf("%v: %+v", call.Op, r)
		}
	}
	consent := location(w.t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	cc := consent.Query().Get("consent_challenge")
	for _, call := range []flow.AppCall{
		{Op: flow.AppGetConsent, Challenge: cc, Caller: anyApp},
		{Op: flow.AppAcceptConsent, Challenge: cc, Caller: anyApp, Body: json.RawMessage(`{"session":` + session + `}`)},
	} {
		if r := w.o.Handle(ctx, call).Response; r.Status != http.StatusOK {
			w.t.Fatalf("%v: %+v", call.Op, r)
		}
	}
}

var sameOrigin = []string{"Sec-Fetch-Site", "same-origin"}

// choose loads the choice page and posts flow, returning the first app's
// login URL.
func (w *world) choose(flowID string) *url.URL {
	w.t.Helper()
	page := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	if page.StatusCode != http.StatusOK {
		w.t.Fatalf("GET /: %d %s", page.StatusCode, text(w.t, page))
	}
	return location(w.t, w.do(http.MethodPost, "/", url.Values{"flow": {flowID}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...), http.StatusSeeOther)
}

// B3: the calls to Hydra of an authentication through the pages, in
// fallback (Stratégie de tests).
func TestHydraCalls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flow   string
		screen bool
		calls  []string
	}{
		{"two steps, choice page, consent skipped", "hydra-sql-2fa", false,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "accept_consent"}},
		{"two steps, consent screen shown", "hydra-sql-2fa", true,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "get_consent", "accept_consent"}},
		{"one step", "hydra-sql", false,
			[]string{"get_login", "accept_login", "get_consent", "accept_consent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.hydra.consentSkip = !tc.screen
			step := w.choose(tc.flow)
			if step.Host != "sql.hydra.test" {
				t.Fatalf("A5: the choice goes straight to the first app: %s", step)
			}
			w.app(step, "alice", `{"email":"alice@example.org","name":"Alice"}`)
			if tc.flow == "hydra-sql-2fa" {
				step = location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
				w.app(step, "alice", `{"email":null}`)
			}
			if u := location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther); u.String() != verifierURL {
				t.Fatalf("final accept: %s", u)
			}
			resp := w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
			if tc.screen {
				page := text(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("consent screen: %d %s", resp.StatusCode, page)
				}
				resp = w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {w.csrf()}, "claims_print": {printIn(t, page)}, "action": {"accept"}}, sameOrigin...)
			}
			if u := location(t, resp, http.StatusSeeOther); u.String() != callbackURL {
				t.Fatalf("consent: %s", u)
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v; want %v", w.hydra.calls, tc.calls)
			}
			// A2: the email of the first step reaches the id_token.
			if got, _ := json.Marshal(w.hydra.consent.Session.IdToken); !strings.Contains(string(got), `"email":"alice@example.org"`) {
				t.Errorf("id_token %s", got)
			}
			// After the end, E1002 without a call (T1, I9).
			n := len(w.hydra.calls)
			if resp := w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil); resp.StatusCode != http.StatusBadRequest || len(w.hydra.calls) != n ||
				!strings.Contains(text(t, resp), "E1002") {
				t.Errorf("RA6: %d", resp.StatusCode)
			}
		})
	}
}

// The choice page: the client, the flows in the locale, the form, the CSRF
// cookie (A4) and the headers of every page.
func TestChoicePage(t *testing.T) {
	w := newWorld(t)
	resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	body := text(t, resp)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	for _, want := range []string{
		`<html lang="fr">`, "Choisissez votre mode de connexion", "pour vous connecter à Test Client",
		`value="hydra-sql"`, "Mot de passe", "Identifiant et mot de passe",
		`value="hydra-sql-2fa"`, "Two factors", // no French title: the first one
		`name="login_challenge" value="` + hydraL + `"`, `name="csrf_token" value="` + w.csrf() + `"`,
		`<form method="post" action="/?login_challenge=` + hydraL + `">`,
		`formaction="/locale/en"`, `/static/base.css?v=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page without %q:\n%s", want, body)
		}
	}
	var csrf *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "dispatcher_flow_csrf" {
			csrf = c
		}
	}
	if csrf == nil || len(csrf.Value) != 64 || !csrf.HttpOnly || csrf.SameSite != http.SameSiteLaxMode || csrf.Secure || csrf.Path != "/" || csrf.MaxAge != 3600 {
		t.Errorf("A4, cookie %+v", csrf)
	}
	securityHeaders(t, "choice page", resp)
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS in HTTP")
	}
	// The language: _locale, then the cookie.
	if body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=en", nil)); !strings.Contains(body, `<html lang="en">`) || !strings.Contains(body, "Choose how to sign in") || !strings.Contains(body, ">Password<") {
		t.Errorf("_locale=en:\n%s", body)
	}
	// POS-2: a flow not offered, the page again with a message.
	resp = w.do(http.MethodPost, "/", url.Values{"flow": {"nope"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...)
	if body := text(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Ce mode de connexion n&#39;est pas proposé") {
		t.Errorf("POS-2: %d\n%s", resp.StatusCode, body)
	}
}

// The forms are checked for their origin (POS-9, CST-21) and their token.
func TestForms(t *testing.T) {
	w := newWorld(t)
	w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	form := url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}
	for _, header := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
		{"Sec-Fetch-Site", "SAME-ORIGIN"},
		{"Origin", "http://evil.example"},
		{"Origin", "null"},     // a sandboxed frame, a data: URL
		{"Origin", base + "/"}, // not an origin
		nil,                    // neither header
	} {
		if resp := w.do(http.MethodPost, "/", form, header...); resp.StatusCode != http.StatusForbidden || !strings.Contains(text(t, resp), "E1008") {
			t.Errorf("POS-9 %v: %d", header, resp.StatusCode)
		}
	}
	if resp := w.do(http.MethodPost, "/", form, "Origin", base); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Origin of the dispatcher: %d", resp.StatusCode)
	}
	// none: typed in, a bookmark (Sécurité, protection des formulaires).
	if resp := w.do(http.MethodPost, "/", form, "Sec-Fetch-Site", "none"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Sec-Fetch-Site none: %d", resp.StatusCode)
	}
	// A body past 64 KiB is no form.
	big := url.Values{"flow": {strings.Repeat("a", maxForm)}}
	if resp := w.do(http.MethodPost, "/", big, sameOrigin...); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Errorf("big form: %d", resp.StatusCode)
	}
	if resp := w.do(http.MethodPost, "/consent", big, sameOrigin...); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Errorf("big consent form: %d", resp.StatusCode)
	}
	if resp := w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}}, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("CST-21: %d", resp.StatusCode)
	}
}

var traceID = regexp.MustCompile(`[0-9a-f]{32}`)

// The error pages: the code's status, its message, the trace id, the link
// to the client, Retry-After when Hydra is saturated.
func TestErrorPages(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		name, target string
		status       int
		code, text   string
	}{
		{"ENT-13", "/", http.StatusBadRequest, "E1001", "Le lien de connexion n&#39;est pas valide."},
		{"BCL-15", "/oauth2/auth", http.StatusBadRequest, "E1001", ""},
		{"BCL-1", "/oauth2/auth?ref=" + flow.Ref("unknown"), http.StatusBadRequest, "E1002", "Votre connexion a expiré"},
		{"CST-1", "/consent", http.StatusBadRequest, "E1001", ""},
	} {
		resp := w.do(http.MethodGet, tc.target, nil)
		body := text(t, resp)
		if resp.StatusCode != tc.status || !strings.Contains(body, tc.code) || !strings.Contains(body, tc.text) ||
			!strings.Contains(body, resp.Header.Get("X-Trace-ID")) || !traceID.MatchString(resp.Header.Get("X-Trace-ID")) {
			t.Errorf("%s: %d\n%s", tc.name, resp.StatusCode, body)
		}
	}
	// ENT-14 saturated: 503 with Retry-After.
	w2 := newWorld(t)
	w2.hydra.errs["get_login"] = fmt.Errorf("login request: %w", hydra.ErrOverloaded)
	resp := w2.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || !strings.Contains(text(t, resp), "E1004") {
		t.Errorf("saturated: %d %v", resp.StatusCode, resp.Header)
	}
	w2.hydra.errs["get_login"] = errors.New("connection refused")
	if resp := w2.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Retry-After") != "" {
		t.Errorf("down: %d", resp.StatusCode)
	}
}

// E1002 links to the client once the flow is finished (RA6).
func TestErrorLink(t *testing.T) {
	w := newWorld(t)
	step := w.choose("hydra-sql")
	r := w.o.Handle(context.Background(), flow.AppCall{Op: flow.AppRejectLogin, Challenge: step.Query().Get("login_challenge"),
		Caller: func(store.App) bool { return true }, Body: json.RawMessage(`{"error":"access_denied"}`)}).Response
	if r.Status != http.StatusOK {
		t.Fatalf("EMU-16: %+v", r)
	}
	resp := w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil)
	if body := text(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, `<a href="http://oidc.client.test/">`) {
		t.Errorf("BCL-2: %d\n%s", resp.StatusCode, body)
	}
}

// The consent screen: the scopes asked with the claims they cover, the
// other claims, the values with consent.show_values only; its language from
// the consent request's ui_locales. What is shown is what is sent: the
// access token's claims and the subject too.
func TestConsentScreen(t *testing.T) {
	for _, show := range []bool{false, true} {
		w := newWorld(t, worldOptions{base: base, showValues: show})
		w.hydra.consentSkip = false
		w.appSession(w.choose("hydra-sql"), "alice", `{"id_token":{"email":"alice@example.org","name":"Alice","groups":["staff"]},`+
			`"access_token":{"roles":["admin"],"email":"alice@corp.example"}}`)
		location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
		resp := w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
		body := text(t, resp)
		for _, want := range []string{
			`<html lang="en">`, "Test Client asks for access to the following data:",
			"Identify you", "Your profile", "Full name", "Your email address", "Email address",
			"Permission “groups”", "Other data", "groups", "Technical identifier", "roles",
			`<form method="post" action="/consent?consent_challenge=` + hydraC + `">`,
			`name="consent_challenge" value="` + hydraC + `"`, `name="action" value="accept"`, `name="action" value="reject"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("show_values %v, no %q:\n%s", show, want, body)
			}
		}
		if strings.Contains(body, "alice@example.org") != show {
			t.Errorf("show_values %v: the email shown %v", show, !show)
		}
		// Both tokens' values, the subject's, the access token's claim.
		for _, value := range []string{"alice@example.org · alice@corp.example", `<span class="value">alice</span>`, `<span class="value">[&#34;admin&#34;]</span>`} {
			if strings.Contains(body, value) != show {
				t.Errorf("show_values %v: %s shown %v", show, value, !show)
			}
		}
		// A key pressed from the page before must not accept.
		if strings.Contains(body, "autofocus") {
			t.Error("a button of the consent has the focus")
		}
		// CST-15: refused.
		resp = w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {w.csrf()}, "action": {"reject"}}, sameOrigin...)
		if u := location(t, resp, http.StatusSeeOther); u.String() != rejectedURL {
			t.Errorf("CST-15: %s", u)
		}
	}
}

// The note of logout the browser holds, opened.
func (w *world) note(t *testing.T) *flow.Remembered {
	t.Helper()
	return w.front.o.Remember.Open(w.cookies["dispatcher_remember"]).Content
}

const logoutPath = "/logout?logout_challenge=" + logoutU

func TestLogoutConfirmation(t *testing.T) {
	w := newWorld(t)
	w.cookies["dispatcher_remember"] = "1.memory.of-another-session"
	resp := w.do(http.MethodGet, logoutPath, nil)
	body := text(t, resp)
	// LGO-6: a page, its form on the URL of the page, nothing cleared.
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `action="/logout?logout_challenge=`+logoutU+`"`) ||
		!strings.Contains(body, `name="logout_challenge" value="`+logoutU+`"`) || !strings.Contains(body, `name="csrf_token" value="`+w.csrf()+`"`) ||
		w.csrf() == "" || !strings.Contains(body, `value="accept"`) {
		t.Fatalf("LGO-6: %d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `name="return" value="/logout?logout_challenge=`+logoutU+`"`) {
		t.Errorf("the page goes back to itself from the change of language:\n%s", body)
	}
	if c := setCookie(resp, "dispatcher_remember"); c != nil {
		t.Errorf("WRT-4, at the confirmation: %+v", c)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", resp.Header.Get("Cache-Control"))
	}

	// LGO-9, LGO-10: from another site, without the token: nothing reaches Hydra.
	calls := len(w.hydra.calls)
	for _, tc := range []struct {
		name   string
		form   url.Values
		header []string
	}{
		{"another site", url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"accept"}}, []string{"Sec-Fetch-Site", "cross-site"}},
		{"another origin", url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"accept"}}, []string{"Origin", "http://evil.example"}},
		{"neither", url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"accept"}}, nil},
		{"no token", url.Values{"logout_challenge": {logoutU}, "action": {"accept"}}, sameOrigin},
		{"another token", url.Values{"logout_challenge": {logoutU}, "csrf_token": {strings.Repeat("0", 64)}, "action": {"accept"}}, sameOrigin},
	} {
		resp := w.do(http.MethodPost, logoutPath, tc.form, tc.header...)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(text(t, resp), "E1008") || len(w.hydra.calls) != calls {
			t.Errorf("%s: %d, calls %v", tc.name, resp.StatusCode, w.hydra.calls)
		}
	}
	// LGO-9: a form beyond 64 KiB.
	if resp := w.do(http.MethodPost, logoutPath, url.Values{"x": {strings.Repeat("a", 64<<10)}}, sameOrigin...); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Errorf("a large form: %d", resp.StatusCode)
	}

	// LGO-11, DEP-1 here, no app having a logout_url: the note, the verifier.
	resp = w.do(http.MethodPost, logoutPath, url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"accept"}}, sameOrigin...)
	if u := location(t, resp, http.StatusSeeOther); u.String() != loggedOut {
		t.Errorf("LGO-11: %s", u)
	}
	c := setCookie(resp, "dispatcher_remember")
	if c == nil || c.MaxAge <= 0 || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("WRT-4: %+v", c)
	}
	if n := w.note(t); n == nil || !n.Lo || n.SID != sessionID || n.Sub != "alice" || n.IDT != nil {
		t.Errorf("WRT-4, the note: %+v", n)
	}
	if want := []string{"get_logout", "get_logout", "accept_logout"}; !slices.Equal(w.hydra.calls, want) {
		t.Errorf("calls %v, want %v", w.hydra.calls, want)
	}
}

// LGO-18, Q62, Q66: no page answers a browser's preload, each of these GET able to act
// without a click: SKP-12 delete a session, SKP-1 and SKC-1 accept, SUI-5 give the
// verifier. The first read is not made, nor a cookie set; the visit goes on. A HEAD with
// the header is a preload: LGO-18 comes before LGO-17.
func TestPagesPreloaded(t *testing.T) {
	ref := strings.Repeat("a", 20)
	for _, target := range []string{
		"/?login_challenge=" + strings.Repeat("b", 32),
		"/?ref=" + ref,
		"/oauth2/auth?ref=" + ref,
		"/consent?consent_challenge=" + strings.Repeat("c", 32),
		logoutPath,
		"/logout/next?ref=" + ref,
	} {
		w := newWorld(t)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			resp := w.do(method, target, nil, "Sec-Purpose", "prefetch")
			if resp.StatusCode != http.StatusTooEarly || text(t, resp) != "" || len(resp.Cookies()) != 0 || len(w.hydra.calls) != 0 {
				t.Errorf("%s %s: %d, cookies %v, calls %v", method, target, resp.StatusCode, resp.Cookies(), w.hydra.calls)
			}
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: Cache-Control %q", method, target, resp.Header.Get("Cache-Control"))
			}
		}
		w.hydra.errs["get_consent"] = &hydra.RequestError{Op: "get_consent_request", Status: http.StatusNotFound}
		if resp := w.do(http.MethodGet, target, nil); resp.StatusCode == http.StatusTooEarly {
			t.Errorf("%s, the visit: %d", target, resp.StatusCode)
		}
	}
}

// LGO-17, LGO-18, with what the pages would do of a visit: a preload or a HEAD after a
// chain stopped deletes nothing (SKP-12), of a session remembered accepts nothing
// (SKP-1, SKC-1); the visit does.
func TestPagesActOnVisitsOnly(t *testing.T) {
	sealed := func(w *world, m *flow.Remembered) string {
		v, err := w.front.o.Remember.Seal(m)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	noVisit := []struct {
		name, method string
		header       []string
		status       int
	}{
		{"a preload", http.MethodGet, []string{"Sec-Purpose", "prefetch"}, http.StatusTooEarly},
		{"a HEAD", http.MethodHead, nil, http.StatusOK},
	}
	t.Run("SKP-12", func(t *testing.T) {
		w := newWorld(t)
		w.hydra.skip = true
		w.cookies["dispatcher_remember"] = sealed(w, &flow.Remembered{V: flow.RememberedFormat, SID: sessionID, Sub: "alice", Lo: true, IAT: time.Now().Unix()})
		target := "/?login_challenge=" + hydraL2
		for _, tc := range noVisit {
			if resp := w.do(tc.method, target, nil, tc.header...); resp.StatusCode != tc.status || len(w.hydra.calls) != 0 {
				t.Errorf("%s: %d, calls %v", tc.name, resp.StatusCode, w.hydra.calls)
			}
		}
		if location(t, w.do(http.MethodGet, target, nil), http.StatusSeeOther); !slices.Contains(w.hydra.calls, "revoke_session") {
			t.Errorf("the visit: calls %v", w.hydra.calls)
		}
	})
	t.Run("SKP-1, SKC-1", func(t *testing.T) {
		w := newWorld(t)
		w.remembered(`{"email":"alice@example.org"}`)
		w.hydra.skip, w.hydra.consentSkip, w.hydra.calls = true, true, nil
		for _, target := range []string{"/?login_challenge=" + hydraL2, "/consent?consent_challenge=" + hydraC} {
			for _, tc := range noVisit {
				if resp := w.do(tc.method, target, nil, tc.header...); resp.StatusCode != tc.status || len(w.hydra.calls) != 0 {
					t.Errorf("%s of %s: %d, calls %v", tc.name, target, resp.StatusCode, w.hydra.calls)
				}
			}
		}
		location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther)
		location(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), http.StatusSeeOther)
		if !slices.Equal(w.hydra.calls, []string{"get_login", "accept_login", "get_consent", "accept_consent"}) {
			t.Errorf("the visits: calls %v", w.hydra.calls)
		}
	})
}

// LGO-18 stops the pages in GET: neither a form nor a static file, which a page
// prerendered loads with the same header.
func TestPreloadStopsOnlyThePages(t *testing.T) {
	w := newWorld(t)
	if resp := w.do(http.MethodGet, "/static/base.css", nil, "Sec-Purpose", "prefetch;prerender"); resp.StatusCode != http.StatusOK {
		t.Errorf("a static file: %d", resp.StatusCode)
	}
	for _, target := range []string{"/", "/consent", "/logout"} {
		if resp := w.do(http.MethodPost, target, url.Values{}, "Sec-Purpose", "prefetch"); resp.StatusCode == http.StatusTooEarly {
			t.Errorf("POST %s: %d", target, resp.StatusCode)
		}
	}
}

// LGO-19, Q65: what another site's page loads for itself asks the question, which no one
// answers there: nothing leaves. A visit from elsewhere leaves, as a subrequest of the
// same site, which the memory cookie reaches (LGO-7).
func TestLogoutSubrequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		site  string
		dest  string
		asked bool
	}{
		{"an image of another site", "cross-site", "image", true},
		{"an iframe of another site", "cross-site", "iframe", true},
		{"a fetch of another site", "cross-site", "empty", true},
		{"a script of another site", "cross-site", "script", true},
		{"a link followed from another site", "cross-site", "document", false},
		{"an image of the same site", "same-site", "image", false},
		{"an iframe of the same origin", "same-origin", "iframe", false},
		{"typed in", "none", "document", false},
		{"another site, no destination", "cross-site", "", false},
		{"a destination, no site", "", "image", false},
		{"no metadata, HTTP", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.hydra.rpInitiated = true
			var header []string
			if tc.site != "" {
				header = append(header, "Sec-Fetch-Site", tc.site)
			}
			if tc.dest != "" {
				header = append(header, "Sec-Fetch-Dest", tc.dest)
			}
			resp := w.do(http.MethodGet, logoutPath, nil, header...)
			if !tc.asked {
				if u := location(t, resp, http.StatusSeeOther); u.String() != loggedOut || !slices.Contains(w.hydra.calls, "accept_logout") || w.note(t) == nil {
					t.Errorf("it should leave: %s, calls %v", u, w.hydra.calls)
				}
				return
			}
			page := text(t, resp)
			if resp.StatusCode != http.StatusOK || !strings.Contains(page, `name="logout_challenge"`) || !slices.Equal(w.hydra.calls, []string{"get_logout"}) || w.note(t) != nil {
				t.Errorf("the question: %d, calls %v, note %+v", resp.StatusCode, w.hydra.calls, w.note(t))
			}
		})
	}
}

// LGO-18, Q59: a browser's preload has no effect, whatever the logout request. A
// HEAD aside, the first request a client's link makes runs the whole chain.
func TestLogoutPreloaded(t *testing.T) {
	for _, header := range [][]string{
		{"Sec-Purpose", "prefetch"},
		{"Sec-Purpose", "prefetch;prerender"},
		{"Sec-Purpose", "prefetch;anonymous-client-ip"},
		{"Sec-Purpose", "prerender"},
		{"Purpose", "prefetch"},
	} {
		w := newWorld(t)
		w.hydra.rpInitiated = true
		resp := w.do(http.MethodGet, logoutPath, nil, header...)
		if resp.StatusCode != http.StatusTooEarly || text(t, resp) != "" || len(resp.Cookies()) != 0 || len(w.hydra.calls) != 0 {
			t.Errorf("%v: %d, cookies %v, calls %v", header, resp.StatusCode, resp.Cookies(), w.hydra.calls)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%v: Cache-Control %q", header, resp.Header.Get("Cache-Control"))
		}
		// The link followed: the logout leaves.
		resp = w.do(http.MethodGet, logoutPath, nil)
		if u := location(t, resp, http.StatusSeeOther); u.String() != loggedOut || w.note(t) == nil {
			t.Errorf("%v, then the visit: %s", header, u)
		}
	}
	w := newWorld(t)
	w.hydra.rpInitiated = true
	if resp := w.do(http.MethodGet, logoutPath, nil, "Purpose", "other"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("another purpose: %d", resp.StatusCode)
	}
}

// The handlers give the engine the cookie they read: the question of LGO-7 on a
// GET, the apps of LST-1 on a POST, which keeps them in the note.
func TestLogoutMemory(t *testing.T) {
	sealed := func(w *world, sid, sub string, ap ...string) string {
		v, err := w.front.o.Remember.Seal(&flow.Remembered{V: flow.RememberedFormat, SID: sid, Sub: sub, AP: ap, IAT: time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	w := newWorld(t)
	w.hydra.rpInitiated = true
	w.cookies["dispatcher_remember"] = sealed(w, "another-session", "bob")
	if resp := w.do(http.MethodGet, logoutPath, nil); !strings.Contains(text(t, resp), "autre session") || resp.StatusCode != http.StatusOK {
		t.Errorf("LGO-7: %d", resp.StatusCode)
	}
	snap := testSnapshot()
	apps := slices.Clone(snap.Apps)
	for i := range apps {
		apps[i].LogoutURL = "http://" + apps[i].ID + ".hydra.test/logout"
	}
	w = newWorld(t, worldOptions{base: base, snapshot: store.NewSnapshot(apps, snap.Flows, snap.Settings)})
	w.do(http.MethodGet, logoutPath, nil)
	w.cookies["dispatcher_remember"] = sealed(w, sessionID, "alice", "sql")
	resp := w.do(http.MethodPost, logoutPath, url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"accept"}}, sameOrigin...)
	if u := location(t, resp, http.StatusSeeOther); u.Host != "sql.hydra.test" {
		t.Errorf("LST-1, the app the cookie names: %s", u)
	}
	if n := w.note(t); n == nil || !slices.Equal(n.AP, []string{"sql"}) {
		t.Errorf("WRT-4: %+v", n)
	}
}

type stubEngine struct{ res flow.Result }

func (e stubEngine) Handle(context.Context, flow.Event) flow.Result { return e.res }

// respond on an error page: the note of DEP-7, and the way out of FIN-3 (Q60).
func TestErrorPageAnswers(t *testing.T) {
	serve := func(t *testing.T, res flow.Result) (*httptest.ResponseRecorder, *world) {
		t.Helper()
		w := newWorld(t)
		o := w.front.o
		o.Engine = stubEngine{res}
		h, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		h.Register(mux)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, logoutPath, nil))
		return rec, w
	}
	t.Run("DEP-7: E1002 and the note", func(t *testing.T) {
		rec, _ := serve(t, flow.Result{Response: flow.Response{Kind: flow.ErrorPage, Code: flow.E1002, Remember: &flow.Remembered{V: flow.RememberedFormat, SID: sessionID, Sub: "alice", Lo: true}}})
		if rec.Code != http.StatusBadRequest || setCookie(rec.Result(), "dispatcher_remember") == nil {
			t.Errorf("%d, cookies %v", rec.Code, rec.Result().Cookies())
		}
	})
	t.Run("FIN-3: the way out", func(t *testing.T) {
		const out = "http://public.hydra.test/oauth2/sessions/logout"
		rec, _ := serve(t, flow.Result{Response: flow.Response{Kind: flow.ErrorPage, Code: flow.E1003, SignOut: out}})
		if body := rec.Body.String(); rec.Code != http.StatusBadRequest || !strings.Contains(body, `<a href="`+out+`">`) || !strings.Contains(body, "Se déconnecter de la session en cours") {
			t.Errorf("%d\n%s", rec.Code, body)
		}
		rec, _ = serve(t, flow.Result{Response: flow.Response{Kind: flow.ErrorPage, Code: flow.E1003}})
		if strings.Contains(rec.Body.String(), "Se déconnecter") {
			t.Errorf("a link without a way out:\n%s", rec.Body.String())
		}
	})
}

func TestLogoutRefused(t *testing.T) {
	w := newWorld(t)
	w.do(http.MethodGet, logoutPath, nil)
	w.cookies["dispatcher_remember"] = "1.memory.of-this-session"
	form := url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"reject"}}
	resp := w.do(http.MethodPost, logoutPath, form, sameOrigin...)
	body := text(t, resp)
	// LGO-12: the same template, no form, no switcher: it has no URL to go back to.
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Vous restez connecté") || strings.Contains(body, "<form") {
		t.Errorf("LGO-12: %d\n%s", resp.StatusCode, body)
	}
	if setCookie(resp, "dispatcher_remember") != nil || !slices.Contains(w.hydra.calls, "reject_logout") {
		t.Errorf("cookie written, or no reject: %v", w.hydra.calls)
	}
	// LGO-15, LGO-16, on any other button; LGO-14 is the engine's.
	for _, tc := range []struct {
		name string
		err  error
		text string
	}{
		{"LGO-15", &hydra.RequestError{Status: 404}, "Vous restez connecté"},
		{"LGO-16", &hydra.RequestError{Status: 410}, "Vous êtes déjà déconnecté"},
	} {
		w := newWorld(t)
		w.do(http.MethodGet, logoutPath, nil)
		w.hydra.errs["get_logout"] = tc.err
		resp := w.do(http.MethodPost, logoutPath, url.Values{"logout_challenge": {logoutU}, "csrf_token": {w.csrf()}, "action": {"other"}}, sameOrigin...)
		if body := text(t, resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, tc.text) || strings.Contains(body, "<form") {
			t.Errorf("%s: %d\n%s", tc.name, resp.StatusCode, body)
		}
	}
}

// LGO-1 to LGO-4 on the pages, HEAD (LGO-17), and a client's demand (LGO-8).
func TestLogoutPages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		err    error
		status int
		code   string
	}{
		{"LGO-1 no challenge", "/logout", nil, http.StatusBadRequest, "E1001"},
		{"LGO-1 illegible", "/logout?logout_challenge=a%2Fb", nil, http.StatusBadRequest, "E1001"},
		{"LGO-2 unknown", logoutPath, &hydra.RequestError{Status: 404}, http.StatusBadRequest, "E1001"},
		{"LGO-3 gone", logoutPath, &hydra.RequestError{Status: 410}, http.StatusBadRequest, "E1002"},
		{"LGO-4 refused", logoutPath, &hydra.RequestError{Status: 400}, http.StatusInternalServerError, "E1007"},
		{"LGO-4 down", logoutPath, errors.New("connection refused"), http.StatusBadGateway, "E1004"},
	} {
		w := newWorld(t)
		w.hydra.errs["get_logout"] = tc.err
		w.cookies["dispatcher_remember"] = "1.memory.of-another-session"
		resp := w.do(http.MethodGet, tc.target, nil)
		if body := text(t, resp); resp.StatusCode != tc.status || !strings.Contains(body, tc.code) || setCookie(resp, "dispatcher_remember") != nil {
			t.Errorf("%s: %d\n%s", tc.name, resp.StatusCode, body)
		}
	}
	// LGO-8: no page, the accept at once; the note and the verifier.
	w := newWorld(t)
	w.hydra.rpInitiated = true
	resp := w.do(http.MethodGet, logoutPath, nil)
	if u := location(t, resp, http.StatusSeeOther); u.String() != loggedOut || w.note(t) == nil || !w.note(t).Lo {
		t.Errorf("LGO-8: %s, note %+v", u, w.note(t))
	}
	// LGO-13: the accept down: an error page, no note.
	w = newWorld(t)
	w.hydra.rpInitiated = true
	w.hydra.errs["accept_logout"] = errors.New("connection refused")
	resp = w.do(http.MethodGet, logoutPath, nil)
	if resp.StatusCode != http.StatusBadGateway || setCookie(resp, "dispatcher_remember") != nil {
		t.Errorf("accept down: %d", resp.StatusCode)
	}
	// LGO-17: a HEAD, which the GET pattern covers: no call, no write, no cookie, on
	// each page in GET (Q66).
	w = newWorld(t)
	w.hydra.rpInitiated = true
	for _, target := range []string{
		logoutPath, "/logout", "/logout/next?ref=" + strings.Repeat("a", 20), "/logout/next",
		"/", "/?login_challenge=" + hydraL, "/?ref=" + strings.Repeat("a", 20), "/oauth2/auth?ref=" + strings.Repeat("a", 20), "/consent?consent_challenge=" + hydraC,
	} {
		resp := w.do(http.MethodHead, target, nil)
		if resp.StatusCode != http.StatusOK || text(t, resp) != "" || len(resp.Cookies()) != 0 || len(w.hydra.calls) != 0 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("HEAD %s: %d, cookies %v, calls %v, Cache-Control %q", target, resp.StatusCode, resp.Cookies(), w.hydra.calls, resp.Header.Get("Cache-Control"))
		}
	}
	// SUI-1, SUI-2.
	w = newWorld(t)
	if resp := w.do(http.MethodGet, "/logout/next?ref=nope", nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Errorf("SUI-1: %d", resp.StatusCode)
	}
	if resp := w.do(http.MethodGet, "/logout/next?ref="+strings.Repeat("a", 20), nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1002") {
		t.Errorf("SUI-2: %d", resp.StatusCode)
	}
}

// DEP-2, SUI-3, SUI-5, through the pages: the note, each logout_url, the verifier.
func TestLogoutChain(t *testing.T) {
	snap := testSnapshot()
	apps := slices.Clone(snap.Apps)
	for i := range apps {
		apps[i].LogoutURL = "http://" + apps[i].ID + ".hydra.test/logout"
	}
	w := newWorld(t, worldOptions{base: base, snapshot: store.NewSnapshot(apps, snap.Flows, snap.Settings)})
	w.hydra.rpInitiated = true
	resp := w.do(http.MethodGet, logoutPath, nil)
	u := location(t, resp, http.StatusSeeOther)
	if u.Host != "2fa.hydra.test" || u.Query().Get("logout_challenge") == "" || !w.note(t).Lo {
		t.Fatalf("DEP-2: %s, note %+v", u, w.note(t))
	}
	ref := w.o.Keys.LogoutRef(sessionID)
	for _, id := range []string{"2fa", "sql"} {
		c := w.o.Keys.LogoutChallenge(ref, map[string]int{"2fa": 0, "sql": 1}[id], id)
		if r := w.o.Handle(context.Background(), flow.AppCall{Op: flow.AppAcceptLogout, Challenge: c, Caller: func(a store.App) bool { return a.ID == id }}); r.Response.Status != http.StatusOK {
			t.Fatalf("LEM-7 %s: %+v", id, r.Response)
		}
		resp = w.do(http.MethodGet, "/logout/next?ref="+ref, nil)
		next := location(t, resp, http.StatusSeeOther)
		want := map[string]string{"2fa": "sql.hydra.test", "sql": "public.hydra.test"}[id]
		if next.Host != want {
			t.Errorf("after %s: %s", id, next)
		}
	}
}

func TestLocale(t *testing.T) {
	w := newWorld(t)
	page := base + "/?login_challenge=" + hydraL
	resp := w.do(http.MethodPost, "/locale/en", url.Values{}, "Sec-Fetch-Site", "same-origin", "Referer", page)
	if u := location(t, resp, http.StatusSeeOther); u.String() != page || w.cookies["dispatcher_locale"] != "en" {
		t.Errorf("back to %s, cookie %q", u, w.cookies["dispatcher_locale"])
	}
	if body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)); !strings.Contains(body, "Choose how to sign in") {
		t.Errorf("the cookie's locale:\n%s", body)
	}
	// A locale without catalog sets nothing; a Referer elsewhere is not
	// followed.
	resp = w.do(http.MethodPost, "/locale/de", url.Values{}, "Sec-Fetch-Site", "same-origin", "Referer", "http://evil.example/")
	if u := location(t, resp, http.StatusSeeOther); u.String() != base+"/" || w.cookies["dispatcher_locale"] != "en" {
		t.Errorf("de from elsewhere: %s, cookie %q", u, w.cookies["dispatcher_locale"])
	}
	if resp := w.do(http.MethodPost, "/locale/fr", url.Values{}, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site: %d", resp.StatusCode)
	}
}

func TestStatic(t *testing.T) {
	w := newWorld(t)
	body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))
	asset := regexp.MustCompile(`/static/base\.css\?v=[0-9a-f]{12}`).FindString(body)
	if asset == "" {
		t.Fatalf("no asset URL:\n%s", body)
	}
	resp := w.do(http.MethodGet, asset, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") || !strings.Contains(text(t, resp), "--color-accent") {
		t.Errorf("%s: %d %v", asset, resp.StatusCode, resp.Header)
	}
	if resp := w.do(http.MethodGet, "/static/base.css?v=old", nil); resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("stale hash: %v", resp.Header)
	}
	if resp := w.do(http.MethodGet, "/static/nope.css", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown: %d", resp.StatusCode)
	}
}

// In HTTPS with the path /, the cookies take the __Host- prefix and Secure,
// and the pages get HSTS (Sécurité, durcissement 6).
func TestHTTPS(t *testing.T) {
	w := newWorld(t, worldOptions{base: "https://dispatcher.example"})
	resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	var csrf *http.Cookie
	for _, c := range resp.Cookies() {
		csrf = c
	}
	if csrf == nil || csrf.Name != "__Host-dispatcher_flow_csrf" || !csrf.Secure || resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("cookie %+v, HSTS %q", csrf, resp.Header.Get("Strict-Transport-Security"))
	}
	// The prefixed cookie is the one read back.
	if resp := w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.cookies["__Host-dispatcher_flow_csrf"]}}, "Origin", "https://dispatcher.example"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("POST with the prefixed cookie: %d %s", resp.StatusCode, text(t, resp))
	}
}

// securityHeaders checks the headers of every response (Sécurité,
// durcissements 5 et 6), and that no Cross-Origin-Opener-Policy cuts a
// sign-in opened in a popup from its opener.
func securityHeaders(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-Trace-ID"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("%s: no %s", what, h)
		}
	}
	if coop := resp.Header.Get("Cross-Origin-Opener-Policy"); coop != "" {
		t.Errorf("%s: Cross-Origin-Opener-Policy %s", what, coop)
	}
}

// Every answer has the security headers; the pages and the redirections are
// never stored (CHX-5).
func TestHeaders(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		what    string
		resp    *http.Response
		status  int
		noStore bool
	}{
		{"page", w.do(http.MethodGet, "/?login_challenge="+hydraL, nil), http.StatusOK, true},
		{"redirection", w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...), http.StatusSeeOther, true},
		{"error page", w.do(http.MethodGet, "/consent", nil), http.StatusBadRequest, true},
		{"change of language", w.do(http.MethodPost, "/locale/en", url.Values{}, sameOrigin...), http.StatusSeeOther, true},
		{"logout", w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil), http.StatusOK, true},
		{"logout at the HEAD", w.do(http.MethodHead, "/logout?logout_challenge="+logoutU, nil), http.StatusOK, true},
		{"static file", w.do(http.MethodGet, "/static/base.css", nil), http.StatusOK, false},
		{"unknown path", w.do(http.MethodGet, "/nope", nil), http.StatusNotFound, false},
	} {
		if tc.resp.StatusCode != tc.status {
			t.Errorf("%s: %d, want %d", tc.what, tc.resp.StatusCode, tc.status)
		}
		securityHeaders(t, tc.what, tc.resp)
		if cc := tc.resp.Header.Get("Cache-Control"); tc.noStore && cc != "no-store" {
			t.Errorf("%s: Cache-Control %q", tc.what, cc)
		}
	}
}

// Without the browser's token or cookie: POS-3 shows the page again, without
// message and without choosing; BCL-3 and CST-11 give E1008, the flow intact.
func TestCSRF(t *testing.T) {
	w := newWorld(t)
	w.hydra.consentSkip = false
	w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	cookie := w.csrf()
	resp := w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {strings.Repeat("0", 64)}}, sameOrigin...)
	if body := text(t, resp); resp.StatusCode != http.StatusOK || strings.Contains(body, "n&#39;est pas proposé") || !strings.Contains(body, `name="csrf_token" value="`+cookie+`"`) {
		t.Errorf("POS-3: %d\n%s", resp.StatusCode, body)
	}
	step := w.choose("hydra-sql")
	w.cookies["dispatcher_flow_csrf"] = strings.Repeat("1", 64)
	if resp := w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil); resp.StatusCode != http.StatusForbidden || !strings.Contains(text(t, resp), "E1008") {
		t.Errorf("BCL-3: %d", resp.StatusCode)
	}
	w.cookies["dispatcher_flow_csrf"] = cookie
	w.app(step, "alice", `{"email":"alice@example.org"}`)
	location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	resp = w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
	screen := text(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CST-13: %d", resp.StatusCode)
	}
	for _, tc := range []struct{ name, token, cookie string }{
		{"no token", "", cookie},
		{"another token", strings.Repeat("2", 64), cookie},
		{"another browser", cookie, strings.Repeat("3", 64)},
	} {
		w.cookies["dispatcher_flow_csrf"] = tc.cookie
		resp := w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {tc.token}, "action": {"accept"}}, sameOrigin...)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(text(t, resp), "E1008") {
			t.Errorf("CST-11, %s: %d", tc.name, resp.StatusCode)
		}
	}
	w.cookies["dispatcher_flow_csrf"] = cookie
	if u := location(t, w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {cookie}, "claims_print": {printIn(t, screen)}, "action": {"accept"}}, sameOrigin...), http.StatusSeeOther); u.String() != callbackURL {
		t.Errorf("CST-14 after the refusals: %s", u)
	}
}

// The values of the client, of the flows and of the claims are escaped in
// their context: text, attribute, URL, where javascript: and data: give
// #ZgotmplZ.
func TestEscaping(t *testing.T) {
	snap := testSnapshot()
	flows := slices.Clone(snap.Flows)
	flows[0].Title = map[string]string{"fr": `"><img src=x onerror=alert(1)>`}
	flows[0].Description = map[string]string{"fr": `<script>alert(2)</script>`}
	flows[0].IconURL = map[string]string{"fr": `javascript:alert(3)`}
	flows[1].IconURL = map[string]string{"fr": `data:image/svg+xml,<svg onload=alert(4)>`}
	w := newWorld(t, worldOptions{base: base, showValues: true, snapshot: store.NewSnapshot(snap.Apps, flows, snap.Settings)})
	w.hydra.consentSkip = false
	w.hydra.client = &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString(`<script>alert("name")</script>%s`),
		LogoUri: ory.PtrString("javascript:alert(5)"), ClientUri: ory.PtrString("javascript:alert(6)")}
	pages := []string{text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))}
	step := location(t, w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...), http.StatusSeeOther)
	w.app(step, "alice", `{"email":"<img src=x onerror=alert(7)>","x<y":"</li><script>"}`)
	location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	pages = append(pages, text(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)))
	// Refused, then E1002 linked to the client_uri (RA6).
	location(t, w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {w.csrf()}, "action": {"reject"}}, sameOrigin...), http.StatusSeeOther)
	pages = append(pages, text(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil)))
	for i, body := range pages {
		for _, bad := range []string{"<script", "<img src=x", "javascript:", "data:image", "onload"} {
			if strings.Contains(body, bad) {
				t.Errorf("page %d holds %q:\n%s", i, bad, body)
			}
		}
		if !strings.Contains(body, "#ZgotmplZ") {
			t.Errorf("page %d without a refused URL:\n%s", i, body)
		}
	}
}

// The change of language goes back to the page its return field names, one a
// POST showed again included (POS-2), even without a Referer; else to the
// Referer's; never with the page's _locale, which would win over the cookie.
func TestLocaleBack(t *testing.T) {
	w := newWorld(t)
	w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=fr", nil)
	// Posted, as a browser does, to the form's action.
	body := text(t, w.do(http.MethodPost, "/?login_challenge="+hydraL, url.Values{"flow": {"nope"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...))
	field := regexp.MustCompile(`<input type="hidden" name="return" value="([^"]+)">`).FindStringSubmatch(body)
	if field == nil || html.UnescapeString(field[1]) != "/?login_challenge="+hydraL {
		t.Fatalf("POS-2, return field %q:\n%s", field, body)
	}
	// No Referer: a browser or an extension that drops it.
	to := location(t, w.do(http.MethodPost, "/locale/en", url.Values{"return": {html.UnescapeString(field[1])}}, sameOrigin...), http.StatusSeeOther)
	if resp := w.do(http.MethodGet, to.RequestURI(), nil); to.String() != base+"/?login_challenge="+hydraL || resp.StatusCode != http.StatusOK || !strings.Contains(text(t, resp), `<html lang="en">`) {
		t.Errorf("back from POS-2 to %s: %d", to, resp.StatusCode)
	}
	// The Referer without a field, its _locale dropped.
	to = location(t, w.do(http.MethodPost, "/locale/fr", url.Values{}, "Sec-Fetch-Site", "same-origin", "Referer", base+"/consent?_locale=en&consent_challenge="+hydraC), http.StatusSeeOther)
	if to.String() != base+"/consent?consent_challenge="+hydraC {
		t.Errorf("back to the Referer: %s", to)
	}
	// Anything but a page of the dispatcher's goes to the pages' root, the
	// field as the Referer: the input never chooses the host.
	for _, bad := range []string{
		"//evil.example/", "/\\evil.example/", "https://evil.example/", "javascript:alert(1)", "evil.example/",
		base + "@evil.example/", "http://user@dispatcher.hydra.test/", "https://dispatcher.hydra.test/",
		"/logout/next?ref=" + strings.Repeat("a", 20), "/static/base.css", "/locale/en", "/consent/../static", "/%2F%2Fevil.example/",
		"/?a=%0d%0aSet-Cookie:x=y", "/\x00",
	} {
		for _, how := range []struct {
			form   url.Values
			header []string
		}{
			{url.Values{"return": {bad}}, sameOrigin},
			{url.Values{}, []string{"Sec-Fetch-Site", "same-origin", "Referer", bad}},
		} {
			resp := w.do(http.MethodPost, "/locale/en", how.form, how.header...)
			if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, base+"/") || loc != base+"/" && !strings.HasPrefix(loc, base+"/?") {
				t.Errorf("%q (%v): %d %s", bad, how.form, resp.StatusCode, loc)
			}
		}
	}
	if _, ok := w.cookies["x"]; ok {
		t.Error("a header written by the way back")
	}
	// A form from elsewhere changes nothing, its field neither.
	if resp := w.do(http.MethodPost, "/locale/fr", url.Values{"return": {"/consent"}}, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site: %d", resp.StatusCode)
	}
}

// Under a path, the base URL's: the proxy removes it, the pages put it
// before their URLs, as the engine before the apps' redirect_to.
func TestBasePath(t *testing.T) {
	const prefixed = "http://dispatcher.hydra.test/auth"
	w := newWorld(t, worldOptions{base: prefixed})
	body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))
	for _, want := range []string{`action="/auth/?login_challenge=` + hydraL + `"`, `formaction="/auth/locale/en"`, `href="/auth/static/base.css?v=`} {
		if !strings.Contains(body, want) {
			t.Errorf("page without %s:\n%s", want, body)
		}
	}
	step := location(t, w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, "Origin", "http://dispatcher.hydra.test"), http.StatusSeeOther)
	anyApp := func(store.App) bool { return true }
	c := step.Query().Get("login_challenge")
	w.o.Handle(context.Background(), flow.AppCall{Op: flow.AppGetLogin, Challenge: c, Caller: anyApp})
	r := w.o.Handle(context.Background(), flow.AppCall{Op: flow.AppAcceptLogin, Challenge: c, Caller: anyApp, Body: json.RawMessage(`{"subject":"alice"}`)}).Response
	back, err := url.Parse(r.Body.(ory.OAuth2RedirectTo).RedirectTo)
	if err != nil || !strings.HasPrefix(back.Path, "/auth/") {
		t.Fatalf("redirect_to %+v", r.Body)
	}
	if u := location(t, w.do(http.MethodGet, strings.TrimPrefix(back.RequestURI(), "/auth"), nil), http.StatusSeeOther); u.Host != "sql.hydra.test" {
		t.Errorf("BCL-7 under the path: %s", u)
	}
	if u := location(t, w.do(http.MethodPost, "/locale/en", url.Values{}, sameOrigin...), http.StatusSeeOther); u.String() != prefixed+"/" {
		t.Errorf("change of language without Referer: %s", u)
	}
	if !strings.Contains(body, `name="return" value="/auth/?login_challenge=`+hydraL+`"`) {
		t.Errorf("return field under the path:\n%s", body)
	}
	for _, tc := range []struct{ field, want string }{
		{"/auth/?login_challenge=" + hydraL, prefixed + "/?login_challenge=" + hydraL},
		{"/auth/consent?consent_challenge=" + hydraC, prefixed + "/consent?consent_challenge=" + hydraC},
		{"/?login_challenge=" + hydraL, prefixed + "/"}, // outside the path
		{"/authx/", prefixed + "/"},
	} {
		if u := location(t, w.do(http.MethodPost, "/locale/en", url.Values{"return": {tc.field}}, sameOrigin...), http.StatusSeeOther); u.String() != tc.want {
			t.Errorf("return %s: back to %s, want %s", tc.field, u, tc.want)
		}
	}
}

// Logout: Hydra saturated, a logout accepted without redirect_to.
func TestLogoutHydra(t *testing.T) {
	w := newWorld(t)
	w.hydra.errs["get_logout"] = fmt.Errorf("logout request: %w", hydra.ErrOverloaded)
	resp := w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || !strings.Contains(text(t, resp), "E1004") {
		t.Errorf("saturated: %d %v", resp.StatusCode, resp.Header)
	}
	w = newWorld(t)
	w.hydra.rpInitiated = true
	w.hydra.noLogoutRedirect = true
	resp = w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(text(t, resp), "E1004") || setCookie(resp, "dispatcher_remember") != nil {
		t.Errorf("without redirect_to: %d", resp.StatusCode)
	}
}

// A page whose template fails is a 500 with the trace id, logged with it,
// never half a page.
func TestRenderFailure(t *testing.T) {
	w := newWorld(t)
	w.front.theme.templates["error"] = template.Must(template.New("layout").Parse(`<p>half{{.Nope}}</p>`))
	resp := w.do(http.MethodGet, "/consent", nil)
	body, trace := text(t, resp), resp.Header.Get("X-Trace-ID")
	if resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "half") || !strings.Contains(body, trace) ||
		!strings.Contains(w.logs.String(), `"trace_id":"`+trace+`"`) {
		t.Errorf("%d %q\n%s", resp.StatusCode, body, w.logs.String())
	}
}

// The start check stops a template that fails, a key a catalog lacks, a
// form without the fields the handlers read (Thèmes, validation).
func TestCheck(t *testing.T) {
	if err := Check(newWorld(t).front.theme); err != nil {
		t.Fatalf("embedded pages: %v", err)
	}
	for _, tc := range []struct {
		name string
		mod  func(h *Handler)
		want []string
	}{
		{"keys lacking", func(h *Handler) {
			delete(h.theme.catalogs["en"], "consent.accept")
			delete(h.theme.catalogs["fr"], "claim.email")
			delete(h.theme.catalogs["en"], "locale.en")
			delete(h.theme.catalogs["fr"], "error.E1006")
		}, []string{"catalog en: no text for consent.accept", "catalog fr: no text for claim.email", "catalog en: no text for locale.en", "catalog fr: no text for error.E1006"}},
		{"fields lacking", func(h *Handler) {
			h.theme.templates["select"] = template.Must(template.New("layout").Parse(`<form method="post" action="{{.Form.Action}}"><input name="login_challenge" value="{{.Form.LoginChallenge}}"><input name="csrf_token" value="x"></form>`))
		}, []string{"page select (flows, one refused) in en: ", "no field flow in the form", `field csrf_token without the value "` + sampleCSRF + `"`}},
		{"template failing", func(h *Handler) {
			h.theme.templates["consent"] = template.Must(template.New("layout").Parse(`{{.Nope}}`))
		}, []string{"page consent (nothing asked) in fr"}},
	} {
		w := newWorld(t)
		tc.mod(w.front)
		err := w.front.check(w.front.theme)
		for _, want := range tc.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v, want %q", tc.name, err, want)
			}
		}
	}
}

// No name leaves static/.
func TestStaticOutside(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{"/static/..%2fweb.go", "/static/%2e%2e%2ftemplates%2flayout.html.tmpl", "/static/%2e%2e", "/static/.", "/static/"} {
		resp := w.do(http.MethodGet, p, nil)
		if body := text(t, resp); resp.StatusCode == http.StatusOK || strings.Contains(body, "package web") || strings.Contains(body, "{{define") {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

// The theme contract (Thèmes, api: 1): the layout's blocks a theme
// redefines, its theme.js and its flags loaded when it has them; the
// embedded theme has none.
func TestThemeContract(t *testing.T) {
	w := newWorld(t)
	body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))
	if strings.Contains(body, "<script") || strings.Contains(body, `class="flag"`) {
		t.Errorf("embedded theme with a script or a flag:\n%s", body)
	}
	if resp := w.do(http.MethodGet, "/static/flags/fr.svg", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a flag in the embedded theme: %d", resp.StatusCode)
	}
	// A theme's files and blocks.
	w.front.theme.statics["theme.js"], w.front.theme.statics["flags/fr.svg"] = staticFile{hash: "0123456789ab"}, staticFile{hash: "ba9876543210"}
	tpl := template.Must(template.ParseFS(web.FS, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/select.html.tmpl"))
	w.front.theme.templates["select"] = template.Must(tpl.Parse(`{{define "head"}}<meta name="theme" content="demo">{{end}}` +
		`{{define "header"}}<p>logo</p>{{end}}{{define "footer"}}<p>{{.LocaleURL "en"}} {{.Flag "fr"}} {{.Asset "nope.css"}}</p>{{end}}`))
	body = text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))
	for _, want := range []string{
		`<script src="/static/theme.js?v=0123456789ab" defer></script>`, `<meta name="theme" content="demo">`,
		`<header><p>logo</p></header>`, `<footer><p>/locale/en /static/flags/fr.svg?v=ba9876543210 </p></footer>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("theme without %s:\n%s", want, body)
		}
	}
	// The default footer shows the flags a theme has.
	w.front.theme.templates["select"] = template.Must(template.ParseFS(web.FS, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/select.html.tmpl"))
	if body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)); !strings.Contains(body, `<img class="flag" src="/static/flags/fr.svg?v=ba9876543210" alt="">Français`) {
		t.Errorf("no flag in the switcher:\n%s", body)
	}
}

var update = flag.Bool("update", false, "rewrite the golden pages of testdata/pages")

// Each page of the embedded theme, in each locale, with check's sample data,
// is that of testdata/pages (Stratégie de tests: rendu golden). go test
// -update rewrites them; the diff then shows what a change did to the pages.
func TestGoldenPages(t *testing.T) {
	h := newWorld(t).front
	cfg := sampleConfig(h.theme)
	slug := regexp.MustCompile(`[^a-z0-9]+`)
	n := 0
	for _, l := range cfg.Settings.SupportedLocales {
		r := httptest.NewRequest(http.MethodGet, "/?_locale="+l, nil)
		for _, s := range h.samples(r, h.theme, cfg) {
			if s.name == "error" && !(s.what == "E1002" && s.page.Error.Link != "" || s.what == "E1004" && s.page.Error.Link == "" || s.what == "sign out") {
				continue
			}
			var buf bytes.Buffer
			if err := h.theme.templates[s.name].ExecuteTemplate(&buf, "layout", s.page); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "pages", s.name+"-"+strings.Trim(slug.ReplaceAllString(strings.ToLower(s.what), "-"), "-")+"."+l+".html")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test -update to create it)", err)
			}
			if got := buf.Bytes(); !bytes.Equal(got, want) {
				gl, wl := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
				i := 0
				for i < len(gl) && i < len(wl) && gl[i] == wl[i] {
					i++
				}
				t.Errorf("%s differs from line %d (go test -update to accept):\n got %q\nwant %q", path, i+1, line(gl, i), line(wl, i))
			}
			n++
		}
	}
	if n != 30 {
		t.Errorf("%d golden pages, want 30", n)
	}
}

func line(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(end)"
}

// hydraL2 is a second login challenge of the same Hydra session.
const hydraL2 = "1d45bbff177259bed0362135f0aa0cc5"

// remembered plays a first authentication on hydra-sql through the pages,
// claims in its id_token, Hydra skipping the consent, and returns the
// response of the consent, which writes the remember cookie (WRT-1).
func (w *world) remembered(claims string) *http.Response {
	w.t.Helper()
	w.hydra.consentSkip = true
	w.app(w.choose("hydra-sql"), "alice", claims)
	location(w.t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	resp := w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
	location(w.t, resp, http.StatusSeeOther)
	return resp
}

// setCookie returns the Set-Cookie of name in resp.
func setCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// WRT-1, MEM-1, MEM-2, SKP-1, SKC-1 to SKC-3 through the pages: the cookie
// written at the consent, read at the next login, which Hydra skips. B3: 4
// calls, 5 with the consent screen.
func TestRememberCookie(t *testing.T) {
	for _, tc := range []struct {
		name   string
		screen bool
		calls  []string
	}{
		{"SKP-1 SKC-1, consent skipped", false, []string{"get_login", "accept_login", "get_consent", "accept_consent"}},
		{"SKP-1 SKC-2 SKC-3, the screen built from the cookie", true, []string{"get_login", "accept_login", "get_consent", "get_consent", "accept_consent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			resp := w.remembered(`{"email":"alice@example.org"}`)
			c := setCookie(resp, "dispatcher_remember")
			if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != 86400 || c.Secure {
				t.Fatalf("WRT-1, Set-Cookie %+v", c)
			}

			w.hydra.skip, w.hydra.consentSkip, w.hydra.calls = true, !tc.screen, nil
			if u := location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther); u.String() != verifierURL {
				t.Fatalf("SKP-1: %s", u)
			}
			resp = w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
			if tc.screen {
				page := text(t, resp)
				m := regexp.MustCompile(`name="claims_print" value="([0-9a-f]{64})"`).FindStringSubmatch(page)
				if resp.StatusCode != http.StatusOK || m == nil || !strings.Contains(page, "Email address") {
					t.Fatalf("SKC-2: %d %s", resp.StatusCode, page)
				}
				resp = w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {w.csrf()}, "claims_print": {m[1]}, "action": {"accept"}}, sameOrigin...)
			}
			if u := location(t, resp, http.StatusSeeOther); u.String() != callbackURL {
				t.Fatalf("SKC-1: %s", u)
			}
			// WRT-5: a skip honoured writes no cookie.
			if setCookie(resp, "dispatcher_remember") != nil {
				t.Error("WRT-5, the cookie written again")
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v; want %v", w.hydra.calls, tc.calls)
			}
			if got, _ := json.Marshal(w.hydra.consent.Session.IdToken); string(got) != `{"email":"alice@example.org"}` {
				t.Errorf("id_token %s", got)
			}
		})
	}
}

// WRT-1, WRT-2: deflated beyond 1.5 KB, one cookie up to 3.8 KB, read back;
// beyond 3.8 KB, none, the former one cleared, and never a second cookie
// (revue R20: the Cookie header under a reverse proxy's 8 KB).
func TestRememberSizes(t *testing.T) {
	random := func(n int) string { // which deflate barely shrinks
		b := make([]byte, n*3/4)
		_, _ = rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	w := newWorld(t)
	resp := w.remembered(`{"email":"alice@example.org","blob":"` + random(2000) + `"}`)
	c := setCookie(resp, "dispatcher_remember")
	if c == nil || len(c.Value) < 1500 || len(c.Value) > 3800 || c.MaxAge != 86400 {
		t.Fatalf("WRT-1, one cookie under 3.8 KB: %+v", c)
	}
	// Read back: the next login is skipped.
	w.hydra.skip = true
	if u := location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("SKP-1 from a large cookie: %s", u)
	}

	// WRT-2: beyond 3.8 KB, the former cookie cleared, nothing else set.
	w = newWorld(t)
	w.cookies["dispatcher_remember"] = "former"
	resp = w.remembered(`{"blob":"` + random(4000) + `"}`)
	if c := setCookie(resp, "dispatcher_remember"); c == nil || c.MaxAge >= 0 {
		t.Errorf("WRT-2: %+v", c)
	}
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "dispatcher_remember") && c.Name != "dispatcher_remember" {
			t.Errorf("WRT-2, a second cookie: %+v", c)
		}
	}
	if !strings.Contains(w.logs.String(), `"msg":"skip.unavailable"`) {
		t.Errorf("WRT-2 not logged: %s", w.logs.String())
	}
}

// WRT-1: Max-Age is the remember_for sent; 0, a cookie of the browser's
// session, as Hydra's is then. WRT-3: remember false, none.
func TestRememberLife(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings func(s *store.Settings)
		maxAge   int
		written  bool
	}{
		{"WRT-1, remember_for", func(s *store.Settings) { s.LoginRememberFor = time.Hour }, 3600, true},
		{"WRT-1, remember_for 0: a cookie of the browser's session", func(s *store.Settings) { s.LoginRememberFor = 0 }, 0, true},
		{"WRT-3, remember false", func(s *store.Settings) { s.Remember = false }, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := testSnapshot()
			tc.settings(&snap.Settings)
			w := newWorld(t, worldOptions{base: base, snapshot: snap})
			c := setCookie(w.remembered(`{"email":"alice@example.org"}`), "dispatcher_remember")
			if (c != nil) != tc.written || c != nil && c.MaxAge != tc.maxAge {
				t.Errorf("Set-Cookie %+v; want written %v, Max-Age %d", c, tc.written, tc.maxAge)
			}
		})
	}
}

// In HTTPS with cookie_path /, the cookies are __Host- and Secure; under
// another path, they keep their names and take it.
func TestRememberHTTPS(t *testing.T) {
	for _, tc := range []struct {
		base, path, prefix string
	}{{"https://dispatcher.example", "/", "__Host-"}, {"https://dispatcher.example/auth", "/auth/", ""}} {
		w := newWorld(t, worldOptions{base: tc.base, path: tc.path})
		w.hydra.consentSkip = true
		w.cookies[tc.prefix+"dispatcher_flow_csrf"] = strings.Repeat("ab", 32)
		page := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
		if page.StatusCode != http.StatusOK {
			t.Fatalf("GET /: %d", page.StatusCode)
		}
		step := location(t, w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.cookies[tc.prefix+"dispatcher_flow_csrf"]}},
			"Origin", "https://dispatcher.example"), http.StatusSeeOther)
		w.app(step, "alice", `{"email":"alice@example.org"}`)
		location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
		c := setCookie(w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil), tc.prefix+"dispatcher_remember")
		if c == nil || !c.Secure || c.Path != tc.path {
			t.Errorf("cookie_path %s: Set-Cookie %+v", tc.path, c)
		}
	}
}

// The consent screen by the catalogue of the scopes (P24): a scope of the
// business and its labels, a standard scope renamed, a claim renamed, in the
// locale of the page or for every locale; a scope it does not know by its
// name.
func TestConsentCatalogue(t *testing.T) {
	snap := testSnapshot()
	snap.Scopes = []store.Scope{
		{Name: "groups", Label: map[string]string{"en": "Your teams <i>"}, Claims: []store.ScopeClaim{{Claim: "groups", Label: map[string]string{"": "Teams <b>"}}}},
		{Name: "profile", Label: map[string]string{"fr": "Qui vous êtes"}, Claims: []store.ScopeClaim{{Claim: "name", Label: map[string]string{"en": "Your name"}}}},
	}
	w := newWorld(t, worldOptions{base: base, snapshot: snap})
	w.hydra.consentSkip = false
	w.appSession(w.choose("hydra-sql"), "alice", `{"id_token":{"email":"alice@example.org","name":"Alice","groups":["staff"]}}`)
	location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
	body := text(t, w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil))
	// The labels of the catalogue escaped (R44).
	if strings.Contains(body, "<i>") || strings.Contains(body, "<b>") {
		t.Errorf("a label not escaped:\n%s", body)
	}
	for _, want := range []string{"Your teams &lt;i&gt;", "<li>Teams &lt;b&gt;</li>", "Your profile", "<li>Your name</li>", "Your email address"} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Permission “groups”") || strings.Contains(body, "Other data") {
		t.Errorf("groups outside the catalogue:\n%s", body)
	}
}

// printIn is the print of the claims a consent screen shows, which its form
// posts (SKC-2, CST-13).
func printIn(t *testing.T, page string) string {
	t.Helper()
	m := regexp.MustCompile(`name="claims_print" value="([0-9a-f]{64})"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no claims_print in:\n%s", page)
	}
	return m[1]
}

// The language chosen on these pages, by the dispatcher_locale cookie or
// _locale, reaches the apps first in the ui_locales of their requests
// (Q138); a language the pages do not speak is none.
func TestChosenLocaleToTheApps(t *testing.T) {
	served := func(w *world, cookie string) []string {
		t.Helper()
		if cookie != "" {
			w.cookies["dispatcher_locale"] = cookie
		}
		login := w.choose("hydra-sql")
		r := w.o.Handle(context.Background(), flow.AppCall{Op: flow.AppGetLogin, Challenge: login.Query().Get("login_challenge"), Caller: func(store.App) bool { return true }}).Response
		var body struct {
			OidcContext struct {
				UILocales []string `json:"ui_locales"`
			} `json:"oidc_context"`
		}
		raw, _ := json.Marshal(r.Body)
		if r.Status != http.StatusOK || json.Unmarshal(raw, &body) != nil {
			t.Fatalf("login request: %+v", r)
		}
		return body.OidcContext.UILocales
	}
	if got := served(newWorld(t), "en"); len(got) == 0 || got[0] != "en" {
		t.Errorf("chosen in English: %q", got)
	}
	if got := served(newWorld(t), "xx"); slices.Contains(got, "xx") {
		t.Errorf("a language the pages do not speak: %q", got)
	}
	if got := served(newWorld(t), ""); slices.Contains(got, "en") {
		t.Errorf("no choice: %q", got)
	}
}
