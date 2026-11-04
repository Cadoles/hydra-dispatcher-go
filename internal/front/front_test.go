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
	// noLogoutRedirect accepts the logout without a redirect_to.
	noLogoutRedirect bool
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
	return &ory.OAuth2LogoutRequest{Challenge: ory.PtrString(challenge)}, nil
}

func (h *fakeHydra) AcceptLogout(context.Context, string) (string, error) {
	if h.noLogoutRedirect {
		return "", h.called("accept_logout")
	}
	return loggedOut, h.called("accept_logout")
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
	h, err := New(Options{Engine: w.o, Hydra: w.hydra, Config: cfg, Remember: memories, BaseURL: opt.base, CookiePath: opt.cookiePath(), ShowValues: opt.showValues, Logger: logger})
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
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("consent screen: %d %s", resp.StatusCode, text(t, resp))
				}
				resp = w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {w.csrf()}, "action": {"accept"}}, sameOrigin...)
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

func TestLogout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		err    error
		status int
		code   string
	}{
		{"accepted at once", "/logout?logout_challenge=" + logoutU, nil, http.StatusSeeOther, ""},
		{"no challenge", "/logout", nil, http.StatusBadRequest, "E1001"},
		{"illegible", "/logout?logout_challenge=a%2Fb", nil, http.StatusBadRequest, "E1001"},
		{"unknown", "/logout?logout_challenge=" + logoutU, &hydra.RequestError{Status: 404}, http.StatusBadRequest, "E1001"},
		{"gone", "/logout?logout_challenge=" + logoutU, &hydra.RequestError{Status: 410}, http.StatusBadRequest, "E1002"},
		{"refused", "/logout?logout_challenge=" + logoutU, &hydra.RequestError{Status: 400}, http.StatusInternalServerError, "E1007"},
		{"down", "/logout?logout_challenge=" + logoutU, errors.New("connection refused"), http.StatusBadGateway, "E1004"},
	} {
		w := newWorld(t)
		w.hydra.errs["get_logout"] = tc.err
		w.cookies["dispatcher_remember"], w.cookies["dispatcher_remember_2"] = "2.memory", "of another session"
		resp := w.do(http.MethodGet, tc.target, nil)
		body := text(t, resp)
		if resp.StatusCode != tc.status || tc.code != "" && !strings.Contains(body, tc.code) ||
			tc.code == "" && resp.Header.Get("Location") != loggedOut {
			t.Errorf("%s: %d %s\n%s", tc.name, resp.StatusCode, resp.Header.Get("Location"), body)
		}
		// WRT-4 (Q41): a logout accepted clears the memory of the skip, both
		// parts, whatever its sid; a logout that fails, nothing.
		for _, name := range []string{"dispatcher_remember", "dispatcher_remember_2"} {
			if c := setCookie(resp, name); (c != nil && c.MaxAge < 0) != (tc.code == "") {
				t.Errorf("%s: WRT-4, %s: %+v", tc.name, name, c)
			}
		}
	}
	w := newWorld(t)
	w.hydra.errs["accept_logout"] = errors.New("connection refused")
	if resp := w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("accept down: %d", resp.StatusCode)
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
		{"logout", w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil), http.StatusSeeOther, true},
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
	if resp := w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil); resp.StatusCode != http.StatusOK {
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
	if u := location(t, w.do(http.MethodPost, "/consent", url.Values{"consent_challenge": {hydraC}, "csrf_token": {cookie}, "action": {"accept"}}, sameOrigin...), http.StatusSeeOther); u.String() != callbackURL {
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
		"/logout?logout_challenge=" + logoutU, "/static/base.css", "/locale/en", "/consent/../logout", "/%2F%2Fevil.example/",
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
	w.hydra.noLogoutRedirect = true
	resp = w.do(http.MethodGet, "/logout?logout_challenge="+logoutU, nil)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(text(t, resp), "E1004") || !strings.Contains(w.logs.String(), "logout accepted without redirect_to") {
		t.Errorf("without redirect_to: %d\n%s", resp.StatusCode, w.logs.String())
	}
}

// A page whose template fails is a 500 with the trace id, logged with it,
// never half a page.
func TestRenderFailure(t *testing.T) {
	w := newWorld(t)
	w.front.pages.templates["error"] = template.Must(template.New("layout").Parse(`<p>half{{.Nope}}</p>`))
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
	if err := newWorld(t).front.check(); err != nil {
		t.Fatalf("embedded pages: %v", err)
	}
	for _, tc := range []struct {
		name string
		mod  func(h *Handler)
		want []string
	}{
		{"keys lacking", func(h *Handler) {
			delete(h.catalogs["en"], "consent.accept")
			delete(h.catalogs["fr"], "claim.email")
			delete(h.catalogs["en"], "locale.en")
			delete(h.catalogs["fr"], "error.E1006")
		}, []string{"catalog en: no text for consent.accept", "catalog fr: no text for claim.email", "catalog en: no text for locale.en", "catalog fr: no text for error.E1006"}},
		{"fields lacking", func(h *Handler) {
			h.pages.templates["select"] = template.Must(template.New("layout").Parse(`<form><input name="login_challenge" value="{{.Form.LoginChallenge}}"><input name="csrf_token" value="x"></form>`))
		}, []string{"page select (flows, one refused) in en: ", "no field flow", `field csrf_token without the value "` + sampleCSRF + `"`}},
		{"template failing", func(h *Handler) {
			h.pages.templates["consent"] = template.Must(template.New("layout").Parse(`{{.Nope}}`))
		}, []string{"page consent (nothing asked) in fr"}},
	} {
		w := newWorld(t)
		tc.mod(w.front)
		err := w.front.check()
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
	w.front.pages.hashes["theme.js"], w.front.pages.hashes["flags/fr.svg"] = "0123456789ab", "ba9876543210"
	tpl := template.Must(template.ParseFS(web.FS, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/select.html.tmpl"))
	w.front.pages.templates["select"] = template.Must(tpl.Parse(`{{define "head"}}<meta name="theme" content="demo">{{end}}` +
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
	w.front.pages.templates["select"] = template.Must(template.ParseFS(web.FS, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/select.html.tmpl"))
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
	cfg := h.sampleConfig()
	slug := regexp.MustCompile(`[^a-z0-9]+`)
	n := 0
	for _, l := range cfg.Settings.SupportedLocales {
		r := httptest.NewRequest(http.MethodGet, "/?_locale="+l, nil)
		for _, s := range h.samples(r, cfg) {
			if s.name == "error" && !(s.what == "E1002" && s.page.Error.Link != "" || s.what == "E1004" && s.page.Error.Link == "") {
				continue
			}
			var buf bytes.Buffer
			if err := h.pages.templates[s.name].ExecuteTemplate(&buf, "layout", s.page); err != nil {
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
	if n != 14 {
		t.Errorf("%d golden pages, want 14", n)
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
			if setCookie(resp, "dispatcher_remember_2") != nil {
				t.Error("a second part for a small memory")
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

// WRT-1, WRT-2, MEM-1: deflated, then in two cookies beyond 3.8 KB, both
// read back; a former second part cleared; beyond 7.5 KB, none, and the
// former one cleared.
func TestRememberSizes(t *testing.T) {
	random := func(n int) string { // which deflate barely shrinks
		b := make([]byte, n*3/4)
		_, _ = rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	w := newWorld(t)
	resp := w.remembered(`{"email":"alice@example.org","blob":"` + random(5000) + `"}`)
	first, second := setCookie(resp, "dispatcher_remember"), setCookie(resp, "dispatcher_remember_2")
	if first == nil || second == nil || second.MaxAge != 86400 || !second.HttpOnly {
		t.Fatalf("WRT-1, two cookies: %+v %+v", first, second)
	}
	// Both parts read back: the next login is skipped.
	w.hydra.skip = true
	if u := location(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil), http.StatusSeeOther); u.String() != verifierURL {
		t.Fatalf("SKP-1 from two cookies: %s", u)
	}
	// MEM-1: without its second part, the skip is ignored.
	delete(w.cookies, "dispatcher_remember_2")
	if resp := w.do(http.MethodGet, "/?login_challenge=2e56ccaa288360cfe1473246a1bb1dd6", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("MEM-1, the second part missing: %d, not the choice page", resp.StatusCode)
	}

	// A small memory written over two cookies clears the second.
	w = newWorld(t)
	w.cookies["dispatcher_remember_2"] = "former"
	resp = w.remembered(`{"email":"alice@example.org"}`)
	if c := setCookie(resp, "dispatcher_remember_2"); c == nil || c.MaxAge >= 0 {
		t.Errorf("the former second part kept: %+v", c)
	}

	// WRT-2: beyond 7.5 KB, the cookie and its second part cleared.
	w = newWorld(t)
	w.cookies["dispatcher_remember"] = "former"
	resp = w.remembered(`{"blob":"` + random(9000) + `"}`)
	for _, name := range []string{"dispatcher_remember", "dispatcher_remember_2"} {
		if c := setCookie(resp, name); c == nil || c.MaxAge >= 0 {
			t.Errorf("WRT-2, %s: %+v", name, c)
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
