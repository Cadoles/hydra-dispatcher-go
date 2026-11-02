package front

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
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
	return &ory.OAuth2LoginRequest{
		Challenge:      challenge,
		Client:         ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client"), ClientUri: ory.PtrString("http://oidc.client.test/")},
		RequestUrl:     "http://public.hydra.test/oauth2/auth?client_id=c1",
		RequestedScope: []string{"openid", "profile", "email", "groups"},
		SessionId:      ory.PtrString(sessionID),
	}, nil
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
	return &ory.OAuth2ConsentRequest{
		Challenge:      challenge,
		Subject:        ory.PtrString(h.accepted.Subject),
		LoginSessionId: ory.PtrString(sessionID),
		Context:        json.RawMessage(ctx),
		RequestedScope: []string{"openid", "profile", "email", "groups"},
		Client:         &ory.OAuth2Client{ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client")},
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
	o       *flow.Orchestrator
	hydra   *fakeHydra
	cookies map[string]string
	logs    bytes.Buffer
}

type worldOptions struct {
	base       string
	showValues bool
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
	w.o = &flow.Orchestrator{
		Store: mem, Config: cfg, Source: flow.Fallback{Hydra: w.hydra}, Hydra: w.hydra, Webhooks: flow.StubWebhooks{},
		BaseURL: opt.base, LoginConsentTTL: 30 * time.Minute, Keys: flow.Keys{[]byte("0123456789abcdef0123456789abcdef")},
	}
	logger := slog.New(slog.NewJSONHandler(&w.logs, nil))
	h, err := New(Options{Engine: w.o, Hydra: w.hydra, Config: cfg, BaseURL: opt.base, CookiePath: "/", ShowValues: opt.showValues, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
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
// the same for its consent once the browser is back.
func (w *world) app(login *url.URL, subject, claims string) {
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
		{Op: flow.AppAcceptConsent, Challenge: cc, Caller: anyApp, Body: json.RawMessage(`{"session":{"id_token":` + claims + `}}`)},
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
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy", "Permissions-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("no %s", h)
		}
	}
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
		{"Origin", "http://evil.example"},
		nil, // neither header
	} {
		if resp := w.do(http.MethodPost, "/", form, header...); resp.StatusCode != http.StatusForbidden || !strings.Contains(text(t, resp), "E1008") {
			t.Errorf("POS-9 %v: %d", header, resp.StatusCode)
		}
	}
	if resp := w.do(http.MethodPost, "/", form, "Origin", base); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Origin of the dispatcher: %d", resp.StatusCode)
	}
	// A body past 64 KiB is no form.
	big := url.Values{"flow": {strings.Repeat("a", maxForm)}}
	if resp := w.do(http.MethodPost, "/", big, sameOrigin...); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text(t, resp), "E1001") {
		t.Errorf("big form: %d", resp.StatusCode)
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
// the consent request's ui_locales.
func TestConsentScreen(t *testing.T) {
	for _, show := range []bool{false, true} {
		w := newWorld(t, worldOptions{base: base, showValues: show})
		w.hydra.consentSkip = false
		w.app(w.choose("hydra-sql"), "alice", `{"email":"alice@example.org","name":"Alice","groups":["staff"]}`)
		location(t, w.do(http.MethodGet, "/oauth2/auth?ref="+flow.Ref(hydraL), nil), http.StatusSeeOther)
		resp := w.do(http.MethodGet, "/consent?consent_challenge="+hydraC, nil)
		body := text(t, resp)
		for _, want := range []string{
			`<html lang="en">`, "Test Client asks for access to the following data:",
			"Identify you", "Your profile", "Full name", "Your email address", "Email address",
			"Permission “groups”", "Other data", "groups",
			`name="consent_challenge" value="` + hydraC + `"`, `name="action" value="accept"`, `name="action" value="reject"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("show_values %v, no %q:\n%s", show, want, body)
			}
		}
		if strings.Contains(body, "alice@example.org") != show {
			t.Errorf("show_values %v: the email shown %v", show, !show)
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
		resp := w.do(http.MethodGet, tc.target, nil)
		body := text(t, resp)
		if resp.StatusCode != tc.status || tc.code != "" && !strings.Contains(body, tc.code) ||
			tc.code == "" && resp.Header.Get("Location") != loggedOut {
			t.Errorf("%s: %d %s\n%s", tc.name, resp.StatusCode, resp.Header.Get("Location"), body)
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
