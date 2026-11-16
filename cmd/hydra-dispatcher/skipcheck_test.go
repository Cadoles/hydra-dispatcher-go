package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	refapp "forge.cadoles.com/rmasson/hydra-dispatcher-go/examples/skipcheck-app/app"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/device"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The exit test of phase 4 (P28): the whole handler of the dispatcher, the
// reference app of the pre-check (examples/skipcheck-app) over HTTP as its
// second step, a fake Hydra. The device enrolled, the step skipped at the
// next login, run again under prompt=login, for another browser, without the
// device cookie, once the device revoked.

const refVerifier = "http://public.hydra.test/oauth2/auth?login_verifier=v"

// refHydra is Hydra's admin API for logins: the request_url of each
// challenge, the accepts kept.
type refHydra struct {
	t        *testing.T
	mu       sync.Mutex
	requests map[string]string
	accepted map[string]ory.AcceptOAuth2LoginRequest
}

func (h *refHydra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := r.URL.Query().Get("login_challenge")
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "GET /health/ready":
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	case "GET /admin/oauth2/auth/requests/login":
		_ = json.NewEncoder(w).Encode(ory.OAuth2LoginRequest{Challenge: c, Client: ory.OAuth2Client{ClientId: ory.PtrString("c1")},
			RequestUrl: h.requests[c], RequestedScope: []string{"openid"}, RequestedAccessTokenAudience: []string{}, SessionId: ory.PtrString("sid-" + c)})
	case "PUT /admin/oauth2/auth/requests/login/accept":
		var body ory.AcceptOAuth2LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.t.Error(err)
		}
		h.accepted[c] = body
		_ = json.NewEncoder(w).Encode(ory.OAuth2RedirectTo{RedirectTo: refVerifier})
	default:
		h.t.Errorf("Hydra: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// refBrowser is a browser: its cookies, its User-Agent, no redirect followed
// by itself.
type refBrowser struct {
	t      *testing.T
	client *http.Client
	agent  string
}

func newRefBrowser(t *testing.T, agent string) *refBrowser {
	jar, _ := cookiejar.New(nil)
	return &refBrowser{t: t, agent: agent, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *refBrowser) do(method, target string, form url.Values, origin string) (*http.Response, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("User-Agent", b.agent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(data)
}

func (b *refBrowser) cookie(base, name string) string {
	u, _ := url.Parse(base)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// forget drops a cookie, as a user who clears it.
func (b *refBrowser) forget(base, name string) {
	u, _ := url.Parse(base)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(u, slices.DeleteFunc(b.client.Jar.Cookies(u), func(c *http.Cookie) bool { return c.Name == name }))
	b.client.Jar = jar
}

// sqlApp plays the first step on the emulated API, from its source.
func sqlApp(t *testing.T, dispatcher string, method, path, param, challenge, body string) string {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, dispatcher+path+"?"+url.Values{param: {challenge}}.Encode(), rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var to struct {
		RedirectTo string `json:"redirect_to"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&to) != nil {
		t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
	}
	return to.RedirectTo
}

var hiddenCSRF = regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`)
var revokeID = regexp.MustCompile(`name="id" value="([0-9a-f]{64})"`)

func TestSkipCheckReferenceApp(t *testing.T) {
	hydra := &refHydra{t: t, requests: map[string]string{}, accepted: map[string]ory.AcceptOAuth2LoginRequest{}}
	hydraSrv := httptest.NewServer(hydra)
	defer hydraSrv.Close()
	dispatcher := httptest.NewUnstartedServer(nil)
	dispatcher.Start()
	defer dispatcher.Close()
	key := []byte("0123456789abcdef0123456789abcdef")
	ref, err := refapp.New(refapp.Options{AdminURL: dispatcher.URL, Key: key, Code: "123456", Log: slog.New(slog.NewTextHandler(t.Output(), nil))})
	if err != nil {
		t.Fatal(err)
	}
	refSrv := httptest.NewServer(ref)
	defer refSrv.Close()

	env := slices.DeleteFunc(requiredEnv(hydraSrv.URL), func(e string) bool {
		return strings.HasPrefix(e, "DISPATCHER_SERVER_BASE_URL=") || strings.HasPrefix(e, "DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=")
	})
	cfg, _, err := config.Load("", append(env, "DISPATCHER_SERVER_BASE_URL="+dispatcher.URL, "DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=127.0.0.1/32"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLS.AllowHTTP = true
	local := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	apps := []store.App{
		{ID: "sql", LoginURL: "http://sql.test/login", ConsentURL: "http://sql.test/consent", Method: "pwd", AuthMode: "network", AllowedSources: local},
		{ID: "ref", LoginURL: refSrv.URL + "/login", ConsentURL: refSrv.URL + "/consent", Method: "otp", AuthMode: "network", AllowedSources: local,
			SkipCheckURL: refSrv.URL + "/skip-check", SkipCheckKey: hex.EncodeToString(key), SkipCheckSignals: []string{"user_agent"}},
	}
	flows := []store.Flow{{ID: "pwd-otp", Enabled: true, Title: map[string]string{"en": "Two factors"}, Steps: []store.Step{
		{AppID: "sql", Position: 1, SubjectCheck: "none"}, {AppID: "ref", Position: 2, SubjectCheck: "equal", SkipCheck: true}}}}
	services := testServices(t, nil)
	services.config = fixedSnapshot{store.NewSnapshot(apps, flows, store.DefaultSettings())}
	h, err := newHandler(cfg, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler), services)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Config.Handler = h

	// login plays a login of alice through the pages of b, and the step of
	// the reference app when it shows (code, remember, revoke the devices
	// listed), back to Hydra; it returns whether the step showed, and the
	// accept sent to Hydra.
	login := func(b *refBrowser, challenge, query string, remember, revoke bool) (bool, ory.AcceptOAuth2LoginRequest) {
		t.Helper()
		hydra.mu.Lock()
		hydra.requests[challenge] = "http://public.hydra.test/oauth2/auth?client_id=c1&scope=openid" + query
		hydra.mu.Unlock()
		if resp, page := b.do(http.MethodGet, dispatcher.URL+"/?login_challenge="+challenge, nil, ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("choice: %d %s", resp.StatusCode, page)
		}
		resp, _ := b.do(http.MethodPost, dispatcher.URL+"/", url.Values{"flow": {"pwd-otp"}, "login_challenge": {challenge},
			"csrf_token": {b.cookie(dispatcher.URL, "dispatcher_flow_csrf")}}, dispatcher.URL)
		step, _ := url.Parse(resp.Header.Get("Location"))
		sc := step.Query().Get("login_challenge")
		sqlApp(t, dispatcher.URL, http.MethodGet, "/admin/oauth2/auth/requests/login", "login_challenge", sc, "")
		back := sqlApp(t, dispatcher.URL, http.MethodPut, "/admin/oauth2/auth/requests/login/accept", "login_challenge", sc, `{"subject":"alice"}`)
		resp, _ = b.do(http.MethodGet, back, nil, "")
		consent, _ := url.Parse(resp.Header.Get("Location"))
		cc := consent.Query().Get("consent_challenge")
		sqlApp(t, dispatcher.URL, http.MethodGet, "/admin/oauth2/auth/requests/consent", "consent_challenge", cc, "")
		back = sqlApp(t, dispatcher.URL, http.MethodPut, "/admin/oauth2/auth/requests/consent/accept", "consent_challenge", cc, `{"session":{}}`)
		resp, _ = b.do(http.MethodGet, back, nil, "")
		showed := false
		for range 8 {
			to := resp.Header.Get("Location")
			switch {
			case resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound:
				t.Fatalf("%s: status %d", challenge, resp.StatusCode)
			case to == refVerifier:
				hydra.mu.Lock()
				defer hydra.mu.Unlock()
				return showed, hydra.accepted[challenge]
			case strings.HasPrefix(to, refSrv.URL+"/login?"):
				showed = true
				var page string
				resp, page = b.do(http.MethodGet, to, nil, "")
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("the step: %d %s", resp.StatusCode, page)
				}
				csrf := hiddenCSRF.FindStringSubmatch(page)
				rc, _ := url.Parse(to)
				if revoke {
					for _, id := range revokeID.FindAllStringSubmatch(page, -1) {
						b.do(http.MethodPost, refSrv.URL+"/revoke", url.Values{"login_challenge": {rc.Query().Get("login_challenge")}, "csrf": {csrf[1]}, "id": {id[1]}}, refSrv.URL)
					}
				}
				form := url.Values{"login_challenge": {rc.Query().Get("login_challenge")}, "csrf": {csrf[1]}, "code": {"123456"}}
				if remember {
					if !strings.Contains(page, `name="remember"`) {
						t.Fatalf("no remember box: %s", page)
					}
					form.Set("remember", "1")
				}
				resp, _ = b.do(http.MethodPost, refSrv.URL+"/login", form, refSrv.URL)
			default:
				resp, _ = b.do(http.MethodGet, to, nil, "")
			}
		}
		t.Fatalf("%s: too many redirects", challenge)
		return false, ory.AcceptOAuth2LoginRequest{}
	}
	skipped := func(a ory.AcceptOAuth2LoginRequest) []string {
		ctx, _ := a.Context.(map[string]any)
		var apps []string
		if l, ok := ctx["x_dispatcher_skipped_steps"].([]any); ok {
			for _, v := range l {
				apps = append(apps, v.(string))
			}
		}
		return apps
	}

	b := newRefBrowser(t, "Firefox/140 on Linux")
	// The enrollment: the step runs, the device remembered.
	if showed, a := login(b, "0000000000000000000000000000000a", "", true, false); !showed || a.Subject != "alice" || skipped(a) != nil ||
		!slices.Equal(a.Amr, []string{"pwd", "otp"}) || b.cookie(dispatcher.URL, device.Cookie) == "" {
		t.Fatalf("enrollment: showed %v, %+v", showed, a)
	}
	// The next login: the step skipped, said in the context, the amr kept.
	if showed, a := login(b, "0000000000000000000000000000000b", "", false, false); showed || a.Subject != "alice" ||
		!slices.Equal(skipped(a), []string{"ref"}) || !slices.Equal(a.Amr, []string{"pwd", "otp"}) {
		t.Errorf("skipped: showed %v, %+v", showed, a)
	}
	// Another browser of the same device cookie: the app, which receives the
	// User-Agent, declines.
	other := newRefBrowser(t, "Chrome/150 on Windows")
	u, _ := url.Parse(dispatcher.URL)
	other.client.Jar.SetCookies(u, b.client.Jar.Cookies(u))
	if showed, _ := login(other, "0000000000000000000000000000000c", "", false, false); !showed {
		t.Error("another browser: the step skipped")
	}
	// The device cookie cleared: the step runs.
	cleared := newRefBrowser(t, b.agent)
	cleared.client.Jar.SetCookies(u, b.client.Jar.Cookies(u))
	cleared.forget(dispatcher.URL, device.Cookie)
	if showed, _ := login(cleared, "0000000000000000000000000000000d", "", false, false); !showed {
		t.Error("without the device cookie: the step skipped")
	}
	// prompt=login: the step runs; its page lists the device, revoked there.
	if showed, a := login(b, "0000000000000000000000000000000e", "&prompt=login", false, true); !showed || skipped(a) != nil {
		t.Errorf("prompt=login: showed %v, %+v", showed, a)
	}
	// Revoked: the step runs again.
	if showed, _ := login(b, "0000000000000000000000000000000f", "", false, false); !showed {
		t.Error("revoked: the step skipped")
	}
}
