//go:build integration

package hydra

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// What a browser does to Hydra's logout (HLO of Table de transitions.md, P9),
// which the fixtures of tools/flowfixtures cannot replay: no admin answer shows
// a session cookie gone, a back-channel sent, a skip that stops. Played against
// throwaway Hydras on Postgres, on ports of their own, never the stack's: the
// foreign keys of HLO-11 and HLO-15 are the database's. The README gives the
// commands.
const (
	// hydraURLsEnv names the instances, comma-separated, each public|admin.
	hydraURLsEnv = "HYDRA_URLS"
	// callbackHostEnv is the address the Hydras reach the test at, for the
	// back-channel: the docker bridge's when unset.
	callbackHostEnv = "HYDRA_CALLBACK_HOST"

	// postLogoutDefault is urls.post_logout_redirect of the instances, and
	// idTokenTTL the most ttl.id_token they may have: HLO-12 waits it out.
	postLogoutDefault = "http://post.test/default"
	idTokenTTL        = 3 * time.Second

	testRedirect   = "http://client.test/cb"
	testPostLogout = "http://client.test/post"
	testSecret     = "secret-secret-secret"
	sessionCookie  = "ory_hydra_session_dev"
)

// hydraInstance is one Hydra, of a version its /version reports.
type hydraInstance struct {
	public, admin, version string
	http                   *http.Client
	backChannel            *backChannel
}

// instances starts the back-channel and reads the instances: the tag without
// HYDRA_URLS fails rather than passing untested, and each of the three versions
// the dispatcher reads must be there.
func instances(t *testing.T) []*hydraInstance {
	t.Helper()
	raw := os.Getenv(hydraURLsEnv)
	if raw == "" {
		t.Fatal("the integration tag needs " + hydraURLsEnv + ": public|admin URLs, comma-separated, of a Hydra 2.1.2, 2.2.0 and 2.3.0 on Postgres (README)")
	}
	bc := newBackChannel(t)
	httpc := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var out []*hydraInstance
	for _, pair := range strings.Split(raw, ",") {
		public, admin, ok := strings.Cut(strings.TrimSpace(pair), "|")
		if !ok {
			t.Fatalf("%s: %q is not public|admin", hydraURLsEnv, pair)
		}
		h := &hydraInstance{public: public, admin: admin, http: httpc, backChannel: bc}
		var v struct {
			Version string `json:"version"`
		}
		if status, body := h.call(t, http.MethodGet, "/version", nil, nil); status != http.StatusOK || json.Unmarshal(body, &v) != nil {
			t.Fatalf("%s/version: %d %s", admin, status, body)
		}
		h.version = v.Version
		out = append(out, h)
	}
	for _, want := range []string{"v2.1.2", "v2.2.0", "v2.3.0"} {
		if !slices.ContainsFunc(out, func(h *hydraInstance) bool { return h.version == want }) {
			t.Fatalf("%s: no %s", hydraURLsEnv, want)
		}
	}
	return out
}

// backChannel is the listener of the clients' backchannel_logout_uri, the path
// naming the client.
type backChannel struct {
	url  string
	mu   sync.Mutex
	hits map[string][]map[string]any
}

func newBackChannel(t *testing.T) *backChannel {
	t.Helper()
	host := os.Getenv(callbackHostEnv)
	if host == "" {
		host = "172.17.0.1"
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	b := &backChannel{url: fmt.Sprintf("http://%s:%d", host, ln.Addr().(*net.TCPAddr).Port), hits: map[string][]map[string]any{}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims, _ := jwtClaims(r.PostForm.Get("logout_token"))
		b.mu.Lock()
		b.hits[r.URL.Path] = append(b.hits[r.URL.Path], claims)
		b.mu.Unlock()
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return b
}

func (b *backChannel) got(client string) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.hits["/"+client])
}

// waitFor waits for n logout tokens to client; quiet waits as long to see no
// more than n.
func (b *backChannel) waitFor(t *testing.T, client string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(b.got(client)) < n && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	got := b.got(client)
	if len(got) != n {
		t.Fatalf("%d logout tokens to %s, want %d", len(got), client, n)
	}
	return got
}

func (b *backChannel) quiet(t *testing.T, client string, n int) {
	t.Helper()
	time.Sleep(700 * time.Millisecond)
	if got := len(b.got(client)); got != n {
		t.Errorf("%d logout tokens to %s, want %d", got, client, n)
	}
}

func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWS: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(payload, &claims)
}

// call is one call of the admin API.
func (h *hydraInstance) call(t *testing.T, method, path string, query url.Values, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	u := h.admin + path
	if query != nil {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

// client registers a client with a secret, a post-logout URL and a
// refresh_token grant; front and back add its channels. Hydra draws its id, which
// names its front-channel and back-channel paths: written once it is known.
func (h *hydraInstance) client(t *testing.T, front, back bool) string {
	t.Helper()
	c := map[string]any{
		"client_name":                "P9",
		"client_secret":              testSecret,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      "openid offline",
		"redirect_uris":              []string{testRedirect},
		"post_logout_redirect_uris":  []string{testPostLogout},
		"token_endpoint_auth_method": "client_secret_post",
	}
	status, body := h.call(t, http.MethodPost, "/admin/clients", nil, c)
	var created struct {
		ID string `json:"client_id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
		t.Fatalf("client: %d %s", status, body)
	}
	if front {
		c["frontchannel_logout_uri"] = "http://client.test/front/" + created.ID
	}
	if back {
		c["backchannel_logout_uri"] = h.backChannel.url + "/" + created.ID
	}
	if front || back {
		c["client_id"] = created.ID
		if status, body := h.call(t, http.MethodPut, "/admin/clients/"+url.PathEscape(created.ID), nil, c); status != http.StatusOK {
			t.Fatalf("client: %d %s", status, body)
		}
	}
	return created.ID
}

// playedLogin and the others are the members of Hydra's answers the facts read.
type playedLogin struct {
	Skip       bool   `json:"skip"`
	Subject    string `json:"subject"`
	SessionID  string `json:"session_id"`
	RequestURL string `json:"request_url"`
}

type playedConsent struct {
	LoginSessionID string   `json:"login_session_id"`
	RequestedScope []string `json:"requested_scope"`
}

type playedLogout struct {
	Subject     string `json:"subject"`
	SID         string `json:"sid"`
	RPInitiated bool   `json:"rp_initiated"`
}

func (h *hydraInstance) login(t *testing.T, l string) (int, playedLogin) {
	t.Helper()
	var r playedLogin
	status, body := h.call(t, http.MethodGet, "/admin/oauth2/auth/requests/login", url.Values{"login_challenge": {l}}, nil)
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatal(err)
		}
	}
	return status, r
}

func (h *hydraInstance) consent(t *testing.T, c string) playedConsent {
	t.Helper()
	var r playedConsent
	status, body := h.call(t, http.MethodGet, "/admin/oauth2/auth/requests/consent", url.Values{"consent_challenge": {c}}, nil)
	if status != http.StatusOK || json.Unmarshal(body, &r) != nil {
		t.Fatalf("consent request: %d %s", status, body)
	}
	return r
}

func (h *hydraInstance) logout(t *testing.T, u string) playedLogout {
	t.Helper()
	var r playedLogout
	status, body := h.call(t, http.MethodGet, "/admin/oauth2/auth/requests/logout", url.Values{"logout_challenge": {u}}, nil)
	if status != http.StatusOK || json.Unmarshal(body, &r) != nil {
		t.Fatalf("logout request: %d %s", status, body)
	}
	return r
}

// accept makes an accept of the admin API, and returns its redirect_to.
func (h *hydraInstance) accept(t *testing.T, kind, challenge string, body any) string {
	t.Helper()
	status, data := h.call(t, http.MethodPut, "/admin/oauth2/auth/requests/"+kind+"/accept", url.Values{kind + "_challenge": {challenge}}, body)
	var r struct {
		RedirectTo string `json:"redirect_to"`
	}
	if status != http.StatusOK || json.Unmarshal(data, &r) != nil || r.RedirectTo == "" {
		t.Fatalf("accept %s: %d %s", kind, status, data)
	}
	return r.RedirectTo
}

func (h *hydraInstance) revoke(t *testing.T, sid string) {
	t.Helper()
	if status, body := h.call(t, http.MethodDelete, "/admin/oauth2/auth/sessions/login", url.Values{"sid": {sid}}, nil); status != http.StatusNoContent {
		t.Fatalf("DELETE sessions/login: %d %s", status, body)
	}
}

// browser keeps its cookies and takes one redirection at a time.
type browser struct {
	t *testing.T
	h *hydraInstance
	c *http.Client
}

func (h *hydraInstance) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, h: h, c: &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: h.http.CheckRedirect}}
}

// answer is a response of Hydra's public port.
type answer struct {
	status   int
	location string
	body     string
}

func (b *browser) do(method, u string, form url.Values) answer {
	b.t.Helper()
	var reader io.Reader
	if form != nil {
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, reader)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	return answer{resp.StatusCode, resp.Header.Get("Location"), string(data)}
}

func (b *browser) get(u string) answer {
	b.t.Helper()
	return b.do(http.MethodGet, u, nil)
}

// follow goes on while the redirections stay on Hydra.
func (b *browser) follow(u string) answer {
	b.t.Helper()
	a := b.get(u)
	for range 10 {
		if a.location == "" || !strings.HasPrefix(a.location, b.h.public) && !strings.HasPrefix(a.location, "/") {
			return a
		}
		next := a.location
		if strings.HasPrefix(next, "/") {
			next = b.h.public + next
		}
		a = b.get(next)
	}
	b.t.Fatalf("too many redirections from %s", u)
	return a
}

// hasCookie tells whether the browser still holds Hydra's session cookie.
func (b *browser) hasCookie() bool {
	u, _ := url.Parse(b.h.public)
	return slices.ContainsFunc(b.c.Jar.Cookies(u), func(c *http.Cookie) bool { return c.Name == sessionCookie })
}

func queryOf(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(name)
}

func (h *hydraInstance) authURL(client, prompt string) string {
	q := url.Values{
		"client_id":     {client},
		"response_type": {"code"},
		"scope":         {"openid offline"},
		"redirect_uri":  {testRedirect},
		"state":         {"client-state-1234"},
		"nonce":         {"client-nonce-1234"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	return h.public + "/oauth2/auth?" + q.Encode()
}

// start asks for an authorization and returns its login challenge, "" when
// Hydra answers without one.
func (b *browser) start(client, prompt string) string {
	b.t.Helper()
	return queryOf(b.t, b.follow(b.h.authURL(client, prompt)).location, "login_challenge")
}

// acceptLogin accepts L for subject, follows the verifier in the browser, and
// returns the consent challenge, "" when Hydra answers without one.
func (b *browser) acceptLogin(l, subject string, remember bool, rememberFor int) string {
	b.t.Helper()
	to := b.h.accept(b.t, "login", l, map[string]any{"subject": subject, "remember": remember, "remember_for": rememberFor})
	return queryOf(b.t, b.follow(to).location, "consent_challenge")
}

// acceptConsent accepts C, follows the verifier in the browser, and returns
// where it leads: the client's redirect_uri with its code or its error.
func (b *browser) acceptConsent(c string) answer {
	b.t.Helper()
	return b.follow(b.h.accept(b.t, "consent", c, map[string]any{"grant_scope": []string{"openid", "offline"}, "session": map[string]any{"id_token": map[string]any{"email": "x@example.test"}}}))
}

// tokens are the answer of the token endpoint.
type tokens struct {
	IDToken string `json:"id_token"`
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

// redeem exchanges the code of a redirect_uri.
func (b *browser) redeem(client, code string) tokens {
	b.t.Helper()
	a := b.do(http.MethodPost, b.h.public+"/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"client_id": {client}, "client_secret": {testSecret},
	})
	var tok tokens
	if err := json.Unmarshal([]byte(a.body), &tok); err != nil || a.status != http.StatusOK {
		b.t.Fatalf("token endpoint: %d %s", a.status, a.body)
	}
	return tok
}

// session is a whole authorization of subject: the session's id_token, and sid.
type session struct {
	tokens
	sid string
}

func (b *browser) signIn(client, subject string, remember bool, rememberFor int) session {
	b.t.Helper()
	l := b.start(client, "")
	if l == "" {
		b.t.Fatal("no login request")
	}
	c := b.acceptLogin(l, subject, remember, rememberFor)
	if c == "" {
		b.t.Fatal("no consent request")
	}
	code := queryOf(b.t, b.acceptConsent(c).location, "code")
	if code == "" {
		b.t.Fatal("no code")
	}
	tok := b.redeem(client, code)
	claims, err := jwtClaims(tok.IDToken)
	if err != nil {
		b.t.Fatal(err)
	}
	sid, _ := claims["sid"].(string)
	return session{tok, sid}
}

// logoutHint is the query of a logout asked by the client: its id_token, back to
// the client with a state.
func logoutHint(idToken string) url.Values {
	return url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {testPostLogout}, "state": {"logout-state"}}
}

// askLogout asks for the logout in the browser, and returns its challenge, ""
// when Hydra answers without one, with where it then leads.
func (b *browser) askLogout(query url.Values) (string, answer) {
	b.t.Helper()
	u := b.h.public + "/oauth2/sessions/logout"
	if query != nil {
		u += "?" + query.Encode()
	}
	a := b.get(u)
	return queryOf(b.t, a.location, "logout_challenge"), a
}

// logoutVerifier asks for the logout, accepts it, and returns its verifier,
// which it does not follow.
func (b *browser) logoutVerifier(query url.Values) string {
	b.t.Helper()
	u, a := b.askLogout(query)
	if u == "" {
		b.t.Fatalf("no logout request: %d %s", a.status, a.location)
	}
	return b.h.accept(b.t, "logout", u, nil)
}

// skip reads what Hydra says of this browser in a new authorization.
func (b *browser) skip(client string) playedLogin {
	b.t.Helper()
	l := b.start(client, "")
	if l == "" {
		b.t.Fatal("no login request")
	}
	_, r := b.h.login(b.t, l)
	return r
}

// sessionInBase tells whether a logout request comes for this token: without
// one, its session is gone from the base (HLO-13).
func (h *hydraInstance) sessionInBase(t *testing.T, idToken string) bool {
	t.Helper()
	u, _ := h.browser(t).askLogout(url.Values{"id_token_hint": {idToken}})
	return u != ""
}

// wantError checks a redirection to Hydra's urls.error with this error.
func wantError(t *testing.T, a answer, name string) {
	t.Helper()
	if got := queryOf(t, a.location, "error"); got != name {
		t.Errorf("redirected to %q (%d), want the error %q", a.location, a.status, name)
	}
}

// wantDefault checks a redirection to urls.post_logout_redirect.
func wantDefault(t *testing.T, a answer) {
	t.Helper()
	if a.status != http.StatusFound || a.location != postLogoutDefault {
		t.Errorf("%d to %q, want urls.post_logout_redirect", a.status, a.location)
	}
}

// wantClientReturn checks a redirection to the client's post_logout_redirect_uri
// with its state.
func wantClientReturn(t *testing.T, a answer) {
	t.Helper()
	if a.status != http.StatusFound || a.location != testPostLogout+"?state=logout-state" {
		t.Errorf("%d to %q, want the client's return with its state", a.status, a.location)
	}
}

// frontChannelTo reads the clients a verifier's page calls.
var frontChannelTo = regexp.MustCompile(`<iframe src="http://client\.test/front/([^?"]+)`)

func frontChannels(a answer) []string {
	var out []string
	for _, m := range frontChannelTo.FindAllStringSubmatch(a.body, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return out
}

// TestHydraLogout plays the facts of HLO-2, HLO-6, HLO-8, HLO-9 and HLO-11 to
// HLO-18 on each version, as a browser, each in its own browsers and client.
func TestHydraLogout(t *testing.T) {
	cases := []struct {
		name string
		play func(t *testing.T, h *hydraInstance)
	}{
		{"HLO-2 the verifier ends the session", hlo2},
		{"HLO-2 the clients of the session", hlo2Clients},
		{"HLO-6 the verifier replayed", hlo6},
		{"HLO-7 POST and HEAD on the public port", hlo7},
		{"HLO-8 the hint of another subject", hlo8},
		{"HLO-8 the verifier in another browser", hlo8OtherBrowser},
		{"HLO-9 a session not remembered", hlo9},
		{"HLO-11 DELETE before the verifier", hlo11},
		{"HLO-11 DELETE before the verifier of a client", hlo11Client},
		{"HLO-11 a second verifier of a client", hlo11Second},
		{"HLO-11 DELETE of a session not remembered", hlo11NotRemembered},
		{"HLO-12 a session past remember_for", hlo12},
		{"HLO-12 the cookie lost", hlo12Lost},
		{"HLO-13 the hint of a session deleted", hlo13},
		{"HLO-14 prompt=login, then the former id_token", hlo14},
		{"HLO-15 a login in progress", hlo15Login},
		{"HLO-15 a consent in progress", hlo15Consent},
		{"HLO-15 prompt=login in progress", hlo15PromptLogin},
		{"HLO-16 the tokens after a logout", hlo16},
		{"HLO-17 the verifier without the cookie", hlo17},
		{"HLO-17 the verifier of a client without the cookie", hlo17Client},
		{"HLO-18 L read and started again after a DELETE", hlo18},
		{"HLO-18 prompt=none and prompt=login", hlo18Prompts},
	}
	for _, h := range instances(t) {
		t.Run(h.version, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					t.Parallel()
					c.play(t, h)
				})
			}
		})
	}
}

// HLO-1, HLO-2: the accept changes nothing, the visit of the browser does it
// all: the cookie removed, the back-channel sent, the session deleted; the page
// of the front-channel.
func hlo2(t *testing.T, h *hydraInstance) {
	client := h.client(t, true, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	verifier := b.logoutVerifier(nil)
	if !b.skip(client).Skip || !b.hasCookie() {
		t.Error("HLO-1: the accept ended the session")
	}
	h.backChannel.quiet(t, client, 0)

	a := b.get(verifier)
	if a.status != http.StatusOK || !slices.Equal(frontChannels(a), []string{client}) {
		t.Errorf("the verifier: %d, front-channels %v, want the page of %s", a.status, frontChannels(a), client)
	}
	got := h.backChannel.waitFor(t, client, 1)
	if got[0]["sid"] != s.sid {
		t.Errorf("logout token for sid %v, want %s", got[0]["sid"], s.sid)
	}
	if b.hasCookie() {
		t.Error("the session cookie stays")
	}
	if b.skip(client).Skip {
		t.Error("Hydra still says skip")
	}
	if h.sessionInBase(t, s.IDToken) {
		t.Error("the session stays in base")
	}
}

// HLO-2: the clients of the session: 2.1.2 takes that of a flow stopped at the
// consent too, 2.2.0 and 2.3.0 not, whose flow is only stored at its verifier.
func hlo2Clients(t *testing.T, h *hydraInstance) {
	done, joined, stopped := h.client(t, true, true), h.client(t, true, true), h.client(t, true, true)
	b := h.browser(t)
	b.signIn(done, "alice", true, 0)
	if c := b.acceptLogin(b.start(joined, ""), "alice", true, 0); c == "" || queryOf(t, b.acceptConsent(c).location, "code") == "" {
		t.Fatal("no code for the second client")
	}
	if b.acceptLogin(b.start(stopped, ""), "alice", true, 0) == "" {
		t.Fatal("no consent for the third client")
	}
	want := []string{done, joined}
	if h.version == "v2.1.2" {
		want = append(want, stopped)
	}
	slices.Sort(want)
	a := b.get(b.logoutVerifier(nil))
	if got := frontChannels(a); !slices.Equal(got, want) {
		t.Errorf("front-channels %v, want %v", got, want)
	}
	for _, c := range want {
		h.backChannel.waitFor(t, c, 1)
	}
}

// HLO-6: the verifier replayed: urls.error in 2.1.2, the post-logout from 2.2.
func hlo6(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	b.signIn(client, "alice", true, 0)
	verifier := b.logoutVerifier(nil)
	wantDefault(t, b.get(verifier))
	replay := b.get(verifier)
	if h.version == "v2.1.2" {
		wantError(t, replay, "Not Found")
		return
	}
	wantDefault(t, replay)
}

// HLO-7: sent by POST, the hint stays out of request_url, without which the
// logout request is the same; HEAD is refused.
func hlo7(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	if a := b.do(http.MethodHead, h.public+"/oauth2/sessions/logout", nil); a.status != http.StatusMethodNotAllowed {
		t.Errorf("HEAD: %d, want 405", a.status)
	}
	a := b.do(http.MethodPost, h.public+"/oauth2/sessions/logout", logoutHint(s.IDToken))
	u := queryOf(t, a.location, "logout_challenge")
	if u == "" {
		t.Fatalf("POST: %d %s", a.status, a.location)
	}
	status, body := h.call(t, http.MethodGet, "/admin/oauth2/auth/requests/logout", url.Values{"logout_challenge": {u}}, nil)
	var r struct {
		RequestURL  string `json:"request_url"`
		RPInitiated bool   `json:"rp_initiated"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &r) != nil {
		t.Fatalf("logout request: %d %s", status, body)
	}
	if !r.RPInitiated || r.RequestURL != "/oauth2/sessions/logout" {
		t.Errorf("rp_initiated %v, request_url %q", r.RPInitiated, r.RequestURL)
	}
}

// HLO-8: the id_token of mallory, in bob's browser: a logout request of mallory
// without a question from Hydra, whose verifier removes bob's cookie and deletes
// mallory's session. Bob's stays in base, no cookie serving it.
func hlo8(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	mallory, bob := h.browser(t), h.browser(t)
	m := mallory.signIn(client, "mallory", true, 0)
	s := bob.signIn(client, "bob", true, 0)
	u, a := bob.askLogout(logoutHint(m.IDToken))
	if u == "" {
		t.Fatalf("no logout request: %d %s", a.status, a.location)
	}
	r := h.logout(t, u)
	if !r.RPInitiated || r.Subject != "mallory" || r.SID != m.sid {
		t.Errorf("logout request %+v, want mallory's, rp_initiated", r)
	}
	wantClientReturn(t, bob.get(h.accept(t, "logout", u, nil)))
	got := h.backChannel.waitFor(t, client, 1)
	if got[0]["sid"] != m.sid {
		t.Errorf("logout token for %v, want mallory's session", got[0]["sid"])
	}
	if bob.hasCookie() {
		t.Error("bob's cookie stays")
	}
	if bob.skip(client).Skip {
		t.Error("Hydra still says skip to bob")
	}
	if mallory.skip(client).Skip {
		t.Error("Hydra still says skip to mallory")
	}
	if !h.sessionInBase(t, s.IDToken) {
		t.Error("bob's session is gone from the base")
	}
}

// HLO-8: without a hint, for a same subject: alice's verifier followed in her
// other browser deletes the session of origin and removes the cookie of the
// other, whose session stays in base.
func hlo8OtherBrowser(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	first, other := h.browser(t), h.browser(t)
	a := first.signIn(client, "alice", true, 0)
	o := other.signIn(client, "alice", true, 0)
	if a.sid == o.sid {
		t.Fatal("two browsers, one session")
	}
	wantDefault(t, other.get(first.logoutVerifier(nil)))
	if first.skip(client).Skip {
		t.Error("the session of origin lives")
	}
	if other.hasCookie() || other.skip(client).Skip {
		t.Error("the other browser's cookie stays")
	}
	if !h.sessionInBase(t, o.IDToken) {
		t.Error("the other browser's session is gone from the base")
	}
}

// HLO-9: a session not remembered gives no logout request, with or without a
// hint: neither the dispatcher nor the apps hear of it.
func hlo9(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", false, 0)
	if s.sid == "" {
		t.Fatal("no sid")
	}
	u, a := b.askLogout(nil)
	if u != "" {
		t.Error("a logout request without a hint")
	}
	wantDefault(t, a)
	u, a = b.askLogout(logoutHint(s.IDToken))
	if u != "" {
		t.Error("a logout request with a hint")
	}
	wantClientReturn(t, a)
}

// HLO-11: DELETE before the verifier: back-channel at the DELETE, not at the
// verifier, whose front-channel page is gone, the flows having lost their
// session; without rp_initiated, the post-logout, the cookie left.
func hlo11(t *testing.T, h *hydraInstance) {
	client := h.client(t, true, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	verifier := b.logoutVerifier(nil)
	h.revoke(t, s.sid)
	h.backChannel.waitFor(t, client, 1)
	if b.skip(client).Skip {
		t.Error("Hydra still says skip")
	}
	a := b.get(verifier)
	wantDefault(t, a)
	if !b.hasCookie() {
		t.Error("the verifier removed the cookie")
	}
	h.backChannel.quiet(t, client, 1)
	h.revoke(t, s.sid) // repeated: 204
}

// HLO-11: with rp_initiated, the cookie removed, the return to the client from
// 2.2, urls.error in 2.1.2 (Q45's reason not to revoke at the accept).
func hlo11Client(t *testing.T, h *hydraInstance) {
	client := h.client(t, true, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	verifier := b.logoutVerifier(logoutHint(s.IDToken))
	h.revoke(t, s.sid)
	h.backChannel.waitFor(t, client, 1)
	a := b.get(verifier)
	if b.hasCookie() {
		t.Error("the cookie stays")
	}
	if len(frontChannels(a)) != 0 {
		t.Errorf("front-channels %v, after a DELETE", frontChannels(a))
	}
	if h.version == "v2.1.2" {
		wantError(t, a, "Not Found")
		return
	}
	wantClientReturn(t, a)
}

// HLO-11: likewise without a DELETE, on a second verifier with rp_initiated: two
// logout requests of a session, the first's verifier once the second ended it.
func hlo11Second(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	first, second := b.logoutVerifier(logoutHint(s.IDToken)), b.logoutVerifier(logoutHint(s.IDToken))
	if first == second {
		t.Fatal("one verifier for two requests")
	}
	wantClientReturn(t, b.get(second))
	a := b.get(first)
	if h.version == "v2.1.2" {
		wantError(t, a, "Not Found")
		return
	}
	wantClientReturn(t, a)
}

// HLO-11: on a session not remembered, 204 without doing anything, no
// back-channel.
func hlo11NotRemembered(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	s := b.signIn(client, "carol", false, 0)
	h.revoke(t, s.sid)
	h.backChannel.quiet(t, client, 0)
}

// HLO-12: past remember_for: without a hint, no logout request; with one, a
// logout request with rp_initiated, the row staying in base. An id_token expired
// is still a hint, the id_tokens of these instances living 3 s at most.
func hlo12(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 2)
	claims, err := jwtClaims(s.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := claims["exp"].(float64)
	if ttl := time.Until(time.Unix(int64(exp), 0)); ttl > idTokenTTL {
		t.Fatalf("the id_token lives %s more: start the instance with TTL_ID_TOKEN=3s", ttl)
	}
	time.Sleep(idTokenTTL + time.Second)
	if b.skip(client).Skip {
		t.Error("Hydra says skip past remember_for")
	}
	u, a := h.browser(t).askLogout(nil)
	if u != "" {
		t.Error("a logout request without a hint")
	}
	wantDefault(t, a)
	u, a = h.browser(t).askLogout(url.Values{"id_token_hint": {s.IDToken}})
	if u == "" {
		t.Fatalf("no logout request from an expired id_token: %d %s", a.status, a.location)
	}
	if r := h.logout(t, u); !r.RPInitiated || r.SID != s.sid {
		t.Errorf("logout request %+v, want the session's, rp_initiated", r)
	}
}

// HLO-12: the cookie lost, remember_for 0 and the browser started again: the
// same.
func hlo12Lost(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	s := h.browser(t).signIn(client, "alice", true, 0)
	restarted := h.browser(t)
	u, a := restarted.askLogout(nil)
	if u != "" {
		t.Error("a logout request without a hint")
	}
	wantDefault(t, a)
	if u, a = restarted.askLogout(url.Values{"id_token_hint": {s.IDToken}}); u == "" {
		t.Fatalf("no logout request with a hint: %d %s", a.status, a.location)
	}
}

// HLO-13: the hint of a session deleted gives no logout request: back to the
// client with its state, else to the post-logout.
func hlo13(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	s := h.browser(t).signIn(client, "alice", true, 0)
	h.revoke(t, s.sid)
	u, a := h.browser(t).askLogout(logoutHint(s.IDToken))
	if u != "" {
		t.Error("a logout request with a post_logout_redirect_uri")
	}
	wantClientReturn(t, a)
	u, a = h.browser(t).askLogout(url.Values{"id_token_hint": {s.IDToken}})
	if u != "" {
		t.Error("a logout request")
	}
	wantDefault(t, a)
}

// HLO-14: prompt=login makes a new session from the login request on, a new
// cookie once accepted, the former staying in base. The former id_token gives a
// logout request of the former sid, whose verifier removes the current cookie
// and deletes the former session; the current stays in base without a cookie,
// its clients not told.
func hlo14(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	former := b.signIn(client, "alice", true, 0)
	l := b.start(client, "login")
	_, r := h.login(t, l)
	if r.Skip || r.SessionID == former.sid || r.SessionID == "" {
		t.Errorf("prompt=login: skip %v, session %q, the former %q", r.Skip, r.SessionID, former.sid)
	}
	c := b.acceptLogin(l, "alice", true, 0)
	if got := h.consent(t, c).LoginSessionID; got != r.SessionID {
		t.Errorf("consent of session %q, want %q", got, r.SessionID)
	}
	current := b.redeem(client, queryOf(t, b.acceptConsent(c).location, "code"))
	if now := b.skip(client); !now.Skip || now.SessionID != r.SessionID {
		t.Errorf("the browser's session %+v, want the new one", now)
	}

	u, _ := b.askLogout(logoutHint(former.IDToken))
	if u == "" {
		t.Fatal("no logout request from the former id_token")
	}
	if got := h.logout(t, u); !got.RPInitiated || got.SID != former.sid {
		t.Errorf("logout request %+v, want the former session", got)
	}
	wantClientReturn(t, b.get(h.accept(t, "logout", u, nil)))
	sent := h.backChannel.waitFor(t, client, 1)
	if sent[0]["sid"] != former.sid {
		t.Errorf("logout token for %v, want the former session", sent[0]["sid"])
	}
	h.backChannel.quiet(t, client, 1)
	if b.hasCookie() || b.skip(client).Skip {
		t.Error("the current cookie stays")
	}
	if !h.sessionInBase(t, current.IDToken) {
		t.Error("the current session is gone from the base")
	}
}

// HLO-15: a login in progress as a logout ends: in 2.1.2 the foreign key empties
// session_id, and the flow ends with a code and an id_token of no sid, which the
// logout refuses; from 2.2 the field keeps its value, coming from the challenge,
// and the client gets error=error at the consent's verifier.
func hlo15Login(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	l := b.start(client, "")
	if _, r := h.login(t, l); !r.Skip || r.SessionID != s.sid {
		t.Fatalf("second login %+v, want a skip of the session", r)
	}
	wantDefault(t, b.get(b.logoutVerifier(nil)))

	_, r := h.login(t, l)
	c := b.acceptLogin(l, "alice", true, 0)
	if c == "" {
		t.Fatal("no consent request")
	}
	consent := h.consent(t, c)
	end := b.acceptConsent(c)
	if h.version == "v2.1.2" {
		if r.SessionID != "" || consent.LoginSessionID != "" {
			t.Errorf("session_id %q, login_session_id %q: want them emptied", r.SessionID, consent.LoginSessionID)
		}
		tok := b.redeem(client, queryOf(t, end.location, "code"))
		claims, err := jwtClaims(tok.IDToken)
		if err != nil {
			t.Fatal(err)
		}
		if sid, _ := claims["sid"].(string); sid != "" {
			t.Errorf("id_token of sid %q, want none", sid)
		}
		u, a := h.browser(t).askLogout(url.Values{"id_token_hint": {tok.IDToken}})
		if u != "" {
			t.Error("a logout request from an id_token without sid")
		}
		wantError(t, a, "invalid_request")
		return
	}
	if r.SessionID != s.sid || consent.LoginSessionID != s.sid {
		t.Errorf("session_id %q, login_session_id %q: want them kept", r.SessionID, consent.LoginSessionID)
	}
	wantError(t, end, "error")
}

// HLO-15: a consent in progress: the same, its login accepted before the logout.
func hlo15Consent(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	c := b.acceptLogin(b.start(client, ""), "alice", true, 0)
	if got := h.consent(t, c).LoginSessionID; got != s.sid {
		t.Fatalf("consent of session %q, want %q", got, s.sid)
	}
	wantDefault(t, b.get(b.logoutVerifier(nil)))
	got := h.consent(t, c).LoginSessionID
	end := b.acceptConsent(c)
	if h.version == "v2.1.2" {
		if got != "" {
			t.Errorf("login_session_id %q: want it emptied", got)
		}
		if queryOf(t, end.location, "code") == "" {
			t.Errorf("redirected to %q, want a code", end.location)
		}
		return
	}
	if got != s.sid {
		t.Errorf("login_session_id %q: want it kept", got)
	}
	wantError(t, end, "error")
}

// HLO-15: prompt=login is apart: its own session, the flow ends normally.
func hlo15PromptLogin(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	b.signIn(client, "alice", true, 0)
	l := b.start(client, "login")
	wantDefault(t, b.get(b.logoutVerifier(nil)))
	c := b.acceptLogin(l, "alice", true, 0)
	if c == "" {
		t.Fatal("no consent request")
	}
	if queryOf(t, b.acceptConsent(c).location, "code") == "" {
		t.Error("no code")
	}
	if !b.skip(client).Skip {
		t.Error("the new session is not remembered")
	}
}

// HLO-16: a logout, even complete, revokes neither the access token nor the
// refresh token: only the back-channel tells the clients.
func hlo16(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	wantDefault(t, b.get(b.logoutVerifier(nil)))
	h.backChannel.waitFor(t, client, 1)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.admin+"/admin/oauth2/introspect", strings.NewReader(url.Values{"token": {s.Access}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var active struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&active); err != nil {
		t.Fatal(err)
	}
	if !active.Active {
		t.Error("the access token is no longer active")
	}
	a := b.do(http.MethodPost, h.public+"/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {s.Refresh}, "client_id": {client}, "client_secret": {testSecret},
	})
	if a.status != http.StatusOK {
		t.Errorf("refresh: %d %s", a.status, a.body)
	}
}

// HLO-17: the verifier followed without the browser's cookie, rp_initiated false:
// the post-logout, without effect, the session whole; in 2.1.2 the verifier is
// spent, and the browser that follows it next ends on urls.error.
func hlo17(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	b.signIn(client, "alice", true, 0)
	verifier := b.logoutVerifier(nil)
	wantDefault(t, h.browser(t).get(verifier))
	h.backChannel.quiet(t, client, 0)
	if !b.skip(client).Skip {
		t.Error("the session ended without the browser's cookie")
	}
	a := b.get(verifier)
	if h.version == "v2.1.2" {
		wantError(t, a, "Not Found")
		if !b.skip(client).Skip {
			t.Error("the spent verifier ended the session")
		}
		return
	}
	wantDefault(t, a)
	if b.skip(client).Skip {
		t.Error("the browser's verifier did not end the session")
	}
}

// HLO-17: rp_initiated true: the session deleted, the back-channel sent, the
// return to the client, or the front-channel's page; the browser's cookie stays,
// without effect. Without post_logout_redirect_uri, urls.post_logout_redirect.
func hlo17Client(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	wantClientReturn(t, h.browser(t).get(b.logoutVerifier(logoutHint(s.IDToken))))
	h.backChannel.waitFor(t, client, 1)
	if !b.hasCookie() {
		t.Error("the browser's cookie is gone")
	}
	if b.skip(client).Skip {
		t.Error("Hydra still says skip")
	}

	withFront := h.client(t, true, false)
	b = h.browser(t)
	s = b.signIn(withFront, "alice", true, 0)
	a := h.browser(t).get(b.logoutVerifier(logoutHint(s.IDToken)))
	if a.status != http.StatusOK || !slices.Equal(frontChannels(a), []string{withFront}) {
		t.Errorf("%d, front-channels %v, want the page", a.status, frontChannels(a))
	}

	b = h.browser(t)
	s = b.signIn(client, "alice", true, 0)
	wantDefault(t, h.browser(t).get(b.logoutVerifier(url.Values{"id_token_hint": {s.IDToken}})))
}

// HLO-18: what SKP-12 and SKP-13 rely on. After a DELETE, L read again says skip
// still, with session_id emptied in 2.1.2, kept from 2.2; its request_url gives a
// new L, no skip, a new session; another subject gets a code, as the same does. A
// former L no longer goes on: no consent, only the last does.
func hlo18(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, true)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	b.logoutVerifier(nil) // the chain stops: the verifier is not followed
	first := b.start(client, "")
	status, r := h.login(t, first)
	if status != http.StatusOK || !r.Skip || r.SessionID != s.sid {
		t.Fatalf("L: %d %+v, want a skip of the session", status, r)
	}
	h.revoke(t, s.sid)
	h.backChannel.waitFor(t, client, 1)
	h.revoke(t, s.sid) // repeated: 204

	status, again := h.login(t, first)
	wantSID := s.sid
	if h.version == "v2.1.2" {
		wantSID = ""
	}
	if status != http.StatusOK || !again.Skip || again.SessionID != wantSID {
		t.Errorf("L read again: %d, skip %v, session %q, want skip and %q", status, again.Skip, again.SessionID, wantSID)
	}

	older := queryOf(t, b.follow(r.RequestURL).location, "login_challenge")
	last := queryOf(t, b.follow(r.RequestURL).location, "login_challenge")
	if _, nl := h.login(t, last); nl.Skip || nl.SessionID == "" || nl.SessionID == s.sid {
		t.Errorf("new L %+v, want no skip and a new session", nl)
	}
	// Hydra's login cookie is the last request's: a former one gets no consent.
	if c := b.acceptLogin(older, "bob", true, 0); c != "" {
		t.Error("a former L went on to a consent")
	}
	last = queryOf(t, b.follow(r.RequestURL).location, "login_challenge")
	c := b.acceptLogin(last, "bob", true, 0)
	if c == "" {
		t.Fatal("the last L: no consent")
	}
	if queryOf(t, b.acceptConsent(c).location, "code") == "" {
		t.Error("another subject gets no code")
	}
	if now := b.skip(client); !now.Skip || now.Subject != "bob" {
		t.Errorf("the browser's session %+v, want bob's", now)
	}
}

// HLO-18: with prompt=none, login_required at the client, from Hydra; with
// prompt=login, no skip, a new session_id, the former staying in base (HLO-14).
func hlo18Prompts(t *testing.T, h *hydraInstance) {
	client := h.client(t, false, false)
	b := h.browser(t)
	s := b.signIn(client, "alice", true, 0)
	b.logoutVerifier(nil)
	l := b.start(client, "none")
	_, r := h.login(t, l)
	if !r.Skip || r.SessionID != s.sid {
		t.Fatalf("prompt=none: %+v, want a skip of the session", r)
	}
	h.revoke(t, s.sid)
	wantError(t, b.follow(r.RequestURL), "login_required")

	b = h.browser(t)
	s = b.signIn(client, "alice", true, 0)
	b.logoutVerifier(nil)
	_, r = h.login(t, b.start(client, "login"))
	if r.Skip || r.SessionID == s.sid || r.SessionID == "" {
		t.Errorf("prompt=login: %+v, want no skip and a new session", r)
	}
	if !h.sessionInBase(t, s.IDToken) {
		t.Error("the former session is gone from the base")
	}
}
