package adminui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// idp is an identity provider for the tests: its discovery, its keys, and a
// token endpoint that checks the client, the code and its PKCE verifier.
// Its codes are given by grant, as the provider would at the end of its
// login page.
type idp struct {
	t         *testing.T
	srv       *httptest.Server
	key       *rsa.PrivateKey
	now       func() time.Time
	mu        sync.Mutex
	codes     map[string]grant
	discovery atomic.Int32
	// sign, when set, signs the ID tokens instead of the key: another
	// algorithm, another key.
	sign func(jwt.MapClaims) string
}

// grant is what a code gives: the challenge of its PKCE, and the claims of
// its ID token.
type grant struct {
	challenge string
	claims    jwt.MapClaims
}

const (
	idpClient = "dispatcher-admin"
	idpSecret = "the secret of the client"
)

func newIdP(t *testing.T, now func() time.Time) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{t: t, key: key, now: now, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.discovery.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		// The credentials of Basic are form-encoded (RFC 6749, 2.3.1).
		id, secret, ok := r.BasicAuth()
		if ok {
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
		} else {
			id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
		}
		p.mu.Lock()
		g, found := p.codes[r.PostFormValue("code")]
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if id != idpClient || secret != idpSecret || !found || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		p.mu.Lock()
		delete(p.codes, r.PostFormValue("code")) // once
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": p.idToken(g.claims)})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) idToken(claims jwt.MapClaims) string {
	if p.sign != nil {
		return p.sign(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	return s
}

// claims are those of an ID token of sub for the request at auth, valid.
func (p *idp) claims(sub string, auth *url.URL) jwt.MapClaims {
	now := p.now()
	return jwt.MapClaims{"iss": p.srv.URL, "aud": idpClient, "sub": sub, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": auth.Query().Get("nonce"), "auth_time": now.Unix()}
}

// grant gives a code for the request at auth with claims, and the address
// of the callback the provider sends the browser to.
func (p *idp) grant(auth *url.URL, claims jwt.MapClaims) string {
	code := randomToken()
	p.mu.Lock()
	p.codes[code] = grant{challenge: auth.Query().Get("code_challenge"), claims: claims}
	p.mu.Unlock()
	cb, _ := url.Parse(auth.Query().Get("redirect_uri"))
	return cb.Path + "?" + url.Values{"code": {code}, "state": {auth.Query().Get("state")}}.Encode()
}

// withIdP gives the rig a provider, and the block admin_oidc that names it.
func withIdP(r *rig) *idp {
	p := newIdP(r.t, r.clock)
	r.config.oidc = &store.AdminOIDC{Enabled: true, Issuer: p.srv.URL, ClientID: idpClient, ClientSecret: idpSecret,
		Scopes: []string{"openid", "email", "profile"}, UsernameClaim: "preferred_username", RequiredACR: []string{}}
	return p
}

// startOIDC opens the login by the provider, and gives the request the
// browser is sent to.
func (b *browser) startOIDC(path string) *url.URL {
	b.r.t.Helper()
	w := b.do(http.MethodGet, path, nil)
	if w.Code != http.StatusSeeOther {
		b.r.t.Fatalf("%s: %d\n%s", path, w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		b.r.t.Fatal(err)
	}
	return u
}

func TestOIDCLogin(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	p := withIdP(r)
	b := r.browser()
	login := b.do(http.MethodGet, "/admin/login?next=/admin/apps", nil)
	if !strings.Contains(login.Body.String(), `href="/admin/oidc/login?next=%2fadmin%2fapps"`) || !strings.Contains(login.Body.String(), `name="password"`) {
		t.Fatalf("login page:\n%s", login.Body)
	}
	auth := b.startOIDC("/admin/oidc/login?next=/admin/apps")
	q := auth.Query()
	if !strings.HasPrefix(auth.String(), p.srv.URL+"/authorize?") || q.Get("client_id") != idpClient || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != "http://dispatcher.test/admin/oidc/callback" || len(q.Get("state")) < 22 || len(q.Get("nonce")) < 22 ||
		q.Get("scope") != "openid email profile" || q.Get("prompt") != "" {
		t.Fatalf("authorize: %s", auth)
	}
	w := b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/apps" || b.cookies[oidcCookie] != nil {
		t.Fatalf("callback: %d %s\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if page := b.do(http.MethodGet, "/admin/apps", nil); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `>olga</a> <small>(admin)</small>`) {
		t.Errorf("as olga: %d", page.Code)
	}
	if got := r.audited(); !slices.Equal(got, []string{"login olga oidc granted"}) {
		t.Errorf("audit: %q", got)
	}
	// The provider was discovered once: a second login does not again.
	other := r.browser()
	auth = other.startOIDC("/admin/oidc/login")
	other.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil)
	if n := p.discovery.Load(); n != 1 {
		t.Errorf("discoveries: %d", n)
	}
}

// What the callback refuses, each with its reason at the audit.
func TestOIDCRefused(t *testing.T) {
	for name, c := range map[string]struct {
		claims func(p *idp, auth *url.URL) jwt.MapClaims
		setup  func(r *rig, p *idp)
		code   int
		reason string
	}{
		"another nonce": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("sub-1", auth)
			c["nonce"] = "another"
			return c
		}, nil, http.StatusForbidden, "id_token"},
		"another audience": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("sub-1", auth)
			c["aud"] = "another-client"
			return c
		}, nil, http.StatusForbidden, "id_token"},
		"another issuer": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("sub-1", auth)
			c["iss"] = "https://evil.test"
			return c
		}, nil, http.StatusForbidden, "id_token"},
		"expired": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("sub-1", auth)
			c["exp"] = p.now().Add(-time.Minute).Unix()
			return c
		}, nil, http.StatusForbidden, "id_token"},
		"no sub": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("", auth)
			delete(c, "sub")
			return c
		}, nil, http.StatusForbidden, "id_token"},
		"HS256 by the client's secret": {func(p *idp, auth *url.URL) jwt.MapClaims { return p.claims("sub-1", auth) }, func(_ *rig, p *idp) {
			p.sign = func(c jwt.MapClaims) string {
				s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(idpSecret))
				return s
			}
		}, http.StatusForbidden, "id_token"},
		"another key": {func(p *idp, auth *url.URL) jwt.MapClaims { return p.claims("sub-1", auth) }, func(r *rig, p *idp) {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			p.sign = func(c jwt.MapClaims) string {
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
				tok.Header["kid"] = "k1"
				s, _ := tok.SignedString(other)
				return s
			}
		}, http.StatusForbidden, "id_token"},
		"an acr too weak": {func(p *idp, auth *url.URL) jwt.MapClaims {
			c := p.claims("sub-1", auth)
			c["acr"] = "pwd"
			return c
		}, func(r *rig, _ *idp) { r.config.oidc.RequiredACR = []string{"mfa", "loa3"} }, http.StatusForbidden, "acr"},
		"a subject no account has": {func(p *idp, auth *url.URL) jwt.MapClaims { return p.claims("stranger", auth) }, nil, http.StatusForbidden, "unknown_subject"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "http://dispatcher.test")
			p := withIdP(r)
			if c.setup != nil {
				c.setup(r, p)
			}
			b := r.browser()
			auth := b.startOIDC("/admin/oidc/login")
			w := b.do(http.MethodGet, p.grant(auth, c.claims(p, auth)), nil)
			if w.Code != c.code || b.cookies[sessionCookie] != nil {
				t.Errorf("%d, session %v\n%s", w.Code, b.cookies[sessionCookie], w.Body)
			}
			if got := r.audited(); len(got) != 1 || !strings.HasSuffix(got[0], "oidc refused "+c.reason) {
				t.Errorf("audit: %q", got)
			}
		})
	}
}

// The state, the cookie that holds it, its delay, the verifier of PKCE.
func TestOIDCState(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	p := withIdP(r)
	b := r.browser()
	auth := b.startOIDC("/admin/oidc/login")
	back := p.grant(auth, p.claims("sub-1", auth))
	// Another browser, without the cookie: a login forced on a victim.
	if w := r.browser().do(http.MethodGet, back, nil); w.Code != http.StatusBadRequest {
		t.Errorf("without the cookie: %d", w.Code)
	}
	forged := strings.Replace(back, "state=", "state=x", 1)
	if w := b.do(http.MethodGet, forged, nil); w.Code != http.StatusBadRequest {
		t.Errorf("another state: %d", w.Code)
	}
	// The cookie is spent: the right state does not pass again.
	if w := b.do(http.MethodGet, back, nil); w.Code != http.StatusBadRequest {
		t.Errorf("the cookie spent: %d", w.Code)
	}
	auth = b.startOIDC("/admin/oidc/login")
	back = p.grant(auth, p.claims("sub-1", auth))
	r.advance(oidcTTL + time.Second)
	if w := b.do(http.MethodGet, back, nil); w.Code != http.StatusBadRequest {
		t.Errorf("too late: %d", w.Code)
	}
	// A code for another challenge: the provider refuses the verifier.
	auth = b.startOIDC("/admin/oidc/login")
	q := auth.Query()
	q.Set("code_challenge", "another")
	auth.RawQuery = q.Encode()
	if w := b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil); w.Code != http.StatusForbidden {
		t.Errorf("another verifier: %d", w.Code)
	}
	// An error of the provider.
	auth = b.startOIDC("/admin/oidc/login")
	if w := b.do(http.MethodGet, "/admin/oidc/callback?error=access_denied&state="+auth.Query().Get("state"), nil); w.Code != http.StatusForbidden {
		t.Errorf("an error: %d", w.Code)
	}
	if b.cookies[sessionCookie] != nil {
		t.Error("logged in")
	}
}

// With admin_oidc.auto_create, a subject no account has gets one, viewer,
// named by its claim, a name taken suffixed.
func TestOIDCAutoCreate(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	p := withIdP(r)
	r.config.oidc.AutoCreate = true
	login := func(sub string, extra jwt.MapClaims) *browser {
		b := r.browser()
		auth := b.startOIDC("/admin/oidc/login")
		c := p.claims(sub, auth)
		for k, v := range extra {
			c[k] = v
		}
		if w := b.do(http.MethodGet, p.grant(auth, c), nil); w.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d\n%s", sub, w.Code, w.Body)
		}
		r.advance(time.Second)
		return b
	}
	b := login("sub-dora-1234567890", jwt.MapClaims{"preferred_username": "dora", "email": "dora@example.com"})
	u, found, _ := r.accounts.Admin(t.Context(), "dora")
	if !found || u.Role != domain.RoleViewer || u.OIDCSub != "sub-dora-1234567890" || u.PasswordHash != "" {
		t.Fatalf("dora: %+v", u)
	}
	if w := b.do(http.MethodGet, "/admin", nil); w.Code != http.StatusOK {
		t.Errorf("dora's session: %d", w.Code)
	}
	// alice is a name taken, by an account of a password: never joined.
	login("sub-alice-abcdefgh", jwt.MapClaims{"preferred_username": "alice"})
	if u, found, _ := r.accounts.Admin(t.Context(), "alice_sub-alic"); !found || u.Role != domain.RoleViewer {
		t.Errorf("alice of the provider: %+v %v", u, found)
	}
	if u, _, _ := r.accounts.Admin(t.Context(), "alice"); u.OIDCSub != "" || u.Role != domain.RoleAdmin {
		t.Errorf("alice taken over: %+v", u)
	}
	// A claim no name may be: the email, then the sub.
	login("sub-x", jwt.MapClaims{"preferred_username": " spaced ", "email": "x@example.com"})
	if _, found, _ := r.accounts.Admin(t.Context(), "x@example.com"); !found {
		t.Error("named by the email")
	}
	if got := r.wrote(); !slices.Contains(got, "write dora admin-users dora create role,oidc_sub") {
		t.Errorf("audit: %q", got)
	}
}

// A session of the provider re-authenticates there: prompt=login, max_age=0,
// an auth_time of now, the same subject.
func TestOIDCReauth(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	p := withIdP(r)
	b := r.browser()
	auth := b.startOIDC("/admin/oidc/login")
	b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil)
	r.advance(6 * time.Minute)
	w := b.do(http.MethodGet, "/admin/test/sensitive", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/oidc/login?reauth=1&next=%2Fadmin%2Ftest%2Fsensitive" {
		t.Fatalf("sensitive: %d %s", w.Code, w.Header().Get("Location"))
	}
	auth = b.startOIDC(w.Header().Get("Location"))
	if auth.Query().Get("prompt") != "login" || auth.Query().Get("max_age") != "0" {
		t.Errorf("authorize: %s", auth)
	}
	// An auth_time of before: the provider did not authenticate anew.
	old := p.claims("sub-1", auth)
	old["auth_time"] = r.clock().Add(-time.Hour).Unix()
	if w := b.do(http.MethodGet, p.grant(auth, old), nil); w.Code != http.StatusForbidden {
		t.Errorf("an old auth_time: %d", w.Code)
	}
	// Another subject, another account's: alice's.
	another, _, _ := r.accounts.Admin(t.Context(), "alice")
	another.OIDCSub = "sub-2"
	r.accounts.set(another)
	auth = b.startOIDC("/admin/oidc/login?reauth=1&next=/admin/test/sensitive")
	if w := b.do(http.MethodGet, p.grant(auth, p.claims("sub-2", auth)), nil); w.Code != http.StatusForbidden {
		t.Errorf("another subject: %d", w.Code)
	}
	auth = b.startOIDC("/admin/oidc/login?reauth=1&next=/admin/test/sensitive")
	w = b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/test/sensitive" {
		t.Fatalf("reauth: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := b.do(http.MethodGet, "/admin/test/sensitive", nil); w.Code != http.StatusOK {
		t.Errorf("sensitive after: %d", w.Code)
	}
	if got := r.audited(); !slices.Contains(got, "login olga oidc granted reauth") || !slices.Contains(got, "login olga oidc refused auth_time") ||
		!slices.Contains(got, "login olga oidc refused reauth_subject") {
		t.Errorf("audit: %q", got)
	}
	// An account without a subject cannot confirm there.
	victor := r.browser()
	victor.login("victor", password, "")
	if w := victor.do(http.MethodGet, "/admin/oidc/login?reauth=1", nil); w.Code != http.StatusForbidden {
		t.Errorf("victor: %d", w.Code)
	}
}

// admin.ui.password_login false: the provider alone; the login and the
// re-authentication by password refused.
func TestPasswordLoginOff(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	withIdP(r)
	b := r.browser()
	b.login("alice", password, "") // before the switch
	r.ui.o.PasswordLogin = false
	if page := r.browser().do(http.MethodGet, "/admin/login", nil).Body.String(); strings.Contains(page, `name="password"`) || !strings.Contains(page, "/admin/oidc/login") {
		t.Errorf("login page:\n%s", page)
	}
	if w := r.browser().do(http.MethodPost, "/admin/login", url.Values{"username": {"alice"}, "password": {password}}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "The login by password is off") {
		t.Errorf("a login by password: %d\n%s", w.Code, w.Body)
	}
	r.advance(6 * time.Minute)
	if w := b.do(http.MethodGet, "/admin/test/sensitive", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/admin/oidc/login?reauth=1") {
		t.Errorf("a sensitive page: %d %s", w.Code, w.Header().Get("Location"))
	}
	form := b.do(http.MethodGet, "/admin/reauth", nil)
	if w := b.do(http.MethodPost, "/admin/reauth", url.Values{"csrf": {token(t, form)}, "password": {password}}); w.Code != http.StatusForbidden {
		t.Errorf("a reauth by password: %d", w.Code)
	}
	r.config.oidc = nil
	if page := r.browser().do(http.MethodGet, "/admin/login", nil).Body.String(); !strings.Contains(page, "No way of logging in is open") {
		t.Errorf("nothing open:\n%s", page)
	}
}

// The provider off, or that cannot be reached.
func TestOIDCUnavailable(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	if w := r.browser().do(http.MethodGet, "/admin/oidc/login", nil); w.Code != http.StatusNotFound {
		t.Errorf("off: %d", w.Code)
	}
	p := withIdP(r)
	p.srv.Close()
	if w := r.browser().do(http.MethodGet, "/admin/oidc/login", nil); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Errorf("unreachable: %d\n%s", w.Code, w.Body)
	}
}
