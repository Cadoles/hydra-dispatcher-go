package adminui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The tests of the revue R42.

// A login by the provider is fresh only when the provider authenticated the
// user within the window: its auth_time. Otherwise the first sensitive action
// asks the provider again.
func TestOIDCLoginFreshness(t *testing.T) {
	for name, c := range map[string]struct {
		authTime func(now time.Time) any
		fresh    bool
	}{
		"now":            {func(now time.Time) any { return now.Unix() }, true},
		"an hour ago":    {func(now time.Time) any { return now.Add(-time.Hour).Unix() }, false},
		"absent":         {nil, false},
		"10 hours ahead": {func(now time.Time) any { return now.Add(10 * time.Hour).Unix() }, false},
		"30 s ahead":     {func(now time.Time) any { return now.Add(30 * time.Second).Unix() }, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "http://dispatcher.test")
			p := withIdP(r)
			b := r.browser()
			auth := b.startOIDC("/admin/oidc/login")
			claims := p.claims("sub-1", auth)
			delete(claims, "auth_time")
			if c.authTime != nil {
				claims["auth_time"] = c.authTime(r.clock())
			}
			if w := b.do(http.MethodGet, p.grant(auth, claims), nil); w.Code != http.StatusSeeOther {
				t.Fatalf("login: %d\n%s", w.Code, w.Body)
			}
			w := b.do(http.MethodGet, "/admin/test/sensitive", nil)
			switch {
			case c.fresh && w.Code != http.StatusOK:
				t.Errorf("fresh, refused: %d", w.Code)
			case !c.fresh && (w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/admin/oidc/login?reauth=1")):
				t.Errorf("not fresh, let through: %d %s", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// A re-authentication of an auth_time ahead of the clocks' skew is refused.
func TestOIDCReauthAhead(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	p := withIdP(r)
	b := r.browser()
	auth := b.startOIDC("/admin/oidc/login")
	b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil)
	r.advance(6 * time.Minute)
	auth = b.startOIDC("/admin/oidc/login?reauth=1&next=/admin/test/sensitive")
	claims := p.claims("sub-1", auth)
	claims["auth_time"] = r.clock().Add(10 * time.Hour).Unix()
	if w := b.do(http.MethodGet, p.grant(auth, claims), nil); w.Code != http.StatusForbidden {
		t.Errorf("10 hours ahead: %d", w.Code)
	}
	if w := b.do(http.MethodGet, "/admin/test/sensitive", nil); w.Code == http.StatusOK {
		t.Error("fresh by an auth_time ahead")
	}
}

// hugeAnswer answers a JSON of n MiB of spaces, then its tail.
func hugeAnswer(n int, tail func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat(" ", 1<<20))
		for range n {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(tail()))
	}
}

// A provider that answers a discovery or keys over the bound is refused, not
// read whole.
func TestProviderAnswersBounded(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	var srv *httptest.Server
	srv = httptest.NewServer(hugeAnswer(2, func() string {
		return `{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/a","token_endpoint":"` + srv.URL + `/t","jwks_uri":"` + srv.URL + `/j"}`
	}))
	defer srv.Close()
	r.config.oidc = &store.AdminOIDC{Enabled: true, Issuer: srv.URL, ClientID: "c", Scopes: []string{"openid"}, UsernameClaim: "sub", RequiredACR: []string{}}
	if w := r.browser().do(http.MethodGet, "/admin/oidc/login", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a discovery of 2 MiB: %d", w.Code)
	}

	r2 := newRig(t, "http://dispatcher.test")
	p := withIdP(r2)
	keys := httptest.NewServer(hugeAnswer(2, func() string { return `{"keys":[]}` }))
	defer keys.Close()
	r2.config.oidc.AuthorizationEndpoint = p.srv.URL + "/authorize"
	r2.config.oidc.TokenEndpoint = p.srv.URL + "/token"
	r2.config.oidc.JWKSURI = keys.URL + "/jwks"
	b := r2.browser()
	auth := b.startOIDC("/admin/oidc/login")
	if w := b.do(http.MethodGet, p.grant(auth, p.claims("sub-1", auth)), nil); w.Code != http.StatusForbidden || b.cookies[sessionCookie] != nil {
		t.Errorf("keys of 2 MiB: %d", w.Code)
	}
}

// A browser that leaves during the discovery does not make the provider
// unavailable for the others.
func TestAbortedDiscovery(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	withIdP(r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/oidc/login", nil).WithContext(ctx)
	req.RemoteAddr = "10.1.2.3:1"
	r.handler.ServeHTTP(httptest.NewRecorder(), req)
	if w := r.browser().do(http.MethodGet, "/admin/oidc/login", nil); w.Code != http.StatusSeeOther {
		t.Errorf("after an aborted discovery: %d", w.Code)
	}
}

// The version of the screen SSO holds the secret, sealed: another admin who
// writes it, the same or another, between the page and its save makes the
// save refused, the secret typed or forgotten as the rest (revue R42). The
// page never holds the secret, nor a digest of it in clear.
func TestSSOVersionHoldsTheSecret(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	withIdP(r)
	b := r.browser()
	b.login("alice", password, "")
	for name, mod := range map[string]func(v map[string][]string){
		"a secret typed":     func(v map[string][]string) { v["admin_oidc.client_secret"] = []string{"mine-mine-mine"} },
		"the secret forgot":  func(v map[string][]string) { v["forget_secret"] = []string{"true"} },
		"nothing else typed": func(map[string][]string) {},
	} {
		t.Run(name, func(t *testing.T) {
			v := ssoValues(b)
			mod(v)
			// Another admin writes another secret.
			theirs := "theirs-" + name
			if err := r.config.UpdateSettings(context.Background(), "admin:other", map[string]json.RawMessage{"admin_oidc.client_secret": json.RawMessage(`"` + theirs + `"`)}); err != nil {
				t.Fatal(err)
			}
			w := b.do(http.MethodPost, "/admin/sso", v)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Another admin changed it") {
				t.Fatalf("%d\n%s", w.Code, w.Body)
			}
			if got := r.config.Snapshot().Settings.AdminOIDC.ClientSecret; got != theirs {
				t.Errorf("the secret of the other admin written over: %q", got)
			}
			if strings.Contains(w.Body.String(), theirs) {
				t.Error("the secret in the page")
			}
		})
	}
	// The same secret written again changes nothing, nor the version.
	v := ssoValues(b)
	if err := r.config.UpdateSettings(context.Background(), "admin:other", map[string]json.RawMessage{"admin_oidc.client_secret": json.RawMessage(`"` + r.config.Snapshot().Settings.AdminOIDC.ClientSecret + `"`)}); err != nil {
		t.Fatal(err)
	}
	v.Set("admin_oidc.scopes", "openid email")
	if w := b.do(http.MethodPost, "/admin/sso", v); w.Code != http.StatusSeeOther {
		t.Errorf("the same secret: %d", w.Code)
	}
	// The form shown again carries the version of now: saved.
	v = ssoValues(b)
	v["admin_oidc.client_secret"] = []string{"mine-mine-mine"}
	if w := b.do(http.MethodPost, "/admin/sso", v); w.Code != http.StatusSeeOther || r.config.Snapshot().Settings.AdminOIDC.ClientSecret != "mine-mine-mine" {
		t.Errorf("saved: %d\n%s", w.Code, w.Body)
	}
}
