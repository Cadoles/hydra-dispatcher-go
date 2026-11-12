package adminui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
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
