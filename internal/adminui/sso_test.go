package adminui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// ssoValues is the form of the screen SSO as the page gives it, unchanged.
func ssoValues(b *browser) url.Values {
	b.r.t.Helper()
	page := b.do(http.MethodGet, "/admin/sso", nil)
	snap := b.r.config.Snapshot()
	f := ssoFormOf(snap.Settings.AdminOIDC, snap.Sealed["admin_oidc.client_secret"])
	v := url.Values{"csrf": {token(b.r.t, page)}, "version": {f.Version}, "admin_oidc.issuer": {f.Issuer}, "admin_oidc.client_id": {f.ClientID},
		"admin_oidc.scopes": {f.Scopes}, "admin_oidc.username_claim": {f.UsernameClaim}, "admin_oidc.required_acr": {f.RequiredACR},
		"admin_oidc.authorization_endpoint": {f.AuthorizationEndpoint}, "admin_oidc.token_endpoint": {f.TokenEndpoint}, "admin_oidc.jwks_uri": {f.JWKSURI}}
	if f.Enabled {
		v.Set("admin_oidc.enabled", "true")
	}
	if f.AutoCreate {
		v.Set("admin_oidc.auto_create", "true")
	}
	return v
}

func TestSSO(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/sso", nil).Body.String()
	if !strings.Contains(page, "<code>http://dispatcher.test/admin/oidc/callback</code>") || !strings.Contains(page, "No secret is set.") ||
		!strings.Contains(page, `name="admin_oidc.scopes" value="openid email profile"`) {
		t.Fatalf("page:\n%s", page)
	}
	form := ssoValues(b)
	form.Set("admin_oidc.enabled", "true")
	form.Set("admin_oidc.issuer", "https://idp.test")
	form.Set("admin_oidc.client_id", "dispatcher-admin")
	form.Set("admin_oidc.client_secret", "the secret of the client")
	form.Set("admin_oidc.required_acr", "mfa loa3")
	w := b.do(http.MethodPost, "/admin/sso", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/sso?done=saved" {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	o := *r.config.oidc
	if !o.Enabled || o.Issuer != "https://idp.test" || o.ClientSecret != "the secret of the client" || !slices.Equal(o.RequiredACR, []string{"mfa", "loa3"}) {
		t.Errorf("block: %+v", o)
	}
	page = b.do(http.MethodGet, "/admin/sso?done=saved", nil).Body.String()
	if strings.Contains(page, "the secret of the client") || !strings.Contains(page, "A secret is set.") || !strings.Contains(page, "Saved.") {
		t.Errorf("page after:\n%s", page)
	}
	// The secret left empty is kept; changed alone, it alone is written.
	form = ssoValues(b)
	form.Set("admin_oidc.client_id", "another-client")
	if w := b.do(http.MethodPost, "/admin/sso", form); w.Code != http.StatusSeeOther || r.config.oidc.ClientSecret != "the secret of the client" {
		t.Errorf("kept: %d %+v", w.Code, r.config.oidc)
	}
	form = ssoValues(b)
	form.Set("forget_secret", "true")
	if w := b.do(http.MethodPost, "/admin/sso", form); w.Code != http.StatusSeeOther || r.config.oidc.ClientSecret != "" {
		t.Errorf("forgotten: %d %+v", w.Code, r.config.oidc)
	}
	if got, want := r.wrote(), []string{
		"write alice settings  update admin_oidc.enabled,admin_oidc.issuer,admin_oidc.client_id,admin_oidc.client_secret,admin_oidc.required_acr",
		"write alice settings  update admin_oidc.client_id",
		"write alice settings  update admin_oidc.client_secret",
	}; !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
	for _, line := range r.audited() {
		if strings.Contains(line, "the secret of the client") {
			t.Errorf("the secret in the audit: %q", line)
		}
	}
}

// What refuses the block is said by its field; the secret typed is not shown
// back; a block changed meanwhile is not written over without a word.
func TestSSORefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := ssoValues(b)
	form.Set("admin_oidc.enabled", "true")
	form.Set("admin_oidc.client_secret", "typed, not saved")
	w := b.do(http.MethodPost, "/admin/sso", form)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `name="admin_oidc.issuer" value="" aria-invalid="true">`) ||
		strings.Contains(w.Body.String(), "typed, not saved") {
		t.Errorf("no issuer: %d\n%s", w.Code, w.Body)
	}
	r.config.fail = &store.RefusedError{Err: errors.New("setting admin_oidc.issuer: is in http://, which needs tls.allow_http")}
	form = ssoValues(b)
	form.Set("admin_oidc.issuer", "http://idp.test")
	if w := b.do(http.MethodPost, "/admin/sso", form); w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), "<small>is in http://, which needs tls.allow_http.</small>") {
		t.Errorf("http: %d\n%s", w.Code, w.Body)
	}
	r.config.fail = nil
	form = ssoValues(b)
	r.config.oidc = &store.AdminOIDC{Issuer: "https://theirs.test", Scopes: []string{"openid"}, UsernameClaim: "sub", RequiredACR: []string{}}
	form.Set("admin_oidc.client_id", "mine")
	if w := b.do(http.MethodPost, "/admin/sso", form); w.Code != http.StatusConflict || r.config.oidc.ClientID != "" {
		t.Errorf("meanwhile: %d %+v", w.Code, r.config.oidc)
	}
	if len(r.wrote()) != 0 {
		t.Errorf("written: %q", r.wrote())
	}
	// Past the window, asked again; a viewer reads.
	r.advance(6 * time.Minute)
	if w := b.do(http.MethodPost, "/admin/sso", ssoValues(b)); w.Code != http.StatusForbidden {
		t.Errorf("past the window: %d", w.Code)
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/sso", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<fieldset disabled>") {
		t.Errorf("a viewer reads: %d", w.Code)
	}
	if w := viewer.do(http.MethodPost, "/admin/sso", ssoValues(viewer)); w.Code != http.StatusForbidden {
		t.Errorf("a viewer writes: %d", w.Code)
	}
}
