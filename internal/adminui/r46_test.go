package adminui

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The tests of the revue R46.

var (
	formRe    = regexp.MustCompile(`(?s)<form[^>]*\baction="([^"]*)"[^>]*>(.*?)</form>`)
	controlRe = regexp.MustCompile(`(?s)<input\b([^>]*)>|<textarea\b([^>]*)>(.*?)</textarea>|<select\b([^>]*)>(.*?)</select>`)
	attrRe    = regexp.MustCompile(`([a-z_-]+)(?:="([^"]*)")?`)
	optionRe  = regexp.MustCompile(`<option\b([^>]*)>`)
)

func attrsOf(s string) map[string]string {
	a := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		a[m[1]] = html.UnescapeString(m[2])
	}
	return a
}

// browserForm is what a browser sends of the form of page posted to action,
// untouched: an <input> without the CR and LF of its value, a <textarea> its
// text, the newline right after its tag dropped, its line ends as CRLF, a
// <select> its option selected, else its first, a box when checked.
func browserForm(t *testing.T, page, action string) url.Values {
	t.Helper()
	for _, f := range formRe.FindAllStringSubmatch(page, -1) {
		if html.UnescapeString(f[1]) != action {
			continue
		}
		v := url.Values{}
		for _, c := range controlRe.FindAllStringSubmatch(f[2], -1) {
			switch {
			case c[1] != "" || strings.HasPrefix(c[0], "<input"):
				a := attrsOf(c[1])
				_, checked := a["checked"]
				if a["name"] == "" || a["type"] == "submit" || (a["type"] == "checkbox" || a["type"] == "radio") && !checked {
					continue
				}
				v.Add(a["name"], strings.NewReplacer("\r", "", "\n", "").Replace(a["value"]))
			case strings.HasPrefix(c[0], "<textarea"):
				text := strings.TrimPrefix(html.UnescapeString(c[3]), "\n")
				text = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
				v.Add(attrsOf(c[2])["name"], strings.ReplaceAll(text, "\n", "\r\n"))
			default:
				a := attrsOf(c[4])
				value := ""
				for i, o := range optionRe.FindAllStringSubmatch(c[5], -1) {
					oa := attrsOf(o[1])
					if _, sel := oa["selected"]; sel || i == 0 {
						value = oa["value"]
					}
				}
				v.Add(a["name"], value)
			}
		}
		return v
	}
	t.Fatalf("no form to %s in:\n%s", action, page)
	return nil
}

// B-a, B-b, B-c: what the browser sends back of a page, untouched, writes
// nothing on any screen, whatever the stored values hold (a line break in a
// field of one line, a CR alone, spaces alone, claims in another order, an
// item of a list with a line break); a change beside them keeps them.
func TestBrowserSendsBack(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	f := &r.config.flows[0]
	f.Title["en"], f.Description["en"], f.Description["fr"] = "Line1\nLine2", "a\rb", "  "
	f.IconURL = map[string]string{"en": " https://icons.test/a.png\n"}
	f.Steps[0].SubjectCheck = "claim:a\nb"
	r.config.apps[0].Method, r.config.apps[0].LoginURL = "pw d\n2", "https://pwd.test/login "
	r.config.apps[0].ReceiveClaims = []string{" a b ", "c\nd"}
	r.config.apps[1].AuthMode, r.config.apps[1].AllowedSources = "mtls", nil
	r.config.apps[1].ClientCertFingerprint = strings.Repeat("AB:", 31) + "AB"
	r.config.scopes = []store.Scope{
		{Name: "biz", Label: map[string]string{"fr": "Ligne1\nLigne2", "en": "   "}, Claims: []store.ScopeClaim{{Claim: " x ", Label: map[string]string{"fr": "  "}}}},
		{Name: "profile", Claims: []store.ScopeClaim{{Claim: "nickname", Label: map[string]string{"fr": "Surnom"}}, {Claim: "name", Label: map[string]string{"fr": "Nom"}},
			{Claim: "picture", Label: map[string]string{"fr": "   "}}}},
	}
	h.putJSON(conforming("two", `{}`))
	for k, v := range map[string]any{"client_name": "Two\nLines", "scope": " openid  offline ", "logo_uri": "https://n.test/logo.png ",
		"jwks_uri": "", "redirect_uris": []any{"https://n.test/cb ", "https://n.test/cb2"}, "audience": []any{" api "}} {
		h.clients["two"][k] = rawOf(v)
	}
	withIdP(r)
	r.config.oidc.ClientID, r.config.oidc.UsernameClaim = " dispatcher-admin\n", " preferred_username "
	r.config.oidc.AuthorizationEndpoint = "https://idp.test/auth\r\n"
	b := r.browser()
	b.login("alice", password, "")

	pages := []struct{ page, action string }{
		{"/admin/flows/simple", "/admin/flows/simple"},
		{"/admin/apps/pwd", "/admin/apps/pwd"},
		{"/admin/apps/spare", "/admin/apps/spare"},
		{"/admin/scopes/biz", "/admin/scopes/biz"},
		{"/admin/scopes/profile", "/admin/scopes/profile"},
		{"/admin/hydra-clients/two", "/admin/hydra-clients/two"},
		{"/admin/sso", "/admin/sso"},
		{"/admin/settings", "/admin/settings"},
	}
	for _, p := range pages {
		form := browserForm(t, b.do(http.MethodGet, p.page, nil).Body.String(), p.action)
		if w := b.do(http.MethodPost, p.action, form); w.Code != http.StatusSeeOther {
			t.Errorf("%s unchanged: %d\n%s", p.action, w.Code, w.Body)
		}
	}
	if len(r.config.by) != 0 || len(r.wrote()) != 0 || len(h.patches) != 0 {
		t.Fatalf("unchanged saves wrote: by %q, audit %q, patches %v", r.config.by, r.wrote(), h.patches)
	}
	if sc, _ := r.config.Snapshot().Scope("profile"); len(sc.Claims) != 3 || sc.Claims[0].Claim != "nickname" {
		t.Errorf("profile: %+v", sc.Claims)
	}

	// B-c: a change of the spaces inside the scope of a Hydra client is a
	// change.
	form := browserForm(t, b.do(http.MethodGet, "/admin/hydra-clients/two", nil).Body.String(), "/admin/hydra-clients/two")
	form.Set("scope", "openid offline")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/two", form); w.Code != http.StatusSeeOther || h.member("two", "scope") != `"openid offline"` {
		t.Errorf("scope changed: %d %s", w.Code, h.member("two", "scope"))
	}
	if got := h.member("two", "client_name") + h.member("two", "redirect_uris") + h.member("two", "logo_uri"); got != `"Two\nLines"["https://n.test/cb ","https://n.test/cb2"]"https://n.test/logo.png "` {
		t.Errorf("the rest of the client: %s", got)
	}

	// A change beside the stored values keeps them.
	page := b.do(http.MethodGet, "/admin/flows/simple", nil).Body.String()
	form = browserForm(t, page, "/admin/flows/simple")
	form["enabled"] = nil
	if w := b.do(http.MethodPost, "/admin/flows/simple", form); w.Code != http.StatusSeeOther {
		t.Fatalf("flow: %d\n%s", w.Code, w.Body)
	}
	if fl, _ := r.config.flow("simple"); fl.Enabled || fl.Title["en"] != "Line1\nLine2" || fl.Description["en"] != "a\rb" || fl.Description["fr"] != "  " ||
		fl.IconURL["en"] != " https://icons.test/a.png\n" || fl.Steps[0].SubjectCheck != "claim:a\nb" {
		t.Errorf("flow %+v", fl)
	}
	form = browserForm(t, b.do(http.MethodGet, "/admin/scopes/biz", nil).Body.String(), "/admin/scopes/biz")
	form.Set("label.", "Business")
	if w := b.do(http.MethodPost, "/admin/scopes/biz", form); w.Code != http.StatusSeeOther {
		t.Fatalf("scope: %d\n%s", w.Code, w.Body)
	}
	if sc, _ := r.config.Snapshot().Scope("biz"); sc.Label["fr"] != "Ligne1\nLigne2" || sc.Label["en"] != "   " || sc.Label[""] != "Business" ||
		len(sc.Claims) != 1 || sc.Claims[0].Claim != " x " || sc.Claims[0].Label["fr"] != "  " {
		t.Errorf("scope %+v", sc)
	}
	form = browserForm(t, b.do(http.MethodGet, "/admin/scopes/profile", nil).Body.String(), "/admin/scopes/profile")
	form.Set("label.fr", "Qui vous êtes")
	b.do(http.MethodPost, "/admin/scopes/profile", form)
	if sc, _ := r.config.Snapshot().Scope("profile"); len(sc.Claims) != 3 || sc.Claims[0].Claim != "nickname" || sc.Claims[2].Label["fr"] != "   " {
		t.Errorf("profile renamed: %+v", sc)
	}
	form = browserForm(t, b.do(http.MethodGet, "/admin/apps/pwd", nil).Body.String(), "/admin/apps/pwd")
	form.Set("consent_url", "https://pwd.test/consent2")
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("app: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("pwd"); a.Method != "pw d\n2" || a.LoginURL != "https://pwd.test/login " || !slices.Equal(a.ReceiveClaims, []string{" a b ", "c\nd"}) {
		t.Errorf("app %+v", a)
	}
	v := ssoValues(b)
	v.Set("admin_oidc.scopes", "openid email")
	v.Set("admin_oidc.client_id", " dispatcher-admin ")
	v.Set("admin_oidc.username_claim", "preferred_username")
	v.Set("admin_oidc.authorization_endpoint", "https://idp.test/auth")
	b.do(http.MethodPost, "/admin/sso", v)
	if o := r.config.Snapshot().Settings.AdminOIDC; o.ClientID != " dispatcher-admin\n" || o.UsernameClaim != " preferred_username " || o.AuthorizationEndpoint != "https://idp.test/auth\r\n" {
		raw, _ := json.Marshal(o)
		t.Errorf("sso %s", raw)
	}
}
