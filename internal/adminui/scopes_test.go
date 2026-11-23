package adminui

import (
	"errors"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// scopeValues is the form of a scope as the page sends it: its locales,
// fr, en and every locale.
func scopeValues(b *browser, version string, labels map[string]string, claims ...string) url.Values {
	v := url.Values{"csrf": {b.csrf()}, "version": {version}, "locale": {"fr", "en", ""}}
	for k, t := range labels {
		v.Set(k, t)
	}
	for _, c := range claims {
		v.Add("claim", c)
	}
	return v
}

var scopeLinkRe = regexp.MustCompile(`<a href="(/admin/scopes/[^"]+)">https://api.test/read</a>`)

// The screen of the catalogue (P24c): the standard scopes and those of the
// business, the overview of the consent, the scopes clients of Hydra ask
// outside it; a scope created, a standard one renamed and given back to the
// code, the refusals; a viewer reads alone.
func TestScopes(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.config.scopes = []store.Scope{
		{Name: "profile", Label: map[string]string{"fr": "Qui vous êtes"}},
		{Name: "groups", Label: map[string]string{"": "Équipes"}, Claims: []store.ScopeClaim{{Claim: "groups", Label: map[string]string{"fr": "Groupes"}}}},
		{Name: "<i>x", Label: map[string]string{"": "<b>y"}, Claims: []store.ScopeClaim{{Claim: "<u>z", Label: map[string]string{"fr": "<s>w"}}}},
		{Name: "https://api.test/read", Claims: []store.ScopeClaim{}},
	}
	h := withHydra(r)
	h.put(map[string]any{"client_id": "pay", "client_name": "Pay", "scope": "openid groups payroll"})
	b := r.browser()
	b.login("alice", password, "")

	list := b.do(http.MethodGet, "/admin/scopes", nil)
	body := list.Body.String()
	for _, want := range []string{
		`<a href="/admin/scopes/openid">openid</a></td><td>Vous identifier</td><td>sub</td><td>standard</td>`,
		`<a href="/admin/scopes/profile">profile</a></td><td>Qui vous êtes</td>`, "standard, renamed",
		`<a href="/admin/scopes/groups">groups</a></td><td>Équipes</td><td>groups</td><td>business</td>`,
		"<tr><td>payroll</td><td>Pay</td>", `<a href="/admin/new-scope?name=payroll">Add it</a>`, "<tr><td>offline</td><td>Web</td>",
		`<a href="/admin/new-scope" role="button">New scope</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list, no %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<tr><td>groups</td>") || strings.Contains(body, "alone are read") {
		t.Errorf("groups, in the catalogue, asked outside it, or the clients not all read:\n%s", body)
	}
	// Beyond maxScanned, the page tells it: pay, the third, is not read.
	defer func(n int) { maxScanned = n }(maxScanned)
	maxScanned = 2
	if body := b.do(http.MethodGet, "/admin/scopes", nil).Body.String(); !strings.Contains(body, "The first 2 clients of Hydra alone are read") ||
		strings.Contains(body, "payroll") || !strings.Contains(body, "<tr><td>offline</td><td>Web</td>") {
		t.Errorf("bounded:\n%s", body)
	}
	maxScanned = 5000
	// A scope named as a URL, by its link.
	m := scopeLinkRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link to the scope named as a URL:\n%s", body)
	}
	if w := b.do(http.MethodGet, m[1], nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<h1>Scope https://api.test/read</h1>") {
		t.Errorf("%s: %d\n%s", m[1], w.Code, w.Body)
	}

	// Names and labels escaped, in the list, the overview and the form (R44).
	hostile := []string{"<i>", "<b>", "<u>", "<s>"}
	for _, path := range []string{"/admin/scopes", "/admin/scopes?preview=%3Ci%3Ex", "/admin/scopes/%3Ci%3Ex"} {
		page := b.do(http.MethodGet, path, nil).Body.String()
		for _, h := range hostile {
			if strings.Contains(page, h) {
				t.Errorf("%s: %s not escaped:\n%s", path, h, page)
			}
		}
		if !strings.Contains(page, "&lt;") {
			t.Errorf("%s: nothing escaped shown:\n%s", path, page)
		}
	}
	preview := b.do(http.MethodGet, "/admin/scopes?preview=profile&preview=groups&preview=other", nil).Body.String()
	for _, want := range []string{`value="profile" checked`, `value="groups" checked`, "<li><strong>Qui vous êtes</strong><ul><li>Nom complet</li>",
		"<li><strong>Équipes</strong><ul><li>Groupes</li></ul></li>", "<li><strong>other</strong></li>"} {
		if !strings.Contains(preview, want) {
			t.Errorf("preview, no %q:\n%s", want, preview)
		}
	}
	if strings.Contains(preview, `value="email" checked`) {
		t.Error("preview: email ticked")
	}

	// A scope of the business, from a scope asked outside the catalogue.
	form := b.do(http.MethodGet, "/admin/new-scope?name=payroll", nil)
	if form.Code != http.StatusOK || !strings.Contains(form.Body.String(), `name="name" value="payroll"`) || strings.Count(form.Body.String(), `name="claim"`) != emptyClaims {
		t.Fatalf("new: %d\n%s", form.Code, form.Body)
	}
	v := scopeValues(b, "", map[string]string{"name": "payroll", "label.": "Paie", "label.en": "Payroll", "claim_label.0.fr": "Salaire", "claim_label.1.en": "lost"}, "salary", "")
	w := b.do(http.MethodPost, "/admin/scopes", v)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/scopes/payroll?done=created" {
		t.Fatalf("create: %d\n%s", w.Code, w.Body)
	}
	got, _ := r.config.Snapshot().Scope("payroll")
	if !maps.Equal(got.Label, map[string]string{"": "Paie", "en": "Payroll"}) || len(got.Claims) != 1 || got.Claims[0].Claim != "salary" ||
		!maps.Equal(got.Claims[0].Label, map[string]string{"fr": "Salaire"}) {
		t.Errorf("created %+v", got)
	}

	// A standard scope without a row, renamed: its claims without a label
	// are not written.
	v = scopeValues(b, b.version("/admin/scopes/email"), map[string]string{"label.fr": "Votre courriel", "claim_label.1.en": "Checked"}, "email", "email_verified")
	if w := b.do(http.MethodPost, "/admin/scopes/email", v); w.Code != http.StatusSeeOther {
		t.Fatalf("rename: %d\n%s", w.Code, w.Body)
	}
	got, _ = r.config.Snapshot().Scope("email")
	if !maps.Equal(got.Label, map[string]string{"fr": "Votre courriel"}) || len(got.Claims) != 1 || got.Claims[0].Claim != "email_verified" {
		t.Errorf("renamed %+v", got)
	}
	page := b.do(http.MethodGet, "/admin/scopes/email", nil).Body.String()
	if !strings.Contains(page, `name="label.fr" value="Votre courriel" placeholder="Votre adresse e-mail"`) || strings.Contains(page, "/admin/scopes/email/delete") {
		t.Errorf("standard page:\n%s", page)
	}
	// Its labels emptied, the row goes: the code's again.
	v = scopeValues(b, b.version("/admin/scopes/profile"), nil, "name")
	if w := b.do(http.MethodPost, "/admin/scopes/profile", v); w.Code != http.StatusSeeOther {
		t.Fatalf("profile given back: %d\n%s", w.Code, w.Body)
	}
	if _, found := r.config.Snapshot().Scope("profile"); found {
		t.Error("profile: its row kept")
	}

	for name, c := range map[string]struct {
		v    url.Values
		code int
		want string
	}{
		"a standard name": {scopeValues(b, "", map[string]string{"name": "email"}), http.StatusConflict, "is a standard scope of OpenID Connect"},
		"a name taken":    {scopeValues(b, "", map[string]string{"name": "groups"}), http.StatusConflict, "is taken"},
		"a space":         {scopeValues(b, "", map[string]string{"name": "a b"}), http.StatusUnprocessableEntity, `value="a b" required maxlength="128" autocomplete="off" aria-invalid="true"`},
		"a claim twice":   {scopeValues(b, "", map[string]string{"name": "twice"}, "x", "x"), http.StatusUnprocessableEntity, `aria-label="Claim 1" aria-invalid="true"`},
	} {
		if w := b.do(http.MethodPost, "/admin/scopes", c.v); w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d\n%s", name, w.Code, w.Body)
		}
	}
	// A version of another admin: refused, the form kept.
	v = scopeValues(b, "stale", map[string]string{"label.en": "Mine"}, "groups")
	if w := b.do(http.MethodPost, "/admin/scopes/groups", v); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `name="label.en" value="Mine"`) {
		t.Errorf("stale: %d\n%s", w.Code, w.Body)
	}

	confirm := b.do(http.MethodGet, "/admin/scopes/email/delete", nil).Body.String()
	if strings.Contains(confirm, `action="/admin/scopes/email/delete"`) || !strings.Contains(confirm, "renamed, never deleted") {
		t.Errorf("delete a standard scope, its page:\n%s", confirm)
	}
	if w := b.do(http.MethodPost, "/admin/scopes/email/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusConflict {
		t.Errorf("delete a standard scope: %d", w.Code)
	}
	if w := b.do(http.MethodPost, "/admin/scopes/payroll/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/admin/scopes?done=deleted" {
		t.Fatalf("delete: %d\n%s", w.Code, w.Body)
	}
	if _, found := r.config.Snapshot().Scope("payroll"); found {
		t.Error("payroll still there")
	}
	if want := []string{
		"write alice scopes payroll create name,label,claims",
		"write alice scopes email update label,claims",
		"write alice scopes profile update label",
		"write alice scopes payroll delete ",
	}; !slices.Equal(r.wrote(), want) {
		t.Errorf("audit:\n got %q\nwant %q", r.wrote(), want)
	}

	// Hydra down: the catalogue still shown.
	h.fail = errors.New("down")
	if w := b.do(http.MethodGet, "/admin/scopes", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "The clients of Hydra cannot be read now") ||
		!strings.Contains(w.Body.String(), ">groups</a>") {
		t.Errorf("Hydra down: %d\n%s", w.Code, w.Body)
	}

	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/scopes", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "New scope") || strings.Contains(w.Body.String(), "Add it") {
		t.Errorf("a viewer, the list: %d\n%s", w.Code, w.Body)
	}
	if w := viewer.do(http.MethodGet, "/admin/scopes/groups", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<fieldset disabled>") {
		t.Errorf("a viewer, a scope: %d", w.Code)
	}
	for _, path := range []string{"/admin/new-scope", "/admin/scopes/groups/delete"} {
		if w := viewer.do(http.MethodGet, path, nil); w.Code != http.StatusForbidden {
			t.Errorf("a viewer, %s: %d", path, w.Code)
		}
	}
	if w := viewer.do(http.MethodPost, "/admin/scopes/groups", scopeValues(viewer, "", nil, "groups")); w.Code != http.StatusForbidden {
		t.Errorf("a viewer writes: %d", w.Code)
	}
	if w := b.do(http.MethodGet, "/admin/scopes/nowhere", nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown scope: %d", w.Code)
	}
}
