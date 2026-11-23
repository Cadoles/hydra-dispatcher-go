package adminui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The reports of the revue R41, fixed in P25c.

// A save that changes nothing writes nothing: neither a value that lost the
// spaces at its ends, nor the author of the row, nor the audit. A value
// untouched beside one changed stays as stored.
func TestSaveWithoutChange(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.config.stored["login_accept_webhook_url"] = json.RawMessage(`" /opt/hooks/login --strict "`)
	r.config.flows[0].Title["en"] = " Simple "
	b := r.browser()
	b.login("alice", password, "")

	// The settings, the webhook as the page shows it.
	if w := b.do(http.MethodPost, "/admin/settings", settingsForm(b)); w.Code != http.StatusSeeOther || len(r.config.by) != 0 {
		t.Fatalf("settings unchanged: %d %q", w.Code, r.config.by)
	}
	form := settingsForm(b)
	form.Set("app_auto_select", "true")
	if w := b.do(http.MethodPost, "/admin/settings", form); w.Code != http.StatusSeeOther {
		t.Fatalf("settings: %d\n%s", w.Code, w.Body)
	}
	if got := string(r.config.stored["login_accept_webhook_url"]); got != `" /opt/hooks/login --strict "` {
		t.Errorf("the webhook untouched rewritten: %s", got)
	}

	// A flow, its texts as the page shows them.
	flowForm := func() url.Values {
		return url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/flows/simple")}, "enabled": {"1"}, "acr": {""},
			"locale": {"fr", "en"}, "title": {"", " Simple "}, "description": {"", "d"}, "icon_url": {"", ""},
			"step_app": {"pwd"}, "step_position": {"1"}, "step_check": {"none"}, "step_claim": {""}}
	}
	by := len(r.config.by)
	if w := b.do(http.MethodPost, "/admin/flows/simple", flowForm()); w.Code != http.StatusSeeOther || len(r.config.by) != by {
		t.Fatalf("flow unchanged: %d %q", w.Code, r.config.by)
	}
	f := flowForm()
	f["description"] = []string{"", "another"}
	if w := b.do(http.MethodPost, "/admin/flows/simple", f); w.Code != http.StatusSeeOther {
		t.Fatalf("flow: %d\n%s", w.Code, w.Body)
	}
	if fl, _ := r.config.flow("simple"); fl.Title["en"] != " Simple " || fl.Description["en"] != "another" {
		t.Errorf("flow %+v", fl)
	}
	// A text typed with spaces of its own, changed: trimmed.
	f = flowForm()
	f["title"] = []string{"", " Plain "}
	f.Set("version", b.version("/admin/flows/simple"))
	b.do(http.MethodPost, "/admin/flows/simple", f)
	if fl, _ := r.config.flow("simple"); fl.Title["en"] != "Plain" {
		t.Errorf("a text changed: %q", fl.Title["en"])
	}

	// An app, an API client, a scope: unchanged, nothing written.
	by = len(r.config.by)
	page := b.do(http.MethodGet, "/admin/apps/pwd", nil).Body.String()
	app := url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/apps/pwd")}, "method": {"pwd"}, "login_url": {"https://pwd.test/login"},
		"consent_url": {"https://pwd.test/consent"}, "auth_mode": {"network"}, "allowed_sources": {"10.0.6.21/32"}, "receive_all_claims": {"1"}}
	if w := b.do(http.MethodPost, "/admin/apps/pwd", app); w.Code != http.StatusSeeOther || len(r.config.by) != by {
		t.Errorf("app unchanged: %d %q\n%s", w.Code, r.config.by, page)
	}
	r.config.clients = []store.APIClient{{ID: "ci", Scopes: []string{"admin:read"}}}
	client := url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/clients/ci")}, "scope": {"admin:read"}}
	if w := b.do(http.MethodPost, "/admin/clients/ci", client); w.Code != http.StatusSeeOther || len(r.config.by) != by {
		t.Errorf("API client unchanged: %d %q", w.Code, r.config.by)
	}
	scope := scopeValues(b, b.version("/admin/scopes/email"), nil, "email", "email_verified")
	if w := b.do(http.MethodPost, "/admin/scopes/email", scope); w.Code != http.StatusSeeOther || len(r.config.by) != by {
		t.Errorf("scope unchanged: %d %q", w.Code, r.config.by)
	}
	audit := strings.Join(r.wrote(), "\n")
	if strings.Contains(audit, "apps pwd") || strings.Contains(audit, "oauth2-clients") || strings.Contains(audit, "scopes") || strings.Count(audit, "flows simple") != 2 || strings.Count(audit, "settings") != 1 {
		t.Errorf("audit:\n%s", audit)
	}
}
