package adminui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var shownRe = regexp.MustCompile(`name="shown_([a-z_]+)" value="([^"]*)"`)

// settingsForm is the form of the settings page as a browser sends it,
// unchanged: the values it shows, its boxes as they are.
func settingsForm(b *browser) url.Values {
	b.r.t.Helper()
	page := b.do(http.MethodGet, "/admin/settings", nil)
	form := url.Values{"csrf": {token(b.r.t, page)}}
	for _, m := range shownRe.FindAllStringSubmatch(page.Body.String(), -1) {
		key, value := m[1], strings.ReplaceAll(m[2], "&#34;", `"`)
		form.Set("shown_"+key, value)
		switch value {
		case "true":
			form.Set(key, "true")
		case "false":
		default:
			form.Set(key, value)
		}
	}
	if len(form) < 10 {
		b.r.t.Fatalf("settings page:\n%s", page.Body)
	}
	return form
}

func TestSettings(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/settings", nil).Body.String()
	if !strings.Contains(page, `name="challenge_ttl" value="600"`) || !strings.Contains(page, `name="reset" value="challenge_ttl"`) ||
		strings.Contains(page, `name="reset" value="remember"`) || !strings.Contains(page, `name="supported_locales" value="fr, en"`) ||
		!strings.Contains(page, `<input type="checkbox" name="remember" value="true" checked>`) {
		t.Fatalf("page:\n%s", page)
	}
	// Unchanged, nothing is written.
	if w := b.do(http.MethodPost, "/admin/settings", settingsForm(b)); w.Code != http.StatusSeeOther || len(r.config.by) != 0 || len(r.wrote()) != 0 {
		t.Fatalf("unchanged: %d %q", w.Code, r.config.by)
	}
	form := settingsForm(b)
	form.Set("app_auto_select", "true")
	form.Del("remember")
	form.Set("supported_locales", "fr en, de")
	form.Add("reset", "challenge_ttl")
	if w := b.do(http.MethodPost, "/admin/settings", form); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/settings?done=saved" {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	if got := r.config.stored; string(got["app_auto_select"]) != "true" || string(got["remember"]) != "false" ||
		string(got["supported_locales"]) != `["fr","en","de"]` || got["challenge_ttl"] != nil || len(got) != 3 {
		t.Errorf("stored: %s", got)
	}
	if got := r.wrote(); !slices.Equal(got, []string{"write alice settings  update app_auto_select,challenge_ttl,remember,supported_locales"}) {
		t.Errorf("audit: %q", got)
	}
}

// A setting another admin changed after the page was shown keeps their
// value when this form does not change it.
func TestSettingsMeanwhile(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := settingsForm(b)
	if err := r.config.UpdateSettings(context.Background(), "admin:other", map[string]json.RawMessage{"consent_auto_accept": json.RawMessage("true")}); err != nil {
		t.Fatal(err)
	}
	form.Set("default_locale", "en")
	if w := b.do(http.MethodPost, "/admin/settings", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	if got := r.config.stored; string(got["consent_auto_accept"]) != "true" || string(got["default_locale"]) != `"en"` {
		t.Errorf("stored: %s", got)
	}
}

func TestSettingsRefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	for name, c := range map[string]struct{ key, value, want string }{
		"a number":  {"challenge_ttl", "an hour", "is not a whole number of seconds."},
		"zero":      {"challenge_ttl", "0", "must be positive."},
		"no locale": {"supported_locales", " ", "is empty."},
	} {
		form := settingsForm(b)
		form.Set(c.key, c.value)
		w := b.do(http.MethodPost, "/admin/settings", form)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "<small>"+c.want+"</small>") ||
			!strings.Contains(w.Body.String(), `name="`+c.key+`" value="`+strings.TrimSpace(c.value)+`" aria-invalid="true">`) {
			t.Errorf("%s: %d\n%s", name, w.Code, w.Body)
		}
	}
	if len(r.config.by) != 0 {
		t.Errorf("written: %q", r.config.by)
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/settings", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<fieldset disabled>") {
		t.Errorf("a viewer reads: %d", w.Code)
	}
	if w := viewer.do(http.MethodPost, "/admin/settings", settingsForm(viewer)); w.Code != http.StatusForbidden {
		t.Errorf("a viewer writes: %d", w.Code)
	}
}
