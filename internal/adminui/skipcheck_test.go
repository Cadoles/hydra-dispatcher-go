package adminui

import (
	"html"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The pre-check of an app on its screen (P26c): a key made is shown once, on
// the page of the secret, and never again, nor in the page of the app, its
// version or the audit; the page sent back untouched writes nothing, the
// signals in another order included; a key typed replaces it without being
// shown; the URL emptied takes the key and the signals with it.
func TestAppSkipCheckScreen(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")

	form := browserForm(t, b.do(http.MethodGet, "/admin/apps/spare", nil).Body.String(), "/admin/apps/spare")
	form.Set("skip_check_url", "https://spare.test/skip-check")
	form.Set("skip_check_key_generate", "1")
	form["skip_check_signals"] = []string{"device_age", "ip"}
	if w := b.do(http.MethodPost, "/admin/apps/spare", form); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/secret" {
		t.Fatalf("key made: %d %s\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	a, _ := r.config.app("spare")
	key := a.SkipCheckKey
	if _, err := domain.ParseKey(key); err != nil || key == "" || !slices.Equal(a.SkipCheckSignals, []string{"device_age", "ip"}) {
		t.Fatalf("app: %+v, key %v", a, err)
	}
	// The pages compared as the browser reads them: html/template writes the
	// + of a key in base64 as &#43;, which a check of the raw page would miss.
	text := func(s string) string { return html.UnescapeString(s) }
	shown := b.do(http.MethodGet, "/admin/secret", nil)
	if shown.Code != http.StatusOK || !strings.Contains(text(shown.Body.String()), `value="`+key+`"`) || !strings.Contains(shown.Body.String(), "The key of spare") ||
		!strings.Contains(shown.Body.String(), "kept encrypted") {
		t.Fatalf("key shown: %d\n%s", shown.Code, shown.Body)
	}
	if again := b.do(http.MethodGet, "/admin/secret", nil); again.Code != http.StatusGone || strings.Contains(text(again.Body.String()), key) {
		t.Errorf("key shown twice: %d", again.Code)
	}
	page := b.do(http.MethodGet, "/admin/apps/spare", nil).Body.String()
	if strings.Contains(text(page), key) || !strings.Contains(page, "A key is held: empty keeps it.") {
		t.Fatalf("app page:\n%s", page)
	}

	// Sent back untouched: nothing written, the boxes in the domain's order.
	writes := len(r.config.by)
	if w := b.do(http.MethodPost, "/admin/apps/spare", browserForm(t, page, "/admin/apps/spare")); w.Code != http.StatusSeeOther || len(r.config.by) != writes {
		t.Errorf("unchanged: %d, writes %d -> %d", w.Code, writes, len(r.config.by))
	}

	// Both a key typed and one asked for, or one asked for without a URL.
	for name, set := range map[string]map[string]string{
		"both":          {"skip_check_key": strings.Repeat("ab", 32), "skip_check_key_generate": "1"},
		"made, no URL":  {"skip_check_url": "", "skip_check_key_generate": "1"},
		"typed, no URL": {"skip_check_url": "", "skip_check_key": strings.Repeat("ab", 32)},
		"short key":     {"skip_check_key": "c2hvcnQ="},
	} {
		form := browserForm(t, page, "/admin/apps/spare")
		for k, v := range set {
			form.Set(k, v)
		}
		w := b.do(http.MethodPost, "/admin/apps/spare", form)
		if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), strings.Repeat("ab", 32)) || strings.Contains(text(w.Body.String()), key) {
			t.Errorf("%s: %d\n%s", name, w.Code, w.Body)
		}
	}
	if a, _ := r.config.app("spare"); a.SkipCheckKey != key {
		t.Fatal("a refused form wrote the key")
	}

	// A key typed: written, not shown, the page of the app next.
	form = browserForm(t, page, "/admin/apps/spare")
	form.Set("skip_check_key", strings.Repeat("ab", 32))
	if w := b.do(http.MethodPost, "/admin/apps/spare", form); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/apps/spare?done=saved" {
		t.Errorf("key typed: %d %s", w.Code, w.Header().Get("Location"))
	}
	if a, _ := r.config.app("spare"); a.SkipCheckKey != strings.Repeat("ab", 32) {
		t.Errorf("key typed not written: %+v", a)
	}

	// The URL emptied: the key and the signals with it, the boxes still checked.
	form = browserForm(t, b.do(http.MethodGet, "/admin/apps/spare", nil).Body.String(), "/admin/apps/spare")
	form.Set("skip_check_url", "")
	if w := b.do(http.MethodPost, "/admin/apps/spare", form); w.Code != http.StatusSeeOther {
		t.Fatalf("URL emptied: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("spare"); a.SkipCheckURL != "" || a.SkipCheckKey != "" || a.SkipCheckSignals != nil {
		t.Errorf("URL emptied: %+v", a)
	}
	audit := strings.Join(r.wrote(), "\n")
	if !strings.Contains(audit, "skip_check_key") || strings.Contains(audit, key) || strings.Contains(audit, strings.Repeat("ab", 32)) {
		t.Errorf("audit:\n%s", audit)
	}
}

// The pre-check in a flow on its screen (P26c): a step asks for it by its
// select, the acr values one per line; sent back untouched, nothing written;
// refused on the first step, the message at its row.
func TestFlowSkipCheckScreen(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.config.apps[1].SkipCheckURL, r.config.apps[1].SkipCheckKey = "https://spare.test/skip-check", strings.Repeat("ab", 32)
	f := &r.config.flows[0]
	f.SkipCheckAllowedACR = []string{"loa2", "loa1"}
	f.Steps = append(f.Steps, store.Step{AppID: "spare", Position: 2, SubjectCheck: "none", SkipCheck: true})
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/flows/simple", nil).Body.String()
	form := browserForm(t, page, "/admin/flows/simple")
	if !slices.Equal(form["step_skip"][:2], []string{"", "1"}) || form.Get("skip_check_allowed_acr") != "loa2\r\nloa1" {
		t.Fatalf("form: %v", form)
	}
	writes := len(r.config.by)
	if w := b.do(http.MethodPost, "/admin/flows/simple", form); w.Code != http.StatusSeeOther || len(r.config.by) != writes {
		t.Errorf("unchanged: %d, writes %d -> %d", w.Code, writes, len(r.config.by))
	}
	first := browserForm(t, page, "/admin/flows/simple")
	first["step_skip"][0] = "1"
	if w := b.do(http.MethodPost, "/admin/flows/simple", first); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "is refused on the first step") {
		t.Errorf("first step: %d\n%s", w.Code, w.Body)
	}
	form.Set("skip_check_allowed_acr", "loa3")
	form["step_skip"][1] = ""
	if w := b.do(http.MethodPost, "/admin/flows/simple", form); w.Code != http.StatusSeeOther {
		t.Fatalf("changed: %d\n%s", w.Code, w.Body)
	}
	if fl, _ := r.config.flow("simple"); !slices.Equal(fl.SkipCheckAllowedACR, []string{"loa3"}) || fl.Steps[1].SkipCheck {
		t.Errorf("flow: %+v", fl)
	}
}

// The version of an app's form tells whether it holds a key, never which:
// no digest of the key in a page (revue R42).
func TestAppVersionWithoutKey(t *testing.T) {
	a := store.App{ID: "a", SkipCheckURL: "https://a/c", SkipCheckKey: strings.Repeat("ab", 32)}
	b := a
	b.SkipCheckKey = strings.Repeat("cd", 32)
	c := a
	c.SkipCheckKey = ""
	if appVersion(a) != appVersion(b) || appVersion(a) == appVersion(c) {
		t.Errorf("versions: %s %s %s", appVersion(a), appVersion(b), appVersion(c))
	}
}

// A key of the pre-check, typed or made, asks a fresh authentication past
// admin.session.reauth_window, as a client's secret; the other writes of the
// app do not.
func TestAppSkipCheckKeyFresh(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	r.advance(6 * time.Minute)
	page := b.do(http.MethodGet, "/admin/apps/spare", nil).Body.String()
	for name, set := range map[string]map[string]string{
		"made":  {"skip_check_url": "https://spare.test/c", "skip_check_key_generate": "1"},
		"typed": {"skip_check_url": "https://spare.test/c", "skip_check_key": strings.Repeat("ab", 32)},
	} {
		form := browserForm(t, page, "/admin/apps/spare")
		for k, v := range set {
			form.Set(k, v)
		}
		w := b.do(http.MethodPost, "/admin/apps/spare", form)
		if a, _ := r.config.app("spare"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Confirm it is you") || a.SkipCheckKey != "" {
			t.Errorf("%s: %d, app %+v", name, w.Code, a)
		}
	}
	form := browserForm(t, page, "/admin/apps/spare")
	form.Set("method", "totp")
	if w := b.do(http.MethodPost, "/admin/apps/spare", form); w.Code != http.StatusSeeOther {
		t.Errorf("another field: %d", w.Code)
	}
}
