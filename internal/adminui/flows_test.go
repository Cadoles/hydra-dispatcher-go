package adminui

import (
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// flowValues is the form of the flow two, new: fr and en, two steps without
// positions, the second checked against a claim.
func flowValues(b *browser) url.Values {
	b.r.t.Helper()
	return url.Values{"csrf": {b.csrf()}, "id": {"two"}, "enabled": {"1"}, "acr": {""},
		"locale": {"fr", "en"}, "title": {"Deux", ""}, "description": {"Mot de passe puis code", ""}, "icon_url": {"", ""},
		"step_app": {"pwd", "spare", "", ""}, "step_position": {"", "", "", ""}, "step_check": {"none", "claim", "none", "none"},
		"step_claim": {"", "email", "", ""}}
}

func TestFlows(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	list := b.do(http.MethodGet, "/admin/flows", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `<td><a href="/admin/flows/simple">simple</a></td><td>Simple</td><td>enabled</td><td>pwd</td>`) {
		t.Fatalf("list: %d\n%s", list.Code, list.Body)
	}
	page := b.do(http.MethodGet, "/admin/flows/simple", nil).Body.String()
	if !strings.Contains(page, "<legend>fr</legend>") || !strings.Contains(page, "<legend>en</legend>") ||
		!strings.Contains(page, `<option value="pwd" selected>pwd</option>`) || strings.Count(page, `name="step_app"`) != 4 ||
		!strings.Contains(page, `<script src="/admin/static/steps.js?v=`) {
		t.Fatalf("page:\n%s", page)
	}

	w := b.do(http.MethodPost, "/admin/flows", flowValues(b))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/flows/two?done=created" {
		t.Fatalf("create: %d\n%s", w.Code, w.Body)
	}
	f, _ := r.config.flow("two")
	if !maps.Equal(f.Title, map[string]string{"fr": "Deux"}) || f.IconURL != nil || !f.Enabled || !slices.Equal(f.Steps, []store.Step{
		{AppID: "pwd", Position: 1, SubjectCheck: "none"}, {AppID: "spare", Position: 2, SubjectCheck: "claim:email"},
	}) {
		t.Errorf("created: %+v", f)
	}

	// Typed positions order the steps; a row left at — is no step.
	form := flowValues(b)
	form.Set("version", b.version("/admin/flows/two"))
	form["step_position"] = []string{"20", "10", "", ""}
	form.Del("enabled")
	w = b.do(http.MethodPost, "/admin/flows/two", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("update: %d\n%s", w.Code, w.Body)
	}
	f, _ = r.config.flow("two")
	if f.Enabled || !slices.Equal(f.Steps, []store.Step{{AppID: "pwd", Position: 20, SubjectCheck: "none"}, {AppID: "spare", Position: 10, SubjectCheck: "claim:email"}}) {
		t.Errorf("updated: %+v", f)
	}
	page = b.do(http.MethodGet, "/admin/flows/two", nil).Body.String()
	if strings.Index(page, `<option value="spare" selected>`) > strings.Index(page, `<option value="pwd" selected>`) ||
		!strings.Contains(page, `name="step_claim" value="email"`) || !strings.Contains(page, "Offered to no user.") {
		t.Errorf("the steps by position:\n%s", page)
	}
	if got, want := r.wrote(), []string{
		"write alice flows two create id,title,description,enabled,steps",
		"write alice flows two update enabled,steps",
	}; !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
}

// The texts of a locale supported_locales does not name are shown, and kept
// by a save.
func TestFlowOtherLocale(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.config.flows[0].Title["de"] = "Einfach"
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/flows/simple", nil).Body.String()
	if !strings.Contains(page, "<legend>de</legend>") || strings.Index(page, "<legend>de</legend>") < strings.Index(page, "<legend>en</legend>") {
		t.Fatalf("de:\n%s", page)
	}
	form := url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/flows/simple")}, "enabled": {"1"},
		"locale": {"fr", "en", "de"}, "title": {"", "Simple", "Einfach"}, "description": {"", "d", ""}, "icon_url": {"", "", ""},
		"step_app": {"pwd"}, "step_position": {"1"}, "step_check": {"none"}, "step_claim": {""}}
	if w := b.do(http.MethodPost, "/admin/flows/simple", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	if f, _ := r.config.flow("simple"); f.Title["de"] != "Einfach" {
		t.Errorf("de lost: %+v", f.Title)
	}
	// Nothing changed: nothing written nor audited (revue R41).
	if got := r.wrote(); len(got) != 0 || len(r.config.by) != 0 {
		t.Errorf("audit: %q, written by %q", got, r.config.by)
	}
}

var invalidStep = regexp.MustCompile(`<select name="step_app" aria-label="App" aria-invalid="true">`)

// The violations of a step are said on its row.
func TestFlowRefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := flowValues(b)
	form["title"] = []string{"", ""}
	if w := b.do(http.MethodPost, "/admin/flows", form); w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), "<strong>Title: is required.</strong>") || !strings.Contains(w.Body.String(), `value="Mot de passe puis code"`) &&
		!strings.Contains(w.Body.String(), ">Mot de passe puis code</textarea>") {
		t.Errorf("no title: %d\n%s", w.Code, w.Body)
	}
	for name, c := range map[string]struct {
		app, position, check, claim []string
		want                        string
	}{
		"an app twice":     {[]string{"pwd", "pwd"}, []string{"", ""}, []string{"none", "none"}, []string{"", ""}, `app &#34;pwd&#34; is already a step of this flow`},
		"a position":       {[]string{"pwd", "spare"}, []string{"1", "x"}, []string{"none", "none"}, []string{"", ""}, `position &#34;x&#34; is not a whole number`},
		"a claim unnamed":  {[]string{"pwd", "spare"}, []string{"", ""}, []string{"none", "claim"}, []string{"", ""}, `&#34;claim:&#34; is not none, equal or claim:&lt;name&gt;`},
		"a position twice": {[]string{"pwd", "spare"}, []string{"3", "3"}, []string{"none", "none"}, []string{"", ""}, `position 3 is already taken in this flow`},
	} {
		form := flowValues(b)
		form["step_app"], form["step_position"], form["step_check"], form["step_claim"] = c.app, c.position, c.check, c.claim
		w := b.do(http.MethodPost, "/admin/flows", form)
		body := w.Body.String()
		// The second row, and it alone, says it.
		if w.Code != http.StatusUnprocessableEntity || len(invalidStep.FindAllStringIndex(body, -1)) != 1 || !strings.Contains(body, c.want) ||
			strings.Index(body, c.want) < strings.Index(body, `<option value="spare"`) && c.app[1] == "spare" {
			t.Errorf("%s: %d\n%s", name, w.Code, body)
		}
	}
	if _, ok := r.config.flow("two"); ok || len(r.wrote()) != 0 {
		t.Errorf("written: %v", r.wrote())
	}
}

// Two admins on one flow: the save of the second is refused once, its
// changes kept on the page; saved again, they are written knowingly.
func TestFlowChanged(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	first, second := r.browser(), r.browser()
	first.login("alice", password, "")
	second.login("alice", password, "")
	form := url.Values{"csrf": {second.csrf()}, "version": {second.version("/admin/flows/simple")}, "enabled": {"1"}, "acr": {"theirs"},
		"locale": {"fr", "en"}, "title": {"", "Simple"}, "description": {"", "d"}, "icon_url": {"", ""},
		"step_app": {"pwd"}, "step_position": {"1"}, "step_check": {"none"}, "step_claim": {""}}
	mine := maps.Clone(form)
	mine.Set("csrf", first.csrf())
	mine.Set("acr", "mine")
	if w := second.do(http.MethodPost, "/admin/flows/simple", form); w.Code != http.StatusSeeOther {
		t.Fatalf("theirs: %d", w.Code)
	}
	w := first.do(http.MethodPost, "/admin/flows/simple", mine)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Another admin changed it") || !strings.Contains(w.Body.String(), `name="acr" value="mine"`) {
		t.Fatalf("mine over theirs: %d\n%s", w.Code, w.Body)
	}
	if f, _ := r.config.flow("simple"); f.ACR != "theirs" {
		t.Errorf("theirs lost: %q", f.ACR)
	}
	m := versionRe.FindStringSubmatch(w.Body.String())
	mine.Set("version", m[1])
	if w := first.do(http.MethodPost, "/admin/flows/simple", mine); w.Code != http.StatusSeeOther {
		t.Fatalf("mine again: %d\n%s", w.Code, w.Body)
	}
	if f, _ := r.config.flow("simple"); f.ACR != "mine" {
		t.Errorf("mine: %q", f.ACR)
	}
}

// The deletion of a flow asks for the password again past the window.
func TestFlowDelete(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	r.advance(6 * time.Minute)
	if w := b.do(http.MethodGet, "/admin/flows/simple/delete", nil); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/admin/reauth?next=%2Fadmin%2Fflows%2Fsimple%2Fdelete" {
		t.Fatalf("page, past the window: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := b.do(http.MethodPost, "/admin/flows/simple/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusForbidden {
		t.Errorf("POST, past the window: %d", w.Code)
	}
	if _, ok := r.config.flow("simple"); !ok {
		t.Fatal("deleted past the window")
	}
	form := b.do(http.MethodGet, "/admin/reauth?next=/admin/flows/simple/delete", nil)
	w := b.do(http.MethodPost, "/admin/reauth", url.Values{"csrf": {token(t, form)}, "password": {password}, "next": {"/admin/flows/simple/delete"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reauth: %d", w.Code)
	}
	page := b.do(http.MethodGet, "/admin/flows/simple/delete", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="/admin/flows/simple/delete"`) {
		t.Fatalf("page: %d\n%s", page.Code, page.Body)
	}
	w = b.do(http.MethodPost, "/admin/flows/simple/delete", url.Values{"csrf": {token(t, page)}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/flows?done=deleted" {
		t.Fatalf("delete: %d\n%s", w.Code, w.Body)
	}
	if _, ok := r.config.flow("simple"); ok {
		t.Error("still there")
	}
	if got := r.wrote(); !slices.Equal(got, []string{"write alice flows simple delete "}) {
		t.Errorf("audit: %q", got)
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/flows", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "_new") {
		t.Errorf("a viewer's list: %d", w.Code)
	}
	if w := viewer.do(http.MethodPost, "/admin/flows", flowValues(viewer)); w.Code != http.StatusForbidden {
		t.Errorf("a viewer creates: %d", w.Code)
	}
}

// The script of the steps: served with the pages' cache, and only to a
// writer.
func TestStepsScript(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	w := b.do(http.MethodGet, "/admin/static/steps.js", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || w.Header().Get("ETag") == "" ||
		!strings.Contains(w.Body.String(), "renumber") {
		t.Errorf("script: %d %v", w.Code, w.Header())
	}
	css := b.do(http.MethodGet, "/admin/static/admin.css", nil)
	login := b.do(http.MethodGet, "/admin/login", nil)
	if css.Code != http.StatusOK || css.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(css.Body.String(), "#steps") ||
		!strings.Contains(login.Body.String(), `<link rel="stylesheet" href="/admin/static/admin.css?v=`) {
		t.Errorf("sheet of the admin: %d %v", css.Code, css.Header())
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if page := viewer.do(http.MethodGet, "/admin/flows/simple", nil); strings.Contains(page.Body.String(), "steps.js") ||
		!strings.Contains(page.Body.String(), "<fieldset disabled>") {
		t.Errorf("a viewer's page:\n%s", page.Body)
	}
	form := flowValues(viewer)
	form.Set("version", viewer.version("/admin/flows/simple"))
	for _, path := range []string{"/admin/flows/simple", "/admin/flows/simple/delete"} {
		if w := viewer.do(http.MethodPost, path, form); w.Code != http.StatusForbidden {
			t.Errorf("a viewer, %s: %d", path, w.Code)
		}
	}
	if w := viewer.do(http.MethodGet, "/admin/flows/simple/delete", nil); w.Code != http.StatusForbidden {
		t.Errorf("a viewer, the page of deletion: %d", w.Code)
	}
	if len(r.config.by) != 0 {
		t.Errorf("written: %q", r.config.by)
	}
}
