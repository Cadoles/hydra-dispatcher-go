package front

import (
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// demoManifest is the theme.yaml writeTheme gives a theme without one.
const demoManifest = "name: demo\nversion: 1.0.0\napi: 1\n"

// writeTheme writes files, by their path, under a new directory, with
// demoManifest unless files gives a theme.yaml.
func writeTheme(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["theme.yaml"]; !ok {
		files["theme.yaml"] = demoManifest
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// german is a whole catalog of a locale the binary has not: the English texts,
// one of them translated, and the name of the locale.
func german(t *testing.T) string {
	t.Helper()
	c, err := i18n.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	de := maps.Clone(c["en"])
	delete(de, "locale.en")
	delete(de, "locale.fr")
	de["locale.de"], de["choice.title"] = "Deutsch", "Anmeldemethode wählen"
	data, _ := json.Marshal(de)
	return string(data)
}

// A theme replaces the files it gives and keeps the others: a partial, a static
// file, texts merged key by key, a locale added and offered (Thèmes, Q92).
func TestThemeOverlay(t *testing.T) {
	dir := writeTheme(t, map[string]string{
		// A new partial, which the one replaced calls.
		"templates/partials/client_header.html.tmpl": `{{define "client_header"}}<p class="brand">Établissement</p>{{template "motto" .}}{{end}}`,
		"templates/partials/motto.html.tmpl":         `{{define "motto"}}<p class="motto">{{.Client.Name}}</p>{{end}}`,
		"static/theme.css":                           "body { color: #123456; }",
		"static/flags/de.svg":                        `<svg xmlns="http://www.w3.org/2000/svg"/>`,
		"translations/fr.json":                       `{"choice.title": "Choisissez"}`,
		"translations/de.json":                       german(t),
		// The source of a build stays at the root, unread.
		"input.css": `@import "tailwindcss";`,
	})
	th, err := LoadTheme(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(th); err != nil {
		t.Fatal(err)
	}
	if th.Manifest != (Manifest{Name: "demo", Version: "1.0.0", API: 1}) || !slices.Equal(th.Locales(), []string{"de", "en", "fr"}) {
		t.Fatalf("manifest %+v, locales %v", th.Manifest, th.Locales())
	}
	snap := testSnapshot()
	snap.Settings.SupportedLocales = []string{"fr", "en", "de"}
	w := newWorld(t, worldOptions{base: base, snapshot: snap, theme: th})

	body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=de", nil))
	for _, want := range []string{
		`<html lang="de">`, "Anmeldemethode wählen", `<p class="brand">Établissement</p><p class="motto">`, `<label class="flow">`,
		`lang="de" aria-current="true" disabled><img class="flag" src="/static/flags/de.svg?v=`, `Deutsch</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("de: no %s\n%s", want, body)
		}
	}
	embedded, _ := i18n.Embedded()
	body = text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=fr", nil))
	if !strings.Contains(body, "Choisissez") || !strings.Contains(body, embedded["fr"]["choice.submit"]) {
		t.Errorf("fr: a text not merged\n%s", body)
	}

	// The theme's theme.css, under its hash; the embedded base.css.
	css := regexp.MustCompile(`href="(/static/theme\.css\?v=[0-9a-f]{12})"`).FindStringSubmatch(body)
	if css == nil {
		t.Fatalf("no theme.css:\n%s", body)
	}
	resp := w.do(http.MethodGet, css[1], nil)
	if got := text(t, resp); got != "body { color: #123456; }" || resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("theme.css %q, %s", got, resp.Header.Get("Cache-Control"))
	}
	if got := text(t, w.do(http.MethodGet, "/static/base.css", nil)); !strings.Contains(got, "--color-accent") {
		t.Errorf("base.css %q", got)
	}
	for _, p := range []string{"/static/..%2finput.css", "/static/..%2ftheme.yaml", "/static/%2e%2e%2ftranslations%2ffr.json"} {
		if resp := w.do(http.MethodGet, p, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s, a file out of static/: %d", p, resp.StatusCode)
		}
	}
}

// A theme the pages could not follow is refused at load: the start stops, a
// login does not (Thèmes, validation).
func TestThemeRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.css")
	if err := os.WriteFile(outside, []byte("p {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		files map[string]string
		// links are symbolic links of the theme, to their target.
		links map[string]string
		want  string
	}{
		"api 2":             {map[string]string{"theme.yaml": "name: demo\nversion: 1.0.0\napi: 2\n"}, nil, "theme.yaml: api 2 is not supported; this binary supports api 1"},
		"no api":            {map[string]string{"theme.yaml": "name: demo\nversion: 1.0.0\n"}, nil, "theme.yaml: no api"},
		"api as text":       {map[string]string{"theme.yaml": "name: demo\nversion: 1.0.0\napi: \"1\"\n"}, nil, "cannot unmarshal !!str `1` into int"},
		"empty theme.yaml":  {map[string]string{"theme.yaml": ""}, nil, "theme.yaml: no name\ntheme.yaml: no version\ntheme.yaml: no api"},
		"unknown key":       {map[string]string{"theme.yaml": demoManifest + "colour: red\n"}, nil, "field colour not found"},
		"unknown page":      {map[string]string{"templates/selec.html.tmpl": ""}, nil, "templates/selec.html.tmpl: not a template of the pages"},
		"subdirectory":      {map[string]string{"templates/pages/select.html.tmpl": ""}, nil, "templates/pages/select.html.tmpl: not a template of the pages"},
		"partial extension": {map[string]string{"templates/partials/card.html": ""}, nil, "templates/partials/card.html: not a template of the pages"},
		"template broken":   {map[string]string{"templates/select.html.tmpl": `{{define "content"}}{{if}}{{end}}`}, nil, "template select: template: select.html.tmpl:1: missing value for if"},
		"translation name":  {map[string]string{"translations/pt-BR.json": "{}"}, nil, `translations/pt-BR.json: "pt-BR" is not a locale in lowercase`},
		"translation JSON":  {map[string]string{"translations/fr.json": `{"choice.title": 1}`}, nil, "translations/fr.json: json: cannot unmarshal number"},
		"translations file": {map[string]string{"translations": ""}, nil, "translations: not a directory"},
		"static link out":   {map[string]string{}, map[string]string{"static/outside.css": outside}, "openat static/outside.css: path escapes from parent"},
		"template link out": {map[string]string{}, map[string]string{"templates/select.html.tmpl": outside}, "openat templates/select.html.tmpl: path escapes from parent"},
	} {
		dir := writeTheme(t, tc.files)
		for link, target := range tc.links {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(link)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := LoadTheme(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// No directory, no theme.yaml.
	if _, err := LoadTheme(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("no directory: %v", err)
	}
	if _, err := LoadTheme(outside); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file: %v", err)
	}
	if _, err := LoadTheme(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no theme.yaml: a theme gives its name, its version and the api of the pages it follows (api: 1)") {
		t.Errorf("no theme.yaml: %v", err)
	}
	// A link that stays in the theme is followed (a Kubernetes volume is made of them).
	dir := writeTheme(t, map[string]string{"static/real/theme.css": "p {}"})
	if err := os.Symlink("real/theme.css", filepath.Join(dir, "static", "theme.css")); err != nil {
		t.Fatal(err)
	}
	if th, err := LoadTheme(dir); err != nil || string(th.statics["theme.css"].data) != "p {}" {
		t.Errorf("a link in the theme: %v", err)
	}
}

// The check of a theme stops what the CSP would block without a word, and a
// locale added without all the texts (Thèmes, validation).
func TestCheckTheme(t *testing.T) {
	errorPage := func(content string) map[string]string {
		return map[string]string{"templates/error.html.tmpl": `{{define "title"}}{{.T "error.title"}}{{end}}{{define "content"}}` + content + `{{end}}`}
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"inline script": {errorPage(`<script>alert(1)</script>`), []string{"page error: <script> without src, which the CSP blocks: a script goes to static/theme.js"}},
		"on attribute":  {errorPage(`<button onClick="go()">x</button>`), []string{"page error: attribute onclick on <button>, which the CSP blocks"}},
		"style element": {errorPage(`<style>p { color: red }</style>`), []string{"page error: <style>, which the CSP blocks: a style goes to static/theme.css"}},
		"style":         {errorPage(`<p style="color: red">x</p>`), []string{"page error: attribute style on <p>, which the CSP blocks"}},
		"javascript":    {errorPage(`<a href=" JavaScript:go()">x</a>`), []string{"page error: javascript: URL in href on <a>, which the CSP blocks"}},
		"layout":        {map[string]string{"templates/layout.html.tmpl": `{{define "layout"}}<body onload="x()">{{block "content" .}}{{end}}</body>{{end}}`}, []string{"page select: attribute onload on <body>", "page logout: attribute onload on <body>"}},
		"locale lacking texts": {map[string]string{"translations/de.json": `{"locale.de": "Deutsch"}`},
			[]string{"catalog de: no text for choice.title", "catalog de: no text for error.E1004"}},
	} {
		th, err := LoadTheme(writeTheme(t, tc.files))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = Check(th)
		for _, want := range tc.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v, want %q", name, err, want)
			}
		}
		// Once a page, whatever its locales and branches.
		if err != nil && strings.Count(err.Error(), "page error: <script>") > 1 {
			t.Errorf("%s: said more than once:\n%v", name, err)
		}
	}
	// A script that has its src, a stylesheet linked, are what the CSP lets through.
	th, err := LoadTheme(writeTheme(t, map[string]string{"static/theme.js": "", "templates/partials/extra.html.tmpl": `{{define "extra"}}<link rel="stylesheet" href="{{.Asset "theme.css"}}">{{end}}`}))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(th); err != nil {
		t.Errorf("theme.js: %v", err)
	}
}

// The check reads the fields in the form that posts them, as a browser sends
// them (revue R32): a form in GET, the default of HTML, fields out of the form,
// in another one, or a form posted to another URL passed, and broke the page.
func TestCheckForms(t *testing.T) {
	page := func(file, title, content string) map[string]string {
		return map[string]string{"templates/" + file + ".html.tmpl": `{{define "title"}}{{.T "` + title + `"}}{{end}}{{define "content"}}` + content + `{{end}}`}
	}
	choice := func(form string) map[string]string {
		return page("select", "choice.title", `{{if .Flows}}`+form+`{{end}}`)
	}
	const (
		choiceFields  = `{{template "csrf" .}}<input type="hidden" name="login_challenge" value="{{.Form.LoginChallenge}}">{{range .Flows}}{{template "flow_card" .}}{{end}}`
		consentHidden = `{{template "csrf" .}}<input type="hidden" name="consent_challenge" value="{{.Form.ConsentChallenge}}">{{if .Form.Print}}<input type="hidden" name="claims_print" value="{{.Form.Print}}">{{end}}`
		accept        = `<button name="action" value="accept">{{.T "consent.accept"}}</button>`
		reject        = `<button name="action" value="reject">{{.T "consent.reject"}}</button>`
	)
	consent := func(content string) map[string]string { return page("consent", "consent.title", content) }
	logout := func(form string) map[string]string {
		return page("logout", "logout.title", `{{if .Form.LogoutChallenge}}`+form+`{{end}}`)
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"choice in GET": {choice(`<form action="{{.Form.Action}}">` + choiceFields + `<button>Go</button></form>`),
			`page select (flows, one refused) in en: no <form method="post" action="/?login_challenge=c2FtcGxlX2NoYWxsZW5nZQ%3D%3D">`},
		"fields out of the form": {choice(`{{template "csrf" .}}<form method="post" action="{{.Form.Action}}"><input type="hidden" name="login_challenge" value="{{.Form.LoginChallenge}}">{{range .Flows}}{{template "flow_card" .}}{{end}}<button>Go</button></form>`),
			"page select (flows, one refused) in en: no field csrf_token in the form"},
		"field disabled": {choice(`<form method="post" action="{{.Form.Action}}"><input type="hidden" name="csrf_token" value="{{.Form.CSRF}}" disabled><input type="hidden" name="login_challenge" value="{{.Form.LoginChallenge}}">{{range .Flows}}{{template "flow_card" .}}{{end}}<button>Go</button></form>`),
			"page select (flow selected) in fr: no field csrf_token in the form"},
		"field of another form": {choice(`<form method="post" action="{{.Form.Action}}">` + choiceFields + `<input type="hidden" name="login_challenge" value="x" form="other"><button>Go</button></form>`),
			""},
		"accept without the challenge": {consent(`<form method="post" action="{{.Form.Action}}">{{template "csrf" .}}` + accept + `</form><form method="post" action="{{.Form.Action}}">` + consentHidden + reject + `</form>`),
			// The form of the challenge and the print, the reject's, judged:
			// it has no accept.
			`page consent (scopes, claims, audience) in en: field action without the value "accept"`},
		// R44: an accept without the print shows the screen again, forever.
		"no print": {consent(`<form method="post" action="{{.Form.Action}}">{{template "csrf" .}}<input type="hidden" name="consent_challenge" value="{{.Form.ConsentChallenge}}">` + accept + reject + `</form>`),
			"page consent (scopes, claims, audience) in en: no field claims_print in the form"},
		"posted to another URL": {consent(`<form method="post" action="/consent">` + consentHidden + accept + reject + `</form>`),
			`page consent (scopes, claims, audience) in en: no <form method="post" action="/consent?consent_challenge=c2FtcGxlX2NoYWxsZW5nZQ%3D%3D">`},
		"action hidden and a button": {consent(`<form method="post" action="{{.Form.Action}}">` + consentHidden + `<input type="hidden" name="action" value="reject">` + accept + reject + `</form>`),
			"page consent (scopes, claims, audience) in en: field action is both a field always sent and a button or a choice"},
		"hidden field posted twice": {consent(`<form method="post" action="{{.Form.Action}}"><input type="hidden" name="consent_challenge" value="x">` + consentHidden + accept + reject + `</form>`),
			`page consent (nothing asked) in fr: field consent_challenge posts "x" first, which the handlers read, before "c2FtcGxlX2NoYWxsZW5nZQ=="`},
		"accept posted elsewhere": {logout(`<form method="post" action="{{.Form.Action}}">{{template "csrf" .}}<input type="hidden" name="logout_challenge" value="{{.Form.LogoutChallenge}}"><button name="action" value="accept" formaction="/logout">Yes</button><button name="action" value="reject">No</button></form>`),
			`page logout (confirm) in en: field action without the value "accept"`},
		"accept of type button": {logout(`<form method="post" action="{{.Form.Action}}">{{template "csrf" .}}<input type="hidden" name="logout_challenge" value="{{.Form.LogoutChallenge}}"><button type="button" name="action" value="accept">Yes</button><button name="action" value="reject">No</button></form>`),
			`page logout (other session) in fr: field action without the value "accept"`},
		// What a browser posts as the handlers read it.
		"two whole forms": {consent(`<form method="POST" action="{{.Form.Action}}">` + consentHidden + accept + `</form><form method="post" action="{{.Form.Action}}">` + consentHidden + reject + `</form>`), ""},
		"formaction of the page": {logout(`<form method="post">{{template "csrf" .}}<input type="hidden" name="logout_challenge" value="{{.Form.LogoutChallenge}}"><button name="action" value="accept" formaction="{{.Form.Action}}">Yes</button></form>`),
			`page logout (confirm) in en: no <form method="post" action="/logout?logout_challenge=c2FtcGxlX2NoYWxsZW5nZQ%3D%3D">`},
		"within a form, a form ignored": {choice(`<form method="post" action="{{.Form.Action}}">` + choiceFields + `<form method="get"></form><button>Go</button></form>`), ""},
	} {
		th, err := LoadTheme(writeTheme(t, tc.files))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = Check(th)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// The locales of the settings the theme has no catalog for are named, each
// with what the pages do without it (Q92).
func TestLocaleWarnings(t *testing.T) {
	embedded, err := LoadTheme("")
	if err != nil {
		t.Fatal(err)
	}
	settings := store.DefaultSettings()
	if w := LocaleWarnings(embedded, settings); len(w) != 0 {
		t.Errorf("defaults: %q", w)
	}
	settings.SupportedLocales, settings.DefaultLocale, settings.FallbackLocale = []string{"fr", "de"}, "de", "es"
	want := []string{
		`setting supported_locales: "de" has no catalog in the theme (en, fr): the pages do not offer it`,
		`setting default_locale: "de" has no catalog in the theme (en, fr): the pages take the first locale they offer`,
		`setting fallback_locale: "es" has no catalog in the theme (en, fr): a text missing from a page's locale shows its key`,
	}
	if got := LocaleWarnings(embedded, settings); !slices.Equal(got, want) {
		t.Errorf("warnings %q\nwant %q", got, want)
	}
	withGerman, err := LoadTheme(writeTheme(t, map[string]string{"translations/de.json": german(t)}))
	if err != nil {
		t.Fatal(err)
	}
	if got := LocaleWarnings(withGerman, settings); !slices.Equal(got, []string{`setting fallback_locale: "es" has no catalog in the theme (de, en, fr): a text missing from a page's locale shows its key`}) {
		t.Errorf("with de: %q", got)
	}
}

// examples/theme-demo, a whole theme in Tailwind with a locale of its own, passes
// the check: a change of the contract that breaks it fails here, not only in its
// job of the CI (Q91).
func TestThemeDemo(t *testing.T) {
	th, err := LoadTheme(filepath.Join("..", "..", "examples", "theme-demo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(th); err != nil {
		t.Fatal(err)
	}
	if th.Manifest.Name != "theme-demo" || !slices.Equal(th.Locales(), []string{"de", "en", "fr"}) {
		t.Errorf("manifest %+v, locales %v", th.Manifest, th.Locales())
	}
	// Its layout loads its theme.css, not the base CSS: Tailwind's preflight takes its place.
	snap := testSnapshot()
	snap.Settings.SupportedLocales = []string{"fr", "en", "de"}
	w := newWorld(t, worldOptions{base: base, snapshot: snap, theme: th})
	body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=de", nil))
	for _, want := range []string{"Wie möchten Sie sich anmelden?", `href="/static/theme.css?v=`, `src="/static/flags/de.svg?v=`, `class="btn btn-primary mt-6"`} {
		if !strings.Contains(body, want) {
			t.Errorf("no %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "base.css") {
		t.Errorf("base.css loaded:\n%s", body)
	}
}
