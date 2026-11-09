package front

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// rewrite writes content to the file of the theme at name, and moves its
// modification time forward: two writes in the same clock tick still differ.
func rewrite(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	when := time.Now()
	if err == nil {
		when = info.ModTime().Add(time.Second)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// themeCSS is the URL of theme.css on the page.
var themeCSS = regexp.MustCompile(`href="(/static/theme\.css\?v=[0-9a-f]{12})"`)

// ui.reload (Q93): a template, a text and a static file changed are served at the
// next page; a theme that fails answers 500 with the error of its check, the static
// files too, without running the request, until it is corrected.
func TestReload(t *testing.T) {
	dir := writeTheme(t, map[string]string{
		"templates/partials/client_header.html.tmpl": `{{define "client_header"}}<p class="brand">One</p>{{end}}`,
		"translations/en.json":                       `{"choice.title": "Pick one"}`,
		"static/theme.css":                           "p { color: #111111; }",
	})
	th, err := LoadTheme(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, worldOptions{base: base, theme: th, reload: true})
	page := func() (*http.Response, string) {
		t.Helper()
		resp := w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=en", nil)
		return resp, text(t, resp)
	}
	_, body := page()
	css := themeCSS.FindStringSubmatch(body)
	if !strings.Contains(body, `<p class="brand">One</p>`) || !strings.Contains(body, "Pick one") || css == nil {
		t.Fatalf("first page:\n%s", body)
	}

	rewrite(t, dir, "templates/partials/client_header.html.tmpl", `{{define "client_header"}}<p class="brand">Two</p>{{end}}`)
	rewrite(t, dir, "translations/en.json", `{"choice.title": "Pick another"}`)
	rewrite(t, dir, "static/theme.css", "p { color: #222222; }")
	_, body = page()
	css2 := themeCSS.FindStringSubmatch(body)
	if !strings.Contains(body, `<p class="brand">Two</p>`) || !strings.Contains(body, "Pick another") || css2 == nil || css2[1] == css[1] {
		t.Fatalf("after the changes:\n%s", body)
	}
	if got := text(t, w.do(http.MethodGet, css2[1], nil)); got != "p { color: #222222; }" {
		t.Errorf("theme.css %q", got)
	}

	// A template that does not parse, then one the check refuses.
	for _, broken := range []struct{ file, content, want string }{
		{"templates/select.html.tmpl", `{{define "content"}}{{if}}{{end}}`, "template select: template: select.html.tmpl:1: missing value for if"},
		{"templates/select.html.tmpl", `{{define "content"}}<p style="color: red">x</p>{{end}}`, "page select: attribute style on <p>, which the CSP blocks"},
	} {
		rewrite(t, dir, broken.file, broken.content)
		calls := len(w.hydra.calls)
		for range 2 {
			resp, body := page()
			trace := resp.Header.Get("X-Trace-ID")
			if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("Cache-Control") != "no-store" ||
				!strings.HasPrefix(body, "theme "+dir+": refused (ui.reload), trace id "+trace+"\n\n") || !strings.Contains(body, broken.want) {
				t.Fatalf("broken %s: %d\n%s", broken.want, resp.StatusCode, body)
			}
		}
		if len(w.hydra.calls) != calls {
			t.Errorf("the request ran: %v", w.hydra.calls[calls:])
		}
		if resp := w.do(http.MethodGet, "/static/base.css", nil); resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("a static file: %d", resp.StatusCode)
		}
	}
	// Logged at each reading that fails, not at each page.
	if n := strings.Count(w.logs.String(), `"msg":"theme.reload_failed"`); n != 2 {
		t.Errorf("%d theme.reload_failed:\n%s", n, w.logs.String())
	}

	if err := os.Remove(filepath.Join(dir, "templates/select.html.tmpl")); err != nil {
		t.Fatal(err)
	}
	if resp, body := page(); resp.StatusCode != http.StatusOK || !strings.Contains(body, `<p class="brand">Two</p>`) {
		t.Errorf("corrected: %d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(w.logs.String(), `"msg":"theme.reloaded"`) {
		t.Errorf("no theme.reloaded:\n%s", w.logs.String())
	}
}

// A file written between serve's reading of the theme and the pages' start,
// the stores' start in between, is served at the first page (revue R32): the
// stamp taken at New counted it as read, until another change.
func TestReloadChangeDuringStart(t *testing.T) {
	dir := writeTheme(t, map[string]string{"translations/en.json": `{"choice.title": "Before"}`})
	th, err := LoadTheme(dir)
	if err != nil {
		t.Fatal(err)
	}
	rewrite(t, dir, "translations/en.json", `{"choice.title": "After"}`)
	w := newWorld(t, worldOptions{base: base, theme: th, reload: true})
	if body := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL+"&_locale=en", nil)); !strings.Contains(body, "After") {
		t.Errorf("first page:\n%s", body)
	}
}

// Without ui.reload, the theme is read once: a file written on the disk after the
// start changes nothing, theme.css served the one hashed.
func TestNoReload(t *testing.T) {
	dir := writeTheme(t, map[string]string{"static/theme.css": "p { color: #111111; }"})
	th, err := LoadTheme(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, worldOptions{base: base, theme: th})
	css := themeCSS.FindStringSubmatch(text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)))
	if css == nil {
		t.Fatal("no theme.css")
	}
	rewrite(t, dir, "static/theme.css", "p { color: #222222; }")
	rewrite(t, dir, "templates/select.html.tmpl", `{{if}}`)
	if got := text(t, w.do(http.MethodGet, css[1], nil)); got != "p { color: #111111; }" {
		t.Errorf("theme.css %q", got)
	}
	if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("page: %d", resp.StatusCode)
	}
}
