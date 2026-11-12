package adminui

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

var secretRe = regexp.MustCompile(`<input id="secret" readonly value="([^"]+)"`)

// secretOf is the secret a page shows.
func secretOf(t *testing.T, w interface{ Body() string }) string {
	t.Helper()
	m := secretRe.FindStringSubmatch(w.Body())
	if m == nil {
		t.Fatalf("no secret in:\n%s", w.Body())
	}
	return m[1]
}

type page struct{ body string }

func (p page) Body() string { return p.body }

func TestClients(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	if w := b.do(http.MethodGet, "/admin/clients", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "No API client yet.") {
		t.Fatalf("list: %d", w.Code)
	}
	form := b.do(http.MethodGet, "/admin/clients/_new", nil)
	if form.Code != http.StatusOK || strings.Count(form.Body.String(), `name="scope"`) != 5 {
		t.Fatalf("form: %d\n%s", form.Code, form.Body)
	}
	w := b.do(http.MethodPost, "/admin/clients", url.Values{"csrf": {token(t, form)}, "id": {"ci"}, "scope": {"admin:read", "admin:apps"}})
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d\n%s", w.Code, w.Body)
	}
	secret := secretOf(t, page{w.Body.String()})
	c, ok := r.config.client("ci")
	if !ok || !domain.SecretMatches(c.SecretHash, secret) || !slices.Equal(c.Scopes, []string{"admin:apps", "admin:read"}) && !slices.Equal(c.Scopes, []string{"admin:read", "admin:apps"}) {
		t.Fatalf("created: %+v", c)
	}
	view := b.do(http.MethodGet, "/admin/clients/ci", nil).Body.String()
	if strings.Contains(view, secret) || strings.Contains(view, c.SecretHash) || !strings.Contains(view, `value="admin:read" checked`) ||
		strings.Contains(view, `value="admin:flows" checked`) {
		t.Errorf("page:\n%s", view)
	}

	w = b.do(http.MethodPost, "/admin/clients/ci", url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/clients/ci")}, "scope": {"admin:read"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("scopes: %d\n%s", w.Code, w.Body)
	}
	if c, _ := r.config.client("ci"); !slices.Equal(c.Scopes, []string{"admin:read"}) {
		t.Errorf("scopes: %q", c.Scopes)
	}

	confirm := b.do(http.MethodGet, "/admin/clients/ci/rotate", nil)
	if confirm.Code != http.StatusOK || !strings.Contains(confirm.Body.String(), `action="/admin/clients/ci/rotate"`) {
		t.Fatalf("rotate, its page: %d\n%s", confirm.Code, confirm.Body)
	}
	w = b.do(http.MethodPost, "/admin/clients/ci/rotate", url.Values{"csrf": {token(t, confirm)}})
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d\n%s", w.Code, w.Body)
	}
	turned := secretOf(t, page{w.Body.String()})
	if c, _ := r.config.client("ci"); turned == secret || domain.SecretMatches(c.SecretHash, secret) || !domain.SecretMatches(c.SecretHash, turned) {
		t.Error("the secret is not turned")
	}

	w = b.do(http.MethodPost, "/admin/clients/ci/delete", url.Values{"csrf": {b.csrf()}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/clients?done=deleted" {
		t.Fatalf("delete: %d\n%s", w.Code, w.Body)
	}
	if _, ok := r.config.client("ci"); ok {
		t.Error("still there")
	}
	got := r.wrote()
	if want := []string{
		"write alice oauth2-clients ci create id,secret,scopes",
		"write alice oauth2-clients ci update scopes",
		"write alice oauth2-clients ci update secret",
		"write alice oauth2-clients ci delete ",
	}; !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
	for _, line := range r.audited() {
		if strings.Contains(line, secret) || strings.Contains(line, turned) {
			t.Errorf("a secret in the audit: %q", line)
		}
	}
}

// A scope the dispatcher does not offer, which a client holds, is shown and
// kept; a client refused writes nothing.
func TestClientScopesKept(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	hash, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	r.config.clients = []store.APIClient{{ID: "legacy", SecretHash: hash, Scopes: []string{"admin:read", "admin:legacy"}}}
	b := r.browser()
	b.login("alice", password, "")
	view := b.do(http.MethodGet, "/admin/clients/legacy", nil).Body.String()
	if !strings.Contains(view, `value="admin:legacy" checked`) {
		t.Fatalf("page:\n%s", view)
	}
	w := b.do(http.MethodPost, "/admin/clients/legacy", url.Values{"csrf": {b.csrf()}, "version": {b.version("/admin/clients/legacy")},
		"scope": {"admin:read", "admin:legacy", "admin:apps"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	if c, _ := r.config.client("legacy"); !slices.Equal(c.Scopes, []string{"admin:read", "admin:legacy", "admin:apps"}) || c.SecretHash != hash {
		t.Errorf("saved: %+v", c)
	}
	for name, c := range map[string]struct {
		id   string
		code int
		want string
	}{
		"a bad id":   {"-bad", http.StatusUnprocessableEntity, `value="-bad" required maxlength="128" aria-invalid="true">`},
		"an id used": {"legacy", http.StatusConflict, "is taken"},
	} {
		form := b.do(http.MethodGet, "/admin/clients/_new", nil)
		w := b.do(http.MethodPost, "/admin/clients", url.Values{"csrf": {token(t, form)}, "id": {c.id}, "scope": {"admin:read"}})
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) || secretRe.MatchString(w.Body.String()) {
			t.Errorf("%s: %d\n%s", name, w.Code, w.Body)
		}
	}
	if len(r.config.clients) != 1 {
		t.Errorf("clients: %+v", r.config.clients)
	}
}

// Every write of a client asks for the password again past the window; a
// viewer reads.
func TestClientSensitive(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	hash, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	r.config.clients = []store.APIClient{{ID: "ci", SecretHash: hash, Scopes: []string{"admin:read"}}}
	b := r.browser()
	b.login("alice", password, "")
	r.advance(6 * time.Minute)
	for _, path := range []string{"/admin/clients/_new", "/admin/clients/ci/rotate", "/admin/clients/ci/delete"} {
		if w := b.do(http.MethodGet, path, nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/admin/reauth?next=") {
			t.Errorf("GET %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/admin/clients", "/admin/clients/ci", "/admin/clients/ci/rotate", "/admin/clients/ci/delete"} {
		form := url.Values{"csrf": {b.csrf()}, "id": {"other"}, "scope": {"admin:apps"}, "version": {b.version("/admin/clients/ci")}}
		if w := b.do(http.MethodPost, path, form); w.Code != http.StatusForbidden {
			t.Errorf("POST %s: %d", path, w.Code)
		}
	}
	if c, _ := r.config.client("ci"); len(r.config.clients) != 1 || c.SecretHash != hash || !slices.Equal(c.Scopes, []string{"admin:read"}) {
		t.Errorf("written: %+v", r.config.clients)
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/clients/ci", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<fieldset disabled>") ||
		strings.Contains(w.Body.String(), "/rotate") {
		t.Errorf("a viewer: %d\n%s", w.Code, w.Body)
	}
	if w := viewer.do(http.MethodPost, "/admin/clients/ci/rotate", url.Values{"csrf": {viewer.csrf()}}); w.Code != http.StatusForbidden {
		t.Errorf("a viewer turns: %d", w.Code)
	}
}
