package adminui

import (
	"net/http"
	"strings"
	"testing"
)

// The navigation (P25): two menus, the Hydra clients between them, and the
// documentation of the admin API when it serves it, as Symfony's menu linked
// to it.
func TestNavigation(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/settings", nil).Body.String()
	for _, want := range []string{"<summary>Configuration</summary>", "<summary>Administration</summary>",
		`<a href="/admin/settings" aria-current="page">Settings</a>`, `<a href="/admin/log-level">Log level</a>`} {
		if !strings.Contains(page, want) {
			t.Errorf("no %s:\n%s", want, page)
		}
	}
	if strings.Contains(page, "/admin/v1/docs") {
		t.Error("the documentation of an API not served")
	}
	r.ui.o.APIDocs = true
	if page := b.do(http.MethodGet, "/admin", nil).Body.String(); !strings.Contains(page, `<a href="/admin/v1/docs">API documentation</a>`) {
		t.Errorf("no documentation:\n%s", page)
	}
}
