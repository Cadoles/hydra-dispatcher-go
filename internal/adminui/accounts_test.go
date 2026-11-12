package adminui

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

func accountValues(b *browser, name, role, secret, again string) url.Values {
	b.r.t.Helper()
	form := b.do(http.MethodGet, "/admin/new-account", nil)
	return url.Values{"csrf": {token(b.r.t, form)}, "username": {name}, "role": {role}, "password": {secret}, "password_again": {again}}
}

func TestAccounts(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	list := b.do(http.MethodGet, "/admin/accounts", nil).Body.String()
	if !strings.Contains(list, `<a href="/admin/accounts/alice">alice</a> <small>(you)</small></td><td>admin</td><td>password</td>`) ||
		!strings.Contains(list, `<td>admin</td><td>the identity provider</td>`) || !strings.Contains(list, `href="/admin/new-account"`) {
		t.Fatalf("list:\n%s", list)
	}
	w := b.do(http.MethodPost, "/admin/accounts", accountValues(b, "dora / ops", domain.RoleViewer, "a password long enough", "a password long enough"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/accounts/dora%20%2F%20ops?done=created" {
		t.Fatalf("create: %d %s\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	u, _, _ := r.accounts.Admin(t.Context(), "dora / ops")
	if u.Role != domain.RoleViewer || !domain.SecretMatches(u.PasswordHash, "a password long enough") {
		t.Errorf("created: %+v", u)
	}
	if page := b.do(http.MethodGet, "/admin/accounts/dora%20%2F%20ops", nil); page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Account dora / ops") {
		t.Errorf("its page: %d\n%s", page.Code, page.Body)
	}
	dora := r.browser()
	dora.login("dora / ops", "a password long enough", "")
	if w := dora.do(http.MethodGet, "/admin", nil); w.Code != http.StatusOK {
		t.Fatalf("dora logs in: %d", w.Code)
	}

	// A role changed ends the sessions of the account.
	w = b.do(http.MethodPost, "/admin/accounts/dora%20%2F%20ops/role", url.Values{"csrf": {b.csrf()}, "role": {domain.RoleAdmin}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("role: %d\n%s", w.Code, w.Body)
	}
	r.advance(time.Second)
	if w := dora.do(http.MethodGet, "/admin", nil); w.Code != http.StatusSeeOther {
		t.Errorf("dora's session, after her role: %d", w.Code)
	}
	if w := b.do(http.MethodPost, "/admin/accounts/dora%20%2F%20ops/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d\n%s", w.Code, w.Body)
	}
	if _, found, _ := r.accounts.Admin(t.Context(), "dora / ops"); found {
		t.Error("still there")
	}
	if got, want := r.wrote(), []string{
		"write alice admin-users dora / ops create role,password",
		"write alice admin-users dora / ops update role",
		"write alice admin-users dora / ops delete ",
	}; !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
}

func TestAccountRefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	for name, c := range map[string]struct {
		form url.Values
		code int
		want string
	}{
		"short":      {accountValues(b, "dora", "viewer", "short", "short"), http.StatusUnprocessableEntity, "has 5 characters: 12 at least."},
		"differ":     {accountValues(b, "dora", "viewer", "a password long enough", "a password long enougH"), http.StatusUnprocessableEntity, "and its confirmation differ."},
		"none":       {accountValues(b, "dora", "viewer", "", ""), http.StatusUnprocessableEntity, "is required for an account without an OIDC subject"},
		"no role":    {accountValues(b, "dora", "", "a password long enough", "a password long enough"), http.StatusUnprocessableEntity, "is required."},
		"a role":     {accountValues(b, "dora", "root", "a password long enough", "a password long enough"), http.StatusUnprocessableEntity, "&#34;root&#34; is not admin or viewer."},
		"taken":      {accountValues(b, "victor", "viewer", "a password long enough", "a password long enough"), http.StatusConflict, "is taken"},
		"a space":    {accountValues(b, "dora ", "viewer", "a password long enough", "a password long enough"), http.StatusUnprocessableEntity, "starts or ends with a space."},
		"html, kept": {accountValues(b, "<b>dora</b>", "", "", ""), http.StatusUnprocessableEntity, `value="&lt;b&gt;dora&lt;/b&gt;"`},
	} {
		w := b.do(http.MethodPost, "/admin/accounts", c.form)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) || strings.Contains(w.Body.String(), "a password long enough") {
			t.Errorf("%s: %d\n%s", name, w.Code, w.Body)
		}
	}
	if _, found, _ := r.accounts.Admin(t.Context(), "dora"); found || len(r.wrote()) != 0 {
		t.Errorf("written: %q", r.wrote())
	}
	// No account deletes itself, another admin there (olga); the last admin
	// keeps the role.
	if w := b.do(http.MethodGet, "/admin/accounts/alice/delete", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), `action="/admin/accounts/alice/delete"`) {
		t.Errorf("one's own deletion, its page: %d\n%s", w.Code, w.Body)
	}
	if w := b.do(http.MethodPost, "/admin/accounts/alice/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "No account deletes itself.") {
		t.Errorf("one's own deletion: %d", w.Code)
	}
	if w := b.do(http.MethodPost, "/admin/accounts/olga/role", url.Values{"csrf": {b.csrf()}, "role": {"viewer"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("olga: %d", w.Code)
	}
	if w := b.do(http.MethodPost, "/admin/accounts/alice/role", url.Values{"csrf": {b.csrf()}, "role": {"viewer"}}); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "the last account of the role admin") {
		t.Errorf("the last admin: %d\n%s", w.Code, w.Body)
	}
	if u, found, _ := r.accounts.Admin(t.Context(), "alice"); !found || u.Role != domain.RoleAdmin {
		t.Errorf("alice: %+v", u)
	}
}

// The writes of the accounts ask for the password again past the window; a
// viewer reads them.
func TestAccountSensitive(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := accountValues(b, "dora", "admin", "a password long enough", "a password long enough")
	r.advance(6 * time.Minute)
	if w := b.do(http.MethodGet, "/admin/new-account", nil); w.Code != http.StatusSeeOther {
		t.Errorf("the form: %d", w.Code)
	}
	for path, f := range map[string]url.Values{
		"/admin/accounts":               form,
		"/admin/accounts/victor/role":   {"csrf": {b.csrf()}, "role": {"admin"}},
		"/admin/accounts/victor/delete": {"csrf": {b.csrf()}},
	} {
		if w := b.do(http.MethodPost, path, f); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	if u, _, _ := r.accounts.Admin(t.Context(), "victor"); u.Role != domain.RoleViewer {
		t.Errorf("victor: %+v", u)
	}
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin/accounts/alice", nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), `name="role"`) {
		t.Errorf("a viewer reads: %d\n%s", w.Code, w.Body)
	}
	if w := viewer.do(http.MethodGet, "/admin/new-account", nil); w.Code != http.StatusForbidden {
		t.Errorf("a viewer, the form: %d", w.Code)
	}
	if w := viewer.do(http.MethodPost, "/admin/accounts/victor/role", url.Values{"csrf": {viewer.csrf()}, "role": {"admin"}}); w.Code != http.StatusForbidden {
		t.Errorf("a viewer makes itself admin: %d", w.Code)
	}
	r.accounts.fail = errStore
	if w := b.do(http.MethodGet, "/admin/accounts", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("the store failing: %d", w.Code)
	}
}

var errStore = store.ErrNotFound

// Its own password, for every role: this browser's session goes on, the
// others end.
func TestOwnPassword(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b, other := r.browser(), r.browser()
	b.login("victor", password, "")
	other.login("victor", password, "")
	own := b.do(http.MethodGet, "/admin/account", nil)
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), `href="/admin/account/password"`) {
		t.Fatalf("own page: %d\n%s", own.Code, own.Body)
	}
	form := b.do(http.MethodGet, "/admin/account/password", nil)
	if form.Code != http.StatusOK {
		t.Fatalf("the form: %d", form.Code)
	}
	post := func(secret, again string) int {
		return b.do(http.MethodPost, "/admin/account/password", url.Values{"csrf": {token(t, form)}, "password": {secret}, "password_again": {again}}).Code
	}
	if code := post("short", "short"); code != http.StatusUnprocessableEntity {
		t.Errorf("short: %d", code)
	}
	if code := post("a new password, long", "a new password, lonG"); code != http.StatusUnprocessableEntity {
		t.Errorf("differ: %d", code)
	}
	if code := post("a new password, long", "a new password, long"); code != http.StatusSeeOther {
		t.Fatalf("changed: %d", code)
	}
	if w := b.do(http.MethodGet, "/admin/account", nil); w.Code != http.StatusOK {
		t.Errorf("this session: %d", w.Code)
	}
	if w := other.do(http.MethodGet, "/admin/account", nil); w.Code != http.StatusSeeOther {
		t.Errorf("the other session: %d", w.Code)
	}
	if w := r.browser().login("victor", password, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("the old password: %d", w.Code)
	}
	if w := r.browser().login("victor", "a new password, long", ""); w.Code != http.StatusSeeOther {
		t.Errorf("the new password: %d", w.Code)
	}
	if got := r.wrote(); !slices.Equal(got, []string{"write victor admin-users victor update password"}) {
		t.Errorf("audit: %q", got)
	}
	// Past the window, the change asks for the password again; the token is
	// the new session's.
	r.advance(6 * time.Minute)
	w := b.do(http.MethodPost, "/admin/account/password", url.Values{"csrf": {b.csrf()}, "password": {"another password, long"}, "password_again": {"another password, long"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "asks for your password again") {
		t.Errorf("past the window: %d\n%s", w.Code, w.Body)
	}
}
