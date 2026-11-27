package adminui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
)

// A violation on the label of a claim of a standard scope shows under the row
// of that claim: the form shows every claim of the code, the scope written
// only those it labels (revue R44).
func TestStandardClaimViolationRow(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	profile, _ := domain.Standard("profile")
	// picture is the eighth claim of profile, the only one labelled: claims[0]
	// of the scope written.
	v := scopeValues(b, b.version("/admin/scopes/profile"), map[string]string{"claim_label.7.fr": "x\x00y"}, profile...)
	w := b.do(http.MethodPost, "/admin/scopes/profile", v)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("%d\n%s", w.Code, w.Body)
	}
	page := w.Body.String()
	row := func(claim string) string {
		start := strings.Index(page, `<input type="hidden" name="claim" value="`+claim+`">`)
		if start < 0 {
			t.Fatalf("no row %s:\n%s", claim, page)
		}
		end := strings.Index(page[start:], "<tr>")
		if end < 0 {
			end = len(page) - start
		}
		return page[start : start+end]
	}
	if !strings.Contains(row("picture"), "NUL character") {
		t.Errorf("not under picture:\n%s", row("picture"))
	}
	if strings.Contains(row("name"), "NUL character") {
		t.Errorf("under name, the first row:\n%s", row("name"))
	}
}

// A logout while the accounts cannot be read: this browser's cookie
// forgotten, the logout audited as local, by the token of the session's form
// alone (revue R41). A forged form, or a session over, logs nothing out.
func TestLogoutAccountsUnreadable(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	csrf := b.csrf()
	r.accounts.fail = errors.New("the database does not answer")
	if w := b.do(http.MethodPost, "/admin/logout", url.Values{"csrf": {"forged"}}); w.Code != http.StatusServiceUnavailable || b.cookies[sessionCookie] == nil {
		t.Errorf("forged: %d %v", w.Code, b.cookies[sessionCookie])
	}
	if slices.ContainsFunc(r.audited(), func(s string) bool { return strings.HasPrefix(s, "logout") }) {
		t.Errorf("a forged form audited: %q", r.audited())
	}
	w := b.do(http.MethodPost, "/admin/logout", url.Values{"csrf": {csrf}})
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "Logged out of this browser only") || b.cookies[sessionCookie] != nil {
		t.Errorf("logout: %d %v\n%s", w.Code, b.cookies[sessionCookie], w.Body)
	}
	if got := r.audited(); got[len(got)-1] != "logout alice local" {
		t.Errorf("audit: %q", got)
	}
	// The other pages, the accounts unreadable: 503 as before.
	r.accounts.fail = nil
	b.login("alice", password, "")
	r.accounts.fail = errors.New("the database does not answer")
	if w := b.do(http.MethodGet, "/admin", nil); w.Code != http.StatusServiceUnavailable || b.cookies[sessionCookie] == nil {
		t.Errorf("a page: %d", w.Code)
	}
}
