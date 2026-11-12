package adminui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests of the reports of the revue R40.

// The forms another site forges are refused before the limit: they do not
// exhaust the attempts of the address of the admin whose browser posts them.
func TestLoginForgedNotCounted(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.headers["Origin"] = "https://evil.test"
	for i := range 15 {
		if w := b.login("alice", "wrong password!", ""); w.Code != http.StatusForbidden {
			t.Fatalf("forged %d: %d", i+1, w.Code)
		}
	}
	delete(b.headers, "Origin")
	if w := b.login("alice", password, ""); w.Code != http.StatusSeeOther || r.limited.Load() != 0 {
		t.Errorf("the admin, after them: %d, limited %d", w.Code, r.limited.Load())
	}
}

// A re-authentication counts among the attempts of the address, with the
// logins.
func TestReauthCounted(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "") // the first attempt
	form := b.do(http.MethodGet, "/admin/reauth", nil)
	attempt := func() int {
		return b.do(http.MethodPost, "/admin/reauth", url.Values{"csrf": {token(t, form)}, "password": {"wrong password!"}}).Code
	}
	for i := range 9 {
		if code := attempt(); code != http.StatusUnauthorized {
			t.Fatalf("reauth %d: %d", i+2, code)
		}
	}
	if code := attempt(); code != http.StatusTooManyRequests {
		t.Errorf("the 11th attempt, a reauth: %d", code)
	}
}

// A session sealed without an account is none, without a read of the store.
func TestSessionWithoutName(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	now := r.clock().UnixMicro()
	data, err := json.Marshal(session{Method: "password", Issued: now, Seen: now, Auth: now, CSRF: "x"})
	if err != nil {
		t.Fatal(err)
	}
	b := r.browser()
	b.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: r.ui.o.Keys.Seal(sessionCookie, sealVersion, data)}
	reads := r.accounts.reads.Load()
	if w := b.do(http.MethodGet, "/admin", nil); w.Code != http.StatusSeeOther || r.accounts.reads.Load() != reads {
		t.Errorf("no name: %d, %d reads", w.Code, r.accounts.reads.Load()-reads)
	}
}

// A database that no longer answers gives a 503 within the bound, to a page
// as to a login.
func TestAccountsFrozen(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.ui.accountsWait = 50 * time.Millisecond
	b := r.browser()
	b.login("alice", password, "")
	r.accounts.hold = make(chan struct{})
	done := make(chan [2]int, 1)
	go func() {
		page := b.do(http.MethodGet, "/admin", nil).Code
		done <- [2]int{page, r.browser().login("alice", password, "").Code}
	}()
	select {
	case codes := <-done:
		if codes != [2]int{http.StatusServiceUnavailable, http.StatusServiceUnavailable} {
			t.Errorf("a page, a login: %v", codes)
		}
		close(r.accounts.hold)
	case <-time.After(3 * time.Second):
		close(r.accounts.hold) // the requests waited for ever
		t.Error("no answer within 3 s")
		<-done
	}
}

// A logout whose sessions cannot be ended logs this browser out and says so;
// the audit writes no logout.
func TestLogoutFailed(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	r.accounts.endFail = errors.New("the database does not answer")
	w := b.do(http.MethodPost, "/admin/logout", url.Values{"csrf": {b.csrf()}})
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "could not be ended") || b.cookies[sessionCookie] != nil {
		t.Errorf("logout: %d %v\n%s", w.Code, b.cookies[sessionCookie], w.Body)
	}
	if slices.Contains(r.audited(), "logout alice") {
		t.Errorf("audit: %q", r.audited())
	}
}
