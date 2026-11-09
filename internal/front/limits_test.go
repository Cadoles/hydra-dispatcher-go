package front

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/limiter"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

var checkedFlow = regexp.MustCompile(`value="([a-z0-9-]+)" required checked`)

// The last flow started from the form is checked on the next choice page, whose order
// does not change; nothing goes straight to it, and a flow no longer offered checks
// nothing (doc, Présélection du dernier flow).
func TestLastFlow(t *testing.T) {
	w := newWorld(t, worldOptions{base: base, lastFlow: true})
	page := func() string {
		resp := w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("choice page: %d", resp.StatusCode)
		}
		return text(t, resp)
	}
	if m := checkedFlow.FindStringSubmatch(text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))); m != nil {
		t.Errorf("a first visit checks %s", m[1])
	}
	resp := w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql-2fa"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...)
	location(t, resp, http.StatusSeeOther)
	var cookie *http.Cookie
	if cookie = setCookie(resp, lastFlowCookie); cookie == nil || cookie.Value != "hydra-sql-2fa" || !cookie.HttpOnly || cookie.MaxAge != 365*24*3600 || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("Set-Cookie %+v", cookie)
	}
	body := page()
	if m := checkedFlow.FindStringSubmatch(body); m == nil || m[1] != "hydra-sql-2fa" {
		t.Errorf("checked %v", m)
	}
	if !strings.Contains(body, `<button type="submit" autofocus>`) {
		t.Error("the button has no focus")
	}
	if strings.Index(body, `value="hydra-sql"`) > strings.Index(body, `value="hydra-sql-2fa"`) {
		t.Error("the order of the list changed")
	}
	// A cookie that names what is not offered, or any value, checks nothing.
	w.cookies[lastFlowCookie] = "not-offered"
	if m := checkedFlow.FindStringSubmatch(page()); m != nil {
		t.Errorf("not offered: checks %s", m[1])
	}
	w.cookies[lastFlowCookie] = `"><script>alert(1)</script>`
	if body := page(); strings.Contains(body, "<script>alert") {
		t.Error("the cookie reached the page")
	}
}

// ui.remember_last_flow: false neither writes nor reads it: a shared computer does not
// reveal the method used.
func TestLastFlowOff(t *testing.T) {
	w := newWorld(t)
	page := text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL, nil))
	if checkedFlow.MatchString(page) {
		t.Error("checked")
	}
	resp := w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}, "csrf_token": {w.csrf()}}, sameOrigin...)
	location(t, resp, http.StatusSeeOther)
	if setCookie(resp, lastFlowCookie) != nil {
		t.Error("cookie written")
	}
	w.cookies[lastFlowCookie] = "hydra-sql"
	if checkedFlow.MatchString(text(t, w.do(http.MethodGet, "/?login_challenge="+hydraL2, nil))) {
		t.Error("cookie read")
	}
}

// A flow the form did not start, the only one offered, does not change the method shown.
func TestLastFlowNotOfAnAutoSelect(t *testing.T) {
	snap := testSnapshot()
	snap.Settings.AppAutoSelect = true
	only := store.NewSnapshot(snap.Apps, snap.Flows[:1], snap.Settings)
	w := newWorld(t, worldOptions{base: base, lastFlow: true, snapshot: only})
	resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	location(t, resp, http.StatusSeeOther)
	if setCookie(resp, lastFlowCookie) != nil {
		t.Error("cookie written by an auto select")
	}
}

// The limiter through the pages: forged challenges from an address end in 429 for it,
// before any call to Hydra, and the addresses around it pass; CSRF tokens count too, an
// expired challenge does not (Q78).
func TestLimiterThroughThePages(t *testing.T) {
	limit := limiter.New(3, time.Minute, 5*time.Minute)
	blocks := 0
	limit.OnBlock = func(context.Context) { blocks++ }
	w := newWorld(t, worldOptions{base: base, guard: limit.Guard("front")})
	w.o.Observers = []flow.Observer{limit}
	gone := func(status int) error {
		return &hydra.RequestError{Op: "get_login_request", Status: status, Body: []byte(`{"error":"x"}`)}
	}

	w.hydra.errs["get_login"] = gone(http.StatusUnauthorized)
	for range 10 {
		if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode == http.StatusTooManyRequests {
			t.Fatal("expired challenges blocked an address")
		}
	}
	w.hydra.errs["get_login"] = gone(http.StatusNotFound)
	for range 4 {
		if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if blocks != 1 {
		t.Errorf("%d blocks", blocks)
	}
	n := len(w.hydra.calls)
	resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if len(w.hydra.calls) != n {
		t.Error("a blocked address reaches Hydra")
	}
	// The static files and the probes stay open: a page needs its CSS.
	if resp := w.do(http.MethodGet, "/static/base.css", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("static: %d", resp.StatusCode)
	}
}

// Another site's page loads the pages in its visitor's browser: images of forged
// challenges, forms posted by fetch. Nothing counts, or the visitor's address, and
// everyone behind it, would be blocked by a page it only visited (Q80, revue R29).
func TestLimiterIgnoresSubrequests(t *testing.T) {
	limit := limiter.New(3, time.Minute, 5*time.Minute)
	w := newWorld(t, worldOptions{base: base, guard: limit.Guard("front")})
	w.o.Observers = []flow.Observer{limit}
	w.hydra.errs["get_login"] = &hydra.RequestError{Op: "get_login_request", Status: http.StatusNotFound, Body: []byte(`{"error":"x"}`)}
	image := []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image"}
	fetch := []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "empty"}
	for range 10 {
		if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil, image...); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("an image: %d", resp.StatusCode)
		}
		if resp := w.do(http.MethodPost, "/", url.Values{"flow": {"hydra-sql"}, "login_challenge": {hydraL}}, fetch...); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a fetch: %d", resp.StatusCode)
		}
	}
	delete(w.hydra.errs, "get_login")
	if resp := w.do(http.MethodGet, "/?login_challenge="+hydraL, nil, "Sec-Fetch-Site", "none", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"); resp.StatusCode != http.StatusOK {
		t.Errorf("a navigation after another site's page: %d", resp.StatusCode)
	}
}
