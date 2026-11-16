package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// emulated is the dispatcher's emulated API for one login of alice, whose
// device value is dev; accepted keeps the accept's body.
func emulated(t *testing.T, dev string, accepted *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/oauth2/auth/requests/login":
			_ = json.NewEncoder(w).Encode(map[string]any{"subject": "alice", "x_dispatcher_device": dev})
		case "PUT /admin/oauth2/auth/requests/login/accept":
			_ = json.NewDecoder(r.Body).Decode(accepted)
			_, _ = io.WriteString(w, `{"redirect_to":"http://dispatcher.test/oauth2/auth?ref=r"}`)
		default:
			t.Errorf("emulated API: %s %s", r.Method, r.URL.Path)
		}
	}))
}

// check posts a pre-check signed by key at the time at.
func check(h http.Handler, key []byte, at time.Time, body string) *httptest.ResponseRecorder {
	ts := strconv.FormatInt(at.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/skip-check", strings.NewReader(body))
	r.Header.Set(headerTimestamp, ts)
	r.Header.Set(headerSignature, sign(key, ts, []byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// skips tells what a valid answer says, its signature checked as the
// dispatcher checks it.
func skips(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	ts := w.Header().Get(headerTimestamp)
	if w.Code != http.StatusOK || w.Header().Get(headerSignature) != sign(testKey, "response."+ts, w.Body.Bytes()) {
		t.Fatalf("answer: %d %s", w.Code, w.Body.String())
	}
	var a struct {
		Nonce string `json:"nonce"`
		Skip  bool   `json:"skip"`
	}
	if json.Unmarshal(w.Body.Bytes(), &a) != nil || a.Nonce != "n1" {
		t.Fatalf("answer: %s", w.Body.String())
	}
	return a.Skip
}

// enroll plays the step of alice with remember checked, by the browser
// agent.
func enroll(t *testing.T, h http.Handler, agent string) {
	t.Helper()
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login?login_challenge=c", nil))
	token := page.Result().Cookies()[0].Value
	form := url.Values{"login_challenge": {"c"}, "csrf": {token}, "code": {"123456"}, "remember": {"1"}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", agent)
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
}

// The step: the code checked, the form's token required; remember checked
// declares the date to the dispatcher and records the device, which skips
// until then, for the browser that enrolled it.
func TestStepAndCheck(t *testing.T) {
	var accepted map[string]any
	api := emulated(t, "dev-of-alice", &accepted)
	defer api.Close()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	h, err := New(Options{AdminURL: api.URL, Key: testKey, Code: "123456", RememberFor: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for name, form := range map[string]url.Values{
		"no token":   {"login_challenge": {"c"}, "code": {"123456"}},
		"wrong code": {"login_challenge": {"c"}, "code": {"654321"}, "csrf": {strings.Repeat("a", 64)}},
	} {
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: strings.Repeat("a", 64)})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusSeeOther || accepted != nil {
			t.Errorf("%s: %d, accepted %v", name, w.Code, accepted)
		}
	}
	body := `{"version":1,"nonce":"n1","subject":"alice","device":"dev-of-alice","signals":{"user_agent":"Firefox"}}`
	if skips(t, check(h, testKey, now, body)) {
		t.Error("before the enrollment: skip")
	}
	enroll(t, h, "Firefox")
	if ctx, _ := accepted["context"].(map[string]any); accepted["subject"] != "alice" || ctx["x_dispatcher_remember_until"] != "2026-11-17T12:00:00Z" {
		t.Errorf("accept: %v", accepted)
	}
	if !skips(t, check(h, testKey, now, body)) {
		t.Error("enrolled: no skip")
	}
	for name, other := range map[string]string{
		"another subject":   `{"version":1,"nonce":"n1","subject":"bob","device":"dev-of-alice"}`,
		"another device":    `{"version":1,"nonce":"n1","subject":"alice","device":"dev-of-mallory"}`,
		"another browser":   `{"version":1,"nonce":"n1","subject":"alice","device":"dev-of-alice","signals":{"user_agent":"Chrome"}}`,
		"no device":         `{"version":1,"nonce":"n1","subject":"alice","device":""}`,
		"no signal is fine": `{"version":1,"nonce":"n1","subject":"alice","device":"dev-of-alice"}`,
	} {
		if got := skips(t, check(h, testKey, now, other)); got != (name == "no signal is fine") {
			t.Errorf("%s: skip %v", name, got)
		}
	}
	now = now.Add(24 * time.Hour)
	if skips(t, check(h, testKey, now, body)) {
		t.Error("expired: skip")
	}
}

// A request the app cannot trust gets no answer: another key, out of the 5
// minutes, unsigned, another version.
func TestCheckRefused(t *testing.T) {
	now := time.Now()
	h, _ := New(Options{AdminURL: "http://unused", Key: testKey, Code: "1"})
	body := `{"version":1,"nonce":"n1","subject":"alice","device":"d"}`
	for name, w := range map[string]*httptest.ResponseRecorder{
		"another key":   check(h, []byte("fedcba9876543210fedcba9876543210"), now, body),
		"too old":       check(h, testKey, now.Add(-6*time.Minute), body),
		"from the past": check(h, testKey, now.Add(6*time.Minute), body),
		"version 2":     check(h, testKey, now, strings.Replace(body, `"version":1`, `"version":2`, 1)),
	} {
		if w.Code == http.StatusOK || w.Header().Get(headerSignature) != "" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/skip-check", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Error("unsigned: answered")
	}
	if _, err := New(Options{Key: []byte("short")}); err == nil {
		t.Error("a short key")
	}
}

// A revoke needs the form's token: another site's form revokes nothing.
func TestRevokeNeedsTheToken(t *testing.T) {
	var accepted map[string]any
	api := emulated(t, "dev-of-alice", &accepted)
	defer api.Close()
	now := time.Now()
	h, _ := New(Options{AdminURL: api.URL, Key: testKey, Code: "123456", Now: func() time.Time { return now }})
	enroll(t, h, "Firefox")
	form := url.Values{"login_challenge": {"c"}, "id": {"anything"}}
	r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := `{"version":1,"nonce":"n1","subject":"alice","device":"dev-of-alice"}`
	if w.Code != http.StatusForbidden || !skips(t, check(h, testKey, now, body)) {
		t.Errorf("revoke without the token: %d", w.Code)
	}
}

// The page's policy leaves the form's target free: Chromium applies
// form-action to the redirection after the POST, which goes to the
// dispatcher, another origin (R51, Q141).
func TestPagePolicy(t *testing.T) {
	var accepted map[string]any
	api := emulated(t, "dev-of-alice", &accepted)
	defer api.Close()
	h, _ := New(Options{AdminURL: api.URL, Key: testKey, Code: "123456"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?login_challenge=c", nil))
	if csp := w.Header().Get("Content-Security-Policy"); w.Code != http.StatusOK || strings.Contains(csp, "form-action") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("%d, policy %q", w.Code, csp)
	}
}
