package adminui

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"github.com/Cadoles/hydra-dispatcher-go/internal/seal"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// wantCSP is the policy of the pages, written out.
const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; " +
	"connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"

const password = "correct horse battery"

// hashOf is a hash of cost 4: the tests compute many.
func hashOf(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword(domain.BcryptInput(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// accounts are the accounts of the store, on the clock of the rig.
type accounts struct {
	mu    sync.Mutex
	users map[string]store.AdminUser
	now   func() time.Time
	reads atomic.Int32
	fail  error
	// hold, when set, holds the reads of an account until it is closed or
	// their context ends: a database that no longer answers.
	hold chan struct{}
	// endFail, when set, is the error of EndSessions.
	endFail error
}

func (a *accounts) Admin(ctx context.Context, username string) (store.AdminUser, bool, error) {
	a.reads.Add(1)
	if a.hold != nil {
		select {
		case <-a.hold:
		case <-ctx.Done():
			return store.AdminUser{}, false, ctx.Err()
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return store.AdminUser{}, false, a.fail
	}
	u, ok := a.users[username]
	return u, ok, nil
}

func (a *accounts) AdminBySubject(_ context.Context, sub string) (store.AdminUser, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return store.AdminUser{}, false, a.fail
	}
	for _, u := range a.users {
		if sub != "" && u.OIDCSub == sub {
			return u, true, nil
		}
	}
	return store.AdminUser{}, false, nil
}

func (a *accounts) EndSessions(_ context.Context, username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.endFail != nil {
		return a.endFail
	}
	u, ok := a.users[username]
	if !ok {
		return store.ErrNotFound
	}
	u.SessionsValidAfter = a.now()
	a.users[username] = u
	return nil
}

func (a *accounts) Admins(context.Context) ([]store.AdminUser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return nil, a.fail
	}
	return slices.SortedFunc(maps.Values(a.users), func(x, y store.AdminUser) int { return strings.Compare(x.Username, y.Username) }), nil
}

func (a *accounts) CreateAdmin(_ context.Context, u store.AdminUser) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v := domain.Collect(u.Check); v != nil {
		return v
	}
	if _, ok := a.users[u.Username]; ok {
		return store.ErrExists
	}
	for _, other := range a.users {
		if u.OIDCSub != "" && other.OIDCSub == u.OIDCSub {
			return domain.Violations{{Field: "oidc_sub", Message: "is the subject of the account " + other.Username}}
		}
	}
	u.SessionsValidAfter = a.now() // as the store: its sessions after its creation
	a.users[u.Username] = u
	return nil
}

// others counts the accounts of the role admin but username.
func (a *accounts) others(username string) int {
	n := 0
	for _, u := range a.users {
		if u.Role == domain.RoleAdmin && u.Username != username {
			n++
		}
	}
	return n
}

// UpdateAdmin is the store's: what changes checked, the last admin kept,
// the sessions ended by a password or a role changed.
func (a *accounts) UpdateAdmin(_ context.Context, username string, change func(*store.AdminUser) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	was, ok := a.users[username]
	if !ok {
		return store.ErrNotFound
	}
	u := was
	if err := change(&u); err != nil {
		return err
	}
	if v := domain.Collect(func(fail domain.Fail) { u.CheckChanged(fail, was) }); v != nil {
		return v
	}
	if was.Role == domain.RoleAdmin && u.Role != domain.RoleAdmin && a.others(username) == 0 {
		return store.ErrLastAdmin
	}
	if u.PasswordHash != was.PasswordHash || u.Role != was.Role {
		u.SessionsValidAfter = a.now()
	}
	a.users[username] = u
	return nil
}

func (a *accounts) DeleteAdmin(_ context.Context, username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[username]
	if !ok {
		return store.ErrNotFound
	}
	if u.Role == domain.RoleAdmin && a.others(username) == 0 {
		return store.ErrLastAdmin
	}
	delete(a.users, username)
	return nil
}

func (a *accounts) set(u store.AdminUser) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[u.Username] = u
}

func (a *accounts) remove(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, username)
}

// rig is the admin UI behind RealIP, a clock, and what its hooks heard.
type rig struct {
	t        *testing.T
	ui       *UI
	handler  http.Handler
	accounts *accounts
	config   *config
	mu       sync.Mutex
	now      time.Time
	audit    []string
	refused  atomic.Int32
	limited  atomic.Int32
}

func newRig(t *testing.T, baseURL string) *rig {
	t.Helper()
	r := &rig{t: t, now: time.Unix(1_800_000_000, 0)}
	r.accounts = &accounts{users: map[string]store.AdminUser{}, now: r.clock}
	r.accounts.set(store.AdminUser{Username: "alice", PasswordHash: hashOf(t, password), Role: domain.RoleAdmin})
	r.accounts.set(store.AdminUser{Username: "victor", PasswordHash: hashOf(t, password), Role: domain.RoleViewer})
	r.accounts.set(store.AdminUser{Username: "olga", OIDCSub: "sub-1", Role: domain.RoleAdmin})
	r.config = newConfig()
	keys, err := seal.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ui, err := New(Options{
		Enabled: true, AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Accounts: r.accounts, Keys: keys,
		BaseURL: baseURL, CookiePath: "/", IdleTimeout: 30 * time.Minute, MaxAge: 8 * time.Hour, ReauthWindow: 5 * time.Minute,
		LoginsPerMinute: 10, PasswordLogin: true, Version: "test",
		Refused:     func(context.Context) { r.refused.Add(1) },
		RateLimited: func(context.Context) { r.limited.Add(1) },
		Login: func(_ context.Context, user, method, result, reason string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.audit = append(r.audit, strings.TrimSpace(strings.Join([]string{"login", user, method, result, reason}, " ")))
		},
		Logout: func(_ context.Context, user, result string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.audit = append(r.audit, "logout "+user+" "+result)
		},
		Dashboard: func(context.Context) Dashboard {
			return Dashboard{Version: "test", Instance: "i1", Dependencies: []Dependency{{Name: "database", OK: true}}, Apps: 3, Flows: 2, FlowsEnabled: 1}
		},
		Config: r.config, Writer: r.config, Scopes: []string{"admin:apps", "admin:flows", "admin:clients", "admin:settings", "admin:read"},
		LogLevel: "info", DebugMaxDuration: time.Hour,
		Wrote: func(_ context.Context, user, resource, id, action string, fields []string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.audit = append(r.audit, strings.Join([]string{"write", user, resource, id, action, strings.Join(fields, ",")}, " "))
		},
		Now: r.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Routes a later lot adds, for the tests of the roles and of the
	// re-authentication.
	ok := func(w http.ResponseWriter, _ *http.Request, s *current) {
		_, _ = w.Write([]byte("done by " + s.account.Username))
	}
	ui.mux.Handle("GET /admin/test/admin", ui.authed(adminRole, ok))
	ui.mux.Handle("GET /admin/test/sensitive", ui.authed(adminRole, ui.fresh(ok)))
	ui.mux.Handle("POST /admin/test/sensitive", ui.authed(adminRole, ui.fresh(ok)))
	mux := http.NewServeMux()
	ui.Register(mux)
	r.ui, r.handler = ui, httpx.Chain(mux, httpx.RealIP(nil))
	return r
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = r.now.Add(d)
}

func (r *rig) audited() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.audit...)
}

// browser keeps the cookies the admin sets, as a browser would, and sends
// them back.
type browser struct {
	r       *rig
	from    string
	cookies map[string]*http.Cookie
	headers map[string]string
}

func (r *rig) browser() *browser {
	return &browser{r: r, from: "10.1.2.3:1", cookies: map[string]*http.Cookie{}, headers: map[string]string{"Sec-Fetch-Site": "same-origin"}}
}

func (b *browser) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = b.from
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.r.handler.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

var tokenRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// token is the token of the form in a page.
func token(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := tokenRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no token in %d:\n%s", w.Code, w.Body)
	}
	return m[1]
}

// login opens the form and posts it; it gives the answer of the post.
func (b *browser) login(user, secret, next string) *httptest.ResponseRecorder {
	b.r.t.Helper()
	form := b.do(http.MethodGet, "/admin/login", nil)
	return b.do(http.MethodPost, "/admin/login", url.Values{"csrf": {token(b.r.t, form)}, "username": {user}, "password": {secret}, "next": {next}})
}

func TestDisabled(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.ui.o.Enabled = false
	for _, path := range []string{"/admin", "/admin/login", "/admin/static/pico.css"} {
		if w := r.browser().do(http.MethodGet, path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}

func TestSurface(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	w := b.do(http.MethodGet, "/admin/login", nil)
	h := w.Header()
	if w.Code != http.StatusOK || h.Get("Content-Security-Policy") != wantCSP || h.Get("Cache-Control") != "no-store" ||
		h.Get("Referrer-Policy") != "same-origin" || !strings.Contains(w.Body.String(), `<link rel="stylesheet" href="/admin/static/pico.css?v=`) {
		t.Errorf("login page: %d %v", w.Code, h)
	}
	css := b.do(http.MethodGet, "/admin/static/pico.css", nil)
	if css.Code != http.StatusOK || css.Header().Get("Content-Type") != "text/css; charset=utf-8" || css.Header().Get("ETag") == "" ||
		!strings.Contains(css.Body.String(), "Pico CSS") {
		t.Fatalf("sheet: %d %v", css.Code, css.Header())
	}
	b.headers["If-None-Match"] = css.Header().Get("ETag")
	if again := b.do(http.MethodGet, "/admin/static/pico.css", nil); again.Code != http.StatusNotModified {
		t.Errorf("sheet again: %d", again.Code)
	}
	delete(b.headers, "If-None-Match")
	if w := b.do(http.MethodGet, "/admin/nothing", nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown page: %d", w.Code)
	}
	outside := r.browser()
	outside.from = "203.0.113.7:1"
	if w := outside.do(http.MethodGet, "/admin/login", nil); w.Code != http.StatusForbidden || r.refused.Load() != 1 {
		t.Errorf("outside the allowlist: %d, refused %d", w.Code, r.refused.Load())
	}
}

func TestLogin(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	w := b.do(http.MethodGet, "/admin", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login?next=%2Fadmin" {
		t.Fatalf("without a session: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = b.login("alice", password, "/admin")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin" {
		t.Fatalf("login: %d %s\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	c := b.cookies[sessionCookie]
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure || c.MaxAge != int((8*time.Hour)/time.Second) {
		t.Fatalf("session cookie: %+v", c)
	}
	if b.cookies[loginCookie] != nil {
		t.Error("the cookie of the login kept")
	}
	w = b.do(http.MethodGet, "/admin", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<a href="/admin/account">alice</a> <small>(admin)</small>`) || !strings.Contains(w.Body.String(), "1 of 2") {
		t.Errorf("dashboard: %d\n%s", w.Code, w.Body)
	}
	if got := r.audited(); len(got) != 1 || got[0] != "login alice password granted" {
		t.Errorf("audit: %q", got)
	}
	// Logged in, the form of the login goes where it was going.
	if w := b.do(http.MethodGet, "/admin/login?next=/admin", nil); w.Code != http.StatusSeeOther {
		t.Errorf("the login again: %d", w.Code)
	}
}

// A refused login says nothing of which accounts exist: one message, one
// bcrypt, and at the audit the name of an account alone.
func TestLoginRefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	var compared atomic.Int32
	saved := secretMatches
	secretMatches = func(hash, secret string) bool { compared.Add(1); return saved(hash, secret) }
	t.Cleanup(func() { secretMatches = saved })
	for _, tt := range []struct{ user, secret, audited string }{
		{"alice", "wrong password!", "login alice password refused invalid_credentials"},
		{"victor typed his password", password, "login (unknown) password refused invalid_credentials"},
		{"olga", password, "login olga password refused invalid_credentials"}, // no password: an account of the provider
		{"a\x00b", password, "login (unknown) password refused invalid_credentials"},
	} {
		before, reads := compared.Load(), r.accounts.reads.Load()
		b := r.browser()
		w := b.login(tt.user, tt.secret, "")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Invalid name or password.") || b.cookies[sessionCookie] != nil {
			t.Errorf("%q: %d\n%s", tt.user, w.Code, w.Body)
		}
		if compared.Load() != before+1 {
			t.Errorf("%q: %d bcrypts", tt.user, compared.Load()-before)
		}
		if got := r.audited(); got[len(got)-1] != tt.audited {
			t.Errorf("%q: audit %q", tt.user, got[len(got)-1])
		}
		if tt.user == "a\x00b" && r.accounts.reads.Load() != reads {
			t.Error("a name no account may have read from the store")
		}
	}
	for _, line := range r.audited() {
		if strings.Contains(line, "typed his password") {
			t.Errorf("a name typed at the audit: %q", line)
		}
	}
}

// The form of the login is the dispatcher's own: its token, still valid, and
// what the browser says of where the post comes from (Durcissements, point 5).
func TestLoginForged(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	post := func(b *browser, csrf string) int {
		return b.do(http.MethodPost, "/admin/login", url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {password}}).Code
	}
	b := r.browser()
	if code := post(b, "forged"); code != http.StatusForbidden {
		t.Errorf("without the form: %d", code)
	}
	b.do(http.MethodGet, "/admin/login", nil) // the form, its token in its cookie
	if code := post(b, "another"); code != http.StatusForbidden {
		t.Errorf("another token: %d", code)
	}
	tok := token(t, b.do(http.MethodGet, "/admin/login", nil))
	b.headers["Origin"] = "https://evil.test"
	if code := post(b, tok); code != http.StatusForbidden {
		t.Errorf("another origin: %d", code)
	}
	delete(b.headers, "Origin")
	b.headers["Sec-Fetch-Site"] = "cross-site"
	tok = token(t, b.do(http.MethodGet, "/admin/login", nil))
	if code := post(b, tok); code != http.StatusForbidden {
		t.Errorf("cross-site: %d", code)
	}
	b.headers["Sec-Fetch-Site"] = "same-origin"
	tok = token(t, b.do(http.MethodGet, "/admin/login", nil))
	r.advance(loginTTL + time.Second)
	if code := post(b, tok); code != http.StatusForbidden {
		t.Errorf("a form too old: %d", code)
	}
	tok = token(t, b.do(http.MethodGet, "/admin/login", nil))
	if code := post(b, tok); code != http.StatusSeeOther {
		t.Errorf("the form itself: %d", code)
	}
}

func TestLoginLimit(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	for i := range 10 {
		if w := b.login("alice", "wrong password!", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, w.Code)
		}
	}
	w := b.login("alice", password, "")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || r.limited.Load() != 1 {
		t.Errorf("the 11th: %d %v, limited %d", w.Code, w.Header(), r.limited.Load())
	}
	other := r.browser()
	other.from = "10.9.9.9:1"
	if w := other.login("alice", password, ""); w.Code != http.StatusSeeOther {
		t.Errorf("another address: %d", w.Code)
	}
	r.advance(2 * time.Minute)
	if w := b.login("alice", password, ""); w.Code != http.StatusSeeOther {
		t.Errorf("after the window: %d", w.Code)
	}
}

// Q120: the session ends with its inactivity, its age, its account deleted,
// or its sessions ended elsewhere; the role is the account's of the moment.
func TestSession(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	loggedIn := func() *browser {
		b := r.browser()
		if w := b.login("alice", password, ""); w.Code != http.StatusSeeOther {
			t.Fatalf("login: %d", w.Code)
		}
		return b
	}
	on := func(b *browser) bool { return b.do(http.MethodGet, "/admin", nil).Code == http.StatusOK }

	b := loggedIn()
	r.advance(29 * time.Minute)
	if !on(b) {
		t.Fatal("29 minutes idle")
	}
	r.advance(31 * time.Minute)
	if on(b) || b.cookies[sessionCookie] != nil {
		t.Error("31 minutes idle: still on, or the cookie kept")
	}

	b = loggedIn()
	for range 24 { // a request each 20 minutes: never idle, 8 hours old at last
		r.advance(20 * time.Minute)
		if !on(b) {
			t.Fatalf("at %v", r.clock())
		}
	}
	r.advance(20 * time.Minute)
	if on(b) {
		t.Error("over 8 hours")
	}

	b = loggedIn()
	victor := r.accounts.users["alice"]
	victor.Role = domain.RoleViewer
	r.accounts.set(victor)
	if w := b.do(http.MethodGet, "/admin/test/admin", nil); w.Code != http.StatusForbidden {
		t.Errorf("the role taken: %d", w.Code)
	}
	victor.Role = domain.RoleAdmin
	r.accounts.set(victor)

	elsewhere := loggedIn()
	r.advance(time.Second)
	if err := r.accounts.EndSessions(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if on(b) || on(elsewhere) {
		t.Error("the sessions ended elsewhere")
	}

	b = loggedIn()
	r.accounts.remove("alice")
	if on(b) {
		t.Error("the account deleted")
	}

	r.accounts.set(store.AdminUser{Username: "alice", PasswordHash: hashOf(t, password), Role: domain.RoleAdmin})
	b = loggedIn()
	c := *b.cookies[sessionCookie]
	// A character of the middle, whose 6 bits all count: the last ones of
	// base64 have unused bits, and "AA" in place of the last two was at
	// times the same bytes (a failure in some hundreds of runs).
	mid, flip := len(c.Value)/2, byte('A')
	if c.Value[mid] == 'A' {
		flip = 'B'
	}
	c.Value = c.Value[:mid] + string(flip) + c.Value[mid+1:]
	b.cookies[sessionCookie] = &c
	if on(b) {
		t.Error("a cookie changed")
	}

	b = loggedIn()
	r.accounts.fail = errors.New("the database does not answer")
	if w := b.do(http.MethodGet, "/admin", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("the accounts unreadable: %d", w.Code)
	}
	r.accounts.fail = nil
}

func TestLogout(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin", nil)
	old := *b.cookies[sessionCookie]
	if w := b.do(http.MethodPost, "/admin/logout", url.Values{"csrf": {"forged"}}); w.Code != http.StatusForbidden {
		t.Errorf("without the token: %d", w.Code)
	}
	r.advance(time.Second)
	w := b.do(http.MethodPost, "/admin/logout", url.Values{"csrf": {token(t, page)}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login" || b.cookies[sessionCookie] != nil {
		t.Fatalf("logout: %d %v", w.Code, w.Header())
	}
	if got := r.audited(); got[len(got)-1] != "logout alice ended" {
		t.Errorf("audit: %q", got)
	}
	// The cookie of before, kept by a thief: the sessions of the account
	// ended with the logout.
	b.cookies[sessionCookie] = &old
	if w := b.do(http.MethodGet, "/admin", nil); w.Code != http.StatusSeeOther {
		t.Errorf("the old cookie: %d", w.Code)
	}
}

func TestReauth(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	if w := b.do(http.MethodGet, "/admin/test/sensitive", nil); w.Code != http.StatusOK {
		t.Fatalf("fresh: %d", w.Code)
	}
	r.advance(6 * time.Minute)
	w := b.do(http.MethodGet, "/admin/test/sensitive", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/reauth?next=%2Fadmin%2Ftest%2Fsensitive" {
		t.Fatalf("stale: %d %s", w.Code, w.Header().Get("Location"))
	}
	form := b.do(http.MethodGet, w.Header().Get("Location"), nil)
	if p := b.do(http.MethodPost, "/admin/test/sensitive", url.Values{"csrf": {token(t, form)}}); p.Code != http.StatusForbidden {
		t.Errorf("a POST stale: %d", p.Code)
	}
	if bad := b.do(http.MethodPost, "/admin/reauth", url.Values{"csrf": {token(t, form)}, "password": {"wrong password!"}, "next": {"/admin/test/sensitive"}}); bad.Code != http.StatusUnauthorized {
		t.Errorf("a wrong password: %d", bad.Code)
	}
	ok := b.do(http.MethodPost, "/admin/reauth", url.Values{"csrf": {token(t, form)}, "password": {password}, "next": {"/admin/test/sensitive"}})
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != "/admin/test/sensitive" {
		t.Fatalf("reauth: %d %s", ok.Code, ok.Header().Get("Location"))
	}
	if w := b.do(http.MethodGet, "/admin/test/sensitive", nil); w.Code != http.StatusOK || w.Body.String() != "done by alice" {
		t.Errorf("after the reauth: %d %s", w.Code, w.Body)
	}
}

func TestRoles(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	viewer := r.browser()
	viewer.login("victor", password, "")
	if w := viewer.do(http.MethodGet, "/admin", nil); w.Code != http.StatusOK {
		t.Errorf("a viewer, the dashboard: %d", w.Code)
	}
	if w := viewer.do(http.MethodGet, "/admin/test/admin", nil); w.Code != http.StatusForbidden {
		t.Errorf("a viewer, a page of an admin: %d", w.Code)
	}
	admin := r.browser()
	admin.login("alice", password, "")
	if w := admin.do(http.MethodGet, "/admin/test/admin", nil); w.Code != http.StatusOK {
		t.Errorf("an admin: %d", w.Code)
	}
}

// After a login, a page of the admin only: never another site.
func TestNext(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	for raw, want := range map[string]string{
		"":                        "/admin",
		"/admin/apps?page=2":      "/admin/apps?page=2",
		"/admin":                  "/admin",
		"//evil.test/admin":       "/admin",
		"https://evil.test/admin": "/admin",
		"/adminx":                 "/admin",
		"/admin/login":            "/admin",
		"/admin/logout":           "/admin",
		"/\\evil.test":            "/admin",
		"javascript:alert(1)":     "/admin",
		"/front":                  "/admin",
	} {
		if got := r.ui.next(raw); got != want {
			t.Errorf("next(%q) = %q, want %q", raw, got, want)
		}
	}
}

// In HTTPS with the cookies at /, they are Secure and __Host-; below a path,
// the links of the admin take it.
func TestSecureAndPath(t *testing.T) {
	r := newRig(t, "https://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	c := b.cookies["__Host-"+sessionCookie]
	if c == nil || !c.Secure || c.Path != "/" {
		t.Errorf("cookies: %v", b.cookies)
	}
	r = newRig(t, "http://proxy.test/dispatcher")
	b = r.browser()
	w := b.do(http.MethodGet, "/admin", nil)
	if w.Header().Get("Location") != "/dispatcher/admin/login?next=%2Fdispatcher%2Fadmin" {
		t.Errorf("below a path: %s", w.Header().Get("Location"))
	}
	if w := b.do(http.MethodGet, "/admin/login", nil); !strings.Contains(w.Body.String(), `action="/dispatcher/admin/login"`) {
		t.Errorf("the form below a path:\n%s", w.Body)
	}
}
