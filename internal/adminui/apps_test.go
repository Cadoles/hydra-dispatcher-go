package adminui

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// config is the configuration of the store, its rules those of the domain:
// what the screens read and write.
type config struct {
	mu    sync.Mutex
	apps  []store.App
	flows []store.Flow
	by    []string
	// fail, when set, is the error of the next writes.
	fail error
}

func newConfig() *config {
	return &config{
		apps: []store.App{
			{ID: "pwd", LoginURL: "https://pwd.test/login", ConsentURL: "https://pwd.test/consent", Method: "pwd", AuthMode: "network",
				AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.0.6.21/32")}},
			{ID: "spare", LoginURL: "https://spare.test/login", ConsentURL: "https://spare.test/consent", Method: "otp", AuthMode: "network",
				ReceiveClaims: []string{}},
		},
		flows: []store.Flow{{ID: "simple", Title: map[string]string{"en": "Simple"}, Description: map[string]string{"en": "d"}, Enabled: true,
			Steps: []store.Step{{AppID: "pwd", Position: 1, SubjectCheck: "none"}}}},
	}
}

func (c *config) Snapshot() *store.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return store.NewSnapshot(slices.Clone(c.apps), slices.Clone(c.flows), store.DefaultSettings())
}

func (c *config) app(id string) (store.App, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := slices.IndexFunc(c.apps, func(a store.App) bool { return a.ID == id })
	if i < 0 {
		return store.App{}, false
	}
	return c.apps[i], true
}

func (c *config) CreateApp(_ context.Context, by string, a store.App) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if v := domain.Collect(a.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(c.apps, func(x store.App) bool { return x.ID == a.ID }) {
		return store.ErrExists
	}
	c.apps, c.by = append(c.apps, a), append(c.by, by)
	return nil
}

func (c *config) UpdateApp(_ context.Context, by, id string, change func(*store.App) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	i := slices.IndexFunc(c.apps, func(a store.App) bool { return a.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	a := c.apps[i]
	if err := change(&a); err != nil {
		return err
	}
	if a.ID != id {
		return domain.Violations{{Field: "id", Message: "an update cannot change it"}}
	}
	if v := domain.Collect(a.Check); v != nil {
		return v
	}
	c.apps[i], c.by = a, append(c.by, by)
	return nil
}

func (c *config) DeleteApp(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	var flows []string
	for _, f := range c.flows {
		if slices.ContainsFunc(f.Steps, func(s store.Step) bool { return s.AppID == id }) {
			flows = append(flows, f.ID)
		}
	}
	if flows != nil {
		return &store.ReferencedError{App: id, Flows: flows}
	}
	i := slices.IndexFunc(c.apps, func(a store.App) bool { return a.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	c.apps = slices.Delete(c.apps, i, i+1)
	return nil
}

// appValues is the form of a new app, valid.
func appValues(b *browser, id string) url.Values {
	b.r.t.Helper()
	return url.Values{"csrf": {b.csrf()}, "id": {id}, "method": {"otp"}, "login_url": {"https://otp.test/login"},
		"consent_url": {"https://otp.test/consent"}, "auth_mode": {"network"}, "allowed_sources": {"10.0.6.23, 10.1.0.0/16"},
		"receive_all_claims": {"1"}}
}

// csrf is the token of the forms of the session, read from a page.
func (b *browser) csrf() string {
	b.r.t.Helper()
	return token(b.r.t, b.do(http.MethodGet, "/admin", nil))
}

func (r *rig) wrote() []string {
	var w []string
	for _, a := range r.audited() {
		if strings.HasPrefix(a, "write ") {
			w = append(w, a)
		}
	}
	return w
}

func TestApps(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	list := b.do(http.MethodGet, "/admin/apps", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `<a href="/admin/apps/pwd">pwd</a>`) ||
		!strings.Contains(list.Body.String(), "<td>simple</td>") || !strings.Contains(list.Body.String(), "no flow") ||
		!strings.Contains(list.Body.String(), `href="/admin/apps/_new"`) || !strings.Contains(list.Body.String(), `aria-current="page">Apps`) {
		t.Fatalf("list: %d\n%s", list.Code, list.Body)
	}
	if w := b.do(http.MethodGet, "/admin/apps/_new", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="id"`) {
		t.Fatalf("new: %d", w.Code)
	}

	w := b.do(http.MethodPost, "/admin/apps", appValues(b, "otp"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/apps/otp?done=created" {
		t.Fatalf("create: %d %s\n%s", w.Code, w.Header().Get("Location"), w.Body)
	}
	a, ok := r.config.app("otp")
	if !ok || a.Method != "otp" || len(a.AllowedSources) != 2 || a.AllowedSources[0].String() != "10.0.6.23/32" || a.ReceiveClaims != nil || a.LogoutURL != "" {
		t.Errorf("created: %+v", a)
	}
	page := b.do(http.MethodGet, "/admin/apps/otp?done=created", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Created.") || !strings.Contains(page.Body.String(), "A step of no flow.") ||
		!strings.Contains(page.Body.String(), "10.0.6.23/32\n10.1.0.0/16</textarea>") {
		t.Errorf("page: %d\n%s", page.Code, page.Body)
	}

	form := appValues(b, "")
	form.Del("id")
	form.Set("method", "otp2")
	form.Set("allowed_sources", "10.0.6.23/32\n10.1.0.0/16")
	w = b.do(http.MethodPost, "/admin/apps/otp", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/apps/otp?done=saved" {
		t.Fatalf("update: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("otp"); a.Method != "otp2" {
		t.Errorf("updated: %+v", a)
	}
	if got, want := r.wrote(), []string{
		"write alice apps otp create id,login_url,consent_url,method,auth_mode,allowed_sources",
		"write alice apps otp update method",
	}; !slices.Equal(got, want) {
		t.Errorf("audit:\n got %q\nwant %q", got, want)
	}
	if !slices.Equal(r.config.by, []string{"admin:alice", "admin:alice"}) {
		t.Errorf("updated_by: %q", r.config.by)
	}
	// An id in the form of an update names no other app: the path does.
	form.Set("id", "pwd")
	if w := b.do(http.MethodPost, "/admin/apps/otp", form); w.Code != http.StatusSeeOther {
		t.Errorf("an id in the form: %d", w.Code)
	}
	if a, _ := r.config.app("pwd"); a.Method != "pwd" {
		t.Errorf("another app written: %+v", a)
	}
}

// A form refused is shown again, its values as typed, each violation by its
// field; nothing is written.
func TestAppRefused(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := appValues(b, "otp")
	form.Set("login_url", "not a url <b>")
	w := b.do(http.MethodPost, "/admin/apps", form)
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `value="not a url &lt;b&gt;" required aria-invalid="true">`) ||
		!strings.Contains(body, `value="otp" required maxlength="64">`) || strings.Contains(body, "<b>") {
		t.Errorf("a bad URL: %d\n%s", w.Code, body)
	}
	form = appValues(b, "otp")
	form.Set("allowed_sources", "10.0.6.23 nowhere")
	if w := b.do(http.MethodPost, "/admin/apps", form); w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), `<small>&#34;nowhere&#34; is neither a CIDR nor an IP address.</small>`) {
		t.Errorf("a bad source: %d\n%s", w.Code, w.Body)
	}
	if w := b.do(http.MethodPost, "/admin/apps", appValues(b, "pwd")); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "is taken") {
		t.Errorf("an id taken: %d\n%s", w.Code, w.Body)
	}
	if w := b.do(http.MethodPost, "/admin/apps", appValues(b, "-bad")); w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), `value="-bad" required maxlength="128" aria-invalid="true">`) {
		t.Errorf("a bad id: %d\n%s", w.Code, w.Body)
	}
	// What refuses the configuration this write leaves, by none of the
	// fields of the form, is said above it, its field named.
	r.config.fail = &store.RefusedError{Err: errors.New("setting login_accept_webhook_url: is in http")}
	if w := b.do(http.MethodPost, "/admin/apps", appValues(b, "otp")); w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), `<p role="alert"><strong>login_accept_webhook_url: is in http</strong></p>`) {
		t.Errorf("a configuration refused: %d\n%s", w.Code, w.Body)
	}
	// A failure of the store: its cause in the log, never on the page.
	r.config.fail = errors.New("dial tcp 10.0.0.5:5432: password authentication failed for user dispatcher")
	if w := b.do(http.MethodPost, "/admin/apps", appValues(b, "otp")); w.Code != http.StatusServiceUnavailable ||
		strings.Contains(w.Body.String(), "5432") {
		t.Errorf("the store failing: %d\n%s", w.Code, w.Body)
	}
	r.config.fail = nil
	if _, ok := r.config.app("otp"); ok || len(r.wrote()) != 0 {
		t.Errorf("written: %v", r.wrote())
	}
	if w := b.do(http.MethodPost, "/admin/apps/nothing", appValues(b, "")); w.Code != http.StatusNotFound {
		t.Errorf("an app that is not: %d", w.Code)
	}
}

// The field of the other mode is left out; a fingerprint takes the form the
// emulated API compares; the claims, every one, none or a list.
func TestAppModes(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	fp := strings.Repeat("AB:", 31) + "AB"
	form := appValues(b, "")
	form.Set("auth_mode", "mtls")
	form.Set("client_cert_fingerprint", fp)
	form.Del("receive_all_claims")
	form.Set("receive_claims", "")
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("to mtls: %d\n%s", w.Code, w.Body)
	}
	a, _ := r.config.app("pwd")
	if a.AuthMode != "mtls" || a.AllowedSources != nil || a.ClientCertFingerprint != strings.Repeat("ab", 32) || a.ReceiveClaims == nil || len(a.ReceiveClaims) != 0 {
		t.Errorf("mtls: %+v", a)
	}
	form.Set("auth_mode", "network")
	form.Set("receive_claims", "email\nname, groups")
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("to network: %d\n%s", w.Code, w.Body)
	}
	a, _ = r.config.app("pwd")
	if a.ClientCertFingerprint != "" || len(a.AllowedSources) != 2 || !slices.Equal(a.ReceiveClaims, []string{"email", "name", "groups"}) {
		t.Errorf("network: %+v", a)
	}
	if got := r.wrote(); !slices.Equal(got, []string{
		"write alice apps pwd update login_url,consent_url,method,auth_mode,allowed_sources,client_cert_fingerprint,receive_claims",
		"write alice apps pwd update auth_mode,allowed_sources,client_cert_fingerprint,receive_claims",
	}) {
		t.Errorf("audit: %q", got)
	}
	form.Set("auth_mode", "carrier pigeon")
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "is not network or mtls") {
		t.Errorf("an unknown mode: %d\n%s", w.Code, w.Body)
	}
}

func TestAppDelete(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	w := b.do(http.MethodGet, "/admin/apps/pwd/delete", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "It is a step of simple: take it out of them first.") || strings.Contains(w.Body.String(), `action="/admin/apps/pwd/delete"`) {
		t.Errorf("a step, its page: %d\n%s", w.Code, w.Body)
	}
	if w := b.do(http.MethodPost, "/admin/apps/pwd/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "It is a step of the flows simple: take it out of them first.") {
		t.Errorf("a step, deleted: %d\n%s", w.Code, w.Body)
	}
	if w := b.do(http.MethodGet, "/admin/apps/spare/delete", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/admin/apps/spare/delete"`) {
		t.Errorf("free, its page: %d\n%s", w.Code, w.Body)
	}
	w = b.do(http.MethodPost, "/admin/apps/spare/delete", url.Values{"csrf": {b.csrf()}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/apps?done=deleted" {
		t.Fatalf("free, deleted: %d\n%s", w.Code, w.Body)
	}
	if _, ok := r.config.app("spare"); ok {
		t.Error("spare is still there")
	}
	if got := r.wrote(); !slices.Equal(got, []string{"write alice apps spare delete "}) {
		t.Errorf("audit: %q", got)
	}
	if w := b.do(http.MethodGet, "/admin/apps?done=deleted", nil); !strings.Contains(w.Body.String(), "Deleted.") {
		t.Errorf("notice: %s", w.Body)
	}
	if w := b.do(http.MethodGet, "/admin/apps?done=%3Cscript%3E", nil); strings.Contains(w.Body.String(), `role="status"`) {
		t.Errorf("a notice of the address: %s", w.Body)
	}
}

// A viewer reads the apps, their forms without a button, and writes none.
func TestAppViewer(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("victor", password, "")
	list := b.do(http.MethodGet, "/admin/apps", nil)
	page := b.do(http.MethodGet, "/admin/apps/pwd", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "_new") || page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "<fieldset disabled>") || strings.Contains(page.Body.String(), `type="submit">Save`) ||
		strings.Contains(page.Body.String(), "/delete") {
		t.Errorf("reads: %d %d\n%s", list.Code, page.Code, page.Body)
	}
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodGet, "/admin/apps/_new"}, {http.MethodPost, "/admin/apps"}, {http.MethodPost, "/admin/apps/pwd"},
		{http.MethodGet, "/admin/apps/spare/delete"}, {http.MethodPost, "/admin/apps/spare/delete"},
	} {
		var form url.Values
		if c.method == http.MethodPost {
			form = appValues(b, "otp")
		}
		if w := b.do(c.method, c.path, form); w.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
	if len(r.config.by) != 0 || len(r.wrote()) != 0 {
		t.Errorf("written: %q", r.config.by)
	}
	// Without a writer, an admin reads alone.
	r.ui.o.Writer = nil
	admin := r.browser()
	admin.login("alice", password, "")
	if w := admin.do(http.MethodGet, "/admin/apps/pwd", nil); !strings.Contains(w.Body.String(), "<fieldset disabled>") {
		t.Errorf("no writer: %s", w.Body)
	}
}

// A form of another site, or without the token of the session, writes
// nothing.
func TestAppForged(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := appValues(b, "otp")
	form.Set("csrf", "x")
	if w := b.do(http.MethodPost, "/admin/apps", form); w.Code != http.StatusForbidden {
		t.Errorf("another token: %d", w.Code)
	}
	form = appValues(b, "otp")
	b.headers["Sec-Fetch-Site"] = "cross-site"
	if w := b.do(http.MethodPost, "/admin/apps", form); w.Code != http.StatusForbidden {
		t.Errorf("another site: %d", w.Code)
	}
	if len(r.config.by) != 0 {
		t.Errorf("written: %q", r.config.by)
	}
}

func TestAuthor(t *testing.T) {
	if got := author("alice"); got != "admin:alice" {
		t.Errorf("alice: %q", got)
	}
	if got := author(strings.Repeat("é", 180)); len([]rune(got)) != maxAuthor || !strings.HasPrefix(got, "admin:é") {
		t.Errorf("a long name: %d", len([]rune(got)))
	}
}
