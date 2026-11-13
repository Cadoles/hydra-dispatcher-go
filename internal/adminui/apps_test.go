package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
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
	mu      sync.Mutex
	apps    []store.App
	flows   []store.Flow
	stored  map[string]json.RawMessage
	clients []store.APIClient
	scopes  []store.Scope
	// oidc, when set, is the block admin_oidc of the snapshots, its secret in
	// clear, which the table would hold encrypted.
	oidc *store.AdminOIDC
	// debug is the window of debug, nil for none.
	debug *store.DebugWindow
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
		stored: map[string]json.RawMessage{"challenge_ttl": json.RawMessage("600")},
	}
}

func (c *config) Snapshot() *store.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	settings, _, err := store.SettingsOf(c.stored)
	if err != nil {
		panic(err)
	}
	if c.oidc != nil {
		settings.AdminOIDC = *c.oidc
	}
	snap := store.NewSnapshot(slices.Clone(c.apps), slices.Clone(c.flows), settings).WithAPIClients(slices.Clone(c.clients))
	snap.StoredSettings = slices.Sorted(maps.Keys(c.stored))
	snap.Scopes = slices.Clone(c.scopes)
	slices.SortFunc(snap.Scopes, func(a, b store.Scope) int { return strings.Compare(a.Name, b.Name) })
	snap.Debug = c.debug
	return snap
}

// SetDebugWindow writes the window as the store does: its rules, its flow and
// its app known.
func (c *config) SetDebugWindow(_ context.Context, by string, w *store.DebugWindow) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if w != nil {
		if v := domain.Collect(w.Check); v != nil {
			return v
		}
		if w.Flow != "" && !slices.ContainsFunc(c.flows, func(f store.Flow) bool { return f.ID == w.Flow }) {
			return domain.Violations{{Field: "flow", Message: fmt.Sprintf("%q is no flow", w.Flow)}}
		}
		if w.App != "" && !slices.ContainsFunc(c.apps, func(a store.App) bool { return a.ID == w.App }) {
			return domain.Violations{{Field: "app", Message: fmt.Sprintf("%q is no app", w.App)}}
		}
		x := *w
		x.UpdatedBy = by
		w = &x
	}
	c.debug = w
	c.by = append(c.by, by)
	return nil
}

// The catalogue of the scopes as the store writes it: a standard scope
// renamed alone, its row gone when it renames nothing.
func (c *config) putScope(s store.Scope, by string) {
	c.scopes = slices.DeleteFunc(c.scopes, func(x store.Scope) bool { return x.Name == s.Name })
	renames := len(s.Label) > 0 || slices.ContainsFunc(s.Claims, func(x store.ScopeClaim) bool { return len(x.Label) > 0 })
	if _, standard := domain.Standard(s.Name); !standard || renames {
		c.scopes = append(c.scopes, s)
	}
	c.by = append(c.by, by)
}

func (c *config) CreateScope(_ context.Context, by string, s store.Scope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if _, standard := domain.Standard(s.Name); standard {
		return store.ErrStandard
	}
	if v := domain.Collect(s.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(c.scopes, func(x store.Scope) bool { return x.Name == s.Name }) {
		return store.ErrExists
	}
	c.putScope(s, by)
	return nil
}

func (c *config) UpdateScope(_ context.Context, by, name string, change func(*store.Scope) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	_, standard := domain.Standard(name)
	i := slices.IndexFunc(c.scopes, func(x store.Scope) bool { return x.Name == name })
	if i < 0 && !standard {
		return store.ErrNotFound
	}
	s := store.Scope{Name: name}
	if i >= 0 {
		s = c.scopes[i]
		s.Claims = slices.Clone(s.Claims)
	}
	if err := change(&s); err != nil {
		return err
	}
	if s.Name != name {
		return domain.Violations{{Field: "name", Message: "an update cannot change it"}}
	}
	if v := domain.Collect(s.Check); v != nil {
		return v
	}
	c.putScope(s, by)
	return nil
}

func (c *config) DeleteScope(_ context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if _, standard := domain.Standard(name); standard {
		return store.ErrStandard
	}
	i := slices.IndexFunc(c.scopes, func(x store.Scope) bool { return x.Name == name })
	if i < 0 {
		return store.ErrNotFound
	}
	c.scopes = slices.Delete(c.scopes, i, i+1)
	return nil
}

func (c *config) client(id string) (store.APIClient, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := slices.IndexFunc(c.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.APIClient{}, false
	}
	return c.clients[i], true
}

func (c *config) CreateAPIClient(_ context.Context, by string, x store.APIClient) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if v := domain.Collect(x.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(c.clients, func(y store.APIClient) bool { return y.ID == x.ID }) {
		return store.ErrExists
	}
	c.clients, c.by = append(c.clients, x), append(c.by, by)
	return nil
}

func (c *config) UpdateAPIClient(_ context.Context, by, id string, change func(*store.APIClient) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	i := slices.IndexFunc(c.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	x := c.clients[i]
	x.Scopes = slices.Clone(x.Scopes)
	if err := change(&x); err != nil {
		return err
	}
	if v := domain.Collect(x.Check); v != nil {
		return v
	}
	c.clients[i], c.by = x, append(c.by, by)
	return nil
}

func (c *config) DeleteAPIClient(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	i := slices.IndexFunc(c.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	c.clients = slices.Delete(c.clients, i, i+1)
	return nil
}

func (c *config) flow(id string) (store.Flow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := slices.IndexFunc(c.flows, func(f store.Flow) bool { return f.ID == id })
	if i < 0 {
		return store.Flow{}, false
	}
	return c.flows[i], true
}

func (c *config) checkFlow(f store.Flow) domain.Violations {
	return domain.Collect(func(fail domain.Fail) {
		f.Check(fail, func(id string) bool { return slices.ContainsFunc(c.apps, func(a store.App) bool { return a.ID == id }) })
	})
}

func (c *config) CreateFlow(_ context.Context, by string, f store.Flow) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	if v := c.checkFlow(f); v != nil {
		return v
	}
	if slices.ContainsFunc(c.flows, func(x store.Flow) bool { return x.ID == f.ID }) {
		return store.ErrExists
	}
	c.flows, c.by = append(c.flows, f), append(c.by, by)
	return nil
}

func (c *config) UpdateFlow(_ context.Context, by, id string, change func(*store.Flow) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	i := slices.IndexFunc(c.flows, func(f store.Flow) bool { return f.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	f := c.flows[i]
	if err := change(&f); err != nil {
		return err
	}
	if f.ID != id {
		return domain.Violations{{Field: "id", Message: "an update cannot change it"}}
	}
	if v := c.checkFlow(f); v != nil {
		return v
	}
	c.flows[i], c.by = f, append(c.by, by)
	return nil
}

func (c *config) DeleteFlow(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	i := slices.IndexFunc(c.flows, func(f store.Flow) bool { return f.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	c.flows = slices.Delete(c.flows, i, i+1)
	return nil
}

// UpdateSettings writes values over the table, null deleting a row, as the
// store does: the settings refused by their rules write nothing.
func (c *config) UpdateSettings(_ context.Context, by string, values map[string]json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	// The block admin_oidc, its secret in clear, goes to oidc: the table
	// would hold the secret encrypted.
	block := store.DefaultSettings().AdminOIDC
	if c.oidc != nil {
		block = *c.oidc
	}
	fields := map[string]any{"admin_oidc.enabled": &block.Enabled, "admin_oidc.issuer": &block.Issuer, "admin_oidc.client_id": &block.ClientID,
		"admin_oidc.client_secret": &block.ClientSecret, "admin_oidc.scopes": &block.Scopes, "admin_oidc.username_claim": &block.UsernameClaim,
		"admin_oidc.required_acr": &block.RequiredACR, "admin_oidc.auto_create": &block.AutoCreate,
		"admin_oidc.authorization_endpoint": &block.AuthorizationEndpoint, "admin_oidc.token_endpoint": &block.TokenEndpoint, "admin_oidc.jwks_uri": &block.JWKSURI}
	next := maps.Clone(c.stored)
	oidcWritten := false
	for k, v := range values {
		if f, ok := fields[k]; ok {
			if err := json.Unmarshal(v, f); err != nil {
				return domain.Violations{{Field: k, Message: err.Error()}}
			}
			oidcWritten = true
			continue
		}
		if string(v) == "null" {
			delete(next, k)
		} else {
			next[k] = v
		}
	}
	s, _, err := store.SettingsOf(next)
	if err != nil {
		return domain.Violations{{Message: err.Error()}}
	}
	s.AdminOIDC = block
	if v := domain.Collect(s.Check); v != nil {
		return v
	}
	c.stored, c.by = next, append(c.by, by)
	if oidcWritten {
		c.oidc = &block
	}
	return nil
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

var versionRe = regexp.MustCompile(`name="version" value="([^"]*)"`)

// version is the version of the entity of the page at path, as its form
// carries it.
func (b *browser) version(path string) string {
	b.r.t.Helper()
	w := b.do(http.MethodGet, path, nil)
	m := versionRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		b.r.t.Fatalf("no version in %s: %d", path, w.Code)
	}
	return m[1]
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
	form.Set("version", b.version("/admin/apps/otp"))
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
	form.Set("version", b.version("/admin/apps/otp"))
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
	form.Set("version", b.version("/admin/apps/pwd"))
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("to mtls: %d\n%s", w.Code, w.Body)
	}
	a, _ := r.config.app("pwd")
	if a.AuthMode != "mtls" || a.AllowedSources != nil || a.ClientCertFingerprint != strings.Repeat("ab", 32) || a.ReceiveClaims == nil || len(a.ReceiveClaims) != 0 {
		t.Errorf("mtls: %+v", a)
	}
	form.Set("auth_mode", "network")
	form.Set("receive_claims", "email\r\n  name \n\ngroups")
	form.Set("version", b.version("/admin/apps/pwd"))
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
	form.Set("version", b.version("/admin/apps/pwd"))
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

// Two admins on one app: the save over a change is refused once.
func TestAppChanged(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	b := r.browser()
	b.login("alice", password, "")
	form := appValues(b, "")
	form.Set("version", b.version("/admin/apps/pwd"))
	if err := r.config.UpdateApp(context.Background(), "admin:other", "pwd", func(a *store.App) error { a.Method = "theirs"; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `name="method" value="otp"`) {
		t.Fatalf("over theirs: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("pwd"); a.Method != "theirs" {
		t.Errorf("theirs lost: %q", a.Method)
	}
	// The page refused carries the version of now: saved again, the form
	// writes over, knowingly (revue R41).
	w := b.do(http.MethodPost, "/admin/apps/pwd", form)
	m := versionRe.FindStringSubmatch(w.Body.String())
	form.Set("version", m[1])
	form.Set("csrf", b.csrf())
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("again: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("pwd"); a.Method != "otp" {
		t.Errorf("mine: %q", a.Method)
	}
}

// The claims are one per line: a name with a space or a comma, which the
// domain takes, stays whole when the app is saved without a change (revue
// R41).
func TestAppClaimsByLine(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	r.config.apps[0].ReceiveClaims = []string{"given name", "x,y"}
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/apps/pwd", nil).Body.String()
	if !strings.Contains(page, "given name\nx,y</textarea>") {
		t.Fatalf("page:\n%s", page)
	}
	a, _ := r.config.app("pwd")
	f := appFormOf(a)
	form := url.Values{"csrf": {b.csrf()}, "version": {f.Version}, "method": {f.Method}, "login_url": {f.LoginURL}, "consent_url": {f.ConsentURL},
		"auth_mode": {f.AuthMode}, "allowed_sources": {f.AllowedSources}, "receive_claims": {f.Claims}}
	if w := b.do(http.MethodPost, "/admin/apps/pwd", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	if a, _ := r.config.app("pwd"); !slices.Equal(a.ReceiveClaims, []string{"given name", "x,y"}) {
		t.Errorf("claims: %q", a.ReceiveClaims)
	}
}
