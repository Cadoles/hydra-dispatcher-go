package admin

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// fakeWriter writes as store.Postgres does, its rules and its errors, in a
// snapshot it publishes at each write.
type fakeWriter struct {
	mu       sync.Mutex
	config   *snapshots
	apps     []store.App
	flows    []store.Flow
	clients  []store.APIClient
	scopes   []store.Scope
	settings map[string]json.RawMessage // the last UpdateSettings
	debug    *store.DebugWindow
	authors  []string
	// fail fails CreateApp, as the database out of reach would.
	fail error
}

func (f *fakeWriter) publish() {
	f.config.mu.Lock()
	defer f.config.mu.Unlock()
	s := store.NewSnapshot(f.apps, f.flows, store.DefaultSettings()).WithAPIClients(f.clients)
	s.Scopes = slices.Clone(f.scopes)
	slices.SortFunc(s.Scopes, func(a, b store.Scope) int { return strings.Compare(a.Name, b.Name) })
	s.Debug = f.debug
	f.config.s = s
}

// SetDebugWindow writes the window as the store does: its rules, its flow and
// its app known.
func (f *fakeWriter) SetDebugWindow(_ context.Context, by string, w *store.DebugWindow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w != nil {
		if v := domain.Collect(w.Check); v != nil {
			return v
		}
		if w.Flow != "" && !slices.ContainsFunc(f.flows, func(x store.Flow) bool { return x.ID == w.Flow }) {
			return domain.Violations{{Field: "flow", Message: fmt.Sprintf("%q is no flow", w.Flow)}}
		}
		if w.App != "" && !f.knownApp(w.App) {
			return domain.Violations{{Field: "app", Message: fmt.Sprintf("%q is no app", w.App)}}
		}
		c := *w
		c.UpdatedBy = by
		w = &c
	}
	f.debug = w
	f.by(by)
	f.publish()
	return nil
}

// The writes of the catalogue, by the rules of the store.
func (f *fakeWriter) CreateScope(_ context.Context, by string, s store.Scope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, standard := domain.Standard(s.Name); standard {
		return store.ErrStandard
	}
	if v := domain.Collect(s.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(f.scopes, func(x store.Scope) bool { return x.Name == s.Name }) {
		return store.ErrExists
	}
	f.by(by)
	f.scopes = append(f.scopes, s)
	f.publish()
	return nil
}

func (f *fakeWriter) UpdateScope(_ context.Context, by, name string, change func(*store.Scope) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, standard := domain.Standard(name)
	i := slices.IndexFunc(f.scopes, func(x store.Scope) bool { return x.Name == name })
	if i < 0 && !standard {
		return store.ErrNotFound
	}
	s := store.Scope{Name: name}
	if i >= 0 {
		s = f.scopes[i]
	}
	if err := change(&s); err != nil {
		return err
	}
	if v := domain.Collect(s.Check); v != nil {
		return v
	}
	f.by(by)
	if i < 0 {
		f.scopes = append(f.scopes, s)
	} else {
		f.scopes[i] = s
	}
	f.publish()
	return nil
}

func (f *fakeWriter) DeleteScope(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, standard := domain.Standard(name); standard {
		return store.ErrStandard
	}
	i := slices.IndexFunc(f.scopes, func(x store.Scope) bool { return x.Name == name })
	if i < 0 {
		return store.ErrNotFound
	}
	f.scopes = slices.Delete(f.scopes, i, i+1)
	f.publish()
	return nil
}

func (f *fakeWriter) by(by string) {
	f.authors = append(f.authors, by)
}

func (f *fakeWriter) CreateApp(_ context.Context, by string, a store.App) error {
	if f.fail != nil {
		return f.fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v := domain.Collect(a.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(f.apps, func(x store.App) bool { return x.ID == a.ID }) {
		return store.ErrExists
	}
	f.by(by)
	f.apps = append(f.apps, a)
	f.publish()
	return nil
}

func (f *fakeWriter) UpdateApp(_ context.Context, by, id string, change func(*store.App) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.apps, func(x store.App) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	a := f.apps[i]
	a.AllowedSources, a.ReceiveClaims = slices.Clone(a.AllowedSources), slices.Clone(a.ReceiveClaims)
	if err := change(&a); err != nil {
		return err
	}
	if a.ID != id {
		return domain.Violations{{Field: "id", Message: "changed"}}
	}
	if v := domain.Collect(a.Check); v != nil {
		return v
	}
	f.by(by)
	f.apps[i] = a
	f.publish()
	return nil
}

func (f *fakeWriter) DeleteApp(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var flows []string
	for _, fl := range f.flows {
		if slices.ContainsFunc(fl.Steps, func(s store.Step) bool { return s.AppID == id }) {
			flows = append(flows, fl.ID)
		}
	}
	if len(flows) > 0 {
		return &store.ReferencedError{App: id, Flows: flows}
	}
	i := slices.IndexFunc(f.apps, func(x store.App) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	f.apps = slices.Delete(f.apps, i, i+1)
	f.publish()
	return nil
}

func (f *fakeWriter) knownApp(id string) bool {
	return slices.ContainsFunc(f.apps, func(a store.App) bool { return a.ID == id })
}

func (f *fakeWriter) CreateFlow(_ context.Context, by string, fl store.Flow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v := domain.Collect(func(fail domain.Fail) { fl.Check(fail, f.knownApp) }); v != nil {
		return v
	}
	if slices.ContainsFunc(f.flows, func(x store.Flow) bool { return x.ID == fl.ID }) {
		return store.ErrExists
	}
	f.by(by)
	f.flows = append(f.flows, fl)
	f.publish()
	return nil
}

func (f *fakeWriter) UpdateFlow(_ context.Context, by, id string, change func(*store.Flow) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.flows, func(x store.Flow) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	fl := f.flows[i]
	fl.Steps = slices.Clone(fl.Steps)
	if err := change(&fl); err != nil {
		return err
	}
	if fl.ID != id {
		return domain.Violations{{Field: "id", Message: "changed"}}
	}
	if v := domain.Collect(func(fail domain.Fail) { fl.Check(fail, f.knownApp) }); v != nil {
		return v
	}
	f.by(by)
	f.flows[i] = fl
	f.publish()
	return nil
}

func (f *fakeWriter) DeleteFlow(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.flows, func(x store.Flow) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	f.flows = slices.Delete(f.flows, i, i+1)
	f.publish()
	return nil
}

func (f *fakeWriter) CreateAPIClient(_ context.Context, by string, c store.APIClient) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v := domain.Collect(c.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(f.clients, func(x store.APIClient) bool { return x.ID == c.ID }) {
		return store.ErrExists
	}
	f.by(by)
	f.clients = append(f.clients, c)
	f.publish()
	return nil
}

func (f *fakeWriter) UpdateAPIClient(_ context.Context, by, id string, change func(*store.APIClient) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	c := f.clients[i]
	c.Scopes = slices.Clone(c.Scopes)
	if err := change(&c); err != nil {
		return err
	}
	if c.ID != id {
		return domain.Violations{{Field: "id", Message: "changed"}}
	}
	if v := domain.Collect(c.Check); v != nil {
		return v
	}
	f.by(by)
	f.clients[i] = c
	f.publish()
	return nil
}

func (f *fakeWriter) DeleteAPIClient(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	f.clients = slices.Delete(f.clients, i, i+1)
	f.publish()
	return nil
}

func (f *fakeWriter) UpdateSettings(_ context.Context, by string, values map[string]json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.by(by)
	f.settings = values
	return nil
}

// resources is an admin API with its writer, behind the RealIP of serve, and
// the tokens of three clients: all the scopes, admin:read alone, admin:flows
// alone.
type resources struct {
	api     *API
	keys    *Keys
	handler http.Handler
	writer  *fakeWriter
	all     string
	reader  string
	flows   string
	mu      sync.Mutex
	wrote   []string
	logs    bytes.Buffer
}

func newResources(t *testing.T) *resources {
	t.Helper()
	config := &snapshots{}
	writer := &fakeWriter{config: config, clients: []store.APIClient{
		{ID: "all", SecretHash: clientHash(), Scopes: slices.Clone(Scopes)},
		{ID: "reader", SecretHash: clientHash(), Scopes: []string{ScopeRead}},
		{ID: "flows", SecretHash: clientHash(), Scopes: []string{ScopeFlows}},
	}}
	writer.publish()
	keys := mustKeys(t, pkcs8(t, ecKey(t, elliptic.P256())), "")
	r := &resources{writer: writer}
	api := mustNew(t, Options{
		Keys: keys, Config: config, Issuer: issuer, TokenTTL: 15 * time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RatePerMinute: 100000,
		Writer:   writer,
		LogLevel: "info", DebugMaxDuration: time.Hour,
		Logger: slog.New(slog.NewJSONHandler(&r.logs, nil)),
		Wrote: func(_ context.Context, client, resource, id, method string, fields []string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.wrote = append(r.wrote, fmt.Sprintf("%s %s %s %s %s", client, method, resource, id, strings.Join(fields, ",")))
		},
	})
	mux := http.NewServeMux()
	api.Register(mux)
	r.api, r.keys = api, keys
	r.handler = httpx.Chain(mux, httpx.RealIP(nil))
	now := time.Now()
	for _, c := range []struct {
		id   string
		into *string
	}{{"all", &r.all}, {"reader", &r.reader}, {"flows", &r.flows}} {
		c0, _ := config.Snapshot().APIClient(c.id)
		tok, err := keys.Issue(issuer, c.id, c0.Scopes, 15*time.Minute, now)
		if err != nil {
			t.Fatal(err)
		}
		*c.into = tok
	}
	return r
}

// do sends method path with the token, the body in contentType ("" for
// application/json, when there is a body).
func (r *resources) do(token, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.1.2.3:1"
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	return w
}

// problemOf decodes a problem, failing on another kind of answer.
func problemOf(t *testing.T, w *httptest.ResponseRecorder) problem {
	t.Helper()
	var p problem
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json; charset=utf-8" {
		t.Fatalf("Content-Type %q, body %s", ct, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Status != w.Code || p.Title != "An error occurred" {
		t.Fatalf("problem %s: %v", w.Body, err)
	}
	return p
}

// paths are the propertyPath of the violations of a 422.
func paths(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var got []string
	for _, v := range problemOf(t, w).Violations {
		got = append(got, v.PropertyPath)
	}
	return got
}

func decodeInto[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %s: %v", w.Body, err)
	}
	return v
}

const appBody = `{"id": "sql", "loginUrl": "http://sql/login", "consentUrl": "http://sql/consent", "logoutUrl": "", "method": "pwd"}`

// DispatcherAppApiCreateTest of Symfony, and the contract of the doc for the
// apps.
func TestApps(t *testing.T) {
	r := newResources(t)
	w := r.do(r.all, http.MethodPost, "/admin/v1/apps", "", appBody)
	if w.Code != http.StatusCreated || w.Header().Get("Location") != "/admin/v1/apps/sql" || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("POST: %d %v %s", w.Code, w.Header(), w.Body)
	}
	// Every field present, null for what is absent (Q108).
	want := `{"id":"sql","loginUrl":"http://sql/login","consentUrl":"http://sql/consent","logoutUrl":"","method":"pwd","authMode":"network","allowedSources":[],"clientCertFingerprint":null,"receiveClaims":null,"skipCheckUrl":null,"skipCheckKeySet":false,"skipCheckSignals":[]}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("POST body:\n%s\nwant\n%s", got, want)
	}
	if got := strings.TrimSpace(r.do(r.reader, http.MethodGet, "/admin/v1/apps/sql", "", "").Body.String()); got != want {
		t.Errorf("GET: %s", got)
	}
	if r.writer.authors[0] != "api_client:all" || r.wrote[0] != "all POST apps sql id,loginUrl,consentUrl,logoutUrl,method" {
		t.Errorf("author %q, audit %q", r.writer.authors, r.wrote)
	}

	// An id that cannot be one: 422 on id, nothing written.
	for _, id := range []string{`"id": ""`, `"id": "a/b"`, `"id": "` + strings.Repeat("a", 129) + `"`, `"id": null`} {
		body := strings.Replace(appBody, `"id": "sql"`, id, 1)
		got := paths(t, r.do(r.all, http.MethodPost, "/admin/v1/apps", "", body))
		if !slices.Contains(got, "id") {
			t.Errorf("%s: paths %q", id, got)
		}
	}
	if n := len(r.writer.apps); n != 1 {
		t.Errorf("%d apps after the refusals", n)
	}

	for name, tt := range map[string]struct {
		method, path, contentType, body string
		status                          int
		paths                           []string
	}{
		"id taken":           {"POST", "/admin/v1/apps", "", appBody, 409, nil},
		"rules of the app":   {"POST", "/admin/v1/apps", "", `{"id": "b", "loginUrl": "/login", "consentUrl": "http://b/c", "method": "", "receiveClaims": ["email", ""]}`, 422, []string{"loginUrl", "method", "receiveClaims[1]"}},
		"sources":            {"POST", "/admin/v1/apps", "", `{"id": "b", "loginUrl": "http://b/l", "consentUrl": "http://b/c", "method": "m", "allowedSources": ["pod-a"]}`, 422, []string{"allowedSources"}},
		"mtls in network":    {"POST", "/admin/v1/apps", "", `{"id": "b", "loginUrl": "http://b/l", "consentUrl": "http://b/c", "method": "m", "clientCertFingerprint": "ab:cd"}`, 422, []string{"clientCertFingerprint"}},
		"typo (Q110)":        {"POST", "/admin/v1/apps", "", `{"id": "b", "loginUrl": "http://b/l", "consentUrl": "http://b/c", "method": "m", "recieveClaims": []}`, 422, []string{"recieveClaims"}},
		"wrong type":         {"POST", "/admin/v1/apps", "", `{"id": "b", "loginUrl": 42}`, 400, nil},
		"not JSON":           {"POST", "/admin/v1/apps", "", `not json`, 400, nil},
		"not an object":      {"POST", "/admin/v1/apps", "", `["id"]`, 400, nil},
		"two objects":        {"POST", "/admin/v1/apps", "", `{} {}`, 400, nil},
		"text/plain":         {"POST", "/admin/v1/apps", "text/plain", appBody, 415, nil},
		"PATCH in text":      {"PATCH", "/admin/v1/apps/sql", "text/plain", `{"method": "otp"}`, 415, nil},
		"too large":          {"POST", "/admin/v1/apps", "", `{"id": "` + strings.Repeat("a", maxResourceBody) + `"}`, 413, nil},
		"unknown":            {"GET", "/admin/v1/apps/nope", "", "", 404, nil},
		"PUT unknown":        {"PUT", "/admin/v1/apps/nope", "", appBody[:0] + `{"loginUrl": "http://a/l", "consentUrl": "http://a/c", "method": "m"}`, 404, nil},
		"DELETE unknown":     {"DELETE", "/admin/v1/apps/nope", "", "", 404, nil},
		"id renamed (Q95)":   {"PATCH", "/admin/v1/apps/sql", "application/merge-patch+json", `{"id": "other"}`, 422, []string{"id"}},
		"id of another, PUT": {"PUT", "/admin/v1/apps/sql", "", strings.Replace(appBody, `"sql"`, `"other"`, 1), 422, []string{"id"}},
		"PUT without login":  {"PUT", "/admin/v1/apps/sql", "", `{"consentUrl": "http://sql/consent", "method": "pwd"}`, 422, []string{"loginUrl"}},
	} {
		w := r.do(r.all, tt.method, tt.path, tt.contentType, tt.body)
		if w.Code != tt.status {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, tt.status, w.Body)
			continue
		}
		if p := problemOf(t, w); tt.paths != nil && !slices.Equal(paths(t, w), tt.paths) {
			t.Errorf("%s: paths %q, want %q (%s)", name, paths(t, w), tt.paths, p.Detail)
		}
	}
	if w := r.do(r.all, http.MethodPost, "/admin/v1/apps", "", `{"id": "b", "loginUrl": 42}`); !strings.Contains(problemOf(t, w).Detail, `The type of the "loginUrl" attribute must be "string", "int" given.`) {
		t.Errorf("type error: %s", w.Body)
	}

	// Q96: admin:read reads and never writes, admin:flows neither reads nor
	// writes an app.
	for name, tt := range map[string]struct {
		token, method string
		status        int
	}{
		"read GET":   {r.reader, http.MethodGet, 200},
		"read PATCH": {r.reader, http.MethodPatch, 403},
		"flows GET":  {r.flows, http.MethodGet, 403},
		"flows PUT":  {r.flows, http.MethodPut, 403},
	} {
		if w := r.do(tt.token, tt.method, "/admin/v1/apps/sql", "", `{"method": "x"}`); w.Code != tt.status {
			t.Errorf("%s: %d, want %d", name, w.Code, tt.status)
		}
	}

	// PATCH: the fields sent; the Go's fields restrict the app.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/apps/sql", "application/merge-patch+json",
		`{"receiveClaims": ["email"], "allowedSources": ["10.0.6.21", "10.0.7.0/24"]}`)
	app := decodeInto[appJSON](t, w)
	if w.Code != 200 || !slices.Equal(app.ReceiveClaims, []string{"email"}) || !slices.Equal(app.AllowedSources, []string{"10.0.6.21/32", "10.0.7.0/24"}) || app.Method != "pwd" {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body)
	}
	// PUT of a tool written for Symfony: its fields replaced, the Go's kept (Q107).
	w = r.do(r.all, http.MethodPut, "/admin/v1/apps/sql", "", `{"id": "sql", "loginUrl": "http://sql2/login", "consentUrl": "http://sql2/consent", "logoutUrl": "", "method": "otp"}`)
	app = decodeInto[appJSON](t, w)
	if w.Code != 200 || app.Method != "otp" || !slices.Equal(app.ReceiveClaims, []string{"email"}) || len(app.AllowedSources) != 2 {
		t.Errorf("PUT kept nothing of the Go's fields: %d %s", w.Code, w.Body)
	}
	// PUT without id: the path's; logoutUrl absent is none.
	w = r.do(r.all, http.MethodPut, "/admin/v1/apps/sql", "", `{"loginUrl": "http://sql/login", "consentUrl": "http://sql/consent", "logoutUrl": "http://sql/out", "method": "pwd"}`)
	if w.Code != 200 || decodeInto[appJSON](t, w).LogoutURL != "http://sql/out" {
		t.Errorf("PUT without id: %d %s", w.Code, w.Body)
	}
	// null gives a field its default: every claim, no sources; in application/json too.
	w = r.do(r.all, http.MethodPatch, "/admin/v1/apps/sql", "application/json", `{"receiveClaims": null, "allowedSources": null, "logoutUrl": null}`)
	app = decodeInto[appJSON](t, w)
	if w.Code != 200 || app.ReceiveClaims != nil || len(app.AllowedSources) != 0 || app.LogoutURL != "" || !strings.Contains(w.Body.String(), `"receiveClaims":null`) {
		t.Errorf("PATCH null: %d %s", w.Code, w.Body)
	}
	// mtls, its fingerprint as openssl writes it.
	fp := strings.ToUpper(strings.TrimSuffix(strings.Repeat("ab:", 32), ":"))
	w = r.do(r.all, http.MethodPatch, "/admin/v1/apps/sql", "", `{"authMode": "mtls", "clientCertFingerprint": "`+fp+`"}`)
	if app = decodeInto[appJSON](t, w); w.Code != 200 || app.ClientCertFingerprint == nil || *app.ClientCertFingerprint != strings.Repeat("ab", 32) {
		t.Errorf("mtls: %d %s", w.Code, w.Body)
	}

	// An app a flow has as a step: 409, the flow named.
	r.writer.flows = []store.Flow{{ID: "f", Title: map[string]string{"fr": "F"}, Description: map[string]string{"fr": "D"}, Enabled: true,
		Steps: []store.Step{{AppID: "sql", Position: 0, SubjectCheck: "none"}}}}
	w = r.do(r.all, http.MethodDelete, "/admin/v1/apps/sql", "", "")
	if w.Code != http.StatusConflict || !strings.Contains(problemOf(t, w).Detail, "flows f") {
		t.Errorf("DELETE referenced: %d %s", w.Code, w.Body)
	}
	r.writer.flows = nil
	if w := r.do(r.all, http.MethodDelete, "/admin/v1/apps/sql", "", ""); w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Errorf("DELETE: %d %s", w.Code, w.Body)
	}
	if w := r.do(r.all, http.MethodGet, "/admin/v1/apps/sql", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE: %d", w.Code)
	}
	r.mu.Lock()
	audit := strings.Join(r.wrote, "\n")
	r.mu.Unlock()
	if !strings.Contains(audit, "all DELETE apps sql ") || strings.Contains(audit, "http://") || strings.Contains(audit, "email") {
		t.Errorf("audit:\n%s", audit)
	}
}

// Collections: 30 a page, by id in byte order (Q103).
func TestAppsPages(t *testing.T) {
	r := newResources(t)
	for i := range 31 {
		r.writer.apps = append(r.writer.apps, store.App{ID: fmt.Sprintf("app-%02d", 30-i), LoginURL: "http://a/l", ConsentURL: "http://a/c", Method: "m", AuthMode: "network"})
	}
	r.writer.publish()
	first := decodeInto[[]appJSON](t, r.do(r.reader, http.MethodGet, "/admin/v1/apps", "", ""))
	second := decodeInto[[]appJSON](t, r.do(r.reader, http.MethodGet, "/admin/v1/apps?page=2", "", ""))
	if len(first) != 30 || first[0].ID != "app-00" || len(second) != 1 || second[0].ID != "app-30" {
		t.Errorf("pages of %d and %d", len(first), len(second))
	}
	if w := r.do(r.reader, http.MethodGet, "/admin/v1/apps?page=3", "", ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("page 3: %s", w.Body)
	}
	for _, p := range []string{"0", "-1", "x"} {
		if w := r.do(r.reader, http.MethodGet, "/admin/v1/apps?page="+p, "", ""); w.Code != http.StatusBadRequest {
			t.Errorf("page=%s: %d", p, w.Code)
		}
	}
	empty := newResources(t)
	if w := empty.do(empty.reader, http.MethodGet, "/admin/v1/apps", "", ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("no app: %s", w.Body)
	}
}

// withApps gives the writer the apps a, b and c.
func (r *resources) withApps(ids ...string) {
	for _, id := range ids {
		r.writer.apps = append(r.writer.apps, store.App{ID: id, LoginURL: "http://" + id + "/l", ConsentURL: "http://" + id + "/c", Method: "m", AuthMode: "network"})
	}
	r.writer.publish()
}

// DispatcherFlowApiCreateTest and DispatcherFlowProcessorTest of Symfony, and
// the contract of the doc for the flows.
func TestFlows(t *testing.T) {
	r := newResources(t)
	r.withApps("a", "b", "c")
	const flow = `{"id": "f", "title": {"fr": "F", "en": ""}, "description": {"fr": "D"}, "steps": [{"appId": "a", "stepOrder": 0}]}`
	w := r.do(r.all, http.MethodPost, "/admin/v1/flows", "", flow)
	want := `{"id":"f","title":{"fr":"F"},"description":{"fr":"D"},"iconUrl":null,"enabled":true,"acr":null,"skipCheckAllowedAcr":[],"steps":[{"appId":"a","stepOrder":0,"subjectCheck":"none","skipCheck":false}]}`
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusCreated || got != want || w.Header().Get("Location") != "/admin/v1/flows/f" {
		t.Fatalf("POST: %d %s", w.Code, got)
	}
	if got := strings.TrimSpace(r.do(r.reader, http.MethodGet, "/admin/v1/flows/f", "", "").Body.String()); got != want {
		t.Errorf("GET: %s", got)
	}
	if got := paths(t, r.do(r.all, http.MethodPost, "/admin/v1/flows", "", strings.Replace(flow, `"id": "f"`, `"id": ""`, 1))); !slices.Contains(got, "id") {
		t.Errorf("POST without id: %q", got)
	}

	steps := func(t *testing.T, w *httptest.ResponseRecorder) string {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var parts []string
		for _, s := range decodeInto[flowJSON](t, w).Steps {
			parts = append(parts, fmt.Sprintf("%s:%d:%s", s.AppID, s.StepOrder, s.SubjectCheck))
		}
		return strings.Join(parts, " ")
	}
	patchF := func(body string) *httptest.ResponseRecorder {
		return r.do(r.all, http.MethodPatch, "/admin/v1/flows/f", "application/merge-patch+json", body)
	}
	// In order: each patch starts from the steps the one before left.
	for _, tt := range []struct{ name, body, want string }{
		{"replaced, order kept", `{"steps": [{"appId": "b", "stepOrder": 5, "subjectCheck": "equal"}, {"appId": "a", "stepOrder": 2}]}`, "a:2:none b:5:equal"},
		{"absent: kept", `{"enabled": false}`, "a:2:none b:5:equal"},
		{"id and order of Symfony", `{"steps": [{"id": "a", "order": 0}, {"id": "b", "order": "1"}]}`, "a:0:none b:1:equal"},
		{"round trip of Symfony read", `{"steps": [{"id": 3, "appId": "c", "stepOrder": 0}, {"id": 4, "appId": "b", "stepOrder": 1}]}`, "c:0:none b:1:equal"},
		{"subjectCheck by app (Q107)", `{"steps": [{"appId": "b", "stepOrder": 0}, {"appId": "a", "stepOrder": 1, "subjectCheck": null}]}`, "b:0:equal a:1:none"},
	} {
		if got := steps(t, patchF(tt.body)); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
	// PUT of a tool written for Symfony: title, description, iconUrl and
	// enabled replaced; the steps and acr, absent, kept.
	if w := patchF(`{"acr": "loa2", "iconUrl": {"fr": "http://i/f.svg"}}`); w.Code != http.StatusOK {
		t.Fatalf("PATCH acr: %d %s", w.Code, w.Body)
	}
	w = r.do(r.all, http.MethodPut, "/admin/v1/flows/f", "", `{"id": "f", "title": {"fr": "F2"}, "description": {"fr": "D2"}}`)
	got := decodeInto[flowJSON](t, w)
	if w.Code != http.StatusOK || got.Title["fr"] != "F2" || got.IconURL != nil || !got.Enabled || got.ACR == nil || *got.ACR != "loa2" || len(got.Steps) != 2 {
		t.Errorf("PUT: %d %s", w.Code, w.Body)
	}
	// A map replaced whole (Q104).
	w = patchF(`{"title": {"en": "E"}}`)
	if got := decodeInto[flowJSON](t, w); len(got.Title) != 1 || got.Title["en"] != "E" {
		t.Errorf("title: %s", w.Body)
	}

	for name, tt := range map[string]struct {
		body   string
		status int
		paths  []string
	}{
		"no step left":       {`{"steps": []}`, 422, []string{"steps"}},
		"unknown app":        {`{"steps": [{"appId": "zz", "stepOrder": 0}]}`, 422, []string{"steps[0]"}},
		"not an object":      {`{"steps": [{"appId": "a", "stepOrder": 0}, "junk", [1]]}`, 422, []string{"steps[1]", "steps[2]"}},
		"no app":             {`{"steps": [{"stepOrder": 0}]}`, 422, []string{"steps[0].appId"}},
		"no order":           {`{"steps": [{"appId": "a"}]}`, 422, []string{"steps[0].stepOrder"}},
		"order not a number": {`{"steps": [{"appId": "a", "order": "first"}]}`, 422, []string{"steps[0].order"}},
		"order fractional":   {`{"steps": [{"appId": "a", "stepOrder": 1.5}]}`, 422, []string{"steps[0].stepOrder"}},
		"unknown key":        {`{"steps": [{"appId": "a", "stepOrder": 0, "position": 0}]}`, 422, []string{"steps[0].position"}},
		"subject check":      {`{"steps": [{"appId": "a", "stepOrder": 0, "subjectCheck": "claim:"}]}`, 422, []string{"steps[0].subjectCheck"}},
		"app twice":          {`{"steps": [{"appId": "a", "stepOrder": 0}, {"appId": "a", "stepOrder": 1}]}`, 422, []string{"steps[1]"}},
		"steps not a list":   {`{"steps": {"appId": "a"}}`, 400, nil},
		"appId a number":     {`{"steps": [{"appId": 1, "stepOrder": 0}]}`, 400, nil},
		"title not a map":    {`{"title": "F"}`, 400, nil},
		"title emptied":      {`{"title": {}}`, 422, []string{"title"}},
		"enabled a string":   {`{"enabled": "yes"}`, 400, nil},
		"acr with a space":   {`{"acr": "loa 2"}`, 422, []string{"acr"}},
	} {
		w := patchF(tt.body)
		if w.Code != tt.status {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, tt.status, w.Body)
			continue
		}
		if tt.paths != nil && !slices.Equal(paths(t, w), tt.paths) {
			t.Errorf("%s: paths %q, want %q", name, paths(t, w), tt.paths)
		}
	}
	if w := r.do(r.flows, http.MethodPatch, "/admin/v1/flows/f", "", `{"enabled": true}`); w.Code != http.StatusOK {
		t.Errorf("admin:flows writes a flow: %d", w.Code)
	}
	if w := r.do(r.reader, http.MethodDelete, "/admin/v1/flows/f", "", ""); w.Code != http.StatusForbidden {
		t.Errorf("admin:read deletes a flow: %d", w.Code)
	}
	// DELETE deletes, where Symfony answered 204 and kept the flow (Q95).
	if w := r.do(r.all, http.MethodDelete, "/admin/v1/flows/f", "", ""); w.Code != http.StatusNoContent {
		t.Errorf("DELETE: %d", w.Code)
	}
	if w := r.do(r.all, http.MethodGet, "/admin/v1/flows/f", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE: %d", w.Code)
	}
	if w := r.do(r.all, http.MethodPost, "/admin/v1/flows", "", flow); w.Code != http.StatusCreated {
		t.Fatal(w.Body)
	}
	if w := r.do(r.all, http.MethodPost, "/admin/v1/flows", "", flow); w.Code != http.StatusConflict {
		t.Errorf("POST twice: %d", w.Code)
	}
	if got := decodeInto[[]flowJSON](t, r.do(r.reader, http.MethodGet, "/admin/v1/flows", "", "")); len(got) != 1 {
		t.Errorf("collection: %+v", got)
	}
}

// OAuth2ClientApiCreateTest and OAuth2ClientApiValidationTest of Symfony, and the
// contract of the doc for the clients.
func TestClients(t *testing.T) {
	r := newResources(t)
	w := r.do(r.all, http.MethodPost, "/admin/v1/oauth2-clients", "", `{"id": "ci", "secret": "s3cret"}`)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusCreated || got != `{"id":"ci","scopes":[]}` || w.Header().Get("Location") != "/admin/v1/oauth2-clients/ci" {
		t.Fatalf("POST: %d %s", w.Code, got)
	}
	c, _ := r.writer.config.Snapshot().APIClient("ci")
	if !domain.SecretMatches(c.SecretHash, "s3cret") || len(c.Scopes) != 0 {
		t.Errorf("client written: %+v", c)
	}
	// A hash of Symfony, taken as it is for the import.
	w = r.do(r.all, http.MethodPost, "/admin/v1/oauth2-clients", "", `{"id": "symfony", "secret": "`+clientHash()+`", "scopes": ["admin:read"]}`)
	if c, _ := r.writer.config.Snapshot().APIClient("symfony"); w.Code != http.StatusCreated || c.SecretHash != clientHash() {
		t.Errorf("hash: %d %s", w.Code, w.Body)
	}
	for name, tt := range map[string]struct {
		method, path, body string
		status             int
		paths              []string
	}{
		"invalid id":        {"POST", "/admin/v1/oauth2-clients", `{"id": "a/b", "secret": "s"}`, 422, []string{"id"}},
		"blank id":          {"POST", "/admin/v1/oauth2-clients", `{"id": "", "secret": "s"}`, 422, []string{"id"}},
		"no secret":         {"POST", "/admin/v1/oauth2-clients", `{"id": "x"}`, 422, []string{"secret"}},
		"empty secret":      {"POST", "/admin/v1/oauth2-clients", `{"id": "x", "secret": ""}`, 422, []string{"secret"}},
		"hash of cost 31":   {"POST", "/admin/v1/oauth2-clients", `{"id": "x", "secret": "` + strings.Replace(clientHash(), "$04$", "$31$", 1) + `"}`, 422, []string{"secret"}},
		"scope with space":  {"POST", "/admin/v1/oauth2-clients", `{"id": "x", "secret": "s", "scopes": ["admin flows"]}`, 422, []string{"scopes[0]"}},
		"taken":             {"POST", "/admin/v1/oauth2-clients", `{"id": "ci", "secret": "s"}`, 409, nil},
		"PATCH slash in id": {"PATCH", "/admin/v1/oauth2-clients/ci", `{"id": "a/b"}`, 422, []string{"id"}},
		"PATCH blank id":    {"PATCH", "/admin/v1/oauth2-clients/ci", `{"id": ""}`, 422, []string{"id"}},
		"secret null":       {"PATCH", "/admin/v1/oauth2-clients/ci", `{"secret": null}`, 422, []string{"secret"}},
		"secret a number":   {"PATCH", "/admin/v1/oauth2-clients/ci", `{"secret": 42}`, 400, nil},
		"groups of Symfony": {"PATCH", "/admin/v1/oauth2-clients/ci", `{"groups": []}`, 422, []string{"groups"}},
	} {
		w := r.do(r.all, tt.method, tt.path, "", tt.body)
		if w.Code != tt.status {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, tt.status, w.Body)
			continue
		}
		if tt.paths != nil && !slices.Equal(paths(t, w), tt.paths) {
			t.Errorf("%s: paths %q", name, paths(t, w))
		}
	}
	// PATCH of the scopes; PUT without secret nor scopes keeps both (Q107, Q112).
	if w := r.do(r.all, http.MethodPatch, "/admin/v1/oauth2-clients/ci", "", `{"scopes": ["admin:apps", "admin:read"]}`); w.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body)
	}
	before, _ := r.writer.config.Snapshot().APIClient("ci")
	if w := r.do(r.all, http.MethodPut, "/admin/v1/oauth2-clients/ci", "", `{"id": "ci"}`); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"id":"ci","scopes":["admin:apps","admin:read"]}` {
		t.Errorf("PUT: %d %s", w.Code, w.Body)
	}
	if after, _ := r.writer.config.Snapshot().APIClient("ci"); after.SecretHash != before.SecretHash {
		t.Error("PUT without secret changed it")
	}
	if w := r.do(r.all, http.MethodPut, "/admin/v1/oauth2-clients/ci", "", `{"secret": "n3w"}`); w.Code != http.StatusOK {
		t.Errorf("PUT secret: %d", w.Code)
	}
	if after, _ := r.writer.config.Snapshot().APIClient("ci"); !domain.SecretMatches(after.SecretHash, "n3w") || len(after.Scopes) != 2 {
		t.Errorf("PUT secret: %+v", after)
	}
	// Never the secret, never its hash.
	for _, path := range []string{"/admin/v1/oauth2-clients", "/admin/v1/oauth2-clients/ci", "/admin/v1/oauth2-clients/symfony"} {
		if w := r.do(r.reader, http.MethodGet, path, "", ""); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "$2") || strings.Contains(w.Body.String(), "secret") {
			t.Errorf("GET %s: %d %s", path, w.Code, w.Body)
		}
	}
	// Q96: only admin:clients writes a client; admin:flows reads none.
	if w := r.do(r.flows, http.MethodGet, "/admin/v1/oauth2-clients", "", ""); w.Code != http.StatusForbidden {
		t.Errorf("admin:flows reads the clients: %d", w.Code)
	}
	if w := r.do(r.reader, http.MethodPost, "/admin/v1/oauth2-clients", "", `{"id": "x", "secret": "s"}`); w.Code != http.StatusForbidden {
		t.Errorf("admin:read creates a client: %d", w.Code)
	}
	// DELETE deletes, where Symfony answered 204 and kept the client (Q95).
	if w := r.do(r.all, http.MethodDelete, "/admin/v1/oauth2-clients/ci", "", ""); w.Code != http.StatusNoContent {
		t.Errorf("DELETE: %d", w.Code)
	}
	if _, ok := r.writer.config.Snapshot().APIClient("ci"); ok {
		t.Error("client still there")
	}
	r.mu.Lock()
	audit := strings.Join(r.wrote, "\n")
	r.mu.Unlock()
	if strings.Contains(audit, "s3cret") || strings.Contains(audit, "n3w") || !strings.Contains(audit, "all PUT oauth2-clients ci secret") {
		t.Errorf("audit:\n%s", audit)
	}
}

// DispatcherSettingsApiTest of Symfony, and the document of Q105.
func TestSettings(t *testing.T) {
	r := newResources(t)
	w := r.do(r.reader, http.MethodGet, "/admin/v1/settings", "", "")
	want := `{"appAutoSelect":false,"consentAutoAccept":false,"aggregateAmrFromLoginRequest":false,"challengeTtl":3600,"remember":true,` +
		`"loginRememberFor":86400,"consentRememberFor":2629800,"loginAcceptWebhookUrl":null,"consentAcceptWebhookUrl":null,` +
		`"supportedLocales":["fr","en"],"defaultLocale":"fr","fallbackLocale":"en","acrValuesMode":"prefer"}`
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusOK || got != want {
		t.Fatalf("GET: %d\n%s\nwant\n%s", w.Code, got, want)
	}
	for _, method := range []string{http.MethodPatch, http.MethodPut} {
		r.writer.settings = nil
		w := r.do(r.all, method, "/admin/v1/settings", "", `{"id": 1, "appAutoSelect": true, "sessionTtl": 1800, "hydraPublicUrl": "http://public", "adminAuthorizedHosts": [], "loginAcceptWebhookUrl": null}`)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body)
		}
		got := map[string]string{}
		for k, v := range r.writer.settings {
			got[k] = string(v)
		}
		if want := map[string]string{"app_auto_select": "true", "login_remember_for": "1800", "login_accept_webhook_url": "null"}; !maps.Equal(got, want) {
			t.Errorf("%s: written %v, want %v", method, got, want)
		}
	}
	if !strings.Contains(r.logs.String(), `"msg":"admin.settings_ignored","fields":["adminAuthorizedHosts","hydraPublicUrl","id"]`) {
		t.Errorf("logs: %s", r.logs.String())
	}
	for name, tt := range map[string]struct {
		body   string
		status int
		paths  []string
	}{
		"both TTLs":           {`{"sessionTtl": 1800, "loginRememberFor": 3600}`, 422, []string{"sessionTtl"}},
		"unknown":             {`{"apAutoSelect": true}`, 422, []string{"apAutoSelect"}},
		"in snake_case":       {`{"app_auto_select": true}`, 422, []string{"app_auto_select"}},
		"int as a string":     {`{"challengeTtl": "abc"}`, 400, nil},
		"locales as a string": {`{"supportedLocales": "fr"}`, 400, nil},
		"bool as an int":      {`{"remember": 1}`, 400, nil},
	} {
		w := r.do(r.all, http.MethodPatch, "/admin/v1/settings", "", tt.body)
		if w.Code != tt.status {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, tt.status, w.Body)
			continue
		}
		if tt.paths != nil && !slices.Equal(paths(t, w), tt.paths) {
			t.Errorf("%s: paths %q", name, paths(t, w))
		}
	}
	if w := r.do(r.all, http.MethodPatch, "/admin/v1/settings", "", `{"sessionTtl": 1800, "loginRememberFor": 1800}`); w.Code != http.StatusOK {
		t.Errorf("both TTLs equal: %d", w.Code)
	}
	if w := r.do(r.flows, http.MethodGet, "/admin/v1/settings", "", ""); w.Code != http.StatusForbidden {
		t.Errorf("admin:flows reads the settings: %d", w.Code)
	}
	if w := r.do(r.reader, http.MethodPatch, "/admin/v1/settings", "", `{"remember": false}`); w.Code != http.StatusForbidden {
		t.Errorf("admin:read writes the settings: %d", w.Code)
	}
	if w := r.do(r.all, http.MethodDelete, "/admin/v1/settings", "", ""); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD, PUT, PATCH" {
		t.Errorf("DELETE /settings: %d %v", w.Code, w.Header())
	}
}

// The violations of the store, under their keys in snake_case, come out in
// camelCase, and a configuration refused names its setting.
func TestViolationPaths(t *testing.T) {
	for in, want := range map[string]string{
		"login_url": "loginUrl", "steps[1].subject_check": "steps[1].subjectCheck", "receive_claims[0]": "receiveClaims[0]",
		"id": "id", "": "", "challenge_ttl": "challengeTtl", "login_accept_webhook_url": "loginAcceptWebhookUrl",
	} {
		if got := camel(in); got != want {
			t.Errorf("camel(%q) = %q, want %q", in, got, want)
		}
	}
	v := refusedViolations(fmt.Errorf("%w\n%w", fmt.Errorf("setting login_accept_webhook_url: is in http://, which needs tls.allow_http"), fmt.Errorf("read apps: boom")))
	if len(v) != 2 || v[0].Field != "login_accept_webhook_url" || v[1].Field != "" {
		t.Errorf("refused: %+v", v)
	}
}

// tokenOf adds to the writer a client holding scopes, and gives its token.
func (r *resources) tokenOf(t *testing.T, id string, scopes ...string) string {
	t.Helper()
	r.writer.mu.Lock()
	r.writer.clients = append(r.writer.clients, store.APIClient{ID: id, SecretHash: clientHash(), Scopes: scopes})
	r.writer.publish()
	r.writer.mu.Unlock()
	tok, err := r.keys.Issue(issuer, id, scopes, 15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// flipping gives another snapshot at each read: a refresh between two.
type flipping struct {
	mu   sync.Mutex
	n    int
	snap [2]*store.Snapshot
}

func (f *flipping) Snapshot() *store.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return f.snap[f.n%2]
}

// A read of a flow takes one snapshot: one refreshed between two reads gave
// another flow, or a panic (revue R35).
func TestFlowReadOneSnapshot(t *testing.T) {
	flow := func(id string) store.Flow {
		return store.Flow{ID: id, Title: map[string]string{"fr": id}, Description: map[string]string{"fr": id}, Enabled: true,
			Steps: []store.Step{{AppID: "a", Position: 0, SubjectCheck: "none"}}}
	}
	clients := []store.APIClient{{ID: "all", SecretHash: clientHash(), Scopes: Scopes}}
	config := &flipping{snap: [2]*store.Snapshot{
		store.NewSnapshot(nil, []store.Flow{flow("a"), flow("b")}, store.DefaultSettings()).WithAPIClients(clients),
		store.NewSnapshot(nil, []store.Flow{flow("c")}, store.DefaultSettings()).WithAPIClients(clients),
	}}
	keys := mustKeys(t, pkcs8(t, ecKey(t, elliptic.P256())), "")
	api := mustNew(t, Options{Keys: keys, Config: config, Issuer: issuer, TokenTTL: time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RatePerMinute: 100000, Writer: &fakeWriter{config: &snapshots{}}})
	mux := http.NewServeMux()
	api.Register(mux)
	h := httpx.Chain(mux, httpx.RealIP(nil))
	tok, _ := keys.Issue(issuer, "all", Scopes, time.Minute, time.Now())
	for range 20 {
		for _, id := range []string{"a", "b", "c"} {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/flows/"+id, nil)
			req.RemoteAddr = "10.1.2.3:1"
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			switch {
			case w.Code == http.StatusOK && decodeInto[flowJSON](t, w).ID != id:
				t.Fatalf("GET /flows/%s gave %s", id, w.Body)
			case w.Code != http.StatusOK && w.Code != http.StatusNotFound:
				t.Fatalf("GET /flows/%s: %d %s", id, w.Code, w.Body)
			}
		}
	}
}
