package admin

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
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
	settings map[string]json.RawMessage // the last UpdateSettings
	authors  []string
}

func (f *fakeWriter) publish() {
	f.config.mu.Lock()
	defer f.config.mu.Unlock()
	f.config.s = store.NewSnapshot(f.apps, f.flows, store.DefaultSettings()).WithAPIClients(f.clients)
}

func (f *fakeWriter) by(by string) {
	f.authors = append(f.authors, by)
}

func (f *fakeWriter) CreateApp(_ context.Context, by string, a store.App) error {
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
	handler http.Handler
	writer  *fakeWriter
	all     string
	reader  string
	flows   string
	mu      sync.Mutex
	wrote   []string
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
	api := New(Options{
		Keys: keys, Config: config, Issuer: issuer, TokenTTL: 15 * time.Minute,
		AuthorizedHosts: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, RatePerMinute: 100000,
		Writer: writer,
		Wrote: func(_ context.Context, client, resource, id, method string, fields []string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.wrote = append(r.wrote, fmt.Sprintf("%s %s %s %s %s", client, method, resource, id, strings.Join(fields, ",")))
		},
	})
	mux := http.NewServeMux()
	api.Register(mux)
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
	want := `{"id":"sql","loginUrl":"http://sql/login","consentUrl":"http://sql/consent","logoutUrl":"","method":"pwd","authMode":"network","allowedSources":[],"clientCertFingerprint":null,"receiveClaims":null}`
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
