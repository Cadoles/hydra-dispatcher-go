package adminui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/hydra"
)

// fakeHydra is the admin API of Hydra for the clients, in memory: it keeps
// the members of a client as JSON, as written, numbers included, and applies
// the JSON Patch of a modification to them as Hydra does: decoded into the
// client it holds, null and remove leave a member as it was (R43).
type fakeHydra struct {
	mu      sync.Mutex
	clients map[string]map[string]json.RawMessage
	order   []string
	patches [][]hydra.PatchOp
	n       int
	// fail is the error of every call, failPatch that of the patches.
	fail, failPatch error
}

func newFakeHydra() *fakeHydra { return &fakeHydra{clients: map[string]map[string]json.RawMessage{}} }

func rawOf(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// put keeps the client c, each member as JSON.
func (f *fakeHydra) put(c map[string]any) {
	m := map[string]json.RawMessage{}
	for k, v := range c {
		m[k] = rawOf(v)
	}
	f.putRaw(m)
}

// putJSON keeps a client as Hydra writes it, its members as written.
func (f *fakeHydra) putJSON(doc string) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		panic(err)
	}
	f.putRaw(m)
}

func (f *fakeHydra) putRaw(m map[string]json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var id string
	_ = json.Unmarshal(m["client_id"], &id)
	if _, ok := f.clients[id]; !ok {
		f.order = append(f.order, id)
	}
	f.clients[id] = m
}

// get is the client id as Hydra holds it, its numbers as json.Number; nil
// for none.
func (f *fakeHydra) get(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[id]
	if !ok {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(rawOf(c)))
	d.UseNumber()
	var m map[string]any
	_ = d.Decode(&m)
	return m
}

// member is a member of the client id as Hydra writes it, "" when absent.
func (f *fakeHydra) member(id, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.clients[id][name])
}

// set changes a member of the client id.
func (f *fakeHydra) set(id, name string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients[id][name] = rawOf(v)
}

func notFound() error {
	return &hydra.RequestError{Op: "get_oauth2_client", Status: http.StatusNotFound, Body: []byte(`{"error":"Unable to locate the resource"}`)}
}

func (f *fakeHydra) Clients(_ context.Context, p hydra.ClientsPage) (hydra.ClientList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return hydra.ClientList{}, f.fail
	}
	var ids []string
	for _, id := range f.order {
		if p.Name == "" || string(f.clients[id]["client_name"]) == string(rawOf(p.Name)) {
			ids = append(ids, id)
		}
	}
	from, _ := strconv.Atoi(p.Token)
	// X-Total-Count, under a filter by name too, counts all the clients, as
	// Hydra 2.1 and 2.2 do (R43).
	l := hydra.ClientList{Total: len(f.order)}
	for i := from; i < len(ids) && i < from+p.Size; i++ {
		l.Clients = append(l.Clients, rawOf(f.clients[ids[i]]))
	}
	if from+p.Size < len(ids) {
		l.Next = strconv.Itoa(from + p.Size)
	}
	return l, nil
}

func (f *fakeHydra) OAuthClient(_ context.Context, id string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	c, ok := f.clients[id]
	if !ok {
		return nil, notFound()
	}
	return rawOf(c), nil
}

func (f *fakeHydra) CreateClient(_ context.Context, body map[string]any) (json.RawMessage, error) {
	f.mu.Lock()
	f.n++
	id := fmt.Sprintf("gen-%d", f.n)
	f.mu.Unlock()
	c := map[string]any{"client_id": id, "created_at": "2026-11-12T10:00:00Z", "updated_at": "2026-11-12T10:00:00.1Z"}
	for k, v := range body {
		c[k] = v
	}
	f.put(c)
	return f.OAuthClient(context.Background(), id)
}

func (f *fakeHydra) PatchClient(_ context.Context, id string, ops []hydra.PatchOp) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPatch != nil {
		return nil, f.failPatch
	}
	c, ok := f.clients[id]
	if !ok {
		return nil, notFound()
	}
	for _, op := range ops {
		v := rawOf(op.Value)
		if op.Op == "remove" || string(v) == "null" {
			continue // Hydra keeps it (R43)
		}
		c[strings.TrimPrefix(op.Path, "/")] = v
	}
	c["updated_at"] = rawOf(time.Now().UTC().Format(time.RFC3339Nano))
	f.patches = append(f.patches, ops)
	return rawOf(c), nil
}

func (f *fakeHydra) DeleteClient(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[id]; !ok {
		return notFound()
	}
	delete(f.clients, id)
	f.order = slices.DeleteFunc(f.order, func(x string) bool { return x == id })
	return nil
}

// withHydra gives the rig a Hydra of two clients: web, conforming, of a
// secret set by the screen; legacy, implicit, of a secret of 2024, with members
// no form shows.
func withHydra(r *rig) *fakeHydra {
	h := newFakeHydra()
	h.put(map[string]any{"client_id": "web", "client_name": "Web", "token_endpoint_auth_method": "client_secret_basic",
		"redirect_uris": []any{"https://web.test/cb"}, "grant_types": []any{"authorization_code", "refresh_token"}, "response_types": []any{"code"},
		"scope": "openid offline", "authorization_code_grant_access_token_lifespan": "30m0s", "contacts": []any{"ops@web.test"},
		"metadata":   map[string]any{"dispatcher": map[string]any{"secret_rotated_at": r.clock().Add(-24 * time.Hour).UTC().Format(time.RFC3339)}, "team": "web"},
		"created_at": "2024-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00.5Z"})
	h.put(map[string]any{"client_id": "legacy", "client_name": "Legacy", "token_endpoint_auth_method": "client_secret_post",
		"redirect_uris": []any{"http://legacy.test/cb"}, "grant_types": []any{"implicit"}, "response_types": []any{"token"},
		"created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"})
	r.ui.o.HydraClients, r.ui.o.SecretMaxAge = h, 365*24*time.Hour
	r.ui.registerHydraClients()
	return h
}

// hydraValues is the form of the page of a client, as a browser sends it
// unchanged.
func hydraValues(b *browser, id string) url.Values {
	b.r.t.Helper()
	raw, err := b.r.ui.o.HydraClients.OAuthClient(context.Background(), id)
	if err != nil {
		b.r.t.Fatal(err)
	}
	c, _ := parseClient(raw)
	v := url.Values{"csrf": {b.csrf()}, "version": {version(c)}, "client_name": {c.Name}, "redirect_uris": {strings.Join(c.RedirectURIs, "\n")},
		"post_logout_redirect_uris": {strings.Join(c.PostLogoutURIs, "\n")}, "grant_types": c.GrantTypes, "response_types": c.ResponseTypes,
		"scope": {c.Scope}, "token_endpoint_auth_method": {c.AuthMethod}, "jwks_uri": {c.JWKSURI}, "flows": c.Flows}
	for _, l := range lifespans {
		v.Set(l, c.Lifespans[l])
	}
	return v
}

func TestHydraClientsList(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	b := r.browser()
	b.login("victor", password, "")
	page := b.do(http.MethodGet, "/admin/hydra-clients", nil).Body.String()
	if !strings.Contains(page, `<a href="/admin/hydra-clients/web">web</a>`) || !strings.Contains(page, "2 clients.") ||
		!strings.Contains(page, "<strong>3 deviations</strong>") || !strings.Contains(page, "at least since 2024-01-01 <strong>to turn</strong>") ||
		!strings.Contains(page, ">kept</td>") || strings.Contains(page, "_new") || !strings.Contains(page, `aria-current="page">Hydra clients`) {
		t.Fatalf("list:\n%s", page)
	}
	if w := b.do(http.MethodGet, "/admin/hydra-clients?q=web", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/hydra-clients/web" {
		t.Errorf("an id: %d %s", w.Code, w.Header().Get("Location"))
	}
	if page := b.do(http.MethodGet, "/admin/hydra-clients?q=Legacy", nil).Body.String(); !strings.Contains(page, "1 client named Legacy.") || strings.Contains(page, ">web</a>") {
		t.Errorf("a name:\n%s", page)
	}
	for i := range 60 {
		h.put(map[string]any{"client_id": fmt.Sprintf("bulk-%02d", i), "grant_types": []any{"client_credentials"}, "token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://k.test"})
	}
	page = b.do(http.MethodGet, "/admin/hydra-clients", nil).Body.String()
	if strings.Count(page, `<tr><td><a href="/admin/hydra-clients/`) != hydraPageSize || !strings.Contains(page, `href="/admin/hydra-clients?q=&amp;page=50">Next page</a>`) {
		t.Errorf("a page:\n%s", page)
	}
	if page := b.do(http.MethodGet, "/admin/hydra-clients?page=50", nil).Body.String(); strings.Count(page, `<tr><td><a href="/admin/hydra-clients/`) != 12 ||
		!strings.Contains(page, ">First page</a>") || strings.Contains(page, "Next page") {
		t.Errorf("the last page:\n%s", page)
	}
	if w := b.do(http.MethodGet, "/admin/hydra-clients/nobody", nil); w.Code != http.StatusNotFound {
		t.Errorf("absent: %d", w.Code)
	}
	h.fail = &hydra.UnavailableError{Op: "list_oauth2_clients"}
	if w := b.do(http.MethodGet, "/admin/hydra-clients", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("Hydra out of reach: %d", w.Code)
	}
}

func TestHydraClientCreate(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	b := r.browser()
	b.login("alice", password, "")
	form := b.do(http.MethodGet, "/admin/hydra-clients/_new", nil)
	if form.Code != http.StatusOK || !strings.Contains(form.Body.String(), `<option value="private_key_jwt" selected>`) || strings.Contains(form.Body.String(), `value="implicit"`) {
		t.Fatalf("form: %d\n%s", form.Code, form.Body)
	}
	values := url.Values{"csrf": {token(t, form)}, "client_name": {"Shop"}, "redirect_uris": {"https://shop.test/cb"}, "grant_types": {"authorization_code"},
		"response_types": {"code"}, "scope": {"openid"}, "token_endpoint_auth_method": {"private_key_jwt"}, "flows": {"simple"}}
	if w := b.do(http.MethodPost, "/admin/hydra-clients", values); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "private_key_jwt needs the keys") {
		t.Errorf("without keys: %d\n%s", w.Code, w.Body)
	}
	values.Set("grant_types", "implicit")
	values.Set("redirect_uris", "https://*.shop.test/cb")
	if w := b.do(http.MethodPost, "/admin/hydra-clients", values); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "the implicit grant") ||
		!strings.Contains(w.Body.String(), "holds a joker") {
		t.Errorf("implicit, a joker: %d\n%s", w.Code, w.Body)
	}
	if len(h.order) != 2 {
		t.Fatalf("created: %v", h.order)
	}
	values.Set("grant_types", "authorization_code")
	values.Set("redirect_uris", "https://shop.test/cb")
	values.Set("jwks_uri", "https://shop.test/jwks")
	w := b.do(http.MethodPost, "/admin/hydra-clients", values)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/hydra-clients/gen-1?done=created" {
		t.Fatalf("by its keys: %d\n%s", w.Code, w.Body)
	}
	if h.member("gen-1", "client_secret") != "" || h.member("gen-1", "metadata") != `{"dispatcher":{"flows":["simple"]}}` {
		t.Errorf("gen-1: %v", h.get("gen-1"))
	}
	values.Set("token_endpoint_auth_method", "client_secret_basic")
	w = b.handed(b.do(http.MethodPost, "/admin/hydra-clients", values))
	if w.Code != http.StatusOK {
		t.Fatalf("by a secret: %d\n%s", w.Code, w.Body)
	}
	secret := secretOf(t, page{w.Body.String()})
	c := h.get("gen-2")
	if c["client_secret"] != secret || len(secret) < 43 || c["metadata"].(map[string]any)["dispatcher"].(map[string]any)["secret_rotated_at"] == nil {
		t.Errorf("gen-2: %v", c)
	}
	if got := r.wrote(); !slices.Equal(got, []string{
		"write alice hydra-clients gen-1 create client_name,redirect_uris,grant_types,token_endpoint_auth_method",
		"write alice hydra-clients gen-2 create client_name,redirect_uris,grant_types,token_endpoint_auth_method,client_secret",
	}) {
		t.Errorf("audit: %q", got)
	}
	for _, line := range r.audited() {
		if strings.Contains(line, secret) {
			t.Errorf("the secret in the audit: %q", line)
		}
	}
}

// A modification writes the fields that change alone; the rest of the client
// stays as Hydra holds it (Q122).
func TestHydraClientUpdate(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	b := r.browser()
	b.login("alice", password, "")
	form := hydraValues(b, "web")
	form.Set("client_name", "The web")
	form.Set("authorization_code_grant_access_token_lifespan", "30m") // as Hydra holds it: 30m0s
	form.Set("refresh_token_grant_refresh_token_lifespan", "720h")
	form["flows"] = []string{"simple"}
	w := b.do(http.MethodPost, "/admin/hydra-clients/web", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", w.Code, w.Body)
	}
	var paths []string
	for _, op := range h.patches[0] {
		paths = append(paths, op.Path)
	}
	if !slices.Equal(paths, []string{"/client_name", "/refresh_token_grant_refresh_token_lifespan", "/metadata"}) {
		t.Errorf("patch: %q", paths)
	}
	c := h.get("web")
	m := c["metadata"].(map[string]any)
	if c["contacts"] == nil || m["team"] != "web" || m["dispatcher"].(map[string]any)["secret_rotated_at"] == nil || c["client_name"] != "The web" {
		t.Errorf("kept: %v", c)
	}
	if got := r.wrote(); !slices.Equal(got, []string{"write alice hydra-clients web update client_name,refresh_token_grant_refresh_token_lifespan,metadata.dispatcher.flows"}) {
		t.Errorf("audit: %q", got)
	}
	// Unchanged, nothing is written.
	if w := b.do(http.MethodPost, "/admin/hydra-clients/web", hydraValues(b, "web")); w.Code != http.StatusSeeOther || len(h.patches) != 1 {
		t.Errorf("unchanged: %d %d", w.Code, len(h.patches))
	}
	// Changed meanwhile: refused once.
	form = hydraValues(b, "web")
	h.set("web", "updated_at", "2026-11-12T11:00:00Z")
	form.Set("client_name", "Mine")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/web", form); w.Code != http.StatusConflict || h.get("web")["client_name"] != "The web" {
		t.Errorf("meanwhile: %d", w.Code)
	}
	// Refused by Hydra: its description under the form.
	h.failPatch = &hydra.RequestError{Op: "patch_oauth2_client", Status: http.StatusBadRequest, Body: []byte(`{"error":"invalid_client_metadata","error_description":"Field scope is malformed"}`)}
	form = hydraValues(b, "web")
	form.Set("scope", "openid offline extra")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/web", form); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "Hydra refuses it: Field scope is malformed") {
		t.Errorf("refused: %d\n%s", w.Code, w.Body)
	}
	h.failPatch = nil
	form = hydraValues(b, "web")
	form.Set("authorization_code_grant_id_token_lifespan", "an hour")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/web", form); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "is not a positive duration") {
		t.Errorf("a lifespan: %d", w.Code)
	}
}

// A client out of the rules: its deviations shown, its save refused while
// they stay; its rotation and its deletion allowed (Q123).
func TestHydraClientLegacy(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/hydra-clients/legacy", nil).Body.String()
	if !strings.Contains(page, "This client breaks the rules of the ANSSI") || !strings.Contains(page, `value="implicit" checked`) ||
		!strings.Contains(page, "is in http://, which needs tls.allow_http") {
		t.Fatalf("page:\n%s", page)
	}
	form := hydraValues(b, "legacy")
	form.Set("client_name", "Still legacy")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/legacy", form); w.Code != http.StatusUnprocessableEntity || len(h.patches) != 0 {
		t.Errorf("kept out of the rules: %d", w.Code)
	}
	w := b.handed(b.do(http.MethodPost, "/admin/hydra-clients/legacy/rotate", url.Values{"csrf": {b.csrf()}}))
	if w.Code != http.StatusOK || h.get("legacy")["client_secret"] != secretOf(t, page2(w.Body.String())) {
		t.Errorf("rotation: %d\n%s", w.Code, w.Body)
	}
	form = hydraValues(b, "legacy")
	form["grant_types"], form["response_types"], form["redirect_uris"] = []string{"authorization_code"}, []string{"code"}, []string{"https://legacy.test/cb"}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/legacy", form); w.Code != http.StatusSeeOther {
		t.Errorf("brought into the rules: %d\n%s", w.Code, w.Body)
	}
	r.ui.o.AllowHTTP = true
	if w := b.do(http.MethodPost, "/admin/hydra-clients/legacy/delete", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusSeeOther || h.get("legacy") != nil {
		t.Errorf("deletion: %d", w.Code)
	}
}

func page2(s string) page { return page{s} }

// The writes are the role admin's, behind the re-authentication; a client
// without a secret has none to turn.
func TestHydraClientSensitive(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.put(map[string]any{"client_id": "keys", "token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://k.test",
		"grant_types": []any{"client_credentials"}})
	viewer := r.browser()
	viewer.login("victor", password, "")
	if page := viewer.do(http.MethodGet, "/admin/hydra-clients/web", nil).Body.String(); !strings.Contains(page, "<fieldset disabled>") || strings.Contains(page, "/rotate") {
		t.Errorf("a viewer reads:\n%s", page)
	}
	for _, path := range []string{"/admin/hydra-clients", "/admin/hydra-clients/web", "/admin/hydra-clients/web/rotate", "/admin/hydra-clients/web/delete"} {
		if w := viewer.do(http.MethodPost, path, hydraValues(viewer, "web")); w.Code != http.StatusForbidden {
			t.Errorf("a viewer, %s: %d", path, w.Code)
		}
	}
	b := r.browser()
	b.login("alice", password, "")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/keys/rotate", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusConflict || h.get("keys")["client_secret"] != nil {
		t.Errorf("no secret to turn: %d", w.Code)
	}
	r.advance(6 * time.Minute)
	for _, path := range []string{"/admin/hydra-clients/web", "/admin/hydra-clients/web/rotate", "/admin/hydra-clients/web/delete"} {
		if w := b.do(http.MethodPost, path, hydraValues(b, "web")); w.Code != http.StatusForbidden {
			t.Errorf("past the window, %s: %d", path, w.Code)
		}
	}
	if len(h.patches) != 0 || h.get("web") == nil {
		t.Errorf("written: %v", h.patches)
	}
	// Off, the screens are not served.
	off := newRig(t, "http://dispatcher.test")
	ob := off.browser()
	ob.login("alice", password, "")
	if w := ob.do(http.MethodGet, "/admin/hydra-clients", nil); w.Code != http.StatusNotFound || strings.Contains(ob.do(http.MethodGet, "/admin", nil).Body.String(), "Hydra clients") {
		t.Errorf("off: %d", w.Code)
	}
}
