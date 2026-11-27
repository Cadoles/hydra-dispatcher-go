package adminui

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cfg "github.com/Cadoles/hydra-dispatcher-go/internal/config"
	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra"
)

// The tests of the revue R43.

// conforming is a client of Hydra within the rules, its metadata as given.
func conforming(id, metadata string) string {
	return `{"client_id":"` + id + `","client_name":"N","token_endpoint_auth_method":"client_secret_basic",` +
		`"redirect_uris":["https://n.test/cb"],"grant_types":["authorization_code"],"response_types":["code"],"scope":"openid",` +
		`"authorization_code_grant_access_token_lifespan":"1h30m0s","created_at":"2025-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z",` +
		`"metadata":` + metadata + `}`
}

// B1: the metadata stay as Hydra holds them, numbers as written, an empty
// list of flows (no flow) included: a save unchanged writes nothing, a
// rotation adds its time alone, a change of the flows them alone; metadata
// that cannot hold the flows refuse them, and the rotation leaves them.
func TestHydraMetadataKept(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.putJSON(conforming("big", `{"id":9007199254740993,"f":1.50,"dispatcher":{"flows":[]}}`))
	h.putJSON(conforming("odd", `{"dispatcher":"x","n":1.50}`))
	h.putJSON(conforming("list", `[1, 2.50]`))
	b := r.browser()
	b.login("alice", password, "")

	page := b.do(http.MethodGet, "/admin/hydra-clients/big", nil).Body.String()
	if !strings.Contains(page, "Its metadata list no flow") || !strings.Contains(page, "9007199254740993") {
		t.Errorf("page:\n%s", page)
	}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/big", hydraValues(b, "big")); w.Code != http.StatusSeeOther || len(h.patches) != 0 {
		t.Fatalf("unchanged: %d, patches %v", w.Code, h.patches)
	}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/big/rotate", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusSeeOther {
		t.Fatalf("rotation: %d", w.Code)
	}
	m := h.member("big", "metadata")
	for _, want := range []string{`"id":9007199254740993`, `"f":1.50`, `"flows":[]`, `"secret_rotated_at":"`} {
		if !strings.Contains(m, want) {
			t.Errorf("after the rotation, no %s: %s", want, m)
		}
	}
	form := hydraValues(b, "big")
	form["flows"] = []string{"simple"}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/big", form); w.Code != http.StatusSeeOther {
		t.Fatalf("flows: %d\n%s", w.Code, w.Body)
	}
	if m := h.member("big", "metadata"); !strings.Contains(m, `"id":9007199254740993`) || !strings.Contains(m, `"f":1.50`) || !strings.Contains(m, `"flows":["simple"]`) ||
		!strings.Contains(m, `"secret_rotated_at"`) {
		t.Errorf("after the flows: %s", m)
	}

	// The flows of metadata that cannot hold them: refused, nothing written.
	for _, id := range []string{"odd", "list"} {
		patches := len(h.patches)
		form := hydraValues(b, id)
		form["flows"] = []string{"simple"}
		if w := b.do(http.MethodPost, "/admin/hydra-clients/"+id, form); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "are not a JSON object") ||
			len(h.patches) != patches {
			t.Errorf("%s, its flows: %d\n%s", id, w.Code, w.Body)
		}
		before := h.member(id, "metadata")
		if w := b.do(http.MethodPost, "/admin/hydra-clients/"+id+"/rotate", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusSeeOther || h.member(id, "metadata") != before {
			t.Errorf("%s, its rotation: %d, metadata %s", id, w.Code, h.member(id, "metadata"))
		}
	}
	if list := b.do(http.MethodGet, "/admin/hydra-clients", nil).Body.String(); !strings.Contains(list, ">list</a>") || !strings.Contains(list, ">odd</a>") {
		t.Errorf("a client of odd metadata missing from the list:\n%s", list)
	}
}

// B2: a 5xx of Hydra is logged by its operation and status, never its error
// document.
func TestHydraFailureLogged(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	withHydra(r)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error","error_description":"FROM-HYDRA client_secret=XYZ"}`))
	}))
	defer srv.Close()
	c, err := hydra.New(cfg.Hydra{AdminURL: srv.URL, Timeout: cfg.Duration(time.Second), MaxInFlight: 1}, cfg.TLS{MinVersion: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	r.ui.o.HydraClients, r.ui.o.Logger = c, slog.New(slog.NewTextHandler(&log, nil))
	b := r.browser()
	b.login("alice", password, "")
	if w := b.do(http.MethodGet, "/admin/hydra-clients/web", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Hydra down: %d", w.Code)
	}
	if got := log.String(); !strings.Contains(got, "admin.hydra_failed") || !strings.Contains(got, "op=get_oauth2_client") || !strings.Contains(got, "status=500") ||
		strings.Contains(got, "FROM-HYDRA") || strings.Contains(got, "XYZ") || strings.Contains(got, "server_error") {
		t.Errorf("log: %s", got)
	}
}

// B3: Hydra never empties a lifespan it holds; the form refuses to, and
// writes nothing.
func TestHydraLifespanHeld(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.putJSON(conforming("held", `{}`))
	b := r.browser()
	b.login("alice", password, "")
	form := hydraValues(b, "held")
	form.Set("authorization_code_grant_access_token_lifespan", "")
	w := b.do(http.MethodPost, "/admin/hydra-clients/held", form)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "is held by Hydra, which never empties it") || len(h.patches) != 0 || len(r.wrote()) != 0 {
		t.Errorf("emptied: %d, patches %v\n%s", w.Code, h.patches, w.Body)
	}
	if h.member("held", "authorization_code_grant_access_token_lifespan") != `"1h30m0s"` {
		t.Errorf("lifespan: %s", h.member("held", "authorization_code_grant_access_token_lifespan"))
	}
}

// B4: private_key_jwt by jwks without a key is out of the rules.
func TestHydraEmptyKeys(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.putJSON(`{"client_id":"nokeys","token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]},"grant_types":["client_credentials"],"metadata":{}}`)
	b := r.browser()
	b.login("alice", password, "")
	page := b.do(http.MethodGet, "/admin/hydra-clients/nokeys", nil).Body.String()
	if !strings.Contains(page, "private_key_jwt needs the keys") {
		t.Errorf("page:\n%s", page)
	}
	form := hydraValues(b, "nokeys")
	form.Set("client_name", "Still none")
	if w := b.do(http.MethodPost, "/admin/hydra-clients/nokeys", form); w.Code != http.StatusUnprocessableEntity || len(h.patches) != 0 {
		t.Errorf("saved without a key: %d", w.Code)
	}
}

// Reports: under a filter by name, the total of Hydra, that of all its
// clients, is not shown; the order of the boxes is no change; the creation
// and the confirmation of a rotation are behind the re-authentication.
func TestHydraReportsOfR43(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.putJSON(`{"client_id":"twin","client_name":"Legacy","grant_types":["authorization_code"],"metadata":{}}`)
	b := r.browser()
	b.login("alice", password, "")
	if page := b.do(http.MethodGet, "/admin/hydra-clients?q=Legacy", nil).Body.String(); !strings.Contains(page, "2 clients named Legacy.") {
		t.Errorf("named:\n%s", page)
	}
	if page := b.do(http.MethodGet, "/admin/hydra-clients", nil).Body.String(); !strings.Contains(page, "3 clients.") {
		t.Errorf("all:\n%s", page)
	}
	form := hydraValues(b, "web")
	form["grant_types"] = []string{"refresh_token", "authorization_code"}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/web", form); w.Code != http.StatusSeeOther || len(h.patches) != 0 {
		t.Errorf("the boxes in another order: %d, patches %v", w.Code, h.patches)
	}
	r.advance(6 * time.Minute)
	values := url.Values{"csrf": {b.csrf()}, "client_name": {"Late"}, "redirect_uris": {"https://late.test/cb"}, "grant_types": {"authorization_code"},
		"response_types": {"code"}, "token_endpoint_auth_method": {"client_secret_basic"}}
	if w := b.do(http.MethodPost, "/admin/hydra-clients", values); w.Code != http.StatusForbidden || len(h.order) != 3 {
		t.Errorf("a creation past the window: %d, clients %v", w.Code, h.order)
	}
	if w := b.do(http.MethodGet, "/admin/hydra-clients/web/rotate", nil); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/admin/reauth") {
		t.Errorf("the confirmation of a rotation past the window: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// A client Hydra holds with a member of another type than the form's stays
// in the list, its page saying why; its secret is turned and it is deleted as
// any other, never written by the form (revue R43).
func TestHydraClientUnreadable(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	h.putRaw(map[string]json.RawMessage{"client_id": rawOf("odd"), "client_name": rawOf("Odd"), "token_endpoint_auth_method": rawOf("client_secret_basic"),
		"audience": rawOf("not-a-list"), "metadata": json.RawMessage(`{"team":"odd","n":12345678901234567890}`)})
	b := r.browser()
	b.login("alice", password, "")
	list := b.do(http.MethodGet, "/admin/hydra-clients", nil).Body.String()
	if !strings.Contains(list, `<a href="/admin/hydra-clients/odd">odd</a></td><td>Odd</td>`) || !strings.Contains(list, "unreadable here") {
		t.Fatalf("list:\n%s", list)
	}
	page := b.do(http.MethodGet, "/admin/hydra-clients/odd", nil)
	if body := page.Body.String(); page.Code != http.StatusOK || !strings.Contains(body, "cannot be changed here") || !strings.Contains(body, "audience") ||
		!strings.Contains(body, `href="/admin/hydra-clients/odd/rotate"`) || !strings.Contains(body, `href="/admin/hydra-clients/odd/delete"`) ||
		strings.Contains(body, `name="client_name"`) {
		t.Fatalf("page: %d\n%s", page.Code, body)
	}
	// Its version as a form would carry it: refused all the same.
	raw, _ := r.ui.o.HydraClients.OAuthClient(context.Background(), "odd")
	odd, _ := parseClient(raw)
	if odd.Unreadable == "" {
		t.Fatalf("read whole: %+v", odd)
	}
	if w := b.do(http.MethodPost, "/admin/hydra-clients/odd", url.Values{"csrf": {b.csrf()}, "version": {version(odd)}, "client_name": {"Renamed"},
		"token_endpoint_auth_method": {"client_secret_basic"}, "grant_types": {"authorization_code"}, "response_types": {"code"},
		"redirect_uris": {"https://odd.test/cb"}, "scope": {"openid"}}); w.Code != http.StatusConflict ||
		h.get("odd")["client_name"] != "Odd" {
		t.Errorf("written by the form: %d %v", w.Code, h.get("odd"))
	}
	confirm := b.do(http.MethodGet, "/admin/hydra-clients/odd/rotate", nil)
	if w := b.do(http.MethodPost, "/admin/hydra-clients/odd/rotate", url.Values{"csrf": {token(t, confirm)}}); w.Code >= 400 || h.get("odd")["client_secret"] == nil {
		t.Errorf("rotation: %d\n%s", w.Code, w.Body)
	}
	if got := string(h.clients["odd"]["metadata"]); !strings.Contains(got, `"n":12345678901234567890`) || !strings.Contains(got, "secret_rotated_at") {
		t.Errorf("metadata after the rotation: %s", got)
	}
	confirm = b.do(http.MethodGet, "/admin/hydra-clients/odd/delete", nil)
	if w := b.do(http.MethodPost, "/admin/hydra-clients/odd/delete", url.Values{"csrf": {token(t, confirm)}}); w.Code != http.StatusSeeOther || h.get("odd") != nil {
		t.Errorf("deletion: %d", w.Code)
	}
}

// A secret just made is shown by a page of its own, once: its reload, or the
// back of the browser, shows it no more nor makes the client again; another
// account, or a minute later, neither (revue R43). The cookie that carries it
// holds it sealed.
func TestSecretHandedOnce(t *testing.T) {
	r := newRig(t, "http://dispatcher.test")
	h := withHydra(r)
	b := r.browser()
	b.login("alice", password, "")
	values := url.Values{"csrf": {b.csrf()}, "client_name": {"Shop"}, "redirect_uris": {"https://shop.test/cb"}, "grant_types": {"authorization_code"},
		"response_types": {"code"}, "scope": {"openid"}, "token_endpoint_auth_method": {"client_secret_basic"}}
	w := b.do(http.MethodPost, "/admin/hydra-clients", values)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/secret" || strings.Contains(w.Body.String(), "readonly value") {
		t.Fatalf("create: %d\n%s", w.Code, w.Body)
	}
	cookie := *b.cookies[secretCookie]
	clients := len(h.order)
	shown := b.do(http.MethodGet, "/admin/secret", nil)
	secret := secretOf(t, page{shown.Body.String()})
	if strings.Contains(cookie.Value, secret) || b.cookies[secretCookie] != nil {
		t.Errorf("the cookie: %q, kept %v", cookie.Value, b.cookies[secretCookie])
	}
	again := b.do(http.MethodGet, "/admin/secret", nil)
	if again.Code != http.StatusGone || strings.Contains(again.Body.String(), secret) || len(h.order) != clients {
		t.Errorf("reloaded: %d, clients %d\n%s", again.Code, len(h.order), again.Body)
	}
	// The cookie of before, replayed: by another account, or past its minute.
	v := r.browser()
	v.login("victor", password, "")
	v.cookies[secretCookie] = &cookie
	if w := v.do(http.MethodGet, "/admin/secret", nil); w.Code != http.StatusGone || strings.Contains(w.Body.String(), secret) {
		t.Errorf("another account: %d", w.Code)
	}
	b.cookies[secretCookie] = &cookie
	r.advance(secretWait + time.Second)
	if w := b.do(http.MethodGet, "/admin/secret", nil); w.Code != http.StatusGone || strings.Contains(w.Body.String(), secret) {
		t.Errorf("a minute later: %d", w.Code)
	}
	// Without a cookie at all.
	if w := b.do(http.MethodGet, "/admin/secret", nil); w.Code != http.StatusGone {
		t.Errorf("none: %d", w.Code)
	}
}
