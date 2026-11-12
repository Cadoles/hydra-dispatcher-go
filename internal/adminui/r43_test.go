package adminui

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cfg "forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
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
	if w := b.do(http.MethodPost, "/admin/hydra-clients/big/rotate", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusOK {
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
		if w := b.do(http.MethodPost, "/admin/hydra-clients/"+id+"/rotate", url.Values{"csrf": {b.csrf()}}); w.Code != http.StatusOK || h.member(id, "metadata") != before {
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
