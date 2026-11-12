package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The catalogue of the scopes: the standard ones first, renamed alone; those
// of the business created, changed, deleted.
func TestScopesResource(t *testing.T) {
	r := newResources(t)
	type claimJ struct {
		Claim string            `json:"claim"`
		Label map[string]string `json:"label"`
	}
	type scopeJ struct {
		Name    string            `json:"name"`
		Label   map[string]string `json:"label"`
		Claims  []claimJ          `json:"claims"`
		Builtin bool              `json:"builtin"`
	}
	list := func() []scopeJ {
		w := r.do(r.reader, http.MethodGet, Prefix+"/scopes", "", "")
		var l []scopeJ
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &l) != nil {
			t.Fatalf("list: %d %s", w.Code, w.Body)
		}
		return l
	}
	l := list()
	if len(l) != 5 || l[0].Name != "openid" || l[1].Name != "profile" || !l[1].Builtin || len(l[1].Claims) != 14 || l[4].Name != "phone" {
		t.Fatalf("standard: %+v", l)
	}

	if w := r.do(r.all, http.MethodPost, Prefix+"/scopes", "application/json", `{"name":"groups","label":{"fr":"Vos groupes"},"claims":[{"claim":"groups","label":{"fr":"Groupes"}}]}`); w.Code != http.StatusCreated ||
		w.Header().Get("Location") != Prefix+"/scopes/groups" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	for body, want := range map[string]int{
		`{"name":"profile"}`:                        http.StatusConflict,
		`{"name":"groups"}`:                         http.StatusConflict,
		`{"name":"my scope"}`:                       http.StatusUnprocessableEntity,
		`{"name":"x","claims":[{"label":{}}]}`:      http.StatusUnprocessableEntity,
		`{"name":"x","other":1}`:                    http.StatusUnprocessableEntity,
		`{"name":"x","builtin":true,"claims":null}`: http.StatusCreated,
	} {
		if w := r.do(r.all, http.MethodPost, Prefix+"/scopes", "application/json", body); w.Code != want {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	w := r.do(r.all, http.MethodPut, Prefix+"/scopes/profile", "application/json", `{"label":{"fr":"Qui vous êtes"},"claims":[{"claim":"picture","label":{"fr":"Votre photo"}}]}`)
	var p scopeJ
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &p) != nil || !p.Builtin || len(p.Claims) != 14 || p.Label["fr"] != "Qui vous êtes" {
		t.Fatalf("profile renamed: %d %s", w.Code, w.Body)
	}
	for _, c := range p.Claims {
		if c.Claim == "picture" && c.Label["fr"] != "Votre photo" || c.Claim == "name" && len(c.Label) != 0 {
			t.Errorf("claim %+v", c)
		}
	}
	if w := r.do(r.all, http.MethodPatch, Prefix+"/scopes/profile", "application/json", `{"claims":[{"claim":"groups"}]}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a claim added to a standard: %d", w.Code)
	}
	if w := r.do(r.all, http.MethodPatch, Prefix+"/scopes/groups", "application/merge-patch+json", `{"label":{"en":"Your groups"}}`); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"claims":[{"claim":"groups","label":{"fr":"Groupes"}}]`) {
		t.Errorf("patch keeps the claims: %d %s", w.Code, w.Body)
	}
	if w := r.do(r.all, http.MethodPut, Prefix+"/scopes/groups", "application/json", `{"name":"other"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("another name: %d", w.Code)
	}
	if w := r.do(r.reader, http.MethodGet, Prefix+"/scopes/email", "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"builtin":true`) {
		t.Errorf("email: %d %s", w.Code, w.Body)
	}
	if w := r.do(r.reader, http.MethodGet, Prefix+"/scopes/nothing", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("nothing: %d", w.Code)
	}
	// A scope named as a URL, its slashes escaped in the path.
	if w := r.do(r.all, http.MethodPost, Prefix+"/scopes", "application/json", `{"name":"https://api.test/read"}`); w.Code != http.StatusCreated {
		t.Fatalf("a URL: %d %s", w.Code, w.Body)
	}
	if w := r.do(r.reader, http.MethodGet, Prefix+"/scopes/https:%2F%2Fapi.test%2Fread", "", ""); w.Code != http.StatusOK {
		t.Errorf("a URL read: %d %s", w.Code, w.Body)
	}
	if l := list(); len(l) != 8 || l[5].Name != "groups" || l[6].Name != "https://api.test/read" || l[7].Name != "x" {
		t.Errorf("catalogue: %+v", l)
	}
	for path, want := range map[string]int{Prefix + "/scopes/profile": http.StatusConflict, Prefix + "/scopes/groups": http.StatusNoContent, Prefix + "/scopes/nothing": http.StatusNotFound} {
		if w := r.do(r.all, http.MethodDelete, path, "", ""); w.Code != want {
			t.Errorf("delete %s: %d", path, w.Code)
		}
	}
	// The scope of the catalogue, admin:read reading it.
	if w := r.do(r.flows, http.MethodGet, Prefix+"/scopes", "", ""); w.Code != http.StatusForbidden {
		t.Errorf("admin:flows reads: %d", w.Code)
	}
	if w := r.do(r.reader, http.MethodPost, Prefix+"/scopes", "application/json", `{"name":"y"}`); w.Code != http.StatusForbidden {
		t.Errorf("admin:read writes: %d", w.Code)
	}
	if audit := strings.Join(r.wrote, "\n"); !strings.Contains(audit, "all POST scopes groups name,label,claims") || !strings.Contains(audit, "all DELETE scopes groups") {
		t.Errorf("audit:\n%s", audit)
	}
}
