package adminui

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseClient(t *testing.T) {
	c, err := parseClient(json.RawMessage(`{"client_id":"c1","client_name":"One","token_endpoint_auth_method":"client_secret_basic",
		"redirect_uris":["https://a.test/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],
		"authorization_code_grant_access_token_lifespan":"30m0s","refresh_token_grant_refresh_token_lifespan":null,
		"jwks":{"keys":[]},"metadata":{"dispatcher":{"flows":["simple"],"secret_rotated_at":"2026-01-02T03:04:05Z"},"other":9007199254740993},
		"created_at":"2025-01-01T00:00:00Z","updated_at":"2026-01-02T03:04:05.123456Z","new_of_2.3":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "c1" || c.Lifespans["authorization_code_grant_access_token_lifespan"] != "30m0s" || c.Lifespans["refresh_token_grant_refresh_token_lifespan"] != "" ||
		!slices.Equal(c.Flows, []string{"simple"}) || c.NoFlow || c.HasJWKS || c.UpdatedAt != "2026-01-02T03:04:05.123456Z" {
		t.Errorf("client: %+v", c)
	}
	// The metadata as Hydra holds them, their numbers as written (R43).
	if m, ok := metadataOf(c.Metadata); !ok || m["other"] != json.Number("9007199254740993") {
		t.Errorf("metadata: %s", c.Metadata)
	}
	// Keys: one at least (R43); metadata that are not an object, an empty
	// list of flows.
	for doc, want := range map[string]bool{`{"keys":[{"kty":"EC"}]}`: true, `{"keys":[]}`: false, `{}`: false, `null`: false, `[]`: false} {
		c, err := parseClient(json.RawMessage(`{"client_id":"k","jwks":` + doc + `}`))
		if err != nil || c.HasJWKS != want {
			t.Errorf("jwks %s: %v %v", doc, c.HasJWKS, err)
		}
	}
	for doc, noFlow := range map[string]bool{`[1, "x"]`: false, `{"dispatcher":{"flows":[]}}`: true, `{"dispatcher":"x"}`: false} {
		c, err := parseClient(json.RawMessage(`{"client_id":"m","metadata":` + doc + `}`))
		if err != nil || c.NoFlow != noFlow || len(c.Flows) != 0 {
			t.Errorf("metadata %s: %+v %v", doc, c, err)
		}
	}
	if at, exact := c.secretSince(); !exact || !at.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("secret since: %v %v", at, exact)
	}
	c.SecretRotatedAt = time.Time{}
	if at, exact := c.secretSince(); exact || at.Year() != 2025 {
		t.Errorf("secret since its creation: %v %v", at, exact)
	}
}

// The rules of the ANSSI (Q123), each on its field.
func TestDeviations(t *testing.T) {
	ok := hydraClient{AuthMethod: "client_secret_basic", GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		RedirectURIs: []string{"https://a.test/cb"}, PostLogoutURIs: []string{"https://a.test/bye"}}
	if d := ok.deviations(false); len(d) != 0 {
		t.Errorf("conforming: %v", d)
	}
	for name, c := range map[string]struct {
		change    func(c *hydraClient)
		allowHTTP bool
		field     string
	}{
		"implicit":                     {func(c *hydraClient) { c.GrantTypes = append(c.GrantTypes, "implicit") }, false, "grant_types"},
		"token":                        {func(c *hydraClient) { c.ResponseTypes = []string{"code", "token"} }, false, "response_types"},
		"hybrid":                       {func(c *hydraClient) { c.ResponseTypes = []string{"code id_token"} }, false, "response_types"},
		"no return":                    {func(c *hydraClient) { c.RedirectURIs = nil }, false, "redirect_uris"},
		"http":                         {func(c *hydraClient) { c.RedirectURIs = []string{"http://a.test/cb"} }, false, "redirect_uris"},
		"a joker":                      {func(c *hydraClient) { c.RedirectURIs = []string{"https://*.a.test/cb"} }, false, "redirect_uris"},
		"a fragment":                   {func(c *hydraClient) { c.RedirectURIs = []string{"https://a.test/cb#x"} }, false, "redirect_uris"},
		"relative":                     {func(c *hydraClient) { c.RedirectURIs = []string{"/cb"} }, false, "redirect_uris"},
		"a custom scheme":              {func(c *hydraClient) { c.RedirectURIs = []string{"app://cb"} }, false, "redirect_uris"},
		"logout in http":               {func(c *hydraClient) { c.PostLogoutURIs = []string{"http://a.test/bye"} }, false, "post_logout_redirect_uris"},
		"none for client_credentials":  {func(c *hydraClient) { c.AuthMethod, c.GrantTypes = "none", []string{"client_credentials"} }, false, "token_endpoint_auth_method"},
		"private_key_jwt without keys": {func(c *hydraClient) { c.AuthMethod = "private_key_jwt" }, false, "jwks_uri"},
	} {
		x := ok
		x.GrantTypes, x.ResponseTypes, x.RedirectURIs = slices.Clone(ok.GrantTypes), slices.Clone(ok.ResponseTypes), slices.Clone(ok.RedirectURIs)
		c.change(&x)
		d := x.deviations(c.allowHTTP)
		if len(d) == 0 || !slices.ContainsFunc(d, func(v deviation) bool { return v.Field == c.field }) {
			t.Errorf("%s: %v", name, d)
		}
	}
	http := ok
	http.RedirectURIs = []string{"http://a.test/cb"}
	if d := http.deviations(true); len(d) != 0 {
		t.Errorf("http with tls.allow_http: %v", d)
	}
	keys := ok
	keys.AuthMethod, keys.JWKSURI = "private_key_jwt", "https://a.test/jwks"
	public := ok
	public.AuthMethod = "none"
	if d := append(keys.deviations(false), public.deviations(false)...); len(d) != 0 {
		t.Errorf("keys, public: %v", d)
	}
	if !strings.Contains(returnURIDeviation("https://a.test/cb*", false), "joker") {
		t.Error("a joker at the end")
	}
}
