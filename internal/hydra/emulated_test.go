package hydra

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata/emulated")

const (
	hydra22   = "flowcodec/testdata/hydra-v2.2.0/"
	symfony21 = "../../testdata/protocol/symfony-hydra-2.1/"
)

// body reads a fixture: a Hydra admin response saved by tools/flowfixtures,
// or the response body of an exchange saved by tools/recorder.
func body(t *testing.T, path string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exchange struct {
		Response struct {
			Body json.RawMessage `json:"body"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &exchange) == nil && exchange.Response.Body != nil {
		return exchange.Response.Body
	}
	return data
}

func decode(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

// diff lists the JSON paths where want and got differ, with both values.
func diff(want, got any, path string) []string {
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok && gok {
		var out []string
		for k, w := range wm {
			if g, ok := gm[k]; ok {
				out = append(out, diff(w, g, path+"."+k)...)
			} else {
				out = append(out, path+"."+k+": dropped")
			}
		}
		for k, g := range gm {
			if _, ok := wm[k]; !ok {
				v, _ := json.Marshal(g)
				out = append(out, path+"."+k+": added "+string(v))
			}
		}
		slices.Sort(out)
		return out
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	return []string{path + ": " + string(w) + " -> " + string(g)}
}

func keys(t *testing.T, data []byte) []string {
	t.Helper()
	var m map[string]any
	decode(t, data, &m)
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// withoutNulls drops null members: the SDK omits null optional fields
// (the client's unset *_lifespan, a logout request's null client), which
// readers treat as absent anyway.
func withoutNulls(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			if x != nil {
				out[k] = withoutNulls(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = withoutNulls(x)
		}
		return out
	}
	return v
}

// The SDK models must carry every value of Hydra's answers, for both
// supported versions: whatever the emulated API re-serves comes through them.
func TestModelsRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		path  string
		model func() any
	}{
		{hydra22 + "login_request.json", func() any { return &ory.OAuth2LoginRequest{} }},
		{hydra22 + "consent_request.json", func() any { return &ory.OAuth2ConsentRequest{} }},
		{symfony21 + "14-sql-2fa-consent-skipped/0032-hydra-GET-admin_oauth2_auth_requests_login.json", func() any { return &ory.OAuth2LoginRequest{} }},
		{symfony21 + "14-sql-2fa-consent-skipped/0069-hydra-GET-admin_oauth2_auth_requests_consent.json", func() any { return &ory.OAuth2ConsentRequest{} }},
		{symfony21 + "13-logout/0029-hydra-GET-admin_oauth2_auth_requests_logout.json", func() any { return &ory.OAuth2LogoutRequest{} }},
	} {
		t.Run(filepath.Base(tt.path), func(t *testing.T) {
			original := body(t, tt.path)
			m := tt.model()
			decode(t, original, m)
			again, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			decode(t, original, &want)
			decode(t, again, &got)
			if d := diff(withoutNulls(want), got, ""); len(d) > 0 {
				t.Errorf("round trip changed the document: %v", d)
			}
		})
	}
}

func golden(t *testing.T, name string, v any) []byte {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "emulated", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Errorf("%s differs from the golden file (go test -update to accept):\n%s", name, got)
	}
	return got
}

func TestLoginRequestForApp(t *testing.T) {
	var r ory.OAuth2LoginRequest
	decode(t, body(t, hydra22+"login_request.json"), &r)
	r.RequestedAccessTokenAudience = nil // as a decrypted flow has it

	first := golden(t, "login_request_first_step.json", LoginRequestForApp(r, Extensions{RestartURL: "http://dispatcher.hydra.test/?login_challenge=L"}))
	var doc map[string]any
	decode(t, first, &doc)
	if !reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) ||
		!reflect.DeepEqual(doc["requested_access_token_audience"], []any{}) ||
		doc["x_dispatcher_restart_url"] != "http://dispatcher.hydra.test/?login_challenge=L" {
		t.Errorf("first step = %s", first)
	}

	second := golden(t, "login_request_second_step.json", LoginRequestForApp(r, Extensions{
		Claims: map[string]any{"email": "test2@test.com", "firstname": "Isabelle", "lastname": "Durand"},
	}))
	doc = nil
	decode(t, second, &doc)
	if _, ok := doc["x_dispatcher_restart_url"]; ok {
		t.Error("x_dispatcher_restart_url served though empty")
	}
	if r.AdditionalProperties != nil && r.AdditionalProperties["x_dispatcher_claims"] != nil {
		t.Error("LoginRequestForApp changed its argument")
	}

	// The login apps keep every field the Symfony dispatcher served them.
	symfony := body(t, symfony21+"14-sql-2fa-consent-skipped/0051-front-GET-oauth2_auth_requests_login.json")
	for _, k := range keys(t, symfony) {
		if !slices.Contains(keys(t, second), k) {
			t.Errorf("field %q served by Symfony is missing", k)
		}
	}
}

func TestConsentRequestForApp(t *testing.T) {
	var r ory.OAuth2ConsentRequest
	decode(t, body(t, hydra22+"consent_request.json"), &r)
	got := golden(t, "consent_request.json", ConsentRequestForApp(r, Extensions{
		Claims: map[string]any{"email": "test2@test.com"},
	}))

	symfony := body(t, symfony21+"14-sql-2fa-consent-skipped/0061-front-GET-oauth2_auth_requests_consent.json")
	for _, k := range keys(t, symfony) {
		if !slices.Contains(keys(t, got), k) {
			t.Errorf("field %q served by Symfony is missing", k)
		}
	}

	for _, empty := range []any{nil, []any{}} {
		r.Context, r.Amr = empty, nil
		out, err := json.Marshal(ConsentRequestForApp(r, Extensions{}))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		decode(t, out, &doc)
		if !reflect.DeepEqual(doc["context"], map[string]any{}) || !reflect.DeepEqual(doc["amr"], []any{}) ||
			!reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) {
			t.Errorf("context %v: served %s", empty, out)
		}
	}
}
