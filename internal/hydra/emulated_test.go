package hydra

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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
	hydra23   = "flowcodec/testdata/hydra-v2.3.0/"
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

// missing lists the members of want absent from got, or of another JSON
// type, through nested objects.
func missing(want, got any, path string) []string {
	wm, ok := want.(map[string]any)
	if !ok {
		return nil
	}
	gm, _ := got.(map[string]any)
	var out []string
	for k, w := range wm {
		g, ok := gm[k]
		switch {
		case !ok:
			out = append(out, path+"."+k+": missing")
		case w != nil && reflect.TypeOf(w) != reflect.TypeOf(g):
			out = append(out, fmt.Sprintf("%s.%s: %T served as %T", path, k, w, g))
		default:
			out = append(out, missing(w, g, path+"."+k)...)
		}
	}
	slices.Sort(out)
	return out
}

// servesSymfonyFields checks the login apps keep every field the Symfony
// dispatcher served them, with its JSON type, client and oidc_context
// included.
func servesSymfonyFields(t *testing.T, symfonyExchange string, served []byte) {
	t.Helper()
	var want, got any
	decode(t, body(t, symfonyExchange), &want)
	decode(t, served, &got)
	for _, m := range missing(want, got, "") {
		t.Errorf("field served by Symfony: %s", m)
	}
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

// The SDK models must carry every value of Hydra's answers, for every
// supported version: whatever the emulated API re-serves comes through them.
func TestModelsRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		path  string
		model func() any
	}{
		{hydra22 + "login_request.json", func() any { return &ory.OAuth2LoginRequest{} }},
		{hydra22 + "consent_request.json", func() any { return &ory.OAuth2ConsentRequest{} }},
		{hydra23 + "login_request.json", func() any { return &ory.OAuth2LoginRequest{} }},
		{hydra23 + "consent_request.json", func() any { return &ory.OAuth2ConsentRequest{} }},
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
	// A Hydra skip the dispatcher ignores: no app may see it.
	r.Skip, r.Subject = true, "hydra-subject"
	hydraChallenge := r.Challenge

	first := golden(t, "login_request_first_step.json", LoginRequestForApp(r,
		Step{Challenge: "step-login-challenge-1"},
		Extensions{RestartURL: "http://dispatcher.hydra.test/?login_challenge=L"}))
	var doc map[string]any
	decode(t, first, &doc)
	if doc["challenge"] != "step-login-challenge-1" || doc["subject"] != "" || doc["skip"] != false ||
		!reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) ||
		!reflect.DeepEqual(doc["requested_access_token_audience"], []any{}) ||
		doc["x_dispatcher_restart_url"] != "http://dispatcher.hydra.test/?login_challenge=L" {
		t.Errorf("first step = %s", first)
	}

	second := golden(t, "login_request_second_step.json", LoginRequestForApp(r,
		Step{Challenge: "step-login-challenge-2", Subject: "test2@test.com"},
		Extensions{Claims: map[string]any{"email": "test2@test.com", "firstname": "Isabelle", "lastname": "Durand"}}))
	doc = nil
	decode(t, second, &doc)
	if doc["challenge"] != "step-login-challenge-2" || doc["subject"] != "test2@test.com" || doc["skip"] != false {
		t.Errorf("second step = %s", second)
	}
	if _, ok := doc["x_dispatcher_restart_url"]; ok {
		t.Error("x_dispatcher_restart_url served though empty")
	}
	if r.Challenge != hydraChallenge || !r.Skip || r.Subject != "hydra-subject" ||
		r.AdditionalProperties != nil && r.AdditionalProperties["x_dispatcher_claims"] != nil {
		t.Error("LoginRequestForApp changed its argument")
	}

	servesSymfonyFields(t, symfony21+"14-sql-2fa-consent-skipped/0051-front-GET-oauth2_auth_requests_login.json", second)
}

func TestConsentRequestForApp(t *testing.T) {
	var r ory.OAuth2ConsentRequest
	decode(t, body(t, hydra22+"consent_request.json"), &r)
	r.Skip = ory.PtrBool(true)
	step := Step{Challenge: "step-consent-challenge-2", LoginChallenge: "step-login-challenge-2", Subject: "test2@test.com"}
	got := golden(t, "consent_request.json", ConsentRequestForApp(r, step, Extensions{
		Claims: map[string]any{"email": "test2@test.com"},
	}))
	var doc map[string]any
	decode(t, got, &doc)
	if doc["challenge"] != step.Challenge || doc["login_challenge"] != step.LoginChallenge ||
		doc["subject"] != step.Subject || doc["skip"] != false {
		t.Errorf("consent request = %s", got)
	}
	servesSymfonyFields(t, symfony21+"14-sql-2fa-consent-skipped/0061-front-GET-oauth2_auth_requests_consent.json", got)

	var nilRaw json.RawMessage
	for _, tt := range []struct {
		context any
		want    any
	}{
		{nil, map[string]any{}},
		{[]any{}, map[string]any{}},
		{map[string]any(nil), map[string]any{}},
		{nilRaw, map[string]any{}}, // flowcodec's flow without context
		{json.RawMessage(" null "), map[string]any{}},
		{json.RawMessage("[]"), map[string]any{}},
		{json.RawMessage(`{"step":1}`), map[string]any{"step": 1.0}},
		{[]any{"a"}, []any{"a"}}, // any JSON is a context for Hydra
	} {
		r.Context, r.Amr = tt.context, nil
		out, err := json.Marshal(ConsentRequestForApp(r, step, Extensions{}))
		if err != nil {
			t.Fatal(err)
		}
		doc = nil
		decode(t, out, &doc)
		if !reflect.DeepEqual(doc["context"], tt.want) || !reflect.DeepEqual(doc["amr"], []any{}) ||
			!reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) {
			t.Errorf("context %#v: served %s", tt.context, out)
		}
	}
}
