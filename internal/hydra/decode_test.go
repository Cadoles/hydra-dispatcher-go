package hydra

import (
	"encoding/json"
	"errors"
	"testing"
)

// A 2xx missing what every Hydra request carries, or not JSON, is refused.
func TestDecodeRefusals(t *testing.T) {
	for _, tt := range []struct {
		name         string
		decodeAnswer func([]byte) (any, error)
		body         string
		want         error // nil: any error
	}{
		{"login without client_id", loginAnswer, `{"challenge":"L","client":{},"request_url":"u","skip":false,"subject":""}`, errIncompleteAnswer},
		{"login without request_url", loginAnswer, `{"challenge":"L","client":{"client_id":"c"},"request_url":"","skip":false,"subject":""}`, errIncompleteAnswer},
		{"consent without subject", consentAnswer, `{"challenge":"C","client":{"client_id":"c"},"request_url":"u"}`, errIncompleteAnswer},
		{"consent with a null client", consentAnswer, `{"challenge":"C","subject":"s","client":null,"request_url":"u"}`, errIncompleteAnswer},
		{"logout without request_url", logoutAnswer, `{"challenge":"U","client":null,"subject":"s","sid":"i"}`, errIncompleteAnswer},
		{"logout without subject (Q57)", logoutAnswer, `{"challenge":"U","client":null,"request_url":"u","sid":"i"}`, errIncompleteAnswer},
		{"logout with an empty subject (Q57)", logoutAnswer, `{"challenge":"U","client":null,"request_url":"u","subject":"","sid":"i"}`, errIncompleteAnswer},
		{"logout without sid (Q57)", logoutAnswer, `{"challenge":"U","client":null,"request_url":"u","subject":"s"}`, errIncompleteAnswer},
		{"logout with an empty sid (Q57)", logoutAnswer, `{"challenge":"U","client":null,"request_url":"u","subject":"s","sid":""}`, errIncompleteAnswer},
		{"blank", logoutAnswer, " \n", errEmptyAnswer},
		{"null", consentAnswer, "null", errEmptyAnswer},
		{"not JSON", logoutAnswer, "<html></html>", nil},
		{"client not an object", consentAnswer, `{"challenge":"C","subject":"s","client":"c","request_url":"u"}`, nil},
		{"client of another type", loginAnswer, `{"challenge":"L","client":{"client_id":5},"request_url":"u","skip":false,"subject":""}`, nil},
	} {
		_, err := tt.decodeAnswer([]byte(tt.body))
		if err == nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

// A logout request initiated by a client keeps it, jwks included.
func TestDecodeLogoutClient(t *testing.T) {
	r, err := decodeLogoutRequest([]byte(`{"challenge":"U","subject":"s","sid":"i","request_url":"/oauth2/sessions/logout","rp_initiated":true,
		"client":{"client_id":"c","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(r.Client.AdditionalProperties["jwks"])
	if r.Client.GetClientId() != "c" || string(jwks) != `{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]}` {
		t.Errorf("client = %+v, jwks %s", r.Client, jwks)
	}
}

func TestDecodeOIDCContext(t *testing.T) {
	for _, data := range []string{"", "null"} {
		if o, err := DecodeOIDCContext(json.RawMessage(data)); o != nil || err != nil {
			t.Errorf("DecodeOIDCContext(%q) = %v, %v; want nil, nil", data, o, err)
		}
	}
	if _, err := DecodeOIDCContext(json.RawMessage(`[]`)); err == nil {
		t.Error("an oidc_context that is not an object is decoded")
	}
	// The state store keeps it as JSON: decoded again, it is served as Hydra
	// served it.
	in := `{"acr_values":["a"],"id_token_hint_claims":{"n":123456789012345678901},"x":{"n":123456789012345678901}}`
	o, err := DecodeOIDCContext(json.RawMessage(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("oidc_context\n got %s\nwant %s", out, in)
	}
}
