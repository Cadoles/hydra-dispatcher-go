package hydra

import (
	"bytes"
	"encoding/json"
	"fmt"

	ory "github.com/ory/hydra-client-go/v26"
)

// decodeLoginRequest decodes the login request of a 2xx answer.
func decodeLoginRequest(body []byte) (*ory.OAuth2LoginRequest, error) {
	r, err := decodeRequest(body, func(r *ory.OAuth2LoginRequest, c *ory.OAuth2Client, members map[string]json.RawMessage) {
		if c != nil {
			r.Client = *c
		}
		keepRaw(r.AdditionalProperties, members)
		keepRawOIDCContext(r.OidcContext, members["oidc_context"])
	})
	if err != nil {
		return nil, err
	}
	if err := required(
		member{"challenge", r.Challenge},
		member{"client_id", r.Client.GetClientId()},
		member{"request_url", r.RequestUrl},
	); err != nil {
		return nil, err
	}
	return r, nil
}

// decodeConsentRequest decodes the consent request of a 2xx answer.
func decodeConsentRequest(body []byte) (*ory.OAuth2ConsentRequest, error) {
	r, err := decodeRequest(body, func(r *ory.OAuth2ConsentRequest, c *ory.OAuth2Client, members map[string]json.RawMessage) {
		r.Client = c
		r.Context = raw(members["context"])
		keepRaw(r.AdditionalProperties, members)
		keepRawOIDCContext(r.OidcContext, members["oidc_context"])
	})
	if err != nil {
		return nil, err
	}
	if err := required(
		member{"challenge", r.Challenge},
		member{"subject", r.GetSubject()},
		member{"client_id", r.Client.GetClientId()},
		member{"request_url", r.GetRequestUrl()},
	); err != nil {
		return nil, err
	}
	return r, nil
}

// decodeLogoutRequest decodes the logout request of a 2xx answer. Its client
// is null when the logout was not initiated by one.
func decodeLogoutRequest(body []byte) (*ory.OAuth2LogoutRequest, error) {
	r, err := decodeRequest(body, func(r *ory.OAuth2LogoutRequest, c *ory.OAuth2Client, members map[string]json.RawMessage) {
		r.Client = c
		keepRaw(r.AdditionalProperties, members)
	})
	if err != nil {
		return nil, err
	}
	if err := required(
		member{"challenge", r.GetChallenge()},
		member{"request_url", r.GetRequestUrl()},
	); err != nil {
		return nil, err
	}
	return r, nil
}

// decodeRequest decodes a login, consent or logout request into the SDK's
// model. keep then sets its client, decoded by DecodeClient (nil for null or
// nothing), and puts back from the request's members the values the model
// holds in an interface{} (see keepRaw).
func decodeRequest[T any](body []byte, keep func(*T, *ory.OAuth2Client, map[string]json.RawMessage)) (*T, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errEmptyAnswer
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, err
	}
	if members == nil {
		return nil, errEmptyAnswer
	}
	client, err := DecodeClient(members["client"])
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	if client != nil {
		members["client"] = json.RawMessage("{}") // set once the model is decoded
	}
	data, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	v := new(T)
	if err := json.Unmarshal(data, v); err != nil {
		return nil, err
	}
	keep(v, client, members)
	return v, nil
}

// DecodeClient decodes a client Hydra serves, nil for null or nothing: the
// client of a request the admin API answers, or the one the state store kept
// as JSON. The SDK requires alg, kid and use on every key of a jwks, where RFC 7517 only
// requires kty and Hydra checks the key material alone: one such key would
// fail the whole request. The jwks is therefore kept as Hydra served it, in
// AdditionalProperties, which the SDK serialises over its own fields; GetJwks
// is empty. Its metadata and unknown members are kept as served too (see
// keepRaw).
func DecodeClient(data json.RawMessage) (*ory.OAuth2Client, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return nil, err
	}
	jwks := raw(members["jwks"])
	delete(members, "jwks")
	data, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	var c ory.OAuth2Client
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	c.Metadata = raw(members["metadata"])
	keepRaw(c.AdditionalProperties, members)
	if jwks != nil {
		if c.AdditionalProperties == nil {
			c.AdditionalProperties = map[string]any{}
		}
		c.AdditionalProperties["jwks"] = jwks
	}
	return &c, nil
}

// DecodeOIDCContext decodes an oidc_context as Hydra serves it, nil for null
// or nothing, its unknown members and id_token_hint_claims kept as served
// (see keepRaw).
func DecodeOIDCContext(data json.RawMessage) (*ory.OAuth2ConsentRequestOpenIDConnectContext, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	var o ory.OAuth2ConsentRequestOpenIDConnectContext
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, err
	}
	keepRawOIDCContext(&o, data)
	return &o, nil
}

// keepRaw sets the values of props back to the JSON Hydra served, taken
// from members. The SDK decodes them into interface{}, numbers as float64:
// an integer beyond 2^53, in a client's metadata or a context, would reach
// the login apps changed. Readers decode the json.RawMessage they find.
func keepRaw(props map[string]any, members map[string]json.RawMessage) {
	for k := range props {
		if v, ok := members[k]; ok {
			props[k] = v
		}
	}
}

// keepRawOIDCContext does the same for an oidc_context's unknown members and
// id_token_hint_claims.
func keepRawOIDCContext(o *ory.OAuth2ConsentRequestOpenIDConnectContext, data json.RawMessage) {
	if o == nil {
		return
	}
	members := objectMembers(data)
	keepRaw(o.AdditionalProperties, members)
	keepRaw(o.IdTokenHintClaims, objectMembers(members["id_token_hint_claims"]))
}

// raw returns data for an interface{} field: nil for null or nothing, the
// JSON as served otherwise.
func raw(data json.RawMessage) any {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	return data
}

// objectMembers returns the members of a JSON object, nil for anything else.
func objectMembers(data json.RawMessage) map[string]json.RawMessage {
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil {
		return nil
	}
	return members
}

// member is a request member required to be non-empty.
type member struct{ name, value string }

// required refuses a request without one of the members every Hydra request
// carries, as flowcodec refuses such a decrypted flow: that 2xx does not come
// from Hydra's admin API.
func required(members ...member) error {
	for _, m := range members {
		if m.value == "" {
			return fmt.Errorf("%w: no %s", errIncompleteAnswer, m.name)
		}
	}
	return nil
}
