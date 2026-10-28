package hydra

import (
	"bytes"
	"encoding/json"
	"fmt"

	ory "github.com/ory/hydra-client-go/v26"
)

// decodeLoginRequest decodes the login request of a 2xx answer.
func decodeLoginRequest(body []byte) (*ory.OAuth2LoginRequest, error) {
	r, err := decodeRequest(body, func(r *ory.OAuth2LoginRequest, c *ory.OAuth2Client) { r.Client = *c })
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
	r, err := decodeRequest(body, func(r *ory.OAuth2ConsentRequest, c *ory.OAuth2Client) { r.Client = c })
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
	r, err := decodeRequest(body, func(r *ory.OAuth2LogoutRequest, c *ory.OAuth2Client) { r.Client = c })
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
// model, with its client decoded by decodeClient and set by setClient.
func decodeRequest[T any](body []byte, setClient func(*T, *ory.OAuth2Client)) (*T, error) {
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
	client, err := decodeClient(members["client"])
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
	if client != nil {
		setClient(v, client)
	}
	return v, nil
}

// decodeClient decodes a client Hydra serves, nil for null or nothing. The
// SDK requires alg, kid and use on every key of a jwks, where RFC 7517 only
// requires kty and Hydra checks the key material alone: one such key would
// fail the whole request. The jwks is therefore kept as Hydra served it, in
// AdditionalProperties, which the SDK serialises over its own fields; GetJwks
// is empty.
func decodeClient(data json.RawMessage) (*ory.OAuth2Client, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return nil, err
	}
	jwks := members["jwks"]
	delete(members, "jwks")
	data, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	var c ory.OAuth2Client
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if jwks != nil && string(jwks) != "null" {
		if c.AdditionalProperties == nil {
			c.AdditionalProperties = map[string]any{}
		}
		c.AdditionalProperties["jwks"] = jwks
	}
	return &c, nil
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
