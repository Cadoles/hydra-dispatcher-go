package hydra

import (
	"encoding/json"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra/flowcodec"
)

// LoginRequestOf is the login request Hydra's admin API serves for the login
// challenge whose decrypted flow is f (P7, DEC-3 of Table de transitions.md):
// the document Hydra 2.2 and 2.3 write, decoded as decodeLoginRequest decodes
// theirs, so that both modes give the engine the same request. The audience
// Hydra keeps null in the flow is served [], as its admin API does.
func LoginRequestOf(challenge string, f *flowcodec.Flow) (*ory.OAuth2LoginRequest, error) {
	return decodedAs(decodeLoginRequest, struct {
		Challenge         string          `json:"challenge"`
		Client            json.RawMessage `json:"client"`
		OIDCContext       json.RawMessage `json:"oidc_context,omitempty"`
		RequestURL        string          `json:"request_url"`
		RequestedScope    []string        `json:"requested_scope"`
		RequestedAudience []string        `json:"requested_access_token_audience"`
		SessionID         string          `json:"session_id,omitempty"`
		Skip              bool            `json:"skip"`
		Subject           string          `json:"subject"`
	}{
		Challenge:         challenge,
		Client:            f.Client,
		OIDCContext:       f.OpenIDConnectContext,
		RequestURL:        f.RequestURL,
		RequestedScope:    nonNil(f.RequestedScope),
		RequestedAudience: nonNil(f.RequestedAudience),
		SessionID:         f.SessionID,
		Skip:              f.LoginSkip,
		Subject:           f.Subject,
	})
}

// ConsentRequestOf is the consent request Hydra's admin API serves for the
// consent challenge whose decrypted flow is f, as LoginRequestOf: its
// login_challenge is the flow's id, not the encrypted login challenge, and
// acr, amr and context are those of the login accept. An acr the accept did
// not give is served "", as the admin API does (consent_accepted of
// testdata/errors).
func ConsentRequestOf(challenge string, f *flowcodec.Flow) (*ory.OAuth2ConsentRequest, error) {
	return decodedAs(decodeConsentRequest, struct {
		Challenge         string          `json:"challenge"`
		Client            json.RawMessage `json:"client"`
		OIDCContext       json.RawMessage `json:"oidc_context,omitempty"`
		RequestURL        string          `json:"request_url"`
		RequestedScope    []string        `json:"requested_scope"`
		RequestedAudience []string        `json:"requested_access_token_audience"`
		Skip              bool            `json:"skip"`
		Subject           string          `json:"subject"`
		LoginChallenge    string          `json:"login_challenge"`
		LoginSessionID    string          `json:"login_session_id,omitempty"`
		ACR               string          `json:"acr"`
		AMR               []string        `json:"amr"`
		Context           json.RawMessage `json:"context,omitempty"`
	}{
		Challenge:         challenge,
		Client:            f.Client,
		OIDCContext:       f.OpenIDConnectContext,
		RequestURL:        f.RequestURL,
		RequestedScope:    nonNil(f.RequestedScope),
		RequestedAudience: nonNil(f.RequestedAudience),
		Skip:              f.ConsentSkip,
		Subject:           f.Subject,
		LoginChallenge:    f.ID,
		LoginSessionID:    f.SessionID,
		ACR:               f.ACR,
		AMR:               nonNil(f.AMR),
		Context:           f.Context,
	})
}

// decodedAs marshals doc and decodes it with decode, the admin API's decoder.
func decodedAs[T any](decode func([]byte) (*T, error), doc any) (*T, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return decode(data)
}
