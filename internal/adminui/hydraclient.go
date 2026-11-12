package adminui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// A client of Hydra as the screens read it (P23): the members the form
// shows, from its JSON whole, which a modification keeps but for them (Q122).

// lifespans are the lifespans of the tokens of the grants the form offers,
// Hydra's members: empty, Hydra's default.
var lifespans = []string{
	"authorization_code_grant_access_token_lifespan", "authorization_code_grant_id_token_lifespan",
	"authorization_code_grant_refresh_token_lifespan", "client_credentials_grant_access_token_lifespan",
	"refresh_token_grant_access_token_lifespan", "refresh_token_grant_id_token_lifespan", "refresh_token_grant_refresh_token_lifespan",
}

// Grants, response types and methods the form offers.
var (
	grantTypes    = []string{"authorization_code", "refresh_token", "client_credentials"}
	responseTypes = []string{"code"}
	authMethods   = []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "none"}
)

// hydraClient is a client of Hydra, its members the form shows.
type hydraClient struct {
	ID, Name, AuthMethod, JWKSURI, LogoURI, Scope string
	RedirectURIs, PostLogoutURIs, GrantTypes      []string
	ResponseTypes, Audience, CORS                 []string
	SkipConsent, HasJWKS                          bool
	// Lifespans are by their members, "" for Hydra's default.
	Lifespans map[string]string
	// Flows are metadata.dispatcher.flows: the flows the client offers, none
	// for every flow.
	Flows []string
	// Metadata is its metadata whole, which a modification keeps but for
	// dispatcher.flows and dispatcher.secret_rotated_at.
	Metadata        map[string]any
	CreatedAt       time.Time
	UpdatedAt       string
	SecretRotatedAt time.Time
}

func parseClient(raw json.RawMessage) (hydraClient, error) {
	var doc struct {
		ID             string          `json:"client_id"`
		Name           string          `json:"client_name"`
		AuthMethod     string          `json:"token_endpoint_auth_method"`
		JWKSURI        string          `json:"jwks_uri"`
		JWKS           json.RawMessage `json:"jwks"`
		LogoURI        string          `json:"logo_uri"`
		Scope          string          `json:"scope"`
		RedirectURIs   []string        `json:"redirect_uris"`
		PostLogoutURIs []string        `json:"post_logout_redirect_uris"`
		GrantTypes     []string        `json:"grant_types"`
		ResponseTypes  []string        `json:"response_types"`
		Audience       []string        `json:"audience"`
		CORS           []string        `json:"allowed_cors_origins"`
		SkipConsent    bool            `json:"skip_consent"`
		Metadata       map[string]any  `json:"metadata"`
		CreatedAt      time.Time       `json:"created_at"`
		UpdatedAt      string          `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return hydraClient{}, err
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(raw, &members) // read above
	c := hydraClient{ID: doc.ID, Name: doc.Name, AuthMethod: doc.AuthMethod, JWKSURI: doc.JWKSURI, LogoURI: doc.LogoURI, Scope: doc.Scope,
		RedirectURIs: doc.RedirectURIs, PostLogoutURIs: doc.PostLogoutURIs, GrantTypes: doc.GrantTypes, ResponseTypes: doc.ResponseTypes,
		Audience: doc.Audience, CORS: doc.CORS, SkipConsent: doc.SkipConsent, Metadata: doc.Metadata, CreatedAt: doc.CreatedAt,
		UpdatedAt: doc.UpdatedAt, Lifespans: map[string]string{}}
	if keys := strings.TrimSpace(string(doc.JWKS)); keys != "" && keys != "null" && keys != "{}" {
		c.HasJWKS = true
	}
	for _, l := range lifespans {
		var v string
		_ = json.Unmarshal(members[l], &v) // a string, or null for the default
		c.Lifespans[l] = v
	}
	if d, ok := doc.Metadata["dispatcher"].(map[string]any); ok {
		if flows, ok := d["flows"].([]any); ok {
			for _, f := range flows {
				if s, ok := f.(string); ok {
					c.Flows = append(c.Flows, s)
				}
			}
		}
		if at, ok := d["secret_rotated_at"].(string); ok {
			c.SecretRotatedAt, _ = time.Parse(time.RFC3339, at)
		}
	}
	return c, nil
}

// secretless tells whether the client has no secret: a public client, or
// one that authenticates by its keys.
func (c hydraClient) secretless() bool {
	return c.AuthMethod == "none" || c.AuthMethod == "private_key_jwt"
}

// secretSince is when its secret was set: by the screen, exact; otherwise its
// creation, at least.
func (c hydraClient) secretSince() (at time.Time, exact bool) {
	if !c.SecretRotatedAt.IsZero() {
		return c.SecretRotatedAt, true
	}
	return c.CreatedAt, false
}

// deviation is a rule of the ANSSI the client breaks (Q123), on a field of
// the form.
type deviation struct{ Field, Message string }

// deviations are the rules of the ANSSI the client breaks (Q123): the implicit
// grant, a response type other than code, an address of return that is not
// absolute in https (http with tls.allow_http) or holds a joker or a
// fragment, the method none for a confidential client, private_key_jwt
// without keys.
func (c hydraClient) deviations(allowHTTP bool) []deviation {
	var d []deviation
	if slices.Contains(c.GrantTypes, "implicit") {
		d = append(d, deviation{"grant_types", "the implicit grant gives tokens in the URL: the ANSSI rules it out, use authorization_code"})
	}
	for _, rt := range c.ResponseTypes {
		if rt != "code" {
			d = append(d, deviation{"response_types", fmt.Sprintf("%q is the implicit or the hybrid flow: code alone", rt)})
		}
	}
	if slices.Contains(c.GrantTypes, "authorization_code") && len(c.RedirectURIs) == 0 {
		d = append(d, deviation{"redirect_uris", "authorization_code needs an address of return"})
	}
	for _, f := range []struct {
		field string
		uris  []string
	}{{"redirect_uris", c.RedirectURIs}, {"post_logout_redirect_uris", c.PostLogoutURIs}} {
		for _, u := range f.uris {
			if why := returnURIDeviation(u, allowHTTP); why != "" {
				d = append(d, deviation{f.field, fmt.Sprintf("%q %s", u, why)})
			}
		}
	}
	if c.AuthMethod == "none" && slices.Contains(c.GrantTypes, "client_credentials") {
		d = append(d, deviation{"token_endpoint_auth_method", "none, for a client of client_credentials: a confidential client authenticates"})
	}
	if c.AuthMethod == "private_key_jwt" && c.JWKSURI == "" && !c.HasJWKS {
		d = append(d, deviation{"jwks_uri", "private_key_jwt needs the keys of the client: its jwks_uri"})
	}
	return d
}

// returnURIDeviation says why an address of return breaks the rules, "" when
// it keeps them: absolute, in https (http with tls.allow_http), without a
// joker nor a fragment.
func returnURIDeviation(raw string, allowHTTP bool) string {
	if strings.Contains(raw, "*") {
		return "holds a joker: the address of return is matched exactly"
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return "is not an absolute URL"
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return "holds a fragment"
	case u.Scheme == "http" && !allowHTTP:
		return "is in http://, which needs tls.allow_http"
	case u.Scheme != "https" && u.Scheme != "http":
		return "is not in https://"
	}
	return ""
}
