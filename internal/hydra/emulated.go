package hydra

import (
	"maps"

	ory "github.com/ory/hydra-client-go/v26"
)

// Extensions are the dispatcher's own fields on the requests the emulated API
// serves to login apps, next to Hydra's.
type Extensions struct {
	// Claims gathered from the consents of the previous steps
	// (x_dispatcher_claims). Always served: {} on the first step.
	Claims map[string]any
	// RestartURL is the flow choice page of this authentication
	// (x_dispatcher_restart_url), omitted when empty.
	RestartURL string
}

// LoginRequestForApp returns a copy of r for the emulated API: collections
// Hydra leaves out or null are served as [], the way the Symfony dispatcher
// served them, and the extensions are added.
func LoginRequestForApp(r ory.OAuth2LoginRequest, ext Extensions) ory.OAuth2LoginRequest {
	r.RequestedScope = nonNil(r.RequestedScope)
	r.RequestedAccessTokenAudience = nonNil(r.RequestedAccessTokenAudience)
	r.AdditionalProperties = withExtensions(r.AdditionalProperties, ext)
	return r
}

// ConsentRequestForApp does the same for a consent request; an empty context
// is served as {}, never [] (a PHP artefact) nor null.
func ConsentRequestForApp(r ory.OAuth2ConsentRequest, ext Extensions) ory.OAuth2ConsentRequest {
	r.RequestedScope = nonNil(r.RequestedScope)
	r.RequestedAccessTokenAudience = nonNil(r.RequestedAccessTokenAudience)
	r.Amr = nonNil(r.Amr)
	if emptyContext(r.Context) {
		r.Context = map[string]any{}
	}
	r.AdditionalProperties = withExtensions(r.AdditionalProperties, ext)
	return r
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func emptyContext(c any) bool {
	switch v := c.(type) {
	case nil:
		return true
	case []any:
		return len(v) == 0
	}
	return false
}

// withExtensions sets the extensions on a copy of props: the SDK serialises
// AdditionalProperties next to the model's own fields.
func withExtensions(props map[string]any, ext Extensions) map[string]any {
	out := maps.Clone(props)
	if out == nil {
		out = map[string]any{}
	}
	claims := ext.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	out["x_dispatcher_claims"] = claims
	if ext.RestartURL != "" {
		out["x_dispatcher_restart_url"] = ext.RestartURL
	}
	return out
}
