package hydra

import (
	"encoding/json"
	"maps"

	ory "github.com/ory/hydra-client-go/v26"
)

// Step is what the emulated API serves in place of Hydra's own values: an
// app only sees its step's challenges and the subject the previous steps
// established, never Hydra's challenge, nor Hydra's skip (which every login
// app honours by accepting without asking anything).
type Step struct {
	// Challenge is the step's challenge, login or consent.
	Challenge string
	// LoginChallenge is, on a consent request, the step's login challenge.
	LoginChallenge string
	// Subject is the flow's current subject, "" until a step sets it.
	Subject string
}

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

// LoginRequestForApp returns a copy of r for the emulated API: the step's
// challenge and subject, skip always false, collections Hydra leaves out or
// null served as [] the way the Symfony dispatcher served them, and the
// extensions added. The copy is shallow: it shares r's slices, maps and
// nested models, and ext.Claims.
func LoginRequestForApp(r ory.OAuth2LoginRequest, step Step, ext Extensions) ory.OAuth2LoginRequest {
	r.Challenge = step.Challenge
	r.Subject = step.Subject
	r.Skip = false
	r.RequestedScope = nonNil(r.RequestedScope)
	r.RequestedAccessTokenAudience = nonNil(r.RequestedAccessTokenAudience)
	r.AdditionalProperties = withExtensions(r.AdditionalProperties, ext)
	return r
}

// ConsentRequestForApp does the same for a consent request, whose acr, amr
// and context the caller has set to the flow's aggregates; an empty context
// is served as {}, never [] (a PHP artefact) nor null.
func ConsentRequestForApp(r ory.OAuth2ConsentRequest, step Step, ext Extensions) ory.OAuth2ConsentRequest {
	r.Challenge = step.Challenge
	r.LoginChallenge = ory.PtrString(step.LoginChallenge)
	r.Subject = ory.PtrString(step.Subject)
	r.Skip = ory.PtrBool(false)
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

// emptyContext reports whether c serialises as null or []. It looks at the
// JSON, so typed nils count too: a nil map, or the nil json.RawMessage
// flowcodec gives for a flow without context.
func emptyContext(c any) bool {
	if c == nil {
		return true
	}
	data, err := json.Marshal(c)
	if err != nil {
		return false
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return false
	}
	switch v := v.(type) {
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
