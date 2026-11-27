package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	ory "github.com/ory/hydra-client-go/v26"

	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

var jsonNull = []byte("null")

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), jsonNull) }

// ObjectOf decodes a JSON object with its values as written; null or
// nothing give {}, as Hydra reads an object null. Anything else is not an
// object: false.
func ObjectOf(data json.RawMessage) (Object, bool) {
	if len(bytes.TrimSpace(data)) == 0 || isNull(data) {
		return Object{}, true
	}
	var o Object
	if json.Unmarshal(data, &o) != nil || o == nil {
		return nil, false
	}
	return o, true
}

// values returns o for a model's interface{} members: each value stays the
// JSON as written.
func (o Object) values() map[string]any {
	out := make(map[string]any, len(o))
	for k, v := range o {
		out[k] = v
	}
	return out
}

// MergeClaims merges claims in order (A2): the last value of a claim wins at
// the first level, but a null is ignored. It erases no earlier value and is
// not kept alone, an absent claim being omitted rather than null (OIDC Core
// 5.3.2). The result is never nil: {} without claims.
func MergeClaims(parts ...Object) Object {
	out := Object{}
	for _, p := range parts {
		for k, v := range p {
			if !isNull(v) {
				out[k] = v
			}
		}
	}
	return out
}

// ContextOf merges the consent contexts of the steps, the last one winning
// at the first level, as Symfony did: the context of the final accept before
// the webhook's and x_dispatcher_ref.
func (f *Flow) ContextOf() Object {
	out := Object{}
	for _, s := range f.Steps {
		maps.Copy(out, s.ConsentContext)
	}
	return out
}

// PreviousClaims returns the id_token claims of the steps strictly before
// position k (I2): x_dispatcher_claims before its filtering, {} on the first
// step.
func (f *Flow) PreviousClaims(k int) Object {
	parts := make([]Object, 0, k)
	for _, s := range f.Steps[:max(0, min(k-1, len(f.Steps)))] {
		parts = append(parts, s.IDToken)
	}
	return MergeClaims(parts...)
}

// ReceivedClaims keeps the claims an app receives: those it names in
// receive_claims, all when it names none (nil), none when the list is empty.
func ReceivedClaims(claims Object, app store.App) Object {
	if app.ReceiveClaims == nil {
		return claims
	}
	out := Object{}
	for _, name := range app.ReceiveClaims {
		if v, ok := claims[name]; ok {
			out[name] = v
		}
	}
	return out
}

// receivedReport is claims.filtered for the app of step k reading its request
// (Q132): the names of the claims of the previous steps it receives, those its
// receive_claims leaves out. None when its app is gone, which the request
// answers.
func (f *Flow) receivedReport(env Env, k int) []Report {
	app, ok := env.Config.App(f.Steps[k-1].App)
	if !ok {
		return nil
	}
	previous := f.PreviousClaims(k)
	received := ReceivedClaims(previous, app)
	var dropped []string
	for name := range previous {
		if _, ok := received[name]; !ok {
			dropped = append(dropped, name)
		}
	}
	slices.Sort(dropped)
	return []Report{{Event: "claims.filtered", Debug: true, App: app.ID, Names: &ClaimNames{Claims: names(received), Dropped: append([]string{}, dropped...)}}}
}

// accepted returns the steps whose login is accepted.
func (f *Flow) accepted() []Step {
	var out []Step
	for _, s := range f.Steps {
		if s.LoginOK {
			out = append(out, s)
		}
	}
	return out
}

// ACRAtEnd is the acr the flow will send at its end: the one it declares,
// otherwise min(2, its steps), each of them accepted or skipped by then
// (ACRNow).
func (f *Flow) ACRAtEnd() string {
	if f.ACR != "" {
		return f.ACR
	}
	return strconv.Itoa(min(2, len(f.Steps)))
}

// ACRNow is the acr of the flow at this point: the one the chosen flow
// declares, otherwise min(2, steps whose login is accepted), as Symfony.
func (f *Flow) ACRNow() string {
	if f.ACR != "" {
		return f.ACR
	}
	return strconv.Itoa(min(2, len(f.accepted())))
}

// AMRNow is the amr of the flow at this point: the method of each app whose
// step login is accepted, or, with aggregate_amr_from_login_request, the amr
// those apps sent, end to end. Never nil.
func (f *Flow) AMRNow(env Env) []string {
	out := []string{}
	for _, s := range f.accepted() {
		if env.Config.Settings.AggregateAMRFromLoginRequest {
			out = append(out, s.AMR...)
		} else if app, ok := env.Config.App(s.App); ok && app.Method != "" {
			out = append(out, app.Method)
		}
	}
	return out
}

// SubjectAllowed applies a step's subject_check rule (hardening 3) to the
// subject of its login accept: none lets any pass, equal requires the first
// step's, claim:<name> the value of that claim as the previous steps gave
// it. An unknown rule lets none pass.
func SubjectAllowed(rule, subject, first string, previous Object) bool {
	switch name, isClaim := strings.CutPrefix(rule, "claim:"); {
	case rule == "" || rule == "none":
		return true
	case rule == "equal":
		return subject == first
	case isClaim && name != "":
		var v string
		return json.Unmarshal(previous[name], &v) == nil && v == subject
	}
	return false
}

// request returns the login request of the snapshot, before the
// replacements of the emulated API.
func (f *Flow) request() (ory.OAuth2LoginRequest, error) {
	client, err := hydra.DecodeClient(f.Hydra.Client)
	if err != nil {
		return ory.OAuth2LoginRequest{}, fmt.Errorf("stored client: %w", err)
	}
	oidc, err := hydra.DecodeOIDCContext(f.Hydra.OIDCContext)
	if err != nil {
		return ory.OAuth2LoginRequest{}, fmt.Errorf("stored oidc_context: %w", err)
	}
	r := ory.OAuth2LoginRequest{
		OidcContext:                  oidc,
		RequestUrl:                   f.Hydra.RequestURL,
		RequestedAccessTokenAudience: f.Hydra.Audience,
		RequestedScope:               f.Hydra.Scope,
		SessionId:                    ory.PtrString(f.HydraSessionID),
	}
	if client != nil {
		r.Client = *client
	}
	return r, nil
}

// errAppGone is the error of a request for an app gone from the snapshot:
// without its receive_claims, it would receive every claim.
var errAppGone = errors.New("flow: app gone from the configuration")

// LoginRequestFor is the login request served to the app of step k (EMU-8):
// the snapshot's members, with the step's challenge, the flow's subject ("" on
// the first step), skip false, the claims of the previous steps the app
// receives, and x_dispatcher_restart_url unless the flow is imposed. Hydra's
// challenge is never in it (I7).
func (f *Flow) LoginRequestFor(env Env, ref string, k int) (ory.OAuth2LoginRequest, error) {
	step := f.Steps[k-1]
	app, ok := env.Config.App(step.App)
	if !ok {
		return ory.OAuth2LoginRequest{}, errAppGone
	}
	r, err := f.request()
	if err != nil {
		return r, err
	}
	ext := hydra.Extensions{Claims: ReceivedClaims(f.PreviousClaims(k), app).values(), Locale: f.Locale, Device: step.Device}
	if !f.Imposed {
		ext.RestartURL = RestartURL(env.BaseURL, ref)
	}
	return hydra.LoginRequestForApp(r, hydra.Step{
		Challenge: env.Keys.Challenge(ref, f.Gen, step.App, KindLogin),
		Subject:   f.Subject,
	}, ext), nil
}

// ConsentRequestFor is the consent request served to the app of step k
// (EMU-18): the step's challenges, the flow's subject, the Hydra session as
// login_session_id, acr and amr at this point, the context of the step's
// login accept without the dispatcher's members (A2, I6), and the claims of
// the previous steps, as on the login request.
func (f *Flow) ConsentRequestFor(env Env, ref string, k int) (ory.OAuth2ConsentRequest, error) {
	step := f.Steps[k-1]
	app, ok := env.Config.App(step.App)
	if !ok {
		return ory.OAuth2ConsentRequest{}, errAppGone
	}
	login, err := f.request()
	if err != nil {
		return ory.OAuth2ConsentRequest{}, err
	}
	r := ory.OAuth2ConsentRequest{
		Acr:                          ory.PtrString(f.ACRNow()),
		Amr:                          f.AMRNow(env),
		Client:                       &login.Client,
		Context:                      step.LoginContext,
		LoginSessionId:               ory.PtrString(f.HydraSessionID),
		OidcContext:                  login.OidcContext,
		RequestUrl:                   ory.PtrString(login.RequestUrl),
		RequestedAccessTokenAudience: login.RequestedAccessTokenAudience,
		RequestedScope:               login.RequestedScope,
	}
	return hydra.ConsentRequestForApp(r, hydra.Step{
		Challenge:      env.Keys.Challenge(ref, f.Gen, step.App, KindConsent),
		LoginChallenge: env.Keys.Challenge(ref, f.Gen, step.App, KindLogin),
		Subject:        f.Subject,
	}, hydra.Extensions{Claims: ReceivedClaims(f.PreviousClaims(k), app).values(), Locale: f.Locale})
}
