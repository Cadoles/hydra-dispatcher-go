package flow

import (
	"encoding/json"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// consent.claims_filter strict (Q129): the claims of the scopes granted
// alone, on the screen as in what Hydra receives, after the consent webhook,
// by the scopes it grants; permissive, everything.
func TestStrictClaims(t *testing.T) {
	get := Consent{Challenge: hydraC, Cookie: cookie}
	read := func(mod func(r *ory.OAuth2ConsentRequest)) said { return said{consent: consentRequest(lref, mod)} }
	skip := func(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(true) }
	strict := func(e *Env) { e.StrictClaims = true }
	hooked := func(strictly bool) func(e *Env) {
		return func(e *Env) {
			e.StrictClaims = strictly
			e.Config.Settings.ConsentAutoAccept, e.Config.Settings.ConsentAcceptWebhookURL = true, "http://hook.test/"
			e.Config.Scopes = []store.Scope{{Name: "groups", Claims: []store.ScopeClaim{{Claim: "groups"}}}}
		}
	}
	idToken := func(want string) func(t *testing.T, p played) {
		return func(t *testing.T, p played) {
			t.Helper()
			b := p.calls[len(p.calls)-1].AcceptConsent
			if got := rawJSON(b.Session.IdToken); got != want {
				t.Errorf("id_token %s, want %s", got, want)
			}
		}
	}
	answer := &ConsentHookAnswer{GrantScope: []string{"openid", "email", "groups"},
		IDToken: json.RawMessage(`{"email":"alice@example.org","groups":["staff"],"secret_of_the_hook":1}`)}
	for _, tc := range []pageCase{
		{name: "strict, Hydra's skip: step, of no scope asked, not sent", ev: get, stored: acceptedFlow(t), env: strict,
			says: hydraSays{GetConsent: read(skip), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR,
			check: idToken(`{"email":"alice@example.org"}`)},
		{name: "permissive, Hydra's skip: everything sent", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(skip), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR,
			check: idToken(`{"email":"alice@example.org","step":"2fa"}`)},
		{name: "strict, the screen shows what is sent", ev: get, stored: acceptedFlow(t), env: strict,
			says: hydraSays{GetConsent: read(nil)}, kind: ConsentPage, calls: []Op{GetConsent},
			write: func(t *testing.T, f *Flow) {},
			check: func(t *testing.T, p played) {
				if got := rawJSON(p.Response.Consent.Claims); got != `{"email":"alice@example.org"}` {
					t.Errorf("screen %s", got)
				}
			}},
		{name: "strict, the webhook's claims by the scopes it grants", ev: get, stored: acceptedFlow(t), env: hooked(true),
			says: hydraSays{GetConsent: read(nil), ConsentHook: {consentHook: answer}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, ConsentHook, AcceptConsent}, write: finishedWithCR,
			check: idToken(`{"email":"alice@example.org","groups":["staff"]}`)},
		{name: "permissive, the webhook's claims as they are", ev: get, stored: acceptedFlow(t), env: hooked(false),
			says: hydraSays{GetConsent: read(nil), ConsentHook: {consentHook: answer}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, ConsentHook, AcceptConsent}, write: finishedWithCR,
			check: idToken(`{"email":"alice@example.org","groups":["staff"],"secret_of_the_hook":1}`)},
	} {
		tc.run(t)
	}
}
