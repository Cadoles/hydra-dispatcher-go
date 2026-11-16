package flow

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// uiLocalesServed is the oidc_context.ui_locales of the request the emulated
// API answers r with.
func uiLocalesServed(t *testing.T, r Result) []string {
	t.Helper()
	if r.Response.Status != http.StatusOK {
		t.Fatalf("emulated API: %d %s", r.Response.Status, rawJSON(r.Response.Body))
	}
	var body struct {
		OidcContext struct {
			UILocales []string `json:"ui_locales"`
		} `json:"oidc_context"`
	}
	if err := json.Unmarshal([]byte(rawJSON(r.Response.Body)), &body); err != nil {
		t.Fatal(err)
	}
	return body.OidcContext.UILocales
}

// The language chosen on the dispatcher's pages goes with the flow and to
// the apps, first in the ui_locales of their login and consent requests,
// once (Q138); a request without a choice keeps the one held; Hydra's request
// stays as Hydra gave it. Without a choice, ui_locales are Hydra's.
func TestChosenLocale(t *testing.T) {
	w := newWorld(t)
	w.hydra.login.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{UiLocales: []string{"fr-FR", "EN"}}
	sql := func(a store.App) bool { return a.ID == "sql" }

	w.handle(Entry{LoginChallenge: hydraL})
	if f := w.stored(); f.Locale != "" {
		t.Errorf("no choice: %q", f.Locale)
	}
	step := w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true, Locale: "en"})
	if f := w.stored(); f.Locale != "en" {
		t.Fatalf("chosen in English: %q", f.Locale)
	}
	c := param(t, step, "login_challenge")
	if got := uiLocalesServed(t, w.handle(AppCall{Op: AppGetLogin, Challenge: c, Caller: sql})); !slices.Equal(got, []string{"en", "fr-FR"}) {
		t.Errorf("login request: %q", got)
	}
	if got := w.hydra.login.OidcContext.UiLocales; !slices.Equal(got, []string{"fr-FR", "EN"}) {
		t.Errorf("Hydra's request changed: %q", got)
	}
	if r := w.handle(AppCall{Op: AppAcceptLogin, Challenge: c, Caller: sql, Body: json.RawMessage(`{"subject":"alice"}`)}); r.Response.Status != http.StatusOK {
		t.Fatalf("accept: %d", r.Response.Status)
	}
	// Back without a choice: the one held stays, on the consent too.
	consent := w.handle(Loop{Ref: lref, Cookie: w.cookie})
	if f := w.stored(); f.Locale != "en" {
		t.Errorf("a request without a choice: %q", f.Locale)
	}
	cc := param(t, consent, "consent_challenge")
	if got := uiLocalesServed(t, w.handle(AppCall{Op: AppGetConsent, Challenge: cc, Caller: sql})); !slices.Equal(got, []string{"en", "fr-FR"}) {
		t.Errorf("consent request: %q", got)
	}

	// Another flow, no choice ever: Hydra's ui_locales as they are.
	w = newWorld(t)
	w.hydra.login.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{UiLocales: []string{"fr-FR", "EN"}}
	w.handle(Entry{LoginChallenge: hydraL})
	step = w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	if got := uiLocalesServed(t, w.handle(AppCall{Op: AppGetLogin, Challenge: param(t, step, "login_challenge"), Caller: sql})); !slices.Equal(got, []string{"fr-FR", "EN"}) {
		t.Errorf("without a choice: %q", got)
	}
}
