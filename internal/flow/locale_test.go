package flow

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
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
	// The flow keeps Hydra's request as Hydra gave it: the language goes to
	// the apps, never into the snapshot (R49).
	if got := string(w.stored().Hydra.OIDCContext); !strings.Contains(got, `"ui_locales":["fr-FR","EN"]`) {
		t.Errorf("Hydra's request changed: %s", got)
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

// The device of the browser at the start of the flow (phase 4): each step
// keeps the value of its app, served to it as x_dispatcher_device on its
// login request alone; another app another value; without a device, none.
func TestDeviceToTheApps(t *testing.T) {
	dev := Device{ID: []byte("0123456789abcdef0123456789abcdef"), Created: 1_794_000_000}
	if v := DeviceValue(dev.ID, "sql"); v == DeviceValue(dev.ID, "2fa") || v != DeviceValue(append([]byte{}, dev.ID...), "sql") {
		t.Fatal("DeviceValue")
	}
	w := newWorld(t)
	sql := func(a store.App) bool { return a.ID == "sql" }
	w.handle(Entry{LoginChallenge: hydraL})
	step := w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true, Device: dev})
	f := w.stored()
	if f.DeviceAt != dev.Created || f.Steps[0].Device != DeviceValue(dev.ID, "sql") || f.Steps[1].Device != DeviceValue(dev.ID, "2fa") {
		t.Fatalf("flow: %+v", f)
	}
	raw := w.handle(AppCall{Op: AppGetLogin, Challenge: param(t, step, "login_challenge"), Caller: sql}).Response.Body
	var body map[string]any
	if err := json.Unmarshal([]byte(rawJSON(raw)), &body); err != nil || body["x_dispatcher_device"] != DeviceValue(dev.ID, "sql") {
		t.Errorf("login request: %v %v", body["x_dispatcher_device"], err)
	}

	w = newWorld(t)
	w.handle(Entry{LoginChallenge: hydraL})
	step = w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	raw = w.handle(AppCall{Op: AppGetLogin, Challenge: param(t, step, "login_challenge"), Caller: sql}).Response.Body
	body = nil
	if _ = json.Unmarshal([]byte(rawJSON(raw)), &body); body["x_dispatcher_device"] != nil || w.stored().DeviceAt != 0 {
		t.Errorf("without a device: %v", body["x_dispatcher_device"])
	}
}

// The enrollment (phase 4): x_dispatcher_remember_until of a login accept is
// told, a date of another form told as ignored, unquoted.
func TestRememberedDevice(t *testing.T) {
	for raw, want := range map[string]Report{
		`"2027-05-16T10:00:00+02:00"`: {Event: "device.remembered", App: "2fa", Detail: "2027-05-16T08:00:00Z"},
		`"next year"`:                 {Event: "device.remember_ignored", App: "2fa"},
		`12`:                          {Event: "device.remember_ignored", App: "2fa"},
	} {
		if got, ok := rememberedDevice("2fa", Object{"x_dispatcher_remember_until": json.RawMessage(raw)}); !ok || got != want {
			t.Errorf("%s: %+v %v", raw, got, ok)
		}
	}
	if _, ok := rememberedDevice("2fa", Object{"email": json.RawMessage(`"a@b"`)}); ok {
		t.Error("without the member")
	}
}

// Each event of the pages carries the language (R49): an entry writes it on
// the flow it creates, a way back that writes (BCL-8) on the flow it
// advances; back at the choice (ENT-3), the flow keeps it; a flow without
// one writes no lc.
func TestChosenLocaleEvents(t *testing.T) {
	w := newWorld(t)
	w.handle(Entry{LoginChallenge: hydraL, Locale: "en"})
	if f := w.stored(); f.Locale != "en" {
		t.Fatalf("entry: %q", f.Locale)
	}
	w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	gen := w.stored().Gen
	w.handle(Entry{LoginChallenge: hydraL, Cookie: w.cookie})
	if f := w.stored(); f.Gen == gen || f.Current != 0 || f.Locale != "en" {
		t.Errorf("back at the choice: gen %d to %d, current %d, %q", gen, f.Gen, f.Current, f.Locale)
	}

	w = newWorld(t)
	w.handle(Entry{LoginChallenge: hydraL})
	step := w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
	if r := w.handle(Loop{Ref: lref, Cookie: w.cookie, Locale: "de"}); r.Response.Kind != Redirect {
		t.Fatalf("loop: %+v", r.Response)
	}
	if f := w.stored(); f.Current != 2 || f.Locale != "de" {
		t.Errorf("loop: current %d, %q", f.Current, f.Locale)
	}

	data, err := json.Marshal(Flow{FlowID: "f"})
	if err != nil || strings.Contains(string(data), `"lc"`) {
		t.Errorf("a flow without a language: %s %v", data, err)
	}
}

// Another browser takes the flow over (ENT-5 by the login challenge, POS-3
// by the choice): the first browser's language does not go with it, its own
// does (R49).
func TestChosenLocaleOtherBrowser(t *testing.T) {
	for name, takeOver := range map[string]func(w *world, other string) Result{
		"ENT-5": func(w *world, other string) Result { return w.handle(Entry{LoginChallenge: hydraL, Cookie: other}) },
		"POS-3": func(w *world, other string) Result {
			return w.handle(Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: other, Cookie: other, SameOrigin: true})
		},
	} {
		w := newWorld(t)
		w.handle(Entry{LoginChallenge: hydraL, Locale: "en"})
		other := strings.Repeat("ef", 32)
		if r := takeOver(w, other); r.Response.SetCSRF != other {
			t.Fatalf("%s: not taken over: %+v", name, r.Response)
		}
		if f := w.stored(); f.Locale != "" || f.CSRF != other {
			t.Errorf("%s: the first browser's language: %q", name, f.Locale)
		}
		w = newWorld(t)
		w.handle(Entry{LoginChallenge: hydraL, Locale: "en"})
		w.handle(Entry{LoginChallenge: hydraL, Cookie: other, Locale: "fr"})
		if f := w.stored(); f.Locale != "fr" {
			t.Errorf("%s: its own language: %q", name, f.Locale)
		}
	}
}
