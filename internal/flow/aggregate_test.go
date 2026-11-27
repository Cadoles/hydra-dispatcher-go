package flow

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// js returns the JSON of v, to compare objects whose values are raw.
func js(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func obj(t *testing.T, s string) Object {
	t.Helper()
	o, ok := ObjectOf(json.RawMessage(s))
	if !ok {
		t.Fatalf("%s is not an object", s)
	}
	return o
}

func TestObjectOf(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		ok             bool
	}{
		{"object", `{"a":1}`, `{"a":1}`, true},
		{"EMU-21, object null is {}", `null`, `{}`, true},
		{"nothing is {}", ``, `{}`, true},
		{"EMU-15, list", `[]`, `null`, false},
		{"EMU-15, string", `"a"`, `null`, false},
		{"numbers as written", `{"n":123456789012345678901}`, `{"n":123456789012345678901}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ObjectOf(json.RawMessage(tc.in))
			if ok != tc.ok || js(t, got) != tc.want {
				t.Errorf("ObjectOf(%s) = %s, %v; want %s, %v", tc.in, js(t, got), ok, tc.want, tc.ok)
			}
		})
	}
}

func TestMergeClaims(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
		want  string
	}{
		{"A2, nothing gives {}", nil, `{}`},
		{"A2, last wins", []string{`{"a":1,"b":1}`, `{"b":2}`}, `{"a":1,"b":2}`},
		{"A2, null erases nothing", []string{`{"email":"alice@example.org"}`, `{"email":null}`}, `{"email":"alice@example.org"}`},
		{"A2, null alone is omitted", []string{`{"email":null,"name":"Alice"}`}, `{"name":"Alice"}`},
		{"A2, nested null is a value", []string{`{"address":{"street":null}}`}, `{"address":{"street":null}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var parts []Object
			for _, p := range tc.parts {
				parts = append(parts, obj(t, p))
			}
			if got := js(t, MergeClaims(parts...)); got != tc.want {
				t.Errorf("MergeClaims = %s; want %s", got, tc.want)
			}
		})
	}
}

func TestContextOf(t *testing.T) {
	f := twoSteps(t)
	f.Steps[1].ConsentContext = obj(t, `{"from":"2fa","x":null}`)
	if got := js(t, f.ContextOf()); got != `{"from":"2fa","sql":1,"x":null}` {
		t.Errorf("final accept, context of the consents = %s", got)
	}
	if got := js(t, (&Flow{}).ContextOf()); got != `{}` {
		t.Errorf("no step: %s", got)
	}
}

func TestPreviousClaims(t *testing.T) {
	f := twoSteps(t)
	f.Steps[1].IDToken = obj(t, `{"amr_hint":"otp"}`)
	for _, tc := range []struct {
		name string
		k    int
		want string
	}{
		{"I2, first step gets {}", 1, `{}`},
		{"I2, second step gets the first's", 2, `{"email":"alice@example.org","name":"Alice"}`},
		{"I2, never its own", 3, `{"amr_hint":"otp","email":"alice@example.org","name":"Alice"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := js(t, f.PreviousClaims(tc.k)); got != tc.want {
				t.Errorf("PreviousClaims(%d) = %s; want %s", tc.k, got, tc.want)
			}
		})
	}
}

func TestReceivedClaims(t *testing.T) {
	claims := Object{"email": json.RawMessage(`"a@b"`), "name": json.RawMessage(`"A"`)}
	for _, tc := range []struct {
		name   string
		claims []string
		want   string
	}{
		{"no receive_claims, all", nil, `{"email":"a@b","name":"A"}`},
		{"receive_claims", []string{"email", "phone"}, `{"email":"a@b"}`},
		{"receive_claims empty", []string{}, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := js(t, ReceivedClaims(claims, store.App{ReceiveClaims: tc.claims})); got != tc.want {
				t.Errorf("ReceivedClaims = %s; want %s", got, tc.want)
			}
		})
	}
}

func TestACRAndAMR(t *testing.T) {
	env := testEnv()
	f := twoSteps(t)
	if got := f.ACRNow(); got != "1" {
		t.Errorf("final accept, acr of one step accepted = %q", got)
	}
	f.Steps[1].LoginOK, f.Steps[1].AMR = true, []string{"otp", "mfa"}
	if got := f.ACRNow(); got != "2" {
		t.Errorf("final accept, acr of two steps = %q", got)
	}
	if got := (&Flow{Steps: []Step{{LoginOK: true}, {LoginOK: true}, {LoginOK: true}}}).ACRNow(); got != "2" {
		t.Errorf("final accept, min(2, n) = %q", got)
	}
	f.ACR = "urn:acr:mfa"
	if got := f.ACRNow(); got != "urn:acr:mfa" {
		t.Errorf("final accept, the flow's acr = %q", got)
	}
	if got := f.AMRNow(env); !reflect.DeepEqual(got, []string{"pwd", "otp"}) {
		t.Errorf("final accept, amr from the methods = %q", got)
	}
	env.Config.Settings.AggregateAMRFromLoginRequest = true
	if got := f.AMRNow(env); !reflect.DeepEqual(got, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("final accept, amr aggregated = %q", got)
	}
	if got := (&Flow{}).AMRNow(env); got == nil || len(got) != 0 {
		t.Errorf("no step: amr %#v", got)
	}
	env.Config.Settings.AggregateAMRFromLoginRequest = false
	if got := (&Flow{Steps: []Step{{App: "gone", LoginOK: true}}}).AMRNow(env); len(got) != 0 {
		t.Errorf("app gone from the snapshot: amr %q", got)
	}
}

func TestSubjectAllowed(t *testing.T) {
	previous := Object{"email": json.RawMessage(`"alice@example.org"`), "n": json.RawMessage(`1`)}
	for _, tc := range []struct {
		name, rule, subject string
		want                bool
	}{
		{"EMU-11, none", "none", "bob", true},
		{"EMU-11, empty rule is none", "", "bob", true},
		{"EMU-11, equal", "equal", "alice", true},
		{"EMU-12, equal", "equal", "bob", false},
		{"EMU-11, claim", "claim:email", "alice@example.org", true},
		{"EMU-12, claim differs", "claim:email", "alice", false},
		{"EMU-12, claim absent", "claim:phone", "alice", false},
		{"EMU-12, claim not a string", "claim:n", "1", false},
		{"EMU-12, claim without name", "claim:", "", false},
		{"EMU-12, unknown rule", "same", "alice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SubjectAllowed(tc.rule, tc.subject, "alice", previous); got != tc.want {
				t.Errorf("SubjectAllowed(%q, %q) = %v", tc.rule, tc.subject, got)
			}
		})
	}
}

func TestLoginRequestFor(t *testing.T) {
	env := testEnv()
	f := twoSteps(t)
	ref := Ref(f.LoginChallenge)
	r, err := f.LoginRequestFor(env, ref, 2)
	if err != nil {
		t.Fatal(err)
	}
	served := js(t, r)
	for _, tc := range []struct{ name, member, want string }{
		{"EMU-8, the step's challenge", "challenge", `"` + testKeys.Challenge(ref, 1003, "2fa", KindLogin) + `"`},
		{"EMU-8, the flow's subject", "subject", `"alice"`},
		{"EMU-8, skip false", "skip", `false`},
		{"EMU-8, session_id", "session_id", `"ba1ce6e4-e93b-401c-b6af-62703fe39df7"`},
		{"EMU-8, scopes", "requested_scope", `["openid","profile","email"]`},
		{"EMU-8, audience []", "requested_access_token_audience", `[]`},
		{"EMU-8, oidc_context {}", "oidc_context", `{}`},
		{"EMU-8 I2, claims the app receives", "x_dispatcher_claims", `{"email":"alice@example.org"}`},
		{"EMU-8 A1, restart URL in ref", "x_dispatcher_restart_url", `"http://dispatcher.hydra.test/?ref=` + ref + `"`},
	} {
		var members map[string]json.RawMessage
		_ = json.Unmarshal([]byte(served), &members)
		if got := string(members[tc.member]); got != tc.want {
			t.Errorf("%s: %s = %s; want %s", tc.name, tc.member, got, tc.want)
		}
	}
	if strings.Contains(served, f.LoginChallenge) {
		t.Error("I7, Hydra's challenge served to an app")
	}

	f.Imposed = true
	r, _ = f.LoginRequestFor(env, ref, 1)
	served = js(t, r)
	if strings.Contains(served, "x_dispatcher_restart_url") {
		t.Error("EMU-8, restart URL of an imposed flow")
	}
	if !strings.Contains(served, `"x_dispatcher_claims":{}`) || !strings.Contains(served, `"subject":"alice"`) {
		t.Errorf("EMU-8, first step: %s", served)
	}

	f.Hydra.Client = json.RawMessage(`[]`)
	if _, err := f.LoginRequestFor(env, ref, 1); err == nil {
		t.Error("a stored client that is not an object")
	}
	f.Hydra.Client, f.Hydra.OIDCContext = json.RawMessage(`{}`), json.RawMessage(`[]`)
	if _, err := f.LoginRequestFor(env, ref, 1); err == nil {
		t.Error("a stored oidc_context that is not an object")
	}
}

func TestConsentRequestFor(t *testing.T) {
	env := testEnv()
	f := twoSteps(t)
	ref := Ref(f.LoginChallenge)
	f.Steps[1].LoginOK, f.Steps[1].Subject = true, "alice"
	f.Steps[1].LoginContext = obj(t, `{"email":"alice@example.org","x_dispatcher_ref":"forged"}`)
	r, err := f.ConsentRequestFor(env, ref, 2)
	if err != nil {
		t.Fatal(err)
	}
	served := js(t, r)
	var members map[string]json.RawMessage
	_ = json.Unmarshal([]byte(served), &members)
	for _, tc := range []struct{ name, member, want string }{
		{"EMU-18, the step's challenge", "challenge", `"` + testKeys.Challenge(ref, 1003, "2fa", KindConsent) + `"`},
		{"EMU-18, its login challenge", "login_challenge", `"` + testKeys.Challenge(ref, 1003, "2fa", KindLogin) + `"`},
		{"EMU-18, subject", "subject", `"alice"`},
		{"EMU-18, skip false", "skip", `false`},
		{"EMU-18, login_session_id", "login_session_id", `"ba1ce6e4-e93b-401c-b6af-62703fe39df7"`},
		{"EMU-18, acr at this point", "acr", `"2"`},
		{"EMU-18, amr at this point", "amr", `["pwd","otp"]`},
		{"EMU-18 A2 I6, the step's login context", "context", `{"email":"alice@example.org"}`},
		{"EMU-18 I2, claims", "x_dispatcher_claims", `{"email":"alice@example.org"}`},
		{"EMU-18, client", "client", ""},
	} {
		got := string(members[tc.member])
		if tc.want == "" {
			if got == "" {
				t.Errorf("%s: no %s", tc.name, tc.member)
			}
		} else if got != tc.want {
			t.Errorf("%s: %s = %s; want %s", tc.name, tc.member, got, tc.want)
		}
	}
	if strings.Contains(served, f.LoginChallenge) || strings.Contains(served, "restart") {
		t.Errorf("I7: %s", served)
	}

	f.Steps[0].LoginContext = nil
	r, _ = f.ConsentRequestFor(env, ref, 1)
	if got := js(t, r.Context); got != `{}` {
		t.Errorf("EMU-18, empty context = %s", got)
	}
	f.Hydra.Client = json.RawMessage(`[]`)
	if _, err := f.ConsentRequestFor(env, ref, 1); err == nil {
		t.Error("a stored client that is not an object")
	}
}
