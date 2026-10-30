package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
)

func TestRef(t *testing.T) {
	// echo -n 0c34aaee066148adbc0251024fee9bb4 | sha256sum, first 20 hex.
	if got := Ref("0c34aaee066148adbc0251024fee9bb4"); got != "c90229d6bf34232d1162" {
		t.Errorf("Ref = %q", got)
	}
	if got := Key("abc"); got != "flow:abc" {
		t.Errorf("Key = %q", got)
	}
}

func TestStateAt(t *testing.T) {
	now := testNow.UnixMilli()
	base := func(mod func(f *Flow)) *Flow {
		f := &Flow{FlowID: "hydra-sql-2fa", Current: 1, Steps: []Step{{App: "sql"}, {App: "2fa"}}, ExpiresAt: now, HydraExpiresAt: now + 1}
		mod(f)
		return f
	}
	for _, tc := range []struct {
		name string
		flow *Flow
		want State
	}{
		{"absent, no flow", nil, Absent},
		{"absent, hx reached (EXP-1, ECR-8)", base(func(f *Flow) { f.HydraExpiresAt = now }), Absent},
		{"choice", base(func(f *Flow) { f.FlowID, f.Current, f.Steps = "", 0, nil }), Choice},
		{"k·0", base(func(f *Flow) {}), StepLogin},
		{"k·L", base(func(f *Flow) { f.Steps[0].LoginOK = true }), StepConsent},
		{"k·LC", base(func(f *Flow) { f.Steps[0].LoginOK, f.Steps[0].ConsentOK = true, true }), StepDone},
		{"k·0 on the second step", base(func(f *Flow) { f.Current = 2; f.Steps[0].LoginOK, f.Steps[0].ConsentOK = true, true }), StepLogin},
		{"accepted", base(func(f *Flow) { f.HydraRedirect = "http://hydra/consent" }), Accepted},
		{"finished", base(func(f *Flow) { f.Done = true; f.ExpiresAt = now - 1 }), Finished},
		{"expired, exp passed (EXP-2)", base(func(f *Flow) { f.ExpiresAt = now - 1 }), Expired},
		{"expired, accepted", base(func(f *Flow) { f.ExpiresAt, f.HydraRedirect = now-1, "http://hydra/consent" }), Expired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.flow.StateAt(testNow); got != tc.want {
				t.Errorf("StateAt = %v; want %v", got, tc.want)
			}
		})
	}
	if s := State(42).String(); s != "state(42)" {
		t.Errorf("unknown state = %q", s)
	}
}

func TestURLs(t *testing.T) {
	base := "http://dispatcher.hydra.test/"
	if got := LoopURL(base, "r"); got != "http://dispatcher.hydra.test/oauth2/auth?ref=r" {
		t.Errorf("LoopURL = %q", got)
	}
	if got := RestartURL(base, "r"); got != "http://dispatcher.hydra.test/?ref=r" {
		t.Errorf("RestartURL = %q", got)
	}
	f := &Flow{HydraRedirect: "http://hydra/oauth2/auth?login_verifier=v"}
	if got := f.ResumeURL(base); got != f.HydraRedirect {
		t.Errorf("Q14, resume before the consent screen = %q", got)
	}
	f.ConsentChallenge = "C/+="
	if got := f.ResumeURL(base); got != "http://dispatcher.hydra.test/consent?consent_challenge=C%2F%2B%3D" {
		t.Errorf("Q14, resume after the consent screen = %q", got)
	}
}

func TestReduce(t *testing.T) {
	f := twoSteps(t)
	f.Hydra.Client = json.RawMessage(`{"client_id":"c","client_uri":"http://client.test/","jwks":{"keys":[]}}`)
	f.HydraRedirect, f.Sent = "http://hydra/r", &SentLogin{Subject: "alice"}
	f.ConsentRedirect, f.ConsentAt = "http://hydra/cr", testNow.UnixMilli()
	r := f.Reduce()
	want := &Flow{
		V:               Format,
		Hydra:           LoginSnapshot{Client: json.RawMessage(`{"client_id":"c","client_uri":"http://client.test/"}`), Scope: []string{}, Audience: []string{}},
		FlowID:          f.FlowID,
		Gen0:            f.Gen0,
		Gen:             f.Gen,
		CSRF:            f.CSRF,
		ConsentRedirect: f.ConsentRedirect,
		ConsentAt:       f.ConsentAt,
		Done:            true,
		ExpiresAt:       f.ExpiresAt,
		HydraExpiresAt:  f.HydraExpiresAt,
	}
	got, _ := Encode(r)
	wantData, _ := Encode(want)
	if !bytes.Equal(got, wantData) {
		t.Errorf("T1, reduced flow\n got %s\nwant %s", got, wantData)
	}
	if r.ClientURI() != "http://client.test/" || r.StateAt(testNow) != Finished {
		t.Errorf("reduced flow: client_uri %q, state %v", r.ClientURI(), r.StateAt(testNow))
	}
	if strings.Contains(string(got), f.LoginChallenge) {
		t.Error("a reduced flow keeps L")
	}
	if (&Flow{Hydra: LoginSnapshot{Client: json.RawMessage(`[]`)}}).ClientURI() != "" {
		t.Error("ClientURI of a client that is not an object")
	}
}

func TestEncodeDecode(t *testing.T) {
	f := twoSteps(t)
	first, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Encode(back)
	if !bytes.Equal(first, again) {
		t.Errorf("Q12, encoding is not stable\nfirst %s\nagain %s", first, again)
	}
	for _, tc := range []struct{ name, data string }{
		{"not JSON", "{"},
		{"other format", `{"v":2}`},
		{"no format", `{}`},
	} {
		if _, err := Decode([]byte(tc.data)); !errors.Is(err, ErrFormat) {
			t.Errorf("Decode, %s: err = %v; want ErrFormat", tc.name, err)
		}
	}
}

func TestSnapshotOf(t *testing.T) {
	r := loginRequest(t)
	snap, sid, err := SnapshotOf(r)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "ba1ce6e4-e93b-401c-b6af-62703fe39df7" || snap.RequestURL != r.RequestUrl || snap.Skip || snap.Subject != "" {
		t.Errorf("snapshot: sid %q, %+v", sid, snap)
	}
	if strings.Join(snap.Scope, " ") != "openid profile email" || snap.Audience == nil || len(snap.Audience) != 0 {
		t.Errorf("scopes %q, audience %#v", snap.Scope, snap.Audience)
	}
	// The client goes back to the apps as Hydra served it.
	back, err := hydra.DecodeClient(snap.Client)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(r.Client)
	got, _ := json.Marshal(back)
	if !bytes.Equal(got, want) {
		t.Errorf("client\n got %s\nwant %s", got, want)
	}

	// A null audience is served []; the oidc_context and a client whose
	// numbers and jwks a float64 or the SDK would change stay as served.
	client, err := hydra.DecodeClient(json.RawMessage(`{"client_id":"c","metadata":{"n":123456789012345678901},"jwks":{"keys":[{"kty":"oct","k":"AA"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	oidc, err := hydra.DecodeOIDCContext(json.RawMessage(`{"ui_locales":["fr"],"id_token_hint_claims":{"n":123456789012345678901}}`))
	if err != nil {
		t.Fatal(err)
	}
	snap, _, err = SnapshotOf(&ory.OAuth2LoginRequest{Client: *client, OidcContext: oidc, Skip: true, Subject: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`123456789012345678901`, `{"kty":"oct","k":"AA"}`} {
		if !strings.Contains(string(snap.Client)+string(snap.OIDCContext), s) {
			t.Errorf("snapshot lost %s: client %s, oidc %s", s, snap.Client, snap.OIDCContext)
		}
	}
	if snap.Audience == nil || snap.Scope == nil || !snap.Skip || snap.Subject != "bob" {
		t.Errorf("snapshot of a bare request: %+v", snap)
	}
}

func TestStepJSON(t *testing.T) {
	// The keys of the doc's structure (v1.3.7), which the table names.
	f := twoSteps(t)
	f.HydraRedirect, f.Sent, f.ConsentChallenge, f.Done = "hr", &SentLogin{}, "cc", true
	f.ConsentRedirect, f.ConsentAt, f.Imposed, f.ACR = "cr", 1, true, "acr"
	data, _ := Encode(f)
	var members map[string]json.RawMessage
	_ = json.Unmarshal(data, &members)
	for _, k := range []string{"v", "l", "sid", "h", "f", "imp", "acr", "g0", "g", "c", "sub", "cur", "steps", "hr", "sent", "cc", "cr", "ct", "done", "exp", "hx"} {
		if _, ok := members[k]; !ok {
			t.Errorf("no member %q in %s", k, data)
		}
	}
	if d := time.Duration(f.HydraExpiresAt-f.ExpiresAt) * time.Millisecond; d != 20*time.Minute {
		t.Errorf("times are not milliseconds: %v", d)
	}
}
