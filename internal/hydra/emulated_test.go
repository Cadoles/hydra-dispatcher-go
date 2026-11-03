package hydra

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata/emulated")

const (
	hydra22   = "flowcodec/testdata/hydra-v2.2.0/"
	hydra23   = "flowcodec/testdata/hydra-v2.3.0/"
	symfony21 = "../../testdata/protocol/symfony-hydra-2.1/"
)

// body reads a fixture: a Hydra admin response saved by tools/flowfixtures,
// or the response body of an exchange saved by tools/recorder.
func body(t *testing.T, path string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var exchange struct {
		Response struct {
			Body json.RawMessage `json:"body"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &exchange) == nil && exchange.Response.Body != nil {
		return exchange.Response.Body
	}
	return data
}

// decode keeps numbers as written: through a float64, an integer changed
// beyond 2^53 would compare equal.
func decode(t *testing.T, data []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

// diff lists the JSON paths where want and got differ, with both values.
func diff(want, got any, path string) []string {
	wm, wok := want.(map[string]any)
	gm, gok := got.(map[string]any)
	if wok && gok {
		var out []string
		for k, w := range wm {
			if g, ok := gm[k]; ok {
				out = append(out, diff(w, g, path+"."+k)...)
			} else {
				out = append(out, path+"."+k+": dropped")
			}
		}
		for k, g := range gm {
			if _, ok := wm[k]; !ok {
				v, _ := json.Marshal(g)
				out = append(out, path+"."+k+": added "+string(v))
			}
		}
		slices.Sort(out)
		return out
	}
	if reflect.DeepEqual(want, got) {
		return nil
	}
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	return []string{path + ": " + string(w) + " -> " + string(g)}
}

// missing lists the members of want absent from got, or of another JSON
// type, through nested objects. Arrays may hold other values: their first
// elements are compared, when both have one.
func missing(want, got any, path string) []string {
	var out []string
	check := func(w, g any, ok bool, path string) {
		switch {
		case !ok:
			out = append(out, path+": missing")
		case w != nil && reflect.TypeOf(w) != reflect.TypeOf(g):
			out = append(out, fmt.Sprintf("%s: %T served as %T", path, w, g))
		default:
			out = append(out, missing(w, g, path)...)
		}
	}
	switch w := want.(type) {
	case map[string]any:
		gm, _ := got.(map[string]any)
		for k, v := range w {
			g, ok := gm[k]
			check(v, g, ok, path+"."+k)
		}
	case []any:
		if g, _ := got.([]any); len(w) > 0 && len(g) > 0 {
			check(w[0], g[0], true, path+"[0]")
		}
	}
	slices.Sort(out)
	return out
}

// servesSymfonyFields checks the login apps keep every field the Symfony
// dispatcher served them, with its JSON type, client and oidc_context
// included.
func servesSymfonyFields(t *testing.T, symfonyExchange string, served []byte) {
	t.Helper()
	var want, got any
	decode(t, body(t, symfonyExchange), &want)
	decode(t, served, &got)
	for _, m := range missing(want, got, "") {
		t.Errorf("field served by Symfony: %s", m)
	}
}

// withoutClientNulls drops the null members the SDK omits: the client's
// unset fields (its *_lifespan, skip_logout_consent) and a logout request's
// null client, which readers treat as absent anyway. A null anywhere else
// is a value the round trip must keep.
func withoutClientNulls(doc map[string]any) map[string]any {
	if c, ok := doc["client"]; ok && c == nil {
		delete(doc, "client")
	}
	client, _ := doc["client"].(map[string]any)
	maps.DeleteFunc(client, func(_ string, v any) bool { return v == nil })
	return doc
}

// roundTrip decodes a 2xx answer as the client does, then serialises the
// model again, as the emulated API does.
func roundTrip(t *testing.T, original []byte, decodeAnswer func([]byte) (any, error)) []string {
	t.Helper()
	m, err := decodeAnswer(original)
	if err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	decode(t, original, &want)
	decode(t, again, &got)
	return diff(withoutClientNulls(want), got, "")
}

func loginAnswer(b []byte) (any, error)   { return decodeLoginRequest(b) }
func consentAnswer(b []byte) (any, error) { return decodeConsentRequest(b) }
func logoutAnswer(b []byte) (any, error)  { return decodeLogoutRequest(b) }

// The SDK models must carry every value of Hydra's answers, for every
// supported version: whatever the emulated API re-serves comes through them.
func TestModelsRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		path         string
		decodeAnswer func([]byte) (any, error)
	}{
		{hydra22 + "login_request.json", loginAnswer},
		{hydra22 + "consent_request.json", consentAnswer},
		{hydra23 + "login_request.json", loginAnswer},
		{hydra23 + "consent_request.json", consentAnswer},
		{symfony21 + "14-sql-2fa-consent-skipped/0032-hydra-GET-admin_oauth2_auth_requests_login.json", loginAnswer},
		{symfony21 + "14-sql-2fa-consent-skipped/0069-hydra-GET-admin_oauth2_auth_requests_consent.json", consentAnswer},
		{symfony21 + "01-skip/0002-hydra-GET-admin_oauth2_auth_requests_login.json", loginAnswer},
		{symfony21 + "01-skip/0005-hydra-GET-admin_oauth2_auth_requests_consent.json", consentAnswer},
		{symfony21 + "13-logout/0029-hydra-GET-admin_oauth2_auth_requests_logout.json", logoutAnswer},
	} {
		t.Run(filepath.Base(tt.path), func(t *testing.T) {
			if d := roundTrip(t, body(t, tt.path), tt.decodeAnswer); len(d) > 0 {
				t.Errorf("round trip changed the document: %v", d)
			}
		})
	}
}

// A client's jwks comes back as Hydra served it, even with keys the SDK's
// model refuses: RFC 7517 only requires kty, Hydra checks the key material.
func TestJWKSKeptAsServed(t *testing.T) {
	jwks := map[string]any{"keys": []any{
		map[string]any{"kty": "EC", "crv": "P-256",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
		map[string]any{"kty": "EC", "crv": "P-256", "kid": "k2", "use": "sig", "alg": "ES256",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
	}}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	var set ory.JsonWebKeySet
	if json.Unmarshal(data, &set) == nil {
		t.Error("the SDK's model takes a key without alg, kid or use: DecodeClient may decode the jwks again")
	}
	for _, tt := range []struct {
		path         string
		decodeAnswer func([]byte) (any, error)
	}{
		{hydra22 + "login_request.json", loginAnswer},
		{hydra22 + "consent_request.json", consentAnswer},
	} {
		var doc map[string]any
		decode(t, body(t, tt.path), &doc)
		doc["client"].(map[string]any)["jwks"] = jwks
		original, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if d := roundTrip(t, original, tt.decodeAnswer); len(d) > 0 {
			t.Errorf("%s: round trip changed the document: %v", tt.path, d)
		}
	}
}

// Integers beyond 2^53 come back as Hydra served them, wherever the SDK's
// models hold an interface{}: a float64 would change them.
func TestNumbersKeptAsServed(t *testing.T) {
	const big = json.Number("12345678901234567891")
	for _, tt := range []struct {
		path         string
		decodeAnswer func([]byte) (any, error)
	}{
		{hydra22 + "login_request.json", loginAnswer},
		{hydra22 + "consent_request.json", consentAnswer},
		{symfony21 + "13-logout/0029-hydra-GET-admin_oauth2_auth_requests_logout.json", logoutAnswer},
	} {
		var doc map[string]any
		decode(t, body(t, tt.path), &doc)
		doc["x_hydra_next"] = map[string]any{"n": big}
		if client, ok := doc["client"].(map[string]any); ok {
			client["metadata"] = map[string]any{"tenant": big}
			client["x_hydra_next"] = big
		}
		if oidc, ok := doc["oidc_context"].(map[string]any); ok {
			oidc["id_token_hint_claims"] = map[string]any{"uid": big}
			oidc["x_hydra_next"] = big
		}
		if _, ok := doc["context"]; ok {
			doc["context"] = map[string]any{"uid": big}
		}
		original, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if d := roundTrip(t, original, tt.decodeAnswer); len(d) > 0 {
			t.Errorf("%s: round trip changed the document: %v", tt.path, d)
		}
	}
}

// loginRequest and consentRequest decode a fixture as the client does.
func loginRequest(t *testing.T, path string) ory.OAuth2LoginRequest {
	t.Helper()
	r, err := decodeLoginRequest(body(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return *r
}

func consentRequest(t *testing.T, path string) ory.OAuth2ConsentRequest {
	t.Helper()
	r, err := decodeConsentRequest(body(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return *r
}

func golden(t *testing.T, name string, v any) []byte {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "emulated", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Errorf("%s differs from the golden file (go test -update to accept):\n%s", name, got)
	}
	return got
}

func TestLoginRequestForApp(t *testing.T) {
	r := loginRequest(t, hydra22+"login_request.json")
	r.RequestedAccessTokenAudience = nil // as a decrypted flow has it
	// A Hydra skip the dispatcher ignores: no app may see it.
	r.Skip, r.Subject = true, "hydra-subject"
	hydraChallenge := r.Challenge

	first := golden(t, "login_request_first_step.json", LoginRequestForApp(r,
		Step{Challenge: "step-login-challenge-1"},
		Extensions{RestartURL: "http://dispatcher.hydra.test/?login_challenge=L"}))
	var doc map[string]any
	decode(t, first, &doc)
	if doc["challenge"] != "step-login-challenge-1" || doc["subject"] != "" || doc["skip"] != false ||
		!reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) ||
		!reflect.DeepEqual(doc["requested_access_token_audience"], []any{}) ||
		doc["x_dispatcher_restart_url"] != "http://dispatcher.hydra.test/?login_challenge=L" {
		t.Errorf("first step = %s", first)
	}

	second := golden(t, "login_request_second_step.json", LoginRequestForApp(r,
		Step{Challenge: "step-login-challenge-2", Subject: "test2@test.com"},
		Extensions{Claims: map[string]any{"email": "test2@test.com", "firstname": "Isabelle", "lastname": "Durand"}}))
	doc = nil
	decode(t, second, &doc)
	if doc["challenge"] != "step-login-challenge-2" || doc["subject"] != "test2@test.com" || doc["skip"] != false {
		t.Errorf("second step = %s", second)
	}
	if _, ok := doc["x_dispatcher_restart_url"]; ok {
		t.Error("x_dispatcher_restart_url served though empty")
	}
	if r.Challenge != hydraChallenge || !r.Skip || r.Subject != "hydra-subject" ||
		r.AdditionalProperties != nil && r.AdditionalProperties["x_dispatcher_claims"] != nil {
		t.Error("LoginRequestForApp changed its argument")
	}

	servesSymfonyFields(t, symfony21+"14-sql-2fa-consent-skipped/0051-front-GET-oauth2_auth_requests_login.json", second)
}

func TestConsentRequestForApp(t *testing.T) {
	r := consentRequest(t, hydra22+"consent_request.json")
	r.Skip = ory.PtrBool(true)
	hydraChallenge, hydraLoginChallenge := r.Challenge, r.GetLoginChallenge()
	step := Step{Challenge: "step-consent-challenge-2", LoginChallenge: "step-login-challenge-2", Subject: "test2@test.com"}
	served, err := ConsentRequestForApp(r, step, Extensions{
		Claims: map[string]any{"email": "test2@test.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := golden(t, "consent_request.json", served)
	var doc map[string]any
	decode(t, got, &doc)
	if doc["challenge"] != step.Challenge || doc["login_challenge"] != step.LoginChallenge ||
		doc["subject"] != step.Subject || doc["skip"] != false {
		t.Errorf("consent request = %s", got)
	}
	if r.Challenge != hydraChallenge || r.GetLoginChallenge() != hydraLoginChallenge || !r.GetSkip() ||
		r.AdditionalProperties != nil && r.AdditionalProperties["x_dispatcher_claims"] != nil {
		t.Error("ConsentRequestForApp changed its argument")
	}
	servesSymfonyFields(t, symfony21+"14-sql-2fa-consent-skipped/0061-front-GET-oauth2_auth_requests_consent.json", got)

	var nilRaw json.RawMessage
	for _, tt := range []struct {
		context any
		want    any // nil: refused
	}{
		{nil, map[string]any{}},
		{[]any{}, map[string]any{}},
		{map[string]any(nil), map[string]any{}},
		{nilRaw, map[string]any{}}, // flowcodec's flow without context
		{json.RawMessage{}, map[string]any{}},
		{json.RawMessage(" "), map[string]any{}},
		{json.RawMessage(" null "), map[string]any{}},
		{json.RawMessage("[]"), map[string]any{}},
		{json.RawMessage(`{"step":1}`), map[string]any{"step": json.Number("1")}},
		// The dispatcher's own members stay out, numbers as they were.
		{json.RawMessage(`{"uid":12345678901234567891,"x_dispatcher_ref":"r"}`), map[string]any{"uid": json.Number("12345678901234567891")}},
		{map[string]any{"step": 1, "x_dispatcher_ref": "r", "x_dispatcher_skipped_steps": []string{"otp"}}, map[string]any{"step": json.Number("1")}},
		// Hydra accepts any JSON, but apps decode the context into a map.
		{[]any{"a"}, nil},
		{json.RawMessage(`"a"`), nil},
		{false, nil},
		{func() {}, nil},
	} {
		r.Context, r.Amr = tt.context, nil
		served, err := ConsentRequestForApp(r, step, Extensions{})
		if tt.want == nil {
			if err == nil {
				t.Errorf("context %#v served, want refused", tt.context)
			}
			continue
		}
		if err != nil {
			t.Fatalf("context %#v: %v", tt.context, err)
		}
		out, err := json.Marshal(served)
		if err != nil {
			t.Fatal(err)
		}
		doc = nil
		decode(t, out, &doc)
		if !reflect.DeepEqual(doc["context"], tt.want) || !reflect.DeepEqual(doc["amr"], []any{}) ||
			!reflect.DeepEqual(doc["x_dispatcher_claims"], map[string]any{}) {
			t.Errorf("context %#v: served %s", tt.context, out)
		}
	}

	ctx := map[string]any{"step": 1, "x_dispatcher_ref": "r"}
	r.Context = ctx
	if _, err := ConsentRequestForApp(r, step, Extensions{}); err != nil || ctx["x_dispatcher_ref"] != "r" {
		t.Errorf("ConsentRequestForApp changed the context it was given: %v, %v", ctx, err)
	}
}

// From a model that leaves them nil, as one built from a decrypted flow may,
// the members Hydra always serves are served all the same.
func TestServedFromBareModels(t *testing.T) {
	login, err := json.Marshal(LoginRequestForApp(ory.OAuth2LoginRequest{}, Step{Challenge: "c1"}, Extensions{}))
	if err != nil {
		t.Fatal(err)
	}
	consentRequest, err := ConsentRequestForApp(ory.OAuth2ConsentRequest{}, Step{Challenge: "c2", LoginChallenge: "c1"}, Extensions{})
	if err != nil {
		t.Fatal(err)
	}
	consent, err := json.Marshal(consentRequest)
	if err != nil {
		t.Fatal(err)
	}
	always := map[string]any{
		"oidc_context": map[string]any{}, "requested_scope": []any{}, "requested_access_token_audience": []any{},
		"skip": false, "subject": "", "x_dispatcher_claims": map[string]any{},
	}
	consentWant := maps.Clone(always)
	maps.Copy(consentWant, map[string]any{"acr": "", "amr": []any{}, "context": map[string]any{}, "login_challenge": "c1"})
	for _, tt := range []struct {
		served []byte
		want   map[string]any
	}{{login, always}, {consent, consentWant}} {
		var doc map[string]any
		decode(t, tt.served, &doc)
		for k, v := range tt.want {
			if !reflect.DeepEqual(doc[k], v) {
				t.Errorf("%s: %s = %#v, want %#v", tt.served, k, doc[k], v)
			}
		}
	}
}

// The SDK serialises AdditionalProperties over the model's own fields: they
// must not bring back Hydra's challenge, subject or skip, replace another
// field (the flow's acr, the request URL), nor add extensions the step does
// not set.
func TestAdditionalPropertiesStayMasked(t *testing.T) {
	hydra := map[string]any{"challenge": "L", "login_challenge": "L", "subject": "hydra-subject", "skip": true, "x_hydra_next": "kept",
		"acr": "hydra-acr", "request_url": "http://elsewhere.test/",
		"x_dispatcher_restart_url": "http://dispatcher.hydra.test/?login_challenge=L", "x_dispatcher_device": "stale"}
	const requestURL = "http://public.hydra.test/oauth2/auth"
	login, err := json.Marshal(LoginRequestForApp(ory.OAuth2LoginRequest{RequestUrl: requestURL, AdditionalProperties: hydra},
		Step{Challenge: "c1"}, Extensions{}))
	if err != nil {
		t.Fatal(err)
	}
	consentRequest, err := ConsentRequestForApp(ory.OAuth2ConsentRequest{Acr: ory.PtrString("aggregate"), RequestUrl: ory.PtrString(requestURL), AdditionalProperties: hydra},
		Step{Challenge: "c2", LoginChallenge: "c1"}, Extensions{})
	if err != nil {
		t.Fatal(err)
	}
	consent, err := json.Marshal(consentRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		served  []byte
		wantAcr any
	}{{login, nil}, {consent, "aggregate"}} {
		var doc map[string]any
		decode(t, tt.served, &doc)
		if doc["challenge"] == "L" || doc["login_challenge"] == "L" || doc["subject"] == "hydra-subject" ||
			doc["skip"] != false || doc["x_hydra_next"] != "kept" || doc["acr"] != tt.wantAcr || doc["request_url"] != requestURL ||
			doc["x_dispatcher_restart_url"] != nil || doc["x_dispatcher_device"] != nil {
			t.Errorf("served %s", tt.served)
		}
	}
	if len(hydra) != 9 {
		t.Errorf("the emulation changed its argument: %v", hydra)
	}
}

// Login apps get Hydra's answer whole, but for what the emulation replaces:
// challenges, subject and skip, an empty context as {}, and the extension.
// The models' fields are masked in the additional properties: a member Hydra
// would add under one of those names (acr on a login request) would be lost.
func TestServedKeepsHydraMembers(t *testing.T) {
	for _, tt := range []struct{ login, consent string }{
		{hydra22 + "login_request.json", hydra22 + "consent_request.json"},
		{hydra23 + "login_request.json", hydra23 + "consent_request.json"},
		{symfony21 + "01-skip/0002-hydra-GET-admin_oauth2_auth_requests_login.json", symfony21 + "01-skip/0005-hydra-GET-admin_oauth2_auth_requests_consent.json"},
		{symfony21 + "14-sql-2fa-consent-skipped/0032-hydra-GET-admin_oauth2_auth_requests_login.json", symfony21 + "14-sql-2fa-consent-skipped/0069-hydra-GET-admin_oauth2_auth_requests_consent.json"},
	} {
		step := Step{Challenge: "step-challenge", LoginChallenge: "step-login-challenge", Subject: "step-subject"}
		login, err := json.Marshal(LoginRequestForApp(loginRequest(t, tt.login), step, Extensions{}))
		if err != nil {
			t.Fatal(err)
		}
		served, err := ConsentRequestForApp(consentRequest(t, tt.consent), step, Extensions{})
		if err != nil {
			t.Fatal(err)
		}
		consent, err := json.Marshal(served)
		if err != nil {
			t.Fatal(err)
		}
		for _, answer := range []struct {
			path   string
			served []byte
		}{{tt.login, login}, {tt.consent, consent}} {
			var want, got map[string]any
			decode(t, body(t, answer.path), &want)
			decode(t, answer.served, &got)
			withoutClientNulls(want)
			want["challenge"], want["subject"], want["skip"] = step.Challenge, step.Subject, false
			want["x_dispatcher_claims"] = map[string]any{}
			if answer.path == tt.consent {
				want["login_challenge"] = step.LoginChallenge
				if c, ok := want["context"].([]any); ok && len(c) == 0 { // Hydra 2.1 behind Symfony
					want["context"] = map[string]any{}
				}
			}
			if d := diff(want, got, ""); len(d) > 0 {
				t.Errorf("%s: served differs from Hydra's: %v", answer.path, d)
			}
		}
	}
}

// On the Hydra 2.1 answers the Symfony dispatcher received, login apps get
// what it served them, value for value. Symfony read Hydra's login request
// before serving each step's: that answer is the source. A step's consent
// request comes from the consent request Hydra served at the end, with the
// aggregates so far, which the caller sets: those Symfony served.
func TestSymfonyParity(t *testing.T) {
	for _, capture := range []string{
		"07-oidc-after-sql-retry-consent-skipped",
		"12-sql-consent-skipped",
		"14-sql-2fa-consent-skipped",
		"27-back-to-sql-2fa",
	} {
		t.Run(capture, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(symfony21, capture, "*.json"))
			if err != nil {
				t.Fatal(err)
			}
			var hydraLogin, hydraConsent string
			var appConsents []string
			logins := 0
			for _, f := range files {
				switch name := filepath.Base(f); {
				case strings.Contains(name, "-hydra-GET-admin_oauth2_auth_requests_login."):
					hydraLogin = f
				case strings.Contains(name, "-front-GET-oauth2_auth_requests_login."):
					logins++
					matchesSymfonyLogin(t, f, loginRequest(t, hydraLogin))
				case strings.Contains(name, "-front-GET-oauth2_auth_requests_consent."):
					appConsents = append(appConsents, f)
				case strings.Contains(name, "-hydra-GET-admin_oauth2_auth_requests_consent.") && hydraConsent == "":
					hydraConsent = f
				}
			}
			if logins == 0 || len(appConsents) == 0 || hydraConsent == "" {
				t.Fatalf("%d login requests, consent requests %q, Hydra's %q: the capture changed", logins, appConsents, hydraConsent)
			}
			for _, f := range appConsents {
				matchesSymfonyConsent(t, f, consentRequest(t, hydraConsent))
			}
		})
	}
}

// matchesSymfonyConsent does the same for a consent request, served from
// Hydra's cr with the aggregates Symfony served.
func matchesSymfonyConsent(t *testing.T, exchange string, cr ory.OAuth2ConsentRequest) {
	t.Helper()
	var symfony map[string]any
	decode(t, body(t, exchange), &symfony)
	cr.Acr, cr.Amr, cr.Context = ory.PtrString(symfony["acr"].(string)), nil, symfony["context"]
	for _, m := range symfony["amr"].([]any) {
		cr.Amr = append(cr.Amr, m.(string))
	}
	served, err := ConsentRequestForApp(cr, Step{
		Challenge:      symfony["challenge"].(string),
		LoginChallenge: symfony["login_challenge"].(string),
		Subject:        symfony["subject"].(string),
	}, Extensions{})
	if err != nil {
		t.Fatal(err)
	}
	symfony["x_dispatcher_claims"] = map[string]any{} // added to consent requests
	matchesSymfony(t, symfony, served)
}

// matchesSymfonyLogin compares the login request Symfony served in exchange
// with the one served from Hydra's answer lr, for the same step. On a first
// step, Symfony served subject null and claims [] (a PHP empty array); the
// emulated API serves "" and {}.
func matchesSymfonyLogin(t *testing.T, exchange string, lr ory.OAuth2LoginRequest) {
	t.Helper()
	var symfony map[string]any
	decode(t, body(t, exchange), &symfony)
	if symfony["subject"] == nil {
		symfony["subject"] = ""
	}
	claims, ok := symfony["x_dispatcher_claims"].(map[string]any)
	if !ok {
		claims = map[string]any{}
		symfony["x_dispatcher_claims"] = claims
	}
	matchesSymfony(t, symfony, LoginRequestForApp(lr,
		Step{Challenge: symfony["challenge"].(string), Subject: symfony["subject"].(string)},
		Extensions{Claims: claims}))
}

// matchesSymfony compares served with Symfony's answer, but for the client's
// dates: Symfony reformatted them (+00:00, no fraction), Go relays Hydra's.
func matchesSymfony(t *testing.T, symfony map[string]any, served any) {
	t.Helper()
	data, err := json.Marshal(served)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	decode(t, data, &got)
	for _, doc := range []map[string]any{symfony, got} {
		client, _ := doc["client"].(map[string]any)
		delete(client, "created_at")
		delete(client, "updated_at")
	}
	if d := diff(symfony, got, ""); len(d) > 0 {
		t.Errorf("served differs from Symfony: %v", d)
	}
}
