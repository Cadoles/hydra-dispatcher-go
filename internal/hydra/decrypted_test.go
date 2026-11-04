package hydra

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra/flowcodec"
)

// devSecret is the secrets.system of the Hydras the flowcodec fixtures come
// from (hydra-dev's files/hydra/config.yaml).
const devSecret = "youReallyNeedToChangeThis"

// The requests built from a decrypted flow are those the admin API served
// for the same challenge, recorded with it by tools/flowfixtures (DEC-3):
// both modes give the engine the same request, member for member.
func TestRequestsOfDecryptedFlows(t *testing.T) {
	for _, tc := range []struct {
		dir     string
		version flowcodec.Version
	}{{hydra22, flowcodec.Hydra22}, {hydra23, flowcodec.Hydra23}} {
		t.Run(tc.dir, func(t *testing.T) {
			codec, err := flowcodec.New(tc.version, []string{devSecret})
			if err != nil {
				t.Fatal(err)
			}
			challenge := func(name string) string {
				data, err := os.ReadFile(tc.dir + name)
				if err != nil {
					t.Fatal(err)
				}
				return strings.TrimSpace(string(data))
			}

			l := challenge("login_challenge.txt")
			loginFlow, err := codec.LoginChallenge(l)
			if err != nil {
				t.Fatal(err)
			}
			login, err := LoginRequestOf(l, loginFlow)
			if err != nil {
				t.Fatal(err)
			}
			served, err := decodeLoginRequest(body(t, tc.dir+"login_request.json"))
			if err != nil {
				t.Fatal(err)
			}
			sameRequest(t, "login request", login, served)

			c := challenge("consent_challenge.txt")
			f, err := codec.ConsentChallenge(c)
			if err != nil {
				t.Fatal(err)
			}
			consent, err := ConsentRequestOf(c, f)
			if err != nil {
				t.Fatal(err)
			}
			servedConsent, err := decodeConsentRequest(body(t, tc.dir+"consent_request.json"))
			if err != nil {
				t.Fatal(err)
			}
			sameRequest(t, "consent request", consent, servedConsent)
			// Q34: the consent request names the flow of the login challenge.
			if consent.GetLoginChallenge() != loginFlow.ID {
				t.Errorf("login_challenge %q, want the login flow's id %q", consent.GetLoginChallenge(), loginFlow.ID)
			}
		})
	}
}

// Beyond the flowcodec fixtures, a first login with an acr: the requests
// built from the flows Hydra keeps for the admin API's recorded answers equal
// those answers: a login skipped (skip true, the subject of the session), a
// consent whose login accept gave no acr ("" served) and a null context. The
// flow keeps a null audience, which the admin API serves [] (fixtures of
// flowcodec, decrypted: RequestedAudience null).
func TestRequestsOfRecordedAnswers(t *testing.T) {
	for _, dir := range []string{"testdata/errors/hydra-v2.2.0/", "testdata/errors/hydra-v2.3.0/"} {
		t.Run(dir, func(t *testing.T) {
			kept := func(name string) (*flowcodec.Flow, string, json.RawMessage) {
				served := body(t, dir+name)
				var m struct {
					Challenge      string          `json:"challenge"`
					Client         json.RawMessage `json:"client"`
					OIDCContext    json.RawMessage `json:"oidc_context"`
					RequestURL     string          `json:"request_url"`
					Scope          []string        `json:"requested_scope"`
					SessionID      string          `json:"session_id"`
					Skip           bool            `json:"skip"`
					Subject        string          `json:"subject"`
					LoginChallenge string          `json:"login_challenge"`
					LoginSessionID string          `json:"login_session_id"`
					ACR            string          `json:"acr"`
					AMR            []string        `json:"amr"`
					Context        json.RawMessage `json:"context"`
				}
				decode(t, served, &m)
				f := &flowcodec.Flow{ID: m.LoginChallenge, Client: m.Client, OpenIDConnectContext: m.OIDCContext, RequestURL: m.RequestURL,
					RequestedScope: m.Scope, SessionID: m.SessionID + m.LoginSessionID, Subject: m.Subject, LoginSkip: m.Skip, ConsentSkip: m.Skip,
					ACR: m.ACR, AMR: m.AMR}
				if string(m.Context) != "null" {
					f.Context = m.Context
				}
				return f, m.Challenge, served
			}

			f, l, served := kept("login_skip.json")
			if !f.LoginSkip || f.Subject == "" {
				t.Fatalf("not a skip: %+v", f)
			}
			login, err := LoginRequestOf(l, f)
			if err != nil {
				t.Fatal(err)
			}
			want, err := decodeLoginRequest(served)
			if err != nil {
				t.Fatal(err)
			}
			sameRequest(t, "login request skipped", login, want)

			f, c, served := kept("consent_accepted.json")
			if f.ACR != "" || f.Context != nil {
				t.Fatalf("acr %q, context %s: want none", f.ACR, f.Context)
			}
			consent, err := ConsentRequestOf(c, f)
			if err != nil {
				t.Fatal(err)
			}
			wantConsent, err := decodeConsentRequest(served)
			if err != nil {
				t.Fatal(err)
			}
			sameRequest(t, "consent request without acr", consent, wantConsent)
		})
	}
}

// A flow whose client does not decode, or without what every request
// carries, builds no request: the decryption then falls back (DEC-6).
func TestRequestsOfIncompleteFlows(t *testing.T) {
	f := &flowcodec.Flow{ID: "91d4f7afaf83455f8e2b8992cba303ef", Client: json.RawMessage(`{"client_id":"c"}`), RequestURL: "http://public.hydra.test/oauth2/auth", Subject: "alice"}
	if _, err := LoginRequestOf("L", f); err != nil {
		t.Errorf("complete flow: %v", err)
	}
	for name, mod := range map[string]func(f *flowcodec.Flow){
		"client of another type": func(f *flowcodec.Flow) { f.Client = json.RawMessage(`[]`) },
		"no client id":           func(f *flowcodec.Flow) { f.Client = json.RawMessage(`{}`) },
		"no request URL":         func(f *flowcodec.Flow) { f.RequestURL = "" },
	} {
		g := *f
		mod(&g)
		if _, err := LoginRequestOf("L", &g); err == nil {
			t.Errorf("%s: login request built", name)
		}
		if _, err := ConsentRequestOf("C", &g); err == nil {
			t.Errorf("%s: consent request built", name)
		}
	}
}

// sameRequest compares two requests as JSON, numbers as written.
func sameRequest(t *testing.T, what string, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var gv, wv any
	decode(t, g, &gv)
	decode(t, w, &wv)
	if d := diff(wv, gv, ""); len(d) > 0 {
		t.Errorf("%s built from the flow differs from the admin's:\n%s", what, strings.Join(d, "\n"))
	}
}
