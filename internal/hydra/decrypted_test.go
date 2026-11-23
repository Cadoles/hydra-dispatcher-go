package hydra

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/hydra/flowcodec"
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

// Beyond the flowcodec fixtures, a first login with an acr: the admin API's
// recorded answers carry their challenge, the flow Hydra sealed, which the
// dev secret opens. The requests built from those flows equal the answers: a
// login skipped (skip true, the subject of the session), a login and a
// consent read again once used, a consent whose login accept gave no acr (""
// served) and a null context. The flows keep a null audience, which the
// admin API serves [] (revue R18: decrypted, not rebuilt from the answer).
func TestRequestsOfRecordedAnswers(t *testing.T) {
	for _, tc := range []struct {
		dir     string
		version flowcodec.Version
	}{{"testdata/errors/hydra-v2.2.0/", flowcodec.Hydra22}, {"testdata/errors/hydra-v2.3.0/", flowcodec.Hydra23}} {
		t.Run(tc.dir, func(t *testing.T) {
			codec, err := flowcodec.New(tc.version, []string{devSecret})
			if err != nil {
				t.Fatal(err)
			}
			opened := func(name string, consent bool) (*flowcodec.Flow, string, json.RawMessage) {
				t.Helper()
				served := body(t, tc.dir+name)
				var m struct {
					Challenge string `json:"challenge"`
				}
				decode(t, served, &m)
				open := codec.LoginChallenge
				if consent {
					open = codec.ConsentChallenge
				}
				f, err := open(m.Challenge)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if f.RequestedAudience != nil {
					t.Errorf("%s: audience %q, want the null Hydra keeps", name, f.RequestedAudience)
				}
				return f, m.Challenge, served
			}

			for _, name := range []string{"login_skip.json", "login_used.json"} {
				f, l, served := opened(name, false)
				if name == "login_skip.json" && (!f.LoginSkip || f.Subject == "") {
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
				sameRequest(t, name, login, want)
			}

			for _, name := range []string{"consent_accepted.json", "consent_used.json"} {
				f, c, served := opened(name, true)
				if f.ACR != "" || f.Context != nil {
					t.Fatalf("%s: acr %q, context %s: want none", name, f.ACR, f.Context)
				}
				consent, err := ConsentRequestOf(c, f)
				if err != nil {
					t.Fatal(err)
				}
				want, err := decodeConsentRequest(served)
				if err != nil {
					t.Fatal(err)
				}
				sameRequest(t, name, consent, want)
			}

			// After a skip (P8): the context, acr and amr of the login accept,
			// on which the x_dispatcher_skip marker is checked (Q38); an
			// accept without amr is served [] and acr "".
			for _, name := range []string{"consent_after_skip.json", "consent_after_skip_no_amr.json"} {
				f, c, served := opened(name, true)
				if !f.LoginSkip || f.Context == nil {
					t.Fatalf("%s: not the consent of a skip with a context: %+v", name, f)
				}
				consent, err := ConsentRequestOf(c, f)
				if err != nil {
					t.Fatal(err)
				}
				want, err := decodeConsentRequest(served)
				if err != nil {
					t.Fatal(err)
				}
				sameRequest(t, name, consent, want)
			}
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
