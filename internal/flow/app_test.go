package flow

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// without2FA is the snapshot without the app 2fa, gone in the course of a
// flow (Q21).
func without2FA(e *Env) {
	e.Config = store.NewSnapshot([]store.App{testApps()[0], testApps()[2]}, testFlows(), e.Config.Settings)
}

// appCase is one line of the table, on the emulated API.
type appCase struct {
	name   string
	env    func(e *Env)
	ev     AppCall
	stored *Flow
	reread *Flow
	says   hydraSays
	// status and body (its JSON, or a part of it when the body ends with
	// "...") are the answer wanted; status 0 is AppForbidden.
	status int
	body   string
	calls  []Op
	write  func(t *testing.T, f *Flow)
	check  func(t *testing.T, p played)
}

func (tc appCase) run(t *testing.T) {
	t.Helper()
	t.Run(tc.name, func(t *testing.T) {
		env := testEnv()
		if tc.env != nil {
			tc.env(&env)
		}
		p := play(t, env, tc.ev, tc.stored, tc.reread, tc.says)
		r := p.Response
		switch {
		case tc.status == 0 && r.Kind != AppForbidden:
			t.Errorf("answer %v %d %s; want the allowlist's refusal", r.Kind, r.Status, rawJSON(r.Body))
		case tc.status != 0 && (r.Kind != AppJSON || r.Status != tc.status):
			t.Errorf("answer %v %d %s; want %d", r.Kind, r.Status, rawJSON(r.Body), tc.status)
		}
		if want, part := strings.CutSuffix(tc.body, "..."); tc.body != "" {
			if got := rawJSON(r.Body); part && !strings.Contains(got, want) || !part && got != want {
				t.Errorf("body %s; want %s", got, tc.body)
			}
		}
		if !slices.Equal(p.ops(), tc.calls) {
			t.Errorf("calls %v; want %v", p.ops(), tc.calls)
		}
		switch {
		case tc.write == nil && p.Write != nil:
			data, _ := Encode(p.Write)
			t.Errorf("wrote %s", data)
		case tc.write != nil && p.Write == nil:
			t.Error("wrote nothing")
		case tc.write != nil:
			tc.write(t, p.Write)
		}
		if tc.check != nil {
			tc.check(t, p)
		}
	})
}

func challenge(gen int64, app string, kind Kind) string {
	return testKeys.Challenge(lref, gen, app, kind)
}

func callBy(op AppOp, gen int64, app, body string) AppCall {
	return AppCall{Op: op, Challenge: challenge(gen, app, op.kind()), Caller: func(a string) bool { return a == app }, Body: json.RawMessage(body)}
}

const (
	loginBody   = `{"subject":"alice","amr":["pwd"],"context":{"email":"alice@example.org"},"remember":true,"remember_for":3600}`
	consentBody = `{"grant_scope":["openid"],"session":{"id_token":{"email":"alice@example.org","name":null},"access_token":null},"context":{"c":1}}`
	rejectBody  = `{"error":"access_denied","error_description":"no"}`
)

var loopBody = `{"redirect_to":"http://dispatcher.hydra.test/oauth2/auth?ref=` + lref + `"}`

func reportsHas(event, detail string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == event && r.Detail == detail }) {
			t.Errorf("no %s %s: %+v", event, detail, p.Reports)
		}
	}
}

func TestAppChecks(t *testing.T) {
	for _, tc := range []appCase{
		{name: "EMU-1", ev: AppCall{Op: AppGetLogin, Challenge: "zz"},
			status: http.StatusNotFound, body: `{"error":"invalid_request","error_description":"request_failed","status_code":404}`},
		{name: "EMU-2", ev: callBy(AppGetLogin, 1000, "sql", ""),
			status: http.StatusNotFound, body: `{"error":"missing_session_error","error_description":"Could not find session metadata in cache","status_code":404}`},
		{name: "EXP-1, hx reached", ev: callBy(AppAcceptLogin, 1000, "sql", loginBody),
			stored: func() *Flow { f := atStep(t, 1, false, false); f.HydraExpiresAt = testNow.UnixMilli(); return f }(),
			status: http.StatusNotFound, body: `{"error":"missing_session_error"...`},
		{name: "EMU-3, forged", ev: AppCall{Op: AppGetLogin, Challenge: Keys{[]byte("another key of thirty-two bytes!")}.Challenge(lref, 1000, "sql", KindLogin), Caller: func(string) bool { return true }},
			stored: atStep(t, 1, false, false), status: http.StatusNotFound, body: `{"error":"missing_session_error"...`,
			check: reportsHas("challenge.invalid", "forged")},
		{name: "EMU-3, future step", ev: callBy(AppGetLogin, 1000, "2fa", ""), stored: atStep(t, 1, false, false),
			status: http.StatusNotFound, body: `{"error":"missing_session_error"...`},
		{name: "EMU-3, other kind", ev: AppCall{Op: AppGetConsent, Challenge: challenge(1000, "sql", KindLogin), Caller: func(string) bool { return true }},
			stored: atStep(t, 1, true, false), status: http.StatusNotFound},
		{name: "EMU-4", ev: AppCall{Op: AppGetLogin, Challenge: challenge(1000, "sql", KindLogin), Caller: func(a string) bool { return a == "2fa" }},
			stored: atStep(t, 1, false, false), status: 0, check: reportsHas("security.ip_rejected", "emulated: app outside its sources")},
		{name: "EMU-5, GET", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: finishedFlow(t, "", 0), status: http.StatusGone, body: loopBody},
		{name: "EMU-5 Q25, PUT", ev: callBy(AppAcceptLogin, 1000, "sql", loginBody), stored: finishedFlow(t, "", 0), status: http.StatusOK, body: loopBody},
		{name: "EMU-6, GET", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: expired(atStep(t, 1, false, false)),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusGone, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished, check: rejected(RejectLogin, "login_required")},
		{name: "EMU-6 Q3, PUT", ev: callBy(AppAcceptConsent, 1000, "sql", consentBody), stored: expired(atStep(t, 1, true, false)),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-6, Hydra 401", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: expired(atStep(t, 1, false, false)),
			says: hydraSays{RejectLogin: {err: err401}}, status: http.StatusGone, body: loopBody, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-6 Q30, Hydra 410", ev: callBy(AppRejectLogin, 1000, "sql", rejectBody), stored: expired(atStep(t, 1, false, false)),
			says: hydraSays{RejectLogin: {err: err410}}, status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-7, GET", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: func() *Flow { f := atStep(t, 1, false, false); f.Gen = 1001; return f }(),
			status: http.StatusGone, body: loopBody, check: reportsHas("challenge.invalid", "stale_generation")},
		{name: "EMU-7 Q25, PUT", ev: callBy(AppAcceptLogin, 1000, "sql", loginBody), stored: func() *Flow { f := atStep(t, 1, false, false); f.Gen = 1001; return f }(),
			status: http.StatusOK, body: loopBody},
		{name: "EMU-7, a flow in choice", ev: callBy(AppGetConsent, 1000, "oidc", ""), stored: func() *Flow { f := choiceFlow(t); f.Gen = 1001; return f }(),
			status: http.StatusGone, body: loopBody},
	} {
		tc.run(t)
	}
}

func TestAppLogin(t *testing.T) {
	stepTwo := func(check string) *Flow {
		f := atStep(t, 2, false, false)
		f.Steps[1].Check = check
		return f
	}
	for _, tc := range []appCase{
		{name: "EMU-8, first step", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: atStep(t, 1, false, false),
			status: http.StatusOK,
			check: func(t *testing.T, p played) {
				got := rawJSON(p.Response.Body)
				for _, want := range []string{`"challenge":"` + challenge(1000, "sql", KindLogin) + `"`, `"subject":""`, `"skip":false`,
					`"x_dispatcher_claims":{}`, `"x_dispatcher_restart_url":"http://dispatcher.hydra.test/?ref=` + lref + `"`, `"session_id":"` + sessionID + `"`} {
					if !strings.Contains(got, want) {
						t.Errorf("A1 I7, no %s in %s", want, got)
					}
				}
				if strings.Contains(got, hydraL) {
					t.Error("I7, Hydra's challenge served")
				}
			}},
		{name: "EMU-8 I2, second step", ev: callBy(AppGetLogin, 1000, "2fa", ""), stored: atStep(t, 2, false, false),
			status: http.StatusOK, body: `"x_dispatcher_claims":{"email":"alice@example.org"}...`},
		{name: "EMU-28 Q21, the login request of an app gone from the snapshot", ev: callBy(AppGetLogin, 1000, "2fa", ""), stored: atStep(t, 2, false, false),
			env:    without2FA,
			status: http.StatusInternalServerError, body: `{"error":"server_error","error_description":"E1005","status_code":500}`,
			check: reportsHas("flow.error", "E1005")},
		{name: "EMU-9, accepted step", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: atStep(t, 1, true, false), status: http.StatusGone, body: loopBody},
		{name: "EMU-9, past step", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: atStep(t, 2, false, false), status: http.StatusGone, body: loopBody},
		{name: "EMU-9, accepted flow", ev: callBy(AppGetLogin, 1000, "2fa", ""), stored: acceptedFlow(t), status: http.StatusGone, body: loopBody},
		{name: "EMU-10", ev: callBy(AppAcceptLogin, 1000, "sql", loginBody), stored: atStep(t, 1, false, false),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				s := f.Steps[0]
				if !s.LoginOK || s.Subject != "alice" || f.Subject != "alice" || !slices.Equal(s.AMR, []string{"pwd"}) ||
					rawJSON(s.LoginContext) != `{"email":"alice@example.org"}` || !*s.Remember || *s.RememberFor != 3600 {
					t.Errorf("step %+v, subject %q", s, f.Subject)
				}
			}},
		{name: "EMU-10, no context", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":"alice"}`), stored: atStep(t, 1, false, false),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				if rawJSON(f.Steps[0].LoginContext) != `{}` {
					t.Errorf("context %s", rawJSON(f.Steps[0].LoginContext))
				}
			}},
		{name: "EMU-11, equal", ev: callBy(AppAcceptLogin, 1000, "2fa", loginBody), stored: stepTwo("equal"),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				if !f.Steps[1].LoginOK || f.Steps[1].Subject != "alice" || f.Subject != "alice" {
					t.Errorf("step %+v", f.Steps[1])
				}
			}},
		{name: "EMU-11, claim", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"alice@example.org"}`), stored: stepTwo("claim:email"),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				if f.Steps[1].Subject != "alice@example.org" || f.Subject != "alice" {
					t.Errorf("subjects %q, %q", f.Steps[1].Subject, f.Subject)
				}
			}},
		{name: "EMU-11, none", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`), stored: stepTwo(""),
			status: http.StatusOK, body: loopBody, write: func(*testing.T, *Flow) {}},
		{name: "EMU-12", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`), stored: stepTwo("equal"),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				rejected(RejectLogin, "access_denied")(t, p)
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "step.subject_mismatch" && r.Audit }) {
					t.Errorf("no audit: %+v", p.Reports)
				}
			}},
		{name: "EMU-13 T4", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":"alice","amr":["other"]}`), stored: atStep(t, 1, true, false),
			status: http.StatusOK, body: loopBody},
		{name: "EMU-13, past step", ev: callBy(AppAcceptLogin, 1000, "sql", loginBody), stored: atStep(t, 2, false, false),
			status: http.StatusOK, body: loopBody},
		{name: "EMU-13 Q27, the step's own subject", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"alice@example.org"}`),
			stored: func() *Flow { f := atStep(t, 2, true, false); f.Steps[1].Subject = "alice@example.org"; return f }(),
			status: http.StatusOK, body: loopBody},
		{name: "EMU-13, accepted flow", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`), stored: acceptedFlow(t),
			status: http.StatusOK, body: loopBody},
		{name: "EMU-14", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":"bob"}`), stored: atStep(t, 1, true, false),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-14 Q27, past step", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"alice"}`),
			stored: func() *Flow {
				f := atStep(t, 2, true, true)
				f.Current = 2
				f.Steps[1].Subject = "alice@example.org"
				return f
			}(),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-15, not an object", ev: callBy(AppAcceptLogin, 1000, "sql", `[]`), stored: atStep(t, 1, false, false),
			status: http.StatusBadRequest, body: `{"error":"invalid_request","error_description":"E1001","status_code":400}`},
		{name: "EMU-15, no subject", ev: callBy(AppAcceptLogin, 1000, "sql", `{"amr":["pwd"]}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-15, empty subject", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":""}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-15, a type", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":1}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-15 A9, context a list", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":"a","context":[]}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-15, data after the object", ev: callBy(AppAcceptLogin, 1000, "sql", `{"subject":"a"} {}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-15, no body", ev: callBy(AppAcceptLogin, 1000, "sql", ``), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-16 T3", ev: callBy(AppRejectLogin, 1000, "sql", rejectBody), stored: atStep(t, 1, false, false),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				if r := p.calls[0].Reject; r.GetError() != "access_denied" || r.GetErrorDescription() != "no" {
					t.Errorf("M8, body not forwarded as received: %+v", r)
				}
			}},
		{name: "EMU-16, invalid body", ev: callBy(AppRejectLogin, 1000, "sql", `{"error":1}`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-17", ev: callBy(AppRejectLogin, 1000, "sql", rejectBody), stored: atStep(t, 1, true, false), status: http.StatusOK, body: loopBody},
		{name: "EMU-17, accepted flow", ev: callBy(AppRejectLogin, 1000, "2fa", rejectBody), stored: acceptedFlow(t), status: http.StatusOK, body: loopBody},
	} {
		tc.run(t)
	}
}

func TestAppConsent(t *testing.T) {
	for _, tc := range []appCase{
		{name: "EMU-18", ev: callBy(AppGetConsent, 1000, "sql", ""), stored: atStep(t, 1, true, false), status: http.StatusOK,
			check: func(t *testing.T, p played) {
				got := rawJSON(p.Response.Body)
				for _, want := range []string{`"challenge":"` + challenge(1000, "sql", KindConsent) + `"`, `"login_challenge":"` + challenge(1000, "sql", KindLogin) + `"`,
					`"context":{"login":"sql"}`, `"subject":"alice"`, `"x_dispatcher_claims":{}`} {
					if !strings.Contains(got, want) {
						t.Errorf("A2 I6, no %s in %s", want, got)
					}
				}
			}},
		{name: "EMU-19", ev: callBy(AppGetConsent, 1000, "sql", ""), stored: atStep(t, 1, true, true), status: http.StatusGone, body: loopBody},
		{name: "EMU-19, past step", ev: callBy(AppGetConsent, 1000, "sql", ""), stored: atStep(t, 2, true, false), status: http.StatusGone, body: loopBody},
		{name: "EMU-19, accepted flow", ev: callBy(AppGetConsent, 1000, "2fa", ""), stored: acceptedFlow(t), status: http.StatusGone, body: loopBody},
		{name: "EMU-20, GET", ev: callBy(AppGetConsent, 1000, "sql", ""), stored: atStep(t, 1, false, false), status: http.StatusGone, body: loopBody},
		{name: "EMU-20 Q25, PUT accept", ev: callBy(AppAcceptConsent, 1000, "sql", consentBody), stored: atStep(t, 1, false, false), status: http.StatusOK, body: loopBody},
		{name: "EMU-20, PUT reject", ev: callBy(AppRejectConsent, 1000, "sql", rejectBody), stored: atStep(t, 1, false, false), status: http.StatusOK, body: loopBody},
		{name: "EMU-21", ev: callBy(AppAcceptConsent, 1000, "sql", consentBody), stored: atStep(t, 1, true, false),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				s := f.Steps[0]
				if !s.ConsentOK || rawJSON(s.IDToken) != `{"email":"alice@example.org","name":null}` || rawJSON(s.AccessToken) != `{}` || rawJSON(s.ConsentContext) != `{"c":1}` {
					t.Errorf("A2, step %+v", s)
				}
			}},
		{name: "EMU-21, no session", ev: callBy(AppAcceptConsent, 1000, "sql", `{}`), stored: atStep(t, 1, true, false),
			status: http.StatusOK, body: loopBody,
			write: func(t *testing.T, f *Flow) {
				if s := f.Steps[0]; rawJSON(s.IDToken) != `{}` || rawJSON(s.AccessToken) != `{}` {
					t.Errorf("step %+v", s)
				}
			}},
		{name: "EMU-15, id_token a list", ev: callBy(AppAcceptConsent, 1000, "sql", `{"session":{"id_token":[]}}`), stored: atStep(t, 1, true, false), status: http.StatusBadRequest},
		{name: "EMU-15, session a string", ev: callBy(AppAcceptConsent, 1000, "sql", `{"session":"x"}`), stored: atStep(t, 1, true, false), status: http.StatusBadRequest},
		{name: "EMU-15, consent context a string", ev: callBy(AppAcceptConsent, 1000, "sql", `{"context":"x"}`), stored: atStep(t, 1, true, false), status: http.StatusBadRequest},
		{name: "EMU-15, consent body not JSON", ev: callBy(AppAcceptConsent, 1000, "sql", `{`), stored: atStep(t, 1, false, false), status: http.StatusBadRequest},
		{name: "EMU-22", ev: callBy(AppAcceptConsent, 1000, "sql", consentBody), stored: atStep(t, 1, true, true), status: http.StatusOK, body: loopBody},
		{name: "EMU-15, a second consent accept with an invalid body", ev: callBy(AppAcceptConsent, 1000, "sql", `{"session":{"id_token":[1]}}`),
			stored: atStep(t, 1, true, true), status: http.StatusBadRequest, body: `{"error":"invalid_request","error_description":"E1001","status_code":400}`},
		{name: "EMU-15, a consent accept with an invalid body on an accepted flow", ev: callBy(AppAcceptConsent, 1000, "2fa", `{"context":[]}`),
			stored: acceptedFlow(t), status: http.StatusBadRequest},
		{name: "EMU-28 Q21, the consent request of an app gone from the snapshot", ev: callBy(AppGetConsent, 1000, "2fa", ""), stored: atStep(t, 2, true, false),
			env:    without2FA,
			status: http.StatusInternalServerError, body: `{"error":"server_error","error_description":"E1005","status_code":500}`},
		{name: "EMU-23", ev: callBy(AppRejectConsent, 1000, "sql", rejectBody), stored: atStep(t, 1, true, false),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}}, status: http.StatusOK, body: `{"redirect_to":"` + hydraDone + `"}`,
			calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-24", ev: callBy(AppRejectConsent, 1000, "sql", rejectBody), stored: atStep(t, 1, true, true), status: http.StatusOK, body: loopBody},
		{name: "EMU-24, past step", ev: callBy(AppRejectConsent, 1000, "sql", rejectBody), stored: atStep(t, 2, false, false), status: http.StatusOK, body: loopBody},
	} {
		tc.run(t)
	}
}

// The Hydra errors of the emulated API's rejects (EMU-25 to EMU-27).
func TestAppRejectErrors(t *testing.T) {
	reject := callBy(AppRejectLogin, 1000, "sql", rejectBody)
	mismatch := callBy(AppAcceptLogin, 1000, "sql", `{"subject":"bob"}`)
	for _, tc := range []appCase{
		{name: "EMU-25, 401", ev: reject, stored: atStep(t, 1, false, false), says: hydraSays{RejectLogin: {err: err401}},
			status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-25, 404", ev: mismatch, stored: atStep(t, 1, true, false), says: hydraSays{RejectLogin: {err: err404}},
			status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-25, 410", ev: callBy(AppRejectConsent, 1000, "sql", rejectBody), stored: atStep(t, 1, true, false), says: hydraSays{RejectLogin: {err: err410}},
			status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}, write: finished},
		{name: "EMU-26, 409, finished meanwhile", ev: reject, stored: atStep(t, 1, false, false), reread: finishedFlow(t, "", 0),
			says: hydraSays{RejectLogin: {err: err409}}, status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}},
		{name: "EMU-26, 409, finished meanwhile, a GET", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: expired(atStep(t, 1, false, false)), reread: finishedFlow(t, "", 0),
			says: hydraSays{RejectLogin: {err: err409}}, status: http.StatusGone, body: loopBody, calls: []Op{RejectLogin}},
		{name: "EMU-26, 409, nothing changed", ev: reject, stored: atStep(t, 1, false, false),
			says: hydraSays{RejectLogin: {err: err409}}, status: http.StatusInternalServerError,
			body: `{"error":"server_error","error_description":"E1007","status_code":500}`, calls: []Op{RejectLogin}},
		{name: "EMU-26, 400, nothing changed", ev: reject, stored: atStep(t, 1, false, false), says: hydraSays{RejectLogin: {err: err400}},
			status: http.StatusInternalServerError, body: `{"error":"server_error","error_description":"E1007","status_code":500}`, calls: []Op{RejectLogin}},
		{name: "EMU-26 Q11, 400, finished meanwhile", ev: reject, stored: atStep(t, 1, false, false), reread: finishedFlow(t, "", 0),
			says: hydraSays{RejectLogin: {err: err400}}, status: http.StatusOK, body: loopBody, calls: []Op{RejectLogin}},
		{name: "EMU-26, 403", ev: mismatch, stored: atStep(t, 1, true, false), says: hydraSays{RejectLogin: {err: err403}},
			status: http.StatusInternalServerError, calls: []Op{RejectLogin}},
		{name: "EMU-27", ev: reject, stored: atStep(t, 1, false, false), says: hydraSays{RejectLogin: {err: errDown}},
			status: http.StatusInternalServerError, body: `{"error":"server_error","error_description":"E1004","status_code":500}`, calls: []Op{RejectLogin}},
		{name: "EMU-27, 2xx without redirect_to", ev: reject, stored: atStep(t, 1, false, false), says: hydraSays{RejectLogin: {}},
			status: http.StatusInternalServerError, body: `{"error":"server_error","error_description":"E1004","status_code":500}`, calls: []Op{RejectLogin}},
		{name: "EMU-27, EMU-6", ev: callBy(AppGetLogin, 1000, "sql", ""), stored: expired(atStep(t, 1, false, false)), says: hydraSays{RejectLogin: {err: errDown}},
			status: http.StatusInternalServerError, calls: []Op{RejectLogin}},
	} {
		tc.run(t)
	}
}

func TestAppStoredCorrupt(t *testing.T) {
	f := atStep(t, 1, true, false)
	f.Hydra.Client = json.RawMessage(`[]`)
	for _, op := range []AppOp{AppGetLogin, AppGetConsent} {
		g := copyFlow(t, f)
		if op == AppGetLogin {
			g.Steps[0].LoginOK = false
		}
		p := play(t, testEnv(), callBy(op, 1000, "sql", ""), g, nil, nil)
		if p.Response.Status != http.StatusInternalServerError {
			t.Errorf("%v on a stored client that is not an object: %d", op, p.Response.Status)
		}
	}
}

// ECR-8: a write that would come at or after hx writes nothing; the answer
// is that to an absent flow, on the pages as on the emulated API.
func TestPast(t *testing.T) {
	env := testEnv()
	late := Outcome{Write: &Flow{HydraExpiresAt: testNow.UnixMilli()}, Response: Response{Kind: Redirect}}
	if out := late.past(Input{Event: callBy(AppAcceptLogin, 1000, "sql", loginBody), Env: env}); out.Write != nil || out.Response.Status != http.StatusNotFound {
		t.Errorf("emulated API: %+v", out)
	}
	if out := late.past(Input{Event: Loop{}, Env: env}); out.Write != nil || out.Response.Code != E1002 {
		t.Errorf("pages: %+v", out)
	}
	// The audit event of a reject made stands; the rest went with the write.
	late.Reports = []Report{{Event: "step.subject_mismatch", Audit: true}, {Event: "flow.rejected"}}
	if out := late.past(Input{Event: Loop{}, Env: env}); len(out.Reports) != 1 || out.Reports[0].Event != "step.subject_mismatch" {
		t.Errorf("reports %+v", out.Reports)
	}
	early := Outcome{Write: &Flow{HydraExpiresAt: testNow.Add(time.Millisecond).UnixMilli()}}
	if out := early.past(Input{Event: Loop{}, Env: env}); out.Write == nil {
		t.Error("a write before hx dropped")
	}
}
