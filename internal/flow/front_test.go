package flow

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const (
	// hydraL is the login challenge of the fixture, hydraC a consent one.
	hydraL    = "0c34aaee066148adbc0251024fee9bb4"
	hydraC    = "5f1d1b2c3a4e4f60a1b2c3d4e5f60718"
	sessionID = "ba1ce6e4-e93b-401c-b6af-62703fe39df7"
	clientURI = "http://oidc.client.test/"
	// hydraDone is Hydra's redirect_to after an accept or a reject.
	hydraDone = "http://public.hydra.test/oauth2/auth?login_verifier=v"
	otherCSRF = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var lref = Ref(hydraL)

// withClient returns the fixture's login request, its client changed.
func withClient(t *testing.T, members string) *ory.OAuth2LoginRequest {
	t.Helper()
	r := loginRequest(t)
	data, _ := json.Marshal(r.Client)
	var c map[string]json.RawMessage
	_ = json.Unmarshal(data, &c)
	var more map[string]json.RawMessage
	if err := json.Unmarshal([]byte(members), &more); err != nil {
		t.Fatal(err)
	}
	for k, v := range more {
		c[k] = v
	}
	data, _ = json.Marshal(c)
	client, err := hydra.DecodeClient(data)
	if err != nil {
		t.Fatal(err)
	}
	r.Client = *client
	return r
}

// withACR returns the fixture's login request with these acr_values.
func withACR(t *testing.T, values ...string) *ory.OAuth2LoginRequest {
	r := loginRequest(t)
	r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: values}
	return r
}

// choiceFlow is the flow of the fixture, in choice, its client with a
// client_uri.
func choiceFlow(t *testing.T) *Flow {
	t.Helper()
	snap, sid, err := SnapshotOf(withClient(t, `{"client_uri":"`+clientURI+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return &Flow{
		V: Format, LoginChallenge: hydraL, HydraSessionID: sid, Hydra: snap,
		Gen0: 1000, Gen: 1000, CSRF: cookie,
		ExpiresAt:      testNow.Add(10 * time.Minute).UnixMilli(),
		HydraExpiresAt: testNow.Add(30 * time.Minute).UnixMilli(),
	}
}

// atStep is choiceFlow on hydra-sql-2fa, step k current, the steps before
// it accepted.
func atStep(t *testing.T, k int, lok, cok bool) *Flow {
	f := choiceFlow(t)
	f.FlowID, f.Current = "hydra-sql-2fa", k
	if k > 1 || lok {
		f.Subject = "alice" // the first step's, once accepted
	}
	f.Steps = []Step{{App: "sql"}, {App: "2fa", Check: "equal"}}
	for i := range f.Steps {
		s := &f.Steps[i]
		if i+1 < k || i+1 == k && lok {
			s.LoginOK, s.Subject, s.AMR = true, "alice", []string{"amr-" + s.App}
			s.LoginContext = Object{"login": json.RawMessage(`"` + s.App + `"`)}
		}
		if i+1 < k || i+1 == k && cok {
			s.ConsentOK = true
			s.ConsentContext = Object{"from": json.RawMessage(`"` + s.App + `"`)}
			s.IDToken = Object{"email": json.RawMessage(`"alice@example.org"`), "step": json.RawMessage(`"` + s.App + `"`)}
			s.AccessToken = Object{}
		}
	}
	return f
}

func lastDone(t *testing.T) *Flow { return atStep(t, 2, true, true) }

func acceptedFlow(t *testing.T) *Flow {
	f := lastDone(t)
	f.HydraRedirect = hydraDone
	f.Sent = &SentLogin{Subject: "alice", ACR: "2", AMR: []string{"pwd", "otp"}}
	return f
}

func finishedFlow(t *testing.T, cr string, ago time.Duration) *Flow {
	f := acceptedFlow(t).Reduce()
	f.ConsentRedirect, f.ConsentAt = cr, testNow.Add(-ago).UnixMilli()
	return f
}

func expired(f *Flow) *Flow {
	f.ExpiresAt = testNow.UnixMilli() - 1
	return f
}

func consentRequest(ref string, mod func(r *ory.OAuth2ConsentRequest)) *ory.OAuth2ConsentRequest {
	r := &ory.OAuth2ConsentRequest{
		Challenge:      hydraC,
		Subject:        ory.PtrString("alice"),
		LoginSessionId: ory.PtrString(sessionID),
		Context:        json.RawMessage(`{"from":"2fa","x_dispatcher_ref":"` + ref + `"}`),
		RequestedScope: []string{"openid", "email"},
		Client:         &ory.OAuth2Client{ClientId: ory.PtrString("c")},
		Skip:           ory.PtrBool(false),
	}
	if mod != nil {
		mod(r)
	}
	return r
}

func loginURL(app string, gen int64) string {
	return "http://" + app + ".hydra.test/login?login_challenge=" + testKeys.Challenge(lref, gen, app, KindLogin)
}

func consentURL(app string, gen int64) string {
	return "http://" + app + ".hydra.test/consent?consent_challenge=" + testKeys.Challenge(lref, gen, app, KindConsent)
}

// pageCase is one line of the table, on the pages.
type pageCase struct {
	name   string
	env    func(e *Env)
	ev     Event
	stored *Flow
	reread *Flow
	says   hydraSays
	// The answer wanted: a redirect to url, a page, or an error page code.
	kind  ResponseKind
	url   string
	code  Code
	link  bool
	calls []Op
	// write checks the flow written; nil wants none.
	write func(t *testing.T, f *Flow)
	check func(t *testing.T, p played)
}

func (tc pageCase) run(t *testing.T) {
	t.Helper()
	t.Run(tc.name, func(t *testing.T) {
		env := testEnv()
		if tc.env != nil {
			tc.env(&env)
		}
		p := play(t, env, tc.ev, tc.stored, tc.reread, tc.says)
		r := p.Response
		if r.Kind != tc.kind || tc.url != "" && r.URL != tc.url || r.Code != tc.code {
			t.Errorf("answer %v %q %s; want %v %q %s", r.Kind, r.URL, r.Code, tc.kind, tc.url, tc.code)
		}
		if tc.kind == ErrorPage && tc.code == E1002 && (r.Link != "") != tc.link {
			t.Errorf("page E1002 link %q; want a link %v", r.Link, tc.link)
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

func finished(t *testing.T, f *Flow) {
	t.Helper()
	if !f.Done || f.Steps != nil || f.LoginChallenge != "" {
		t.Errorf("not finished and reduced: %+v", f)
	}
}

// finishedWithCR wants f finished by its consent, Hydra's redirect_to and
// the time kept for a double submission (Q13).
func finishedWithCR(t *testing.T, f *Flow) {
	t.Helper()
	finished(t, f)
	if f.ConsentRedirect != hydraDone || f.ConsentAt != testNow.UnixMilli() {
		t.Errorf("Q13, cr %q ct %d", f.ConsentRedirect, f.ConsentAt)
	}
}

// shownConsent is the accepted flow past exp whose consent screen was shown:
// cc is Hydra's consent challenge.
func shownConsent(t *testing.T) *Flow {
	f := expired(acceptedFlow(t))
	f.ConsentChallenge = hydraC
	return f
}

// pastExpSays is Hydra on a page past exp without the cookie, on
// shownConsent (ENT-20, POS-10, BCL-16): the consent read, then rejected.
func pastExpSays() hydraSays {
	return hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, RejectConsent: {redirectTo: hydraDone}}
}

// rejectedAgo is a flow CST-22 (or ENT-20, POS-10, BCL-16) finished ago:
// its consent rejected past exp, the browser without the cookie since.
func rejectedAgo(t *testing.T, ago time.Duration) *Flow {
	f := finishedFlow(t, "http://hydra/cr", ago)
	f.ExpiresAt = f.ConsentAt - 1
	return f
}

// reportedForged wants the page E1001 of a Hydra challenge the admin API does
// not know reported forged, for the failure limiter (Q32, P11).
func reportedForged(t *testing.T, p played) {
	t.Helper()
	if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "challenge.invalid" && r.Detail == "forged" }) {
		t.Errorf("Q32, not reported forged: %+v", p.Reports)
	}
}

// reportedExpired wants the page E1002 of a Hydra challenge past its
// lifetime reported expired, in every mode: Hydra 2.2's 401 as DEC-4
// (ENT-11, CST-4; revue R18).
func reportedExpired(t *testing.T, p played) {
	t.Helper()
	if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "challenge.invalid" && r.Detail == "expired" }) {
		t.Errorf("not reported expired: %+v", p.Reports)
	}
}

// unreported wants no challenge.invalid: Hydra 2.1's 410, a request handled
// (ENT-10, CST-3), or a challenge the flow holds, read again (BCL-9, ENT-20,
// BCL-16), which is never counted.
func unreported(t *testing.T, p played) {
	t.Helper()
	if slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "challenge.invalid" }) {
		t.Errorf("reported: %+v", p.Reports)
	}
}

// skewReported wants hydra.clock_skew of detail, "" for none (DEC-3).
func skewReported(detail string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		var got []string
		for _, r := range p.Reports {
			if r.Event == "hydra.clock_skew" {
				got = append(got, r.Detail)
			}
		}
		if detail == "" && got != nil || detail != "" && !slices.Equal(got, []string{detail}) {
			t.Errorf("hydra.clock_skew %q; want %q", got, detail)
		}
	}
}

// withLoginID sets Hydra's id of L in f's snapshot (Q34).
func withLoginID(f *Flow, id string) *Flow {
	f.Hydra.LoginID = id
	return f
}

// atExp sets f's exp to now: its step challenges are still valid (I1, exp
// inclusive), nothing expires yet.
func atExp(f *Flow) *Flow {
	f.ExpiresAt = testNow.UnixMilli()
	return f
}

func inChoice(gen int64, csrf string) func(t *testing.T, f *Flow) {
	return func(t *testing.T, f *Flow) {
		t.Helper()
		if f.StateAt(testNow) != Choice || f.Gen != gen || f.CSRF != csrf || f.Steps != nil || f.Subject != "" || f.LoginChallenge != hydraL {
			t.Errorf("flow %+v; want in choice, generation %d, csrf %q", f, gen, csrf)
		}
	}
}

func started(flow string, gen int64, imposed bool) func(t *testing.T, f *Flow) {
	return func(t *testing.T, f *Flow) {
		t.Helper()
		if f.FlowID != flow || f.Current != 1 || f.Gen != gen || f.Imposed != imposed || f.StateAt(testNow) != StepLogin {
			t.Errorf("flow %s step %d generation %d imposed %v; want %s, 1, %d, %v", f.FlowID, f.Current, f.Gen, f.Imposed, flow, gen, imposed)
		}
	}
}

func offered(flows ...string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		if c := p.Response.Choice; c == nil || !slices.Equal(c.Flows, flows) {
			t.Errorf("choice page %+v; want flows %v", c, flows)
		}
	}
}

func rejected(op Op, name string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		for _, c := range p.calls {
			if c.Op == op {
				if got := c.Reject.GetError(); got != name {
					t.Errorf("rejected with %q; want %q", got, name)
				}
				return
			}
		}
		t.Errorf("no %v", op)
	}
}

func TestEntry(t *testing.T) {
	login := hydraSays{GetLogin: {login: loginRequest(t)}}
	for _, tc := range []pageCase{
		{name: "ENT-1", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, says: login,
			kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.StateAt(testNow) != Choice || f.Gen0 != 5000 || f.Gen != 5000 || f.CSRF != cookie || f.LoginChallenge != hydraL || f.HydraSessionID != sessionID {
					t.Errorf("flow created %+v", f)
				}
				// min(now + 1 h, first read + 30 min − 60 s), and L's end at Hydra.
				if f.ExpiresAt != testNow.Add(29*time.Minute).UnixMilli() || f.HydraExpiresAt != testNow.Add(30*time.Minute).UnixMilli() {
					t.Errorf("Q2, exp %d hx %d", f.ExpiresAt, f.HydraExpiresAt)
				}
			},
			check: func(t *testing.T, p played) {
				if p.Response.SetCSRF != cookie || p.Response.Choice.CSRF != cookie || p.Response.Choice.LoginChallenge != hydraL {
					t.Errorf("A4, cookie %q, page %+v", p.Response.SetCSRF, p.Response.Choice)
				}
				offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa")(t, p)
			}},
		{name: "ENT-1, no cookie: a new value", ev: Entry{LoginChallenge: hydraL}, says: login,
			kind: ChoicePage, calls: []Op{GetLogin},
			write: inChoice(5000, newCSRF),
			check: func(t *testing.T, p played) {
				if p.Response.SetCSRF != newCSRF {
					t.Errorf("Set-Cookie %q", p.Response.SetCSRF)
				}
			}},
		{name: "ENT-1, a cookie of another shape is replaced", ev: Entry{LoginChallenge: hydraL, Cookie: "short"}, says: login,
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, newCSRF)},
		{name: "ENT-1 Q2, exp bounded by challenge_ttl", env: func(e *Env) { e.Config.Settings.ChallengeTTL = 10 * time.Minute },
			ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, says: login, kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.ExpiresAt != testNow.Add(10*time.Minute).UnixMilli() {
					t.Errorf("exp %d", f.ExpiresAt)
				}
			}},
		{name: "ENT-1 Q2, from requested_at", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(-5 * time.Minute)}},
			kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.ExpiresAt != testNow.Add(24*time.Minute).UnixMilli() || f.HydraExpiresAt != testNow.Add(25*time.Minute).UnixMilli() {
					t.Errorf("exp %d hx %d", f.ExpiresAt, f.HydraExpiresAt)
				}
			}},
		{name: "ENT-1 Q34, Hydra's id of L kept", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), loginID: "91d4f7afaf83455f8e2b8992cba303ef"}},
			kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.Hydra.LoginID != "91d4f7afaf83455f8e2b8992cba303ef" {
					t.Errorf("hid %q", f.Hydra.LoginID)
				}
			}},
		{name: "ENT-22 Q33, read in the last minute of L: rejected at once", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(-29*time.Minute - 30*time.Second)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished, check: rejected(RejectLogin, "login_required")},
		{name: "ENT-22, exp at now: born expired", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(-29 * time.Minute)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "ENT-22, Hydra 401 on the reject", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: withClient(t, `{"client_uri":"`+clientURI+`"}`), requestedAt: testNow.Add(-29*time.Minute - 30*time.Second)}, RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "ENT-1, exp 1 ms after now: a flow", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(-29*time.Minute + time.Millisecond)}},
			kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.ExpiresAt != testNow.UnixMilli()+1 {
					t.Errorf("exp %d", f.ExpiresAt)
				}
			}},
		{name: "ENT-11 DEC-4, a challenge read past its lifetime", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {err: ErrChallengeExpired}}, kind: ErrorPage, code: E1002, calls: []Op{GetLogin}, check: reportedExpired},
		{name: "DEC-3, Hydra's clock 10 s ahead: reported at the creation", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(10 * time.Second), decrypted: true}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: func(t *testing.T, f *Flow) {},
			check: skewReported("Hydra's requested_at 10s ahead")},
		{name: "DEC-3, Hydra's clock 5 s ahead: within the tolerance", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(5 * time.Second), decrypted: true}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: func(t *testing.T, f *Flow) {}, check: skewReported("")},
		{name: "DEC-1, the first read ahead in fallback: not Hydra's clock", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(10 * time.Second)}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: func(t *testing.T, f *Flow) {}, check: skewReported("")},
		{name: "ECR-8, L already past its end at Hydra: no write", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: loginRequest(t), requestedAt: testNow.Add(-31 * time.Minute)}},
			kind: ErrorPage, code: E1002, calls: []Op{GetLogin}},
		{name: "ENT-9, Hydra's skip kept, ignored", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: func() *ory.OAuth2LoginRequest {
				r := loginRequest(t)
				r.Skip, r.Subject = true, "alice"
				return r
			}()}},
			kind: ChoicePage, calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if !f.Hydra.Skip || f.Hydra.Subject != "alice" || f.Subject != "" {
					t.Errorf("snapshot %+v, subject %q", f.Hydra, f.Subject)
				}
			}},
		{name: "ENT-2", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: choiceFlow(t),
			kind: ChoicePage, check: offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa")},
		{name: "ENT-2, the configuration changed: the rules apply", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: choiceFlow(t),
			env:  func(e *Env) { e.Config.Settings.AppAutoSelect = true; e.Config.Flows = e.Config.Flows[1:2] },
			kind: Redirect, url: loginURL("sql", 1000), write: started("hydra-sql", 1000, false)},
		{name: "ENT-3, from k·0", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: atStep(t, 1, false, false),
			kind: ChoicePage, write: inChoice(1001, cookie)},
		{name: "ENT-3, from k·L", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: atStep(t, 2, true, false),
			kind: ChoicePage, write: inChoice(1001, cookie)},
		{name: "ENT-3, from k·LC", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: lastDone(t),
			kind: ChoicePage, write: inChoice(1001, cookie)},
		{name: "ENT-4", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: acceptedFlow(t),
			kind: Redirect, url: hydraDone},
		{name: "ENT-4 Q31, past exp: no reject, the consent applies it", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: expired(acceptedFlow(t)),
			kind: Redirect, url: hydraDone},
		{name: "ENT-4 Q14, after the consent screen", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			stored: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			kind:   Redirect, url: "http://dispatcher.hydra.test/consent?consent_challenge=" + hydraC},
		{name: "ENT-5, another cookie", ev: Entry{LoginChallenge: hydraL, Cookie: otherCSRF}, stored: atStep(t, 1, true, false),
			kind: ChoicePage, write: inChoice(1001, otherCSRF),
			check: func(t *testing.T, p played) {
				if p.Response.SetCSRF != otherCSRF {
					t.Errorf("Set-Cookie %q", p.Response.SetCSRF)
				}
			}},
		{name: "ENT-5, no cookie, in choice", ev: Entry{LoginChallenge: hydraL}, stored: choiceFlow(t),
			kind: ChoicePage, write: inChoice(1001, newCSRF)},
		{name: "ENT-20 Q31, past exp, cookie lost: the consent shown rejected", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "ENT-20, by ref", ev: Entry{Ref: lref}, stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "ENT-20, another browser's cookie", ev: Entry{LoginChallenge: hydraL, Cookie: otherCSRF}, stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "ENT-20 R16, no consent shown: hr, which only Hydra's login cookie follows", ev: Entry{LoginChallenge: hydraL}, stored: expired(acceptedFlow(t)),
			kind: Redirect, url: hydraDone},
		{name: "ENT-20, no consent shown, by ref, another browser's cookie", ev: Entry{Ref: lref, Cookie: otherCSRF}, stored: expired(acceptedFlow(t)),
			kind: Redirect, url: hydraDone},
		{name: "ENT-20, the consent shown names another flow", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {consent: consentRequest("0123456789abcdef0123", nil)}}, kind: ErrorPage, code: E1007, calls: []Op{GetConsent}},
		{name: "ENT-20 after A3", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Subject = ory.PtrString("bob") })}, RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: finished, check: rejected(RejectConsent, "access_denied")},
		{name: "ENT-20, Hydra 401 on the reject", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, RejectConsent: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, RejectConsent}, write: finished},
		{name: "ENT-20 R16, Hydra 404 on the read: finished without a reject", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {err: err404}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}, write: finished, check: unreported},
		{name: "ENT-20 R16, Hydra 2.1 410 on the read", ev: Entry{Ref: lref}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {err: err410}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}, write: finished},
		{name: "ENT-20, Hydra unavailable on the read: flow intact", ev: Entry{Ref: lref}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {err: errDown}}, kind: ErrorPage, code: E1004, calls: []Op{GetConsent}},
		{name: "ENT-21 R16, reloaded within 10 s: the reject's cr", ev: Entry{LoginChallenge: hydraL}, stored: rejectedAgo(t, 2*time.Second),
			kind: Redirect, url: "http://hydra/cr"},
		{name: "ENT-21, by ref, another browser's cookie", ev: Entry{Ref: lref, Cookie: otherCSRF}, stored: rejectedAgo(t, 9*time.Second),
			kind: Redirect, url: "http://hydra/cr"},
		{name: "ENT-21, after a concurrent reject (Hydra 2.1 409)", ev: Entry{LoginChallenge: hydraL}, stored: shownConsent(t), reread: rejectedAgo(t, 0),
			says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, RejectConsent: {err: err409}},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent, RejectConsent}},
		{name: "ENT-21, beyond the 10 s: ENT-7", ev: Entry{LoginChallenge: hydraL}, stored: rejectedAgo(t, 10*time.Second),
			kind: ErrorPage, code: E1002, link: true},
		{name: "ENT-7, consent accepted 2 s ago: no replay on the pages, cookie or not", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			stored: finishedFlow(t, "http://hydra/cr", 2*time.Second), kind: ErrorPage, code: E1002, link: true},
		{name: "ENT-6", ev: Entry{LoginChallenge: hydraL, Cookie: otherCSRF}, stored: acceptedFlow(t),
			kind: ErrorPage, code: E1008},
		{name: "ENT-6 I1, at exp: not yet ENT-20", ev: Entry{LoginChallenge: hydraL}, stored: atExp(shownConsent(t)),
			kind: ErrorPage, code: E1008},
		{name: "ENT-18 I1, at exp", ev: Entry{Ref: lref}, stored: atExp(shownConsent(t)), kind: ErrorPage, code: E1008},
		{name: "ENT-7", ev: Entry{LoginChallenge: hydraL}, stored: finishedFlow(t, "", 0),
			kind: ErrorPage, code: E1002, link: true},
		{name: "ENT-8", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: expired(atStep(t, 1, false, false)),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{RejectLogin},
			write: finished, check: rejected(RejectLogin, "login_required")},
		{name: "ENT-8, Hydra 401", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: expired(atStep(t, 1, false, false)),
			says: hydraSays{RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}, write: finished},
		{name: "ENT-8, Hydra 404", ev: Entry{LoginChallenge: hydraL}, stored: expired(choiceFlow(t)),
			says: hydraSays{RejectLogin: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}, write: finished},
		{name: "ENT-10, Hydra 2.1 410", ev: Entry{LoginChallenge: hydraL}, says: hydraSays{GetLogin: {err: err410}},
			kind: ErrorPage, code: E1002, calls: []Op{GetLogin}, check: unreported},
		{name: "ENT-11, Hydra 2.2 401: expired, in every mode", ev: Entry{LoginChallenge: hydraL}, says: hydraSays{GetLogin: {err: err401}},
			kind: ErrorPage, code: E1002, calls: []Op{GetLogin}, check: reportedExpired},
		{name: "ENT-12 Q32, Hydra 404: forged, in every mode", ev: Entry{LoginChallenge: hydraL}, says: hydraSays{GetLogin: {err: err404}},
			kind: ErrorPage, code: E1001, calls: []Op{GetLogin}, check: reportedForged},
		{name: "ENT-12, Hydra refuses the read", ev: Entry{LoginChallenge: hydraL}, says: hydraSays{GetLogin: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{GetLogin}},
		{name: "ENT-13, nothing", ev: Entry{}, kind: ErrorPage, code: E1001},
		{name: "ENT-13, not base64url", ev: Entry{LoginChallenge: "a b"}, kind: ErrorPage, code: E1001},
		{name: "ENT-13, beyond 64 KiB", ev: Entry{LoginChallenge: strings.Repeat("a", 64<<10+1)}, kind: ErrorPage, code: E1001},
		{name: "ENT-13, a ref of another shape", ev: Entry{Ref: "ABC"}, kind: ErrorPage, code: E1001},
		{name: "ENT-13 Q10, the padding of 2.2 is readable", ev: Entry{LoginChallenge: "A-_z=="}, says: hydraSays{GetLogin: {err: err404}},
			kind: ErrorPage, code: E1001, calls: []Op{GetLogin}},
		{name: "ENT-14", ev: Entry{LoginChallenge: hydraL}, says: hydraSays{GetLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin}},
		{name: "ENT-15", ev: Entry{Ref: lref, Cookie: cookie}, kind: ErrorPage, code: E1002},
		{name: "ENT-16", ev: Entry{Ref: lref, Cookie: cookie}, stored: finishedFlow(t, "", 0), kind: ErrorPage, code: E1002, link: true},
		{name: "ENT-17, as ENT-3", ev: Entry{Ref: lref, Cookie: cookie}, stored: atStep(t, 1, false, false),
			kind: ChoicePage, write: inChoice(1001, cookie)},
		{name: "ENT-17, as ENT-2", ev: Entry{Ref: lref, Cookie: cookie}, stored: choiceFlow(t), kind: ChoicePage},
		{name: "ENT-18", ev: Entry{Ref: lref, Cookie: otherCSRF}, stored: atStep(t, 1, false, false), kind: ErrorPage, code: E1008},
		{name: "ENT-18, accepted", ev: Entry{Ref: lref}, stored: acceptedFlow(t), kind: ErrorPage, code: E1008},
		{name: "ENT-19", ev: Entry{Ref: lref, Cookie: cookie}, stored: acceptedFlow(t), kind: Redirect, url: hydraDone},
	} {
		tc.run(t)
	}
}

func TestChoiceRules(t *testing.T) {
	entry := Entry{LoginChallenge: hydraL, Cookie: cookie}
	acr := func(e *Env) {
		flows := testFlows()
		flows[2].ACR = "urn:acr:eidas"
		e.Config = store.NewSnapshot(testApps(), flows, e.Config.Settings)
	}
	for _, tc := range []pageCase{
		{name: "CHX-1, acr_values_mode require", env: requireACR, ev: entry, says: hydraSays{GetLogin: {login: withACR(t, "urn:acr:eidas")}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: rejected(RejectLogin, "unmet_authentication_requirements")},
		// Q151: acr_values are a request; no flow declaring one, every flow
		// is offered, and the event says which were asked.
		{name: "CHX-6, no flow meets acr_values: every flow offered", ev: entry,
			says: hydraSays{GetLogin: {login: withACR(t, "urn:acr:eidas", "urn:acr:other")}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie),
			check: func(t *testing.T, p played) {
				offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa")(t, p)
				if !slices.ContainsFunc(p.Reports, func(r Report) bool {
					return r.Event == EventACRValuesUnmet && r.Detail == "urn:acr:eidas urn:acr:other"
				}) {
					t.Errorf("no %s: %+v", EventACRValuesUnmet, p.Reports)
				}
			}},
		{name: "CHX-1, a flow meets acr_values", env: acr, ev: entry, says: hydraSays{GetLogin: {login: withACR(t, "urn:acr:eidas", "urn:acr:other")}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie), check: offered("hydra-oidc")},
		{name: "CHX-1, retour au choix", env: func(e *Env) { acr(e); requireACR(e) }, ev: entry,
			stored: func() *Flow {
				f := atStep(t, 1, false, false)
				f.Hydra.OIDCContext = json.RawMessage(`{"acr_values":["urn:acr:none"]}`)
				return f
			}(),
			says: hydraSays{RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{RejectLogin}, write: finished},
		{name: "CHX-2", ev: entry, says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":["nope"]}}}`)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				rejected(RejectLogin, "access_denied")(t, p)
				if d := p.calls[1].Reject.GetErrorDescription(); !strings.Contains(d, "metadata.dispatcher.flows") {
					t.Errorf("Q18, description %q", d)
				}
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "config.warning" }) {
					t.Errorf("no warning for an unknown id: %+v", p.Reports)
				}
			}},
		{name: "CHX-2, a restriction that is not a list", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":"hydra-sql"}}}`)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "CHX-2, a dispatcher member that is a list", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":["hydra-sql-2fa"]}}`)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "CHX-2, a dispatcher member that is a string", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":"hydra-sql"}}`)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "CHX-2, metadata that is no object restricts nothing", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":"hydra-sql"}`)}},
			kind: ChoicePage, calls: []Op{GetLogin}, check: offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa"), write: inChoice(5000, cookie)},
		{name: "CHX-2, a dispatcher member without flows restricts nothing", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{}}}`)}},
			kind: ChoicePage, calls: []Op{GetLogin}, check: offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa"), write: inChoice(5000, cookie)},
		{name: "CHX-2, a disabled flow is not left", env: func(e *Env) { e.Config.Flows[1].Enabled = false }, ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":["hydra-sql"]}}}`)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "CHX-2, the restriction narrows the page", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":["hydra-sql","hydra-oidc","nope"]}}}`)}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie), check: offered("hydra-oidc", "hydra-sql")},
		{name: "CHX-2, metadata null restricts nothing", ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":null}}}`)}},
			kind: ChoicePage, calls: []Op{GetLogin}, check: offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa"), write: inChoice(5000, cookie)},
		{name: "CHX-3", ev: entry, says: hydraSays{GetLogin: {login: withACR(t, preferredPrefix+"hydra-sql")}},
			kind: Redirect, url: loginURL("sql", 5000), calls: []Op{GetLogin}, write: started("hydra-sql", 5000, true)},
		{name: "CHX-3 Q19, a preferred flow not offered is ignored", ev: entry,
			says: hydraSays{GetLogin: {login: withACR(t, preferredPrefix+"hydra-nope")}},
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie),
			check: func(t *testing.T, p played) {
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "config.warning" }) {
					t.Errorf("no warning: %+v", p.Reports)
				}
			}},
		{name: "CHX-3 Q19, then the auto-selection", env: func(e *Env) { e.Config.Settings.AppAutoSelect = true }, ev: entry,
			says: hydraSays{GetLogin: {login: func() *ory.OAuth2LoginRequest {
				r := withClient(t, `{"metadata":{"dispatcher":{"flows":["hydra-oidc"]}}}`)
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{preferredPrefix + "hydra-sql"}}
				return r
			}()}},
			kind: Redirect, url: loginURL("oidc", 5000), calls: []Op{GetLogin}, write: started("hydra-oidc", 5000, true)},
		{name: "CHX-4 Q29, imposed by the client", env: func(e *Env) { e.Config.Settings.AppAutoSelect = true }, ev: entry,
			says: hydraSays{GetLogin: {login: withClient(t, `{"metadata":{"dispatcher":{"flows":["hydra-sql"]}}}`)}},
			kind: Redirect, url: loginURL("sql", 5000), calls: []Op{GetLogin}, write: started("hydra-sql", 5000, true)},
		{name: "CHX-4 Q19, app_auto_select imposes nothing", ev: entry, says: login(t),
			env: func(e *Env) {
				e.Config.Settings.AppAutoSelect = true
				e.Config.Flows[0].Enabled, e.Config.Flows[2].Enabled = false, false
			},
			kind: Redirect, url: loginURL("sql", 5000), calls: []Op{GetLogin}, write: started("hydra-sql", 5000, false)},
		{name: "CHX-5", ev: entry, says: login(t), kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie),
			check: offered("hydra-oidc", "hydra-sql", "hydra-sql-2fa")},
		{name: "CHX-5, a disabled flow is not offered", env: func(e *Env) { e.Config.Flows[0].Enabled = false }, ev: entry, says: login(t),
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie), check: offered("hydra-sql", "hydra-sql-2fa")},
		{name: "CHX-5, one flow without app_auto_select", env: func(e *Env) { e.Config.Flows = e.Config.Flows[:1] }, ev: entry, says: login(t),
			kind: ChoicePage, calls: []Op{GetLogin}, write: inChoice(5000, cookie), check: offered("hydra-oidc")},
	} {
		tc.run(t)
	}
}

func login(t *testing.T) hydraSays { return hydraSays{GetLogin: {login: loginRequest(t)}} }

func TestChoose(t *testing.T) {
	post := func(flow string) Choose {
		return Choose{FlowID: flow, LoginChallenge: hydraL, Token: cookie, Cookie: cookie, SameOrigin: true}
	}
	// preferred is f with acr_values preferring hydra-sql, a candidate.
	preferred := func(f *Flow) *Flow {
		f.Hydra.OIDCContext = json.RawMessage(`{"acr_values":["` + preferredPrefix + `hydra-sql"]}`)
		return f
	}
	restricted := func() *Flow {
		f := choiceFlow(t)
		snap, _, _ := SnapshotOf(withClient(t, `{"metadata":{"dispatcher":{"flows":["hydra-sql"]}}}`))
		f.Hydra = snap
		return f
	}
	for _, tc := range []pageCase{
		{name: "POS-1", ev: post("hydra-sql-2fa"), stored: choiceFlow(t), kind: Redirect, url: loginURL("sql", 1000),
			write: func(t *testing.T, f *Flow) {
				started("hydra-sql-2fa", 1000, false)(t, f)
				if len(f.Steps) != 2 || f.Steps[0].App != "sql" || f.Steps[0].Check != "" || f.Steps[1].Check != "equal" {
					t.Errorf("Q21, steps copied %+v", f.Steps)
				}
			}},
		{name: "POS-1 Q29, the client's only flow is imposed", ev: post("hydra-sql"), stored: restricted(),
			kind: Redirect, url: loginURL("sql", 1000), write: started("hydra-sql", 1000, true)},
		{name: "POS-1, the flow's acr copied", ev: post("hydra-oidc"), stored: choiceFlow(t),
			env:  func(e *Env) { e.Config.Flows[0].ACR = "urn:acr:x" },
			kind: Redirect, url: loginURL("oidc", 1000),
			write: func(t *testing.T, f *Flow) {
				if f.ACR != "urn:acr:x" {
					t.Errorf("acr %q", f.ACR)
				}
			}},
		{name: "POS-2, unknown flow", ev: post("nope"), stored: choiceFlow(t), kind: ChoicePage,
			check: func(t *testing.T, p played) {
				if !p.Response.Choice.Invalid {
					t.Error("no message")
				}
			}},
		{name: "POS-2, disabled flow", ev: post("hydra-sql"), stored: choiceFlow(t), env: func(e *Env) { e.Config.Flows[1].Enabled = false }, kind: ChoicePage},
		{name: "POS-2, outside the client's restriction", ev: post("hydra-oidc"), stored: restricted(), kind: ChoicePage},
		{name: "POS-2 Q30, on a step", ev: post("nope"), stored: atStep(t, 1, true, false), kind: ChoicePage},
		{name: "POS-3, token other than the cookie", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: otherCSRF, Cookie: cookie, SameOrigin: true},
			stored: choiceFlow(t), kind: ChoicePage, write: inChoice(1001, cookie),
			check: func(t *testing.T, p played) {
				if p.Response.Choice.Invalid || p.Response.SetCSRF != cookie {
					t.Errorf("Q7, page %+v, cookie %q", p.Response.Choice, p.Response.SetCSRF)
				}
			}},
		{name: "POS-3, cookie other than the flow's", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: otherCSRF, Cookie: otherCSRF, SameOrigin: true},
			stored: atStep(t, 1, false, false), kind: ChoicePage, write: inChoice(1001, otherCSRF),
			check: func(t *testing.T, p played) {
				if p.Response.SetCSRF != otherCSRF {
					t.Errorf("Q7, cookie %q", p.Response.SetCSRF)
				}
			}},
		{name: "POS-4 Q8", ev: post("hydra-sql"), stored: atStep(t, 2, true, false),
			kind: Redirect, url: loginURL("sql", 1001), write: started("hydra-sql", 1001, false)},
		{name: "POS-4 Q29, the preferred flow chosen again is imposed", ev: post("hydra-sql"), stored: preferred(atStep(t, 1, false, false)),
			kind: Redirect, url: loginURL("sql", 1001), write: started("hydra-sql", 1001, true)},
		{name: "POS-1 Q29, the preferred flow is imposed", ev: post("hydra-sql"), stored: preferred(choiceFlow(t)),
			kind: Redirect, url: loginURL("sql", 1000), write: started("hydra-sql", 1000, true)},
		{name: "POS-1 Q29, another candidate is not", ev: post("hydra-oidc"), stored: preferred(choiceFlow(t)),
			kind: Redirect, url: loginURL("oidc", 1000), write: started("hydra-oidc", 1000, false)},
		{name: "POS-5", ev: post("hydra-sql"), stored: acceptedFlow(t), kind: Redirect, url: hydraDone},
		{name: "POS-5 Q31, past exp", ev: post("hydra-sql"), stored: expired(acceptedFlow(t)), kind: Redirect, url: hydraDone},
		{name: "POS-6", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, Cookie: otherCSRF, SameOrigin: true},
			stored: acceptedFlow(t), kind: ErrorPage, code: E1008},
		{name: "POS-7", ev: post("hydra-sql"), stored: finishedFlow(t, "", 0), kind: ErrorPage, code: E1002, link: true},
		{name: "POS-8", ev: post("hydra-sql"), kind: ErrorPage, code: E1002},
		{name: "POS-10 Q31, past exp, cookie lost: the consent shown rejected", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, SameOrigin: true},
			stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "POS-10 R16, no consent shown: hr", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, SameOrigin: true},
			stored: expired(acceptedFlow(t)), kind: Redirect, url: hydraDone},
		{name: "POS-10, the cookie without the form's token", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Cookie: cookie, SameOrigin: true},
			stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "POS-6 I1, at exp: not yet POS-10", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, SameOrigin: true},
			stored: atExp(shownConsent(t)), kind: ErrorPage, code: E1008},
		{name: "POS-11 R16, posted again within 10 s: the reject's cr", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, SameOrigin: true},
			stored: rejectedAgo(t, 2*time.Second), kind: Redirect, url: "http://hydra/cr"},
		{name: "POS-9 before POS-11", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie}, stored: rejectedAgo(t, 2*time.Second),
			kind: ErrorPage, code: E1008},
		{name: "POS-9 before POS-10", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie}, stored: shownConsent(t),
			kind: ErrorPage, code: E1008},
		{name: "POS-9", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: cookie, Cookie: cookie}, stored: choiceFlow(t),
			kind: ErrorPage, code: E1008},
		{name: "BCL-11, the first app gone at the start: nothing written", ev: post("hydra-sql"), stored: choiceFlow(t),
			env:  func(e *Env) { e.Config = store.NewSnapshot(testApps()[1:], testFlows(), e.Config.Settings) },
			kind: ErrorPage, code: E1005},
		{name: "POS, L illegible", ev: Choose{LoginChallenge: "", SameOrigin: true}, kind: ErrorPage, code: E1001},
		{name: "POS, expired", ev: post("hydra-sql"), stored: expired(choiceFlow(t)), says: hydraSays{RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{RejectLogin}, write: finished},
	} {
		tc.run(t)
	}
}

func TestLoop(t *testing.T) {
	loop := Loop{Ref: lref, Cookie: cookie}
	for _, tc := range []pageCase{
		{name: "BCL-1", ev: loop, kind: ErrorPage, code: E1002},
		{name: "BCL-2", ev: Loop{Ref: lref}, stored: finishedFlow(t, "", 0), kind: ErrorPage, code: E1002, link: true},
		{name: "BCL-3", ev: Loop{Ref: lref, Cookie: otherCSRF}, stored: atStep(t, 1, false, false), kind: ErrorPage, code: E1008},
		{name: "BCL-3, accepted", ev: Loop{Ref: lref}, stored: acceptedFlow(t), kind: ErrorPage, code: E1008},
		{name: "BCL-16 Q31, past exp, cookie lost: the consent shown rejected", ev: Loop{Ref: lref}, stored: shownConsent(t), says: pastExpSays(),
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "BCL-16 R16, no consent shown: hr", ev: Loop{Ref: lref}, stored: expired(acceptedFlow(t)), kind: Redirect, url: hydraDone},
		{name: "BCL-3, no consent shown, before exp: never hr without the cookie", ev: Loop{Ref: lref}, stored: acceptedFlow(t), kind: ErrorPage, code: E1008},
		{name: "BCL-3 before exp, the consent shown", ev: Loop{Ref: lref}, stored: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			kind: ErrorPage, code: E1008},
		{name: "BCL-3 I1, at exp: not yet BCL-16", ev: Loop{Ref: lref}, stored: atExp(shownConsent(t)), kind: ErrorPage, code: E1008},
		{name: "BCL-16 R16, Hydra 2.2 401 on the read: finished without a reject", ev: Loop{Ref: lref}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {err: err401}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}, write: finished, check: unreported},
		{name: "BCL-16, the consent shown read past its lifetime (DEC-4): not counted", ev: Loop{Ref: lref}, stored: shownConsent(t),
			says: hydraSays{GetConsent: {err: ErrChallengeExpired}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}, write: finished, check: unreported},
		{name: "BCL-17 R16, reloaded within 10 s: the reject's cr", ev: Loop{Ref: lref}, stored: rejectedAgo(t, 2*time.Second),
			kind: Redirect, url: "http://hydra/cr"},
		{name: "BCL-17, after a concurrent reject (Hydra 2.1 409)", ev: Loop{Ref: lref}, stored: shownConsent(t), reread: rejectedAgo(t, 0),
			says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, RejectConsent: {err: err409}},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent, RejectConsent}},
		{name: "BCL-4 RA5", ev: loop, stored: acceptedFlow(t), kind: Redirect, url: hydraDone},
		{name: "BCL-4 Q31, past exp", ev: loop, stored: expired(acceptedFlow(t)), kind: Redirect, url: hydraDone},
		{name: "BCL-4 Q14", ev: loop, stored: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			kind: Redirect, url: "http://dispatcher.hydra.test/consent?consent_challenge=" + hydraC},
		{name: "BCL-5 Q15", ev: loop, stored: choiceFlow(t), kind: ChoicePage},
		{name: "BCL-6", ev: loop, stored: atStep(t, 1, false, false), kind: Redirect, url: loginURL("sql", 1000)},
		{name: "BCL-6, second step", ev: loop, stored: atStep(t, 2, false, false), kind: Redirect, url: loginURL("2fa", 1000)},
		{name: "BCL-7", ev: loop, stored: atStep(t, 1, true, false), kind: Redirect, url: consentURL("sql", 1000)},
		{name: "BCL-8", ev: loop, stored: atStep(t, 1, true, true), says: login(t),
			kind: Redirect, url: loginURL("2fa", 1000), calls: []Op{GetLogin},
			write: func(t *testing.T, f *Flow) {
				if f.Current != 2 || f.StateAt(testNow) != StepLogin || !f.Steps[0].ConsentOK {
					t.Errorf("flow %+v", f)
				}
			}},
		{name: "BCL-8, the app's own query kept", ev: loop, stored: atStep(t, 1, true, true), says: login(t),
			env: func(e *Env) {
				apps := testApps()
				apps[1].LoginURL = "http://2fa.hydra.test/login?theme=dark"
				e.Config = store.NewSnapshot(apps, testFlows(), e.Config.Settings)
			},
			kind: Redirect, calls: []Op{GetLogin}, write: func(*testing.T, *Flow) {},
			check: func(t *testing.T, p played) {
				u, _ := url.Parse(p.Response.URL)
				if u.Query().Get("theme") != "dark" || u.Query().Get("login_challenge") == "" {
					t.Errorf("url %q", p.Response.URL)
				}
			}},
		{name: "BCL-9, 404: L comes from the flow, never counted", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin}, write: finished, check: unreported},
		{name: "BCL-9, 401", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin}, write: finished, check: unreported},
		{name: "BCL-9, DEC-4", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: ErrChallengeExpired}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin}, write: finished, check: unreported},
		{name: "BCL-9, 410", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: err410}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin}, write: finished, check: unreported},
		{name: "BCL-10", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin}},
		{name: "BCL-10, Hydra refuses the read", ev: loop, stored: atStep(t, 1, true, true), says: hydraSays{GetLogin: {err: err403}},
			kind: ErrorPage, code: E1007, calls: []Op{GetLogin}},
		{name: "BCL-11", ev: loop, stored: func() *Flow { f := atStep(t, 1, false, false); f.Steps[0].App = "gone"; return f }(),
			kind: ErrorPage, code: E1005},
		{name: "BCL-11 Q30, next app gone, no call", ev: loop, stored: func() *Flow { f := atStep(t, 1, true, true); f.Steps[1].App = "gone"; return f }(),
			kind: ErrorPage, code: E1005},
		{name: "BCL-11, current app gone at the final accept", ev: loop, stored: func() *Flow { f := lastDone(t); f.Steps[1].App = "gone"; return f }(),
			kind: ErrorPage, code: E1005},
		{name: "BCL-12", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{AcceptLogin}, write: func(*testing.T, *Flow) {}},
		{name: "BCL-13", ev: loop, stored: expired(atStep(t, 2, true, false)), says: hydraSays{RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{RejectLogin}, write: finished},
		{name: "BCL-14 Q16", ev: Loop{LoginChallenge: "a+b"}, kind: Redirect, url: "http://dispatcher.hydra.test/?login_challenge=a%2Bb"},
		{name: "BCL-15", ev: Loop{}, kind: ErrorPage, code: E1001},
		{name: "BCL-15, a ref of another shape", ev: Loop{Ref: "nope"}, kind: ErrorPage, code: E1001},
		{name: "EXP-1, hx reached", ev: loop, stored: func() *Flow { f := atStep(t, 1, false, false); f.HydraExpiresAt = testNow.UnixMilli(); return f }(),
			kind: ErrorPage, code: E1002},
	} {
		tc.run(t)
	}
}

func TestFinalAccept(t *testing.T) {
	loop := Loop{Ref: lref, Cookie: cookie}
	accept := hydraSays{AcceptLogin: {redirectTo: hydraDone}}
	accepted := func(t *testing.T, f *Flow) {
		t.Helper()
		if f.HydraRedirect != hydraDone || f.StateAt(testNow) != Accepted || f.Sent == nil || f.Sent.Subject != "alice" {
			t.Errorf("flow %+v, sent %+v", f, f.Sent)
		}
	}
	body := func(want func(t *testing.T, b ory.AcceptOAuth2LoginRequest)) func(t *testing.T, p played) {
		return func(t *testing.T, p played) {
			t.Helper()
			for _, c := range p.calls {
				if c.Op == AcceptLogin {
					want(t, c.AcceptLogin)
					return
				}
			}
			t.Error("no accept")
		}
	}
	skip := func(sub string) *Flow {
		f := lastDone(t)
		f.Hydra.Skip, f.Hydra.Subject = true, sub
		f.Hydra.RequestURL = "http://public.hydra.test/oauth2/auth?client_id=c"
		return f
	}
	hook := func(e *Env) { e.Config.Settings.LoginAcceptWebhookURL = "http://hook.test/" }
	for _, tc := range []pageCase{
		{name: "FIN-1", ev: loop, stored: lastDone(t), says: accept, kind: Redirect, url: hydraDone, calls: []Op{AcceptLogin},
			write: func(t *testing.T, f *Flow) {
				accepted(t, f)
				if f.Sent.ACR != "2" || !slices.Equal(f.Sent.AMR, []string{"pwd", "otp"}) {
					t.Errorf("sent %+v", f.Sent)
				}
			},
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				ctx := rawJSON(b.Context)
				if b.Subject != "alice" || b.GetAcr() != "2" || !slices.Equal(b.Amr, []string{"pwd", "otp"}) || !b.GetRemember() || b.GetRememberFor() != 86400 {
					t.Errorf("A8, accept %+v", b)
				}
				if ctx != `{"from":"2fa","x_dispatcher_ref":"`+lref+`"}` {
					t.Errorf("context %s", ctx)
				}
			})},
		{name: "FIN-1, amr aggregated", ev: loop, stored: lastDone(t), says: accept, env: func(e *Env) { e.Config.Settings.AggregateAMRFromLoginRequest = true },
			kind: Redirect, url: hydraDone, calls: []Op{AcceptLogin}, write: accepted,
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				if !slices.Equal(b.Amr, []string{"amr-sql", "amr-2fa"}) {
					t.Errorf("amr %q", b.Amr)
				}
			})},
		{name: "FIN-1, x_dispatcher_ref overwrites the apps'", ev: loop, says: accept, kind: Redirect, url: hydraDone, calls: []Op{AcceptLogin}, write: accepted,
			stored: func() *Flow {
				f := lastDone(t)
				f.Steps[1].ConsentContext["x_dispatcher_ref"] = json.RawMessage(`"forged"`)
				return f
			}(),
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				if !strings.Contains(rawJSON(b.Context), `"x_dispatcher_ref":"`+lref+`"`) {
					t.Errorf("context %s", rawJSON(b.Context))
				}
			})},
		{name: "FIN-1 A9, the webhook's context", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`{"hook":true}`), ACR: ory.PtrString("hook"), AMR: []string{"hook"},
				Remember: ory.PtrBool(false), RememberFor: ory.PtrInt64(60)}}, AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin}, write: accepted,
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				if rawJSON(b.Context) != `{"hook":true,"x_dispatcher_ref":"`+lref+`"}` || b.GetAcr() != "hook" || b.Amr[0] != "hook" || b.GetRemember() || b.GetRememberFor() != 60 {
					t.Errorf("accept %+v, context %s", b, rawJSON(b.Context))
				}
			})},
		{name: "FIN-1 A9, a webhook context null is {}", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`null`)}}, AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin}, write: accepted,
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				if rawJSON(b.Context) != `{"x_dispatcher_ref":"`+lref+`"}` {
					t.Errorf("context %s", rawJSON(b.Context))
				}
			})},
		{name: "FIN-2", ev: loop, stored: skip("alice"), says: accept, kind: Redirect, url: hydraDone, calls: []Op{AcceptLogin}, write: accepted},
		{name: "FIN-2 A7, compared after the webhook", ev: loop, stored: skip("bob"), env: hook,
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin},
			write: func(t *testing.T, f *Flow) {
				if f.Sent.Subject != "bob" {
					t.Errorf("sent %+v", f.Sent)
				}
			}},
		{name: "FIN-3", ev: loop, stored: skip("bob"), says: hydraSays{RejectLogin: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1003, calls: []Op{RejectLogin}, write: finished, check: func(t *testing.T, p played) {
				rejected(RejectLogin, "login_required")(t, p)
				if p.Response.SignOut != "http://public.hydra.test/oauth2/sessions/logout" { // Q60
					t.Errorf("the way out: %q", p.Response.SignOut)
				}
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "flow.rejected" && r.Detail == "skip_subject" }) { // Q67
					t.Errorf("reports %+v", p.Reports)
				}
			}},
		{name: "FIN-3, Hydra 401", ev: loop, stored: skip("bob"), says: hydraSays{RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}, write: finished},
		{name: "FIN-4, webhook failed", ev: loop, stored: lastDone(t), env: hook, says: hydraSays{LoginHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{LoginHook}},
		{name: "FIN-4 A9, webhook context a list", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`["a"]`)}}},
			kind: ErrorPage, code: E1006, calls: []Op{LoginHook}, check: hookReport("webhook.failed", "login")},
		{name: "FIN-4, what the log says of a webhook that failed", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {hookErr: &HookError{Host: "hooks:8443", Status: 503, Cause: "status 503", Elapsed: time.Second, Err: errDown}}},
			kind: ErrorPage, code: E1006, calls: []Op{LoginHook}, check: func(t *testing.T, p played) {
				hookReport("webhook.failed", "login")(t, p)
				i := slices.IndexFunc(p.Reports, func(r Report) bool { return r.Event == "webhook.failed" })
				if r := p.Reports[i]; r.Host != "hooks:8443" || r.Status != 503 || r.Detail != "status 503" || r.Sentry {
					t.Errorf("report %+v", r)
				}
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "flow.error" && r.Detail == "E1006" && r.Sentry }) {
					t.Errorf("no flow.error: %+v", p.Reports)
				}
			}},
		{name: "FIN-4 Q72, a client gone: neither webhook.failed nor Sentry", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {hookErr: &HookError{Host: "hooks", Cause: "the client left", Elapsed: 2 * time.Second, Err: context.Canceled}}},
			kind: ErrorPage, code: E1006, calls: []Op{LoginHook}, check: func(t *testing.T, p played) {
				if len(p.Reports) != 1 || p.Reports[0].Event != "webhook.abandoned" || p.Reports[0].Host != "hooks" || p.Reports[0].Sentry || p.Reports[0].Elapsed != 2*time.Second {
					t.Errorf("reports %+v", p.Reports)
				}
			}},
		{name: "FIN-1, the call: the location of the snapshot, the client, L", ev: loop, stored: lastDone(t), env: hook, says: hydraSays{LoginHook: {}, AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin}, write: accepted, check: func(t *testing.T, p played) {
				c := p.calls[0]
				if c.Challenge != hydraL || c.Hook == nil || c.Hook.Location != "http://hook.test/" || !strings.Contains(string(c.Hook.Client), `"client_id"`) {
					t.Errorf("call %+v", c)
				}
				if _, ok := c.AcceptLogin.Context.(Object); !ok {
					t.Errorf("context %T: no x_dispatcher_ref yet, an object", c.AcceptLogin.Context)
				}
				if strings.Contains(rawJSON(c.AcceptLogin.Context), memberRef) {
					t.Errorf("x_dispatcher_ref sent to the webhook: %s", rawJSON(c.AcceptLogin.Context))
				}
			}},
		{name: "FIN-1 R28, the webhook gets no x_dispatcher_* of an app, as at a skip", ev: loop, env: hook, says: hydraSays{LoginHook: {}, AcceptLogin: {redirectTo: hydraDone}},
			stored: func() *Flow {
				f := lastDone(t)
				f.Steps[1].ConsentContext["x_dispatcher_ref"] = json.RawMessage(`"forged"`)
				f.Steps[1].ConsentContext["x_dispatcher_other"] = json.RawMessage(`1`)
				return f
			}(),
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin}, write: accepted, check: func(t *testing.T, p played) {
				if ctx := rawJSON(p.calls[0].AcceptLogin.Context); ctx != `{"from":"2fa"}` {
					t.Errorf("context sent to the webhook: %s", ctx)
				}
			}},
		{name: "FIN-1, a null from the webhook drops the member, as Symfony", ev: loop, stored: lastDone(t), env: hook,
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{NullACR: true, NullRemember: true, NullRememberFor: true}}, AcceptLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{LoginHook, AcceptLogin}, write: accepted,
			check: body(func(t *testing.T, b ory.AcceptOAuth2LoginRequest) {
				if b.Acr != nil || b.Remember != nil || b.RememberFor != nil {
					t.Errorf("accept %+v", b)
				}
			})},
		{name: "FIN-5, accepted by a concurrent request", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err409}},
			reread: func() *Flow { f := acceptedFlow(t); f.HydraRedirect = "http://hydra/theirs"; return f }(),
			kind:   Redirect, url: "http://hydra/theirs", calls: []Op{AcceptLogin}},
		{name: "FIN-5 Q14, its verifier followed", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err409}},
			reread: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			kind:   Redirect, url: "http://dispatcher.hydra.test/consent?consent_challenge=" + hydraC, calls: []Op{AcceptLogin}},
		{name: "FIN-5, finished meanwhile", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err409}},
			reread: finishedFlow(t, "", 0), kind: ErrorPage, code: E1002, link: true, calls: []Op{AcceptLogin}},
		{name: "FIN-5, nothing changed", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{AcceptLogin}},
		{name: "FIN-6, 401", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{AcceptLogin}, write: finished},
		{name: "FIN-6, 404", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{AcceptLogin}, write: finished},
		{name: "FIN-7, 400", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{AcceptLogin}},
		{name: "FIN-7, 403", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err403}},
			kind: ErrorPage, code: E1007, calls: []Op{AcceptLogin}},
		{name: "FIN-7 Q11, 400, accepted by a concurrent request", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: err400}},
			reread: func() *Flow { f := acceptedFlow(t); f.HydraRedirect = "http://hydra/theirs"; return f }(),
			kind:   Redirect, url: "http://hydra/theirs", calls: []Op{AcceptLogin}},
		{name: "FIN-8", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{AcceptLogin}},
		{name: "FIN-8, 2xx without redirect_to", ev: loop, stored: lastDone(t), says: hydraSays{AcceptLogin: {}},
			kind: ErrorPage, code: E1004, calls: []Op{AcceptLogin}},
	} {
		tc.run(t)
	}
}

// shownPrint is the print of the claims the screen of acceptedFlow shows, which
// its form posts (CST-13, CST-14).
var shownPrint = testKeys.ClaimsPrint(Object{"email": json.RawMessage(`"alice@example.org"`), "step": json.RawMessage(`"2fa"`)}, Object{})

func TestConsent(t *testing.T) {
	get := Consent{Challenge: hydraC, Cookie: cookie}
	post := func(accept bool) Consent {
		return Consent{Challenge: hydraC, Cookie: cookie, Post: true, Accept: accept, Token: cookie, SameOrigin: true, Print: shownPrint}
	}
	read := func(mod func(r *ory.OAuth2ConsentRequest)) said { return said{consent: consentRequest(lref, mod)} }
	// notOurs wants the reject of A3, its audit event naming the check that
	// failed (CST-8 flow, CST-9 session, CST-10 subject, CST-23 login).
	notOurs := func(check string) func(t *testing.T, p played) {
		return func(t *testing.T, p played) {
			t.Helper()
			rejected(RejectConsent, "access_denied")(t, p)
			if !slices.ContainsFunc(p.Reports, func(r Report) bool {
				return r.Audit && r.Event == "flow.rejected" && r.Detail == "not_ours:"+check
			}) {
				t.Errorf("A3, no audit event not_ours:%s: %+v", check, p.Reports)
			}
		}
	}
	reducedNoCR := func(t *testing.T, f *Flow) {
		t.Helper()
		finished(t, f)
		if f.ConsentRedirect != "" {
			t.Errorf("the A3 reject's redirect_to is kept: %q", f.ConsentRedirect)
		}
	}
	for _, tc := range []pageCase{
		{name: "CST-1", ev: Consent{}, kind: ErrorPage, code: E1001},
		{name: "CST-1, illegible", ev: Consent{Challenge: "a/b"}, kind: ErrorPage, code: E1001},
		{name: "CST-2 Q32, forged", ev: get, says: hydraSays{GetConsent: {err: err404}}, kind: ErrorPage, code: E1001, calls: []Op{GetConsent},
			check: reportedForged},
		{name: "CST-2 Q32, the consent shown, posted: forged all the same", ev: post(true), stored: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			says: hydraSays{GetConsent: {err: err404}}, kind: ErrorPage, code: E1001, calls: []Op{GetConsent}, check: reportedForged},
		{name: "CST-3", ev: get, says: hydraSays{GetConsent: {err: err410}}, kind: ErrorPage, code: E1002, calls: []Op{GetConsent}, check: unreported},
		{name: "CST-4: expired, in every mode", ev: get, says: hydraSays{GetConsent: {err: err401}}, kind: ErrorPage, code: E1002, calls: []Op{GetConsent},
			check: reportedExpired},
		{name: "CST-5 A6", ev: get,
			says: hydraSays{GetConsent: {consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Context = nil })}, RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
		{name: "CST-5, Hydra 410 on the reject", ev: get,
			says: hydraSays{GetConsent: {consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{}`) })}, RejectConsent: {err: err410}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-5, Hydra unavailable on the reject", ev: get,
			says: hydraSays{GetConsent: {consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Context = nil })}, RejectConsent: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-5, Hydra refuses the reject", ev: get,
			says: hydraSays{GetConsent: {consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Context = nil })}, RejectConsent: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-6 T2", ev: get, says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "CST-6, a ref of another shape", ev: get, says: hydraSays{GetConsent: {consent: consentRequest("forged", nil)}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "CST-7", ev: get, stored: finishedFlow(t, "", 0), says: hydraSays{GetConsent: read(nil)},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-7, past 10 s", ev: get, stored: finishedFlow(t, hydraDone, 10*time.Second), says: hydraSays{GetConsent: read(nil)},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-7, another cookie within 10 s", ev: Consent{Challenge: hydraC, Cookie: otherCSRF}, stored: finishedFlow(t, hydraDone, time.Second),
			says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-8 I8", ev: get, stored: lastDone(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("flow")},
		{name: "CST-8, in choice, no cookie", ev: Consent{Challenge: hydraC}, stored: choiceFlow(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("flow")},
		{name: "CST-8 Q20, generic description", ev: get, stored: atStep(t, 1, false, false), says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR,
			check: func(t *testing.T, p played) {
				if d := p.calls[1].Reject.GetErrorDescription(); strings.Contains(d, "alice") || d == "" {
					t.Errorf("description %q", d)
				}
			}},
		{name: "CST-9", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.LoginSessionId = ory.PtrString("other") }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("session")},
		{name: "CST-10", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Subject = ory.PtrString("bob") }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("subject")},
		{name: "CST-10 Q30, before the cookie", ev: Consent{Challenge: hydraC}, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Subject = ory.PtrString("bob") }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR},
		{name: "CST-16, counted as a return", ev: get, stored: finishedFlow(t, hydraDone, 2*time.Second), says: hydraSays{GetConsent: read(nil)}, kind: Redirect, url: hydraDone, calls: []Op{GetConsent},
			check: func(t *testing.T, p played) {
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "consent.resubmitted" && r.Result == "replayed" }) {
					t.Errorf("reports %+v", p.Reports)
				}
			}},
		{name: "CST-7, counted as a return too late", ev: get, stored: finishedFlow(t, hydraDone, time.Minute), says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent},
			check: func(t *testing.T, p played) {
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "consent.resubmitted" && r.Result == "too_late" }) {
					t.Errorf("reports %+v", p.Reports)
				}
			}},
		{name: "CST-12 Q38, the webhook gets what Hydra holds of the login and the context sent", ev: get,
			stored: func() *Flow {
				f := acceptedFlow(t)
				f.Sent.Context = Object{"from": json.RawMessage(`"login"`)}
				return f
			}(),
			env: func(e *Env) {
				e.Config.Settings.ConsentAutoAccept, e.Config.Settings.ConsentAcceptWebhookURL = true, "http://hook.test/consent"
			},
			says: hydraSays{GetConsent: read(nil), ConsentHook: {}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, ConsentHook, AcceptConsent}, write: finishedWithCR,
			check: func(t *testing.T, p played) {
				h := p.calls[1].Hook
				if h == nil || h.Location != "http://hook.test/consent" || h.Subject != "alice" || !strings.Contains(string(h.Client), `"client_id"`) {
					t.Fatalf("hook %+v", h)
				}
				if got := rawJSON(h.Context); got != `{"from":"login"}` {
					t.Errorf("context %s, want the one sent, never the consent request's", got)
				}
			}},
		{name: "CST-11", ev: Consent{Challenge: hydraC, Cookie: otherCSRF}, stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil)},
			kind: ErrorPage, code: E1008, calls: []Op{GetConsent}},
		{name: "CST-11, POST token", ev: Consent{Challenge: hydraC, Cookie: cookie, Post: true, Accept: true, Token: otherCSRF, SameOrigin: true},
			stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1008, calls: []Op{GetConsent}},
		{name: "CST-11 I1, at exp: not yet CST-22", ev: Consent{Challenge: hydraC}, stored: atExp(acceptedFlow(t)), says: hydraSays{GetConsent: read(nil)},
			kind: ErrorPage, code: E1008, calls: []Op{GetConsent}},
		{name: "CST-23 Q34, the consent request of another login", ev: get, stored: withLoginID(acceptedFlow(t), hydraL),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.LoginChallenge = ory.PtrString("0123456789abcdef0123456789abcdef")
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("login")},
		{name: "CST-23, before CST-22 and the cookie", ev: Consent{Challenge: hydraC}, stored: withLoginID(expired(acceptedFlow(t)), hydraL),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("login")},
		{name: "CST-23, the login of the flow: the screen", ev: get, stored: withLoginID(acceptedFlow(t), hydraL),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.LoginChallenge = ory.PtrString(hydraL) })},
			kind: ConsentPage, calls: []Op{GetConsent}, write: func(t *testing.T, f *Flow) {}},
		{name: "CST-4 DEC-4, a consent challenge read past its lifetime", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: {err: ErrChallengeExpired}}, kind: ErrorPage, code: E1002, calls: []Op{GetConsent}, check: reportedExpired},
		{name: "CST-14 I1, accepted at exp", ev: post(true), stored: atExp(acceptedFlow(t)), says: hydraSays{GetConsent: read(nil), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR},
		{name: "CST-12, Hydra's skip", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(true) }), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR,
			check: func(t *testing.T, p played) {
				b := p.calls[1].AcceptConsent
				if !slices.Equal(b.GrantScope, []string{"openid", "email"}) || b.GrantAccessTokenAudience == nil || b.GetRememberFor() != 2629800 || !b.GetRemember() {
					t.Errorf("A8, accept %+v", b)
				}
				if got := rawJSON(b.Session.IdToken); got != `{"email":"alice@example.org","step":"2fa"}` {
					t.Errorf("A2, id_token %s", got)
				}
				if got := rawJSON(b.Session.AccessToken); got != `{}` {
					t.Errorf("access_token %s", got)
				}
			}},
		{name: "CST-12, client skip_consent", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Client.SkipConsent = ory.PtrBool(true) }), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR},
		{name: "CST-12, consent_auto_accept", ev: get, stored: acceptedFlow(t), env: func(e *Env) { e.Config.Settings.ConsentAutoAccept = true },
			says: hydraSays{GetConsent: read(nil), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR},
		{name: "CST-12, consent webhook", ev: get, stored: acceptedFlow(t),
			env: func(e *Env) {
				e.Config.Settings.ConsentAutoAccept, e.Config.Settings.ConsentAcceptWebhookURL = true, "http://hook.test/"
			},
			says: hydraSays{GetConsent: read(nil), ConsentHook: {}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, ConsentHook, AcceptConsent}, write: finishedWithCR},
		{name: "CST-12, consent webhook failed", ev: get, stored: acceptedFlow(t),
			env: func(e *Env) {
				e.Config.Settings.ConsentAutoAccept, e.Config.Settings.ConsentAcceptWebhookURL = true, "http://hook.test/"
			},
			says: hydraSays{GetConsent: read(nil), ConsentHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{GetConsent, ConsentHook}},
		{name: "CST-13", ev: get, stored: func() *Flow {
			f := acceptedFlow(t)
			f.Steps[1].AccessToken = Object{"roles": json.RawMessage(`["admin"]`)}
			return f
		}(), says: hydraSays{GetConsent: read(nil)},
			kind: ConsentPage, calls: []Op{GetConsent},
			write: func(t *testing.T, f *Flow) {
				if f.ConsentChallenge != hydraC || f.StateAt(testNow) != Accepted {
					t.Errorf("Q14, cc %q", f.ConsentChallenge)
				}
			},
			check: func(t *testing.T, p played) {
				c := p.Response.Consent
				if c.Challenge != hydraC || c.CSRF != cookie || !slices.Equal(c.Scopes, []string{"openid", "email"}) || rawJSON(c.Claims) != `{"email":"alice@example.org","step":"2fa"}` {
					t.Errorf("screen %+v", c)
				}
				// What is shown is what is sent: the access token's claims and
				// the subject too.
				if c.Subject != "alice" || rawJSON(c.AccessClaims) != `{"roles":["admin"]}` {
					t.Errorf("subject %q, access token %s", c.Subject, rawJSON(c.AccessClaims))
				}
			}},
		{name: "CST-13, cc already kept", ev: get, stored: func() *Flow { f := acceptedFlow(t); f.ConsentChallenge = hydraC; return f }(),
			says: hydraSays{GetConsent: read(nil)}, kind: ConsentPage, calls: []Op{GetConsent}},
		{name: "CST-14 B3", ev: post(true), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR},
		{name: "CST-15", ev: post(false), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "access_denied")},
		{name: "CST-16, GET", ev: get, stored: finishedFlow(t, "http://hydra/cr", 2*time.Second), says: hydraSays{GetConsent: read(nil)},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent}},
		{name: "CST-16, POST", ev: post(true), stored: finishedFlow(t, "http://hydra/cr", 9*time.Second), says: hydraSays{GetConsent: read(nil)},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent}},
		{name: "CST-16 Q31, rejected past exp: replayed without the cookie", ev: Consent{Challenge: hydraC, Post: true, Accept: true, SameOrigin: true},
			stored: rejectedAgo(t, 2*time.Second), says: hydraSays{GetConsent: read(nil)},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent}},
		{name: "CST-16 Q31, rejected past exp, GET without the cookie", ev: Consent{Challenge: hydraC}, stored: rejectedAgo(t, 9*time.Second),
			says: hydraSays{GetConsent: read(nil)}, kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent}},
		{name: "CST-16 Q31, rejected past exp, beyond the 10 s: CST-7", ev: Consent{Challenge: hydraC}, stored: rejectedAgo(t, 10*time.Second),
			says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-16, settled before exp: the cookie still required", ev: Consent{Challenge: hydraC},
			stored: func() *Flow {
				f := finishedFlow(t, "http://hydra/cr", 2*time.Second)
				f.ExpiresAt = testNow.Add(-time.Second).UnixMilli()
				return f
			}(),
			says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-16 I1, accepted at exp (ct = exp): the cookie still required", ev: Consent{Challenge: hydraC},
			stored: func() *Flow {
				f := finishedFlow(t, "http://hydra/cr", 2*time.Second)
				f.ExpiresAt = f.ConsentAt
				return f
			}(),
			says: hydraSays{GetConsent: read(nil)}, kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent}},
		{name: "CST-17 Q31, rejected past exp by a concurrent request", ev: Consent{Challenge: hydraC}, stored: expired(acceptedFlow(t)), reread: rejectedAgo(t, 0),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err409}},
			kind: Redirect, url: "http://hydra/cr", calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-17, finished by a concurrent request", ev: post(true), stored: acceptedFlow(t), reread: finishedFlow(t, "http://hydra/theirs", 0),
			says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err409}},
			kind: Redirect, url: "http://hydra/theirs", calls: []Op{GetConsent, AcceptConsent}},
		{name: "CST-17, nothing changed", ev: post(false), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-18, 401", ev: post(true), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, AcceptConsent}, write: finished},
		{name: "CST-18, 404", ev: post(true), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, AcceptConsent}, write: finished},
		{name: "CST-19, the read", ev: get, says: hydraSays{GetConsent: {err: errDown}}, kind: ErrorPage, code: E1004, calls: []Op{GetConsent}},
		{name: "CST-19, the read refused", ev: get, says: hydraSays{GetConsent: {err: err400}}, kind: ErrorPage, code: E1007, calls: []Op{GetConsent}},
		{name: "CST-19, the accept", ev: post(true), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, AcceptConsent}},
		{name: "CST-19, 2xx without redirect_to", ev: post(false), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-20, 400", ev: post(true), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, AcceptConsent}},
		{name: "CST-20, 403", ev: post(false), stored: acceptedFlow(t), says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err403}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-20 Q11, 400, finished by a concurrent request", ev: post(true), stored: acceptedFlow(t), reread: finishedFlow(t, "http://hydra/theirs", 0),
			says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err400}},
			kind: Redirect, url: "http://hydra/theirs", calls: []Op{GetConsent, AcceptConsent}},
		{name: "CST-21", ev: Consent{Challenge: hydraC, Cookie: cookie, Post: true, Token: cookie}, kind: ErrorPage, code: E1008},
		{name: "CST-22 Q31, past exp: the consent rejected, not L", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "CST-22, accept pressed past exp", ev: post(true), stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "CST-22, Hydra's skip past exp", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(true) }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "CST-22, Hydra 404 on the reject", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, RejectConsent}, write: finished},
		{name: "CST-22, Hydra 410 on the reject", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err410}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, RejectConsent}, write: finished},
		{name: "CST-22, Hydra 409 on the reject, nothing changed", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-22, Hydra 400 on the reject", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-22, Hydra unavailable", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, RejectConsent}},
		{name: "CST-22, Hydra 401 on the reject", ev: post(true), stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetConsent, RejectConsent}, write: finished},
		{name: "CST-22 after A3", ev: get, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Subject = ory.PtrString("bob") }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("subject")},
		{name: "CST-22 before the cookie, gone with exp", ev: Consent{Challenge: hydraC, Post: true, Accept: true, SameOrigin: true}, stored: expired(acceptedFlow(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rejected(RejectConsent, "login_required")},
		{name: "CST-22 after CST-21", ev: Consent{Challenge: hydraC, Cookie: cookie, Post: true, Accept: true, Token: cookie}, stored: expired(acceptedFlow(t)),
			kind: ErrorPage, code: E1008},
		{name: "CST-8 Q31, expired before the final accept", ev: get, stored: expired(lastDone(t)),
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, write: reducedNoCR, check: notOurs("flow")},
	} {
		tc.run(t)
	}
}

// Rejects of the pages and their Hydra errors (EXP-4).
func TestPageRejects(t *testing.T) {
	entry := Entry{LoginChallenge: hydraL, Cookie: cookie}
	unmet := withACR(t, "urn:acr:none")
	for _, tc := range []pageCase{
		{name: "EXP-4, 410", ev: entry, stored: expired(choiceFlow(t)), says: hydraSays{RejectLogin: {err: err410}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}, write: finished},
		{name: "EXP-4, 409, finished meanwhile", ev: entry, stored: expired(choiceFlow(t)), reread: finishedFlow(t, "", 0),
			says: hydraSays{RejectLogin: {err: err409}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}},
		{name: "EXP-4, 409, nothing changed", ev: entry, stored: expired(choiceFlow(t)),
			says: hydraSays{RejectLogin: {err: err409}}, kind: ErrorPage, code: E1007, calls: []Op{RejectLogin}},
		{name: "EXP-4, 400", ev: entry, stored: expired(choiceFlow(t)), says: hydraSays{RejectLogin: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{RejectLogin}},
		{name: "EXP-4 Q11, 403, finished meanwhile", ev: entry, stored: expired(choiceFlow(t)), reread: finishedFlow(t, "", 0),
			says: hydraSays{RejectLogin: {err: err403}}, kind: ErrorPage, code: E1002, link: true, calls: []Op{RejectLogin}},
		{name: "EXP-4, unavailable", ev: entry, stored: expired(choiceFlow(t)), says: hydraSays{RejectLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{RejectLogin}},
		{name: "EXP-4, CHX at the creation: 401 writes it finished", env: requireACR, ev: entry,
			says: hydraSays{GetLogin: {login: unmet}, RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: false, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "EXP-4, CHX at the creation: unavailable creates nothing", env: requireACR, ev: entry,
			says: hydraSays{GetLogin: {login: unmet}, RejectLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, RejectLogin}},
	} {
		tc.run(t)
	}
}

// The facts of Hydra a transition replayed on a changed flow no longer
// reaches (ECR-3, ECR-4, ECR-9): the engine's part, the orchestrator
// re-reading after a write conflict (P3e).
func TestFactsCarriedOver(t *testing.T) {
	env := testEnv()
	loop := Loop{Ref: lref, Cookie: cookie}
	acceptCall := Call{Op: AcceptLogin, Challenge: hydraL, Gen: 1000, AcceptLogin: ory.AcceptOAuth2LoginRequest{Subject: "alice", Acr: ory.PtrString("2"), Amr: []string{"pwd"}}}
	accept := &Done{Call: acceptCall, RedirectTo: "http://hydra/mine"}
	reject := &Done{Call: Call{Op: RejectLogin, Reason: ReasonExpired}, RedirectTo: "http://hydra/rejected"}
	consentAccept := &Done{Call: Call{Op: AcceptConsent}, RedirectTo: "http://hydra/mine"}
	consentReject := &Done{Call: Call{Op: RejectConsent, Reason: ReasonUser}, RedirectTo: "http://hydra/mine"}
	conflict := func(t *testing.T, out Outcome) {
		t.Helper()
		if !slices.ContainsFunc(out.Reports, func(r Report) bool { return r.Event == "state.conflict" && r.Sentry }) {
			t.Errorf("no state.conflict: %+v", out.Reports)
		}
	}
	// expiry wants none: a flow gone is one past hx (ECR-8, EXP-1; revue
	// R19), whose key expired between the call and its write.
	expiry := func(t *testing.T, out Outcome) {
		t.Helper()
		if slices.ContainsFunc(out.Reports, func(r Report) bool { return r.Event == "state.conflict" || r.Sentry }) {
			t.Errorf("an expiry reported as a conflict: %+v", out.Reports)
		}
	}
	// audit wants the audit event of a reject made, then the checks more.
	audit := func(event string, more ...func(t *testing.T, out Outcome)) func(t *testing.T, out Outcome) {
		return func(t *testing.T, out Outcome) {
			t.Helper()
			if !slices.ContainsFunc(out.Reports, func(r Report) bool { return r.Event == event && r.Audit }) {
				t.Errorf("no audit %s: %+v", event, out.Reports)
			}
			for _, check := range more {
				check(t, out)
			}
		}
	}
	a3 := &Done{Call: Call{Op: RejectConsent, Reason: ReasonNotOurs}, RedirectTo: "http://hydra/a3"}
	mismatch := &Done{Call: Call{Op: RejectLogin, Reason: ReasonSubject}, RedirectTo: hydraDone}
	read := &ConsentRead{Request: consentRequest(lref, nil)}
	refuse := Consent{Challenge: hydraC, Cookie: cookie, Post: true, Token: cookie, SameOrigin: true}
	noCR := func(t *testing.T, f *Flow) {
		t.Helper()
		finished(t, f)
		if f.ConsentRedirect != "" {
			t.Errorf("Q20, the A3 reject's redirect_to kept: %q", f.ConsentRedirect)
		}
	}
	for _, tc := range []struct {
		name    string
		ev      Event
		flow    *Flow
		answers Answers
		kind    ResponseKind
		url     string
		code    Code
		write   func(t *testing.T, f *Flow)
		check   func(t *testing.T, out Outcome)
	}{
		{name: "ECR-3, accepted by a concurrent request: its own redirect_to", ev: loop, flow: acceptedFlow(t), answers: Answers{Accept: accept},
			kind: Redirect, url: "http://hydra/mine"},
		{name: "ECR-4, back to the choice meanwhile: hr carried over", ev: loop, flow: choiceFlow(t), answers: Answers{Accept: accept},
			kind: Redirect, url: "http://hydra/mine",
			write: func(t *testing.T, f *Flow) {
				if f.HydraRedirect != "http://hydra/mine" || f.Sent.Subject != "alice" || f.Sent.ACR != "2" {
					t.Errorf("flow %+v", f)
				}
			}},
		{name: "ECR-9, an accept on a finished flow", ev: loop, flow: finishedFlow(t, "", 0), answers: Answers{Accept: accept},
			kind: ErrorPage, code: E1002, check: conflict},
		{name: "ECR-8, an accept, the flow gone past hx", ev: loop, answers: Answers{Accept: accept},
			kind: ErrorPage, code: E1002, check: expiry},
		{name: "ECR-8, an accept, the flow read past hx", ev: loop, flow: func() *Flow { f := lastDone(t); f.HydraExpiresAt = testNow.UnixMilli(); return f }(),
			answers: Answers{Accept: accept}, kind: ErrorPage, code: E1002, check: expiry},
		{name: "ECR-4, a reject carried over", ev: loop, flow: acceptedFlow(t), answers: Answers{Reject: reject},
			kind: Redirect, url: "http://hydra/rejected", write: finished},
		{name: "ECR-4, a reject for Hydra's skip", ev: loop, flow: choiceFlow(t),
			answers: Answers{Reject: &Done{Call: Call{Op: RejectLogin, Reason: ReasonSkipSubject}, RedirectTo: "http://hydra/rejected"}},
			kind:    ErrorPage, code: E1003, write: finished, check: func(t *testing.T, out Outcome) {
				if !strings.HasSuffix(out.Response.SignOut, "/oauth2/sessions/logout") { // Q60
					t.Errorf("the way out: %q", out.Response.SignOut)
				}
			}},
		{name: "ECR-8, a reject, the flow gone past hx: its redirect_to", ev: loop, answers: Answers{Reject: reject},
			kind: Redirect, url: "http://hydra/rejected", check: expiry},
		{name: "ECR-9, a reject on a finished flow: its redirect_to", ev: loop, flow: finishedFlow(t, "", 0), answers: Answers{Reject: reject},
			kind: Redirect, url: "http://hydra/rejected", check: conflict},
		{name: "ECR-3 Q30, the consent accepted twice", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: finishedFlow(t, "http://hydra/theirs", 0),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentAccept: consentAccept},
			kind:    Redirect, url: "http://hydra/mine"},
		{name: "ECR-3 Q30, a reject against an accept of the consent", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: finishedFlow(t, "http://hydra/theirs", 0),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentReject: consentReject},
			kind:    Redirect, url: "http://hydra/mine"},
		{name: "ECR-9, the consent accepted on a flow finished otherwise", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: finishedFlow(t, "", 0),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentAccept: consentAccept},
			kind:    ErrorPage, code: E1002, check: conflict},
		{name: "ECR-9, the consent rejected on a flow finished otherwise", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: finishedFlow(t, "", 0),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentReject: consentReject},
			kind:    Redirect, url: "http://hydra/mine", check: conflict},
		{name: "ECR-8, the consent accepted, the flow gone past hx", ev: Consent{Challenge: hydraC, Cookie: cookie},
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentAccept: consentAccept},
			kind:    ErrorPage, code: E1002, check: expiry},
		{name: "ECR-4, the consent accepted, the flow expired meanwhile", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: expired(acceptedFlow(t)),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, nil)}, ConsentAccept: consentAccept},
			kind:    Redirect, url: "http://hydra/mine",
			write: func(t *testing.T, f *Flow) {
				if !f.Done || f.ConsentRedirect != "http://hydra/mine" {
					t.Errorf("flow %+v", f)
				}
			}},
		{name: "ECR-4, the A3 reject of the consent carried over", ev: loop, flow: acceptedFlow(t),
			answers: Answers{ConsentReject: &Done{Call: Call{Op: RejectConsent, Reason: ReasonNotOurs}, RedirectTo: "http://hydra/mine"}},
			kind:    ErrorPage, code: E1007, write: noCR, check: audit("flow.rejected")},
		{name: "ECR-9 Q20, an A3 reject on a flow finished by its consent: never its redirect_to", ev: Consent{Challenge: hydraC, Cookie: cookie},
			flow: finishedFlow(t, "http://hydra/theirs", 0), answers: Answers{Consent: read, ConsentReject: a3},
			kind: ErrorPage, code: E1007, check: audit("flow.rejected", conflict)},
		{name: "ECR-9 Q20, an A3 reject on a flow finished otherwise", ev: Consent{Challenge: hydraC, Cookie: cookie},
			flow: finishedFlow(t, "", 0), answers: Answers{Consent: read, ConsentReject: a3},
			kind: ErrorPage, code: E1007, check: audit("flow.rejected", conflict)},
		{name: "Q20, an A3 reject reached again by the user's refusal", ev: refuse, flow: acceptedFlow(t), answers: Answers{Consent: read, ConsentReject: a3},
			kind: ErrorPage, code: E1007, write: noCR, check: audit("flow.rejected")},
		{name: "ECR-4, a subject mismatch carried over to a flow back to the choice", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`),
			flow: atStep(t, 2, false, false).restart(), answers: Answers{Reject: mismatch},
			kind: AppJSON, write: finished, check: audit("step.subject_mismatch")},
		{name: "ECR-9, a subject mismatch on a flow finished meanwhile", ev: callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`),
			flow: finishedFlow(t, "", 0), answers: Answers{Reject: mismatch},
			kind: AppJSON, check: audit("step.subject_mismatch", conflict)},
		{name: "no second mutation: the final accept after a reject", ev: loop, flow: lastDone(t), answers: Answers{Reject: reject},
			kind: Redirect, url: "http://hydra/rejected", write: finished},
		{name: "no second mutation: the consent accept after an A3 reject", ev: Consent{Challenge: hydraC, Cookie: cookie}, flow: acceptedFlow(t),
			answers: Answers{Consent: &ConsentRead{Request: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(true) })}, ConsentReject: a3},
			kind:    ErrorPage, code: E1007, write: noCR, check: audit("flow.rejected")},
		{name: "no second mutation: the consent reject after an accept", ev: refuse, flow: acceptedFlow(t), answers: Answers{Consent: read, ConsentAccept: consentAccept},
			kind: Redirect, url: "http://hydra/mine",
			write: func(t *testing.T, f *Flow) {
				if !f.Done || f.ConsentRedirect != "http://hydra/mine" {
					t.Errorf("flow %+v", f)
				}
			}},
		{name: "no second mutation after a failed one", ev: loop, flow: expired(lastDone(t)), answers: Answers{Accept: &Done{Call: acceptCall, Err: errDown}},
			kind: ErrorPage, code: E1007, check: conflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Decide(Input{Event: tc.ev, Loaded: true, Flow: tc.flow, Reread: true, Answers: tc.answers, Env: env})
			if out.Load != "" || out.Call != nil || out.Reread {
				t.Fatalf("asks for more: %+v", out)
			}
			if r := out.Response; r.Kind != tc.kind || tc.url != "" && r.URL != tc.url || r.Code != tc.code {
				t.Errorf("answer %v %q %s; want %v %q %s", r.Kind, r.URL, r.Code, tc.kind, tc.url, tc.code)
			}
			switch {
			case tc.write == nil && out.Write != nil:
				t.Errorf("wrote %+v", out.Write)
			case tc.write != nil && out.Write == nil:
				t.Error("wrote nothing")
			case tc.write != nil:
				tc.write(t, out.Write)
			}
			if tc.check != nil {
				tc.check(t, out)
			}
		})
	}
}

func TestNames(t *testing.T) {
	if ReasonNotOurs.String() != "not_ours" || ReasonExpired.String() != "expired" {
		t.Error("reason names")
	}
	if out := Decide(Input{Env: testEnv()}); out.Response.Code != E1000 {
		t.Errorf("no event: %+v", out)
	}
}
