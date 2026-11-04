package flow

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The memory of the skip (Mémoire du skip of the table, P8): MEM, SKP, SKC
// and WRT lines.

const (
	// requestURL is the fixture's, which carries the client's state and
	// nonce.
	requestURL = "http://public.hydra.test/oauth2/auth?client_id=da4e4867-af3c-4d18-ae67-ebe7ce2f79c4&nonce=WtIsDSHiTSnEtmQ61ASHEA&redirect_uri=http%3A%2F%2Foidc.client.test%2Fauth%2Fcallback&response_type=code&scope=openid+profile+email&state=tt7gLyH546h_GonwJiy2UQ"
	skipCSRF   = "http://public.hydra.test/oauth2/auth?login_verifier=skip"
)

// skipRequest is the fixture's login request with Hydra's skip, for alice,
// changed by mod.
func skipRequest(t *testing.T, mod func(r *ory.OAuth2LoginRequest)) *ory.OAuth2LoginRequest {
	r := withClient(t, `{"client_uri":"`+clientURI+`"}`)
	r.Skip, r.Subject = true, "alice"
	if mod != nil {
		mod(r)
	}
	return r
}

// memory is a remember cookie that passes every check against
// skipRequest: hydra-sql, the fixture's scopes, alive for an hour.
func memory(mod func(c *Remembered)) Memory {
	c := &Remembered{
		V: RememberedFormat, SID: sessionID, Sub: "alice", Flow: "hydra-sql", FH: Composition([]string{"sql"}),
		ACR: "1", AMR: []string{"pwd"},
		Ctx: Object{"app": json.RawMessage(`"sql"`), "x_dispatcher_ref": json.RawMessage(`"old"`)},
		Scp: []string{"openid", "profile", "email", "offline"},
		IDT: Object{"email": json.RawMessage(`"alice@example.org"`), "name": json.RawMessage(`"Alice"`), "gone": json.RawMessage(`null`)},
		ACT: Object{"groups": json.RawMessage(`["a"]`)},
		IAT: testNow.Add(-time.Hour).Unix(), Exp: testNow.Add(time.Hour).Unix(),
	}
	if mod != nil {
		mod(c)
	}
	return Memory{Content: c}
}

// configured returns the flow id of the snapshot, to change.
func configured(e *Env, id string) *store.Flow {
	for i := range e.Config.Flows {
		if e.Config.Flows[i].ID == id {
			return &e.Config.Flows[i]
		}
	}
	panic("no flow " + id)
}

// withACRs gives hydra-sql acr 1 and hydra-sql-2fa acr 2.
func withACRs(e *Env) {
	configured(e, "hydra-sql").ACR = "1"
	configured(e, "hydra-sql-2fa").ACR = "2"
}

// ignoredFor wants the skip ignored for reason, of kind (MEM, ENT-9,
// SKC-6).
func ignoredFor(kind, reason string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		var got []Report
		for _, r := range p.Reports {
			if strings.HasPrefix(r.Event, "skip.") {
				got = append(got, r)
			}
		}
		if want := []Report{{Event: "skip.ignored", Kind: kind, Reason: reason}}; !slices.Equal(got, want) {
			t.Errorf("skip reports %+v; want %+v", got, want)
		}
	}
}

func acceptedSkip(kind string) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		if !slices.Contains(p.Reports, Report{Event: "skip.accepted", Kind: kind}) {
			t.Errorf("no skip.accepted %s: %+v", kind, p.Reports)
		}
		if p.Response.Remember != nil {
			t.Errorf("WRT-5, the cookie written again: %+v", p.Response.Remember)
		}
	}
}

// playedAgain is a flow written by ENT-9: in choice, Hydra's skip and
// subject kept for the final accept (A7).
func playedAgain(t *testing.T, f *Flow) {
	t.Helper()
	inChoice(5000, cookie)(t, f)
	if !f.Hydra.Skip || f.Hydra.Subject != "alice" {
		t.Errorf("h.skip %v h.sub %q", f.Hydra.Skip, f.Hydra.Subject)
	}
}

// skipWritten is the flow SKP-1 writes: finished, reduced, keeping the
// accept's redirect_to and its time, marked sk (Q35), with the client_uri
// of page E1002.
func skipWritten(t *testing.T, f *Flow) {
	t.Helper()
	finished(t, f)
	if !f.Skipped || f.ConsentRedirect != skipCSRF || f.ConsentAt != testNow.UnixMilli() || f.ClientURI() != clientURI {
		t.Errorf("Q35, sk %v cr %q ct %d client_uri %q", f.Skipped, f.ConsentRedirect, f.ConsentAt, f.ClientURI())
	}
	if f.HydraExpiresAt != testNow.Add(30*time.Minute).UnixMilli() {
		t.Errorf("hx %d", f.HydraExpiresAt)
	}
}

// MEM-1 to MEM-9, at the entry: the first check that fails ignores Hydra's
// skip, the flow played again (ENT-9, SKP-2), with its reason.
func TestMemoryAtEntry(t *testing.T) {
	entry := func(m Memory) Entry { return Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: m} }
	read := func(mod func(r *ory.OAuth2LoginRequest)) hydraSays {
		return hydraSays{GetLogin: {login: skipRequest(t, mod)}, AcceptLogin: {redirectTo: skipCSRF}}
	}
	ignoredCase := func(name string, env func(e *Env), m Memory, mod func(r *ory.OAuth2LoginRequest), reason string) pageCase {
		return pageCase{name: name, env: env, ev: entry(m), says: read(mod), kind: ChoicePage, calls: []Op{GetLogin},
			write: playedAgain, check: ignoredFor("login", reason)}
	}
	honoured := func(name string, env func(e *Env), m Memory, mod func(r *ory.OAuth2LoginRequest)) pageCase {
		return pageCase{name: name, env: env, ev: entry(m), says: read(mod), kind: Redirect, url: skipCSRF,
			calls: []Op{GetLogin, AcceptLogin}, write: skipWritten, check: acceptedSkip("login")}
	}
	preferred := func(id string) func(r *ory.OAuth2LoginRequest) {
		return func(r *ory.OAuth2LoginRequest) {
			r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{preferredPrefix + id}}
		}
	}
	acrValues := func(v ...string) func(r *ory.OAuth2LoginRequest) {
		return func(r *ory.OAuth2LoginRequest) {
			r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: v}
		}
	}
	for _, tc := range []pageCase{
		ignoredCase("MEM-1, no cookie", nil, Memory{}, nil, SkipAbsent),
		ignoredCase("MEM-1, the second part missing", nil, Memory{Reason: SkipAbsent}, nil, SkipAbsent),
		ignoredCase("MEM-2, unreadable", nil, Memory{Reason: SkipUnreadable}, nil, SkipUnreadable),
		ignoredCase("MEM-3, expired", nil, memory(func(c *Remembered) { c.Exp = testNow.Unix() }), nil, SkipExpired),
		honoured("MEM-3, a second before exp", nil, memory(func(c *Remembered) { c.Exp = testNow.Unix() + 1 }), nil),
		honoured("MEM-3, exp 0: a cookie of the browser's session", nil, memory(func(c *Remembered) { c.Exp = 0 }), nil),
		ignoredCase("MEM-4, another session", nil, memory(func(c *Remembered) { c.SID = "other" }), nil, SkipSession),
		ignoredCase("MEM-4, no session on either side", nil, memory(func(c *Remembered) { c.SID = "" }), func(r *ory.OAuth2LoginRequest) { r.SessionId = ory.PtrString("") }, SkipSession),
		ignoredCase("MEM-5, another subject", nil, memory(func(c *Remembered) { c.Sub = "bob" }), nil, SkipSubject),
		ignoredCase("MEM-6, a flow unknown", nil, memory(func(c *Remembered) { c.Flow = "gone" }), nil, SkipFlow),
		ignoredCase("MEM-6, the flow disabled", func(e *Env) { configured(e, "hydra-sql").Enabled = false }, memory(nil), nil, SkipFlow),
		ignoredCase("MEM-6 Q36, outside the client's restriction", nil, memory(nil), func(r *ory.OAuth2LoginRequest) {
			r.Client.Metadata = map[string]any{"dispatcher": map[string]any{"flows": []any{"hydra-oidc"}}}
		}, SkipFlow),
		ignoredCase("MEM-6 Q36, filtered out by acr_values", withACRs, memory(nil), acrValues("2"), SkipFlow),
		// Ignored, the flow played again starts the preferred one (CHX-3).
		{name: "MEM-6 Q36, another flow preferred", ev: entry(memory(nil)), says: read(preferred("hydra-sql-2fa")),
			kind: Redirect, url: loginURL("sql", 5000), calls: []Op{GetLogin}, write: started("hydra-sql-2fa", 5000, true),
			check: ignoredFor("login", SkipFlow)},
		honoured("MEM-6 Q36 Q19, its flow preferred", nil, memory(nil), preferred("hydra-sql")),
		honoured("MEM-6 Q19, a preferred flow outside the candidates keeps no skip off", nil, memory(nil), preferred("gone")),
		ignoredCase("MEM-7, the flow's composition changed", nil, memory(func(c *Remembered) { c.FH = Composition([]string{"sql", "2fa"}) }), nil, SkipComposition),
		ignoredCase("MEM-8, a scope more than granted", nil, memory(func(c *Remembered) { c.Scp = []string{"openid", "email"} }), nil, SkipScopes),
		honoured("MEM-8, fewer scopes than granted", nil, memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedScope = []string{"openid"} }),
		// MEM-9 (Q36): the admin raised hydra-sql's acr to 2, fh unchanged.
		ignoredCase("MEM-9, the cookie's acr not among acr_values", func(e *Env) { withACRs(e); configured(e, "hydra-sql").ACR = "2" }, memory(nil), acrValues("2"), SkipACR),
		honoured("MEM-9, the cookie's acr among acr_values", withACRs, memory(nil), acrValues("1", "2")),
		honoured("MEM-9, only the preferred flow's prefix", nil, memory(nil), preferred("hydra-sql")),
	} {
		tc.run(t)
	}
}

func TestSkipLogin(t *testing.T) {
	entry := Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)}
	read := func(mod func(r *ory.OAuth2LoginRequest)) said { return said{login: skipRequest(t, mod)} }
	hook := func(e *Env) { e.Config.Settings.LoginAcceptWebhookURL = "http://hook.test/login" }
	accept := func(t *testing.T, p played) *ory.AcceptOAuth2LoginRequest {
		t.Helper()
		for _, c := range p.calls {
			if c.Op == AcceptLogin {
				return &c.AcceptLogin
			}
		}
		t.Fatal("no accept")
		return nil
	}
	for _, tc := range []pageCase{
		{name: "SKP-1", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin}, write: skipWritten,
			check: func(t *testing.T, p played) {
				acceptedSkip("login")(t, p)
				b := accept(t, p)
				ctx := b.Context.(Object)
				// Q38: the cookie's members, without x_dispatcher_ref, and the
				// marker on what was sent.
				if b.Subject != "alice" || b.GetAcr() != "1" || !slices.Equal(b.Amr, []string{"pwd"}) || rawJSON(ctx["app"]) != `"sql"` || ctx["x_dispatcher_ref"] != nil {
					t.Errorf("accept %+v, context %s", b, rawJSON(ctx))
				}
				var marker string
				_ = json.Unmarshal(ctx["x_dispatcher_skip"], &marker)
				if !testKeys.validSkipMarker(marker, sessionID, "alice", "1", []string{"pwd"}, requestURL) {
					t.Errorf("Q38, marker %q", marker)
				}
				// Q43 withdrawn: the settings' remember, as at FIN-1.
				if !b.GetRemember() || b.GetRememberFor() != 86400 {
					t.Errorf("remember %v for %d", b.GetRemember(), b.GetRememberFor())
				}
				if c := p.calls[1]; !c.Skip || c.Challenge != hydraL {
					t.Errorf("call %+v", c)
				}
				if !p.Guard {
					t.Error("SKP-8, the write is not a guard")
				}
			}},
		{name: "SKP-1, an amr absent from the cookie: [] sent and signed", ev: Entry{LoginChallenge: hydraL, Memory: memory(func(c *Remembered) { c.AMR = nil })},
			says: hydraSays{GetLogin: read(nil), AcceptLogin: {redirectTo: skipCSRF}}, kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin},
			write: skipWritten, check: func(t *testing.T, p played) {
				if b := accept(t, p); b.Amr == nil || len(b.Amr) != 0 {
					t.Errorf("amr %#v", b.Amr)
				}
			}},
		{name: "SKP-1 DEC-3, Hydra's clock ahead: reported", ev: entry,
			says: hydraSays{GetLogin: {login: skipRequest(t, nil), requestedAt: testNow.Add(10 * time.Second), decrypted: true}, AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin}, write: func(*testing.T, *Flow) {},
			check: skewReported("Hydra's requested_at 10s ahead")},
		{name: "SKP-1, the login webhook's answer sent and signed", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{ACR: ory.PtrString("3"), AMR: []string{"hwk"},
				Context: json.RawMessage(`{"hook":1,"x_dispatcher_skip":"forged"}`), RememberFor: ory.PtrInt64(60)}}, AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, LoginHook, AcceptLogin}, write: skipWritten,
			check: func(t *testing.T, p played) {
				b := accept(t, p)
				ctx := b.Context.(Object)
				var marker string
				_ = json.Unmarshal(ctx["x_dispatcher_skip"], &marker)
				if !testKeys.validSkipMarker(marker, sessionID, "alice", "3", []string{"hwk"}, requestURL) || rawJSON(ctx["hook"]) != "1" || b.GetRememberFor() != 60 {
					t.Errorf("accept %+v, context %s", b, rawJSON(ctx))
				}
				// The webhook got the cookie's context, without the members of the
				// dispatcher.
				if c := p.calls[1].AcceptLogin.Context.(Object); c["x_dispatcher_ref"] != nil || c["app"] == nil {
					t.Errorf("webhook context %s", rawJSON(c))
				}
			}},
		{name: "SKP-3, Hydra 401 at the accept", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, AcceptLogin},
			write: func(t *testing.T, f *Flow) {
				finished(t, f)
				if f.ConsentRedirect != "" || f.Skipped {
					t.Errorf("cr %q sk %v", f.ConsentRedirect, f.Skipped)
				}
			}},
		{name: "SKP-3, Hydra 404 at the accept", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: err404}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, AcceptLogin}, write: finished},
		{name: "SKP-4, Hydra 409: a concurrent skip's flow, its cr replayed", ev: entry,
			reread: func() *Flow {
				f := choiceFlow(t).Reduce()
				f.ConsentRedirect, f.ConsentAt, f.Skipped = "http://hydra/other", testNow.UnixMilli(), true
				return f
			}(),
			says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: err409}}, kind: Redirect, url: "http://hydra/other", calls: []Op{GetLogin, AcceptLogin}},
		{name: "SKP-4, Hydra 409, the flow still absent", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{GetLogin, AcceptLogin}},
		{name: "SKP-4, Hydra 400", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: err400}},
			kind: ErrorPage, code: E1007, calls: []Op{GetLogin, AcceptLogin}},
		{name: "SKP-5, Hydra unavailable", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, AcceptLogin}},
		{name: "SKP-5, an accept without redirect_to", ev: entry, says: hydraSays{GetLogin: read(nil), AcceptLogin: {}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, AcceptLogin}},
		{name: "SKP-7, the webhook gives another subject", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, RejectLogin: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1003, calls: []Op{GetLogin, LoginHook, RejectLogin}, write: finished, check: rejected(RejectLogin, "login_required")},
		{name: "SKP-7 EXP-4, Hydra 401 on the reject", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, LoginHook, RejectLogin}, write: finished},
		{name: "SKP-7 EXP-4, Hydra unavailable on the reject: not created", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, RejectLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, LoginHook, RejectLogin}},
		{name: "SKP-9, the webhook fails", env: hook, ev: entry, says: hydraSays{GetLogin: read(nil), LoginHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{GetLogin, LoginHook}},
		{name: "SKP-9 A9, a context that is no object", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`[]`)}}},
			kind: ErrorPage, code: E1006, calls: []Op{GetLogin, LoginHook}},
		// SKP-10: L read in its last moment, hx reached before the write
		// (ECR-8); the accept is made, its redirect_to never followed.
		{name: "SKP-10, hx reached before the write", ev: entry,
			says: hydraSays{GetLogin: {login: skipRequest(t, nil), requestedAt: testNow.Add(-30 * time.Minute)}, AcceptLogin: {redirectTo: skipCSRF}},
			kind: ErrorPage, code: E1002, calls: []Op{GetLogin, AcceptLogin}},
		// No ENT-22 on this path: the accept leaves at once.
		{name: "SKP-1, L in its last minute: accepted all the same", ev: entry,
			says: hydraSays{GetLogin: {login: skipRequest(t, nil), requestedAt: testNow.Add(-29*time.Minute - 30*time.Second)}, AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin}, write: finished},
		// SKP-2 at ENT-22: ignored, then rejected as a flow born expired.
		{name: "SKP-2 ENT-22, ignored in the last minute of L", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: {login: skipRequest(t, nil), requestedAt: testNow.Add(-29*time.Minute - 30*time.Second)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished, check: ignoredFor("login", SkipAbsent)},
		// SKP-2 at CHX-1: ignored, then the rules of the choice reject.
		{name: "SKP-2 CHX-1, ignored then rejected", env: withACRs, ev: Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)},
			says: hydraSays{GetLogin: read(func(r *ory.OAuth2LoginRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"3"}}
			}), RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				ignoredFor("login", SkipFlow)(t, p)
				rejected(RejectLogin, "unmet_authentication_requirements")(t, p)
			}},
		// Q44: a flow in store keeps its lines, a cookie valid since or not.
		{name: "Q44, ENT-2: a flow in choice is not judged again", ev: entry,
			stored: func() *Flow { f := choiceFlow(t); f.Hydra.Skip, f.Hydra.Subject = true, "alice"; return f }(),
			kind:   ChoicePage},
		{name: "Q44, ENT-3: a flow at a step back to the choice", ev: entry,
			stored: func() *Flow { f := atStep(t, 1, false, false); f.Hydra.Skip, f.Hydra.Subject = true, "alice"; return f }(),
			kind:   ChoicePage, write: inChoice(1001, cookie)},
	} {
		tc.run(t)
	}
}

// ENT-21 after SKP-1 (Q35): a return within 10 s of ct, cookie or not, gets
// the cr of the skip, on GET / by L or by ref, on POST /, on /oauth2/auth;
// afterwards, page E1002 with its link, without a call.
func TestSkipReplayed(t *testing.T) {
	skipped := func(ago time.Duration) *Flow {
		f := choiceFlow(t).Reduce()
		f.ConsentRedirect, f.ConsentAt, f.Skipped = skipCSRF, testNow.Add(-ago).UnixMilli(), true
		return f
	}
	for _, tc := range []pageCase{
		{name: "ENT-21 Q35, a reload during the redirection, no cookie", ev: Entry{LoginChallenge: hydraL, Memory: memory(nil)}, stored: skipped(time.Second),
			kind: Redirect, url: skipCSRF},
		{name: "ENT-21 Q35, with the cookie", ev: Entry{LoginChallenge: hydraL, Cookie: cookie}, stored: skipped(9 * time.Second),
			kind: Redirect, url: skipCSRF},
		{name: "ENT-21 Q35, by ref", ev: Entry{Ref: lref}, stored: skipped(time.Second), kind: Redirect, url: skipCSRF},
		{name: "POS-11 Q35", ev: Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, SameOrigin: true}, stored: skipped(time.Second),
			kind: Redirect, url: skipCSRF},
		{name: "BCL-17 Q35", ev: Loop{Ref: lref}, stored: skipped(time.Second), kind: Redirect, url: skipCSRF},
		{name: "ENT-7 Q35, 10 s after: E1002, no call nor webhook", ev: Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)},
			stored: skipped(10 * time.Second), kind: ErrorPage, code: E1002, link: true},
		{name: "ENT-16 Q35, by ref, 10 s after", ev: Entry{Ref: lref}, stored: skipped(10 * time.Second), kind: ErrorPage, code: E1002, link: true},
	} {
		tc.run(t)
	}
}

// consentSkip is the consent request of a login accepted in skip from
// memory(nil): no x_dispatcher_ref, the marker on what the accept sent,
// changed by mod.
func consentSkip(mod func(r *ory.OAuth2ConsentRequest)) *ory.OAuth2ConsentRequest {
	marker := testKeys.SkipMarker(sessionID, "alice", "1", []string{"pwd"}, requestURL)
	r := &ory.OAuth2ConsentRequest{
		Challenge:                    hydraC,
		Subject:                      ory.PtrString("alice"),
		LoginSessionId:               ory.PtrString(sessionID),
		Acr:                          ory.PtrString("1"),
		Amr:                          []string{"pwd"},
		RequestUrl:                   ory.PtrString(requestURL),
		Context:                      json.RawMessage(`{"app":"sql","x_dispatcher_skip":"` + marker + `"}`),
		RequestedScope:               []string{"openid", "email"},
		RequestedAccessTokenAudience: []string{"api"},
		Client:                       &ory.OAuth2Client{ClientId: ory.PtrString("c")},
		Skip:                         ory.PtrBool(true),
	}
	if mod != nil {
		mod(r)
	}
	return r
}

func noSkip(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(false) }

// consentAccepted wants the consent accepted from the cookie (SKC-1,
// SKC-3): the scopes and audiences requested, the cookie's claims, a null
// ignored, the consent's remember.
func consentAccepted(t *testing.T, p played) {
	t.Helper()
	acceptedSkip("consent")(t, p)
	for _, c := range p.calls {
		if c.Op != AcceptConsent {
			continue
		}
		b := c.AcceptConsent
		if !slices.Equal(b.GrantScope, []string{"openid", "email"}) || !slices.Equal(b.GrantAccessTokenAudience, []string{"api"}) ||
			rawJSON(b.Session.IdToken) != `{"email":"alice@example.org","name":"Alice"}` || rawJSON(b.Session.AccessToken) != `{"groups":["a"]}` ||
			!b.GetRemember() || b.GetRememberFor() != 2629800 {
			t.Errorf("accept %+v, session %s %s", b, rawJSON(b.Session.IdToken), rawJSON(b.Session.AccessToken))
		}
		return
	}
	t.Error("no accept")
}

func TestConsentWithoutFlow(t *testing.T) {
	get := Consent{Challenge: hydraC, Cookie: cookie, Memory: memory(nil)}
	print := testKeys.ClaimsPrint(MergeClaims(memory(nil).Content.IDT), MergeClaims(memory(nil).Content.ACT))
	post := func(accept bool, mod func(c *Consent)) Consent {
		c := Consent{Challenge: hydraC, Cookie: cookie, Memory: memory(nil), Post: true, Accept: accept, Token: cookie, Print: print, SameOrigin: true}
		if mod != nil {
			mod(&c)
		}
		return c
	}
	read := func(mod func(r *ory.OAuth2ConsentRequest)) said { return said{consent: consentSkip(mod)} }
	marker := func(sid, sub, acr string, amr []string, url string) func(r *ory.OAuth2ConsentRequest) {
		return func(r *ory.OAuth2ConsentRequest) {
			m := testKeys.SkipMarker(sid, sub, acr, amr, url)
			r.Context = json.RawMessage(`{"x_dispatcher_skip":"` + m + `"}`)
		}
	}
	notOursSkip := func(t *testing.T, p played) {
		t.Helper()
		rejected(RejectConsent, "access_denied")(t, p)
		if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Audit && r.Event == "flow.rejected" && r.Detail == "not_ours:skip" }) {
			t.Errorf("Q38, no audit not_ours:skip: %+v", p.Reports)
		}
	}
	screen := func(csrf string) func(t *testing.T, p played) {
		return func(t *testing.T, p played) {
			t.Helper()
			s := p.Response.Consent
			if s == nil || s.Print != print || s.CSRF != csrf || p.Response.SetCSRF != csrf || s.Subject != "alice" ||
				rawJSON(s.Claims) != `{"email":"alice@example.org","name":"Alice"}` || rawJSON(s.AccessClaims) != `{"groups":["a"]}` {
				t.Errorf("Q37, screen %+v, Set-Cookie %q", s, p.Response.SetCSRF)
			}
		}
	}
	consentHook := func(e *Env) { e.Config.Settings.ConsentAcceptWebhookURL = "http://hook.test/consent" }
	accept := hydraSays{GetConsent: read(nil), AcceptConsent: {redirectTo: callbackURL}}
	for _, tc := range []pageCase{
		{name: "SKC-1, Hydra's skip", ev: get, says: accept,
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}, check: consentAccepted},
		{name: "SKC-1, the client's skip_consent", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { noSkip(r); r.Client.SkipConsent = ory.PtrBool(true) }), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}, check: consentAccepted},
		{name: "SKC-1, consent_auto_accept", env: func(e *Env) { e.Config.Settings.ConsentAutoAccept = true }, ev: get,
			says: hydraSays{GetConsent: read(noSkip), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}, check: consentAccepted},
		{name: "SKC-1 Q38, an amr absent: the marker of an empty one", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.Amr = nil
				marker(sessionID, "alice", "1", []string{}, requestURL)(r)
			}), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-1, the consent webhook's claims sent", env: consentHook, ev: get,
			says: hydraSays{GetConsent: read(nil), ConsentHook: {consentHook: &ConsentHookAnswer{IDToken: json.RawMessage(`{"hook":1}`)}}, AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, ConsentHook, AcceptConsent},
			check: func(t *testing.T, p played) {
				if got := rawJSON(p.calls[2].AcceptConsent.Session.IdToken); got != `{"hook":1}` {
					t.Errorf("id_token %s", got)
				}
			}},
		{name: "SKC-2, no skip: the screen, from the cookie", ev: get, says: hydraSays{GetConsent: read(noSkip)},
			kind: ConsentPage, calls: []Op{GetConsent}, check: screen(cookie)},
		{name: "SKC-2, no CSRF cookie: a new one set", ev: Consent{Challenge: hydraC, Memory: memory(nil)}, says: hydraSays{GetConsent: read(noSkip)},
			kind: ConsentPage, calls: []Op{GetConsent}, check: screen(newCSRF)},
		{name: "SKC-3, accepted", ev: post(true, nil), says: hydraSays{GetConsent: read(noSkip), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}, check: consentAccepted},
		{name: "SKC-3, the print of the previous challenge key", ev: post(true, func(c *Consent) {
			c.Print = Keys{oldKey}.ClaimsPrint(MergeClaims(memory(nil).Content.IDT), MergeClaims(memory(nil).Content.ACT))
		}), says: hydraSays{GetConsent: read(noSkip), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-4, refused", ev: post(false, nil), says: hydraSays{GetConsent: read(noSkip), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "access_denied")},
		{name: "SKC-5, a token unlike the cookie", ev: post(true, func(c *Consent) { c.Token = otherCSRF }), says: hydraSays{GetConsent: read(noSkip)},
			kind: ErrorPage, code: E1008, calls: []Op{GetConsent}},
		{name: "SKC-5, refused without the cookie", ev: post(false, func(c *Consent) { c.Cookie = "" }), says: hydraSays{GetConsent: read(noSkip)},
			kind: ErrorPage, code: E1008, calls: []Op{GetConsent}},
		{name: "CST-21, from another site: before the read", ev: post(true, func(c *Consent) { c.SameOrigin = false }),
			kind: ErrorPage, code: E1008},
		{name: "SKC-6, the cookie lost", ev: Consent{Challenge: hydraC, Cookie: cookie}, says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent},
			check: func(t *testing.T, p played) {
				rejected(RejectConsent, "login_required")(t, p)
				ignoredFor("consent", SkipAbsent)(t, p)
			}},
		{name: "SKC-6, the flow changed since", ev: Consent{Challenge: hydraC, Cookie: cookie, Memory: memory(func(c *Remembered) { c.FH = "0000000000000000" })},
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipComposition)},
		{name: "SKC-6 MEM-4, another session", ev: Consent{Challenge: hydraC, Memory: memory(func(c *Remembered) { c.SID = "other" })},
			says: hydraSays{GetConsent: read(nil), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipSession)},
		{name: "SKC-6 MEM-8, a scope more", ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid", "phone"} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipScopes)},
		{name: "SKC-6 MEM-6, outside the client's restriction", ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.Client.Metadata = map[string]any{"dispatcher": map[string]any{"flows": []any{"hydra-oidc"}}}
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipFlow)},
		{name: "SKC-6 MEM-9, acr_values", env: withACRs, ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"2"}}
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipFlow)},
		{name: "SKC-7, no marker", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"app":"sql"}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
		{name: "SKC-7, a context that is no object (Symfony's [])", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = []any{} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
		{name: "SKC-8 Q38, a marker forged", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"x_dispatcher_skip":"00"}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8 Q38, a marker for another acr", ev: get,
			says: hydraSays{GetConsent: read(marker(sessionID, "alice", "2", []string{"pwd"}, requestURL)), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8 Q38, a marker for another amr", ev: get,
			says: hydraSays{GetConsent: read(marker(sessionID, "alice", "1", []string{"pwd", "otp"}, requestURL)), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8 Q38, a marker for another request_url", ev: get,
			says: hydraSays{GetConsent: read(marker(sessionID, "alice", "1", []string{"pwd"}, requestURL+"&x=1")), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8 Q38, a marker of another session", ev: get,
			says: hydraSays{GetConsent: read(marker("other", "alice", "1", []string{"pwd"}, requestURL)), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8 Q38, a marker of another subject", ev: get,
			says: hydraSays{GetConsent: read(marker(sessionID, "bob", "1", []string{"pwd"}, requestURL)), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8, the marker before the cookie", ev: Consent{Challenge: hydraC},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"x_dispatcher_skip":"00"}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-9, Hydra 404 at the accept", ev: get, says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err404}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-9, Hydra 401 at the accept", ev: get, says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err401}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-9, Hydra 410 at the reject", ev: post(false, nil), says: hydraSays{GetConsent: read(noSkip), RejectConsent: {err: err410}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent, RejectConsent}},
		{name: "SKC-10, Hydra 409 at the accept", ev: get, says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: err409}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, AcceptConsent},
			check: func(t *testing.T, p played) {
				if !slices.Contains(p.Reports, Report{Event: "flow.error", Detail: "E1007", Sentry: true}) {
					t.Errorf("no Sentry: %+v", p.Reports)
				}
			}},
		{name: "SKC-10, Hydra 403 at the reject", ev: Consent{Challenge: hydraC}, says: hydraSays{GetConsent: read(nil), RejectConsent: {err: err403}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}},
		{name: "SKC-11, Hydra unavailable at the accept", ev: get, says: hydraSays{GetConsent: read(nil), AcceptConsent: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-11, an accept without redirect_to", ev: get, says: hydraSays{GetConsent: read(nil), AcceptConsent: {}},
			kind: ErrorPage, code: E1004, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-12 Q37, the cookie written again since the screen", ev: post(true, func(c *Consent) {
			c.Memory = memory(func(r *Remembered) { r.IDT = Object{"email": json.RawMessage(`"new@example.org"`)} })
		}), says: hydraSays{GetConsent: read(noSkip)}, kind: ConsentPage, calls: []Op{GetConsent},
			check: func(t *testing.T, p played) {
				s := p.Response.Consent
				if want := testKeys.ClaimsPrint(Object{"email": json.RawMessage(`"new@example.org"`)}, MergeClaims(memory(nil).Content.ACT)); s == nil || s.Print != want || rawJSON(s.Claims) != `{"email":"new@example.org"}` {
					t.Errorf("screen %+v", s)
				}
			}},
		{name: "SKC-12, no print", ev: post(true, func(c *Consent) { c.Print = "" }), says: hydraSays{GetConsent: read(noSkip)},
			kind: ConsentPage, calls: []Op{GetConsent}},
		{name: "SKC-13, the consent webhook fails", env: consentHook, ev: get, says: hydraSays{GetConsent: read(nil), ConsentHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{GetConsent, ConsentHook}},
		{name: "SKC-13, claims that are no object", env: consentHook, ev: post(true, nil),
			says: hydraSays{GetConsent: read(noSkip), ConsentHook: {consentHook: &ConsentHookAnswer{AccessToken: json.RawMessage(`"x"`)}}},
			kind: ErrorPage, code: E1006, calls: []Op{GetConsent, ConsentHook}},
		// T2: a consent request with x_dispatcher_ref never takes this path,
		// whatever its marker and the cookie.
		{name: "CST-6 T2, a ref and a valid marker", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				m := testKeys.SkipMarker(sessionID, "alice", "1", []string{"pwd"}, requestURL)
				r.Context = json.RawMessage(`{"x_dispatcher_ref":"` + lref + `","x_dispatcher_skip":"` + m + `"}`)
			})}, kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
	} {
		tc.run(t)
	}
}

// remembered wants the cookie the consent accept writes (WRT-1, Q39): what
// the final accept sent and what the consent grants, alive remember_for.
func rememberedOf(want func(c *Remembered)) func(t *testing.T, p played) {
	return func(t *testing.T, p played) {
		t.Helper()
		got := p.Response.Remember
		if want == nil {
			if got != nil {
				t.Errorf("WRT-3, a cookie written: %+v", got)
			}
			return
		}
		w := &Remembered{
			V: RememberedFormat, SID: sessionID, Sub: "alice", Flow: "hydra-sql-2fa", FH: Composition([]string{"sql", "2fa"}),
			ACR: "2", AMR: []string{"pwd", "otp"}, Ctx: Object{"from": json.RawMessage(`"2fa"`)},
			Scp: []string{"openid", "email"},
			IDT: Object{"email": json.RawMessage(`"alice@example.org"`), "step": json.RawMessage(`"2fa"`)}, ACT: Object{},
			IAT: testNow.Unix(), Exp: testNow.Unix() + 86400,
		}
		want(w)
		if rawJSON(got) != rawJSON(w) {
			t.Errorf("WRT-1, cookie\n%s\nwant\n%s", rawJSON(got), rawJSON(w))
		}
	}
}

// sentFlow is acceptedFlow with what FIN-1 keeps since Q39: the context,
// remember and remember_for sent.
func sentFlow(t *testing.T, mod func(s *SentLogin)) *Flow {
	f := acceptedFlow(t)
	f.Sent.Context, f.Sent.Remember, f.Sent.RememberFor = Object{"from": json.RawMessage(`"2fa"`)}, true, 86400
	if mod != nil {
		mod(f.Sent)
	}
	return f
}

func TestRememberWritten(t *testing.T) {
	get := Consent{Challenge: hydraC, Cookie: cookie}
	post := func(accept bool) Consent {
		return Consent{Challenge: hydraC, Cookie: cookie, Post: true, Accept: accept, Token: cookie, SameOrigin: true}
	}
	skipped := func(mod func(r *ory.OAuth2ConsentRequest)) said {
		return said{consent: consentRequest(lref, func(r *ory.OAuth2ConsentRequest) {
			r.Skip = ory.PtrBool(true)
			if mod != nil {
				mod(r)
			}
		})}
	}
	for _, tc := range []pageCase{
		{name: "WRT-1, CST-12", ev: get, stored: sentFlow(t, nil), says: hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(func(*Remembered) {})},
		{name: "WRT-1, CST-14", ev: post(true), stored: sentFlow(t, nil), says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(func(*Remembered) {})},
		{name: "WRT-1, the consent webhook's claims", env: func(e *Env) { e.Config.Settings.ConsentAcceptWebhookURL = "http://hook.test/consent" },
			ev: get, stored: sentFlow(t, nil),
			says: hydraSays{GetConsent: skipped(nil), ConsentHook: {consentHook: &ConsentHookAnswer{IDToken: json.RawMessage(`{"hook":1}`)}}, AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, ConsentHook, AcceptConsent}, write: finishedWithCR,
			check: rememberedOf(func(c *Remembered) { c.IDT = Object{"hook": json.RawMessage(`1`)} })},
		{name: "WRT-1, the remember_for sent: the cookie's life", ev: get, stored: sentFlow(t, func(s *SentLogin) { s.RememberFor = 60 }),
			says: hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(func(c *Remembered) { c.Exp = testNow.Unix() + 60 })},
		{name: "WRT-1, remember_for 0: a cookie of the browser's session", ev: get, stored: sentFlow(t, func(s *SentLogin) { s.RememberFor = 0 }),
			says: hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(func(c *Remembered) { c.Exp = 0 })},
		{name: "WRT-1 Q38, never a member of the dispatcher in the cookie", ev: get,
			stored: sentFlow(t, func(s *SentLogin) { s.Context["x_dispatcher_skip"] = json.RawMessage(`"m"`) }),
			says:   hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(func(*Remembered) {})},
		{name: "WRT-3, remember false: nothing", ev: get, stored: sentFlow(t, func(s *SentLogin) { s.Remember = false }),
			says: hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(nil)},
		{name: "WRT-3, a flow accepted before P8: nothing", ev: get, stored: acceptedFlow(t),
			says: hydraSays{GetConsent: skipped(nil), AcceptConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR, check: rememberedOf(nil)},
		{name: "CST-15, a consent refused neither writes nor clears", ev: post(false), stored: sentFlow(t, nil),
			says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}, RejectConsent: {redirectTo: hydraDone}}, kind: Redirect, url: hydraDone,
			calls: []Op{GetConsent, RejectConsent}, write: finishedWithCR, check: rememberedOf(nil)},
		{name: "CST-13, the screen writes no cookie", ev: get, stored: sentFlow(t, nil), says: hydraSays{GetConsent: {consent: consentRequest(lref, nil)}},
			kind: ConsentPage, calls: []Op{GetConsent}, write: func(*testing.T, *Flow) {}, check: rememberedOf(nil)},
		// ECR-4: the accept carried over to a flow read again, not finished:
		// written; ECR-9: a flow finished by another transition: never.
		{name: "WRT-1 ECR-4, the accept carried over", ev: get, stored: sentFlow(t, nil),
			reread: func() *Flow { f := sentFlow(t, nil); f.ConsentChallenge = "other"; return f }(),
			says:   hydraSays{GetConsent: skipped(nil), AcceptConsent: {err: err409}},
			kind:   ErrorPage, code: E1007, calls: []Op{GetConsent, AcceptConsent}, check: rememberedOf(nil)},
	} {
		tc.run(t)
	}
}

// FIN-1 (Q38, Q39): the x_dispatcher_* members of the steps and of the
// webhook are dropped before x_dispatcher_ref; what was sent is kept, the
// context, remember and remember_for included.
func TestFinalAcceptContext(t *testing.T) {
	stored := lastDone(t)
	stored.Steps[0].ConsentContext["x_dispatcher_skip"] = json.RawMessage(`"from an app"`)
	stored.Steps[1].ConsentContext["x_dispatcher_ref"] = json.RawMessage(`"0000"`)
	for _, tc := range []pageCase{
		{name: "FIN-1 Q38 Q39", ev: Loop{Ref: lref, Cookie: cookie}, stored: stored, says: hydraSays{AcceptLogin: {redirectTo: verifierURL}},
			kind: Redirect, url: verifierURL, calls: []Op{AcceptLogin},
			write: func(t *testing.T, f *Flow) {
				s := f.Sent
				if rawJSON(s.Context) != `{"from":"2fa"}` || !s.Remember || s.RememberFor != 86400 {
					t.Errorf("Q39, sent %+v, context %s", s, rawJSON(s.Context))
				}
			},
			check: func(t *testing.T, p played) {
				if got := rawJSON(p.calls[0].AcceptLogin.Context); got != `{"from":"2fa","x_dispatcher_ref":"`+lref+`"}` {
					t.Errorf("Q38, context %s", got)
				}
			}},
		{name: "FIN-1 Q38, the webhook's members of the dispatcher dropped", env: func(e *Env) {
			e.Config.Settings.LoginAcceptWebhookURL = "http://hook.test/login"
		}, ev: Loop{Ref: lref, Cookie: cookie}, stored: lastDone(t),
			says: hydraSays{LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`{"x_dispatcher_ref":"forged","x_dispatcher_skip":"forged","h":1}`),
				Remember: ory.PtrBool(false), RememberFor: ory.PtrInt64(5)}}, AcceptLogin: {redirectTo: verifierURL}},
			kind: Redirect, url: verifierURL, calls: []Op{LoginHook, AcceptLogin},
			write: func(t *testing.T, f *Flow) {
				if s := f.Sent; rawJSON(s.Context) != `{"h":1}` || s.Remember || s.RememberFor != 5 {
					t.Errorf("Q39, sent %+v", s)
				}
			},
			check: func(t *testing.T, p played) {
				if got := rawJSON(p.calls[1].AcceptLogin.Context); got != `{"h":1,"x_dispatcher_ref":"`+lref+`"}` {
					t.Errorf("Q38, context %s", got)
				}
			}},
	} {
		tc.run(t)
	}
}

// SKP-6 ECR-3: the accept of a skip, its flow's creation lost to a
// concurrent load of the same skip: its own redirect_to; on a flow
// finished otherwise, ECR-9; on a flow in progress, ECR-4.
func TestSkipFactCarriedOver(t *testing.T) {
	read := hydraSays{GetLogin: {login: skipRequest(t, nil)}, AcceptLogin: {redirectTo: skipCSRF}}
	in := Input{Event: Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)}, Env: testEnv(), Loaded: true}
	var calls []Call
	for range 4 {
		out := Decide(in)
		if out.Call == nil {
			break
		}
		calls = append(calls, *out.Call)
		answer(&in.Answers, *out.Call, read[out.Call.Op])
	}
	if len(calls) != 2 {
		t.Fatalf("calls %+v", calls)
	}
	other := choiceFlow(t).Reduce()
	other.ConsentRedirect, other.ConsentAt, other.Skipped = "http://hydra/other", testNow.UnixMilli(), true
	rejectedOther := choiceFlow(t).Reduce()
	for _, tc := range []struct {
		name   string
		reread *Flow
		url    string
		code   Code
		write  bool
	}{
		{"SKP-6 ECR-3, the same skip written by a concurrent load", other, skipCSRF, "", false},
		{"ECR-9, a flow finished otherwise", rejectedOther, "", E1002, false},
		{"ECR-4, a flow in progress: the accept carried over", choiceFlow(t), skipCSRF, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			again := in
			again.Reread, again.Flow = true, copyFlow(t, tc.reread)
			out := Decide(again)
			if out.Response.URL != tc.url || out.Response.Code != tc.code || (out.Write != nil) != tc.write {
				t.Errorf("answer %+v, write %v", out.Response, out.Write != nil)
			}
		})
	}
}
