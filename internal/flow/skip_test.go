package flow

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
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
	r.RequestedAccessTokenAudience = []string{"api"}
	if mod != nil {
		mod(r)
	}
	return r
}

// promptNoneRequest gives the authorization request prompt=none, which a login
// request only shows in its request_url.
func promptNoneRequest(r *ory.OAuth2LoginRequest) { r.RequestUrl = requestURL + "&prompt=none" }

// memory is a remember cookie that passes every check against
// skipRequest: hydra-sql, the fixture's scopes and the audience api, the same
// sets (MEM-8, MEM-10), alive for an hour.
func memory(mod func(c *Remembered)) Memory {
	c := &Remembered{
		V: RememberedFormat, SID: sessionID, Sub: "alice", Flow: "hydra-sql", FH: Composition([]string{"sql"}),
		ACR: "1", AMR: []string{"pwd"},
		Ctx: Object{"app": json.RawMessage(`"sql"`), "x_dispatcher_ref": json.RawMessage(`"old"`)},
		Scp: []string{"openid", "profile", "email"},
		Aud: []string{"api"},
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
		if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "skip.accepted" && r.Kind == kind && r.Flow != "" }) {
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

// MEM-1 to MEM-10, at the entry: the first check that fails ignores Hydra's
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
		ignoredCase("MEM-1, as a page opens it", nil, Memory{Reason: SkipAbsent}, nil, SkipAbsent),
		ignoredCase("MEM-2, unreadable", nil, Memory{Reason: SkipUnreadable}, nil, SkipUnreadable),
		ignoredCase("MEM-3, expired", nil, memory(func(c *Remembered) { c.Exp = testNow.Unix() }), nil, SkipExpired),
		honoured("MEM-3, a second before exp", nil, memory(func(c *Remembered) { c.Exp = testNow.Unix() + 1 }), nil),
		honoured("MEM-3, exp 0: a cookie of the browser's session", nil, memory(func(c *Remembered) { c.Exp = 0 }), nil),
		ignoredCase("MEM-4, another session", nil, memory(func(c *Remembered) { c.SID = "other" }), nil, SkipSession),
		ignoredCase("MEM-4, a cookie without a session", nil, memory(func(c *Remembered) { c.SID = "" }), nil, SkipSession),
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
		// Revue R20: the cookie's claims were filtered for the scopes granted;
		// fewer would get claims of scopes not requested.
		ignoredCase("MEM-8, fewer scopes than granted", nil, memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedScope = []string{"openid"} }, SkipScopes),
		honoured("MEM-8, the same scopes, in another order and repeated", nil, memory(nil), func(r *ory.OAuth2LoginRequest) {
			r.RequestedScope = []string{"email", "openid", "profile", "openid"}
		}),
		// Q164: a partner asks openid alone after the portal's openid profile
		// email (a partner behind an authenticating proxy that tries
		// prompt=none).
		honoured("MEM-8 Q164, fewer scopes, skip_scopes subset", skipScopes(store.SkipScopesSubset), memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedScope = []string{"openid"} }),
		ignoredCase("MEM-8 Q164, a scope more, skip_scopes subset", skipScopes(store.SkipScopesSubset), memory(func(c *Remembered) { c.Scp = []string{"openid", "email"} }), nil, SkipScopes),
		honoured("MEM-8 Q164, fewer scopes, skip_scopes any", skipScopes(store.SkipScopesAny), memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedScope = []string{"openid"} }),
		honoured("MEM-8 Q164, a scope more, skip_scopes any", skipScopes(store.SkipScopesAny), memory(func(c *Remembered) { c.Scp = []string{"openid"} }), nil),
		ignoredCase("MEM-10 Q164: skip_scopes any leaves the audience compared", skipScopes(store.SkipScopesAny), memory(nil), func(r *ory.OAuth2LoginRequest) {
			r.RequestedScope = []string{"openid"}
			r.RequestedAccessTokenAudience = []string{"other"}
		}, SkipAudience),
		// MEM-9 (Q36): the admin raised hydra-sql's acr to 2, fh unchanged.
		ignoredCase("MEM-9, the cookie's acr not among acr_values", func(e *Env) { withACRs(e); configured(e, "hydra-sql").ACR = "2" }, memory(nil), acrValues("2"), SkipACR),
		honoured("MEM-9, the cookie's acr among acr_values", withACRs, memory(nil), acrValues("1", "2")),
		honoured("MEM-9, only the preferred flow's prefix", nil, memory(nil), preferred("hydra-sql")),
		// MEM-10 (revue R21): the access token claims were written for the
		// audiences of the consent that wrote the cookie.
		ignoredCase("MEM-10, another audience", nil, memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedAccessTokenAudience = []string{"other"} }, SkipAudience),
		ignoredCase("MEM-10, an audience more than granted", nil, memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedAccessTokenAudience = []string{"api", "other"} }, SkipAudience),
		ignoredCase("MEM-10, no audience requested", nil, memory(nil), func(r *ory.OAuth2LoginRequest) { r.RequestedAccessTokenAudience = nil }, SkipAudience),
		ignoredCase("MEM-10, none in a cookie without the member", nil, memory(func(c *Remembered) { c.Aud = nil }), nil, SkipAudience),
		ignoredCase("MEM-9 before MEM-10", func(e *Env) { withACRs(e); configured(e, "hydra-sql").ACR = "2" }, memory(nil), func(r *ory.OAuth2LoginRequest) {
			acrValues("2")(r)
			r.RequestedAccessTokenAudience = []string{"other"}
		}, SkipACR),
		honoured("MEM-10, the same audiences, in another order and repeated", nil, memory(func(c *Remembered) { c.Aud = []string{"b", "a"} }), func(r *ory.OAuth2LoginRequest) {
			r.RequestedAccessTokenAudience = []string{"a", "b", "a"}
		}),
		honoured("MEM-10, none on either side", nil, memory(func(c *Remembered) { c.Aud = nil }), func(r *ory.OAuth2LoginRequest) { r.RequestedAccessTokenAudience = nil }),
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
			kind: ErrorPage, code: E1003, calls: []Op{GetLogin, LoginHook, RejectLogin}, write: finished, check: func(t *testing.T, p played) {
				rejected(RejectLogin, "login_required")(t, p)
				if !strings.HasSuffix(p.Response.SignOut, "/oauth2/sessions/logout") { // Q63: past a logout, no skip, nothing compared
					t.Errorf("the way out: %q", p.Response.SignOut)
				}
				// Q67: the log tells a webhook's doing from FIN-3.
				if !slices.ContainsFunc(p.Reports, func(r Report) bool { return r.Event == "flow.rejected" && r.Detail == "skip_subject:webhook" }) {
					t.Errorf("reports %+v", p.Reports)
				}
			}},
		{name: "SKP-7 EXP-4, Hydra 401 on the reject", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, LoginHook, RejectLogin}, write: finished},
		{name: "SKP-7 EXP-4, Hydra unavailable on the reject: not created", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Subject: ory.PtrString("bob")}}, RejectLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, LoginHook, RejectLogin}},
		// Q88: the page gives Hydra's logout, as E1003.
		{name: "SKP-9, the webhook fails", env: hook, ev: entry, says: hydraSays{GetLogin: read(nil), LoginHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{GetLogin, LoginHook}, check: signOut("http://public.hydra.test/oauth2/sessions/logout")},
		{name: "SKP-9 A9, a context that is no object", env: hook, ev: entry,
			says: hydraSays{GetLogin: read(nil), LoginHook: {loginHook: &LoginHookAnswer{Context: json.RawMessage(`[]`)}}},
			kind: ErrorPage, code: E1006, calls: []Op{GetLogin, LoginHook}, check: signOut("http://public.hydra.test/oauth2/sessions/logout")},
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
		{name: "SKP-2 CHX-1, ignored then rejected", env: func(e *Env) { withACRs(e); requireACR(e) }, ev: Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)},
			says: hydraSays{GetLogin: read(func(r *ory.OAuth2LoginRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"3"}}
			}), RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				ignoredFor("login", SkipFlow)(t, p)
				rejected(RejectLogin, "unmet_authentication_requirements")(t, p)
			}},
		// Q151: acr_values no flow declares, every flow offered; a flow run
		// again would meet them no better, the skip is honoured (MEM-6, MEM-9).
		{name: "SKP-1 CHX-6, acr_values no flow declares: honoured", env: withACRs, ev: Entry{LoginChallenge: hydraL, Cookie: cookie, Memory: memory(nil)},
			says: hydraSays{GetLogin: read(func(r *ory.OAuth2LoginRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"3"}}
			}), AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin}, write: finished},
		// SKP-11 (revue R21): prompt=none forbids the page a skip ignored would
		// show; Hydra, which has a session, leaves that to the login app.
		{name: "SKP-11, prompt=none without the cookie: login_required", ev: Entry{LoginChallenge: hydraL, Cookie: cookie},
			says: hydraSays{GetLogin: read(promptNoneRequest), RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				rejected(RejectLogin, "login_required")(t, p)
				ignoredFor("login", SkipAbsent)(t, p)
				if !slices.Contains(p.Reports, Report{Event: "flow.rejected", Detail: "prompt_none"}) {
					t.Errorf("no flow.rejected prompt_none: %+v", p.Reports)
				}
			}},
		{name: "SKP-11, prompt=none and fewer scopes: login_required", ev: entry,
			says: hydraSays{GetLogin: read(func(r *ory.OAuth2LoginRequest) {
				promptNoneRequest(r)
				r.RequestedScope = []string{"openid"}
			}), RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished, check: ignoredFor("login", SkipScopes)},
		{name: "SKP-11 EXP-4, Hydra 401 on the reject", ev: Entry{LoginChallenge: hydraL},
			says: hydraSays{GetLogin: read(promptNoneRequest), RejectLogin: {err: err401}},
			kind: ErrorPage, code: E1002, link: true, calls: []Op{GetLogin, RejectLogin}, write: finished},
		{name: "SKP-11 EXP-4, Hydra unavailable on the reject: not created", ev: Entry{LoginChallenge: hydraL},
			says: hydraSays{GetLogin: read(promptNoneRequest), RejectLogin: {err: errDown}},
			kind: ErrorPage, code: E1004, calls: []Op{GetLogin, RejectLogin}},
		{name: "SKP-11, before ENT-22: prompt=none in the last minute of L", ev: Entry{LoginChallenge: hydraL},
			says: hydraSays{GetLogin: {login: skipRequest(t, promptNoneRequest), requestedAt: testNow.Add(-29*time.Minute - 30*time.Second)}, RejectLogin: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetLogin, RejectLogin}, write: finished,
			check: func(t *testing.T, p played) {
				if !slices.Contains(p.Reports, Report{Event: "flow.rejected", Detail: "prompt_none"}) {
					t.Errorf("no flow.rejected prompt_none: %+v", p.Reports)
				}
			}},
		// With the cookie valid, nothing is shown: prompt=none is honoured.
		{name: "SKP-1, prompt=none, the cookie valid", ev: entry, says: hydraSays{GetLogin: read(promptNoneRequest), AcceptLogin: {redirectTo: skipCSRF}},
			kind: Redirect, url: skipCSRF, calls: []Op{GetLogin, AcceptLogin}, write: skipWritten, check: acceptedSkip("login")},
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
		RequestedScope:               []string{"openid", "profile", "email"},
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
		if !slices.Equal(b.GrantScope, []string{"openid", "profile", "email"}) || !slices.Equal(b.GrantAccessTokenAudience, []string{"api"}) ||
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
		{name: "SKC-1 strict (Q129): groups, of no scope asked, not sent", env: func(e *Env) { e.StrictClaims = true }, ev: get, says: accept,
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent},
			check: func(t *testing.T, p played) {
				b := p.calls[len(p.calls)-1].AcceptConsent
				if rawJSON(b.Session.IdToken) != `{"email":"alice@example.org","name":"Alice"}` || rawJSON(b.Session.AccessToken) != `{}` {
					t.Errorf("session %s %s", rawJSON(b.Session.IdToken), rawJSON(b.Session.AccessToken))
				}
			}},
		{name: "SKC-2 strict: the screen without the flow shows what is sent", env: func(e *Env) { e.StrictClaims = true }, ev: get,
			says: hydraSays{GetConsent: read(noSkip)}, kind: ConsentPage, calls: []Op{GetConsent},
			check: func(t *testing.T, p played) {
				if s := p.Response.Consent; s == nil || rawJSON(s.AccessClaims) != `{}` || rawJSON(s.Claims) != `{"email":"alice@example.org","name":"Alice"}` {
					t.Errorf("screen %+v", s)
				}
			}},
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
		{name: "SKC-1 strict (Q129): the webhook's claims by the scopes granted", ev: get,
			env:  func(e *Env) { consentHook(e); e.StrictClaims = true },
			says: hydraSays{GetConsent: read(nil), ConsentHook: {consentHook: &ConsentHookAnswer{IDToken: json.RawMessage(`{"hook":1,"email":"a@b"}`)}}, AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, ConsentHook, AcceptConsent},
			check: func(t *testing.T, p played) {
				if got := rawJSON(p.calls[2].AcceptConsent.Session.IdToken); got != `{"email":"a@b"}` {
					t.Errorf("id_token %s", got)
				}
			}},
		{name: "SKC-1 Q38, the webhook gets the cookie's context, never the request's", env: consentHook, ev: get,
			says: hydraSays{GetConsent: read(nil), ConsentHook: {}, AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, ConsentHook, AcceptConsent},
			check: func(t *testing.T, p played) {
				h := p.calls[1].Hook
				if h == nil || h.Location != "http://hook.test/consent" || h.Subject != "alice" || h.ACR != "1" {
					t.Fatalf("hook %+v", h)
				}
				if got := rawJSON(h.Context); got != `{"app":"sql"}` {
					t.Errorf("context %s, want the cookie's, without its x_dispatcher_* members", got)
				}
				if !strings.Contains(string(h.Client), `"client_id"`) {
					t.Errorf("client %s", h.Client)
				}
			}},
		{name: "SKC-1, the webhook replaces the scopes and the audiences", env: consentHook, ev: get,
			says: hydraSays{GetConsent: read(nil), ConsentHook: {consentHook: &ConsentHookAnswer{GrantScope: []string{"openid", "extra"}, GrantAudience: []string{}}}, AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, ConsentHook, AcceptConsent},
			check: func(t *testing.T, p played) {
				b := p.calls[2].AcceptConsent
				if !slices.Equal(b.GrantScope, []string{"openid", "extra"}) || len(b.GrantAccessTokenAudience) != 0 || b.GrantAccessTokenAudience == nil {
					t.Errorf("accept %+v", b)
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
		// A refusal sends no claim: the print does not hold it back (SKC-12).
		{name: "SKC-4, refused from a screen whose claims changed", ev: post(false, func(c *Consent) { c.Print = "stale" }),
			says: hydraSays{GetConsent: read(noSkip), RejectConsent: {redirectTo: hydraDone}},
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
		// Revue R20: fewer scopes would get the claims of scopes not requested.
		{name: "SKC-6 MEM-8, fewer scopes than granted", ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid"} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent},
			check: func(t *testing.T, p played) {
				rejected(RejectConsent, "login_required")(t, p)
				ignoredFor("consent", SkipScopes)(t, p)
			}},
		// Q164: the partner's openid alone, the portal's cookie. Permissive,
		// the cookie's claims; strict, those of openid alone (none here).
		{name: "SKC-1 Q164, fewer scopes, skip_scopes any: the cookie's claims", env: skipScopes(store.SkipScopesAny), ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid"} }), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent},
			check: func(t *testing.T, p played) {
				b := p.calls[len(p.calls)-1].AcceptConsent
				if !slices.Equal(b.GrantScope, []string{"openid"}) || rawJSON(b.Session.IdToken) != `{"email":"alice@example.org","name":"Alice"}` {
					t.Errorf("grant %v, session %s", b.GrantScope, rawJSON(b.Session.IdToken))
				}
			}},
		// R62: the consent without a flow compares as the entry does.
		{name: "SKC-6 MEM-8 Q164, a scope more, skip_scopes subset", env: skipScopes(store.SkipScopesSubset), ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid", "phone"} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent},
			check: func(t *testing.T, p played) {
				rejected(RejectConsent, "login_required")(t, p)
				ignoredFor("consent", SkipScopes)(t, p)
			}},
		{name: "SKC-1 Q164, a scope more, skip_scopes any: the cookie's claims, no more", env: skipScopes(store.SkipScopesAny), ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid", "phone"} }), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent},
			check: func(t *testing.T, p played) {
				b := p.calls[len(p.calls)-1].AcceptConsent
				if !slices.Equal(b.GrantScope, []string{"openid", "phone"}) || rawJSON(b.Session.IdToken) != `{"email":"alice@example.org","name":"Alice"}` {
					t.Errorf("grant %v, session %s", b.GrantScope, rawJSON(b.Session.IdToken))
				}
			}},
		{name: "SKC-1 Q164 strict, fewer scopes, skip_scopes subset: the claims of the scopes asked", env: func(e *Env) { skipScopes(store.SkipScopesSubset)(e); e.StrictClaims = true }, ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedScope = []string{"openid"} }), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent},
			check: func(t *testing.T, p played) {
				b := p.calls[len(p.calls)-1].AcceptConsent
				if rawJSON(b.Session.IdToken) != `{}` || rawJSON(b.Session.AccessToken) != `{}` {
					t.Errorf("session %s %s", rawJSON(b.Session.IdToken), rawJSON(b.Session.AccessToken))
				}
			}},
		// Revue R21: the access token claims were written for other audiences.
		{name: "SKC-6 MEM-10, another audience", ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.RequestedAccessTokenAudience = []string{"other"} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent},
			check: func(t *testing.T, p played) {
				rejected(RejectConsent, "login_required")(t, p)
				ignoredFor("consent", SkipAudience)(t, p)
			}},
		{name: "SKC-6 MEM-6, outside the client's restriction", ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.Client.Metadata = map[string]any{"dispatcher": map[string]any{"flows": []any{"hydra-oidc"}}}
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipFlow)},
		{name: "SKC-6 MEM-6, filtered out by acr_values", env: withACRs, ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"2"}}
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipFlow)},
		{name: "SKC-6 MEM-9, the cookie's acr not among acr_values", env: func(e *Env) { withACRs(e); configured(e, "hydra-sql").ACR = "2" },
			ev: Consent{Challenge: hydraC, Memory: memory(nil)},
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				r.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: []string{"2"}}
			}), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: ignoredFor("consent", SkipACR)},
		{name: "SKC-7, no marker", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"app":"sql"}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
		{name: "SKC-7, a context that is no object (Symfony's [])", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = []any{} }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
		{name: "SKC-8 Q38, a marker forged", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"x_dispatcher_skip":"00"}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		// Revue R20: a marker the dispatcher never writes, of another type, is
		// forged, not absent: audited.
		{name: "SKC-8, a marker that is a number", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = json.RawMessage(`{"x_dispatcher_skip":123}`) }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-8, a marker null", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = map[string]any{"x_dispatcher_skip": nil} }), RejectConsent: {redirectTo: hydraDone}},
			kind: ErrorPage, code: E1007, calls: []Op{GetConsent, RejectConsent}, check: notOursSkip},
		{name: "SKC-7, a context null", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) { r.Context = nil }), RejectConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, RejectConsent}, check: rejected(RejectConsent, "login_required")},
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
		// SKC-14 (revue R20): the screen posted again once its verifier was
		// followed. Hydra 2.1 answers 410 to the read: E1002; 2.2 and 2.3
		// serve it again (consent_used), the accept passes as SKC-3 and the
		// client gets access_denied at the verifier: nothing stored tells it.
		{name: "SKC-14, Hydra 2.1: the consent used, 410", ev: post(true, nil), says: hydraSays{GetConsent: {err: err410}},
			kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "SKC-14, Hydra 2.2 and 2.3: served again, accepted again, as SKC-3", ev: post(true, nil),
			says: hydraSays{GetConsent: read(noSkip), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}, check: consentAccepted},
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
		{name: "SKC-12, only the access token's claims changed", ev: post(true, func(c *Consent) {
			c.Memory = memory(func(r *Remembered) { r.ACT = Object{"groups": json.RawMessage(`["b"]`)} })
		}), says: hydraSays{GetConsent: read(noSkip)}, kind: ConsentPage, calls: []Op{GetConsent}},
		// Rotation des clés: the marker of a skip accepted before the rotation.
		{name: "SKC-1, the marker of the previous challenge key", ev: get,
			says: hydraSays{GetConsent: read(func(r *ory.OAuth2ConsentRequest) {
				m := Keys{oldKey}.SkipMarker(sessionID, "alice", "1", []string{"pwd"}, requestURL)
				r.Context = json.RawMessage(`{"x_dispatcher_skip":"` + m + `"}`)
			}), AcceptConsent: {redirectTo: callbackURL}},
			kind: Redirect, url: callbackURL, calls: []Op{GetConsent, AcceptConsent}},
		{name: "SKC-13, the consent webhook fails", env: consentHook, ev: get, says: hydraSays{GetConsent: read(nil), ConsentHook: {hookErr: errDown}},
			kind: ErrorPage, code: E1006, calls: []Op{GetConsent, ConsentHook}, check: hookReport("webhook.failed", "consent")},
		{name: "SKC-13 Q72, a client gone", env: consentHook, ev: get, says: hydraSays{GetConsent: read(nil), ConsentHook: {hookErr: context.Canceled}},
			kind: ErrorPage, code: E1006, calls: []Op{GetConsent, ConsentHook}, check: hookReport("webhook.abandoned", "consent")},
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
		// Revue R21: nor a ref of another type, null included, that the
		// dispatcher never writes.
		{name: "CST-6 T2, a ref that is a number, and a valid marker", ev: get, says: refOfAnotherType(`123`), kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "CST-6 T2, a ref null, and a valid marker", ev: get, says: refOfAnotherType(`null`), kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "CST-6 T2, a ref that is an object, and a valid marker", ev: get, says: refOfAnotherType(`{"a":1}`), kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
		{name: "CST-6 T2, a ref that is a list, and a valid marker", ev: get, says: refOfAnotherType(`["` + lref + `"]`), kind: ErrorPage, code: E1002, calls: []Op{GetConsent}},
	} {
		tc.run(t)
	}
}

// refOfAnotherType is a consent request whose x_dispatcher_ref is raw, with a
// marker valid for it.
func refOfAnotherType(raw string) hydraSays {
	m := testKeys.SkipMarker(sessionID, "alice", "1", []string{"pwd"}, requestURL)
	return hydraSays{GetConsent: {consent: consentSkip(func(r *ory.OAuth2ConsentRequest) {
		r.Context = json.RawMessage(`{"x_dispatcher_ref":` + raw + `,"x_dispatcher_skip":"` + m + `"}`)
	})}}
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
			V: RememberedFormat, SID: sessionID, Sub: "alice", Flow: "hydra-sql-2fa", FH: Composition([]string{"sql", "2fa"}), AP: []string{"sql", "2fa"},
			ACR: "2", AMR: []string{"pwd", "otp"}, Ctx: Object{"from": json.RawMessage(`"2fa"`)},
			Scp: []string{"openid", "email"}, Aud: []string{},
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
		return Consent{Challenge: hydraC, Cookie: cookie, Post: true, Accept: accept, Token: cookie, SameOrigin: true, Print: shownPrint}
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
		{name: "WRT-1 MEM-10, the audiences granted", ev: get, stored: sentFlow(t, nil),
			says: hydraSays{GetConsent: skipped(func(r *ory.OAuth2ConsentRequest) { r.RequestedAccessTokenAudience = []string{"api"} }), AcceptConsent: {redirectTo: hydraDone}},
			kind: Redirect, url: hydraDone, calls: []Op{GetConsent, AcceptConsent}, write: finishedWithCR,
			check: rememberedOf(func(c *Remembered) { c.Aud = []string{"api"} })},
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
		// CST-17: the accept refused, no cookie. After a write in conflict:
		// TestRememberAfterConflict.
		{name: "CST-17, Hydra 409 at the accept: no cookie", ev: get, stored: sentFlow(t, nil),
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

// signOut checks the link to Hydra's logout of an error page.
func signOut(want string) func(*testing.T, played) {
	return func(t *testing.T, p played) {
		t.Helper()
		if p.Response.SignOut != want {
			t.Errorf("the way out: %q, want %q", p.Response.SignOut, want)
		}
	}
}
