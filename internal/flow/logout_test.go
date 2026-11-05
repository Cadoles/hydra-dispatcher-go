package flow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const (
	logoutSID = "e1ab6d8c-1c0b-4a39-a3c5-7c3bd1c1ab0f"
	logoutU   = "2f9c7a2e-54a1-4f7e-8d3e-6b1f0c9e7a11"
	logoutU2  = "7b1d0a5f-8e23-4c16-9f4a-1d2e3c4b5a66"
)

func verifierOf(u string) string {
	return "http://public.hydra.test/oauth2/sessions/logout?logout_verifier=" + u
}

// logoutWorld is a dispatcher whose three apps have a logout_url, the second
// with a query of its own; set changes the apps.
func logoutWorld(t *testing.T, set ...func(apps []store.App)) *world {
	t.Helper()
	w := newWorld(t)
	apps := testApps()
	apps[0].LogoutURL = "http://sql.hydra.test/logout"
	apps[1].LogoutURL = "http://2fa.hydra.test/logout?tenant=t"
	apps[2].LogoutURL = "http://oidc.hydra.test/logout"
	for _, f := range set {
		f(apps)
	}
	w.o.Config = snapshots{store.NewSnapshot(apps, testFlows(), store.DefaultSettings())}
	return w
}

// demand is a logout request Hydra knows, of alice's session.
func (w *world) demand(u string, rp bool, mod ...func(*ory.OAuth2LogoutRequest)) {
	r := &ory.OAuth2LogoutRequest{
		Challenge: ory.PtrString(u), Subject: ory.PtrString("alice"), Sid: ory.PtrString(logoutSID),
		RequestUrl: ory.PtrString("/oauth2/sessions/logout"), RpInitiated: ory.PtrBool(rp),
	}
	if rp {
		r.RequestUrl = ory.PtrString("/oauth2/sessions/logout?id_token_hint=the.id.token&post_logout_redirect_uri=http%3A%2F%2Fc%2Fpost&state=st")
		r.Client = &ory.OAuth2Client{
			ClientId: ory.PtrString("c1"), ClientName: ory.PtrString("Test Client"), LogoUri: ory.PtrString("http://c/logo"),
			ClientUri: ory.PtrString("http://c/"), PolicyUri: ory.PtrString("http://c/policy"), TosUri: ory.PtrString("http://c/tos"),
			Metadata: json.RawMessage(`{"tenant":"t"}`), RedirectUris: []string{"http://c/cb"},
		}
	}
	for _, f := range mod {
		f(r)
	}
	w.hydra.logouts[u] = r
}

func logoutRef() string { return testKeys.LogoutRef(logoutSID) }

// record returns the chain stored, nil when absent.
func (w *world) record() *LogoutRecord {
	w.t.Helper()
	data, _, err := w.store.StateStore.Get(context.Background(), LogoutKey(logoutRef()))
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	r, err := DecodeLogout(data)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// putRecord writes r, as another request would.
func (w *world) putRecord(r *LogoutRecord) {
	w.t.Helper()
	_, v, _ := w.store.StateStore.Get(context.Background(), LogoutKey(logoutRef()))
	data, _ := r.encode()
	if err := w.store.StateStore.Put(context.Background(), LogoutKey(logoutRef()), data, time.Hour, v); err != nil {
		w.t.Fatal(err)
	}
}

// chain is a record of the three apps, at position cur, the browser sent there
// long ago.
func (w *world) chain(cur int) *LogoutRecord {
	return &LogoutRecord{
		V: LogoutFormat, U: logoutU, RT: verifierOf(logoutU), Subject: "alice", SID: logoutSID, URL: "/oauth2/sessions/logout",
		Apps: []string{"sql", "2fa", "oidc"}, Cur: cur, Sent: cur, SentAt: w.now.Add(-time.Hour).UnixMilli(),
	}
}

func appURL(app string, ref string, i int) string {
	u := map[string]string{"sql": "http://sql.hydra.test/logout", "2fa": "http://2fa.hydra.test/logout", "oidc": "http://oidc.hydra.test/logout"}[app]
	q := "logout_challenge=" + testKeys.LogoutChallenge(ref, i, app)
	if app == "2fa" {
		return u + "?" + q + "&tenant=t"
	}
	return u + "?" + q
}

func has(r Result, event string, match ...func(Report) bool) bool {
	return slices.ContainsFunc(r.Reports, func(x Report) bool {
		if x.Event != event {
			return false
		}
		for _, m := range match {
			if !m(x) {
				return false
			}
		}
		return true
	})
}

func wasPassed(app string) func(Report) bool {
	return func(x Report) bool { return x.App == app && x.Result == "skipped" }
}

// LGO-1 to LGO-5, LGO-9, LGO-10: what never reaches the accept.
func TestLogoutPageErrors(t *testing.T) {
	soon := func(d time.Duration) func(*ory.OAuth2LogoutRequest) {
		return func(r *ory.OAuth2LogoutRequest) {
			at := testNow.Add(d)
			r.ExpiresAt = &at
		}
	}
	confirm := func(token string) Logout {
		return Logout{Challenge: logoutU, Post: true, Accept: true, Token: token, Cookie: cookie, SameOrigin: true}
	}
	for _, tc := range []struct {
		name  string
		ev    Logout
		get   error
		mod   func(*ory.OAuth2LogoutRequest)
		code  Code
		calls []string
		// report is an event of the answer, Sentry the page's.
		report string
		sentry bool
	}{
		{name: "LGO-1 no challenge", ev: Logout{}, code: E1001},
		{name: "LGO-1 illegible", ev: Logout{Challenge: "a/b"}, code: E1001},
		{name: "LGO-1 beyond 64 KiB", ev: Logout{Challenge: strings.Repeat("a", 64<<10+1)}, code: E1001},
		{name: "LGO-1 a POST without U, origin and token passed", ev: confirm(cookie), code: E1001},
		{name: "LGO-2 unknown", ev: Logout{Challenge: logoutU}, get: err404, code: E1001, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-2 a POST to confirm, a reject past", ev: confirm(cookie), get: err404, code: E1001, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-3 410", ev: Logout{Challenge: logoutU}, get: err410, code: E1002, calls: []string{"get_logout"}},
		{name: "LGO-3 401", ev: Logout{Challenge: logoutU}, get: err401, code: E1002, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-3 a POST to refuse, 401", ev: Logout{Challenge: logoutU, Post: true, Token: cookie, Cookie: cookie, SameOrigin: true}, get: err401, code: E1002, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-4 400", ev: Logout{Challenge: logoutU}, get: err400, code: E1007, calls: []string{"get_logout"}, sentry: true},
		{name: "LGO-4 403", ev: Logout{Challenge: logoutU}, get: err403, code: E1007, calls: []string{"get_logout"}, sentry: true},
		{name: "LGO-4 409", ev: Logout{Challenge: logoutU}, get: err409, code: E1007, calls: []string{"get_logout"}, sentry: true},
		{name: "LGO-4 unavailable", ev: Logout{Challenge: logoutU}, get: errDown, code: E1004, calls: []string{"get_logout"}, sentry: true},
		{name: "LGO-4 a POST to refuse, unavailable", ev: Logout{Challenge: logoutU, Post: true, Token: cookie, Cookie: cookie, SameOrigin: true}, get: errDown, code: E1004, calls: []string{"get_logout"}, sentry: true},
		{name: "LGO-5 expires_at past", ev: Logout{Challenge: logoutU}, mod: soon(-time.Second), code: E1002, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-5 expires_at under 60 s", ev: Logout{Challenge: logoutU}, mod: soon(59 * time.Second), code: E1002, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-5 a POST to confirm", ev: confirm(cookie), mod: soon(59 * time.Second), code: E1002, calls: []string{"get_logout"}, report: "challenge.invalid"},
		{name: "LGO-9 from another site", ev: Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie}, code: E1008},
		{name: "LGO-10 no token", ev: Logout{Challenge: logoutU, Post: true, Accept: true, Cookie: cookie, SameOrigin: true}, code: E1008},
		{name: "LGO-10 another token", ev: confirm(strings.Repeat("0", 64)), code: E1008},
		{name: "LGO-10 no cookie", ev: Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, SameOrigin: true}, code: E1008},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, false)
			if tc.mod != nil {
				tc.mod(w.hydra.logouts[logoutU])
			}
			if tc.get != nil {
				w.hydra.errs["get_logout"] = tc.get
			}
			if tc.name == "LGO-1 a POST without U, origin and token passed" {
				tc.ev.Challenge = ""
			}
			r := w.handle(tc.ev)
			if r.Response.Kind != ErrorPage || r.Response.Code != tc.code || r.Response.Link != "" {
				t.Errorf("answer %+v, want %s without a link", r.Response, tc.code)
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v, want %v", w.hydra.calls, tc.calls)
			}
			if tc.report != "" && !has(r, tc.report) {
				t.Errorf("no %s: %+v", tc.report, r.Reports)
			}
			if tc.report == "" && has(r, "challenge.invalid") {
				t.Errorf("challenge.invalid: %+v", r.Reports)
			}
			if got := slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Sentry }); got != tc.sentry {
				t.Errorf("Sentry %v, want %v: %+v", got, tc.sentry, r.Reports)
			}
			if r.Response.Remember != nil || w.record() != nil || w.store.puts != 0 {
				t.Errorf("a note or a record: %+v, %+v", r.Response.Remember, w.record())
			}
		})
	}
	// LGO-5, just above the margin: the logout goes on.
	w := logoutWorld(t)
	w.demand(logoutU, true, soon(61*time.Second))
	if r := w.handle(Logout{Challenge: logoutU}); r.Response.Kind != Redirect {
		t.Errorf("61 s left: %+v", r.Response)
	}
}

// LGO-4, Q57: internal/hydra answers an incomplete request as unavailable.
func TestLogoutRequiresSession(t *testing.T) {
	w := logoutWorld(t)
	w.hydra.errs["get_logout"] = &hydra.UnavailableError{Op: "get_logout", Status: 200}
	w.demand(logoutU, false)
	if r := w.handle(Logout{Challenge: logoutU}); r.Response.Code != E1004 {
		t.Errorf("answer %+v, want E1004", r.Response)
	}
}

// LGO-6, LGO-7, LGO-8: the confirmation, and when a client's demand has none.
func TestLogoutConfirmation(t *testing.T) {
	other := Memory{Content: &Remembered{V: 1, SID: "another-session", Sub: "bob", AP: []string{"sql"}}}
	same := Memory{Content: &Remembered{V: 1, SID: logoutSID, Sub: "alice", AP: []string{"sql"}}}
	noteOther := Memory{Content: &Remembered{V: 1, SID: "another-session", Sub: "bob", Lo: true}}
	unread := Memory{Reason: SkipUnreadable}
	for _, tc := range []struct {
		name    string
		rp      bool
		memory  Memory
		confirm bool
		other   bool
	}{
		{"LGO-6, no client", false, Memory{}, true, false},
		{"LGO-6, a cookie of the session", false, same, true, false},
		{"LGO-6, a cookie of another session: no text, it asks all the same", false, other, true, false},
		{"LGO-7, a client, a cookie of another session", true, other, true, true},
		{"LGO-7 ignores a note, which stays after a logout finished", true, noteOther, false, false},
		{"LGO-8, a client, no cookie", true, Memory{}, false, false},
		{"LGO-8, a client, a cookie of the session", true, same, false, false},
		{"LGO-8, a client, a cookie unreadable", true, unread, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, tc.rp)
			r := w.handle(Logout{Challenge: logoutU, Memory: tc.memory, Cookie: cookie})
			if !tc.confirm {
				if r.Response.Kind != Redirect || !slices.Equal(w.hydra.calls, []string{"get_logout", "accept_logout"}) || r.Response.Remember == nil {
					t.Errorf("LGO-8: %+v, calls %v", r.Response, w.hydra.calls)
				}
				return
			}
			s := r.Response.Logout
			if r.Response.Kind != LogoutPage || s == nil || s.State != LogoutConfirm || s.OtherSession != tc.other || s.Challenge != logoutU || s.CSRF != cookie {
				t.Fatalf("answer %+v, screen %+v", r.Response, s)
			}
			if r.Response.SetCSRF != cookie || r.Response.Remember != nil || w.store.puts != 0 || !slices.Equal(w.hydra.calls, []string{"get_logout"}) {
				t.Errorf("WRT-4: nothing written at the confirmation: %+v, calls %v", r.Response, w.hydra.calls)
			}
			if (s.Client != nil) != tc.rp {
				t.Errorf("HLO-7: client %+v, rp %v", s.Client, tc.rp)
			}
		})
	}
	// A browser without the cookie gets a new value.
	w := logoutWorld(t)
	w.demand(logoutU, false)
	if r := w.handle(Logout{Challenge: logoutU}); r.Response.SetCSRF != newCSRF && len(r.Response.SetCSRF) != 64 {
		t.Errorf("no new CSRF: %+v", r.Response)
	}
}

// LGO-11, LGO-12 to LGO-16: the answers of the form.
func TestLogoutForm(t *testing.T) {
	refuse := Logout{Challenge: logoutU, Post: true, Token: cookie, Cookie: cookie, SameOrigin: true}
	accept := refuse
	accept.Accept = true
	for _, tc := range []struct {
		name    string
		ev      Logout
		errs    map[string]error
		record  func(w *world) *LogoutRecord
		state   LogoutState
		next    bool
		code    Code
		calls   []string
		noCalls bool
	}{
		{name: "LGO-12 refused", ev: refuse, state: LogoutDeclined, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-13 the reject 404", ev: refuse, errs: map[string]error{"reject_logout": err404}, code: E1001, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-13 the reject 410", ev: refuse, errs: map[string]error{"reject_logout": err410}, code: E1002, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-13 the reject 401", ev: refuse, errs: map[string]error{"reject_logout": err401}, code: E1002, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-13 the reject 403", ev: refuse, errs: map[string]error{"reject_logout": err403}, code: E1007, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-13 the reject unavailable", ev: refuse, errs: map[string]error{"reject_logout": errDown}, code: E1004, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-14 a chain of this U: no reject, which would refuse its verifier", ev: refuse, record: func(w *world) *LogoutRecord { return w.chain(0) }, state: LogoutInProgress, next: true, calls: []string{"get_logout"}},
		{name: "LGO-14 a chain of another U: rejected", ev: refuse, record: func(w *world) *LogoutRecord {
			r := w.chain(0)
			r.U = logoutU2
			return r
		}, state: LogoutInProgress, next: true, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-14 the reject fails", ev: refuse, record: func(w *world) *LogoutRecord {
			r := w.chain(0)
			r.U = logoutU2
			return r
		}, errs: map[string]error{"reject_logout": errDown}, code: E1004, calls: []string{"get_logout", "reject_logout"}},
		{name: "LGO-15 refused already: a double click", ev: refuse, errs: map[string]error{"get_logout": err404}, state: LogoutDeclined, calls: []string{"get_logout"}},
		{name: "LGO-16 already out", ev: refuse, errs: map[string]error{"get_logout": err410}, state: LogoutAlreadyOut, calls: []string{"get_logout"}},
		{name: "LGO-13 the accept 404", ev: accept, errs: map[string]error{"accept_logout": err404}, code: E1001, calls: []string{"get_logout", "accept_logout"}},
		{name: "LGO-13 the accept 410", ev: accept, errs: map[string]error{"accept_logout": err410}, code: E1002, calls: []string{"get_logout", "accept_logout"}},
		{name: "LGO-13 the accept 401", ev: accept, errs: map[string]error{"accept_logout": err401}, code: E1002, calls: []string{"get_logout", "accept_logout"}},
		{name: "LGO-13 the accept 400", ev: accept, errs: map[string]error{"accept_logout": err400}, code: E1007, calls: []string{"get_logout", "accept_logout"}},
		{name: "LGO-13 the accept 409", ev: accept, errs: map[string]error{"accept_logout": err409}, code: E1007, calls: []string{"get_logout", "accept_logout"}},
		{name: "LGO-13 the accept unavailable", ev: accept, errs: map[string]error{"accept_logout": errDown}, code: E1004, calls: []string{"get_logout", "accept_logout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, false)
			for op, err := range tc.errs {
				w.hydra.errs[op] = err
			}
			if tc.record != nil {
				w.putRecord(tc.record(w))
			}
			before := w.record()
			r := w.handle(tc.ev)
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v, want %v", w.hydra.calls, tc.calls)
			}
			if tc.code != "" {
				if r.Response.Code != tc.code || r.Response.Kind != ErrorPage || r.Response.Link != "" {
					t.Errorf("answer %+v, want %s", r.Response, tc.code)
				}
			} else {
				s := r.Response.Logout
				if r.Response.Kind != LogoutPage || s == nil || s.State != tc.state {
					t.Fatalf("answer %+v, screen %+v", r.Response, s)
				}
				if want := ""; !tc.next && s.Next != want {
					t.Errorf("a link: %q", s.Next)
				}
				if tc.next && s.Next != "http://dispatcher.hydra.test/logout/next?ref="+logoutRef() {
					t.Errorf("the link %q", s.Next)
				}
			}
			if r.Response.Remember != nil {
				t.Errorf("cookies touched: %+v", r.Response.Remember)
			}
			if has(r, "challenge.invalid") {
				t.Errorf("challenge.invalid: nothing changed: %+v", r.Reports)
			}
			if got := w.record(); !sameRecord(got, before) {
				t.Errorf("the record changed: %+v", got)
			}
		})
	}
	// LGO-16: the store unreadable on the way of a refusal.
	w := logoutWorld(t)
	w.demand(logoutU, false)
	w.store.getErr = 1
	if r := w.handle(refuse); r.Response.Code != E1000 || !has(r, "state.error") {
		t.Errorf("store unreadable: %+v", r.Response)
	}
	// LGO-13: a 2xx without redirect_to.
	w = logoutWorld(t)
	w.demand(logoutU, false)
	w.hydra.noLogoutRedirect = true
	if r := w.handle(accept); r.Response.Code != E1004 || r.Response.Remember != nil || w.record() != nil {
		t.Errorf("no redirect_to: %+v", r.Response)
	}
	// LGO-13: saturated.
	w = logoutWorld(t)
	w.demand(logoutU, false)
	w.hydra.errs["accept_logout"] = hydra.ErrOverloaded
	if r := w.handle(accept); r.Response.Code != E1004 || !r.Response.Overloaded {
		t.Errorf("saturated: %+v", r.Response)
	}
}

func sameRecord(a, b *LogoutRecord) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// LST: the apps of the chain.
func TestLogoutApps(t *testing.T) {
	seen := func(sid, sub string, ap ...string) Memory {
		return Memory{Content: &Remembered{V: 1, SID: sid, Sub: sub, AP: ap, Exp: testNow.Add(time.Hour).Unix()}}
	}
	note := seen(logoutSID, "alice", "2fa", "sql")
	note.Content.Lo = true
	for _, tc := range []struct {
		name   string
		memory Memory
		mode   string
		apps   []store.App
		want   []string
		listed bool
	}{
		{name: "LST-1 those the session saw, in their order", memory: seen(logoutSID, "alice", "2fa", "sql"), want: []string{"2fa", "sql"}},
		{name: "LST-1 on a note, the record expired", memory: note, want: []string{"2fa", "sql"}},
		{name: "LST-1 an app gone from the snapshot, or without a logout_url", memory: seen(logoutSID, "alice", "gone", "oidc", "2fa", "sql"), want: []string{"2fa", "sql"},
			apps: []store.App{{ID: "2fa", LogoutURL: "http://2fa.hydra.test/logout?tenant=t"}, {ID: "sql", LogoutURL: "http://sql.hydra.test/logout"}, {ID: "oidc"}}},
		// The order of the snapshot, by id.
		{name: "LST-2 no cookie", want: []string{"2fa", "oidc", "sql"}, listed: true},
		{name: "LST-2 another session", memory: seen("other", "alice", "2fa"), want: []string{"2fa", "oidc", "sql"}, listed: true},
		{name: "LST-2 another subject", memory: seen(logoutSID, "bob", "2fa"), want: []string{"2fa", "oidc", "sql"}, listed: true},
		{name: "LST-2 no app seen, a cookie of before", memory: seen(logoutSID, "alice"), want: []string{"2fa", "oidc", "sql"}, listed: true},
		{name: "LST-2 unreadable", memory: Memory{Reason: SkipUnreadable}, want: []string{"2fa", "oidc", "sql"}, listed: true},
		{name: "LST-3 none", mode: "none"},
		{name: "LST-3 none does not touch a cookie's", memory: seen(logoutSID, "alice", "2fa"), mode: "none", want: []string{"2fa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			if tc.apps != nil {
				w.o.Config = snapshots{store.NewSnapshot(tc.apps, nil, store.DefaultSettings())}
			}
			w.o.PropagateWithoutRecord = tc.mode
			w.demand(logoutU, true)
			r := w.handle(Logout{Challenge: logoutU, Memory: tc.memory, Cookie: cookie, Post: true, Accept: true, Token: cookie, SameOrigin: true})
			rec := w.record()
			if tc.want == nil {
				// DEP-1: no record, the verifier at once.
				if rec != nil || r.Response.URL != verifierOf(logoutU) {
					t.Errorf("answer %+v, record %+v", r.Response, rec)
				}
				return
			}
			if rec == nil || !slices.Equal(rec.Apps, tc.want) || rec.Listed != tc.listed {
				t.Fatalf("record %+v, want apps %v, listed %v", rec, tc.want, tc.listed)
			}
			if rec.Cur != 0 || rec.Sent != 0 {
				t.Errorf("DEP-2: cur %d, sn %d", rec.Cur, rec.Sent)
			}
		})
	}
}

// WRT-4: the note that replaces the cookie at the start of the chain.
func TestLogoutNote(t *testing.T) {
	settings := store.DefaultSettings()
	now := testNow.Unix()
	rf := now + int64(settings.LoginRememberFor/time.Second)
	cookieOf := func(sid string, exp int64) Memory {
		return Memory{Content: &Remembered{
			V: 1, SID: sid, Sub: "bob", Flow: "hydra-sql", FH: "print", AP: []string{"2fa"}, ACR: "1", AMR: []string{"pwd"}, Exp: exp, IAT: now - 100,
			Ctx: Object{"a": json.RawMessage(`1`)}, Scp: []string{"openid"}, Aud: []string{"x"}, IDT: Object{"email": json.RawMessage(`"e"`)}, ACT: Object{"r": json.RawMessage(`1`)},
		}}
	}
	for _, tc := range []struct {
		name   string
		memory Memory
		ap     []string
		exp    int64
	}{
		{"its exp, a cookie of the session", cookieOf(logoutSID, now+500), []string{"2fa"}, now + 500},
		{"a cookie of the browser's session stays one", cookieOf(logoutSID, 0), []string{"2fa"}, 0},
		{"past its exp: login_remember_for", cookieOf(logoutSID, now-1), []string{"2fa"}, rf},
		{"another session: no ap, login_remember_for", cookieOf("other", now+500), nil, rf},
		{"no cookie", Memory{}, nil, rf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, true)
			r := w.handle(Logout{Challenge: logoutU, Memory: tc.memory, Cookie: cookie, Post: true, Accept: true, Token: cookie, SameOrigin: true})
			n := r.Response.Remember
			if n == nil {
				t.Fatalf("no note: %+v", r.Response)
			}
			if !n.Lo || n.V != RememberedFormat || n.SID != logoutSID || n.Sub != "alice" || n.IAT != now || n.Exp != tc.exp || !slices.Equal(n.AP, tc.ap) {
				t.Errorf("note %+v; want ap %v, exp %d", n, tc.ap, tc.exp)
			}
			data, _ := json.Marshal(n)
			for _, member := range []string{"idt", "act", "ctx", "scp", "aud", "flow", "fh", "acr", "amr"} {
				if strings.Contains(string(data), `"`+member+`"`) {
					t.Errorf("the note holds %s: %s", member, data)
				}
			}
		})
	}
	// login_remember_for 0: a cookie of the browser's session.
	w := logoutWorld(t)
	apps := w.o.Config.Snapshot().Apps
	s := store.DefaultSettings()
	s.LoginRememberFor = 0
	w.o.Config = snapshots{store.NewSnapshot(apps, testFlows(), s)}
	w.demand(logoutU, true)
	if n := w.handle(Logout{Challenge: logoutU}).Response.Remember; n == nil || n.Exp != 0 {
		t.Errorf("note %+v", n)
	}
}

// DEP-1 to DEP-4, DEP-7: the start of the chain.
func TestLogoutStart(t *testing.T) {
	t.Run("DEP-1 no app: no record, the verifier", func(t *testing.T) {
		w := logoutWorld(t, func(apps []store.App) {
			for i := range apps {
				apps[i].LogoutURL = ""
			}
		})
		w.demand(logoutU, true)
		r := w.handle(Logout{Challenge: logoutU})
		if r.Response.URL != verifierOf(logoutU) || r.Response.Remember == nil || w.store.puts != 0 || w.store.gets != 0 {
			t.Errorf("answer %+v, puts %d, gets %d", r.Response, w.store.puts, w.store.gets)
		}
		if !has(r, "logout.started", func(x Report) bool { return x.Audit && x.Apps == 0 && !x.Again && x.RP != nil && *x.RP }) || !has(r, "logout.verifier_sent") {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("DEP-2 the record, what it keeps of the request", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, true)
		r := w.handle(Logout{Challenge: logoutU, Memory: Memory{Content: &Remembered{V: 1, SID: logoutSID, Sub: "alice", AP: []string{"sql", "2fa"}}}})
		ref := logoutRef()
		if r.Response.URL != appURL("sql", ref, 0) || r.Response.Remember == nil {
			t.Errorf("answer %+v", r.Response)
		}
		rec := w.record()
		if rec.U != logoutU || rec.RT != verifierOf(logoutU) || rec.Subject != "alice" || rec.SID != logoutSID || !rec.RP || rec.Listed {
			t.Errorf("record %+v", rec)
		}
		if rec.URL != "/oauth2/sessions/logout?post_logout_redirect_uri=http%3A%2F%2Fc%2Fpost" {
			t.Errorf("Q48: request_url kept %q", rec.URL)
		}
		data, _ := rec.encode()
		for _, secret := range []string{"the.id.token", "metadata", "redirect_uris", "tenant"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("Q48, Q51: the record holds %q: %s", secret, data)
			}
		}
		want := LogoutClient{ID: "c1", Name: "Test Client", LogoURI: "http://c/logo", ClientURI: "http://c/", PolicyURI: "http://c/policy", TosURI: "http://c/tos"}
		if rec.Client == nil || *rec.Client != want {
			t.Errorf("Q51: client %+v", rec.Client)
		}
		if rec.Cur != 0 || rec.Sent != 0 || rec.SentAt != testNow.UnixMilli() {
			t.Errorf("cur %d, sn %d, st %d", rec.Cur, rec.Sent, rec.SentAt)
		}
		if got := w.store.ttls; len(got) != 1 || got[0] != time.Hour {
			t.Errorf("TTL %v, want an hour (Q46)", got)
		}
		if !has(r, "logout.started", func(x Report) bool { return x.Apps == 2 && !x.Again }) {
			t.Errorf("reports %+v", r.Reports)
		}
		if has(r, "logout.verifier_sent") {
			t.Errorf("the verifier is not sent yet: %+v", r.Reports)
		}
	})
	t.Run("DEP-2 TTL up to expires_at - 60 s", func(t *testing.T) {
		w := logoutWorld(t)
		at := testNow.Add(10 * time.Minute)
		w.demand(logoutU, true, func(r *ory.OAuth2LogoutRequest) { r.ExpiresAt, r.RequestedAt = &at, &testNow })
		w.handle(Logout{Challenge: logoutU})
		if got := w.store.ttls; len(got) != 1 || got[0] != 9*time.Minute {
			t.Errorf("TTL %v, want 9 min (Q52)", got)
		}
		if rec := w.record(); rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(at) || rec.RequestedAt == nil {
			t.Errorf("record %+v", rec)
		}
	})
	t.Run("DEP-3 double submission: no write, the same step", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(1))
		w.demand(logoutU, false)
		r := w.handle(Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		if r.Response.URL != appURL("2fa", logoutRef(), 1) || r.Response.Remember == nil || w.store.puts != 0 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
		if has(r, "logout.started") {
			t.Errorf("Q58, not a new demand: %+v", r.Reports)
		}
	})
	t.Run("DEP-3 the next app not seen yet: SUI-3 writes, in the note's answer", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(1)
		rec.Sent = 0
		w.putRecord(rec)
		w.demand(logoutU, false)
		r := w.handle(Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		got := w.record()
		if r.Response.URL != appURL("2fa", logoutRef(), 1) || r.Response.Remember == nil || got.Sent != 1 || got.SentAt != testNow.UnixMilli() {
			t.Errorf("answer %+v, record %+v", r.Response, got)
		}
	})
	t.Run("DEP-3 the chain over: the verifier", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(3))
		w.demand(logoutU, false)
		r := w.handle(Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		if r.Response.URL != verifierOf(logoutU) || !has(r, "logout.verifier_sent") {
			t.Errorf("answer %+v, reports %+v", r.Response, r.Reports)
		}
	})
	for _, tc := range []struct {
		name string
		// at sets the state: cur, sn, and how long ago st.
		cur, sn int
		ago     time.Duration
		want    int
		passed  string
		verif   bool
	}{
		{"DEP-4 passes the app the browser was sent to 15 s ago", 1, 1, 15 * time.Second, 2, "2fa", false},
		{"DEP-4 st under 15 s: a double click, no skip", 1, 1, 14 * time.Second, 1, "", false},
		{"DEP-4 sn differs: the next app not seen yet, no skip", 1, 0, time.Hour, 1, "", false},
		{"DEP-4 the chain over: cur stays, the new verifier", 3, 2, time.Hour, 3, "", true},
		{"DEP-4 the last app passed: the new verifier", 2, 2, time.Hour, 3, "oidc", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			rec := w.chain(tc.cur)
			rec.Sent, rec.SentAt = tc.sn, testNow.Add(-tc.ago).UnixMilli()
			w.putRecord(rec)
			w.demand(logoutU2, true)
			r := w.handle(Logout{Challenge: logoutU2})
			got := w.record()
			if got.Cur != tc.want || got.U != logoutU2 || got.RT != verifierOf(logoutU2) || !got.RP || got.Client == nil || !slices.Equal(got.Apps, rec.Apps) {
				t.Errorf("record %+v, want cur %d", got, tc.want)
			}
			if !has(r, "logout.started", func(x Report) bool { return x.Again && x.Apps == 3 }) {
				t.Errorf("Q58: %+v", r.Reports)
			}
			passed := has(r, "logout.propagated", func(x Report) bool { return x.Result == "skipped" })
			if passed != (tc.passed != "") || tc.passed != "" && !has(r, "logout.propagated", wasPassed(tc.passed)) {
				t.Errorf("passed %q: %+v", tc.passed, r.Reports)
			}
			if tc.verif {
				if r.Response.URL != verifierOf(logoutU2) || !has(r, "logout.verifier_sent") {
					t.Errorf("answer %+v", r.Response)
				}
				return
			}
			if r.Response.URL != appURL(rec.Apps[tc.want], logoutRef(), tc.want) || got.Sent != tc.want {
				t.Errorf("answer %+v, record %+v", r.Response, got)
			}
			// st only moves with sn: repeated demands do not push the 15 s back.
			if moved := got.SentAt == testNow.UnixMilli(); moved != (tc.sn != tc.want) {
				t.Errorf("st %d, sn %d then %d", got.SentAt, tc.sn, got.Sent)
			}
		})
	}
	t.Run("DEP-4 the apps of the record, whatever LST says now", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		rec.Apps = []string{"2fa"}
		rec.SentAt = testNow.UnixMilli()
		w.putRecord(rec)
		w.demand(logoutU2, false)
		w.handle(Logout{Challenge: logoutU2, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		if got := w.record(); !slices.Equal(got.Apps, []string{"2fa"}) {
			t.Errorf("apps %v", got.Apps)
		}
	})
	t.Run("DEP-7 ea - 60 s reached between the read and the write", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			record bool
		}{{"absent", false}, {"present", true}} {
			w := logoutWorld(t)
			at := testNow.Add(10 * time.Minute)
			w.demand(logoutU2, true, func(r *ory.OAuth2LogoutRequest) { r.ExpiresAt = &at })
			if tc.record {
				w.putRecord(w.chain(0))
			}
			puts := w.store.puts
			w.hydra.before["accept_logout"] = func() { w.now = testNow.Add(9 * time.Minute) }
			r := w.handle(Logout{Challenge: logoutU2})
			if r.Response.Code != E1002 || r.Response.Link != "" || r.Response.Remember == nil || w.store.puts != puts {
				t.Errorf("%s: answer %+v, puts %d", tc.name, r.Response, w.store.puts)
			}
			if tc.record && w.record().U != logoutU {
				t.Errorf("%s: written: %+v", tc.name, w.record())
			}
			if !tc.record && w.record() != nil {
				t.Errorf("%s: written: %+v", tc.name, w.record())
			}
		}
	})
}

// DEP-5, DEP-6: the store at the start of the chain.
func TestLogoutStartStore(t *testing.T) {
	ioErr := errors.New("redis: i/o timeout")
	key := LogoutKey(logoutRef())
	t.Run("DEP-5 two Put(0) on the same U: DEP-3", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, true)
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				rec := w.chain(0)
				rec.SentAt = w.now.UnixMilli()
				data, _ := rec.encode()
				_ = w.store.StateStore.Put(context.Background(), key, data, time.Hour, 0)
			}
			return nil, false
		}
		r := w.handle(Logout{Challenge: logoutU})
		rec := w.record()
		if r.Response.URL != appURL("sql", logoutRef(), 0) || rec.Cur != 0 || r.Response.Remember == nil {
			t.Errorf("answer %+v, record %+v", r.Response, rec)
		}
	})
	t.Run("DEP-5 two Put(0) on two U: DEP-4, no skip", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU2, true)
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				rec := w.chain(0)
				rec.SentAt = w.now.UnixMilli()
				data, _ := rec.encode()
				_ = w.store.StateStore.Put(context.Background(), key, data, time.Hour, 0)
			}
			return nil, false
		}
		r := w.handle(Logout{Challenge: logoutU2})
		rec := w.record()
		if r.Response.URL != appURL("sql", logoutRef(), 0) || rec.Cur != 0 || rec.U != logoutU2 {
			t.Errorf("answer %+v, record %+v", r.Response, rec)
		}
		if has(r, "logout.propagated") {
			t.Errorf("a skip: %+v", r.Reports)
		}
	})
	dep6 := func(t *testing.T, w *world, r Result, rt string, apps int) {
		t.Helper()
		if r.Response.URL != rt || r.Response.Kind != Redirect || r.Response.Remember == nil {
			t.Errorf("answer %+v, want the verifier and the note", r.Response)
		}
		if !has(r, "state.error", func(x Report) bool { return x.Sentry }) || !has(r, "logout.verifier_sent") || !has(r, "logout.started") {
			t.Errorf("reports %+v", r.Reports)
		}
		n := 0
		for _, x := range r.Reports {
			if x.Event == "logout.propagated" && x.Result == "error" {
				n++
			}
		}
		if n != apps {
			t.Errorf("%d apps with an error, want %d: %+v", n, apps, r.Reports)
		}
	}
	for _, tc := range []struct {
		name    string
		prepare func(w *world)
		written bool
	}{
		{"DEP-6 the read fails", func(w *world) { w.store.getErr = 1 }, false},
		{"DEP-6 the store closed at the write", func(w *world) {
			w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		}, false},
		{"DEP-6 of unknown outcome twice", func(w *world) {
			w.store.hook = func(int, string, []byte, uint64) (error, bool) { return ioErr, true }
		}, false},
		{"DEP-6 of unknown outcome, then a conflict when written again", func(w *world) {
			w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
				if n == 1 {
					return ioErr, true
				}
				return state.ErrConflict, true
			}
		}, false},
		{"DEP-6 of unknown outcome, then unreadable", func(w *world) {
			w.store.hook = func(int, string, []byte, uint64) (error, bool) { w.store.getErr = w.store.gets + 1; return ioErr, true }
		}, false},
		{"DEP-6 a second conflict", func(w *world) {
			w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrConflict, true }
		}, false},
		{"ECR-5 of unknown outcome, written all the same", func(w *world) {
			w.store.hook = func(n int, k string, v []byte, _ uint64) (error, bool) {
				if n == 1 {
					_ = w.store.StateStore.Put(context.Background(), k, v, time.Hour, 0)
					return ioErr, true
				}
				return nil, false
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, true)
			tc.prepare(w)
			r := w.handle(Logout{Challenge: logoutU})
			if tc.written {
				if r.Response.URL != appURL("2fa", logoutRef(), 0) || w.record() == nil {
					t.Errorf("answer %+v", r.Response)
				}
				return
			}
			dep6(t, w, r, verifierOf(logoutU), 3)
			w.store.getErr = 0
			if w.record() != nil {
				t.Errorf("written: %+v", w.record())
			}
		})
	}
	t.Run("DEP-6 on DEP-4: the record's apps", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		rec.Apps = []string{"sql"}
		w.putRecord(rec)
		w.demand(logoutU2, true)
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		r := w.handle(Logout{Challenge: logoutU2})
		dep6(t, w, r, verifierOf(logoutU2), 1)
	})
	t.Run("DEP-6 on DEP-3 and SUI-4", func(t *testing.T) {
		w := logoutWorld(t, func(apps []store.App) { apps[0].LogoutURL = "" })
		w.putRecord(w.chain(0))
		w.demand(logoutU, false)
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		r := w.handle(Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		if r.Response.URL != verifierOf(logoutU) || r.Response.Remember == nil {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("SUI-3 on DEP-3: its answer stands, with the note", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(1)
		rec.Sent = 0
		w.putRecord(rec)
		w.demand(logoutU, false)
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		r := w.handle(Logout{Challenge: logoutU, Post: true, Accept: true, Token: cookie, Cookie: cookie, SameOrigin: true})
		if r.Response.URL != appURL("2fa", logoutRef(), 1) || r.Response.Remember == nil {
			t.Errorf("answer %+v", r.Response)
		}
	})
}

// SUI: GET /logout/next.
func TestLogoutNextPage(t *testing.T) {
	ioErr := errors.New("redis: i/o timeout")
	ev := LogoutNext{Ref: logoutRef()}
	for _, ref := range []string{"", "xyz", strings.Repeat("A", 20), strings.Repeat("0", 21)} {
		w := logoutWorld(t)
		if r := w.handle(LogoutNext{Ref: ref}); r.Response.Code != E1001 || w.store.gets != 0 {
			t.Errorf("SUI-1 %q: %+v", ref, r.Response)
		}
	}
	t.Run("SUI-2 absent", func(t *testing.T) {
		w := logoutWorld(t)
		if r := w.handle(ev); r.Response.Code != E1002 || r.Response.Link != "" {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("SUI-3 the first time: written, by withQuery", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(1)
		rec.Sent = 0
		w.putRecord(rec)
		r := w.handle(ev)
		got := w.record()
		if r.Response.URL != appURL("2fa", logoutRef(), 1) || got.Sent != 1 || got.SentAt != testNow.UnixMilli() {
			t.Errorf("answer %+v, record %+v", r.Response, got)
		}
		if !strings.Contains(r.Response.URL, "tenant=t") {
			t.Errorf("the logout_url's query is lost: %s", r.Response.URL)
		}
		// A reload: the same step, no write.
		w.store.puts = 0
		if again := w.handle(ev); again.Response.URL != r.Response.URL || w.store.puts != 0 {
			t.Errorf("reload %+v, puts %d", again.Response, w.store.puts)
		}
	})
	t.Run("SUI-3 the write fails: the answer stands", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			hook func(n int, key string, val []byte, v uint64) (error, bool)
		}{
			{"closed", func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }},
			{"unknown outcome", func(int, string, []byte, uint64) (error, bool) { return ioErr, true }},
			{"second conflict", func(int, string, []byte, uint64) (error, bool) { return state.ErrConflict, true }},
		} {
			w := logoutWorld(t)
			rec := w.chain(1)
			rec.Sent = 0
			w.putRecord(rec)
			w.store.hook = tc.hook
			r := w.handle(ev)
			if r.Response.URL != appURL("2fa", logoutRef(), 1) || !has(r, "state.error") {
				t.Errorf("%s: answer %+v, reports %+v", tc.name, r.Response, r.Reports)
			}
		}
	})
	t.Run("SUI-3 TTL gone: no write", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(1)
		rec.Sent = 0
		at := testNow.Add(30 * time.Second)
		rec.ExpiresAt = &at
		w.putRecord(rec)
		r := w.handle(ev)
		if r.Response.URL != appURL("2fa", logoutRef(), 1) || w.store.puts != 0 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("SUI-4 an app gone: passed, then SUI-3 on the state written", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		rec.Apps = []string{"gone", "sql"}
		w.putRecord(rec)
		r := w.handle(ev)
		got := w.record()
		if r.Response.URL != appURL("sql", logoutRef(), 1) || got.Cur != 1 || got.Sent != 1 || w.store.puts != 1 {
			t.Errorf("answer %+v, record %+v, puts %d", r.Response, got, w.store.puts)
		}
		if !has(r, "logout.propagated", wasPassed("gone")) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("SUI-4 without a logout_url since the start", func(t *testing.T) {
		w := logoutWorld(t, func(apps []store.App) { apps[2].LogoutURL = "" })
		w.putRecord(w.chain(2))
		r := w.handle(ev)
		if r.Response.URL != verifierOf(logoutU) || w.record().Cur != 3 || !has(r, "logout.propagated", wasPassed("oidc")) || !has(r, "logout.verifier_sent") {
			t.Errorf("answer %+v, reports %+v", r.Response, r.Reports)
		}
	})
	t.Run("SUI-4 the write fails: E1000", func(t *testing.T) {
		w := logoutWorld(t, func(apps []store.App) { apps[2].LogoutURL = "" })
		w.putRecord(w.chain(2))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		if r := w.handle(ev); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("SUI-4 TTL gone: SUI-2", func(t *testing.T) {
		w := logoutWorld(t, func(apps []store.App) { apps[0].LogoutURL = "" })
		rec := w.chain(0)
		at := testNow.Add(30 * time.Second)
		rec.ExpiresAt = &at
		w.putRecord(rec)
		if r := w.handle(ev); r.Response.Code != E1002 || w.store.puts != 0 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("SUI-5 over: the verifier, the record living on", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(3)
		rec.RP = true
		w.putRecord(rec)
		r := w.handle(ev)
		if r.Response.URL != verifierOf(logoutU) || w.store.puts != 0 || w.record() == nil {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
		if !has(r, "logout.verifier_sent", func(x Report) bool { return x.RP != nil && *x.RP }) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("SUI-6 unreadable", func(t *testing.T) {
		w := logoutWorld(t)
		w.store.getErr = 1
		if r := w.handle(ev); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("SUI-6 a record of another version", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		rec.V = 99
		w.putRecord(rec)
		if r := w.handle(ev); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
}

func callerOf(app string) func(store.App) bool {
	return func(a store.App) bool { return a.ID == app }
}

func (w *world) appCall(op AppOp, challenge, app string) Result {
	w.t.Helper()
	return w.handle(AppCall{Op: op, Challenge: challenge, Caller: callerOf(app), Body: json.RawMessage(`null`)})
}

func redirectedTo(t *testing.T, r Result, status int, want string) {
	t.Helper()
	body, ok := r.Response.Body.(ory.OAuth2RedirectTo)
	if r.Response.Kind != AppJSON || r.Response.Status != status || !ok || body.RedirectTo != want {
		t.Errorf("answer %+v, want %d and %s", r.Response, status, want)
	}
}

// LEM: the emulated API.
func TestLogoutEmulated(t *testing.T) {
	ref := logoutRef()
	next := "http://dispatcher.hydra.test/logout/next?ref=" + ref
	ch := func(i int, app string) string { return testKeys.LogoutChallenge(ref, i, app) }
	for _, c := range []string{"", "abc", strings.Repeat("a", 32), "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", strings.Repeat("a", 36), "aaaaaaaa_aaaa-aaaa-aaaa-aaaaaaaaaaaa"} {
		w := logoutWorld(t)
		r := w.appCall(AppGetLogout, c, "sql")
		e, ok := r.Response.Body.(AppError)
		if r.Response.Status != http.StatusNotFound || !ok || e.Error != "invalid_request" || w.store.gets != 0 {
			t.Errorf("LEM-1 %q: %+v", c, r.Response)
		}
	}
	missing := func(t *testing.T, r Result) {
		t.Helper()
		e, ok := r.Response.Body.(AppError)
		if r.Response.Status != http.StatusNotFound || !ok || e.Error != missingSession {
			t.Errorf("answer %+v, want 404 %s", r.Response, missingSession)
		}
	}
	t.Run("LEM-2 absent", func(t *testing.T) {
		w := logoutWorld(t)
		for _, op := range []AppOp{AppGetLogout, AppAcceptLogout, AppRejectLogout} {
			missing(t, w.appCall(op, ch(0, "sql"), "sql"))
		}
	})
	t.Run("LEM-3 no signature, or a future position's", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		for _, c := range []string{
			ref[:8] + "-" + ref[8:12] + "-" + ref[12:16] + "-" + ref[16:20] + "-000000000000", // no signature
			ch(1, "2fa"), // the next position's
			ch(1, "sql"), // the signature of another position, for this app
		} {
			r := w.appCall(AppGetLogout, c, "sql")
			missing(t, r)
			if !has(r, "challenge.invalid", func(x Report) bool { return x.Detail == "forged" }) {
				t.Errorf("%q: not reported: %+v", c, r.Reports)
			}
		}
		// A step challenge's signature does not stand for a logout's (kind).
		c := ref + signature(testKey, ref, 0, "sql", KindLogin)
		missing(t, w.appCall(AppGetLogout, c[:8]+"-"+c[8:12]+"-"+c[12:16]+"-"+c[16:20]+"-"+c[20:], "sql"))
	})
	t.Run("LEM-4 another app, or one gone", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		for _, tc := range []struct {
			op    AppOp
			c     string
			agent string
		}{{AppGetLogout, ch(0, "sql"), "2fa"}, {AppAcceptLogout, ch(0, "sql"), "2fa"}, {AppRejectLogout, ch(0, "sql"), "oidc"}} {
			r := w.appCall(tc.op, tc.c, tc.agent)
			e, ok := r.Response.Body.(AppError)
			if r.Response.Status != http.StatusForbidden || !ok || e.Error != forbidden || !has(r, "security.ip_rejected") {
				t.Errorf("%+v: %+v", tc, r.Response)
			}
		}
		if got := w.record(); got.Cur != 0 {
			t.Errorf("cur %d", got.Cur)
		}
		rec := w.chain(0)
		rec.Apps = []string{"gone", "sql"}
		w = logoutWorld(t)
		w.putRecord(rec)
		if r := w.appCall(AppAcceptLogout, ch(0, "gone"), "gone"); r.Response.Status != http.StatusForbidden {
			t.Errorf("gone: %+v", r.Response)
		}
		r := w.handle(AppCall{Op: AppGetLogout, Challenge: ch(0, "gone")})
		if r.Response.Status != http.StatusForbidden {
			t.Errorf("no caller: %+v", r.Response)
		}
	})
	t.Run("LEM-5 the request served", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		w.putRecord(rec)
		r := w.appCall(AppGetLogout, ch(0, "sql"), "sql")
		data, _ := json.Marshal(r.Response.Body)
		want := `{"challenge":"` + ch(0, "sql") + `","subject":"alice","sid":"` + logoutSID + `","request_url":"/oauth2/sessions/logout","rp_initiated":false,"client":null}`
		if r.Response.Status != http.StatusOK || string(data) != want {
			t.Errorf("served %d %s\nwant %s", r.Response.Status, data, want)
		}
		if strings.Contains(string(data), logoutU) || strings.Contains(string(data), "verifier") {
			t.Errorf("I7: %s", data)
		}
		if w.store.puts != 0 || len(w.hydra.calls) != 0 {
			t.Errorf("no line writes or calls: %d, %v", w.store.puts, w.hydra.calls)
		}
	})
	t.Run("LEM-5 a client's, its dates", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		at, ask := testNow.Add(10*time.Minute).UTC(), testNow.UTC()
		rec.RP, rec.Client, rec.ExpiresAt, rec.RequestedAt = true, &LogoutClient{ID: "c1", Name: "C"}, &at, &ask
		w.putRecord(rec)
		data, _ := json.Marshal(w.appCall(AppGetLogout, ch(0, "sql"), "sql").Response.Body)
		for _, part := range []string{`"rp_initiated":true`, `"client":{"client_id":"c1","client_name":"C"}`, `"expires_at":"`, `"requested_at":"`} {
			if !strings.Contains(string(data), part) {
				t.Errorf("no %s in %s", part, data)
			}
		}
	})
	t.Run("LEM-5 LST-2: subject and sid hidden from an app with a list", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(1)
		rec.Listed = true
		w.putRecord(rec)
		data, _ := json.Marshal(w.appCall(AppGetLogout, ch(1, "2fa"), "2fa").Response.Body)
		if !strings.Contains(string(data), `"subject":""`) || !strings.Contains(string(data), `"sid":""`) {
			t.Errorf("2fa has a list: %s", data)
		}
		w = logoutWorld(t)
		rec = w.chain(0)
		rec.Listed = true
		w.putRecord(rec)
		data, _ = json.Marshal(w.appCall(AppGetLogout, ch(0, "sql"), "sql").Response.Body)
		if !strings.Contains(string(data), `"subject":"alice"`) {
			t.Errorf("sql has no list: %s", data)
		}
		// LST-1: the app saw the session; its list changes nothing.
		w = logoutWorld(t)
		w.putRecord(w.chain(1))
		data, _ = json.Marshal(w.appCall(AppGetLogout, ch(1, "2fa"), "2fa").Response.Body)
		if !strings.Contains(string(data), `"subject":"alice"`) {
			t.Errorf("LST-1: %s", data)
		}
	})
	t.Run("LEM-6 a position past", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(1))
		redirectedTo(t, w.appCall(AppGetLogout, ch(0, "sql"), "sql"), http.StatusGone, next)
	})
	for _, tc := range []struct {
		name   string
		op     AppOp
		result string
	}{
		{"LEM-7 accept", AppAcceptLogout, "accepted"},
		{"LEM-9 reject: 200 and redirect_to (Q49)", AppRejectLogout, "rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			rec := w.chain(0)
			w.putRecord(rec)
			r := w.appCall(tc.op, ch(0, "sql"), "sql")
			redirectedTo(t, r, http.StatusOK, next)
			got := w.record()
			if got.Cur != 1 || got.Sent != 0 {
				t.Errorf("cur %d, sn %d: sn says where the browser went", got.Cur, got.Sent)
			}
			if !has(r, "logout.propagated", func(x Report) bool { return x.App == "sql" && x.Result == tc.result }) {
				t.Errorf("reports %+v", r.Reports)
			}
			// LEM-8, LEM-10: the first call stands.
			w.store.puts = 0
			again := w.appCall(tc.op, ch(0, "sql"), "sql")
			redirectedTo(t, again, http.StatusOK, next)
			if w.store.puts != 0 || w.record().Cur != 1 || has(again, "logout.propagated") {
				t.Errorf("a second call counted: %+v", again.Reports)
			}
		})
	}
	t.Run("the body of a PUT is not read", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		r := w.handle(AppCall{Op: AppAcceptLogout, Challenge: ch(0, "sql"), Caller: callerOf("sql"), Body: json.RawMessage(`not json`)})
		redirectedTo(t, r, http.StatusOK, next)
	})
	t.Run("a former key still verifies a chain in progress", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		c := Keys{oldKey}.LogoutChallenge(ref, 0, "sql")
		redirectedTo(t, w.appCall(AppAcceptLogout, c, "sql"), http.StatusOK, next)
	})
	t.Run("LEM-11 two accepts at once: ECR-3, LEM-8", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				w.putRecord(func() *LogoutRecord { r := w.chain(1); r.Sent = 0; return r }())
			}
			return nil, false
		}
		r := w.appCall(AppAcceptLogout, ch(0, "sql"), "sql")
		redirectedTo(t, r, http.StatusOK, next)
		if got := w.record(); got.Cur != 1 {
			t.Errorf("cur %d", got.Cur)
		}
		if has(r, "logout.propagated") {
			t.Errorf("counted twice: %+v", r.Reports)
		}
	})
	t.Run("LEM-11 a second conflict: ECR-2", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrConflict, true }
		r := w.appCall(AppAcceptLogout, ch(0, "sql"), "sql")
		e, ok := r.Response.Body.(AppError)
		if r.Response.Status != http.StatusInternalServerError || !ok || e.Description != string(E1007) || !has(r, "state.conflict") {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("LEM-11 the store fails: E1000, the chain stops at this app", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		r := w.appCall(AppRejectLogout, ch(0, "sql"), "sql")
		e, ok := r.Response.Body.(AppError)
		if r.Response.Status != http.StatusInternalServerError || !ok || e.Description != string(E1000) || !has(r, "state.error") {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("LEM-11 the store unreadable", func(t *testing.T) {
		w := logoutWorld(t)
		w.store.getErr = 1
		r := w.appCall(AppGetLogout, ch(0, "sql"), "sql")
		e, ok := r.Response.Body.(AppError)
		if r.Response.Status != http.StatusInternalServerError || !ok || e.Description != string(E1000) {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("LEM-11 TTL gone", func(t *testing.T) {
		w := logoutWorld(t)
		rec := w.chain(0)
		at := testNow.Add(30 * time.Second)
		rec.ExpiresAt = &at
		w.putRecord(rec)
		missing(t, w.appCall(AppAcceptLogout, ch(0, "sql"), "sql"))
		if w.store.puts != 0 {
			t.Errorf("puts %d", w.store.puts)
		}
	})
	t.Run("LEM-11 ECR-5, written all the same", func(t *testing.T) {
		w := logoutWorld(t)
		w.putRecord(w.chain(0))
		key := LogoutKey(ref)
		w.store.hook = func(n int, _ string, v []byte, _ uint64) (error, bool) {
			if n == 1 {
				_, at, _ := w.store.StateStore.Get(context.Background(), key)
				_ = w.store.StateStore.Put(context.Background(), key, v, time.Hour, at)
				return errors.New("redis: i/o timeout"), true
			}
			return nil, false
		}
		redirectedTo(t, w.appCall(AppAcceptLogout, ch(0, "sql"), "sql"), http.StatusOK, next)
	})
}

// A whole chain, over the two kinds of apps: B3, the calls of the decompte.
func TestLogoutChain(t *testing.T) {
	ref := logoutRef()
	for _, tc := range []struct {
		name string
		// rp is a client's demand, confirmed without a page.
		rp    bool
		calls []string
	}{
		{"B3, without id_token_hint, confirmed", false, []string{"get_logout", "get_logout", "accept_logout"}},
		{"B3, with id_token_hint", true, []string{"get_logout", "accept_logout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := logoutWorld(t)
			w.demand(logoutU, tc.rp)
			memory := Memory{Content: &Remembered{V: 1, SID: logoutSID, Sub: "alice", AP: []string{"sql", "2fa"}}}
			r := w.handle(Logout{Challenge: logoutU, Memory: memory, Cookie: cookie})
			if !tc.rp {
				if r.Response.Kind != LogoutPage {
					t.Fatalf("no confirmation: %+v", r.Response)
				}
				r = w.handle(Logout{Challenge: logoutU, Memory: memory, Cookie: cookie, Post: true, Accept: true, Token: cookie, SameOrigin: true})
			}
			if r.Response.URL != appURL("sql", ref, 0) {
				t.Fatalf("to the first app: %+v", r.Response)
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v, want %v", w.hydra.calls, tc.calls)
			}
			next := w.appCall(AppAcceptLogout, testKeys.LogoutChallenge(ref, 0, "sql"), "sql")
			redirectedTo(t, next, http.StatusOK, NextURL(w.o.BaseURL, ref))
			r = w.handle(LogoutNext{Ref: ref})
			if r.Response.URL != appURL("2fa", ref, 1) {
				t.Fatalf("to the second app: %+v", r.Response)
			}
			w.appCall(AppAcceptLogout, testKeys.LogoutChallenge(ref, 1, "2fa"), "2fa")
			r = w.handle(LogoutNext{Ref: ref})
			if r.Response.URL != verifierOf(logoutU) || !has(r, "logout.verifier_sent") {
				t.Errorf("to the verifier: %+v", r.Response)
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("the chain called Hydra: %v", w.hydra.calls)
			}
		})
	}
	t.Run("B3, refused", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, false)
		w.handle(Logout{Challenge: logoutU, Cookie: cookie})
		before := w.store.gets
		r := w.handle(Logout{Challenge: logoutU, Cookie: cookie, Post: true, Token: cookie, SameOrigin: true})
		if r.Response.Logout == nil || r.Response.Logout.State != LogoutDeclined {
			t.Fatalf("answer %+v", r.Response)
		}
		if want := []string{"get_logout", "get_logout", "reject_logout"}; !slices.Equal(w.hydra.calls, want) {
			t.Errorf("calls %v, want %v", w.hydra.calls, want)
		}
		if w.store.gets-before != 1 || w.store.puts != 0 {
			t.Errorf("gets %d, puts %d", w.store.gets-before, w.store.puts)
		}
	})
	t.Run("a new demand passes the app that blocks, up to the verifier", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, false)
		memory := Memory{Content: &Remembered{V: 1, SID: logoutSID, Sub: "alice", AP: []string{"sql", "2fa"}}}
		confirmed := func(u string) Result {
			return w.handle(Logout{Challenge: u, Memory: memory, Cookie: cookie, Post: true, Accept: true, Token: cookie, SameOrigin: true})
		}
		if r := confirmed(logoutU); r.Response.URL != appURL("sql", ref, 0) {
			t.Fatalf("first: %+v", r.Response)
		}
		// sql never answers. A second demand, 10 s later, does not pass it.
		w.now = w.now.Add(10 * time.Second)
		w.demand(logoutU2, false)
		if r := confirmed(logoutU2); r.Response.URL != appURL("sql", ref, 0) {
			t.Fatalf("DEP-4 under 15 s: %+v", r.Response)
		}
		// 20 s later it does, and st is new for the next one.
		w.now = w.now.Add(10 * time.Second)
		const logoutU3 = "aaaa2e7a-54a1-4f7e-8d3e-6b1f0c9e7a11"
		w.demand(logoutU3, false)
		r := confirmed(logoutU3)
		if r.Response.URL != appURL("2fa", ref, 1) || !has(r, "logout.propagated", wasPassed("sql")) {
			t.Fatalf("DEP-4 past 15 s: %+v", r.Response)
		}
		// A quick double click does not pass the next one.
		const logoutU4 = "bbbb2e7a-54a1-4f7e-8d3e-6b1f0c9e7a11"
		w.demand(logoutU4, false)
		if r := confirmed(logoutU4); r.Response.URL != appURL("2fa", ref, 1) {
			t.Fatalf("a double click: %+v", r.Response)
		}
		// Nor the next app, never seen, once the former answered.
		w.now = w.now.Add(time.Minute)
		w.appCall(AppAcceptLogout, testKeys.LogoutChallenge(ref, 1, "2fa"), "2fa")
		const logoutU5 = "cccc2e7a-54a1-4f7e-8d3e-6b1f0c9e7a11"
		w.demand(logoutU5, false)
		if r := confirmed(logoutU5); r.Response.URL != verifierOf(logoutU5) {
			t.Fatalf("the end, the last verifier: %+v", r.Response)
		}
	})
}

// LGO-15, the double click on each button: the second gets the same answer, no
// second reject (Q50); on Accept, DEP-3.
func TestLogoutDoubleClick(t *testing.T) {
	t.Run("refuse", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, false)
		ev := Logout{Challenge: logoutU, Cookie: cookie, Post: true, Token: cookie, SameOrigin: true}
		if r := w.handle(ev); r.Response.Logout == nil || r.Response.Logout.State != LogoutDeclined {
			t.Fatalf("first: %+v", r.Response)
		}
		delete(w.hydra.logouts, logoutU) // Hydra: a reject makes it 404 (HLO-5)
		r := w.handle(ev)
		if r.Response.Logout == nil || r.Response.Logout.State != LogoutDeclined || has(r, "challenge.invalid") {
			t.Fatalf("second: %+v", r.Response)
		}
		if n := strings.Count(strings.Join(w.hydra.calls, " "), "reject_logout"); n != 1 {
			t.Errorf("%d rejects", n)
		}
		// A tab left on the confirmation: E1001, before the accept that would
		// erase the refusal (HLO-5).
		w.hydra.calls = nil
		ev.Accept = true
		if r := w.handle(ev); r.Response.Code != E1001 || slices.Contains(w.hydra.calls, "accept_logout") {
			t.Errorf("another tab: %+v, %v", r.Response, w.hydra.calls)
		}
	})
	t.Run("accept", func(t *testing.T) {
		w := logoutWorld(t)
		w.demand(logoutU, false)
		ev := Logout{Challenge: logoutU, Cookie: cookie, Post: true, Accept: true, Token: cookie, SameOrigin: true}
		first := w.handle(ev)
		second := w.handle(ev)
		if first.Response.URL == "" || second.Response.URL != first.Response.URL || w.record().Cur != 0 {
			t.Errorf("first %+v, second %+v", first.Response, second.Response)
		}
		if has(second, "logout.propagated") || has(second, "logout.started") {
			t.Errorf("second: %+v", second.Reports)
		}
	})
}

// Q48: what the record keeps of the request_url.
func TestLogoutRequestURL(t *testing.T) {
	for raw, want := range map[string]string{
		"/oauth2/sessions/logout":                                                    "/oauth2/sessions/logout",
		"/oauth2/sessions/logout?id_token_hint=abc":                                  "/oauth2/sessions/logout",
		"/oauth2/sessions/logout?id_token_hint=abc&state=s":                          "/oauth2/sessions/logout",
		"/oauth2/sessions/logout?id_token_hint=abc&post_logout_redirect_uri=u&ui=fr": "/oauth2/sessions/logout?post_logout_redirect_uri=u&ui=fr",
		"/oauth2/sessions/logout?id_token_hint=abc%ZZ&state=s":                       "/oauth2/sessions/logout",
		"/oauth2/sessions/logout?id_token_hint=abc;state=s":                          "/oauth2/sessions/logout",
		"http://[bad/oauth2?id_token_hint=abc":                                       "http://[bad/oauth2",
	} {
		if got := logoutRequestURL(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}

// The reference: of a session, with the active key, as a key of the store.
func TestLogoutRef(t *testing.T) {
	ref := testKeys.LogoutRef("sid")
	if !isRef(ref) || ref == testKeys.LogoutRef("sid2") || ref == (Keys{oldKey}).LogoutRef("sid") {
		t.Errorf("ref %q", ref)
	}
	// Q46: its message cannot be a challenge's nor a marker's.
	m := hmac.New(sha256.New, testKey)
	m.Write([]byte("logout|sid"))
	if want := hex.EncodeToString(m.Sum(nil))[:20]; ref != want {
		t.Errorf("ref %q, want %q", ref, want)
	}
	c := testKeys.LogoutChallenge(ref, 2, "sql")
	got, sig, ok := logoutChallengeParts(c)
	if !ok || got != ref || len(c) != 36 || len(sig) != signatureLen {
		t.Errorf("challenge %q: %q %q %v", c, got, sig, ok)
	}
	if i, ok := testKeys.logoutPosition(ref, sig, []string{"a", "b", "sql"}); !ok || i != 2 {
		t.Errorf("position %d %v", i, ok)
	}
	if _, ok := testKeys.logoutPosition(ref, sig, []string{"sql", "a", "b"}); ok {
		t.Error("another position")
	}
}

// DecodeLogout refuses what is no record of this version.
func TestDecodeLogout(t *testing.T) {
	for _, data := range []string{`{`, `{"v":2}`, `[]`} {
		if _, err := DecodeLogout([]byte(data)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", data, err)
		}
	}
}

// The log lines of the logout, in the catalogue's levels, without the subject nor
// the challenges.
func TestLogoutLogs(t *testing.T) {
	w := logoutWorld(t)
	w.demand(logoutU, true)
	w.handle(Logout{Challenge: logoutU})
	w.handle(AppCall{Op: AppAcceptLogout, Challenge: testKeys.LogoutChallenge(logoutRef(), 0, "2fa"), Caller: callerOf("2fa")})
	logs := w.logs.String()
	for _, want := range []string{
		`"level":"INFO","msg":"logout.started","surface":"front"`,
		`"audit":true,"rp_initiated":true,"apps":3,"again":false`,
		`"level":"INFO","msg":"logout.propagated","surface":"emulated"`,
		`"app":"2fa","result":"accepted"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %s in\n%s", want, logs)
		}
	}
	for _, secret := range []string{"alice", logoutU, logoutSID} {
		if strings.Contains(logs, secret) {
			t.Errorf("%s in the logs:\n%s", secret, logs)
		}
	}
}

// MEM-11, SKP-12, SKP-13: a note of logout at the login.
func TestLoginAfterLogoutNote(t *testing.T) {
	note := Memory{Content: &Remembered{V: 1, SID: "the-session", Sub: "alice", Lo: true, AP: []string{"sql"}}}
	skip := func(w *world, sid string, url string) {
		w.hydra.login.Skip, w.hydra.login.Subject = true, "alice"
		w.hydra.login.SessionId = ory.PtrString(sid)
		if url != "" {
			w.hydra.login.RequestUrl = url
		}
	}
	const authURL = "http://public.hydra.test/oauth2/auth?client_id=c1&state=s"
	t.Run("SKP-12 its session: deleted, the authorization started again, no flow", func(t *testing.T) {
		w := newWorld(t)
		skip(w, "the-session", authURL)
		r := w.handle(Entry{LoginChallenge: hydraL, Memory: note})
		if r.Response.Kind != Redirect || r.Response.URL != authURL {
			t.Errorf("answer %+v", r.Response)
		}
		if want := []string{"get_login", "revoke_session"}; !slices.Equal(w.hydra.calls, want) || !slices.Equal(w.hydra.revoked, []string{"the-session"}) {
			t.Errorf("calls %v, revoked %v", w.hydra.calls, w.hydra.revoked)
		}
		if w.store.puts != 0 || r.Response.Remember != nil {
			t.Errorf("written: puts %d, %+v", w.store.puts, r.Response.Remember)
		}
		if !has(r, "skip.ignored", func(x Report) bool { return x.Reason == SkipLogout && x.Kind == "login" }) ||
			!has(r, "logout.session_revoked", func(x Report) bool { return x.Audit }) {
			t.Errorf("reports %+v", r.Reports)
		}
		if !strings.Contains(w.logs.String(), `"level":"INFO","msg":"logout.session_revoked"`) {
			t.Errorf("logs %s", w.logs.String())
		}
	})
	t.Run("SKP-12 with prompt=none: the same, Hydra answers login_required", func(t *testing.T) {
		w := newWorld(t)
		const none = authURL + "&prompt=none"
		skip(w, "the-session", none)
		if r := w.handle(Entry{LoginChallenge: hydraL, Memory: note}); r.Response.URL != none || slices.Contains(w.hydra.calls, "reject_login") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
	})
	t.Run("SKP-12 the DELETE fails: E1004, a reload plays it again", func(t *testing.T) {
		for _, err := range []error{errDown, err400, err404} {
			w := newWorld(t)
			skip(w, "the-session", authURL)
			w.hydra.errs["revoke_session"] = err
			r := w.handle(Entry{LoginChallenge: hydraL, Memory: note})
			if r.Response.Code != E1004 || w.store.puts != 0 {
				t.Errorf("%v: answer %+v", err, r.Response)
			}
			delete(w.hydra.errs, "revoke_session")
			if r := w.handle(Entry{LoginChallenge: hydraL, Memory: note}); r.Response.URL != authURL {
				t.Errorf("%v: reload %+v", err, r.Response)
			}
		}
	})
	t.Run("SKP-13 session_id empty, whatever the cookie: no delete, no flow", func(t *testing.T) {
		for _, m := range []Memory{{}, note, {Content: &Remembered{V: 1, SID: "other", Sub: "alice"}}} {
			w := newWorld(t)
			skip(w, "", authURL)
			r := w.handle(Entry{LoginChallenge: hydraL, Memory: m})
			if r.Response.URL != authURL || w.store.puts != 0 || !slices.Equal(w.hydra.calls, []string{"get_login"}) {
				t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
			}
		}
	})
	t.Run("SKP-13 before ENT-22 and SKP-11: prompt=none", func(t *testing.T) {
		w := newWorld(t)
		skip(w, "", authURL+"&prompt=none")
		if r := w.handle(Entry{LoginChallenge: hydraL}); r.Response.URL != authURL+"&prompt=none" || slices.Contains(w.hydra.calls, "reject_login") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
	})
	t.Run("MEM-11 a note of another session: the skip ignored", func(t *testing.T) {
		w := newWorld(t)
		skip(w, "another", authURL)
		r := w.handle(Entry{LoginChallenge: hydraL, Memory: note})
		if r.Response.Kind != ChoicePage || slices.Contains(w.hydra.calls, "revoke_session") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
		if !has(r, "skip.ignored", func(x Report) bool { return x.Reason == SkipLogout }) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("MEM-11 with prompt=none: SKP-11", func(t *testing.T) {
		w := newWorld(t)
		skip(w, "another", authURL+"&prompt=none")
		r := w.handle(Entry{LoginChallenge: hydraL, Memory: note})
		if r.Response.URL != hydraDone || !slices.Contains(w.hydra.calls, "reject_login") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
	})
	t.Run("MEM-11 is checked before the rest: a note past its exp", func(t *testing.T) {
		w := newWorld(t)
		skip(w, "another", authURL)
		past := Memory{Content: &Remembered{V: 1, SID: "another", Sub: "alice", Lo: true, Exp: testNow.Add(-time.Hour).Unix()}}
		// Of its session: SKP-12, a note's exp is not read.
		if r := w.handle(Entry{LoginChallenge: hydraL, Memory: past}); r.Response.URL != authURL {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("no skip: a note changes nothing", func(t *testing.T) {
		w := newWorld(t)
		w.hydra.login.SessionId = ory.PtrString("the-session")
		r := w.handle(Entry{LoginChallenge: hydraL, Memory: note})
		if r.Response.Kind != ChoicePage || slices.Contains(w.hydra.calls, "revoke_session") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
	})
}

// The consent after a logout: MEM-11, CST-24, SKC-15, WRT-1.
func TestConsentAfterLogout(t *testing.T) {
	t.Run("MEM-11, SKC-6 a note written since the accept of the skip", func(t *testing.T) {
		w := newWorld(t)
		m := w.remembered(t)
		w.hydra.login.Skip, w.hydra.login.Subject = true, "alice"
		if r := w.handle(Entry{LoginChallenge: hydraL2, Memory: m}); r.Response.URL != verifierURL {
			t.Fatalf("SKP-1: %+v", r.Response)
		}
		note := Memory{Content: &Remembered{V: 1, SID: m.Content.SID, Sub: "alice", Lo: true}}
		r := w.handle(Consent{Challenge: hydraC, Memory: note, Cookie: w.cookie})
		if r.Response.URL != hydraDone || !slices.Contains(w.hydra.calls, "reject_consent") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
		if !has(r, "skip.ignored", func(x Report) bool { return x.Kind == "consent" && x.Reason == SkipLogout }) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("SKC-15 a marker, login_session_id empty", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
			code Code
		}{{"rejected", nil, ""}, {"404", err404, E1002}, {"410", err410, E1002}, {"down", errDown, E1004}, {"400", err400, E1007}} {
			w := newWorld(t)
			m := w.remembered(t)
			w.hydra.login.Skip, w.hydra.login.Subject = true, "alice"
			w.handle(Entry{LoginChallenge: hydraL2, Memory: m})
			w.hydra.login.SessionId = ory.PtrString("")
			if tc.err != nil {
				w.hydra.errs["reject_consent"] = tc.err
			}
			r := w.handle(Consent{Challenge: hydraC, Memory: m, Cookie: w.cookie})
			if r.Response.Code != tc.code || tc.code == "" && r.Response.URL != hydraDone {
				t.Errorf("%s: answer %+v", tc.name, r.Response)
			}
			if has(r, "flow.rejected", func(x Report) bool { return x.Audit }) || tc.err == nil && slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Sentry }) {
				t.Errorf("%s: no audit nor Sentry: %+v", tc.name, r.Reports)
			}
		}
	})
	accepted := func(t *testing.T) *world {
		w := newWorld(t)
		w.hydra.consentSkip = true
		w.hydra.login.Client.ClientUri = ory.PtrString("http://client.test/")
		w.handle(Entry{LoginChallenge: hydraL})
		step := w.handle(Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
		w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
		if r := w.handle(Loop{Ref: lref, Cookie: w.cookie}); r.Response.URL != verifierURL {
			t.Fatalf("final accept: %+v", r.Response)
		}
		w.hydra.login.SessionId = ory.PtrString("") // the logout ended in another tab
		return w
	}
	t.Run("CST-24 the flow's session deleted", func(t *testing.T) {
		w := accepted(t)
		r := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
		if r.Response.URL != hydraDone || r.Response.Remember != nil || !slices.Contains(w.hydra.calls, "reject_consent") {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
		if has(r, "flow.rejected", func(x Report) bool { return x.Audit }) || slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Sentry }) {
			t.Errorf("no audit nor Sentry: %+v", r.Reports)
		}
		f := w.stored()
		if !f.Done || f.ConsentRedirect != hydraDone || f.ConsentAt == 0 {
			t.Errorf("flow %+v", f)
		}
	})
	t.Run("CST-24 before the cookie", func(t *testing.T) {
		w := accepted(t)
		if r := w.handle(Consent{Challenge: hydraC, Cookie: "another"}); r.Response.URL != hydraDone {
			t.Errorf("answer %+v", r.Response)
		}
	})
	for _, err := range []error{err404, err401, err410} {
		t.Run("CST-24 Hydra no longer knows it: finished, no reject", func(t *testing.T) {
			w := accepted(t)
			w.hydra.errs["reject_consent"] = err
			r := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
			if r.Response.Code != E1002 || r.Response.Link == "" {
				t.Errorf("answer %+v", r.Response)
			}
			if f := w.stored(); !f.Done {
				t.Errorf("flow %+v", f)
			}
		})
	}
	t.Run("CST-9 another session, not empty", func(t *testing.T) {
		w := accepted(t)
		w.hydra.login.SessionId = ory.PtrString("another")
		r := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
		if r.Response.Code != E1007 || !has(r, "flow.rejected", func(x Report) bool { return x.Audit && x.Detail == "not_ours:session" }) {
			t.Errorf("answer %+v, reports %+v", r.Response, r.Reports)
		}
	})
}

// WRT-1 (Q45, Q56): ap gathered on two flows, a note that stays.
func TestRememberApps(t *testing.T) {
	finish := func(t *testing.T, w *world, m Memory, flow string, apps ...string) Result {
		t.Helper()
		w.hydra.consentSkip = true
		w.handle(Entry{LoginChallenge: hydraL})
		step := w.handle(Choose{FlowID: flow, LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
		for _, app := range apps {
			w.app(t, app, step, "alice", `{"email":"alice@example.org"}`)
			step = w.handle(Loop{Ref: lref, Cookie: w.cookie})
		}
		if step.Response.URL != verifierURL {
			t.Fatalf("final accept: %+v", step.Response)
		}
		return w.handle(Consent{Challenge: hydraC, Cookie: w.cookie, Memory: m})
	}
	sid := loginSessionID(t)
	for _, tc := range []struct {
		name   string
		memory Memory
		flow   string
		apps   []string
		want   []string
	}{
		{"no cookie: those of the flow", Memory{}, "hydra-sql-2fa", []string{"sql", "2fa"}, []string{"sql", "2fa"}},
		{"the same session: gathered, no repeat", Memory{Content: &Remembered{V: 1, SID: sid, Sub: "alice", AP: []string{"oidc", "sql"}}}, "hydra-sql-2fa", []string{"sql", "2fa"}, []string{"oidc", "sql", "2fa"}},
		{"another session: its apps are not this one's", Memory{Content: &Remembered{V: 1, SID: "other", Sub: "alice", AP: []string{"oidc"}}}, "hydra-sql", []string{"sql"}, []string{"sql"}},
		{"unreadable", Memory{Reason: SkipUnreadable}, "hydra-sql", []string{"sql"}, []string{"sql"}},
		{"a note of another session: replaced", Memory{Content: &Remembered{V: 1, SID: "other", Sub: "bob", Lo: true, AP: []string{"oidc"}}}, "hydra-sql", []string{"sql"}, []string{"sql"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := finish(t, newWorld(t), tc.memory, tc.flow, tc.apps...)
			m := r.Response.Remember
			if m == nil || !slices.Equal(m.AP, tc.want) || m.Lo {
				t.Errorf("cookie %+v, want ap %v", m, tc.want)
			}
		})
	}
	t.Run("a note of this session stays: no cookie, the skip not honoured again", func(t *testing.T) {
		note := Memory{Content: &Remembered{V: 1, SID: sid, Sub: "alice", Lo: true}}
		r := finish(t, newWorld(t), note, "hydra-sql", "sql")
		if r.Response.Remember != nil || r.Response.URL != callbackURL {
			t.Errorf("answer %+v", r.Response)
		}
	})
}

func loginSessionID(t *testing.T) string {
	t.Helper()
	return loginRequest(t).GetSessionId()
}
