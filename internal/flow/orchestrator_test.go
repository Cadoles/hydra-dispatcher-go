package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra/flowcodec"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

const (
	verifierURL = "http://public.hydra.test/oauth2/auth?login_verifier=v1"
	callbackURL = "http://oidc.client.test/auth/callback?code=c"
)

// fakeHydra is an admin API that keeps what it accepted: the consent request
// it serves carries the final login accept's subject and context, as Hydra's.
type fakeHydra struct {
	mu          sync.Mutex
	login       *ory.OAuth2LoginRequest
	consentSkip bool
	// loginChallenge is the consent request's login_challenge: L itself,
	// as Hydra 2.1, when "".
	loginChallenge string
	calls          []string
	errs           map[string]error
	// before runs before answering a call, to change the store meanwhile.
	before   map[string]func()
	accepted *ory.AcceptOAuth2LoginRequest
	consent  *ory.AcceptOAuth2ConsentRequest
}

func (h *fakeHydra) called(op string) error {
	h.mu.Lock()
	h.calls = append(h.calls, op)
	f, err := h.before[op], h.errs[op]
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return err
}

func (h *fakeHydra) LoginRequest(_ context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	if err := h.called("get_login"); err != nil {
		return nil, err
	}
	r := *h.login
	r.RequestedAccessTokenAudience = nil // served null, as Hydra may
	return &r, nil
}

func (h *fakeHydra) AcceptLogin(_ context.Context, _ string, body ory.AcceptOAuth2LoginRequest) (string, error) {
	if err := h.called("accept_login"); err != nil {
		return "", err
	}
	h.accepted = &body
	return verifierURL, nil
}

func (h *fakeHydra) RejectLogin(context.Context, string, ory.RejectOAuth2Request) (string, error) {
	return hydraDone, h.called("reject_login")
}

func (h *fakeHydra) ConsentRequest(_ context.Context, challenge string) (*ory.OAuth2ConsentRequest, error) {
	if err := h.called("get_consent"); err != nil {
		return nil, err
	}
	ctx, _ := json.Marshal(h.accepted.Context)
	login := hydraL // Hydra 2.1 names L itself (Q34)
	if h.loginChallenge != "" {
		login = h.loginChallenge
	}
	return &ory.OAuth2ConsentRequest{
		Challenge:      challenge,
		LoginChallenge: ory.PtrString(login),
		Subject:        ory.PtrString(h.accepted.Subject),
		LoginSessionId: h.login.SessionId,
		Context:        json.RawMessage(ctx),
		RequestedScope: h.login.RequestedScope,
		Client:         &h.login.Client,
		Skip:           ory.PtrBool(h.consentSkip),
	}, nil
}

func (h *fakeHydra) AcceptConsent(_ context.Context, _ string, body ory.AcceptOAuth2ConsentRequest) (string, error) {
	if err := h.called("accept_consent"); err != nil {
		return "", err
	}
	h.consent = &body
	return callbackURL, nil
}

func (h *fakeHydra) RejectConsent(context.Context, string, ory.RejectOAuth2Request) (string, error) {
	return hydraDone, h.called("reject_consent")
}

// fakeStore is the memory store, whose Put a test may intercept: hook runs
// first, and its error, when it says so, replaces the write.
type fakeStore struct {
	state.StateStore
	puts int
	// ttls are those of the writes, in order (I4, Q2).
	ttls []time.Duration
	hook func(n int, key string, val []byte, ifVersion uint64) (error, bool)
	gets int
	// getErr fails the reads from the one numbered, from 1; 0 never.
	getErr int
}

func (s *fakeStore) Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error {
	s.puts++
	s.ttls = append(s.ttls, ttl)
	if s.hook != nil {
		if err, done := s.hook(s.puts, key, val, ifVersion); done {
			return err
		}
	}
	return s.StateStore.Put(ctx, key, val, ttl, ifVersion)
}

func (s *fakeStore) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	s.gets++
	if s.getErr != 0 && s.gets >= s.getErr {
		return nil, 0, errors.New("redis: i/o timeout")
	}
	return s.StateStore.Get(ctx, key)
}

type snapshots struct{ s *store.Snapshot }

func (s snapshots) Snapshot() *store.Snapshot { return s.s }

// world is a dispatcher with its fakes, a browser and the login apps.
type world struct {
	t      *testing.T
	o      *Orchestrator
	hydra  *fakeHydra
	store  *fakeStore
	now    time.Time
	cookie string
	logs   bytes.Buffer
}

func newWorld(t *testing.T) *world {
	mem := state.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	w := &world{t: t, hydra: &fakeHydra{login: loginRequest(t), errs: map[string]error{}, before: map[string]func(){}}, store: &fakeStore{StateStore: mem}, now: testNow}
	env := testEnv()
	w.o = &Orchestrator{
		Store:           w.store,
		Config:          snapshots{env.Config},
		Source:          Fallback{Hydra: w.hydra, Now: func() time.Time { return w.now }},
		Hydra:           w.hydra,
		Webhooks:        StubWebhooks{},
		BaseURL:         env.BaseURL,
		LoginConsentTTL: env.LoginConsentTTL,
		Keys:            testKeys,
		Log:             slog.New(slog.NewJSONHandler(&w.logs, nil)),
		Now:             func() time.Time { return w.now },
	}
	return w
}

func (w *world) handle(ev Event) Result {
	w.t.Helper()
	r := w.o.Handle(context.Background(), ev)
	if r.Response.SetCSRF != "" {
		w.cookie = r.Response.SetCSRF
	}
	return r
}

// stored returns the flow under the ref, nil when absent.
func (w *world) stored() *Flow {
	w.t.Helper()
	data, _, err := w.store.StateStore.Get(context.Background(), Key(lref))
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	f, err := Decode(data)
	if err != nil {
		w.t.Fatal(err)
	}
	return f
}

// put writes f under the ref, as another request would.
func (w *world) put(f *Flow) {
	w.t.Helper()
	_, v, _ := w.store.StateStore.Get(context.Background(), Key(lref))
	data, _ := Encode(f)
	if err := w.store.StateStore.Put(context.Background(), Key(lref), data, time.Hour, v); err != nil {
		w.t.Fatal(err)
	}
}

// param returns a query parameter of a redirect.
func param(t *testing.T, r Result, name string) string {
	t.Helper()
	if r.Response.Kind != Redirect {
		t.Fatalf("not a redirect: %+v", r.Response)
	}
	u, err := url.Parse(r.Response.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(name)
}

// app plays a login app on its step: read, accept, then the same for its
// consent, each through the emulated API.
func (w *world) app(t *testing.T, app string, login Result, subject, claims string) {
	t.Helper()
	caller := func(a store.App) bool { return a.ID == app }
	c := param(t, login, "login_challenge")
	for _, call := range []AppCall{
		{Op: AppGetLogin, Challenge: c},
		{Op: AppAcceptLogin, Challenge: c, Body: json.RawMessage(`{"subject":"` + subject + `","context":{"app":"` + app + `"}}`)},
	} {
		call.Caller = caller
		if r := w.handle(call); r.Response.Status != http.StatusOK {
			t.Fatalf("%s %v: %d %s", app, call.Op, r.Response.Status, rawJSON(r.Response.Body))
		}
	}
	consent := w.handle(Loop{Ref: lref, Cookie: w.cookie})
	cc := param(t, consent, "consent_challenge")
	for _, call := range []AppCall{
		{Op: AppGetConsent, Challenge: cc},
		{Op: AppAcceptConsent, Challenge: cc, Body: json.RawMessage(`{"session":{"id_token":` + claims + `}}`)},
	} {
		call.Caller = caller
		if r := w.handle(call); r.Response.Status != http.StatusOK {
			t.Fatalf("%s %v: %d %s", app, call.Op, r.Response.Status, rawJSON(r.Response.Body))
		}
	}
}

// fakeCodec decrypts the fake Hydra's challenges, whatever they are: the
// flow of its login request, completed by the login accept it kept, as Hydra
// seals them (P7).
type fakeCodec struct{ h *fakeHydra }

// hydraFlowID is the id of the fake Hydra's flow, which its consent request
// names as login_challenge once decrypted (Q34).
const hydraFlowID = "91d4f7afaf83455f8e2b8992cba303ef"

func (c fakeCodec) LoginChallenge(string) (*flowcodec.Flow, error)   { return c.flow(false) }
func (c fakeCodec) ConsentChallenge(string) (*flowcodec.Flow, error) { return c.flow(true) }

func (c fakeCodec) flow(consent bool) (*flowcodec.Flow, error) {
	r := c.h.login
	client, _ := json.Marshal(r.Client)
	oidc, _ := json.Marshal(r.OidcContext)
	f := &flowcodec.Flow{
		ID: hydraFlowID, RequestedAt: testNow.Add(-time.Minute), ClientID: r.Client.GetClientId(), Client: client,
		RequestURL: r.RequestUrl, OpenIDConnectContext: oidc, RequestedScope: r.RequestedScope,
		SessionID: r.GetSessionId(), Subject: r.Subject, LoginSkip: r.Skip,
	}
	if consent {
		ctx, _ := json.Marshal(c.h.accepted.Context)
		f.ConsentChallengeID, f.Subject, f.Context = "consent-id", c.h.accepted.Subject, ctx
		f.ACR, f.AMR, f.ConsentSkip = c.h.accepted.GetAcr(), c.h.accepted.Amr, c.h.consentSkip
	}
	return f, nil
}

// B3: the calls to Hydra of an authentication, the engine's and the
// orchestrator's (Stratégie de tests): in fallback, and decrypted (P7), where
// only the accepts are left.
func TestHydraCalls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flow    string
		screen  bool
		decrypt bool
		calls   []string
	}{
		{"B3, two steps, choice page, consent skipped by Hydra", "hydra-sql-2fa", false, false,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "accept_consent"}},
		{"B3, two steps, consent screen shown", "hydra-sql-2fa", true, false,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "get_consent", "accept_consent"}},
		{"B3, one step", "hydra-sql", false, false,
			[]string{"get_login", "accept_login", "get_consent", "accept_consent"}},
		{"B3 P7, two steps, choice page, consent skipped, decrypted", "hydra-sql-2fa", false, true,
			[]string{"accept_login", "accept_consent"}},
		{"B3 P7, two steps, consent screen shown, decrypted", "hydra-sql-2fa", true, true,
			[]string{"accept_login", "accept_consent"}},
		{"B3 P7, one step, decrypted", "hydra-sql", false, true,
			[]string{"accept_login", "accept_consent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			if tc.decrypt {
				w.o.Source = Decrypt{Codec: fakeCodec{w.hydra}, Fallback: Fallback{Hydra: w.hydra}, TTL: w.o.LoginConsentTTL, Now: func() time.Time { return w.now }}
			}
			w.hydra.consentSkip = !tc.screen
			if r := w.handle(Entry{LoginChallenge: hydraL}); r.Response.Kind != ChoicePage {
				t.Fatalf("GET /: %+v", r.Response)
			}
			// A5: the choice does not read the login request again.
			step := w.handle(Choose{FlowID: tc.flow, LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
			w.app(t, "sql", step, "alice", `{"email":"alice@example.org","name":"Alice"}`)
			if tc.flow == "hydra-sql-2fa" {
				step = w.handle(Loop{Ref: lref, Cookie: w.cookie})
				w.app(t, "2fa", step, "alice", `{"email":null,"amr":"otp"}`)
			}
			final := w.handle(Loop{Ref: lref, Cookie: w.cookie})
			if final.Response.URL != verifierURL {
				t.Fatalf("final accept: %+v", final.Response)
			}
			c := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
			if tc.screen {
				if c.Response.Kind != ConsentPage {
					t.Fatalf("consent screen: %+v", c.Response)
				}
				c = w.handle(Consent{Challenge: hydraC, Cookie: w.cookie, Post: true, Accept: true, Token: w.cookie, SameOrigin: true})
			}
			if c.Response.URL != callbackURL {
				t.Fatalf("consent: %+v", c.Response)
			}
			if !slices.Equal(w.hydra.calls, tc.calls) {
				t.Errorf("calls %v; want %v", w.hydra.calls, tc.calls)
			}
			// The id_token of hydra-sql-2fa carries the email (1a): a null of
			// the second step erases nothing (A2).
			if got := rawJSON(w.hydra.consent.Session.IdToken); !strings.Contains(got, `"email":"alice@example.org"`) {
				t.Errorf("id_token %s", got)
			}
			if f := w.stored(); f == nil || !f.Done || f.ConsentRedirect != callbackURL {
				t.Errorf("T1, flow after the consent %+v", f)
			}
			if tc.decrypt && strings.Contains(w.logs.String(), "hydra.decrypt_fallback") {
				t.Errorf("a fallback: %s", w.logs.String())
			}
			// After the end, every return gives E1002 without a call (T1, I9).
			calls := len(w.hydra.calls)
			if r := w.handle(Loop{Ref: lref, Cookie: w.cookie}); r.Response.Code != E1002 || len(w.hydra.calls) != calls {
				t.Errorf("RA6, a return after the end: %+v", r.Response)
			}
		})
	}
}

// failingCodec opens no challenge: err for every one.
type failingCodec struct{ err error }

func (c failingCodec) LoginChallenge(string) (*flowcodec.Flow, error)   { return nil, c.err }
func (c failingCodec) ConsentChallenge(string) (*flowcodec.Flow, error) { return nil, c.err }

// A fallback the decryption could not avoid is logged as a warning, which
// names the step that failed (DEC-6); a forged challenge is not (DEC-5, Q32),
// but is reported forged, once, by ENT-12, whatever the mode and the shape of
// the challenge.
func TestDecryptFallbackLogged(t *testing.T) {
	forged := `"msg":"challenge.invalid","surface":"front","detail":"forged"`
	for _, tc := range []struct {
		name    string
		err     error // of the codec; nil: no codec (DEC-1)
		hydra   error
		warning string
	}{
		{"DEC-6, another format", fmt.Errorf("%w: no client", flowcodec.ErrFormat), nil, `"msg":"hydra.decrypt_fallback"`},
		{"DEC-5, a secret missing", flowcodec.ErrInvalid, nil, `"msg":"hydra.decrypt_fallback"`},
		{"DEC-5, forged", flowcodec.ErrInvalid, err404, forged},
		{"DEC-2, Hydra 2.1", flowcodec.ErrNotEncrypted, nil, ""},
		{"DEC-2, 32 hexadecimals unknown to Hydra: forged (Q32)", flowcodec.ErrNotEncrypted, err404, forged},
		{"DEC-1, unknown to Hydra: forged (Q32)", nil, err404, forged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			if tc.err != nil {
				w.o.Source = Decrypt{Codec: failingCodec{tc.err}, Fallback: Fallback{Hydra: w.hydra}, TTL: w.o.LoginConsentTTL}
			}
			if tc.hydra != nil {
				w.hydra.errs["get_login"] = tc.hydra
			}
			w.handle(Entry{LoginChallenge: hydraL})
			logs := w.logs.String()
			if !slices.Equal(w.hydra.calls, []string{"get_login"}) {
				t.Errorf("calls %v: the fallback reads the admin API once", w.hydra.calls)
			}
			switch {
			case tc.warning == "" && (strings.Contains(logs, "decrypt_fallback") || strings.Contains(logs, "challenge.invalid")),
				tc.warning != "" && !strings.Contains(logs, `"level":"WARN","msg"`+strings.TrimPrefix(tc.warning, `"msg"`)):
				t.Errorf("logs %s; want %s", logs, tc.warning)
			}
			if n := strings.Count(logs, `"msg":"challenge.invalid"`); tc.warning == forged && n != 1 {
				t.Errorf("forged logged %d times: %s", n, logs)
			}
		})
	}

	// DEC-6 then 404: a flow the secret opens, unreadable, that Hydra does
	// not know (a wrong hydra.version and another instance's challenge): the
	// decryption alert, which only Hydra's own flows raise, and the page's
	// forged, as any 404 (revue R18). Each once.
	t.Run("DEC-6, unknown to Hydra: the alert and forged", func(t *testing.T) {
		w := newWorld(t)
		w.o.Source = Decrypt{Codec: failingCodec{fmt.Errorf("%w: no client", flowcodec.ErrFormat)}, Fallback: Fallback{Hydra: w.hydra}, TTL: w.o.LoginConsentTTL}
		w.hydra.errs["get_login"] = err404
		if r := w.handle(Entry{LoginChallenge: hydraL}); r.Response.Code != E1001 {
			t.Fatalf("answer %+v", r.Response)
		}
		logs := w.logs.String()
		if strings.Count(logs, `"level":"WARN","msg":"hydra.decrypt_fallback"`) != 1 || strings.Count(logs, forged) != 1 {
			t.Errorf("logs %s", logs)
		}
	})

	// ECR-1: the transition replayed on the flow read again keeps the read,
	// which is logged once.
	t.Run("ECR-1, a read's report logged once when replayed", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.o.Source = Decrypt{Codec: failingCodec{fmt.Errorf("%w: no client", flowcodec.ErrFormat)}, Fallback: Fallback{Hydra: w.hydra},
			TTL: w.o.LoginConsentTTL, Now: func() time.Time { return w.now }}
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				return state.ErrConflict, true
			}
			return nil, false
		}
		r := w.handle(Loop{Ref: lref, Cookie: cookie})
		if r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 2 || !slices.Equal(w.hydra.calls, []string{"get_login"}) {
			t.Fatalf("answer %+v, puts %d, calls %v", r.Response, w.store.puts, w.hydra.calls)
		}
		if n := strings.Count(w.logs.String(), `"msg":"hydra.decrypt_fallback"`); n != 1 {
			t.Errorf("logged %d times: %s", n, w.logs.String())
		}
	})
}

// aheadCodec is fakeCodec under a Hydra whose clock is ahead of the
// dispatcher's: its flows' requested_at is in the dispatcher's future.
type aheadCodec struct {
	fakeCodec
	ahead time.Duration
}

func (c aheadCodec) LoginChallenge(s string) (*flowcodec.Flow, error) {
	f, err := c.fakeCodec.LoginChallenge(s)
	f.RequestedAt = testNow.Add(c.ahead)
	return f, err
}

func (c aheadCodec) ConsentChallenge(s string) (*flowcodec.Flow, error) {
	f, err := c.fakeCodec.ConsentChallenge(s)
	f.RequestedAt = testNow.Add(c.ahead)
	return f, err
}

// DEC-3: Hydra's clock ahead is logged once per authentication, at the
// creation, however many reads follow (two steps, the consent screen and its
// POST, all decrypted; revue R18).
func TestClockSkewLoggedOnce(t *testing.T) {
	w := newWorld(t)
	w.o.Source = Decrypt{Codec: aheadCodec{fakeCodec{w.hydra}, 10 * time.Minute}, Fallback: Fallback{Hydra: w.hydra}, TTL: w.o.LoginConsentTTL, Now: func() time.Time { return w.now }}
	w.handle(Entry{LoginChallenge: hydraL})
	step := w.handle(Choose{FlowID: "hydra-sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
	step = w.handle(Loop{Ref: lref, Cookie: w.cookie})
	w.app(t, "2fa", step, "alice", `{"amr":"otp"}`)
	if final := w.handle(Loop{Ref: lref, Cookie: w.cookie}); final.Response.URL != verifierURL {
		t.Fatalf("final accept: %+v", final.Response)
	}
	if c := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie}); c.Response.Kind != ConsentPage {
		t.Fatalf("consent screen: %+v", c.Response)
	}
	if c := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie, Post: true, Accept: true, Token: w.cookie, SameOrigin: true}); c.Response.URL != callbackURL {
		t.Fatalf("consent: %+v", c.Response)
	}
	logs := w.logs.String()
	if !slices.Equal(w.hydra.calls, []string{"accept_login", "accept_consent"}) ||
		strings.Count(logs, `"level":"WARN","msg":"hydra.clock_skew","surface":"front","detail":"Hydra's requested_at 10m0s ahead"`) != 1 {
		t.Errorf("calls %v, logs %s", w.hydra.calls, logs)
	}
}

// otherLoginCodec opens the consent challenges as those of another login of
// Hydra: their flow's id is not the one of L.
type otherLoginCodec struct{ fakeCodec }

func (c otherLoginCodec) ConsentChallenge(string) (*flowcodec.Flow, error) {
	f, err := c.flow(true)
	if err == nil {
		f.ID = "0123456789abcdef0123456789abcdef"
	}
	return f, err
}

// loginOnlyCodec opens the login challenges only: the consent ones fall back
// on the admin API, as under a secret Hydra rotated meanwhile.
type loginOnlyCodec struct{ fakeCodec }

func (c loginOnlyCodec) ConsentChallenge(string) (*flowcodec.Flow, error) {
	return nil, flowcodec.ErrInvalid
}

// CST-23 (Q34) through the orchestrator: L decrypted keeps the flow's id,
// which the consent request must name, read locally or on the admin API.
func TestConsentOfTheLogin(t *testing.T) {
	for _, tc := range []struct {
		name  string
		codec func(*fakeHydra) Codec
		// admin is the login_challenge of the admin API's consent request.
		admin string
		ok    bool
	}{
		{"decrypted, the consent of the login", func(h *fakeHydra) Codec { return fakeCodec{h} }, "", true},
		{"decrypted, the consent of another login", func(h *fakeHydra) Codec { return otherLoginCodec{fakeCodec{h}} }, "", false},
		{"L decrypted, the consent on the admin API of 2.2: the flow's id", func(h *fakeHydra) Codec { return loginOnlyCodec{fakeCodec{h}} }, hydraFlowID, true},
		{"L decrypted, the consent on the admin API naming another login", func(h *fakeHydra) Codec { return loginOnlyCodec{fakeCodec{h}} }, hydraL, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.o.Source = Decrypt{Codec: tc.codec(w.hydra), Fallback: Fallback{Hydra: w.hydra}, TTL: w.o.LoginConsentTTL, Now: func() time.Time { return w.now }}
			w.hydra.consentSkip, w.hydra.loginChallenge = true, tc.admin
			w.handle(Entry{LoginChallenge: hydraL})
			step := w.handle(Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
			w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
			if final := w.handle(Loop{Ref: lref, Cookie: w.cookie}); final.Response.URL != verifierURL {
				t.Fatalf("final accept: %+v", final.Response)
			}
			if f := w.stored(); f.Hydra.LoginID != hydraFlowID {
				t.Fatalf("hid %q", f.Hydra.LoginID)
			}
			c := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
			switch {
			case tc.ok && c.Response.URL != callbackURL:
				t.Errorf("consent %+v", c.Response)
			case !tc.ok && (c.Response.Code != E1007 || !slices.ContainsFunc(c.Reports, func(r Report) bool {
				return r.Audit && r.Detail == "not_ours:login"
			})):
				t.Errorf("CST-23: %+v, reports %+v", c.Response, c.Reports)
			}
		})
	}
}

// running is a world with a flow of hydra-sql-2fa in the store.
func running(t *testing.T, f *Flow) *world {
	w := newWorld(t)
	w.cookie = cookie
	w.put(f)
	return w
}

func reported(r Result, event string) bool {
	return slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == event })
}

func TestConditionalWrites(t *testing.T) {
	loop := Loop{Ref: lref, Cookie: cookie}
	t.Run("ECR-1, a conflict replayed with the answer obtained", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				f := atStep(t, 1, true, true)
				f.ConsentChallenge = "unrelated" // a concurrent write that changes nothing of the step
				w.put(f)
			}
			return nil, false
		}
		r := w.handle(loop)
		if r.Response.URL != loginURL("2fa", 1000) || w.stored().Current != 2 {
			t.Errorf("answer %+v, flow %+v", r.Response, w.stored())
		}
		if !slices.Equal(w.hydra.calls, []string{"get_login"}) || w.store.puts != 2 || !reported(r, "state.conflict") {
			t.Errorf("Q12, calls %v, puts %d, reports %+v", w.hydra.calls, w.store.puts, r.Reports)
		}
	})
	t.Run("ECR-2, a second conflict", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrConflict, true }
		r := w.handle(loop)
		if r.Response.Code != E1007 || w.store.puts != 2 || len(w.hydra.calls) != 1 {
			t.Errorf("answer %+v, puts %d, calls %v", r.Response, w.store.puts, w.hydra.calls)
		}
		if !slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == "state.conflict" && x.Sentry }) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("ECR-3, BCL-6 after a concurrent BCL-8", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.hydra.before["get_login"] = func() { w.put(atStep(t, 2, false, false)) }
		r := w.handle(loop)
		if r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 1 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("ECR-3, two final accepts: each its own redirect_to", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.before["accept_login"] = func() {
			f := acceptedFlow(t)
			f.HydraRedirect = "http://hydra/theirs"
			w.put(f)
		}
		r := w.handle(loop)
		if r.Response.URL != verifierURL || w.stored().HydraRedirect != "http://hydra/theirs" {
			t.Errorf("answer %+v, flow hr %q", r.Response, w.stored().HydraRedirect)
		}
		if !slices.Equal(w.hydra.calls, []string{"accept_login"}) {
			t.Errorf("calls %v", w.hydra.calls)
		}
	})
	t.Run("ECR-4, back to the choice meanwhile: the accept carried over", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.before["accept_login"] = func() { w.put(lastDone(t).restart()) }
		r := w.handle(loop)
		f := w.stored()
		if r.Response.URL != verifierURL || f.HydraRedirect != verifierURL || f.Sent == nil || f.Gen != 1001 {
			t.Errorf("answer %+v, flow %+v", r.Response, f)
		}
	})
	t.Run("ECR-9, finished meanwhile: no accept carried over", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.before["accept_login"] = func() { w.put(finishedFlow(t, "", 0)) }
		r := w.handle(loop)
		if r.Response.Code != E1002 || !w.stored().Done || w.stored().HydraRedirect != "" {
			t.Errorf("answer %+v, flow %+v", r.Response, w.stored())
		}
		if !slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == "state.conflict" && x.Sentry }) {
			t.Errorf("reports %+v", r.Reports)
		}
	})
	t.Run("ECR-9, a reject on a flow finished meanwhile: its redirect_to", func(t *testing.T) {
		w := running(t, expired(atStep(t, 1, false, false)))
		w.hydra.before["reject_login"] = func() { w.put(finishedFlow(t, "", 0)) }
		r := w.handle(loop)
		if r.Response.URL != hydraDone || !w.stored().Done {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-5, written", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, key string, val []byte, v uint64) (error, bool) {
			_ = w.store.StateStore.Put(context.Background(), key, val, time.Hour, v)
			return errors.New("redis: i/o timeout"), true
		}
		r := w.handle(loop)
		if r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 1 || reported(r, "state.conflict") {
			t.Errorf("answer %+v, puts %d, reports %+v", r.Response, w.store.puts, r.Reports)
		}
	})
	t.Run("ECR-5, not written: written again once", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			return errors.New("redis: i/o timeout"), n == 1
		}
		r := w.handle(loop)
		if r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 2 || w.stored().Current != 2 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("ECR-5, not written, then written of unknown outcome", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, key string, val []byte, v uint64) (error, bool) {
			if n == 2 {
				_ = w.store.StateStore.Put(context.Background(), key, val, time.Hour, v)
			}
			return errors.New("redis: i/o timeout"), true
		}
		if r := w.handle(loop); r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 2 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("ECR-5, not written twice", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return errors.New("redis: i/o timeout"), true }
		if r := w.handle(loop); r.Response.Code != E1007 || w.store.puts != 2 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("ECR-5, another value: a conflict", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				w.put(atStep(t, 2, false, false))
				return errors.New("redis: i/o timeout"), true
			}
			return nil, false
		}
		r := w.handle(loop)
		if r.Response.URL != loginURL("2fa", 1000) || w.store.puts != 1 || len(w.hydra.calls) != 1 {
			t.Errorf("answer %+v, puts %d, calls %v", r.Response, w.store.puts, w.hydra.calls)
		}
	})
	t.Run("ECR-5, another value with no replay left", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				return state.ErrConflict, true
			}
			w.put(lastDone(t).restart())
			return errors.New("redis: i/o timeout"), true
		}
		if r := w.handle(loop); r.Response.Code != E1007 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-7, store closed on the write again", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				return errors.New("redis: i/o timeout"), true
			}
			return state.ErrClosed, true
		}
		if r := w.handle(loop); r.Response.Code != E1000 || !reported(r, "state.error") {
			t.Errorf("answer %+v, reports %+v", r.Response, r.Reports)
		}
	})
	t.Run("ECR-8, hx passed before the write again: nothing written", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			w.now = testNow.Add(31 * time.Minute)
			return errors.New("redis: i/o timeout"), true
		}
		if r := w.handle(loop); r.Response.Code != E1002 || w.store.puts != 1 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("I4 Q2, the TTL runs to hx, the write again's too", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.now = testNow.Add(5 * time.Minute)
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			w.now = w.now.Add(time.Minute)
			return errors.New("redis: i/o timeout"), n == 1
		}
		w.handle(loop)
		if want := []time.Duration{25 * time.Minute, 24 * time.Minute}; !slices.Equal(w.store.ttls, want) {
			t.Errorf("ttls %v; want %v", w.store.ttls, want)
		}
	})
	t.Run("ECR-4, a subject mismatch carried over keeps its audit event", func(t *testing.T) {
		w := running(t, atStep(t, 2, false, false))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				w.put(atStep(t, 2, false, false).restart()) // back to the choice meanwhile
			}
			return nil, false
		}
		r := w.handle(callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`))
		if r.Response.Status != http.StatusOK || !slices.Equal(w.hydra.calls, []string{"reject_login"}) || !w.stored().Done {
			t.Errorf("answer %d %s, calls %v", r.Response.Status, rawJSON(r.Response.Body), w.hydra.calls)
		}
		if !slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == "step.subject_mismatch" && x.Audit }) {
			t.Errorf("no audit: %+v", r.Reports)
		}
	})
	t.Run("ECR-6, two loads of GET /: the last one wins", func(t *testing.T) {
		w := newWorld(t)
		w.hydra.before["get_login"] = func() {
			f := choiceFlow(t)
			f.CSRF = otherCSRF
			w.put(f)
		}
		r := w.handle(Entry{LoginChallenge: hydraL, Cookie: cookie})
		f := w.stored()
		if r.Response.Kind != ChoicePage || f.CSRF != cookie || f.Gen != 1001 || len(w.hydra.calls) != 1 {
			t.Errorf("A4 Q12, answer %+v, flow csrf %q gen %d, calls %v", r.Response, f.CSRF, f.Gen, w.hydra.calls)
		}
	})
	t.Run("ECR-6, the same cookie: the page of the flow read", func(t *testing.T) {
		w := newWorld(t)
		w.hydra.before["get_login"] = func() { w.put(choiceFlow(t)) }
		r := w.handle(Entry{LoginChallenge: hydraL, Cookie: cookie})
		if r.Response.Kind != ChoicePage || w.stored().Gen != 1000 || w.store.puts != 1 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("Q12, EMU-11 replayed as EMU-14: then the first call", func(t *testing.T) {
		w := running(t, atStep(t, 2, false, false))
		w.store.hook = func(n int, _ string, _ []byte, _ uint64) (error, bool) {
			if n == 1 {
				f := atStep(t, 2, true, false)
				f.Steps[1].Subject = "alice"
				w.put(f)
				return state.ErrConflict, true
			}
			return nil, false
		}
		w.o.Config = snapshots{store.NewSnapshot(testApps(), testFlows(), store.DefaultSettings())}
		r := w.handle(callBy(AppAcceptLogin, 1000, "2fa", `{"subject":"bob"}`))
		if r.Response.Status != http.StatusOK || rawJSON(r.Response.Body) != `{"redirect_to":"`+hydraDone+`"}` || !slices.Equal(w.hydra.calls, []string{"reject_login"}) {
			t.Errorf("answer %d %s, calls %v", r.Response.Status, rawJSON(r.Response.Body), w.hydra.calls)
		}
	})
	t.Run("ECR-7, store failing on the read", func(t *testing.T) {
		w := running(t, atStep(t, 1, false, false))
		w.store.getErr = 1
		r := w.handle(loop)
		if r.Response.Code != E1000 || !slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == "state.error" && x.Sentry }) {
			t.Errorf("answer %+v, reports %+v", r.Response, r.Reports)
		}
		if r := w.handle(callBy(AppGetLogin, 1000, "sql", "")); r.Response.Status != http.StatusInternalServerError ||
			rawJSON(r.Response.Body) != `{"error":"server_error","error_description":"E1000","status_code":500}` {
			t.Errorf("API: %d %s", r.Response.Status, rawJSON(r.Response.Body))
		}
	})
	t.Run("ECR-7, store closed on the write", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrClosed, true }
		if r := w.handle(loop); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-7, store failing on the re-read", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return state.ErrConflict, true }
		w.store.getErr = 2
		if r := w.handle(loop); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-7, store failing after an unknown outcome", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.store.hook = func(int, string, []byte, uint64) (error, bool) { return errors.New("redis: i/o timeout"), true }
		w.store.getErr = 2
		if r := w.handle(loop); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-7, a flow this version cannot read", func(t *testing.T) {
		w := newWorld(t)
		_ = w.store.StateStore.Put(context.Background(), Key(lref), []byte(`{"v":9}`), time.Hour, 0)
		if r := w.handle(loop); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-7, the 409 re-read fails", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.errs["accept_login"] = err409
		w.store.getErr = 2
		if r := w.handle(loop); r.Response.Code != E1000 {
			t.Errorf("answer %+v", r.Response)
		}
	})
	t.Run("ECR-8, L ended at Hydra during the call: no write", func(t *testing.T) {
		w := running(t, atStep(t, 1, true, true))
		w.hydra.before["get_login"] = func() { w.now = testNow.Add(31 * time.Minute) }
		r := w.handle(loop)
		if r.Response.Code != E1002 || w.store.puts != 0 {
			t.Errorf("answer %+v, puts %d", r.Response, w.store.puts)
		}
	})
	t.Run("FIN-5, a 409 read again in the store", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.errs["accept_login"] = err409
		w.hydra.before["accept_login"] = func() { w.put(acceptedFlow(t)) }
		r := w.handle(loop)
		if r.Response.URL != hydraDone || !slices.Equal(w.hydra.calls, []string{"accept_login"}) {
			t.Errorf("answer %+v, calls %v", r.Response, w.hydra.calls)
		}
	})
	t.Run("webhooks stubbed until P10", func(t *testing.T) {
		w := running(t, lastDone(t))
		snap := store.NewSnapshot(testApps(), testFlows(), store.DefaultSettings())
		snap.Settings.LoginAcceptWebhookURL = "http://hook.test/"
		w.o.Config = snapshots{snap}
		if r := w.handle(loop); r.Response.URL != verifierURL {
			t.Errorf("answer %+v", r.Response)
		}
		if got := rawJSON(w.hydra.accepted.Context); got != `{"from":"2fa","x_dispatcher_ref":"`+lref+`"}` {
			t.Errorf("context %s", got)
		}
	})
}

// The rejects of the consent, made by the orchestrator (CST-15, CST-8).
func TestConsentRejects(t *testing.T) {
	login := &ory.AcceptOAuth2LoginRequest{Subject: "alice", Context: map[string]any{"x_dispatcher_ref": lref}}
	t.Run("CST-15", func(t *testing.T) {
		w := running(t, acceptedFlow(t))
		w.hydra.accepted = login
		r := w.handle(Consent{Challenge: hydraC, Cookie: cookie, Post: true, Token: cookie, SameOrigin: true})
		f := w.stored()
		if r.Response.URL != hydraDone || !slices.Equal(w.hydra.calls, []string{"get_consent", "reject_consent"}) || !f.Done || f.ConsentRedirect != hydraDone {
			t.Errorf("answer %+v, calls %v, flow %+v", r.Response, w.hydra.calls, f)
		}
	})
	t.Run("CST-8, the cookie not even checked", func(t *testing.T) {
		w := running(t, lastDone(t))
		w.hydra.accepted = login
		r := w.handle(Consent{Challenge: hydraC})
		f := w.stored()
		if r.Response.Code != E1007 || !slices.Equal(w.hydra.calls, []string{"get_consent", "reject_consent"}) || !f.Done || f.ConsentRedirect != "" {
			t.Errorf("answer %+v, calls %v, flow %+v", r.Response, w.hydra.calls, f)
		}
		if !slices.ContainsFunc(r.Reports, func(x Report) bool { return x.Event == "flow.rejected" && x.Audit }) {
			t.Errorf("A3, no audit: %+v", r.Reports)
		}
	})
}

// traced is the log handler of serve, as far as the orchestrator sees it: it
// writes the trace id of the request's context.
type traced struct{ slog.Handler }

type traceKey struct{}

func (h traced) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := ctx.Value(traceKey{}).(string); ok {
		r.AddAttrs(slog.String("trace_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func TestOrchestratorLogs(t *testing.T) {
	w := running(t, atStep(t, 1, false, false))
	w.o.Log = slog.New(traced{slog.NewJSONHandler(&w.logs, nil)})
	// A future step: forged. Logged in the request's context, with its
	// surface.
	r := w.o.Handle(context.WithValue(context.Background(), traceKey{}, "t1"), callBy(AppGetLogin, 1000, "2fa", ""))
	if r.Response.Status != http.StatusNotFound ||
		!strings.Contains(w.logs.String(), `"level":"WARN","msg":"challenge.invalid","surface":"emulated","detail":"forged","audit":false,"trace_id":"t1"`) {
		t.Errorf("answer %d, logs %s", r.Response.Status, w.logs.String())
	}
	w.store.getErr = 1
	w.handle(Loop{Ref: lref, Cookie: cookie})
	if !strings.Contains(w.logs.String(), `"level":"ERROR","msg":"state.error","surface":"front"`) {
		t.Errorf("logs %s", w.logs.String())
	}
	w.o.Log, w.o.Now = nil, nil
	if r := w.handle(Entry{}); r.Response.Code != E1001 {
		t.Errorf("answer %+v", r.Response)
	}
}

func TestDraw(t *testing.T) {
	w := newWorld(t)
	a, b := w.o.env().Draw, w.o.env().Draw
	if a.Gen0 < 0 || a.Gen0 >= 1<<32 || len(a.CSRF) != 64 || !lowerHex(a.CSRF) || a.CSRF == b.CSRF {
		t.Errorf("Q9 A4, draws %+v and %+v", a, b)
	}
}
