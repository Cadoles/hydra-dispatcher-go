package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

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
	calls       []string
	errs        map[string]error
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
	return &ory.OAuth2ConsentRequest{
		Challenge:      challenge,
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
	caller := func(a string) bool { return a == app }
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

// B3: the calls to Hydra of an authentication, in fallback, the engine's
// and the orchestrator's (Stratégie de tests).
func TestHydraCalls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flow   string
		screen bool
		calls  []string
	}{
		{"B3, two steps, choice page, consent skipped by Hydra", "hydra-sql-2fa", false,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "accept_consent"}},
		{"B3, two steps, consent screen shown", "hydra-sql-2fa", true,
			[]string{"get_login", "get_login", "accept_login", "get_consent", "get_consent", "accept_consent"}},
		{"B3, one step", "hydra-sql", false,
			[]string{"get_login", "accept_login", "get_consent", "accept_consent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
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
			// After the end, every return gives E1002 without a call (T1, I9).
			calls := len(w.hydra.calls)
			if r := w.handle(Loop{Ref: lref, Cookie: w.cookie}); r.Response.Code != E1002 || len(w.hydra.calls) != calls {
				t.Errorf("RA6, a return after the end: %+v", r.Response)
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

func TestOrchestratorLogs(t *testing.T) {
	w := running(t, atStep(t, 1, false, false))
	r := w.handle(callBy(AppGetLogin, 1000, "2fa", "")) // a future step: forged
	if r.Response.Status != http.StatusNotFound || !strings.Contains(w.logs.String(), `"level":"WARN","msg":"challenge.invalid","detail":"forged"`) {
		t.Errorf("answer %d, logs %s", r.Response.Status, w.logs.String())
	}
	w.store.getErr = 1
	w.handle(Loop{Ref: lref, Cookie: cookie})
	if !strings.Contains(w.logs.String(), `"level":"ERROR","msg":"state.error"`) {
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
