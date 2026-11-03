package flow

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Hydra is the admin API the orchestrator calls, as internal/hydra's client
// does; the login and consent requests are read through the Source.
type Hydra interface {
	AcceptLogin(ctx context.Context, challenge string, body ory.AcceptOAuth2LoginRequest) (string, error)
	RejectLogin(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error)
	AcceptConsent(ctx context.Context, challenge string, body ory.AcceptOAuth2ConsentRequest) (string, error)
	RejectConsent(ctx context.Context, challenge string, body ory.RejectOAuth2Request) (string, error)
}

// Webhooks call the accept webhooks, with what the call would send to Hydra.
type Webhooks interface {
	Login(ctx context.Context, call Call) LoginHookAnswer
	Consent(ctx context.Context, call Call) ConsentHookAnswer
}

// StubWebhooks change nothing: the webhooks come with P10.
type StubWebhooks struct{}

func (StubWebhooks) Login(context.Context, Call) LoginHookAnswer     { return LoginHookAnswer{} }
func (StubWebhooks) Consent(context.Context, Call) ConsentHookAnswer { return ConsentHookAnswer{} }

// Snapshots gives the configuration snapshot of the moment, as store.Live
// does.
type Snapshots interface {
	Snapshot() *store.Snapshot
}

// Orchestrator runs the transitions of the requests: it reads the flow,
// makes the calls a transition asks for, then writes conditionally on the
// version read (Moteur de flows, Écritures conditionnelles).
type Orchestrator struct {
	Store    state.StateStore
	Config   Snapshots
	Source   Source
	Hydra    Hydra
	Webhooks Webhooks
	// BaseURL, LoginConsentTTL and Keys are server.base_url,
	// hydra.login_consent_ttl and the challenge keys.
	BaseURL         string
	LoginConsentTTL time.Duration
	Keys            Keys
	// Log gets the reports of each request, nil drops them.
	Log *slog.Logger
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// Result is the answer to a request, what to log of it, and the snapshot of
// the configuration it was decided on: the pages render its flows.
type Result struct {
	Response Response
	Reports  []Report
	Config   *store.Snapshot
}

// maxRounds bounds the rounds of one request: a read, the calls (two to
// Hydra and a webhook at most), a re-read, a replay.
const maxRounds = 16

// Handle runs the transition of ev to its end. A write that conflicts is
// replayed once on the flow read again, with the answers already obtained,
// then gives E1007 (ECR-1, ECR-2); a write of unknown outcome is read again
// before deciding (ECR-5); a store that fails gives E1000 (ECR-7).
func (o *Orchestrator) Handle(ctx context.Context, ev Event) Result {
	in := Input{Event: ev, Env: o.env()}
	var (
		key     string
		version uint64
		read    []byte // as read: a write of unknown outcome compares to it
		replay  = true
		reports []Report
	)
	load := func() error {
		data, v, err := o.Store.Get(ctx, key)
		switch {
		case errors.Is(err, state.ErrNotFound):
			in.Flow, version, read = nil, 0, nil
			return nil
		case err != nil:
			return err
		}
		f, err := Decode(data)
		if err != nil {
			return err
		}
		in.Flow, version, read = f, v, data
		return nil
	}
	fail := func(err error) Result {
		out := (&run{Input: in}).surface().fail(E1000)
		return o.result(ctx, in, out, append(reports, Report{Event: "state.error", Detail: err.Error(), Sentry: true}))
	}
	for range maxRounds {
		out := Decide(in)
		switch {
		case out.Load != "":
			key, in.Loaded = Key(out.Load), true
			if err := load(); err != nil {
				return fail(err)
			}
			continue
		case out.Reread:
			in.Reread = true
			if err := load(); err != nil {
				return fail(err)
			}
			continue
		case out.Call != nil:
			reports = append(reports, o.call(ctx, *out.Call, &in.Answers)...)
			continue
		case out.Write == nil:
			return o.result(ctx, in, out, reports)
		}

		data, err := Encode(out.Write)
		if err != nil {
			return fail(err)
		}
		ttl := time.UnixMilli(out.Write.HydraExpiresAt).Sub(o.now())
		if ttl <= 0 {
			// ECR-8: L ended at Hydra during the calls; decided again at this
			// time, the flow is absent.
			in.Env.Now = o.now()
			continue
		}
		err = o.Store.Put(ctx, key, data, ttl, version)
		switch {
		case err == nil:
			return o.result(ctx, in, out, reports)
		case errors.Is(err, state.ErrConflict):
		case errors.Is(err, state.ErrClosed), errors.Is(err, state.ErrNoTTL), ctx.Err() != nil:
			return fail(err)
		default:
			// ECR-5: written or not, read again before deciding.
			before, at := read, version
			if err := load(); err != nil {
				return fail(err)
			}
			switch {
			case bytes.Equal(read, data):
				return o.result(ctx, in, out, reports)
			case version == at && bytes.Equal(read, before) && replay:
				// Not written: written once again, as the replay, with the TTL
				// left now (ECR-8 when hx passed meanwhile).
				replay = false
				reports = append(reports, Report{Event: "state.conflict", Detail: "write of unknown outcome, written again"})
				if ttl = time.UnixMilli(out.Write.HydraExpiresAt).Sub(o.now()); ttl <= 0 {
					in.Env.Now = o.now()
					continue
				}
				switch err := o.Store.Put(ctx, key, data, ttl, version); {
				case err == nil:
					return o.result(ctx, in, out, reports)
				case errors.Is(err, state.ErrClosed), errors.Is(err, state.ErrNoTTL), ctx.Err() != nil:
					return fail(err) // ECR-7, as on the first write
				case !errors.Is(err, state.ErrConflict):
					// Of unknown outcome again: written if the bytes are.
					if err := load(); err != nil {
						return fail(err)
					}
					if bytes.Equal(read, data) {
						return o.result(ctx, in, out, reports)
					}
				}
				return o.result(ctx, in, in.surface(E1007), append(reports, Report{Event: "state.conflict", Detail: "write failed twice", Sentry: true}))
			}
		}
		// A conflict (ECR-1, ECR-6), or another value read after an unknown
		// outcome: the transition is replayed once on the flow read again.
		if !replay {
			return o.result(ctx, in, in.surface(E1007), append(reports, Report{Event: "state.conflict", Detail: "replayed", Sentry: true}))
		}
		replay = false
		reports = append(reports, Report{Event: "state.conflict", Detail: "replay"})
		if errors.Is(err, state.ErrConflict) {
			if err := load(); err != nil {
				return fail(err)
			}
		}
	}
	return o.result(ctx, in, in.surface(E1000), append(reports, Report{Event: "flow.error", Detail: "no outcome", Sentry: true}))
}

// surface answers code in the forms of the event.
func (in Input) surface(code Code) Outcome {
	return (&run{Input: in}).surface().fail(code)
}

// result logs the reports in the request's context, which gives them its
// trace id and route, with the surface of the event: the trace id of an
// error the app or the page shows leads to its cause.
func (o *Orchestrator) result(ctx context.Context, in Input, out Outcome, reports []Report) Result {
	reports = append(reports, out.Reports...)
	if o.Log != nil {
		surface := "front"
		if _, ok := in.Event.(AppCall); ok {
			surface = "emulated"
		}
		for _, r := range reports {
			level := slog.LevelInfo
			switch {
			case r.Sentry:
				level = slog.LevelError
			case r.Event == "challenge.invalid", r.Event == "security.ip_rejected", r.Event == "config.warning", r.Event == "hydra.decrypt_fallback", r.Audit:
				level = slog.LevelWarn
			}
			o.Log.Log(ctx, level, r.Event, "surface", surface, "detail", r.Detail, "audit", r.Audit)
		}
	}
	return Result{Response: out.Response, Reports: reports, Config: in.Env.Config}
}

// call makes a call a transition asked for, its answer kept for the request,
// and returns what a read reports (DEC-4 to DEC-6).
func (o *Orchestrator) call(ctx context.Context, c Call, a *Answers) []Report {
	done := func(to string, err error) *Done { return &Done{Call: c, RedirectTo: to, Err: err} }
	switch c.Op {
	case GetLogin:
		read := o.Source.LoginRequest(ctx, c.Challenge)
		a.Login = &read
		return read.Reports
	case AcceptLogin:
		a.Accept = done(o.Hydra.AcceptLogin(ctx, c.Challenge, c.AcceptLogin))
	case RejectLogin:
		a.Reject = done(o.Hydra.RejectLogin(ctx, c.Challenge, c.Reject))
	case GetConsent:
		read := o.Source.ConsentRequest(ctx, c.Challenge)
		a.Consent = &read
		return read.Reports
	case AcceptConsent:
		a.ConsentAccept = done(o.Hydra.AcceptConsent(ctx, c.Challenge, c.AcceptConsent))
	case RejectConsent:
		a.ConsentReject = done(o.Hydra.RejectConsent(ctx, c.Challenge, c.Reject))
	case LoginHook:
		h := o.Webhooks.Login(ctx, c)
		a.LoginHook = &h
	case ConsentHook:
		h := o.Webhooks.Consent(ctx, c)
		a.ConsentHook = &h
	}
	return nil
}

func (o *Orchestrator) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// env is the environment of one request: the snapshot of the moment, and
// what it may draw, a generation on 32 bits (Q9) and a CSRF value.
func (o *Orchestrator) env() Env {
	var b [4 + 32]byte
	_, _ = rand.Read(b[:]) // crypto/rand never fails
	return Env{
		Config:          o.Config.Snapshot(),
		BaseURL:         o.BaseURL,
		LoginConsentTTL: o.LoginConsentTTL,
		Keys:            o.Keys,
		Now:             o.now(),
		Draw:            Draw{Gen0: int64(binary.BigEndian.Uint32(b[:4])), CSRF: hex.EncodeToString(b[4:])},
	}
}
