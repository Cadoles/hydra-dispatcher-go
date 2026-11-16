package flow

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/loglevel"
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
	LogoutRequest(ctx context.Context, challenge string) (*ory.OAuth2LogoutRequest, error)
	AcceptLogout(ctx context.Context, challenge string) (string, error)
	RejectLogout(ctx context.Context, challenge string) error
	RevokeLoginSession(ctx context.Context, sid string) error
}

// Webhooks call the accept webhooks, with what the call would send to Hydra.
type Webhooks interface {
	Login(ctx context.Context, call Call) LoginHookAnswer
	Consent(ctx context.Context, call Call) ConsentHookAnswer
}

// StubWebhooks change nothing, for a test without webhooks to call.
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
	// PropagateWithoutRecord is logout.propagate_without_record.
	PropagateWithoutRecord string
	// StrictClaims is consent.claims_filter strict.
	StrictClaims bool
	// Log gets the reports of each request, nil drops them.
	Log *slog.Logger
	// LogSample thins what a client or a clock can make endless: nil keeps every line.
	LogSample *httpx.Sampler
	// Observers watch what each request decided, once its lines are logged.
	Observers []Observer
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

// slowAbandon is how long a call must have waited for its abandon to say something of
// Hydra or a webhook: a browser closed at once stays at the info level, a proxy's timeout
// during a call that hangs does not (Q67, Q72).
const slowAbandon = time.Second

// maxRounds bounds the rounds of one request: a read, the calls (two to
// Hydra and a webhook at most), a re-read, a replay.
const maxRounds = 16

// Handle runs the transition of ev to its end. A write that conflicts is
// replayed once on the flow read again, with the answers already obtained,
// then gives E1007 (ECR-1, ECR-2); a write of unknown outcome is read again
// before deciding (ECR-5); a store that fails gives E1000 (ECR-7). A write
// that only guards against a return, after the accept of a skip, keeps its
// answer when it stays of unknown outcome or the store fails (SKP-8): E1000
// would make the browser reload, and Hydra accept L again. Where the logout goes
// on without the store, the outcome gives the answer of a failure, second
// conflict included (DEP-6, SUI-3).
func (o *Orchestrator) Handle(ctx context.Context, ev Event) Result {
	in := Input{Event: ev, Env: o.env()}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		in.Env.Trace = sc.TraceID().String() + "-" + sc.SpanID().String()
	}
	var (
		key     string
		logout  bool
		version uint64
		read    []byte // as read: a write of unknown outcome compares to it
		replay  = true
		reports []Report
	)
	load := func() error {
		data, v, err := o.Store.Get(ctx, key)
		switch {
		case errors.Is(err, state.ErrNotFound):
			in.Flow, in.Logout, version, read = nil, nil, 0, nil
			return nil
		case err != nil:
			return err
		}
		if logout {
			r, err := DecodeLogout(data)
			if err != nil {
				return err
			}
			in.Logout, version, read = r, v, data
			return nil
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
	// failWrite is fail for the read or the write of out: its own answer when
	// the write only guards (SKP-8), the one it gives for a failure (DEP-6, SUI-3).
	failWrite := func(out Outcome, err error) Result {
		failed := Report{Event: "state.error", Detail: err.Error(), Sentry: true}
		switch {
		case out.Failed != nil:
			return o.result(ctx, in, *out.Failed, append(reports, failed))
		case out.Guard:
			return o.result(ctx, in, out, append(reports, failed))
		}
		return fail(err)
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
		case out.LoadLogout != "":
			key, logout, in.Loaded = LogoutKey(out.LoadLogout), true, true
			if err := load(); err != nil {
				return failWrite(out, err)
			}
			continue
		case out.Reread:
			in.Reread = true
			if err := load(); err != nil {
				return fail(err)
			}
			continue
		case out.Call != nil:
			reports = append(reports, o.call(scoped(ctx, in, nil), *out.Call, &in.Answers)...)
			continue
		case out.Write == nil && out.WriteLogout == nil:
			return o.result(ctx, in, out, reports)
		}

		// The language the browser chose goes with the flow it writes.
		if l := chosenLocale(ev); l != "" && out.Write != nil {
			out.Write.Locale = l
		}
		data, ttlAt, err := out.written()
		if err != nil {
			return fail(err)
		}
		ttl := ttlAt(o.now())
		if ttl <= 0 {
			// ECR-8: L ended at Hydra during the calls; decided again at this
			// time, the flow is absent. Of a record, the transition answers for
			// a TTL gone (DEP-7, LEM-11, SUI-4).
			in.Env.Now = o.now()
			continue
		}
		err = o.Store.Put(ctx, key, data, ttl, version)
		switch {
		case err == nil:
			return o.result(ctx, in, out, reports)
		case errors.Is(err, state.ErrConflict):
		case errors.Is(err, state.ErrClosed), errors.Is(err, state.ErrNoTTL), ctx.Err() != nil:
			return failWrite(out, err)
		default:
			// ECR-5: written or not, read again before deciding.
			before, at := read, version
			if err := load(); err != nil {
				return failWrite(out, err)
			}
			switch {
			case bytes.Equal(read, data):
				return o.result(ctx, in, out, reports)
			case version == at && bytes.Equal(read, before) && replay:
				// Not written: written once again, as the replay, with the TTL
				// left now (ECR-8 when hx passed meanwhile).
				replay = false
				reports = append(reports, Report{Event: "state.conflict", Detail: "write of unknown outcome, written again"})
				if ttl = ttlAt(o.now()); ttl <= 0 {
					in.Env.Now = o.now()
					continue
				}
				switch err := o.Store.Put(ctx, key, data, ttl, version); {
				case err == nil:
					return o.result(ctx, in, out, reports)
				case errors.Is(err, state.ErrClosed), errors.Is(err, state.ErrNoTTL), ctx.Err() != nil:
					return failWrite(out, err) // ECR-7, as on the first write
				case !errors.Is(err, state.ErrConflict):
					// Of unknown outcome again: written if the bytes are.
					if err := load(); err != nil {
						return failWrite(out, err)
					}
					if bytes.Equal(read, data) {
						return o.result(ctx, in, out, reports)
					}
					if out.Guard || out.Failed != nil {
						return failWrite(out, errors.New("write of unknown outcome, twice"))
					}
				case out.Guard || out.Failed != nil:
					// A concurrent load wrote since the read: the accept of a
					// skip was made, its answer stands (SKP-8, revue R21).
					return failWrite(out, err)
				}
				return o.result(ctx, in, in.surface(E1007), append(reports, Report{Event: "state.conflict", Detail: "write failed twice", Sentry: true}))
			}
		}
		// A conflict (ECR-1, ECR-6), or another value read after an unknown
		// outcome: the transition is replayed once on the flow read again.
		if !replay {
			if out.Failed != nil {
				return failWrite(out, errors.New("write failed twice")) // DEP-6, SUI-3
			}
			return o.result(ctx, in, in.surface(E1007), append(reports, Report{Event: "state.conflict", Detail: "replayed", Sentry: true}))
		}
		replay = false
		reports = append(reports, Report{Event: "state.conflict", Detail: "replay"})
		if errors.Is(err, state.ErrConflict) {
			if err := load(); err != nil {
				return failWrite(out, err)
			}
		}
	}
	return o.result(ctx, in, in.surface(E1000), append(reports, Report{Event: "flow.error", Detail: "no outcome", Sentry: true}))
}

// written returns what an outcome writes, and its TTL at a given time.
func (o Outcome) written() ([]byte, func(time.Time) time.Duration, error) {
	if r := o.WriteLogout; r != nil {
		data, err := r.encode()
		return data, r.TTL, err
	}
	data, err := Encode(o.Write)
	return data, func(now time.Time) time.Duration { return time.UnixMilli(o.Write.HydraExpiresAt).Sub(now) }, err
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
	reports = append(reports, requestFailed(in.Answers, reports)...)
	surface := "front"
	if _, ok := in.Event.(AppCall); ok {
		surface = "emulated"
	}
	ctx = scoped(ctx, in, &out)
	if o.Log != nil {
		o.transition(ctx, in, out)
		for _, r := range reports {
			if r.Debug {
				o.debug(ctx, r)
				continue
			}
			if !o.sampled(ctx, r.Event) {
				continue
			}
			level := slog.LevelInfo
			switch {
			case r.Event == "logout.started", r.Event == "logout.session_revoked":
				// Info, as the catalogue has them, in the audit log too.
			case r.Sentry, r.Event == "hydra.request_failed", r.Event == "webhook.failed":
				// The last two without Sentry: flow.error, of the same request, goes.
				level = slog.LevelError
			case (r.Event == "hydra.request_abandoned" || r.Event == "webhook.abandoned") && r.Elapsed >= slowAbandon,
				r.Event == "flow.rejected" && r.Detail == ReasonSkipSubject.String()+":"+checkWebhook:
				level = slog.LevelWarn
			case r.Event == "challenge.invalid", r.Event == "security.ip_rejected", r.Event == "config.warning", r.Event == "hydra.decrypt_fallback", r.Event == "hydra.clock_skew", r.Audit:
				level = slog.LevelWarn
			}
			args := []any{"surface", surface, "detail", r.Detail, "audit", r.Audit}
			if r.Kind != "" {
				args = append(args, "kind", r.Kind)
			}
			if r.Reason != "" {
				args = append(args, "reason", r.Reason)
			}
			if r.App != "" {
				args = append(args, "app", r.App, "result", r.Result)
			}
			if r.RP != nil {
				args = append(args, "rp_initiated", *r.RP)
			}
			if r.Event == "logout.started" {
				args = append(args, "apps", r.Apps, "again", r.Again)
			}
			if r.Event == "hydra.request_failed" {
				args = append(args, "operation", r.Operation, "status", r.Status)
			}
			if r.Event == "hydra.request_abandoned" {
				args = append(args, "operation", r.Operation, "duration_ms", r.Elapsed.Milliseconds())
			}
			if r.Event == "webhook.failed" {
				args = append(args, "host", r.Host, "status", r.Status, "duration_ms", r.Elapsed.Milliseconds())
			}
			if r.Event == "webhook.abandoned" {
				args = append(args, "host", r.Host, "duration_ms", r.Elapsed.Milliseconds())
			}
			if r.Event == "consent.resubmitted" {
				args = append(args, "result", r.Result)
			}
			o.Log.Log(ctx, level, r.Event, args...)
		}
	}
	if len(o.Observers) > 0 {
		after := in.Flow
		if out.Write != nil {
			after = out.Write
		}
		seen := Observation{Event: in.Event, Surface: surface, Before: in.Flow, After: after, Response: out.Response,
			Reports: reports, Answers: in.Answers, Validations: in.Answers.validations(reports), Config: in.Env.Config, Now: o.now()}
		for _, w := range o.Observers {
			o.observe(ctx, w, seen)
		}
	}
	return Result{Response: out.Response, Reports: reports, Config: in.Env.Config}
}

// scoped is ctx with the flow of in and the app of its current step, those of
// out when it writes another (Q132): a window of debug in their scope lets the
// lines of the request pass, and the lines of debug of its calls name them.
func scoped(ctx context.Context, in Input, out *Outcome) context.Context {
	f := in.Flow
	if out != nil && out.Write != nil {
		f = out.Write
	}
	if f == nil {
		return ctx
	}
	app := ""
	if f.Current >= 1 && f.Current <= len(f.Steps) {
		app = f.Steps[f.Current-1].App
	}
	return loglevel.WithScope(ctx, f.FlowID, app)
}

// eventNames name the events in flow.transition.
var eventNames = map[string]string{"flow.Entry": "entry", "flow.Choose": "choice", "flow.Loop": "loop", "flow.Consent": "consent",
	"flow.AppCall": "app_call", "flow.Logout": "logout", "flow.LogoutNext": "logout_next"}

// appOps name the endpoints of the emulated API in flow.transition.
var appOps = map[AppOp]string{AppGetLogin: "get_login", AppAcceptLogin: "accept_login", AppRejectLogin: "reject_login",
	AppGetConsent: "get_consent", AppAcceptConsent: "accept_consent", AppRejectConsent: "reject_consent",
	AppGetLogout: "get_logout", AppAcceptLogout: "accept_logout", AppRejectLogout: "reject_logout"}

// outcomeNames name the answers in flow.transition.
var outcomeNames = map[ResponseKind]string{Redirect: "redirect", ChoicePage: "choice_page", ConsentPage: "consent_page", ErrorPage: "error_page",
	AppJSON: "app_json", LogoutPage: "logout_page"}

// transition writes flow.transition at the level debug (Q132): the event, the
// step of the flow before and after it, what it answered; names and numbers,
// never a challenge nor a claim.
func (o *Orchestrator) transition(ctx context.Context, in Input, out Outcome) {
	if !o.Log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	before, after := 0, 0
	if in.Flow != nil {
		before, after = in.Flow.Current, in.Flow.Current
	}
	if out.Write != nil {
		after = out.Write.Current
	}
	args := []any{"event", eventNames[fmt.Sprintf("%T", in.Event)], "step_before", before, "step_after", after, "outcome", outcomeNames[out.Response.Kind]}
	if call, ok := in.Event.(AppCall); ok {
		args = append(args, "operation", appOps[call.Op])
	}
	switch out.Response.Kind {
	case ErrorPage:
		args = append(args, "error_code", string(out.Response.Code))
	case AppJSON:
		args = append(args, "status", out.Response.Status)
	}
	o.Log.DebugContext(ctx, "flow.transition", append(args, loglevel.ScopeAttrs(ctx)...)...)
}

// debug writes a line of the level debug of the engine (Q132): the names of
// claims it holds, the flow and the app of its request; that of an app reading
// its request is its current step's.
func (o *Orchestrator) debug(ctx context.Context, r Report) {
	if !o.Log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	var args []any
	if n := r.Names; n != nil {
		for _, f := range []struct {
			key   string
			names []string
		}{{"id_token", n.IDToken}, {"access_token", n.AccessToken}, {"claims", n.Claims}, {"dropped", n.Dropped}, {"conflicts", n.Conflicts}} {
			if f.names != nil {
				args = append(args, f.key, f.names)
			}
		}
	}
	o.Log.DebugContext(ctx, r.Event, append(args, loglevel.ScopeAttrs(ctx)...)...)
}

// observe gives seen to w. A panic of w is caught and logged, observer.panic, which goes
// to Sentry by its name, and the answer goes all the same (revue R29): it gave 500 after
// an accept, which a reload then resumed without a second one. The other observers still
// see the request.
func (o *Orchestrator) observe(ctx context.Context, w Observer, seen Observation) {
	defer func() {
		if p := recover(); p != nil && o.Log != nil {
			o.Log.ErrorContext(ctx, "observer.panic", "observer", fmt.Sprintf("%T", w), "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	w.Observe(ctx, seen)
}

// sampled tells whether a line goes: by client for what a client makes endless
// (challenge.invalid, security.ip_rejected, as the catalogue says), by instance for a
// clock that drifts, the same for everyone (hydra.clock_skew). The metrics, the audit and
// the limiter read the reports all the same.
func (o *Orchestrator) sampled(ctx context.Context, event string) bool {
	switch event {
	case "challenge.invalid", "security.ip_rejected":
		return o.LogSample.AllowClient(ctx, event)
	case "hydra.clock_skew":
		return o.LogSample.Allow(event)
	}
	return true
}

// requestFailed reports the calls of this request that Hydra failed
// (hydra.request_failed): what an exploitant needs to understand an E1004 or an
// E1007, which only name their code. Hydra unavailable, whatever the page; any other
// answer when the page says so, a 409 of 2.1 being read again before it concludes, a
// DELETE of SKP-12 answered 404 (Q67). Not a challenge unknown or expired under another
// page, an expected answer that challenge.invalid reports; nor a call that max_in_flight
// did not make. A call whose client closed its connection is another event,
// hydra.request_abandoned, at the info level, warn past slowAbandon (Q64, Q67).
func requestFailed(a Answers, reports []Report) []Report {
	failedPage := slices.ContainsFunc(reports, func(r Report) bool {
		return r.Event == "flow.error" && (r.Detail == string(E1004) || r.Detail == string(E1007))
	})
	var out []Report
	for _, err := range a.failures() {
		switch class := classify(err); {
		case class == unavailable && errors.Is(err, context.Canceled):
			op, _, _ := hydra.Failure(err)
			out = append(out, Report{Event: "hydra.request_abandoned", Operation: op, Elapsed: hydra.Elapsed(err)})
		case class == unavailable && !errors.Is(err, hydra.ErrOverloaded),
			class != unavailable && failedPage:
			op, status, cause := hydra.Failure(err)
			out = append(out, Report{Event: "hydra.request_failed", Operation: op, Status: status, Detail: cause})
		}
	}
	return out
}

// failures are the errors of the calls made during the request.
func (a Answers) failures() []error {
	var errs []error
	if a.Login != nil && a.Login.Err != nil {
		errs = append(errs, a.Login.Err)
	}
	if a.Consent != nil && a.Consent.Err != nil {
		errs = append(errs, a.Consent.Err)
	}
	if a.Logout != nil && a.Logout.Err != nil {
		errs = append(errs, a.Logout.Err)
	}
	for _, d := range []*Done{a.Accept, a.Reject, a.ConsentAccept, a.ConsentReject, a.LogoutAccept, a.LogoutReject, a.Revoke} {
		if d != nil && d.Err != nil {
			errs = append(errs, d.Err)
		}
	}
	return errs
}

// call makes a call a transition asked for, its answer kept for the request,
// and returns what a read reports (DEC-5, DEC-6).
func (o *Orchestrator) call(ctx context.Context, c Call, a *Answers) []Report {
	ctx, span := otel.Tracer("forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow").Start(ctx, callNames[c.Op], trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	done := func(to string, err error) *Done {
		if err != nil {
			span.SetStatus(codes.Error, "")
		}
		return &Done{Call: c, RedirectTo: to, Err: err}
	}
	switch c.Op {
	case GetLogin:
		read := o.Source.LoginRequest(ctx, c.Challenge)
		a.Login = &read
		if read.Decrypted {
			span.SetName(spanDecrypt)
		}
		return read.Reports
	case AcceptLogin:
		a.Accept = done(o.Hydra.AcceptLogin(ctx, c.Challenge, c.AcceptLogin))
	case RejectLogin:
		a.Reject = done(o.Hydra.RejectLogin(ctx, c.Challenge, c.Reject))
	case GetConsent:
		read := o.Source.ConsentRequest(ctx, c.Challenge)
		a.Consent = &read
		if read.Decrypted {
			span.SetName(spanDecrypt)
		}
		return read.Reports
	case AcceptConsent:
		a.ConsentAccept = done(o.Hydra.AcceptConsent(ctx, c.Challenge, c.AcceptConsent))
	case RejectConsent:
		a.ConsentReject = done(o.Hydra.RejectConsent(ctx, c.Challenge, c.Reject))
	case LoginHook:
		h := o.Webhooks.Login(ctx, c)
		a.LoginHook = &h
		span.SetAttributes(attribute.String("dispatcher.webhook.kind", hookLogin))
		if h.Err != nil {
			span.SetStatus(codes.Error, "")
		}
	case ConsentHook:
		h := o.Webhooks.Consent(ctx, c)
		a.ConsentHook = &h
		span.SetAttributes(attribute.String("dispatcher.webhook.kind", hookConsent))
		if h.Err != nil {
			span.SetStatus(codes.Error, "")
		}
	case GetLogout:
		r, err := o.Hydra.LogoutRequest(ctx, c.Challenge)
		a.Logout = &LogoutRead{Request: r, Err: err}
	case AcceptLogout:
		a.LogoutAccept = done(o.Hydra.AcceptLogout(ctx, c.Challenge))
	case RejectLogout:
		a.LogoutReject = done("", o.Hydra.RejectLogout(ctx, c.Challenge))
	case RevokeSession:
		a.Revoke = done("", o.Hydra.RevokeLoginSession(ctx, c.Challenge))
	}
	return nil
}

// spanDecrypt names the read of a challenge that needed no call.
const spanDecrypt = "hydra.challenge.decrypt"

// callNames are the spans of the calls, by name alone: no challenge nor body.
var callNames = map[Op]string{
	GetLogin: "hydra.login_request", AcceptLogin: "hydra.accept_login", RejectLogin: "hydra.reject_login",
	GetConsent: "hydra.consent_request", AcceptConsent: "hydra.accept_consent", RejectConsent: "hydra.reject_consent",
	LoginHook: "webhook.call", ConsentHook: "webhook.call",
	GetLogout: "hydra.logout_request", AcceptLogout: "hydra.accept_logout", RejectLogout: "hydra.reject_logout", RevokeSession: "hydra.revoke_session",
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
		Config:                 o.Config.Snapshot(),
		BaseURL:                o.BaseURL,
		LoginConsentTTL:        o.LoginConsentTTL,
		Keys:                   o.Keys,
		PropagateWithoutRecord: o.PropagateWithoutRecord,
		StrictClaims:           o.StrictClaims,
		Now:                    o.now(),
		Draw:                   Draw{Gen0: int64(binary.BigEndian.Uint32(b[:4])), CSRF: hex.EncodeToString(b[4:])},
	}
}

// chosenLocale is the language a browser's request carried, chosen on the
// dispatcher's pages: "" for an event of an app or of a logout.
func chosenLocale(ev Event) string {
	switch e := ev.(type) {
	case Entry:
		return e.Locale
	case Choose:
		return e.Locale
	case Loop:
		return e.Locale
	}
	return ""
}
