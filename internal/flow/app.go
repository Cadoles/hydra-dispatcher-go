package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// AppOp is an endpoint of the emulated API, on the v2 paths and their v1
// aliases (P4).
type AppOp int

const (
	AppGetLogin AppOp = iota + 1
	AppAcceptLogin
	AppRejectLogin
	AppGetConsent
	AppAcceptConsent
	AppRejectConsent
)

// kind is the kind of the challenges the endpoint takes.
func (o AppOp) kind() Kind {
	if o <= AppRejectLogin {
		return KindLogin
	}
	return KindConsent
}

func (o AppOp) get() bool { return o == AppGetLogin || o == AppGetConsent }

// AppCall is a call of a login app to the emulated API: the endpoint, the
// step challenge, the body of a PUT, and whether the caller is the app
// given, as the handler identifies it by its sources (nil refuses all). The
// app is the one of the snapshot the transition decides on: the caller is
// never identified on another (revue R12).
type AppCall struct {
	Op        AppOp
	Challenge string
	Caller    func(app store.App) bool
	Body      json.RawMessage
}

func (AppCall) event() {}

// AppError is an error of the emulated API, in Symfony's form (T5); P4 adds
// the trace_id.
type AppError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	StatusCode  int    `json:"status_code"`
}

const (
	missingSession     = "missing_session_error"
	missingSessionText = "Could not find session metadata in cache"
	// forbidden is Hydra's error for a request it does not allow, the
	// refusal of an app outside its sources (EMU-4) as of an address outside
	// the allowlist (P4). Symfony answered its allowlist's refusal as any
	// error, 500 server_error (capture 26).
	forbidden     = "request_forbidden"
	forbiddenText = "The request is not allowed."
)

func appError(status int, name, description string) Outcome {
	return Outcome{Response: Response{Kind: AppJSON, Status: status, Body: AppError{name, description, status}}}
}

// invalidBody is the answer to a body Hydra would refuse (EMU-15).
func invalidBody() Outcome {
	return appError(http.StatusBadRequest, "invalid_request", string(E1001))
}

// appCall is a call of the emulated API (EMU): the common checks of the
// challenge, then the step of the challenge against the current one.
func (r *run) appCall(ev AppCall) Outcome {
	s := r.surface()
	ref, ok := ChallengeRef(ev.Challenge)
	if !ok {
		return appError(http.StatusNotFound, "invalid_request", "request_failed") // EMU-1
	}
	if !r.Loaded {
		return Outcome{Load: ref}
	}
	f := r.Flow
	if f.StateAt(r.Env.Now) == Absent {
		return s.absent() // EMU-2, EXP-1
	}
	caller := func(id string) bool {
		app, ok := r.Env.Config.App(id)
		return ok && ev.Caller != nil && ev.Caller(app)
	}
	check := r.Env.Keys.Verify(f, ev.Challenge, ev.Op.kind(), r.Env.appIDs(), caller, r.Env.Now)
	switch check.Verdict {
	case ChallengeForged:
		// EMU-3 (Q17): an unknown challenge, for the failure limiter (P11).
		return s.absent().report(forged())
	case ChallengeOtherApp:
		return appError(http.StatusForbidden, forbidden, forbiddenText).report(Report{Event: "security.ip_rejected", Detail: "emulated: app outside its sources"}) // EMU-4
	case ChallengeFinished:
		return s.ended(f) // EMU-5
	case ChallengeExpired:
		return r.expire(f).report(expiredChallenge()) // EMU-6
	case ChallengeStale:
		return s.redirect(s.loop).report(Report{Event: "challenge.invalid", Detail: "stale_generation"}) // EMU-7
	}

	k, step := check.Step, f.Steps[check.Step-1]
	// open: the challenge's step is the current one, and its part of the
	// endpoint is not accepted yet; otherwise the first answer stands.
	current := k == f.Current && f.HydraRedirect == ""
	switch ev.Op {
	case AppGetLogin:
		if !current || step.LoginOK {
			return s.redirect(s.loop) // EMU-9 (RA2, Q4)
		}
		return s.served(f.LoginRequestFor(r.Env, ref, k)) // EMU-8
	case AppAcceptLogin:
		body, ctx, err := loginAcceptOf(ev.Body)
		switch {
		case err != nil:
			return invalidBody() // EMU-15
		case current && !step.LoginOK:
			return r.loginAccepted(ref, f, k, body, ctx) // EMU-10, EMU-11, EMU-12
		case f.HydraRedirect != "" || body.Subject == step.Subject:
			return s.redirect(s.loop) // EMU-13 (T4, Q5): the first accept stands
		}
		return r.subjectMismatch(f) // EMU-14 (Q5, Q27)
	case AppRejectLogin:
		if !current || step.LoginOK {
			return s.redirect(s.loop) // EMU-17 (Q4, Q25)
		}
		return r.appReject(f, ev.Body) // EMU-16 (M8, T3)
	}

	// The consent of a step. Its accept's body is checked first, as the
	// login's: a second accept with an invalid body gets 400 (EMU-15).
	var idt, act, ctx Object
	if ev.Op == AppAcceptConsent {
		var err error
		if idt, act, ctx, err = consentAcceptOf(ev.Body); err != nil {
			return invalidBody() // EMU-15
		}
	}
	switch done := !current || step.ConsentOK; {
	case done:
		return s.redirect(s.loop) // EMU-19, EMU-22, EMU-24
	case !step.LoginOK:
		return s.redirect(s.loop) // EMU-20: cC(k) is only issued after lok
	}
	switch ev.Op {
	case AppGetConsent:
		return s.served(f.ConsentRequestFor(r.Env, ref, k)) // EMU-18
	case AppAcceptConsent:
		g := f.clone()
		g.Steps[k-1].ConsentOK = true
		g.Steps[k-1].IDToken, g.Steps[k-1].AccessToken, g.Steps[k-1].ConsentContext = idt, act, ctx
		return s.redirect(s.loop).writing(g).report(Report{Event: "step.consent_accepted", Detail: step.App}) // EMU-21
	}
	return r.appReject(f, ev.Body) // EMU-23: a reject of the login (M8)
}

// served answers with a login or consent request served to an app (EMU-8,
// EMU-18): its app gone from the snapshot is E1005, as on the pages (EMU-28,
// BCL-11, Q21), its options with it; a stored flow it cannot read, E1000.
func (s surface) served(req any, err error) Outcome {
	switch {
	case errors.Is(err, errAppGone):
		return s.fail(E1005)
	case err != nil:
		return s.fail(E1000)
	}
	return Outcome{Response: Response{Kind: AppJSON, Status: http.StatusOK, Body: req}}
}

// loginAccepted records the login accept of the current step k (EMU-10,
// EMU-11), once its subject passes the step's subject_check.
func (r *run) loginAccepted(ref string, f *Flow, k int, body ory.AcceptOAuth2LoginRequest, ctx Object) Outcome {
	s := r.surface()
	step := f.Steps[k-1]
	if k > 1 && !SubjectAllowed(step.Check, body.Subject, f.Subject, f.PreviousClaims(k)) {
		return r.subjectMismatch(f) // EMU-12
	}
	g := f.clone()
	st := &g.Steps[k-1]
	st.LoginOK, st.Subject, st.AMR, st.LoginContext = true, body.Subject, body.Amr, ctx
	st.Remember, st.RememberFor = body.Remember, body.RememberFor
	if k == 1 {
		g.Subject = body.Subject
	}
	return s.redirect(s.loop).writing(g).report(Report{Event: "step.login_accepted", Detail: step.App})
}

// subjectMismatch rejects L when an accept's subject fails the step's rule,
// or is not the one of the step's first accept (hardening 3, Q6): the app
// gets Hydra's redirect_to in 200, as for its own reject.
func (r *run) subjectMismatch(f *Flow) Outcome {
	return r.rejectLogin(f, ReasonSubject, rejection(ReasonSubject, "The subject does not match the authentication's."), r.surface().redirect).
		report(Report{Event: "step.subject_mismatch", Audit: true})
}

// appReject forwards an app's reject to Hydra as a reject of the login, its
// body as received (M8, T3) but for the members the model does not know:
// Hydra refuses them (DisallowUnknownFields, 2.1 and 2.2), which would make
// the reject an E1007, and the model would round their numbers.
func (r *run) appReject(f *Flow, data json.RawMessage) Outcome {
	var body ory.RejectOAuth2Request
	if err := strictJSON(data, &body); err != nil {
		return invalidBody()
	}
	body.AdditionalProperties = nil
	return r.rejectLogin(f, ReasonApp, body, r.surface().redirect)
}

// loginAcceptOf decodes a step's login accept: the SDK's model, strict on
// the types, its context an object or null (A9).
func loginAcceptOf(data json.RawMessage) (ory.AcceptOAuth2LoginRequest, Object, error) {
	var body ory.AcceptOAuth2LoginRequest
	if err := strictJSON(data, &body); err != nil {
		return body, nil, err
	}
	if body.Subject == "" {
		return body, nil, errors.New("no subject")
	}
	var members map[string]json.RawMessage
	_ = json.Unmarshal(data, &members) // an object, as the model shows
	ctx, ok := ObjectOf(members["context"])
	if !ok {
		return body, nil, errors.New("context is not an object")
	}
	return body, ctx, nil
}

// consentAcceptOf decodes a step's consent accept: its session's claims and
// its context, objects or null (an object null is {}).
func consentAcceptOf(data json.RawMessage) (idt, act, ctx Object, err error) {
	var body ory.AcceptOAuth2ConsentRequest
	if err := strictJSON(data, &body); err != nil {
		return nil, nil, nil, err
	}
	var members struct {
		Context json.RawMessage `json:"context"`
		Session json.RawMessage `json:"session"`
	}
	_ = json.Unmarshal(data, &members)
	var session struct {
		IDToken     json.RawMessage `json:"id_token"`
		AccessToken json.RawMessage `json:"access_token"`
	}
	if len(members.Session) > 0 && !isNull(members.Session) {
		if err := json.Unmarshal(members.Session, &session); err != nil {
			return nil, nil, nil, err
		}
	}
	var ok [3]bool
	idt, ok[0] = ObjectOf(session.IDToken)
	act, ok[1] = ObjectOf(session.AccessToken)
	ctx, ok[2] = ObjectOf(members.Context)
	if ok != [3]bool{true, true, true} {
		return nil, nil, nil, errors.New("claims or context are not objects")
	}
	return idt, act, ctx, nil
}

// strictJSON decodes one JSON object into the SDK's model, refusing what is
// not one, or what follows it: json.Valid, as a decoder's More does not see
// a closing brace or bracket after the object.
func strictJSON(data json.RawMessage, v any) error {
	if !json.Valid(data) || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("the body is not one JSON object")
	}
	return json.Unmarshal(data, v)
}
