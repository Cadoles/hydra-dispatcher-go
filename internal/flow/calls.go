package flow

import (
	"encoding/json"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// consentReplay is how long a finished flow replays the redirect_to of its
// consent to a double submission (Q13).
const consentReplay = 10 * time.Second

// rejection is the body of a reject the dispatcher sends to Hydra.
func rejection(reason Reason, description string) ory.RejectOAuth2Request {
	name := "login_required"
	switch reason {
	case ReasonUnmet:
		name = "unmet_authentication_requirements"
	case ReasonRestricted, ReasonNotOurs, ReasonUser, ReasonSubject:
		name = "access_denied"
	}
	return ory.RejectOAuth2Request{Error: ory.PtrString(name), ErrorDescription: ory.PtrString(description)}
}

// mutated tells whether the request already made an accept or a reject at
// Hydra other than op: a transition replayed on a changed flow never makes a
// second one, the first being carried over instead (ECR-4, ECR-9).
func (r *run) mutated(op Op) bool {
	a := r.Answers
	for o, d := range map[Op]*Done{AcceptLogin: a.Accept, RejectLogin: a.Reject, AcceptConsent: a.ConsentAccept, RejectConsent: a.ConsentReject} {
		if o != op && d != nil {
			return true
		}
	}
	return false
}

// blocked stands for an accept or a reject the transition would make after
// another: Decide answers with the fact of the first, when it succeeded.
func blocked() Outcome {
	return Outcome{Response: Response{Kind: ErrorPage, Code: E1007}, Reports: []Report{{Event: "state.conflict", Detail: "second mutation", Sentry: true}}}
}

// hydraFailure answers the error of an accept or a reject made on f (Q11,
// EXP-4): a request gone at Hydra finishes the flow without a rejection; a
// refusal (400, 403, 409) reads the flow again first, a concurrent request
// having perhaps moved it on or finished it, then is E1007; an unavailable
// Hydra is E1004, the flow unchanged.
func (r *run) hydraFailure(f *Flow, err error) Outcome {
	s := r.surface()
	switch classify(err) {
	case unknown, gone:
		return s.ended(f).writing(f.Reduce())
	case conflict, refused:
		if !r.Reread {
			return Outcome{Reread: true}
		}
		return s.fail(E1007)
	}
	return s.unavailable(err)
}

// rejectLogin rejects L for reason and finishes f, answering ok with Hydra's
// redirect_to.
func (r *run) rejectLogin(f *Flow, reason Reason, body ory.RejectOAuth2Request, ok func(redirectTo string) Outcome) Outcome {
	d := r.Answers.Reject
	switch {
	case d == nil && r.mutated(RejectLogin):
		return blocked()
	case d == nil:
		return Outcome{Call: &Call{Op: RejectLogin, Challenge: f.LoginChallenge, Reason: reason, Gen: f.Gen, Reject: body}}
	}
	r.use(RejectLogin)
	if err := d.err(); err != nil {
		return r.hydraFailure(f, err)
	}
	return ok(d.RedirectTo).writing(f.Reduce()).report(Report{Event: "flow.rejected", Detail: d.Call.Reason.String()})
}

// expire rejects an expired flow with login_required (M9, ENT-8, EXP-2).
func (r *run) expire(f *Flow) Outcome {
	return r.rejectLogin(f, ReasonExpired, rejection(ReasonExpired, "The authentication took too long."), r.surface().redirect)
}

// finalAccept accepts L once every step is accepted (M6, FIN): the first
// step's subject, the flow's acr and amr, the consents' context, then the
// login webhook, Hydra's skip subject checked (A7), the x_dispatcher_*
// members of the steps or the webhook dropped and x_dispatcher_ref set last
// (Q38), and the accept.
func (r *run) finalAccept(ref string, f *Flow) Outcome {
	s := r.page()
	settings := r.Env.Config.Settings
	body := ory.AcceptOAuth2LoginRequest{
		Subject:     f.Subject,
		Acr:         ory.PtrString(f.ACRNow()),
		Amr:         f.AMRNow(r.Env),
		Remember:    ory.PtrBool(settings.Remember),
		RememberFor: ory.PtrInt64(int64(settings.LoginRememberFor / time.Second)),
	}
	ctx, stop := r.loginHook(f, &body, f.ContextOf())
	if stop != nil {
		return *stop // FIN-4: flow unchanged, a reload replays the webhook
	}
	if f.Hydra.Skip && body.Subject != f.Hydra.Subject {
		return r.rejectLogin(f, ReasonSkipSubject, rejection(ReasonSkipSubject, "The subject authenticated is not the one of the Hydra session."),
			func(string) Outcome { return s.fail(E1003) })
	}
	ctx = withoutDispatcher(ctx)
	ctx[memberRef], _ = json.Marshal(ref) // a string always marshals
	body.Context = ctx

	d := r.Answers.Accept
	switch {
	case d == nil && r.mutated(AcceptLogin):
		return blocked()
	case d == nil:
		return Outcome{Call: &Call{Op: AcceptLogin, Challenge: f.LoginChallenge, Gen: f.Gen, AcceptLogin: body}}
	}
	r.use(AcceptLogin)
	if err := d.err(); err != nil {
		return r.hydraFailure(f, err)
	}
	return r.accepted(f, d)
}

// loginHook calls the login webhook with body and ctx, before the final
// accept or the accept of a skip (FIN-4, SKP-9): the members it returns
// replace those sent. A webhook that fails, or a context that is neither an
// object nor null (A9), stops the authentication: page E1006, nothing
// written nor rejected. stop is the outcome to return, nil once done.
func (r *run) loginHook(f *Flow, body *ory.AcceptOAuth2LoginRequest, ctx Object) (_ Object, stop *Outcome) {
	if r.Env.Config.Settings.LoginAcceptWebhookURL == "" {
		return ctx, nil
	}
	h := r.Answers.LoginHook
	if h == nil {
		call := *body
		call.Context = ctx
		return nil, &Outcome{Call: &Call{Op: LoginHook, Challenge: f.LoginChallenge, Gen: f.Gen, AcceptLogin: call}}
	}
	r.use(LoginHook)
	if h.Err != nil {
		out := r.page().fail(E1006)
		return nil, &out
	}
	if h.Context != nil {
		o, ok := ObjectOf(h.Context)
		if !ok {
			out := r.page().fail(E1006).report(Report{Event: "webhook.failed", Detail: "context is neither an object nor null"})
			return nil, &out
		}
		ctx = o
	}
	if h.Subject != nil {
		body.Subject = *h.Subject
	}
	if h.ACR != nil {
		body.Acr = h.ACR
	}
	if h.AMR != nil {
		body.Amr = h.AMR
	}
	if h.Remember != nil {
		body.Remember = h.Remember
	}
	if h.RememberFor != nil {
		body.RememberFor = h.RememberFor
	}
	return ctx, nil
}

// accepted carries a final accept Hydra made over to f: its redirect_to,
// and what it sent, the context, remember and remember_for included, from
// which the consent writes the remember cookie (FIN-1, Q39).
func (r *run) accepted(f *Flow, d *Done) Outcome {
	g := f.clone()
	g.HydraRedirect = d.RedirectTo
	sent := d.Call.AcceptLogin
	ctx, _ := sent.Context.(Object)
	g.Sent = &SentLogin{
		Subject:     sent.Subject,
		ACR:         sent.GetAcr(),
		AMR:         nonNil(sent.Amr),
		Context:     withoutDispatcher(ctx),
		Remember:    sent.GetRemember(),
		RememberFor: sent.GetRememberFor(),
	}
	return r.page().redirect(d.RedirectTo).writing(g).report(Report{Event: "hydra.login_accepted", Detail: g.Sent.ACR})
}

// consentBody is the consent accept of f for req (M7): the scopes and
// audiences requested, the steps' claims merged (A2), the consent's
// remember.
func (r *run) consentBody(f *Flow, req *ory.OAuth2ConsentRequest) ory.AcceptOAuth2ConsentRequest {
	settings := r.Env.Config.Settings
	var idt, act []Object
	for _, s := range f.Steps {
		idt, act = append(idt, s.IDToken), append(act, s.AccessToken)
	}
	return ory.AcceptOAuth2ConsentRequest{
		GrantScope:               nonNil(req.RequestedScope),
		GrantAccessTokenAudience: nonNil(req.RequestedAccessTokenAudience),
		Remember:                 ory.PtrBool(settings.Remember),
		RememberFor:              ory.PtrInt64(int64(settings.ConsentRememberFor / time.Second)),
		Session: &ory.AcceptOAuth2ConsentRequestSession{
			IdToken:     MergeClaims(idt...),
			AccessToken: MergeClaims(act...),
		},
	}
}

// acceptConsent accepts the consent C of the accepted flow f (CST-12,
// CST-14): the consent webhook, then the accept; f finishes, keeping the
// redirect_to for a double submission (Q13).
func (r *run) acceptConsent(f *Flow, c string, req *ory.OAuth2ConsentRequest) Outcome {
	body := r.consentBody(f, req)
	if stop := r.consentHook(c, f.Gen, &body); stop != nil {
		return *stop
	}
	d := r.Answers.ConsentAccept
	switch {
	case d == nil && r.mutated(AcceptConsent):
		return blocked()
	case d == nil:
		return Outcome{Call: &Call{Op: AcceptConsent, Challenge: c, Gen: f.Gen, AcceptConsent: body}}
	}
	r.use(AcceptConsent)
	if err := d.err(); err != nil {
		return r.hydraFailure(f, err)
	}
	return r.consentDone(f, d).report(Report{Event: "hydra.consent_accepted"})
}

// consentHook calls the consent webhook with body, before a consent accept
// with a flow or without (CST-12, CST-14, SKC-1, SKC-3): the claims it
// returns replace those sent. A webhook that fails, or claims that are not
// objects, stop the authentication: page E1006, nothing written nor rejected
// (SKC-13). stop is the outcome to return, nil once done.
func (r *run) consentHook(c string, gen int64, body *ory.AcceptOAuth2ConsentRequest) (stop *Outcome) {
	if r.Env.Config.Settings.ConsentAcceptWebhookURL == "" {
		return nil
	}
	h := r.Answers.ConsentHook
	if h == nil {
		return &Outcome{Call: &Call{Op: ConsentHook, Challenge: c, Gen: gen, AcceptConsent: *body}}
	}
	r.use(ConsentHook)
	if h.Err != nil {
		out := r.page().fail(E1006)
		return &out
	}
	for raw, member := range map[*json.RawMessage]*any{&h.IDToken: &body.Session.IdToken, &h.AccessToken: &body.Session.AccessToken} {
		if *raw != nil {
			o, ok := ObjectOf(*raw)
			if !ok {
				out := r.page().fail(E1006).report(Report{Event: "webhook.failed", Detail: "claims are not an object"})
				return &out
			}
			*member = o
		}
	}
	return nil
}

// rejectConsent rejects the consent C for reason and finishes f (CST-8 to
// CST-10, CST-15), answering ok with Hydra's redirect_to; f nil is a consent
// without a flow (CST-5, SKC-4, SKC-6 to SKC-8).
func (r *run) rejectConsent(f *Flow, c string, reason Reason, body ory.RejectOAuth2Request, ok func(redirectTo string) Outcome) Outcome {
	s := r.page()
	d := r.Answers.ConsentReject
	switch {
	case d == nil && r.mutated(RejectConsent):
		return blocked()
	case d == nil:
		call := &Call{Op: RejectConsent, Challenge: c, Reason: reason, Reject: body}
		if f != nil {
			call.Gen = f.Gen
		}
		return Outcome{Call: call}
	}
	r.use(RejectConsent)
	switch {
	case d.err() != nil && f != nil:
		return r.hydraFailure(f, d.err())
	case d.err() != nil:
		// No flow to finish or read again.
		switch classify(d.err()) {
		case unknown, gone:
			return s.absent()
		case unavailable:
			return s.unavailable(d.err())
		}
		return s.fail(E1007)
	case f == nil:
		return ok(d.RedirectTo).report(Report{Event: "flow.rejected", Detail: d.Call.detail(), Audit: d.Call.Reason == ReasonNotOurs})
	}
	out, answer := r.consentDone(f, d), ok(d.RedirectTo)
	if d.Call.Reason == ReasonNotOurs {
		// Q20: the reject made is A3's, whatever the transition replayed on
		// the flow read again would answer.
		answer = s.fail(E1007)
	}
	out.Response, out.Reports = answer.Response, append(out.Reports, answer.Reports...)
	return out.report(Report{Event: "flow.rejected", Detail: d.Call.detail(), Audit: d.Call.Reason == ReasonNotOurs})
}

// consentDone finishes f after the accept or the reject of its consent,
// keeping Hydra's redirect_to and the time for a double submission (Q13);
// a reject for A3 keeps none, its redirect_to never being followed. An
// accept writes the remember cookie (WRT-1); a reject neither writes nor
// clears it.
func (r *run) consentDone(f *Flow, d *Done) Outcome {
	g := f.Reduce()
	if d.Call.Reason != ReasonNotOurs {
		g.ConsentRedirect, g.ConsentAt = d.RedirectTo, r.now()
	}
	out := r.page().redirect(d.RedirectTo).writing(g)
	if d.Call.Op == AcceptConsent {
		out.Response.Remember = r.remembered(f, d.Call.AcceptConsent)
	}
	return out
}

// unusedFact answers an accept or a reject Hydra made that the transition,
// replayed on a flow read again, did not reach (ECR-3, ECR-4, ECR-9):
// carried over to the flow unless it is finished, never a second one. The
// audit event of a reject stands either way: the reject was made. A flow
// absent is one whose hx passed between the call and its write (ECR-8),
// the engine deleting none: an expiry (EXP-1), not a conflict, which Sentry
// does not get (revue R19).
func (r *run) unusedFact() (Outcome, bool) {
	a, s, f := r.Answers, r.surface(), r.Flow
	conflict := Report{Event: "state.conflict", Detail: "finished meanwhile", Sentry: true}
	absent := f == nil || f.StateAt(r.Env.Now) == Absent
	switch {
	case a.Accept.ok() && !r.used[AcceptLogin]:
		switch {
		case absent:
			return s.absent(), true // ECR-8, SKP-10
		case f.Done && f.Skipped && a.Accept.Call.Skip:
			// SKP-6, ECR-3: the same skip, written by a concurrent load; Hydra
			// accepted both, each request answers its own redirect_to.
			return s.redirect(a.Accept.RedirectTo), true
		case f.Done:
			return s.ended(f).report(conflict), true // ECR-9: its redirect_to is never followed
		case f.HydraRedirect != "":
			return s.redirect(a.Accept.RedirectTo), true // ECR-3
		}
		out := r.accepted(f, a.Accept)
		out.Guard = a.Accept.Call.Skip // SKP-8: reported or not, the accept of a skip was made
		return out, true               // ECR-4
	case a.Reject.ok() && !r.used[RejectLogin]:
		d := a.Reject
		switch {
		case absent:
			return s.redirect(d.RedirectTo).audited(d), true // ECR-8: it grants nothing
		case f.Done:
			return s.redirect(d.RedirectTo).report(conflict).audited(d), true // ECR-9: it grants nothing
		}
		out := s.redirect(d.RedirectTo)
		if d.Call.Reason == ReasonSkipSubject {
			out = s.fail(E1003)
		}
		return out.writing(f.Reduce()).audited(d), true // ECR-4
	case a.ConsentAccept.ok() && !r.used[AcceptConsent], a.ConsentReject.ok() && !r.used[RejectConsent]:
		d := a.ConsentAccept
		if !d.ok() || r.used[AcceptConsent] {
			d = a.ConsentReject
		}
		switch {
		case absent:
			return s.absent().audited(d), true // ECR-8
		case f.Done && d.Call.Reason == ReasonNotOurs:
			// Q20: an A3 reject's redirect_to is never followed, and the cr
			// of the flow is another consent's.
			return s.fail(E1007).report(conflict).audited(d), true
		case f.Done && f.ConsentRedirect != "":
			return s.redirect(d.RedirectTo), true // ECR-3, Q30: the same consent
		case f.Done && d.Call.Op == AcceptConsent:
			return s.ended(f).report(conflict), true // ECR-9
		case f.Done:
			return s.redirect(d.RedirectTo).report(conflict), true
		}
		out := r.consentDone(f, d)
		if d.Call.Reason == ReasonNotOurs {
			fail := s.fail(E1007)
			out.Response, out.Reports = fail.Response, fail.Reports
		}
		return out.audited(d), true // ECR-4
	}
	return Outcome{}, false
}

// audited adds the audit event of the reject d (EMU-12, EMU-14, CST-8 to
// CST-10), which the transition reports when it reaches the reject itself.
func (o Outcome) audited(d *Done) Outcome {
	switch d.Call.Reason {
	case ReasonSubject:
		return o.report(Report{Event: "step.subject_mismatch", Audit: true})
	case ReasonNotOurs:
		return o.report(Report{Event: "flow.rejected", Detail: d.Call.detail(), Audit: true})
	}
	return o
}
