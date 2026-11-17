package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"slices"
	"strings"
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
	return Outcome{Response: Response{Kind: ErrorPage, Code: E1007}, Reports: []Report{
		{Event: "state.conflict", Detail: "second mutation", Sentry: true},
		{Event: "flow.error", Detail: string(E1007), Sentry: true},
	}}
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
	return ok(d.RedirectTo).writing(f.Reduce()).report(Report{Event: "flow.rejected", Detail: d.Call.detail()})
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
	// Without the x_dispatcher_* members an app wrote, as at a skip: the webhook
	// receives what Hydra will (R28).
	ctx, stop := r.loginHook(f, &body, withSkipped(withoutDispatcher(f.ContextOf()), f.SkippedApps()))
	if stop != nil {
		return *stop // FIN-4: flow unchanged, a reload replays the webhook
	}
	if f.Hydra.Skip && body.Subject != f.Hydra.Subject {
		return r.rejectLogin(f, ReasonSkipSubject, rejection(ReasonSkipSubject, "The subject authenticated is not the one of the Hydra session."),
			func(string) Outcome { return otherSubject(s, f) })
	}
	ctx = withSkipped(withoutDispatcher(ctx), f.SkippedApps())
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

// otherSubject is page E1003 of FIN-3 and SKP-7: Hydra keeps a session of someone else
// in this browser, and refuses this sign-in. The page gives the way out, Hydra's logout,
// which asks first (LGO-6): nothing ends without a click (Q60, Q63).
func otherSubject(s surface, f *Flow) Outcome {
	o := s.fail(E1003)
	o.Response.SignOut = signOutURL(f.Hydra.RequestURL)
	return o
}

// signOutURL is Hydra's logout, beside its authorization endpoint that a login
// request's request_url names, a path prefix of urls.self.public included; "" when it
// names no such endpoint.
func signOutURL(requestURL string) string {
	u, err := url.Parse(requestURL)
	if err != nil || !u.IsAbs() {
		return ""
	}
	prefix, ok := strings.CutSuffix(u.Path, "/oauth2/auth")
	if !ok {
		return ""
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = prefix+"/oauth2/sessions/logout", "", "", ""
	return u.String()
}

// loginHook calls the login webhook with body and ctx, before the final
// accept or the accept of a skip (FIN-4, SKP-9): the members it returns
// replace those sent. A webhook that fails, or a context that is neither an
// object nor null (A9), stops the authentication: page E1006, nothing
// written nor rejected. stop is the outcome to return, nil once done.
func (r *run) loginHook(f *Flow, body *ory.AcceptOAuth2LoginRequest, ctx Object) (_ Object, stop *Outcome) {
	location := r.Env.Config.Settings.LoginAcceptWebhookURL
	if location == "" {
		return ctx, nil
	}
	h := r.Answers.LoginHook
	if h == nil {
		call := *body
		call.Context = ctx
		return nil, &Outcome{Call: &Call{Op: LoginHook, Challenge: f.LoginChallenge, Gen: f.Gen, AcceptLogin: call,
			Hook: &HookCall{Location: location, Client: f.Hydra.Client}}}
	}
	r.use(LoginHook)
	if h.Err != nil {
		out := r.hookFailed(hookLogin, h.Err)
		return nil, &out
	}
	if h.Context != nil {
		o, ok := ObjectOf(h.Context)
		if !ok {
			out := r.page().fail(E1006).report(Report{Event: "webhook.failed", Kind: hookLogin, Detail: "context is neither an object nor null"})
			return nil, &out
		}
		ctx = o
	}
	if h.Subject != nil {
		body.Subject = *h.Subject
	}
	if h.ACR != nil || h.NullACR {
		body.Acr = h.ACR
	}
	if h.AMR != nil {
		body.Amr = h.AMR
	}
	if h.Remember != nil || h.NullRemember {
		body.Remember = h.Remember
	}
	if h.RememberFor != nil || h.NullRememberFor {
		body.RememberFor = h.RememberFor
	}
	return ctx, nil
}

// The kinds of webhook, as the logs give them.
const (
	hookLogin   = "login"
	hookConsent = "consent"
)

// hookFailed answers a webhook call that failed: page E1006, nothing written nor
// rejected, a reload replaying it (Q23); webhook.failed tells why, flow.error going to
// Sentry. A connection the client closed cancels the call: nothing says the webhook
// failed, so neither of them; webhook.abandoned tells it, as hydra.request_abandoned
// does for Hydra (Q64, Q67, Q72).
func (r *run) hookFailed(kind string, err error) Outcome {
	out := r.page().fail(E1006)
	failed := Report{Event: "webhook.failed", Kind: kind, Detail: err.Error()}
	var e *HookError
	if errors.As(err, &e) {
		failed.Host, failed.Status, failed.Detail, failed.Elapsed = e.Host, e.Status, e.Cause, e.Elapsed
	}
	if errors.Is(err, context.Canceled) {
		out.Reports = nil
		failed.Event, failed.Detail = "webhook.abandoned", ""
	}
	return out.report(failed)
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
			IdToken:     r.granted(req.RequestedScope, MergeClaims(idt...)),
			AccessToken: r.granted(req.RequestedScope, MergeClaims(act...)),
		},
	}
}

// granted are the claims of o the scopes cover, with consent.claims_filter
// strict (Q129): the others are not sent, nor shown. Permissive, o as it is.
func (r *run) granted(scopes []string, o Object) Object {
	if !r.Env.StrictClaims || o == nil {
		return o
	}
	covered := map[string]bool{}
	for _, s := range scopes {
		claims, _ := r.Env.Config.ScopeClaims(s)
		for _, c := range claims {
			covered[c] = true
		}
	}
	out := Object{}
	for k, v := range o {
		if covered[k] {
			out[k] = v
			continue
		}
		if r.dropped == nil {
			r.dropped = map[string]bool{}
		}
		r.dropped[k] = true
	}
	return out
}

// sameJSON tells whether a and b are the same JSON, whatever their spaces.
func sameJSON(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

// names are the names of the claims of o, sorted; [] for none.
func names(o any) []string {
	m, _ := o.(Object)
	return append([]string{}, slices.Sorted(maps.Keys(m))...)
}

// claimsReports are the lines of debug of the claims of a consent accepted
// (Q132): claims.merged, of the steps of f (A2), the claims a later step gave
// another value among them; claims.filtered, the names body sends in each
// token and those the strict filter left out. Names, never values.
func (r *run) claimsReports(f *Flow, body ory.AcceptOAuth2ConsentRequest) []Report {
	var reports []Report
	if f != nil && len(f.Steps) > 0 {
		var idt, act []Object
		for _, s := range f.Steps {
			idt, act = append(idt, s.IDToken), append(act, s.AccessToken)
		}
		conflicts := map[string]bool{}
		for _, parts := range [][]Object{idt, act} {
			seen := Object{}
			for _, p := range parts {
				for k, v := range p {
					if isNull(v) {
						continue
					}
					if before, ok := seen[k]; ok && !sameJSON(before, v) {
						conflicts[k] = true
					}
					seen[k] = v
				}
			}
		}
		reports = append(reports, Report{Event: "claims.merged", Debug: true, Names: &ClaimNames{IDToken: names(MergeClaims(idt...)),
			AccessToken: names(MergeClaims(act...)), Conflicts: append([]string{}, slices.Sorted(maps.Keys(conflicts))...)}})
	}
	filtered := &ClaimNames{IDToken: []string{}, AccessToken: []string{}, Dropped: append([]string{}, slices.Sorted(maps.Keys(r.dropped))...)}
	if s := body.Session; s != nil {
		filtered.IDToken, filtered.AccessToken = names(s.IdToken), names(s.AccessToken)
	}
	return append(reports, Report{Event: "claims.filtered", Debug: true, Names: filtered})
}

// grantedSession filters the session of body by the scopes it grants, after
// the consent webhook, which may change both (Q129): what Hydra receives.
func (r *run) grantedSession(body *ory.AcceptOAuth2ConsentRequest) {
	if !r.Env.StrictClaims || body.Session == nil {
		return
	}
	if o, ok := body.Session.IdToken.(Object); ok {
		body.Session.IdToken = r.granted(body.GrantScope, o)
	}
	if o, ok := body.Session.AccessToken.(Object); ok {
		body.Session.AccessToken = r.granted(body.GrantScope, o)
	}
}

// acceptConsent accepts the consent C of the accepted flow f (CST-12,
// CST-14): the consent webhook, then the accept; f finishes, keeping the
// redirect_to for a double submission (Q13).
func (r *run) acceptConsent(f *Flow, c string, req *ory.OAuth2ConsentRequest) Outcome {
	body := r.consentBody(f, req)
	var ctx Object
	if f.Sent != nil {
		ctx = f.Sent.Context
	}
	if stop := r.consentHook(c, f.Gen, &body, req, ctx); stop != nil {
		return *stop
	}
	r.grantedSession(&body)
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
	out := r.consentDone(f, d).report(Report{Event: "hydra.consent_accepted"})
	out.Reports = append(out.Reports, r.claimsReports(f, d.Call.AcceptConsent)...)
	return out
}

// consentHook calls the consent webhook with body, what the request req holds of the
// login, and ctx, the login's context (Q38), before a consent accept with a flow or
// without (CST-12, CST-14, SKC-1, SKC-3): what it returns replaces the scopes, the
// audiences and the claims to send. A webhook that fails, or claims that are not
// objects, stop the authentication: page E1006, nothing written nor rejected
// (SKC-13). stop is the outcome to return, nil once done.
func (r *run) consentHook(c string, gen int64, body *ory.AcceptOAuth2ConsentRequest, req *ory.OAuth2ConsentRequest, ctx Object) (stop *Outcome) {
	location := r.Env.Config.Settings.ConsentAcceptWebhookURL
	if location == "" {
		return nil
	}
	h := r.Answers.ConsentHook
	if h == nil {
		client, _ := json.Marshal(req.Client) // a model of the SDK always marshals
		return &Outcome{Call: &Call{Op: ConsentHook, Challenge: c, Gen: gen, AcceptConsent: *body, Hook: &HookCall{
			Location: location, Client: client, Subject: req.GetSubject(), ACR: req.GetAcr(), AMR: nonNil(req.Amr), Context: ctx,
		}}}
	}
	r.use(ConsentHook)
	if h.Err != nil {
		out := r.hookFailed(hookConsent, h.Err)
		return &out
	}
	for raw, member := range map[*json.RawMessage]*any{&h.IDToken: &body.Session.IdToken, &h.AccessToken: &body.Session.AccessToken} {
		if *raw != nil {
			o, ok := ObjectOf(*raw)
			if !ok {
				out := r.page().fail(E1006).report(Report{Event: "webhook.failed", Kind: hookConsent, Detail: "claims are not an object"})
				return &out
			}
			*member = o
		}
	}
	if h.GrantScope != nil {
		body.GrantScope = h.GrantScope
	}
	if h.GrantAudience != nil {
		body.GrantAccessTokenAudience = h.GrantAudience
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
		case a.Accept.Call.Gen != f.Gen && !a.Accept.Call.Skip:
			// Q142 (R51): the flow read again is of another generation, back to
			// the choice meanwhile, another subject maybe; carried over, the
			// accept made for the one before would go with this one's claims at
			// the consent. As ECR-9, nothing written, its redirect_to never
			// followed: this flow's own final accept replaces it at Hydra. A
			// skip's goes on: its consent reads the memory, not a flow.
			return s.ended(f).report(conflict), true
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
			out = otherSubject(s, f)
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

// withSkipped gives ctx the apps of the steps a pre-check skipped, for the
// webhooks to tell a factor remembered from a factor typed (the client, only
// through a claim the consent webhook makes of it)
// (x_dispatcher_skipped_steps, phase 4), at the final accept and at the
// accept of a skip (Q140); ctx as it is when none was.
func withSkipped(ctx Object, apps []string) Object {
	if len(apps) > 0 {
		ctx["x_dispatcher_skipped_steps"], _ = json.Marshal(apps) // strings always marshal
	}
	return ctx
}
