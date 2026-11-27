package flow

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The memory of the skip (Mémoire du skip of Table de transitions.md, lot
// P8): Hydra's skip is honoured when the dispatcher_remember cookie passes
// its checks, MEM-1 to MEM-11, and only when the flow is created (Q44); the
// consent of such a login comes without x_dispatcher_ref, and is accepted
// from the cookie without a flow, the x_dispatcher_skip marker binding it to
// the login the dispatcher accepted (Q38).

// memoryFails checks the cookie m against a request of Hydra, the login
// request at the entry or the consent request without a flow, in the order
// of MEM-1 to MEM-11, and returns the reason of the first check failed, ""
// when all pass. sid and sub are the request's session and subject, probe
// holds its client and oidc_context for the choice rules, scopes and audience
// are those it requests. It also returns what the choice rules reported.
func (r *run) memoryFails(m Memory, sid, sub string, probe *Flow, scopes, audience []string) (string, []Report) {
	c := m.Content
	switch {
	case c == nil && m.Reason == SkipUnreadable:
		return SkipUnreadable, nil // MEM-2
	case c == nil:
		return SkipAbsent, nil // MEM-1
	case c.Lo:
		return SkipLogout, nil // MEM-11 (Q45): nothing to serve a skip with
	case c.Exp != 0 && !r.Env.Now.Before(time.Unix(c.Exp, 0)):
		return SkipExpired, nil // MEM-3: 0 is a cookie of the browser's session
	case c.SID == "" || c.SID != sid:
		return SkipSession, nil // MEM-4
	case c.Sub != sub:
		return SkipSubject, nil // MEM-5
	}
	// MEM-6 (Q36): among the candidates of the choice rules for this
	// request, and the preferred flow when CHX-3 retains one; a preferred
	// flow outside the candidates is ignored (Q19), and keeps no skip off.
	o := r.offer(probe)
	if o.reject != 0 || !slices.Contains(o.flows, c.Flow) || o.preferred != "" && o.preferred != c.Flow {
		return SkipFlow, o.reports
	}
	fl, _ := flowOf(r.Env.Config, c.Flow) // a candidate is in the snapshot
	apps := make([]string, len(fl.Steps))
	for i, s := range fl.Steps {
		apps[i] = s.AppID
	}
	acr, _ := acrValues(probe.Hydra.OIDCContext)
	switch {
	case c.FH != Composition(apps):
		return SkipComposition, o.reports // MEM-7
	case !scopesServe(r.Env.Config.Settings.SkipScopes, scopes, c.Scp):
		// MEM-8 (revue R20, Q164): the scopes, compared as skip_scopes says.
		return SkipScopes, o.reports
	case len(acr) > 0 && len(o.unmet) == 0 && !slices.Contains(acr, c.ACR):
		// MEM-9 (Q36): fh does not cover the acr the flow declares, which
		// may have changed since the cookie was written; the accept sends
		// the cookie's. acr_values no flow declares (Q151): a request, not a
		// requirement; the skip stands, and the acr sent, the cookie's, says
		// what was done.
		return SkipACR, o.reports
	case !sameSet(audience, c.Aud):
		// MEM-10 (revue R21): the access token claims of the cookie were
		// written for the audiences of its consent; another audience would
		// get them, an app's roles for one API read by another.
		return SkipAudience, o.reports
	}
	return "", o.reports
}

// scopesServe tells whether the scopes a request asks let the cookie serve
// it (MEM-8, Q164), as skip_scopes says:
//   - equal, the default, the same set (revue R20): a login app may have
//     filtered the cookie's claims for the scopes of the consent that wrote
//     it (hydra-sql's FILTER_CLAIMS_BY_SCOPE); fewer scopes would get claims
//     of scopes neither requested nor granted, another client's included,
//     unless consent.claims_filter strict filters them by the catalogue;
//   - subset, the scopes requested among the cookie's: the claims served are
//     those of the cookie, filtered by the catalogue under strict;
//   - any, whatever they are, as Symfony, for a deployment whose apps give
//     every claim whatever the scopes (hydra-sql with
//     FILTER_CLAIMS_BY_SCOPE=false, for example); a scope the cookie's login
//     was not asked may find no claim.
//
// The cookie is not written again at the skip (WRT-5): another client's
// scopes never replace those of the login that wrote it.
func scopesServe(mode string, requested, remembered []string) bool {
	switch mode {
	case store.SkipScopesAny:
		return true
	case store.SkipScopesSubset:
		return within(requested, remembered)
	}
	return sameSet(requested, remembered)
}

// within tells whether each of a is in b.
func within(a, b []string) bool {
	return !slices.ContainsFunc(a, func(s string) bool { return !slices.Contains(b, s) })
}

// sameSet tells whether what is requested is what the cookie holds, order and
// repeats aside (MEM-8, MEM-10).
func sameSet(requested, remembered []string) bool {
	return within(requested, remembered) && within(remembered, requested)
}

// ignored is the report of a skip ignored, of kind login or consent.
func ignored(kind, reason string) Report {
	return Report{Event: "skip.ignored", Kind: kind, Reason: reason}
}

// skipLogin accepts L from the remember cookie c, Hydra's skip honoured
// (SKP-1): the subject, acr, amr and context of the cookie, after the login
// webhook as at the final accept, without x_dispatcher_* members, with the
// x_dispatcher_skip marker (Q38); remember and remember_for of the settings,
// Hydra setting remember itself on a skip (Q43 withdrawn). Then f, the flow
// being created, is written finished, reduced, keeping the accept's
// redirect_to for 10 s (Q35): a write that only guards against a return.
func (r *run) skipLogin(f *Flow, c *Remembered) Outcome {
	s, settings := r.page(), r.Env.Config.Settings
	body := ory.AcceptOAuth2LoginRequest{
		Subject:     c.Sub,
		Acr:         ory.PtrString(c.ACR),
		Amr:         nonNil(c.AMR),
		Remember:    ory.PtrBool(settings.Remember),
		RememberFor: ory.PtrInt64(int64(settings.LoginRememberFor / time.Second)),
	}
	ctx, stop := r.loginHook(f, &body, withSkipped(withoutDispatcher(c.Ctx), c.SK))
	if stop != nil {
		// SKP-9: nothing written, a reload replays the webhook. The page gives Hydra's
		// logout, as E1003 does (Q88): a webhook that refuses the subject it rewrote
		// already, or that fails, would hold the user until the end of the session.
		// The full authentication that follows calls the webhook again: the link only
		// gets past a refusal tied to the rewritten subject.
		if stop.Call == nil && stop.Response.Code == E1006 {
			stop.Response.SignOut = signOutURL(f.Hydra.RequestURL)
		}
		return *stop
	}
	if body.Subject != f.Hydra.Subject {
		// SKP-7: Hydra 2.1 would refuse the accept, 2.2 start a login again. The page
		// gives the way out, as FIN-3: past a logout, Hydra says no skip, and the
		// webhook's subject is no longer compared to anything (Q63). The cookie's
		// subject being the session's (MEM-5), only the webhook changed it: its log
		// line says so, an exploitant's to fix (Q67).
		out := r.rejectLogin(f, ReasonSkipSubject, rejection(ReasonSkipSubject, "The subject authenticated is not the one of the Hydra session."),
			func(string) Outcome { return otherSubject(s, f) })
		if out.Call != nil {
			out.Call.Check = checkWebhook
		}
		return out
	}
	ctx = withSkipped(withoutDispatcher(ctx), c.SK) // Q140
	marker := r.Env.Keys.SkipMarker(f.HydraSessionID, body.Subject, body.GetAcr(), body.Amr, f.Hydra.RequestURL)
	ctx[memberSkip], _ = json.Marshal(marker) // a string always marshals
	body.Context = ctx

	d := r.Answers.Accept
	switch {
	case d == nil && r.mutated(AcceptLogin):
		return blocked()
	case d == nil:
		return Outcome{Call: &Call{Op: AcceptLogin, Challenge: f.LoginChallenge, Gen: f.Gen, AcceptLogin: body, Skip: true}}
	}
	r.use(AcceptLogin)
	if err := d.err(); err != nil {
		// SKP-3: 401 or 404, written finished without cr, no reject; SKP-4:
		// 400, 403 or 409, read again, a concurrent skip's flow replaying
		// its cr (ENT-21), E1007 otherwise; SKP-5: unavailable, E1004.
		return r.hydraFailure(f, err)
	}
	g := f.Reduce()
	g.ConsentRedirect, g.ConsentAt, g.Skipped = d.RedirectTo, r.now(), true
	out := s.redirect(d.RedirectTo).writing(g).
		report(Report{Event: "hydra.login_accepted", Detail: body.GetAcr(), Flow: c.Flow}).
		report(Report{Event: "skip.accepted", Kind: "login", Flow: c.Flow})
	out.Guard = true // SKP-8
	return out
}

// withoutFlow is /consent on a consent request without x_dispatcher_ref
// (SKC), the consent of a login accepted in skip: nothing is stored (A6,
// Q37). The marker is checked first, on the consent request's session,
// subject, acr, amr and request_url, then the cookie, then, on a POST, the
// token and the print of the claims shown.
func (r *run) withoutFlow(ev Consent, req *ory.OAuth2ConsentRequest) Outcome {
	s := r.page()
	marker, ok := dispatcherMember(req.Context, memberSkip)
	switch {
	case !ok:
		// SKC-7, CST-5 (A6): a login accepted without the dispatcher, or
		// accepted by Symfony (a context that is no object).
		return r.rejectConsent(nil, ev.Challenge, ReasonNoRef, rejection(ReasonNoRef, "No authentication of the dispatcher is in progress."), s.redirect)
	case req.GetLoginSessionId() == "":
		// SKC-15 (Q55): on 2.1, a session deleted since the accept of the skip.
		// The marker, signed on the sid, can no longer be checked: neither the
		// audit of SKC-8 nor Sentry, for two tabs.
		return r.rejectConsent(nil, ev.Challenge, ReasonSessionGone, rejection(ReasonSessionGone, "The session ended during the authentication."), s.redirect)
	case !r.Env.Keys.validSkipMarker(marker, req.GetLoginSessionId(), req.GetSubject(), req.GetAcr(), req.Amr, req.GetRequestUrl()):
		// SKC-8 (Q38): a login the dispatcher did not accept, or not with
		// these values.
		return r.notOurs(nil, ev.Challenge, checkSkip)
	}
	probe, err := consentProbe(req)
	if err != nil {
		return s.fail(E1004)
	}
	reason, reports := r.memoryFails(ev.Memory, req.GetLoginSessionId(), req.GetSubject(), probe, nonNil(req.RequestedScope), nonNil(req.RequestedAccessTokenAudience))
	if reason != "" {
		// SKC-6: the cookie lost, or a flow changed since; nothing can be
		// played again, the client starts over.
		out := r.rejectConsent(nil, ev.Challenge, ReasonMemory, rejection(ReasonMemory, "The authentication cannot be remembered anymore."), s.redirect)
		if out.Call == nil {
			out = out.report(ignored("consent", reason))
		}
		return out
	}
	c := ev.Memory.Content
	settings := r.Env.Config.Settings
	// The claims of the scopes asked alone, strict: those the screen shows
	// and its print covers (Q129).
	idt, act := r.granted(req.RequestedScope, MergeClaims(c.IDT)), r.granted(req.RequestedScope, MergeClaims(c.ACT))
	switch {
	case ev.Post && !sameCSRF(ev.Token, ev.Cookie):
		return s.fail(E1008) // SKC-5
	case ev.Post && !ev.Accept:
		return r.rejectConsent(nil, ev.Challenge, ReasonUser, rejection(ReasonUser, "The user refused the consent."), s.redirect) // SKC-4
	case ev.Post && !r.Env.Keys.validClaimsPrint(ev.Print, idt, act):
		// SKC-12 (Q37): another tab wrote the cookie since the screen was
		// shown; shown again, what is sent being what is shown.
		return r.screenWithoutFlow(ev, req, idt, act)
	case !ev.Post && !(req.GetSkip() || req.Client != nil && req.Client.GetSkipConsent() || settings.ConsentAutoAccept):
		return r.screenWithoutFlow(ev, req, idt, act) // SKC-2
	}
	// SKC-1, SKC-3: the scopes and audiences requested, the cookie's claims.
	body := ory.AcceptOAuth2ConsentRequest{
		GrantScope:               nonNil(req.RequestedScope),
		GrantAccessTokenAudience: nonNil(req.RequestedAccessTokenAudience),
		Remember:                 ory.PtrBool(settings.Remember),
		RememberFor:              ory.PtrInt64(int64(settings.ConsentRememberFor / time.Second)),
		Session:                  &ory.AcceptOAuth2ConsentRequestSession{IdToken: idt, AccessToken: act},
	}
	if stop := r.consentHook(ev.Challenge, 0, &body, req, withoutDispatcher(c.Ctx)); stop != nil {
		return *stop // SKC-13
	}
	r.grantedSession(&body)
	d := r.Answers.ConsentAccept
	switch {
	case d == nil && r.mutated(AcceptConsent):
		return blocked()
	case d == nil:
		return Outcome{Call: &Call{Op: AcceptConsent, Challenge: ev.Challenge, AcceptConsent: body}}
	}
	r.use(AcceptConsent)
	if err := d.err(); err != nil {
		switch classify(err) {
		case unknown, gone:
			return s.absent() // SKC-9
		case unavailable:
			return s.unavailable(err) // SKC-11
		}
		return s.fail(E1007) // SKC-10: no flow to read again
	}
	// WRT-5: the cookie is not written again, its life stays its login's.
	out := s.redirect(d.RedirectTo).
		report(Report{Event: "hydra.consent_accepted", Flow: c.Flow}).
		report(Report{Event: "skip.accepted", Kind: "consent", Flow: c.Flow})
	out.Reports = append(append(reports, out.Reports...), r.claimsReports(nil, d.Call.AcceptConsent)...)
	return out
}

// screenWithoutFlow is the consent screen built from the cookie's claims
// (SKC-2, SKC-12): its form carries the CSRF token, the browser's cookie or
// a new one, set, and the print of the claims shown (Q37).
func (r *run) screenWithoutFlow(ev Consent, req *ory.OAuth2ConsentRequest, idt, act Object) Outcome {
	csrf := csrfValue(ev.Cookie, r.Env.Draw)
	return Outcome{Response: Response{Kind: ConsentPage, SetCSRF: csrf, Consent: &ConsentScreen{
		Challenge:    ev.Challenge,
		CSRF:         csrf,
		Client:       req.Client,
		Scopes:       nonNil(req.RequestedScope),
		Audience:     nonNil(req.RequestedAccessTokenAudience),
		Subject:      req.GetSubject(),
		Claims:       idt,
		AccessClaims: act,
		UILocales:    req.GetOidcContext().UiLocales,
		Print:        r.Env.Keys.ClaimsPrint(idt, act),
	}}}
}

// consentProbe is what the choice rules read of a consent request (MEM-6):
// its client and its oidc_context, as a login request's.
func consentProbe(req *ory.OAuth2ConsentRequest) (*Flow, error) {
	f := &Flow{}
	var err error
	if f.Hydra.Client, err = json.Marshal(req.Client); err != nil {
		return nil, err
	}
	if req.OidcContext != nil {
		if f.Hydra.OIDCContext, err = json.Marshal(req.OidcContext); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// remembered is the remember cookie the consent accept body writes for the
// flow f it finishes (WRT-1, Q39): what the final accept sent, after the
// webhook, and what the consent grants; nil when the remember sent is false
// (WRT-3), Hydra not remembering that session, or when the cookie read is a note
// of logout of this session, which stays: a consent in progress in another tab
// does not make the skip honoured again (Q45).
func (r *run) remembered(f *Flow, body ory.AcceptOAuth2ConsentRequest) *Remembered {
	if f.Sent == nil || !f.Sent.Remember {
		return nil
	}
	var read *Remembered
	if ev, ok := r.Event.(Consent); ok {
		read = ev.Memory.Content
	}
	if read != nil && read.Lo && read.SID == f.HydraSessionID {
		return nil
	}
	now := r.Env.Now.Unix()
	m := &Remembered{
		V:    RememberedFormat,
		SID:  f.HydraSessionID,
		Sub:  f.Sent.Subject,
		Flow: f.FlowID,
		FH:   f.composition(),
		AP:   f.appsSeen(read),
		ACR:  f.Sent.ACR,
		AMR:  nonNil(f.Sent.AMR),
		Ctx:  withoutDispatcher(f.Sent.Context),
		SK:   f.SkippedApps(),
		Scp:  nonNil(body.GrantScope),
		Aud:  nonNil(body.GrantAccessTokenAudience),
		IAT:  now,
	}
	if s := body.Session; s != nil {
		m.IDT, _ = s.IdToken.(Object)
		m.ACT, _ = s.AccessToken.(Object)
	}
	if f.Sent.RememberFor > 0 {
		m.Exp = now + f.Sent.RememberFor // 0: a cookie of the browser's session
	}
	return m
}

// appsSeen are the apps of the session after f (WRT-1, Q56): those of the cookie
// read, when it is of this session, then those of f, without a repeat. The cookie
// only names the last flow, and a session may have gone through two.
func (f *Flow) appsSeen(read *Remembered) []string {
	var apps []string
	if read != nil && read.SID == f.HydraSessionID {
		apps = slices.Clone(read.AP)
	}
	for _, s := range f.Steps {
		if !slices.Contains(apps, s.App) {
			apps = append(apps, s.App)
		}
	}
	return apps
}

// dispatcherPrefix starts the members of a context that are the
// dispatcher's: x_dispatcher_ref, x_dispatcher_skip.
const dispatcherPrefix = "x_dispatcher_"

// withoutDispatcher returns a copy of ctx without the dispatcher's members,
// those of an app, a webhook or a cookie included (Q38); never nil.
func withoutDispatcher(ctx Object) Object {
	out := make(Object, len(ctx))
	for k, v := range ctx {
		if !strings.HasPrefix(k, dispatcherPrefix) {
			out[k] = v
		}
	}
	return out
}

// checkWebhook is the Call.Check of SKP-7's reject.
const checkWebhook = "webhook"

// The members of a context that are the dispatcher's.
const (
	memberRef  = dispatcherPrefix + "ref"
	memberSkip = dispatcherPrefix + "skip"
)

// dispatcherMember returns the member name of a consent request's context,
// and whether it has one; a context that is not an object has none (SKC-7). A
// member that is no string, null included, is one the dispatcher never wrote:
// present with "", neither a ref (CST-6, T2) nor a marker, which no key gives
// (SKC-8, revues R20 et R21).
func dispatcherMember(context any, name string) (string, bool) {
	data, err := json.Marshal(context)
	if err != nil {
		return "", false
	}
	var c map[string]json.RawMessage
	if json.Unmarshal(data, &c) != nil {
		return "", false
	}
	raw, ok := c[name]
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", true
	}
	return value, true
}
