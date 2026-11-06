package flow

import (
	"net/url"
	"slices"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// Entry is GET / (ENT): Hydra's login challenge, or the ref of
// x_dispatcher_restart_url, with the browser's dispatcher_flow_csrf cookie
// and its dispatcher_remember cookie, opened.
type Entry struct {
	LoginChallenge string
	Ref            string
	Cookie         string
	Memory         Memory
}

// Choose is POST / (POS): the form of the choice page, the browser's cookie,
// and whether Sec-Fetch-Site or Origin says the form comes from the
// dispatcher's own pages.
type Choose struct {
	FlowID         string
	LoginChallenge string
	Token          string
	Cookie         string
	SameOrigin     bool
}

// Loop is GET /oauth2/auth (BCL), where the step accepts send the browser
// back: the ref, or Symfony's form with Hydra's login challenge.
type Loop struct {
	Ref            string
	LoginChallenge string
	Cookie         string
}

// Consent is GET or POST /consent (CST): Hydra's consent challenge, the
// browser's cookies and, on a POST, the user's answer, the form's token and
// the print of the claims a screen without a flow showed (SKC-3, Q37).
type Consent struct {
	Challenge  string
	Cookie     string
	Memory     Memory
	Post       bool
	Accept     bool
	Token      string
	Print      string
	SameOrigin bool
	// ref is the flow a page already read, when it rejects the consent of
	// that flow (pastExp): the consent request must name it.
	ref string
}

func (Entry) event()   {}
func (Choose) event()  {}
func (Loop) event()    {}
func (Consent) event() {}

// entry is GET / (ENT): the flow is read first, Hydra only called when it is
// absent (M1).
func (r *run) entry(ev Entry) Outcome {
	s, byRef, ref := r.page(), ev.LoginChallenge == "", ev.Ref
	switch {
	case !byRef && !hydraChallenge(ev.LoginChallenge), byRef && !isRef(ref):
		return s.fail(E1001) // ENT-13
	case !byRef:
		ref = Ref(ev.LoginChallenge)
	}
	if !r.Loaded {
		return Outcome{Load: ref}
	}
	f := r.Flow
	switch f.StateAt(r.Env.Now) {
	case Absent:
		if byRef {
			return s.absent() // ENT-15
		}
		return r.create(ref, ev)
	case Finished:
		return r.endedPage(f) // ENT-7, ENT-16, ENT-21
	case Expired:
		return r.expire(f) // ENT-8, EXP-2
	case Accepted:
		switch {
		case sameCSRF(ev.Cookie, f.CSRF):
			return s.redirect(f.ResumeURL(r.Env.BaseURL)) // ENT-4, ENT-19 (Q1)
		case r.now() > f.ExpiresAt:
			return r.pastExp(ref, f) // ENT-20
		}
		return s.fail(E1008) // ENT-6, ENT-18
	}
	switch {
	case !sameCSRF(ev.Cookie, f.CSRF) && byRef:
		return s.fail(E1008) // ENT-18: the apps know the ref
	case !sameCSRF(ev.Cookie, f.CSRF):
		// ENT-5: replaced under the same ref, the browser's cookie taken.
		g := f.restart()
		g.CSRF = csrfValue(ev.Cookie, r.Env.Draw)
		out := r.choice(ref, g)
		out.Response.SetCSRF = g.CSRF
		return out
	case f.StateAt(r.Env.Now) == Choice:
		// ENT-2: nothing to invalidate, the page again; the rules only
		// write when the configuration changed meanwhile.
		if o := r.offer(f); o.reject == 0 && o.start == "" {
			return r.choicePage(f, o, false)
		}
		return r.choice(ref, f)
	}
	return r.choice(ref, f.restart()).report(Report{Event: "flow.reset"}) // ENT-3, ENT-17 (RA1)
}

// create creates the flow of L, from the login request read (ENT-1, ENT-9):
// its generation drawn, the browser's cookie or a new one, its expiry and
// the end of L at Hydra (Q2). Hydra's skip is honoured here only (Q44), when
// the remember cookie passes its checks (SKP-1): the flow is then written
// finished. Otherwise it is ignored, the flow played again (SKP-2).
func (r *run) create(ref string, ev Entry) Outcome {
	s, read := r.page(), r.Answers.Login
	if read == nil {
		return Outcome{Call: &Call{Op: GetLogin, Challenge: ev.LoginChallenge}}
	}
	r.use(GetLogin)
	switch classify(read.Err) {
	case none:
	case unknown:
		return s.fail(E1001).report(forged()) // ENT-12 (Q32)
	case gone:
		return expiredIf(s.absent(), read.Err) // ENT-10, ENT-11: the 410 of 2.1 is not followed
	case unavailable:
		return s.unavailable(read.Err) // ENT-14
	default:
		return s.fail(E1007)
	}
	snap, sid, err := SnapshotOf(read.Request)
	if err != nil {
		return s.fail(E1004)
	}
	snap.LoginID = read.LoginID // Q34
	since := read.RequestedAt
	if since.IsZero() {
		since = r.Env.Now
	}
	end := since.Add(r.Env.LoginConsentTTL)
	exp := r.Env.Now.Add(r.Env.Config.Settings.ChallengeTTL)
	if bound := end.Add(-hydraMargin); bound.Before(exp) {
		exp = bound
	}
	f := &Flow{
		V:              Format,
		LoginChallenge: ev.LoginChallenge,
		HydraSessionID: sid,
		Hydra:          snap,
		Gen0:           r.Env.Draw.Gen0,
		Gen:            r.Env.Draw.Gen0,
		CSRF:           csrfValue(ev.Cookie, r.Env.Draw),
		ExpiresAt:      exp.UnixMilli(),
		HydraExpiresAt: end.UnixMilli(),
	}
	var skip []Report
	if snap.Skip {
		if out, ok := r.sessionGone(read.Request, ev.Memory); ok {
			return r.skewed(read, out)
		}
		reason, reports := r.memoryFails(ev.Memory, sid, snap.Subject, f, snap.Scope, snap.Audience)
		if reason == "" {
			// SKP-1: before ENT-22, the accept leaves at once; past hx
			// meanwhile, SKP-10.
			out := r.skipLogin(f, ev.Memory.Content)
			out.Reports = append(reports, out.Reports...)
			return r.skewed(read, out)
		}
		skip = []Report{ignored("login", reason)} // ENT-9, SKP-2
		if promptNone(snap.RequestURL) {
			// SKP-11 (revue R21): no page may be shown, and Hydra, which has a
			// session, leaves that to the login app: the client gets
			// login_required, as without a session.
			out := r.rejectLogin(f, ReasonPromptNone, rejection(ReasonPromptNone, "The session cannot be used without a login, which prompt=none forbids."), s.redirect)
			out.Reports = append(skip, out.Reports...)
			return r.skewed(read, out)
		}
	}
	if f.ExpiresAt <= r.now() && r.now() < f.HydraExpiresAt {
		// ENT-22 (Q33): read in the last minute of L at Hydra, with Hydra's
		// requested_at (P7), the flow would be born expired; past hx, the
		// write is refused instead (ECR-8). In fallback, the first read
		// stands for requested_at: never, hydra.login_consent_ttl being
		// above the margin (internal/config).
		out := r.expire(f)
		out.Reports = append(skip, out.Reports...)
		return r.skewed(read, out)
	}
	out := r.choice(ref, f)
	out.Response.SetCSRF = f.CSRF
	out.Reports = append(skip, out.Reports...)
	return r.skewed(read, out)
}

// sessionGone answers a login request in skip whose session must not, or does
// not, serve: before SKP-1, SKP-2, SKP-11 and ENT-22, no flow is born.
// Restarting the authorization on its request_url gives a new L without a skip,
// or login_required from Hydra itself with prompt=none (HLO-18).
//
// SKP-13: session_id empty, whatever the cookie: on 2.1, the session was deleted
// since L was created; the flow would be born without a sid, which CST-24 does
// not see, and Hydra deliver an id_token without one.
//
// SKP-12 (Q45): a note of logout of this session: its chain stopped in this
// browser, or this is one more load on an L of before the delete, 204 again. The
// session is deleted, which sends the back-channel; the note stays, only of use
// to an L of before. A Hydra unavailable gives E1004, a reload plays it again.
func (r *run) sessionGone(req *ory.OAuth2LoginRequest, m Memory) (Outcome, bool) {
	s, sid := r.page(), req.GetSessionId()
	if sid == "" {
		return s.redirect(req.RequestUrl), true // SKP-13
	}
	if c := m.Content; c == nil || !c.Lo || c.SID != sid {
		return Outcome{}, false
	}
	d := r.Answers.Revoke
	if d == nil {
		return Outcome{Call: &Call{Op: RevokeSession, Challenge: sid}}, true
	}
	if d.Err != nil {
		return s.unavailable(d.Err), true
	}
	return s.redirect(req.RequestUrl).
		report(ignored("login", SkipLogout)).
		report(Report{Event: "logout.session_revoked", Audit: true}), true
}

// promptNone tells whether the authorization request says prompt=none (OIDC
// Core 3.1.2.1). A login request does not carry the prompt: only its
// request_url does, the query of the authorization request; one sent by POST,
// or with the prompt in a request object, does not show it (doc, Mémoire du
// skip).
func promptNone(requestURL string) bool {
	u, err := url.Parse(requestURL)
	if err != nil {
		return false
	}
	return slices.Contains(strings.Fields(u.Query().Get("prompt")), "none")
}

// clockSkewTolerance is how far in the future Hydra's requested_at may be
// before the creation reports the clocks apart: Hydra sets it before
// redirecting the browser, so it is always past for a clock in step.
const clockSkewTolerance = 5 * time.Second

// skewed adds hydra.clock_skew to out when the L decrypted at the flow's
// creation carries a requested_at ahead of the dispatcher's clock, the one
// sign of clocks apart (DEC-3, Versions Hydra): exp, hx, the last minute of
// ENT-22 and the age of DEC-4 are judged on the dispatcher's clock against
// it. Once per authentication, at the creation, where exp and hx are drawn
// from it (revue R18); a consent request carries the requested_at of its
// login. A dispatcher ahead of Hydra shows nothing, and ends the flows early.
func (r *run) skewed(read *LoginRead, out Outcome) Outcome {
	if ahead := read.RequestedAt.Sub(r.Env.Now); read.Decrypted && ahead > clockSkewTolerance {
		return out.report(Report{Event: "hydra.clock_skew", Detail: "Hydra's requested_at " + ahead.Round(time.Second).String() + " ahead"})
	}
	return out
}

// choose is POST / (POS): the form chooses the flow, created on GET / (A5).
func (r *run) choose(ev Choose) Outcome {
	s := r.page()
	switch {
	case !ev.SameOrigin:
		return s.fail(E1008) // POS-9
	case !hydraChallenge(ev.LoginChallenge):
		return s.fail(E1001)
	}
	ref := Ref(ev.LoginChallenge)
	if !r.Loaded {
		return Outcome{Load: ref}
	}
	f := r.Flow
	csrf := sameCSRF(ev.Token, ev.Cookie) && sameCSRF(ev.Cookie, f.csrf())
	state := f.StateAt(r.Env.Now)
	switch state {
	case Absent:
		return s.absent() // POS-8
	case Finished:
		return r.endedPage(f) // POS-7, POS-11
	case Expired:
		return r.expire(f)
	case Accepted:
		switch {
		case csrf:
			return s.redirect(f.ResumeURL(r.Env.BaseURL)) // POS-5 (Q1)
		case r.now() > f.ExpiresAt:
			return r.pastExp(ref, f) // POS-10
		}
		return s.fail(E1008) // POS-6
	}
	if !csrf {
		// POS-3 (Q7): replaced as on GET /, the page shown again, no message.
		g := f.restart()
		g.CSRF = csrfValue(ev.Cookie, r.Env.Draw)
		out := r.choicePage(g, r.offer(g), false).writing(g)
		out.Response.SetCSRF = g.CSRF
		return out
	}
	o := r.offer(f)
	if o.reject != 0 || !slices.Contains(o.flows, ev.FlowID) {
		return r.choicePage(f, o, true) // POS-2, Q30
	}
	g := f
	if state != Choice {
		g = f.restart() // POS-4 (Q8): back to the choice and chosen, one write
	}
	return r.start(ref, g, ev.FlowID, ev.FlowID == o.clientOnly || ev.FlowID == o.preferred, "choice") // Q29
}

// csrf returns the copy of the cookie, "" for no flow.
func (f *Flow) csrf() string {
	if f == nil {
		return ""
	}
	return f.CSRF
}

// loop is GET /oauth2/auth (BCL): a flow absent or finished answers E1002
// before the cookie is checked.
func (r *run) loop(ev Loop) Outcome {
	s := r.page()
	switch {
	case ev.Ref == "" && ev.LoginChallenge != "":
		// BCL-14 (Q16): Symfony's form, that of the logins in progress at the
		// switch-over, back to the choice.
		return s.redirect(strings.TrimRight(r.Env.BaseURL, "/") + "/?login_challenge=" + url.QueryEscape(ev.LoginChallenge))
	case !isRef(ev.Ref):
		return s.fail(E1001) // BCL-15
	}
	if !r.Loaded {
		return Outcome{Load: ev.Ref}
	}
	f := r.Flow
	state := f.StateAt(r.Env.Now)
	switch state {
	case Absent:
		return s.absent() // BCL-1
	case Finished:
		return r.endedPage(f) // BCL-2, BCL-17
	case Expired:
		return r.expire(f) // BCL-13
	}
	if !sameCSRF(ev.Cookie, f.CSRF) {
		if state == Accepted && r.now() > f.ExpiresAt {
			return r.pastExp(ev.Ref, f) // BCL-16
		}
		return s.fail(E1008) // BCL-3 (Q7)
	}
	k := f.Current
	switch state {
	case Accepted:
		return s.redirect(f.ResumeURL(r.Env.BaseURL)) // BCL-4 (RA5, Q14)
	case Choice:
		return r.choicePage(f, r.offer(f), false) // BCL-5 (Q15)
	case StepLogin:
		return r.toStep(ev.Ref, f, k, KindLogin) // BCL-6
	case StepConsent:
		return r.toStep(ev.Ref, f, k, KindConsent) // BCL-7
	}
	if _, ok := r.Env.Config.App(f.Steps[k-1].App); !ok {
		return s.fail(E1005) // BCL-11
	}
	if k == len(f.Steps) {
		return r.finalAccept(ev.Ref, f) // BCL-12
	}
	return r.advance(ev.Ref, f)
}

// advance moves f to its next step (M4, BCL-8): in fallback, L is read again
// first, only its status counting.
func (r *run) advance(ref string, f *Flow) Outcome {
	s := r.page()
	if _, ok := r.Env.Config.App(f.Steps[f.Current].App); !ok {
		return s.fail(E1005) // BCL-11 before any call (Q30)
	}
	read := r.Answers.Login
	if read == nil {
		return Outcome{Call: &Call{Op: GetLogin, Challenge: f.LoginChallenge, Gen: f.Gen}}
	}
	r.use(GetLogin)
	switch classify(read.Err) {
	case none:
	case unknown, gone:
		return s.ended(f).writing(f.Reduce()) // BCL-9: no rejection
	case unavailable:
		return s.unavailable(read.Err) // BCL-10
	default:
		return s.fail(E1007)
	}
	g := f.clone()
	g.Current++
	return r.toStep(ref, g, g.Current, KindLogin).writing(g)
}

// consent is GET or POST /consent (M7, CST): the consent request is read
// first, it alone carries x_dispatcher_ref.
func (r *run) consent(ev Consent) Outcome {
	s := r.page()
	switch {
	case ev.Post && !ev.SameOrigin:
		return s.fail(E1008) // CST-21
	case !hydraChallenge(ev.Challenge):
		return s.fail(E1001) // CST-1
	}
	read := r.Answers.Consent
	if read == nil {
		return Outcome{Call: &Call{Op: GetConsent, Challenge: ev.Challenge}}
	}
	r.use(GetConsent)
	switch classify(read.Err) {
	case none:
	case unknown:
		return s.fail(E1001).report(forged()) // CST-2 (Q32)
	case gone:
		return expiredIf(s.absent(), read.Err) // CST-3, CST-4
	case unavailable:
		return s.unavailable(read.Err) // CST-19
	default:
		return s.fail(E1007)
	}
	req := read.Request
	ref, ok := dispatcherMember(req.Context, memberRef)
	if !ok {
		// SKC (A6, P8): a login accepted in skip carries the dispatcher's
		// marker; without it, rejected as CST-5 (SKC-7).
		return r.withoutFlow(ev, req)
	}
	if !isRef(ref) {
		return s.absent() // CST-6
	}
	if ev.ref != "" && ref != ev.ref {
		// The consent the flow showed names another flow: never decided on
		// this one.
		return s.fail(E1007)
	}
	if !r.Loaded {
		return Outcome{Load: ref}
	}
	f := r.Flow
	csrf := sameCSRF(ev.Cookie, f.csrf()) && (!ev.Post || sameCSRF(ev.Token, ev.Cookie))
	switch f.StateAt(r.Env.Now) {
	case Absent:
		return s.absent() // CST-6 (T2): never accepted from the remember cookie
	case Finished:
		byConsent := f.ConsentRedirect != "" && !f.Skipped
		if r.replays(f, csrf) {
			out := s.redirect(f.ConsentRedirect) // CST-16 (Q13)
			if byConsent {
				out = out.report(Report{Event: "consent.resubmitted", Result: "replayed"})
			}
			return out
		}
		out := s.ended(f) // CST-7
		if byConsent {
			out = out.report(Report{Event: "consent.resubmitted", Result: "too_late"})
		}
		return out
	case Accepted:
	default:
		// CST-8: not accepted by the dispatcher, expired or not; L is
		// accepted at Hydra all the same, by someone else.
		return r.notOurs(f, ev.Challenge, checkFlow)
	}
	switch {
	case f.HydraSessionID != "" && req.GetLoginSessionId() == "":
		// CST-24 (Q55): on 2.1, the session was deleted since by a logout finished
		// in another tab, a foreign key emptying the field (HLO-15): no audit nor
		// Sentry, for two tabs. Without a check, Hydra would deliver an id_token
		// without a sid. Before A3's checks and the cookie.
		return r.rejectConsent(f, ev.Challenge, ReasonSessionGone, rejection(ReasonSessionGone, "The session ended during the authentication."), s.redirect)
	case f.HydraSessionID != req.GetLoginSessionId():
		return r.notOurs(f, ev.Challenge, checkSession) // CST-9
	case f.Sent == nil || f.Sent.Subject != req.GetSubject():
		return r.notOurs(f, ev.Challenge, checkSubject) // CST-10
	case f.Hydra.LoginID != "" && f.Hydra.LoginID != req.GetLoginChallenge():
		return r.notOurs(f, ev.Challenge, checkLogin) // CST-23 (Q34)
	}
	if r.now() > f.ExpiresAt {
		// CST-22 (Q31): L is accepted, its reject would be refused by
		// Hydra 2.1 (409); the consent is rejected instead, the client
		// getting login_required from either version. Before the cookie,
		// as on the other pages (ENT-8): its Max-Age is challenge_ttl, the
		// browser has lost it by now.
		return r.rejectConsent(f, ev.Challenge, ReasonExpired, rejection(ReasonExpired, "The authentication took too long."), s.redirect)
	}
	if !csrf {
		return s.fail(E1008) // CST-11, after the checks of A3 (Q30)
	}
	switch {
	case ev.Post && ev.Accept:
		return r.acceptConsent(f, ev.Challenge, req) // CST-14
	case ev.Post:
		return r.rejectConsent(f, ev.Challenge, ReasonUser, rejection(ReasonUser, "The user refused the consent."), s.redirect) // CST-15
	case req.GetSkip() || req.Client != nil && req.Client.GetSkipConsent() || r.Env.Config.Settings.ConsentAutoAccept:
		return r.acceptConsent(f, ev.Challenge, req) // CST-12
	}
	// CST-13: the screen; C kept as the flow's resume target (Q14).
	session := r.consentBody(f, req).Session
	out := Outcome{Response: Response{Kind: ConsentPage, Consent: &ConsentScreen{
		Challenge:    ev.Challenge,
		CSRF:         f.CSRF,
		Client:       req.Client,
		Scopes:       nonNil(req.RequestedScope),
		Audience:     nonNil(req.RequestedAccessTokenAudience),
		Subject:      req.GetSubject(),
		Claims:       session.IdToken.(Object),
		AccessClaims: session.AccessToken.(Object),
		UILocales:    req.GetOidcContext().UiLocales,
	}}}
	if f.ConsentChallenge != ev.Challenge {
		g := f.clone()
		g.ConsentChallenge = ev.Challenge
		out = out.writing(g)
	}
	return out
}

// pastExp answers a page on the accepted flow f of ref past exp, without the
// cookie, which the browser lost with exp (ENT-20, POS-10, BCL-16; Q31,
// revue R15): the consent the flow showed is rejected, as /consent does
// (CST-22). Never that consent challenge: the apps know the ref (ENT-18),
// and it would let one that reaches Hydra's admin accept the consent itself.
// A consent Hydra no longer knows (404, 401, 410) finishes the flow without
// a reject, as CST-18. Without a consent shown, hr (revue R16): Hydra 2.1
// refuses a reject of L, and the login_verifier of hr is only followed with
// Hydra's login cookie, the browser's, which then reaches /consent and
// CST-22; in 2.1, an hr already followed ends in an error at the client.
func (r *run) pastExp(ref string, f *Flow) Outcome {
	s := r.page()
	if f.ConsentChallenge == "" {
		return s.redirect(f.HydraRedirect)
	}
	if read := r.Answers.Consent; read != nil {
		switch classify(read.Err) {
		case unknown, gone:
			r.use(GetConsent)
			return s.ended(f).writing(f.Reduce())
		}
	}
	return r.consent(Consent{Challenge: f.ConsentChallenge, ref: ref})
}

// replays tells whether the finished flow f gives its cr again (CST-16,
// Q13): within 10 s of ct, the cookie matching, or without it for a consent
// rejected past exp (ct > exp, which only CST-22 and the pages of ENT-20,
// POS-10 and BCL-16 make, Q31): the browser lost the cookie with exp, and
// the redirect_to of a login_required reject grants nothing. Or without it
// for a flow finished by a skip honoured (sk, Q35), which set no cookie: the
// login_verifier of its cr is only followed with Hydra's CSRF cookie, the
// browser's.
func (r *run) replays(f *Flow, csrf bool) bool {
	return f.ConsentRedirect != "" && (csrf || f.Skipped || f.ConsentAt > f.ExpiresAt) && r.now()-f.ConsentAt < consentReplay.Milliseconds()
}

// endedPage answers a page other than /consent on the finished flow f: page
// E1002 with its link, or, within 10 s of a consent rejected past exp, that
// reject's cr, as /consent replays it (ENT-21, POS-11, BCL-17; revue R16): a
// second load, or a concurrent page whose own reject Hydra 2.1 refused (409);
// likewise the cr of a skip honoured, a reload during its redirection (Q35).
func (r *run) endedPage(f *Flow) Outcome {
	if r.replays(f, false) {
		return r.page().redirect(f.ConsentRedirect)
	}
	return r.page().ended(f)
}

// The checks of A3 a consent request fails, named in the audit event of its
// reject (not_ours:<check>): CST-23 is the sign of an app that accepted a
// login itself with the flow's ref (Q34), CST-9 also comes from a Hydra
// session that changed.
const (
	checkFlow    = "flow"    // CST-8: the flow is not accepted by the dispatcher
	checkSession = "session" // CST-9
	checkSubject = "subject" // CST-10
	checkLogin   = "login"   // CST-23
	checkSkip    = "skip"    // SKC-8: the x_dispatcher_skip marker (Q38)
)

// notOurs rejects the consent of a flow the dispatcher did not accept, or
// of another session, subject or login (A3, Q20): access_denied, page E1007
// without following the reject's redirect_to, an audit event naming the
// check failed, the flow finished.
func (r *run) notOurs(f *Flow, c, check string) Outcome {
	out := r.rejectConsent(f, c, ReasonNotOurs, rejection(ReasonNotOurs, "The consent request does not match the authentication."),
		func(string) Outcome { return r.page().fail(E1007) })
	if out.Call != nil {
		out.Call.Check = check
	}
	return out
}

// hydraMargin is taken from the end of L at Hydra for the flow's expiry:
// beyond it, Hydra 2.1 would accept a login whose verifier the client then
// refuses (Versions Hydra). It is internal/config's, which requires
// hydra.login_consent_ttl above it, or every flow would be born expired
// (ENT-22): one constant, which the two cannot drift from (revue R18).
const hydraMargin = config.HydraMargin
