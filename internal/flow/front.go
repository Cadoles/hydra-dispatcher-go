package flow

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Entry is GET / (ENT): Hydra's login challenge, or the ref of
// x_dispatcher_restart_url, with the browser's dispatcher_flow_csrf cookie.
type Entry struct {
	LoginChallenge string
	Ref            string
	Cookie         string
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
// browser's cookie and, on a POST, the user's answer and the form's token.
type Consent struct {
	Challenge  string
	Cookie     string
	Post       bool
	Accept     bool
	Token      string
	SameOrigin bool
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
		return s.ended(f) // ENT-7, ENT-16
	case Expired:
		return r.expire(f) // ENT-8, EXP-2
	case Accepted:
		if !sameCSRF(ev.Cookie, f.CSRF) {
			return s.fail(E1008) // ENT-6, ENT-18
		}
		return s.redirect(f.ResumeURL(r.Env.BaseURL)) // ENT-4, ENT-19 (Q1)
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
// the end of L at Hydra (Q2).
func (r *run) create(ref string, ev Entry) Outcome {
	s, read := r.page(), r.Answers.Login
	if read == nil {
		return Outcome{Call: &Call{Op: GetLogin, Challenge: ev.LoginChallenge}}
	}
	r.use(GetLogin)
	switch classify(read.Err) {
	case none:
	case unknown:
		return s.fail(E1001) // ENT-12
	case gone:
		return s.absent() // ENT-10, ENT-11: the 410 of 2.1 is not followed
	case unavailable:
		return s.fail(E1004) // ENT-14
	default:
		return s.fail(E1007)
	}
	snap, sid, err := SnapshotOf(read.Request)
	if err != nil {
		return s.fail(E1004)
	}
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
	out := r.choice(ref, f)
	out.Response.SetCSRF = f.CSRF
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
		return s.ended(f) // POS-7
	case Expired:
		return r.expire(f)
	case Accepted:
		if !csrf {
			return s.fail(E1008) // POS-6
		}
		return s.redirect(f.ResumeURL(r.Env.BaseURL)) // POS-5 (Q1)
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
	return r.start(ref, g, ev.FlowID, ev.FlowID == o.clientOnly, "choice")
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
		return s.ended(f) // BCL-2
	case Expired:
		return r.expire(f) // BCL-13
	}
	if !sameCSRF(ev.Cookie, f.CSRF) {
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
		return s.fail(E1004) // BCL-10
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
		return s.fail(E1001) // CST-2
	case gone:
		return s.absent() // CST-3, CST-4
	case unavailable:
		return s.fail(E1004) // CST-19
	default:
		return s.fail(E1007)
	}
	req := read.Request
	ref, ok := dispatcherRef(req.Context)
	if !ok {
		// CST-5 (A6, 1a): a login accepted without the dispatcher's flow.
		return r.rejectConsent(nil, ev.Challenge, ReasonNoRef, rejection(ReasonNoRef, "No authentication of the dispatcher is in progress."), s.redirect)
	}
	if !isRef(ref) {
		return s.absent() // CST-6
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
		if f.ConsentRedirect != "" && csrf && r.now()-f.ConsentAt < consentReplay.Milliseconds() {
			return s.redirect(f.ConsentRedirect) // CST-16 (Q13)
		}
		return s.ended(f) // CST-7
	case Expired:
		return r.expire(f)
	case Accepted:
	default:
		return r.notOurs(f, ev.Challenge) // CST-8: not accepted by the dispatcher
	}
	if f.HydraSessionID != req.GetLoginSessionId() || f.Sent == nil || f.Sent.Subject != req.GetSubject() {
		return r.notOurs(f, ev.Challenge) // CST-9, CST-10
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
	out := Outcome{Response: Response{Kind: ConsentPage, Consent: &ConsentScreen{
		Challenge: ev.Challenge,
		CSRF:      f.CSRF,
		Client:    req.Client,
		Scopes:    nonNil(req.RequestedScope),
		Audience:  nonNil(req.RequestedAccessTokenAudience),
		Claims:    r.consentBody(f, req).Session.IdToken.(Object),
	}}}
	if f.ConsentChallenge != ev.Challenge {
		g := f.clone()
		g.ConsentChallenge = ev.Challenge
		out = out.writing(g)
	}
	return out
}

// notOurs rejects the consent of a flow the dispatcher did not accept, or
// of another session or subject (A3, Q20): access_denied, page E1007 without
// following the reject's redirect_to, an audit event, the flow finished.
func (r *run) notOurs(f *Flow, c string) Outcome {
	return r.rejectConsent(f, c, ReasonNotOurs, rejection(ReasonNotOurs, "The consent request does not match the authentication."),
		func(string) Outcome { return r.page().fail(E1007) })
}

// dispatcherRef returns the x_dispatcher_ref of a consent request's
// context, which the final accept set.
func dispatcherRef(context any) (string, bool) {
	data, err := json.Marshal(context)
	if err != nil {
		return "", false
	}
	var c struct {
		Ref *string `json:"x_dispatcher_ref"`
	}
	if json.Unmarshal(data, &c) != nil || c.Ref == nil {
		return "", false
	}
	return *c.Ref, true
}

// hydraMargin is taken from the end of L at Hydra for the flow's expiry:
// beyond it, Hydra 2.1 would accept a login whose verifier the client then
// refuses (Versions Hydra).
const hydraMargin = 60 * time.Second
