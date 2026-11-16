package flow

import (
	"net/url"
	"slices"
	"strings"
	"time"
)

// SkipCheckCall is what the pre-check of the step K asks its app (phase 4,
// Plan phase 4, P27 en détail): the client signs it, with the app's key and
// the signals it declares, which it takes from the configuration and the
// browser's request.
type SkipCheckCall struct {
	K        int
	App      string
	Subject  string
	Device   string
	ClientID string
	Flow     string
	// Claims are those of the previous steps the app receives, as on its
	// login request.
	Claims   map[string]any
	DeviceAt int64
}

// SkipCheckAnswer is the answer: Skip only from a valid response saying so.
type SkipCheckAnswer struct {
	Skip    bool
	Subject string
	// Context, IDToken and AccessToken of the response, objects or nil.
	Context, IDToken, AccessToken Object
	// Result is skipped, declined (a valid response without the skip) or
	// failed; Cause, of a failure, names it without the response.
	Result  string
	Cause   string
	Elapsed time.Duration
}

// The results of a pre-check (step_skips_total), and its event.
const (
	SkipSkipped  = "skipped"
	SkipDeclined = "declined"
	SkipRefused  = "refused"
	SkipFailed   = "failed"

	eventSkipCheck = "step.skip_check"
)

// preCheck runs the pre-check of the current step of g (BCL-8): false and no
// call when the step does not ask for it, a guard refuses it, or the app
// declines; a call to make; or true, the step marked done by the response.
// Each pre-check reports its result.
func (r *run) preCheck(g *Flow) (bool, *Outcome, []Report) {
	k := g.Current
	step := g.Steps[k-1]
	if !step.SkipCheck {
		return false, nil, nil
	}
	refused := func(reason string) (bool, *Outcome, []Report) {
		return false, nil, []Report{{Event: eventSkipCheck, App: step.App, Result: SkipRefused, Reason: reason}}
	}
	app, ok := r.Env.Config.App(step.App)
	switch {
	case !ok:
		return false, nil, nil // BCL-11 answers
	case app.SkipCheckURL == "" || app.SkipCheckKey == "":
		return refused("no_url")
	case step.Device == "":
		return refused("no_device")
	}
	req, err := g.request()
	if err != nil {
		return refused("request")
	}
	if reason := fresh(req.GetRequestUrl(), req.GetOidcContext().AcrValues, g.SkipCheckACR); reason != "" {
		return refused(reason)
	}
	a := r.Answers.SkipChecks[k]
	if a == nil {
		return false, &Outcome{Call: &Call{Op: SkipCheck, Gen: g.Gen, SkipCheck: &SkipCheckCall{
			K: k, App: step.App, Subject: g.Subject, Device: step.Device, ClientID: req.Client.GetClientId(), Flow: g.FlowID,
			Claims: ReceivedClaims(g.PreviousClaims(k), app).values(), DeviceAt: g.DeviceAt,
		}}}, nil
	}
	rep := Report{Event: eventSkipCheck, App: step.App, Result: a.Result, Reason: a.Cause, Elapsed: a.Elapsed}
	if !a.Skip {
		return false, nil, []Report{rep}
	}
	subject := a.Subject
	if subject == "" {
		subject = g.Subject
	}
	if !SubjectAllowed(step.Check, subject, g.Subject, g.PreviousClaims(k)) {
		rep.Result, rep.Reason = SkipRefused, "subject"
		return false, nil, []Report{rep}
	}
	st := &g.Steps[k-1]
	st.LoginOK, st.ConsentOK, st.Subject, st.Skipped = true, true, subject, true
	st.LoginContext, st.ConsentContext = a.Context, a.Context
	st.IDToken, st.AccessToken = a.IDToken, a.AccessToken
	return true, nil, []Report{rep, {Event: "step.skipped", App: step.App, Audit: true}}
}

// fresh names the freshness the client asks that a skipped step would not
// give, "" for none: prompt=login, a max_age of any value (the dispatcher
// does not know when the app last saw the device), acr_values none of which
// the flow allows the skip under.
func fresh(requestURL string, acrValues, allowed []string) string {
	q := url.Values{}
	if u, err := url.Parse(requestURL); err == nil {
		q = u.Query()
	}
	if slices.Contains(strings.Fields(q.Get("prompt")), "login") {
		return "prompt"
	}
	if q.Has("max_age") {
		return "max_age"
	}
	if len(acrValues) > 0 && !slices.ContainsFunc(acrValues, func(v string) bool { return slices.Contains(allowed, v) }) {
		return "acr"
	}
	return ""
}

// SkippedApps are the apps of the steps a pre-check skipped, in order: the
// context of the final accept carries them (x_dispatcher_skipped_steps).
func (f *Flow) SkippedApps() []string {
	var apps []string
	for _, s := range f.Steps {
		if s.Skipped {
			apps = append(apps, s.App)
		}
	}
	return apps
}
