package flow

import (
	"encoding/json"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// preferredPrefix marks, in acr_values, the flow the client prefers.
const preferredPrefix = "urn:hydra-dispatcher:preferred-app:"

// offer is what the choice rules (CHX) make of a flow's login request.
type offer struct {
	// reject, when set, rejects the login request: no flow is left.
	reject      Reason
	description string
	// start is the flow to start without a page, imposed or not.
	start   string
	imposed bool
	// flows are the candidates, in the snapshot's order.
	flows []string
	// clientOnly is the one flow the client's restriction leaves, "" when
	// none or several, and preferred the flow acr_values prefers, when it is
	// a candidate: chosen by any path, either is imposed (Q29).
	clientOnly string
	preferred  string
	reports    []Report
}

// offer evaluates the choice rules on the login request kept in f (CHX):
// flows enabled, by id, restricted to the client's metadata.dispatcher.flows
// (unknown ids ignored, with a warning), then to those whose acr is among the
// acr_values other than the preferred flow's prefix.
func (r *run) offer(f *Flow) offer {
	cfg := r.Env.Config
	var o offer
	for _, fl := range cfg.Flows {
		if fl.Enabled {
			o.flows = append(o.flows, fl.ID)
		}
	}
	if ids, restricted := clientFlows(f.Hydra.Client); restricted {
		for _, id := range ids {
			if !slices.ContainsFunc(cfg.Flows, func(fl store.Flow) bool { return fl.ID == id }) {
				o.reports = append(o.reports, Report{Event: "config.warning", Detail: "client restriction names an unknown flow " + id})
			}
		}
		o.flows = slices.DeleteFunc(o.flows, func(id string) bool { return !slices.Contains(ids, id) })
		if len(o.flows) == 0 {
			o.reject, o.description = ReasonRestricted, "The client's metadata.dispatcher.flows leaves no flow enabled."
			return o
		}
		if len(o.flows) == 1 {
			o.clientOnly = o.flows[0]
		}
	}
	acr, preferred := acrValues(f.Hydra.OIDCContext)
	if len(acr) > 0 {
		o.flows = slices.DeleteFunc(o.flows, func(id string) bool {
			fl, _ := flowOf(cfg, id)
			return !slices.Contains(acr, fl.ACR)
		})
		if len(o.flows) == 0 {
			o.reject, o.description = ReasonUnmet, "No flow meets the acr_values requested."
			return o
		}
	}
	switch {
	case preferred != "" && slices.Contains(o.flows, preferred):
		o.start, o.imposed, o.preferred = preferred, true, preferred
	case preferred != "":
		o.reports = append(o.reports, Report{Event: "config.warning", Detail: "preferred flow not offered, ignored: " + preferred})
		fallthrough
	default:
		if len(o.flows) == 1 && cfg.Settings.AppAutoSelect {
			o.start, o.imposed = o.flows[0], o.flows[0] == o.clientOnly
		}
	}
	return o
}

// clientFlows returns the client's metadata.dispatcher.flows, and whether it
// restricts the flows. A restriction that is not a list of ids, or a
// dispatcher member that is not an object, leaves none: it only ever narrows
// what the client may use. Metadata that is not an object holds no
// restriction.
func clientFlows(client json.RawMessage) ([]string, bool) {
	var c struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	_ = json.Unmarshal(client, &c) // a client that is no object has no metadata
	var metadata, dispatcher map[string]json.RawMessage
	_ = json.Unmarshal(c.Metadata, &metadata)
	d, ok := metadata["dispatcher"]
	if !ok || isNull(d) {
		return nil, false
	}
	if json.Unmarshal(d, &dispatcher) != nil {
		return nil, true
	}
	flows, ok := dispatcher["flows"]
	if !ok || isNull(flows) {
		return nil, false
	}
	var ids []string
	if json.Unmarshal(flows, &ids) != nil {
		return nil, true
	}
	return ids, true
}

// acrValues returns the oidc_context's acr_values other than the preferred
// flow's, and the preferred flow, the first one named.
func acrValues(oidc json.RawMessage) ([]string, string) {
	var o struct {
		ACRValues []string `json:"acr_values"`
	}
	_ = json.Unmarshal(oidc, &o) // none read is none asked
	var acr []string
	preferred := ""
	for _, v := range o.ACRValues {
		if id, ok := strings.CutPrefix(v, preferredPrefix); ok {
			if preferred == "" {
				preferred = id
			}
		} else {
			acr = append(acr, v)
		}
	}
	return acr, preferred
}

func flowOf(cfg *store.Snapshot, id string) (store.Flow, bool) {
	i := slices.IndexFunc(cfg.Flows, func(fl store.Flow) bool { return fl.ID == id })
	if i < 0 {
		return store.Flow{}, false
	}
	return cfg.Flows[i], true
}

// restart returns f back to the choice (RA1): its generation incremented, so
// that every step challenge issued becomes stale, nothing chosen.
func (f *Flow) restart() *Flow {
	g := *f
	g.Gen++
	g.FlowID, g.Imposed, g.ACR, g.Subject, g.Current, g.Steps = "", false, "", "", 0, nil
	return &g
}

// clone returns a copy of f whose steps may be changed.
func (f *Flow) clone() *Flow {
	g := *f
	g.Steps = slices.Clone(f.Steps)
	return &g
}

// choice applies the choice rules to f, a flow being created or back to the
// choice, written in every case: a rejection, a start, or the page.
func (r *run) choice(ref string, f *Flow) Outcome {
	o := r.offer(f)
	var out Outcome
	switch {
	case o.reject != 0:
		out = r.rejectLogin(f, o.reject, rejection(o.reject, o.description), func(to string) Outcome {
			return r.page().redirect(to)
		})
	case o.start != "":
		out = r.start(ref, f, o.start, o.imposed, "auto_select")
	default:
		out = r.choicePage(f, o, false).writing(f)
	}
	out.Reports = append(o.reports, out.Reports...)
	return out
}

// start starts the flow id on f: its steps copied (Q21), the first one
// current, and the browser sent straight to the first app's login_url (M3,
// A5), without going through /oauth2/auth.
func (r *run) start(ref string, f *Flow, id string, imposed bool, trigger string) Outcome {
	fl, ok := flowOf(r.Env.Config, id)
	if !ok || len(fl.Steps) == 0 {
		return r.page().fail(E1005)
	}
	g := f.clone()
	g.FlowID, g.Imposed, g.ACR, g.Current = id, imposed, fl.ACR, 1
	if g.StartedAt == 0 {
		g.StartedAt = r.now()
	}
	g.Steps = make([]Step, len(fl.Steps))
	dev := r.device()
	g.DeviceAt = 0
	if !dev.None() {
		g.DeviceAt = dev.Created
	}
	for i, s := range fl.Steps {
		g.Steps[i] = Step{App: s.AppID, Check: s.SubjectCheck}
		if s.SubjectCheck == "none" {
			g.Steps[i].Check = ""
		}
		if !dev.None() {
			g.Steps[i].Device = DeviceValue(dev.ID, s.AppID)
		}
	}
	if imposed && trigger == "auto_select" {
		trigger = "acr"
	}
	out := r.toStep(ref, g, 1, KindLogin)
	if out.Response.Kind != Redirect {
		return out // E1005, the flow unchanged
	}
	return out.writing(g).report(Report{Event: "flow.started", Detail: trigger})
}

// toStep sends the browser to the app of step k, for its login or its
// consent; an app gone from the snapshot is E1005 (BCL-11).
func (r *run) toStep(ref string, f *Flow, k int, kind Kind) Outcome {
	app, ok := r.Env.Config.App(f.Steps[k-1].App)
	if !ok {
		return r.page().fail(E1005)
	}
	challenge := r.Env.Keys.Challenge(ref, f.Gen, app.ID, kind)
	if kind == KindLogin {
		return r.page().redirect(withQuery(app.LoginURL, "login_challenge", challenge))
	}
	return r.page().redirect(withQuery(app.ConsentURL, "consent_challenge", challenge))
}

// choicePage is the choice page of f (CHX-5).
func (r *run) choicePage(f *Flow, o offer, invalid bool) Outcome {
	var oidc struct {
		UILocales []string `json:"ui_locales"`
	}
	_ = json.Unmarshal(f.Hydra.OIDCContext, &oidc) // none read is none asked
	return Outcome{Response: Response{Kind: ChoicePage, Choice: &ChoiceScreen{
		Flows:          o.flows,
		LoginChallenge: f.LoginChallenge,
		CSRF:           f.CSRF,
		Client:         f.Hydra.Client,
		Invalid:        invalid,
		UILocales:      oidc.UILocales,
	}}}
}
