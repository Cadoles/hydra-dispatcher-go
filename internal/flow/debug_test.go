package flow

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/loglevel"
)

// namesOf are the names of the line of debug event of p, nil when it has none.
func namesOf(p played, event string) *ClaimNames {
	for _, r := range p.Reports {
		if r.Event == event && r.Debug {
			return r.Names
		}
	}
	return nil
}

func sameNames(got, want []string) bool { return got != nil && slices.Equal(got, want) }

// The lines of debug of the claims (Q132): those merged from the steps and
// those a later step gave another value; those each token sends, those the
// strict filter or receive_claims leave out. Names, never values.
func TestClaimsReports(t *testing.T) {
	skip := func(r *ory.OAuth2ConsentRequest) { r.Skip = ory.PtrBool(true) }
	says := hydraSays{GetConsent: said{consent: consentRequest(lref, skip)}, AcceptConsent: {redirectTo: hydraDone}}
	get := Consent{Challenge: hydraC, Cookie: cookie}

	// Strict: step, of no scope asked, left out; given by both steps, another
	// value each time.
	env := testEnv()
	env.StrictClaims = true
	p := play(t, env, get, acceptedFlow(t), nil, says)
	if n := namesOf(p, "claims.merged"); n == nil || !sameNames(n.IDToken, []string{"email", "step"}) || !sameNames(n.AccessToken, []string{}) ||
		!sameNames(n.Conflicts, []string{"step"}) {
		t.Errorf("merged %+v", n)
	}
	if n := namesOf(p, "claims.filtered"); n == nil || !sameNames(n.IDToken, []string{"email"}) || !sameNames(n.AccessToken, []string{}) ||
		!sameNames(n.Dropped, []string{"step"}) {
		t.Errorf("filtered %+v", n)
	}
	values, _ := json.Marshal(p.Reports)
	if strings.Contains(string(values), "alice@example.org") || strings.Contains(string(values), `"2fa"`) {
		t.Errorf("a value in the reports: %s", values)
	}
	// Permissive: nothing left out; the same value twice is no conflict.
	f := acceptedFlow(t)
	f.Steps[1].IDToken["step"] = f.Steps[0].IDToken["step"]
	p = play(t, testEnv(), get, f, nil, says)
	if n := namesOf(p, "claims.merged"); n == nil || !sameNames(n.Conflicts, []string{}) {
		t.Errorf("merged %+v", n)
	}
	if n := namesOf(p, "claims.filtered"); n == nil || !sameNames(n.IDToken, []string{"email", "step"}) || !sameNames(n.Dropped, []string{}) {
		t.Errorf("permissive %+v", n)
	}
	// A null is no value: neither merged nor a conflict.
	f = acceptedFlow(t)
	f.Steps[1].IDToken["step"] = json.RawMessage("null")
	f.Steps[1].AccessToken = Object{"scope": json.RawMessage(`"x"`)}
	if n := namesOf(play(t, testEnv(), get, f, nil, says), "claims.merged"); n == nil || !sameNames(n.Conflicts, []string{}) ||
		!sameNames(n.AccessToken, []string{"scope"}) {
		t.Errorf("null %+v", n)
	}
	// The screen, before any accept: no line of the claims.
	if p := play(t, env, get, acceptedFlow(t), nil, hydraSays{GetConsent: said{consent: consentRequest(lref, nil)}}); namesOf(p, "claims.filtered") != nil {
		t.Errorf("a screen: %+v", p.Reports)
	}

	// The skip, from the cookie: the filter alone, no steps to merge.
	strict := testEnv()
	strict.StrictClaims = true
	p = play(t, strict, Consent{Challenge: hydraC, Cookie: cookie, Memory: memory(nil)}, nil, nil,
		hydraSays{GetConsent: said{consent: consentSkip(nil)}, AcceptConsent: {redirectTo: callbackURL}})
	if n := namesOf(p, "claims.merged"); n != nil {
		t.Errorf("a skip merged %+v", n)
	}
	if n := namesOf(p, "claims.filtered"); n == nil || !sameNames(n.IDToken, []string{"email", "name"}) || !sameNames(n.AccessToken, []string{}) ||
		!sameNames(n.Dropped, []string{"groups"}) {
		t.Errorf("skip %+v", n)
	}

	// An app reading its request: what receive_claims leaves out of the
	// previous steps' claims.
	for _, c := range []struct {
		ev           AppCall
		stored       *Flow
		claims, gone []string
		app          string
	}{
		{callBy(AppGetLogin, 1000, "2fa", ""), atStep(t, 2, false, false), []string{"email"}, []string{"step"}, "2fa"},
		{callBy(AppGetConsent, 1000, "2fa", ""), atStep(t, 2, true, false), []string{"email"}, []string{"step"}, "2fa"},
		{callBy(AppGetLogin, 1000, "sql", ""), atStep(t, 1, false, false), []string{}, []string{}, "sql"},
	} {
		p := play(t, testEnv(), c.ev, c.stored, nil, nil)
		r := slices.IndexFunc(p.Reports, func(r Report) bool { return r.Event == "claims.filtered" })
		if p.Response.Kind != AppJSON || r < 0 || p.Reports[r].App != c.app || !sameNames(p.Reports[r].Names.Claims, c.claims) ||
			!sameNames(p.Reports[r].Names.Dropped, c.gone) {
			t.Errorf("%s %v: %+v %+v", c.app, c.ev.Op, p.Response, p.Reports)
		}
	}
}

// scopedHydra records the flow and the app of each accept's context.
type scopedHydra struct {
	*fakeHydra
	scopes []string
}

func (h *scopedHydra) AcceptLogin(ctx context.Context, c string, body ory.AcceptOAuth2LoginRequest) (string, error) {
	flow, app := loglevel.Scope(ctx)
	h.scopes = append(h.scopes, "accept_login "+flow+" "+app)
	return h.fakeHydra.AcceptLogin(ctx, c, body)
}

func (h *scopedHydra) AcceptConsent(ctx context.Context, c string, body ory.AcceptOAuth2ConsentRequest) (string, error) {
	flow, app := loglevel.Scope(ctx)
	h.scopes = append(h.scopes, "accept_consent "+flow+" "+app)
	return h.fakeHydra.AcceptConsent(ctx, c, body)
}

// flow.transition for each request (Q132): its event, the step before and
// after, its answer; the flow and the app its calls and its lines are about.
func TestTransitionLines(t *testing.T) {
	w := newWorld(t)
	w.o.Log = slog.New(slog.NewJSONHandler(&w.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := &scopedHydra{fakeHydra: w.hydra}
	w.o.Hydra = h
	w.hydra.consentSkip = true
	w.handle(Entry{LoginChallenge: hydraL})
	step := w.handle(Choose{FlowID: "hydra-sql", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true})
	w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
	w.handle(Loop{Ref: lref, Cookie: w.cookie})
	w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
	w.handle(Loop{Ref: lref, Cookie: w.cookie}) // the flow finished
	var lines []string
	for l := range strings.SplitSeq(strings.TrimSpace(w.logs.String()), "\n") {
		if strings.Contains(l, `"msg":"flow.transition"`) {
			_, rest, _ := strings.Cut(l, `"msg":"flow.transition",`)
			lines = append(lines, strings.TrimSuffix(rest, "}"))
		}
	}
	want := []string{
		`"event":"entry","step_before":0,"step_after":0,"outcome":"choice_page"`,
		`"event":"choice","step_before":0,"step_after":1,"outcome":"redirect","flow":"hydra-sql","app":"sql"`,
		`"event":"app_call","step_before":1,"step_after":1,"outcome":"app_json","operation":"get_login","status":200,"flow":"hydra-sql","app":"sql"`,
		`"event":"app_call","step_before":1,"step_after":1,"outcome":"app_json","operation":"accept_login","status":200,"flow":"hydra-sql","app":"sql"`,
		`"event":"loop","step_before":1,"step_after":1,"outcome":"redirect","flow":"hydra-sql","app":"sql"`,
		`"event":"app_call","step_before":1,"step_after":1,"outcome":"app_json","operation":"get_consent","status":200,"flow":"hydra-sql","app":"sql"`,
		`"event":"app_call","step_before":1,"step_after":1,"outcome":"app_json","operation":"accept_consent","status":200,"flow":"hydra-sql","app":"sql"`,
		`"event":"loop","step_before":1,"step_after":1,"outcome":"redirect","flow":"hydra-sql","app":"sql"`,
		`"event":"consent","step_before":1,"step_after":0,"outcome":"redirect","flow":"hydra-sql"`,
		`"event":"loop","step_before":0,"step_after":0,"outcome":"error_page","error_code":"E1002","flow":"hydra-sql"`,
	}
	if !slices.Equal(lines, want) {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(h.scopes, []string{"accept_login hydra-sql sql", "accept_consent hydra-sql sql"}) {
		t.Errorf("the scopes of the calls: %q", h.scopes)
	}
	if strings.Contains(w.logs.String(), "alice") || strings.Contains(w.logs.String(), hydraL) {
		t.Errorf("a subject or a challenge in the lines:\n%s", w.logs.String())
	}
	// Above the level debug, none.
	w.logs.Reset()
	w.o.Log = slog.New(slog.NewJSONHandler(&w.logs, nil))
	w.handle(Entry{LoginChallenge: "forged-forged-forged"})
	if strings.Contains(w.logs.String(), "flow.transition") {
		t.Errorf("at info:\n%s", w.logs.String())
	}
}
