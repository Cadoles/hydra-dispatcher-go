package flow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// fakeChecker answers the pre-checks as said, by app, or by answer when
// set, and keeps the calls; during runs before its first answer, as another
// request of the browser would meanwhile.
type fakeChecker struct {
	mu     sync.Mutex
	says   map[string]SkipCheckAnswer
	answer func(SkipCheckCall) SkipCheckAnswer
	during func()
	calls  []SkipCheckCall
}

func (c *fakeChecker) Check(_ context.Context, call SkipCheckCall) SkipCheckAnswer {
	if during := c.during; during != nil {
		c.during = nil
		during()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
	if c.answer != nil {
		return c.answer(call)
	}
	return c.says[call.App]
}

func (c *fakeChecker) apps() []string {
	var apps []string
	for _, call := range c.calls {
		apps = append(apps, call.App)
	}
	return apps
}

var testDevice = Device{ID: []byte("0123456789abcdef0123456789abcdef"), Created: 1_700_000_000}

// skipWorld is a world whose 2fa and oidc ask for the pre-check: the flow
// sql-2fa its second step, sql-2fa-oidc its second and third.
func skipWorld(t *testing.T, says map[string]SkipCheckAnswer) (*world, *fakeChecker) {
	t.Helper()
	w := newWorld(t)
	apps := testApps()
	for i := range apps {
		if apps[i].ID != "sql" {
			apps[i].SkipCheckURL, apps[i].SkipCheckKey = "https://"+apps[i].ID+".hydra.test/skip-check", strings.Repeat("ab", 32)
		}
	}
	flows := append(testFlows(),
		store.Flow{ID: "sql-2fa", Enabled: true, ACR: "loa3", SkipCheckAllowedACR: []string{"loa2"}, Steps: []store.Step{
			{AppID: "sql", Position: 1, SubjectCheck: "none"}, {AppID: "2fa", Position: 2, SubjectCheck: "equal", SkipCheck: true}}},
		store.Flow{ID: "sql-oidc", Enabled: true, Steps: []store.Step{
			{AppID: "sql", Position: 1, SubjectCheck: "none"}, {AppID: "oidc", Position: 2, SubjectCheck: "equal", SkipCheck: true}}},
		store.Flow{ID: "sql-2fa-oidc", Enabled: true, Steps: []store.Step{
			{AppID: "sql", Position: 1, SubjectCheck: "none"}, {AppID: "2fa", Position: 2, SubjectCheck: "equal", SkipCheck: true},
			{AppID: "oidc", Position: 3, SubjectCheck: "equal", SkipCheck: true}}})
	w.o.Config = snapshots{store.NewSnapshot(apps, flows, store.DefaultSettings())}
	c := &fakeChecker{says: says}
	w.o.SkipCheck = c
	return w, c
}

// throughSQL chooses flowID with the device dev, then plays sql, the first
// step, and returns the answer of the way back to the dispatcher.
func throughSQL(t *testing.T, w *world, flowID string, dev Device) Result {
	t.Helper()
	w.handle(Entry{LoginChallenge: hydraL, Device: dev})
	step := w.handle(Choose{FlowID: flowID, LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true, Device: dev})
	w.app(t, "sql", step, "alice", `{"email":"alice@example.org","name":"Alice"}`)
	return w.handle(Loop{Ref: lref, Cookie: w.cookie})
}

func reportsOf(r Result, event string) []Report {
	var l []Report
	for _, rep := range r.Reports {
		if rep.Event == event {
			l = append(l, rep)
		}
	}
	return l
}

// A step the app says may be skipped (P27b): the call carries the subject,
// the app's device value and the claims it receives; the step is done, the
// flow accepted on Hydra straight away, its context naming the step skipped,
// its amr the app's method; the result reported, the skip audited.
func TestSkipCheckSkips(t *testing.T) {
	w, c := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped,
		Context: Object{"device": json.RawMessage(`"known"`)}, IDToken: Object{"email": json.RawMessage(`"alice@example.org"`)}}})
	final := throughSQL(t, w, "sql-2fa", testDevice)
	if final.Response.URL != verifierURL {
		t.Fatalf("final accept: %+v", final.Response)
	}
	if len(c.calls) != 1 {
		t.Fatalf("calls: %+v", c.calls)
	}
	call := c.calls[0]
	if call.K != 2 || call.App != "2fa" || call.Subject != "alice" || call.Device != DeviceValue(testDevice.ID, "2fa") || call.Flow != "sql-2fa" ||
		call.DeviceAt != testDevice.Created || claimsJSON(call.Claims) != `{"email":"alice@example.org"}` {
		t.Errorf("call: %+v", call)
	}
	f := w.stored()
	if !f.Steps[1].Skipped || !f.Steps[1].LoginOK || !f.Steps[1].ConsentOK || f.Steps[1].Subject != "alice" {
		t.Errorf("step: %+v", f.Steps[1])
	}
	var skipped []string
	if err := json.Unmarshal(w.hydra.accepted.Context.(Object)["x_dispatcher_skipped_steps"], &skipped); err != nil || !slices.Equal(skipped, []string{"2fa"}) {
		t.Errorf("context: %v %v", w.hydra.accepted.Context, err)
	}
	if !slices.Equal(w.hydra.accepted.Amr, []string{"pwd", "otp"}) {
		t.Errorf("amr: %q", w.hydra.accepted.Amr)
	}
	if reps := reportsOf(final, eventSkipCheck); len(reps) != 1 || reps[0].Result != SkipSkipped || reps[0].App != "2fa" {
		t.Errorf("reports: %+v", final.Reports)
	}
	if reps := reportsOf(final, EventStepSkipped); len(reps) != 1 || reps[0].App != "2fa" {
		t.Errorf("audit: %+v", final.Reports)
	}
}

// Two steps skipped in a row, then the final accept; the second keeps its
// subject_check.
func TestSkipCheckChain(t *testing.T) {
	w, c := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped}, "oidc": {Skip: true, Result: SkipSkipped}})
	if final := throughSQL(t, w, "sql-2fa-oidc", testDevice); final.Response.URL != verifierURL || !slices.Equal(c.apps(), []string{"2fa", "oidc"}) {
		t.Fatalf("final: %+v, calls %q", final.Response, c.apps())
	}
	if got := w.stored().SkippedApps(); !slices.Equal(got, []string{"2fa", "oidc"}) {
		t.Errorf("skipped: %q", got)
	}
}

// Every way to run the step after all: the app declines or fails, the
// subject it gives breaks the step's rule, no client; the browser to the
// app's login_url, its result reported.
func TestSkipCheckRunsTheStep(t *testing.T) {
	for name, tt := range map[string]struct {
		answer SkipCheckAnswer
		result string
	}{
		"declined":      {SkipCheckAnswer{Result: SkipDeclined}, SkipDeclined},
		"failed":        {SkipCheckAnswer{Result: SkipFailed, Cause: "timeout"}, SkipFailed},
		"other subject": {SkipCheckAnswer{Skip: true, Subject: "mallory", Result: SkipSkipped}, SkipRefused},
	} {
		w, _ := skipWorld(t, map[string]SkipCheckAnswer{"2fa": tt.answer})
		r := throughSQL(t, w, "sql-2fa", testDevice)
		if !strings.HasPrefix(r.Response.URL, "http://2fa.hydra.test/login?") || w.stored().Steps[1].Skipped {
			t.Errorf("%s: %+v", name, r.Response)
		}
		if reps := reportsOf(r, eventSkipCheck); len(reps) != 1 || reps[0].Result != tt.result {
			t.Errorf("%s: reports %+v", name, r.Reports)
		}
	}
	w, _ := skipWorld(t, nil)
	w.o.SkipCheck = nil
	if r := throughSQL(t, w, "sql-2fa", testDevice); !strings.HasPrefix(r.Response.URL, "http://2fa.hydra.test/login?") || reportsOf(r, eventSkipCheck)[0].Reason != "no_client" {
		t.Errorf("no client: %+v", r)
	}
}

// The guards, each without a call: no device, prompt=login, a max_age,
// acr_values the flow does not allow the skip under; acr_values it allows go
// on. The flow declares loa3, which the client may ask (CHX-1).
func TestSkipCheckGuards(t *testing.T) {
	for name, tt := range map[string]struct {
		dev     Device
		url     string
		acr     []string
		reason  string
		called  bool
		allowed bool
	}{
		"no device":   {dev: Device{}, reason: "no_device"},
		"prompt":      {dev: testDevice, url: "&prompt=consent%20login", reason: "prompt"},
		"max_age":     {dev: testDevice, url: "&max_age=3600", reason: "max_age"},
		"acr refused": {dev: testDevice, acr: []string{"loa3"}, reason: "acr"},
		"acr allowed": {dev: testDevice, acr: []string{"loa3", "loa2"}, called: true},
	} {
		w, c := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Result: SkipDeclined}})
		w.hydra.login.RequestUrl += tt.url
		if tt.acr != nil {
			w.hydra.login.OidcContext = &ory.OAuth2ConsentRequestOpenIDConnectContext{AcrValues: tt.acr}
		}
		r := throughSQL(t, w, "sql-2fa", tt.dev)
		if r.Response.Kind != Redirect || !strings.HasPrefix(r.Response.URL, "http://2fa.hydra.test/login?") || (len(c.calls) > 0) != tt.called {
			t.Errorf("%s: %+v, calls %d", name, r.Response, len(c.calls))
			continue
		}
		if !tt.called {
			if reps := reportsOf(r, eventSkipCheck); len(reps) != 1 || reps[0].Result != SkipRefused || reps[0].Reason != tt.reason {
				t.Errorf("%s: reports %+v", name, r.Reports)
			}
		}
	}
	// An app without its URL in the configuration of the moment: refused.
	w, c := skipWorld(t, nil)
	snap := w.o.Config.Snapshot()
	apps := slices.Clone(snap.Apps)
	for i := range apps {
		apps[i].SkipCheckURL = ""
	}
	w.o.Config = snapshots{store.NewSnapshot(apps, snap.Flows, store.DefaultSettings())}
	if r := throughSQL(t, w, "sql-2fa", testDevice); len(c.calls) != 0 || reportsOf(r, eventSkipCheck)[0].Reason != "no_url" || r.Response.Status == http.StatusInternalServerError {
		t.Errorf("no URL: %+v", r)
	}
}

// claimsJSON is the JSON of claims, as the call sends them.
func claimsJSON(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return string(b)
}

// Five steps skipped in a row: four pre-checks, the fifth step runs, its
// pre-check refused (maxSkipChecks).
func TestSkipCheckChainBound(t *testing.T) {
	w, c := skipWorld(t, nil)
	snap := w.o.Config.Snapshot()
	apps, steps := slices.Clone(snap.Apps), []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}}
	c.says = map[string]SkipCheckAnswer{}
	for i := 2; i <= 6; i++ {
		id := "f" + string(rune('0'+i))
		apps = append(apps, store.App{ID: id, LoginURL: "http://" + id + ".hydra.test/login", ConsentURL: "http://" + id + ".hydra.test/consent",
			Method: id, SkipCheckURL: "https://" + id + ".hydra.test/skip", SkipCheckKey: strings.Repeat("ab", 32)})
		steps = append(steps, store.Step{AppID: id, Position: i, SubjectCheck: "equal", SkipCheck: true})
		c.says[id] = SkipCheckAnswer{Skip: true, Result: SkipSkipped}
	}
	w.o.Config = snapshots{store.NewSnapshot(apps, append(snap.Flows, store.Flow{ID: "long", Enabled: true, Steps: steps}), store.DefaultSettings())}
	r := throughSQL(t, w, "long", testDevice)
	if !strings.HasPrefix(r.Response.URL, "http://f6.hydra.test/login?") || len(c.calls) != maxSkipChecks {
		t.Fatalf("%+v, calls %q", r.Response, c.apps())
	}
	if reps := reportsOf(r, eventSkipCheck); len(reps) != 5 || reps[4].Reason != "chain" {
		t.Errorf("reports: %+v", reps)
	}
}

// Under aggregate_amr_from_login_request, a step skipped gives its app's
// method, as it would without (the amr of the answer is not taken).
func TestSkipCheckAggregateAMR(t *testing.T) {
	w, _ := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped}})
	snap := w.o.Config.Snapshot()
	settings := store.DefaultSettings()
	settings.AggregateAMRFromLoginRequest = true
	w.o.Config = snapshots{store.NewSnapshot(snap.Apps, snap.Flows, settings)}
	w.handle(Entry{LoginChallenge: hydraL, Device: testDevice})
	step := w.handle(Choose{FlowID: "sql-2fa", LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true, Device: testDevice})
	w.app(t, "sql", step, "alice", `{"email":"alice@example.org"}`)
	if final := w.handle(Loop{Ref: lref, Cookie: w.cookie}); final.Response.URL != verifierURL || !slices.Contains(w.hydra.accepted.Amr, "otp") {
		t.Errorf("%+v, amr %q", final.Response, w.hydra.accepted.Amr)
	}
}

// The lines of the log (P27c): a pre-check failing, step.skip_check_failed
// at warn with its cause and duration; one that skips, a line of the level
// debug alone, and step.skipped at info.
func TestSkipCheckLogs(t *testing.T) {
	w, _ := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Result: SkipFailed, Cause: "timeout", Elapsed: 301 * time.Millisecond}})
	throughSQL(t, w, "sql-2fa", testDevice)
	line := logLine(t, w, "step.skip_check_failed")
	if line["level"] != "WARN" || line["app"] != "2fa" || line["reason"] != "timeout" || line["duration_ms"] != float64(301) {
		t.Errorf("failed: %v", line)
	}
	w, _ = skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped}})
	throughSQL(t, w, "sql-2fa", testDevice)
	if strings.Contains(w.logs.String(), `"msg":"step.skip_check"`) {
		t.Errorf("a pre-check at info: %s", w.logs.String())
	}
	if line := logLine(t, w, EventStepSkipped); line["level"] != "INFO" || line["app"] != "2fa" {
		t.Errorf("skipped: %v", line)
	}
}

// logLine is the line of the log of w named msg, decoded.
func logLine(t *testing.T, w *world, msg string) map[string]any {
	t.Helper()
	for l := range strings.SplitSeq(w.logs.String(), "\n") {
		var line map[string]any
		if json.Unmarshal([]byte(l), &line) == nil && line["msg"] == msg {
			return line
		}
	}
	t.Fatalf("no %s in %s", msg, w.logs.String())
	return nil
}

// R50, B1: an answer is for the call it was asked for. During the pre-check
// of 2fa for alice, the same browser goes back to the choice and plays sql
// again, as bob, or into another flow whose second step is oidc; the write
// of the first request conflicts, the flow is read again: the answer for
// alice's 2fa skips nothing there, the step runs, no second call.
func TestSkipCheckStaleAnswer(t *testing.T) {
	for _, tt := range []struct{ flow, subject, app string }{
		{"sql-2fa-oidc", "bob", "2fa"},
		{"sql-oidc", "alice", "oidc"},
	} {
		w, c := skipWorld(t, nil)
		c.answer = func(call SkipCheckCall) SkipCheckAnswer {
			if call.App == "2fa" && call.Subject == "alice" {
				return SkipCheckAnswer{Skip: true, Result: SkipSkipped}
			}
			return SkipCheckAnswer{Result: SkipDeclined}
		}
		c.during = func() {
			step := w.handle(Choose{FlowID: tt.flow, LoginChallenge: hydraL, Token: w.cookie, Cookie: w.cookie, SameOrigin: true, Device: testDevice})
			w.app(t, "sql", step, tt.subject, `{"email":"`+tt.subject+`@example.org"}`)
		}
		r := throughSQL(t, w, "sql-2fa-oidc", testDevice)
		f := w.stored()
		if f.FlowID != tt.flow || f.Subject != tt.subject || f.Current != 2 || f.Steps[1].Skipped || f.Sent != nil {
			t.Errorf("%s: flow %s, subject %s, current %d, skipped %v", tt.flow, f.FlowID, f.Subject, f.Current, f.Steps[1].Skipped)
		}
		if !strings.HasPrefix(r.Response.URL, "http://"+tt.app+".hydra.test/login?") || w.hydra.accepted != nil {
			t.Errorf("%s: %+v", tt.flow, r.Response)
		}
		if reps := reportsOf(r, eventSkipCheck); len(reps) != 1 || reps[0].Result != SkipRefused || reps[0].Reason != "changed" {
			t.Errorf("%s: reports %+v", tt.flow, reps)
		}
	}
}

// R50 H1, Q140: the memory of the skip keeps the apps skipped, beside the amr
// they describe; a second login in the same Hydra session, Hydra's skip
// honoured from it, carries them again in its accept's context.
func TestSkipCheckRemembered(t *testing.T) {
	w, _ := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped}})
	w.hydra.consentSkip = true
	if final := throughSQL(t, w, "sql-2fa", testDevice); final.Response.URL != verifierURL {
		t.Fatalf("final accept: %+v", final.Response)
	}
	c := w.handle(Consent{Challenge: hydraC, Cookie: w.cookie})
	if c.Response.Remember == nil || !slices.Equal(c.Response.Remember.SK, []string{"2fa"}) {
		t.Fatalf("memory: %+v", c.Response.Remember)
	}
	w.hydra.login.Skip, w.hydra.login.Subject = true, "alice"
	if r := w.handle(Entry{LoginChallenge: hydraL2, Memory: Memory{Content: c.Response.Remember}}); r.Response.URL != verifierURL {
		t.Fatalf("SKP-1: %+v", r.Response)
	}
	var skipped []string
	ctx := w.hydra.accepted.Context.(Object)
	if err := json.Unmarshal(ctx["x_dispatcher_skipped_steps"], &skipped); err != nil || !slices.Equal(skipped, []string{"2fa"}) ||
		!slices.Equal(w.hydra.accepted.Amr, []string{"pwd", "otp"}) {
		t.Errorf("the skip's accept: %v, amr %q", ctx, w.hydra.accepted.Amr)
	}
}

// recordingHooks keep the context the login webhook receives; fail makes
// it fail.
type recordingHooks struct {
	fail     bool
	contexts []Object
}

func (h *recordingHooks) Login(_ context.Context, c Call) LoginHookAnswer {
	ctx, _ := c.AcceptLogin.Context.(Object)
	h.contexts = append(h.contexts, ctx)
	if h.fail {
		return LoginHookAnswer{Err: errors.New("down")}
	}
	return LoginHookAnswer{}
}

func (h *recordingHooks) Consent(context.Context, Call) ConsentHookAnswer { return ConsentHookAnswer{} }

// The login webhook receives x_dispatcher_skipped_steps (R50). The skip is
// audited when it takes effect: not on a final accept that fails (FIN-4, the
// webhook down), once on the reload that goes through, which calls again
// (R50).
func TestSkipCheckWebhookAndAudit(t *testing.T) {
	w, c := skipWorld(t, map[string]SkipCheckAnswer{"2fa": {Skip: true, Result: SkipSkipped}})
	snap := w.o.Config.Snapshot()
	settings := store.DefaultSettings()
	settings.LoginAcceptWebhookURL = "http://hooks.test/login"
	w.o.Config = snapshots{store.NewSnapshot(snap.Apps, snap.Flows, settings)}
	hooks := &recordingHooks{fail: true}
	w.o.Webhooks = hooks
	r := throughSQL(t, w, "sql-2fa", testDevice)
	if r.Response.Code != E1006 || len(reportsOf(r, EventStepSkipped)) != 0 || w.stored().Steps[1].Skipped {
		t.Fatalf("FIN-4: %+v, reports %+v", r.Response, r.Reports)
	}
	var skipped []string
	if len(hooks.contexts) != 1 || json.Unmarshal(hooks.contexts[0]["x_dispatcher_skipped_steps"], &skipped) != nil || !slices.Equal(skipped, []string{"2fa"}) {
		t.Errorf("the webhook's context: %v", hooks.contexts)
	}
	hooks.fail = false
	r = w.handle(Loop{Ref: lref, Cookie: w.cookie})
	if r.Response.URL != verifierURL || len(reportsOf(r, EventStepSkipped)) != 1 || len(c.calls) != 2 {
		t.Errorf("the reload: %+v, reports %+v, %d calls", r.Response, r.Reports, len(c.calls))
	}
}

// An app with its URL and without its key in the configuration of the
// moment: refused, no call (R50).
func TestSkipCheckWithoutKey(t *testing.T) {
	w, c := skipWorld(t, nil)
	snap := w.o.Config.Snapshot()
	apps := slices.Clone(snap.Apps)
	for i := range apps {
		apps[i].SkipCheckKey = ""
	}
	w.o.Config = snapshots{store.NewSnapshot(apps, snap.Flows, store.DefaultSettings())}
	if r := throughSQL(t, w, "sql-2fa", testDevice); len(c.calls) != 0 || reportsOf(r, eventSkipCheck)[0].Reason != "no_url" {
		t.Errorf("no key: %+v", r)
	}
}
