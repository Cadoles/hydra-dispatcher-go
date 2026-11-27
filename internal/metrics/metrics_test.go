package metrics

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"github.com/Cadoles/hydra-dispatcher-go/internal/state"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

func scrape(t *testing.T, m *Metrics, accept ...string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if len(accept) > 0 {
		r.Header.Set("Accept", accept[0])
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: %d %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// series is the value of a series as written, "" when it does not exist.
func series(body, name string) string {
	for line := range strings.Lines(body) {
		if rest, ok := strings.CutPrefix(line, namespace+"_"+name+" "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// The catalogue of the doc that phase 1 feeds, in full: a metric added or renamed
// without the doc fails here (Cardinalité). encrypted_values comes with the secrets in the
// database (phase 3), step_skips_total with the step check (phase 4).
func TestCatalogue(t *testing.T) {
	m := New(200, nil)
	exercise(m, []string{"hydra-sql"}, []string{"sql"})
	want := map[string]struct {
		kind   string
		labels []string
	}{
		"login_requests_total":                  {"counter", []string{"flow", "outcome"}},
		"consent_requests_total":                {"counter", []string{"flow", "outcome"}},
		"hydra_errors_total":                    {"counter", []string{"flow", "operation"}},
		"flow_starts_total":                     {"counter", []string{"flow", "trigger"}},
		"step_requests_total":                   {"counter", []string{"app", "kind", "outcome"}},
		"step_skips_total":                      {"counter", []string{"app", "result"}},
		"skip_total":                            {"counter", []string{"kind", "result"}},
		"consent_resubmits_total":               {"counter", []string{"result"}},
		"auth_duration_seconds":                 {"histogram", []string{"outcome"}},
		"hydra_requests_total":                  {"counter", []string{"operation", "status_class"}},
		"hydra_request_duration_seconds":        {"histogram", []string{"operation"}},
		"hydra_in_flight":                       {"gauge", nil},
		"hydra_rejected_total":                  {"counter", []string{"reason"}},
		"challenge_validations_total":           {"counter", []string{"mode", "result"}},
		"state_operation_duration_seconds":      {"histogram", []string{"op"}},
		"state_errors_total":                    {"counter", []string{"op"}},
		"state_conflicts_total":                 {"counter", nil},
		"acr_values_unmet_total":                {"counter", nil},
		"webhook_duration_seconds":              {"histogram", []string{"kind", "outcome"}},
		"http_requests_total":                   {"counter", []string{"method", "route", "status_class"}},
		"http_request_duration_seconds":         {"histogram", []string{"route"}},
		"http_requests_in_flight":               {"gauge", nil},
		"ip_filter_rejections_total":            {"counter", []string{"surface"}},
		"config_last_refresh_timestamp_seconds": {"gauge", nil},
		"config_refresh_errors_total":           {"counter", nil},
		"build_info":                            {"gauge", []string{"go_version", "hydra_mode", "state_backend", "version"}},
		"logout_propagations_total":             {"counter", []string{"app", "result"}},
		"failure_rate_limited_total":            {"counter", []string{"surface"}},
		"ready_check_up":                        {"gauge", []string{"check"}},
		"audit_dropped_total":                   {"counter", nil},
		"admin_rate_limited_total":              {"counter", nil},
	}
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range families {
		name, ok := strings.CutPrefix(f.GetName(), namespace+"_")
		if !ok {
			continue // go_*, process_*
		}
		seen[name] = true
		w, ok := want[name]
		if !ok {
			t.Errorf("%s is not in the catalogue", name)
			continue
		}
		if kind := strings.ToLower(f.GetType().String()); kind != w.kind {
			t.Errorf("%s is a %s, want a %s", name, kind, w.kind)
		}
		var labels []string
		for _, l := range f.GetMetric()[0].GetLabel() {
			labels = append(labels, l.GetName())
		}
		slices.Sort(labels)
		if !slices.Equal(labels, w.labels) {
			t.Errorf("%s has the labels %v, want %v", name, labels, w.labels)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s is missing", name)
		}
	}
}

// exercise gives every label every value it can take, the whole of what the code can
// expose, more than any real load.
func exercise(m *Metrics, flows, apps []string) {
	snap := store.NewSnapshot(nil, nil, store.DefaultSettings())
	for _, id := range apps {
		snap.Apps = append(snap.Apps, store.App{ID: id})
	}
	for _, id := range flows {
		snap.Flows = append(snap.Flows, store.Flow{ID: id})
	}
	snap = store.NewSnapshot(snap.Apps, snap.Flows, snap.Settings)
	operations := []string{"get_login", "accept_login", "reject_login", "get_consent", "accept_consent", "reject_consent", "get_logout", "accept_logout", "reject_logout", "revoke_login_session"}
	m.WatchHydraInFlight(func() int { return 0 })
	m.SetBuild("v1", "redis", "decrypt")
	m.ConfigRefreshed(nil)
	m.ConfigRefreshed(errors.New("down"))
	m.AuditDropped()
	for _, check := range append(slices.Clone(readyChecks), "unknown") {
		m.ReadyCheck(check, false)
	}
	for _, id := range flows {
		f := &flow.Flow{FlowID: id}
		for _, ev := range []flow.Event{flow.Entry{}, flow.Consent{}, flow.Consent{Post: true}} {
			for _, r := range []flow.Response{{Kind: flow.ChoicePage}, {Kind: flow.ConsentPage}, {Code: flow.E1001}, {Code: flow.E1002}} {
				m.Observe(context.Background(), flow.Observation{Event: ev, After: f, Response: r, Config: snap, Now: time.Now()})
			}
			m.Observe(context.Background(), flow.Observation{Event: ev, After: f, Config: snap, Now: time.Now(), Reports: []flow.Report{
				{Event: "hydra.login_accepted"}, {Event: "hydra.consent_accepted"},
				{Event: "flow.rejected", Detail: "user"}, {Event: "flow.rejected", Detail: "no_ref"},
				{Event: "flow.started", Detail: "choice"}, {Event: "flow.started", Detail: "auto_select"}, {Event: "flow.started", Detail: "acr"},
			}})
		}
		for _, op := range operations {
			m.Observe(context.Background(), flow.Observation{After: f, Config: snap, Reports: []flow.Report{{Event: "hydra.request_failed", Operation: op}}})
		}
	}
	for _, id := range apps {
		f := &flow.Flow{Current: 1, Steps: []flow.Step{{App: id}}}
		m.Observe(context.Background(), flow.Observation{Config: snap, Reports: []flow.Report{
			{Event: "step.login_accepted", Detail: id}, {Event: "step.consent_accepted", Detail: id},
			{Event: "logout.propagated", App: id, Result: "accepted"}, {Event: "logout.propagated", App: id, Result: "rejected"},
			{Event: "logout.propagated", App: id, Result: "skipped"}, {Event: "logout.propagated", App: id, Result: "error"},
			{Event: flow.EventSkipCheck, App: id, Result: flow.SkipSkipped}, {Event: flow.EventSkipCheck, App: id, Result: flow.SkipDeclined},
			{Event: flow.EventSkipCheck, App: id, Result: flow.SkipRefused}, {Event: flow.EventSkipCheck, App: id, Result: flow.SkipFailed},
		}})
		for _, op := range []flow.AppOp{flow.AppAcceptLogin, flow.AppRejectConsent} {
			for _, detail := range []string{"app", "expired"} {
				m.Observe(context.Background(), flow.Observation{Event: flow.AppCall{Op: op}, Before: f, Config: snap, Now: time.Now(),
					Reports: []flow.Report{{Event: "flow.rejected", Detail: detail}}})
			}
		}
	}
	for _, kind := range []string{"login", "consent"} {
		m.Observe(context.Background(), flow.Observation{Reports: []flow.Report{{Event: "skip.accepted", Kind: kind}, {Event: "skip.ignored", Kind: kind}}})
	}
	m.SkipUnavailable()
	m.Observe(context.Background(), flow.Observation{Reports: []flow.Report{
		{Event: "consent.resubmitted", Result: "replayed"}, {Event: "consent.resubmitted", Result: "too_late"},
		{Event: "security.ip_rejected"},
	}})
	m.Refused("metrics")
	m.RateLimited("front")
	m.RateLimited("emulated")
	for _, v := range [][2]string{{flow.ModeDecrypt, flow.ValidationOK}, {flow.ModeDecrypt, flow.ValidationExpired}, {flow.ModeDecrypt, flow.ValidationDecryptError},
		{flow.ModeFallback, flow.ValidationOK}, {flow.ModeFallback, flow.ValidationExpired}, {flow.ModeFallback, flow.ValidationInvalid}} {
		m.Observe(context.Background(), flow.Observation{Validations: []flow.Validation{{Mode: v[0], Result: v[1]}}})
	}
	for _, f := range []*flow.Flow{{StartedAt: 1}} {
		for _, detail := range []string{"app", "expired"} {
			m.Observe(context.Background(), flow.Observation{Before: f, Now: time.Now(), Reports: []flow.Report{{Event: "flow.rejected", Detail: detail}}})
		}
		m.Observe(context.Background(), flow.Observation{Before: f, Now: time.Now(), Reports: []flow.Report{{Event: "hydra.login_accepted"}}})
	}
	for _, op := range operations {
		for _, class := range []string{hydra.Class2xx, hydra.Class4xx, hydra.Class5xx, hydra.ClassError, hydra.ClassCanceled} {
			m.HydraCall(context.Background(), op, class, time.Millisecond)
		}
	}
	m.HydraRejected(hydra.RejectedLimit)
	m.HydraRejected(hydra.RejectedTimeout)
	s := m.States(erring{})
	_, _, _ = s.Get(context.Background(), "k")
	_ = s.Put(context.Background(), "k", nil, time.Second, 0)
	_ = s.Delete(context.Background(), "k")
	_ = m.States(erring{conflict: true}).Put(context.Background(), "k", nil, time.Second, 0)
	w := m.Webhooks(flow.StubWebhooks{})
	w.Login(context.Background(), flow.Call{})
	w.Consent(context.Background(), flow.Call{})
	failing := m.Webhooks(failingHooks{})
	failing.Login(context.Background(), flow.Call{})
	failing.Consent(context.Background(), flow.Call{})
	// Every route of the dispatcher: the pages, the emulated API twice, the probes.
	mux := http.NewServeMux()
	for _, route := range routesOfTheDispatcher {
		mux.HandleFunc(route, func(http.ResponseWriter, *http.Request) {})
	}
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), m.HTTP)
	for _, route := range routesOfTheDispatcher {
		method, path, _ := strings.Cut(route, " ")
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
		for _, class := range []string{"3xx", "4xx", "5xx"} {
			m.httpRequests.WithLabelValues(path, method, class).Inc()
		}
	}
}

// routesOfTheDispatcher are those of the serve: the pages, the emulated API on its v2
// and v1 paths, the probes, /metrics.
var routesOfTheDispatcher = func() []string {
	routes := []string{"GET /", "POST /", "GET /oauth2/auth", "GET /consent", "POST /consent", "GET /logout", "POST /logout", "GET /logout/next",
		"POST /locale/{locale}", "GET /static/{path...}", "GET /health", "GET /ready", "GET /metrics"}
	for _, kind := range []string{"login", "consent", "logout"} {
		routes = append(routes,
			"GET /admin/oauth2/auth/requests/"+kind, "PUT /admin/oauth2/auth/requests/"+kind+"/accept", "PUT /admin/oauth2/auth/requests/"+kind+"/reject",
			"GET /oauth2/auth/requests/"+kind, "PUT /oauth2/auth/requests/"+kind+"/accept", "PUT /oauth2/auth/requests/"+kind+"/reject")
	}
	return routes
}()

type erring struct {
	state.StateStore
	conflict bool
}

func (erring) Get(context.Context, string) ([]byte, uint64, error) {
	return nil, 0, errors.New("down")
}

func (e erring) Put(context.Context, string, []byte, time.Duration, uint64) error {
	if e.conflict {
		return state.ErrConflict
	}
	return errors.New("down")
}

func (erring) Delete(context.Context, string) error { return errors.New("down") }

type failingHooks struct{}

func (failingHooks) Login(context.Context, flow.Call) flow.LoginHookAnswer {
	return flow.LoginHookAnswer{Err: errors.New("down")}
}

func (failingHooks) Consent(context.Context, flow.Call) flow.ConsentHookAnswer {
	return flow.ConsentHookAnswer{Err: errors.New("down")}
}

// budget is the doc's: series = 1 000 + 23 F + 14 A (step_skips_total, four
// results by app, since phase 4).
func budget(flows, apps int) int { return 1000 + 23*flows + 14*apps }

// The budget of series, with 50 flows and 50 apps, every label at every value it can take
// (Cardinalité): over the formula plus 10 %, the catalogue has drifted.
func TestSeriesBudget(t *testing.T) {
	for _, size := range []int{1, 10, 50} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var flows, apps []string
			for i := range size {
				flows, apps = append(flows, fmt.Sprintf("flow-%d", i)), append(apps, fmt.Sprintf("app-%d", i))
			}
			m := New(200, nil)
			exercise(m, flows, apps)
			n := 0
			scanner := bufio.NewScanner(strings.NewReader(scrape(t, m)))
			scanner.Buffer(nil, 1<<20)
			for scanner.Scan() {
				if line := scanner.Text(); line != "" && !strings.HasPrefix(line, "#") {
					n++
				}
			}
			limit := budget(size, size) * 11 / 10
			t.Logf("%d series for %d flows and %d apps, budget %d, limit %d", n, size, size, budget(size, size), limit)
			if n > limit {
				t.Errorf("%d series, over %d", n, limit)
			}
		})
	}
}

// A flow or an app the configuration does not hold is other, and the values stay under
// max_label_values, the log saying so once (Cardinalité).
func TestLabelsBounded(t *testing.T) {
	var logs bytes.Buffer
	m := New(2, slog.New(slog.NewJSONHandler(&logs, nil)))
	snap := store.NewSnapshot(nil, []store.Flow{{ID: "a"}, {ID: "b"}, {ID: "c"}}, store.DefaultSettings())
	observe := func(id string) {
		m.Observe(context.Background(), flow.Observation{After: &flow.Flow{FlowID: id}, Config: snap, Reports: []flow.Report{{Event: "hydra.login_accepted"}}})
	}
	for _, id := range []string{"a", "b", "c", "a", "removed"} {
		observe(id)
	}
	m.Observe(context.Background(), flow.Observation{Config: snap, Reports: []flow.Report{{Event: "hydra.login_accepted"}}})
	body := scrape(t, m)
	for name, want := range map[string]string{
		`login_requests_total{flow="a",outcome="accepted"}`:     "2",
		`login_requests_total{flow="b",outcome="accepted"}`:     "1",
		`login_requests_total{flow="other",outcome="accepted"}`: "2", // c, over the budget; removed
		`login_requests_total{flow="none",outcome="accepted"}`:  "1",
	} {
		if got := series(body, name); got != want {
			t.Errorf("%s = %q, want %s\n%s", name, got, want, body)
		}
	}
	if n := strings.Count(logs.String(), "metrics.label_overflow"); n != 1 {
		t.Errorf("%d warnings: %s", n, logs.String())
	}
}

// A value that is not valid UTF-8, an id of a database not in UTF-8, is other: Prometheus
// panics on it (revue R29).
func TestLabelNotUTF8(t *testing.T) {
	m := New(200, nil)
	bad := "fl\xffow"
	snap := store.NewSnapshot(nil, []store.Flow{{ID: bad}}, store.DefaultSettings())
	m.Observe(context.Background(), flow.Observation{After: &flow.Flow{FlowID: bad}, Config: snap, Reports: []flow.Report{{Event: "hydra.login_accepted"}}})
	if got := series(scrape(t, m), `login_requests_total{flow="other",outcome="accepted"}`); got != "1" {
		t.Errorf("login_requests_total of other = %q", got)
	}
}

// What the requests count, event by event.
func TestObserve(t *testing.T) {
	snap := store.NewSnapshot([]store.App{{ID: "sql"}}, []store.Flow{{ID: "f"}}, store.DefaultSettings())
	running := &flow.Flow{FlowID: "f", Current: 1, Steps: []flow.Step{{App: "sql"}}, StartedAt: time.Unix(1000, 0).UnixMilli()}
	accepted := *running
	accepted.HydraRedirect = "http://hydra/verifier"
	now := time.Unix(1042, 0)
	for name, tc := range map[string]struct {
		o    flow.Observation
		want map[string]string
	}{
		"the choice page": {flow.Observation{Event: flow.Entry{}, Response: flow.Response{Kind: flow.ChoicePage}},
			map[string]string{`login_requests_total{flow="none",outcome="displayed"}`: "1"}},
		"a forged challenge": {flow.Observation{Event: flow.Entry{}, Response: flow.Response{Code: flow.E1001}},
			map[string]string{`login_requests_total{flow="none",outcome="invalid_challenge"}`: "1"}},
		"a flow gone": {flow.Observation{Event: flow.Loop{}, Before: running, Response: flow.Response{Code: flow.E1002}},
			map[string]string{`login_requests_total{flow="f",outcome="session_missing"}`: "1"}},
		"the final accept, its duration": {flow.Observation{Event: flow.Loop{}, Before: running, After: &accepted, Reports: []flow.Report{{Event: "hydra.login_accepted"}}},
			map[string]string{`login_requests_total{flow="f",outcome="accepted"}`: "1", `auth_duration_seconds_sum{outcome="accepted"}`: "42", `auth_duration_seconds_count{outcome="accepted"}`: "1"}},
		"pre-checks, an app unknown, a result unknown": {flow.Observation{Event: flow.Loop{}, Before: running, Config: snap, Reports: []flow.Report{
			{Event: flow.EventSkipCheck, App: "sql", Result: flow.SkipSkipped}, {Event: flow.EventSkipCheck, App: "sql", Result: flow.SkipFailed},
			{Event: flow.EventSkipCheck, App: "gone", Result: flow.SkipDeclined}, {Event: flow.EventSkipCheck, App: "sql", Result: "maybe"}}},
			map[string]string{`step_skips_total{app="sql",result="skipped"}`: "1", `step_skips_total{app="sql",result="failed"}`: "1",
				`step_skips_total{app="other",result="declined"}`: "1", `step_skips_total{app="sql",result="other"}`: "1"}},
		"the consent screen": {flow.Observation{Event: flow.Consent{}, Before: &accepted, Response: flow.Response{Kind: flow.ConsentPage}},
			map[string]string{`consent_requests_total{flow="f",outcome="displayed"}`: "1"}},
		"a consent posted": {flow.Observation{Event: flow.Consent{Post: true}, Before: &accepted, Reports: []flow.Report{{Event: "hydra.consent_accepted"}}},
			map[string]string{`consent_requests_total{flow="f",outcome="accepted"}`: "1"}},
		"a consent Hydra skips": {flow.Observation{Event: flow.Consent{}, Before: &accepted, Reports: []flow.Report{{Event: "hydra.consent_accepted"}}},
			map[string]string{`consent_requests_total{flow="f",outcome="skip_accepted"}`: "1"}},
		"a consent refused": {flow.Observation{Event: flow.Consent{Post: true}, Before: &accepted, Reports: []flow.Report{{Event: "flow.rejected", Detail: "user"}}},
			map[string]string{`consent_requests_total{flow="f",outcome="rejected"}`: "1"}},
		"an A3 reject": {flow.Observation{Event: flow.Consent{}, Before: &accepted, Reports: []flow.Report{{Event: "flow.rejected", Detail: "not_ours:login"}}},
			map[string]string{`consent_requests_total{flow="f",outcome="rejected"}`: "1"}},
		"a consent without a session": {flow.Observation{Event: flow.Consent{}, Reports: []flow.Report{{Event: "flow.rejected", Detail: "no_ref"}}},
			map[string]string{`consent_requests_total{flow="none",outcome="session_missing"}`: "1"}},
		"a consent page E1002": {flow.Observation{Event: flow.Consent{}, Response: flow.Response{Code: flow.E1002}},
			map[string]string{`consent_requests_total{flow="none",outcome="session_missing"}`: "1"}},
		"Hydra failing a page": {flow.Observation{Before: running, Reports: []flow.Report{{Event: "hydra.request_failed", Operation: "accept_login"}}},
			map[string]string{`hydra_errors_total{flow="f",operation="accept_login"}`: "1"}},
		"a read failing a page, by Symfony's name": {flow.Observation{Before: running, Reports: []flow.Report{{Event: "hydra.request_failed", Operation: "get_login_request"}}},
			map[string]string{`hydra_errors_total{flow="f",operation="get_login"}`: "1"}},
		"a skip, by the flow of the cookie": {flow.Observation{Event: flow.Entry{}, Reports: []flow.Report{{Event: "hydra.login_accepted", Flow: "f"}}},
			map[string]string{`login_requests_total{flow="f",outcome="accepted"}`: "1"}},
		"a consent without a flow, by the flow of the cookie": {flow.Observation{Event: flow.Consent{}, Reports: []flow.Report{{Event: "hydra.consent_accepted", Flow: "f"}}},
			map[string]string{`consent_requests_total{flow="f",outcome="skip_accepted"}`: "1"}},
		"a flow started": {flow.Observation{After: running, Reports: []flow.Report{{Event: "flow.started", Detail: "auto_select"}}},
			map[string]string{`flow_starts_total{flow="f",trigger="auto_select"}`: "1"}},
		"a trigger out of the enumeration": {flow.Observation{After: running, Reports: []flow.Report{{Event: "flow.started", Detail: "new"}}},
			map[string]string{`flow_starts_total{flow="f",trigger="other"}`: "1"}},
		"an app accepts": {flow.Observation{Reports: []flow.Report{{Event: "step.login_accepted", Detail: "sql"}, {Event: "step.consent_accepted", Detail: "sql"}}},
			map[string]string{`step_requests_total{app="sql",kind="login",outcome="accepted"}`: "1", `step_requests_total{app="sql",kind="consent",outcome="accepted"}`: "1"}},
		"an app rejects": {flow.Observation{Event: flow.AppCall{Op: flow.AppRejectLogin}, Before: running, Reports: []flow.Report{{Event: "flow.rejected", Detail: "app"}}},
			map[string]string{`step_requests_total{app="sql",kind="login",outcome="rejected"}`: "1", `auth_duration_seconds_count{outcome="rejected"}`: "1"}},
		"a step expired": {flow.Observation{Event: flow.AppCall{Op: flow.AppAcceptConsent}, Before: running, Reports: []flow.Report{{Event: "flow.rejected", Detail: "expired"}}},
			map[string]string{`step_requests_total{app="sql",kind="consent",outcome="expired"}`: "1", `auth_duration_seconds_count{outcome="expired"}`: "1"}},
		"a skip": {flow.Observation{Reports: []flow.Report{{Event: "skip.accepted", Kind: "login"}, {Event: "skip.ignored", Kind: "consent"}}},
			map[string]string{`skip_total{kind="login",result="accepted"}`: "1", `skip_total{kind="consent",result="ignored"}`: "1"}},
		"a double submission": {flow.Observation{Reports: []flow.Report{{Event: "consent.resubmitted", Result: "replayed"}}},
			map[string]string{`consent_resubmits_total{result="replayed"}`: "1"}},
		"an app outside its sources": {flow.Observation{Reports: []flow.Report{{Event: "security.ip_rejected"}}},
			map[string]string{`ip_filter_rejections_total{surface="emulated"}`: "1"}},
		"the logout through an app": {flow.Observation{Reports: []flow.Report{{Event: "logout.propagated", App: "sql", Result: "skipped"}}},
			map[string]string{`logout_propagations_total{app="sql",result="skipped"}`: "1"}},
		"a validation": {flow.Observation{Validations: []flow.Validation{{Mode: flow.ModeDecrypt, Result: flow.ValidationExpired}}},
			map[string]string{`challenge_validations_total{mode="decrypt",result="expired"}`: "1"}},
		"a reject of a consent ends no authentication": {flow.Observation{Event: flow.Consent{Post: true}, Before: &accepted, Reports: []flow.Report{{Event: "flow.rejected", Detail: "user"}}},
			map[string]string{`auth_duration_seconds_count{outcome="rejected"}`: ""}},
		"a skip accepted ends no authentication of a flow": {flow.Observation{After: &flow.Flow{Done: true}, Reports: []flow.Report{{Event: "hydra.login_accepted"}}},
			map[string]string{`auth_duration_seconds_count{outcome="accepted"}`: ""}},
	} {
		t.Run(name, func(t *testing.T) {
			m := New(200, nil)
			tc.o.Config, tc.o.Now = snap, now
			m.Observe(context.Background(), tc.o)
			body := scrape(t, m)
			for s, want := range tc.want {
				if got := series(body, s); got != want {
					t.Errorf("%s = %q, want %q\n%s", s, got, want, body)
				}
			}
		})
	}
}

// No subject, challenge, IP, URL nor message becomes a label, whatever the reports hold
// (Cardinalité).
func TestNoValueInALabel(t *testing.T) {
	const sentinel = "sentinel-value"
	m := New(200, nil)
	snap := store.NewSnapshot(nil, []store.Flow{{ID: "f"}}, store.DefaultSettings())
	m.Observe(context.Background(), flow.Observation{After: &flow.Flow{FlowID: sentinel, Subject: sentinel, LoginChallenge: sentinel}, Config: snap, Now: time.Now(), Reports: []flow.Report{
		{Event: "hydra.login_accepted", Detail: sentinel}, {Event: "flow.started", Detail: sentinel}, {Event: "flow.error", Detail: sentinel},
		{Event: "flow.rejected", Detail: sentinel}, {Event: "state.error", Detail: sentinel}, {Event: "step.login_accepted", Detail: sentinel},
		{Event: "webhook.failed", Detail: sentinel, Host: sentinel}, {Event: "challenge.invalid", Detail: sentinel},
	}})
	h := httpx.Chain(http.NotFoundHandler(), httpx.RealIP(nil), m.HTTP)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/"+sentinel+"?login_challenge="+sentinel, nil))
	r := httptest.NewRequest(sentinel, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if body := scrape(t, m); strings.Contains(body, sentinel) {
		t.Errorf("a value in a label:\n%s", regexp.MustCompile(`(?m)^[^\n]*`+sentinel+`[^\n]*$`).FindAllString(body, -1))
	}
}

// The requests by route: the pattern of the mux, without its method; unmatched for none;
// a method out of the enumeration is other.
func TestHTTP(t *testing.T) {
	m := New(200, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/auth", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusSeeOther) })
	mux.HandleFunc("POST /consent", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), m.HTTP)
	for _, r := range []struct{ method, path string }{{"GET", "/oauth2/auth?login_challenge=secret"}, {"POST", "/consent"}, {"GET", "/ok"}, {"GET", "/nowhere"}, {"BREW", "/ok"}} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(r.method, r.path, nil))
	}
	body := scrape(t, m)
	for s, want := range map[string]string{
		`http_requests_total{method="GET",route="/oauth2/auth",status_class="3xx"}`: "1",
		`http_requests_total{method="POST",route="/consent",status_class="5xx"}`:    "1",
		`http_requests_total{method="GET",route="/ok",status_class="2xx"}`:          "1",
		`http_requests_total{method="GET",route="unmatched",status_class="4xx"}`:    "1",
		`http_request_duration_seconds_count{route="/oauth2/auth"}`:                 "1",
		`http_requests_in_flight`: "0",
	} {
		if got := series(body, s); got != want {
			t.Errorf("%s = %q, want %q\n%s", s, got, want, body)
		}
	}
	if !regexp.MustCompile(`http_requests_total\{method="other",route="[^"]*",status_class="4xx"\} 1`).MatchString(body) {
		t.Errorf("BREW:\n%s", body)
	}
}

// A request that panics still counts, its status the 500 Recover writes.
func TestHTTPCountsAPanic(t *testing.T) {
	m := New(200, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	h := httpx.Chain(httpx.Routes(mux), httpx.RealIP(nil), m.HTTP, httpx.Recover(slog.New(slog.DiscardHandler)))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
	if got := series(scrape(t, m), `http_requests_total{method="GET",route="/boom",status_class="5xx"}`); got != "1" {
		t.Errorf("got %q", got)
	}
}

// /metrics behind security.metrics_authorized_hosts: refused out of it, counted and
// logged, since the access log keeps silent on it; OpenMetrics when asked for.
func TestFiltered(t *testing.T) {
	var logs bytes.Buffer
	m := New(200, slog.New(slog.NewJSONHandler(&logs, nil)))
	h := httpx.Chain(m.Filtered([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, "full", nil), httpx.RealIP(nil))
	get := func(remote, accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.RemoteAddr = remote
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	if rec := get("203.0.113.9:1", ""); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), namespace) {
		t.Errorf("outside: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), `"security.ip_rejected"`) || !strings.Contains(logs.String(), `"surface":"metrics"`) || !strings.Contains(logs.String(), "203.0.113.9") {
		t.Errorf("log: %s", logs.String())
	}
	rec := get("10.1.2.3:1", "")
	if rec.Code != http.StatusOK || series(rec.Body.String(), `ip_filter_rejections_total{surface="metrics"}`) != "1" {
		t.Errorf("inside: %d %s", rec.Code, rec.Body)
	}
	rec = get("10.1.2.3:1", "application/openmetrics-text; version=1.0.0")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/openmetrics-text") {
		t.Errorf("Content-Type %q", ct)
	}
	if !strings.HasSuffix(rec.Body.String(), "# EOF\n") {
		t.Errorf("no OpenMetrics end: %q", rec.Body.String()[max(0, rec.Body.Len()-40):])
	}
}

// The state store: a key absent, a replay, a client gone are not errors of the store.
func TestStates(t *testing.T) {
	m := New(200, nil)
	mem := state.NewMemory()
	defer mem.Close()
	s := m.States(mem)
	ctx := context.Background()
	if _, _, err := s.Get(ctx, "absent"); !errors.Is(err, state.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "k", []byte("v"), time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "k", []byte("v"), time.Minute, 0); !errors.Is(err, state.ErrConflict) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, _ = s.Get(canceled, "k")
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, m)
	for name, want := range map[string]string{
		`state_conflicts_total`: "1", `state_errors_total{op="get"}`: "", `state_errors_total{op="put"}`: "",
		`state_operation_duration_seconds_count{op="get"}`: "2", `state_operation_duration_seconds_count{op="put"}`: "2", `state_operation_duration_seconds_count{op="delete"}`: "1",
	} {
		if got := series(body, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	mem.Close()
	_, _, _ = s.Get(ctx, "k")
	if got := series(scrape(t, m), `state_errors_total{op="get"}`); got != "1" {
		t.Errorf("errors %q", got)
	}
}

// A webhook cancelled by its client says nothing of the webhook.
func TestWebhooks(t *testing.T) {
	m := New(200, nil)
	w := m.Webhooks(answering{})
	w.Login(context.Background(), flow.Call{})
	w.Consent(context.Background(), flow.Call{Challenge: "fail"})
	w.Login(context.Background(), flow.Call{Challenge: "cancel"})
	body := scrape(t, m)
	for name, want := range map[string]string{
		`webhook_duration_seconds_count{kind="login",outcome="ok"}`:      "1",
		`webhook_duration_seconds_count{kind="consent",outcome="error"}`: "1",
		`webhook_duration_seconds_count{kind="login",outcome="error"}`:   "",
	} {
		if got := series(body, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

type answering struct{}

func (answering) Login(_ context.Context, c flow.Call) flow.LoginHookAnswer {
	if c.Challenge == "cancel" {
		return flow.LoginHookAnswer{Err: context.Canceled}
	}
	return flow.LoginHookAnswer{}
}

func (answering) Consent(_ context.Context, c flow.Call) flow.ConsentHookAnswer {
	if c.Challenge == "fail" {
		return flow.ConsentHookAnswer{Err: errors.New("down")}
	}
	return flow.ConsentHookAnswer{}
}

func TestBuildAndConfig(t *testing.T) {
	m := New(200, nil)
	m.SetBuild("v1.2.3", "redis", "decrypt")
	m.WatchHydraInFlight(func() int { return 3 })
	m.ConfigRefreshed(errors.New("down"))
	body := scrape(t, m)
	if !regexp.MustCompile(`hydra_dispatcher_build_info\{go_version="go[^"]+",hydra_mode="decrypt",state_backend="redis",version="v1.2.3"\} 1`).MatchString(body) {
		t.Errorf("build_info:\n%s", body)
	}
	if got := series(body, "hydra_in_flight"); got != "3" {
		t.Errorf("hydra_in_flight = %q", got)
	}
	if got := series(body, "config_refresh_errors_total"); got != "1" {
		t.Errorf("errors = %q", got)
	}
	if got := series(body, "config_last_refresh_timestamp_seconds"); got != "0" {
		t.Errorf("a refresh that failed moved the time: %q", got)
	}
	m.ConfigRefreshed(nil)
	if got := series(scrape(t, m), "config_last_refresh_timestamp_seconds"); got == "0" || got == "" {
		t.Errorf("last refresh = %q", got)
	}
}

// A request sampled by OpenTelemetry leaves its trace_id as an exemplar, in OpenMetrics:
// from a peak of latency to a trace, at no cost in series (Exposition).
func TestExemplars(t *testing.T) {
	m := New(200, nil)
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	sampled := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled}))
	unsampled := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID}))
	m.HydraCall(sampled, "accept_login", "2xx", 3*time.Millisecond)
	m.HydraCall(unsampled, "reject_login", "2xx", 3*time.Millisecond)
	body := scrape(t, m, "application/openmetrics-text; version=1.0.0")
	if !strings.Contains(body, `# {trace_id="4bf92f3577b34da6a3ce929d0e0e4736"}`) {
		t.Errorf("no exemplar:\n%s", body)
	}
	if n := strings.Count(body, "trace_id="); n != 1 {
		t.Errorf("%d exemplars: the unsampled one too", n)
	}
	if strings.Contains(scrape(t, m), "trace_id") {
		t.Error("an exemplar in the text format")
	}
}

// hydra_dispatcher_encrypted_values: the settings encrypted, by kid, as the
// configuration of the moment has them.
func TestEncrypted(t *testing.T) {
	m := New(100, nil)
	counts := map[string]int{"a1b2c3d4": 1}
	m.WatchEncrypted(func() map[string]int { return counts })
	if body := scrape(t, m); !strings.Contains(body, `hydra_dispatcher_encrypted_values{kid="a1b2c3d4"} 1`) {
		t.Errorf("one:\n%s", body)
	}
	counts = map[string]int{}
	if body := scrape(t, m); strings.Contains(body, `kid="a1b2c3d4"`) {
		t.Errorf("after the rekey:\n%s", body)
	}
}
