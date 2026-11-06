package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// scrape reads the dispatcher's /metrics, as a collector on the host does: series by
// name and labels.
func (d *driver) scrape() (map[string]float64, error) {
	u := d.dispatcher.JoinPath("metrics")
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", u.Path, resp.StatusCode)
	}
	series := map[string]float64{}
	for line := range strings.Lines(string(body)) {
		if !strings.HasPrefix(line, "hydra_dispatcher_") {
			continue
		}
		at := strings.LastIndexByte(line, ' ')
		value, err := strconv.ParseFloat(strings.TrimSpace(line[at+1:]), 64)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		series[line[:at]] = value
	}
	return series, nil
}

// noValueInALabel is what must never be in a label: the challenges of an authorization,
// its subject.
var noValueInALabel = regexp.MustCompile(`login_challenge|consent_challenge|isabelle|@example`)

// metricsOfALogin signs in once and reads what that adds to the catalogue, from the
// dispatcher that served it, behind Caddy: its counters, the calls to Hydra, the state
// store, the build.
func (d *driver) metricsOfALogin() error {
	if d.symfony {
		d.note("the catalogue of the Go dispatcher: left out")
		return nil
	}
	before, err := d.scrape()
	if err != nil {
		return err
	}
	if err := d.signIn(login{flow: "hydra-sql", user: isabelle, consent: "accept"}); err != nil {
		return err
	}
	after, err := d.scrape()
	if err != nil {
		return err
	}
	for name := range after {
		if noValueInALabel.MatchString(name) {
			return fmt.Errorf("a value in a label: %s", name)
		}
	}
	for _, name := range []string{
		`hydra_dispatcher_login_requests_total{flow="hydra-sql",outcome="accepted"}`,
		`hydra_dispatcher_flow_starts_total{flow="hydra-sql",trigger="choice"}`,
		`hydra_dispatcher_step_requests_total{app="hydra-sql",kind="login",outcome="accepted"}`,
		`hydra_dispatcher_step_requests_total{app="hydra-sql",kind="consent",outcome="accepted"}`,
		`hydra_dispatcher_auth_duration_seconds_count{outcome="accepted"}`,
		`hydra_dispatcher_hydra_requests_total{operation="accept_login",status_class="2xx"}`,
		`hydra_dispatcher_state_operation_duration_seconds_count{op="put"}`,
		`hydra_dispatcher_http_requests_total{method="GET",route="/oauth2/auth",status_class="3xx"}`,
	} {
		if after[name] <= before[name] {
			return fmt.Errorf("%s did not move: %v, then %v", name, before[name], after[name])
		}
	}
	found := false
	for name := range after {
		found = found || strings.HasPrefix(name, "hydra_dispatcher_build_info{")
	}
	if !found {
		return fmt.Errorf("no build_info")
	}
	return nil
}

// lastFlowPreselected signs in with a flow from the form, then lands on the choice page
// again in the same browser, prompt=login making Hydra ask anew: that flow is checked.
// Nothing goes straight to it.
func (d *driver) lastFlowPreselected() error {
	if d.symfony {
		d.note("the preselection of the Go dispatcher: left out")
		return nil
	}
	if err := d.signIn(login{flow: "hydra-sql", user: isabelle, consent: "accept"}); err != nil {
		return err
	}
	p, err := d.start("login")
	if err != nil {
		return err
	}
	if d.kind(p) != "choice" {
		return fmt.Errorf("not on the choice page: %w", errUnexpected(p))
	}
	if !regexp.MustCompile(`value="hydra-sql" required checked`).MatchString(p.Body) {
		return fmt.Errorf("hydra-sql is not checked: %w", errUnexpected(p))
	}
	return nil
}

// limiterStopsForgery forges challenges from this host until the dispatcher answers 429
// (Durcissements point 4), a real brake on the stack; opt-in, since it blocks this
// address for security.failure_rate_limit.block, and every scenario with it.
func (d *driver) limiterStopsForgery() error {
	for i := range 50 {
		forged := fmt.Sprintf("%032x", i+1)
		u := *d.dispatcher
		u.RawQuery = "login_challenge=" + forged
		p, err := d.b.get(u.String())
		if err != nil {
			return err
		}
		if p.Status == http.StatusTooManyRequests {
			d.note("429 after %d forged challenges", i)
			return nil
		}
		if code := errorCode.FindString(p.Body); code != "E1001" {
			return fmt.Errorf("forged challenge %d: status %d, code %q", i, p.Status, code)
		}
	}
	return fmt.Errorf("no 429 after 50 forged challenges")
}
