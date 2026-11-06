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
