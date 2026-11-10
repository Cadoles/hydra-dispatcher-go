package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seedfile"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// maxPages bounds the pages read of a collection: Symfony serves 30 a page.
const maxPages = 10000

// export writes the apps, the flows and the settings of Symfony's admin API
// as a seed: all the pages of a collection, a map Symfony serves [] read as
// {}, hydraPublicUrl and adminAuthorizedHosts left out with a warning,
// sessionTtl written login_remember_for (Q94 to Q105, point I).
func export(ctx context.Context, args []string, stdout, stderr io.Writer, stdin io.Reader) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("url", "", "the base URL of the Symfony dispatcher (http://dispatcher.example)")
	host := fs.String("host", "", "the Host header, when -url reaches it by another name or by its address")
	clientID := fs.String("client-id", "", "an API client of Symfony")
	secretFile := fs.String("client-secret-file", "", "the file of its secret")
	secretStdin := fs.Bool("client-secret-stdin", false, "read its secret from the standard input")
	timeout := fs.Duration("timeout", 30*time.Second, "the time each request may take")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *base == "" || *clientID == "" {
		fmt.Fprintln(stderr, "-url and -client-id are required")
		return errUsage
	}
	secret, err := readSecret("the client's secret", *secretFile, *secretStdin, stdin)
	if err != nil {
		return err
	}
	s := &symfony{base: strings.TrimRight(*base, "/"), host: *host, client: &http.Client{Timeout: *timeout}}
	if err := s.login(ctx, *clientID, secret); err != nil {
		return err
	}
	snap, warnings, err := s.read(ctx)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	return seedfile.Write(stdout, snap, map[string]bool{"settings": true, "apps": true, "flows": true}, seedfile.Options{NoReceiveClaims: true},
		"The configuration of the Symfony dispatcher at "+s.base+", in the format of the seed (tools/symfonyimport export).",
		"The apps come without allowed_sources: declare each one's, else the emulated API takes its steps from any address of its allowlist.",
		"Without the API clients or the admin accounts: tools/symfonyimport accounts takes them from the database of Symfony.")
}

// symfony is the admin API of a Symfony dispatcher.
type symfony struct {
	base, host string
	client     *http.Client
	token      string
}

func (s *symfony) do(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return nil, err
	}
	if s.host != "" {
		req.Host = s.host
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(data[:min(len(data), 300)]))
	}
	return data, nil
}

func (s *symfony) login(ctx context.Context, id, secret string) error {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	data, err := s.do(ctx, http.MethodPost, "/admin/v1/token", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &t); err != nil || t.AccessToken == "" {
		return errors.New("token: no access_token in the answer")
	}
	s.token = t.AccessToken
	return nil
}

// pages reads every page of a collection, until an empty one.
func (s *symfony) pages(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for page := 1; page <= maxPages; page++ {
		data, err := s.do(ctx, http.MethodGet, fmt.Sprintf("%s?page=%d", path, page), nil, "")
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, fmt.Errorf("%s page %d: %w", path, page, err)
		}
		if len(items) == 0 {
			return all, nil
		}
		all = append(all, items...)
	}
	return nil, fmt.Errorf("%s: more than %d pages", path, maxPages)
}

type symfonyApp struct {
	ID         string  `json:"id"`
	LoginURL   string  `json:"loginUrl"`
	ConsentURL string  `json:"consentUrl"`
	LogoutURL  *string `json:"logoutUrl"`
	Method     string  `json:"method"`
}

type symfonyFlow struct {
	ID          string    `json:"id"`
	Title       localized `json:"title"`
	Description localized `json:"description"`
	IconURL     localized `json:"iconUrl"`
	Enabled     bool      `json:"enabled"`
	Steps       []struct {
		AppID     string      `json:"appId"`
		StepOrder json.Number `json:"stepOrder"`
	} `json:"steps"`
}

// localized is a map of locale to text, which Symfony serves [] when empty;
// a null text is no text.
type localized map[string]string

func (l *localized) UnmarshalJSON(data []byte) error {
	switch t := bytes.TrimSpace(data); {
	case string(t) == "null", string(t) == "[]":
		*l = nil
		return nil
	}
	var m map[string]*string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*l = localized{}
	for locale, text := range m {
		if text != nil && *text != "" {
			(*l)[locale] = *text
		}
	}
	return nil
}

// settingKeys are the settings of Symfony, by their camelCase, and the key of
// the registry each one is; sessionTtl is login_remember_for (Q105).
var settingKeys = map[string]string{
	"appAutoSelect":                "app_auto_select",
	"consentAutoAccept":            "consent_auto_accept",
	"aggregateAmrFromLoginRequest": "aggregate_amr_from_login_request",
	"challengeTtl":                 "challenge_ttl",
	"remember":                     "remember",
	"sessionTtl":                   "login_remember_for",
	"loginRememberFor":             "login_remember_for",
	"consentRememberFor":           "consent_remember_for",
	"loginAcceptWebhookUrl":        "login_accept_webhook_url",
	"consentAcceptWebhookUrl":      "consent_accept_webhook_url",
	"supportedLocales":             "supported_locales",
	"defaultLocale":                "default_locale",
	"fallbackLocale":               "fallback_locale",
}

// settingsLeft are the settings of Symfony the Go dispatcher has not: in its
// configuration, not its database (Q105).
var settingsLeft = []string{"hydraPublicUrl", "adminAuthorizedHosts"}

// read reads the apps, the flows and the settings, as a snapshot whose
// StoredSettings are those Symfony gave.
func (s *symfony) read(ctx context.Context) (*store.Snapshot, []string, error) {
	var warnings []string
	rawApps, err := s.pages(ctx, "/admin/v1/apps")
	if err != nil {
		return nil, nil, err
	}
	var apps []store.App
	for _, raw := range rawApps {
		var a symfonyApp
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, nil, fmt.Errorf("an app: %w", err)
		}
		app := store.App{ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, Method: a.Method, AuthMode: "network"}
		if a.LogoutURL != nil {
			app.LogoutURL = *a.LogoutURL
		}
		apps = append(apps, app)
	}
	rawFlows, err := s.pages(ctx, "/admin/v1/flows")
	if err != nil {
		return nil, nil, err
	}
	var flows []store.Flow
	for _, raw := range rawFlows {
		var f symfonyFlow
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, nil, fmt.Errorf("a flow: %w", err)
		}
		flow := store.Flow{ID: f.ID, Title: f.Title, Description: f.Description, IconURL: f.IconURL, Enabled: f.Enabled}
		for _, st := range f.Steps {
			n, err := st.StepOrder.Int64()
			if err != nil {
				return nil, nil, fmt.Errorf("flow %s, step %s: stepOrder %q", f.ID, st.AppID, st.StepOrder)
			}
			flow.Steps = append(flow.Steps, store.Step{AppID: st.AppID, Position: int(n), SubjectCheck: "none"})
		}
		slices.SortStableFunc(flow.Steps, func(a, b store.Step) int { return a.Position - b.Position })
		flows = append(flows, flow)
	}

	data, err := s.do(ctx, http.MethodGet, "/admin/v1/settings", nil, "")
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("settings: %w", err)
	}
	values := map[string]json.RawMessage{}
	for _, field := range slices.Sorted(maps.Keys(doc)) {
		raw := doc[field]
		key, known := settingKeys[field]
		switch {
		case field == "id":
		case slices.Contains(settingsLeft, field):
			warnings = append(warnings, fmt.Sprintf("setting %s left out: the Go dispatcher reads it from its configuration, not its database", field))
		case !known:
			warnings = append(warnings, fmt.Sprintf("setting %s unknown to the Go dispatcher: left out", field))
		case string(bytes.TrimSpace(raw)) == "null":
		case field == "sessionTtl" && doc["loginRememberFor"] != nil:
			// loginRememberFor wins, as the admin API reads them.
		default:
			values[key] = raw
		}
	}
	settings, more, err := store.SettingsOf(values)
	if err != nil {
		return nil, nil, fmt.Errorf("settings: %w", err)
	}
	warnings = append(warnings, more...)
	if err := settings.Validate(); err != nil {
		warnings = append(warnings, "settings the Go dispatcher refuses, bootstrap will say why: "+err.Error())
	}
	// What bootstrap will refuse, named now: Symfony checked little (an
	// empty description, an URL that is not one).
	known := func(id string) bool { return slices.ContainsFunc(apps, func(a store.App) bool { return a.ID == id }) }
	for _, a := range apps {
		for _, v := range domain.Collect(a.Check) {
			warnings = append(warnings, fmt.Sprintf("app %s, %s: %s: bootstrap will refuse it, correct the seed", a.ID, v.Field, v.Message))
		}
	}
	for _, f := range flows {
		for _, v := range domain.Collect(func(fail domain.Fail) { f.Check(fail, known) }) {
			warnings = append(warnings, fmt.Sprintf("flow %s, %s: %s: bootstrap will refuse it, correct the seed", f.ID, v.Field, v.Message))
		}
	}
	snap := store.NewSnapshot(apps, flows, settings)
	for _, v := range settings.Document() {
		if _, ok := values[v.Key]; ok {
			snap.StoredSettings = append(snap.StoredSettings, v.Key)
		}
	}
	return snap, warnings, nil
}
