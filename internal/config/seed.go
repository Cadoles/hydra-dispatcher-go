package config

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Seed is the dispatcher: block, read only by bootstrap to initialise the
// database. It takes the Symfony dispatcher.yaml as is, apart from its
// %env(VAR)% placeholders (write ${VAR}), and accepts a few more forms and
// keys: app_id/position in steps, subject_check, plain-string title,
// comma-separated lists, durations such as "1h", remember and remember_for,
// and the fields the Go model adds to apps and flows.
type Seed struct {
	Apps          []SeedApp    `yaml:"apps"`
	Flows         []SeedFlow   `yaml:"flows"`
	OAuth2Clients []SeedClient `yaml:"oauth2_clients"`
	SeedSettings  `yaml:",inline"`

	// NullSettings lists the settings the file sets to null (~): bootstrap
	// --force resets them, where it leaves an absent setting alone.
	NullSettings []string `yaml:"-"`

	// Symfony keys with no Go counterpart: accepted, then ignored with a
	// warning.
	HydraPublicURL       any `yaml:"hydra_public_url"`
	SessionTTL           any `yaml:"session_ttl"`
	CacheProviders       any `yaml:"cache_providers"`
	AdminAuthorizedHosts any `yaml:"admin_authorized_hosts"`
	OAuth2Issuer         any `yaml:"oauth2_issuer"`
}

// SeedSettings are pointers: bootstrap --force only rewrites the settings the
// file sets. Their defaults belong to the settings registry, not to the seed.
type SeedSettings struct {
	AppAutoSelect                *bool     `yaml:"app_auto_select"`
	ConsentAutoAccept            *bool     `yaml:"consent_auto_accept"`
	AggregateAMRFromLoginRequest *bool     `yaml:"aggregate_amr_from_login_request"`
	ChallengeTTL                 *Duration `yaml:"challenge_ttl"`
	Remember                     *bool     `yaml:"remember"`
	RememberFor                  *Duration `yaml:"remember_for"`
	LoginAcceptWebhookURL        *string   `yaml:"login_accept_webhook_url"`
	ConsentAcceptWebhookURL      *string   `yaml:"consent_accept_webhook_url"`
	SupportedLocales             *List     `yaml:"supported_locales"`
	DefaultLocale                *string   `yaml:"default_locale"`
	FallbackLocale               *string   `yaml:"fallback_locale"`
}

type SeedApp struct {
	ID         string `yaml:"id"`
	LoginURL   string `yaml:"login_url"`
	ConsentURL string `yaml:"consent_url"`
	// LogoutURL is optional: an app without one is left out of the logout.
	LogoutURL string         `yaml:"logout_url"`
	Method    string         `yaml:"method"`
	Options   map[string]any `yaml:"options"`
	// AuthMode is how the emulated API identifies the app: network, by
	// AllowedSources, or mtls, by ClientCertFingerprint. Empty until Load
	// applies the default, network.
	AuthMode string `yaml:"auth_mode"`
	// AllowedSources empty falls back to
	// security.emulated_api_authorized_hosts.
	AllowedSources List `yaml:"allowed_sources"`
	// ClientCertFingerprint is the SHA-256 of the app certificate, which Load
	// turns into lowercase hex without colons.
	ClientCertFingerprint string `yaml:"client_cert_fingerprint"`
}

// appKeys are the app fields of the Go model: in options, where the design
// document once put two of them, they would pass unread.
var appKeys = []string{"auth_mode", "allowed_sources", "client_cert_fingerprint"}

type SeedFlow struct {
	ID string `yaml:"id"`
	// Enabled is nil until Load applies the Symfony default, true.
	Enabled     *bool      `yaml:"enabled"`
	Steps       []SeedStep `yaml:"steps"`
	Title       Localized  `yaml:"title"`
	Description Localized  `yaml:"description"`
	IconURL     Localized  `yaml:"icon_url"`
	// ACR is sent to Hydra at the final accept and matched against the
	// acr_values of the client; empty sends none.
	ACR string `yaml:"acr"`
}

// SeedStep accepts both spellings of the Symfony seed and admin API:
// id or app_id, order or position, the latter a number or, as Symfony casts
// it, a numeric string.
type SeedStep struct {
	AppID    string
	Position int
	// SubjectCheck is none, equal or claim:<name>; empty leaves the engine's
	// default.
	SubjectCheck string
}

var stepKeys = []string{"id", "app_id", "order", "position", "subject_check"}

func (s *SeedStep) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("%sa step is a mapping", at(n))
	}
	for i := 0; i < len(n.Content); i += 2 {
		if k := n.Content[i]; !isMerge(k) && !slices.Contains(stepKeys, k.Value) {
			return fmt.Errorf("%sunknown step key %q, a step takes %s", at(k), k.Value, strings.Join(stepKeys, ", "))
		}
	}
	var raw struct {
		ID           string  `yaml:"id"`
		AppID        string  `yaml:"app_id"`
		Order        *string `yaml:"order"`
		Position     *string `yaml:"position"`
		SubjectCheck string  `yaml:"subject_check"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	switch {
	case raw.ID == "" && raw.AppID == "":
		return fmt.Errorf("%sstep without id or app_id", at(n))
	case raw.ID != "" && raw.AppID != "" && raw.ID != raw.AppID:
		return fmt.Errorf("%sstep id and app_id differ", at(n))
	}
	var positions []int
	for _, p := range []*string{raw.Position, raw.Order} {
		if p == nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(*p))
		if err != nil {
			return fmt.Errorf("%sstep order %q is not an integer", at(n), *p)
		}
		positions = append(positions, v)
	}
	switch {
	case len(positions) == 0:
		return fmt.Errorf("%sstep without order or position", at(n))
	case len(positions) == 2 && positions[0] != positions[1]:
		return fmt.Errorf("%sstep order and position differ", at(n))
	}
	*s = SeedStep{AppID: cmp.Or(raw.AppID, raw.ID), Position: positions[0], SubjectCheck: raw.SubjectCheck}
	return nil
}

type SeedClient struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
	// Scopes is nil until Load applies the Symfony default, admin:flows, to
	// absent scopes; null ones are no scope, as in Symfony.
	Scopes *List `yaml:"scopes"`
}

// resolve applies the Symfony defaults of the entries: bootstrap writes an
// app, a flow or a client whole, so they need no pointer semantics.
func (s *Seed) resolve() {
	for i := range s.Apps {
		a := &s.Apps[i]
		a.AuthMode = cmp.Or(a.AuthMode, "network")
		a.ClientCertFingerprint = strings.ToLower(strings.ReplaceAll(a.ClientCertFingerprint, ":", ""))
	}
	for i := range s.Flows {
		if s.Flows[i].Enabled == nil {
			enabled := true
			s.Flows[i].Enabled = &enabled
		}
	}
	for i := range s.OAuth2Clients {
		if s.OAuth2Clients[i].Scopes == nil {
			s.OAuth2Clients[i].Scopes = &List{"admin:flows"}
		}
	}
}

// validate refuses what Symfony refused (missing or malformed ids, URLs,
// method, title, description, secret) and what the Go schema forbids:
// duplicate ids, a flow without steps, a step on an undeclared app, an app or
// a position twice in a flow, an identification field of the other auth_mode.
// Messages never quote a client secret.
func (s *Seed) validate(fail func(path, format string, args ...any)) {
	apps := map[string]bool{}
	for i, a := range s.Apps {
		path := fmt.Sprintf("dispatcher.apps[%d]", i)
		uniqueID(fail, path, a.ID, apps)
		for _, u := range []struct {
			key, value string
		}{{"login_url", a.LoginURL}, {"consent_url", a.ConsentURL}, {"logout_url", a.LogoutURL}} {
			if u.value == "" && u.key == "logout_url" {
				continue
			}
			if _, err := absoluteURL(u.value); err != nil {
				fail(path+"."+u.key, "%v", err)
			}
		}
		if a.Method == "" {
			fail(path+".method", "is required")
		}
		for _, k := range appKeys {
			if _, ok := a.Options[k]; ok {
				fail(path+".options."+k, "is a key of the app, not an option")
			}
		}
		// The field of the other mode would pass unread.
		switch a.AuthMode {
		case "network":
			if a.ClientCertFingerprint != "" {
				fail(path+".client_cert_fingerprint", "only applies to auth_mode: mtls")
			}
		case "mtls":
			if len(a.AllowedSources) > 0 {
				fail(path+".allowed_sources", "only applies to auth_mode: network")
			}
			if b, err := hex.DecodeString(a.ClientCertFingerprint); err != nil || len(b) != sha256.Size {
				fail(path+".client_cert_fingerprint", "must be the SHA-256 of the app certificate, in hex, for auth_mode: mtls")
			}
		default:
			fail(path+".auth_mode", "%q is not network or mtls", a.AuthMode)
		}
		if _, err := a.AllowedSources.Prefixes(); err != nil {
			fail(path+".allowed_sources", "%v", err)
		}
	}

	flows := map[string]bool{}
	for i, f := range s.Flows {
		path := fmt.Sprintf("dispatcher.flows[%d]", i)
		uniqueID(fail, path, f.ID, flows)
		if len(f.Title) == 0 {
			fail(path+".title", "is required")
		}
		if len(f.Description) == 0 {
			fail(path+".description", "is required")
		}
		if len(f.Steps) == 0 {
			fail(path+".steps", "is empty")
		}
		if strings.ContainsFunc(f.ACR, unicode.IsSpace) {
			// acr_values is a space-separated list: no value would match.
			fail(path+".acr", "%q contains a space", f.ACR)
		}
		stepApps, positions := map[string]bool{}, map[int]bool{}
		for j, step := range f.Steps {
			stepPath := fmt.Sprintf("%s.steps[%d]", path, j)
			switch {
			case !apps[step.AppID]:
				fail(stepPath, "app %q is not declared in dispatcher.apps", step.AppID)
			case stepApps[step.AppID]:
				fail(stepPath, "app %q is already a step of this flow", step.AppID)
			}
			if positions[step.Position] {
				fail(stepPath, "position %d is already taken in this flow", step.Position)
			}
			stepApps[step.AppID], positions[step.Position] = true, true
			if c := step.SubjectCheck; c != "" && c != "none" && c != "equal" && (!strings.HasPrefix(c, "claim:") || c == "claim:") {
				fail(stepPath+".subject_check", "%q is not none, equal or claim:<name>", c)
			}
		}
	}

	clients := map[string]bool{}
	for i, c := range s.OAuth2Clients {
		path := fmt.Sprintf("dispatcher.oauth2_clients[%d]", i)
		uniqueID(fail, path, c.ID, clients)
		if c.Secret == "" {
			fail(path+".secret", "is required")
		}
	}

	if s.ChallengeTTL != nil && *s.ChallengeTTL <= 0 {
		fail("dispatcher.challenge_ttl", "must be positive")
	}
	if s.SupportedLocales != nil && len(*s.SupportedLocales) == 0 {
		fail("dispatcher.supported_locales", "is empty")
	}
}

// resourceID is Symfony's ResourceId: an id is a path segment of the admin
// API (/admin/v1/apps/{id}).
var resourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func uniqueID(fail func(path, format string, args ...any), path, id string, seen map[string]bool) {
	switch {
	case id == "":
		fail(path+".id", "is required")
	case !resourceID.MatchString(id):
		fail(path+".id", "%q is not an id: up to 128 letters, digits, '.', '_' or '-', starting with a letter or a digit", id)
	case seen[id]:
		fail(path+".id", "%q is declared twice", id)
	}
	seen[id] = true
}

// ignoredKeys lists the Symfony keys present in the seed, with the reason
// they are ignored.
func (s *Seed) ignoredKeys() []string {
	var warnings []string
	for _, k := range []struct {
		set    bool
		name   string
		reason string
	}{
		{s.HydraPublicURL != nil, "hydra_public_url", "never read by the Symfony app either"},
		{s.SessionTTL != nil, "session_ttl", "a flow lasts challenge_ttl, the skip memory remember_for"},
		{s.CacheProviders != nil, "cache_providers", "the flow state store is state.redis_dsn"},
		{s.AdminAuthorizedHosts != nil, "admin_authorized_hosts", "use security.admin_authorized_hosts"},
		{s.OAuth2Issuer != nil, "oauth2_issuer", "not supported yet"},
	} {
		if k.set {
			warnings = append(warnings, fmt.Sprintf("dispatcher.%s is ignored: %s", k.name, k.reason))
		}
	}
	return warnings
}
