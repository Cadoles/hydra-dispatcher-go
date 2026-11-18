package config

import (
	"cmp"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

// Seed is the dispatcher: block, read only by bootstrap to initialise the
// database. It takes the Symfony dispatcher.yaml as is, apart from its
// %env(VAR)% placeholders (write ${VAR}), and accepts a few more forms and
// keys: app_id/position in steps, subject_check, plain-string title,
// comma-separated lists, durations such as "1h", remember,
// login_remember_for and consent_remember_for, and the fields the Go model
// adds to apps and flows.
type Seed struct {
	Apps          []SeedApp    `yaml:"apps"`
	Flows         []SeedFlow   `yaml:"flows"`
	OAuth2Clients []SeedClient `yaml:"oauth2_clients"`
	// Scopes are the catalogue of the scopes (P24): those of the business,
	// and the labels a standard scope renames.
	Scopes       []SeedScope `yaml:"scopes"`
	SeedSettings `yaml:",inline"`

	// NullSettings lists the settings the file sets to null (~): bootstrap
	// --force resets them, where it leaves an absent setting alone.
	NullSettings []string `yaml:"-"`

	// SessionTTL is the Symfony name of login_remember_for, the duration
	// Symfony sent at the login accept: Load moves it there.
	SessionTTL *Duration `yaml:"session_ttl"`
	// bothLoginTTLs records that the file has session_ttl and
	// login_remember_for both, null or not: validate refuses it.
	bothLoginTTLs bool

	// Symfony keys with no Go counterpart: accepted, then ignored with a
	// warning.
	HydraPublicURL       ignored `yaml:"hydra_public_url"`
	CacheProviders       ignored `yaml:"cache_providers"`
	AdminAuthorizedHosts ignored `yaml:"admin_authorized_hosts"`
	OAuth2Issuer         ignored `yaml:"oauth2_issuer"`
}

// ignored records that a Symfony key is set. Its value is never read, so
// neither expanded nor checked: cache_providers may keep its %env(REDIS_DSN)%.
type ignored bool

func (i *ignored) UnmarshalYAML(*yaml.Node) error {
	*i = true
	return nil
}

// SeedSettings are pointers: bootstrap --force only rewrites the settings the
// file sets. Their defaults belong to the settings registry, not to the seed.
type SeedSettings struct {
	AppAutoSelect                *bool     `yaml:"app_auto_select"`
	ConsentAutoAccept            *bool     `yaml:"consent_auto_accept"`
	AggregateAMRFromLoginRequest *bool     `yaml:"aggregate_amr_from_login_request"`
	ChallengeTTL                 *Duration `yaml:"challenge_ttl"`
	Remember                     *bool     `yaml:"remember"`
	LoginRememberFor             *Duration `yaml:"login_remember_for"`
	ConsentRememberFor           *Duration `yaml:"consent_remember_for"`
	LoginAcceptWebhookURL        *string   `yaml:"login_accept_webhook_url"`
	ConsentAcceptWebhookURL      *string   `yaml:"consent_accept_webhook_url"`
	SupportedLocales             *List     `yaml:"supported_locales"`
	DefaultLocale                *string   `yaml:"default_locale"`
	FallbackLocale               *string   `yaml:"fallback_locale"`
	ACRValuesMode                *string   `yaml:"acr_values_mode"`
	// The block admin_oidc, by the keys of the setting table (P22): the
	// login to the admin by an identity provider. client_secret is encrypted
	// in the database by secrets.encryption_key; give it by ${...}.
	AdminOIDCEnabled               *bool   `yaml:"admin_oidc.enabled"`
	AdminOIDCIssuer                *string `yaml:"admin_oidc.issuer"`
	AdminOIDCClientID              *string `yaml:"admin_oidc.client_id"`
	AdminOIDCClientSecret          *string `yaml:"admin_oidc.client_secret"`
	AdminOIDCScopes                *List   `yaml:"admin_oidc.scopes"`
	AdminOIDCUsernameClaim         *string `yaml:"admin_oidc.username_claim"`
	AdminOIDCRequiredACR           *List   `yaml:"admin_oidc.required_acr"`
	AdminOIDCAutoCreate            *bool   `yaml:"admin_oidc.auto_create"`
	AdminOIDCAuthorizationEndpoint *string `yaml:"admin_oidc.authorization_endpoint"`
	AdminOIDCTokenEndpoint         *string `yaml:"admin_oidc.token_endpoint"`
	AdminOIDCJWKSURI               *string `yaml:"admin_oidc.jwks_uri"`
}

type SeedApp struct {
	ID         string `yaml:"id"`
	LoginURL   string `yaml:"login_url"`
	ConsentURL string `yaml:"consent_url"`
	// LogoutURL is optional: an app without one is left out of the logout.
	LogoutURL string `yaml:"logout_url"`
	Method    string `yaml:"method"`
	// Options, which Symfony accepts and never reads, are ignored with a
	// warning, their values unread; the keys of appKeys are refused.
	Options appOptions `yaml:"options"`
	// ReceiveClaims names the claims of the previous steps the app receives:
	// none when empty, an empty variable included. Without the key, a new app
	// receives every claim and bootstrap leaves an existing one as it is.
	ReceiveClaims *List `yaml:"receive_claims"`
	// NullReceiveClaims records receive_claims: ~, which gives every claim,
	// to an app that has a list too.
	NullReceiveClaims bool `yaml:"-"`
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
	// SkipCheckURL is where the dispatcher asks the app whether a step of it
	// may be skipped (phase 4); empty leaves the app out of it.
	SkipCheckURL string `yaml:"skip_check_url"`
	// SkipCheckKey signs those requests: 32 bytes, in hex or base64, by
	// ${VAR} or by SkipCheckKeyFile. Without it, bootstrap keeps the key the
	// database holds (config dump leaves it out).
	SkipCheckKey     string `yaml:"skip_check_key"`
	SkipCheckKeyFile string `yaml:"skip_check_key_file"`
	// SkipCheckSignals are the signals of the browser the app receives.
	SkipCheckSignals List `yaml:"skip_check_signals"`
	// SkipCheckSet records that the seed names skip_check_url, ~ or empty
	// included: without the key, bootstrap leaves the pre-check of an
	// existing app as the database holds it, URL, key and signals, as
	// receive_claims; a key lost is lost for good (R48, Q139).
	SkipCheckSet bool `yaml:"-"`
}

// appKeys are the app fields of the Go model: in options, where the design
// document once put them, they would pass unread, and an app would receive
// every claim for want of its receive_claims.
var appKeys = []string{"auth_mode", "allowed_sources", "client_cert_fingerprint", "receive_claims",
	"skip_check_url", "skip_check_key", "skip_check_key_file", "skip_check_signals"}

// appOptions is the options key of an app. Symfony takes any form (its
// variableNode) and never reads it: nothing here is expanded or checked. Only
// the keys of a mapping are kept, merged ones included, for appKeys.
type appOptions struct {
	keys map[string]ignored
	set  bool // holds something: not ~, {}, [] or ""
}

func (o *appOptions) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		o.set = len(n.Content) > 0
		return n.Decode(&o.keys)
	case yaml.SequenceNode:
		o.set = len(n.Content) > 0
	default:
		o.set = n.Value != ""
	}
	return nil
}

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
	// SkipCheckAllowedACR are the acr_values under which a step may be
	// skipped by its pre-check.
	SkipCheckAllowedACR List `yaml:"skip_check_allowed_acr"`
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
	// SkipCheck asks the app of the step whether it may be skipped (phase 4).
	SkipCheck bool
}

var stepKeys = []string{"id", "app_id", "order", "position", "subject_check", "skip_check"}

func (s *SeedStep) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("%sa step is a mapping", at(n))
	}
	if err := checkStepKeys(n); err != nil {
		return err
	}
	var raw struct {
		ID           string  `yaml:"id"`
		AppID        string  `yaml:"app_id"`
		Order        *string `yaml:"order"`
		Position     *string `yaml:"position"`
		SubjectCheck string  `yaml:"subject_check"`
		SkipCheck    bool    `yaml:"skip_check"`
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
	*s = SeedStep{AppID: cmp.Or(raw.AppID, raw.ID), Position: positions[0], SubjectCheck: raw.SubjectCheck, SkipCheck: raw.SkipCheck}
	return nil
}

// checkStepKeys refuses an unknown key in a step, merged ones included.
func checkStepKeys(n *yaml.Node) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if !isMerge(k) {
			if !slices.Contains(stepKeys, k.Value) {
				return fmt.Errorf("%sunknown step key %q, a step takes %s", at(k), k.Value, strings.Join(stepKeys, ", "))
			}
			continue
		}
		for _, m := range mergedMappings(n.Content[i+1]) {
			if err := checkStepKeys(m); err != nil {
				return err
			}
		}
	}
	return nil
}

type SeedClient struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
	// SecretFile gives Secret by a file, as a secret (Q87).
	SecretFile string `yaml:"secret_file"`
	// Scopes is nil until Load applies the Symfony default, admin:flows, to
	// absent scopes; null ones are no scope, as in Symfony.
	Scopes *List `yaml:"scopes"`
}

// resolve applies the Symfony defaults of the entries: bootstrap writes an
// app, a flow or a client whole, so they need no pointer semantics, the
// receive_claims of an app apart. It moves session_ttl to login_remember_for,
// unless both are set, which validate refuses.
func (s *Seed) resolve() {
	if s.SessionTTL != nil && s.LoginRememberFor == nil {
		s.LoginRememberFor, s.SessionTTL = s.SessionTTL, nil
	}
	for i := range s.Apps {
		a := &s.Apps[i]
		a.AuthMode = cmp.Or(a.AuthMode, "network")
		a.ClientCertFingerprint = domain.NormalizeFingerprint(a.ClientCertFingerprint)
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
// The rules of an entry are those of internal/domain, which the writes of the
// store follow too; those of the seed as a file stay here. Messages never
// quote a client secret.
func (s *Seed) validate(fail func(path, format string, args ...any)) {
	// in reports the violations of an entry under its path.
	in := func(path string) domain.Fail {
		return func(field, format string, args ...any) {
			if field != "" {
				fail(path+"."+field, format, args...)
				return
			}
			fail(path, format, args...)
		}
	}
	apps, skipCheck := map[string]bool{}, map[string]bool{}
	for i, a := range s.Apps {
		path := fmt.Sprintf("dispatcher.apps[%d]", i)
		unique(fail, path, a.ID, apps)
		app, err := a.App()
		if err != nil {
			fail(path+".allowed_sources", "%v", err)
		}
		if app.SkipCheckURL != "" && app.SkipCheckKey == "" {
			// bootstrap keeps the key the database holds, which config dump
			// leaves out: the write says whether there is one.
			app.SkipCheckKey = strings.Repeat("0", 64)
		}
		app.Check(in(path))
		// An app the seed is silent on may hold its URL in the database, which
		// bootstrap keeps (Q139): bootstrap's check of the whole decides (R51).
		skipCheck[a.ID] = a.SkipCheckURL != "" || !a.SkipCheckSet
		for _, k := range appKeys {
			if _, ok := a.Options.keys[k]; ok {
				fail(path+".options."+k, "is a key of the app, not an option")
			}
		}
	}

	flows := map[string]bool{}
	for i, f := range s.Flows {
		path := fmt.Sprintf("dispatcher.flows[%d]", i)
		unique(fail, path, f.ID, flows)
		f.Flow().Check(in(path), func(id string) bool { return apps[id] })
		for j, st := range f.Steps {
			if st.SkipCheck && apps[st.AppID] && !skipCheck[st.AppID] {
				fail(fmt.Sprintf("%s.steps[%d].skip_check", path, j), "app %s has no skip_check_url", st.AppID)
			}
		}
	}

	clients := map[string]bool{}
	for i, c := range s.OAuth2Clients {
		path := fmt.Sprintf("dispatcher.oauth2_clients[%d]", i)
		domain.CheckID(in(path), c.ID)
		unique(fail, path, c.ID, clients)
		if c.Secret == "" {
			fail(path+".secret", "is required")
		}
		if c.Scopes != nil {
			domain.CheckScopes(in(path), *c.Scopes)
		}
	}

	if s.ChallengeTTL != nil && *s.ChallengeTTL <= 0 {
		fail("dispatcher.challenge_ttl", "must be positive")
	}
	// Null included: session_ttl: ~ would reset what login_remember_for sets.
	if s.SessionTTL != nil || s.bothLoginTTLs {
		fail("dispatcher.session_ttl", "is the Symfony name of login_remember_for, which is set too: keep login_remember_for")
	}
	// The cookie would expire at once, while Hydra reads 0 as no expiry.
	for _, d := range []struct {
		key   string
		value *Duration
	}{{"login_remember_for", s.LoginRememberFor}, {"consent_remember_for", s.ConsentRememberFor}} {
		if d.value != nil && *d.value <= 0 {
			fail("dispatcher."+d.key, "must be positive")
		}
	}
	if s.SupportedLocales != nil && len(*s.SupportedLocales) == 0 {
		fail("dispatcher.supported_locales", "is empty")
	}
}

// unique refuses an id the seed declares twice; domain.Check refuses a
// missing or malformed one.
func unique(fail func(path, format string, args ...any), path, id string, seen map[string]bool) {
	if domain.ValidID(id) && seen[id] {
		fail(path+".id", "%q is declared twice", id)
	}
	seen[id] = true
}

// App gives the app as the store keeps it: receive_claims nil when the seed
// has none, absent or ~, which bootstrap tells apart.
func (a SeedApp) App() (domain.App, error) {
	sources, err := domain.ParsePrefixes(a.AllowedSources)
	if len(sources) == 0 {
		sources = nil
	}
	var claims []string
	if a.ReceiveClaims != nil {
		claims = *a.ReceiveClaims
	}
	var signals []string
	if len(a.SkipCheckSignals) > 0 {
		signals = a.SkipCheckSignals
	}
	return domain.App{
		ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
		AuthMode: a.AuthMode, AllowedSources: sources, ClientCertFingerprint: a.ClientCertFingerprint, ReceiveClaims: claims,
		SkipCheckURL: a.SkipCheckURL, SkipCheckKey: strings.TrimSpace(a.SkipCheckKey), SkipCheckSignals: signals,
	}, err
}

// SeedScope is a scope of the catalogue: its label and its claims, each with
// its label, by locale or a plain string for every locale.
type SeedScope struct {
	Name   string           `yaml:"name"`
	Label  Localized        `yaml:"label"`
	Claims []SeedScopeClaim `yaml:"claims"`
}

type SeedScopeClaim struct {
	Claim string    `yaml:"claim"`
	Label Localized `yaml:"label"`
}

// Scope gives the scope as the store keeps it.
func (s SeedScope) Scope() domain.Scope {
	d := domain.Scope{Name: s.Name, Label: map[string]string(s.Label)}
	for _, c := range s.Claims {
		d.Claims = append(d.Claims, domain.ScopeClaim{Claim: c.Claim, Label: map[string]string(c.Label)})
	}
	return d
}

// Flow gives the flow as the store keeps it: steps by position, none for
// subject_check when the seed leaves it out.
func (f SeedFlow) Flow() domain.Flow {
	d := domain.Flow{
		ID: f.ID, Title: f.Title, Description: f.Description, Enabled: f.Enabled == nil || *f.Enabled, ACR: f.ACR,
	}
	if len(f.SkipCheckAllowedACR) > 0 {
		d.SkipCheckAllowedACR = f.SkipCheckAllowedACR
	}
	if len(f.IconURL) > 0 {
		d.IconURL = f.IconURL
	}
	for _, s := range f.Steps {
		d.Steps = append(d.Steps, domain.Step{AppID: s.AppID, Position: s.Position, SubjectCheck: cmp.Or(s.SubjectCheck, "none"), SkipCheck: s.SkipCheck})
	}
	slices.SortFunc(d.Steps, func(a, b domain.Step) int { return cmp.Compare(a.Position, b.Position) })
	return d
}

// warnings lists the Symfony keys present in the seed, with the reason they
// are ignored, the settings set to ~ that Symfony read otherwise, and the
// apps a ~ gives every claim.
func (s *Seed) warnings() []string {
	var warnings []string
	for _, k := range []struct {
		set    ignored
		name   string
		reason string
	}{
		{s.HydraPublicURL, "hydra_public_url", "never read by the Symfony app either"},
		{s.CacheProviders, "cache_providers", "the flow state store is state.redis_dsn"},
		{s.AdminAuthorizedHosts, "admin_authorized_hosts", "use security.admin_authorized_hosts"},
		{s.OAuth2Issuer, "oauth2_issuer", "not supported yet"},
	} {
		if k.set {
			warnings = append(warnings, fmt.Sprintf("dispatcher.%s is ignored: %s", k.name, k.reason))
		}
	}
	for i, a := range s.Apps {
		if a.Options.set {
			warnings = append(warnings, fmt.Sprintf("dispatcher.apps[%d].options is ignored: never read by the Symfony app either", i))
		}
		if a.NullReceiveClaims {
			warnings = append(warnings, fmt.Sprintf("dispatcher.apps[%d].receive_claims: ~ gives every claim, and bootstrap -force takes back a list: [] gives none, and without the key bootstrap leaves the database as it is", i))
		}
	}
	settings := yamlFields(reflect.TypeFor[SeedSettings]())
	symfony := map[reflect.Type]string{reflect.TypeFor[*bool](): "true", reflect.TypeFor[*List](): "an empty list"}
	for _, k := range s.NullSettings {
		if read, ok := symfony[settings[k]]; ok && !strings.HasPrefix(k, "admin_oidc.") {
			warnings = append(warnings, fmt.Sprintf("dispatcher.%s: ~ resets it to its default, where Symfony read it as %s", k, read))
		}
	}
	return warnings
}
