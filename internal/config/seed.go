package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Seed is the dispatcher: block, read only by bootstrap to initialise the
// database. It keeps the format of the Symfony dispatcher.yaml so existing
// seeds load unchanged.
type Seed struct {
	Apps          []SeedApp    `yaml:"apps"`
	Flows         []SeedFlow   `yaml:"flows"`
	OAuth2Clients []SeedClient `yaml:"oauth2_clients"`
	SeedSettings  `yaml:",inline"`

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
	ID         string         `yaml:"id"`
	LoginURL   string         `yaml:"login_url"`
	ConsentURL string         `yaml:"consent_url"`
	LogoutURL  string         `yaml:"logout_url"`
	Method     string         `yaml:"method"`
	Options    map[string]any `yaml:"options"`
}

type SeedFlow struct {
	ID          string     `yaml:"id"`
	Enabled     *bool      `yaml:"enabled"`
	Steps       []SeedStep `yaml:"steps"`
	Title       Localized  `yaml:"title"`
	Description Localized  `yaml:"description"`
	IconURL     Localized  `yaml:"icon_url"`
}

// SeedStep accepts both spellings of the Symfony seed and admin API:
// id or app_id, order or position.
type SeedStep struct {
	AppID    string
	Position int
}

func (s *SeedStep) UnmarshalYAML(n *yaml.Node) error {
	var raw struct {
		ID       string `yaml:"id"`
		AppID    string `yaml:"app_id"`
		Order    *int   `yaml:"order"`
		Position *int   `yaml:"position"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	s.AppID = raw.AppID
	if s.AppID == "" {
		s.AppID = raw.ID
	}
	switch {
	case raw.Position != nil:
		s.Position = *raw.Position
	case raw.Order != nil:
		s.Position = *raw.Order
	default:
		return fmt.Errorf("line %d: step without order or position", n.Line)
	}
	return nil
}

type SeedClient struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
	Scopes *List  `yaml:"scopes"`
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
