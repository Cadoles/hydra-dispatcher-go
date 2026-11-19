package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// loadSeed loads the dispatcher: block of content, as serve and bootstrap
// load the file.
func loadSeed(t *testing.T, content string) config.Seed {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dispatcher.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path, []string{
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES=10.0.0.10",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24",
		"DISPATCHER_HYDRA_ADMIN_URL=http://hydra:4445",
		"DISPATCHER_STORE_DSN=postgres://dispatcher@postgres/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Seed
}

// Every setting of the seed has a key in the registry, and seedSettings
// gives it the type of its field.
func TestSeedSettings(t *testing.T) {
	seed := loadSeed(t, `
dispatcher:
  app_auto_select: true
  consent_auto_accept: true
  aggregate_amr_from_login_request: true
  challenge_ttl: 1800
  remember: false
  login_remember_for: 1h
  consent_remember_for: 7d
  login_accept_webhook_url: http://hooks/login
  consent_accept_webhook_url: http://hooks/consent
  supported_locales: [en]
  default_locale: en
  fallback_locale: fr
  skip_scopes: any
  acr_values_mode: require
  admin_oidc.enabled: true
  admin_oidc.issuer: https://idp.test
  admin_oidc.client_id: dispatcher-admin
  admin_oidc.client_secret: s3cret
  admin_oidc.scopes: [openid, email]
  admin_oidc.username_claim: email
  admin_oidc.required_acr: [mfa]
  admin_oidc.auto_create: true
  admin_oidc.authorization_endpoint: https://idp.test/authorize
  admin_oidc.token_endpoint: https://idp.test/token
  admin_oidc.jwks_uri: https://idp.test/jwks
`)
	values := seedSettings(seed.SeedSettings)
	if len(values) != len(registry) {
		t.Errorf("%d seed settings for %d keys", len(values), len(registry))
	}
	tags := reflect.TypeFor[config.SeedSettings]()
	for i := range tags.NumField() {
		key, _, _ := strings.Cut(tags.Field(i).Tag.Get("yaml"), ",")
		if _, ok := lookup(key); !ok {
			t.Errorf("seed setting %s has no key in the registry", key)
		}
	}
	var s Settings
	for _, st := range registry {
		reflect.ValueOf(st.field(&s)).Elem().Set(reflect.ValueOf(values[st.key])) // panics on a wrong type
	}
	want := Settings{
		AppAutoSelect: true, ConsentAutoAccept: true, AggregateAMRFromLoginRequest: true,
		ChallengeTTL: 30 * time.Minute, LoginRememberFor: time.Hour, ConsentRememberFor: 7 * 24 * time.Hour,
		LoginAcceptWebhookURL: "http://hooks/login", ConsentAcceptWebhookURL: "http://hooks/consent",
		SupportedLocales: []string{"en"}, DefaultLocale: "en", FallbackLocale: "fr", SkipScopes: SkipScopesAny, ACRValuesMode: ACRValuesRequire,
		AdminOIDC: AdminOIDC{Enabled: true, Issuer: "https://idp.test", ClientID: "dispatcher-admin", ClientSecret: "s3cret",
			Scopes: []string{"openid", "email"}, UsernameClaim: "email", RequiredACR: []string{"mfa"}, AutoCreate: true,
			AuthorizationEndpoint: "https://idp.test/authorize", TokenEndpoint: "https://idp.test/token", JWKSURI: "https://idp.test/jwks"},
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("settings = %+v\nwant %+v", s, want)
	}
}

func TestFlowFromSeed(t *testing.T) {
	seed := loadSeed(t, `
dispatcher:
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
    - { id: b, login_url: http://b/login, consent_url: http://b/consent, method: otp }
  flows:
    - id: f
      title: F
      description: D
      icon_url: http://icons/f.svg
      steps: [{ id: b, order: 1, subject_check: equal }, { id: a, order: 0 }]
`)
	f := seed.Flows[0].Flow()
	want := Flow{
		ID: "f", Title: map[string]string{"": "F"}, Description: map[string]string{"": "D"}, // a plain string: any locale
		IconURL: map[string]string{"": "http://icons/f.svg"}, Enabled: true,
		Steps: []Step{{AppID: "a", Position: 0, SubjectCheck: "none"}, {AppID: "b", Position: 1, SubjectCheck: "equal"}},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("flow = %+v\nwant %+v", f, want)
	}
}
