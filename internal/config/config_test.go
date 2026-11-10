package config

import (
	"encoding/base64"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// A key serves one use only: tests that set several take distinct ones.
var (
	hexKey     = strings.Repeat("ab", 32)
	hexKey2    = strings.Repeat("cd", 32)
	hexKey3    = strings.Repeat("ef", 32)
	base64Key  = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	base64Key2 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32)))
)

// envOf turns a map into an os.Environ() list.
func envOf(m map[string]string) []string {
	var env []string
	for k, v := range m {
		env = append(env, k+"="+v)
	}
	return env
}

// required holds the keys without default, set through DISPATCHER_* variables.
func required(extra map[string]string) map[string]string {
	m := map[string]string{
		"DISPATCHER_SERVER_BASE_URL":        "http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES": "10.0.0.10",
		"DISPATCHER_HYDRA_ADMIN_URL":        "http://hydra:4445",
		"DISPATCHER_STORE_DSN":              "postgres://lasql:lasql@postgres:5432/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY":     hexKey,
		"DISPATCHER_SECRETS_CHALLENGE_KEY":  base64Key,
		// The networks of the login apps.
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS": "10.0.1.0/24",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dispatcher.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// load loads content with the required variables plus env.
func load(t *testing.T, content string, env map[string]string) (*Config, []string, error) {
	t.Helper()
	return Load(writeFile(t, content), envOf(required(env)))
}

const adminHTTPWarning = "hydra.admin_url is in http://"

func hasWarning(warnings []string, substr string) bool {
	return slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, substr) })
}

const memoryWarning = "state.redis_dsn is empty"

// The example of the design document must keep loading as is.
func TestDesignDocExample(t *testing.T) {
	c, warnings, err := Load("testdata/design-doc.yaml", envOf(map[string]string{
		"HYDRA_SYSTEM_SECRETS":      "youReallyNeedToChangeThis,an-older-system-secret",
		"DISPATCHER_COOKIE_KEY":     hexKey,
		"DISPATCHER_ENCRYPTION_KEY": base64Key,
		"DISPATCHER_CHALLENGE_KEY":  hexKey2,
		"DISPATCHER_WEBHOOK_KEY":    hexKey3,
		"DATABASE_URL":              "postgres://lasql:lasql@postgres:5432/dispatcher",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// REDIS_DSN is unset: the in-memory store, with its warning; Hydra's admin in
	// http://, with its own; OAUTH2_PRIVATE_KEY unset, the admin API without its key.
	// The DISPATCHER_*_KEY references are no overrides, and draw no warning.
	if len(warnings) != 3 || !hasWarning(warnings, memoryWarning) || !hasWarning(warnings, adminHTTPWarning) ||
		!hasWarning(warnings, "admin.api.enabled without admin.api.private_key: /admin/v1 is not served") {
		t.Errorf("warnings = %q", warnings)
	}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"server.base_url", c.Server.BaseURL, "http://dispatcher.hydra.test"},
		{"hydra.system_secrets", c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "an-older-system-secret"}},
		{"secrets.encryption_key", len(c.Secrets.EncryptionKey), 32},
		{"secrets.webhook_signing_key", len(c.Secrets.WebhookSigningKey), 32},
		{"secrets.encryption_keys_previous", c.Secrets.EncryptionKeysPrevious, Keys{}},
		// Unset variables give empty values, not the defaults.
		{"state.redis_dsn", c.State.RedisDSN, ""},
		{"admin.api.private_key", c.Admin.API.PrivateKey, ""},
		{"dispatcher.challenge_ttl", c.Seed.ChallengeTTL.Std(), time.Hour},
		{"dispatcher.login_remember_for", c.Seed.LoginRememberFor.Std(), 86400 * time.Second},
		{"dispatcher.consent_remember_for", c.Seed.ConsentRememberFor.Std(), 2629800 * time.Second},
		{"dispatcher.supported_locales", *c.Seed.SupportedLocales, List{"fr", "en"}},
		{"serve.bootstrap", c.Serve.Bootstrap, "off"},
		{"dispatcher.remember", *c.Seed.Remember, true},
		{"server.replicas_hint", c.Server.ReplicasHint, 1},
		{"security.emulated_api_authorized_hosts", *c.Security.EmulatedAPIAuthorizedHosts, List{"10.0.1.0/24"}},
		{"webhooks.max_processes", c.Webhooks.MaxProcesses, 32},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

// Hydra's admin in http:// is told of, outside development (Q70).
func TestAdminInHTTP(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"http://", map[string]string{"DISPATCHER_HYDRA_ADMIN_URL": "http://hydra:4445"}, true},
		{"in capitals", map[string]string{"DISPATCHER_HYDRA_ADMIN_URL": "HTTP://hydra:4445"}, true},
		{"https://", map[string]string{"DISPATCHER_HYDRA_ADMIN_URL": "https://hydra:4445"}, false},
		{"tls.allow_http", map[string]string{"DISPATCHER_HYDRA_ADMIN_URL": "http://hydra:4445", "DISPATCHER_TLS_ALLOW_HTTP": "true"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, warnings, err := Load("testdata/design-doc.yaml", envOf(required(tc.env)))
			if err != nil {
				t.Fatal(err)
			}
			if got := hasWarning(warnings, adminHTTPWarning); got != tc.want {
				t.Errorf("warnings = %q", warnings)
			}
		})
	}
}

// Every key of non-defaults.yaml differs from its default, so a key the
// decoder skipped would keep its default and show here.
func TestEveryKeyIsRead(t *testing.T) {
	c, warnings, err := Load("testdata/non-defaults.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	// ui.reload, true there, alone is warned of (Q93).
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "ui.reload is for the development of a theme") {
		t.Errorf("warnings = %q", warnings)
	}
	got, defaultKeys := envKeys(c), envKeys(defaults())
	if len(got) != len(defaultKeys) {
		t.Fatalf("%d keys, want %d", len(got), len(defaultKeys))
	}
	for i, k := range got {
		// postgres is the only store, cookie the only skip memory; pinning,
		// strict claims and the server memory are refused until implemented.
		if k.path == "store.backend" || k.path == "remember.backend" || k.path == "tls.pinned_spki_sha256" || k.path == "consent.claims_filter" {
			continue
		}
		// A secret and its file exclude each other: TestSecretFiles reads the files.
		if strings.HasSuffix(k.path, "_file") && k.path != "hydra.system_secrets_file" {
			continue
		}
		if reflect.DeepEqual(k.field.Interface(), defaultKeys[i].field.Interface()) {
			t.Errorf("%s = %v, its default: the file value is not read", k.path, k.field.Interface())
		}
	}
	// Unread, these lists would copy the admin one, which differs from their
	// nil default too: check their values.
	if !slices.Equal(*c.Security.EmulatedAPIAuthorizedHosts, List{"10.3.0.0/16"}) || !slices.Equal(*c.Security.MetricsAuthorizedHosts, List{"10.4.0.0/16"}) {
		t.Errorf("emulated = %v, metrics = %v", *c.Security.EmulatedAPIAuthorizedHosts, *c.Security.MetricsAuthorizedHosts)
	}
	if !slices.Equal(c.UI.CSPExtra["font-src"], List{"https://fonts.gstatic.com"}) {
		t.Errorf("ui.csp_extra = %v", c.UI.CSPExtra)
	}
}

// Every seed setting, each with its own value, so that two swapped tags show.
func TestSeedSettings(t *testing.T) {
	c, _, err := load(t, `
dispatcher:
  app_auto_select: true
  consent_auto_accept: false
  aggregate_amr_from_login_request: true
  challenge_ttl: 1800
  remember: false
  login_remember_for: 12h
  consent_remember_for: 7d
  login_accept_webhook_url: http://hooks/login
  consent_accept_webhook_url: http://hooks/consent
  supported_locales: [en, de]
  default_locale: en
  fallback_locale: de
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Seed.SeedSettings
	v := reflect.ValueOf(s)
	for i := range v.NumField() {
		if v.Field(i).IsNil() {
			t.Errorf("%s is not read", v.Type().Field(i).Name)
		}
	}
	if t.Failed() {
		return
	}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"app_auto_select", *s.AppAutoSelect, true},
		{"consent_auto_accept", *s.ConsentAutoAccept, false},
		{"aggregate_amr_from_login_request", *s.AggregateAMRFromLoginRequest, true},
		{"challenge_ttl", s.ChallengeTTL.Std(), 30 * time.Minute},
		{"remember", *s.Remember, false},
		{"login_remember_for", s.LoginRememberFor.Std(), 12 * time.Hour},
		{"consent_remember_for", s.ConsentRememberFor.Std(), 7 * 24 * time.Hour},
		{"login_accept_webhook_url", *s.LoginAcceptWebhookURL, "http://hooks/login"},
		{"consent_accept_webhook_url", *s.ConsentAcceptWebhookURL, "http://hooks/consent"},
		{"supported_locales", *s.SupportedLocales, List{"en", "de"}},
		{"default_locale", *s.DefaultLocale, "en"},
		{"fallback_locale", *s.FallbackLocale, "de"},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

func checkHydraDevSeed(t *testing.T, path string) {
	t.Helper()
	c, warnings, err := Load(path, envOf(required(nil)))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Seed
	var appIDs, flowIDs []string
	for _, a := range s.Apps {
		appIDs = append(appIDs, a.ID)
	}
	for _, f := range s.Flows {
		flowIDs = append(flowIDs, f.ID)
	}
	if !slices.Equal(appIDs, []string{"hydra-oidc", "hydra-sql", "hydra-2fa"}) || !slices.Equal(flowIDs, []string{"hydra-oidc", "hydra-sql", "hydra-sql-2fa"}) {
		t.Fatalf("apps = %v, flows = %v", appIDs, flowIDs)
	}
	sql := s.Apps[1]
	if sql.LoginURL != "http://sql.hydra.test/login" || sql.ConsentURL != "http://sql.hydra.test/consent" || sql.LogoutURL != "http://sql.hydra.test/logout" ||
		sql.Method != "pwd" || sql.AuthMode != "network" {
		t.Errorf("hydra-sql app = %+v", sql)
	}
	twoFA := s.Flows[2]
	if !reflect.DeepEqual(twoFA.Steps, []SeedStep{{AppID: "hydra-sql", Position: 0}, {AppID: "hydra-2fa", Position: 1}}) ||
		twoFA.Title["fr"] != "Hydra SQL 2FA" || twoFA.Description["en"] != "SQL Authentication second factor" ||
		twoFA.IconURL != nil || twoFA.Enabled == nil || !*twoFA.Enabled {
		t.Errorf("hydra-sql-2fa flow = %+v", twoFA)
	}
	// The Symfony default scope.
	if len(s.OAuth2Clients) != 1 || s.OAuth2Clients[0].ID != "test" || !slices.Equal(*s.OAuth2Clients[0].Scopes, List{"admin:flows"}) {
		t.Errorf("oauth2_clients = %+v", s.OAuth2Clients)
	}
	// Set in the file, so bootstrap --force rewrites them; remember is absent.
	// session_ttl is Symfony's login_remember_for.
	if s.AppAutoSelect == nil || *s.AppAutoSelect || s.ConsentAutoAccept == nil || s.Remember != nil || len(s.NullSettings) != 0 ||
		s.LoginRememberFor == nil || s.LoginRememberFor.Std() != 24*time.Hour || s.SessionTTL != nil {
		t.Errorf("settings = %+v, null = %v", s.SeedSettings, s.NullSettings)
	}
	if hasWarning(warnings, "dispatcher.session_ttl") {
		t.Errorf("session_ttl warned of in %q", warnings)
	}
	for _, key := range []string{"hydra_public_url", "cache_providers"} {
		if !hasWarning(warnings, "dispatcher."+key) {
			t.Errorf("no warning for ignored dispatcher.%s in %q", key, warnings)
		}
	}
}

// The seed format is unchanged: hydra-dev's Symfony dispatcher.yaml loads.
func TestHydraDevSeed(t *testing.T) {
	checkHydraDevSeed(t, "testdata/hydra-dev-dispatcher.yaml")
	// Catches drift between the snapshot and the file hydra-dev mounts.
	live := "../../../hydra-dev/files/apps/dispatcher/dispatcher.yaml"
	if _, err := os.Stat(live); err != nil {
		t.Skip("hydra-dev is not a sibling checkout")
	}
	checkHydraDevSeed(t, live)
}

// The Symfony repository's own seed: its %env()% placeholders would make a
// client whose secret is the literal "%env(OAUTH2_ADMIN_CLIENT_SECRET)%".
func TestSymfonySeed(t *testing.T) {
	_, _, err := Load("testdata/symfony-dispatcher.yaml", envOf(required(nil)))
	for _, want := range []string{"dispatcher.oauth2_clients[0].id: Symfony %env()%", "dispatcher.oauth2_clients[0].secret: Symfony %env()%"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}

	data, err := os.ReadFile("testdata/symfony-dispatcher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rewritten := regexp.MustCompile(`%env\((\w+)\)%`).ReplaceAllString(string(data), "$${${1}}")
	c, warnings, err := load(t, rewritten, map[string]string{
		"OAUTH2_ADMIN_CLIENT_ID":     "admin",
		"OAUTH2_ADMIN_CLIENT_SECRET": "s3cret",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := c.Seed
	if cl := s.OAuth2Clients[0]; cl.ID != "admin" || cl.Secret != "s3cret" || !slices.Equal(*cl.Scopes, List{"admin:flows"}) {
		t.Errorf("client = %+v", cl)
	}
	// Scopes absent get the default; null ones are none, as in Symfony, merged
	// or not. The null entry the decoder drops does not shift the clients.
	c, _, err = load(t, `
dispatcher:
  oauth2_clients:
    - ~
    - { id: absent, secret: s }
    - &nulled { id: nulled, secret: s, scopes: ~ }
    - { id: blank, secret: s, scopes: }
    - { id: empty, secret: s, scopes: [] }
    - { <<: *nulled, id: merged }
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var scopes []string
	for _, cl := range c.Seed.OAuth2Clients {
		scopes = append(scopes, cl.ID+"="+strings.Join(*cl.Scopes, ","))
	}
	if !slices.Equal(scopes, []string{"absent=admin:flows", "nulled=", "blank=", "empty=", "merged="}) {
		t.Errorf("scopes = %q", scopes)
	}
	// The ignored keys are not read: %env()% or a bad ${} may stay.
	_, ignoredWarnings, err := load(t, `
dispatcher:
  cache_providers:
    - { type: redis, dsn: "%env(REDIS_DSN)%" }
  oauth2_issuer: "%env(BASE_PATH)%"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cache_providers", "oauth2_issuer"} {
		if !hasWarning(ignoredWarnings, "dispatcher."+key+" is ignored") {
			t.Errorf("no warning for ignored dispatcher.%s in %q", key, ignoredWarnings)
		}
	}
	// login_accept_webhook_url: ~ clears the webhook, as Symfony's --force did.
	if !slices.Equal(s.NullSettings, []string{"login_accept_webhook_url", "consent_accept_webhook_url"}) || s.LoginAcceptWebhookURL != nil {
		t.Errorf("null settings = %v", s.NullSettings)
	}
	// icon_url: { fr: ~, en: ~ } is no icon.
	if s.Flows[0].IconURL != nil || s.Apps[1].LoginURL != "http://sql.hydra.test/" {
		t.Errorf("flow = %+v, app = %+v", s.Flows[0], s.Apps[1])
	}
	for _, key := range []string{"hydra_public_url", "admin_authorized_hosts"} {
		if !hasWarning(warnings, "dispatcher."+key) {
			t.Errorf("no warning for ignored dispatcher.%s in %q", key, warnings)
		}
	}
}

func TestEnvOverrides(t *testing.T) {
	path := writeFile(t, `
server:
  listen: ":9000"
security:
  admin_authorized_hosts: ["10.0.0.0/8"]
admin:
  ui: { enabled: true }
`)
	c, _, err := Load(path, envOf(required(map[string]string{
		"DISPATCHER_SERVER_LISTEN":                     ":7000",
		"DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS":   "10.1.0.0/16, 127.0.0.1",
		"DISPATCHER_SECURITY_METRICS_AUTHORIZED_HOSTS": "",
		"DISPATCHER_ADMIN_UI_ENABLED":                  "false",
		"DISPATCHER_ADMIN_API_TOKEN_TTL":               "600",
		"DISPATCHER_ADMIN_CLIENT_SECRET_MAX_AGE":       "90d",
		"DISPATCHER_OBSERVABILITY_ACCESS_LOG_SAMPLE":   "0.1",
		"DISPATCHER_HYDRA_SYSTEM_SECRETS":              "youReallyNeedToChangeThis,another-secret",
		"DISPATCHER_HYDRA_VERSION":                     "2.3",
		"DISPATCHER_SECRETS_ENCRYPTION_KEY":            hexKey3,
		"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS":  hexKey2 + "," + base64Key2,
		"DISPATCHER_ADMIN_API_PUBLIC_KEY":              pem,
	})))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"server.listen", c.Server.Listen, ":7000"},
		{"security.admin_authorized_hosts", c.Security.AdminAuthorizedHosts, List{"10.1.0.0/16", "127.0.0.1"}},
		// No default: never the admin list (B2).
		{"security.emulated_api_authorized_hosts", *c.Security.EmulatedAPIAuthorizedHosts, List{"10.0.1.0/24"}},
		// Set to "": no address, not the admin list.
		{"security.metrics_authorized_hosts", len(*c.Security.MetricsAuthorizedHosts), 0},
		{"admin.ui.enabled", c.Admin.UI.Enabled, false},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL.Std(), 10 * time.Minute},
		{"admin.client_secret_max_age", c.Admin.ClientSecretMaxAge.Std(), 90 * 24 * time.Hour},
		{"observability.access_log_sample", c.Observability.AccessLogSample, 0.1},
		{"hydra.system_secrets", c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "another-secret"}},
		{"hydra.version", c.Hydra.Version, "2.3"},
		{"secrets.encryption_keys_previous", len(c.Secrets.EncryptionKeysPrevious), 2},
		{"admin.api.public_key", c.Admin.API.PublicKey, pem},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}

	for name, value := range map[string]string{
		"DISPATCHER_HYDRA_TIMEOUT":                   "soon",
		"DISPATCHER_HYDRA_MAX_IN_FLIGHT":             "many",
		"DISPATCHER_SERVER_REPLICAS_HINT":            "2.9", // not truncated to 2
		"DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_MAX": "1e3",
		"DISPATCHER_ADMIN_UI_ENABLED":                "maybe",
		"DISPATCHER_OBSERVABILITY_ACCESS_LOG_SAMPLE": "half",
	} {
		if _, _, err := Load(path, envOf(required(map[string]string{name: value}))); err == nil ||
			!strings.Contains(err.Error(), name+" (") || strings.Contains(err.Error(), "line 0") {
			t.Errorf("invalid %s: err = %v, want it to name the variable, without a line", name, err)
		}
	}
}

// The SHA-256 of a certificate, as Load keeps it and as openssl x509
// -fingerprint -sha256 writes it (uppercase in the tests).
var (
	fingerprint      = strings.Repeat("0a1b2c3d", 8)
	colonFingerprint = regexp.MustCompile(`(..)`).ReplaceAllString(fingerprint, "$1:")[:3*32-1]
)

// A multi-line value, quoted or not, reaches a string key unchanged.
const pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE: #not a comment\n  'single' \"double\"\n-----END PUBLIC KEY-----\n"

// An empty variable empties a string, a list or a key, even over a value of
// the file; it is an error elsewhere. "~" and "null" are text, not null.
func TestEnvEmptyOverride(t *testing.T) {
	c, _, err := load(t, `
state: { redis_dsn: "redis://redis:6379" }
observability:
  metrics: { listen: ":9090" }
  sentry: { environment: prod }
`, map[string]string{
		"DISPATCHER_STATE_REDIS_DSN":                  "",
		"DISPATCHER_OBSERVABILITY_METRICS_LISTEN":     "",
		"DISPATCHER_OBSERVABILITY_SENTRY_ENVIRONMENT": "null",
		"DISPATCHER_SECRETS_ENCRYPTION_KEY":           "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.State.RedisDSN != "" || c.Observability.Metrics.Listen != "" || c.Observability.Sentry.Environment != "null" || c.Secrets.EncryptionKey != nil {
		t.Errorf("redis_dsn = %q, metrics.listen = %q, sentry.environment = %q, encryption_key set = %v",
			c.State.RedisDSN, c.Observability.Metrics.Listen, c.Observability.Sentry.Environment, c.Secrets.EncryptionKey != nil)
	}
	if _, _, err := load(t, "", map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY": ""}); err == nil || !strings.Contains(err.Error(), "secrets.cookie_key: is required") {
		t.Errorf("emptied cookie key: err = %v", err)
	}
	for _, name := range []string{"DISPATCHER_HYDRA_TIMEOUT", "DISPATCHER_ADMIN_UI_ENABLED", "DISPATCHER_HYDRA_MAX_IN_FLIGHT", "DISPATCHER_OBSERVABILITY_ACCESS_LOG_SAMPLE"} {
		if _, _, err := load(t, "", map[string]string{name: ""}); err == nil || !strings.Contains(err.Error(), name+" (") || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("%s empty: err = %v", name, err)
		}
	}
}

// A DISPATCHER_<SECTION>_* variable that names no key is a typo: warned
// about, unless the file references it. Other DISPATCHER_* names are free for
// ${VAR} references.
func TestUnknownOverrides(t *testing.T) {
	_, warnings, err := load(t, "store:\n  dsn: \"postgres://u:${DISPATCHER_STORE_PASSWORD}@db/d\"\n", map[string]string{
		"DISPATCHER_SERVER_BASEURL":      "http://typo",
		"DISPATCHER_UI_CSP_EXTRA":        "font-src",
		"DISPATCHER_DISPATCHER_REMEMBER": "true",
		"DISPATCHER_COOKIE_KEY":          hexKey,
		"DISPATCHER_UPSTREAM":            "dispatcher:80",
		"DISPATCHER_STORE_PASSWORD":      "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DISPATCHER_SERVER_BASEURL", "DISPATCHER_UI_CSP_EXTRA", "DISPATCHER_DISPATCHER_REMEMBER"} {
		if !hasWarning(warnings, name+" is ignored") {
			t.Errorf("no warning for %s in %q", name, warnings)
		}
	}
	for _, name := range []string{"DISPATCHER_COOKIE_KEY", "DISPATCHER_UPSTREAM", "DISPATCHER_SERVER_BASE_URL", "DISPATCHER_STORE_PASSWORD"} {
		if hasWarning(warnings, name) {
			t.Errorf("warning for %s in %q", name, warnings)
		}
	}

	// The warning comes with the error it explains, whichever step fails.
	env := required(map[string]string{"DISPATCHER_SERVER_BASEURL": "http://typo"})
	delete(env, "DISPATCHER_SERVER_BASE_URL")
	for _, extra := range []map[string]string{nil, {"DISPATCHER_HYDRA_TIMEOUT": "soon"}} {
		maps.Copy(env, extra)
		if _, warnings, err := Load("", envOf(env)); err == nil || !hasWarning(warnings, "DISPATCHER_SERVER_BASEURL is ignored") {
			t.Errorf("%v: warnings = %q, err = %v", extra, warnings, err)
		}
	}
}

// The variable names are a contract with the deployments: renaming a YAML
// key renames its variable, which this list catches.
func TestEnvKeys(t *testing.T) {
	var names []string
	seen := map[string]string{}
	for _, k := range envKeys(defaults()) {
		if other, dup := seen[k.name]; dup {
			t.Errorf("%s reaches both %s and %s", k.name, other, k.path)
		}
		seen[k.name] = k.path
		names = append(names, k.name)
	}
	want := []string{
		"DISPATCHER_SERVER_LISTEN",
		"DISPATCHER_SERVER_BASE_URL",
		"DISPATCHER_SERVER_TRUSTED_PROXIES",
		"DISPATCHER_SERVER_COOKIE_PATH",
		"DISPATCHER_SERVER_REPLICAS_HINT",
		"DISPATCHER_SERVER_DRAIN_DELAY",
		"DISPATCHER_HYDRA_ADMIN_URL",
		"DISPATCHER_HYDRA_TIMEOUT",
		"DISPATCHER_HYDRA_VERSION",
		"DISPATCHER_HYDRA_SYSTEM_SECRETS",
		"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE",
		"DISPATCHER_HYDRA_LOGIN_CONSENT_TTL",
		"DISPATCHER_HYDRA_MAX_IN_FLIGHT",
		"DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS",
		"DISPATCHER_SECURITY_METRICS_AUTHORIZED_HOSTS",
		"DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_MAX",
		"DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_PER",
		"DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_BLOCK",
		"DISPATCHER_SECRETS_COOKIE_KEY",
		"DISPATCHER_SECRETS_COOKIE_KEY_FILE",
		"DISPATCHER_SECRETS_COOKIE_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_COOKIE_KEYS_PREVIOUS_FILE",
		"DISPATCHER_SECRETS_ENCRYPTION_KEY",
		"DISPATCHER_SECRETS_ENCRYPTION_KEY_FILE",
		"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS_FILE",
		"DISPATCHER_SECRETS_CHALLENGE_KEY",
		"DISPATCHER_SECRETS_CHALLENGE_KEY_FILE",
		"DISPATCHER_SECRETS_CHALLENGE_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_CHALLENGE_KEYS_PREVIOUS_FILE",
		"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY",
		"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY_FILE",
		"DISPATCHER_SECRETS_AUDIT_KEY",
		"DISPATCHER_SECRETS_AUDIT_KEY_FILE",
		"DISPATCHER_TLS_MIN_VERSION",
		"DISPATCHER_TLS_CA_FILE",
		"DISPATCHER_TLS_ALLOW_HTTP",
		"DISPATCHER_TLS_PINNED_SPKI_SHA256",
		"DISPATCHER_TLS_HSTS_INCLUDE_SUBDOMAINS",
		"DISPATCHER_STATE_REDIS_DSN",
		"DISPATCHER_STATE_REDIS_DSN_FILE",
		"DISPATCHER_STATE_KEY_PREFIX",
		"DISPATCHER_STATE_REDIS_POOL_SIZE",
		"DISPATCHER_REMEMBER_BACKEND",
		"DISPATCHER_STORE_BACKEND",
		"DISPATCHER_STORE_DSN",
		"DISPATCHER_STORE_DSN_FILE",
		"DISPATCHER_ADMIN_UI_ENABLED",
		"DISPATCHER_ADMIN_API_ENABLED",
		"DISPATCHER_ADMIN_API_PRIVATE_KEY",
		"DISPATCHER_ADMIN_API_PRIVATE_KEY_FILE",
		"DISPATCHER_ADMIN_API_PUBLIC_KEY",
		"DISPATCHER_ADMIN_API_PUBLIC_KEYS_PREVIOUS",
		"DISPATCHER_ADMIN_API_TOKEN_TTL",
		"DISPATCHER_ADMIN_API_RATE_LIMIT_PER_MINUTE",
		"DISPATCHER_ADMIN_SESSION_IDLE_TIMEOUT",
		"DISPATCHER_ADMIN_SESSION_MAX_AGE",
		"DISPATCHER_ADMIN_SESSION_REAUTH_WINDOW",
		"DISPATCHER_ADMIN_HYDRA_CLIENTS_ENABLED",
		"DISPATCHER_ADMIN_CLIENT_SECRET_MAX_AGE",
		"DISPATCHER_UI_THEME_DIR",
		"DISPATCHER_UI_RELOAD",
		"DISPATCHER_UI_REMEMBER_LAST_FLOW",
		"DISPATCHER_EMULATED_API_LEGACY_V1_PATHS",
		"DISPATCHER_CONSENT_CLAIMS_FILTER",
		"DISPATCHER_CONSENT_SHOW_VALUES",
		"DISPATCHER_OBSERVABILITY_LOG_LEVEL",
		"DISPATCHER_OBSERVABILITY_LOG_FORMAT",
		"DISPATCHER_OBSERVABILITY_ACCESS_LOG_SAMPLE",
		"DISPATCHER_OBSERVABILITY_LOG_IP",
		"DISPATCHER_OBSERVABILITY_DEBUG_MAX_DURATION",
		"DISPATCHER_OBSERVABILITY_SENTRY_DSN",
		"DISPATCHER_OBSERVABILITY_SENTRY_ENVIRONMENT",
		"DISPATCHER_OBSERVABILITY_SENTRY_RELEASE",
		"DISPATCHER_OBSERVABILITY_SENTRY_SAMPLE_RATE",
		"DISPATCHER_OBSERVABILITY_SENTRY_TRACES_SAMPLE_RATE",
		"DISPATCHER_OBSERVABILITY_SENTRY_MAX_EVENTS_PER_MINUTE",
		"DISPATCHER_OBSERVABILITY_METRICS_LISTEN",
		"DISPATCHER_OBSERVABILITY_METRICS_MAX_LABEL_VALUES",
		"DISPATCHER_OBSERVABILITY_AUDIT_OUTPUT",
		"DISPATCHER_OBSERVABILITY_AUDIT_PSEUDONYMIZE_SUBJECT",
		"DISPATCHER_OBSERVABILITY_TRACING_ENABLED",
		"DISPATCHER_OBSERVABILITY_TRACING_ENDPOINT",
		"DISPATCHER_OBSERVABILITY_TRACING_PROTOCOL",
		"DISPATCHER_OBSERVABILITY_TRACING_SAMPLER_RATIO",
		"DISPATCHER_WEBHOOKS_PROCESS_TIMEOUT",
		"DISPATCHER_WEBHOOKS_MAX_PROCESSES",
		"DISPATCHER_WEBHOOKS_CA_FILE",
		"DISPATCHER_LOGOUT_PROPAGATE_WITHOUT_RECORD",
		"DISPATCHER_SERVE_MIGRATE",
		"DISPATCHER_SERVE_BOOTSTRAP",
	}
	if !slices.Equal(names, want) {
		t.Errorf("variables changed:\n got %q\nwant %q", names, want)
	}
}

// An expanded value is typed by what it became, quoted or not.
func TestExpansion(t *testing.T) {
	path := writeFile(t, `
server:
  listen: "${LISTEN:-:8080}"
  base_url: "${BASE}/"
hydra:
  timeout: "${TIMEOUT:-5s}"
  version: ${HYDRA_VERSION:-2.3}
  system_secrets: "${SECRETS}"
admin:
  ui: { enabled: "${ADMIN_UI:-false}" }
  api:
    token_ttl: ${TTL:-900}
    private_key: "${PEM}"
    public_key: ${PEM}
observability:
  sentry: { environment: "${SENTRY_ENV:-123}", release: "$${NOT_EXPANDED}" }
dispatcher:
  apps:
    - id: a
      login_url: http://a/login
      consent_url: http://a/consent
      method: pwd
  oauth2_clients:
    - id: admin
      secret: "${ADMIN_CLIENT_SECRET}"
    - id: tilde
      secret: "${TILDE}"
`)
	c, _, err := Load(path, envOf(required(map[string]string{
		"BASE":                "http://dispatcher.example",
		"SECRETS":             "youReallyNeedToChangeThis,second",
		"TTL":                 "",
		"ADMIN_CLIENT_SECRET": "s3cr3t: with colon",
		"TILDE":               "~",
		"PEM":                 pem,
	})))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"server.listen", c.Server.Listen, ":8080"},
		// DISPATCHER_SERVER_BASE_URL from required() wins over the file.
		{"server.base_url", c.Server.BaseURL, "http://dispatcher.hydra.test"},
		{"hydra.timeout", c.Hydra.Timeout.Std(), 5 * time.Second},
		{"hydra.system_secrets", c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "second"}},
		// A float to YAML, a version to the dispatcher.
		{"hydra.version", c.Hydra.Version, "2.3"},
		{"admin.ui.enabled", c.Admin.UI.Enabled, false},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL.Std(), 900 * time.Second},
		{"admin.api.private_key", c.Admin.API.PrivateKey, pem},
		{"admin.api.public_key", c.Admin.API.PublicKey, pem},
		{"observability.sentry.environment", c.Observability.Sentry.Environment, "123"},
		{"observability.sentry.release", c.Observability.Sentry.Release, "${NOT_EXPANDED}"},
		{"dispatcher.oauth2_clients[0].secret", c.Seed.OAuth2Clients[0].Secret, "s3cr3t: with colon"},
		{"dispatcher.oauth2_clients[1].secret", c.Seed.OAuth2Clients[1].Secret, "~"},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

// An explicit tag survives the expansion: a boolean key refuses a string, even
// one that reads as a boolean.
func TestExplicitTag(t *testing.T) {
	for value, refused := range map[string]bool{"${FLAG}": false, `"${FLAG}"`: false, "!!str ${FLAG}": true, `!!str "${FLAG}"`: true} {
		c, _, err := load(t, "ui:\n  reload: "+value+"\n", map[string]string{"FLAG": "true"})
		switch {
		case refused && (err == nil || !strings.Contains(err.Error(), "cannot unmarshal !!str")):
			t.Errorf("%s: err = %v, want a type error", value, err)
		case !refused && (err != nil || !c.UI.Reload):
			t.Errorf("%s: err = %v", value, err)
		}
	}
}

// An empty variable gives an empty value, never the default of the key: an
// allowlist without address, as with DISPATCHER_* variables. In a sequence,
// it gives no item.
func TestEmptyExpansion(t *testing.T) {
	env := required(map[string]string{"METRICS": ""})
	// The file sets them.
	delete(env, "DISPATCHER_SERVER_TRUSTED_PROXIES")
	delete(env, "DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS")
	c, _, err := Load(writeFile(t, `
server:
  trusted_proxies: ${UNSET}
  cookie_path: "${COOKIE_PATH:-/}"
security:
  admin_authorized_hosts: ["10.9.0.0/16", "${UNSET}"]
  metrics_authorized_hosts: "${METRICS}"
  emulated_api_authorized_hosts: ["${UNSET}"]
`), envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(*c.Server.TrustedProxies) != 0 || len(*c.Security.MetricsAuthorizedHosts) != 0 || len(*c.Security.EmulatedAPIAuthorizedHosts) != 0 ||
		!slices.Equal(c.Security.AdminAuthorizedHosts, List{"10.9.0.0/16"}) || c.Server.CookiePath != "/" {
		t.Errorf("trusted = %v, metrics = %v, emulated = %v, admin = %v, cookie_path = %q", *c.Server.TrustedProxies,
			*c.Security.MetricsAuthorizedHosts, *c.Security.EmulatedAPIAuthorizedHosts, c.Security.AdminAuthorizedHosts, c.Server.CookiePath)
	}
	for _, content := range []string{
		"hydra:\n  timeout: \"${UNSET}\"\n",
		"admin:\n  ui: { enabled: \"${UNSET}\" }\n",
		"hydra:\n  max_in_flight: ${UNSET}\n",
	} {
		if _, _, err := load(t, content, nil); err == nil {
			t.Errorf("%q: want an error for an empty value", content)
		}
	}
	if _, _, err := load(t, "server:\n  cookie_path: \"${UNSET}\"\n", nil); err == nil || !strings.Contains(err.Error(), "server.cookie_path") {
		t.Errorf("empty cookie path: err = %v", err)
	}
}

// A boolean or a number key decides a quoted value, as it decides an
// expanded one. A float is no integer, rather than one truncated.
func TestTypedValues(t *testing.T) {
	c, _, err := load(t, `
hydra:
  max_in_flight: "512"
admin:
  ui: { enabled: "false" }
observability:
  access_log_sample: '0.5'
dispatcher:
  remember: "false"
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hydra.MaxInFlight != 512 || c.Admin.UI.Enabled || c.Observability.AccessLogSample != 0.5 || *c.Seed.Remember {
		t.Errorf("max_in_flight = %d, admin.ui.enabled = %v, access_log_sample = %v, remember = %v",
			c.Hydra.MaxInFlight, c.Admin.UI.Enabled, c.Observability.AccessLogSample, *c.Seed.Remember)
	}
	for content, want := range map[string]string{
		"server:\n  replicas_hint: 1.9\n":                     "line 2: server.replicas_hint: 1.9 is not an integer",
		"security:\n  failure_rate_limit: { max: \"2.5\" }\n": "line 2: security.failure_rate_limit.max: 2.5 is not an integer",
		"hydra:\n  max_in_flight: \"${N:-1.5}\"\n":            "line 2: hydra.max_in_flight: 1.5 is not an integer",
		"hydra:\n  max_in_flight: \"\"\n":                     "line 2: cannot unmarshal",
		"admin:\n  ui: { enabled: \"~\" }\n":                  "line 2: cannot unmarshal",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
}

func TestExpand(t *testing.T) {
	env := lookupIn([]string{"SET=value", "EMPTY=", "SET=shadowed"})
	for in, want := range map[string]string{
		"${SET}":             "value",
		"${UNSET}":           "",
		"${UNSET:-default}":  "default",
		"${EMPTY:-default}":  "default",
		"${SET:-default}":    "value",
		"a-${SET}-${UNSET}b": "a-value-b",
		"plain":              "plain",
		"${UNSET:-}":         "",
		"${UNSET:-x:y}":      "x:y",
		"$${SET}":            "${SET}",
		"a$${SET}${SET}":     "a${SET}value",
		"pa$$word $SET":      "pa$$word $SET",
	} {
		if got, err := expand(in, env); err != nil || got != want {
			t.Errorf("expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"${1INVALID}", "${SET-default}", "${SET:?missing}", "${UNSET:-${SET}}", "${SET", "${}"} {
		if got, err := expand(in, env); err == nil {
			t.Errorf("expand(%q) = %q, want an error", in, got)
		}
	}
}

func TestUnknownKeys(t *testing.T) {
	for content, want := range map[string]string{
		"server:\n  lisen: \":8080\"\n":                     "line 2: server.lisen: unknown key",
		"dispatcher:\n  apps: []\n  app_autoselect: true\n": "line 3: dispatcher.app_autoselect: unknown key",
		"nope: 1\n": "line 1: nope: unknown key",
		"dispatcher:\n  apps:\n    - { id: a, nope: 1 }\n":                                     "line 3: dispatcher.apps[0].nope: unknown key",
		"dispatcher:\n  flows:\n    - id: f\n      steps:\n        - { ap_id: a, order: 0 }\n": "line 5: unknown step key \"ap_id\"",
		// A merged mapping is checked like the step it merges into.
		"dispatcher:\n  flows:\n    - id: f\n      steps:\n        - { <<: [{ order: 0 }, { ap_id: b }], id: a }\n": "line 5: unknown step key \"ap_id\"",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
	// Every unknown key at once.
	if _, _, err := load(t, "a: 1\nb: 2\n", nil); err == nil || !strings.Contains(err.Error(), "line 1: a") || !strings.Contains(err.Error(), "line 2: b") {
		t.Errorf("two unknown keys: err = %v", err)
	}
}

// Errors give the lines of the file, blank lines and comments included.
func TestErrorLines(t *testing.T) {
	for content, want := range map[string]string{
		"server:\n\n\n  listen: \":8080\"\n\n# comment\n\nadmin:\n\n  lisen: 1\n":     "line 10: admin.lisen",
		"\n\n# comment\n\nhydra:\n\n  timeout: soon\n":                                "line 7: invalid duration",
		"\n\nhydra:\n\n\n  max_in_flight: many\n":                                     "line 6: cannot unmarshal",
		"\n\nsecrets:\n\n  cookie_key: tooshort\n":                                    "line 5: key must be 32 bytes",
		"\n\nobservability:\n\n  sentry: { dsn: \"${A-b}\" }\n":                       "line 5: observability.sentry.dsn: unsupported",
		"dispatcher:\n  flows:\n\n    - id: f\n      steps:\n\n        - { id: a }\n": "line 7: step without order",
		"server:\n  listen: ':1'\n---\n\nnope: 1\n":                                   "line 5: a second YAML document",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
}

func TestAnchorsAndMerge(t *testing.T) {
	c, _, err := load(t, `
security:
  admin_authorized_hosts: &hosts ["10.7.0.0/16", "${EXTRA}"]
  metrics_authorized_hosts: *hosts
dispatcher:
  apps:
    - &app
      id: a
      login_url: "${BASE:-http://a}/login"
      consent_url: http://a/consent
      method: pwd
    - <<: *app
      id: b
`, map[string]string{"EXTRA": "10.8.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (List{"10.7.0.0/16", "10.8.0.0/16"}); !slices.Equal(c.Security.AdminAuthorizedHosts, want) || !slices.Equal(*c.Security.MetricsAuthorizedHosts, want) {
		t.Errorf("admin = %v, metrics = %v", c.Security.AdminAuthorizedHosts, *c.Security.MetricsAuthorizedHosts)
	}
	if apps := c.Seed.Apps; len(apps) != 2 || apps[1].ID != "b" || apps[1].LoginURL != "http://a/login" {
		t.Errorf("apps = %+v", apps)
	}
	// A merged mapping is checked like the one it merges into.
	if _, _, err := load(t, "x: &x { nope: 1 }\n", nil); err == nil {
		t.Error("unknown top-level key holding an anchor: want an error")
	}
	// An anchor that contains itself is an error, not an endless walk.
	for content, want := range map[string]string{
		"server:\n  trusted_proxies: &a [*a]\n":             "line 2: server.trusted_proxies[0]: anchor \"a\" contains itself",
		"server:\n  trusted_proxies: [&a [*a]]\n":           "line 2: server.trusted_proxies[0][0]: anchor \"a\" contains itself",
		"dispatcher:\n  flows: &f [{ id: f, steps: *f }]\n": "line 2: dispatcher.flows[0].steps: anchor \"f\" contains itself",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
	// Ten levels of ten aliases: 10^10 values unfolded, walked once each. A
	// list takes no nested list: the decoder refuses it, without unfolding.
	var bomb strings.Builder
	bomb.WriteString("dispatcher:\n  apps:\n    - id: a\n      allowed_sources:\n        - &l0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&bomb, "        - &l%d [%s]\n", i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*l%d, ", i-1), 10), ", "))
	}
	refused := make(chan error, 1)
	go func() {
		_, _, err := load(t, bomb.String(), nil)
		refused <- err
	}()
	select {
	case err := <-refused:
		if err == nil || !strings.Contains(err.Error(), "cannot unmarshal") {
			t.Errorf("alias bomb: err = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("alias bomb: still walking its aliases")
	}
	// An anchor is walked once per type: a quoted number stays a string for
	// the first alias and is a number for the second.
	typed, _, err := load(t, "observability:\n  sentry:\n    environment: &n \"512\"\n    release: *n\nhydra:\n  max_in_flight: *n\n", nil)
	if err != nil || typed.Hydra.MaxInFlight != 512 || typed.Observability.Sentry.Release != "512" {
		t.Errorf("an anchor of two types: err = %v", err)
	}
	// options take any key, an app does not.
	if _, _, err := load(t, `
dispatcher:
  apps:
    - { id: a, login_url: "http://a", consent_url: "http://a", method: m, options: &extra { nope: 1 } }
    - { <<: *extra, id: b, login_url: "http://b", consent_url: "http://b", method: m }
`, nil); err == nil || !strings.Contains(err.Error(), "dispatcher.apps[1].nope: unknown key") {
		t.Errorf("unknown key through a merge: err = %v", err)
	}
}

func TestMalformed(t *testing.T) {
	if _, _, err := Load("testdata/missing.yaml", nil); err == nil {
		t.Error("missing file: want an error")
	}
	for content, want := range map[string]string{
		"server:\n  listen: [\n":                              "line 2: did not find",
		"hydra:\n  system_secrets: [[a]]\n":                   "line 2",
		"secrets:\n  encryption_keys_previous: { a: b }\n":    "line 2: expected a list",
		"dispatcher:\n  flows:\n    - { title: [a] }\n":       "line 3",
		"dispatcher:\n  flows:\n    - steps: [{ id: [a] }]\n": "line 3",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
	// Aliases of a list, and a list of merged mappings.
	c, _, err := load(t, `
dispatcher:
  apps:
    - { id: a, login_url: &login "http://a", consent_url: "http://a", method: m, receive_claims: &claims ["${CLAIM}"] }
    - { id: b, login_url: *login, consent_url: "http://b", method: m, receive_claims: *claims }
    - <<: [{ login_url: "http://c" }, { consent_url: "http://c" }]
      id: c
      method: m
`, map[string]string{"CLAIM": "email"})
	if err != nil {
		t.Fatal(err)
	}
	if apps := c.Seed.Apps; !reflect.DeepEqual(apps[1].ReceiveClaims, &List{"email"}) || apps[1].LoginURL != "http://a" ||
		apps[2].LoginURL != "http://c" || apps[2].ConsentURL != "http://c" {
		t.Errorf("apps = %+v", apps)
	}
}

func TestDocuments(t *testing.T) {
	for _, content := range []string{"", "# nothing but a comment\n", "---\n", "---\nserver: { listen: \":1\" }\n",
		// An empty second document holds nothing to lose.
		"server: { listen: \":1\" }\n---\n", "server: { listen: \":1\" }\n---\n# end\n---\n~\n"} {
		if _, _, err := load(t, content, nil); err != nil {
			t.Errorf("%q: %v", content, err)
		}
	}
	if _, _, err := load(t, "- a\n", nil); err == nil {
		t.Error("top-level sequence: want an error")
	}
}

func TestValidation(t *testing.T) {
	_, _, err := Load("", nil)
	for _, path := range []string{"server.base_url", "server.trusted_proxies", "security.emulated_api_authorized_hosts", "hydra.admin_url", "store.dsn", "secrets.cookie_key", "secrets.challenge_key"} {
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("empty configuration: err = %v, want it to name %s", err, path)
		}
	}

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"relative base URL", map[string]string{"DISPATCHER_SERVER_BASE_URL": "/dispatcher"}, "server.base_url"},
		{"base URL with query", map[string]string{"DISPATCHER_SERVER_BASE_URL": "http://d.example/?"}, "server.base_url"},
		// The browsers' Origin and Referer are compared with base_url as
		// written: it must be written as they serialize it.
		{"base URL with a user", map[string]string{"DISPATCHER_SERVER_BASE_URL": "https://user:secret@d.example"}, "server.base_url: holds a user"},
		{"base URL scheme in uppercase", map[string]string{"DISPATCHER_SERVER_BASE_URL": "HTTPS://d.example"}, "server.base_url: \"https://d.example\": write its scheme in lowercase"},
		{"base URL host in uppercase", map[string]string{"DISPATCHER_SERVER_BASE_URL": "https://D.example"}, "write its host in lowercase"},
		{"base URL default port", map[string]string{"DISPATCHER_SERVER_BASE_URL": "https://d.example:443/"}, "leave out the default port of https"},
		{"base URL empty port", map[string]string{"DISPATCHER_SERVER_BASE_URL": "http://d.example:/"}, "leave out the default port of http"},
		{"base URL path not clean", map[string]string{"DISPATCHER_SERVER_BASE_URL": "https://d.example/a//b/"}, `its path is not clean ("/a/b")`},
		{"cookie path beside the pages", map[string]string{"DISPATCHER_SERVER_BASE_URL": "https://d.example/auth", "DISPATCHER_SERVER_COOKIE_PATH": "/au"}, `server.cookie_path: "/au" does not cover "/auth/"`},
		{"cookie path below the pages", map[string]string{"DISPATCHER_SERVER_COOKIE_PATH": "/auth"}, `server.cookie_path: "/auth" does not cover "/"`},
		{"cookie path", map[string]string{"DISPATCHER_SERVER_COOKIE_PATH": "auth"}, "server.cookie_path"},
		{"bad CIDR", map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "REMOTE_ADDR"}, "server.trusted_proxies"},
		{"replicas without Redis", map[string]string{"DISPATCHER_SERVER_REPLICAS_HINT": "3"}, "state.redis_dsn"},
		{"Redis DSN scheme", map[string]string{"DISPATCHER_STATE_REDIS_DSN": "http://redis:6379"}, "state.redis_dsn"},
		{"short Hydra secret", map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS": "short"}, "hydra.system_secrets"},
		{"Hydra version", map[string]string{"DISPATCHER_HYDRA_VERSION": "2.4"}, "hydra.version"},
		// ENT-22: at or under the 60 s the flows keep before the end of L at
		// Hydra, every flow would be born expired.
		{"login consent TTL within the margin", map[string]string{"DISPATCHER_HYDRA_LOGIN_CONSENT_TTL": "60s"}, "hydra.login_consent_ttl: must be above 1m0s"},
		{"serve bootstrap", map[string]string{"DISPATCHER_SERVE_BOOTSTRAP": "true"}, `serve.bootstrap: "true" is not one of off, missing, force`},
		{"log level", map[string]string{"DISPATCHER_OBSERVABILITY_LOG_LEVEL": "verbose"}, "observability.log_level"},
		{"sample rate", map[string]string{"DISPATCHER_OBSERVABILITY_SENTRY_SAMPLE_RATE": "1.5"}, "observability.sentry.sample_rate"},
		{"audit output", map[string]string{"DISPATCHER_OBSERVABILITY_AUDIT_OUTPUT": "stderr"}, "observability.audit.output"},
		{"remember backend", map[string]string{"DISPATCHER_REMEMBER_BACKEND": "redis"}, "remember.backend"},
		// Q40: the server memory has no lot yet.
		{"remember backend postgres", map[string]string{"DISPATCHER_REMEMBER_BACKEND": "postgres"}, "remember.backend: postgres is not available yet"},
		{"logout propagation", map[string]string{"DISPATCHER_LOGOUT_PROPAGATE_WITHOUT_RECORD": "some"}, "logout.propagate_without_record"},
		{"missing CA file", map[string]string{"DISPATCHER_TLS_CA_FILE": "/nonexistent/ca.pem"}, "tls.ca_file"},
		{"missing webhooks CA file", map[string]string{"DISPATCHER_WEBHOOKS_CA_FILE": "/nonexistent/ca.pem"}, "webhooks.ca_file"},
		{"overflowing duration", map[string]string{"DISPATCHER_ADMIN_CLIENT_SECRET_MAX_AGE": "10000000000"}, "too long"},
		{"NaN ratio", map[string]string{"DISPATCHER_OBSERVABILITY_TRACING_SAMPLER_RATIO": ".nan"}, "observability.tracing.sampler_ratio"},
		{"no block", map[string]string{"DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_BLOCK": "0"}, "security.failure_rate_limit.block"},
		{"negative replicas", map[string]string{"DISPATCHER_SERVER_REPLICAS_HINT": "-1"}, "server.replicas_hint"},
		{"negative pool", map[string]string{"DISPATCHER_STATE_REDIS_POOL_SIZE": "-1"}, "state.redis_pool_size"},
		{"audit file without path", map[string]string{"DISPATCHER_OBSERVABILITY_AUDIT_OUTPUT": "file:"}, "observability.audit.output"},
		{"pinning", map[string]string{"DISPATCHER_TLS_PINNED_SPKI_SHA256": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}, "tls.pinned_spki_sha256: is not supported yet"},
		{"shared key", map[string]string{"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY": hexKey}, "secrets.webhook_signing_key: shares a key with secrets.cookie_key"},
		{"shared previous key", map[string]string{"DISPATCHER_SECRETS_CHALLENGE_KEYS_PREVIOUS": hexKey}, "secrets.challenge_key: shares a key with secrets.cookie_key"},
		{"previous key only", map[string]string{"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS": hexKey2}, "secrets.encryption_key: is required with secrets.encryption_keys_previous"},
		{"claims filter", map[string]string{"DISPATCHER_CONSENT_CLAIMS_FILTER": "loose"}, "consent.claims_filter"},
		{"strict claims before the catalogue", map[string]string{"DISPATCHER_CONSENT_CLAIMS_FILTER": "strict"}, "consent.claims_filter: strict needs the scope catalogue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Load("", envOf(required(tt.env))); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %s", err, tt.want)
			}
		})
	}

	// A port other than the default one, a path the cookies cover.
	for _, env := range []map[string]string{
		{"DISPATCHER_SERVER_BASE_URL": "https://d.example:8443"},
		{"DISPATCHER_SERVER_BASE_URL": "http://[::1]:8080/"},
		{"DISPATCHER_SERVER_BASE_URL": "https://d.example/auth/", "DISPATCHER_SERVER_COOKIE_PATH": "/auth"},
		{"DISPATCHER_SERVER_BASE_URL": "https://d.example/auth", "DISPATCHER_SERVER_COOKIE_PATH": "/auth/"},
		{"DISPATCHER_SERVER_BASE_URL": "https://d.example/a/auth", "DISPATCHER_SERVER_COOKIE_PATH": "/a"},
	} {
		if _, _, err := Load("", envOf(required(env))); err != nil {
			t.Errorf("%v: %v", env, err)
		}
	}
	// ENT-22: the TTL just above the margin is accepted; at it, the file's key
	// is refused as the variable is.
	if c, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_HYDRA_LOGIN_CONSENT_TTL": "61s"}))); err != nil || c.Hydra.LoginConsentTTL != Duration(HydraMargin+time.Second) {
		t.Errorf("login consent TTL above the margin: %v", err)
	}
	if _, _, err := load(t, "hydra: { login_consent_ttl: 1m }\n", nil); err == nil || !strings.Contains(err.Error(), "hydra.login_consent_ttl: must be above 1m0s") {
		t.Errorf("login consent TTL of the file at the margin: err = %v", err)
	}
	// A key may stay in its own keyring, as during a rotation.
	if _, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_SECRETS_COOKIE_KEYS_PREVIOUS": hexKey}))); err != nil {
		t.Errorf("active key also previous: %v", err)
	}
	// The lists copying the admin one do not repeat its errors.
	_, _, err = Load("", envOf(required(map[string]string{"DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS": "nowhere"})))
	if err == nil || strings.Count(err.Error(), "nowhere") != 1 {
		t.Errorf("invalid admin list: err = %v, want one error", err)
	}
}

// server.trusted_proxies has no default: the private networks let any host,
// or any address translation into them, choose its address.
func TestTrustedProxiesRequired(t *testing.T) {
	env := required(nil)
	delete(env, "DISPATCHER_SERVER_TRUSTED_PROXIES")
	if _, _, err := Load("", envOf(env)); err == nil || !strings.Contains(err.Error(), "server.trusted_proxies: is required") {
		t.Errorf("unset: err = %v", err)
	}
	// [] says the clients connect directly, by the file or a variable.
	for _, tt := range []struct {
		file string
		env  map[string]string
	}{
		{"server:\n  trusted_proxies: []\n", nil},
		{"", map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": ""}},
	} {
		env := required(nil)
		delete(env, "DISPATCHER_SERVER_TRUSTED_PROXIES")
		maps.Copy(env, tt.env)
		c, _, err := Load(writeFile(t, tt.file), envOf(env))
		if err != nil || c.Server.TrustedProxies == nil || len(*c.Server.TrustedProxies) != 0 {
			t.Errorf("%q %v: err = %v", tt.file, tt.env, err)
		}
	}
}

// security.emulated_api_authorized_hosts has no default (B2): the admin
// networks it copied were too wide for the step accepts and the claims.
func TestEmulatedAPIHostsRequired(t *testing.T) {
	env := required(map[string]string{"DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS": "10.9.0.0/16"})
	delete(env, "DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS")
	if _, _, err := Load("", envOf(env)); err == nil || !strings.Contains(err.Error(), "security.emulated_api_authorized_hosts: is required") {
		t.Errorf("unset: err = %v", err)
	}
	c, warnings, err := Load(writeFile(t, "security:\n  emulated_api_authorized_hosts: [10.5.0.0/24]\n"), envOf(env))
	if err != nil || !slices.Equal(*c.Security.EmulatedAPIAuthorizedHosts, List{"10.5.0.0/24"}) || hasWarning(warnings, "emulated_api_authorized_hosts is empty") {
		t.Errorf("set by the file: err = %v, warnings %q", err, warnings)
	}
	// Empty, written [] or by a variable left empty: it passes, the API
	// closed, and says so.
	for _, file := range []string{"security:\n  emulated_api_authorized_hosts: []\n", "security:\n  emulated_api_authorized_hosts: ${UNSET}\n"} {
		_, warnings, err := Load(writeFile(t, file), envOf(env))
		if err != nil || !hasWarning(warnings, "security.emulated_api_authorized_hosts is empty: the emulated API refuses every call") {
			t.Errorf("%q: err = %v, warnings %q", file, err, warnings)
		}
	}
}

func TestWarnings(t *testing.T) {
	_, warnings, err := Load("", envOf(required(map[string]string{"DISPATCHER_SECURITY_METRICS_AUTHORIZED_HOSTS": "0.0.0.0/0,::/0"})))
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(warnings, "metrics_authorized_hosts covers 0.0.0.0/0") || !hasWarning(warnings, "metrics_authorized_hosts covers ::/0") {
		t.Errorf("warnings = %q, want one per open network", warnings)
	}

	_, warnings, err = Load("", envOf(required(map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "0.0.0.0/0"})))
	if err != nil || !hasWarning(warnings, "server.trusted_proxies covers 0.0.0.0/0: X-Forwarded-For is trusted from every address") {
		t.Errorf("trusted proxies 0.0.0.0/0: warnings = %q, err = %v", warnings, err)
	}

	// Every address, however written; not most of them.
	for hosts, want := range map[string][]string{
		"0.0.0.0/1,128.0.0.0/1":                  {"0.0.0.0/0"},
		"::ffff:0:0/96":                          {"0.0.0.0/0"},
		"8000::/1,::/2,4000::/2,0.0.0.0/0":       {"0.0.0.0/0", "::/0"},
		"0.0.0.0/1,128.0.0.0/2,192.0.0.0/3,::/1": nil,
		"10.0.0.0/8,10.1.0.0/16,1.2.3.4":         nil,
	} {
		_, warnings, err := Load("", envOf(required(map[string]string{"DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS": hosts})))
		var got []string
		for _, w := range warnings {
			if rest, ok := strings.CutPrefix(w, "security.admin_authorized_hosts covers "); ok {
				all, _, _ := strings.Cut(rest, ": ")
				got = append(got, all)
			}
		}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: open = %q, want %q (err = %v)", hosts, got, want, err)
		}
	}

	// Without trusted proxies, clients behind a proxy have its address.
	_, warnings, _ = Load("", envOf(required(map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": ""})))
	if !hasWarning(warnings, "server.trusted_proxies is empty: behind a reverse proxy") {
		t.Errorf("no trusted proxies: warnings = %q", warnings)
	}
	_, warnings, _ = Load("", envOf(required(map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "", "DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS": "",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS": ""})))
	if hasWarning(warnings, "server.trusted_proxies is empty") {
		t.Errorf("no trusted proxies, no allowlist: warnings = %q", warnings)
	}

	// ui.reload is for the development of a theme, and needs one (Q93).
	_, warnings, _ = Load("", envOf(required(map[string]string{"DISPATCHER_UI_RELOAD": "true", "DISPATCHER_UI_THEME_DIR": "/theme"})))
	if !hasWarning(warnings, "ui.reload is for the development of a theme: the pages read it again when a file changed, and answer 500 with the error of its check while it fails") {
		t.Errorf("ui.reload: warnings = %q", warnings)
	}
	_, warnings, _ = Load("", envOf(required(map[string]string{"DISPATCHER_UI_RELOAD": "true"})))
	if !hasWarning(warnings, "ui.reload does nothing without ui.theme_dir") || hasWarning(warnings, "ui.reload is for the development") {
		t.Errorf("ui.reload without a theme: warnings = %q", warnings)
	}
	if _, warnings, _ := Load("", envOf(required(nil))); hasWarning(warnings, "ui.reload") {
		t.Errorf("without ui.reload: warnings = %q", warnings)
	}

	// The in-memory store is only for a single instance.
	if _, warnings, _ := Load("", envOf(required(nil))); !hasWarning(warnings, memoryWarning) {
		t.Errorf("no Redis: warnings = %q", warnings)
	}
	if _, warnings, _ := Load("", envOf(required(map[string]string{"DISPATCHER_STATE_REDIS_DSN": "redis://redis:6379"}))); hasWarning(warnings, memoryWarning) {
		t.Errorf("Redis: warnings = %q", warnings)
	}

	// Hydra 2.1 ignores the secrets, so their length does not matter.
	_, warnings, err = Load("", envOf(required(map[string]string{
		"DISPATCHER_HYDRA_VERSION":        "2.1",
		"DISPATCHER_HYDRA_SYSTEM_SECRETS": "short",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(warnings, "hydra.system_secrets is ignored") {
		t.Errorf("warnings = %q, want system secrets ignored with Hydra 2.1", warnings)
	}
}

// Errors end up in the logs: they never show a password, a secret or a key.
func TestNoSecretInErrors(t *testing.T) {
	for _, env := range []map[string]string{
		{"DISPATCHER_SERVER_BASE_URL": "https://user:hunter2@dispatcher.example/?q=1"},
		{"DISPATCHER_HYDRA_ADMIN_URL": "ftp://admin:hunter2@hydra:4445"},
		{"DISPATCHER_HYDRA_ADMIN_URL": "http://admin:hunter2@[::1"},
		{"DISPATCHER_HYDRA_ADMIN_URL": "http://hydra:4445/?token=hunter2#hunter2"},
		// Without an authority, url.Parse leaves the password in the path.
		{"DISPATCHER_HYDRA_ADMIN_URL": "https//admin:hunter2@hydra"},
		{"DISPATCHER_HYDRA_ADMIN_URL": "http:/admin:hunter2@hydra"},
		{"DISPATCHER_SECRETS_COOKIE_KEY": "hunter2"},
		{"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS": hexKey + ",hunter2"},
	} {
		_, _, err := Load("", envOf(required(env)))
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v: err = %v", env, err)
		}
	}
	for _, content := range []string{
		"dispatcher:\n  oauth2_clients:\n    - { id: a, secret: \"hun${ter2\" }\n",
		"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://u:hunter2@a\", consent_url: \"ftp://u:hunter2@a\", method: m }\n",
		"dispatcher:\n  apps:\n    - { id: a, login_url: \"ftp://a/?k=hunter2#hunter2\", consent_url: \"http://a\", method: m }\n",
		"dispatcher:\n  apps:\n    - { id: a, login_url: \"https//u:hunter2@a\", consent_url: \"http://a\", method: m }\n",
	} {
		_, _, err := load(t, content, nil)
		if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "hun${ter2") {
			t.Errorf("%q: err = %v", content, err)
		}
	}
}

func TestCSPExtra(t *testing.T) {
	if c, _, err := load(t, "ui:\n  csp_extra:\n    font-src: [\"https://fonts.gstatic.com\"]\n    script-src: [\"'self'\", \"https://cdn.example.org\"]\n", nil); err != nil || len(c.UI.CSPExtra) != 2 {
		t.Errorf("valid csp_extra: err = %v", err)
	}
	for content, want := range map[string]string{
		"ui:\n  csp_extra: { default-src: [\"*\"] }\n":                    "ui.csp_extra.default-src: is not one of",
		"ui:\n  csp_extra: { img-src: [\"https://a; script-src *\"] }\n":  "is not a single source",
		"ui:\n  csp_extra: { script-src: [\"'unsafe-inline'\"] }\n":       "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"*\"] }\n":                     "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"https:\"] }\n":                "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"blob:\"] }\n":                 "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"https://*.example.org\"] }\n": "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"'strict-dynamic'\"] }\n":      "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"'nonce-abc'\"] }\n":           "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { img-src: [\"https://a\\nb\"] }\n":            "is not a single source",
		// Browsers match keywords whatever their case.
		"ui:\n  csp_extra: { script-src: [\"'UNSAFE-INLINE'\"] }\n":  "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"'Strict-Dynamic'\"] }\n": "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"'NONCE-abc'\"] }\n":      "would allow inline or arbitrary scripts",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
}

func TestSeedValidation(t *testing.T) {
	const apps = `
dispatcher:
  apps:
    - { id: a, login_url: "http://a/login", consent_url: "http://a/consent", method: pwd }
    - { id: b, login_url: "http://b/login", consent_url: "http://b/consent", logout_url: "http://b/logout", method: otp }
`
	const flow = `  flows:
    - id: f
      title: F
      description: { fr: Flow F }
      steps:
`
	const app = `
dispatcher:
  apps:
    - id: a
      login_url: http://a/login
      consent_url: http://a/consent
      method: pwd
`
	// Network identification, the default, and mtls; acr goes to Hydra as is.
	c, _, err := load(t, `
dispatcher:
  apps:
    - { id: a, login_url: "http://a", consent_url: "http://a", method: m, allowed_sources: "10.1.0.0/16, 10.2.0.1" }
    - { id: b, login_url: "http://b", consent_url: "http://b", method: m, auth_mode: mtls, client_cert_fingerprint: "`+strings.ToUpper(colonFingerprint)+`" }
  flows:
    - id: f
      title: T
      description: D
      acr: "urn:example:loa:2"
      enabled: false
      icon_url: http://a/icon.svg
      steps: [{ id: a, order: 0 }, { id: b, order: 1 }]
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := c.Seed.Apps[0], c.Seed.Apps[1]; a.AuthMode != "network" || !slices.Equal(a.AllowedSources, List{"10.1.0.0/16", "10.2.0.1"}) ||
		b.AuthMode != "mtls" || b.ClientCertFingerprint != fingerprint {
		t.Errorf("apps = %+v", c.Seed.Apps)
	}
	if f := c.Seed.Flows[0]; f.ACR != "urn:example:loa:2" || *f.Enabled || f.IconURL[""] != "http://a/icon.svg" {
		t.Errorf("flow = %+v", f)
	}

	if c, _, err := load(t, apps+flow+"        - { id: a, order: 0 }\n        - { app_id: b, position: 1, subject_check: \"claim:email\" }\n", nil); err != nil ||
		c.Seed.Flows[0].Steps[1].SubjectCheck != "claim:email" || c.Seed.Flows[0].Title[""] != "F" {
		t.Errorf("valid seed: err = %v", err)
	}
	for name, tt := range map[string]struct{ content, want string }{
		"missing app id":           {"dispatcher:\n  apps:\n    - { login_url: \"http://a\", consent_url: \"http://a\", method: m }\n", "dispatcher.apps[0].id: is required"},
		"app id with a slash":      {"dispatcher:\n  apps:\n    - { id: a/b, login_url: \"http://a\", consent_url: \"http://a\", method: m }\n", "dispatcher.apps[0].id: \"a/b\" is not an id"},
		"flow id with a space":     {apps + "  flows:\n    - { id: \"f g\", title: T, description: D, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].id: \"f g\" is not an id"},
		"long client id":           {"dispatcher:\n  oauth2_clients:\n    - { id: " + strings.Repeat("c", 129) + ", secret: s }\n", "dispatcher.oauth2_clients[0].id"},
		"duplicate app":            {apps + "    - { id: a, login_url: \"http://a\", consent_url: \"http://a\", method: m }\n", "dispatcher.apps[2].id: \"a\" is declared twice"},
		"relative login URL":       {"dispatcher:\n  apps:\n    - { id: a, login_url: /login, consent_url: \"http://a\", method: m }\n", "dispatcher.apps[0].login_url"},
		"missing consent URL":      {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", method: m }\n", "dispatcher.apps[0].consent_url: is required"},
		"relative logout URL":      {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", consent_url: \"http://a\", logout_url: /out, method: m }\n", "dispatcher.apps[0].logout_url"},
		"missing method":           {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", consent_url: \"http://a\" }\n", "dispatcher.apps[0].method: is required"},
		"flow without steps":       {apps + flow + "        []\n", "dispatcher.flows[0].steps: is empty"},
		"undeclared app":           {apps + flow + "        - { id: c, order: 0 }\n", "app \"c\" is not declared"},
		"app twice":                {apps + flow + "        - { id: a, order: 0 }\n        - { id: a, order: 1 }\n", "app \"a\" is already a step"},
		"position twice":           {apps + flow + "        - { id: a, order: 0 }\n        - { id: b, order: 0 }\n", "position 0 is already taken"},
		"subject check":            {apps + flow + "        - { id: a, order: 0, subject_check: \"claim:\" }\n", "subject_check: \"claim:\" is not none, equal or claim:<name>"},
		"missing title":            {apps + "  flows:\n    - { id: f, description: D, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].title: is required"},
		"null description":         {apps + "  flows:\n    - { id: f, title: T, description: { fr: ~ }, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].description: is required"},
		"duplicate flow":           {apps + "  flows:\n    - { id: f, title: T, description: D, steps: [{ id: a, order: 0 }] }\n    - { id: f, title: T, description: D, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[1].id: \"f\" is declared twice"},
		"missing client secret":    {"dispatcher:\n  oauth2_clients:\n    - { id: c }\n", "dispatcher.oauth2_clients[0].secret: is required"},
		"duplicate client":         {"dispatcher:\n  oauth2_clients:\n    - { id: c, secret: s }\n    - { id: c, secret: t }\n", "dispatcher.oauth2_clients[1].id"},
		"challenge TTL":            {"dispatcher:\n  challenge_ttl: 0\n", "dispatcher.challenge_ttl: must be positive"},
		"login remember for":       {"dispatcher:\n  login_remember_for: 0\n", "dispatcher.login_remember_for: must be positive"},
		"session TTL":              {"dispatcher:\n  session_ttl: 0\n", "dispatcher.login_remember_for: must be positive"},
		"consent remember for":     {"dispatcher:\n  consent_remember_for: 0\n", "dispatcher.consent_remember_for: must be positive"},
		"session TTL twice":        {"dispatcher:\n  session_ttl: 1h\n  login_remember_for: 1h\n", "dispatcher.session_ttl: is the Symfony name of login_remember_for"},
		"session TTL null twice":   {"dispatcher:\n  session_ttl: ~\n  login_remember_for: 1h\n", "dispatcher.session_ttl: is the Symfony name of login_remember_for"},
		"login TTL null twice":     {"dispatcher:\n  login_remember_for: ~\n  session_ttl: 1h\n", "dispatcher.session_ttl: is the Symfony name of login_remember_for"},
		"position out of range":    {apps + flow + "        - { id: a, order: 3000000000 }\n", "position 3000000000 is out of range"},
		"NUL in a title":           {apps + "  flows:\n    - { id: f, title: \"a\\0b\", description: D, steps: [{ id: a, order: 0 }] }\n", "line 7: dispatcher.flows[0].title: contains a NUL character"},
		"NUL in a locale":          {apps + "  flows:\n    - { id: f, title: { \"fr\\0\": F }, description: D, steps: [{ id: a, order: 0 }] }\n", "line 7: dispatcher.flows[0].title: key \"fr\\x00\" contains a NUL character"},
		"NUL in a claim":           {app + "      receive_claims: [\"a\\0\"]\n", "dispatcher.apps[0].receive_claims[0]: contains a NUL character"},
		"NUL in a method":          {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", consent_url: \"http://a\", method: \"m\\0\" }\n", "dispatcher.apps[0].method: contains a NUL character"},
		"acr with a space":         {apps + "  flows:\n    - { id: f, title: T, description: D, acr: \"loa 2\", steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].acr: \"loa 2\" contains a space"},
		"auth mode":                {app + "      auth_mode: token\n", "dispatcher.apps[0].auth_mode: \"token\" is not network or mtls"},
		"source":                   {app + "      allowed_sources: [10.1.0.0/16, pod-a]\n", "dispatcher.apps[0].allowed_sources: \"pod-a\" is neither"},
		"fingerprint in network":   {app + "      client_cert_fingerprint: " + fingerprint + "\n", "dispatcher.apps[0].client_cert_fingerprint: only applies to auth_mode: mtls"},
		"sources in mtls":          {app + "      auth_mode: mtls\n      client_cert_fingerprint: " + fingerprint + "\n      allowed_sources: [10.1.0.0/16]\n", "dispatcher.apps[0].allowed_sources: only applies to auth_mode: network"},
		"mtls without fingerprint": {app + "      auth_mode: mtls\n", "dispatcher.apps[0].client_cert_fingerprint: must be the SHA-256"},
		"short fingerprint":        {app + "      auth_mode: mtls\n      client_cert_fingerprint: abcd\n", "dispatcher.apps[0].client_cert_fingerprint: must be the SHA-256"},
		"source in options":        {app + "      options: { allowed_sources: [10.1.0.0/16] }\n", "dispatcher.apps[0].options.allowed_sources: is a key of the app"},
		"mode in options":          {app + "      options: { auth_mode: mtls }\n", "dispatcher.apps[0].options.auth_mode: is a key of the app"},
		"fingerprint in options":   {app + "      options: { client_cert_fingerprint: abcd }\n", "dispatcher.apps[0].options.client_cert_fingerprint: is a key of the app"},
		"claims merged in options": {app + "      options: { <<: { receive_claims: [email] } }\n", "dispatcher.apps[0].options.receive_claims: is a key of the app"},
		"claims in options":        {app + "      options: { receive_claims: [email] }\n", "dispatcher.apps[0].options.receive_claims: is a key of the app"},
		"claims as a mapping":      {app + "      receive_claims: { a: b }\n", "expected a list"},
		"no locale":                {"dispatcher:\n  supported_locales: []\n", "dispatcher.supported_locales: is empty"},
		"token TTL fraction":       {"admin:\n  api: { token_ttl: 1500ms }\n", "admin.api.token_ttl: must be a whole number of seconds"},
	} {
		if _, _, err := load(t, tt.content, nil); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
}

// A list gives the claims it names, an empty one none: an empty variable must
// not widen what the app sees. Absent and null both leave no list, which
// bootstrap tells apart: only null, with a warning, gives every claim back.
func TestReceiveClaims(t *testing.T) {
	const app = "dispatcher:\n  apps:\n    - { id: a, login_url: http://a, consent_url: http://a, method: m%s }\n"
	const warning = "dispatcher.apps[0].receive_claims: ~ gives every claim"
	for extra, want := range map[string]struct {
		claims *List
		null   bool
	}{
		"":                                 {nil, false},
		", receive_claims: ~":              {nil, true},
		", receive_claims: null":           {nil, true},
		", receive_claims: ":               {nil, true},
		", receive_claims: []":             {&List{}, false},
		`, receive_claims: ""`:             {&List{}, false},
		`, receive_claims: " , "`:          {&List{}, false},
		`, receive_claims: [""]`:           {&List{}, false},
		", receive_claims: [~]":            {&List{}, false},
		", receive_claims: [email, name]":  {&List{"email", "name"}, false},
		`, receive_claims: "email, name"`:  {&List{"email", "name"}, false},
		`, receive_claims: "${NO_CLAIMS}"`: {&List{}, false},
		// A variable is never null.
		`, receive_claims: "${TILDE}"`: {&List{"~"}, false},
		// Through an alias and a merge, as the decoder reads them.
		", logout_url: &none ~, receive_claims: *none":             {nil, true},
		`, logout_url: &empty "", receive_claims: *empty`:          {&List{}, false},
		", <<: { receive_claims: ~ }":                              {nil, true},
		", <<: { receive_claims: [a] }":                            {&List{"a"}, false},
		", <<: { receive_claims: [] }":                             {&List{}, false},
		", <<: { receive_claims: [a] }, receive_claims: ~":         {nil, true},
		", <<: { receive_claims: ~ }, receive_claims: [a]":         {&List{"a"}, false},
		", <<: [{ receive_claims: ~ }, { receive_claims: [a] }]":   {nil, true},
		", <<: [{ receive_claims: [a] }, { receive_claims: ~ }]":   {&List{"a"}, false},
		", <<: [{ logout_url: http://a }, { receive_claims: ~ }]":  {nil, true},
		", <<: [{ logout_url: http://a }, { receive_claims: [] }]": {&List{}, false},
	} {
		c, warnings, err := load(t, fmt.Sprintf(app, extra), map[string]string{"TILDE": "~"})
		if err != nil {
			t.Errorf("%q: %v", extra, err)
			continue
		}
		a := c.Seed.Apps[0]
		if !reflect.DeepEqual(a.ReceiveClaims, want.claims) || a.NullReceiveClaims != want.null {
			t.Errorf("%q: ReceiveClaims = %v, null %v, want %v, %v", extra, a.ReceiveClaims, a.NullReceiveClaims, want.claims, want.null)
		}
		if got := strings.Contains(strings.Join(warnings, "\n"), warning); got != want.null {
			t.Errorf("%q: warnings = %q, want the warning: %v", extra, warnings, want.null)
		}
	}
	// By the index of the app the decoder keeps, a null entry dropped.
	c, _, err := load(t, "dispatcher:\n  apps:\n    - ~\n"+
		"    - { id: a, login_url: http://a, consent_url: http://a, method: m }\n"+
		"    - { id: b, login_url: http://a, consent_url: http://a, method: m, receive_claims: ~ }\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if apps := c.Seed.Apps; len(apps) != 2 || apps[0].NullReceiveClaims || !apps[1].NullReceiveClaims {
		t.Errorf("apps = %+v", apps)
	}
}

// The options of an app, which Symfony never read, are dropped unread, in every
// form its variableNode takes: their values may hold what the expansion
// refuses.
func TestOptionsIgnored(t *testing.T) {
	const app = "dispatcher:\n  apps:\n    - { id: a, login_url: http://a, consent_url: http://a, method: m, options: %s }\n"
	const warning = "dispatcher.apps[0].options is ignored"
	for options, warned := range map[string]bool{
		`{ theme: "%env(THEME)%", n: 123456789012345678901 }`: true,
		`{ x: &o { y: *o } }`:    true,
		`&o { y: *o }`:           true,
		`&o [*o]`:                true,
		`{ <<: { x: 1 } }`:       true,
		`{ "k\0": "\0" }`:        true,
		`[a, b]`:                 true,
		`[receive_claims]`:       true,
		`texte`:                  true,
		`12`:                     true,
		`false`:                  true,
		`"%env(json:OPTIONS)%"`:  true,
		`"${UNSET_AND_UNREAD?}"`: true,
		`"\0"`:                   true,
		`{}`:                     false,
		`[]`:                     false,
		`""`:                     false,
		`~`:                      false,
	} {
		_, warnings, err := load(t, fmt.Sprintf(app, options), nil)
		if err != nil {
			t.Errorf("%s: %v", options, err)
			continue
		}
		if got := strings.Contains(strings.Join(warnings, "\n"), warning); got != warned {
			t.Errorf("%s: warnings = %q, want the warning: %v", options, warnings, warned)
		}
	}
	// One warning per app, at its index, through a merge too.
	_, warnings, err := load(t, `
dispatcher:
  apps:
    - &a { id: a, login_url: http://a, consent_url: http://a, method: m, options: { x: 1 } }
    - { id: b, login_url: http://a, consent_url: http://a, method: m }
    - { <<: *a, id: c }
    - { <<: *a, id: d, options: {} }
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range warnings {
		if strings.Contains(w, ".options") {
			got = append(got, w[:strings.Index(w, " is ignored")])
		}
	}
	if want := []string{"dispatcher.apps[0].options", "dispatcher.apps[2].options"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	// A merge is decoded for its keys: yaml.v3 bounds what its aliases unfold.
	var bomb strings.Builder
	bomb.WriteString("dispatcher:\n  apps:\n    - id: a\n      login_url: http://a\n      consent_url: http://a\n      method: m\n      options:\n        l0: &l0 { x: 1 }\n")
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&bomb, "        l%d: &l%d { <<: [%s] }\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*l%d, ", i-1), 10), ", "))
	}
	bomb.WriteString("        <<: *l10\n")
	if _, _, err := load(t, bomb.String(), nil); err == nil || !strings.Contains(err.Error(), "excessive aliasing") {
		t.Errorf("merge bomb: err = %v", err)
	}
}

// Outside the seed, ~ has no meaning: yaml.v3 would keep some defaults and
// empty other keys. A section left empty is null too.
func TestNullOutsideSeed(t *testing.T) {
	for content, want := range map[string]string{
		"hydra:\n  timeout: ~\n":                             "line 2: hydra.timeout: is null",
		"server:\n  listen:\n":                               "line 2: server.listen: is null",
		"security:\n  emulated_api_authorized_hosts: null\n": "line 2: security.emulated_api_authorized_hosts: is null",
		"ui:\n  csp_extra: { font-src: ~ }\n":                "line 2: ui.csp_extra.font-src: is null",
		"server: &none ~\nhydra: *none\n":                    "line 2: hydra: is null",
		"observability:\n  sentry:\n# all keys commented\n":  "line 2: observability.sentry: is null",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", content, err, want)
		}
	}
	// In the seed, ~ resets a setting, and an empty seed is no seed.
	for _, content := range []string{"dispatcher: ~\n", "dispatcher:\n  remember: ~\n", "server: { listen: \"~\" }\n"} {
		if _, _, err := load(t, content, nil); err != nil {
			t.Errorf("%q: %v", content, err)
		}
	}
}

// ~ sets a seed setting to null, which bootstrap --force resets; an empty
// variable sets it to "".
func TestNullSettings(t *testing.T) {
	c, warnings, err := load(t, `
dispatcher:
  <<: { supported_locales: ~, consent_auto_accept: true }
  login_accept_webhook_url: ~
  consent_accept_webhook_url: "${UNSET}"
  remember:
  fallback_locale: &none ~
  default_locale: *none
  consent_auto_accept: ~
  session_ttl: ~
  apps: ~
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Seed
	if !slices.Equal(s.NullSettings, []string{"consent_auto_accept", "remember", "login_remember_for", "login_accept_webhook_url", "supported_locales", "default_locale", "fallback_locale"}) ||
		s.ConsentAcceptWebhookURL == nil || *s.ConsentAcceptWebhookURL != "" {
		t.Errorf("null = %v, consent webhook = %v", s.NullSettings, s.ConsentAcceptWebhookURL)
	}
	// Where Symfony read ~ otherwise than as its default.
	var symfony []string
	for _, w := range warnings {
		if strings.Contains(w, "where Symfony read it as") {
			symfony = append(symfony, w)
		}
	}
	if !slices.Equal(symfony, []string{
		"dispatcher.consent_auto_accept: ~ resets it to its default, where Symfony read it as true",
		"dispatcher.remember: ~ resets it to its default, where Symfony read it as true",
		"dispatcher.supported_locales: ~ resets it to its default, where Symfony read it as an empty list",
	}) {
		t.Errorf("warnings = %q", symfony)
	}
}

func TestSystemSecretsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets")
	// One secret per line: a comma belongs to the secret, CRLF is trimmed.
	if err := os.WriteFile(file, []byte("youReallyNeedToChangeThis\r\nan,older,secret\r\n\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file})))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "an,older,secret"}) {
		t.Errorf("system_secrets = %q", c.Hydra.SystemSecrets)
	}
	if _, _, err := Load("", envOf(required(map[string]string{
		"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file,
		"DISPATCHER_HYDRA_SYSTEM_SECRETS":      "youReallyNeedToChangeThis",
	}))); err == nil {
		t.Error("system_secrets and system_secrets_file together: want an error")
	}
	if _, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file + ".missing"}))); err == nil ||
		!strings.Contains(err.Error(), "hydra.system_secrets_file") {
		t.Errorf("missing file: err = %v", err)
	}
	// A secret not provisioned yet, rather than the fallback mode.
	if err := os.WriteFile(file, []byte(" \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file}))); err == nil ||
		!strings.Contains(err.Error(), "hydra.system_secrets_file: holds no secret") {
		t.Errorf("empty file: err = %v", err)
	}
}

// An IPv4-mapped network is its IPv4 network: clients are matched by their
// IPv4 address.
func TestPrefixes(t *testing.T) {
	ps, err := List{"10.0.0.1/8", "::ffff:10.0.0.0/104", "::ffff:192.168.1.1", "fe80::1%eth0", "::ffff:0:0/80"}.Prefixes()
	var got []string
	for _, p := range ps {
		got = append(got, p.String())
	}
	if want := []string{"10.0.0.0/8", "10.0.0.0/8", "192.168.1.1/32", "fe80::1/128", "::/80"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("prefixes = %q, %v; want %q", got, err, want)
	}
}

func TestEmptyFile(t *testing.T) {
	c, _, err := Load(writeFile(t, "# nothing but a comment\n"), envOf(required(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8080" || c.Admin.API.TokenTTL.Std() != 15*time.Minute {
		t.Errorf("defaults not applied: %+v", c.Server)
	}
}
