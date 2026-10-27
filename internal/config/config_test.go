package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	hexKey    = strings.Repeat("ab", 32)
	base64Key = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
)

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// required holds the keys without default, set through DISPATCHER_* variables.
func required(extra map[string]string) map[string]string {
	m := map[string]string{
		"DISPATCHER_SERVER_BASE_URL":       "http://dispatcher.hydra.test",
		"DISPATCHER_HYDRA_ADMIN_URL":       "http://hydra:4445",
		"DISPATCHER_STORE_DSN":             "postgres://lasql:lasql@postgres:5432/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY":    hexKey,
		"DISPATCHER_SECRETS_CHALLENGE_KEY": base64Key,
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

// The example of the design document must keep loading as is.
func TestDesignDocExample(t *testing.T) {
	c, warnings, err := Load("testdata/design-doc.yaml", envOf(map[string]string{
		"HYDRA_SYSTEM_SECRETS":      "youReallyNeedToChangeThis,an-older-system-secret",
		"DISPATCHER_COOKIE_KEY":     hexKey,
		"DISPATCHER_ENCRYPTION_KEY": base64Key,
		"DISPATCHER_CHALLENGE_KEY":  hexKey,
		"DISPATCHER_WEBHOOK_KEY":    hexKey,
		"DATABASE_URL":              "postgres://lasql:lasql@postgres:5432/dispatcher",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %q", warnings)
	}
	for _, check := range []struct {
		name      string
		got, want any
	}{
		{"server.base_url", c.Server.BaseURL, "http://dispatcher.hydra.test"},
		{"hydra.timeout", c.Hydra.Timeout.Std(), 5 * time.Second},
		{"hydra.system_secrets", c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "an-older-system-secret"}},
		{"hydra.login_consent_ttl", c.Hydra.LoginConsentTTL.Std(), 30 * time.Minute},
		{"security.failure_rate_limit.block", c.Security.FailureRateLimit.Block.Std(), 5 * time.Minute},
		{"security.metrics_authorized_hosts", *c.Security.MetricsAuthorizedHosts, privateNetworks},
		{"secrets.encryption_key", len(c.Secrets.EncryptionKey), 32},
		{"secrets.encryption_keys_previous", len(c.Secrets.EncryptionKeysPrevious), 0},
		{"state.redis_dsn", c.State.RedisDSN, ""},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL.Std(), 900 * time.Second},
		{"admin.session.max_age", c.Admin.Session.MaxAge.Std(), 8 * time.Hour},
		{"admin.client_secret_max_age", c.Admin.ClientSecretMaxAge.Std(), 365 * 24 * time.Hour},
		{"ui.supported_locales", c.UI.SupportedLocales, List{"fr", "en"}},
		{"observability.tracing.sampler_ratio", c.Observability.Tracing.SamplerRatio, 0.01},
		{"dispatcher.challenge_ttl", c.Seed.ChallengeTTL.Std(), time.Hour},
		{"dispatcher.remember_for", c.Seed.RememberFor.Std(), 2629800 * time.Second},
		{"dispatcher.remember", *c.Seed.Remember, true},
		{"logout.propagate_without_record", c.Logout.PropagateWithoutRecord, "all"},
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
	if sql.LoginURL != "http://sql.hydra.test/login" || sql.ConsentURL != "http://sql.hydra.test/consent" || sql.Method != "pwd" {
		t.Errorf("hydra-sql app = %+v", sql)
	}
	twoFA := s.Flows[2]
	if !reflect.DeepEqual(twoFA.Steps, []SeedStep{{"hydra-sql", 0}, {"hydra-2fa", 1}}) ||
		twoFA.Title["fr"] != "Hydra SQL 2FA" || twoFA.Description["en"] != "SQL Authentication second factor" ||
		twoFA.IconURL != nil || twoFA.Enabled != nil {
		t.Errorf("hydra-sql-2fa flow = %+v", twoFA)
	}
	if len(s.OAuth2Clients) != 1 || s.OAuth2Clients[0].ID != "test" || s.OAuth2Clients[0].Scopes != nil {
		t.Errorf("oauth2_clients = %+v", s.OAuth2Clients)
	}
	// Set in the file, so bootstrap --force rewrites them; remember is absent.
	if s.AppAutoSelect == nil || *s.AppAutoSelect || s.ConsentAutoAccept == nil || s.Remember != nil {
		t.Errorf("settings = %+v", s.SeedSettings)
	}
	for _, key := range []string{"hydra_public_url", "cache_providers", "session_ttl"} {
		if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, key) }) {
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
		// Unset: follows the admin list, after overrides.
		{"security.emulated_api_authorized_hosts", *c.Security.EmulatedAPIAuthorizedHosts, List{"10.1.0.0/16", "127.0.0.1"}},
		// Set to "": no address, not the admin list.
		{"security.metrics_authorized_hosts", len(*c.Security.MetricsAuthorizedHosts), 0},
		{"admin.ui.enabled", c.Admin.UI.Enabled, false},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL.Std(), 10 * time.Minute},
		{"admin.client_secret_max_age", c.Admin.ClientSecretMaxAge.Std(), 90 * 24 * time.Hour},
		{"observability.access_log_sample", c.Observability.AccessLogSample, 0.1},
		{"hydra.system_secrets", c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "another-secret"}},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}

	if _, _, err := Load(path, envOf(required(map[string]string{"DISPATCHER_HYDRA_TIMEOUT": "soon"}))); err == nil ||
		!strings.Contains(err.Error(), "DISPATCHER_HYDRA_TIMEOUT") {
		t.Errorf("invalid override: err = %v, want it to name the variable", err)
	}
}

func TestEnvKeys(t *testing.T) {
	seen := map[string]string{}
	for _, k := range envKeys(defaults()) {
		if other, dup := seen[k.name]; dup {
			t.Errorf("%s reaches both %s and %s", k.name, other, k.path)
		}
		seen[k.name] = k.path
	}
	for _, name := range []string{"DISPATCHER_SERVER_BASE_URL", "DISPATCHER_ADMIN_API_TOKEN_TTL", "DISPATCHER_OBSERVABILITY_SENTRY_DSN", "DISPATCHER_SECURITY_FAILURE_RATE_LIMIT_BLOCK"} {
		if _, ok := seen[name]; !ok {
			t.Errorf("%s is not an override", name)
		}
	}
	for name := range seen {
		if strings.HasPrefix(name, "DISPATCHER_DISPATCHER_") || strings.HasPrefix(name, "DISPATCHER_UI_CSP_EXTRA") {
			t.Errorf("%s must not be an override", name)
		}
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
  system_secrets: "${SECRETS}"
admin:
  ui: { enabled: "${ADMIN_UI:-false}" }
  api:
    token_ttl: ${TTL:-900}
observability:
  sentry: { environment: "${SENTRY_ENV:-123}" }
dispatcher:
  oauth2_clients:
    - id: admin
      secret: "${ADMIN_CLIENT_SECRET}"
`)
	c, _, err := Load(path, envOf(required(map[string]string{
		"BASE":                "http://dispatcher.example",
		"SECRETS":             "youReallyNeedToChangeThis,second",
		"TTL":                 "",
		"ADMIN_CLIENT_SECRET": "s3cr3t: with colon",
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
		{"admin.ui.enabled", c.Admin.UI.Enabled, false},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL.Std(), 900 * time.Second},
		{"observability.sentry.environment", c.Observability.Sentry.Environment, "123"},
		{"dispatcher.oauth2_clients[0].secret", c.Seed.OAuth2Clients[0].Secret, "s3cr3t: with colon"},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

func TestExpand(t *testing.T) {
	env := envOf(map[string]string{"SET": "value", "EMPTY": ""})
	for in, want := range map[string]string{
		"${SET}":             "value",
		"${UNSET}":           "",
		"${UNSET:-default}":  "default",
		"${EMPTY:-default}":  "default",
		"${SET:-default}":    "value",
		"a-${SET}-${UNSET}b": "a-value-b",
		"${1INVALID}":        "${1INVALID}",
		"plain":              "plain",
		"${UNSET:-}":         "",
	} {
		if got := expand(in, env); got != want {
			t.Errorf("expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnknownKeys(t *testing.T) {
	for _, content := range []string{
		"server:\n  lisen: \":8080\"\n",
		"dispatcher:\n  apps: []\n  app_autoselect: true\n",
		"nope: 1\n",
	} {
		if _, _, err := Load(writeFile(t, content), envOf(required(nil))); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("%q: err = %v, want an unknown field error", content, err)
		}
	}
}

func TestValidation(t *testing.T) {
	_, _, err := Load("", envOf(nil))
	for _, path := range []string{"server.base_url", "hydra.admin_url", "store.dsn", "secrets.cookie_key", "secrets.challenge_key"} {
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
		{"bad CIDR", map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "REMOTE_ADDR"}, "server.trusted_proxies"},
		{"replicas without Redis", map[string]string{"DISPATCHER_SERVER_REPLICAS_HINT": "3"}, "state.redis_dsn"},
		{"Redis DSN scheme", map[string]string{"DISPATCHER_STATE_REDIS_DSN": "http://redis:6379"}, "state.redis_dsn"},
		{"short Hydra secret", map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS": "short"}, "hydra.system_secrets"},
		{"default locale", map[string]string{"DISPATCHER_UI_DEFAULT_LOCALE": "de"}, "ui.default_locale"},
		{"log level", map[string]string{"DISPATCHER_OBSERVABILITY_LOG_LEVEL": "verbose"}, "observability.log_level"},
		{"sample rate", map[string]string{"DISPATCHER_OBSERVABILITY_SENTRY_SAMPLE_RATE": "1.5"}, "observability.sentry.sample_rate"},
		{"audit output", map[string]string{"DISPATCHER_OBSERVABILITY_AUDIT_OUTPUT": "stderr"}, "observability.audit.output"},
		{"remember backend", map[string]string{"DISPATCHER_REMEMBER_BACKEND": "redis"}, "remember.backend"},
		{"logout propagation", map[string]string{"DISPATCHER_LOGOUT_PROPAGATE_WITHOUT_RECORD": "some"}, "logout.propagate_without_record"},
		{"missing CA file", map[string]string{"DISPATCHER_TLS_CA_FILE": "/nonexistent/ca.pem"}, "tls.ca_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Load("", envOf(required(tt.env))); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %s", err, tt.want)
			}
		})
	}

	_, warnings, err := Load("", envOf(required(map[string]string{"DISPATCHER_SECURITY_METRICS_AUTHORIZED_HOSTS": "0.0.0.0/0,::/0"})))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Errorf("warnings = %q, want one per open network", warnings)
	}
}

func TestSystemSecretsFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(file, []byte("youReallyNeedToChangeThis\nan-older-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := Load("", envOf(required(map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file})))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Hydra.SystemSecrets, List{"youReallyNeedToChangeThis", "an-older-secret"}) {
		t.Errorf("system_secrets = %q", c.Hydra.SystemSecrets)
	}
	if _, _, err := Load("", envOf(required(map[string]string{
		"DISPATCHER_HYDRA_SYSTEM_SECRETS_FILE": file,
		"DISPATCHER_HYDRA_SYSTEM_SECRETS":      "youReallyNeedToChangeThis",
	}))); err == nil {
		t.Error("system_secrets and system_secrets_file together: want an error")
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
