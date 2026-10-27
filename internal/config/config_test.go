package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	hexKey    = strings.Repeat("ab", 32)
	base64Key = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
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

// load loads content with the required variables plus env.
func load(t *testing.T, content string, env map[string]string) (*Config, []string, error) {
	t.Helper()
	return Load(writeFile(t, content), envOf(required(env)))
}

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
		"DISPATCHER_CHALLENGE_KEY":  hexKey,
		"DISPATCHER_WEBHOOK_KEY":    hexKey,
		"DATABASE_URL":              "postgres://lasql:lasql@postgres:5432/dispatcher",
	}))
	if err != nil {
		t.Fatal(err)
	}
	// REDIS_DSN is unset: the in-memory store, with its warning. The
	// DISPATCHER_*_KEY references are no overrides, and draw no warning.
	if len(warnings) != 1 || !hasWarning(warnings, memoryWarning) {
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
		{"dispatcher.remember_for", c.Seed.RememberFor.Std(), 2629800 * time.Second},
		{"dispatcher.remember", *c.Seed.Remember, true},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

// Every key of non-defaults.yaml differs from its default, so a key the
// decoder skipped would keep its default and show here.
func TestEveryKeyIsRead(t *testing.T) {
	c, warnings, err := Load("testdata/non-defaults.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %q", warnings)
	}
	got, defaultKeys := envKeys(c), envKeys(defaults())
	if len(got) != len(defaultKeys) {
		t.Fatalf("%d keys, want %d", len(got), len(defaultKeys))
	}
	for i, k := range got {
		if k.path == "store.backend" { // postgres is its only value
			continue
		}
		if reflect.DeepEqual(k.field.Interface(), defaultKeys[i].field.Interface()) {
			t.Errorf("%s = %v, its default: the file value is not read", k.path, k.field.Interface())
		}
	}
	if !slices.Equal(c.UI.CSPExtra["font-src"], List{"https://fonts.gstatic.com"}) {
		t.Errorf("ui.csp_extra = %v", c.UI.CSPExtra)
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
	if s.AppAutoSelect == nil || *s.AppAutoSelect || s.ConsentAutoAccept == nil || s.Remember != nil || len(s.NullSettings) != 0 {
		t.Errorf("settings = %+v, null = %v", s.SeedSettings, s.NullSettings)
	}
	for _, key := range []string{"hydra_public_url", "cache_providers", "session_ttl"} {
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
	// login_accept_webhook_url: ~ clears the webhook, as Symfony's --force did.
	if !slices.Equal(s.NullSettings, []string{"login_accept_webhook_url", "consent_accept_webhook_url"}) || s.LoginAcceptWebhookURL != nil {
		t.Errorf("null settings = %v", s.NullSettings)
	}
	// icon_url: { fr: ~, en: ~ } is no icon.
	if s.Flows[0].IconURL != nil || s.Apps[1].LoginURL != "http://sql.hydra.test/" {
		t.Errorf("flow = %+v, app = %+v", s.Flows[0], s.Apps[1])
	}
	for _, key := range []string{"hydra_public_url", "session_ttl", "admin_authorized_hosts"} {
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
		"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS":  hexKey + "," + base64Key,
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
		{"hydra.version", c.Hydra.Version, "2.3"},
		{"secrets.encryption_keys_previous", len(c.Secrets.EncryptionKeysPrevious), 2},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}

	if _, _, err := Load(path, envOf(required(map[string]string{"DISPATCHER_HYDRA_TIMEOUT": "soon"}))); err == nil ||
		!strings.Contains(err.Error(), "DISPATCHER_HYDRA_TIMEOUT") || strings.Contains(err.Error(), "line 0") {
		t.Errorf("invalid override: err = %v, want it to name the variable, without a line", err)
	}
}

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
// about. Other DISPATCHER_* names are free for ${VAR} references.
func TestUnknownOverrides(t *testing.T) {
	_, warnings, err := load(t, "", map[string]string{
		"DISPATCHER_SERVER_BASEURL":      "http://typo",
		"DISPATCHER_UI_CSP_EXTRA":        "font-src",
		"DISPATCHER_DISPATCHER_REMEMBER": "true",
		"DISPATCHER_COOKIE_KEY":          hexKey,
		"DISPATCHER_UPSTREAM":            "dispatcher:80",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DISPATCHER_SERVER_BASEURL", "DISPATCHER_UI_CSP_EXTRA", "DISPATCHER_DISPATCHER_REMEMBER"} {
		if !hasWarning(warnings, name+" is ignored") {
			t.Errorf("no warning for %s in %q", name, warnings)
		}
	}
	for _, name := range []string{"DISPATCHER_COOKIE_KEY", "DISPATCHER_UPSTREAM", "DISPATCHER_SERVER_BASE_URL"} {
		if hasWarning(warnings, name) {
			t.Errorf("warning for %s in %q", name, warnings)
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
		"DISPATCHER_SECRETS_COOKIE_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_ENCRYPTION_KEY",
		"DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_CHALLENGE_KEY",
		"DISPATCHER_SECRETS_CHALLENGE_KEYS_PREVIOUS",
		"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY",
		"DISPATCHER_TLS_MIN_VERSION",
		"DISPATCHER_TLS_CA_FILE",
		"DISPATCHER_TLS_PINNED_SPKI_SHA256",
		"DISPATCHER_TLS_HSTS_INCLUDE_SUBDOMAINS",
		"DISPATCHER_STATE_REDIS_DSN",
		"DISPATCHER_STATE_KEY_PREFIX",
		"DISPATCHER_STATE_REDIS_POOL_SIZE",
		"DISPATCHER_REMEMBER_BACKEND",
		"DISPATCHER_STORE_BACKEND",
		"DISPATCHER_STORE_DSN",
		"DISPATCHER_ADMIN_UI_ENABLED",
		"DISPATCHER_ADMIN_API_ENABLED",
		"DISPATCHER_ADMIN_API_PRIVATE_KEY",
		"DISPATCHER_ADMIN_API_PUBLIC_KEY",
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
		"DISPATCHER_UI_DEFAULT_LOCALE",
		"DISPATCHER_UI_SUPPORTED_LOCALES",
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
observability:
  sentry: { environment: "${SENTRY_ENV:-123}", release: "$${NOT_EXPANDED}" }
dispatcher:
  apps:
    - id: a
      login_url: http://a/login
      consent_url: http://a/consent
      method: pwd
      options:
        literal: "0123"
        quoted: "${CLIENT_ID}"
        plain: ${CLIENT_ID}
        flag: ${FLAG}
        empty: "${UNSET}"
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
		"CLIENT_ID":           "0123",
		"FLAG":                "true",
		"TILDE":               "~",
	})))
	if err != nil {
		t.Fatal(err)
	}
	options := c.Seed.Apps[0].Options
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
		{"observability.sentry.environment", c.Observability.Sentry.Environment, "123"},
		{"observability.sentry.release", c.Observability.Sentry.Release, "${NOT_EXPANDED}"},
		// Options keep their YAML types: quoted text stays text.
		{"options.literal", options["literal"], "0123"},
		{"options.quoted", options["quoted"], "0123"},
		{"options.plain", options["plain"], 83},
		{"options.flag", options["flag"], true},
		{"options.empty", options["empty"], ""},
		{"dispatcher.oauth2_clients[0].secret", c.Seed.OAuth2Clients[0].Secret, "s3cr3t: with colon"},
		{"dispatcher.oauth2_clients[1].secret", c.Seed.OAuth2Clients[1].Secret, "~"},
	} {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

// An empty variable gives an empty value, never the default of the key: an
// allowlist without address, as with DISPATCHER_* variables.
func TestEmptyExpansion(t *testing.T) {
	c, _, err := load(t, `
server:
  trusted_proxies: ${UNSET}
  cookie_path: "${COOKIE_PATH:-/}"
security:
  admin_authorized_hosts: ["10.9.0.0/16"]
  metrics_authorized_hosts: "${METRICS}"
  emulated_api_authorized_hosts: ${UNSET}
`, map[string]string{"METRICS": ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Server.TrustedProxies) != 0 || len(*c.Security.MetricsAuthorizedHosts) != 0 || len(*c.Security.EmulatedAPIAuthorizedHosts) != 0 || c.Server.CookiePath != "/" {
		t.Errorf("trusted = %v, metrics = %v, emulated = %v, cookie_path = %q",
			c.Server.TrustedProxies, *c.Security.MetricsAuthorizedHosts, *c.Security.EmulatedAPIAuthorizedHosts, c.Server.CookiePath)
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
	// Aliases under options, and a list of merged mappings.
	c, _, err := load(t, `
dispatcher:
  apps:
    - { id: a, login_url: &login "http://a", consent_url: "http://a", method: m, options: { scopes: &scopes ["${SCOPE}"] } }
    - { id: b, login_url: *login, consent_url: "http://b", method: m, options: { scopes: *scopes, all: [*scopes] } }
    - <<: [{ login_url: "http://c" }, { consent_url: "http://c" }]
      id: c
      method: m
`, map[string]string{"SCOPE": "openid"})
	if err != nil {
		t.Fatal(err)
	}
	if apps := c.Seed.Apps; !reflect.DeepEqual(apps[1].Options["scopes"], []any{"openid"}) || apps[1].LoginURL != "http://a" ||
		apps[2].LoginURL != "http://c" || apps[2].ConsentURL != "http://c" {
		t.Errorf("apps = %+v", apps)
	}
}

func TestDocuments(t *testing.T) {
	for _, content := range []string{"", "# nothing but a comment\n", "---\n", "---\nserver: { listen: \":1\" }\n"} {
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
		{"base URL with query", map[string]string{"DISPATCHER_SERVER_BASE_URL": "http://d.example/?"}, "server.base_url"},
		{"cookie path", map[string]string{"DISPATCHER_SERVER_COOKIE_PATH": "auth"}, "server.cookie_path"},
		{"bad CIDR", map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "REMOTE_ADDR"}, "server.trusted_proxies"},
		{"replicas without Redis", map[string]string{"DISPATCHER_SERVER_REPLICAS_HINT": "3"}, "state.redis_dsn"},
		{"Redis DSN scheme", map[string]string{"DISPATCHER_STATE_REDIS_DSN": "http://redis:6379"}, "state.redis_dsn"},
		{"short Hydra secret", map[string]string{"DISPATCHER_HYDRA_SYSTEM_SECRETS": "short"}, "hydra.system_secrets"},
		{"Hydra version", map[string]string{"DISPATCHER_HYDRA_VERSION": "2.4"}, "hydra.version"},
		{"default locale", map[string]string{"DISPATCHER_UI_DEFAULT_LOCALE": "de"}, "ui.default_locale"},
		{"log level", map[string]string{"DISPATCHER_OBSERVABILITY_LOG_LEVEL": "verbose"}, "observability.log_level"},
		{"sample rate", map[string]string{"DISPATCHER_OBSERVABILITY_SENTRY_SAMPLE_RATE": "1.5"}, "observability.sentry.sample_rate"},
		{"audit output", map[string]string{"DISPATCHER_OBSERVABILITY_AUDIT_OUTPUT": "stderr"}, "observability.audit.output"},
		{"remember backend", map[string]string{"DISPATCHER_REMEMBER_BACKEND": "redis"}, "remember.backend"},
		{"logout propagation", map[string]string{"DISPATCHER_LOGOUT_PROPAGATE_WITHOUT_RECORD": "some"}, "logout.propagate_without_record"},
		{"missing CA file", map[string]string{"DISPATCHER_TLS_CA_FILE": "/nonexistent/ca.pem"}, "tls.ca_file"},
		{"overflowing duration", map[string]string{"DISPATCHER_ADMIN_CLIENT_SECRET_MAX_AGE": "10000000000"}, "too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Load("", envOf(required(tt.env))); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %s", err, tt.want)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	_, warnings, err := Load("", envOf(required(map[string]string{"DISPATCHER_SECURITY_METRICS_AUTHORIZED_HOSTS": "0.0.0.0/0,::/0"})))
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(warnings, "metrics_authorized_hosts contains 0.0.0.0/0") || !hasWarning(warnings, "metrics_authorized_hosts contains ::/0") {
		t.Errorf("warnings = %q, want one per open network", warnings)
	}

	_, warnings, err = Load("", envOf(required(map[string]string{"DISPATCHER_SERVER_TRUSTED_PROXIES": "0.0.0.0/0"})))
	if err != nil || !hasWarning(warnings, "server.trusted_proxies contains 0.0.0.0/0: X-Forwarded-For is trusted from every address") {
		t.Errorf("trusted proxies 0.0.0.0/0: warnings = %q, err = %v", warnings, err)
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
		"ui:\n  csp_extra: { default-src: [\"*\"] }\n":                   "ui.csp_extra.default-src: is not one of",
		"ui:\n  csp_extra: { img-src: [\"https://a; script-src *\"] }\n": "is not a single source",
		"ui:\n  csp_extra: { script-src: [\"'unsafe-inline'\"] }\n":      "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { script-src: [\"*\"] }\n":                    "would allow inline or arbitrary scripts",
		"ui:\n  csp_extra: { font-src: [\"\"] }\n":                       "is not a single source",
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
	if c, _, err := load(t, apps+flow+"        - { id: a, order: 0 }\n        - { app_id: b, position: 1, subject_check: \"claim:email\" }\n", nil); err != nil ||
		c.Seed.Flows[0].Steps[1].SubjectCheck != "claim:email" || c.Seed.Flows[0].Title[""] != "F" {
		t.Errorf("valid seed: err = %v", err)
	}
	for name, tt := range map[string]struct{ content, want string }{
		"missing app id":        {"dispatcher:\n  apps:\n    - { login_url: \"http://a\", consent_url: \"http://a\", method: m }\n", "dispatcher.apps[0].id: is required"},
		"duplicate app":         {apps + "    - { id: a, login_url: \"http://a\", consent_url: \"http://a\", method: m }\n", "dispatcher.apps[2].id: \"a\" is declared twice"},
		"relative login URL":    {"dispatcher:\n  apps:\n    - { id: a, login_url: /login, consent_url: \"http://a\", method: m }\n", "dispatcher.apps[0].login_url"},
		"missing consent URL":   {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", method: m }\n", "dispatcher.apps[0].consent_url: is required"},
		"relative logout URL":   {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", consent_url: \"http://a\", logout_url: /out, method: m }\n", "dispatcher.apps[0].logout_url"},
		"missing method":        {"dispatcher:\n  apps:\n    - { id: a, login_url: \"http://a\", consent_url: \"http://a\" }\n", "dispatcher.apps[0].method: is required"},
		"flow without steps":    {apps + flow + "        []\n", "dispatcher.flows[0].steps: is empty"},
		"undeclared app":        {apps + flow + "        - { id: c, order: 0 }\n", "app \"c\" is not declared"},
		"app twice":             {apps + flow + "        - { id: a, order: 0 }\n        - { id: a, order: 1 }\n", "app \"a\" is already a step"},
		"position twice":        {apps + flow + "        - { id: a, order: 0 }\n        - { id: b, order: 0 }\n", "position 0 is already taken"},
		"subject check":         {apps + flow + "        - { id: a, order: 0, subject_check: \"claim:\" }\n", "subject_check: \"claim:\" is not none, equal or claim:<name>"},
		"missing title":         {apps + "  flows:\n    - { id: f, description: D, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].title: is required"},
		"null description":      {apps + "  flows:\n    - { id: f, title: T, description: { fr: ~ }, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[0].description: is required"},
		"duplicate flow":        {apps + "  flows:\n    - { id: f, title: T, description: D, steps: [{ id: a, order: 0 }] }\n    - { id: f, title: T, description: D, steps: [{ id: a, order: 0 }] }\n", "dispatcher.flows[1].id: \"f\" is declared twice"},
		"missing client secret": {"dispatcher:\n  oauth2_clients:\n    - { id: c }\n", "dispatcher.oauth2_clients[0].secret: is required"},
		"empty scope":           {"dispatcher:\n  oauth2_clients:\n    - { id: c, secret: s, scopes: [\"admin:flows\", \"\"] }\n", "dispatcher.oauth2_clients[0].scopes: contains an empty scope"},
		"duplicate client":      {"dispatcher:\n  oauth2_clients:\n    - { id: c, secret: s }\n    - { id: c, secret: t }\n", "dispatcher.oauth2_clients[1].id"},
		"challenge TTL":         {"dispatcher:\n  challenge_ttl: 0\n", "dispatcher.challenge_ttl: must be positive"},
		"no locale":             {"dispatcher:\n  supported_locales: []\n", "dispatcher.supported_locales: is empty"},
	} {
		if _, _, err := load(t, tt.content, nil); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
}

// ~ sets a seed setting to null, which bootstrap --force resets; an empty
// variable sets it to "".
func TestNullSettings(t *testing.T) {
	c, _, err := load(t, `
dispatcher:
  login_accept_webhook_url: ~
  consent_accept_webhook_url: "${UNSET}"
  remember:
  fallback_locale: &none ~
  default_locale: *none
  apps: ~
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Seed
	if !slices.Equal(s.NullSettings, []string{"login_accept_webhook_url", "remember", "fallback_locale", "default_locale"}) ||
		s.ConsentAcceptWebhookURL == nil || *s.ConsentAcceptWebhookURL != "" {
		t.Errorf("null = %v, consent webhook = %v", s.NullSettings, s.ConsentAcceptWebhookURL)
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
