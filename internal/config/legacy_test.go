package config

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// symfonyEnv reads testdata/symfony-dispatcher.env, a copy of hydra-dev's
// files/apps/dispatcher/dispatcher.env, its keys of development included.
func symfonyEnv(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/symfony-dispatcher.env")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var env []string
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		if line := strings.TrimSpace(lines.Text()); line != "" && !strings.HasPrefix(line, "#") {
			env = append(env, line)
		}
	}
	return env
}

// noEquivalent are the keys hydra-dev's Symfony variables do not give.
var noEquivalent = []string{
	"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24",
	"DISPATCHER_SECRETS_CHALLENGE_KEY=" + hexKey,
	"DISPATCHER_SECRETS_COOKIE_KEY=" + hexKey2,
}

// TestSymfonyEnv loads hydra-dev's Symfony variables with the keys they lack: each
// gives its key or a warning.
func TestSymfonyEnv(t *testing.T) {
	env := symfonyEnv(t)
	c, warnings, err := Load("", append(env, noEquivalent...))
	if err != nil {
		t.Fatalf("err = %v, warnings:\n%s", err, strings.Join(warnings, "\n"))
	}
	for _, check := range []struct {
		key       string
		got, want any
	}{
		{"server.base_url", c.Server.BaseURL, "http://dispatcher.hydra.test"},
		{"server.trusted_proxies", *c.Server.TrustedProxies, List{"127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
		{"hydra.admin_url", c.Hydra.AdminURL, "http://hydra:4445"},
		{"security.admin_authorized_hosts", c.Security.AdminAuthorizedHosts, List{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
		{"state.redis_dsn", c.State.RedisDSN, "redis://redis:6379"},
		{"store.dsn", c.Store.DSN, "postgresql://lasql:lasql@postgres:5432/dispatcher"},
		{"admin.api.token_ttl", c.Admin.API.TokenTTL, Duration(time.Hour)},
		{"admin.api.private_key", strings.HasPrefix(c.Admin.API.PrivateKey, "LS0tLS1CRUdJTiBQUklWQVRF"), true},
		{"admin.api.public_key", strings.HasPrefix(c.Admin.API.PublicKey, "LS0tLS1CRUdJTiBQVUJMSUMg"), true},
	} {
		if g, w := fmtAny(check.got), fmtAny(check.want); g != w {
			t.Errorf("%s = %s, want %s", check.key, g, w)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !hasWarning(warnings, name) {
			t.Errorf("no warning names %s; warnings:\n%s", name, strings.Join(warnings, "\n"))
		}
	}
	for _, want := range []string{
		"BASE_PATH and SERVER_NAME (Symfony) are read as server.base_url until 1.0: set server.base_url, or DISPATCHER_SERVER_BASE_URL, instead; the value of BASE_PATH, an absolute URL; SERVER_NAME unused",
		"TRUSTED_PROXIES (Symfony) is read as server.trusted_proxies until 1.0: set server.trusted_proxies, or DISPATCHER_SERVER_TRUSTED_PROXIES, instead; REMOTE_ADDR, every caller a trusted proxy, has no equivalent and is dropped",
		"HYDRA_ADMIN_AUTHORIZED_HOSTS (Symfony) is read as security.admin_authorized_hosts until 1.0: set security.admin_authorized_hosts, or DISPATCHER_SECURITY_ADMIN_AUTHORIZED_HOSTS, instead; security.emulated_api_authorized_hosts does not inherit it",
		"DATABASE_URL (Symfony) is read as store.dsn",
		"store.dsn: charset, serverVersion dropped, parameters of Doctrine that Postgres refuses",
		"OAUTH2_ADMIN_CLIENT_ID and OAUTH2_ADMIN_CLIENT_SECRET (Symfony) are not read: there is no implicit client of the admin API any more",
		"DEFAULT_LOCALE and APP_LOCALES (Symfony) are not read: the locales are the settings default_locale and supported_locales",
		"variables of the Symfony dispatcher without use here, ignored: APP_DEBUG, APP_ENV, CADDY_HTTP_PORT, HYDRA_BASE_URL, HYDRA_NEW_ISSUER, " +
			"HYDRA_ORIGINAL_ISSUER, HYDRA_REWRITE_ISSUER, OPCACHE_REVALIDATE_FREQ, OPCACHE_VALIDATE_TIMESTAMP, PHP_MEMORY_LIMIT, " +
			"XDEBUG_CLIENT_HOST, XDEBUG_MODE, XDEBUG_START_WITH_REQUEST",
	} {
		if !hasWarning(warnings, want) {
			t.Errorf("no warning %q; warnings:\n%s", want, strings.Join(warnings, "\n"))
		}
	}
	// Values of secrets and DSNs are never quoted.
	for _, w := range warnings {
		if strings.Contains(w, "lasql") || strings.Contains(w, "LS0tLS1") {
			t.Errorf("warning quotes a secret: %s", w)
		}
	}
}

// fmtAny writes a value for TestSymfonyEnv's comparisons.
func fmtAny(v any) string {
	switch v := v.(type) {
	case List:
		return strings.Join(v, ",")
	case Duration:
		return v.Std().String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	}
	return "?"
}

// TestLegacyOrder checks the order of the sources: defaults < variables of the
// Symfony dispatcher < file < DISPATCHER_*.
func TestLegacyOrder(t *testing.T) {
	const admin = "http://symfony:4445"
	for _, tt := range []struct {
		name    string
		file    string
		env     map[string]string
		want    string
		warning string // "" for none naming HYDRA_ADMIN_BASE_URL
	}{
		{"the variable alone", "", map[string]string{"HYDRA_ADMIN_BASE_URL": admin}, admin,
			"HYDRA_ADMIN_BASE_URL (Symfony) is read as hydra.admin_url until 1.0: set hydra.admin_url, or DISPATCHER_HYDRA_ADMIN_URL, instead"},
		{"the file wins", "hydra: {admin_url: http://file:4445}\n", map[string]string{"HYDRA_ADMIN_BASE_URL": admin}, "http://file:4445",
			"HYDRA_ADMIN_BASE_URL (Symfony) is ignored: hydra.admin_url is set, by the file or DISPATCHER_HYDRA_ADMIN_URL; remove it, the two may differ"},
		{"DISPATCHER_* wins", "", map[string]string{"HYDRA_ADMIN_BASE_URL": admin, "DISPATCHER_HYDRA_ADMIN_URL": "http://env:4445"}, "http://env:4445",
			"HYDRA_ADMIN_BASE_URL (Symfony) is ignored: hydra.admin_url is set"},
		{"over the file", "hydra: {admin_url: http://file:4445}\n", map[string]string{"DISPATCHER_HYDRA_ADMIN_URL": "http://env:4445"}, "http://env:4445", ""},
		{"referenced by the file", "hydra: {admin_url: \"${HYDRA_ADMIN_BASE_URL}\"}\n", map[string]string{"HYDRA_ADMIN_BASE_URL": admin}, admin, ""},
		{"none", "", nil, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := required(tt.env)
			if _, ok := tt.env["DISPATCHER_HYDRA_ADMIN_URL"]; !ok {
				delete(env, "DISPATCHER_HYDRA_ADMIN_URL")
			}
			path := ""
			if tt.file != "" {
				path = writeFile(t, tt.file)
			}
			c, warnings, err := Load(path, envOf(env))
			if tt.want == "" {
				if err == nil || !strings.Contains(err.Error(), "hydra.admin_url: is required") {
					t.Fatalf("err = %v, want hydra.admin_url required", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Hydra.AdminURL != tt.want {
				t.Errorf("hydra.admin_url = %q, want %q", c.Hydra.AdminURL, tt.want)
			}
			if tt.warning == "" && hasWarning(warnings, "HYDRA_ADMIN_BASE_URL") || tt.warning != "" && !hasWarning(warnings, tt.warning) {
				t.Errorf("warnings:\n%s\nwant %q", strings.Join(warnings, "\n"), tt.warning)
			}
		})
	}

	// A default the variable replaces, below the file and DISPATCHER_*.
	c, _, err := Load("", envOf(required(map[string]string{"WEBHOOK_PROCESS_TIMEOUT": "2.5"})))
	if err != nil || c.Webhooks.ProcessTimeout != Duration(2500*time.Millisecond) {
		t.Errorf("WEBHOOK_PROCESS_TIMEOUT=2.5: %v, %v", c.Webhooks.ProcessTimeout.Std(), err)
	}
	// A variable a set key leaves aside is not translated: its error does not stop.
	_, warnings, err := Load("", envOf(required(map[string]string{"TRUSTED_PROXIES": "REMOTE_ADDR"})))
	if err != nil || !hasWarning(warnings, "TRUSTED_PROXIES (Symfony) is ignored") {
		t.Errorf("err = %v, warnings %q", err, warnings)
	}
}

// TestLegacyValues checks what each variable becomes, on top of the required keys
// it leaves set (base and trusted removed for those two).
func TestLegacyValues(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  map[string]string
		get  func(*Config) string
		want string
		// warning, or the error when err.
		warning string
		err     bool
	}{
		// server.base_url
		{name: "BASE_URL", env: map[string]string{"BASE_URL": "https://login.example/", "BASE_PATH": "/x", "SERVER_NAME": "http://a"},
			get: baseURL, want: "https://login.example", warning: "the value of BASE_URL; BASE_PATH and SERVER_NAME unused"},
		{name: "BASE_URL of Symfony's default", env: map[string]string{"BASE_URL": "//", "SERVER_NAME": "https://login.example"},
			get: baseURL, want: "https://login.example", warning: "BASE_URL and SERVER_NAME (Symfony) are read as server.base_url"},
		{name: "BASE_URL relative", env: map[string]string{"BASE_URL": "//login.example", "SERVER_NAME": "https://login.example:443", "BASE_PATH": "/dispatcher/"},
			get: baseURL, want: "https://login.example/dispatcher", warning: "BASE_URL (Symfony) is not an absolute http(s) URL"},
		{name: "BASE_PATH absolute", env: map[string]string{"BASE_PATH": "http://dispatcher.hydra.test"},
			get: baseURL, want: "http://dispatcher.hydra.test", warning: "the value of BASE_PATH, an absolute URL"},
		{name: "BASE_PATH after SERVER_NAME", env: map[string]string{"BASE_PATH": "auth", "SERVER_NAME": "http://login.example:8080"},
			get: baseURL, want: "http://login.example:8080/auth"},
		{name: "BASE_PATH empty", env: map[string]string{"BASE_PATH": "", "SERVER_NAME": "http://login.example:80"},
			get: baseURL, want: "http://login.example"},
		{name: "SERVER_NAME without scheme", env: map[string]string{"SERVER_NAME": "login.example"},
			warning: `SERVER_NAME (Symfony) "login.example" is not one http:// or https:// address`, err: true},
		{name: "SERVER_NAME of two addresses", env: map[string]string{"SERVER_NAME": "http://a, http://b"},
			warning: "is not one http:// or https:// address", err: true},
		{name: "BASE_PATH without SERVER_NAME", env: map[string]string{"BASE_PATH": "/auth"},
			warning: "BASE_PATH (Symfony) is a path, which needs SERVER_NAME: set server.base_url", err: true},
		{name: "SERVER_NAME in uppercase", env: map[string]string{"SERVER_NAME": "http://Login.example"},
			warning: "server.base_url: \"http://Login.example\": write its host in lowercase", err: true},

		// server.trusted_proxies (Q81)
		{name: "REMOTE_ADDR among others", env: map[string]string{"TRUSTED_PROXIES": "REMOTE_ADDR, 10.0.0.10"},
			get: trusted, want: "10.0.0.10", warning: "a reverse proxy outside them passes its own address for that of all its clients"},
		{name: "REMOTE_ADDR alone", env: map[string]string{"TRUSTED_PROXIES": "REMOTE_ADDR"},
			warning: "TRUSTED_PROXIES (server.trusted_proxies): REMOTE_ADDR alone makes every caller a trusted proxy", err: true},
		{name: "PRIVATE_SUBNETS", env: map[string]string{"TRUSTED_PROXIES": "PRIVATE_SUBNETS"},
			get: trusted, want: "127.0.0.0/8,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,169.254.0.0/16,0.0.0.0/8,240.0.0.0/4,::1/128,fc00::/7,fe80::/10,::/128"},
		{name: "no proxy", env: map[string]string{"TRUSTED_PROXIES": ""}, get: trusted, want: ""},

		// state.redis_dsn
		{name: "Redis", env: map[string]string{"REDIS_DSN": "redis://redis:6379/2"}, get: redisDSN, want: "redis://redis:6379/2"},
		{name: "Redis password", env: map[string]string{"REDIS_DSN": "rediss://s3cret@redis:6380"},
			get: redisDSN, want: "rediss://:s3cret@redis:6380", warning: "is given as redis://:password@"},
		{name: "Redis user and password", env: map[string]string{"REDIS_DSN": "redis://app:s3cret@redis"}, get: redisDSN, want: "redis://app:s3cret@redis"},
		{name: "Valkey", env: map[string]string{"REDIS_DSN": "valkey://redis"}, get: redisDSN, want: "redis://redis"},
		{name: "no Redis", env: map[string]string{"REDIS_DSN": ""}, get: redisDSN, want: ""},
		{name: "Redis cluster", env: map[string]string{"REDIS_DSN": "redis:?host[r1:6379]&host[r2:6379]&redis_cluster=1"},
			warning: "REDIS_DSN (state.redis_dsn): its query holds options of Symfony", err: true},
		{name: "Redis option", env: map[string]string{"REDIS_DSN": "redis://s3cret@redis?timeout=3"}, warning: "its query holds options of Symfony", err: true},
		{name: "Redis socket", env: map[string]string{"REDIS_DSN": "redis:///var/run/redis.sock"}, warning: "names no host", err: true},
		{name: "Memcached", env: map[string]string{"REDIS_DSN": "memcached://m"}, warning: "is not a redis:", err: true},

		// The others.
		{name: "ADMIN_UI_ENABLED", env: map[string]string{"ADMIN_UI_ENABLED": "0"}, get: func(c *Config) string { return fmtAny(c.Admin.UI.Enabled) }, want: "false"},
		{name: "ADMIN_UI_ENABLED yes", env: map[string]string{"ADMIN_UI_ENABLED": "Yes"}, get: func(c *Config) string { return fmtAny(c.Admin.UI.Enabled) }, want: "true"},
		{name: "ADMIN_UI_ENABLED word", env: map[string]string{"ADMIN_UI_ENABLED": "enabled"}, get: func(c *Config) string { return fmtAny(c.Admin.UI.Enabled) }, want: "false"},
		{name: "HYDRA_HTTP_MAX_DURATION", env: map[string]string{"HYDRA_HTTP_MAX_DURATION": "7"}, get: func(c *Config) string { return c.Hydra.Timeout.Std().String() }, want: "7s"},
		{name: "WEBHOOK_PROCESS_TIMEOUT", env: map[string]string{"WEBHOOK_PROCESS_TIMEOUT": "five"}, warning: `"five" is not a number of seconds`, err: true},
		{name: "COOKIE_PATH", env: map[string]string{"COOKIE_PATH": "/"}, get: func(c *Config) string { return c.Server.CookiePath }, want: "/"},
		{name: "SENTRY", env: map[string]string{"SENTRY_DSN": "https://k@sentry.example/1", "SENTRY_ENVIRONMENT": "prod", "SENTRY_RELEASE": "r"},
			get: func(c *Config) string {
				s := c.Observability.Sentry
				return s.DSN + " " + s.Environment + " " + s.Release
			}, want: "https://k@sentry.example/1 prod r", warning: "observability.sentry.sample_rate is 1 by default, where Symfony sent 0.25 of the errors"},
		{name: "SENTRY_DSN empty", env: map[string]string{"SENTRY_DSN": ""}, get: func(c *Config) string { return c.Observability.Sentry.DSN }, want: ""},
		{name: "OAUTH2_TOKEN_TTL", env: map[string]string{"OAUTH2_TOKEN_TTL": "900"}, get: func(c *Config) string { return c.Admin.API.TokenTTL.Std().String() }, want: "15m0s"},
		{name: "DATABASE_URL", env: map[string]string{"DATABASE_URL": "postgresql://u:p@db:5432/d?serverVersion=17&charset=utf8&sslmode=require"},
			get: func(c *Config) string { return c.Store.DSN }, want: "postgresql://u:p@db:5432/d?sslmode=require"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := required(tt.env)
			for _, own := range []struct{ legacy, key string }{
				{"BASE_URL", "DISPATCHER_SERVER_BASE_URL"}, {"BASE_PATH", "DISPATCHER_SERVER_BASE_URL"}, {"SERVER_NAME", "DISPATCHER_SERVER_BASE_URL"},
				{"TRUSTED_PROXIES", "DISPATCHER_SERVER_TRUSTED_PROXIES"}, {"DATABASE_URL", "DISPATCHER_STORE_DSN"},
			} {
				if _, ok := tt.env[own.legacy]; ok {
					delete(env, own.key)
				}
			}
			c, warnings, err := Load("", envOf(env))
			text := strings.Join(warnings, "\n")
			if err != nil {
				text += "\n" + err.Error()
			}
			switch {
			case tt.err != (err != nil):
				t.Fatalf("err = %v, want an error: %v; warnings:\n%s", err, tt.err, strings.Join(warnings, "\n"))
			case tt.warning != "" && !strings.Contains(text, tt.warning):
				t.Errorf("warnings and error:\n%s\nwant %q", text, tt.warning)
			case tt.err:
				for _, secret := range []string{"s3cret"} {
					if strings.Contains(text, secret) {
						t.Errorf("a secret is quoted:\n%s", text)
					}
				}
			default:
				if got := tt.get(c); got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func baseURL(c *Config) string  { return c.Server.BaseURL }
func trusted(c *Config) string  { return strings.Join(*c.Server.TrustedProxies, ",") }
func redisDSN(c *Config) string { return c.State.RedisDSN }

// TestLegacyRedisReadByGoRedis checks that the translations parse as go-redis reads
// them: the password where Symfony reads it.
func TestLegacyRedisReadByGoRedis(t *testing.T) {
	for _, tt := range []struct{ dsn, user, password, addr string }{
		{"redis://s3cret@redis:6379", "", "s3cret", "redis:6379"},
		{"redis://default:s3cret@redis", "default", "s3cret", "redis:6379"},
		{"rediss://redis/3", "", "", "redis:6379"},
	} {
		value, _, ok, err := legacyRedisDSN(lookupIn([]string{"REDIS_DSN=" + tt.dsn}))
		if !ok || err != nil {
			t.Fatalf("%s: %v", tt.dsn, err)
		}
		o, err := redis.ParseURL(value)
		if err != nil {
			t.Fatalf("%s: %v", tt.dsn, err)
		}
		if o.Username != tt.user || o.Password != tt.password || o.Addr != tt.addr {
			t.Errorf("%s: user %q, password %q, addr %q", tt.dsn, o.Username, o.Password, o.Addr)
		}
	}
}

// TestWithoutDoctrine checks what store.dsn loses, whatever its source.
func TestWithoutDoctrine(t *testing.T) {
	for _, tt := range []struct {
		dsn, want string
		dropped   []string
	}{
		{"postgresql://u:p@db/d?serverVersion=17&charset=utf8", "postgresql://u:p@db/d", []string{"charset", "serverVersion"}},
		{"postgres://u@db/d?sslmode=disable&serverVersion=16", "postgres://u@db/d?sslmode=disable", []string{"serverVersion"}},
		{"postgres://u@db/d?defaultTableOptions[charset]=utf8", "postgres://u@db/d", []string{"defaultTableOptions[charset]"}},
		{"postgres://u@db/d?sslmode=disable", "postgres://u@db/d?sslmode=disable", nil},
		{"host=db dbname=d", "host=db dbname=d", nil},
	} {
		got, dropped := withoutDoctrine(tt.dsn)
		if got != tt.want || !slices.Equal(dropped, tt.dropped) {
			t.Errorf("%s: %q %q, want %q %q", tt.dsn, got, dropped, tt.want, tt.dropped)
		}
	}
	// From the file, with a warning, and no warning of DATABASE_URL, the file's.
	env := required(map[string]string{"DATABASE_URL": "postgresql://u:p@db/d?serverVersion=17"})
	delete(env, "DISPATCHER_STORE_DSN")
	c, warnings, err := Load(writeFile(t, "store: {dsn: \"${DATABASE_URL}\"}\n"), envOf(env))
	if err != nil || c.Store.DSN != "postgresql://u:p@db/d" {
		t.Fatalf("%v, %q", err, c.Store.DSN)
	}
	if !hasWarning(warnings, "store.dsn: serverVersion dropped") || hasWarning(warnings, "DATABASE_URL") {
		t.Errorf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
}
