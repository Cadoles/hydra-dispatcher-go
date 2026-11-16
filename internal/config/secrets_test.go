package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// secretFileOf writes content to a file of its own.
func secretFileOf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every secret key may be given by a file (Q87): the file gives it its value, the key
// and its file together are an error, and so is a file that cannot be read or gives
// no value.
func TestSecretFiles(t *testing.T) {
	keyA, keyB := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	for _, tt := range []struct {
		name    string
		env     map[string]string // besides required(), less what each one gives
		content string
		get     func(*Config) any
		want    any
	}{
		{"cookie_key", map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY": ""}, keyA + "\n",
			func(c *Config) any { return c.Secrets.CookieKey }, mustKey(t, keyA)},
		{"cookie_keys_previous", nil, keyA + "\r\n\n" + keyB + "\n",
			func(c *Config) any { return c.Secrets.CookieKeysPrevious }, Keys{mustKey(t, keyA), mustKey(t, keyB)}},
		{"encryption_key", nil, keyA, func(c *Config) any { return c.Secrets.EncryptionKey }, mustKey(t, keyA)},
		{"encryption_keys_previous", map[string]string{"DISPATCHER_SECRETS_ENCRYPTION_KEY": keyB}, keyA,
			func(c *Config) any { return c.Secrets.EncryptionKeysPrevious }, Keys{mustKey(t, keyA)}},
		{"challenge_key", map[string]string{"DISPATCHER_SECRETS_CHALLENGE_KEY": ""}, keyA,
			func(c *Config) any { return c.Secrets.ChallengeKey }, mustKey(t, keyA)},
		{"challenge_keys_previous", nil, "", func(c *Config) any { return c.Secrets.ChallengeKeysPrevious }, Keys{}},
		{"webhook_signing_key", nil, keyA, func(c *Config) any { return c.Secrets.WebhookSigningKey }, mustKey(t, keyA)},
		{"audit_key", nil, keyA, func(c *Config) any { return c.Secrets.AuditKey }, mustKey(t, keyA)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := required(tt.env)
			for k, v := range tt.env {
				if v == "" {
					delete(env, k)
				}
			}
			env["DISPATCHER_SECRETS_"+strings.ToUpper(tt.name)+"_FILE"] = secretFileOf(t, tt.content)
			c, _, err := Load("", envOf(env))
			if err != nil {
				t.Fatal(err)
			}
			if got := tt.get(c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%v, want %v", got, tt.want)
			}
		})
	}

	t.Run("DSNs and the private key", func(t *testing.T) {
		env := required(map[string]string{
			"DISPATCHER_STORE_DSN_FILE":             secretFileOf(t, "postgres://u:p@db/d?serverVersion=17\n"),
			"DISPATCHER_STATE_REDIS_DSN_FILE":       secretFileOf(t, "redis://:p@redis:6379/0"),
			"DISPATCHER_ADMIN_API_PRIVATE_KEY_FILE": secretFileOf(t, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		})
		delete(env, "DISPATCHER_STORE_DSN")
		c, warnings, err := Load("", envOf(env))
		if err != nil {
			t.Fatal(err)
		}
		// Read before the parameters of Doctrine are dropped.
		if c.Store.DSN != "postgres://u:p@db/d" || c.State.RedisDSN != "redis://:p@redis:6379/0" ||
			c.Admin.API.PrivateKey != "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" {
			t.Errorf("store %q, state %q, private key %q", c.Store.DSN, c.State.RedisDSN, c.Admin.API.PrivateKey)
		}
		if !hasWarning(warnings, "store.dsn: serverVersion dropped") {
			t.Errorf("warnings %q", warnings)
		}
	})

	for _, tt := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"the key and its file", map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY_FILE": secretFileOf(t, keyA)},
			"secrets.cookie_key and secrets.cookie_key_file are exclusive"},
		{"a DSN and its file", map[string]string{"DISPATCHER_STORE_DSN_FILE": secretFileOf(t, "postgres://db/d")},
			"store.dsn and store.dsn_file are exclusive"},
		{"a missing file", map[string]string{"DISPATCHER_SECRETS_AUDIT_KEY_FILE": "/nonexistent/key"},
			"secrets.audit_key_file: open /nonexistent/key: no such file or directory"},
		{"an empty file", map[string]string{"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY_FILE": secretFileOf(t, "\n")},
			"secrets.webhook_signing_key_file: holds no key"},
		{"a wrong key", map[string]string{"DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY_FILE": secretFileOf(t, "s3cret")},
			"secrets.webhook_signing_key_file: key must be 32 bytes"},
		{"a wrong previous key", map[string]string{"DISPATCHER_SECRETS_COOKIE_KEYS_PREVIOUS_FILE": secretFileOf(t, keyA+"\ns3cret\n")},
			"secrets.cookie_keys_previous_file: line 2: key must be 32 bytes"},
		{"an empty DSN", map[string]string{"DISPATCHER_STATE_REDIS_DSN_FILE": secretFileOf(t, " ")},
			"state.redis_dsn_file: is empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Load("", envOf(required(tt.env)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the error quotes the file: %v", err)
			}
		})
	}
}

func mustKey(t *testing.T, s string) Key {
	t.Helper()
	k, err := parseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// EnvironmentSecrets names the secret keys the environment gave, whatever the way: a
// DISPATCHER_* variable, a ${VAR} of the file, a variable of the Symfony dispatcher;
// not a value of the file, a file, nor a DSN without a password.
func TestEnvironmentSecrets(t *testing.T) {
	keyFile := secretFileOf(t, strings.Repeat("e5", 32))
	for _, tt := range []struct {
		name string
		file string
		env  map[string]string
		want []string
	}{
		// required() gives a store.dsn with a password.
		{"DISPATCHER_* variables", "", nil, []string{"secrets.cookie_key", "secrets.challenge_key", "store.dsn"}},
		{"values of the file", "secrets: {cookie_key: \"" + hexKey + "\", challenge_key: \"" + base64Key + "\"}\nstore: {dsn: \"postgres://u:p@db/d\"}\n",
			map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY": "", "DISPATCHER_SECRETS_CHALLENGE_KEY": "", "DISPATCHER_STORE_DSN": ""}, nil},
		// R30: the variable, not the file, gives the key.
		{"values of the file replaced by DISPATCHER_* variables", "secrets: {cookie_key: \"" + hexKey3 + "\", challenge_key: \"" + base64Key + "\"}\nstore: {dsn: \"postgres://u:p@db/d\"}\n",
			map[string]string{"DISPATCHER_SECRETS_CHALLENGE_KEY": ""}, []string{"secrets.cookie_key", "store.dsn"}},
		{"${VAR} of the file", "secrets:\n  cookie_key: \"" + hexKey + "\"\n  challenge_keys_previous: [\"${OLD}\"]\nstore: {dsn: \"postgres://u:${PGPASSWORD}@db/d\"}\n",
			map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY": "", "DISPATCHER_STORE_DSN": "", "OLD": hexKey3, "PGPASSWORD": "p"},
			[]string{"secrets.challenge_key", "secrets.challenge_keys_previous", "store.dsn"}},
		{"files", "", map[string]string{"DISPATCHER_SECRETS_COOKIE_KEY": "", "DISPATCHER_SECRETS_COOKIE_KEY_FILE": keyFile},
			[]string{"secrets.challenge_key", "store.dsn"}},
		{"Symfony's DATABASE_URL and the system secrets", "", map[string]string{"DISPATCHER_STORE_DSN": "", "DATABASE_URL": "postgres://u:p@db/d",
			"DISPATCHER_HYDRA_SYSTEM_SECRETS": "youReallyNeedToChangeThis", "DISPATCHER_STATE_REDIS_DSN": "redis://redis:6379"},
			[]string{"secrets.cookie_key", "secrets.challenge_key", "store.dsn", "hydra.system_secrets"}},
		// R30: the secret of an API client of the seed, by a ${VAR} as the warning of
		// OAUTH2_ADMIN_CLIENT_* advises, or by its file; one written in the file is not
		// named.
		{"secrets of the seed", "dispatcher:\n  oauth2_clients:\n    - { id: a, secret: \"${OAUTH2_ADMIN_CLIENT_SECRET}\" }\n    - { id: b, secret: s3cret }\n    - { id: c, secret_file: " + secretFileOf(t, "c-secret\n") + " }\n",
			map[string]string{"OAUTH2_ADMIN_CLIENT_SECRET": "a-secret"},
			[]string{"secrets.cookie_key", "secrets.challenge_key", "store.dsn", "dispatcher.oauth2_clients[0].secret"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := required(tt.env)
			for k, v := range tt.env {
				if v == "" {
					delete(env, k)
				}
			}
			path := ""
			if tt.file != "" {
				path = writeFile(t, tt.file)
			}
			c, _, err := Load(path, envOf(env))
			if err != nil {
				t.Fatal(err)
			}
			if got := c.EnvironmentSecrets(); !slices.Equal(got, tt.want) {
				t.Errorf("%q, want %q", got, tt.want)
			}
		})
	}
}

// The secret of an API client of the seed by its file: trimmed, exclusive of
// secret, and its absence still refused.
func TestSeedClientSecretFile(t *testing.T) {
	c, _, err := load(t, "dispatcher:\n  oauth2_clients:\n    - { id: c, secret_file: "+secretFileOf(t, "  s3cret\n")+" }\n", nil)
	if err != nil || c.Seed.OAuth2Clients[0].Secret != "s3cret" {
		t.Fatalf("secret = %q, %v", c.Seed.OAuth2Clients[0].Secret, err)
	}
	for content, want := range map[string]string{
		"dispatcher:\n  oauth2_clients:\n    - { id: c, secret: s, secret_file: " + secretFileOf(t, "s3cret") + " }\n": "dispatcher.oauth2_clients[0].secret and dispatcher.oauth2_clients[0].secret_file are exclusive",
		"dispatcher:\n  oauth2_clients:\n    - { id: c, secret_file: " + secretFileOf(t, " \n") + " }\n":               "dispatcher.oauth2_clients[0].secret_file: is empty",
		"dispatcher:\n  oauth2_clients:\n    - { id: c, secret_file: /nonexistent/secret }\n":                          "dispatcher.oauth2_clients[0].secret_file: open /nonexistent/secret",
	} {
		if _, _, err := load(t, content, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}

// The pre-check of an app (phase 4): its key by ${VAR} or by a file, the
// fields to the domain; the URL without the key, which bootstrap fills from
// the database.
func TestSeedSkipCheck(t *testing.T) {
	key := strings.Repeat("0a", 32)
	c, _, err := load(t, `
dispatcher:
  apps:
    - { id: pwd, login_url: https://pwd/login, consent_url: https://pwd/consent, method: pwd }
    - { id: otp, login_url: https://otp/login, consent_url: https://otp/consent, method: otp,
        skip_check_url: https://otp/skip-check, skip_check_key: "${OTP_KEY}", skip_check_signals: "ip, device_age" }
    - { id: totp, login_url: https://totp/login, consent_url: https://totp/consent, method: otp,
        skip_check_url: https://totp/skip-check, skip_check_key_file: `+secretFileOf(t, key+"\n")+` }
    - { id: dump, login_url: https://dump/login, consent_url: https://dump/consent, method: otp,
        skip_check_url: https://dump/skip-check }
  flows:
    - { id: f, title: F, description: D, skip_check_allowed_acr: [loa1, loa2],
        steps: [{ id: pwd, order: 0 }, { id: otp, order: 1, skip_check: true }, { id: totp, order: 2, skip_check: true }] }
`, map[string]string{"OTP_KEY": key})
	if err != nil {
		t.Fatal(err)
	}
	otp, err := c.Seed.Apps[1].App()
	if err != nil || otp.SkipCheckURL != "https://otp/skip-check" || otp.SkipCheckKey != key || !slices.Equal(otp.SkipCheckSignals, []string{"ip", "device_age"}) {
		t.Errorf("otp = %+v, %v", otp, err)
	}
	if totp, _ := c.Seed.Apps[2].App(); totp.SkipCheckKey != key {
		t.Errorf("key by a file: %q", totp.SkipCheckKey)
	}
	if dump, _ := c.Seed.Apps[3].App(); dump.SkipCheckKey != "" || dump.SkipCheckSignals != nil {
		t.Errorf("URL without its key: %+v", dump)
	}
	f := c.Seed.Flows[0].Flow()
	if !slices.Equal(f.SkipCheckAllowedACR, []string{"loa1", "loa2"}) || f.Steps[0].SkipCheck || !f.Steps[1].SkipCheck || !f.Steps[2].SkipCheck {
		t.Errorf("flow = %+v", f)
	}
	if _, _, err := load(t, "dispatcher:\n  apps:\n    - { id: a, login_url: https://a, consent_url: https://a, method: m, skip_check_url: https://a/c, skip_check_key: k, skip_check_key_file: "+secretFileOf(t, key)+" }\n", nil); err == nil ||
		!strings.Contains(err.Error(), "dispatcher.apps[0].skip_check_key and dispatcher.apps[0].skip_check_key_file are exclusive") {
		t.Errorf("key and its file: %v", err)
	}
}
