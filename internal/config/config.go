// Package config loads the dispatcher configuration: one YAML file describing
// the infrastructure plus, in its dispatcher: block, the seed bootstrap writes
// to the database. Every value accepts ${VAR} and ${VAR:-default}, and a
// DISPATCHER_<SECTION>_<KEY> variable overrides any infrastructure key.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server        Server        `yaml:"server"`
	Hydra         Hydra         `yaml:"hydra"`
	Security      Security      `yaml:"security"`
	Secrets       Secrets       `yaml:"secrets"`
	TLS           TLS           `yaml:"tls"`
	State         State         `yaml:"state"`
	Remember      Remember      `yaml:"remember"`
	Store         Store         `yaml:"store"`
	Admin         Admin         `yaml:"admin"`
	UI            UI            `yaml:"ui"`
	EmulatedAPI   EmulatedAPI   `yaml:"emulated_api"`
	Consent       Consent       `yaml:"consent"`
	Observability Observability `yaml:"observability"`
	Webhooks      Webhooks      `yaml:"webhooks"`
	Logout        Logout        `yaml:"logout"`
	Serve         Serve         `yaml:"serve"`

	// Seed is only read by bootstrap; DISPATCHER_* variables do not reach it.
	Seed Seed `yaml:"dispatcher"`
}

type Server struct {
	Listen  string `yaml:"listen"`
	BaseURL string `yaml:"base_url"`
	// TrustedProxies has no default (nil): it is required, [] when clients
	// connect directly.
	TrustedProxies *List  `yaml:"trusted_proxies"`
	CookiePath     string `yaml:"cookie_path"`
	// ReplicasHint > 1 refuses the in-memory state store.
	ReplicasHint int `yaml:"replicas_hint"`
	// DrainDelay is how long, after SIGTERM, /ready answers 503 while the
	// requests are still served, before the shutdown: an orchestrator still
	// routes to the instance for a few seconds (Q82). Distroless has no sleep
	// for a preStop hook.
	DrainDelay Duration `yaml:"drain_delay"`
}

type Hydra struct {
	AdminURL string   `yaml:"admin_url"`
	Timeout  Duration `yaml:"timeout"`
	// Version is the Hydra release: it fixes the format of the challenges
	// SystemSecrets decrypts. Hydra 2.1 does not encrypt them.
	Version string `yaml:"version"`
	// SystemSecrets is Hydra's secrets.system, in Hydra's order; empty means
	// the fallback mode (challenges validated by the admin API).
	SystemSecrets List `yaml:"system_secrets"`
	// SystemSecretsFile holds one secret per line, so a secret may contain a
	// comma. Like every path of the file, a relative one starts from the
	// working directory.
	SystemSecretsFile string   `yaml:"system_secrets_file"`
	LoginConsentTTL   Duration `yaml:"login_consent_ttl"`
	MaxInFlight       int      `yaml:"max_in_flight"`
}

type Security struct {
	AdminAuthorizedHosts List `yaml:"admin_authorized_hosts"`
	// EmulatedAPIAuthorizedHosts has no default (nil): it is required, the
	// networks the login apps call from (B2).
	EmulatedAPIAuthorizedHosts *List `yaml:"emulated_api_authorized_hosts"`
	// Nil until Load resolves it to the admin list when unset.
	MetricsAuthorizedHosts *List            `yaml:"metrics_authorized_hosts"`
	FailureRateLimit       FailureRateLimit `yaml:"failure_rate_limit"`
}

type FailureRateLimit struct {
	Max   int      `yaml:"max"`
	Per   Duration `yaml:"per"`
	Block Duration `yaml:"block"`
}

// Secrets the dispatcher reads back are keyrings: the active key encrypts or
// signs, the previous ones only decrypt or verify, for rotation without
// downtime. The webhook key only signs, receivers verify.
type Secrets struct {
	CookieKey              Key  `yaml:"cookie_key"`
	CookieKeysPrevious     Keys `yaml:"cookie_keys_previous"`
	EncryptionKey          Key  `yaml:"encryption_key"`
	EncryptionKeysPrevious Keys `yaml:"encryption_keys_previous"`
	ChallengeKey           Key  `yaml:"challenge_key"`
	ChallengeKeysPrevious  Keys `yaml:"challenge_keys_previous"`
	WebhookSigningKey      Key  `yaml:"webhook_signing_key"`
	// AuditKey pseudonymises the subjects of the audit log; empty, a key derived from
	// ChallengeKey, whose rotation then changes the pseudonyms (Q75).
	AuditKey Key `yaml:"audit_key"`
}

type TLS struct {
	MinVersion string `yaml:"min_version"`
	// CAFile replaces the system's authorities towards Hydra; the webhooks have
	// their own, Webhooks.CAFile.
	CAFile string `yaml:"ca_file"`
	// AllowHTTP accepts targets in http:// without a word: a webhook in http://
	// is refused without it, Hydra's admin warned about, its TLS coming after the
	// cutover (Q70).
	AllowHTTP             bool `yaml:"allow_http"`
	PinnedSPKISHA256      List `yaml:"pinned_spki_sha256"`
	HSTSIncludeSubdomains bool `yaml:"hsts_include_subdomains"`
}

type State struct {
	// RedisDSN set selects Redis; empty selects the in-memory store.
	RedisDSN  string `yaml:"redis_dsn"`
	KeyPrefix string `yaml:"key_prefix"`
	// RedisPoolSize 0 lets the client size the pool (10 per CPU).
	RedisPoolSize int `yaml:"redis_pool_size"`
}

type Remember struct {
	// Backend is cookie, the dispatcher_remember cookie; postgres, the
	// server variant of the design document, is refused until a lot does it
	// (Q40).
	Backend string `yaml:"backend"`
}

type Store struct {
	Backend string `yaml:"backend"`
	DSN     string `yaml:"dsn"`
}

type Admin struct {
	UI struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"ui"`
	API struct {
		Enabled    bool   `yaml:"enabled"`
		PrivateKey string `yaml:"private_key"`
		PublicKey  string `yaml:"public_key"`
		// PublicKeysPrevious verify the tokens signed before a rotation of
		// PrivateKey, until they expire.
		PublicKeysPrevious List     `yaml:"public_keys_previous"`
		TokenTTL           Duration `yaml:"token_ttl"`
		RateLimitPerMinute int      `yaml:"rate_limit_per_minute"`
	} `yaml:"api"`
	Session struct {
		IdleTimeout  Duration `yaml:"idle_timeout"`
		MaxAge       Duration `yaml:"max_age"`
		ReauthWindow Duration `yaml:"reauth_window"`
	} `yaml:"session"`
	HydraClients struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"hydra_clients"`
	ClientSecretMaxAge Duration `yaml:"client_secret_max_age"`
}

type UI struct {
	ThemeDir         string          `yaml:"theme_dir"`
	Reload           bool            `yaml:"reload"`
	RememberLastFlow bool            `yaml:"remember_last_flow"`
	CSPExtra         map[string]List `yaml:"csp_extra"`
}

type EmulatedAPI struct {
	// LegacyV1Paths serves the v1 paths of the Symfony dispatcher
	// (/oauth2/auth/requests/...) as deprecated aliases, until 1.0.
	LegacyV1Paths bool `yaml:"legacy_v1_paths"`
}

type Consent struct {
	// ClaimsFilter is permissive: the claims outside the scope catalogue are
	// sent too, and listed on the screen. strict waits for the catalogue in
	// the database (phase 3).
	ClaimsFilter string `yaml:"claims_filter"`
	// ShowValues shows the values of the claims on the consent screen.
	ShowValues bool `yaml:"show_values"`
}

// Values of consent.claims_filter.
const (
	ClaimsPermissive = "permissive"
	ClaimsStrict     = "strict"
)

type Observability struct {
	LogLevel         string   `yaml:"log_level"`
	LogFormat        string   `yaml:"log_format"`
	AccessLogSample  float64  `yaml:"access_log_sample"`
	LogIP            string   `yaml:"log_ip"`
	DebugMaxDuration Duration `yaml:"debug_max_duration"`
	Sentry           struct {
		DSN         string `yaml:"dsn"`
		Environment string `yaml:"environment"`
		// Release empty means the version of the binary.
		Release            string  `yaml:"release"`
		SampleRate         float64 `yaml:"sample_rate"`
		TracesSampleRate   float64 `yaml:"traces_sample_rate"`
		MaxEventsPerMinute int     `yaml:"max_events_per_minute"`
	} `yaml:"sentry"`
	Metrics struct {
		Listen         string `yaml:"listen"`
		MaxLabelValues int    `yaml:"max_label_values"`
	} `yaml:"metrics"`
	Audit struct {
		Output              string `yaml:"output"`
		PseudonymizeSubject bool   `yaml:"pseudonymize_subject"`
	} `yaml:"audit"`
	Tracing struct {
		Enabled      bool    `yaml:"enabled"`
		Endpoint     string  `yaml:"endpoint"`
		Protocol     string  `yaml:"protocol"`
		SamplerRatio float64 `yaml:"sampler_ratio"`
	} `yaml:"tracing"`
}

type Webhooks struct {
	ProcessTimeout Duration `yaml:"process_timeout"`
	MaxProcesses   int      `yaml:"max_processes"`
	// CAFile replaces the system's authorities towards the webhooks; empty keeps
	// them, whatever tls.ca_file says of Hydra (Q71).
	CAFile string `yaml:"ca_file"`
}

type Logout struct {
	PropagateWithoutRecord string `yaml:"propagate_without_record"`
}

// Serve lets `hydra-dispatcher serve` migrate and bootstrap at startup, for
// development; production prefers the explicit subcommands.
type Serve struct {
	Migrate bool `yaml:"migrate"`
	// Bootstrap is off, missing (bootstrap) or force (bootstrap --force).
	Bootstrap string `yaml:"bootstrap"`
}

// Values of serve.bootstrap.
const (
	BootstrapOff     = "off"
	BootstrapMissing = "missing"
	BootstrapForce   = "force"
)

var privateNetworks = List{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// DefaultListen is server.listen when neither the file nor
// DISPATCHER_SERVER_LISTEN sets it.
const DefaultListen = ":8080"

// defaults returns the values of the design document for every key a file
// may omit.
func defaults() *Config {
	c := &Config{}
	c.Server.Listen = DefaultListen
	c.Server.CookiePath = "/"
	c.Hydra.Timeout = Duration(5 * time.Second)
	c.Hydra.Version = "2.2"
	c.Hydra.LoginConsentTTL = Duration(30 * time.Minute)
	c.Hydra.MaxInFlight = 512
	c.Security.AdminAuthorizedHosts = append(List{}, privateNetworks...)
	c.Security.FailureRateLimit = FailureRateLimit{Max: 20, Per: Duration(time.Minute), Block: Duration(5 * time.Minute)}
	c.TLS.MinVersion = "1.2"
	c.Remember.Backend = "cookie"
	c.Store.Backend = "postgres"
	c.Admin.UI.Enabled = true
	c.Admin.API.Enabled = true
	c.Admin.API.TokenTTL = Duration(15 * time.Minute)
	c.Admin.API.RateLimitPerMinute = 100
	c.Admin.Session.IdleTimeout = Duration(30 * time.Minute)
	c.Admin.Session.MaxAge = Duration(8 * time.Hour)
	c.Admin.Session.ReauthWindow = Duration(5 * time.Minute)
	c.Admin.HydraClients.Enabled = true
	c.Admin.ClientSecretMaxAge = Duration(365 * 24 * time.Hour)
	c.UI.RememberLastFlow = true
	c.EmulatedAPI.LegacyV1Paths = true
	c.Consent.ClaimsFilter = ClaimsPermissive
	c.Observability.LogLevel = "info"
	c.Observability.LogFormat = "json"
	c.Observability.AccessLogSample = 1
	c.Observability.LogIP = "truncated"
	c.Observability.DebugMaxDuration = Duration(time.Hour)
	c.Observability.Sentry.SampleRate = 1
	c.Observability.Sentry.MaxEventsPerMinute = 60
	c.Observability.Metrics.MaxLabelValues = 200
	c.Observability.Audit.Output = "stdout"
	c.Observability.Audit.PseudonymizeSubject = true
	c.Observability.Tracing.Protocol = "grpc"
	c.Observability.Tracing.SamplerRatio = 0.01
	c.Webhooks.ProcessTimeout = Duration(5 * time.Second)
	c.Webhooks.MaxProcesses = 32
	c.Logout.PropagateWithoutRecord = "all"
	c.Serve.Bootstrap = BootstrapOff
	return c
}

// Load reads the configuration file at path (none when path is empty),
// applies the environment (os.Environ() outside tests), the variables of the
// Symfony dispatcher in fallback, and validates the result. Warnings report
// accepted but dubious settings; they come with an error too, which a
// mistyped variable may explain.
func Load(path string, environ []string) (*Config, []string, error) {
	lookupEnv := lookupIn(environ)
	c := defaults()
	referenced := map[string]bool{}
	set := map[string]bool{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		lookupRef := func(name string) (string, bool) {
			referenced[name] = true
			return lookupEnv(name)
		}
		if set, err = decodeFile(data, c, lookupRef); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	warnings := unknownOverrides(environ, referenced)
	if err := applyEnv(c, lookupEnv, set); err != nil {
		return nil, warnings, err
	}
	legacyWarnings, err := applyLegacy(c, environ, lookupEnv, set, referenced)
	warnings = append(warnings, legacyWarnings...)
	if err != nil {
		return nil, warnings, err
	}
	resolveWarnings, err := c.resolve()
	warnings = append(warnings, resolveWarnings...)
	if err != nil {
		return nil, warnings, err
	}
	warnings = append(warnings, c.Seed.warnings()...)
	validationWarnings, err := c.validate()
	return c, append(warnings, validationWarnings...), err
}

// resolve fills the values that default to other values, reads the
// secrets given as files, and drops from store.dsn what Doctrine's
// DATABASE_URL holds and Postgres refuses.
func (c *Config) resolve() (warnings []string, err error) {
	c.Seed.resolve()
	var dropped []string
	if c.Store.DSN, dropped = withoutDoctrine(c.Store.DSN); len(dropped) > 0 {
		warnings = append(warnings, fmt.Sprintf("store.dsn: %s dropped, parameters of Doctrine that Postgres refuses", strings.Join(dropped, ", ")))
	}
	if c.Security.MetricsAuthorizedHosts == nil {
		l := append(List{}, c.Security.AdminAuthorizedHosts...)
		c.Security.MetricsAuthorizedHosts = &l
	}
	if c.Hydra.SystemSecretsFile != "" {
		if len(c.Hydra.SystemSecrets) > 0 {
			return warnings, errors.New("hydra.system_secrets and hydra.system_secrets_file are exclusive")
		}
		data, err := os.ReadFile(c.Hydra.SystemSecretsFile)
		if err != nil {
			return warnings, fmt.Errorf("hydra.system_secrets_file: %w", err)
		}
		c.Hydra.SystemSecrets = List{}
		for line := range strings.Lines(string(data)) {
			if line = strings.TrimSpace(line); line != "" {
				c.Hydra.SystemSecrets = append(c.Hydra.SystemSecrets, line)
			}
		}
		if len(c.Hydra.SystemSecrets) == 0 {
			// A secret not provisioned yet, rather than the fallback mode.
			return warnings, errors.New("hydra.system_secrets_file: holds no secret; for the fallback mode, leave the key empty")
		}
	}
	return warnings, nil
}
