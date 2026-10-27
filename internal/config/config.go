// Package config loads the dispatcher configuration: one YAML file describing
// the infrastructure plus, in its dispatcher: block, the seed bootstrap writes
// to the database. Every value accepts ${VAR} and ${VAR:-default}, and a
// DISPATCHER_<SECTION>_<KEY> variable overrides any infrastructure key.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	Observability Observability `yaml:"observability"`
	Webhooks      Webhooks      `yaml:"webhooks"`
	Logout        Logout        `yaml:"logout"`
	Serve         Serve         `yaml:"serve"`

	// Seed is only read by bootstrap; DISPATCHER_* variables do not reach it.
	Seed Seed `yaml:"dispatcher"`
}

type Server struct {
	Listen         string `yaml:"listen"`
	BaseURL        string `yaml:"base_url"`
	TrustedProxies List   `yaml:"trusted_proxies"`
	CookiePath     string `yaml:"cookie_path"`
	// ReplicasHint > 1 refuses the in-memory state store.
	ReplicasHint int `yaml:"replicas_hint"`
}

type Hydra struct {
	AdminURL string   `yaml:"admin_url"`
	Timeout  Duration `yaml:"timeout"`
	// SystemSecrets is Hydra's secrets.system, in Hydra's order; empty means
	// the fallback mode (challenges validated by the admin API).
	SystemSecrets     List     `yaml:"system_secrets"`
	SystemSecretsFile string   `yaml:"system_secrets_file"`
	LoginConsentTTL   Duration `yaml:"login_consent_ttl"`
	MaxInFlight       int      `yaml:"max_in_flight"`
}

type Security struct {
	AdminAuthorizedHosts List `yaml:"admin_authorized_hosts"`
	// Nil until Load resolves them to the admin list when unset.
	EmulatedAPIAuthorizedHosts *List            `yaml:"emulated_api_authorized_hosts"`
	MetricsAuthorizedHosts     *List            `yaml:"metrics_authorized_hosts"`
	FailureRateLimit           FailureRateLimit `yaml:"failure_rate_limit"`
}

type FailureRateLimit struct {
	Max   int      `yaml:"max"`
	Per   Duration `yaml:"per"`
	Block Duration `yaml:"block"`
}

type Secrets struct {
	CookieKey              Key  `yaml:"cookie_key"`
	EncryptionKey          Key  `yaml:"encryption_key"`
	EncryptionKeysPrevious Keys `yaml:"encryption_keys_previous"`
	ChallengeKey           Key  `yaml:"challenge_key"`
	WebhookSigningKey      Key  `yaml:"webhook_signing_key"`
}

type TLS struct {
	MinVersion            string `yaml:"min_version"`
	CAFile                string `yaml:"ca_file"`
	PinnedSPKISHA256      List   `yaml:"pinned_spki_sha256"`
	HSTSIncludeSubdomains bool   `yaml:"hsts_include_subdomains"`
}

type State struct {
	// RedisDSN set selects Redis; empty selects the in-memory store.
	RedisDSN  string `yaml:"redis_dsn"`
	KeyPrefix string `yaml:"key_prefix"`
	// RedisPoolSize 0 lets the client size the pool (10 per CPU).
	RedisPoolSize int `yaml:"redis_pool_size"`
}

type Remember struct {
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
		Enabled            bool     `yaml:"enabled"`
		PrivateKey         string   `yaml:"private_key"`
		PublicKey          string   `yaml:"public_key"`
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
	DefaultLocale    string          `yaml:"default_locale"`
	SupportedLocales List            `yaml:"supported_locales"`
}

type Observability struct {
	LogLevel         string   `yaml:"log_level"`
	LogFormat        string   `yaml:"log_format"`
	AccessLogSample  float64  `yaml:"access_log_sample"`
	LogIP            string   `yaml:"log_ip"`
	DebugMaxDuration Duration `yaml:"debug_max_duration"`
	Sentry           struct {
		DSN                string  `yaml:"dsn"`
		Environment        string  `yaml:"environment"`
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
}

type Logout struct {
	PropagateWithoutRecord string `yaml:"propagate_without_record"`
}

// Serve lets `dispatcher serve` migrate and bootstrap at startup, for
// development; production prefers the explicit subcommands.
type Serve struct {
	Migrate   bool `yaml:"migrate"`
	Bootstrap bool `yaml:"bootstrap"`
}

var privateNetworks = List{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// defaults returns the values of the design document for every key a file
// may omit.
func defaults() *Config {
	c := &Config{}
	c.Server.Listen = ":8080"
	c.Server.TrustedProxies = append(List{}, privateNetworks...)
	c.Server.CookiePath = "/"
	c.Hydra.Timeout = Duration(5 * time.Second)
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
	c.UI.DefaultLocale = "fr"
	c.UI.SupportedLocales = List{"fr", "en"}
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
	return c
}

// Load reads the configuration file at path (none when path is empty),
// applies the environment and validates the result. lookupEnv is
// os.LookupEnv outside tests. Warnings report accepted but dubious settings.
func Load(path string, lookupEnv func(string) (string, bool)) (*Config, []string, error) {
	c := defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		if err := decodeFile(data, c, lookupEnv); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if err := applyEnv(c, lookupEnv); err != nil {
		return nil, nil, err
	}
	if err := c.resolve(); err != nil {
		return nil, nil, err
	}
	warnings := c.Seed.ignoredKeys()
	validationWarnings, err := c.validate()
	return c, append(warnings, validationWarnings...), err
}

// decodeFile expands ${VAR} in every value, then decodes strictly: an
// unknown key is an error, so typos do not pass silently.
func decodeFile(data []byte, c *Config, lookupEnv func(string) (string, bool)) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Kind == 0 { // empty file
		return nil
	}
	expandNode(&doc, lookupEnv)
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// resolve fills the values that default to other values, and reads the
// secrets given as files.
func (c *Config) resolve() error {
	if c.Security.EmulatedAPIAuthorizedHosts == nil {
		l := append(List{}, c.Security.AdminAuthorizedHosts...)
		c.Security.EmulatedAPIAuthorizedHosts = &l
	}
	if c.Security.MetricsAuthorizedHosts == nil {
		l := append(List{}, c.Security.AdminAuthorizedHosts...)
		c.Security.MetricsAuthorizedHosts = &l
	}
	if c.Hydra.SystemSecretsFile != "" {
		if len(c.Hydra.SystemSecrets) > 0 {
			return errors.New("hydra.system_secrets and hydra.system_secrets_file are exclusive")
		}
		data, err := os.ReadFile(c.Hydra.SystemSecretsFile)
		if err != nil {
			return fmt.Errorf("hydra.system_secrets_file: %w", err)
		}
		c.Hydra.SystemSecrets = splitList(strings.ReplaceAll(string(data), "\n", ","))
	}
	return nil
}
