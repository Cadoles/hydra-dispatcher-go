package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
)

// validate checks what the dispatcher needs to start. It reports every
// problem at once, each with the path of its key.
func (c *Config) validate() (warnings []string, err error) {
	var errs []error
	fail := func(path, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
	}
	oneOf := func(path, value string, allowed ...string) {
		if !slices.Contains(allowed, value) {
			fail(path, "%q is not one of %s", value, strings.Join(allowed, ", "))
		}
	}
	ratio := func(path string, v float64) {
		if v < 0 || v > 1 {
			fail(path, "%v is not between 0 and 1", v)
		}
	}
	positive := func(path string, v int64) {
		if v <= 0 {
			fail(path, "must be positive")
		}
	}

	if c.Server.Listen == "" {
		fail("server.listen", "is required")
	}
	if err := httpURL(c.Server.BaseURL); err != nil {
		fail("server.base_url", "%v", err)
	}
	if _, err := c.Server.TrustedProxies.Prefixes(); err != nil {
		fail("server.trusted_proxies", "%v", err)
	}
	if c.Server.ReplicasHint > 1 && c.State.RedisDSN == "" {
		fail("state.redis_dsn", "is required when server.replicas_hint is above 1: the in-memory store is not shared")
	}

	if err := httpURL(c.Hydra.AdminURL); err != nil {
		fail("hydra.admin_url", "%v", err)
	}
	positive("hydra.timeout", int64(c.Hydra.Timeout))
	positive("hydra.login_consent_ttl", int64(c.Hydra.LoginConsentTTL))
	positive("hydra.max_in_flight", int64(c.Hydra.MaxInFlight))
	for i, s := range c.Hydra.SystemSecrets {
		// Hydra itself refuses a first secret under 16 characters.
		if i == 0 && len(s) < 16 {
			fail("hydra.system_secrets", "the first secret is shorter than 16 characters, Hydra refuses it")
		}
	}

	for _, l := range []struct {
		path  string
		hosts List
	}{
		{"security.admin_authorized_hosts", c.Security.AdminAuthorizedHosts},
		{"security.emulated_api_authorized_hosts", *c.Security.EmulatedAPIAuthorizedHosts},
		{"security.metrics_authorized_hosts", *c.Security.MetricsAuthorizedHosts},
	} {
		ps, err := l.hosts.Prefixes()
		if err != nil {
			fail(l.path, "%v", err)
		}
		for _, p := range ps {
			if p.Bits() == 0 {
				warnings = append(warnings, fmt.Sprintf("%s contains %s: open to every address", l.path, p))
			}
		}
	}
	positive("security.failure_rate_limit.max", int64(c.Security.FailureRateLimit.Max))
	positive("security.failure_rate_limit.per", int64(c.Security.FailureRateLimit.Per))

	if c.Secrets.CookieKey == nil {
		fail("secrets.cookie_key", "is required")
	}
	if c.Secrets.ChallengeKey == nil {
		fail("secrets.challenge_key", "is required")
	}

	oneOf("tls.min_version", c.TLS.MinVersion, "1.2", "1.3")
	if c.TLS.CAFile != "" {
		if _, err := os.Stat(c.TLS.CAFile); err != nil {
			fail("tls.ca_file", "%v", err)
		}
	}

	if c.State.RedisDSN != "" {
		if u, err := url.Parse(c.State.RedisDSN); err != nil || !slices.Contains([]string{"redis", "rediss", "unix"}, u.Scheme) {
			fail("state.redis_dsn", "must be a redis://, rediss:// or unix:// URL")
		}
	}
	oneOf("remember.backend", c.Remember.Backend, "cookie", "postgres")
	oneOf("store.backend", c.Store.Backend, "postgres")
	if c.Store.DSN == "" {
		fail("store.dsn", "is required")
	}

	positive("admin.api.token_ttl", int64(c.Admin.API.TokenTTL))
	positive("admin.api.rate_limit_per_minute", int64(c.Admin.API.RateLimitPerMinute))
	positive("admin.session.idle_timeout", int64(c.Admin.Session.IdleTimeout))
	positive("admin.session.max_age", int64(c.Admin.Session.MaxAge))

	if len(c.UI.SupportedLocales) == 0 {
		fail("ui.supported_locales", "is empty")
	} else if !slices.Contains(c.UI.SupportedLocales, c.UI.DefaultLocale) {
		fail("ui.default_locale", "%q is not in ui.supported_locales", c.UI.DefaultLocale)
	}

	o := c.Observability
	oneOf("observability.log_level", o.LogLevel, "debug", "info", "warn", "error")
	oneOf("observability.log_format", o.LogFormat, "json", "text")
	oneOf("observability.log_ip", o.LogIP, "truncated", "full", "none")
	ratio("observability.access_log_sample", o.AccessLogSample)
	ratio("observability.sentry.sample_rate", o.Sentry.SampleRate)
	ratio("observability.sentry.traces_sample_rate", o.Sentry.TracesSampleRate)
	ratio("observability.tracing.sampler_ratio", o.Tracing.SamplerRatio)
	oneOf("observability.tracing.protocol", o.Tracing.Protocol, "grpc", "http/protobuf")
	if out := o.Audit.Output; out != "stdout" && out != "syslog" && !strings.HasPrefix(out, "file:") {
		fail("observability.audit.output", "%q is not stdout, syslog or file:<path>", out)
	}

	positive("webhooks.process_timeout", int64(c.Webhooks.ProcessTimeout))
	positive("webhooks.max_processes", int64(c.Webhooks.MaxProcesses))
	oneOf("logout.propagate_without_record", c.Logout.PropagateWithoutRecord, "all", "none")

	return warnings, errors.Join(errs...)
}

func httpURL(s string) error {
	if s == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q is not an absolute http(s) URL without query", s)
	}
	return nil
}

// Prefixes parses a list of CIDRs; a bare address stands for itself (/32 or
// /128). Load has validated the allowlists and trusted proxies already.
func (l List) Prefixes() ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(l))
	for _, s := range l {
		if p, err := netip.ParsePrefix(s); err == nil {
			ps = append(ps, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is neither a CIDR nor an IP address", s)
		}
		ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
	}
	return ps, nil
}
