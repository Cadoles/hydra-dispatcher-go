package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
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
		if !(v >= 0 && v <= 1) { // NaN included
			fail(path, "%v is not between 0 and 1", v)
		}
	}
	positive := func(path string, v int64) {
		if v <= 0 {
			fail(path, "must be positive")
		}
	}
	nonNegative := func(path string, v int) {
		if v < 0 {
			fail(path, "must not be negative")
		}
	}

	if c.Server.Listen == "" {
		fail("server.listen", "is required")
	}
	if err := httpURL(c.Server.BaseURL); err != nil {
		fail("server.base_url", "%v", err)
	}
	if !strings.HasPrefix(c.Server.CookiePath, "/") {
		fail("server.cookie_path", "%q does not start with /", c.Server.CookiePath)
	}
	nonNegative("server.replicas_hint", c.Server.ReplicasHint)
	if c.State.RedisDSN == "" {
		if c.Server.ReplicasHint > 1 {
			fail("state.redis_dsn", "is required when server.replicas_hint is above 1: the in-memory store is not shared")
		} else {
			warnings = append(warnings, "state.redis_dsn is empty: flows in progress stay in this instance's memory, unshared and lost on restart")
		}
	}

	if err := httpURL(c.Hydra.AdminURL); err != nil {
		fail("hydra.admin_url", "%v", err)
	}
	positive("hydra.timeout", int64(c.Hydra.Timeout))
	positive("hydra.login_consent_ttl", int64(c.Hydra.LoginConsentTTL))
	positive("hydra.max_in_flight", int64(c.Hydra.MaxInFlight))
	// 2.2 and 2.3 are the formats internal/hydra/flowcodec reads.
	oneOf("hydra.version", c.Hydra.Version, "2.1", "2.2", "2.3")
	switch {
	case len(c.Hydra.SystemSecrets) == 0:
	case c.Hydra.Version == "2.1":
		warnings = append(warnings, "hydra.system_secrets is ignored: Hydra 2.1 does not encrypt its challenges")
	case len(c.Hydra.SystemSecrets[0]) < 16:
		// Hydra itself refuses a first secret under 16 characters.
		fail("hydra.system_secrets", "the first secret is shorter than 16 characters, Hydra refuses it")
	}

	admin := c.Security.AdminAuthorizedHosts
	for _, l := range []struct {
		path  string
		hosts List
		open  string // what a /0 network means
	}{
		{"server.trusted_proxies", c.Server.TrustedProxies, "X-Forwarded-For is trusted from every address, the allowlists can be bypassed"},
		{"security.admin_authorized_hosts", admin, "open to every address"},
		{"security.emulated_api_authorized_hosts", *c.Security.EmulatedAPIAuthorizedHosts, "open to every address"},
		{"security.metrics_authorized_hosts", *c.Security.MetricsAuthorizedHosts, "open to every address"},
	} {
		ps, err := l.hosts.Prefixes()
		// A list that copies the admin one has its errors reported once,
		// under the admin list.
		if err != nil && (l.path == "security.admin_authorized_hosts" || !slices.Equal(l.hosts, admin)) {
			fail(l.path, "%v", err)
		}
		for _, p := range ps {
			if p.Bits() == 0 {
				warnings = append(warnings, fmt.Sprintf("%s contains %s: %s", l.path, p, l.open))
			}
		}
	}
	positive("security.failure_rate_limit.max", int64(c.Security.FailureRateLimit.Max))
	positive("security.failure_rate_limit.per", int64(c.Security.FailureRateLimit.Per))
	positive("security.failure_rate_limit.block", int64(c.Security.FailureRateLimit.Block))

	if c.Secrets.CookieKey == nil {
		fail("secrets.cookie_key", "is required")
	}
	if c.Secrets.ChallengeKey == nil {
		fail("secrets.challenge_key", "is required")
	}
	c.Secrets.checkSharedKeys(fail)

	oneOf("tls.min_version", c.TLS.MinVersion, "1.2", "1.3")
	if c.TLS.CAFile != "" {
		if _, err := os.Stat(c.TLS.CAFile); err != nil {
			fail("tls.ca_file", "%v", err)
		}
	}
	if len(c.TLS.PinnedSPKISHA256) > 0 {
		// Accepting it would let an operator believe Hydra is pinned.
		fail("tls.pinned_spki_sha256", "is not supported yet, leave it empty")
	}

	if c.State.RedisDSN != "" {
		if u, err := url.Parse(c.State.RedisDSN); err != nil || !slices.Contains([]string{"redis", "rediss", "unix"}, u.Scheme) {
			fail("state.redis_dsn", "must be a redis://, rediss:// or unix:// URL")
		}
	}
	nonNegative("state.redis_pool_size", c.State.RedisPoolSize)
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
	for _, d := range slices.Sorted(maps.Keys(c.UI.CSPExtra)) {
		path := "ui.csp_extra." + d
		if !slices.Contains(cspDirectives, d) {
			fail(path, "is not one of %s", strings.Join(cspDirectives, ", "))
			continue
		}
		for _, src := range c.UI.CSPExtra[d] {
			switch {
			case strings.ContainsFunc(src, notInSource): // List drops empty sources
				fail(path, "%q is not a single source", src)
			case d == "script-src" && anyScript(src):
				fail(path, "%q would allow inline or arbitrary scripts", src)
			}
		}
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
	if out := o.Audit.Output; out != "stdout" && out != "syslog" && (!strings.HasPrefix(out, "file:") || out == "file:") {
		fail("observability.audit.output", "%q is not stdout, syslog or file:<path>", out)
	}

	positive("webhooks.process_timeout", int64(c.Webhooks.ProcessTimeout))
	positive("webhooks.max_processes", int64(c.Webhooks.MaxProcesses))
	oneOf("logout.propagate_without_record", c.Logout.PropagateWithoutRecord, "all", "none")

	c.Seed.validate(fail)

	return warnings, errors.Join(errs...)
}

// cspDirectives are the directives ui.csp_extra may extend: sources of
// content, never default-src or frame-ancestors.
var cspDirectives = []string{"connect-src", "font-src", "frame-src", "img-src", "media-src", "script-src", "style-src", "worker-src"}

// notInSource reports the runes that end a CSP source or break the header.
func notInSource(r rune) bool {
	return r == ';' || r == ',' || unicode.IsSpace(r) || unicode.IsControl(r)
}

var schemeSource = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:$`)

// anyScript reports the script sources that name no script and no host:
// inline scripts ('unsafe-…', a nonce fixed in the configuration), a whole
// scheme (https:, data:, blob:), a wildcard, or whatever a script loads.
func anyScript(src string) bool {
	return strings.HasPrefix(src, "'unsafe-") || strings.HasPrefix(src, "'nonce-") ||
		src == "'strict-dynamic'" || strings.Contains(src, "*") || schemeSource.MatchString(src)
}

// checkSharedKeys refuses a key in two keyrings: one secret for the cookies
// and for the challenge HMAC, say, ties their rotations and their leaks.
func (s Secrets) checkSharedKeys(fail func(path, format string, args ...any)) {
	owner := map[string]string{}
	for _, ring := range []struct {
		path string
		keys Keys
	}{
		{"secrets.cookie_key", append(Keys{s.CookieKey}, s.CookieKeysPrevious...)},
		{"secrets.encryption_key", append(Keys{s.EncryptionKey}, s.EncryptionKeysPrevious...)},
		{"secrets.challenge_key", append(Keys{s.ChallengeKey}, s.ChallengeKeysPrevious...)},
		{"secrets.webhook_signing_key", Keys{s.WebhookSigningKey}},
	} {
		for _, k := range ring.keys {
			switch other, ok := owner[string(k)]; {
			case k == nil:
			case ok && other != ring.path:
				fail(ring.path, "shares a key with %s: each use needs its own key", other)
			default:
				owner[string(k)] = ring.path
			}
		}
	}
}

// httpURL checks a base URL: absolute, without query or fragment.
func httpURL(s string) error {
	u, err := absoluteURL(s)
	if err != nil {
		return err
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%q has a query or a fragment", redacted(u))
	}
	return nil
}

// absoluteURL parses an absolute http(s) URL. Errors hide its password,
// query and fragment: an error ends up in the logs.
func absoluteURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("is not a valid URL") // url.Parse quotes it whole
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", redacted(u))
	}
	return u, nil
}

// redacted writes u for an error, without what may hold a secret: password,
// query (?token=…) and fragment.
func redacted(u *url.URL) string {
	v := *u
	v.RawQuery, v.ForceQuery, v.Fragment, v.RawFragment = "", false, "", ""
	return v.Redacted()
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
