package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

// HydraMargin is the margin internal/flow takes from the end of L at Hydra
// for a flow's expiry (Versions Hydra), which reads it from here:
// hydra.login_consent_ttl must exceed it, or every flow would be born expired
// (ENT-22).
const HydraMargin = 60 * time.Second

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
	base, baseErr := publicURL(c.Server.BaseURL)
	if baseErr != nil {
		fail("server.base_url", "%v", baseErr)
	}
	switch {
	case !strings.HasPrefix(c.Server.CookiePath, "/"):
		fail("server.cookie_path", "%q does not start with /", c.Server.CookiePath)
	case base != nil && !pathMatch(strings.TrimSuffix(base.EscapedPath(), "/")+"/", c.Server.CookiePath):
		fail("server.cookie_path", "%q does not cover %q, the path of server.base_url: browsers would not send the cookies to the pages",
			c.Server.CookiePath, strings.TrimSuffix(base.EscapedPath(), "/")+"/")
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
	// The flow's exp is taken 60 s before the end of L at Hydra (Versions
	// Hydra): at or under it, every flow would be born expired and each L
	// rejected at once (ENT-22), in fallback as decrypted.
	if c.Hydra.LoginConsentTTL <= Duration(HydraMargin) {
		fail("hydra.login_consent_ttl", "must be above %s, the margin the flows keep before the end of L at Hydra; it is Hydra's ttl.login_consent_request (30m by default)", HydraMargin)
	}
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
	if strings.HasPrefix(strings.ToLower(c.Hydra.AdminURL), "http://") && !c.TLS.AllowHTTP {
		warnings = append(warnings, "hydra.admin_url is in http://: subjects and claims travel in clear; tls.allow_http accepts it in development")
	}

	// No default: the private networks were one, and let any host in them,
	// or any address translation into them (a Kubernetes node, docker-proxy),
	// choose its address by X-Forwarded-For.
	trusted := List{}
	if c.Server.TrustedProxies == nil {
		fail("server.trusted_proxies", "is required: the addresses of the reverse proxies only, or [] when clients connect directly")
	} else {
		trusted = *c.Server.TrustedProxies
	}
	// No default either (B2): the emulated API is the most sensitive surface
	// (step accepts, claims), and the admin networks were too wide a default.
	emulated := List{}
	if c.Security.EmulatedAPIAuthorizedHosts == nil {
		fail("security.emulated_api_authorized_hosts", "is required: the networks the login apps call the emulated API from")
	} else {
		emulated = *c.Security.EmulatedAPIAuthorizedHosts
		if len(emulated) == 0 {
			// [] passes the requirement, as a ${VAR} left empty does.
			warnings = append(warnings, "security.emulated_api_authorized_hosts is empty: the emulated API refuses every call of the login apps")
		}
	}
	admin := c.Security.AdminAuthorizedHosts
	allowlists := false
	for _, l := range []struct {
		path  string
		hosts List
		open  string // what a list covering every address means
	}{
		{"server.trusted_proxies", trusted, "X-Forwarded-For is trusted from every address, the allowlists can be bypassed"},
		{"security.admin_authorized_hosts", admin, "open to every address"},
		{"security.emulated_api_authorized_hosts", emulated, "open to every address"},
		{"security.metrics_authorized_hosts", *c.Security.MetricsAuthorizedHosts, "open to every address"},
	} {
		ps, err := l.hosts.Prefixes()
		// A list that copies the admin one has its errors reported once,
		// under the admin list.
		if err != nil && (l.path == "security.admin_authorized_hosts" || !slices.Equal(l.hosts, admin)) {
			fail(l.path, "%v", err)
		}
		// However written: 0.0.0.0/0, or 0.0.0.0/1 and 128.0.0.0/1.
		for _, all := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")} {
			if Covers(ps, all) {
				warnings = append(warnings, fmt.Sprintf("%s covers %s: %s", l.path, all, l.open))
			}
		}
		allowlists = allowlists || (l.path != "server.trusted_proxies" && len(l.hosts) > 0)
	}
	if c.Server.TrustedProxies != nil && len(trusted) == 0 && allowlists {
		// A forgotten ${TRUSTED_PROXIES}, say: the proxy's address is often
		// in the private networks of the default allowlists.
		warnings = append(warnings, "server.trusted_proxies is empty: behind a reverse proxy, every client has the proxy's address and passes the allowlists that contain it")
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
	if c.Secrets.EncryptionKey == nil && len(c.Secrets.EncryptionKeysPrevious) > 0 {
		fail("secrets.encryption_key", "is required with secrets.encryption_keys_previous: a previous key only decrypts what an active one encrypted")
	}
	c.Secrets.checkSharedKeys(fail)

	oneOf("tls.min_version", c.TLS.MinVersion, "1.2", "1.3")
	if c.TLS.CAFile != "" {
		if _, err := os.Stat(c.TLS.CAFile); err != nil {
			fail("tls.ca_file", "%v", err)
		}
	}
	if c.Webhooks.CAFile != "" {
		if _, err := os.Stat(c.Webhooks.CAFile); err != nil {
			fail("webhooks.ca_file", "%v", err)
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
	if c.Remember.Backend == "postgres" {
		// Q40: the server variant of the skip memory has no lot yet.
		fail("remember.backend", "postgres is not available yet: the skip memory is the dispatcher_remember cookie; use cookie")
	} else {
		oneOf("remember.backend", c.Remember.Backend, "cookie")
	}
	oneOf("store.backend", c.Store.Backend, "postgres")
	if c.Store.DSN == "" {
		fail("store.dsn", "is required")
	}

	positive("admin.api.token_ttl", int64(c.Admin.API.TokenTTL))
	positive("admin.api.rate_limit_per_minute", int64(c.Admin.API.RateLimitPerMinute))
	positive("admin.session.idle_timeout", int64(c.Admin.Session.IdleTimeout))
	positive("admin.session.max_age", int64(c.Admin.Session.MaxAge))

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

	oneOf("consent.claims_filter", c.Consent.ClaimsFilter, ClaimsPermissive, ClaimsStrict)
	if c.Consent.ClaimsFilter == ClaimsStrict {
		// The standard scopes alone would drop every business claim.
		fail("consent.claims_filter", "strict needs the scope catalogue of the database, which phase 3 brings: use permissive")
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
	oneOf("serve.bootstrap", c.Serve.Bootstrap, BootstrapOff, BootstrapMissing, BootstrapForce)

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
// Browsers match keywords whatever their case.
func anyScript(src string) bool {
	src = strings.ToLower(src)
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

// publicURL checks server.base_url, the address the browsers see. Its scheme
// and host are written as a browser serializes its Origin, in lowercase and
// without the scheme's default port nor a user, since the forms' origin
// check and the Referer of the change of language compare them as written
// (Sécurité, protection des formulaires). Its path, clean, is the prefix a
// proxy removes before the dispatcher: the pages put it before their URLs.
func publicURL(s string) (*url.URL, error) {
	if err := httpURL(s); err != nil {
		return nil, err
	}
	u, _ := url.Parse(s)
	defaultPort := u.Port() == "" && strings.HasSuffix(u.Host, ":") ||
		u.Scheme == "http" && u.Port() == "80" || u.Scheme == "https" && u.Port() == "443"
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	switch {
	case u.User != nil:
		// No quote: the user part may hold a password.
		return nil, errors.New("holds a user, which no browser sends in its Origin")
	case !strings.HasPrefix(s, u.Scheme+"://"):
		return nil, fmt.Errorf("%q: write its scheme in lowercase, as browsers send their Origin", redacted(u))
	case u.Host != strings.ToLower(u.Host):
		return nil, fmt.Errorf("%q: write its host in lowercase, as browsers send their Origin", redacted(u))
	case defaultPort:
		return nil, fmt.Errorf("%q: leave out the default port of %s, as browsers do in their Origin", redacted(u), u.Scheme)
	case p != "" && path.Clean(p) != p:
		return nil, fmt.Errorf("%q: its path is not clean (%q)", redacted(u), path.Clean(p))
	}
	return u, nil
}

// pathMatch reports whether a cookie of path cookiePath is sent to the
// request path p (RFC 6265, 5.1.4).
func pathMatch(p, cookiePath string) bool {
	return p == cookiePath || strings.HasPrefix(p, cookiePath) &&
		(strings.HasSuffix(cookiePath, "/") || p[len(cookiePath)] == '/')
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
	switch {
	case u.Host == "":
		// Without an authority, as in https//user:password@host, the
		// password stays in the path: no quote.
		return nil, errors.New("is not an absolute http(s) URL")
	case u.Scheme != "http" && u.Scheme != "https":
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
// /128). An IPv4-mapped IPv6 network (::ffff:10.0.0.0/104) is its IPv4
// network, since clients are matched by their IPv4 address. Load has
// validated the allowlists and trusted proxies already.
func (l List) Prefixes() ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(l))
	for _, s := range l {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is neither a CIDR nor an IP address", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 128-32 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-(128-32))
		}
		ps = append(ps, p.Masked())
	}
	return ps, nil
}

// Covers reports whether ps hold every address of p, however split.
func Covers(ps []netip.Prefix, p netip.Prefix) bool {
	split := false
	for _, q := range ps {
		switch {
		case q.Bits() <= p.Bits() && q.Contains(p.Addr()):
			return true
		case q.Bits() > p.Bits() && p.Contains(q.Addr()):
			split = true // q holds a part of p: look at each half
		}
	}
	if !split {
		return false
	}
	bits := p.Bits() + 1
	high := p.Addr().AsSlice()
	high[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	h, _ := netip.AddrFromSlice(high)
	return Covers(ps, netip.PrefixFrom(p.Addr(), bits)) && Covers(ps, netip.PrefixFrom(h, bits))
}
