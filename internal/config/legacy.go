package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The variables of the Symfony dispatcher are read in fallback during the
// cohabitation, until 1.0 (Configuration et déploiement): a key takes the
// value of its variable only when neither the file nor a DISPATCHER_*
// variable sets it, so the sources rank defaults < Symfony variables < file <
// DISPATCHER_*. Each one read gives a warning naming the key to use instead,
// and so does one a set key leaves aside, the two possibly differing. A
// variable the file references by ${VAR} is the file's: neither read nor
// warned of here.

// legacyKey is a key the variables of the Symfony dispatcher give.
type legacyKey struct {
	path string
	// vars are the variables read, those present named by the warnings.
	vars []string
	// read returns the value of the key, as a DISPATCHER_* variable gives it,
	// and what the warning adds; ok false when the variables give no value,
	// note then saying why. It is called with at least one of vars present.
	read func(lookupEnv func(string) (string, bool)) (value, note string, ok bool, err error)
}

// legacyKeys follow the table of the design document, plus COOKIE_PATH and
// HYDRA_HTTP_MAX_DURATION, of the same meaning here.
var legacyKeys = []legacyKey{
	{path: "hydra.admin_url", vars: []string{"HYDRA_ADMIN_BASE_URL"}, read: verbatim("HYDRA_ADMIN_BASE_URL", "")},
	{path: "hydra.timeout", vars: []string{"HYDRA_HTTP_MAX_DURATION"}, read: seconds("HYDRA_HTTP_MAX_DURATION")},
	{path: "server.base_url", vars: []string{"BASE_URL", "BASE_PATH", "SERVER_NAME"}, read: legacyBaseURL},
	{path: "server.cookie_path", vars: []string{"COOKIE_PATH"}, read: verbatim("COOKIE_PATH", "")},
	{path: "server.trusted_proxies", vars: []string{"TRUSTED_PROXIES"}, read: legacyTrustedProxies},
	{path: "security.admin_authorized_hosts", vars: []string{"HYDRA_ADMIN_AUTHORIZED_HOSTS"},
		read: verbatim("HYDRA_ADMIN_AUTHORIZED_HOSTS", "security.emulated_api_authorized_hosts does not inherit it: the login apps' networks are declared apart")},
	{path: "state.redis_dsn", vars: []string{"REDIS_DSN"}, read: legacyRedisDSN},
	{path: "store.dsn", vars: []string{"DATABASE_URL"}, read: verbatim("DATABASE_URL", "")},
	{path: "admin.api.private_key", vars: []string{"OAUTH2_PRIVATE_KEY"}, read: verbatim("OAUTH2_PRIVATE_KEY", "")},
	{path: "admin.api.public_key", vars: []string{"OAUTH2_PUBLIC_KEY"}, read: verbatim("OAUTH2_PUBLIC_KEY", "")},
	{path: "admin.api.token_ttl", vars: []string{"OAUTH2_TOKEN_TTL"}, read: verbatim("OAUTH2_TOKEN_TTL", "")},
	{path: "admin.ui.enabled", vars: []string{"ADMIN_UI_ENABLED"}, read: phpBool("ADMIN_UI_ENABLED")},
	{path: "webhooks.process_timeout", vars: []string{"WEBHOOK_PROCESS_TIMEOUT"}, read: seconds("WEBHOOK_PROCESS_TIMEOUT")},
	{path: "observability.sentry.dsn", vars: []string{"SENTRY_DSN"}, read: legacySentryDSN},
	{path: "observability.sentry.environment", vars: []string{"SENTRY_ENVIRONMENT"}, read: verbatim("SENTRY_ENVIRONMENT", "")},
	{path: "observability.sentry.release", vars: []string{"SENTRY_RELEASE"}, read: verbatim("SENTRY_RELEASE", "")},
}

// legacyUnread are the variables of the Symfony dispatcher with an equivalent that is
// no key of the file, each group warned of once.
var legacyUnread = []struct {
	vars []string
	why  string
}{
	{[]string{"OAUTH2_ADMIN_CLIENT_ID", "OAUTH2_ADMIN_CLIENT_SECRET"},
		"there is no implicit client of the admin API any more: declare it in dispatcher.oauth2_clients (id: ${OAUTH2_ADMIN_CLIENT_ID}, secret: ${OAUTH2_ADMIN_CLIENT_SECRET})"},
	{[]string{"DEFAULT_LOCALE", "APP_LOCALES"},
		"the locales are the settings default_locale and supported_locales, which the dispatcher: seed writes to the database"},
}

// legacyUseless are the variables of the Symfony dispatcher and of its FrankenPHP
// image that mean nothing here, those hydra-dev sets that Symfony does not read
// included; a trailing * is a prefix. One warning lists those present.
var legacyUseless = []string{
	"APP_ENV", "APP_DEBUG", "APP_SECRET", "METRICS_STORAGE", "FRANKENPHP_*", "XDEBUG_*", "OPCACHE_*", "CADDY_*",
	"PHP_MEMORY_LIMIT", "SERVER_ROOT", "HYDRA_BASE_URL", "HYDRA_REWRITE_ISSUER", "HYDRA_ORIGINAL_ISSUER",
	"HYDRA_NEW_ISSUER", "HYDRA_HTTP_TIMEOUT", "HTTP_CLIENT_TIMEOUT", "HTTP_CLIENT_MAX_DURATION", "MEMCACHED_DSN",
	"DATABASE_SERVER_VERSION", "URL_LINK", "OIDC_WELL_KNOWN_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
	"VAR_DUMPER_SERVER",
}

// applyLegacy gives the keys neither the file nor a DISPATCHER_* variable set (set)
// the values of the Symfony variables, and warns of every Symfony variable present
// that the file does not reference.
func applyLegacy(c *Config, environ []string, lookupEnv func(string) (string, bool), set, referenced map[string]bool) ([]string, error) {
	keys := map[string]envKey{}
	for _, k := range envKeys(c) {
		keys[k.path] = k
	}
	present := func(names []string) []string {
		var p []string
		for _, n := range names {
			if _, ok := lookupEnv(n); ok && !referenced[n] {
				p = append(p, n)
			}
		}
		return p
	}
	var warnings []string
	var errs []error
	for _, l := range legacyKeys {
		vars := present(l.vars)
		if len(vars) == 0 {
			continue
		}
		k := keys[l.path]
		if set[l.path] {
			warnings = append(warnings, fmt.Sprintf("%s ignored: %s is set, by the file or %s; remove %s, the two may differ",
				symfony(vars), l.path, k.name, them(vars)))
			continue
		}
		value, note, ok, err := l.read(lookupEnv)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s (%s): %w", strings.Join(vars, ", "), l.path, err))
			continue
		case !ok:
			warnings = append(warnings, note)
			continue
		}
		if err := k.set(value); err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", strings.Join(vars, ", "), l.path, err))
			continue
		}
		w := fmt.Sprintf("%s read as %s until 1.0: set %s, or %s, instead", symfony(vars), l.path, l.path, k.name)
		if note != "" {
			w += "; " + note
		}
		warnings = append(warnings, w)
	}
	for _, u := range legacyUnread {
		if vars := present(u.vars); len(vars) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s not read: %s", symfony(vars), u.why))
		}
	}
	var useless []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if referenced[name] || slices.Contains(useless, name) {
			continue
		}
		for _, u := range legacyUseless {
			if prefix, wild := strings.CutSuffix(u, "*"); name == u || wild && strings.HasPrefix(name, prefix) && name != prefix {
				useless = append(useless, name)
				break
			}
		}
	}
	if len(useless) > 0 {
		slices.Sort(useless)
		warnings = append(warnings, "variables of the Symfony dispatcher without use here, ignored: "+strings.Join(useless, ", "))
	}
	return warnings, errors.Join(errs...)
}

// symfony names variables of the Symfony dispatcher, with the verb that
// follows: "BASE_PATH (Symfony) is", "BASE_PATH and SERVER_NAME (Symfony) are".
func symfony(vars []string) string {
	if len(vars) == 1 {
		return vars[0] + " (Symfony) is"
	}
	return strings.Join(vars[:len(vars)-1], ", ") + " and " + vars[len(vars)-1] + " (Symfony) are"
}

func them(vars []string) string {
	if len(vars) == 1 {
		return "it"
	}
	return "them"
}

// verbatim reads a variable as the key's value, with a note for the warning.
func verbatim(name, note string) func(func(string) (string, bool)) (string, string, bool, error) {
	return func(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
		v, _ := lookupEnv(name)
		return v, note, true, nil
	}
}

// seconds reads a number of seconds, a fraction allowed, as Symfony's timeouts take
// it.
func seconds(name string) func(func(string) (string, bool)) (string, string, bool, error) {
	return func(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
		v, _ := lookupEnv(name)
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f < 0 || f > float64(1<<62)/float64(time.Second) {
			return "", "", false, fmt.Errorf("%q is not a number of seconds", v)
		}
		return time.Duration(f * float64(time.Second)).String(), "", true, nil
	}
}

// phpBool reads a boolean as Symfony's %env(bool:)% does: true, on, yes and 1 are
// true, false, off, no, 0 and "" false, whatever their case; anything else is true
// when it is a number other than zero.
func phpBool(name string) func(func(string) (string, bool)) (string, string, bool, error) {
	return func(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
		v, _ := lookupEnv(name)
		v = strings.ToLower(strings.TrimSpace(v))
		b := false
		switch v {
		case "1", "true", "on", "yes":
			b = true
		case "", "0", "false", "off", "no":
		default:
			f, err := strconv.ParseFloat(v, 64)
			b = err == nil && f != 0
		}
		return strconv.FormatBool(b), "", true, nil
	}
}

// legacyBaseURL is server.base_url from BASE_URL, Symfony's default URI of its
// router, when it is absolute; else from BASE_PATH, when it is an absolute URL, as in
// hydra-dev; else from SERVER_NAME, FrankenPHP's address, followed by BASE_PATH as a
// path, / by default.
func legacyBaseURL(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
	var notes []string
	if v, ok := lookupEnv("BASE_URL"); ok {
		switch v = strings.TrimSpace(v); {
		case v == "" || v == "//": // Symfony's default: the URL of each request
		case absoluteHTTP(v):
			return strings.TrimSuffix(v, "/"), notUsed(lookupEnv, "BASE_URL"), true, nil
		default:
			notes = append(notes, "BASE_URL (Symfony) is not an absolute http(s) URL, which server.base_url needs")
		}
	}
	basePath, hasPath := lookupEnv("BASE_PATH")
	basePath = strings.TrimSpace(basePath)
	if absoluteHTTP(basePath) {
		return strings.TrimSuffix(basePath, "/"), strings.Join(append(notes, notUsed(lookupEnv, "BASE_PATH")), "; "), true, nil
	}
	server, ok := lookupEnv("SERVER_NAME")
	server = strings.TrimSpace(server)
	u, err := url.Parse(server)
	switch {
	case !ok || server == "":
		if hasPath && basePath != "" && basePath != "/" {
			notes = append(notes, "BASE_PATH (Symfony) is a path, which needs SERVER_NAME")
		}
		if len(notes) == 0 {
			// BASE_URL left to Symfony's default, an empty BASE_PATH: nothing
			// to read, nothing wrong.
			notes = append(notes, "BASE_URL, BASE_PATH or SERVER_NAME (Symfony) give no server.base_url")
		}
		return "", strings.Join(notes, "; ") + ": set server.base_url", false, nil
	case strings.ContainsAny(server, ", \t") || err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		notes = append(notes, fmt.Sprintf("SERVER_NAME (Symfony) %q is not one http:// or https:// address, which server.base_url needs", server))
		return "", strings.Join(notes, "; ") + ": set server.base_url", false, nil
	}
	// FrankenPHP may name the default port of its scheme, which a browser's
	// Origin leaves out.
	if p := u.Port(); u.Scheme == "http" && p == "80" || u.Scheme == "https" && p == "443" {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	path := strings.Trim(basePath, "/")
	if path != "" {
		path = "/" + path
	}
	return u.Scheme + "://" + u.Host + path, strings.Join(notes, "; "), true, nil
}

// notUsed is the note of server.base_url taken from one variable: the others it
// leaves unused.
func notUsed(lookupEnv func(string) (string, bool), from string) string {
	note := "the value of " + from
	if from == "BASE_PATH" {
		note += ", an absolute URL"
	}
	var unused []string
	for _, v := range []string{"BASE_PATH", "SERVER_NAME"} {
		if _, ok := lookupEnv(v); ok && v != from {
			unused = append(unused, v)
		}
	}
	if len(unused) > 0 {
		note += "; " + strings.Join(unused, " and ") + " unused"
	}
	return note
}

func absoluteHTTP(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// legacyTrustedProxies reads Symfony's comma-separated list. REMOTE_ADDR, every
// caller a trusted proxy, has no equivalent: dropped, the other entries kept,
// alone an error (Q81). PRIVATE_SUBNETS, or private_ranges, is Symfony's list of
// private networks, but its IPv4-mapped IPv6 network: Symfony matches it only
// against an address written in IPv6, where here a client is matched by its IPv4
// address, and it would cover all of them.
func legacyTrustedProxies(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
	v, _ := lookupEnv("TRUSTED_PROXIES")
	var kept []string
	remote := false
	for item := range strings.SplitSeq(v, ",") {
		switch item = strings.TrimSpace(item); item {
		case "":
		case "REMOTE_ADDR":
			remote = true
		case "PRIVATE_SUBNETS", "private_ranges":
			kept = append(kept, "127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16",
				"0.0.0.0/8", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "::/128")
		default:
			kept = append(kept, item)
		}
	}
	if !remote {
		return strings.Join(kept, ","), "", true, nil
	}
	if len(kept) == 0 {
		return "", "", false, errors.New("REMOTE_ADDR alone makes every caller a trusted proxy, which nothing here does: " +
			"set server.trusted_proxies to the addresses of the reverse proxies, [] when clients connect directly")
	}
	return strings.Join(kept, ","), "REMOTE_ADDR, every caller a trusted proxy, has no equivalent and is dropped, the other entries kept: " +
		"a reverse proxy outside them passes its own address for that of all its clients", true, nil
}

// legacyRedisDSN reads a Redis DSN of Symfony as go-redis takes it: a password
// without a user, which Symfony reads as the password, is written as one. What
// go-redis does not read is refused: the options in a query (Symfony's host[] of
// several servers, redis_sentinel, redis_cluster, timeout, dbindex…), a socket. An
// empty one is no Redis, as for Symfony, which then kept its cache in APCu.
func legacyRedisDSN(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
	v, _ := lookupEnv("REDIS_DSN")
	if v = strings.TrimSpace(v); v == "" {
		return "", "", true, nil
	}
	scheme, rest, _ := strings.Cut(v, ":")
	switch scheme {
	case "redis", "rediss":
	case "valkey", "valkeys":
		scheme = "redis" + strings.TrimPrefix(scheme, "valkey")
	default:
		return "", "", false, errors.New("is not a redis:, rediss:, valkey: or valkeys: DSN")
	}
	// No quote of the DSN in the errors: it may hold a password.
	u, err := url.Parse(scheme + ":" + rest)
	switch {
	case err != nil:
		return "", "", false, errors.New("is not a valid URL")
	case u.RawQuery != "" || u.ForceQuery:
		return "", "", false, errors.New("its query holds options of Symfony (host[] for several servers, redis_sentinel, redis_cluster, timeout, dbindex…), " +
			"which go-redis does not read: set state.redis_dsn, a redis:// URL of one server, whose query takes dial_timeout, read_timeout, write_timeout and max_retries")
	case u.Host == "":
		return "", "", false, errors.New("names no host, a socket maybe: set state.redis_dsn, unix:///path for a socket")
	}
	note := ""
	if u.User != nil {
		if _, ok := u.User.Password(); !ok && u.User.Username() != "" {
			u.User = url.UserPassword("", u.User.Username())
			note = "its password, written without a user as Symfony reads it, is given as redis://:password@, as go-redis reads it"
		}
	}
	return u.String(), note, true, nil
}

// legacySentryDSN reads SENTRY_DSN, and warns of what changes with it.
func legacySentryDSN(lookupEnv func(string) (string, bool)) (string, string, bool, error) {
	v, _ := lookupEnv("SENTRY_DSN")
	note := ""
	if strings.TrimSpace(v) != "" {
		note = "observability.sentry.sample_rate is 1 by default, where Symfony sent 0.25 of the errors"
	}
	return v, note, true, nil
}

// doctrineParameters are the parameters of a Doctrine DATABASE_URL that are no
// connection parameters: pgx would send them to Postgres as runtime parameters,
// which it refuses.
var doctrineParameters = []string{"serverVersion", "charset", "driver", "driverClass", "wrapperClass", "platform", "defaultTableOptions"}

// withoutDoctrine drops the parameters of Doctrine from a postgres:// DSN, and names
// them; another DSN is left as it is.
func withoutDoctrine(dsn string) (string, []string) {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn, nil
	}
	u, err := url.Parse(dsn)
	if err != nil || u.RawQuery == "" {
		return dsn, nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return dsn, nil // pgx says what is wrong
	}
	var dropped []string
	for k := range q {
		name, _, _ := strings.Cut(k, "[") // defaultTableOptions[charset]
		if slices.Contains(doctrineParameters, name) {
			dropped = append(dropped, k)
			q.Del(k)
		}
	}
	if len(dropped) == 0 {
		return dsn, nil
	}
	slices.Sort(dropped)
	u.RawQuery = q.Encode()
	return u.String(), dropped
}
