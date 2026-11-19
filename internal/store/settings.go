package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/secretbox"
)

// Settings are what the setting table holds, one row per key: a key absent
// from the table has its default, so a new setting needs no migration.
type Settings struct {
	AppAutoSelect                bool
	ConsentAutoAccept            bool
	AggregateAMRFromLoginRequest bool
	ChallengeTTL                 time.Duration
	Remember                     bool
	LoginRememberFor             time.Duration
	ConsentRememberFor           time.Duration
	LoginAcceptWebhookURL        string
	ConsentAcceptWebhookURL      string
	SupportedLocales             []string
	DefaultLocale                string
	FallbackLocale               string
	// ACRValuesMode is what a client's acr_values do when no flow declares
	// one of them (Q151): ACRValuesPrefer offers every flow, ACRValuesRequire
	// rejects the login.
	ACRValuesMode string
	// SkipScopes is how the scopes a client requests compare with those of
	// the remember cookie for Hydra's skip to be honoured (MEM-8, Q164):
	// SkipScopesEqual, SkipScopesSubset or SkipScopesAny.
	SkipScopes string
	AdminOIDC  AdminOIDC
}

// The values of acr_values_mode.
const (
	ACRValuesPrefer  = "prefer"
	ACRValuesRequire = "require"
)

// The values of skip_scopes.
const (
	SkipScopesEqual  = "equal"
	SkipScopesSubset = "subset"
	SkipScopesAny    = "any"
)

// AdminOIDC is the block admin_oidc: the login to the admin UI by an identity
// provider (P22). It stays out of the document of the admin API and of the
// screen of the settings, as Symfony kept it out of its API: the screen SSO,
// the seed and bootstrap write it.
type AdminOIDC struct {
	Enabled  bool
	Issuer   string
	ClientID string
	// ClientSecret is in clear here, encrypted in the table by
	// secrets.encryption_key (secretbox); "" for a public client.
	ClientSecret  string
	Scopes        []string
	UsernameClaim string
	// RequiredACR are the acr one of which the ID token must hold; none,
	// any.
	RequiredACR []string
	// AutoCreate creates the account of a subject no account has, in the
	// role viewer (Q126).
	AutoCreate bool
	// The endpoints, declared; empty, those of the discovery of Issuer.
	AuthorizationEndpoint, TokenEndpoint, JWKSURI string
}

// DefaultSettings are the values of the keys absent from the table: those of
// Symfony.
func DefaultSettings() Settings {
	return Settings{
		ChallengeTTL:       time.Hour,
		Remember:           true,
		LoginRememberFor:   24 * time.Hour,
		ConsentRememberFor: 2629800 * time.Second,
		SupportedLocales:   []string{"fr", "en"},
		DefaultLocale:      "fr",
		FallbackLocale:     "en",
		ACRValuesMode:      ACRValuesPrefer,
		SkipScopes:         SkipScopesEqual,
		AdminOIDC:          AdminOIDC{Scopes: []string{"openid", "email", "profile"}, UsernameClaim: "preferred_username", RequiredACR: []string{}},
	}
}

// setting is a key of the registry. Its value is the JSON of the field,
// durations in seconds as Symfony stored them; a secret's is encrypted in the
// table (row).
type setting struct {
	key    string
	help   string
	field  func(s *Settings) any
	secret bool
	// block is admin_oidc for the settings of the login by an identity
	// provider, out of the document; "" for those of the document.
	block string
}

// blockOIDC is the block of the settings of the login to the admin by an
// identity provider.
const blockOIDC = "admin_oidc"

// registry declares every setting the dispatcher reads.
var registry = []setting{
	{key: "app_auto_select", help: "start the only flow offered without the choice page", field: func(s *Settings) any { return &s.AppAutoSelect }},
	{key: "consent_auto_accept", help: "accept the consent without the consent screen", field: func(s *Settings) any { return &s.ConsentAutoAccept }},
	{key: "aggregate_amr_from_login_request", help: "send Hydra the amr the apps give rather than their methods", field: func(s *Settings) any { return &s.AggregateAMRFromLoginRequest }},
	{key: "challenge_ttl", help: "lifetime of a flow, in seconds", field: func(s *Settings) any { return &s.ChallengeTTL }},
	{key: "remember", help: "ask Hydra to remember the login and the consent", field: func(s *Settings) any { return &s.Remember }},
	{key: "login_remember_for", help: "lifetime of Hydra's login session and of the skip memory, in seconds", field: func(s *Settings) any { return &s.LoginRememberFor }},
	{key: "consent_remember_for", help: "how long Hydra remembers a consent, in seconds", field: func(s *Settings) any { return &s.ConsentRememberFor }},
	{key: "login_accept_webhook_url", help: "webhook called before the login accept: http(s) URL, file:// URL or command, empty for none", field: func(s *Settings) any { return &s.LoginAcceptWebhookURL }},
	{key: "consent_accept_webhook_url", help: "webhook called before the consent accept: http(s) URL, file:// URL or command, empty for none", field: func(s *Settings) any { return &s.ConsentAcceptWebhookURL }},
	{key: "supported_locales", help: "locales of the pages", field: func(s *Settings) any { return &s.SupportedLocales }},
	{key: "default_locale", help: "locale of the pages when the browser asks for none of them", field: func(s *Settings) any { return &s.DefaultLocale }},
	{key: "fallback_locale", help: "locale of a text missing from the page's locale", field: func(s *Settings) any { return &s.FallbackLocale }},
	{key: "skip_scopes", help: "the scopes a client requests, compared with those of the remembered login for Hydra's skip: equal, the same; subset, among them; any, whatever they are", field: func(s *Settings) any { return &s.SkipScopes }},
	{key: "acr_values_mode", help: "prefer: the acr_values of a client narrow the flows offered to those declaring one of them, every flow when none does; require: none declaring one rejects the login", field: func(s *Settings) any { return &s.ACRValuesMode }},
	{key: "admin_oidc.enabled", help: "log in to the admin by the identity provider", field: func(s *Settings) any { return &s.AdminOIDC.Enabled }, block: blockOIDC},
	{key: "admin_oidc.issuer", help: "issuer of the identity provider, as its ID tokens name it", field: func(s *Settings) any { return &s.AdminOIDC.Issuer }, block: blockOIDC},
	{key: "admin_oidc.client_id", help: "client_id of the admin at the identity provider", field: func(s *Settings) any { return &s.AdminOIDC.ClientID }, block: blockOIDC},
	{key: "admin_oidc.client_secret", help: "client_secret of the admin at the identity provider; empty for a public client", field: func(s *Settings) any { return &s.AdminOIDC.ClientSecret }, secret: true, block: blockOIDC},
	{key: "admin_oidc.scopes", help: "scopes asked, openid among them", field: func(s *Settings) any { return &s.AdminOIDC.Scopes }, block: blockOIDC},
	{key: "admin_oidc.username_claim", help: "claim the name of an account created is taken from, then email, then sub", field: func(s *Settings) any { return &s.AdminOIDC.UsernameClaim }, block: blockOIDC},
	{key: "admin_oidc.required_acr", help: "acr one of which the ID token must hold; empty, any", field: func(s *Settings) any { return &s.AdminOIDC.RequiredACR }, block: blockOIDC},
	{key: "admin_oidc.auto_create", help: "create, in the role viewer, the account of a subject no account has", field: func(s *Settings) any { return &s.AdminOIDC.AutoCreate }, block: blockOIDC},
	{key: "admin_oidc.authorization_endpoint", help: "authorization endpoint, declared; empty, that of the discovery", field: func(s *Settings) any { return &s.AdminOIDC.AuthorizationEndpoint }, block: blockOIDC},
	{key: "admin_oidc.token_endpoint", help: "token endpoint, declared; empty, that of the discovery", field: func(s *Settings) any { return &s.AdminOIDC.TokenEndpoint }, block: blockOIDC},
	{key: "admin_oidc.jwks_uri", help: "JWKS of the identity provider, declared; empty, that of the discovery", field: func(s *Settings) any { return &s.AdminOIDC.JWKSURI }, block: blockOIDC},
}

// SettingValue is a setting and its value, in the JSON of its type.
type SettingValue struct {
	Key   string
	Value json.RawMessage
	// Secret marks a value never shown: admin_oidc.client_secret.
	Secret bool
}

// Document gives the settings of the document of the admin API (Q105), in the
// order of the registry: the block admin_oidc stays out.
func (s Settings) Document() []SettingValue {
	return s.values("")
}

// AdminOIDCDocument gives the settings of the block admin_oidc, in the order of
// the registry, the secret in clear and marked: for the screen SSO and
// config dump, which never show it.
func (s Settings) AdminOIDCDocument() []SettingValue {
	return s.values(blockOIDC)
}

func (s Settings) values(block string) []SettingValue {
	var values []SettingValue
	for _, st := range registry {
		if st.block == block {
			values = append(values, SettingValue{Key: st.key, Value: st.encode(&s), Secret: st.secret})
		}
	}
	return values
}

// SettingKey is a key of the registry and its help, for the admin forms.
type SettingKey struct{ Key, Help string }

// SettingKeys lists the settings of the document, in the order of the
// registry: the block admin_oidc has its own screen.
func SettingKeys() []SettingKey {
	var keys []SettingKey
	for _, st := range registry {
		if st.block == "" {
			keys = append(keys, SettingKey{st.key, st.help})
		}
	}
	return keys
}

// SecretSettings are the keys of the settings the table holds encrypted.
func SecretSettings() []string {
	var keys []string
	for _, st := range registry {
		if st.secret {
			keys = append(keys, st.key)
		}
	}
	return keys
}

func lookup(key string) (setting, bool) {
	i := slices.IndexFunc(registry, func(st setting) bool { return st.key == key })
	if i < 0 {
		return setting{}, false
	}
	return registry[i], true
}

// decode reads raw into the field of st in s.
func (st setting) decode(raw []byte, s *Settings) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("is null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	switch p := st.field(s).(type) {
	case *time.Duration:
		// Into any: a json.Number would take the string "3600" too.
		var v any
		if err := dec.Decode(&v); err != nil {
			return err
		}
		n, ok := v.(json.Number)
		if !ok {
			return fmt.Errorf("%s is not a whole number of seconds", bytes.TrimSpace(raw))
		}
		secs, err := seconds(n)
		if err != nil {
			return fmt.Errorf("%s %w", n, err)
		}
		*p = time.Duration(secs) * time.Second
	default:
		// Into a zero value: over the default, a null element of a list
		// would keep the default's element at its place.
		reflect.ValueOf(p).Elem().SetZero()
		if err := dec.Decode(p); err != nil {
			return err
		}
	}
	// Nothing after the value: More would let a ] or a } through.
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("holds more than one value")
	}
	return nil
}

// maxSeconds is the most seconds a time.Duration holds, either way.
const maxSeconds = math.MaxInt64 / int64(time.Second)

// seconds reads a whole number of seconds. 3600.0, as Postgres keeps a
// number written so, is whole too.
func seconds(n json.Number) (int64, error) {
	secs, err := n.Int64()
	if err != nil {
		// Past float64, ±Inf and an error: out of range below.
		f, ferr := n.Float64()
		if ferr == nil && f != math.Trunc(f) {
			return 0, errors.New("is not a whole number of seconds")
		}
		if ferr != nil || math.Abs(f) > float64(maxSeconds) {
			return 0, fmt.Errorf("is out of range: %d seconds at most", maxSeconds)
		}
		secs = int64(f)
	}
	if secs > maxSeconds || secs < -maxSeconds {
		return 0, fmt.Errorf("is out of range: %d seconds at most", maxSeconds)
	}
	return secs, nil
}

// decodeRow reads a row of the table into the field of st in s: a secret's
// value is encrypted, which keys open (secretbox), an empty secret is not.
func (st setting) decodeRow(raw []byte, s *Settings, keys *secretbox.Keys) error {
	if !st.secret {
		return st.decode(raw, s)
	}
	var sealed string
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return errors.New("is not a string")
	}
	if sealed == "" {
		return st.decode(raw, s)
	}
	plain, err := keys.Open(st.key, sealed)
	if err != nil {
		return err
	}
	return st.decode(plain, s)
}

// row returns the value of st in s as the table holds it: a secret's
// encrypted by the active key, an empty secret as it is.
func (st setting) row(s *Settings, keys *secretbox.Keys) ([]byte, error) {
	plain := st.encode(s)
	if !st.secret || string(plain) == `""` {
		return plain, nil
	}
	sealed, err := keys.Seal(st.key, plain)
	if err != nil {
		return nil, domain.Violations{{Field: st.key, Message: "cannot be written without secrets.encryption_key, which encrypts it in the database"}}
	}
	return json.Marshal(sealed)
}

// encryptedKIDs are the kids of the encrypted rows, by key: the gauge
// hydra_dispatcher_encrypted_values and secrets status.
func encryptedKIDs(rows map[string][]byte) map[string]string {
	kids := map[string]string{}
	for _, st := range registry {
		var sealed string
		if raw, ok := rows[st.key]; ok && st.secret && json.Unmarshal(raw, &sealed) == nil {
			if kid, ok := secretbox.KID(sealed); ok {
				kids[st.key] = kid
			}
		}
	}
	return kids
}

// sealedDigests are the digests of the encrypted settings as the table holds
// them, by key: a secret written again, the same or not, changes its digest
// (a nonce of its own), which tells nothing of it. A form of the secret
// carries it in its version (revue R42).
func sealedDigests(rows map[string][]byte) map[string]string {
	digests := map[string]string{}
	for _, st := range registry {
		if raw, ok := rows[st.key]; ok && st.secret {
			sum := sha256.Sum256(raw)
			digests[st.key] = hex.EncodeToString(sum[:12])
		}
	}
	return digests
}

// encode returns the JSON of the field of st in s.
func (st setting) encode(s *Settings) []byte {
	v := st.field(s)
	if d, ok := v.(*time.Duration); ok {
		v = int64(*d / time.Second) // whole: Validate refuses a fraction
	}
	if l, ok := v.(*[]string); ok && *l == nil {
		return []byte("[]") // a list, never null, which decode refuses
	}
	b, _ := json.Marshal(v) // bools, numbers, strings and string lists
	return b
}

// settingsFrom assembles the rows of the setting table, by key, over the
// defaults, and validates them. An unknown key is a warning, so that an older
// version still starts on the table of a newer one; a value of the wrong type
// is an error. The locales are not those of a catalog: the theme brings its
// own, which the pages know, not the store (Q92).
func settingsFrom(rows map[string][]byte, keys *secretbox.Keys) (Settings, []string, error) {
	s, warnings, err := decodeSettings(rows, keys)
	if err != nil {
		return Settings{}, warnings, err
	}
	return s, warnings, s.Validate()
}

// SettingsOf assembles settings from values, by key of the registry, each in
// the JSON of its type (durations in seconds), over the defaults, as the
// setting table is read, without Validate; an unknown key is a warning, a
// value of the wrong type an error. tools/symfonyimport reads the settings of
// Symfony with it.
func SettingsOf(values map[string]json.RawMessage) (Settings, []string, error) {
	rows := make(map[string][]byte, len(values))
	for k, v := range values {
		rows[k] = v
	}
	return decodeSettings(rows, nil)
}

// decodeSettings is settingsFrom without the validation.
func decodeSettings(rows map[string][]byte, keys *secretbox.Keys) (Settings, []string, error) {
	s := DefaultSettings()
	var warnings []string
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		st, ok := lookup(key)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("setting %q is unknown to this version: ignored", key))
			continue
		}
		if err := st.decodeRow(rows[key], &s, keys); err != nil {
			errs = append(errs, fmt.Errorf("setting %s: %w", key, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Settings{}, warnings, err
	}
	return s, warnings, nil
}

// Validate checks the settings as a whole: durations in whole positive
// seconds, webhook locations, locales well formed, whether a catalog holds
// them or not (Q92).
func (s Settings) Validate() error {
	var errs []error
	s.Check(func(key, format string, args ...any) {
		errs = append(errs, fmt.Errorf("setting %s: %s", key, fmt.Sprintf(format, args...)))
	})
	return errors.Join(errs...)
}

// Check is Validate, each problem reported under the key of its setting.
func (s Settings) Check(fail domain.Fail) {
	for _, d := range []struct {
		key   string
		value time.Duration
	}{
		{"challenge_ttl", s.ChallengeTTL},
		{"login_remember_for", s.LoginRememberFor},
		{"consent_remember_for", s.ConsentRememberFor},
	} {
		switch {
		case d.value <= 0:
			fail(d.key, "must be positive")
		case d.value%time.Second != 0:
			fail(d.key, "must be a whole number of seconds")
		}
	}
	for _, u := range []struct{ key, value string }{
		{"login_accept_webhook_url", s.LoginAcceptWebhookURL},
		{"consent_accept_webhook_url", s.ConsentAcceptWebhookURL},
	} {
		if u.value == "" {
			continue
		}
		if err := checkWebhook(u.value); err != nil {
			fail(u.key, "%v", err)
		}
	}
	if len(s.SupportedLocales) == 0 {
		fail("supported_locales", "is empty")
	}
	for i, l := range s.SupportedLocales {
		switch {
		case l == "":
			fail("supported_locales", "holds an empty locale")
		case !i18n.WellFormed(l):
			fail("supported_locales", "%q is not a locale in lowercase (fr, pt-br)", l)
		case slices.Contains(s.SupportedLocales[:i], l):
			fail("supported_locales", "%q is listed twice", l)
		}
	}
	if !slices.Contains(s.SupportedLocales, s.DefaultLocale) {
		fail("default_locale", "%q is not in supported_locales", s.DefaultLocale)
	}
	if !i18n.WellFormed(s.FallbackLocale) {
		fail("fallback_locale", "%q is not a locale in lowercase (fr, pt-br)", s.FallbackLocale)
	}
	if s.SkipScopes != SkipScopesEqual && s.SkipScopes != SkipScopesSubset && s.SkipScopes != SkipScopesAny {
		fail("skip_scopes", "%q is none of %s, %s, %s", s.SkipScopes, SkipScopesEqual, SkipScopesSubset, SkipScopesAny)
	}
	if s.ACRValuesMode != ACRValuesPrefer && s.ACRValuesMode != ACRValuesRequire {
		fail("acr_values_mode", "%q is neither %s nor %s", s.ACRValuesMode, ACRValuesPrefer, ACRValuesRequire)
	}
	s.AdminOIDC.check(fail)
}

// check checks the block admin_oidc: enabled, it names its provider and its
// client; the endpoints declared all three or none. Whether http is allowed
// is serve's (tls.allow_http).
func (o AdminOIDC) check(fail domain.Fail) {
	if o.Enabled {
		if o.Issuer == "" {
			fail("admin_oidc.issuer", "is required when admin_oidc.enabled is true")
		}
		if o.ClientID == "" {
			fail("admin_oidc.client_id", "is required when admin_oidc.enabled is true")
		}
		if !slices.Contains(o.Scopes, "openid") {
			fail("admin_oidc.scopes", "lacks openid: no ID token would come")
		}
		if o.UsernameClaim == "" {
			fail("admin_oidc.username_claim", "is required when admin_oidc.enabled is true")
		}
	}
	for _, u := range []struct{ key, value string }{
		{"admin_oidc.issuer", o.Issuer}, {"admin_oidc.authorization_endpoint", o.AuthorizationEndpoint},
		{"admin_oidc.token_endpoint", o.TokenEndpoint}, {"admin_oidc.jwks_uri", o.JWKSURI},
	} {
		if u.value == "" {
			continue
		}
		if _, err := domain.AbsoluteURL(u.value); err != nil {
			fail(u.key, "%v", err)
		}
	}
	if declared := []bool{o.AuthorizationEndpoint != "", o.TokenEndpoint != "", o.JWKSURI != ""}; slices.Contains(declared, true) && slices.Contains(declared, false) {
		fail("admin_oidc.authorization_endpoint", "and admin_oidc.token_endpoint and admin_oidc.jwks_uri are declared together, or none of them")
	}
	for _, l := range []struct {
		key    string
		values []string
	}{{"admin_oidc.scopes", o.Scopes}, {"admin_oidc.required_acr", o.RequiredACR}} {
		for _, v := range l.values {
			if v == "" || strings.ContainsFunc(v, unicode.IsSpace) {
				fail(l.key, "%q is empty or holds a space", v)
			}
		}
	}
	if strings.ContainsRune(o.ClientSecret, 0) || strings.ContainsRune(o.ClientID, 0) {
		fail("admin_oidc.client_id", "or admin_oidc.client_secret holds a NUL character")
	}
}

// uriScheme is the scheme of a URL (RFC 3986), colon included.
var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// WebhookScheme is the scheme of a webhook location, in lowercase; "" for a
// command line.
func WebhookScheme(location string) string {
	return strings.ToLower(strings.TrimSuffix(uriScheme.FindString(location), ":"))
}

// checkWebhook checks a webhook location as Symfony reads it: an http(s) URL;
// a file:// URL, the program to run without arguments; or, without a scheme,
// a command line, split on spaces and run without a shell.
func checkWebhook(location string) error {
	scheme := WebhookScheme(location)
	if scheme == "" {
		if strings.TrimSpace(location) == "" {
			return errors.New("is a blank command")
		}
		return nil
	}
	u, err := url.Parse(location)
	switch scheme {
	case "http", "https":
		if err != nil || u.Host == "" {
			return errors.New("is not an absolute http(s) URL")
		}
	case "file":
		if err != nil || u.Path == "" {
			return errors.New("is a file:// URL without a path")
		}
	default:
		return fmt.Errorf("has the scheme %q: http, https or file, or a command without a scheme", scheme)
	}
	return nil
}
