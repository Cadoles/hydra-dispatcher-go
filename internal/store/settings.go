package store

import (
	"bytes"
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

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
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
	}
}

// setting is a key of the registry. Its value is the JSON of the field,
// durations in seconds as Symfony stored them.
type setting struct {
	key   string
	help  string
	field func(s *Settings) any
}

// registry declares every setting the dispatcher reads.
var registry = []setting{
	{"app_auto_select", "start the only flow offered without the choice page", func(s *Settings) any { return &s.AppAutoSelect }},
	{"consent_auto_accept", "accept the consent without the consent screen", func(s *Settings) any { return &s.ConsentAutoAccept }},
	{"aggregate_amr_from_login_request", "send Hydra the amr the apps give rather than their methods", func(s *Settings) any { return &s.AggregateAMRFromLoginRequest }},
	{"challenge_ttl", "lifetime of a flow, in seconds", func(s *Settings) any { return &s.ChallengeTTL }},
	{"remember", "ask Hydra to remember the login and the consent", func(s *Settings) any { return &s.Remember }},
	{"login_remember_for", "lifetime of Hydra's login session and of the skip memory, in seconds", func(s *Settings) any { return &s.LoginRememberFor }},
	{"consent_remember_for", "how long Hydra remembers a consent, in seconds", func(s *Settings) any { return &s.ConsentRememberFor }},
	{"login_accept_webhook_url", "webhook called before the login accept: http(s) URL, file:// URL or command, empty for none", func(s *Settings) any { return &s.LoginAcceptWebhookURL }},
	{"consent_accept_webhook_url", "webhook called before the consent accept: http(s) URL, file:// URL or command, empty for none", func(s *Settings) any { return &s.ConsentAcceptWebhookURL }},
	{"supported_locales", "locales of the pages", func(s *Settings) any { return &s.SupportedLocales }},
	{"default_locale", "locale of the pages when the browser asks for none of them", func(s *Settings) any { return &s.DefaultLocale }},
	{"fallback_locale", "locale of a text missing from the page's locale", func(s *Settings) any { return &s.FallbackLocale }},
}

// SettingValue is a setting and its value, in the JSON of its type.
type SettingValue struct {
	Key   string
	Value json.RawMessage
}

// Document gives every setting of s, in the order of the registry: the
// document of the admin API (Q105).
func (s Settings) Document() []SettingValue {
	values := make([]SettingValue, len(registry))
	for i, st := range registry {
		values[i] = SettingValue{Key: st.key, Value: st.encode(&s)}
	}
	return values
}

// SettingKey is a key of the registry and its help, for the admin forms.
type SettingKey struct{ Key, Help string }

// SettingKeys lists the registry, in its order.
func SettingKeys() []SettingKey {
	keys := make([]SettingKey, len(registry))
	for i, st := range registry {
		keys[i] = SettingKey{st.key, st.help}
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

// encode returns the JSON of the field of st in s.
func (st setting) encode(s *Settings) []byte {
	v := st.field(s)
	if d, ok := v.(*time.Duration); ok {
		v = int64(*d / time.Second) // whole: Validate refuses a fraction
	}
	b, _ := json.Marshal(v) // bools, numbers, strings and string lists
	return b
}

// settingsFrom assembles the rows of the setting table, by key, over the
// defaults, and validates them. An unknown key is a warning, so that an older
// version still starts on the table of a newer one; a value of the wrong type
// is an error. The locales are not those of a catalog: the theme brings its
// own, which the pages know, not the store (Q92).
func settingsFrom(rows map[string][]byte) (Settings, []string, error) {
	s, warnings, err := decodeSettings(rows)
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
	return decodeSettings(rows)
}

// decodeSettings is settingsFrom without the validation.
func decodeSettings(rows map[string][]byte) (Settings, []string, error) {
	s := DefaultSettings()
	var warnings []string
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		st, ok := lookup(key)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("setting %q is unknown to this version: ignored", key))
			continue
		}
		if err := st.decode(rows[key], &s); err != nil {
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
