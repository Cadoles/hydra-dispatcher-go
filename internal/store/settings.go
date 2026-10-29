package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/url"
	"slices"
	"time"
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

// catalogLocales are the locales the pages have a catalog for. internal/i18n
// will hold them.
var catalogLocales = []string{"fr", "en"}

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
	{"login_accept_webhook_url", "webhook called before the login accept, empty for none", func(s *Settings) any { return &s.LoginAcceptWebhookURL }},
	{"consent_accept_webhook_url", "webhook called before the consent accept, empty for none", func(s *Settings) any { return &s.ConsentAcceptWebhookURL }},
	{"supported_locales", "locales of the pages", func(s *Settings) any { return &s.SupportedLocales }},
	{"default_locale", "locale of the pages when the browser asks for none of them", func(s *Settings) any { return &s.DefaultLocale }},
	{"fallback_locale", "locale of a text missing from the page's locale", func(s *Settings) any { return &s.FallbackLocale }},
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
		secs, err := n.Int64()
		if !ok || err != nil || secs > math.MaxInt64/int64(time.Second) || secs < math.MinInt64/int64(time.Second) {
			return fmt.Errorf("%s is not a whole number of seconds", bytes.TrimSpace(raw))
		}
		*p = time.Duration(secs) * time.Second
	default:
		if err := dec.Decode(p); err != nil {
			return err
		}
	}
	if dec.More() {
		return errors.New("holds more than one value")
	}
	return nil
}

// encode returns the JSON of the field of st in s.
func (st setting) encode(s *Settings) []byte {
	v := st.field(s)
	if d, ok := v.(*time.Duration); ok {
		v = int64(*d / time.Second)
	}
	b, _ := json.Marshal(v) // bools, numbers, strings and string lists
	return b
}

// settingsFrom assembles the rows of the setting table, by key, over the
// defaults, and validates them. An unknown key is a warning, so that an older
// version still starts on the table of a newer one; a value of the wrong type
// is an error.
func settingsFrom(rows map[string][]byte) (Settings, []string, error) {
	s, warnings, err := decodeSettings(rows)
	if err != nil {
		return Settings{}, warnings, err
	}
	return s, warnings, s.Validate()
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

// Validate checks the settings as a whole: positive durations, webhook URLs,
// locales that have a catalog.
func (s Settings) Validate() error {
	var errs []error
	fail := func(key, format string, args ...any) {
		errs = append(errs, fmt.Errorf("setting %s: %s", key, fmt.Sprintf(format, args...)))
	}
	for _, d := range []struct {
		key   string
		value time.Duration
	}{
		{"challenge_ttl", s.ChallengeTTL},
		{"login_remember_for", s.LoginRememberFor},
		{"consent_remember_for", s.ConsentRememberFor},
	} {
		if d.value <= 0 {
			fail(d.key, "must be positive")
		}
	}
	for _, u := range []struct{ key, value string }{
		{"login_accept_webhook_url", s.LoginAcceptWebhookURL},
		{"consent_accept_webhook_url", s.ConsentAcceptWebhookURL},
	} {
		if u.value == "" {
			continue
		}
		if p, err := url.Parse(u.value); err != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https") {
			fail(u.key, "is not an absolute http(s) URL")
		}
	}
	if len(s.SupportedLocales) == 0 {
		fail("supported_locales", "is empty")
	}
	for i, l := range s.SupportedLocales {
		switch {
		case !slices.Contains(catalogLocales, l):
			fail("supported_locales", "%q has no catalog, only %v do", l, catalogLocales)
		case slices.Contains(s.SupportedLocales[:i], l):
			fail("supported_locales", "%q is listed twice", l)
		}
	}
	if !slices.Contains(s.SupportedLocales, s.DefaultLocale) {
		fail("default_locale", "%q is not in supported_locales", s.DefaultLocale)
	}
	if !slices.Contains(catalogLocales, s.FallbackLocale) {
		fail("fallback_locale", "%q has no catalog, only %v do", s.FallbackLocale, catalogLocales)
	}
	return errors.Join(errs...)
}
