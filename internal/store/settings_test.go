package store

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Every field of Settings has exactly one key, and every key its own field.
func TestRegistryCoversSettings(t *testing.T) {
	var s Settings
	base := reflect.ValueOf(&s).Elem()
	fields := map[uintptr]string{}
	for _, st := range registry {
		p := reflect.ValueOf(st.field(&s)).Pointer() - base.Addr().Pointer()
		if other, ok := fields[p]; ok {
			t.Errorf("%s and %s share a field", other, st.key)
		}
		fields[p] = st.key
		if st.help == "" {
			t.Errorf("%s has no help", st.key)
		}
	}
	if len(fields) != base.NumField() {
		t.Errorf("%d keys for %d fields of Settings", len(fields), base.NumField())
	}
	if keys := SettingKeys(); len(keys) != len(registry) || keys[0].Key != "app_auto_select" || keys[0].Help == "" {
		t.Errorf("SettingKeys = %v", keys)
	}
}

func TestDefaultSettings(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	// Those of Symfony.
	if s := DefaultSettings(); s.ChallengeTTL != time.Hour || s.LoginRememberFor != 86400*time.Second ||
		s.ConsentRememberFor != 2629800*time.Second || !s.Remember || s.DefaultLocale != "fr" || s.FallbackLocale != "en" {
		t.Errorf("defaults = %+v", s)
	}
}

// Encoded then decoded, every key gives its value back.
func TestSettingsRoundTrip(t *testing.T) {
	want := Settings{
		AppAutoSelect:                true,
		ConsentAutoAccept:            true,
		AggregateAMRFromLoginRequest: true,
		ChallengeTTL:                 30 * time.Minute,
		Remember:                     false,
		LoginRememberFor:             12 * time.Hour,
		ConsentRememberFor:           7 * 24 * time.Hour,
		LoginAcceptWebhookURL:        "http://hooks/login",
		ConsentAcceptWebhookURL:      "https://hooks/consent",
		SupportedLocales:             []string{"en"},
		DefaultLocale:                "en",
		FallbackLocale:               "fr",
	}
	rows := map[string][]byte{}
	for _, st := range registry {
		rows[st.key] = st.encode(&want)
	}
	if got := string(rows["challenge_ttl"]); got != "1800" {
		t.Errorf("challenge_ttl encoded as %s, want seconds", got)
	}
	got, warnings, err := settingsFrom(rows)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("settingsFrom = %v, %q", err, warnings)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestSettingsFrom(t *testing.T) {
	s, warnings, err := settingsFrom(map[string][]byte{
		"consent_auto_accept": []byte("true"),
		"login_remember_for":  []byte(" 3600 "),
		"session_ttl":         []byte("86400"), // a key of no version
	})
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultSettings()
	want.ConsentAutoAccept, want.LoginRememberFor = true, time.Hour
	if !reflect.DeepEqual(s, want) {
		t.Errorf("settings = %+v", s)
	}
	if !slices.Equal(warnings, []string{`setting "session_ttl" is unknown to this version: ignored`}) {
		t.Errorf("warnings = %q", warnings)
	}

	for raw, want := range map[string]string{
		`{"consent_auto_accept": "yes"}`:          "setting consent_auto_accept: json: cannot unmarshal string",
		`{"consent_auto_accept": null}`:           "setting consent_auto_accept: is null",
		`{"challenge_ttl": 1.5}`:                  "setting challenge_ttl: 1.5 is not a whole number of seconds",
		`{"challenge_ttl": "3600"}`:               `setting challenge_ttl: "3600" is not a whole number of seconds`,
		`{"challenge_ttl": 10000000000000000000}`: "setting challenge_ttl: 10000000000000000000 is out of range: 9223372036 seconds at most",
		`{"challenge_ttl": 9223372036}`:           "", // the longest a time.Duration holds
		`{"challenge_ttl": 9223372037}`:           "setting challenge_ttl: 9223372037 is out of range",
		`{"challenge_ttl": 1e400}`:                "setting challenge_ttl: 1e400 is out of range",
		`{"challenge_ttl": 3600.0}`:               "", // as Postgres keeps it
		`{"challenge_ttl": 1e3}`:                  "",
		`{"default_locale": "fr" }`:               "",
		`{"supported_locales": ["fr", 1]}`:        "setting supported_locales: json: cannot unmarshal number",
		`{"challenge_ttl": 0}`:                    "setting challenge_ttl: must be positive",
		// A null element is empty, not the default's element at its place.
		`{"supported_locales": [null]}`:       "setting supported_locales: holds an empty locale",
		`{"supported_locales": ["fr", null]}`: "setting supported_locales: holds an empty locale",
	} {
		rows := map[string][]byte{}
		// One key per case: split the object by hand.
		key, value, _ := strings.Cut(strings.Trim(raw, "{}"), ":")
		rows[strings.Trim(strings.TrimSpace(key), `"`)] = []byte(value)
		_, _, err := settingsFrom(rows)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", raw, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: err = %v, want %q", raw, err, want)
		}
	}
	for _, raw := range []string{"true false", "true]", "true }"} {
		if _, _, err := settingsFrom(map[string][]byte{"remember": []byte(raw)}); err == nil || !strings.Contains(err.Error(), "more than one value") {
			t.Errorf("%q: err = %v", raw, err)
		}
	}
	if s, _, err := settingsFrom(map[string][]byte{"challenge_ttl": []byte("3600.0")}); err != nil || s.ChallengeTTL != time.Hour {
		t.Errorf("3600.0: %v, %v", s.ChallengeTTL, err)
	}
}

func TestSettingsValidate(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*Settings)
		want   string
	}{
		"login lifetime":       {func(s *Settings) { s.LoginRememberFor = 0 }, "setting login_remember_for: must be positive"},
		"consent lifetime":     {func(s *Settings) { s.ConsentRememberFor = -time.Second }, "setting consent_remember_for: must be positive"},
		"under a second":       {func(s *Settings) { s.ChallengeTTL = 500 * time.Millisecond }, "setting challenge_ttl: must be a whole number of seconds"},
		"fraction of a second": {func(s *Settings) { s.LoginRememberFor = 1500 * time.Millisecond }, "setting login_remember_for: must be a whole number of seconds"},
		"webhook without host": {func(s *Settings) { s.LoginAcceptWebhookURL = "http:///hook" }, "setting login_accept_webhook_url: is not an absolute http(s) URL"},
		"webhook scheme":       {func(s *Settings) { s.ConsentAcceptWebhookURL = "ftp://hooks/consent" }, `setting consent_accept_webhook_url: has the scheme "ftp"`},
		"file without path":    {func(s *Settings) { s.LoginAcceptWebhookURL = "file://" }, "setting login_accept_webhook_url: is a file:// URL without a path"},
		"blank command":        {func(s *Settings) { s.LoginAcceptWebhookURL = "   " }, "setting login_accept_webhook_url: is a blank command"},
		"no locale":            {func(s *Settings) { s.SupportedLocales = nil }, "setting supported_locales: is empty"},
		"empty locale":         {func(s *Settings) { s.SupportedLocales = []string{"fr", ""} }, "setting supported_locales: holds an empty locale"},
		"locale in capitals":   {func(s *Settings) { s.SupportedLocales = []string{"fr", "pt-BR"} }, `setting supported_locales: "pt-BR" is not a locale in lowercase`},
		"locale with _":        {func(s *Settings) { s.SupportedLocales = []string{"fr", "pt_br"} }, `setting supported_locales: "pt_br" is not a locale`},
		"locale twice":         {func(s *Settings) { s.SupportedLocales = []string{"fr", "fr"} }, `"fr" is listed twice`},
		"default unsupported":  {func(s *Settings) { s.SupportedLocales = []string{"en"} }, `setting default_locale: "fr" is not in supported_locales`},
		"fallback":             {func(s *Settings) { s.FallbackLocale = "EN" }, `setting fallback_locale: "EN" is not a locale in lowercase`},
		"no fallback":          {func(s *Settings) { s.FallbackLocale = "" }, `setting fallback_locale: "" is not a locale`},
	} {
		s := DefaultSettings()
		tt.change(&s)
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
}

// A webhook is where Symfony found it: an http(s) URL, a file:// URL or a
// command line without a scheme.
func TestWebhookLocations(t *testing.T) {
	for _, location := range []string{
		"http://hooks/login",
		"HTTPS://hooks/consent",
		"file:///opt/hooks/login",
		"/opt/hooks/login",
		`/opt/hooks/login --at=10:00 "two words"`,
		"login-hook",
	} {
		s := DefaultSettings()
		s.LoginAcceptWebhookURL = location
		if err := s.Validate(); err != nil {
			t.Errorf("%q: %v", location, err)
		}
	}
}

// A locale is any well-formed one, whether a catalog holds it or not: a theme
// brings its own, which the pages know, not the store (Q92). A table a newer
// version wrote, or that names a theme's locale, is read as it is.
func TestSettingsLocales(t *testing.T) {
	rows := map[string][]byte{"supported_locales": []byte(`["fr", "de", "pt-br"]`), "default_locale": []byte(`"de"`), "fallback_locale": []byte(`"es"`)}
	got, warnings, err := settingsFrom(rows)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("settingsFrom = %v, warnings %q", err, warnings)
	}
	if !slices.Equal(got.SupportedLocales, []string{"fr", "de", "pt-br"}) || got.DefaultLocale != "de" || got.FallbackLocale != "es" {
		t.Errorf("settings = %+v", got)
	}
	// What no version would write stays an error.
	if _, _, err := settingsFrom(map[string][]byte{"supported_locales": []byte(`["fr", "de", "fr"]`)}); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("a locale twice: err = %v", err)
	}
}
