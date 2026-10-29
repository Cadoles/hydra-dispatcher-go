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
		`{"challenge_ttl": 10000000000000000000}`: "is not a whole number of seconds",
		`{"default_locale": "fr" }`:               "",
		`{"supported_locales": ["fr", 1]}`:        "setting supported_locales: json: cannot unmarshal number",
		`{"challenge_ttl": 0}`:                    "setting challenge_ttl: must be positive",
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
	if _, _, err := settingsFrom(map[string][]byte{"remember": []byte("true false")}); err == nil || !strings.Contains(err.Error(), "more than one value") {
		t.Errorf("two values: err = %v", err)
	}
}

func TestSettingsValidate(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*Settings)
		want   string
	}{
		"login lifetime":       {func(s *Settings) { s.LoginRememberFor = 0 }, "setting login_remember_for: must be positive"},
		"consent lifetime":     {func(s *Settings) { s.ConsentRememberFor = -time.Second }, "setting consent_remember_for: must be positive"},
		"relative webhook":     {func(s *Settings) { s.LoginAcceptWebhookURL = "/hook" }, "setting login_accept_webhook_url: is not an absolute http(s) URL"},
		"webhook scheme":       {func(s *Settings) { s.ConsentAcceptWebhookURL = "ftp://hooks/consent" }, "setting consent_accept_webhook_url"},
		"no locale":            {func(s *Settings) { s.SupportedLocales = nil }, "setting supported_locales: is empty"},
		"locale without texts": {func(s *Settings) { s.SupportedLocales = []string{"fr", "de"} }, `setting supported_locales: "de" has no catalog`},
		"locale twice":         {func(s *Settings) { s.SupportedLocales = []string{"fr", "fr"} }, `"fr" is listed twice`},
		"default unsupported":  {func(s *Settings) { s.SupportedLocales = []string{"en"} }, `setting default_locale: "fr" is not in supported_locales`},
		"fallback":             {func(s *Settings) { s.FallbackLocale = "de" }, `setting fallback_locale: "de" has no catalog`},
	} {
		s := DefaultSettings()
		tt.change(&s)
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
}
