package i18n

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// Each locale has every key of the others, and Locales, which the settings'
// registry reads (internal/store), names the catalogs.
func TestCatalogs(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Locales(), []string{"en", "fr"}) || !slices.Equal(Locales(), c.Locales()) {
		t.Fatalf("locales %v, Locales %v", c.Locales(), Locales())
	}
	if !c.Has("fr", "choice.title") || c.Has("fr", "nope") || c.Has("de", "choice.title") {
		t.Error("Has")
	}
	for _, a := range c.Locales() {
		for _, b := range c.Locales() {
			for k := range c[a] {
				if _, ok := c[b][k]; !ok {
					t.Errorf("%s has %s, %s has not", a, k, b)
				}
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(c["fr"])) {
		if strings.TrimSpace(c["fr"][k]) == "" {
			t.Errorf("fr %s is empty", k)
		}
	}
}

func TestT(t *testing.T) {
	c := Catalogs{"fr": {"a": "Bonjour %s"}, "en": {"a": "Hello %s", "b": "Only in English"}}
	for _, tc := range []struct{ locale, key, want string }{
		{"fr", "a", "Bonjour Alice"},
		{"fr", "b", "Only in English"},
		{"fr", "c", "c"},
		{"de", "a", "Hello Alice"},
	} {
		if got := c.T(tc.locale, "en", tc.key, "Alice"); got != tc.want {
			t.Errorf("%s %s: %q", tc.locale, tc.key, got)
		}
	}
}

func TestNegotiate(t *testing.T) {
	supported := []string{"fr", "en"}
	for _, tc := range []struct {
		param, cookie string
		ui            []string
		want          string
	}{
		{"en", "fr", []string{"fr"}, "en"},
		{"de", "en", []string{"fr"}, "en"},
		{"", "", []string{"de", "EN"}, "en"},
		{"", "", []string{"fr-CA", "en"}, "en"},
		{"", "", []string{"fr-CA"}, "fr"},
		{"", "", []string{"de"}, "fr"},
		{"", "", nil, "fr"},
	} {
		if got := Negotiate(tc.param, tc.cookie, tc.ui, supported, "fr"); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}
