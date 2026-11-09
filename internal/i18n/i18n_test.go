package i18n

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// Each locale has every key of the others.
func TestCatalogs(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Locales(), []string{"en", "fr"}) {
		t.Fatalf("locales %v", c.Locales())
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

// The catalogs of a theme's translations/: a <locale>.json of texts for each
// locale; anything else is refused rather than left unread.
func TestRead(t *testing.T) {
	c, err := Read(fstest.MapFS{"fr.json": {Data: []byte(`{"a": "A"}`)}, "pt-br.json": {Data: []byte(`{}`)}})
	if err != nil || !slices.Equal(c.Locales(), []string{"fr", "pt-br"}) || c["fr"]["a"] != "A" {
		t.Fatalf("Read = %v, %v", c, err)
	}
	for name, tc := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"another file":   {fstest.MapFS{"README.md": {}}, "README.md: not a <locale>.json"},
		"a directory":    {fstest.MapFS{"de/fr.json": {}}, "de: not a <locale>.json"},
		"capitals":       {fstest.MapFS{"pt-BR.json": {Data: []byte(`{}`)}}, `pt-BR.json: "pt-BR" is not a locale in lowercase`},
		"underscore":     {fstest.MapFS{"pt_br.json": {Data: []byte(`{}`)}}, `pt_br.json: "pt_br" is not a locale`},
		"not JSON":       {fstest.MapFS{"de.json": {Data: []byte(`{"a": `)}}, "de.json: unexpected end of JSON input"},
		"not a text":     {fstest.MapFS{"de.json": {Data: []byte(`{"a": 1}`)}}, "de.json: json: cannot unmarshal number"},
		"nested objects": {fstest.MapFS{"de.json": {Data: []byte(`{"a": {"b": "c"}}`)}}, "de.json: json: cannot unmarshal object"},
	} {
		if _, err := Read(tc.fsys); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// A theme's texts replace those of the same key, the others stay, and a locale
// it brings is added; the catalogs merged are left as they were.
func TestMerge(t *testing.T) {
	base := Catalogs{"fr": {"a": "A", "b": "B"}, "en": {"a": "A"}}
	got := base.Merge(Catalogs{"fr": {"b": "Bé"}, "de": {"a": "Ä"}})
	if got["fr"]["a"] != "A" || got["fr"]["b"] != "Bé" || got["en"]["a"] != "A" || got["de"]["a"] != "Ä" {
		t.Errorf("Merge = %v", got)
	}
	if base["fr"]["b"] != "B" || base["de"] != nil {
		t.Errorf("the base changed: %v", base)
	}
}

func TestWellFormed(t *testing.T) {
	for l, want := range map[string]bool{
		"fr": true, "de": true, "pt-br": true, "zh-hant-tw": true, "gsw": true, "es-419": true,
		"": false, "f": false, "FR": false, "pt-BR": false, "pt_br": false, "fr-": false, "-fr": false, "fr--ca": false, "français": false, "../fr": false,
	} {
		if WellFormed(l) != want {
			t.Errorf("WellFormed(%q) = %v", l, !want)
		}
	}
}
