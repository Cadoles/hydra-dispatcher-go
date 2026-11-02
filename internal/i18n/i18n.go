// Package i18n holds the catalogs of the pages, fr and en, embedded in the
// binary, and the negotiation of the page's locale.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
)

//go:embed *.json
var files embed.FS

// Catalogs are the texts of each locale, by key.
type Catalogs map[string]map[string]string

// Embedded returns the catalogs of the binary.
func Embedded() (Catalogs, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	c := Catalogs{}
	for _, e := range entries {
		data, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		texts := map[string]string{}
		if err := json.Unmarshal(data, &texts); err != nil {
			return nil, fmt.Errorf("catalog %s: %w", e.Name(), err)
		}
		c[strings.TrimSuffix(e.Name(), path.Ext(e.Name()))] = texts
	}
	return c, nil
}

// Locales returns the locales of the catalogs, sorted.
func (c Catalogs) Locales() []string {
	out := make([]string, 0, len(c))
	for l := range c {
		out = append(out, l)
	}
	slices.Sort(out)
	return out
}

// T returns the text of key in locale, else in fallback, else the key
// itself, so that a missing text shows rather than an empty one. args fill
// its %s, in order; a text without them ignores them.
func (c Catalogs) T(locale, fallback, key string, args ...any) string {
	text, ok := c[locale][key]
	if !ok {
		if text, ok = c[fallback][key]; !ok {
			return key
		}
	}
	if len(args) == 0 || !strings.Contains(text, "%") {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// Negotiate returns the locale of a page among supported (Page de sélection
// de flow, négociation de la langue): the request's _locale parameter, then
// the dispatcher_locale cookie, then the oidc_context's ui_locales of the
// login request (exact match, then primary subtag: fr-CA gives fr), then
// def, the default locale.
func Negotiate(param, cookie string, uiLocales []string, supported []string, def string) string {
	for _, l := range []string{param, cookie} {
		if slices.Contains(supported, l) {
			return l
		}
	}
	for _, l := range uiLocales {
		if l = strings.ToLower(l); slices.Contains(supported, l) {
			return l
		}
	}
	for _, l := range uiLocales {
		primary, _, _ := strings.Cut(strings.ToLower(l), "-")
		if slices.Contains(supported, primary) {
			return primary
		}
	}
	return def
}
