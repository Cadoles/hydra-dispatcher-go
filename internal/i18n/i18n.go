// Package i18n holds the catalogs of the pages, fr and en, embedded in the
// binary, those a theme adds or changes, and the negotiation of the page's
// locale.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
)

//go:embed *.json
var files embed.FS

// Catalogs are the texts of each locale, by key.
type Catalogs map[string]map[string]string

// Embedded returns the catalogs of the binary.
func Embedded() (Catalogs, error) { return Read(files) }

// Read returns the catalogs of fsys, a <locale>.json of a flat object, key to
// text, for each locale: the embedded ones, or the translations/ of a theme.
// Anything else is refused, a file a theme author would think read: another
// name, a directory, a locale that is not well formed, a value that is not a
// text.
func Read(fsys fs.FS) (Catalogs, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	c := Catalogs{}
	for _, e := range entries {
		locale, ok := strings.CutSuffix(e.Name(), ".json")
		switch {
		case e.IsDir() || !ok:
			return nil, fmt.Errorf("%s: not a <locale>.json", e.Name())
		case !WellFormed(locale):
			return nil, fmt.Errorf("%s: %q is not a locale in lowercase (fr, pt-br)", e.Name(), locale)
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		texts := map[string]string{}
		if err := json.Unmarshal(data, &texts); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		c[locale] = texts
	}
	return c, nil
}

// Merge returns c with the texts of over, key by key: a theme changes the
// texts it gives and adds the locales it brings.
func (c Catalogs) Merge(over Catalogs) Catalogs {
	out := Catalogs{}
	for l, texts := range c {
		out[l] = maps.Clone(texts)
	}
	for l, texts := range over {
		if out[l] == nil {
			out[l] = map[string]string{}
		}
		maps.Copy(out[l], texts)
	}
	return out
}

// locale is a language tag (BCP 47) in lowercase, as Negotiate compares them:
// a language, then subtags of letters or digits.
var locale = regexp.MustCompile(`^[a-z]{2,3}(-[a-z0-9]{1,8})*$`)

// WellFormed tells whether l is a locale the settings and the themes may name,
// whether or not a catalog holds it (Q92).
func WellFormed(l string) bool { return locale.MatchString(l) }

// Has tells whether the catalog of locale holds key, without falling back.
func (c Catalogs) Has(locale, key string) bool {
	_, ok := c[locale][key]
	return ok
}

// Locales returns the locales of the catalogs, sorted.
func (c Catalogs) Locales() []string {
	return slices.Sorted(maps.Keys(c))
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
