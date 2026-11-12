package domain

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Scope is a scope of the catalogue (Page de consent): its label and the
// labels of its claims, by locale. A standard scope is the code's (Q125):
// its row, when there is one, renames labels alone.
type Scope struct {
	Name   string
	Label  map[string]string
	Claims []ScopeClaim
}

// ScopeClaim is a claim a scope covers, its label by locale.
type ScopeClaim struct {
	Claim string            `json:"claim"`
	Label map[string]string `json:"label"`
}

// StandardScope is a scope of OpenID Connect, and the claims it covers.
type StandardScope struct {
	Name   string
	Claims []string
}

// StandardScopes are the scopes of OpenID Connect Core 1.0, section 5.4, and
// openid with sub (Q130), in this order.
var StandardScopes = []StandardScope{
	{"openid", []string{"sub"}},
	{"profile", []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile",
		"picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"}},
	{"email", []string{"email", "email_verified"}},
	{"address", []string{"address"}},
	{"phone", []string{"phone_number", "phone_number_verified"}},
}

// Standard gives the claims of the standard scope name; false for a scope
// of the business.
func Standard(name string) ([]string, bool) {
	i := slices.IndexFunc(StandardScopes, func(s StandardScope) bool { return s.Name == name })
	if i < 0 {
		return nil, false
	}
	return StandardScopes[i].Claims, true
}

// maxScope is the length of scope.name.
const maxScope = 128

// CheckScopeName checks the name of a scope: 1 to 128 characters, without a
// space nor a control character, as a token request separates them.
func CheckScopeName(fail Fail, s string) {
	switch {
	case s == "":
		fail("name", "is required")
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		fail("name", "%q holds a space or a control character", s)
	default:
		text(fail, "name", s, maxScope)
	}
}

// Check checks s: its name, its labels, its claims, named once each; those
// of a standard scope among the standard's, whose labels alone it renames.
func (s Scope) Check(fail Fail) {
	CheckScopeName(fail, s.Name)
	labels(fail, "label", s.Label)
	standard, isStandard := Standard(s.Name)
	seen := map[string]bool{}
	for i, c := range s.Claims {
		field := fmt.Sprintf("claims[%d]", i)
		switch {
		case c.Claim == "":
			fail(field, "names no claim")
		case seen[c.Claim]:
			fail(field, "%q is named twice", c.Claim)
		case isStandard && !slices.Contains(standard, c.Claim):
			fail(field, "%q is no claim of the standard scope %s, whose labels alone change", c.Claim, s.Name)
		}
		seen[c.Claim] = true
		text(fail, field, c.Claim, 0)
		labels(fail, field+".label", c.Label)
	}
}

// labels checks the texts of a label by locale; the empty locale is every
// locale, as a plain string of the seed gives it.
func labels(fail Fail, field string, l map[string]string) {
	for locale, t := range l {
		if strings.ContainsRune(locale, 0) {
			fail(field, "has a locale holding a NUL character")
		}
		text(fail, field, t, 0)
	}
}
