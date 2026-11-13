package domain

import (
	"slices"
	"strings"
	"testing"
)

func TestStandardScopes(t *testing.T) {
	profile, ok := Standard("profile")
	if !ok || len(profile) != 14 || !slices.Contains(profile, "picture") || !slices.Contains(profile, "updated_at") {
		t.Errorf("profile: %v", profile)
	}
	if _, ok := Standard("groups"); ok {
		t.Error("groups is standard")
	}
}

func TestScopeCheck(t *testing.T) {
	ok := Scope{Name: "groups", Label: map[string]string{"fr": "Vos groupes", "": "Groups"}, Claims: []ScopeClaim{{Claim: "groups", Label: map[string]string{"en": "Groups"}}}}
	if v := Collect(ok.Check); v != nil {
		t.Errorf("valid: %v", v)
	}
	for name, s := range map[string]Scope{
		"no name":                   {},
		"a space":                   {Name: "my scope"},
		"a tab":                     {Name: "my\tscope"},
		"too long":                  {Name: strings.Repeat("s", 129)},
		"a claim twice":             {Name: "g", Claims: []ScopeClaim{{Claim: "a"}, {Claim: "a"}}},
		"a claim unnamed":           {Name: "g", Claims: []ScopeClaim{{}}},
		"a NUL locale":              {Name: "g", Label: map[string]string{"f\x00r": "x"}},
		"a NUL label":               {Name: "g", Label: map[string]string{"fr": "x\x00"}},
		"a claim added to standard": {Name: "profile", Claims: []ScopeClaim{{Claim: "groups"}}},
		// RFC 6749, 3.3; neither "." nor ".." (revue R44).
		"a zero-width space":  {Name: "email\u200b"},
		"a byte order mark":   {Name: "\ufeffemail"},
		"a letter of Latin-1": {Name: "privé"},
		"a quote":             {Name: `a"b`},
		"a backslash":         {Name: `a\b`},
		"a DEL":               {Name: "a\x7f"},
		"a dot":               {Name: "."},
		"two dots":            {Name: ".."},
	} {
		if v := Collect(s.Check); v == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, name := range []string{"https://api.test/read", "...", ".hidden", "a.b", "offline_access", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~", strings.Repeat("s", 128)} {
		if v := Collect(Scope{Name: name}.Check); v != nil {
			t.Errorf("%q refused: %v", name, v)
		}
	}
	renamed := Scope{Name: "profile", Label: map[string]string{"fr": "Votre identité"}, Claims: []ScopeClaim{{Claim: "picture", Label: map[string]string{"fr": "Votre photo"}}}}
	if v := Collect(renamed.Check); v != nil {
		t.Errorf("a standard renamed: %v", v)
	}
}

// The name of an account is no segment of a path (revue R42).
func TestUsernameDots(t *testing.T) {
	for _, name := range []string{".", ".."} {
		if v := Collect(func(fail Fail) { CheckUsername(fail, name) }); v == nil || v[0].Field != "username" {
			t.Errorf("%q: %v", name, v)
		}
	}
	for _, name := range []string{"...", ".alice", "alice.", "a.b"} {
		if v := Collect(func(fail Fail) { CheckUsername(fail, name) }); v != nil {
			t.Errorf("%q refused: %v", name, v)
		}
	}
}
