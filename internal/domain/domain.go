// Package domain holds the entities of the configuration and the rules they
// follow, whoever writes them: the seed of bootstrap and the writes of the
// store check them alike, before anything reaches the database. The rules of
// the snapshot as a whole, settings included, stay with the store.
package domain

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// App is a login app.
type App struct {
	ID         string
	LoginURL   string
	ConsentURL string
	// LogoutURL "" leaves the app out of the logout.
	LogoutURL string
	Method    string
	// AuthMode is network (AllowedSources) or mtls (ClientCertFingerprint):
	// how the emulated API knows the app.
	AuthMode              string
	AllowedSources        []netip.Prefix
	ClientCertFingerprint string
	// ReceiveClaims names the claims of the previous steps the app receives:
	// all of them when nil, none when empty.
	ReceiveClaims []string
}

// Flow is a sequence of apps the user may choose.
type Flow struct {
	ID          string
	Title       map[string]string
	Description map[string]string
	// IconURL is nil for no icon.
	IconURL map[string]string
	Enabled bool
	// ACR "" sends none.
	ACR   string
	Steps []Step // by position
}

type Step struct {
	AppID        string `json:"app_id"`
	Position     int    `json:"position"`
	SubjectCheck string `json:"subject_check"` // none, equal or claim:<name>
}

// APIClient is a client of the admin API.
type APIClient struct {
	ID string
	// SecretHash is the bcrypt hash of its secret (HashSecret).
	SecretHash string
	Scopes     []string
}

// Fail reports a violation of field, a path in the entity ("login_url",
// "steps[1].subject_check"), "" for the entity itself.
type Fail func(field, format string, args ...any)

// Lengths of the columns: past them, Postgres refuses the row with an error
// that names neither the entity nor the field.
const (
	maxMethod       = 64
	maxACR          = 255
	maxSubjectCheck = 128
)

// id is Symfony's ResourceId: an id is a path segment of the admin API
// (/admin/v1/apps/{id}).
var id = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidID tells whether s is an id of an app, a flow or an API client.
func ValidID(s string) bool { return id.MatchString(s) }

// CheckID checks the id of an entity.
func CheckID(fail Fail, s string) {
	switch {
	case s == "":
		fail("id", "is required")
	case !ValidID(s):
		fail("id", "%q is not an id: up to 128 letters, digits, '.', '_' or '-', starting with a letter or a digit", s)
	}
}

// Check checks a, its id included.
func (a App) Check(fail Fail) {
	CheckID(fail, a.ID)
	for _, u := range []struct{ field, value string }{
		{"login_url", a.LoginURL}, {"consent_url", a.ConsentURL}, {"logout_url", a.LogoutURL},
	} {
		if u.value == "" && u.field == "logout_url" {
			continue
		}
		if _, err := AbsoluteURL(u.value); err != nil {
			fail(u.field, "%v", err)
		}
	}
	if a.Method == "" {
		fail("method", "is required")
	}
	text(fail, "method", a.Method, maxMethod)
	// The field of the other mode would pass unread.
	switch a.AuthMode {
	case "network":
		if a.ClientCertFingerprint != "" {
			fail("client_cert_fingerprint", "only applies to auth_mode: mtls")
		}
	case "mtls":
		if len(a.AllowedSources) > 0 {
			fail("allowed_sources", "only applies to auth_mode: network")
		}
		if b, err := hex.DecodeString(a.ClientCertFingerprint); err != nil || len(b) != sha256.Size ||
			a.ClientCertFingerprint != NormalizeFingerprint(a.ClientCertFingerprint) {
			fail("client_cert_fingerprint", "must be the SHA-256 of the app certificate, in hex, for auth_mode: mtls")
		}
	default:
		fail("auth_mode", "%q is not network or mtls", a.AuthMode)
	}
	for i, p := range a.AllowedSources {
		if !p.IsValid() || p != p.Masked() {
			fail(fmt.Sprintf("allowed_sources[%d]", i), "%q is not a network in its canonical form", p)
		}
	}
	for i, c := range a.ReceiveClaims {
		nonEmpty(fail, fmt.Sprintf("receive_claims[%d]", i), c)
	}
}

// NormalizeFingerprint gives a certificate fingerprint the form the emulated
// API compares: lowercase hex, without the colons of openssl's output.
func NormalizeFingerprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, ":", ""))
}

// Check checks f, its id included; app tells whether an app exists.
func (f Flow) Check(fail Fail, app func(id string) bool) {
	CheckID(fail, f.ID)
	for _, t := range []struct {
		field    string
		texts    map[string]string
		required bool
	}{{"title", f.Title, true}, {"description", f.Description, true}, {"icon_url", f.IconURL, false}} {
		if t.required && !slices.ContainsFunc(slices.Collect(maps.Values(t.texts)), func(s string) bool { return s != "" }) {
			fail(t.field, "is required")
		}
		for locale, s := range t.texts {
			if strings.ContainsRune(locale, 0) {
				fail(t.field, "key %q contains a NUL character, which Postgres does not store", locale)
			}
			text(fail, t.field, s, 0)
		}
	}
	if len(f.Steps) == 0 {
		fail("steps", "is empty")
	}
	text(fail, "acr", f.ACR, maxACR)
	if strings.ContainsFunc(f.ACR, unicode.IsSpace) {
		// acr_values is a space-separated list: no value would match.
		fail("acr", "%q contains a space", f.ACR)
	}
	apps, positions := map[string]bool{}, map[int]bool{}
	for j, s := range f.Steps {
		field := fmt.Sprintf("steps[%d]", j)
		switch {
		case !app(s.AppID):
			fail(field, "app %q is not declared", s.AppID)
		case apps[s.AppID]:
			fail(field, "app %q is already a step of this flow", s.AppID)
		}
		if positions[s.Position] {
			fail(field, "position %d is already taken in this flow", s.Position)
		}
		if s.Position < math.MinInt32 || s.Position > math.MaxInt32 {
			fail(field, "position %d is out of range: the database keeps 32-bit integers", s.Position)
		}
		apps[s.AppID], positions[s.Position] = true, true
		if c := s.SubjectCheck; c != "none" && c != "equal" && (!strings.HasPrefix(c, "claim:") || c == "claim:") {
			fail(field+".subject_check", "%q is not none, equal or claim:<name>", c)
		} else {
			text(fail, field+".subject_check", c, maxSubjectCheck)
		}
	}
}

// Check checks c, its id included.
func (c APIClient) Check(fail Fail) {
	CheckID(fail, c.ID)
	if _, err := bcrypt.Cost([]byte(c.SecretHash)); err != nil {
		fail("secret", "is not a bcrypt hash")
	}
	CheckScopes(fail, c.Scopes)
}

// CheckScopes checks the scopes of an API client: a token request names them
// separated by spaces.
func CheckScopes(fail Fail, scopes []string) {
	for i, s := range scopes {
		field := fmt.Sprintf("scopes[%d]", i)
		nonEmpty(fail, field, s)
		if strings.ContainsFunc(s, unicode.IsSpace) {
			fail(field, "%q contains a space", s)
		}
	}
}

// nonEmpty checks an item of a list: a name, never empty.
func nonEmpty(fail Fail, field, s string) {
	if s == "" {
		fail(field, "is empty")
	}
	text(fail, field, s, 0)
}

// text checks a string Postgres stores: UTF-8 without NUL, and max characters
// at most when max is positive.
func text(fail Fail, field, s string, max int) {
	switch {
	case strings.ContainsRune(s, 0):
		fail(field, "contains a NUL character, which Postgres does not store")
	case !utf8.ValidString(s):
		fail(field, "is not UTF-8")
	case max > 0 && utf8.RuneCountInString(s) > max:
		fail(field, "is longer than %d characters", max)
	}
}

// AbsoluteURL parses an absolute http(s) URL. Errors hide its password,
// query and fragment.
func AbsoluteURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("is not a valid URL") // url.Parse quotes it whole
	}
	switch {
	case u.Host == "":
		// Without an authority, as in https//user:password@host, the
		// password stays in the path: no quote.
		return nil, errors.New("is not an absolute http(s) URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", Redacted(u))
	}
	return u, nil
}

// Redacted writes u for an error, without what may hold a secret: password,
// query (?token=…) and fragment.
func Redacted(u *url.URL) string {
	v := *u
	v.RawQuery, v.ForceQuery, v.Fragment, v.RawFragment = "", false, "", ""
	return v.Redacted()
}

// ParsePrefixes reads networks and addresses, an address being the network
// of that address alone, in the form the store keeps and the emulated API
// compares: masked, an IPv4 address mapped in IPv6 written as IPv4.
func ParsePrefixes(l []string) ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(l))
	for _, s := range l {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is neither a CIDR nor an IP address", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 128-32 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-(128-32))
		}
		ps = append(ps, p.Masked())
	}
	return ps, nil
}

// HashSecret hashes the secret of an API client. bcrypt reads 72 bytes: a
// longer secret, or one holding a NUL, is hashed first, as Symfony's
// NativePasswordHasher does (BcryptInput).
func HashSecret(secret string) (string, error) {
	h, err := bcrypt.GenerateFromPassword(BcryptInput(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// SecretMatches tells whether secret is the one hash holds.
func SecretMatches(hash, secret string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), BcryptInput(secret)) == nil
}

// BcryptInput is what bcrypt hashes of a client secret, the secret itself up
// to the 72 bytes bcrypt reads. A longer one, or one holding a NUL, is hashed
// first, as Symfony's NativePasswordHasher does: SHA-512 in base64, of which
// bcrypt reads 72 bytes too. Whatever checks a secret against its hash goes
// through it.
func BcryptInput(secret string) []byte {
	if len(secret) <= 72 && !strings.ContainsRune(secret, 0) {
		return []byte(secret)
	}
	sum := sha512.Sum512([]byte(secret))
	return []byte(base64.StdEncoding.EncodeToString(sum[:])[:72])
}
