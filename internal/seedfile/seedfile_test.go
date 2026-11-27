package seedfile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The block admin_oidc is dumped by the keys of the table; its secret, held
// encrypted, left out, a comment saying so.
func TestAdminOIDC(t *testing.T) {
	s := store.DefaultSettings()
	s.AdminOIDC.Enabled, s.AdminOIDC.Issuer, s.AdminOIDC.ClientID, s.AdminOIDC.ClientSecret = true, "https://idp.test", "dispatcher-admin", "s3cret-of-the-idp"
	snap := store.NewSnapshot(nil, nil, s)
	snap.StoredSettings = []string{"admin_oidc.enabled", "admin_oidc.issuer", "admin_oidc.client_id", "admin_oidc.client_secret"}
	var b bytes.Buffer
	if err := Write(&b, snap, map[string]bool{"settings": true}, Options{}, "a header"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "s3cret") || !strings.Contains(out, "# admin_oidc.client_secret is held encrypted, and left out") ||
		!strings.Contains(out, `admin_oidc.issuer: "https://idp.test"`) || !strings.Contains(out, "admin_oidc.enabled: true") ||
		strings.Contains(out, "admin_oidc.scopes") {
		t.Errorf("dump:\n%s", out)
	}
}

// The pre-check of a step (phase 4): its URL, signals, steps and acr values
// dumped; the key never, a comment saying so on the app that has one.
func TestSkipCheck(t *testing.T) {
	key := strings.Repeat("0a", 32)
	apps := []store.App{
		{ID: "pwd", LoginURL: "https://pwd/l", ConsentURL: "https://pwd/c", Method: "pwd", AuthMode: "network"},
		{ID: "otp", LoginURL: "https://otp/l", ConsentURL: "https://otp/c", Method: "otp", AuthMode: "network",
			SkipCheckURL: "https://otp/skip-check", SkipCheckKey: key, SkipCheckSignals: []string{"full_ip", "user_agent"}},
	}
	flows := []store.Flow{{ID: "f", Title: map[string]string{"fr": "F"}, Description: map[string]string{"fr": "D"}, Enabled: true,
		SkipCheckAllowedACR: []string{"loa2"},
		Steps:               []store.Step{{AppID: "pwd", Position: 0, SubjectCheck: "none"}, {AppID: "otp", Position: 1, SubjectCheck: "equal", SkipCheck: true}}}}
	snap := store.NewSnapshot(apps, flows, store.DefaultSettings())
	var b bytes.Buffer
	if err := Write(&b, snap, map[string]bool{"apps": true, "flows": true}, Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"skip_check_url: https://otp/skip-check", "- full_ip", "- user_agent",
		"# skip_check_key: not dumped, held encrypted; without it, bootstrap keeps the key the database holds",
		"skip_check_allowed_acr:", "- loa2", "skip_check: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dump lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, key) || strings.Count(out, "skip_check_key") != 1 || strings.Count(out, "skip_check: true") != 1 {
		t.Errorf("dump:\n%s", out)
	}
}
