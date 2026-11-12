package seedfile

import (
	"bytes"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
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
