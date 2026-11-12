//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seal"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/secretbox"
)

var (
	encKeyA = bytes.Repeat([]byte{0xa1}, 32)
	encKeyB = bytes.Repeat([]byte{0xb2}, 32)
)

func keyring(t *testing.T, active []byte, previous ...[]byte) *secretbox.Keys {
	t.Helper()
	k, err := secretbox.New(active, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rawSetting is the value the table holds for key, as it holds it.
func rawSetting(t *testing.T, p *Postgres, key string) string {
	t.Helper()
	var v string
	if err := p.db.QueryRow(`SELECT value::text FROM setting WHERE key = $1`, key).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The secret of the block admin_oidc: encrypted in its row, in clear in the
// snapshot; refused without a key; a key no longer held named; turned by
// Rekey, once.
func TestSecretsOnPostgres(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	block := map[string]json.RawMessage{
		"admin_oidc.enabled": json.RawMessage("true"), "admin_oidc.issuer": json.RawMessage(`"https://idp.test"`),
		"admin_oidc.client_id": json.RawMessage(`"dispatcher-admin"`), "admin_oidc.client_secret": json.RawMessage(`"s3cret-of-the-idp"`),
	}
	if err := p.UpdateSettings(ctx, "test", block); !violated(err, "admin_oidc.client_secret") {
		t.Fatalf("without a key: %v", err)
	}
	p.SetSecrets(keyring(t, encKeyA))
	if err := p.UpdateSettings(ctx, "test", block); err != nil {
		t.Fatal(err)
	}
	if raw := rawSetting(t, p, "admin_oidc.client_secret"); strings.Contains(raw, "s3cret") || !strings.HasPrefix(raw, `"v1:`+seal.KeyID(encKeyA)+`:`) {
		t.Errorf("in the table: %s", raw)
	}
	snap, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if o := snap.Settings.AdminOIDC; !o.Enabled || o.ClientSecret != "s3cret-of-the-idp" || o.ClientID != "dispatcher-admin" ||
		snap.Encrypted["admin_oidc.client_secret"] != seal.KeyID(encKeyA) {
		t.Errorf("snapshot: %+v %v", o, snap.Encrypted)
	}
	// The same value again writes nothing: its row keeps its nonce.
	before := rawSetting(t, p, "admin_oidc.client_secret")
	if err := p.UpdateSettings(ctx, "test", map[string]json.RawMessage{"admin_oidc.client_secret": json.RawMessage(`"s3cret-of-the-idp"`)}); err != nil {
		t.Fatal(err)
	}
	if after := rawSetting(t, p, "admin_oidc.client_secret"); after != before {
		t.Error("an unchanged secret written again")
	}

	// A key no longer held: the snapshot is refused, the key and the setting
	// named.
	p.SetSecrets(keyring(t, encKeyB))
	if _, err := p.Snapshot(ctx); err == nil || !strings.Contains(err.Error(), seal.KeyID(encKeyA)) || !strings.Contains(err.Error(), "admin_oidc.client_secret") {
		t.Errorf("a key not held: %v", err)
	}
	// The rotation: B active, A previous; rekey once, then nothing.
	p.SetSecrets(keyring(t, encKeyB, encKeyA))
	done, err := p.Rekey(ctx)
	if err != nil || !slices.Equal(done, []string{"admin_oidc.client_secret"}) {
		t.Fatalf("rekey: %v %v", done, err)
	}
	if done, err := p.Rekey(ctx); err != nil || len(done) != 0 {
		t.Errorf("rekey again: %v %v", done, err)
	}
	l, err := p.EncryptedSettings(ctx)
	if err != nil || len(l) != 1 || l[0].KID != seal.KeyID(encKeyB) {
		t.Errorf("encrypted: %+v %v", l, err)
	}
	p.SetSecrets(keyring(t, encKeyB))
	if snap, err := p.Snapshot(ctx); err != nil || snap.Settings.AdminOIDC.ClientSecret != "s3cret-of-the-idp" {
		t.Errorf("A removed: %v", err)
	}
	p.SetSecrets(keyring(t, nil, encKeyB))
	if _, err := p.Rekey(ctx); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("rekey without an active key: %v", err)
	}
	// An empty secret needs no key.
	p.SetSecrets(nil)
	if err := p.UpdateSettings(ctx, "test", map[string]json.RawMessage{"admin_oidc.client_secret": json.RawMessage(`""`)}); err != nil {
		t.Errorf("emptied without a key: %v", err)
	}
	if snap, err := p.Snapshot(ctx); err != nil || snap.Settings.AdminOIDC.ClientSecret != "" || len(snap.Encrypted) != 0 {
		t.Errorf("emptied: %v", err)
	}
}

// bootstrap writes the secret of the seed encrypted; its diff says whether it
// changes, never its values.
func TestSecretsBootstrap(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetSecrets(keyring(t, encKeyA))
	seed := func(secret string) string {
		return `
dispatcher:
  admin_oidc.enabled: true
  admin_oidc.issuer: https://idp.test
  admin_oidc.client_id: dispatcher-admin
  admin_oidc.client_secret: ` + secret + `
`
	}
	if _, err := p.Bootstrap(ctx, loadSeed(t, seed("first-secret")), Force, true); err != nil {
		t.Fatal(err)
	}
	if raw := rawSetting(t, p, "admin_oidc.client_secret"); strings.Contains(raw, "first-secret") || !strings.HasPrefix(raw, `"v1:`) {
		t.Errorf("in the table: %s", raw)
	}
	changes, err := p.Diff(ctx, loadSeed(t, seed("first-secret")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if c.ID == "admin_oidc.client_secret" && c.Action != Same {
			t.Errorf("the same secret: %+v", c)
		}
	}
	changes, err = p.Diff(ctx, loadSeed(t, seed("second-secret")))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(changes, func(c Change) bool { return c.ID == "admin_oidc.client_secret" })
	if i < 0 || changes[i].Action == Same || len(changes[i].Fields) != 1 || !changes[i].Fields[0].Secret ||
		changes[i].Fields[0].Old != "" || changes[i].Fields[0].New != "" {
		t.Errorf("another secret: %+v", changes)
	}
	text, _ := json.Marshal(changes)
	if bytes.Contains(text, []byte("first-secret")) || bytes.Contains(text, []byte("second-secret")) {
		t.Errorf("a secret in the changes: %s", text)
	}
}
