package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/seal"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

var (
	encA = bytes.Repeat([]byte{0xa1}, 32)
	encB = bytes.Repeat([]byte{0xb2}, 32)
)

// secrets status names each setting's key, active, previous or not held, and
// exits 1 for one not held; rekey turns what is under a previous key, and
// audits the settings without their values.
func TestSecretsCommands(t *testing.T) {
	keepLoggers(t)
	commandEnv(t, "DISPATCHER_SECRETS_ENCRYPTION_KEY="+hex.EncodeToString(encB), "DISPATCHER_SECRETS_ENCRYPTION_KEYS_PREVIOUS="+hex.EncodeToString(encA))
	f := &fakeStore{encrypted: []store.EncryptedSetting{{Key: "admin_oidc.client_secret", KID: seal.KeyID(encA)}}}
	out, _, err := runCLI(t, f, false, "", nil, "secrets", "status")
	if err != nil || out != "admin_oidc.client_secret\t"+seal.KeyID(encA)+"\tprevious\n" {
		t.Errorf("status: %q %v", out, err)
	}
	_, errOut, err := runCLI(t, f, false, "", nil, "secrets", "rekey")
	if err != nil || !strings.Contains(errOut, "admin_oidc.client_secret encrypted again by the key "+seal.KeyID(encB)) ||
		!strings.Contains(errOut, `"command":"secrets rekey"`) || !strings.Contains(errOut, `"fields":["admin_oidc.client_secret"]`) {
		t.Errorf("rekey: %v\n%s", err, errOut)
	}
	out, _, err = runCLI(t, f, false, "", nil, "secrets", "status")
	if err != nil || !strings.HasSuffix(out, "\tactive\n") {
		t.Errorf("status after: %q %v", out, err)
	}
	if _, errOut, err := runCLI(t, f, false, "", nil, "secrets", "rekey"); err != nil || !strings.Contains(errOut, "nothing to do") {
		t.Errorf("rekey again: %v %s", err, errOut)
	}
	f.encrypted = append(f.encrypted, store.EncryptedSetting{Key: "app.skip_check_key", KID: "0badc0de"})
	if out, errOut, err := runCLI(t, f, false, "", nil, "secrets", "status"); !errors.Is(err, errFailed) || !strings.Contains(out, "0badc0de\tnot held") ||
		!strings.Contains(errOut, "neither secrets.encryption_key") {
		t.Errorf("a key not held: %v %q %s", err, out, errOut)
	}
	if out, _, err := runCLI(t, &fakeStore{}, false, "", nil, "secrets", "status"); err != nil || out != "No setting is encrypted.\n" {
		t.Errorf("none: %q %v", out, err)
	}
	if !slices.Contains(f.calls, "rekey") {
		t.Errorf("calls: %q", f.calls)
	}
}

// The identity provider of the admin in http:// needs tls.allow_http, as the
// webhooks do.
func TestConfigCheckOIDC(t *testing.T) {
	snap := store.NewSnapshot(nil, nil, store.DefaultSettings())
	snap.Settings.AdminOIDC.Issuer = "http://idp.test"
	snap.Settings.AdminOIDC.JWKSURI = "HTTP://idp.test/jwks"
	err := configCheck(false, false)(snap)
	if err == nil || !strings.Contains(err.Error(), "setting admin_oidc.issuer: is in http://") || !strings.Contains(err.Error(), "admin_oidc.jwks_uri") {
		t.Errorf("without allow_http: %v", err)
	}
	if err := configCheck(true, false)(snap); err != nil {
		t.Errorf("with allow_http: %v", err)
	}
	snap.Settings.AdminOIDC.Issuer, snap.Settings.AdminOIDC.JWKSURI = "https://idp.test", ""
	if err := configCheck(false, false)(snap); err != nil {
		t.Errorf("https: %v", err)
	}
}

// The pre-check of an app in http:// needs tls.allow_http, as a webhook.
func TestConfigCheckSkipCheck(t *testing.T) {
	snap := store.NewSnapshot([]store.App{{ID: "otp", SkipCheckURL: "HTTP://otp/skip-check"}}, nil, store.DefaultSettings())
	if err := configCheck(false, false)(snap); err == nil || !strings.Contains(err.Error(), "app otp: skip_check_url is in http://, which needs tls.allow_http") {
		t.Errorf("without allow_http: %v", err)
	}
	if err := configCheck(true, false)(snap); err != nil {
		t.Errorf("with allow_http: %v", err)
	}
}
