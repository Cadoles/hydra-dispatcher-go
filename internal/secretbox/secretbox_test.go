package secretbox

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/seal"
)

var (
	keyA = bytes.Repeat([]byte{1}, 32)
	keyB = bytes.Repeat([]byte{2}, 32)
)

func TestSealOpen(t *testing.T) {
	k, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal("admin_oidc.client_secret", []byte(`"s3cret"`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:"+seal.KeyID(keyA)+":") || strings.Contains(sealed, "s3cret") {
		t.Fatalf("sealed: %s", sealed)
	}
	if kid, ok := KID(sealed); !ok || kid != seal.KeyID(keyA) {
		t.Errorf("kid: %q %v", kid, ok)
	}
	plain, err := k.Open("admin_oidc.client_secret", sealed)
	if err != nil || string(plain) != `"s3cret"` {
		t.Fatalf("open: %q %v", plain, err)
	}
	again, _ := k.Seal("admin_oidc.client_secret", []byte(`"s3cret"`))
	if again == sealed {
		t.Error("the same nonce twice")
	}
	// Another name, a byte changed, another form.
	if _, err := k.Open("app.skip_check_key", sealed); !errors.Is(err, ErrOpen) {
		t.Errorf("another name: %v", err)
	}
	changed := []byte(sealed)
	changed[len(changed)-5] ^= 1
	if _, err := k.Open("admin_oidc.client_secret", string(changed)); err == nil {
		t.Error("a byte changed opens")
	}
	for _, s := range []string{"", "s3cret", "v2:" + seal.KeyID(keyA) + ":abc", "v1:short:abc", "v1:" + seal.KeyID(keyA) + ":!!", "v1:" + seal.KeyID(keyA) + ":"} {
		if _, err := k.Open("admin_oidc.client_secret", s); !errors.Is(err, ErrForm) {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// The rotation: a previous key opens, the active one alone seals; a key no
// longer held is named.
func TestRotation(t *testing.T) {
	old, _ := New(keyA)
	sealed, _ := old.Seal("n", []byte("x"))
	both, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := both.Open("n", sealed); err != nil || string(plain) != "x" {
		t.Errorf("by a previous key: %q %v", plain, err)
	}
	if again, _ := both.Seal("n", []byte("x")); !strings.Contains(again, ":"+seal.KeyID(keyB)+":") || both.Active() != seal.KeyID(keyB) {
		t.Errorf("sealed by: %s", again)
	}
	only, _ := New(keyB)
	var unknown *UnknownKeyError
	if _, err := only.Open("n", sealed); !errors.As(err, &unknown) || unknown.KID != seal.KeyID(keyA) || !strings.Contains(err.Error(), seal.KeyID(keyA)) {
		t.Errorf("a key no longer held: %v", err)
	}
	// Previous keys alone: they open, nothing seals.
	previous, _ := New(nil, keyA)
	if _, err := previous.Open("n", sealed); err != nil {
		t.Errorf("previous alone: %v", err)
	}
	if _, err := previous.Seal("n", []byte("x")); !errors.Is(err, ErrNoKey) {
		t.Errorf("sealed without an active key: %v", err)
	}
	var none *Keys
	if _, err := none.Seal("n", []byte("x")); !errors.Is(err, ErrNoKey) {
		t.Errorf("nil seals: %v", err)
	}
	if _, err := none.Open("n", sealed); !errors.As(err, &unknown) {
		t.Errorf("nil opens: %v", err)
	}
	if _, err := New(keyA[:16]); !errors.Is(err, ErrKeySize) {
		t.Errorf("16 bytes: %v", err)
	}
}
