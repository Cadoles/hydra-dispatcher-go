package seal

import (
	"bytes"
	"strings"
	"testing"
)

var (
	active   = bytes.Repeat([]byte{1}, 32)
	previous = bytes.Repeat([]byte{2}, 32)
)

func mustNew(t *testing.T, keys ...[]byte) *Keys {
	t.Helper()
	k, err := New(keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A value opens for its cookie and its version alone, by the key that sealed
// it, a previous one included; changed, it does not.
func TestSealOpen(t *testing.T) {
	k := mustNew(t, active)
	sealed := k.Seal("dispatcher_admin", "1", []byte("alice"))
	if !strings.HasPrefix(sealed, "1."+KeyID(active)+".") {
		t.Errorf("sealed = %s", sealed)
	}
	if plain, ok := k.Open("dispatcher_admin", "1", sealed); !ok || string(plain) != "alice" {
		t.Errorf("Open = %q, %v", plain, ok)
	}
	if k.Seal("dispatcher_admin", "1", []byte("alice")) == sealed {
		t.Error("the same nonce twice")
	}
	for name, open := range map[string]func() bool{
		"another cookie":  func() bool { _, ok := k.Open("dispatcher_remember", "1", sealed); return ok },
		"another version": func() bool { _, ok := k.Open("dispatcher_admin", "2", "2"+sealed[1:]); return ok },
		"a byte changed": func() bool {
			b := []byte(sealed)
			b[len(b)-2] ^= 1
			_, ok := k.Open("dispatcher_admin", "1", string(b))
			return ok
		},
		"another key":  func() bool { _, ok := mustNew(t, previous).Open("dispatcher_admin", "1", sealed); return ok },
		"empty":        func() bool { _, ok := k.Open("dispatcher_admin", "1", ""); return ok },
		"not base64":   func() bool { _, ok := k.Open("dispatcher_admin", "1", "1."+KeyID(active)+".!!"); return ok },
		"a short data": func() bool { _, ok := k.Open("dispatcher_admin", "1", "1."+KeyID(active)+".AAAA"); return ok },
	} {
		if open() {
			t.Errorf("%s: opened", name)
		}
	}
	// Rotation: sealed by a key now previous, it opens; sealed again, by the
	// active one.
	rotated := mustNew(t, previous, active)
	if _, ok := rotated.Open("dispatcher_admin", "1", sealed); !ok {
		t.Error("a value of the previous key")
	}
	if again := rotated.Seal("dispatcher_admin", "1", []byte("alice")); !strings.HasPrefix(again, "1."+KeyID(previous)+".") {
		t.Errorf("sealed by %s", again[:11])
	}
}

func TestKeySize(t *testing.T) {
	for _, keys := range [][][]byte{{[]byte("short")}, {active, make([]byte, 16)}, {make([]byte, 33)}} {
		if _, err := New(keys[0], keys[1:]...); err != ErrKeySize {
			t.Errorf("keys %d bytes: %v", len(keys[len(keys)-1]), err)
		}
	}
}
