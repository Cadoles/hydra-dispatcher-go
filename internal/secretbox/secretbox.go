// Package secretbox encrypts the secrets the database holds, as the setting
// admin_oidc.client_secret, by secrets.encryption_key (Rotation des clés):
// AES-256-GCM, written v1:<kid>:<base64url(nonce ‖ sealed)>, kid being the
// first 8 hexadecimal characters of the key's SHA-256. A value is opened by
// the key its kid names, without trying the others; the keys of
// secrets.encryption_keys_previous open what they sealed, and only the active
// key seals. The data associated with a value name what it is, the key of its
// setting, and its kid: a value never opens as another's.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/seal"
)

// version is the first field of a sealed value.
const version = "v1"

// Errors of Seal and Open.
var (
	// ErrNoKey refuses to seal without secrets.encryption_key.
	ErrNoKey = errors.New("no secrets.encryption_key to encrypt it")
	// ErrForm refuses a value that is not one Seal wrote.
	ErrForm = errors.New("is not a value secrets.encryption_key encrypted (v1:<kid>:<data>)")
	// ErrOpen refuses a value its key does not open: changed, or sealed for
	// another name.
	ErrOpen = errors.New("does not open by its key: changed, or encrypted for another")
	// ErrKeySize refuses a key of another size than 32 bytes.
	ErrKeySize = errors.New("secretbox: the keys are 32 bytes")
)

// UnknownKeyError refuses a value sealed by a key the keyring does not hold.
type UnknownKeyError struct{ KID string }

func (e *UnknownKeyError) Error() string {
	return fmt.Sprintf("is encrypted by the key %s, which neither secrets.encryption_key nor secrets.encryption_keys_previous holds", e.KID)
}

// Keys seal by the active key and open by any of them. A nil *Keys has no key:
// it seals nothing and opens nothing.
type Keys struct {
	active string
	aeads  map[string]cipher.AEAD
}

// New returns the keyring of active, nil for none, then of previous, 32
// bytes each.
func New(active []byte, previous ...[]byte) (*Keys, error) {
	k := &Keys{aeads: map[string]cipher.AEAD{}}
	add := func(key []byte) (string, error) {
		if len(key) != 32 {
			return "", ErrKeySize
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		id := seal.KeyID(key)
		k.aeads[id] = aead
		return id, nil
	}
	for _, p := range previous {
		if _, err := add(p); err != nil {
			return nil, err
		}
	}
	if active != nil {
		id, err := add(active)
		if err != nil {
			return nil, err
		}
		k.active = id
	}
	return k, nil
}

// Active is the kid of the active key, "" for none.
func (k *Keys) Active() string {
	if k == nil {
		return ""
	}
	return k.active
}

// Holds tells whether the keyring holds the key kid.
func (k *Keys) Holds(kid string) bool {
	if k == nil {
		return false
	}
	_, ok := k.aeads[kid]
	return ok
}

func associated(name, kid string) []byte {
	return []byte(version + ":" + kid + ":" + name)
}

// Seal encrypts plain, the value of name, by the active key.
func (k *Keys) Seal(name string, plain []byte) (string, error) {
	if k.Active() == "" {
		return "", ErrNoKey
	}
	aead := k.aeads[k.active]
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce) // crypto/rand never fails
	return version + ":" + k.active + ":" + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, associated(name, k.active))), nil
}

// KID is the kid of a sealed value; false for what is not one.
func KID(sealed string) (string, bool) {
	v, rest, ok := strings.Cut(sealed, ":")
	kid, _, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || v != version || len(kid) != 8 {
		return "", false
	}
	return kid, true
}

// Open decrypts what Seal encrypted for name: an *UnknownKeyError when its key
// is not held, ErrForm or ErrOpen otherwise.
func (k *Keys) Open(name, sealed string) ([]byte, error) {
	kid, ok := KID(sealed)
	if !ok {
		return nil, ErrForm
	}
	if !k.Holds(kid) {
		return nil, &UnknownKeyError{KID: kid}
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed[len(version)+1+len(kid)+1:])
	aead := k.aeads[kid]
	if err != nil || len(raw) < aead.NonceSize() {
		return nil, ErrForm
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, raw[:n], raw[n:], associated(name, kid))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}
