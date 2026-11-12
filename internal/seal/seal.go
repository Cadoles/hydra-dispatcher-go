// Package seal seals the values of the dispatcher's cookies: AES-256-GCM by
// secrets.cookie_key, the key's id first, so that the keys of
// secrets.cookie_keys_previous still open what they sealed. A sealed value is
// a version, the key's id, then the nonce and the sealed data in base64url,
// dot-separated. The data associated with it name its cookie, its version and
// its key: the value of one cookie never opens as another's, the memory of
// the skip (dispatcher_remember) as the session of the admin
// (dispatcher_admin).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Keys seals with the first key and opens with any of them.
type Keys struct {
	keys []key
}

type key struct {
	id   string
	aead cipher.AEAD
}

// ErrKeySize refuses a key of another size than 32 bytes.
var ErrKeySize = errors.New("seal: the keys are 32 bytes")

// New returns the keys of active, then of previous, 32 bytes each.
func New(active []byte, previous ...[]byte) (*Keys, error) {
	s := &Keys{}
	for _, k := range append([][]byte{active}, previous...) {
		if len(k) != 32 {
			return nil, ErrKeySize
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.keys = append(s.keys, key{id: KeyID(k), aead: aead})
	}
	return s, nil
}

// KeyID is the first 8 hexadecimal characters of the key's SHA-256, as for
// secrets.encryption_key (Rotation des clés).
func KeyID(k []byte) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:4])
}

func associated(cookie, version, id string) []byte {
	return []byte(cookie + "." + version + "." + id)
}

// Seal seals plain for the cookie, at version, with the first key.
func (s *Keys) Seal(cookie, version string, plain []byte) string {
	k := s.keys[0]
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce) // crypto/rand never fails
	return version + "." + k.id + "." + base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plain, associated(cookie, version, k.id)))
}

// Open opens what Seal sealed for the cookie at version, by the key its id
// names; false for anything else: another cookie, another version, a key no
// longer held, a value changed.
func (s *Keys) Open(cookie, version, sealed string) ([]byte, bool) {
	v, rest, _ := strings.Cut(sealed, ".")
	id, data, _ := strings.Cut(rest, ".")
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if v != version || err != nil {
		return nil, false
	}
	for _, k := range s.keys {
		n := k.aead.NonceSize()
		if k.id != id || len(raw) < n {
			continue
		}
		plain, err := k.aead.Open(nil, raw[:n], raw[n:], associated(cookie, version, k.id))
		if err != nil || len(plain) == 0 {
			continue
		}
		return plain, true
	}
	return nil, false
}
