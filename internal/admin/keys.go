// Package admin is the administration of the dispatcher: the admin API
// /admin/v1, its tokens and their keys.
package admin

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// minRSABits is the size an RSA key must have at least.
const minRSABits = 2048

// key is a key of the tokens: its id, the method it signs or verifies with,
// fixed by its type, never read from a token, and its public part.
type key struct {
	id     string
	method jwt.SigningMethod
	public crypto.PublicKey
}

// Keys is the key ring of the tokens: the active key signs, it and the
// previous ones verify, each found by its id (kid).
type Keys struct {
	private crypto.Signer
	active  key
	byID    map[string]key
}

// ParseKeys reads the keys of the admin API: private, the active key that
// signs; public, its public part, empty to derive it; previous, the public
// keys of the rotations before, which verify only. Each is a PEM, or the base64
// of a PEM as Symfony's OAUTH2_PRIVATE_KEY, of an EC P-256 key (ES256) or of
// an RSA key of 2048 bits at least (PS256). Errors name the key, never quote
// it.
func ParseKeys(private, public string, previous []string) (*Keys, error) {
	block, err := pemBlock(private)
	if err != nil {
		return nil, fmt.Errorf("admin.api.private_key: %w", err)
	}
	signer, err := parsePrivate(block)
	if err != nil {
		return nil, fmt.Errorf("admin.api.private_key: %w", err)
	}
	active, err := newKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("admin.api.private_key: %w", err)
	}
	if public != "" {
		pub, err := parsePublicText(public)
		if err != nil {
			return nil, fmt.Errorf("admin.api.public_key: %w", err)
		}
		if !equalKeys(pub, signer.Public()) {
			return nil, errors.New("admin.api.public_key: is not the public key of admin.api.private_key")
		}
	}
	k := &Keys{private: signer, active: active, byID: map[string]key{active.id: active}}
	for i, p := range previous {
		pub, err := parsePublicText(p)
		if err == nil {
			var prev key
			if prev, err = newKey(pub); err == nil {
				if _, taken := k.byID[prev.id]; !taken {
					k.byID[prev.id] = prev
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("admin.api.public_keys_previous[%d]: %w", i, err)
		}
	}
	return k, nil
}

// KeyID is the id of the active key, the kid of the tokens it signs.
func (k *Keys) KeyID() string { return k.active.id }

// Algorithm is the method of the active key: ES256 or PS256.
func (k *Keys) Algorithm() string { return k.active.method.Alg() }

// Previous counts the previous keys that verify, the active one apart.
func (k *Keys) Previous() int { return len(k.byID) - 1 }

// pemBlock reads the PEM block of s, or of the base64 of a PEM.
func pemBlock(s string) (*pem.Block, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("is empty")
	}
	if !strings.HasPrefix(s, "-----BEGIN") {
		// The base64 of a PEM, as Symfony takes its keys; line breaks allowed.
		raw := strings.Join(strings.Fields(s), "")
		var decoded []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if decoded, err = enc.DecodeString(raw); err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.New("is neither a PEM nor the base64 of a PEM")
		}
		s = string(decoded)
	}
	block, rest := pem.Decode([]byte(s))
	switch {
	case block == nil:
		return nil, errors.New("is neither a PEM nor the base64 of a PEM")
	case len(strings.TrimSpace(string(rest))) > 0:
		return nil, errors.New("holds more than one PEM block")
	case block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "":
		return nil, errors.New("is encrypted: give it in clear, as a secret (the key followed by _file)")
	}
	return block, nil
}

func parsePrivate(block *pem.Block) (crypto.Signer, error) {
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("is a PEM block %q: PRIVATE KEY, EC PRIVATE KEY or RSA PRIVATE KEY", block.Type)
	}
	if err != nil {
		return nil, errors.New("is not a readable private key") // x509 may quote bytes
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("is not a key that signs")
	}
	return signer, nil
}

func parsePublicText(s string) (crypto.PublicKey, error) {
	block, err := pemBlock(s)
	if err != nil {
		return nil, err
	}
	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("is a PEM block %q: PUBLIC KEY or RSA PUBLIC KEY", block.Type)
	}
	if err != nil {
		return nil, errors.New("is not a readable public key")
	}
	return pub, nil
}

// newKey gives a public key its method and its id.
func newKey(pub crypto.PublicKey) (key, error) {
	var method jwt.SigningMethod
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return key{}, fmt.Errorf("is an EC key on %s: P-256 only (ES256)", p.Curve.Params().Name)
		}
		method = jwt.SigningMethodES256
	case *rsa.PublicKey:
		if p.N.BitLen() < minRSABits {
			return key{}, fmt.Errorf("is an RSA key of %d bits: %d at least (PS256)", p.N.BitLen(), minRSABits)
		}
		method = jwt.SigningMethodPS256
	default:
		return key{}, fmt.Errorf("is a %T key: EC P-256 (ES256) or RSA (PS256)", pub)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return key{}, errors.New("is not a public key that can be written")
	}
	sum := sha256.Sum256(der)
	return key{id: hex.EncodeToString(sum[:])[:16], method: method, public: pub}, nil
}

func equalKeys(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && e.Equal(b)
}
