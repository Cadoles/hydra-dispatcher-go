// Package flowcodec reads Hydra 2.2 login and consent challenges locally.
//
// Since Hydra 2.2 a challenge is the Hydra flow itself: JSON, gzipped, sealed
// with XChaCha20-Poly1305 (random 24-byte nonce first) under SHA-256 of a
// secrets.system entry, then base64url-encoded with padding. The additional
// data names the challenge's purpose, so a login challenge never opens as a
// consent challenge. Reference: oauth2/flowctx/encoding.go, aead/xchacha20.go
// and driver/config/provider_fosite.go at Hydra tag v2.2.0.
//
// The package only decrypts: holding the secret must not let the dispatcher
// mint challenges.
package flowcodec

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrInvalid reports a challenge that does not decrypt under any configured
// secret: forged, tampered, of another purpose, from Hydra 2.1 (32 hex), or
// sealed with a secret the dispatcher lacks.
var ErrInvalid = errors.New("flowcodec: invalid challenge")

// maxFlowSize bounds the decompressed flow (a two-step flow is about 3 KB).
const maxFlowSize = 1 << 20

// Additional data per purpose, as flowctx marshals {"p": purpose} with
// omitempty: the login challenge (purpose 0) carries "{}", not nothing.
var (
	adLoginChallenge   = []byte(`{}`)
	adConsentChallenge = []byte(`{"p":2}`)
)

// Codec decrypts challenges with the keys derived from Hydra's secrets.system.
type Codec struct {
	keys [][]byte
}

// New derives one key per secrets.system entry. Like Hydra, every key may
// decrypt, so the list follows Hydra's rotation as is.
func New(systemSecrets []string) (*Codec, error) {
	if len(systemSecrets) == 0 {
		return nil, errors.New("flowcodec: no system secret")
	}
	c := &Codec{keys: make([][]byte, 0, len(systemSecrets))}
	for i, s := range systemSecrets {
		if s == "" {
			return nil, fmt.Errorf("flowcodec: system secret %d is empty", i)
		}
		key := sha256.Sum256([]byte(s))
		c.keys = append(c.keys, key[:])
	}
	return c, nil
}

// LoginChallenge decrypts the login_challenge Hydra sends to the login URL.
func (c *Codec) LoginChallenge(challenge string) (*Flow, error) {
	return c.decode(challenge, adLoginChallenge)
}

// ConsentChallenge decrypts the consent_challenge Hydra sends to the consent URL.
func (c *Codec) ConsentChallenge(challenge string) (*Flow, error) {
	return c.decode(challenge, adConsentChallenge)
}

func (c *Codec) decode(challenge string, ad []byte) (*Flow, error) {
	msg, err := base64.URLEncoding.DecodeString(challenge)
	if err != nil || len(msg) < chacha20poly1305.NonceSizeX {
		return nil, ErrInvalid
	}
	plain, err := c.open(msg[:chacha20poly1305.NonceSizeX], msg[chacha20poly1305.NonceSizeX:], ad)
	if err != nil {
		return nil, err
	}

	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", ErrInvalid, err)
	}
	defer func() { _ = zr.Close() }()
	var f Flow
	if err := json.NewDecoder(io.LimitReader(zr, maxFlowSize)).Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: json: %v", ErrInvalid, err)
	}
	return &f, nil
}

// open tries every key, the active one first, as Hydra does.
func (c *Codec) open(nonce, sealed, ad []byte) ([]byte, error) {
	for _, key := range c.keys {
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		if plain, err := aead.Open(nil, nonce, sealed, ad); err == nil {
			return plain, nil
		}
	}
	return nil, ErrInvalid
}

// Flow is the part of Hydra's flow the dispatcher reads to build the login and
// consent requests it would otherwise fetch from the admin API. Hydra marshals
// its flow.Flow without json tags, hence the Go field names. Unknown fields
// are ignored, so new Hydra fields do not break decoding.
type Flow struct {
	// ID is the flow identifier (32 hex). It is the same in the login and
	// consent challenges, and it is what Hydra 2.2 returns as login_challenge
	// in a consent request, not the encrypted login challenge.
	ID                 string
	ConsentChallengeID string
	RequestedAt        time.Time

	ClientID             string
	Client               json.RawMessage
	RequestURL           string
	OpenIDConnectContext json.RawMessage
	RequestedScope       []string
	RequestedAudience    []string

	// SessionID is the Hydra login session (login request session_id,
	// consent request login_session_id).
	SessionID   string
	Subject     string
	LoginSkip   bool
	ConsentSkip bool

	// Set by the login accept, read back by the consent request.
	ACR     string
	AMR     []string
	Context json.RawMessage
}
