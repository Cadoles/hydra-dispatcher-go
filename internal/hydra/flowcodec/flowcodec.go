// Package flowcodec reads Hydra 2.2 and 2.3 login and consent challenges
// locally.
//
// Since Hydra 2.2 a challenge is the Hydra flow itself: JSON, gzipped, sealed
// with XChaCha20-Poly1305 (random 24-byte nonce first) under SHA-256 of a
// secrets.system entry, then base64url-encoded with padding. The additional
// data names the challenge's purpose, so a login challenge never opens as a
// consent challenge. Reference: oauth2/flowctx/encoding.go, aead/xchacha20.go
// and driver/config/provider_fosite.go at Hydra tags v2.2.0 and v2.3.0.
//
// What changes between releases is listed in formats: the codec reads the
// format of the one Hydra version it is given, and a flow that does not read
// as such fails with ErrFormat instead of coming out empty.
//
// The package only decrypts: holding the secret must not let the dispatcher
// mint challenges.
package flowcodec

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrNotEncrypted reports a Hydra 2.1 challenge (32 hex), which only the
	// admin API can read.
	ErrNotEncrypted = errors.New("flowcodec: challenge not encrypted")

	// ErrInvalid reports a challenge that no configured secret opens for this
	// purpose: forged, tampered, of another purpose, sealed with a secret the
	// dispatcher lacks, or longer than any Hydra challenge.
	ErrInvalid = errors.New("flowcodec: invalid challenge")

	// ErrFormat reports a challenge Hydra sealed but that does not read as a
	// flow of the configured version: the version is wrong, or Hydra changed
	// its format.
	ErrFormat = errors.New("flowcodec: unexpected flow format")
)

const (
	// maxChallengeSize bounds the work a forged challenge costs; Hydra's are
	// about 2 KB.
	maxChallengeSize = 64 << 10

	// maxFlowSize bounds the decompressed flow (a two-step flow is about 3 KB).
	maxFlowSize = 1 << 20
)

// Version is a Hydra release whose challenge format the codec reads.
type Version string

const (
	Hydra22 Version = "2.2"
	Hydra23 Version = "2.3"
)

// format is what a Hydra release decides: the additional data of each purpose
// and the JSON keys of its flow.
type format struct {
	login, consent []byte
	decode         func(io.Reader) (Flow, error)
}

// Additional data as flowctx marshals {"p": purpose} with omitempty: the
// login challenge (purpose 0) carries "{}", not nothing. Hydra 25.4 inserts
// the device purposes before consent, which becomes {"p":4}.
var formats = map[Version]format{
	Hydra22: {login: []byte(`{}`), consent: []byte(`{"p":2}`), decode: decodeAs[flowV22]},
	Hydra23: {login: []byte(`{}`), consent: []byte(`{"p":2}`), decode: decodeAs[flowV23]},
}

// Codec decrypts challenges with the keys derived from Hydra's secrets.system.
// It holds ciphers rather than keys, so that printing it shows no key.
type Codec struct {
	format format
	aeads  []cipher.AEAD
}

// New derives one key per secrets.system entry, for challenges of Hydra
// version v. Like Hydra, every key may decrypt, so the list follows Hydra's
// rotation as is.
func New(v Version, systemSecrets []string) (*Codec, error) {
	f, ok := formats[v]
	if !ok {
		return nil, fmt.Errorf("flowcodec: unsupported Hydra version %q", v)
	}
	if len(systemSecrets) == 0 {
		return nil, errors.New("flowcodec: no system secret")
	}
	c := &Codec{format: f, aeads: make([]cipher.AEAD, 0, len(systemSecrets))}
	for i, s := range systemSecrets {
		if s == "" {
			return nil, fmt.Errorf("flowcodec: system secret %d is empty", i)
		}
		key := sha256.Sum256([]byte(s))
		aead, err := chacha20poly1305.NewX(key[:])
		if err != nil {
			return nil, err
		}
		c.aeads = append(c.aeads, aead)
	}
	return c, nil
}

// LoginChallenge decrypts the login_challenge Hydra sends to the login URL.
func (c *Codec) LoginChallenge(challenge string) (*Flow, error) {
	return c.decode(challenge, c.format.login, false)
}

// ConsentChallenge decrypts the consent_challenge Hydra sends to the consent URL.
func (c *Codec) ConsentChallenge(challenge string) (*Flow, error) {
	return c.decode(challenge, c.format.consent, true)
}

func (c *Codec) decode(challenge string, ad []byte, consent bool) (*Flow, error) {
	if isLegacy(challenge) {
		return nil, ErrNotEncrypted
	}
	if len(challenge) > maxChallengeSize {
		return nil, ErrInvalid
	}
	msg, err := base64.URLEncoding.DecodeString(challenge)
	if err != nil || len(msg) < chacha20poly1305.NonceSizeX {
		return nil, ErrInvalid
	}
	plain, err := c.open(msg[:chacha20poly1305.NonceSizeX], msg[chacha20poly1305.NonceSizeX:], ad)
	if err != nil {
		return nil, err
	}

	// Past this point Hydra sealed the content: errors name the step, never
	// the content, which holds verifiers and CSRF tokens.
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("%w: not gzip", ErrFormat)
	}
	defer func() { _ = zr.Close() }()
	lr := &io.LimitedReader{R: zr, N: maxFlowSize}
	f, err := c.format.decode(lr)
	if err != nil {
		if lr.N == 0 {
			return nil, fmt.Errorf("%w: flow over %d bytes", ErrFormat, maxFlowSize)
		}
		return nil, fmt.Errorf("%w: not a JSON flow", ErrFormat)
	}
	if err := f.complete(consent); err != nil {
		return nil, err
	}
	return &f, nil
}

// open tries every key, the active one first, as Hydra does.
func (c *Codec) open(nonce, sealed, ad []byte) ([]byte, error) {
	for _, aead := range c.aeads {
		if plain, err := aead.Open(nil, nonce, sealed, ad); err == nil {
			return plain, nil
		}
	}
	return nil, ErrInvalid
}

// isLegacy reports a Hydra 2.1 challenge: 32 hex characters.
func isLegacy(challenge string) bool {
	if len(challenge) != 32 {
		return false
	}
	_, err := hex.DecodeString(challenge)
	return err == nil
}

// Flow is the part of Hydra's flow the dispatcher reads to build the login and
// consent requests it would otherwise fetch from the admin API. It is the same
// whatever the Hydra version; JSON null comes out as nil.
type Flow struct {
	// ID is the flow identifier (32 hex). It is the same in the login and
	// consent challenges, and it is what Hydra returns as login_challenge in
	// a consent request, not the encrypted login challenge.
	ID                 string
	ConsentChallengeID string
	RequestedAt        time.Time

	// ClientID is read from Client: Hydra's own ClientID field is empty in
	// challenges.
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

// complete fills ClientID, turns JSON null into nil and checks that the flow
// holds what every Hydra flow has, so that a flow of another format fails
// instead of reading as an empty one.
func (f *Flow) complete(consent bool) error {
	var client struct {
		ID string `json:"client_id"`
	}
	_ = json.Unmarshal(f.Client, &client) // a client that does not decode has no ID
	f.ClientID = client.ID
	f.OpenIDConnectContext = nilIfNull(f.OpenIDConnectContext)
	f.Context = nilIfNull(f.Context)

	missing := ""
	switch {
	case f.ID == "":
		missing = "flow ID"
	case f.RequestedAt.IsZero():
		missing = "request time"
	case f.ClientID == "":
		missing = "client"
	case f.RequestURL == "":
		missing = "request URL"
	case consent && f.ConsentChallengeID == "":
		missing = "consent challenge ID"
	case consent && f.Subject == "":
		missing = "subject"
	default:
		return nil
	}
	return fmt.Errorf("%w: no %s", ErrFormat, missing)
}

func nilIfNull(m json.RawMessage) json.RawMessage {
	if string(m) == "null" {
		return nil
	}
	return m
}

// decodeAs decodes a flow under the JSON keys of one Hydra version. The wire
// types have Flow's fields, so the conversion fails to compile if they drift.
func decodeAs[W flowV22 | flowV23](r io.Reader) (Flow, error) {
	var w W
	if err := json.NewDecoder(r).Decode(&w); err != nil {
		return Flow{}, err
	}
	return Flow(w), nil
}

// flowV22 reads Hydra 2.2's flow.Flow, marshaled without json tags: the keys
// are its Go field names.
type flowV22 struct {
	ID                   string
	ConsentChallengeID   string
	RequestedAt          time.Time
	ClientID             string `json:"-"`
	Client               json.RawMessage
	RequestURL           string
	OpenIDConnectContext json.RawMessage
	RequestedScope       []string
	RequestedAudience    []string
	SessionID            string
	Subject              string
	LoginSkip            bool
	ConsentSkip          bool
	ACR                  string
	AMR                  []string
	Context              json.RawMessage
}

// flowV23 reads Hydra 2.3's flow.Flow, which has short json tags.
type flowV23 struct {
	ID                   string          `json:"i"`
	ConsentChallengeID   string          `json:"cc"`
	RequestedAt          time.Time       `json:"ia"`
	ClientID             string          `json:"-"`
	Client               json.RawMessage `json:"c"`
	RequestURL           string          `json:"r"`
	OpenIDConnectContext json.RawMessage `json:"oc"`
	RequestedScope       []string        `json:"rs"`
	RequestedAudience    []string        `json:"ra"`
	SessionID            string          `json:"si"`
	Subject              string          `json:"s"`
	LoginSkip            bool            `json:"ls"`
	ConsentSkip          bool            `json:"cs"`
	ACR                  string          `json:"a"`
	AMR                  []string        `json:"am"`
	Context              json.RawMessage `json:"ct"`
}
