// Package remember seals the memory of the skip into the dispatcher_remember
// cookie (Stockage de l'état, Mémoire du skip): AES-256-GCM by
// secrets.cookie_key, the key's id first so that the previous keys of
// secrets.cookie_keys_previous still open what they sealed; deflated beyond
// 1.5 KB, not written beyond 3.8 KB. The flow engine judges what it holds
// (MEM-3 to MEM-9) and says what to write (WRT-1); this package only opens
// and seals, out of the engine, which draws no nonce.
package remember

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
)

// The bounds of the doc, in bytes: the JSON is deflated beyond deflateAbove,
// and the sealed value refused beyond maxSealed. One cookie, never two: it
// travels with every request to the dispatcher, and a Cookie header beyond
// the 8 KB of a reverse proxy's line (nginx, Apache) would answer 400 to
// every page, the logout that clears it included, until it expires (revue
// R20). maxSealed and the __Host- name stay under a browser's 4096 bytes.
const (
	deflateAbove = 1500
	maxSealed    = 3800
)

// maxPlain bounds what an inflated cookie may give: a sealed one came from
// the dispatcher, but a bound costs nothing.
const maxPlain = 64 << 10

// The sealed value: format "1", the key's id, then the nonce and the sealed
// data in base64url, dot-separated.
const (
	format     = "1"
	plainJSON  = 0
	plainFlate = 1
)

// ErrTooLarge is the answer of Seal beyond 3.8 KB: no cookie is written, and
// the former one is cleared, which would serve the next skip with former
// claims (WRT-2).
var ErrTooLarge = errors.New("remember: the memory of the skip is beyond 3.8 KB")

// Codec seals with the first key and opens with any of them.
type Codec struct {
	keys []key
}

type key struct {
	id   string
	aead cipher.AEAD
}

// New returns the codec of secrets.cookie_key, then the keys of
// secrets.cookie_keys_previous, 32 bytes each.
func New(active []byte, previous ...[]byte) (*Codec, error) {
	c := &Codec{}
	for _, k := range append([][]byte{active}, previous...) {
		block, err := aes.NewCipher(k)
		if err != nil || len(k) != 32 {
			return nil, errors.New("remember: secrets.cookie_key and its previous keys are 32 bytes")
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		c.keys = append(c.keys, key{id: keyID(k), aead: aead})
	}
	return c, nil
}

// keyID is the first 8 hexadecimal characters of the key's SHA-256, as for
// secrets.encryption_key (Rotation des clés).
func keyID(k []byte) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:4])
}

// aad binds a sealed value to this cookie and its key: secrets.cookie_key
// seals dispatcher_admin too.
func aad(id string) []byte { return []byte("dispatcher_remember." + format + "." + id) }

// Seal returns the cookie value of r; ErrTooLarge beyond 3.8 KB.
func (c *Codec) Seal(r *flow.Remembered) (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	plain := append([]byte{plainJSON}, data...)
	if len(data) > deflateAbove {
		var b bytes.Buffer
		b.WriteByte(plainFlate)
		w, _ := flate.NewWriter(&b, flate.BestCompression) // a valid level
		_, _ = w.Write(data)                               // into a Buffer, which never fails
		_ = w.Close()
		plain = b.Bytes()
	}
	k := c.keys[0]
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce) // crypto/rand never fails
	sealed := format + "." + k.id + "." + base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plain, aad(k.id)))
	if len(sealed) > maxSealed {
		return "", ErrTooLarge
	}
	return sealed, nil
}

// Open reads the cookie value the browser sent ("" for none): absent without
// it (MEM-1); unreadable when no key opens it, or for a version unknown
// (MEM-2).
func (c *Codec) Open(sealed string) flow.Memory {
	if sealed == "" {
		return flow.Memory{Reason: flow.SkipAbsent}
	}
	r, err := c.open(sealed)
	if err != nil {
		return flow.Memory{Reason: flow.SkipUnreadable}
	}
	return flow.Memory{Content: r}
}

var errUnreadable = errors.New("remember: unreadable")

func (c *Codec) open(sealed string) (*flow.Remembered, error) {
	f, rest, _ := strings.Cut(sealed, ".")
	id, data, _ := strings.Cut(rest, ".")
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if f != format || err != nil {
		return nil, errUnreadable
	}
	for _, k := range c.keys {
		n := k.aead.NonceSize()
		if k.id != id || len(raw) < n {
			continue
		}
		plain, err := k.aead.Open(nil, raw[:n], raw[n:], aad(k.id))
		if err != nil || len(plain) == 0 {
			continue
		}
		return decode(plain)
	}
	return nil, errUnreadable
}

func decode(plain []byte) (*flow.Remembered, error) {
	data := plain[1:]
	switch plain[0] {
	case plainJSON:
	case plainFlate:
		inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(data)), maxPlain+1))
		if err != nil || len(inflated) > maxPlain {
			return nil, errUnreadable
		}
		data = inflated
	default:
		return nil, errUnreadable
	}
	var r flow.Remembered
	if json.Unmarshal(data, &r) != nil || r.V != flow.RememberedFormat {
		return nil, errUnreadable
	}
	return &r, nil
}
