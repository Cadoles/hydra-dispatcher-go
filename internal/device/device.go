// Package device is the device cookie of the pre-check of a step (phase 4):
// 32 random bytes and the time they were drawn, sealed by secrets.cookie_key
// as the memory of the skip is, its rotation with it. The dispatcher alone
// reads it; an app receives a value derived for it (flow.DeviceValue).
package device

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seal"
)

// Cookie is the name of the cookie, without the __Host- prefix of HTTPS.
const Cookie = "dispatcher_device"

// Lifetime is the cookie's: 400 days, the most a browser keeps.
const Lifetime = 400 * 24 * time.Hour

// version is that of the sealed value: the id, then the time in 8 bytes.
const version = "d1"

const idSize = 32

// Codec seals and opens the cookie.
type Codec struct{ keys *seal.Keys }

// New returns the codec of the keys of secrets.cookie_key: the active one
// seals, every one opens.
func New(active []byte, previous ...[]byte) (*Codec, error) {
	keys, err := seal.New(active, previous...)
	if err != nil {
		return nil, err
	}
	return &Codec{keys: keys}, nil
}

// Draw draws a new device at now.
func Draw(now time.Time) flow.Device {
	id := make([]byte, idSize)
	_, _ = rand.Read(id) // crypto/rand never fails
	return flow.Device{ID: id, Created: now.Unix()}
}

// Seal gives the value of the cookie of d.
func (c *Codec) Seal(d flow.Device) string {
	plain := make([]byte, idSize+8)
	copy(plain, d.ID)
	binary.BigEndian.PutUint64(plain[idSize:], uint64(d.Created))
	return c.keys.Seal(Cookie, version, plain)
}

// Open reads the value of the cookie: false for anything else, another
// cookie, a key no longer held, a value changed or of another size.
func (c *Codec) Open(value string) (flow.Device, bool) {
	plain, ok := c.keys.Open(Cookie, version, value)
	if !ok || len(plain) != idSize+8 {
		return flow.Device{}, false
	}
	return flow.Device{ID: plain[:idSize], Created: int64(binary.BigEndian.Uint64(plain[idSize:]))}, true
}
