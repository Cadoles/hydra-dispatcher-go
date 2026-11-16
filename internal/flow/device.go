package flow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Device is the device cookie of a browser, opened (phase 4, the pre-check
// of a step): 32 random bytes and the Unix time they were drawn. The zero
// Device is none.
type Device struct {
	ID      []byte
	Created int64
}

// None tells whether d is no device.
func (d Device) None() bool { return len(d.ID) == 0 }

// DeviceValue is the value of the device id for the app: base64url of
// HMAC-SHA256(id, app). Without the id, an app can neither find the device
// nor compute the value of another app (doc, Identifiant d'appareil).
func DeviceValue(id []byte, app string) string {
	mac := hmac.New(sha256.New, id)
	mac.Write([]byte(app))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// device is the device the event of the run carries: GET / and POST /.
func (r *run) device() Device {
	switch e := r.Event.(type) {
	case Entry:
		return e.Device
	case Choose:
		return e.Device
	}
	return Device{}
}
