package device

import (
	"bytes"
	"testing"
	"time"
)

var (
	keyA = bytes.Repeat([]byte{0xa1}, 32)
	keyB = bytes.Repeat([]byte{0xb2}, 32)
)

// The cookie seals the id and its time; the previous key opens it, a value
// of another key, changed, or empty does not; two draws differ.
func TestCodec(t *testing.T) {
	a, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_794_000_000, 0)
	d := Draw(now)
	if len(d.ID) != 32 || d.Created != now.Unix() || bytes.Equal(d.ID, Draw(now).ID) {
		t.Fatalf("draw: %+v", d)
	}
	sealed := a.Seal(d)
	if bytes.Contains([]byte(sealed), d.ID) {
		t.Error("the id in clear")
	}
	if got, ok := a.Open(sealed); !ok || !bytes.Equal(got.ID, d.ID) || got.Created != d.Created {
		t.Fatalf("open: %+v %v", got, ok)
	}
	rotated, _ := New(keyB, keyA)
	if got, ok := rotated.Open(sealed); !ok || !bytes.Equal(got.ID, d.ID) {
		t.Errorf("under the previous key: %v", ok)
	}
	other, _ := New(keyB)
	for name, v := range map[string]string{"another key": sealed, "changed": sealed[:len(sealed)-2] + "AA", "empty": ""} {
		c := a
		if name == "another key" {
			c = other
		}
		if _, ok := c.Open(v); ok {
			t.Errorf("%s: opened", name)
		}
	}
}
