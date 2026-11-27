package remember

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"github.com/Cadoles/hydra-dispatcher-go/internal/seal"
)

var (
	activeKey = []byte("0123456789abcdef0123456789abcdef")
	oldKey    = []byte("fedcba9876543210fedcba9876543210")
)

func codec(t *testing.T, keys ...[]byte) *Codec {
	t.Helper()
	c, err := New(keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// remembered is a memory of the skip whose claims hold n bytes: random
// base64url, which deflate barely shrinks, or a repeated letter, which it
// does.
func remembered(n int, compressible bool) *flow.Remembered {
	b := make([]byte, n*3/4)
	_, _ = rand.Read(b)
	claim := base64.RawURLEncoding.EncodeToString(b)
	if compressible {
		claim = strings.Repeat("a", n)
	}
	return &flow.Remembered{
		V: flow.RememberedFormat, SID: "ba1ce6e4-e93b-401c-b6af-62703fe39df7", Sub: "alice",
		Flow: "hydra-sql-2fa", FH: flow.Composition([]string{"sql", "2fa"}), ACR: "2", AMR: []string{"pwd", "otp"},
		Ctx: flow.Object{"app": json.RawMessage(`"sql"`)}, Scp: []string{"openid", "email"},
		IDT: flow.Object{"email": json.RawMessage(`"alice@example.org"`), "blob": json.RawMessage(`"` + claim + `"`)},
		ACT: flow.Object{}, IAT: 1_790_000_000, Exp: 1_790_086_400,
	}
}

func jsonOf(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// WRT-1, MEM-1, MEM-2: what is sealed opens as it was, in one cookie,
// deflated beyond 1.5 KB.
func TestSealOpen(t *testing.T) {
	c := codec(t, activeKey)
	for _, tc := range []struct {
		name        string
		r           *flow.Remembered
		smallerThan int // the JSON, when deflated
	}{
		{"WRT-1, a small memory", remembered(64, false), 0},
		{"WRT-1, beyond 1.5 KB, deflated", remembered(3000, true), 3000},
		{"WRT-1, beyond 1.5 KB of claims deflate barely shrinks, under 3.8 KB sealed", remembered(2000, false), 0},
		{"WRT-1, a session cookie, exp 0", func() *flow.Remembered { r := remembered(64, false); r.Exp = 0; return r }(), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := c.Seal(tc.r)
			if err != nil {
				t.Fatal(err)
			}
			if len(v) > maxSealed {
				t.Errorf("a cookie of %d bytes", len(v))
			}
			// A cookie value as browsers keep it, without quotes.
			if strings.ContainsAny(v, " \",;\\") {
				t.Errorf("the cookie holds a separator: %q", v)
			}
			if tc.smallerThan > 0 && len(v) >= tc.smallerThan {
				t.Errorf("deflated: %d bytes, not under %d", len(v), tc.smallerThan)
			}
			got := c.Open(v)
			if got.Reason != "" || got.Content == nil {
				t.Fatalf("opened %+v", got)
			}
			// Compared as JSON: an empty object omitted is read back nil.
			if a, b := jsonOf(got.Content), jsonOf(tc.r); a != b {
				t.Errorf("opened %.200s…, want %.200s…", a, b)
			}
		})
	}
}

// WRT-2 (revue R20): beyond 3.8 KB, nothing to write, never a second cookie;
// the page clears the former one.
func TestSealTooLarge(t *testing.T) {
	for _, n := range []int{4000, 8000} {
		if v, err := codec(t, activeKey).Seal(remembered(n, false)); !errors.Is(err, ErrTooLarge) || v != "" {
			t.Errorf("Seal of %d bytes of claims = %d bytes, %v; want ErrTooLarge", n, len(v), err)
		}
	}
}

// The largest cookie, under its HTTPS name, stays within a browser's 4096
// bytes for name and value (revue R20: one cookie only).
func TestBrowserBound(t *testing.T) {
	if n := len("__Host-dispatcher_remember") + len("=") + maxSealed; n > 4096 {
		t.Errorf("%d bytes", n)
	}
}

// MEM-1, MEM-2: absent, or unreadable, with the reason skip.ignored gives.
func TestOpenFails(t *testing.T) {
	c := codec(t, activeKey, oldKey)
	one, err := c.Seal(remembered(64, false))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := c.Seal(&flow.Remembered{V: flow.RememberedFormat + 1})
	if err != nil {
		t.Fatal(err)
	}
	onlyOld, err := codec(t, oldKey).Seal(remembered(64, false))
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(one)
	tampered[len(tampered)-5] ^= 1
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{"MEM-1, no cookie", "", flow.SkipAbsent},
		{"MEM-2, tampered", string(tampered), flow.SkipUnreadable},
		{"MEM-2, a version unknown", unknown, flow.SkipUnreadable},
		{"MEM-2, a format unknown", "3" + one[1:], flow.SkipUnreadable},
		// The first half of a value split in two, before revue R20.
		{"MEM-2, a first part of former times", "2." + one[:len(one)/2], flow.SkipUnreadable},
		{"MEM-2, a key unknown", strings.Replace(one, seal.KeyID(activeKey), "00000000", 1), flow.SkipUnreadable},
		{"MEM-2, not base64url", "1." + seal.KeyID(activeKey) + ".!!!", flow.SkipUnreadable},
		{"MEM-2, shorter than a nonce", "1." + seal.KeyID(activeKey) + ".AAAA", flow.SkipUnreadable},
		{"MEM-2, garbage", "garbage", flow.SkipUnreadable},
		{"MEM-2, sealed by a key the dispatcher no longer has", onlyOld, flow.SkipUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec := c
			if strings.Contains(tc.name, "no longer") {
				dec = codec(t, activeKey)
			}
			if got := dec.Open(tc.value); got.Content != nil || got.Reason != tc.want {
				t.Errorf("Open = %+v, want reason %s", got, tc.want)
			}
		})
	}
}

// MEM-2 (Rotation des clés): sealed by a key now previous, it still opens;
// the next cookie is sealed by the active one.
func TestRotation(t *testing.T) {
	before := codec(t, oldKey)
	v, err := before.Seal(remembered(64, false))
	if err != nil {
		t.Fatal(err)
	}
	after := codec(t, activeKey, oldKey)
	if got := after.Open(v); got.Content == nil {
		t.Fatalf("a cookie of the previous key: %+v", got)
	}
	again, _ := after.Seal(remembered(64, false))
	if !strings.HasPrefix(again, "1."+seal.KeyID(activeKey)+".") {
		t.Errorf("sealed by %s", again[:11])
	}
}

// secrets.cookie_key seals dispatcher_admin too: a value it sealed for
// another use does not open here.
func TestOtherUse(t *testing.T) {
	c := codec(t, activeKey)
	keys, err := seal.New(activeKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(remembered(64, false))
	sealed := keys.Seal("dispatcher_admin", format, append([]byte{plainJSON}, data...))
	if got := c.Open(sealed); got.Reason != flow.SkipUnreadable {
		t.Errorf("Open = %+v, want unreadable", got)
	}
}

func TestNewKeys(t *testing.T) {
	for _, keys := range [][][]byte{{[]byte("short")}, {activeKey, []byte("short")}, {make([]byte, 16)}} {
		if _, err := New(keys[0], keys[1:]...); err == nil {
			t.Errorf("keys of %d bytes accepted", len(keys[len(keys)-1]))
		}
	}
}

// WRT-4, MEM-11: a note of logout is read back as what it is, without the members
// of a memory.
func TestNote(t *testing.T) {
	c, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal(&flow.Remembered{V: flow.RememberedFormat, SID: "s", Sub: "alice", Lo: true, AP: []string{"sql"}, IAT: 5, Exp: 10})
	if err != nil {
		t.Fatal(err)
	}
	got := c.Open(sealed).Content
	if got == nil || !got.Lo || got.SID != "s" || got.Sub != "alice" || !slices.Equal(got.AP, []string{"sql"}) || got.Exp != 10 || got.IDT != nil || got.Flow != "" {
		t.Errorf("note %+v", got)
	}
}
