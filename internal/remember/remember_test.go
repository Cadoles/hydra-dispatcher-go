package remember

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
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

func open(c *Codec, values []string) flow.Memory {
	second := ""
	if len(values) > 1 {
		second = values[1]
	}
	return c.Open(values[0], second)
}

// WRT-1, MEM-1, MEM-2: what is sealed opens as it was, in one cookie,
// deflated beyond 1.5 KB, in two beyond 3.8 KB.
func TestSealOpen(t *testing.T) {
	c := codec(t, activeKey)
	for _, tc := range []struct {
		name         string
		r            *flow.Remembered
		parts        int
		smallerThan  int // the JSON, when deflated
		compressible bool
	}{
		{"WRT-1, a small memory, one cookie", remembered(64, false), 1, 0, false},
		{"WRT-1, beyond 1.5 KB, deflated", remembered(3000, true), 1, 3000, true},
		{"WRT-1, beyond 3.8 KB, two cookies", remembered(4000, false), 2, 0, false},
		{"WRT-1, a session cookie, exp 0", func() *flow.Remembered { r := remembered(64, false); r.Exp = 0; return r }(), 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values, err := c.Seal(tc.r)
			if err != nil {
				t.Fatal(err)
			}
			if len(values) != tc.parts {
				t.Fatalf("%d cookies, want %d", len(values), tc.parts)
			}
			for i, v := range values {
				if len(v) > splitAbove+len(splitMark) {
					t.Errorf("cookie %d of %d bytes", i+1, len(v))
				}
				// A cookie value as browsers keep it, without quotes.
				if strings.ContainsAny(v, " \",;\\") {
					t.Errorf("cookie %d holds a separator: %q", i+1, v)
				}
			}
			if tc.smallerThan > 0 && len(values[0]) >= tc.smallerThan {
				t.Errorf("deflated: %d bytes, not under %d", len(values[0]), tc.smallerThan)
			}
			got := open(c, values)
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

// WRT-2: beyond 7.5 KB, nothing to write; the page clears the former one.
func TestSealTooLarge(t *testing.T) {
	if _, err := codec(t, activeKey).Seal(remembered(8000, false)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Seal = %v, want ErrTooLarge", err)
	}
}

// MEM-1, MEM-2: absent, or unreadable, with the reason skip.ignored gives.
func TestOpenFails(t *testing.T) {
	c := codec(t, activeKey, oldKey)
	one, err := c.Seal(remembered(64, false))
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.Seal(remembered(4000, false))
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.Seal(remembered(4000, false))
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
	tampered := []byte(one[0])
	tampered[len(tampered)-5] ^= 1
	for _, tc := range []struct {
		name          string
		first, second string
		want          string
	}{
		{"MEM-1, no cookie", "", "", flow.SkipAbsent},
		{"MEM-1, the second part missing", two[0], "", flow.SkipAbsent},
		{"MEM-1, the second part alone", "", two[1], flow.SkipAbsent},
		{"MEM-2, the second part of another cookie", two[0], other[1], flow.SkipUnreadable},
		{"MEM-2, tampered", string(tampered), "", flow.SkipUnreadable},
		{"MEM-2, a version unknown", unknown[0], "", flow.SkipUnreadable},
		{"MEM-2, a format unknown", "3" + one[0][1:], "", flow.SkipUnreadable},
		{"MEM-2, a key unknown", strings.Replace(one[0], keyID(activeKey), "00000000", 1), "", flow.SkipUnreadable},
		{"MEM-2, not base64url", "1." + keyID(activeKey) + ".!!!", "", flow.SkipUnreadable},
		{"MEM-2, shorter than a nonce", "1." + keyID(activeKey) + ".AAAA", "", flow.SkipUnreadable},
		{"MEM-2, garbage", "garbage", "", flow.SkipUnreadable},
		{"MEM-2, sealed by a key the dispatcher no longer has", onlyOld[0], "", flow.SkipUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec := c
			if strings.Contains(tc.name, "no longer") {
				dec = codec(t, activeKey)
			}
			if got := dec.Open(tc.first, tc.second); got.Content != nil || got.Reason != tc.want {
				t.Errorf("Open = %+v, want reason %s", got, tc.want)
			}
		})
	}
}

// MEM-2 (Rotation des clés): sealed by a key now previous, it still opens;
// the next cookie is sealed by the active one.
func TestRotation(t *testing.T) {
	before := codec(t, oldKey)
	values, err := before.Seal(remembered(64, false))
	if err != nil {
		t.Fatal(err)
	}
	after := codec(t, activeKey, oldKey)
	if got := open(after, values); got.Content == nil {
		t.Fatalf("a cookie of the previous key: %+v", got)
	}
	again, _ := after.Seal(remembered(64, false))
	if !strings.HasPrefix(again[0], "1."+keyID(activeKey)+".") {
		t.Errorf("sealed by %s", again[0][:11])
	}
}

// secrets.cookie_key seals dispatcher_admin too: a value it sealed for
// another use does not open here.
func TestOtherUse(t *testing.T) {
	c := codec(t, activeKey)
	k := c.keys[0]
	nonce := make([]byte, k.aead.NonceSize())
	data, _ := json.Marshal(remembered(64, false))
	sealed := sealWith(k.aead, nonce, append([]byte{plainJSON}, data...), []byte("dispatcher_admin"))
	if got := c.Open("1."+k.id+"."+sealed, ""); got.Reason != flow.SkipUnreadable {
		t.Errorf("Open = %+v, want unreadable", got)
	}
}

func sealWith(aead cipher.AEAD, nonce, plain, ad []byte) string {
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, ad))
}

func TestNewKeys(t *testing.T) {
	for _, keys := range [][][]byte{{[]byte("short")}, {activeKey, []byte("short")}, {make([]byte, 16)}} {
		if _, err := New(keys[0], keys[1:]...); err == nil {
			t.Errorf("keys of %d bytes accepted", len(keys[len(keys)-1]))
		}
	}
}
