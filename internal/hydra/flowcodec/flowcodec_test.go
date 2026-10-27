package flowcodec

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// Fixtures recorded by tools/flowfixtures, one directory per Hydra release,
// against a Hydra whose secrets.system is devSecret: hydra-dev's (files/hydra/
// config.yaml) for v2.2.0, a throwaway container for v2.3.0.
const devSecret = "youReallyNeedToChangeThis"

var fixtureDirs = []struct {
	dir     string
	version Version
}{
	{"hydra-v2.2.0", Hydra22},
	{"hydra-v2.3.0", Hydra23},
}

// forEachFixture runs test on the fixtures of every Hydra release.
func forEachFixture(t *testing.T, test func(t *testing.T, dir string, v Version)) {
	for _, fd := range fixtureDirs {
		t.Run(fd.dir, func(t *testing.T) { test(t, fd.dir, fd.version) })
	}
}

func fixture(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func adminResponse(t *testing.T, dir, name string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(fixture(t, dir, name)), v); err != nil {
		t.Fatal(err)
	}
}

func devCodec(t *testing.T, v Version) *Codec {
	t.Helper()
	c, err := New(v, []string{devSecret})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// jsonEqual compares two JSON documents, ignoring key order and layout.
func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return reflect.DeepEqual(va, vb)
}

func isFlowID(id string) bool {
	_, err := hex.DecodeString(id)
	return len(id) == 32 && err == nil
}

// Every fixture directory is tested, and every supported version has one.
func TestFixturesCoverVersions(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		dirs = append(dirs, e.Name())
	}
	tested := map[Version]bool{}
	for _, fd := range fixtureDirs {
		if !slices.Contains(dirs, fd.dir) {
			t.Errorf("fixtureDirs lists %s, absent from testdata", fd.dir)
		}
		dirs = slices.DeleteFunc(dirs, func(d string) bool { return d == fd.dir })
		tested[fd.version] = true
	}
	if len(dirs) > 0 {
		t.Errorf("testdata/%s: not in fixtureDirs", dirs)
	}
	for v := range formats {
		if !tested[v] {
			t.Errorf("Hydra %s: no fixtures", v)
		}
	}
}

// The decrypted flow must carry what Hydra's admin API serves as the login
// request for the same challenge.
func TestLoginChallenge(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string, v Version) {
		var want struct {
			Challenge         string          `json:"challenge"`
			Client            json.RawMessage `json:"client"`
			OIDCContext       json.RawMessage `json:"oidc_context"`
			RequestURL        string          `json:"request_url"`
			RequestedScope    []string        `json:"requested_scope"`
			RequestedAudience []string        `json:"requested_access_token_audience"`
			SessionID         string          `json:"session_id"`
			Skip              bool            `json:"skip"`
			Subject           string          `json:"subject"`
		}
		adminResponse(t, dir, "login_request.json", &want)
		challenge := fixture(t, dir, "login_challenge.txt")
		if want.Challenge != challenge {
			t.Fatal("fixture mismatch: login_request.json is not the admin response for login_challenge.txt")
		}
		var client struct {
			ID string `json:"client_id"`
		}
		if err := json.Unmarshal(want.Client, &client); err != nil {
			t.Fatal(err)
		}

		f, err := devCodec(t, v).LoginChallenge(challenge)
		if err != nil {
			t.Fatal(err)
		}
		if !isFlowID(f.ID) || f.ConsentChallengeID != "" {
			t.Errorf("ID = %q, ConsentChallengeID = %q: want a 32-hex id and no consent yet", f.ID, f.ConsentChallengeID)
		}
		if f.ClientID != client.ID {
			t.Errorf("ClientID = %q, want %q", f.ClientID, client.ID)
		}
		if !jsonEqual(t, f.Client, want.Client) {
			t.Errorf("Client = %s, want %s", f.Client, want.Client)
		}
		if !jsonEqual(t, f.OpenIDConnectContext, want.OIDCContext) {
			t.Errorf("OpenIDConnectContext = %s, want %s", f.OpenIDConnectContext, want.OIDCContext)
		}
		// Hydra has no context before the login accept: JSON null, read as nil.
		if f.Context != nil {
			t.Errorf("Context = %q, want nil", f.Context)
		}
		// slices.Equal treats Hydra's null audience in the flow and the admin
		// API's [] alike; the emulated API will have to serve [].
		if f.RequestURL != want.RequestURL ||
			!slices.Equal(f.RequestedScope, want.RequestedScope) ||
			!slices.Equal(f.RequestedAudience, want.RequestedAudience) ||
			f.SessionID != want.SessionID || f.LoginSkip != want.Skip || f.Subject != want.Subject {
			t.Errorf("flow = %+v\nwant  %+v", f, want)
		}
	})
}

// The consent challenge holds the same flow, completed by the login accept
// that tools/flowfixtures sent (subject alice, acr, amr, context).
func TestConsentChallenge(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string, v Version) {
		var want struct {
			Challenge         string          `json:"challenge"`
			LoginChallenge    string          `json:"login_challenge"`
			LoginSessionID    string          `json:"login_session_id"`
			Client            json.RawMessage `json:"client"`
			OIDCContext       json.RawMessage `json:"oidc_context"`
			RequestURL        string          `json:"request_url"`
			RequestedScope    []string        `json:"requested_scope"`
			RequestedAudience []string        `json:"requested_access_token_audience"`
			Subject           string          `json:"subject"`
			Skip              bool            `json:"skip"`
			ACR               string          `json:"acr"`
			AMR               []string        `json:"amr"`
			Context           json.RawMessage `json:"context"`
		}
		adminResponse(t, dir, "consent_request.json", &want)
		challenge := fixture(t, dir, "consent_challenge.txt")
		if want.Challenge != challenge {
			t.Fatal("fixture mismatch: consent_request.json is not the admin response for consent_challenge.txt")
		}

		c := devCodec(t, v)
		f, err := c.ConsentChallenge(challenge)
		if err != nil {
			t.Fatal(err)
		}
		login, err := c.LoginChallenge(fixture(t, dir, "login_challenge.txt"))
		if err != nil {
			t.Fatal(err)
		}

		// Hydra gives the flow ID as the consent request's login_challenge,
		// not the encrypted login challenge the login URL received.
		if f.ID != want.LoginChallenge || f.ID != login.ID {
			t.Errorf("ID = %q, consent request login_challenge = %q, login flow ID = %q: want all equal", f.ID, want.LoginChallenge, login.ID)
		}
		if f.ConsentChallengeID == "" || f.ClientID != login.ClientID {
			t.Errorf("ConsentChallengeID = %q, ClientID = %q: want an id and the login's client %q", f.ConsentChallengeID, f.ClientID, login.ClientID)
		}
		if !jsonEqual(t, f.Context, want.Context) || !jsonEqual(t, f.Context, json.RawMessage(`{"fixture":"flowfixtures","step":1}`)) {
			t.Errorf("Context = %s, want %s", f.Context, want.Context)
		}
		if !jsonEqual(t, f.Client, want.Client) {
			t.Errorf("Client = %s, want %s", f.Client, want.Client)
		}
		if !jsonEqual(t, f.OpenIDConnectContext, want.OIDCContext) {
			t.Errorf("OpenIDConnectContext = %s, want %s", f.OpenIDConnectContext, want.OIDCContext)
		}
		if f.SessionID != want.LoginSessionID || f.Subject != "alice" || f.Subject != want.Subject ||
			f.ConsentSkip != want.Skip || f.ACR != want.ACR || !slices.Equal(f.AMR, want.AMR) ||
			f.RequestURL != want.RequestURL || !slices.Equal(f.RequestedScope, want.RequestedScope) ||
			!slices.Equal(f.RequestedAudience, want.RequestedAudience) {
			t.Errorf("flow = %+v\nwant  %+v", f, want)
		}
	})
}

// A codec set for another Hydra version opens the challenge (same secret and
// purpose) but does not read the flow: ErrFormat, never an empty flow.
func TestOtherVersion(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string, v Version) {
		for other := range formats {
			if other == v {
				continue
			}
			c := devCodec(t, other)
			if f, err := c.LoginChallenge(fixture(t, dir, "login_challenge.txt")); !errors.Is(err, ErrFormat) {
				t.Errorf("login challenge read as Hydra %s: got %+v, %v; want ErrFormat", other, f, err)
			}
			if f, err := c.ConsentChallenge(fixture(t, dir, "consent_challenge.txt")); !errors.Is(err, ErrFormat) {
				t.Errorf("consent challenge read as Hydra %s: got %+v, %v; want ErrFormat", other, f, err)
			}
		}
	})
}

func TestRejected(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string, v Version) {
		login := fixture(t, dir, "login_challenge.txt")
		consent := fixture(t, dir, "consent_challenge.txt")
		mid := len(login) / 2
		flipped := byte('A')
		if login[mid] == 'A' {
			flipped = 'B'
		}

		other, err := New(v, []string{"another-system-secret-0123456789"})
		if err != nil {
			t.Fatal(err)
		}
		dev := devCodec(t, v)

		type rejected struct {
			name   string
			codec  *Codec
			decode func(*Codec, string) (*Flow, error)
			input  string
			want   error
		}
		tests := []rejected{
			{"wrong secret", other, (*Codec).LoginChallenge, login, ErrInvalid},
			{"login challenge read as consent", dev, (*Codec).ConsentChallenge, login, ErrInvalid},
			{"consent challenge read as login", dev, (*Codec).LoginChallenge, consent, ErrInvalid},
			{"tampered", dev, (*Codec).LoginChallenge, login[:mid] + string(flipped) + login[mid+1:], ErrInvalid},
			{"not base64", dev, (*Codec).LoginChallenge, "%%%", ErrInvalid},
			{"empty", dev, (*Codec).LoginChallenge, "", ErrInvalid},
			{"too long", dev, (*Codec).LoginChallenge, login + strings.Repeat("AAAA", maxChallengeSize/4), ErrInvalid},
			{"Hydra 2.1 login challenge", dev, (*Codec).LoginChallenge, "94c484d41c384964b49723f39a22e0ec", ErrNotEncrypted},
			{"Hydra 2.1 consent challenge", dev, (*Codec).ConsentChallenge, "5471077c144c4a52836de596c4781df0", ErrNotEncrypted},
		}
		// Only a challenge whose length is not a multiple of 3 bytes is padded.
		if unpadded := strings.TrimRight(login, "="); unpadded != login {
			tests = append(tests, rejected{"unpadded base64", dev, (*Codec).LoginChallenge, unpadded, ErrInvalid})
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if f, err := tt.decode(tt.codec, tt.input); !errors.Is(err, tt.want) {
					t.Errorf("got %+v, %v; want %v", f, err, tt.want)
				}
			})
		}
	})
}

// seal does what Hydra does to a flow. It stays in the tests: the package
// never seals.
func seal(t *testing.T, ad, plain []byte, compress bool) string {
	t.Helper()
	if compress {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		plain = b.Bytes()
	}
	key := sha256.Sum256([]byte(devSecret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, ad))
}

// Flows sealed with the dev secret, in the Hydra 2.2 format: what passes the
// AEAD but is not a complete flow fails with ErrFormat, whose message never
// quotes the content ("leak" marks content).
func TestSealedFlows(t *testing.T) {
	const (
		login   = `"ID":"91d4f7afaf83455f8e2b8992cba303ef","RequestedAt":"2026-10-27T08:15:18Z","Client":{"client_id":"c"},"RequestURL":"http://hydra.test/oauth2/auth"`
		consent = login + `,"ConsentChallengeID":"5471077c144c4a52836de596c4781df0","Subject":"alice"`
	)
	c := devCodec(t, Hydra22)
	tests := []struct {
		name     string
		consent  bool
		plain    string
		compress bool
		want     error
	}{
		{"complete login", false, `{` + login + `,"Context":null,"OpenIDConnectContext":null}`, true, nil},
		{"complete consent", true, `{` + consent + `}`, true, nil},
		{"null", false, `null`, true, ErrFormat},
		{"empty object", false, `{}`, true, ErrFormat},
		{"Hydra 2.3 keys", false, `{"i":"91d4f7afaf83455f8e2b8992cba303ef","s":"leak"}`, true, ErrFormat},
		{"no client", false, `{` + strings.Replace(login, `"Client":{"client_id":"c"}`, `"Client":null`, 1) + `}`, true, ErrFormat},
		{"client without id", false, `{` + strings.Replace(login, `{"client_id":"c"}`, `{"client_name":"leak"}`, 1) + `}`, true, ErrFormat},
		{"no request time", false, `{` + strings.Replace(login, `"RequestedAt"`, `"Leak"`, 1) + `}`, true, ErrFormat},
		{"bad request time", false, `{` + strings.Replace(login, `2026-10-27T08:15:18Z`, `leak`, 1) + `}`, true, ErrFormat},
		{"no request URL", false, `{` + strings.Replace(login, `"RequestURL"`, `"Leak"`, 1) + `}`, true, ErrFormat},
		{"consent without subject", true, `{` + login + `,"ConsentChallengeID":"5471077c144c4a52836de596c4781df0"}`, true, ErrFormat},
		{"consent without consent ID", true, `{` + login + `,"Subject":"alice"}`, true, ErrFormat},
		{"not gzip", false, `{` + login + `}`, false, ErrFormat},
		{"flow over the limit", false, `{` + login + `,"Context":"` + strings.Repeat("leak", maxFlowSize/4) + `"}`, true, ErrFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, decode := c.format.login, c.LoginChallenge
			if tt.consent {
				ad, decode = c.format.consent, c.ConsentChallenge
			}
			f, err := decode(seal(t, ad, []byte(tt.plain), tt.compress))
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %+v, %v; want %v", f, err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "leak") {
				t.Errorf("error %q quotes the flow", err)
			}
			if err == nil && (f.ClientID != "c" || f.Context != nil || f.OpenIDConnectContext != nil) {
				t.Errorf("flow = %+v: want ClientID c and null read as nil", f)
			}
		})
	}
}

// The additional data of Hydra's other purposes never opens as a challenge:
// verifiers (1, 3), no purpose, and Hydra 25.4's consent challenge (4).
func TestOtherPurposes(t *testing.T) {
	c := devCodec(t, Hydra22)
	flow := []byte(`{"ID":"91d4f7afaf83455f8e2b8992cba303ef","RequestedAt":"2026-10-27T08:15:18Z","Client":{"client_id":"c"},"RequestURL":"u","ConsentChallengeID":"x","Subject":"alice"}`)
	for _, ad := range []string{`{"p":1}`, `{"p":3}`, `{"p":4}`, ``} {
		challenge := seal(t, []byte(ad), flow, true)
		if _, err := c.LoginChallenge(challenge); !errors.Is(err, ErrInvalid) {
			t.Errorf("additional data %q opened as a login challenge: %v", ad, err)
		}
		if _, err := c.ConsentChallenge(challenge); !errors.Is(err, ErrInvalid) {
			t.Errorf("additional data %q opened as a consent challenge: %v", ad, err)
		}
	}
}

// Every secrets.system entry decrypts, whatever its position, as in Hydra.
func TestRotation(t *testing.T) {
	forEachFixture(t, func(t *testing.T, dir string, v Version) {
		login := fixture(t, dir, "login_challenge.txt")
		for _, secrets := range [][]string{
			{devSecret, "an-older-system-secret-0123"},
			{"a-newer-system-secret-01234", devSecret},
		} {
			c, err := New(v, secrets)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.LoginChallenge(login); err != nil {
				t.Errorf("secrets %q: %v", secrets, err)
			}
		}
	})
}

func TestNew(t *testing.T) {
	for _, secrets := range [][]string{nil, {}, {""}, {devSecret, ""}} {
		if _, err := New(Hydra22, secrets); err == nil {
			t.Errorf("New(%q): want an error", secrets)
		}
	}
	for _, v := range []Version{"", "2.1", "25.4"} {
		if _, err := New(v, []string{devSecret}); err == nil {
			t.Errorf("New(%q): want an error", v)
		}
	}
}

// The derived key forges challenges: printing or logging a codec must not
// show it.
func TestCodecHidesKey(t *testing.T) {
	c := devCodec(t, Hydra22)
	key := sha256.Sum256([]byte(devSecret))
	var log bytes.Buffer
	slog.New(slog.NewTextHandler(&log, nil)).Info("codec", "c", c, "v", *c)
	out := fmt.Sprintf("%v %+v %#v %s", c, *c, *c, log.String())
	for _, k := range []string{hex.EncodeToString(key[:8]), strings.Trim(fmt.Sprint(key[:8]), "[]")} {
		if strings.Contains(out, k) {
			t.Fatalf("key %s printed: %s", k, out)
		}
	}
}
