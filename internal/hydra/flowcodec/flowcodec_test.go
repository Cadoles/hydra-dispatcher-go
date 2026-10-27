package flowcodec

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Fixtures recorded by tools/flowfixtures against hydra-dev's Hydra v2.2.0,
// whose secrets.system is devSecret (hydra-dev files/hydra/config.yaml).
const (
	fixtureDir = "testdata/hydra-v2.2.0"
	devSecret  = "youReallyNeedToChangeThis"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func adminResponse(t *testing.T, name string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(fixture(t, name)), v); err != nil {
		t.Fatal(err)
	}
}

func devCodec(t *testing.T) *Codec {
	t.Helper()
	c, err := New([]string{devSecret})
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

// The decrypted flow must carry what Hydra's admin API serves as the login
// request for the same challenge.
func TestLoginChallenge(t *testing.T) {
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
	adminResponse(t, "login_request.json", &want)
	challenge := fixture(t, "login_challenge.txt")
	if want.Challenge != challenge {
		t.Fatal("fixture mismatch: login_request.json is not the admin response for login_challenge.txt")
	}

	f, err := devCodec(t).LoginChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ID) != 32 || f.RequestedAt.IsZero() {
		t.Errorf("ID = %q, RequestedAt = %v: want a 32-hex id and a request time", f.ID, f.RequestedAt)
	}
	if !jsonEqual(t, f.Client, want.Client) {
		t.Errorf("Client = %s, want %s", f.Client, want.Client)
	}
	if !jsonEqual(t, f.OpenIDConnectContext, want.OIDCContext) {
		t.Errorf("OpenIDConnectContext = %s, want %s", f.OpenIDConnectContext, want.OIDCContext)
	}
	// slices.Equal treats Hydra's null audience in the flow and the admin
	// API's [] alike; the emulated API will have to serve [].
	if f.RequestURL != want.RequestURL ||
		!slices.Equal(f.RequestedScope, want.RequestedScope) ||
		!slices.Equal(f.RequestedAudience, want.RequestedAudience) ||
		f.SessionID != want.SessionID || f.LoginSkip != want.Skip || f.Subject != want.Subject {
		t.Errorf("flow = %+v\nwant  %+v", f, want)
	}
}

// The consent challenge holds the same flow, completed by the login accept
// that tools/flowfixtures sent (subject alice, acr, amr, context).
func TestConsentChallenge(t *testing.T) {
	var want struct {
		Challenge      string          `json:"challenge"`
		LoginChallenge string          `json:"login_challenge"`
		LoginSessionID string          `json:"login_session_id"`
		Client         json.RawMessage `json:"client"`
		RequestedScope []string        `json:"requested_scope"`
		Subject        string          `json:"subject"`
		Skip           bool            `json:"skip"`
		ACR            string          `json:"acr"`
		AMR            []string        `json:"amr"`
		Context        json.RawMessage `json:"context"`
	}
	adminResponse(t, "consent_request.json", &want)
	challenge := fixture(t, "consent_challenge.txt")
	if want.Challenge != challenge {
		t.Fatal("fixture mismatch: consent_request.json is not the admin response for consent_challenge.txt")
	}

	c := devCodec(t)
	f, err := c.ConsentChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	login, err := c.LoginChallenge(fixture(t, "login_challenge.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// Hydra 2.2 gives the flow ID as the consent request's login_challenge,
	// not the encrypted login challenge the login URL received.
	if f.ID != want.LoginChallenge || f.ID != login.ID {
		t.Errorf("ID = %q, consent request login_challenge = %q, login flow ID = %q: want all equal", f.ID, want.LoginChallenge, login.ID)
	}
	if f.ConsentChallengeID == "" {
		t.Error("ConsentChallengeID is empty")
	}
	if !jsonEqual(t, f.Context, want.Context) || !jsonEqual(t, f.Context, json.RawMessage(`{"fixture":"flowfixtures","step":1}`)) {
		t.Errorf("Context = %s, want %s", f.Context, want.Context)
	}
	if !jsonEqual(t, f.Client, want.Client) {
		t.Errorf("Client = %s, want %s", f.Client, want.Client)
	}
	if f.SessionID != want.LoginSessionID || f.Subject != "alice" || f.Subject != want.Subject ||
		f.ConsentSkip != want.Skip || f.ACR != want.ACR || !slices.Equal(f.AMR, want.AMR) ||
		!slices.Equal(f.RequestedScope, want.RequestedScope) {
		t.Errorf("flow = %+v\nwant  %+v", f, want)
	}
}

func TestRejected(t *testing.T) {
	login := fixture(t, "login_challenge.txt")
	consent := fixture(t, "consent_challenge.txt")
	mid := len(login) / 2
	flipped := byte('A')
	if login[mid] == 'A' {
		flipped = 'B'
	}

	other, err := New([]string{"another-system-secret-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	dev := devCodec(t)

	tests := []struct {
		name   string
		codec  *Codec
		decode func(*Codec, string) (*Flow, error)
		input  string
	}{
		{"wrong secret", other, (*Codec).LoginChallenge, login},
		{"login challenge read as consent", dev, (*Codec).ConsentChallenge, login},
		{"consent challenge read as login", dev, (*Codec).LoginChallenge, consent},
		{"tampered", dev, (*Codec).LoginChallenge, login[:mid] + string(flipped) + login[mid+1:]},
		{"Hydra 2.1 challenge", dev, (*Codec).LoginChallenge, "94c484d41c384964b49723f39a22e0ec"},
		{"unpadded base64", dev, (*Codec).LoginChallenge, strings.TrimRight(login, "=")},
		{"not base64", dev, (*Codec).LoginChallenge, "%%%"},
		{"empty", dev, (*Codec).LoginChallenge, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f, err := tt.decode(tt.codec, tt.input); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %+v, %v; want ErrInvalid", f, err)
			}
		})
	}
}

// Every secrets.system entry decrypts, whatever its position, as in Hydra.
func TestRotation(t *testing.T) {
	login := fixture(t, "login_challenge.txt")
	for _, secrets := range [][]string{
		{devSecret, "an-older-system-secret-0123"},
		{"a-newer-system-secret-01234", devSecret},
	} {
		c, err := New(secrets)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.LoginChallenge(login); err != nil {
			t.Errorf("secrets %q: %v", secrets, err)
		}
	}
}

func TestNew(t *testing.T) {
	for _, secrets := range [][]string{nil, {}, {""}, {devSecret, ""}} {
		if _, err := New(secrets); err == nil {
			t.Errorf("New(%q): want an error", secrets)
		}
	}
}
