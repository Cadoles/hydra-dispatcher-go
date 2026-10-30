package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// hydraReader is the admin API of a fake Hydra.
type hydraReader struct {
	r   *ory.OAuth2LoginRequest
	err error
	got string
}

func (h *hydraReader) LoginRequest(_ context.Context, challenge string) (*ory.OAuth2LoginRequest, error) {
	h.got = challenge
	return h.r, h.err
}

// decrypted stands for the decryption of P7: the login request read locally,
// with Hydra's requested_at.
type decrypted struct {
	r           *ory.OAuth2LoginRequest
	requestedAt time.Time
}

func (d decrypted) LoginRequest(context.Context, string) (*ory.OAuth2LoginRequest, time.Time, error) {
	return d.r, d.requestedAt, nil
}

// created is the flow ENT-1 creates from what the source gives.
func created(t *testing.T, src LoginSource) *Flow {
	t.Helper()
	r, at, err := src.LoginRequest(context.Background(), hydraL)
	if err != nil {
		t.Fatal(err)
	}
	out := Decide(Input{Event: Entry{LoginChallenge: hydraL, Cookie: cookie}, Loaded: true, Env: testEnv(),
		Answers: Answers{Login: &LoginRead{Request: r, RequestedAt: at}}})
	if out.Write == nil {
		t.Fatalf("no flow created: %+v", out)
	}
	return out.Write
}

func TestFallback(t *testing.T) {
	r := loginRequest(t)
	r.RequestedAccessTokenAudience = nil
	h := &hydraReader{r: r}
	src := Fallback{Hydra: h, Now: func() time.Time { return testNow }}

	// The first read stands for requested_at (ENT-1, Q2).
	f := created(t, src)
	if h.got != hydraL {
		t.Errorf("read %q", h.got)
	}
	if f.HydraExpiresAt != testNow.Add(30*time.Minute).UnixMilli() || f.ExpiresAt != testNow.Add(29*time.Minute).UnixMilli() {
		t.Errorf("Q2, fallback: exp %d hx %d", f.ExpiresAt, f.HydraExpiresAt)
	}
	// A null audience is served [] (P3).
	if f.Hydra.Audience == nil {
		t.Error("audience null")
	}
	got, _, _ := src.LoginRequest(context.Background(), hydraL)
	if got.RequestedAccessTokenAudience == nil || len(got.RequestedAccessTokenAudience) != 0 {
		t.Errorf("audience %#v", got.RequestedAccessTokenAudience)
	}

	// Hydra's errors as internal/hydra gives them.
	h.r, h.err = nil, err404
	if _, at, err := src.LoginRequest(context.Background(), hydraL); !errors.Is(err, err404) || !at.IsZero() {
		t.Errorf("err %v, at %v", err, at)
	}
	h.err = nil
	h.r = loginRequest(t)
	if _, at, _ := (Fallback{Hydra: h}).LoginRequest(context.Background(), hydraL); time.Since(at) > time.Minute {
		t.Errorf("the default clock: %v", at)
	}
}

func TestDecryptedSource(t *testing.T) {
	// Decrypted, the flow ends with L at Hydra, from requested_at (Q2).
	f := created(t, decrypted{r: loginRequest(t), requestedAt: testNow.Add(-10 * time.Minute)})
	if f.HydraExpiresAt != testNow.Add(20*time.Minute).UnixMilli() || f.ExpiresAt != testNow.Add(19*time.Minute).UnixMilli() {
		t.Errorf("Q2, decrypted: exp %d hx %d", f.ExpiresAt, f.HydraExpiresAt)
	}
}
