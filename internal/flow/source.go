package flow

import (
	"context"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// LoginSource reads Hydra's login request of a challenge, and when Hydra
// received it. Two implement it: Fallback, which asks the admin API, and the
// decryption of the challenge (P7), which reads it locally with
// requested_at. Hydra's errors come back as internal/hydra gives them.
type LoginSource interface {
	LoginRequest(ctx context.Context, challenge string) (r *ory.OAuth2LoginRequest, requestedAt time.Time, err error)
}

// LoginReader is the admin API's read of a login request, as
// internal/hydra's client does it.
type LoginReader interface {
	LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, error)
}

// Fallback reads the login request on Hydra's admin API, which does not
// serve requested_at: the time of the read stands for it. It follows
// requested_at, so that the flow never ends before L at Hydra (Q2).
type Fallback struct {
	Hydra LoginReader
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

func (s Fallback) LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, time.Time, error) {
	r, err := s.Hydra.LoginRequest(ctx, challenge)
	if err != nil {
		return nil, time.Time{}, err
	}
	// Hydra serves no audience as null: the apps are served [] (P3).
	if r.RequestedAccessTokenAudience == nil {
		r.RequestedAccessTokenAudience = []string{}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return r, now(), nil
}
