package flow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/hydra/flowcodec"
)

// Source reads Hydra's login and consent requests (Déchiffrement local of
// Table de transitions.md): Fallback asks the admin API, Decrypt reads the
// challenges themselves, which Hydra 2.2 and 2.3 seal with the flow. Hydra's
// errors come back as internal/hydra gives them; a request Decrypt reads past
// its lifetime, as ErrChallengeExpired.
type Source interface {
	LoginRequest(ctx context.Context, challenge string) LoginRead
	ConsentRequest(ctx context.Context, challenge string) ConsentRead
}

// AdminReader is the admin API's reads, as internal/hydra's client does them.
type AdminReader interface {
	LoginRequest(ctx context.Context, challenge string) (*ory.OAuth2LoginRequest, error)
	ConsentRequest(ctx context.Context, challenge string) (*ory.OAuth2ConsentRequest, error)
}

// ErrChallengeExpired is a challenge Decrypt read at or past requested_at +
// hydra.login_consent_ttl, the lifetime Hydra gives it (DEC-4): gone, as the
// 401 request_unauthorized of Hydra 2.2's admin API.
var ErrChallengeExpired = errors.New("flow: challenge past its lifetime at Hydra")

// Fallback reads the requests on Hydra's admin API, which does not serve
// requested_at: the time of the read stands for it. It follows requested_at,
// so that the flow never ends before L at Hydra (Q2).
type Fallback struct {
	Hydra AdminReader
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

func (s Fallback) LoginRequest(ctx context.Context, challenge string) LoginRead {
	r, err := s.Hydra.LoginRequest(ctx, challenge)
	if err != nil {
		return LoginRead{Err: err}
	}
	// Hydra serves no audience as null: the apps are served [] (P3).
	if r.RequestedAccessTokenAudience == nil {
		r.RequestedAccessTokenAudience = []string{}
	}
	read := LoginRead{Request: r, RequestedAt: clock(s.Now)}
	if legacy(challenge) {
		// Hydra 2.1 names L itself in the consent request (Q34); a 2.2
		// challenge read here gives no id.
		read.LoginID = challenge
	}
	return read
}

func (s Fallback) ConsentRequest(ctx context.Context, challenge string) ConsentRead {
	r, err := s.Hydra.ConsentRequest(ctx, challenge)
	if err != nil {
		return ConsentRead{Err: err}
	}
	return ConsentRead{Request: r}
}

// Codec decrypts Hydra's challenges, as flowcodec.Codec does.
type Codec interface {
	LoginChallenge(challenge string) (*flowcodec.Flow, error)
	ConsentChallenge(challenge string) (*flowcodec.Flow, error)
}

// Decrypt reads the requests from the challenges, without calling Hydra
// (DEC-3), and gives a request past its lifetime as ErrChallengeExpired
// (DEC-4), which the page that answers E1002 reports (ENT-11, CST-4). A
// challenge it does not read goes to Fallback: Hydra 2.1's (DEC-2), one no
// secret opens (DEC-5), a flow of another format (DEC-6). The reports of a
// fallback follow Q32: one Hydra knows means the dispatcher lacks its secret;
// one unknown to the admin API too is forged, which the page that answers
// E1001 reports (ENT-12, CST-2), in every mode.
type Decrypt struct {
	Codec    Codec
	Fallback Fallback
	// TTL is hydra.login_consent_ttl, Hydra's ttl.login_consent_request.
	TTL time.Duration
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// errUnbuilt is a flow opened and read whose request does not build: its
// client does not decode, or it lacks what every request carries.
var errUnbuilt = fmt.Errorf("%w: the request does not build", flowcodec.ErrFormat)

func (s Decrypt) LoginRequest(ctx context.Context, challenge string) LoginRead {
	f, err := s.Codec.LoginChallenge(challenge)
	if err == nil {
		if s.expired(f) {
			return LoginRead{Err: ErrChallengeExpired, Decrypted: true}
		}
		r, buildErr := hydra.LoginRequestOf(challenge, f)
		if buildErr == nil {
			return LoginRead{Request: r, RequestedAt: f.RequestedAt, LoginID: f.ID, Decrypted: true}
		}
		err = errUnbuilt
	}
	read := s.Fallback.LoginRequest(ctx, challenge)
	read.Reports = append(read.Reports, fellBack(err, read.Err)...)
	return read
}

func (s Decrypt) ConsentRequest(ctx context.Context, challenge string) ConsentRead {
	f, err := s.Codec.ConsentChallenge(challenge)
	if err == nil {
		if s.expired(f) {
			return ConsentRead{Err: ErrChallengeExpired, Decrypted: true}
		}
		r, buildErr := hydra.ConsentRequestOf(challenge, f)
		if buildErr == nil {
			return ConsentRead{Request: r, Decrypted: true}
		}
		err = errUnbuilt
	}
	read := s.Fallback.ConsentRequest(ctx, challenge)
	read.Reports = append(read.Reports, fellBack(err, read.Err)...)
	return read
}

// expired tells whether f is at or past its lifetime at Hydra, the bound of
// hx: Hydra 2.2's admin API would answer 401.
func (s Decrypt) expired(f *flowcodec.Flow) bool {
	return !clock(s.Now).Before(f.RequestedAt.Add(s.TTL))
}

// fellBack is what a fallback after the decryption error decryptErr reports,
// once the admin API answered adminErr (DEC-2, DEC-5, DEC-6, Q32). The detail
// names the step that failed, never the flow's content.
func fellBack(decryptErr, adminErr error) []Report {
	switch {
	case errors.Is(decryptErr, flowcodec.ErrNotEncrypted):
		return nil // DEC-2: a Hydra 2.1 challenge, which the switch-over expects
	case errors.Is(decryptErr, flowcodec.ErrInvalid):
		switch classify(adminErr) {
		case unknown:
			// Unknown to Hydra too: forged or tampered, never the decryption
			// alert. The page that answers E1001 reports it (ENT-12, CST-2),
			// as for a 32-hexadecimal challenge or in fallback mode.
			return nil
		case unavailable:
			return nil // Hydra could not tell; its E1004 says so
		}
	}
	// Hydra knows the challenge, or sealed a flow the dispatcher cannot
	// read: a secret missing from the list, or the wrong hydra.version.
	return []Report{{Event: "hydra.decrypt_fallback", Detail: decryptErr.Error()}}
}

// legacy reports a Hydra 2.1 challenge: 32 hexadecimal characters.
func legacy(challenge string) bool {
	_, err := hex.DecodeString(challenge)
	return len(challenge) == 32 && err == nil
}

// clock is now, from now when not nil.
func clock(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}
