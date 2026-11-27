package flow

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// Observer watches what the requests decided, without deciding anything: the metrics,
// the audit, Sentry, the failure limiter. It must not block: it runs on the request.
type Observer interface {
	Observe(ctx context.Context, o Observation)
}

// Observation is what one request decided, once, at its end.
type Observation struct {
	Event Event
	// Surface is front or emulated.
	Surface string
	// Before is the flow as last read, nil when absent; After as the request left it,
	// the flow written when there is one.
	Before, After *Flow
	Response      Response
	Reports       []Report
	// Answers are the calls made during the request, what they read and what they sent.
	Answers Answers
	// Validations are how the challenges of Hydra read during the request came out.
	Validations []Validation
	Config      *store.Snapshot
	Now         time.Time
}

// Validation is how a challenge of Hydra came out (challenge_validations_total).
type Validation struct {
	// Mode is decrypt or fallback, Result ok, expired, invalid or decrypt_error.
	Mode, Result string
}

// Modes and results of a Validation.
const (
	ModeDecrypt  = "decrypt"
	ModeFallback = "fallback"

	ValidationOK           = "ok"
	ValidationExpired      = "expired"
	ValidationInvalid      = "invalid"
	ValidationDecryptError = "decrypt_error"
)

// validations reads the outcome of the login and consent requests read: a challenge
// unknown to Hydra is invalid in every mode, one past its lifetime expired in every
// mode, decrypt_error only when Hydra knows what the dispatcher could not open (Q32,
// DEC-6). Hydra unavailable says nothing of the challenge, and a request Hydra 2.1 says
// handled (410) neither.
func (a Answers) validations(reports []Report) []Validation {
	for _, r := range reports {
		if r.Event == "hydra.decrypt_fallback" {
			return []Validation{{Mode: ModeDecrypt, Result: ValidationDecryptError}}
		}
	}
	var out []Validation
	read := func(decrypted bool, err error) {
		mode := ModeFallback
		if decrypted {
			mode = ModeDecrypt
		}
		var re *hydra.RequestError
		switch {
		case err == nil:
			out = append(out, Validation{Mode: mode, Result: ValidationOK})
		case errors.Is(err, ErrChallengeExpired), errors.As(err, &re) && re.Status == http.StatusUnauthorized:
			out = append(out, Validation{Mode: mode, Result: ValidationExpired})
		case errors.As(err, &re) && re.Status == http.StatusNotFound:
			out = append(out, Validation{Mode: mode, Result: ValidationInvalid})
		}
	}
	if l := a.Login; l != nil {
		read(l.Decrypted, l.Err)
	}
	if c := a.Consent; c != nil {
		read(c.Decrypted, c.Err)
	}
	return out
}

// Consent tells whether the operation is on a consent step, not a login one.
func (o AppOp) Consent() bool { return o.kind() == KindConsent }
