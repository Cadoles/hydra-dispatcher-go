package flow

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
)

// hydraSays is what the fake Hydra and the webhooks answer, by call.
type hydraSays map[Op]said

type said struct {
	login       *ory.OAuth2LoginRequest
	requestedAt time.Time
	loginID     string
	consent     *ory.OAuth2ConsentRequest
	redirectTo  string
	err         error
	loginHook   *LoginHookAnswer
	hookErr     error
}

var (
	errDown = errors.New("connection refused")
	// The errors of internal/hydra, by status.
	err404 = &hydra.RequestError{Status: http.StatusNotFound}
	err401 = &hydra.RequestError{Status: http.StatusUnauthorized}
	err410 = &hydra.RequestError{Status: http.StatusGone}
	err409 = &hydra.RequestError{Status: http.StatusConflict}
	err400 = &hydra.RequestError{Status: http.StatusBadRequest}
	err403 = &hydra.RequestError{Status: http.StatusForbidden}
)

// played is a request played to its end.
type played struct {
	Outcome
	calls []Call
}

func (p played) ops() []Op {
	var ops []Op
	for _, c := range p.calls {
		ops = append(ops, c.Op)
	}
	return ops
}

// play runs Decide as the orchestrator would, without a store: the flow
// read is stored, a re-read gives reread when set (a concurrent request's
// write), and the calls get what says answers.
func play(t *testing.T, env Env, ev Event, stored, reread *Flow, says hydraSays) played {
	t.Helper()
	in := Input{Event: ev, Env: env}
	var p played
	for range 20 {
		out := Decide(in)
		switch {
		case out.Load != "":
			if in.Loaded {
				t.Fatalf("flow loaded twice")
			}
			in.Loaded, in.Flow = true, copyFlow(t, stored)
		case out.Reread:
			if in.Reread {
				t.Fatalf("flow read again twice")
			}
			in.Reread, in.Flow = true, copyFlow(t, stored)
			if reread != nil {
				in.Flow = copyFlow(t, reread)
			}
		case out.Call != nil:
			for _, c := range p.calls {
				if c.Op == out.Call.Op {
					t.Fatalf("call %v made twice", c.Op)
				}
			}
			p.calls = append(p.calls, *out.Call)
			a, ok := says[out.Call.Op]
			if !ok {
				t.Fatalf("unexpected call %v %+v", out.Call.Op, *out.Call)
			}
			answer(&in.Answers, *out.Call, a)
		default:
			p.Outcome = out
			return p
		}
	}
	t.Fatal("no outcome after 20 rounds")
	return p
}

func answer(a *Answers, c Call, s said) {
	switch c.Op {
	case GetLogin:
		a.Login = &LoginRead{Request: s.login, RequestedAt: s.requestedAt, LoginID: s.loginID, Err: s.err}
	case GetConsent:
		a.Consent = &ConsentRead{Request: s.consent, Err: s.err}
	case AcceptLogin:
		a.Accept = &Done{Call: c, RedirectTo: s.redirectTo, Err: s.err}
	case RejectLogin:
		a.Reject = &Done{Call: c, RedirectTo: s.redirectTo, Err: s.err}
	case AcceptConsent:
		a.ConsentAccept = &Done{Call: c, RedirectTo: s.redirectTo, Err: s.err}
	case RejectConsent:
		a.ConsentReject = &Done{Call: c, RedirectTo: s.redirectTo, Err: s.err}
	case LoginHook:
		a.LoginHook = &LoginHookAnswer{Err: s.hookErr}
		if s.loginHook != nil {
			a.LoginHook = s.loginHook
		}
	case ConsentHook:
		a.ConsentHook = &ConsentHookAnswer{Err: s.hookErr}
	}
}

// copyFlow returns a deep copy of f, as the store would read it.
func copyFlow(t *testing.T, f *Flow) *Flow {
	t.Helper()
	if f == nil {
		return nil
	}
	data, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// rawJSON is the JSON of v, for the claims compared.
func rawJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}
