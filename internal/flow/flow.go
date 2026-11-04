// Package flow is the dispatcher's engine: one flow per Hydra login request,
// kept in the state store under flow:<ref>. Its transitions are those of
// Table de transitions.md (lot P3 of the phase 1 plan), whose references the
// tests cite. They see neither HTTP nor the store: each receives the flow, an
// event, the configuration, the time and the random values it may draw, and
// returns the flow changed and what to do (redirect, call Hydra, answer the
// app, show a page).
package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"
)

// Format is the version of the stored document (v). A flow of another
// version is unreadable: E1000, as a store that fails.
const Format = 1

// Object is a JSON object whose values stay as written: decoded through
// interface{}, an integer beyond 2^53 would reach Hydra and the apps
// changed. A value null is the JSON null, which the claim merges tell apart
// from an absent member.
type Object map[string]json.RawMessage

// Flow is the state of one authentication, from the login request Hydra sends
// to the dispatcher's root until its consent is accepted or rejected. Times
// are Unix milliseconds.
type Flow struct {
	V int `json:"v"`
	// LoginChallenge is Hydra's challenge, L: only ever sent back to Hydra,
	// never to an app.
	LoginChallenge string `json:"l,omitempty"`
	HydraSessionID string `json:"sid,omitempty"`
	// Hydra is the login request as read once, on GET /: never read again
	// for this flow.
	Hydra LoginSnapshot `json:"h"`
	// FlowID is the flow chosen, "" while the user has not.
	FlowID string `json:"f,omitempty"`
	// Imposed flows (preferred by acr_values, or the only one the client's
	// restriction leaves) serve no x_dispatcher_restart_url.
	Imposed bool `json:"imp,omitempty"`
	// ACR is the acr the chosen flow declares, copied with its steps; ""
	// sends min(2, steps accepted).
	ACR string `json:"acr,omitempty"`
	// Gen0 is the generation drawn at random when the flow was created; Gen
	// only grows from it, at every return to the choice and every
	// replacement: the step challenges of a former generation are stale.
	Gen0 int64 `json:"g0"`
	Gen  int64 `json:"g"`
	// CSRF is the copy of the browser's dispatcher_flow_csrf cookie.
	CSRF string `json:"c"`
	// Subject is the first step's, the one later steps are checked against.
	Subject string `json:"sub,omitempty"`
	// Current is the position of the current step, from 1; 0 before the
	// choice.
	Current int `json:"cur,omitempty"`
	// Steps are those of the flow chosen, copied at the choice: the flow
	// follows its copy when the configuration changes.
	Steps []Step `json:"steps"`
	// HydraRedirect is the redirect_to of the final login accept: set, the
	// flow is accepted on Hydra by the dispatcher.
	HydraRedirect string     `json:"hr,omitempty"`
	Sent          *SentLogin `json:"sent,omitempty"`
	// ConsentChallenge is Hydra's consent challenge, kept when /consent
	// shows its screen: from then on, the flow resumes there rather than on
	// HydraRedirect, whose verifier Hydra followed.
	ConsentChallenge string `json:"cc,omitempty"`
	// ConsentRedirect and ConsentAt are the redirect_to and the time of the
	// consent's accept or reject, replayed for 10 s to a double submission.
	ConsentRedirect string `json:"cr,omitempty"`
	ConsentAt       int64  `json:"ct,omitempty"`
	// Done flows are finished: kept reduced until HydraExpiresAt, so that
	// any return on them gets E1002.
	Done bool `json:"done,omitempty"`
	// Skipped flows were finished by a skip honoured (SKP-1, Q35):
	// ConsentRedirect is then the redirect_to of the login accept, replayed
	// for 10 s with or without the cookie (ENT-21).
	Skipped bool `json:"sk,omitempty"`
	// ExpiresAt ends the step challenges (inclusive); HydraExpiresAt is the
	// end of L at Hydra, and of the key.
	ExpiresAt      int64 `json:"exp"`
	HydraExpiresAt int64 `json:"hx"`
}

// LoginSnapshot is what the apps are served of Hydra's login request, and
// what the final accept checks.
type LoginSnapshot struct {
	// Client is kept as Hydra served it (see hydra.DecodeClient).
	Client      json.RawMessage `json:"client"`
	OIDCContext json.RawMessage `json:"oidc,omitempty"`
	Scope       []string        `json:"scope"`
	Audience    []string        `json:"aud"`
	RequestURL  string          `json:"url,omitempty"`
	// Skip and Subject are Hydra's: the dispatcher ignores the skip, and then
	// requires Hydra's subject at the final accept.
	Skip    bool   `json:"skip,omitempty"`
	Subject string `json:"sub,omitempty"`
	// LoginID is Hydra's id of L, which its consent request names as
	// login_challenge: /consent requires it there (CST-23, Q34). "" when
	// nothing gave it (fallback on Hydra 2.2), and in the flows written
	// before P7. Never served to an app: on Hydra 2.1, it is L (I7).
	LoginID string `json:"hid,omitempty"`
}

// SentLogin is the final login accept sent to Hydra, after the webhook:
// /consent checks its subject against the consent request's, and writes the
// remember cookie from it (Q39).
type SentLogin struct {
	Subject string   `json:"sub"`
	ACR     string   `json:"acr"`
	AMR     []string `json:"amr"`
	// Context is the context sent, without x_dispatcher_* members; Remember
	// and RememberFor the remember and remember_for sent: the cookie is
	// only written when Remember is, for RememberFor seconds (WRT-1, WRT-3).
	Context     Object `json:"ctx,omitempty"`
	Remember    bool   `json:"rem,omitempty"`
	RememberFor int64  `json:"rf,omitempty"`
}

// Step is the state of one app of the flow.
type Step struct {
	App string `json:"app"`
	// Check is the step's subject_check rule, copied with the step; "" is
	// none.
	Check string `json:"chk,omitempty"`
	// Subject is the one of the step's login accept, which a second accept
	// must repeat.
	Subject   string   `json:"sub,omitempty"`
	LoginOK   bool     `json:"lok"`
	ConsentOK bool     `json:"cok"`
	AMR       []string `json:"amr,omitempty"`
	// LoginContext is served in the step's consent request, as Hydra does;
	// ConsentContext goes into the context of the final accept.
	LoginContext   Object `json:"lctx,omitempty"`
	ConsentContext Object `json:"cctx,omitempty"`
	IDToken        Object `json:"idt,omitempty"`
	AccessToken    Object `json:"act,omitempty"`
	Remember       *bool  `json:"rem,omitempty"`
	RememberFor    *int64 `json:"remf,omitempty"`
}

// State is derived from the flow read: it is not stored.
type State int

const (
	// Absent: no flow under the ref, never created, expired past
	// HydraExpiresAt, or lost with an in-memory store.
	Absent State = iota
	// Choice: no flow chosen yet.
	Choice
	// StepLogin, StepConsent and StepDone are the current step without an
	// accept (k·0), with its login accepted (k·L), and with both (k·LC).
	StepLogin
	StepConsent
	StepDone
	// Accepted: accepted on Hydra by the dispatcher (HydraRedirect set),
	// past ExpiresAt too: only its consent is left, which /consent rejects
	// once ExpiresAt is past (CST-22, Q31).
	Accepted
	// Finished: done, reduced, kept until HydraExpiresAt.
	Finished
	// Expired: past ExpiresAt, neither done nor accepted on Hydra; the key
	// lives until HydraExpiresAt.
	Expired
)

var stateNames = [...]string{"absent", "choice", "step_login", "step_consent", "step_done", "accepted", "finished", "expired"}

func (s State) String() string {
	if int(s) < len(stateNames) {
		return stateNames[s]
	}
	return fmt.Sprintf("state(%d)", int(s))
}

// StateAt returns the state of f at now; f nil is absent. A flow read at or
// past HydraExpiresAt is absent, as the store would have it a moment later.
func (f *Flow) StateAt(now time.Time) State {
	switch t := now.UnixMilli(); {
	case f == nil || t >= f.HydraExpiresAt:
		return Absent
	case f.Done:
		return Finished
	case f.HydraRedirect != "":
		return Accepted
	case t > f.ExpiresAt:
		return Expired
	case f.FlowID == "" || f.Current < 1 || f.Current > len(f.Steps):
		return Choice
	}
	switch step := f.Steps[f.Current-1]; {
	case !step.LoginOK:
		return StepLogin
	case !step.ConsentOK:
		return StepConsent
	default:
		return StepDone
	}
}

// Ref returns the flow reference of a login challenge: hex(SHA256(L))[0:20].
func Ref(loginChallenge string) string {
	sum := sha256.Sum256([]byte(loginChallenge))
	return hex.EncodeToString(sum[:])[:refLen]
}

// Key returns the state store key of a flow. A finished flow no longer holds
// L: its reference is the key's, never recomputed from the flow.
func Key(ref string) string { return "flow:" + ref }

// LoopURL is where the step accepts send the browser back: the redirect_to
// the apps receive, never Hydra's challenge.
func LoopURL(base, ref string) string {
	return strings.TrimRight(base, "/") + "/oauth2/auth?ref=" + ref
}

// RestartURL is the choice page of the flow, x_dispatcher_restart_url.
func RestartURL(base, ref string) string {
	return strings.TrimRight(base, "/") + "/?ref=" + ref
}

// ResumeURL is where an accepted flow sends the browser back (Q1, Q14): the
// redirect_to of the final login accept until /consent showed its screen,
// /consent on that consent challenge from then on, Hydra having followed the
// verifier of the former.
func (f *Flow) ResumeURL(base string) string {
	if f.ConsentChallenge != "" {
		return strings.TrimRight(base, "/") + "/consent?consent_challenge=" + url.QueryEscape(f.ConsentChallenge)
	}
	return f.HydraRedirect
}

// ClientURI is the client_uri of the login request's client, for the link
// of page E1002; "" without one.
func (f *Flow) ClientURI() string {
	var c struct {
		URI string `json:"client_uri"`
	}
	if json.Unmarshal(f.Hydra.Client, &c) != nil {
		return ""
	}
	return c.URI
}

// Reduce returns what a finished flow keeps (T1): what its answers need, to
// recognise its challenges (Gen0, Gen), answer a double submission of the
// consent (CSRF, ConsentRedirect, ConsentAt) and link page E1002 to the
// client (its client_id and client_uri). L, the steps and the claims go.
func (f *Flow) Reduce() *Flow {
	client, _ := json.Marshal(struct {
		ID  string `json:"client_id,omitempty"`
		URI string `json:"client_uri,omitempty"`
	}{f.clientID(), f.ClientURI()})
	return &Flow{
		V:               Format,
		Hydra:           LoginSnapshot{Client: client, Scope: []string{}, Audience: []string{}},
		FlowID:          f.FlowID,
		Gen0:            f.Gen0,
		Gen:             f.Gen,
		CSRF:            f.CSRF,
		ConsentRedirect: f.ConsentRedirect,
		ConsentAt:       f.ConsentAt,
		Done:            true,
		ExpiresAt:       f.ExpiresAt,
		HydraExpiresAt:  f.HydraExpiresAt,
	}
}

func (f *Flow) clientID() string {
	var c struct {
		ID string `json:"client_id"`
	}
	if json.Unmarshal(f.Hydra.Client, &c) != nil {
		return ""
	}
	return c.ID
}

// Encode returns the stored document of f. encoding/json keeps the order of
// the fields and sorts the keys of maps: a same flow always gives the same
// bytes, which the orchestrator compares after a write of unknown outcome.
func Encode(f *Flow) ([]byte, error) {
	return json.Marshal(f)
}

// ErrFormat is the answer for a stored document this version cannot read.
var ErrFormat = errors.New("flow: unreadable document")

// Decode reads a stored document.
func Decode(data []byte) (*Flow, error) {
	var f Flow
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if f.V != Format {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, f.V)
	}
	return &f, nil
}

// SnapshotOf returns what a flow keeps of Hydra's login request, and its
// session_id. Requested scopes and audiences are never null: Hydra serves
// [] (the fallback reads null as [] too, P3).
func SnapshotOf(r *ory.OAuth2LoginRequest) (LoginSnapshot, string, error) {
	client, err := json.Marshal(r.Client)
	if err != nil {
		return LoginSnapshot{}, "", fmt.Errorf("login request client: %w", err)
	}
	s := LoginSnapshot{
		Client:     client,
		Scope:      nonNil(r.RequestedScope),
		Audience:   nonNil(r.RequestedAccessTokenAudience),
		RequestURL: r.RequestUrl,
		Skip:       r.Skip,
		Subject:    r.Subject,
	}
	if r.OidcContext != nil {
		if s.OIDCContext, err = json.Marshal(r.OidcContext); err != nil {
			return LoginSnapshot{}, "", fmt.Errorf("login request oidc_context: %w", err)
		}
	}
	return s, r.GetSessionId(), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
