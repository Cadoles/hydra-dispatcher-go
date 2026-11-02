package flow

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Env is what a transition reads besides the flow and its event.
type Env struct {
	Config *store.Snapshot
	// BaseURL is server.base_url, that of every URL served.
	BaseURL string
	// LoginConsentTTL is hydra.login_consent_ttl, Hydra's
	// ttl.login_consent_request.
	LoginConsentTTL time.Duration
	Keys            Keys
	Now             time.Time
	Draw            Draw
}

// Draw are the random values a request may use, drawn by the orchestrator:
// the generation of a new flow, on 32 bits (Q9), and a new value for the
// CSRF cookie, 32 random bytes in hexadecimal.
type Draw struct {
	Gen0 int64
	CSRF string
}

// appIDs returns the ids of the snapshot's apps.
func (e Env) appIDs() []string {
	ids := make([]string, len(e.Config.Apps))
	for i, a := range e.Config.Apps {
		ids[i] = a.ID
	}
	return ids
}

// Decide runs the transition of in.Event on in.Flow. It is called again and
// again for one request, the orchestrator bringing each time what the
// outcome asked for: the flow (Load), the answer of a call (Call), the flow
// read again (Reread). Calls answered stay in in.Answers for the whole
// request, re-reads after a conflict included: a transition replayed on the
// flow read again finds the answers already obtained and makes no call twice
// (Q12). It never changes in.Flow.
//
// An accept or a reject Hydra made that the transition replayed no longer
// reaches, the flow having changed meanwhile, is a fact all the same: it is
// carried over to the flow read, unless finished (ECR-4, ECR-9).
func Decide(in Input) Outcome {
	r := &run{Input: in}
	var out Outcome
	switch ev := in.Event.(type) {
	case Entry:
		out = r.entry(ev)
	case Choose:
		out = r.choose(ev)
	case Loop:
		out = r.loop(ev)
	case Consent:
		out = r.consent(ev)
	case AppCall:
		out = r.appCall(ev)
	default:
		out = r.page().fail(E1000)
	}
	if out.Load == "" && out.Call == nil && !out.Reread {
		if fact, ok := r.unusedFact(); ok {
			out = fact
		}
	}
	return out.past(in)
}

// Event is what a request asks of a flow.
type Event interface{ event() }

// Input is what a transition decides on.
type Input struct {
	Event Event
	// Loaded tells whether the flow under the event's ref was read; Flow is
	// then nil for an absent one.
	Loaded bool
	Flow   *Flow
	// Reread is set once the flow was read again at the outcome's request.
	Reread  bool
	Answers Answers
	Env     Env
}

// Outcome is what a transition asks for, then what it decided. One of Load,
// Call and Reread is set while it needs more; none once it decided.
type Outcome struct {
	// Load is the ref of the flow to read.
	Load string
	// Call is a call to make, whose answer comes back in Input.Answers.
	Call *Call
	// Reread asks to read the flow again (Hydra 2.1 answered 409).
	Reread bool

	// Write is the flow to write, conditional on the version read (created
	// when absent), its TTL running to HydraExpiresAt; nil writes nothing.
	Write    *Flow
	Response Response
	Reports  []Report
}

func (o Outcome) report(r Report) Outcome {
	o.Reports = append(o.Reports, r)
	return o
}

func (o Outcome) writing(f *Flow) Outcome {
	o.Write = f
	return o
}

// past turns a write that would come at or after HydraExpiresAt into the
// answer to an absent flow (ECR-8): no key is written without a TTL. The
// audit events stand: what they report, a reject Hydra made, happened.
func (o Outcome) past(in Input) Outcome {
	if o.Write == nil || in.Env.Now.UnixMilli() < o.Write.HydraExpiresAt {
		return o
	}
	out := (&run{Input: in}).surface().absent()
	for _, rep := range o.Reports {
		if rep.Audit {
			out = out.report(rep)
		}
	}
	return out
}

// Code is an error code of the pages and of the emulated API.
type Code string

const (
	E1000 Code = "E1000" // generic error, store failing
	E1001 Code = "E1001" // invalid challenge
	E1002 Code = "E1002" // session absent
	E1003 Code = "E1003" // invalid skip
	E1004 Code = "E1004" // Hydra unavailable
	E1005 Code = "E1005" // flow configuration inconsistent
	E1006 Code = "E1006" // webhook failed
	E1007 Code = "E1007" // flow state invalid, write conflict
	E1008 Code = "E1008" // invalid CSRF
)

// ResponseKind is what the handler answers.
type ResponseKind int

const (
	// Redirect: 303 to Response.URL.
	Redirect ResponseKind = iota + 1
	// ChoicePage: 200, the flow choice page.
	ChoicePage
	// ConsentPage: 200, the consent screen.
	ConsentPage
	// ErrorPage: page Response.Code, linked to Response.Link ("" none).
	ErrorPage
	// AppJSON: the emulated API's answer, Response.Status and Response.Body.
	AppJSON
)

// Response is the answer the handler gives.
type Response struct {
	Kind ResponseKind
	URL  string
	Code Code
	// Link is the client's client_uri on page E1002, "" for none.
	Link    string
	Choice  *ChoiceScreen
	Consent *ConsentScreen
	// SetCSRF is the dispatcher_flow_csrf value to set, its Max-Age
	// extended (A4); "" sets nothing.
	SetCSRF string
	Status  int
	Body    any
}

// ChoiceScreen is what the choice page shows.
type ChoiceScreen struct {
	// Flows are the ids offered, in the snapshot's order.
	Flows []string
	// LoginChallenge and CSRF go into the form.
	LoginChallenge string
	CSRF           string
	// Client is the login request's client, as Hydra served it.
	Client json.RawMessage
	// Invalid is set when the flow posted is not one offered (POS-2).
	Invalid bool
}

// ConsentScreen is what the consent screen shows.
type ConsentScreen struct {
	Challenge string
	CSRF      string
	Client    *ory.OAuth2Client
	Scopes    []string
	Audience  []string
	// Claims are those the flow sends in the id_token.
	Claims Object
}

// Report is something to log: an event of the catalogue, also sent to
// Sentry or to the audit log when told. Detail never holds personal data.
type Report struct {
	Event  string
	Detail string
	Sentry bool
	Audit  bool
}

// Op is a call a transition asks for.
type Op int

const (
	GetLogin Op = iota + 1
	AcceptLogin
	RejectLogin
	GetConsent
	AcceptConsent
	RejectConsent
	LoginHook
	ConsentHook
)

// Reason is why a login or a consent is rejected.
type Reason int

const (
	// ReasonExpired: the flow is past ExpiresAt (M9).
	ReasonExpired Reason = iota + 1
	// ReasonUnmet: no flow meets acr_values (CHX-1).
	ReasonUnmet
	// ReasonRestricted: the client's restriction leaves no flow (CHX-2).
	ReasonRestricted
	// ReasonSkipSubject: Hydra's skip subject is not the final one (FIN-3).
	ReasonSkipSubject
	// ReasonNoRef: a consent request without x_dispatcher_ref (CST-5).
	ReasonNoRef
	// ReasonNotOurs: /consent on a flow the dispatcher did not accept, or on
	// another session or subject (A3).
	ReasonNotOurs
	// ReasonUser: the user refused the consent (CST-15).
	ReasonUser
	// ReasonApp: an app rejected its step (M8).
	ReasonApp
	// ReasonSubject: subject_check failed, or a second accept changed the
	// subject (EMU-12, EMU-14).
	ReasonSubject
)

var reasonNames = [...]string{"", "expired", "unmet_acr", "client_restriction", "skip_subject", "no_ref", "not_ours", "user", "app", "subject"}

func (r Reason) String() string { return reasonNames[r] }

// Call is a call to Hydra or to a webhook.
type Call struct {
	Op Op
	// Challenge is L for the login calls, C for the consent ones.
	Challenge string
	Reason    Reason
	// Gen is the flow's generation when the call was decided.
	Gen           int64
	AcceptLogin   ory.AcceptOAuth2LoginRequest
	AcceptConsent ory.AcceptOAuth2ConsentRequest
	Reject        ory.RejectOAuth2Request
}

// Answers are the calls made during the request, with their answers.
type Answers struct {
	Login         *LoginRead
	Consent       *ConsentRead
	Accept        *Done
	Reject        *Done
	ConsentAccept *Done
	ConsentReject *Done
	LoginHook     *LoginHookAnswer
	ConsentHook   *ConsentHookAnswer
}

// LoginRead is the answer to GetLogin, from the source of the login request
// (P3d): RequestedAt is Hydra's requested_at when the challenge is
// decrypted, the time of the first read in fallback.
type LoginRead struct {
	Request     *ory.OAuth2LoginRequest
	RequestedAt time.Time
	Err         error
}

// ConsentRead is the answer to GetConsent.
type ConsentRead struct {
	Request *ory.OAuth2ConsentRequest
	Err     error
}

// Done is the answer to an accept or a reject: Hydra's redirect_to.
type Done struct {
	Call       Call
	RedirectTo string
	Err        error
}

func (d *Done) ok() bool { return d != nil && d.err() == nil }

// errNoRedirect is a 2xx without redirect_to, which internal/hydra already
// refuses: hr and cr are never written empty (FIN-8, CST-19).
var errNoRedirect = errors.New("hydra: no redirect_to")

func (d *Done) err() error {
	if d.Err == nil && d.RedirectTo == "" {
		return errNoRedirect
	}
	return d.Err
}

// LoginHookAnswer is the login accept webhook's answer (P10): the members it
// returned replace those sent, a member nil is unchanged. Context must be an
// object or null (A9).
type LoginHookAnswer struct {
	Subject     *string
	ACR         *string
	AMR         []string
	Context     json.RawMessage
	Remember    *bool
	RememberFor *int64
	Err         error
}

// ConsentHookAnswer is the consent accept webhook's answer (P10): claims
// that replace those sent, nil unchanged.
type ConsentHookAnswer struct {
	IDToken     json.RawMessage
	AccessToken json.RawMessage
	Err         error
}

// failure is the class of a Hydra error (B1, Q11).
type failure int

const (
	none failure = iota
	// unknown: 404, an unknown or tampered challenge.
	unknown
	// gone: 401 request_unauthorized (expired, 2.2) or 410 (handled, 2.1).
	gone
	// conflict: 409, a second accept or a reject once the verifier is
	// followed (2.1).
	conflict
	// refused: another 4xx with Hydra's error document (400, 403).
	refused
	// unavailable: no answer, 5xx, unexpected answer, 2xx without
	// redirect_to (E1004).
	unavailable
)

func classify(err error) failure {
	var re *hydra.RequestError
	switch {
	case err == nil:
		return none
	case !errors.As(err, &re):
		return unavailable
	case re.Status == http.StatusNotFound:
		return unknown
	case re.Status == http.StatusUnauthorized || re.Status == http.StatusGone:
		return gone
	case re.Status == http.StatusConflict:
		return conflict
	}
	return refused
}

// run is one Decide: the input, and which answers the transition used.
type run struct {
	Input
	used map[Op]bool
}

func (r *run) use(op Op) {
	if r.used == nil {
		r.used = map[Op]bool{}
	}
	r.used[op] = true
}

func (r *run) now() int64 { return r.Env.Now.UnixMilli() }

// sameCSRF compares two CSRF values in constant time; an empty one matches
// nothing.
func sameCSRF(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// csrfValue returns the browser's cookie when it has the shape the
// dispatcher gives it (64 hexadecimal characters), a new value otherwise.
func csrfValue(cookie string, draw Draw) string {
	if len(cookie) != 64 || !lowerHex(cookie) {
		return draw.CSRF
	}
	return cookie
}

func lowerHex(s string) bool {
	for _, c := range []byte(s) {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// maxHydraChallenge is flowcodec's bound on a Hydra 2.2 challenge.
const maxHydraChallenge = 64 << 10

// hydraChallenge tells whether c may be a Hydra challenge (Q10): not empty,
// at most 64 KiB, in the base64url alphabet with its = padding, of which a
// 2.1 challenge's hexadecimal is a part.
func hydraChallenge(c string) bool {
	if c == "" || len(c) > maxHydraChallenge {
		return false
	}
	for _, b := range []byte(c) {
		if !('0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || b == '-' || b == '_' || b == '=') {
			return false
		}
	}
	return true
}

// isRef tells whether r has the shape of a flow reference, as Ref gives it.
func isRef(r string) bool { return len(r) == refLen && lowerHex(r) }

// withQuery returns raw with the query parameter set: the login and consent
// URLs of the apps may carry their own.
func withQuery(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// surface answers in the forms of the pages or of the emulated API.
type surface struct {
	api bool
	// get is a read of the emulated API, answered 410 where a PUT gets 200
	// (Q25): no app follows a 410 on a PUT.
	get bool
	// loop is the redirect_to of the flow's ref, on the emulated API.
	loop string
}

func (r *run) page() surface { return surface{} }

// surface is the one of the event.
func (r *run) surface() surface {
	ev, ok := r.Event.(AppCall)
	if !ok {
		return r.page()
	}
	ref, _ := ChallengeRef(ev.Challenge)
	return surface{api: true, get: ev.Op.get(), loop: LoopURL(r.Env.BaseURL, ref)}
}

// redirect sends to a URL: a page redirects (303), the emulated API answers
// it as redirect_to, in 410 to a GET and in 200 to a PUT.
func (s surface) redirect(to string) Outcome {
	if !s.api {
		return Outcome{Response: Response{Kind: Redirect, URL: to}}
	}
	status := http.StatusOK
	if s.get {
		status = http.StatusGone
	}
	return Outcome{Response: Response{Kind: AppJSON, Status: status, Body: ory.OAuth2RedirectTo{RedirectTo: to}}}
}

// fail is an error the user cannot fix by going on: an error page, or on the
// emulated API a 500 server_error that names the code.
func (s surface) fail(code Code) Outcome {
	o := Outcome{Response: Response{Kind: ErrorPage, Code: code}}
	if s.api {
		o = appError(http.StatusInternalServerError, "server_error", string(code))
	}
	switch code {
	case E1000, E1004, E1005, E1006, E1007:
		o = o.report(Report{Event: "flow.error", Detail: string(code), Sentry: true})
	}
	return o
}

// absent answers for a flow absent, or gone past HydraExpiresAt: E1002
// without a link, or the emulated API's unknown challenge (EXP-1, T5).
func (s surface) absent() Outcome {
	if s.api {
		return appError(http.StatusNotFound, missingSession, missingSessionText)
	}
	return s.fail(E1002)
}

// ended answers for the flow f, finished: E1002 linked to the client, or on
// the emulated API the redirect_to of the ref, which leads there (EMU-5).
func (s surface) ended(f *Flow) Outcome {
	if s.api {
		return s.redirect(s.loop)
	}
	o := s.fail(E1002)
	o.Response.Link = f.ClientURI()
	return o
}
