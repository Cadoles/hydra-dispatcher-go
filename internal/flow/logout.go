package flow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The logout (Logout of Table de transitions.md, lot P9). Hydra's accept ends
// nothing: only the browser's visit of its verifier does (HLO-1, HLO-2), so the
// verifier comes last, after the apps, and a note of logout replaces the memory
// of the skip at the start of the chain: if the chain stops, the next login in
// this browser deletes the session (Q45). A new demand passes the app the chain
// stopped at (Q46), found again by a reference drawn from the session.

// Logout is GET or POST /logout (LGO): Hydra's logout challenge, the browser's
// cookies and, on a POST, its answer, the form's token, and whether
// Sec-Fetch-Site or Origin says the form comes from the dispatcher's pages.
type Logout struct {
	Challenge  string
	Cookie     string
	Memory     Memory
	Post       bool
	Accept     bool
	Token      string
	SameOrigin bool
	// Subrequest is what another site's page loads for itself, no visit (LGO-19).
	Subrequest bool
}

// LogoutNext is GET /logout/next (SUI), where the apps send the browser back.
type LogoutNext struct{ Ref string }

func (Logout) event()     {}
func (LogoutNext) event() {}

// LogoutFormat is the version of the stored record (v): another one is
// unreadable, E1000 as a store that fails.
const LogoutFormat = 1

const (
	// logoutTTL is the life of the record at each write, a new demand at most
	// that far from the former passing the app that blocks (Q46).
	logoutTTL = 60 * time.Minute
	// logoutPass is how long after the browser was sent to an app a new demand
	// passes it: under it, a double click, or two quick tabs (Q46).
	logoutPass = 15 * time.Second
)

// LogoutRecord is the chain of a logout, under logout:<ref> (notations of the
// section Logout). No generation: the chain has one state, whose writes follow
// ECR-1, ECR-2, ECR-3, ECR-5 and ECR-7. Times are Unix milliseconds, but
// RequestedAt and ExpiresAt, as Hydra 2.3 serves them.
type LogoutRecord struct {
	V int `json:"v"`
	// U and RT are Hydra's last challenge and the redirect_to of its accept,
	// which holds the verifier: never served to an app (I7).
	U       string `json:"u"`
	RT      string `json:"rt"`
	Subject string `json:"sub"`
	SID     string `json:"sid"`
	RP      bool   `json:"rp,omitempty"`
	// URL is the request_url without id_token_hint nor state (Q48); Client the
	// client without what the apps have no use of (Q51).
	URL         string        `json:"url"`
	Client      *LogoutClient `json:"cl,omitempty"`
	RequestedAt *time.Time    `json:"ra,omitempty"`
	ExpiresAt   *time.Time    `json:"ea,omitempty"`
	// Apps are the ids of the chain, in order, chosen once (Q51); Listed tells
	// they come from the configuration, not from the cookie (LST-2).
	Apps   []string `json:"apps"`
	Listed bool     `json:"lst,omitempty"`
	// Cur is the position; Sent and SentAt the last position the browser was
	// sent to, and when (Q46).
	Cur    int   `json:"cur"`
	Sent   int   `json:"sn"`
	SentAt int64 `json:"st"`
}

// LogoutClient is what the record keeps of a logout request's client, and what
// the apps are served of it (Q51): the rest stopped the chain, the SDK refusing a
// jwks key without alg, and exposed the client's metadata.
type LogoutClient struct {
	ID        string `json:"client_id,omitempty"`
	Name      string `json:"client_name,omitempty"`
	LogoURI   string `json:"logo_uri,omitempty"`
	ClientURI string `json:"client_uri,omitempty"`
	PolicyURI string `json:"policy_uri,omitempty"`
	TosURI    string `json:"tos_uri,omitempty"`
}

func logoutClient(c *ory.OAuth2Client) *LogoutClient {
	if c == nil {
		return nil
	}
	return &LogoutClient{c.GetClientId(), c.GetClientName(), c.GetLogoUri(), c.GetClientUri(), c.GetPolicyUri(), c.GetTosUri()}
}

// LogoutRequest is the logout request served to an app (LEM-5): client null
// without one, as Hydra serves it; never U nor the verifier (I7).
type LogoutRequest struct {
	Challenge   string        `json:"challenge"`
	Subject     string        `json:"subject"`
	SID         string        `json:"sid"`
	RequestURL  string        `json:"request_url"`
	RPInitiated bool          `json:"rp_initiated"`
	RequestedAt *time.Time    `json:"requested_at,omitempty"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	Client      *LogoutClient `json:"client"`
}

// LogoutState is what the logout page says.
type LogoutState int

const (
	// LogoutConfirm: the question, its form (LGO-6, LGO-7).
	LogoutConfirm LogoutState = iota + 1
	// LogoutDeclined: "you stay connected" (LGO-12, LGO-15).
	LogoutDeclined
	// LogoutInProgress: a chain of this session has started, with the link to
	// take it up again (LGO-14).
	LogoutInProgress
	// LogoutAlreadyOut: the verifier was followed (LGO-16).
	LogoutAlreadyOut
)

// LogoutScreen is what the logout page shows.
type LogoutScreen struct {
	State LogoutState
	// Challenge and CSRF go into the form of LogoutConfirm.
	Challenge string
	CSRF      string
	// Client is the logout request's, nil without rp_initiated (HLO-7).
	Client *ory.OAuth2Client
	// OtherSession adds the text of LGO-7: the subject is not shown, the page
	// alone says the demand aims at another session (Q47).
	OtherSession bool
	// Next is the link of LogoutInProgress.
	Next string
}

// encode returns the stored record of r: a same record always gives the same
// bytes, which the orchestrator compares after a write of unknown outcome.
func (r *LogoutRecord) encode() ([]byte, error) { return json.Marshal(r) }

// DecodeLogout reads a stored record.
func DecodeLogout(data []byte) (*LogoutRecord, error) {
	var r LogoutRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if r.V != LogoutFormat {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, r.V)
	}
	return &r, nil
}

// LogoutKey returns the state store key of a chain.
func LogoutKey(ref string) string { return "logout:" + ref }

// NextURL is where the emulated API sends the browser back (next).
func NextURL(base, ref string) string {
	return strings.TrimRight(base, "/") + "/logout/next?ref=" + ref
}

// TTL is the life of a write of r at now: 60 minutes, at most up to
// expires_at - 60 s when Hydra gave one, its verifier being refused past it
// (Q46, Q52). Zero or less: nothing is written (I4).
func (r *LogoutRecord) TTL(now time.Time) time.Duration {
	ttl := logoutTTL
	if r.ExpiresAt != nil {
		ttl = min(ttl, r.ExpiresAt.Add(-hydraMargin).Sub(now))
	}
	return ttl
}

func (r *LogoutRecord) clone() *LogoutRecord {
	c := *r
	return &c
}

// LogoutRef is the reference of a session's chain (Q46): the HMAC by the active
// key keeps it out of reach of who knows the sid, as the apps do. Its message
// cannot be a challenge's (<ref>|…, 20 hexadecimal characters first) nor a
// marker's (["dispatcher-…). A rotation only starts the next demand over, under
// another ref; the chain in progress goes on, its challenges verified by the
// former keys.
func (k Keys) LogoutRef(sid string) string {
	m := hmac.New(sha256.New, k[0])
	m.Write([]byte("logout|" + sid))
	return hex.EncodeToString(m.Sum(nil))[:refLen]
}

// LogoutChallenge is the challenge of the app at position i: signed as a step's,
// in the shape of an UUID, as Hydra's. The three apps copy it without reading it.
func (k Keys) LogoutChallenge(ref string, i int, app string) string {
	c := ref + signature(k[0], ref, int64(i), app, KindLogout)
	return c[:8] + "-" + c[8:12] + "-" + c[12:16] + "-" + c[16:20] + "-" + c[20:]
}

// logoutChallengeParts returns the reference and the signature of a challenge in
// the shape 8-4-4-4-12, or false for anything else (LEM-1).
func logoutChallengeParts(c string) (ref, sig string, ok bool) {
	if len(c) != 36 || c[8] != '-' || c[13] != '-' || c[18] != '-' || c[23] != '-' {
		return "", "", false
	}
	plain := c[:8] + c[9:13] + c[14:18] + c[19:23] + c[24:]
	for _, b := range []byte(plain) {
		if !('0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F') {
			return "", "", false
		}
	}
	return plain[:refLen], plain[refLen:], true
}

// logoutPosition finds the position whose signature is sig, the active key first
// (Rotation des clés).
func (k Keys) logoutPosition(ref, sig string, apps []string) (int, bool) {
	for _, key := range k {
		for i, app := range apps {
			if hmac.Equal([]byte(signature(key, ref, int64(i), app, KindLogout)), []byte(sig)) {
				return i, true
			}
		}
	}
	return 0, false
}

// logoutRequestURL is the request_url the record keeps (Q48): without
// id_token_hint, the user's whole id_token, which would pass receive_claims, nor
// state, the client's. One it cannot read goes without its query: the hint would
// otherwise pass, which withQuery's raw value on an error would let through.
func logoutRequestURL(raw string) string {
	path, query, _ := strings.Cut(raw, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		return path
	}
	q.Del("id_token_hint")
	q.Del("state")
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// logoutStarted reports a logout request accepted (Q58), of a chain new or not.
func logoutStarted(rp bool, apps int, again bool) Report {
	return Report{Event: "logout.started", Audit: true, RP: &rp, Apps: apps, Again: again}
}

// verifierSent reports the browser receiving the verifier (Q58): the difference
// with logout.started gives the chains stopped.
func verifierSent(rp bool) Report {
	return Report{Event: "logout.verifier_sent", RP: &rp}
}

func propagated(app, result string) Report {
	return Report{Event: "logout.propagated", App: app, Result: result}
}

// logout is GET or POST /logout (LGO): on a POST, the origin then the token,
// before any read; then the logout request, read first, on the admin API: U is
// never encrypted, in any version.
func (r *run) logout(ev Logout) Outcome {
	s := r.page()
	switch {
	case ev.Post && !ev.SameOrigin:
		return s.fail(E1008) // LGO-9
	case ev.Post && !sameCSRF(ev.Token, ev.Cookie):
		return s.fail(E1008) // LGO-10
	case !hydraChallenge(ev.Challenge):
		return s.fail(E1001) // LGO-1
	}
	read := r.Answers.Logout
	if read == nil {
		return Outcome{Call: &Call{Op: GetLogout, Challenge: ev.Challenge}}
	}
	decline := ev.Post && !ev.Accept
	switch classify(read.Err) {
	case none:
	case unknown:
		if decline {
			return logoutPage(&LogoutScreen{State: LogoutDeclined}) // LGO-15: nothing changed
		}
		return s.fail(E1001).report(forged()) // LGO-2
	case gone:
		var re *hydra.RequestError
		if decline && errors.As(read.Err, &re) && re.Status == http.StatusGone {
			return logoutPage(&LogoutScreen{State: LogoutAlreadyOut}) // LGO-16
		}
		return expiredIf(s.absent(), read.Err) // LGO-3
	case unavailable:
		return s.unavailable(read.Err) // LGO-4
	default:
		return s.fail(E1007) // LGO-4
	}
	req := read.Request
	if decline {
		return r.logoutDecline(ev, req) // LGO-12, LGO-14
	}
	if ea := req.ExpiresAt; ea != nil && r.Answers.LogoutAccept == nil && ea.Sub(r.Env.Now) < hydraMargin {
		// LGO-5 (Q52): the accept would answer 200, and the verifier be refused,
		// the session whole: the clocks are not the same. Only before the accept:
		// once made, a write decided again past that time is DEP-7's (ECR-8).
		return s.absent().report(expiredChallenge())
	}
	if ev.Post {
		return r.logoutStart(ev, req) // LGO-11: what the form says of the session is not believed
	}
	c := ev.Memory.Content
	// Another person's session: the cookie names another session and another
	// subject. The same subject in another session is this browser's user: a
	// partner's prompt=login opened a new session, and a client keeps the
	// id_token of the former one (HLO-14); the client may sign its own user
	// out without a question (Q163).
	other := c != nil && !c.Lo && c.SID != req.GetSid() && c.Sub != req.GetSubject()
	if !req.GetRpInitiated() || other || ev.Subrequest {
		// LGO-6, LGO-7 (Q47): nothing cleared. A cookie of another person's
		// session asks too, a client's id_token sufficing to Hydra to make a
		// browser lose its cookie (HLO-8); a note stays after a logout finished,
		// and says nothing. So does a subrequest of another site, which that
		// cookie does not reach: no one answers the question there, and nothing
		// leaves (LGO-19, Q65).
		csrf := csrfValue(ev.Cookie, r.Env.Draw)
		out := logoutPage(&LogoutScreen{State: LogoutConfirm, Challenge: ev.Challenge, CSRF: csrf, Client: req.Client, OtherSession: req.GetRpInitiated() && other})
		out.Response.SetCSRF = csrf
		return out
	}
	return r.logoutStart(ev, req) // LGO-8
}

func logoutPage(screen *LogoutScreen) Outcome {
	return Outcome{Response: Response{Kind: LogoutPage, Logout: screen}}
}

// logoutFailed is the page of an error of Hydra at an accept or a reject (LGO-13):
// no note, no record, and a reload plays it again.
func (r *run) logoutFailed(err error) Outcome {
	s := r.page()
	switch classify(err) {
	case unknown:
		return s.fail(E1001)
	case gone:
		return s.absent()
	case unavailable:
		return s.unavailable(err)
	}
	return s.fail(E1007)
}

// logoutDecline is the other buttons of the confirmation (Q50): the read tells
// the states apart, a reject answering 204 in each. Without a chain of this
// session, the reject and "you stay connected" (LGO-12): the logout request stays
// otherwise valid, for a former page to confirm. With one, "a logout has started",
// and no reject of its U, whose verifier would be refused (LGO-14, HLO-5).
func (r *run) logoutDecline(ev Logout, req *ory.OAuth2LogoutRequest) Outcome {
	ref := r.Env.Keys.LogoutRef(req.GetSid())
	if !r.Loaded {
		return Outcome{LoadLogout: ref}
	}
	rec := r.Logout
	screen := &LogoutScreen{State: LogoutDeclined, Client: req.Client}
	if rec != nil {
		screen.State, screen.Next = LogoutInProgress, NextURL(r.Env.BaseURL, ref)
		if rec.U == ev.Challenge {
			return logoutPage(screen)
		}
	}
	d := r.Answers.LogoutReject
	if d == nil {
		return Outcome{Call: &Call{Op: RejectLogout, Challenge: ev.Challenge}}
	}
	if d.Err != nil {
		return r.logoutFailed(d.Err) // LGO-13
	}
	return logoutPage(screen)
}

// logoutNote is what replaces the cookie at the start of the chain, whatever its
// sid (WRT-4): v, the sid and sub of the logout request, lo, the apps of a cookie
// of that sid, and no claim. It keeps the end of that cookie, else it lives as a
// login remembered now.
func (r *run) logoutNote(req *ory.OAuth2LogoutRequest, m Memory) *Remembered {
	now := r.Env.Now.Unix()
	note := &Remembered{V: RememberedFormat, SID: req.GetSid(), Sub: req.GetSubject(), Lo: true, IAT: now}
	if c := m.Content; c != nil && c.SID == note.SID {
		note.AP = c.AP
		if c.Exp == 0 || now < c.Exp {
			note.Exp = c.Exp
			return note
		}
	}
	if rf := int64(r.Env.Config.Settings.LoginRememberFor / time.Second); rf > 0 {
		note.Exp = now + rf
	}
	return note
}

// logoutApps are the apps to log out, computed at the start of the chain, once
// (LST, Q51), those with a logout_url alone. A cookie, a note included, of this
// session and subject designates them: those it saw, in order, still in the
// snapshot, whatever became of the flows (LST-1, Q56). Otherwise all of them, or
// none, as logout.propagate_without_record says (LST-2, LST-3); listed tells the
// former, which hides subject and sid from an app with a receive_claims list.
func (r *run) logoutApps(req *ory.OAuth2LogoutRequest, m Memory) (apps []string, listed bool) {
	cfg := r.Env.Config
	if c := m.Content; c != nil && c.SID == req.GetSid() && c.Sub == req.GetSubject() && len(c.AP) > 0 {
		for _, id := range c.AP {
			if app, ok := cfg.App(id); ok && app.LogoutURL != "" {
				apps = append(apps, id)
			}
		}
		return apps, false
	}
	if r.Env.PropagateWithoutRecord == "none" {
		return nil, false
	}
	for _, app := range cfg.Apps {
		if app.LogoutURL != "" {
			apps = append(apps, app.ID)
		}
	}
	return apps, true
}

// logoutStart is the accept, then the start of the chain (LGO-8, LGO-11, DEP).
// The note replaces the cookie in this answer, not after the last app: if the
// chain stops, the skip of this session is no longer honoured in this browser,
// and the next login there deletes the session (SKP-12, Q45).
func (r *run) logoutStart(ev Logout, req *ory.OAuth2LogoutRequest) Outcome {
	s := r.page()
	d := r.Answers.LogoutAccept
	if d == nil {
		return Outcome{Call: &Call{Op: AcceptLogout, Challenge: ev.Challenge}}
	}
	if err := d.err(); err != nil {
		return r.logoutFailed(err) // LGO-13
	}
	note := r.logoutNote(req, ev.Memory)
	rp := req.GetRpInitiated()
	apps, listed := r.logoutApps(req, ev.Memory)
	if len(apps) == 0 {
		// DEP-1.
		return noted(s.redirect(d.RedirectTo), note).report(logoutStarted(rp, 0, false)).report(verifierSent(rp))
	}
	// DEP-6 (Q53): the end of the session before the propagation: E1000 would
	// leave it alive, to protect what is best effort. Apps not told for this
	// logout, and no longer, Hydra giving no logout request for this session.
	failed := func(apps []string, cur int, again bool) *Outcome {
		out := noted(s.redirect(d.RedirectTo), note).report(logoutStarted(rp, len(apps), again))
		for _, id := range apps[cur:] {
			out = out.report(propagated(id, "error"))
		}
		out = out.report(verifierSent(rp))
		return &out
	}
	ref := r.Env.Keys.LogoutRef(req.GetSid())
	if !r.Loaded {
		return Outcome{LoadLogout: ref, Failed: failed(apps, 0, false)}
	}
	now := r.Env.Now
	rec := r.Logout
	switch {
	case rec == nil:
		// DEP-2.
		g := &LogoutRecord{
			V: LogoutFormat, Apps: apps, Listed: listed, Subject: req.GetSubject(), SID: req.GetSid(),
			Sent: 0, SentAt: now.UnixMilli(),
		}
		g.demand(ev.Challenge, d.RedirectTo, req)
		if g.TTL(now) <= 0 {
			return noted(s.absent(), note) // DEP-7
		}
		app, _ := r.Env.Config.App(apps[0]) // chosen from this snapshot
		out := noted(s.redirect(withQuery(app.LogoutURL, "logout_challenge", r.Env.Keys.LogoutChallenge(ref, 0, app.ID))), note).
			report(logoutStarted(rp, len(apps), false))
		out.WriteLogout, out.Failed = g, failed(apps, 0, false)
		return out
	case rec.U == ev.Challenge:
		// DEP-3: a double submission, or a reload.
		out := r.logoutStep(ref, rec.clone(), false)
		out.Response.Remember = note
		if out.Failed != nil {
			out.Failed.Response.Remember = note // SUI-3: its answer stands, with the note
		} else if out.WriteLogout != nil {
			out.Failed = failed(rec.Apps, rec.Cur, false) // SUI-4
		}
		return out
	}
	// DEP-4 (Q46): a new demand for this session. It passes apps[cur] only if the
	// browser was sent there 15 s ago at least, which did not answer: not a double
	// click, nor two quick tabs, nor the next app not seen yet, nor a chain over.
	g := rec.clone()
	g.demand(ev.Challenge, d.RedirectTo, req)
	if g.TTL(now) <= 0 {
		return noted(s.absent(), note) // DEP-7
	}
	var passed []Report
	if g.Cur < len(g.Apps) && g.Sent == g.Cur && now.UnixMilli()-g.SentAt >= logoutPass.Milliseconds() {
		passed = append(passed, propagated(g.Apps[g.Cur], "skipped"))
		g.Cur++
	}
	out := r.logoutStep(ref, g, true)
	out.Response.Remember = note
	out.Failed = failed(rec.Apps, rec.Cur, true)
	out.Reports = append(append([]Report{logoutStarted(rp, len(g.Apps), true)}, passed...), out.Reports...)
	return out
}

// noted adds the note to an answer of the start of the chain (WRT-4).
func noted(o Outcome, note *Remembered) Outcome {
	o.Response.Remember = note
	return o
}

// demand takes over what a logout request says, on a record new or not (DEP-2,
// DEP-4).
func (r *LogoutRecord) demand(u, rt string, req *ory.OAuth2LogoutRequest) {
	r.U, r.RT, r.RP = u, rt, req.GetRpInitiated()
	r.URL, r.Client = logoutRequestURL(req.GetRequestUrl()), logoutClient(req.Client)
	r.RequestedAt, r.ExpiresAt = req.RequestedAt, req.ExpiresAt
}

// logoutNext is GET /logout/next (SUI). No check of a cookie: a logout with
// rp_initiated leaves without a form, sometimes without a CSRF cookie, and the ref
// cannot be guessed (see the section Logout).
func (r *run) logoutNext(ev LogoutNext) Outcome {
	s := r.page()
	if !isRef(ev.Ref) {
		return s.fail(E1001) // SUI-1
	}
	if !r.Loaded {
		return Outcome{LoadLogout: ev.Ref}
	}
	if r.Logout == nil {
		return s.absent() // SUI-2: Hydra's redirect_to is lost, the client starts over
	}
	return r.logoutStep(ev.Ref, r.Logout.clone(), false)
}

// logoutStep answers for the position of g, a copy of the record, changed tells
// that it must be written: to the app (SUI-3), past those gone from the snapshot
// or without a logout_url since the start (SUI-4), or to the verifier (SUI-5). One
// write: cur only moves by an app's call, a new demand, or an app gone, and a
// reload or a step back gets the same step.
func (r *run) logoutStep(ref string, g *LogoutRecord, changed bool) Outcome {
	s, now := r.page(), r.Env.Now
	var reports []Report
	gone := false
	var app store.App
	for g.Cur < len(g.Apps) {
		found, ok := r.Env.Config.App(g.Apps[g.Cur])
		if ok && found.LogoutURL != "" {
			app = found
			break
		}
		reports = append(reports, propagated(g.Apps[g.Cur], "skipped"))
		g.Cur++
		gone = true
	}
	if (changed || gone) && g.TTL(now) <= 0 {
		return s.absent() // SUI-2; DEP-4 answered DEP-7 before
	}
	var out Outcome
	if g.Cur >= len(g.Apps) {
		out = s.redirect(g.RT).report(verifierSent(g.RP)) // SUI-5
	} else {
		out = s.redirect(withQuery(app.LogoutURL, "logout_challenge", r.Env.Keys.LogoutChallenge(ref, g.Cur, app.ID)))
	}
	out.Reports = append(reports, out.Reports...)
	first := g.Cur < len(g.Apps) && g.Sent != g.Cur
	if first {
		g.Sent, g.SentAt = g.Cur, now.UnixMilli()
	}
	switch {
	case changed || gone:
		out.WriteLogout = g
	case first && g.TTL(now) > 0:
		// SUI-3: this write only guards against passing an app wrongly: when it
		// fails, the answer stands, second conflict included.
		answer := out
		out.WriteLogout, out.Failed = g, &answer
	}
	return out
}

// appLogout is a call of the emulated API on a logout's challenge (LEM): no line
// calls Hydra, and the body of a PUT is not read, as at Hydra: hydra-passwordless
// sends null, the SDKs nothing.
func (r *run) appLogout(ev AppCall) Outcome {
	ref, sig, ok := logoutChallengeParts(ev.Challenge)
	if !ok {
		return appError(http.StatusNotFound, "invalid_request", "request_failed") // LEM-1
	}
	if !r.Loaded {
		return Outcome{LoadLogout: ref}
	}
	s := surface{api: true, get: ev.Op.get(), loop: NextURL(r.Env.BaseURL, ref)}
	rec := r.Logout
	if rec == nil {
		return s.absent() // LEM-2
	}
	i, ok := r.Env.Keys.logoutPosition(ref, sig, rec.Apps)
	if !ok || i > rec.Cur {
		return s.absent().report(forged()) // LEM-3: a future position cannot have been served
	}
	id := rec.Apps[i]
	app, known := r.Env.Config.App(id)
	if !known || ev.Caller == nil || !ev.Caller(app) {
		// LEM-4 (Q17, Q21): gone from the snapshot, the app can no longer be
		// identified, as EMU-28; DEP-4 or SUI-4 take the chain up.
		return appError(http.StatusForbidden, forbidden, forbiddenText).report(Report{Event: "security.ip_rejected", Detail: "emulated: app outside its sources"})
	}
	if ev.Op == AppGetLogout {
		if i < rec.Cur {
			return s.redirect(s.loop) // LEM-6: the step has passed
		}
		return Outcome{Response: Response{Kind: AppJSON, Status: http.StatusOK, Body: rec.requestFor(r.Env.Keys, ref, i, app)}} // LEM-5
	}
	if i < rec.Cur {
		return s.redirect(s.loop) // LEM-8, LEM-10: the first call stands (T4)
	}
	// LEM-7, LEM-9 (Q49): 200 and redirect_to on a reject too, where Hydra gives 204
	// without a body: the app could not send the browser back.
	result := "accepted"
	if ev.Op == AppRejectLogout {
		result = "rejected"
	}
	g := rec.clone()
	g.Cur++
	if g.TTL(r.Env.Now) <= 0 {
		return s.absent() // LEM-11
	}
	out := s.redirect(s.loop).report(propagated(id, result))
	out.WriteLogout = g
	return out
}

// requestFor is the logout request of position i served to app (LEM-5): subject
// and sid empty, in LST-2, for an app with a receive_claims list: the subject
// often is the email, which the list refuses (Q51).
func (r *LogoutRecord) requestFor(k Keys, ref string, i int, app store.App) LogoutRequest {
	out := LogoutRequest{
		Challenge:   k.LogoutChallenge(ref, i, app.ID),
		Subject:     r.Subject,
		SID:         r.SID,
		RequestURL:  r.URL,
		RPInitiated: r.RP,
		RequestedAt: r.RequestedAt,
		ExpiresAt:   r.ExpiresAt,
		Client:      r.Client,
	}
	if r.Listed && app.ReceiveClaims != nil {
		out.Subject, out.SID = "", ""
	}
	return out
}
