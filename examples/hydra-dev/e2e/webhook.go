package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/webhook"
)

// errNoWebhook is the answer of a scenario of the webhooks without a receiver.
var errNoWebhook = errors.New("needs -webhook, and the stack started with HYDRA_DEV_WEBHOOK at the same URL")

// hookReceiver is a webhook as the doc asks for one, the two kinds at one URL: it
// refuses a signature that does not verify, or a timestamp over 5 minutes old, which the
// browser then sees as page E1006. It answers what the scenario says, {} by default: any
// scenario can run through it.
type hookReceiver struct {
	key     []byte
	mu      sync.Mutex
	login   string
	consent string
	// logins and consents are the payloads received; refused the signatures.
	logins   []map[string]any
	consents []map[string]any
	refused  int
}

func (r *hookReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	stamp := req.Header.Get(webhook.HeaderTimestamp)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.verifies(stamp, req.Header.Get(webhook.HeaderSignature), body) {
		r.refused++
		http.Error(w, "refused", http.StatusUnauthorized)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	answer := r.login
	if _, ok := payload["grant_scope"]; ok {
		answer = r.consent
		r.consents = append(r.consents, payload)
	} else {
		r.logins = append(r.logins, payload)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, answer)
}

// verifies is what a receiver of production checks (Durcissements, webhooks signés).
func (r *hookReceiver) verifies(stamp, signature string, body []byte) bool {
	at, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || time.Since(time.Unix(at, 0)).Abs() > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(stamp + "."))
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(signature))
}

// answers sets what the webhooks answer from now on, and forgets the payloads.
func (r *hookReceiver) answers(login, consent string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.login, r.consent, r.logins, r.consents = login, consent, nil, nil
}

// last returns the last payload of each kind, nil for none.
func (r *hookReceiver) last() (login, consent map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.logins); n > 0 {
		login = r.logins[n-1]
	}
	if n := len(r.consents); n > 0 {
		consent = r.consents[n-1]
	}
	return login, consent
}

// listenWebhooks serves the webhooks where reach says, http://10.0.6.1:<port> on
// hydra-dev, the address of the host on its network.
func (d *driver) listenWebhooks(reach string, key []byte) (func(), error) {
	u, err := url.Parse(reach)
	if err != nil || u.Port() == "" {
		return nil, fmt.Errorf("-webhook: %q is not http://host:port", reach)
	}
	ln, err := net.Listen("tcp", ":"+u.Port())
	if err != nil {
		return nil, err
	}
	d.hooks = &hookReceiver{key: key, login: `{}`, consent: `{}`}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: d.hooks}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Shutdown(context.Background()) }, nil
}

// member reads a member of a payload as text, for a comparison.
func member(payload map[string]any, names ...string) string {
	var v any = payload
	for _, name := range names {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[name]
	}
	if s, ok := v.(string); ok {
		return s
	}
	data, _ := json.Marshal(v)
	return string(data)
}

// webhookRewrites signs in through webhooks that rewrite the subject, the acr, the amr,
// the context and the claims: Hydra takes them, the id_token says them. The second login
// is a skip, honoured on what the cookie kept: the marker holds on the values rewritten
// (Q38), the webhooks are called again with them (SKP-1, SKC-1), the consent webhook with
// the cookie's context, never the request's (Q38).
func (d *driver) webhookRewrites() error {
	if d.hooks == nil {
		return errNoWebhook
	}
	defer d.hooks.answers(`{}`, `{}`)
	const mapped = "mapped-subject"
	d.hooks.answers(`{"subject":"`+mapped+`","acr":"hook-acr","amr":["hook"],"context":{"hook":true},"status":"ok"}`,
		`{"id_token":{"hook_claim":"yes"},"access_token":[]}`)
	want := identity{Sub: mapped, ACR: "hook-acr", AMR: []string{"hook"}}

	o, err := d.authorize(login{flow: "hydra-sql", user: isabelle, consent: "accept"})
	if err != nil {
		return err
	}
	if err := d.granted(o, want); err != nil {
		return err
	}
	claims, err := idTokenClaims(d.client.idToken)
	if err != nil {
		return err
	}
	if claims["hook_claim"] != "yes" {
		return fmt.Errorf("id_token %v: the consent webhook's claims lost", claims)
	}
	loginHook, consentHook := d.hooks.last()
	challenge := o.entry.Query().Get("login_challenge")
	for name, got := range map[string][2]string{
		"challenge, L":         {member(loginHook, "challenge"), challenge},
		"subject before":       {member(loginHook, "subject"), isabelle},
		"browser":              {member(loginHook, "browser", "user-agent"), browserAgent},
		"client":               {member(loginHook, "client", "client_id"), d.client.id},
		"subject for Hydra":    {member(consentHook, "subject"), mapped},
		"acr for Hydra":        {member(consentHook, "acr"), "hook-acr"},
		"context of the login": {member(consentHook, "context"), `{"hook":true}`},
	} {
		if got[0] != got[1] {
			return fmt.Errorf("%s: %q, want %q; login %v, consent %v", name, got[0], got[1], loginHook, consentHook)
		}
	}
	if !d.b.has(d.dispatcher, rememberCookie) {
		return fmt.Errorf("no %s cookie (WRT-1)", rememberCookie)
	}

	p, err := d.start("")
	if err != nil {
		return err
	}
	if err := d.skipped(p); err != nil {
		return err
	}
	if err := d.granted(outcome{entry: p.Trail[0], seen: []string{d.kind(p)}, end: p}, want); err != nil {
		return err
	}
	loginHook, consentHook = d.hooks.last()
	for name, got := range map[string][2]string{
		"skip, subject":              {member(loginHook, "subject"), mapped},
		"skip, the cookie's context": {member(loginHook, "context"), `{"hook":true}`},
		"skip, consent's context":    {member(consentHook, "context"), `{"hook":true}`},
	} {
		if got[0] != got[1] {
			return fmt.Errorf("%s: %q, want %q", name, got[0], got[1])
		}
	}
	d.note("subject, acr, amr, context and claims rewritten; skip honoured on them")
	return nil
}

// webhookFails has each webhook fail in turn: page E1006, nothing rejected at Hydra, and
// a reload calls it again, which then answers (FIN-4, CST-12, Q23, A9).
func (d *driver) webhookFails() error {
	if d.hooks == nil {
		return errNoWebhook
	}
	defer d.hooks.answers(`{}`, `{}`)
	l := login{flow: "hydra-sql", user: isabelle, consent: "accept"}
	d.hooks.answers(`{"context":["a"]}`, `{}`)
	o, err := d.authorize(l)
	if err != nil {
		return err
	}
	if o.code != "E1006" {
		return fmt.Errorf("a context in a list: pages %v, ended on %q %s, want the page E1006", o.seen, o.code, endURL(o))
	}
	d.hooks.answers(`[]`, `{"id_token":"not an object"}`)
	p, err := d.b.get(o.end.URL.String())
	if err != nil {
		return err
	}
	o, err = d.drive(p, l)
	if err != nil {
		return err
	}
	if o.code != "E1006" {
		return fmt.Errorf("claims that are no object: pages %v, ended on %q %s, want the page E1006", o.seen, o.code, endURL(o))
	}
	d.hooks.answers(`{}`, `{}`)
	if p, err = d.b.get(o.end.URL.String()); err != nil {
		return err
	}
	if o, err = d.drive(p, l); err != nil {
		return err
	}
	return d.granted(o, identities["hydra-sql"])
}

// webhookOtherSubjectAtSkip has the login webhook give another subject at a skip: Hydra
// would refuse it or start over; page E1003, with the way out (SKP-7, Q63).
func (d *driver) webhookOtherSubjectAtSkip() error {
	if d.hooks == nil {
		return errNoWebhook
	}
	defer d.hooks.answers(`{}`, `{}`)
	if err := d.remembered(); err != nil {
		return err
	}
	d.hooks.answers(`{"subject":"someone-else"}`, `{}`)
	p, err := d.start("")
	if err != nil {
		return err
	}
	if code := errorCode.FindString(p.Body); d.kind(p) != "error" || code != "E1003" {
		return fmt.Errorf("ended on %q: %w", code, errUnexpected(p))
	}
	return nil
}
