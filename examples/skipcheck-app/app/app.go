// Package app is the reference login app of the pre-check of a step (phase 4,
// Plan phase 4, P28): a second factor that remembers a device. It shows what
// an app does on each side of the extension:
//
//   - its step: GET and POST /login read the login request of the dispatcher's
//     emulated API, ask the code (a stand-in for an OTP), and accept; with
//     "remember this device" checked, the app records the subject and the
//     device value the request carries (x_dispatcher_device), until a date it
//     declares to the dispatcher (context.x_dispatcher_remember_until);
//   - the user's devices: listed on the step's page, each one revoked there
//     (POST /revoke);
//   - the pre-check: POST /skip-check, its signature checked, answers skip
//     true for a device recorded for that subject and not expired, signed.
//
// The devices are kept in memory: an app of production keeps them in its
// database, with the user's account.
package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Options configure the app.
type Options struct {
	// AdminURL is the dispatcher's emulated API, as Hydra's admin URL: the
	// paths /admin/oauth2/auth/requests/... follow it.
	AdminURL string
	// Key is the app's skip_check_key, 32 bytes: it checks the requests of
	// the pre-check and signs the answers.
	Key []byte
	// Code is the code the step asks.
	Code string
	// RememberFor is how long a device stays trusted, 30 days by default.
	RememberFor time.Duration
	// Client calls the emulated API; Now gives the time; Log, nil for none.
	Client *http.Client
	Now    func() time.Time
	Log    *slog.Logger
}

// device is a device trusted for a subject.
type device struct {
	ID        string // drawn: the revoke button names it, never the value
	Value     string // the dispatcher's device value for this app
	UserAgent string // of the browser that enrolled it
	Created   time.Time
	Until     time.Time
}

type app struct {
	o       Options
	mu      sync.Mutex
	devices map[string][]device // by subject
}

// New returns the handler of the app.
func New(o Options) (http.Handler, error) {
	if len(o.Key) != 32 {
		return nil, errors.New("app: the key is 32 bytes")
	}
	if o.RememberFor <= 0 {
		o.RememberFor = 30 * 24 * time.Hour
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	a := &app{o: o, devices: map[string][]device{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /revoke", a.revoke)
	mux.HandleFunc("GET /consent", a.consent)
	mux.HandleFunc("POST /skip-check", a.skipCheck)
	return mux, nil
}

// loginRequest is what the app reads of the login request.
type loginRequest struct {
	Subject string `json:"subject"`
	// Device is the browser's device for this app, when the dispatcher's
	// configuration asks for the pre-check.
	Device string `json:"x_dispatcher_device"`
}

// The pages: the step's form, its devices, and the error.
var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Second factor</title></head>
<body>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
{{if .Challenge}}
<form method="post" action="login">
<input type="hidden" name="login_challenge" value="{{.Challenge}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Code <input name="code" autocomplete="one-time-code" required autofocus></label>
{{if .Device}}<label><input type="checkbox" name="remember" value="1"> Remember this device</label>{{end}}
<button>Confirm</button>
</form>
{{if .Devices}}
<h2>Your trusted devices</h2>
<ul>{{range .Devices}}
<li>{{.UserAgent}}, since {{.Created.Format "2006-01-02"}}, until {{.Until.Format "2006-01-02"}}
<form method="post" action="revoke"><input type="hidden" name="login_challenge" value="{{$.Challenge}}">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><button>Revoke</button></form></li>
{{end}}</ul>
{{end}}
{{end}}
</body></html>`))

type view struct {
	Challenge, CSRF, Error string
	Device                 bool
	Devices                []device
}

const csrfCookie = "skipcheck_app_csrf"

// csrf returns the browser's token, drawn and set when it has none.
func csrf(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) == 64 {
		return c.Value
	}
	v := random()
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: v, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	return v
}

// sameCSRF tells that the form carries the browser's token.
func sameCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	return err == nil && len(c.Value) == 64 && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand never fails
	return hex.EncodeToString(b)
}

func (a *app) render(w http.ResponseWriter, status int, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = page.Execute(w, v)
}

// form is the step's page for the login request of challenge.
func (a *app) form(w http.ResponseWriter, r *http.Request, challenge string, req loginRequest, status int, msg string) {
	a.render(w, status, view{Challenge: challenge, CSRF: csrf(w, r), Error: msg, Device: req.Device != "", Devices: a.trusted(req.Subject)})
}

func (a *app) loginPage(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	req, err := a.readLogin(r.Context(), challenge)
	if err != nil {
		a.o.Log.WarnContext(r.Context(), "login request unreadable", "err", err)
		a.render(w, http.StatusBadRequest, view{Error: "This sign-in cannot go on: start again from the application."})
		return
	}
	a.form(w, r, challenge, req, http.StatusOK, "")
}

// login is the step: the code, then the accept, the device recorded when
// asked. The login request is read again: the form says only which.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	challenge := r.PostFormValue("login_challenge")
	req, err := a.readLogin(r.Context(), challenge)
	switch {
	case err != nil:
		a.render(w, http.StatusBadRequest, view{Error: "This sign-in cannot go on: start again from the application."})
		return
	case !sameCSRF(r):
		a.form(w, r, challenge, req, http.StatusForbidden, "The form expired: try again.")
		return
	case subtle.ConstantTimeCompare([]byte(r.PostFormValue("code")), []byte(a.o.Code)) != 1:
		a.form(w, r, challenge, req, http.StatusUnprocessableEntity, "Wrong code.")
		return
	}
	accept := map[string]any{"subject": req.Subject}
	var enrolled *device
	if r.PostFormValue("remember") == "1" && req.Device != "" {
		now := a.o.Now().UTC()
		enrolled = &device{ID: random(), Value: req.Device, UserAgent: r.UserAgent(), Created: now, Until: now.Add(a.o.RememberFor)}
		accept["context"] = map[string]any{"x_dispatcher_remember_until": enrolled.Until.Format(time.RFC3339)}
	}
	var done struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := a.admin(r.Context(), http.MethodPut, "/admin/oauth2/auth/requests/login/accept", "login_challenge", challenge, accept, &done); err != nil || done.RedirectTo == "" {
		a.o.Log.WarnContext(r.Context(), "login accept failed", "err", err)
		a.render(w, http.StatusBadGateway, view{Error: "This sign-in cannot go on: start again from the application."})
		return
	}
	if enrolled != nil {
		a.mu.Lock()
		list := slices.DeleteFunc(a.devices[req.Subject], func(d device) bool { return d.Value == enrolled.Value })
		a.devices[req.Subject] = append(list, *enrolled)
		a.mu.Unlock()
	}
	http.Redirect(w, r, done.RedirectTo, http.StatusSeeOther)
}

// revoke forgets a device of the subject of the login request: a user
// revokes only their own, from their step.
func (a *app) revoke(w http.ResponseWriter, r *http.Request) {
	challenge := r.PostFormValue("login_challenge")
	req, err := a.readLogin(r.Context(), challenge)
	if err != nil {
		a.render(w, http.StatusBadRequest, view{Error: "This sign-in cannot go on: start again from the application."})
		return
	}
	if !sameCSRF(r) {
		a.form(w, r, challenge, req, http.StatusForbidden, "The form expired: try again.")
		return
	}
	id := r.PostFormValue("id")
	a.mu.Lock()
	a.devices[req.Subject] = slices.DeleteFunc(a.devices[req.Subject], func(d device) bool { return d.ID == id })
	a.mu.Unlock()
	http.Redirect(w, r, "login?"+url.Values{"login_challenge": {challenge}}.Encode(), http.StatusSeeOther)
}

// trusted returns the devices of subject not expired.
func (a *app) trusted(subject string) []device {
	now := a.o.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	list := slices.DeleteFunc(a.devices[subject], func(d device) bool { return !now.Before(d.Until) })
	if len(list) == 0 {
		delete(a.devices, subject)
		return nil
	}
	a.devices[subject] = list
	return slices.Clone(list)
}

// consent accepts at once: the step adds no claim.
func (a *app) consent(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("consent_challenge")
	var req struct {
		Scope    []string `json:"requested_scope"`
		Audience []string `json:"requested_access_token_audience"`
	}
	var done struct {
		RedirectTo string `json:"redirect_to"`
	}
	err := a.admin(r.Context(), http.MethodGet, "/admin/oauth2/auth/requests/consent", "consent_challenge", challenge, nil, &req)
	if err == nil {
		err = a.admin(r.Context(), http.MethodPut, "/admin/oauth2/auth/requests/consent/accept", "consent_challenge", challenge,
			map[string]any{"grant_scope": nonNil(req.Scope), "grant_access_token_audience": nonNil(req.Audience)}, &done)
	}
	if err != nil || done.RedirectTo == "" {
		a.o.Log.WarnContext(r.Context(), "consent failed", "err", err)
		a.render(w, http.StatusBadGateway, view{Error: "This sign-in cannot go on: start again from the application."})
		return
	}
	http.Redirect(w, r, done.RedirectTo, http.StatusSeeOther)
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func (a *app) readLogin(ctx context.Context, challenge string) (loginRequest, error) {
	var req loginRequest
	if challenge == "" {
		return req, errors.New("no login_challenge")
	}
	err := a.admin(ctx, http.MethodGet, "/admin/oauth2/auth/requests/login", "login_challenge", challenge, nil, &req)
	if err == nil && req.Subject == "" {
		err = errors.New("no subject: this app is never a first step")
	}
	return req, err
}

// admin calls the emulated API, as an app calls Hydra's admin API.
func (a *app) admin(ctx context.Context, method, path, param, challenge string, body, into any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.o.AdminURL+path+"?"+url.Values{param: {challenge}}.Encode(), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.o.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

// The pre-check, as the dispatcher sends it (Plan phase 4, P27 en détail).
const (
	headerTimestamp = "X-Dispatcher-Timestamp"
	headerSignature = "X-Dispatcher-Signature"
	skew            = 5 * time.Minute
)

type checkRequest struct {
	Version int            `json:"version"`
	Nonce   string         `json:"nonce"`
	Subject string         `json:"subject"`
	Device  string         `json:"device"`
	Signals map[string]any `json:"signals"`
}

// skipCheck answers the pre-check: skip for a device recorded for the
// subject, not expired, and, when the dispatcher sends the User-Agent (the
// app declares user_agent), of the browser that enrolled it. Anything it
// cannot read is a 4xx: the dispatcher runs the step.
func (a *app) skipCheck(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	ts := r.Header.Get(headerTimestamp)
	t, tsErr := strconv.ParseInt(ts, 10, 64)
	switch {
	case err != nil:
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	case tsErr != nil || a.o.Now().Sub(time.Unix(t, 0)).Abs() > skew:
		http.Error(w, "timestamp", http.StatusUnauthorized)
		return
	case !hmac.Equal([]byte(r.Header.Get(headerSignature)), []byte(sign(a.o.Key, ts, body))):
		http.Error(w, "signature", http.StatusUnauthorized)
		return
	}
	var req checkRequest
	if json.Unmarshal(body, &req) != nil || req.Version != 1 || req.Nonce == "" {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	skip := false
	if req.Device != "" {
		for _, d := range a.trusted(req.Subject) {
			ua, sent := req.Signals["user_agent"].(string)
			if hmac.Equal([]byte(d.Value), []byte(req.Device)) && (!sent || ua == d.UserAgent) {
				skip = true
			}
		}
	}
	answer, _ := json.Marshal(map[string]any{"nonce": req.Nonce, "skip": skip}) // always marshals
	now := strconv.FormatInt(a.o.Now().Unix(), 10)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(headerTimestamp, now)
	// The answer's signature covers "response." first: a request sent back
	// as it came never passes for an answer.
	w.Header().Set(headerSignature, sign(a.o.Key, "response."+now, answer))
	_, _ = w.Write(answer)
}

// sign is hex(HMAC-SHA256(key, ts + "." + body)), the webhooks' signature.
func sign(key []byte, ts string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
