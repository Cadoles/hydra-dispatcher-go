package adminui

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// loginTTL is how long the form of the login stays valid.
const loginTTL = 10 * time.Minute

// unknown names, at the audit, a refused login whose name is no account's: a
// password typed into the field of the name never reaches the audit.
const unknown = "(unknown)"

// secretMatches compares a password with a hash, the dummy one included; the
// tests count its calls.
var secretMatches = domain.SecretMatches

// dummyHash is compared for a name no account has, or an account without a
// password (one of the identity provider): the answer takes the time of a
// real one, and does not tell which accounts exist.
var dummyHash = sync.OnceValue(func() string {
	h, _ := domain.HashSecret("no admin account has this password")
	return h
})

// loginToken is what the cookie of the login seals: the token of its form,
// and when it ends. It guards the form against a login forged by another
// site (Durcissements, point 5).
type loginToken struct {
	Token   string `json:"t"`
	Expires int64  `json:"e"`
}

// loginForm shows the form of the login, a new token in its cookie; a
// session that holds goes back to where it was going.
func (ui *UI) loginForm(w http.ResponseWriter, r *http.Request) {
	if s, err := ui.current(r); err == nil && s != nil {
		http.Redirect(w, r, ui.next(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	ui.renderLogin(w, http.StatusOK, r.URL.Query().Get("next"), "")
}

func (ui *UI) renderLogin(w http.ResponseWriter, status int, next, message string) {
	t := loginToken{Token: randomToken(), Expires: ui.o.Now().Add(loginTTL).Unix()}
	data, _ := json.Marshal(t) // a string and a number
	ui.setCookie(w, loginCookie, ui.o.Keys.Seal(loginCookie, sealVersion, data), loginTTL)
	ui.render(w, status, "login", view{Title: "Log in", CSRF: t.Token, Next: ui.next(next), Error: message,
		SSO: ui.block().Enabled, PasswordLogin: ui.o.PasswordLogin})
}

// loginTokenOK tells whether the form posted carries the token its cookie
// seals, still valid.
func (ui *UI) loginTokenOK(r *http.Request) bool {
	c, err := r.Cookie(ui.prefix + loginCookie)
	if err != nil {
		return false
	}
	plain, ok := ui.o.Keys.Open(loginCookie, sealVersion, c.Value)
	var t loginToken
	if !ok || json.Unmarshal(plain, &t) != nil || ui.o.Now().Unix() > t.Expires {
		return false
	}
	return sameToken(r.PostFormValue("csrf"), t.Token)
}

// login checks a name and a password: the form's own token and origin
// first, then the limit of the address, then the password, by bcrypt among a
// bounded number of them, against a dummy hash for a name no account has.
// The forms another site forges are refused before the limit: a page that
// posts them from an admin's browser does not exhaust the attempts of the
// admin's address (revue R40).
func (ui *UI) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	next := r.PostFormValue("next")
	if !ui.o.PasswordLogin {
		ui.renderLogin(w, http.StatusForbidden, next, "The login by password is off: log in by the identity provider.")
		return
	}
	if !ui.sameOrigin(r) || !ui.loginTokenOK(r) {
		ui.renderLogin(w, http.StatusForbidden, next, "The form had expired: try again.")
		return
	}
	if !ui.allowed(w, r) {
		return
	}
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	a, found, err := ui.account(ctx, username)
	if err != nil {
		if ui.o.Logger != nil {
			ui.o.Logger.ErrorContext(ctx, "admin.accounts_unreadable", "cause", err.Error())
		}
		ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "The admin accounts cannot be read now: try again in a moment.", nil)
		return
	}
	hash := dummyHash()
	if found && a.PasswordHash != "" {
		hash = a.PasswordHash
	}
	var matches bool
	if !ui.withBcrypt(ctx, func() { matches = secretMatches(hash, password) }) {
		return // the client left while its turn came
	}
	if !matches || !found || a.PasswordHash == "" {
		user := unknown
		if found {
			user = a.Username
		}
		ui.audit(ctx, user, "password", "refused", "invalid_credentials")
		ui.renderLogin(w, http.StatusUnauthorized, next, "Invalid name or password.")
		return
	}
	ui.setSession(w, ui.newSession(a.Username, "password"))
	ui.setCookie(w, loginCookie, "", 0)
	ui.audit(ctx, a.Username, "password", "granted", "")
	http.Redirect(w, r, ui.next(next), http.StatusSeeOther)
}

// account reads the account of a name typed: a name no account may have is
// none, without a request to the database, which would refuse a NUL.
func (ui *UI) account(ctx context.Context, username string) (a store.AdminUser, found bool, err error) {
	if domain.Collect(func(fail domain.Fail) { domain.CheckUsername(fail, username) }) != nil {
		return a, false, nil
	}
	ctx, cancel := ui.bounded(ctx)
	defer cancel()
	return ui.o.Accounts.Admin(ctx, username)
}

// logout ends every session of the account (Q120), this one included. When
// the others cannot be ended, the cookie of this browser goes all the same,
// and the page says so: the audit writes no logout, a stolen cookie being
// still valid (revue R40).
func (ui *UI) logout(w http.ResponseWriter, r *http.Request, s *current) {
	ui.setCookie(w, sessionCookie, "", 0)
	ctx, cancel := ui.bounded(r.Context())
	defer cancel()
	if err := ui.o.Accounts.EndSessions(ctx, s.account.Username); err != nil {
		if ui.o.Logger != nil {
			ui.o.Logger.ErrorContext(r.Context(), "admin.logout_failed", "cause", err.Error())
		}
		ui.status(w, r, http.StatusServiceUnavailable, "Logged out of this browser only",
			"Your sessions in other browsers could not be ended: log in and out again in a moment.", nil)
		return
	}
	if ui.o.Logout != nil {
		ui.o.Logout(r.Context(), s.account.Username)
	}
	http.Redirect(w, r, ui.base+"/login", http.StatusSeeOther)
}

func (ui *UI) reauthForm(w http.ResponseWriter, r *http.Request, s *current) {
	ui.render(w, http.StatusOK, "reauth", view{Title: "Confirm it is you", Account: &s.account, CSRF: s.session.CSRF, Next: ui.next(r.URL.Query().Get("next"))})
}

// reauth checks the password of the account again: the time of the last
// authentication moves, and the sensitive actions open for
// admin.session.reauth_window. An account of the identity provider has no
// password here: P22 sends it to the provider.
func (ui *UI) reauth(w http.ResponseWriter, r *http.Request, s *current) {
	ctx := r.Context()
	if !ui.o.PasswordLogin {
		ui.status(w, r, http.StatusForbidden, "Confirm it is you", "The login by password is off: confirm it by the identity provider.", s)
		return
	}
	if !ui.allowed(w, r) {
		return
	}
	next := r.PostFormValue("next")
	hash := s.account.PasswordHash
	if hash == "" {
		hash = dummyHash()
	}
	var matches bool
	if !ui.withBcrypt(ctx, func() { matches = secretMatches(hash, r.PostFormValue("password")) }) {
		return
	}
	if !matches || s.account.PasswordHash == "" {
		ui.audit(ctx, s.account.Username, "password", "refused", "reauth_failed")
		ui.render(w, http.StatusUnauthorized, "reauth", view{Title: "Confirm it is you", Account: &s.account, CSRF: s.session.CSRF, Next: ui.next(next), Error: "Invalid password."})
		return
	}
	s.session.Auth = ui.o.Now().UnixMicro()
	s.session.Seen = s.session.Auth
	ui.setSession(w, s.session)
	ui.audit(ctx, s.account.Username, "password", "granted", "reauth")
	http.Redirect(w, r, ui.next(next), http.StatusSeeOther)
}

// allowed takes an attempt of the address from its limit; past it, the
// answer is 429 with Retry-After.
func (ui *UI) allowed(w http.ResponseWriter, r *http.Request) bool {
	now := ui.o.Now()
	rt := ui.limit.Take(httpx.ClientIP(r.Context()), now)
	if rt.Allowed {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(rt.Reset.Sub(now).Seconds())))))
	if ui.o.RateLimited != nil {
		ui.o.RateLimited(r.Context())
	}
	ui.status(w, r, http.StatusTooManyRequests, "Too many attempts", "Too many attempts from this address: wait a minute.", nil)
	return false
}

// withBcrypt runs f with a place among ui.bcrypt, given back by a defer;
// false when ctx ended before a place came.
func (ui *UI) withBcrypt(ctx context.Context, f func()) bool {
	select {
	case ui.bcrypt <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-ui.bcrypt }()
	f()
	return true
}

func (ui *UI) audit(ctx context.Context, user, method, result, reason string) {
	if ui.o.Login != nil {
		ui.o.Login(ctx, user, method, result, reason)
	}
}
