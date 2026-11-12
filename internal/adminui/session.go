package adminui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The cookies of the admin, prefixed __Host- in HTTPS with the cookies at /,
// and the version of what they seal.
const (
	sessionCookie = "dispatcher_admin"
	loginCookie   = "dispatcher_admin_login"
	sealVersion   = "1"
)

// refreshAfter is how old the last request of a session may be before the
// cookie is sealed again: the inactivity counts from it, at a minute near.
const refreshAfter = time.Minute

// session is what the cookie holds: no role, which is read from the account
// at each request (Q120). The times are in microseconds.
type session struct {
	User   string `json:"u"`
	Method string `json:"m"`
	// Issued is the login, Seen the last request, Auth the last
	// authentication, a re-authentication included.
	Issued int64  `json:"i"`
	Seen   int64  `json:"s"`
	Auth   int64  `json:"a"`
	CSRF   string `json:"c"`
}

// current is the session of a request and its account, read again.
type current struct {
	session session
	account store.AdminUser
}

// randomToken is 128 bits in base64url.
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand never fails
	return base64.RawURLEncoding.EncodeToString(b)
}

func (ui *UI) newSession(user, method string) session {
	now := ui.o.Now().UnixMicro()
	return session{User: user, Method: method, Issued: now, Seen: now, Auth: now, CSRF: randomToken()}
}

func (ui *UI) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{Name: ui.prefix + name, Value: value, Path: ui.o.CookiePath, HttpOnly: true, Secure: ui.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge / time.Second)}
	if maxAge <= 0 {
		c.Value, c.MaxAge = "", -1
	}
	http.SetCookie(w, c)
}

// setSession seals s into the cookie, which the browser keeps until the end
// of the session's age.
func (ui *UI) setSession(w http.ResponseWriter, s session) {
	data, _ := json.Marshal(s) // strings and numbers
	left := time.UnixMicro(s.Issued).Add(ui.o.MaxAge).Sub(ui.o.Now())
	ui.setCookie(w, sessionCookie, ui.o.Keys.Seal(sessionCookie, sealVersion, data), max(left, time.Second))
}

// current reads the session of r: errNoSession when there is none, or it is
// over (its age, its inactivity, its account gone, its sessions ended since);
// another error when the accounts cannot be read.
func (ui *UI) current(r *http.Request) (*current, error) {
	c, err := r.Cookie(ui.prefix + sessionCookie)
	if err != nil {
		return nil, errNoSession
	}
	plain, ok := ui.o.Keys.Open(sessionCookie, sealVersion, c.Value)
	if !ok {
		return nil, errNoSession
	}
	var s session
	if json.Unmarshal(plain, &s) != nil || s.User == "" {
		return nil, errNoSession
	}
	now := ui.o.Now()
	if now.Sub(time.UnixMicro(s.Issued)) > ui.o.MaxAge || now.Sub(time.UnixMicro(s.Seen)) > ui.o.IdleTimeout {
		return nil, errNoSession
	}
	ctx, cancel := ui.bounded(r.Context())
	defer cancel()
	a, found, err := ui.o.Accounts.Admin(ctx, s.User)
	if err != nil {
		return nil, err
	}
	if !found || !time.UnixMicro(s.Issued).After(a.SessionsValidAfter) {
		return nil, errNoSession
	}
	return &current{session: s, account: a}, nil
}

// role is what a route asks of the account.
type role int

const (
	anyRole role = iota
	adminRole
)

// authed serves h to a request whose session holds, by an account of the
// role need; a POST also needs the token of its session and to come from the
// dispatcher's own pages. A session over sends a GET to the login, which
// comes back to it.
func (ui *UI) authed(need role, h func(http.ResponseWriter, *http.Request, *current)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := ui.current(r)
		switch {
		case err != nil && !errors.Is(err, errNoSession):
			if ui.o.Logger != nil {
				ui.o.Logger.ErrorContext(r.Context(), "admin.accounts_unreadable", "cause", err.Error())
			}
			ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "The admin accounts cannot be read now: try again in a moment.", nil)
			return
		case err != nil:
			if _, err := r.Cookie(ui.prefix + sessionCookie); err == nil {
				ui.setCookie(w, sessionCookie, "", 0) // over: the browser forgets it
			}
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, ui.base+"/login?next="+url.QueryEscape(ui.root()+r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			ui.status(w, r, http.StatusForbidden, "Session ended", "Your session has ended: log in again.", nil)
			return
		}
		if need == adminRole && s.account.Role != domain.RoleAdmin {
			ui.status(w, r, http.StatusForbidden, "Forbidden", "This action needs the role admin.", s)
			return
		}
		if r.Method == http.MethodPost {
			if !ui.sameOrigin(r) || !sameToken(r.PostFormValue("csrf"), s.session.CSRF) {
				ui.status(w, r, http.StatusForbidden, "Refused", "The form could not be checked: reload the page and try again.", s)
				return
			}
		} else if ui.o.Now().Sub(time.UnixMicro(s.session.Seen)) > refreshAfter {
			s.session.Seen = ui.o.Now().UnixMicro()
			ui.setSession(w, s.session)
		}
		h(w, r, s)
	})
}

// fresh serves h when the last authentication of the session is within
// admin.session.reauth_window; otherwise a GET goes to the
// re-authentication, which comes back to it, and a POST is refused: the
// sensitive actions (a secret shown or turned, a client or a flow deleted, a
// role changed) have a page of their own before their POST.
func (ui *UI) fresh(h func(http.ResponseWriter, *http.Request, *current)) func(http.ResponseWriter, *http.Request, *current) {
	return func(w http.ResponseWriter, r *http.Request, s *current) {
		if ui.o.Now().Sub(time.UnixMicro(s.session.Auth)) <= ui.o.ReauthWindow {
			h(w, r, s)
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, ui.base+"/reauth?next="+url.QueryEscape(ui.root()+r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		ui.status(w, r, http.StatusForbidden, "Confirm it is you", "This action asks for your password again: open it anew.", s)
	}
}

// root is the path of server.base_url, before /admin.
func (ui *UI) root() string { return strings.TrimSuffix(ui.base, "/admin") }

// sameOrigin tells whether a POST comes from the dispatcher's own pages, as
// far as the browser says: Sec-Fetch-Site same-origin, an Origin that is the
// dispatcher's. A browser that says neither relies on the token alone.
func (ui *UI) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != ui.origin {
		return false
	}
	return true
}

func sameToken(got, want string) bool {
	return got != "" && want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
