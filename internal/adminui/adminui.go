// Package adminui serves the admin UI, /admin: pages rendered on the server
// by html/template, styled by Pico CSS without classes (Q119), behind
// security.admin_authorized_hosts and a session of an admin account (Q120).
// The admin API, /admin/v1, is internal/admin; the more specific route of the
// mux takes it.
package adminui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/ratelimit"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seal"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/web"
)

// csp is the policy of the pages of the admin: the sheet and the scripts of
// the dispatcher alone, no inline style or script; the images of Pico are
// SVG in data:.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; " +
	"connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"

// Accounts are the admin accounts of the store, read at each request (Q120).
type Accounts interface {
	Admin(ctx context.Context, username string) (store.AdminUser, bool, error)
	EndSessions(ctx context.Context, username string) error
}

// Options configure the admin UI.
type Options struct {
	// Enabled is admin.ui.enabled: off, /admin answers 404.
	Enabled         bool
	AuthorizedHosts []netip.Prefix
	Accounts        Accounts
	// Keys seal the cookies: secrets.cookie_key and its previous keys.
	Keys *seal.Keys
	// BaseURL and CookiePath are server.base_url and server.cookie_path.
	BaseURL    string
	CookiePath string
	// The bounds of a session: admin.session.idle_timeout, max_age and
	// reauth_window.
	IdleTimeout, MaxAge, ReauthWindow time.Duration
	// LoginsPerMinute bounds the attempts of an address, login and
	// re-authentication together.
	LoginsPerMinute int
	Logger          *slog.Logger
	LogIP           string
	LogSample       *httpx.Sampler
	// Refused is told of an address outside the allowlist, RateLimited of an
	// address past the limit of its attempts.
	Refused     func(ctx context.Context)
	RateLimited func(ctx context.Context)
	// Login is told of a login, granted or refused, and Logout of a logout:
	// the audit (Durcissements, point 8).
	Login  func(ctx context.Context, user, method, result, reason string)
	Logout func(ctx context.Context, user string)
	// Dashboard gives what the dashboard shows.
	Dashboard func(ctx context.Context) Dashboard
	Version   string
	Now       func() time.Time
}

// Dashboard is what the dashboard shows.
type Dashboard struct {
	Version, Instance                     string
	Dependencies                          []Dependency
	Apps, Flows, FlowsEnabled, APIClients int
}

// Dependency is one of what serve depends on, ready or not.
type Dependency struct {
	Name   string
	OK     bool
	Detail string
}

// UI is the admin UI.
type UI struct {
	o      Options
	mux    *http.ServeMux
	pages  map[string]*template.Template
	sheet  asset
	origin string // of server.base_url, for the Origin of a POST
	base   string // the path of server.base_url, then /admin
	secure bool
	prefix string // __Host- in HTTPS with the cookies at /
	limit  *ratelimit.Limiter
	bcrypt chan struct{}
}

// New returns the admin UI.
func New(o Options) (*UI, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LoginsPerMinute <= 0 {
		o.LoginsPerMinute = 10
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("adminui: server.base_url: %w", err)
	}
	ui := &UI{o: o, mux: http.NewServeMux(), pages: map[string]*template.Template{},
		origin: u.Scheme + "://" + u.Host, base: strings.TrimSuffix(u.EscapedPath(), "/") + "/admin",
		secure: u.Scheme == "https", limit: ratelimit.New(o.LoginsPerMinute), bcrypt: make(chan struct{}, runtime.GOMAXPROCS(0))}
	if ui.secure && o.CookiePath == "/" {
		ui.prefix = "__Host-"
	}
	for _, name := range []string{"login", "reauth", "dashboard", "status"} {
		t, err := template.New(name).ParseFS(web.Admin, "admin/layout.html.tmpl", "admin/"+name+".html.tmpl")
		if err != nil {
			return nil, fmt.Errorf("adminui: %s: %w", name, err)
		}
		ui.pages[name] = t
	}
	sheet, err := web.Pico.ReadFile("pico/pico.classless.min.css")
	if err != nil {
		return nil, err
	}
	ui.sheet = newAsset("text/css; charset=utf-8", sheet)

	ui.mux.Handle("GET /admin/static/pico.css", ui.sheet)
	ui.mux.Handle("GET /admin", ui.authed(anyRole, ui.dashboard))
	ui.mux.Handle("GET /admin/{$}", ui.authed(anyRole, ui.dashboard))
	ui.mux.HandleFunc("GET /admin/login", ui.loginForm)
	ui.mux.HandleFunc("POST /admin/login", ui.login)
	ui.mux.Handle("POST /admin/logout", ui.authed(anyRole, ui.logout))
	ui.mux.Handle("GET /admin/reauth", ui.authed(anyRole, ui.reauthForm))
	ui.mux.Handle("POST /admin/reauth", ui.authed(anyRole, ui.reauth))
	ui.mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		ui.status(w, r, http.StatusNotFound, "Not found", "No page of the admin has this address.", nil)
	})
	return ui, nil
}

// Register serves the admin UI on mux, at /admin and below; /admin/v1, the
// admin API, keeps its own routes, more specific.
func (ui *UI) Register(mux *http.ServeMux) {
	mux.Handle("/admin", ui)
	mux.Handle("/admin/", ui)
}

// ServeHTTP answers 404 when the UI is off, 403 outside the allowlist, then
// routes. No page is cached; the sheet is, by its ETag.
func (ui *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !ui.o.Enabled {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("Referrer-Policy", "same-origin")
	ip := httpx.ClientIP(r.Context())
	if !httpx.Within(ui.o.AuthorizedHosts, ip) {
		if ui.o.Logger != nil && ui.o.LogSample.AllowClient(r.Context(), "security.ip_rejected") {
			ui.o.Logger.WarnContext(r.Context(), "security.ip_rejected", "surface", "admin_ui", "ip", httpx.FormatIP(ip, ui.o.LogIP))
		}
		if ui.o.Refused != nil {
			ui.o.Refused(r.Context())
		}
		ui.status(w, r, http.StatusForbidden, "Forbidden", "This address may not reach the admin.", nil)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/admin/static/") {
		h.Set("Cache-Control", "no-store")
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	}
	ui.mux.ServeHTTP(w, r)
}

// maxForm bounds the body of a form of the admin.
const maxForm = 64 << 10

// view is what a page renders.
type view struct {
	Title, Base, Asset, CSRF, Error, Next, Version, Message string
	Account                                                 *store.AdminUser
	Dashboard                                               *Dashboard
}

func (ui *UI) render(w http.ResponseWriter, status int, name string, v view) {
	v.Base, v.Asset, v.Version = ui.base, ui.base+"/static/pico.css?v="+ui.sheet.etag, ui.o.Version
	var b bytes.Buffer
	if err := ui.pages[name].ExecuteTemplate(&b, "layout", v); err != nil {
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

// status renders a page that says why the request stops.
func (ui *UI) status(w http.ResponseWriter, _ *http.Request, code int, title, message string, s *current) {
	v := view{Title: title, Message: message}
	if s != nil {
		v.Account, v.CSRF = &s.account, s.session.CSRF
	}
	ui.render(w, code, "status", v)
}

func (ui *UI) dashboard(w http.ResponseWriter, r *http.Request, s *current) {
	d := Dashboard{}
	if ui.o.Dashboard != nil {
		d = ui.o.Dashboard(r.Context())
	}
	ui.render(w, http.StatusOK, "dashboard", view{Title: "Dashboard", Account: &s.account, CSRF: s.session.CSRF, Dashboard: &d})
}

// asset is a file of the pages, with its ETag.
type asset struct {
	contentType string
	data        []byte
	etag        string
}

func newAsset(contentType string, data []byte) asset {
	sum := sha256.Sum256(data)
	return asset{contentType: contentType, data: data, etag: hex.EncodeToString(sum[:8])}
}

func (a asset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", `"`+a.etag+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.data))
}

// next is the page a login or a re-authentication goes back to: a path of
// the admin, never another site nor the login itself, the dashboard by
// default.
func (ui *UI) next(raw string) string {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return ui.base
	}
	if u.Path != ui.base && !strings.HasPrefix(u.Path, ui.base+"/") {
		return ui.base
	}
	switch strings.TrimPrefix(u.Path, ui.base) {
	case "/login", "/logout", "/reauth":
		return ui.base
	}
	return u.RequestURI()
}

var errNoSession = errors.New("adminui: no session")
