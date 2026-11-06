// Package front serves the browser (lot P5): the choice of the flow (GET and
// POST /), the return of the login apps (/oauth2/auth), Hydra's consent
// (/consent) and logout (/logout, /logout/next, P9), and the pages' static files.
// The flow engine decides; the handlers read the request, render its answer, and set
// the dispatcher_flow_csrf cookie and the dispatcher_remember one, the
// memory of the skip (P8), which they open and seal.
package front

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// Engine runs the transition of an event to its end: flow.Orchestrator.
type Engine interface {
	Handle(ctx context.Context, ev flow.Event) flow.Result
}

// Memories seals and opens the dispatcher_remember cookie: remember.Codec.
type Memories interface {
	Seal(r *flow.Remembered) (string, error)
	Open(value string) flow.Memory
}

// Snapshots gives the configuration of the moment, as store.Live does, for
// the pages the engine does not answer.
type Snapshots interface {
	Snapshot() *store.Snapshot
}

// Options configure the handlers.
type Options struct {
	Engine Engine
	Config Snapshots
	// Remember seals the memory of the skip, by secrets.cookie_key.
	Remember Memories
	// BaseURL and CookiePath are server.base_url and server.cookie_path.
	BaseURL    string
	CookiePath string
	// ShowValues is consent.show_values.
	ShowValues bool
	Logger     *slog.Logger
}

// Handler serves the pages.
type Handler struct {
	o        Options
	pages    *pages
	catalogs i18n.Catalogs
	// origin is the scheme and host of BaseURL, for the forms' origin check;
	// internal/config has them written as browsers serialize an Origin.
	origin string
	// path is the path of BaseURL without its final slash: a proxy removes
	// it before the dispatcher, the pages put it before their URLs.
	path string
	// secure cookies in HTTPS, prefixed __Host- when their path is /.
	secure bool
	prefix string
}

// maxForm bounds the body of a form: a Hydra 2.2 challenge is about 1.5 KiB.
const maxForm = 64 << 10

// Cookie names, without the __Host- prefix of HTTPS.
const (
	csrfCookie     = "dispatcher_flow_csrf"
	localeCookie   = "dispatcher_locale"
	rememberCookie = "dispatcher_remember"
)

// New parses the templates and the catalogs, and renders each page in each
// locale: a template that fails stops the start, not a login.
func New(o Options) (*Handler, error) {
	if o.Remember == nil {
		return nil, errors.New("front: no codec for the remember cookie")
	}
	catalogs, err := i18n.Embedded()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(o.BaseURL)
	if err != nil {
		return nil, err
	}
	h := &Handler{o: o, catalogs: catalogs, origin: u.Scheme + "://" + u.Host, path: strings.TrimSuffix(u.EscapedPath(), "/"), secure: u.Scheme == "https"}
	if h.secure && o.CookiePath == "/" {
		h.prefix = "__Host-"
	}
	if h.pages, err = parsePages(); err != nil {
		return nil, err
	}
	if err := h.check(); err != nil {
		return nil, err
	}
	return h, nil
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.entry)
	mux.HandleFunc("POST /{$}", h.choose)
	mux.HandleFunc("GET /oauth2/auth", h.loop)
	mux.HandleFunc("GET /consent", h.consentGet)
	mux.HandleFunc("POST /consent", h.consentPost)
	mux.HandleFunc("GET /logout", h.logoutGet)
	mux.HandleFunc("POST /logout", h.logoutPost)
	mux.HandleFunc("GET /logout/next", h.logoutNext)
	mux.HandleFunc("POST /locale/{code}", h.locale)
	mux.HandleFunc("GET /static/{name...}", h.static)
}

// entry is GET / (ENT): Hydra's login challenge, or the ref of
// x_dispatcher_restart_url.
func (h *Handler) entry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Entry{
		LoginChallenge: q.Get("login_challenge"),
		Ref:            q.Get("ref"),
		Cookie:         h.cookie(r, csrfCookie),
		Memory:         h.memory(r),
	}))
}

// choose is POST / (POS), the choice form.
func (h *Handler) choose(w http.ResponseWriter, r *http.Request) {
	if !h.form(w, r) {
		return
	}
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Choose{
		FlowID:         r.PostForm.Get("flow"),
		LoginChallenge: r.PostForm.Get("login_challenge"),
		Token:          r.PostForm.Get("csrf_token"),
		Cookie:         h.cookie(r, csrfCookie),
		SameOrigin:     h.sameOrigin(r),
	}))
}

// loop is GET /oauth2/auth (BCL), where the step accepts send the browser
// back.
func (h *Handler) loop(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Loop{
		Ref:            q.Get("ref"),
		LoginChallenge: q.Get("login_challenge"),
		Cookie:         h.cookie(r, csrfCookie),
	}))
}

// consentGet is GET /consent (CST).
func (h *Handler) consentGet(w http.ResponseWriter, r *http.Request) {
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Consent{
		Challenge: r.URL.Query().Get("consent_challenge"),
		Cookie:    h.cookie(r, csrfCookie),
		Memory:    h.memory(r),
	}))
}

// consentPost is POST /consent, the consent screen's answer: accept, or any
// other button refuses. Without a flow, its form carries the print of the
// claims shown (SKC-3, Q37).
func (h *Handler) consentPost(w http.ResponseWriter, r *http.Request) {
	if !h.form(w, r) {
		return
	}
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Consent{
		Challenge:  r.PostForm.Get("consent_challenge"),
		Cookie:     h.cookie(r, csrfCookie),
		Post:       true,
		Accept:     r.PostForm.Get("action") == "accept",
		Token:      r.PostForm.Get("csrf_token"),
		Print:      r.PostForm.Get("claims_print"),
		Memory:     h.memory(r),
		SameOrigin: h.sameOrigin(r),
	}))
}

// form reads the body of a form, at most maxForm; an unreadable one is an
// invalid challenge (E1001).
func (h *Handler) form(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, flow.Response{Kind: flow.ErrorPage, Code: flow.E1001}, h.o.Config.Snapshot())
		return false
	}
	return true
}

// sameOrigin tells whether a form comes from the dispatcher's own pages:
// Sec-Fetch-Site same-origin or none (typed in), else an Origin of the
// dispatcher's. Without either, it does not.
func (h *Handler) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	return r.Header.Get("Origin") == h.origin
}

// cookie returns the value of the dispatcher's cookie name, "" without one.
func (h *Handler) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(h.prefix + name)
	if err != nil {
		return ""
	}
	return c.Value
}

// memory opens the dispatcher_remember cookie of r (MEM-1, MEM-2).
func (h *Handler) memory(r *http.Request) flow.Memory {
	return h.o.Remember.Open(h.cookie(r, rememberCookie))
}

// remember writes the memory of the skip the engine gives (WRT-1), or the note
// of logout that replaces it (WRT-4): one cookie, living until its exp, of the
// browser's session for exp 0. Beyond
// 3.8 KB, none is written and the former one is cleared, which would serve
// the next skip with former claims (WRT-2); never a second cookie, the
// Cookie header staying under a reverse proxy's 8 KB (revue R20).
func (h *Handler) remember(w http.ResponseWriter, r *http.Request, m *flow.Remembered) {
	value, err := h.o.Remember.Seal(m)
	if err != nil {
		h.forget(w)
		h.o.Logger.InfoContext(r.Context(), "skip.unavailable", "detail", err.Error())
		return
	}
	var maxAge time.Duration // 0: a cookie of the browser's session
	if m.Exp > 0 {
		maxAge = time.Duration(m.Exp-m.IAT) * time.Second
	}
	h.setCookie(w, rememberCookie, value, maxAge, true)
}

// forget clears the dispatcher_remember cookie (WRT-2).
func (h *Handler) forget(w http.ResponseWriter) {
	h.setCookie(w, rememberCookie, "", -1, true)
}

// setCookie sets the dispatcher's cookie name for maxAge, rounded down to the
// second: 0 is a cookie of the browser's session, a negative one clears it.
func (h *Handler) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, httpOnly bool) {
	seconds := int(maxAge / time.Second)
	if maxAge < 0 {
		seconds = -1 // Max-Age=0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.prefix + name,
		Value:    value,
		Path:     h.o.CookiePath,
		MaxAge:   seconds,
		HttpOnly: httpOnly,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// respond writes the engine's answer: a redirection (303), a page, or an
// error page. The CSRF cookie set lives challenge_ttl, extended at each flow
// created (A4).
func (h *Handler) respond(w http.ResponseWriter, r *http.Request, res flow.Result) {
	resp, cfg := res.Response, res.Config
	if cfg == nil {
		cfg = h.o.Config.Snapshot()
	}
	w.Header().Set("Cache-Control", "no-store")
	if resp.SetCSRF != "" {
		h.setCookie(w, csrfCookie, resp.SetCSRF, cfg.Settings.ChallengeTTL, true)
	}
	if resp.Remember != nil {
		h.remember(w, r, resp.Remember)
	}
	switch resp.Kind {
	case flow.Redirect:
		http.Redirect(w, r, resp.URL, http.StatusSeeOther)
	case flow.ChoicePage:
		h.render(w, r, http.StatusOK, "select", h.choicePage(r, cfg, resp.Choice))
	case flow.ConsentPage:
		h.render(w, r, http.StatusOK, "consent", h.consentPage(r, cfg, resp.Consent))
	case flow.LogoutPage:
		h.render(w, r, http.StatusOK, "logout", h.logoutPage(r, cfg, resp.Logout))
	case flow.ErrorPage:
		h.fail(w, r, resp, cfg)
	default:
		// The engine answering the emulated API to a page: a bug.
		h.fail(w, r, flow.Response{Kind: flow.ErrorPage, Code: flow.E1000}, cfg)
	}
}

// statuses are those of the error codes (Observabilité, codes d'erreur).
var statuses = map[flow.Code]int{
	flow.E1000: http.StatusInternalServerError,
	flow.E1001: http.StatusBadRequest,
	flow.E1002: http.StatusBadRequest,
	flow.E1003: http.StatusBadRequest,
	flow.E1004: http.StatusBadGateway,
	flow.E1005: http.StatusInternalServerError,
	flow.E1006: http.StatusBadGateway,
	flow.E1007: http.StatusInternalServerError,
	flow.E1008: http.StatusForbidden,
}

// fail renders the error page of resp: its code's status, or 503 with
// Retry-After when Hydra was saturated (hydra.max_in_flight).
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, resp flow.Response, cfg *store.Snapshot) {
	status, ok := statuses[resp.Code]
	if !ok {
		resp.Code, status = flow.E1000, http.StatusInternalServerError
	}
	if resp.Overloaded {
		w.Header().Set("Retry-After", "1")
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	p := h.page(r, cfg, nil)
	p.Error = &pageError{Code: string(resp.Code), MessageKey: "error." + string(resp.Code), TraceID: httpx.TraceID(r.Context()), Link: resp.Link, SignOut: resp.SignOut}
	h.render(w, r, status, "error", p)
}

// logoutGet is GET /logout (LGO): the confirmation, or the accept at once of a
// client's demand. A HEAD, which the pattern covers, neither calls nor writes
// nothing, a logout otherwise leaving on a HEAD (LGO-17, Q57).
func (h *Handler) logoutGet(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.Header().Set("Cache-Control", "no-store")
		return
	}
	if preloaded(r) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		return // LGO-18
	}
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Logout{
		Challenge: r.URL.Query().Get("logout_challenge"),
		Cookie:    h.cookie(r, csrfCookie),
		Memory:    h.memory(r),
	}))
}

// preloaded tells a browser's preload from a visit (LGO-18, Q59): Sec-Purpose on a
// prefetch or a prerender, Purpose on those of the browsers before it. A client's
// demand has no page: answered, the preload would run the whole chain, without a
// click. A browser drops a 503, and asks again when the link is followed.
func preloaded(r *http.Request) bool {
	return r.Header.Get("Sec-Purpose") != "" || r.Header.Get("Purpose") == "prefetch"
}

// logoutPost is POST /logout, the confirmation's answer: accept, or any other
// button refuses.
func (h *Handler) logoutPost(w http.ResponseWriter, r *http.Request) {
	if !h.form(w, r) {
		return
	}
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.Logout{
		Challenge:  r.PostForm.Get("logout_challenge"),
		Cookie:     h.cookie(r, csrfCookie),
		Memory:     h.memory(r),
		Post:       true,
		Accept:     r.PostForm.Get("action") == "accept",
		Token:      r.PostForm.Get("csrf_token"),
		SameOrigin: h.sameOrigin(r),
	}))
}

// logoutNext is GET /logout/next (SUI), where the apps send the browser back.
func (h *Handler) logoutNext(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.Header().Set("Cache-Control", "no-store")
		return // LGO-17
	}
	h.respond(w, r, h.o.Engine.Handle(r.Context(), flow.LogoutNext{Ref: r.URL.Query().Get("ref")}))
}

// pagePaths are the paths of the pages, below the base path: the change of
// language goes back to them only.
var pagePaths = []string{"/", "/oauth2/auth", "/consent", "/logout"}

// back returns the page raw names, as a path below the base path with its
// query, without the _locale that would win over the cookie. raw is a path
// (the return field of the language form, which the page writes) or an
// absolute URL of the dispatcher's origin (the Referer). Anything else gives
// false: a URL of another origin, a path that is not a page's (/logout/next,
// /static), a scheme-relative //host, a backslash that some browsers read as
// a slash, a user. The way back is then built on the dispatcher's own origin:
// the input never chooses the host (Sécurité, Redirections).
func (h *Handler) back(raw string) (string, bool) {
	if raw == "" || strings.Contains(raw, "\\") {
		return "", false
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.User != nil || u.Opaque != "":
		return "", false
	case u.Scheme == "" && u.Host == "":
		if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
			return "", false
		}
	case u.Scheme+"://"+u.Host != h.origin:
		return "", false
	}
	p, ok := strings.CutPrefix(u.EscapedPath(), h.path)
	if !ok || !slices.Contains(pagePaths, p) {
		return "", false
	}
	q := u.Query()
	q.Del("_locale")
	if len(q) == 0 {
		return h.path + p, true
	}
	return h.path + p + "?" + q.Encode(), true
}

// locale is POST /locale/{code}: the dispatcher_locale cookie, for a year,
// then back to the page the form's return field names, else to the page of
// the Referer, else to the pages' root. A form from elsewhere changes
// nothing (E1008).
func (h *Handler) locale(w http.ResponseWriter, r *http.Request) {
	cfg := h.o.Config.Snapshot()
	if !h.sameOrigin(r) {
		h.fail(w, r, flow.Response{Kind: flow.ErrorPage, Code: flow.E1008}, cfg)
		return
	}
	if !h.form(w, r) {
		return
	}
	if code := r.PathValue("code"); h.supported(cfg, code) {
		h.setCookie(w, localeCookie, code, 365*24*time.Hour, false)
	}
	to := h.path + "/"
	if back, ok := h.back(r.PostForm.Get("return")); ok {
		to = back
	} else if back, ok := h.back(r.Referer()); ok {
		to = back
	}
	to = h.origin + to
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusSeeOther)
}
