package front

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	ory "github.com/ory/hydra-client-go/v26"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/web"
)

// pageNames are the pages, each parsed with the layout and the partials.
var pageNames = []string{"select", "consent", "error", "logout"}

type pages struct {
	templates map[string]*template.Template
	// hashes are those of the static files, for their URLs.
	hashes map[string]string
}

func parsePages() (*pages, error) {
	p := &pages{templates: map[string]*template.Template{}, hashes: map[string]string{}}
	for _, name := range pageNames {
		t, err := template.ParseFS(web.FS, "templates/layout.html.tmpl", "templates/partials/*.html.tmpl", "templates/"+name+".html.tmpl")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		p.templates[name] = t
	}
	// The static files and those of its directories (flags/, images/,
	// fonts/ of the theme's tree), by their path under static/.
	err := fs.WalkDir(web.FS, "static", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(web.FS, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		p.hashes[strings.TrimPrefix(name, "static/")] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// page is the data of every page (Thèmes, contrat de données, api: 1). Its
// methods are the functions of the templates: T, Asset, Flag and LocaleURL
// depend on the page's locale or base path, which html/template's
// functions, bound at parse time, would not see.
type page struct {
	h        *Handler
	Locale   string
	fallback string
	// Return is the page the change of language goes back to, "" on a page
	// it does not go back to (see Handler.back).
	Return string
	// missing, set while check renders the pages, records the keys a
	// catalog lacks.
	missing  map[[2]string]bool
	Locales  []localeChoice
	Client   client
	Flows    []flowCard
	Scopes   []scopeGroup
	Audience []string
	Error    *pageError
	Form     form
	Logout   logoutData
}

type localeChoice struct {
	Code, Label, Action, Flag string
	Current                   bool
}

type client struct{ Name, LogoURI, ClientURI, PolicyURI, TosURI string }

type flowCard struct {
	ID, Title, Description, IconURL string
	Selected                        bool
}

type scopeGroup struct {
	Label  string
	Claims []claimLine
}

type claimLine struct{ Label, Value string }

type pageError struct{ Code, MessageKey, TraceID, Link string }

// form is what a page's form posts back. Print is the print of the claims a
// consent screen without a flow shows (SKC-2, Q37), "" on a flow's.
type form struct{ Action, LoginChallenge, ConsentChallenge, LogoutChallenge, CSRF, Print string }

// logoutData is what the logout page says: confirm, declined, in_progress or
// already_out, the text for a demand on another session (LGO-7), and the link to
// take a chain up again (LGO-14).
type logoutData struct {
	State        string
	OtherSession bool
	Next         string
}

// T translates key in the page's locale.
func (p page) T(key string, args ...any) string {
	p.note(p.Locale, key)
	return p.h.catalogs.T(p.Locale, p.fallback, key, args...)
}

// note records key when the catalog of locale lacks it, while check renders
// the pages: the page would show it in the fallback locale, or the key
// itself.
func (p page) note(locale, key string) {
	if p.missing != nil && !p.h.catalogs.Has(locale, key) {
		p.missing[[2]string{locale, key}] = true
	}
}

// labelled tells whether key has a text, in the page's locale or in the
// fallback one.
func (p page) labelled(key string) bool {
	return p.h.catalogs.Has(p.Locale, key) || p.h.catalogs.Has(p.fallback, key)
}

// Asset is the URL of a static file, its hash in the query; "" when there is
// no such file, for the optional ones (theme.js, a flag).
func (p page) Asset(name string) string {
	hash, ok := p.h.pages.hashes[name]
	if !ok {
		return ""
	}
	return p.h.path + "/static/" + name + "?v=" + hash
}

// Flag is the URL of the flag of locale, flags/<locale>.svg; "" without it,
// as in the embedded theme.
func (p page) Flag(locale string) string { return p.Asset("flags/" + locale + ".svg") }

// LocaleURL is where the form of the change of language to locale posts.
func (p page) LocaleURL(locale string) string { return p.h.path + "/locale/" + locale }

// supported are the locales of the settings the catalogs hold.
func (h *Handler) supportedLocales(cfg *store.Snapshot) []string {
	var out []string
	for _, l := range cfg.Settings.SupportedLocales {
		if _, ok := h.catalogs[l]; ok {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = h.catalogs.Locales()
	}
	return out
}

func (h *Handler) supported(cfg *store.Snapshot, code string) bool {
	return slices.Contains(h.supportedLocales(cfg), code)
}

// page returns the data shared by the pages, in the locale negotiated.
func (h *Handler) page(r *http.Request, cfg *store.Snapshot, uiLocales []string) page {
	supported := h.supportedLocales(cfg)
	def := cfg.Settings.DefaultLocale
	if !slices.Contains(supported, def) {
		def = supported[0]
	}
	p := page{h: h, fallback: cfg.Settings.FallbackLocale}
	p.missing, _ = r.Context().Value(checking{}).(map[[2]string]bool)
	p.Locale = i18n.Negotiate(r.URL.Query().Get("_locale"), h.cookie(r, localeCookie), uiLocales, supported, def)
	// The URL the browser shows, the proxy's prefix put back.
	p.Return, _ = h.back(h.path + r.URL.RequestURI())
	for _, l := range supported {
		p.note(l, "locale."+l)
		p.Locales = append(p.Locales, localeChoice{Code: l, Label: h.catalogs.T(l, p.fallback, "locale."+l), Action: p.LocaleURL(l), Flag: p.Flag(l), Current: l == p.Locale})
	}
	return p
}

// choicePage is the page of the choice of the flow (CHX-5, POS-2). Its form
// posts to the URL of GET /, which the browser keeps for the page a POST
// shows again (POS-2, POS-3): the change of language goes back to it.
func (h *Handler) choicePage(r *http.Request, cfg *store.Snapshot, c *flow.ChoiceScreen) page {
	p := h.page(r, cfg, c.UILocales)
	p.Client = clientOf(c.Client)
	p.Form = form{Action: h.path + "/?login_challenge=" + url.QueryEscape(c.LoginChallenge), LoginChallenge: c.LoginChallenge, CSRF: c.CSRF}
	if c.Invalid {
		p.Error = &pageError{MessageKey: "choice.invalid"}
	}
	for _, id := range c.Flows {
		i := slices.IndexFunc(cfg.Flows, func(f store.Flow) bool { return f.ID == id })
		if i < 0 {
			continue
		}
		f := cfg.Flows[i]
		p.Flows = append(p.Flows, flowCard{ID: id, Title: localized(f.Title, p.Locale, p.fallback, id),
			Description: localized(f.Description, p.Locale, p.fallback, ""), IconURL: localized(f.IconURL, p.Locale, p.fallback, "")})
	}
	return p
}

// localized resolves a text in the locale, then the fallback one, then the
// first locale holding one, else def.
func localized(texts map[string]string, locale, fallback, def string) string {
	for _, l := range []string{locale, fallback} {
		if t := texts[l]; t != "" {
			return t
		}
	}
	for _, l := range slices.Sorted(maps.Keys(texts)) {
		if texts[l] != "" {
			return texts[l]
		}
	}
	return def
}

func clientOf(data json.RawMessage) client {
	var c struct {
		ID        string `json:"client_id"`
		Name      string `json:"client_name"`
		LogoURI   string `json:"logo_uri"`
		ClientURI string `json:"client_uri"`
		PolicyURI string `json:"policy_uri"`
		TosURI    string `json:"tos_uri"`
	}
	_ = json.Unmarshal(data, &c)
	if c.Name == "" {
		c.Name = c.ID
	}
	return client{Name: c.Name, LogoURI: c.LogoURI, ClientURI: c.ClientURI, PolicyURI: c.PolicyURI, TosURI: c.TosURI}
}

// standardScopes are the OpenID Connect scopes and their claims, built in
// for phase 1 (Page de consent).
var standardScopes = map[string][]string{
	"openid":  {"sub"},
	"profile": {"name", "family_name", "given_name", "preferred_username", "locale"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// consentPage is the consent screen (CST-13): the scopes asked with the
// claims of the flow they cover, then the other claims, sent too
// (claims_filter permissive). What is shown is what is sent: the claims of
// the id_token and of the access token, and the subject, sub of both. Its
// form posts to the URL of GET /consent, as the choice page does.
func (h *Handler) consentPage(r *http.Request, cfg *store.Snapshot, c *flow.ConsentScreen) page {
	p := h.page(r, cfg, c.UILocales)
	if c.Client != nil {
		data, _ := json.Marshal(c.Client)
		p.Client = clientOf(data)
	}
	p.Form = form{Action: h.path + "/consent?consent_challenge=" + url.QueryEscape(c.Challenge), ConsentChallenge: c.Challenge, CSRF: c.CSRF, Print: c.Print}
	p.Audience = c.Audience
	sent := sentClaims(c)
	covered := map[string]bool{}
	for _, s := range c.Scopes {
		var g scopeGroup
		claims, known := standardScopes[s]
		if known {
			g.Label = p.T("scope." + s)
		} else {
			g.Label = p.T("scope.generic", s)
		}
		for _, name := range claims {
			if values, ok := sent[name]; ok {
				covered[name] = true
				g.Claims = append(g.Claims, h.claim(p, name, values))
			}
		}
		p.Scopes = append(p.Scopes, g)
	}
	other := scopeGroup{Label: p.T("consent.other")}
	for _, name := range slices.Sorted(maps.Keys(sent)) {
		if !covered[name] {
			other.Claims = append(other.Claims, h.claim(p, name, sent[name]))
		}
	}
	if len(other.Claims) > 0 {
		p.Scopes = append(p.Scopes, other)
	}
	return p
}

// logoutStates name the states of the logout page, in its data.
var logoutStates = map[flow.LogoutState]string{
	flow.LogoutConfirm:    "confirm",
	flow.LogoutDeclined:   "declined",
	flow.LogoutInProgress: "in_progress",
	flow.LogoutAlreadyOut: "already_out",
}

// logoutPage is the logout page (LGO): the confirmation posts to the URL of GET
// /logout, for an error page to keep its way back to the language; after a
// refusal, an answer to a POST, the same template has no form nor switcher, for
// it has no URL to go back to.
func (h *Handler) logoutPage(r *http.Request, cfg *store.Snapshot, l *flow.LogoutScreen) page {
	p := h.page(r, cfg, nil)
	if l.Client != nil {
		data, _ := json.Marshal(l.Client)
		p.Client = clientOf(data)
	}
	p.Logout = logoutData{State: logoutStates[l.State], OtherSession: l.OtherSession, Next: l.Next}
	if l.State == flow.LogoutConfirm {
		p.Form = form{Action: h.path + "/logout?logout_challenge=" + url.QueryEscape(l.Challenge), LogoutChallenge: l.Challenge, CSRF: l.CSRF}
		return p
	}
	p.Locales, p.Return = nil, ""
	return p
}

// sentClaims are the claims the consent sends, by name, each with its
// values: the subject, as sub, then those of the id_token and of the access
// token, a value both send only once.
func sentClaims(c *flow.ConsentScreen) map[string][]json.RawMessage {
	sent := map[string][]json.RawMessage{}
	add := func(name string, v json.RawMessage) {
		if !slices.ContainsFunc(sent[name], func(w json.RawMessage) bool { return bytes.Equal(w, v) }) {
			sent[name] = append(sent[name], v)
		}
	}
	if c.Subject != "" {
		sub, _ := json.Marshal(c.Subject)
		add("sub", sub)
	}
	for _, claims := range []flow.Object{c.Claims, c.AccessClaims} {
		for _, name := range slices.Sorted(maps.Keys(claims)) {
			add(name, claims[name])
		}
	}
	return sent
}

// claim is the line of a claim: its label, or its name when the catalogs
// have none, and with consent.show_values its values, a string as it is,
// anything else in JSON.
func (h *Handler) claim(p page, name string, values []json.RawMessage) claimLine {
	l := claimLine{Label: name}
	if key := "claim." + name; p.labelled(key) {
		l.Label = p.T(key)
	}
	if h.o.ShowValues {
		shown := make([]string, 0, len(values))
		for _, v := range values {
			var s string
			if json.Unmarshal(v, &s) != nil {
				s = string(v)
			}
			shown = append(shown, s)
		}
		l.Value = strings.Join(shown, " · ")
	}
	return l
}

// render writes the page, rendered first: a template that fails gives a
// 500, never half a page.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	var buf bytes.Buffer
	if err := h.pages.templates[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		h.o.Logger.ErrorContext(r.Context(), "http.render_failed", "page", name, "err", err)
		http.Error(w, "internal error, trace id "+httpx.TraceID(r.Context()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// checking marks the requests of check: their pages record the keys a
// catalog lacks.
type checking struct{}

// The sample challenge, token and print of the claims of check's forms.
const (
	sampleChallenge = "c2FtcGxlX2NoYWxsZW5nZQ=="
	sampleCSRF      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	samplePrint     = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// check renders each page in each locale with sample data, through each
// branch of the templates (Thèmes, validation). A template that fails, a
// key a catalog lacks, or a form without the fields the handlers read stops
// the start, not a login.
func (h *Handler) check() error {
	cfg := h.sampleConfig()
	settings := cfg.Settings
	missing := map[[2]string]bool{}
	var errs []error
	for _, l := range settings.SupportedLocales {
		r, _ := http.NewRequestWithContext(context.WithValue(context.Background(), checking{}, missing), http.MethodGet, "/?_locale="+url.QueryEscape(l), nil)
		for _, s := range h.samples(r, cfg) {
			var buf bytes.Buffer
			err := h.pages.templates[s.name].ExecuteTemplate(&buf, "layout", s.page)
			if err == nil {
				err = formFields(buf.Bytes(), s.fields)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("page %s (%s) in %s: %w", s.name, s.what, l, err))
			}
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(missing), func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) }) {
		errs = append(errs, fmt.Errorf("catalog %s: no text for %s", k[0], k[1]))
	}
	return errors.Join(errs...)
}

// sampleConfig is the configuration of check's pages: a flow, each catalog's
// locale supported.
func (h *Handler) sampleConfig() *store.Snapshot {
	settings := store.DefaultSettings()
	settings.SupportedLocales = h.catalogs.Locales()
	settings.DefaultLocale = settings.SupportedLocales[0]
	return store.NewSnapshot(nil, []store.Flow{{ID: "f", Enabled: true, Title: map[string]string{settings.DefaultLocale: "F"}, Description: map[string]string{settings.DefaultLocale: "D"},
		IconURL: map[string]string{settings.DefaultLocale: "https://flow.example/icon.svg"}}}, settings)
}

// sample is a page check renders, with the fields its form must carry and
// their values ("" for any).
type sample struct {
	name, what string
	page       page
	fields     map[string]string
}

func (h *Handler) samples(r *http.Request, cfg *store.Snapshot) []sample {
	client := json.RawMessage(`{"client_id":"c","client_name":"Client","logo_uri":"https://client.example/logo.png","client_uri":"https://client.example/"}`)
	scopes := slices.Sorted(maps.Keys(standardScopes))
	claims := flow.Object{"custom": json.RawMessage(`["v"]`)}
	for _, s := range scopes {
		for _, c := range standardScopes[s] {
			claims[c] = json.RawMessage(`"v"`)
		}
	}
	consent := &flow.ConsentScreen{Challenge: sampleChallenge, CSRF: sampleCSRF, Client: &ory.OAuth2Client{ClientId: ory.PtrString("c"), ClientName: ory.PtrString("Client")},
		Scopes: append(scopes, "custom"), Audience: []string{"https://api.example/"}, Subject: "s", Claims: claims, AccessClaims: flow.Object{"roles": json.RawMessage(`["admin"]`)}}
	choiceFields := map[string]string{"flow": "f", "login_challenge": sampleChallenge, "csrf_token": sampleCSRF}
	consentFields := map[string]string{"consent_challenge": sampleChallenge, "csrf_token": sampleCSRF, "action": "accept"}
	logoutFields := map[string]string{"logout_challenge": sampleChallenge, "csrf_token": sampleCSRF, "action": "accept"}
	out := []sample{
		{"select", "flows, one refused", h.choicePage(r, cfg, &flow.ChoiceScreen{Flows: []string{"f"}, LoginChallenge: sampleChallenge, CSRF: sampleCSRF, Client: client, Invalid: true}), choiceFields},
		{"select", "no flow", h.choicePage(r, cfg, &flow.ChoiceScreen{LoginChallenge: sampleChallenge, CSRF: sampleCSRF}), nil},
		{"consent", "scopes, claims, audience", h.consentPage(r, cfg, consent), consentFields},
		{"consent", "nothing asked", h.consentPage(r, cfg, &flow.ConsentScreen{Challenge: sampleChallenge, CSRF: sampleCSRF}), consentFields},
		{"consent", "without a flow", h.consentPage(r, cfg, &flow.ConsentScreen{Challenge: sampleChallenge, CSRF: sampleCSRF, Print: samplePrint, Subject: "s", Claims: flow.Object{"email": json.RawMessage(`"v"`)}}),
			map[string]string{"consent_challenge": sampleChallenge, "csrf_token": sampleCSRF, "action": "accept", "claims_print": samplePrint}},
		{"logout", "confirm", h.logoutPage(r, cfg, &flow.LogoutScreen{State: flow.LogoutConfirm, Challenge: sampleChallenge, CSRF: sampleCSRF}), logoutFields},
		{"logout", "other session", h.logoutPage(r, cfg, &flow.LogoutScreen{State: flow.LogoutConfirm, Challenge: sampleChallenge, CSRF: sampleCSRF, OtherSession: true, Client: &ory.OAuth2Client{ClientId: ory.PtrString("c"), ClientName: ory.PtrString("Client")}}), logoutFields},
		{"logout", "declined", h.logoutPage(r, cfg, &flow.LogoutScreen{State: flow.LogoutDeclined}), nil},
		{"logout", "in progress", h.logoutPage(r, cfg, &flow.LogoutScreen{State: flow.LogoutInProgress, Next: "/logout/next?ref=0"}), nil},
		{"logout", "already out", h.logoutPage(r, cfg, &flow.LogoutScreen{State: flow.LogoutAlreadyOut}), nil},
	}
	for _, code := range slices.Sorted(maps.Keys(statuses)) {
		for _, link := range []string{"", "https://client.example/"} {
			p := h.page(r, cfg, nil)
			p.Error = &pageError{Code: string(code), MessageKey: "error." + string(code), TraceID: "0123456789abcdef0123456789abcdef", Link: link}
			out = append(out, sample{name: "error", what: string(code), page: p})
		}
	}
	return out
}

// formFields checks that the page's form fields (input, button, select,
// textarea) carry each name of want, with its value when one is given.
func formFields(page []byte, want map[string]string) error {
	got := map[string][]string{}
	d := xml.NewDecoder(bytes.NewReader(page))
	d.Strict, d.AutoClose, d.Entity = false, xml.HTMLAutoClose, xml.HTMLEntity
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("unreadable HTML: %w", err)
		}
		if e, ok := tok.(xml.StartElement); ok && slices.Contains([]string{"input", "button", "select", "textarea"}, e.Name.Local) {
			var name, value string
			for _, a := range e.Attr {
				switch a.Name.Local {
				case "name":
					name = a.Value
				case "value":
					value = a.Value
				}
			}
			got[name] = append(got[name], value)
		}
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(want)) {
		switch values, ok := got[name]; {
		case !ok:
			errs = append(errs, fmt.Errorf("no field %s", name))
		case want[name] != "" && !slices.Contains(values, want[name]):
			errs = append(errs, fmt.Errorf("field %s without the value %q", name, want[name]))
		}
	}
	return errors.Join(errs...)
}

// static serves a static file, cached for a year when its URL carries its
// hash. fs.ReadFile refuses a name that would leave static/ (.., an empty
// element).
func (h *Handler) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	data, err := fs.ReadFile(web.FS, "static/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if v := r.URL.Query().Get("v"); v != "" && v == h.pages.hashes[name] {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		w.Header().Set("Content-Type", t)
	}
	_, _ = w.Write(data)
}
