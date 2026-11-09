package front

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	ory "github.com/ory/hydra-client-go/v26"
	"golang.org/x/net/html"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// page is the data of every page (Thèmes, contrat de données, api: 1). Its
// methods are the functions of the templates: T, Asset, Flag and LocaleURL
// depend on the page's locale or base path, which html/template's
// functions, bound at parse time, would not see.
type page struct {
	h *Handler
	// th is the theme the page is rendered with, from its texts to its
	// template.
	th       *Theme
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

type pageError struct{ Code, MessageKey, TraceID, Link, SignOut string }

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
	return p.th.catalogs.T(p.Locale, p.fallback, key, args...)
}

// note records key when the catalog of locale lacks it, while check renders
// the pages: the page would show it in the fallback locale, or the key
// itself.
func (p page) note(locale, key string) {
	if p.missing != nil && !p.th.catalogs.Has(locale, key) {
		p.missing[[2]string{locale, key}] = true
	}
}

// labelled tells whether key has a text, in the page's locale or in the
// fallback one.
func (p page) labelled(key string) bool {
	return p.th.catalogs.Has(p.Locale, key) || p.th.catalogs.Has(p.fallback, key)
}

// Asset is the URL of a static file, its hash in the query; "" when there is
// no such file, for the optional ones (theme.js, a flag).
func (p page) Asset(name string) string {
	f, ok := p.th.statics[name]
	if !ok {
		return ""
	}
	return p.h.path + "/static/" + name + "?v=" + f.hash
}

// Flag is the URL of the flag of locale, flags/<locale>.svg; "" without it,
// as in the embedded theme.
func (p page) Flag(locale string) string { return p.Asset("flags/" + locale + ".svg") }

// LocaleURL is where the form of the change of language to locale posts.
func (p page) LocaleURL(locale string) string { return p.h.path + "/locale/" + locale }

// supportedLocales are the locales of the settings the theme has a catalog
// for, all of its own when it has none of them (Q92).
func supportedLocales(th *Theme, cfg *store.Snapshot) []string {
	var out []string
	for _, l := range cfg.Settings.SupportedLocales {
		if _, ok := th.catalogs[l]; ok {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = th.catalogs.Locales()
	}
	return out
}

// LocaleWarnings name the locales of settings the theme has no catalog for:
// the pages set them aside (Q92).
func LocaleWarnings(th *Theme, settings store.Settings) []string {
	var out []string
	missing := func(key, l, then string) {
		if _, ok := th.catalogs[l]; !ok {
			out = append(out, fmt.Sprintf("setting %s: %q has no catalog in the theme (%s): %s", key, l, strings.Join(th.Locales(), ", "), then))
		}
	}
	for _, l := range settings.SupportedLocales {
		missing("supported_locales", l, "the pages do not offer it")
	}
	missing("default_locale", settings.DefaultLocale, "the pages take the first locale they offer")
	missing("fallback_locale", settings.FallbackLocale, "a text missing from a page's locale shows its key")
	return out
}

// page returns the data shared by the pages, in the locale negotiated, with
// the theme th.
func (h *Handler) page(r *http.Request, th *Theme, cfg *store.Snapshot, uiLocales []string) page {
	supported := supportedLocales(th, cfg)
	def := cfg.Settings.DefaultLocale
	if !slices.Contains(supported, def) {
		def = supported[0]
	}
	p := page{h: h, th: th, fallback: cfg.Settings.FallbackLocale}
	p.missing, _ = r.Context().Value(checking{}).(map[[2]string]bool)
	p.Locale = i18n.Negotiate(r.URL.Query().Get("_locale"), h.cookie(r, localeCookie), uiLocales, supported, def)
	// The URL the browser shows, the proxy's prefix put back.
	p.Return, _ = h.back(h.path + r.URL.RequestURI())
	for _, l := range supported {
		p.note(l, "locale."+l)
		p.Locales = append(p.Locales, localeChoice{Code: l, Label: th.catalogs.T(l, p.fallback, "locale."+l), Action: p.LocaleURL(l), Flag: p.Flag(l), Current: l == p.Locale})
	}
	return p
}

// choicePage is the page of the choice of the flow (CHX-5, POS-2). Its form
// posts to the URL of GET /, which the browser keeps for the page a POST
// shows again (POS-2, POS-3): the change of language goes back to it.
func (h *Handler) choicePage(r *http.Request, th *Theme, cfg *store.Snapshot, c *flow.ChoiceScreen) page {
	p := h.page(r, th, cfg, c.UILocales)
	p.Client = clientOf(c.Client)
	p.Form = form{Action: h.path + "/?login_challenge=" + url.QueryEscape(c.LoginChallenge), LoginChallenge: c.LoginChallenge, CSRF: c.CSRF}
	if c.Invalid {
		p.Error = &pageError{MessageKey: "choice.invalid"}
	}
	// The flows offered are those allowed for this client and acr_values: a cookie that
	// names another selects nothing.
	last := ""
	if h.o.RememberLastFlow {
		last = h.cookie(r, lastFlowCookie)
	}
	for _, id := range c.Flows {
		i := slices.IndexFunc(cfg.Flows, func(f store.Flow) bool { return f.ID == id })
		if i < 0 {
			continue
		}
		f := cfg.Flows[i]
		p.Flows = append(p.Flows, flowCard{ID: id, Selected: id == last, Title: localized(f.Title, p.Locale, p.fallback, id),
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
// the id_token and of the access token, and the subject, sub of both; their
// values with show, consent.show_values. Its form posts to the URL of GET
// /consent, as the choice page does.
func (h *Handler) consentPage(r *http.Request, th *Theme, cfg *store.Snapshot, c *flow.ConsentScreen, show bool) page {
	p := h.page(r, th, cfg, c.UILocales)
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
				g.Claims = append(g.Claims, claim(p, name, values, show))
			}
		}
		p.Scopes = append(p.Scopes, g)
	}
	other := scopeGroup{Label: p.T("consent.other")}
	for _, name := range slices.Sorted(maps.Keys(sent)) {
		if !covered[name] {
			other.Claims = append(other.Claims, claim(p, name, sent[name], show))
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
func (h *Handler) logoutPage(r *http.Request, th *Theme, cfg *store.Snapshot, l *flow.LogoutScreen) page {
	p := h.page(r, th, cfg, nil)
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
// have none, and with show its values, a string as it is, anything else in
// JSON.
func claim(p page, name string, values []json.RawMessage, show bool) claimLine {
	l := claimLine{Label: name}
	if key := "claim." + name; p.labelled(key) {
		l.Label = p.T(key)
	}
	if show {
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
	if err := p.th.templates[name].ExecuteTemplate(&buf, "layout", p); err != nil {
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

// check renders each page of th in each locale with sample data, through each
// branch of the templates (Thèmes, validation). A template that fails, a
// key a catalog lacks, a form without the fields the handlers read, or code
// the CSP would block stops the start, not a login.
func (h *Handler) check(th *Theme) error {
	cfg := sampleConfig(th)
	missing := map[[2]string]bool{}
	var errs []error
	// The code the CSP blocks, once a page, whatever its locales and branches.
	blocked := map[string]bool{}
	for _, l := range cfg.Settings.SupportedLocales {
		r, _ := http.NewRequestWithContext(context.WithValue(context.Background(), checking{}, missing), http.MethodGet, "/?_locale="+url.QueryEscape(l), nil)
		for _, s := range h.samples(r, th, cfg) {
			var buf bytes.Buffer
			err := th.templates[s.name].ExecuteTemplate(&buf, "layout", s.page)
			if err == nil {
				err = formFields(buf.Bytes(), s.fields)
				for _, b := range inlineCode(buf.Bytes()) {
					blocked[fmt.Sprintf("page %s: %s", s.name, b)] = true
				}
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("page %s (%s) in %s: %w", s.name, s.what, l, err))
			}
		}
	}
	for _, b := range slices.Sorted(maps.Keys(blocked)) {
		errs = append(errs, errors.New(b))
	}
	for _, k := range slices.SortedFunc(maps.Keys(missing), func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) }) {
		errs = append(errs, fmt.Errorf("catalog %s: no text for %s", k[0], k[1]))
	}
	return errors.Join(errs...)
}

// sampleConfig is the configuration of check's pages: a flow, each locale of
// the theme's catalogs supported.
func sampleConfig(th *Theme) *store.Snapshot {
	settings := store.DefaultSettings()
	settings.SupportedLocales = th.Locales()
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

func (h *Handler) samples(r *http.Request, th *Theme, cfg *store.Snapshot) []sample {
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
	// The last flow, preselected (ui.remember_last_flow).
	selected := h.choicePage(r, th, cfg, &flow.ChoiceScreen{Flows: []string{"f"}, LoginChallenge: sampleChallenge, CSRF: sampleCSRF, Client: client})
	selected.Flows[0].Selected = true
	out := []sample{
		{"select", "flows, one refused", h.choicePage(r, th, cfg, &flow.ChoiceScreen{Flows: []string{"f"}, LoginChallenge: sampleChallenge, CSRF: sampleCSRF, Client: client, Invalid: true}), choiceFields},
		{"select", "flow selected", selected, choiceFields},
		{"select", "no flow", h.choicePage(r, th, cfg, &flow.ChoiceScreen{LoginChallenge: sampleChallenge, CSRF: sampleCSRF}), nil},
		{"consent", "scopes, claims, audience", h.consentPage(r, th, cfg, consent, false), consentFields},
		{"consent", "values shown", h.consentPage(r, th, cfg, consent, true), consentFields},
		{"consent", "nothing asked", h.consentPage(r, th, cfg, &flow.ConsentScreen{Challenge: sampleChallenge, CSRF: sampleCSRF}, false), consentFields},
		{"consent", "without a flow", h.consentPage(r, th, cfg, &flow.ConsentScreen{Challenge: sampleChallenge, CSRF: sampleCSRF, Print: samplePrint, Subject: "s", Claims: flow.Object{"email": json.RawMessage(`"v"`)}}, false),
			map[string]string{"consent_challenge": sampleChallenge, "csrf_token": sampleCSRF, "action": "accept", "claims_print": samplePrint}},
		{"logout", "confirm", h.logoutPage(r, th, cfg, &flow.LogoutScreen{State: flow.LogoutConfirm, Challenge: sampleChallenge, CSRF: sampleCSRF}), logoutFields},
		{"logout", "other session", h.logoutPage(r, th, cfg, &flow.LogoutScreen{State: flow.LogoutConfirm, Challenge: sampleChallenge, CSRF: sampleCSRF, OtherSession: true, Client: &ory.OAuth2Client{ClientId: ory.PtrString("c"), ClientName: ory.PtrString("Client")}}), logoutFields},
		{"logout", "declined", h.logoutPage(r, th, cfg, &flow.LogoutScreen{State: flow.LogoutDeclined}), nil},
		{"logout", "in progress", h.logoutPage(r, th, cfg, &flow.LogoutScreen{State: flow.LogoutInProgress, Next: "/logout/next?ref=0"}), nil},
		{"logout", "already out", h.logoutPage(r, th, cfg, &flow.LogoutScreen{State: flow.LogoutAlreadyOut}), nil},
	}
	for _, code := range slices.Sorted(maps.Keys(statuses)) {
		for _, link := range []string{"", "https://client.example/"} {
			p := h.page(r, th, cfg, nil)
			p.Error = &pageError{Code: string(code), MessageKey: "error." + string(code), TraceID: "0123456789abcdef0123456789abcdef", Link: link}
			out = append(out, sample{name: "error", what: string(code), page: p})
		}
	}
	p := h.page(r, th, cfg, nil)
	p.Error = &pageError{Code: string(flow.E1003), MessageKey: "error." + string(flow.E1003), TraceID: "0123456789abcdef0123456789abcdef", SignOut: "https://hydra.example/oauth2/sessions/logout"}
	out = append(out, sample{name: "error", what: "sign out", page: p})
	return out
}

// inlineCode names what the CSP of the pages blocks without a word: a script
// without src, an on… attribute, a style element or attribute, a javascript:
// URL. A theme's script and style go to static/ (Thèmes, CSS et JavaScript).
func inlineCode(page []byte) []string {
	var out []string
	z := html.NewTokenizer(bytes.NewReader(page))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return out
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			src := false
			for _, a := range t.Attr {
				name := strings.ToLower(a.Key)
				switch {
				case strings.HasPrefix(name, "on"):
					out = append(out, fmt.Sprintf("attribute %s on <%s>, which the CSP blocks: a script goes to static/theme.js", name, t.Data))
				case name == "style":
					out = append(out, fmt.Sprintf("attribute style on <%s>, which the CSP blocks: a style goes to static/theme.css", t.Data))
				case name == "src":
					src = true
				}
				if slices.Contains([]string{"href", "src", "action", "formaction"}, name) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.Val)), "javascript:") {
					out = append(out, fmt.Sprintf("javascript: URL in %s on <%s>, which the CSP blocks", name, t.Data))
				}
			}
			switch {
			case t.Data == "script" && !src:
				out = append(out, "<script> without src, which the CSP blocks: a script goes to static/theme.js")
			case t.Data == "style":
				out = append(out, "<style>, which the CSP blocks: a style goes to static/theme.css")
			}
		}
	}
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

// static serves a static file of the theme, cached for a year when its URL
// carries its hash. Only the files of static/ are known: no name leaves it.
func (h *Handler) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	f, ok := h.themeOf(r).statics[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if v := r.URL.Query().Get("v"); v != "" && v == f.hash {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if t := mime.TypeByExtension(path.Ext(name)); t != "" {
		w.Header().Set("Content-Type", t)
	}
	_, _ = w.Write(f.data)
}
