package front

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"maps"
	"mime"
	"net/http"
	"path"
	"slices"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/i18n"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/web"
)

// pageNames are the pages, each parsed with the layout and the partials.
var pageNames = []string{"select", "consent", "error"}

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
	files, err := fs.ReadDir(web.FS, "static")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		data, err := fs.ReadFile(web.FS, "static/"+f.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		p.hashes[f.Name()] = hex.EncodeToString(sum[:])[:12]
	}
	return p, nil
}

// page is the data of every page (Thèmes, contrat de données, api: 1).
type page struct {
	h        *Handler
	Locale   string
	fallback string
	Locales  []localeChoice
	Client   client
	Flows    []flowCard
	Scopes   []scopeGroup
	Audience []string
	Error    *pageError
	Form     form
}

type localeChoice struct {
	Code, Label, Action string
	Current             bool
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

type form struct{ Action, LoginChallenge, ConsentChallenge, CSRF string }

// T translates key in the page's locale.
func (p page) T(key string, args ...any) string {
	return p.h.catalogs.T(p.Locale, p.fallback, key, args...)
}

// Asset is the URL of a static file, its hash in the query.
func (p page) Asset(name string) string {
	return "/static/" + name + "?v=" + p.h.pages.hashes[name]
}

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
	p.Locale = i18n.Negotiate(r.URL.Query().Get("_locale"), h.cookie(r, localeCookie), uiLocales, supported, def)
	for _, l := range supported {
		p.Locales = append(p.Locales, localeChoice{Code: l, Label: h.catalogs.T(l, p.fallback, "locale."+l), Action: "/locale/" + l, Current: l == p.Locale})
	}
	return p
}

// choicePage is the page of the choice of the flow (CHX-5, POS-2).
func (h *Handler) choicePage(r *http.Request, cfg *store.Snapshot, c *flow.ChoiceScreen) page {
	p := h.page(r, cfg, c.UILocales)
	p.Client = clientOf(c.Client)
	p.Form = form{Action: "/", LoginChallenge: c.LoginChallenge, CSRF: c.CSRF}
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
// (claims_filter permissive).
func (h *Handler) consentPage(r *http.Request, cfg *store.Snapshot, c *flow.ConsentScreen) page {
	p := h.page(r, cfg, c.UILocales)
	if c.Client != nil {
		data, _ := json.Marshal(c.Client)
		p.Client = clientOf(data)
	}
	p.Form = form{Action: "/consent", ConsentChallenge: c.Challenge, CSRF: c.CSRF}
	p.Audience = c.Audience
	covered := map[string]bool{}
	for _, s := range c.Scopes {
		claims, known := standardScopes[s]
		g := scopeGroup{Label: p.T("scope." + s)}
		if !known {
			g.Label = p.T("scope.generic", s)
		}
		for _, name := range claims {
			if v, ok := c.Claims[name]; ok {
				covered[name] = true
				g.Claims = append(g.Claims, h.claim(p, name, v))
			}
		}
		p.Scopes = append(p.Scopes, g)
	}
	other := scopeGroup{Label: p.T("consent.other")}
	for _, name := range slices.Sorted(maps.Keys(c.Claims)) {
		if !covered[name] {
			other.Claims = append(other.Claims, h.claim(p, name, c.Claims[name]))
		}
	}
	if len(other.Claims) > 0 {
		p.Scopes = append(p.Scopes, other)
	}
	return p
}

// claim is the line of a claim: its label, or its name, and its value with
// consent.show_values.
func (h *Handler) claim(p page, name string, value json.RawMessage) claimLine {
	l := claimLine{Label: p.T("claim." + name)}
	if l.Label == "claim."+name {
		l.Label = name
	}
	if h.o.ShowValues {
		var s string
		if json.Unmarshal(value, &s) == nil {
			l.Value = s
		} else {
			l.Value = string(value)
		}
	}
	return l
}

// render writes the page, rendered first: a template that fails gives a
// 500, never half a page.
func (h *Handler) render(w http.ResponseWriter, _ *http.Request, status int, name string, p page) {
	var buf bytes.Buffer
	if err := h.pages.templates[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		h.o.Logger.Error("http.render_failed", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// check renders each page with sample data in each locale (Thèmes,
// validation).
func (h *Handler) check() error {
	cfg := store.NewSnapshot(nil, nil, store.DefaultSettings())
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, l := range h.catalogs.Locales() {
		p := h.page(r, cfg, []string{l})
		p.Client = client{Name: "Client"}
		p.Flows = []flowCard{{ID: "f", Title: "F"}}
		p.Scopes = []scopeGroup{{Label: "S", Claims: []claimLine{{Label: "C", Value: "v"}}}}
		p.Error = &pageError{Code: "E1000", MessageKey: "error.E1000", TraceID: "t", Link: "https://client.example/"}
		for _, name := range pageNames {
			if err := h.pages.templates[name].ExecuteTemplate(&bytes.Buffer{}, "layout", p); err != nil {
				return fmt.Errorf("page %s in %s: %w", name, l, err)
			}
		}
	}
	return nil
}

// static serves a static file, cached for a year when its URL carries its
// hash.
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
