package adminui

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/hydra"
	"github.com/Cadoles/hydra-dispatcher-go/internal/i18n"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The screen of the catalogue of the scopes (P24): the standard scopes of the
// code (Q125, Q130), whose labels alone change, and those of the business; an
// overview of the consent screen for the scopes chosen; the scopes clients of
// Hydra ask that the catalogue lacks. Every role reads, the role admin
// writes.

// embedded are the texts of the dispatcher, the labels of the standard scopes
// and of their claims by default.
var embedded = sync.OnceValue(func() i18n.Catalogs {
	c, _ := i18n.Embedded()
	return c
})

// defaultLabel is the label of the code for key (scope.x, claim.x) in locale,
// else in fallback; "" for none.
func defaultLabel(key, locale, fallback string) string {
	c := embedded()
	for _, l := range []string{locale, fallback} {
		if t := c[l][key]; t != "" && !strings.Contains(t, "%") {
			return t
		}
	}
	return ""
}

// labelIn is a label of the catalogue in locale, else for every locale, else
// in fallback; "" for none.
func labelIn(l map[string]string, locale, fallback string) string {
	for _, k := range []string{locale, "", fallback} {
		if t := l[k]; t != "" {
			return t
		}
	}
	return ""
}

// scopeEntry is a scope of the catalogue as the screens show it.
type scopeEntry struct {
	Name     string
	Standard bool
	// Label is its label in the default locale, Renamed whether its row
	// gives one.
	Label   string
	Renamed bool
	Claims  []string
	// Chosen ticks it in the overview of the consent.
	Chosen bool
}

func (ui *UI) catalogue() []scopeEntry {
	snap := ui.o.Config.Snapshot()
	def, fb := snap.Settings.DefaultLocale, snap.Settings.FallbackLocale
	var l []scopeEntry
	for _, s := range domain.StandardScopes {
		row, _ := snap.Scope(s.Name)
		e := scopeEntry{Name: s.Name, Standard: true, Claims: s.Claims, Label: labelIn(row.Label, def, fb), Renamed: len(row.Label) > 0}
		if e.Label == "" {
			e.Label = defaultLabel("scope."+s.Name, def, fb)
		}
		l = append(l, e)
	}
	for _, row := range snap.Scopes {
		if _, standard := domain.Standard(row.Name); standard {
			continue
		}
		claims, _ := snap.ScopeClaims(row.Name)
		l = append(l, scopeEntry{Name: row.Name, Label: labelIn(row.Label, def, fb), Claims: claims})
	}
	return l
}

// previewGroup is a scope of the overview: its label and those of its claims,
// in the default locale, as the consent screen shows them.
type previewGroup struct {
	Label  string
	Claims []string
}

func (ui *UI) preview(names []string) []previewGroup {
	snap := ui.o.Config.Snapshot()
	def, fb := snap.Settings.DefaultLocale, snap.Settings.FallbackLocale
	var groups []previewGroup
	for _, name := range names {
		row, _ := snap.Scope(name)
		claims, known := snap.ScopeClaims(name)
		g := previewGroup{Label: labelIn(row.Label, def, fb)}
		if g.Label == "" && known {
			g.Label = defaultLabel("scope."+name, def, fb)
		}
		if g.Label == "" {
			g.Label = name
		}
		for _, c := range claims {
			label := ""
			if i := slices.IndexFunc(row.Claims, func(x store.ScopeClaim) bool { return x.Claim == c }); i >= 0 {
				label = labelIn(row.Claims[i].Label, def, fb)
			}
			if label == "" {
				label = defaultLabel("claim."+c, def, fb)
			}
			g.Claims = append(g.Claims, cmpOr(label, c))
		}
		groups = append(groups, g)
	}
	return groups
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// asked are the scopes clients of Hydra ask that the catalogue lacks, each with
// the clients that ask it; read page by page, a few thousand clients at most.
type asked struct {
	Scope   string
	Clients []string
}

// maxScanned bounds the clients of Hydra the screen reads for the scopes they
// ask, the page telling it when reached; a variable for the tests.
var maxScanned = 5000

// askedOutside gives the scopes asked outside the catalogue, whether the
// clients were read (the Hydra clients served), and whether maxScanned
// stopped the reading before the last.
func (ui *UI) askedOutside(r *http.Request) (out []asked, scanned, partial bool, err error) {
	if ui.o.HydraClients == nil {
		return nil, false, false, nil
	}
	snap := ui.o.Config.Snapshot()
	byScope := map[string][]string{}
	token, read := "", 0
	for {
		l, err := ui.o.HydraClients.Clients(r.Context(), hydra.ClientsPage{Size: min(500, maxScanned), Token: token})
		if err != nil {
			return nil, false, false, err
		}
		for _, raw := range l.Clients {
			c, err := parseClient(raw)
			if err != nil {
				continue
			}
			for _, s := range strings.Fields(c.Scope) {
				if _, ok := snap.ScopeClaims(s); !ok {
					byScope[s] = append(byScope[s], cmpOr(c.Name, c.ID))
				}
			}
		}
		read += len(l.Clients)
		if l.Next == "" {
			break
		}
		if read >= maxScanned {
			partial = true
			break
		}
		token = l.Next
	}
	for _, s := range slices.Sorted(maps.Keys(byScope)) {
		out = append(out, asked{Scope: s, Clients: byScope[s]})
	}
	return out, true, partial, nil
}

type scopesPage struct {
	Scopes  []scopeEntry
	Chosen  []string
	Preview []previewGroup
	// Asked are the scopes clients of Hydra ask outside the catalogue;
	// Scanned whether the clients could be read; Partial, when not 0, the
	// number of the first clients read alone.
	Asked   []asked
	Scanned bool
	Partial int
	Error   string
}

func (ui *UI) registerScopes() {
	ui.mux.Handle("GET /admin/scopes", ui.authed(anyRole, ui.scopes))
	ui.mux.Handle("GET /admin/scopes/{name}", ui.authed(anyRole, ui.scopeView))
	if ui.o.Writer == nil {
		return
	}
	// Any name is a scope's, but no path of the scopes: the creation is
	// beside them.
	ui.mux.Handle("GET /admin/new-scope", ui.authed(adminRole, ui.newScope))
	ui.mux.Handle("POST /admin/scopes", ui.authed(adminRole, ui.createScope))
	ui.mux.Handle("POST /admin/scopes/{name}", ui.authed(adminRole, ui.updateScope))
	ui.mux.Handle("GET /admin/scopes/{name}/delete", ui.authed(adminRole, ui.deleteScopeForm))
	ui.mux.Handle("POST /admin/scopes/{name}/delete", ui.authed(adminRole, ui.deleteScope))
}

func (ui *UI) scopePath(name string) string { return ui.base + "/scopes/" + url.PathEscape(name) }

func (ui *UI) scopes(w http.ResponseWriter, r *http.Request, s *current) {
	p := scopesPage{Scopes: ui.catalogue(), Chosen: r.URL.Query()["preview"]}
	for i := range p.Scopes {
		p.Scopes[i].Chosen = slices.Contains(p.Chosen, p.Scopes[i].Name)
	}
	if len(p.Chosen) > 0 {
		p.Preview = ui.preview(p.Chosen)
	}
	var err error
	var partial bool
	if p.Asked, p.Scanned, partial, err = ui.askedOutside(r); err != nil {
		ui.hydraFailedLog(r.Context(), err)
		p.Error = "The clients of Hydra cannot be read now: the scopes they ask are not shown."
	}
	if partial {
		p.Partial = maxScanned
	}
	ui.show(w, r, s, http.StatusOK, "scopes", "Scopes", "scopes", p)
}

// scopeForm is the form of a scope: its labels by locale, its claims and
// theirs.
type scopeForm struct {
	Name, Version string
	Standard      bool
	Locales       []string
	// Label is by locale, Default the code's.
	Label, Default map[string]string
	Claims         []claimRow
}

type claimRow struct {
	Claim          string
	Label, Default map[string]string
}

type scopePage struct {
	Form   scopeForm
	Errors fieldErrors
	New    bool
}

// scopeLocales are those of the labels of a scope: supported_locales, the
// every-locale label "", then the others the scope holds.
func scopeLocales(supported []string, sc store.Scope) []string {
	l := append(slices.Clone(supported), "")
	var others []string
	add := func(m map[string]string) {
		for k := range m {
			if !slices.Contains(l, k) && !slices.Contains(others, k) {
				others = append(others, k)
			}
		}
	}
	add(sc.Label)
	for _, c := range sc.Claims {
		add(c.Label)
	}
	slices.Sort(others)
	return append(l, others...)
}

// emptyClaims are the rows left empty to add claims to a scope of the
// business.
const emptyClaims = 3

func (ui *UI) scopeFormOf(name string, sc store.Scope) scopeForm {
	snap := ui.o.Config.Snapshot()
	fb := snap.Settings.FallbackLocale
	f := scopeForm{Name: name, Version: version(sc), Locales: scopeLocales(snap.Settings.SupportedLocales, sc), Label: nonNil(sc.Label), Default: map[string]string{}}
	standard, isStandard := domain.Standard(name)
	f.Standard = isStandard
	labelOf := func(claim string) map[string]string {
		if i := slices.IndexFunc(sc.Claims, func(c store.ScopeClaim) bool { return c.Claim == claim }); i >= 0 {
			return nonNil(sc.Claims[i].Label)
		}
		return map[string]string{}
	}
	if isStandard {
		for _, l := range f.Locales {
			f.Default[l] = defaultLabel("scope."+name, l, fb)
		}
		for _, c := range standard {
			row := claimRow{Claim: c, Label: labelOf(c), Default: map[string]string{}}
			for _, l := range f.Locales {
				row.Default[l] = defaultLabel("claim."+c, l, fb)
			}
			f.Claims = append(f.Claims, row)
		}
		return f
	}
	for _, c := range sc.Claims {
		f.Claims = append(f.Claims, claimRow{Claim: c.Claim, Label: nonNil(c.Label)})
	}
	for range emptyClaims {
		f.Claims = append(f.Claims, claimRow{Label: map[string]string{}})
	}
	return f
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// readScopeForm reads the scope of the form: its labels by locale
// (label.<locale>), its claims by rows (claim and claim_label.<row>.<locale>);
// a row without a claim is none, a label left empty none, and so a claim of a
// standard scope without a label, which renames nothing.
func readScopeForm(r *http.Request, name string) store.Scope {
	_, standard := domain.Standard(name)
	sc := store.Scope{Name: name, Label: map[string]string{}}
	locales := r.PostForm["locale"]
	for _, l := range locales {
		if t := strings.TrimSpace(r.PostFormValue("label." + l)); t != "" {
			sc.Label[l] = t
		}
	}
	for i, claim := range r.PostForm["claim"] {
		claim = strings.TrimSpace(claim)
		if claim == "" {
			continue
		}
		c := store.ScopeClaim{Claim: claim, Label: map[string]string{}}
		for _, l := range locales {
			if t := strings.TrimSpace(r.PostFormValue(fmt.Sprintf("claim_label.%d.%s", i, l))); t != "" {
				c.Label[l] = t
			}
		}
		if standard && len(c.Label) == 0 {
			continue
		}
		sc.Claims = append(sc.Claims, c)
	}
	return sc
}

// scopeFields are the fields of the form of a scope, by the fields of its
// violations.
func scopeFields(sc store.Scope) []string {
	fields := []string{"name", "label", "claims"}
	for i := range sc.Claims {
		fields = append(fields, fmt.Sprintf("claims[%d]", i))
	}
	return fields
}

func (ui *UI) scopeView(w http.ResponseWriter, r *http.Request, s *current) {
	name := r.PathValue("name")
	sc, found := ui.o.Config.Snapshot().Scope(name)
	if _, standard := domain.Standard(name); !found && !standard {
		ui.status(w, r, http.StatusNotFound, "Not found", "No scope of the catalogue has this name.", s)
		return
	}
	// A standard scope without a row is as the update reads it: its name
	// alone, the version of the form the same.
	sc.Name = name
	ui.show(w, r, s, http.StatusOK, "scope", "Scope "+name, "scopes", scopePage{Form: ui.scopeFormOf(name, sc)})
}

func (ui *UI) newScope(w http.ResponseWriter, r *http.Request, s *current) {
	// The name of a scope a client of Hydra asks, from the list.
	f := ui.scopeFormOf("", store.Scope{})
	f.Name, f.Version = strings.TrimSpace(r.URL.Query().Get("name")), ""
	ui.show(w, r, s, http.StatusOK, "scope", "New scope", "scopes", scopePage{Form: f, New: true})
}

// formAgain is the form of sc as it was typed, its rows numbered as the
// violations number them.
func (ui *UI) formAgain(sc store.Scope, v string) scopeForm {
	f := ui.scopeFormOf(sc.Name, sc)
	f.Version = v
	return f
}

// byRow numbers the violations of the claims of sc by the rows of its form f.
// That of a standard scope shows each claim of the code, sc only those it
// labels: claims[1] of sc may be the fourth row (revue R44). A scope of the
// business shows the claims of sc, in their order.
func byRow(errs fieldErrors, sc store.Scope, f scopeForm) fieldErrors {
	if !f.Standard {
		return errs
	}
	out := fieldErrors{}
	for field, messages := range errs {
		var k int
		if n, _ := fmt.Sscanf(field, "claims[%d]", &k); n == 1 && k >= 0 && k < len(sc.Claims) && field == fmt.Sprintf("claims[%d]", k) {
			if row := slices.IndexFunc(f.Claims, func(c claimRow) bool { return c.Claim == sc.Claims[k].Claim }); row >= 0 {
				field = fmt.Sprintf("claims[%d]", row)
			}
		}
		out[field] = append(out[field], messages...)
	}
	return out
}

func (ui *UI) createScope(w http.ResponseWriter, r *http.Request, s *current) {
	sc := readScopeForm(r, strings.TrimSpace(r.PostFormValue("name")))
	again := func(status int, errs fieldErrors) {
		f := ui.formAgain(sc, "")
		ui.show(w, r, s, status, "scope", "New scope", "scopes", scopePage{Form: f, Errors: errs, New: true})
	}
	if err := ui.o.Writer.CreateScope(r.Context(), author(s.account.Username), sc); err != nil {
		if errors.Is(err, store.ErrStandard) {
			again(http.StatusConflict, fieldErrors{"name": {"is a standard scope of OpenID Connect: open it to rename it"}})
			return
		}
		if errors.Is(err, store.ErrExists) {
			again(http.StatusConflict, fieldErrors{"name": {"is taken: another scope has this name"}})
			return
		}
		ui.failed(w, r, s, err, scopeFields(sc), again)
		return
	}
	ui.wrote(r.Context(), s, "scopes", sc.Name, "create", []string{"name", "label", "claims"})
	http.Redirect(w, r, ui.scopePath(sc.Name)+"?done=created", http.StatusSeeOther)
}

func (ui *UI) updateScope(w http.ResponseWriter, r *http.Request, s *current) {
	name := r.PathValue("name")
	sc := readScopeForm(r, name)
	v := strings.TrimSpace(r.PostFormValue("version"))
	again := func(status int, errs fieldErrors) {
		f := ui.formAgain(sc, v)
		ui.show(w, r, s, status, "scope", "Scope "+name, "scopes", scopePage{Form: f, Errors: byRow(errs, sc, f)})
	}
	var fields []string
	err := ui.o.Writer.UpdateScope(r.Context(), author(s.account.Username), name, func(old *store.Scope) error {
		if now := version(*old); now != v {
			v = now
			return errChanged
		}
		// What the browser sent back as stored stays as stored (revues R45,
		// R46): labels, claims, their order.
		sc.Label = untouched(old.Label, sc.Label, keptLine)
		for i, c := range sc.Claims {
			if j := slices.IndexFunc(old.Claims, func(o store.ScopeClaim) bool { return asLine(o.Claim) == c.Claim }); j >= 0 {
				sc.Claims[i].Claim, sc.Claims[i].Label = old.Claims[j].Claim, untouched(old.Claims[j].Label, c.Label, keptLine)
			}
		}
		if _, standard := domain.Standard(name); standard {
			// The form lists every claim of the code, those it labels kept:
			// a claim the row holds with labels of spaces alone stays.
			for _, o := range old.Claims {
				if !slices.ContainsFunc(sc.Claims, func(c store.ScopeClaim) bool { return c.Claim == o.Claim }) &&
					!slices.ContainsFunc(slices.Collect(maps.Values(o.Label)), func(t string) bool { return asText(t) != "" }) {
					sc.Claims = append(sc.Claims, o)
				}
			}
			// The order of the row, the form's being the code's: the same
			// claims in another order change nothing. A scope of the business
			// shows its claims in the row's order.
			at := func(claim string) int {
				if j := slices.IndexFunc(old.Claims, func(o store.ScopeClaim) bool { return o.Claim == claim }); j >= 0 {
					return j
				}
				return len(old.Claims)
			}
			slices.SortStableFunc(sc.Claims, func(a, b store.ScopeClaim) int { return at(a.Claim) - at(b.Claim) })
		}
		var c changes
		c.add("label", !maps.Equal(nonNil(old.Label), sc.Label))
		c.add("claims", !slices.EqualFunc(old.Claims, sc.Claims, func(a, b store.ScopeClaim) bool {
			return a.Claim == b.Claim && maps.Equal(nonNil(a.Label), nonNil(b.Label))
		}))
		if fields = c; len(fields) == 0 {
			return errUnchanged
		}
		*old = sc
		return nil
	})
	if errors.Is(err, errUnchanged) {
		http.Redirect(w, r, ui.scopePath(name)+"?done=saved", http.StatusSeeOther)
		return
	}
	if err != nil {
		ui.failed(w, r, s, err, scopeFields(sc), again)
		return
	}
	ui.wrote(r.Context(), s, "scopes", name, "update", fields)
	http.Redirect(w, r, ui.scopePath(name)+"?done=saved", http.StatusSeeOther)
}

func (ui *UI) scopeConfirm(name string, errs fieldErrors) confirmPage {
	p := confirmPage{Title: "Delete the scope " + name + "?", Action: ui.scopePath(name) + "/delete", Button: "Delete the scope",
		Message: "The consent screen shows it by its name again; with the strict filter, its claims are sent no more. Its deletion cannot be undone.",
		Back:    ui.scopePath(name), Errors: errs}
	if _, standard := domain.Standard(name); standard {
		p.Action, p.Message = "", "A standard scope of OpenID Connect is renamed, never deleted: empty its labels to give it back those of the code."
	}
	return p
}

func (ui *UI) deleteScopeForm(w http.ResponseWriter, r *http.Request, s *current) {
	name := r.PathValue("name")
	if _, found := ui.o.Config.Snapshot().Scope(name); !found {
		if _, standard := domain.Standard(name); !standard {
			ui.status(w, r, http.StatusNotFound, "Not found", "No scope of the catalogue has this name.", s)
			return
		}
	}
	p := ui.scopeConfirm(name, nil)
	ui.show(w, r, s, http.StatusOK, "confirm", p.Title, "scopes", p)
}

func (ui *UI) deleteScope(w http.ResponseWriter, r *http.Request, s *current) {
	name := r.PathValue("name")
	again := func(status int, errs fieldErrors) {
		p := ui.scopeConfirm(name, errs)
		ui.show(w, r, s, status, "confirm", p.Title, "scopes", p)
	}
	if err := ui.o.Writer.DeleteScope(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrStandard) {
			again(http.StatusConflict, fieldErrors{"": {"A standard scope is renamed, never deleted."}})
			return
		}
		ui.failed(w, r, s, err, nil, again)
		return
	}
	ui.wrote(r.Context(), s, "scopes", name, "delete", nil)
	http.Redirect(w, r, ui.base+"/scopes?done=deleted", http.StatusSeeOther)
}
