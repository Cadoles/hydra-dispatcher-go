package adminui

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// emptySteps are the rows of a flow's form left empty, to add steps.
const emptySteps = 3

// flowForm is the form of a flow as it was typed.
type flowForm struct {
	ID, ACR, Version string
	Enabled          bool
	// Texts are by locale: supported_locales, then those the flow holds
	// besides, for a save to lose none.
	Texts []flowText
	// Steps are the rows of the steps, by their order in the form.
	Steps []stepRow
}

type flowText struct{ Locale, Title, Description, IconURL string }

// stepRow is a step as the form shows it: Check is none, equal or claim, the
// name of the claim apart.
type stepRow struct{ App, Position, Check, Claim string }

// locales are those of the texts of a flow: supported, then the others of the
// flow, in their order.
func locales(supported []string, f store.Flow) []string {
	l := slices.Clone(supported)
	var others []string
	for _, m := range []map[string]string{f.Title, f.Description, f.IconURL} {
		for k := range m {
			if !slices.Contains(l, k) && !slices.Contains(others, k) {
				others = append(others, k)
			}
		}
	}
	slices.Sort(others)
	return append(l, others...)
}

func flowFormOf(f store.Flow, supported []string) flowForm {
	form := flowForm{ID: f.ID, ACR: f.ACR, Enabled: f.Enabled, Version: version(f)}
	for _, l := range locales(supported, f) {
		form.Texts = append(form.Texts, flowText{Locale: l, Title: f.Title[l], Description: f.Description[l], IconURL: f.IconURL[l]})
	}
	steps := slices.SortedFunc(slices.Values(f.Steps), func(a, b store.Step) int { return cmp.Compare(a.Position, b.Position) })
	for _, s := range steps {
		row := stepRow{App: s.AppID, Position: strconv.Itoa(s.Position), Check: s.SubjectCheck}
		if name, ok := strings.CutPrefix(s.SubjectCheck, "claim:"); ok {
			row.Check, row.Claim = "claim", name
		}
		form.Steps = append(form.Steps, row)
	}
	return form
}

func readFlowForm(r *http.Request) flowForm {
	v := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	at := func(name string, i int) string {
		if l := r.PostForm[name]; i < len(l) {
			return strings.TrimSpace(l[i])
		}
		return ""
	}
	f := flowForm{ID: v("id"), ACR: v("acr"), Version: v("version"), Enabled: r.PostFormValue("enabled") != ""}
	for i, l := range r.PostForm["locale"] {
		f.Texts = append(f.Texts, flowText{Locale: l, Title: at("title", i), Description: at("description", i), IconURL: at("icon_url", i)})
	}
	for i := range r.PostForm["step_app"] {
		row := stepRow{App: at("step_app", i), Position: at("step_position", i), Check: at("step_check", i), Claim: at("step_claim", i)}
		if row.App != "" {
			f.Steps = append(f.Steps, row)
		}
	}
	return f
}

// flow is the flow of the form, or what cannot be read of it. A step without
// a position takes the one after the highest, in the order of the form.
func (f flowForm) flow() (store.Flow, fieldErrors) {
	fl := store.Flow{ID: f.ID, ACR: f.ACR, Enabled: f.Enabled, Title: map[string]string{}, Description: map[string]string{}}
	for _, t := range f.Texts {
		for _, x := range []struct {
			into  *map[string]string
			value string
		}{{&fl.Title, t.Title}, {&fl.Description, t.Description}, {&fl.IconURL, t.IconURL}} {
			if x.value != "" {
				if *x.into == nil {
					*x.into = map[string]string{}
				}
				(*x.into)[t.Locale] = x.value
			}
		}
	}
	errs := fieldErrors{}
	highest, positioned := 0, false
	positions := make([]int, len(f.Steps))
	for i, row := range f.Steps {
		if row.Position == "" {
			continue
		}
		p, err := strconv.Atoi(row.Position)
		if err != nil {
			errs[fmt.Sprintf("steps[%d]", i)] = append(errs[fmt.Sprintf("steps[%d]", i)], fmt.Sprintf("position %q is not a whole number", row.Position))
			continue
		}
		positions[i] = p
		if !positioned || p > highest {
			highest, positioned = p, true
		}
	}
	for i, row := range f.Steps {
		if row.Position == "" {
			highest++
			positions[i] = highest
		}
		check := row.Check
		if check == "claim" {
			check = "claim:" + row.Claim
		}
		fl.Steps = append(fl.Steps, store.Step{AppID: row.App, Position: positions[i], SubjectCheck: check})
	}
	if len(errs) > 0 {
		return fl, errs
	}
	return fl, nil
}

// flowFields are the fields of the form of a flow, its rows of steps
// included.
func (f flowForm) fields() []string {
	fields := []string{"id", "title", "description", "icon_url", "enabled", "acr", "steps"}
	for i := range f.Steps {
		fields = append(fields, fmt.Sprintf("steps[%d]", i))
	}
	return fields
}

// flowChanges names the fields of b that differ from a, by their names in the
// seed.
func flowChanges(a, b store.Flow) []string {
	var c changes
	c.add("title", !maps.Equal(a.Title, b.Title))
	c.add("description", !maps.Equal(a.Description, b.Description))
	c.add("icon_url", !maps.Equal(a.IconURL, b.IconURL))
	c.add("enabled", a.Enabled != b.Enabled)
	c.add("acr", a.ACR != b.ACR)
	byPosition := func(s []store.Step) []store.Step {
		return slices.SortedFunc(slices.Values(s), func(x, y store.Step) int { return cmp.Compare(x.Position, y.Position) })
	}
	c.add("steps", !slices.Equal(byPosition(a.Steps), byPosition(b.Steps)))
	return c
}

type flowRow struct {
	ID, Title, ACR string
	Enabled        bool
	Steps          []string
}

type flowsPage struct{ Flows []flowRow }

type flowPage struct {
	Form   flowForm
	Errors fieldErrors
	New    bool
	// Apps are those a step may name, Rows the rows of the steps: those of
	// the form, then the empty ones.
	Apps []string
	Rows []stepRow
}

// title is the title of a flow in the default locale, else in the fallback
// one, else in the first of its locales.
func title(f store.Flow, s store.Settings) string {
	for _, l := range []string{s.DefaultLocale, s.FallbackLocale} {
		if t := f.Title[l]; t != "" {
			return t
		}
	}
	for _, l := range slices.Sorted(maps.Keys(f.Title)) {
		if f.Title[l] != "" {
			return f.Title[l]
		}
	}
	return ""
}

func (ui *UI) registerFlows() {
	ui.mux.Handle("GET /admin/flows", ui.authed(anyRole, ui.flows))
	ui.mux.Handle("GET /admin/flows/{id}", ui.authed(anyRole, ui.flowView))
	if ui.o.Writer == nil {
		return
	}
	ui.mux.Handle("GET /admin/flows/_new", ui.authed(adminRole, ui.newFlow))
	ui.mux.Handle("POST /admin/flows", ui.authed(adminRole, ui.createFlow))
	ui.mux.Handle("POST /admin/flows/{id}", ui.authed(adminRole, ui.updateFlow))
	// The deletion of a flow is sensitive (Authentification des
	// administrateurs): its page and its POST ask for the password again.
	ui.mux.Handle("GET /admin/flows/{id}/delete", ui.authed(adminRole, ui.fresh(ui.deleteFlowForm)))
	ui.mux.Handle("POST /admin/flows/{id}/delete", ui.authed(adminRole, ui.fresh(ui.deleteFlow)))
}

func (ui *UI) flowPath(id string) string { return ui.base + "/flows/" + url.PathEscape(id) }

func (ui *UI) flows(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	p := flowsPage{}
	for _, f := range snap.Flows {
		row := flowRow{ID: f.ID, Title: title(f, snap.Settings), ACR: f.ACR, Enabled: f.Enabled}
		for _, st := range slices.SortedFunc(slices.Values(f.Steps), func(a, b store.Step) int { return cmp.Compare(a.Position, b.Position) }) {
			row.Steps = append(row.Steps, st.AppID)
		}
		p.Flows = append(p.Flows, row)
	}
	ui.show(w, r, s, http.StatusOK, "flows", "Flows", "flows", p)
}

// flowPage is the page of the form f.
func (ui *UI) flowPage(f flowForm, errs fieldErrors, isNew bool) flowPage {
	snap := ui.o.Config.Snapshot()
	p := flowPage{Form: f, Errors: errs, New: isNew, Rows: slices.Clone(f.Steps)}
	for _, a := range snap.Apps {
		p.Apps = append(p.Apps, a.ID)
	}
	for range emptySteps {
		p.Rows = append(p.Rows, stepRow{Check: "none"})
	}
	return p
}

func (ui *UI) flowView(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	i := slices.IndexFunc(snap.Flows, func(f store.Flow) bool { return f.ID == r.PathValue("id") })
	if i < 0 {
		ui.status(w, r, http.StatusNotFound, "Not found", "No flow has this id.", s)
		return
	}
	f := snap.Flows[i]
	ui.show(w, r, s, http.StatusOK, "flow", "Flow "+f.ID, "flows", ui.flowPage(flowFormOf(f, snap.Settings.SupportedLocales), nil, false))
}

func (ui *UI) newFlow(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	f := flowFormOf(store.Flow{Enabled: true}, snap.Settings.SupportedLocales)
	f.Version = ""
	ui.show(w, r, s, http.StatusOK, "flow", "New flow", "flows", ui.flowPage(f, nil, true))
}

func (ui *UI) createFlow(w http.ResponseWriter, r *http.Request, s *current) {
	f := readFlowForm(r)
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "flow", "New flow", "flows", ui.flowPage(f, errs, true))
	}
	fl, errs := f.flow()
	if errs != nil {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	if err := ui.o.Writer.CreateFlow(r.Context(), author(s.account.Username), fl); err != nil {
		ui.failed(w, r, s, err, f.fields(), again)
		return
	}
	ui.wrote(r.Context(), s, "flows", fl.ID, "create", append([]string{"id"}, flowChanges(store.Flow{}, fl)...))
	http.Redirect(w, r, ui.flowPath(fl.ID)+"?done=created", http.StatusSeeOther)
}

func (ui *UI) updateFlow(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	f := readFlowForm(r)
	f.ID = id
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "flow", "Flow "+id, "flows", ui.flowPage(f, errs, false))
	}
	fl, errs := f.flow()
	if errs != nil {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	var fields []string
	err := ui.o.Writer.UpdateFlow(r.Context(), author(s.account.Username), id, func(old *store.Flow) error {
		if v := version(*old); v != f.Version {
			f.Version = v
			return errChanged
		}
		fields = flowChanges(*old, fl)
		*old = fl
		return nil
	})
	if err != nil {
		ui.failed(w, r, s, err, f.fields(), again)
		return
	}
	ui.wrote(r.Context(), s, "flows", id, "update", fields)
	http.Redirect(w, r, ui.flowPath(id)+"?done=saved", http.StatusSeeOther)
}

type flowDeletePage struct {
	ID     string
	Errors fieldErrors
}

func (ui *UI) deleteFlowForm(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	id := r.PathValue("id")
	if !slices.ContainsFunc(snap.Flows, func(f store.Flow) bool { return f.ID == id }) {
		ui.status(w, r, http.StatusNotFound, "Not found", "No flow has this id.", s)
		return
	}
	ui.show(w, r, s, http.StatusOK, "flow_delete", "Delete the flow "+id, "flows", flowDeletePage{ID: id})
}

func (ui *UI) deleteFlow(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	if err := ui.o.Writer.DeleteFlow(r.Context(), id); err != nil {
		ui.failed(w, r, s, err, nil, func(status int, errs fieldErrors) {
			ui.show(w, r, s, status, "flow_delete", "Delete the flow "+id, "flows", flowDeletePage{ID: id, Errors: errs})
		})
		return
	}
	ui.wrote(r.Context(), s, "flows", id, "delete", nil)
	http.Redirect(w, r, ui.base+"/flows?done=deleted", http.StatusSeeOther)
}
