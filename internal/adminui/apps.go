package adminui

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// appForm is the form of an app as it was typed, shown again as it was when
// the write is refused.
type appForm struct {
	ID, LoginURL, ConsentURL, LogoutURL, Method, AuthMode, AllowedSources, Fingerprint, Claims string
	// Version is that of the app the form showed.
	Version string
	// AllClaims is a ReceiveClaims of nil: every claim.
	AllClaims bool
}

func appFormOf(a store.App) appForm {
	sources := make([]string, len(a.AllowedSources))
	for i, p := range a.AllowedSources {
		sources[i] = p.String()
	}
	return appForm{ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
		AuthMode: a.AuthMode, AllowedSources: strings.Join(sources, "\n"), Fingerprint: a.ClientCertFingerprint,
		Claims: strings.Join(a.ReceiveClaims, "\n"), AllClaims: a.ReceiveClaims == nil, Version: version(a)}
}

func readAppForm(r *http.Request) appForm {
	v := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return appForm{ID: v("id"), LoginURL: v("login_url"), ConsentURL: v("consent_url"), LogoutURL: v("logout_url"),
		Method: v("method"), AuthMode: v("auth_mode"), AllowedSources: v("allowed_sources"), Fingerprint: v("client_cert_fingerprint"),
		Claims: v("receive_claims"), AllClaims: r.PostFormValue("receive_all_claims") != "", Version: v("version")}
}

// app is the app of the form, or what cannot be read of it. The field of the
// other mode is left out: switching from one mode to the other drops it.
func (f appForm) app() (store.App, fieldErrors) {
	a := store.App{ID: f.ID, LoginURL: f.LoginURL, ConsentURL: f.ConsentURL, LogoutURL: f.LogoutURL, Method: f.Method, AuthMode: f.AuthMode}
	switch f.AuthMode {
	case "network":
		sources, err := domain.ParsePrefixes(words(f.AllowedSources))
		if err != nil {
			return a, fieldErrors{"allowed_sources": {err.Error()}}
		}
		if len(sources) > 0 {
			a.AllowedSources = sources
		}
	case "mtls":
		a.ClientCertFingerprint = domain.NormalizeFingerprint(f.Fingerprint)
	}
	if !f.AllClaims {
		a.ReceiveClaims = append([]string{}, lines(f.Claims)...)
	}
	return a, nil
}

// appFields are the fields of the form of an app, by their names in the seed
// and in the violations of the store.
var appFields = []string{"id", "login_url", "consent_url", "logout_url", "method", "auth_mode", "allowed_sources",
	"client_cert_fingerprint", "receive_claims"}

// appChanges names the fields of b that differ from a, by their names in the
// seed.
func appChanges(a, b store.App) []string {
	var c changes
	c.add("login_url", a.LoginURL != b.LoginURL)
	c.add("consent_url", a.ConsentURL != b.ConsentURL)
	c.add("logout_url", a.LogoutURL != b.LogoutURL)
	c.add("method", a.Method != b.Method)
	c.add("auth_mode", a.AuthMode != b.AuthMode)
	c.add("allowed_sources", !slices.Equal(a.AllowedSources, b.AllowedSources))
	c.add("client_cert_fingerprint", a.ClientCertFingerprint != b.ClientCertFingerprint)
	c.add("receive_claims", !slices.Equal(a.ReceiveClaims, b.ReceiveClaims) || (a.ReceiveClaims == nil) != (b.ReceiveClaims == nil))
	return c
}

// stepOf gives the flows that have the app id as a step, by id.
func stepOf(snap *store.Snapshot, id string) []string {
	var flows []string
	for _, f := range snap.Flows {
		if slices.ContainsFunc(f.Steps, func(s store.Step) bool { return s.AppID == id }) {
			flows = append(flows, f.ID)
		}
	}
	return flows
}

type appRow struct {
	store.App
	Flows []string
}

type appsPage struct{ Apps []appRow }

type appPage struct {
	Form   appForm
	Errors fieldErrors
	New    bool
	// Flows have the app as a step.
	Flows []string
}

func (ui *UI) registerApps() {
	ui.mux.Handle("GET /admin/apps", ui.authed(anyRole, ui.apps))
	ui.mux.Handle("GET /admin/apps/{id}", ui.authed(anyRole, ui.appView))
	if ui.o.Writer == nil {
		return
	}
	// _new is no id: an id starts with a letter or a digit.
	ui.mux.Handle("GET /admin/apps/_new", ui.authed(adminRole, ui.newApp))
	ui.mux.Handle("POST /admin/apps", ui.authed(adminRole, ui.createApp))
	ui.mux.Handle("POST /admin/apps/{id}", ui.authed(adminRole, ui.updateApp))
	ui.mux.Handle("GET /admin/apps/{id}/delete", ui.authed(adminRole, ui.deleteAppForm))
	ui.mux.Handle("POST /admin/apps/{id}/delete", ui.authed(adminRole, ui.deleteApp))
}

func (ui *UI) appPath(id string) string { return ui.base + "/apps/" + url.PathEscape(id) }

func (ui *UI) apps(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	p := appsPage{}
	for _, a := range snap.Apps {
		p.Apps = append(p.Apps, appRow{App: a, Flows: stepOf(snap, a.ID)})
	}
	ui.show(w, r, s, http.StatusOK, "apps", "Apps", "apps", p)
}

func (ui *UI) appView(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	a, ok := snap.App(r.PathValue("id"))
	if !ok {
		ui.status(w, r, http.StatusNotFound, "Not found", "No app has this id.", s)
		return
	}
	ui.show(w, r, s, http.StatusOK, "app", "App "+a.ID, "apps", appPage{Form: appFormOf(a), Flows: stepOf(snap, a.ID)})
}

func (ui *UI) newApp(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "app", "New app", "apps", appPage{Form: appForm{AuthMode: "network", AllClaims: true}, New: true})
}

func (ui *UI) createApp(w http.ResponseWriter, r *http.Request, s *current) {
	f := readAppForm(r)
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "app", "New app", "apps", appPage{Form: f, Errors: errs, New: true})
	}
	a, errs := f.app()
	if errs != nil {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	if err := ui.o.Writer.CreateApp(r.Context(), author(s.account.Username), a); err != nil {
		ui.failed(w, r, s, err, appFields, again)
		return
	}
	ui.wrote(r.Context(), s, "apps", a.ID, "create", append([]string{"id"}, appChanges(store.App{}, a)...))
	http.Redirect(w, r, ui.appPath(a.ID)+"?done=created", http.StatusSeeOther)
}

func (ui *UI) updateApp(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	f := readAppForm(r)
	f.ID = id
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "app", "App "+id, "apps", appPage{Form: f, Errors: errs, Flows: stepOf(ui.o.Config.Snapshot(), id)})
	}
	a, errs := f.app()
	if errs != nil {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	var fields []string
	err := ui.o.Writer.UpdateApp(r.Context(), author(s.account.Username), id, func(old *store.App) error {
		if v := version(*old); v != f.Version {
			f.Version = v // saved again, the form writes over
			return errChanged
		}
		fields = appChanges(*old, a)
		*old = a
		return nil
	})
	if err != nil {
		ui.failed(w, r, s, err, appFields, again)
		return
	}
	ui.wrote(r.Context(), s, "apps", id, "update", fields)
	http.Redirect(w, r, ui.appPath(id)+"?done=saved", http.StatusSeeOther)
}

func (ui *UI) deleteAppForm(w http.ResponseWriter, r *http.Request, s *current) {
	snap := ui.o.Config.Snapshot()
	a, ok := snap.App(r.PathValue("id"))
	if !ok {
		ui.status(w, r, http.StatusNotFound, "Not found", "No app has this id.", s)
		return
	}
	ui.show(w, r, s, http.StatusOK, "app_delete", "Delete the app "+a.ID, "apps", appPage{Form: appFormOf(a), Flows: stepOf(snap, a.ID)})
}

func (ui *UI) deleteApp(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	err := ui.o.Writer.DeleteApp(r.Context(), id)
	if err != nil {
		ui.failed(w, r, s, err, appFields, func(status int, errs fieldErrors) {
			snap := ui.o.Config.Snapshot()
			a, _ := snap.App(id)
			a.ID = id
			ui.show(w, r, s, status, "app_delete", "Delete the app "+id, "apps", appPage{Form: appFormOf(a), Errors: errs, Flows: stepOf(snap, id)})
		})
		return
	}
	ui.wrote(r.Context(), s, "apps", id, "delete", nil)
	http.Redirect(w, r, ui.base+"/apps?done=deleted", http.StatusSeeOther)
}
