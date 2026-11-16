package adminui

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	// The pre-check of a step (phase 4). SkipCheckKey is the key typed, never
	// shown again; KeyGenerate asks for a new one, shown once; KeySet tells
	// whether the app holds one.
	SkipCheckURL, SkipCheckKey string
	SkipCheckSignals           []string
	KeyGenerate, KeySet        bool
}

// signalBox is a box of a signal of the browser on the form of an app.
type signalBox struct {
	Name, Label string
	Checked     bool
}

// signalLabels say what each signal gives the app.
var signalLabels = map[string]string{
	"ip": "its address, truncated (/24, /48)", "full_ip": "its whole address", "user_agent": "its User-Agent",
	"client_hints": "its client hints (Sec-CH-UA, -Platform, -Mobile)", "accept_language": "its Accept-Language",
	"device_age": "the age of the device cookie",
}

// Signals are the boxes of the signals: those the domain knows, in its order,
// then those the app holds besides, for a save to lose none.
func (f appForm) Signals() []signalBox {
	var boxes []signalBox
	for _, s := range domain.SkipCheckSignals {
		boxes = append(boxes, signalBox{Name: s, Label: signalLabels[s], Checked: slices.Contains(f.SkipCheckSignals, s)})
	}
	for _, s := range f.SkipCheckSignals {
		if !slices.Contains(domain.SkipCheckSignals, s) {
			boxes = append(boxes, signalBox{Name: s, Label: s, Checked: true})
		}
	}
	return boxes
}

// appVersion is the version of a: whether it holds a key, never the key
// (revue R42).
func appVersion(a store.App) string {
	return version(struct {
		App    store.App
		KeySet bool
	}{a, a.SkipCheckKey != ""})
}

// newSkipCheckKey makes a key of the pre-check: 32 random bytes, in base64.
func newSkipCheckKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand never fails
	return base64.StdEncoding.EncodeToString(b)
}

func appFormOf(a store.App) appForm {
	sources := make([]string, len(a.AllowedSources))
	for i, p := range a.AllowedSources {
		sources[i] = p.String()
	}
	return appForm{ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
		AuthMode: a.AuthMode, AllowedSources: strings.Join(sources, "\n"), Fingerprint: a.ClientCertFingerprint,
		Claims: strings.Join(a.ReceiveClaims, "\n"), AllClaims: a.ReceiveClaims == nil, Version: appVersion(a),
		SkipCheckURL: a.SkipCheckURL, SkipCheckSignals: a.SkipCheckSignals, KeySet: a.SkipCheckKey != ""}
}

func readAppForm(r *http.Request) appForm {
	v := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return appForm{ID: v("id"), LoginURL: v("login_url"), ConsentURL: v("consent_url"), LogoutURL: v("logout_url"),
		Method: v("method"), AuthMode: v("auth_mode"), AllowedSources: v("allowed_sources"), Fingerprint: v("client_cert_fingerprint"),
		Claims: v("receive_claims"), AllClaims: r.PostFormValue("receive_all_claims") != "", Version: v("version"),
		SkipCheckURL: v("skip_check_url"), SkipCheckKey: v("skip_check_key"), SkipCheckSignals: r.PostForm["skip_check_signals"],
		KeyGenerate: r.PostFormValue("skip_check_key_generate") != ""}
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
	// The URL is the switch of the pre-check: without it, the signals go; a
	// key typed or asked for stays, for the domain to refuse it.
	a.SkipCheckURL, a.SkipCheckKey = f.SkipCheckURL, f.SkipCheckKey
	if f.SkipCheckURL != "" && len(f.SkipCheckSignals) > 0 {
		a.SkipCheckSignals = slices.Clone(f.SkipCheckSignals)
	}
	switch {
	case f.KeyGenerate && f.SkipCheckKey != "":
		return a, fieldErrors{"skip_check_key": {"type a key or make one, not both"}}
	case f.KeyGenerate && f.SkipCheckURL == "":
		return a, fieldErrors{"skip_check_key": {"only applies with a skip_check_url"}}
	case f.KeyGenerate:
		a.SkipCheckKey = newSkipCheckKey()
	}
	return a, nil
}

// appFields are the fields of the form of an app, by their names in the seed
// and in the violations of the store.
var appFields = []string{"id", "login_url", "consent_url", "logout_url", "method", "auth_mode", "allowed_sources",
	"client_cert_fingerprint", "receive_claims", "skip_check_url", "skip_check_key", "skip_check_signals"}

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
	c.add("skip_check_url", a.SkipCheckURL != b.SkipCheckURL)
	c.add("skip_check_key", a.SkipCheckKey != b.SkipCheckKey)
	c.add("skip_check_signals", !slices.Equal(a.SkipCheckSignals, b.SkipCheckSignals))
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
	ui.mux.Handle("POST /admin/apps", ui.authed(adminRole, ui.keyFresh(ui.createApp)))
	ui.mux.Handle("POST /admin/apps/{id}", ui.authed(adminRole, ui.keyFresh(ui.updateApp)))
	ui.mux.Handle("GET /admin/apps/{id}/delete", ui.authed(adminRole, ui.deleteAppForm))
	ui.mux.Handle("POST /admin/apps/{id}/delete", ui.authed(adminRole, ui.deleteApp))
}

// keyFresh asks a write that gives an app a key of the pre-check, typed or
// made, to confirm it is the account's, within admin.session.reauth_window,
// as the secret of a client does: whoever holds the key signs for the app.
// The other writes of an app ask nothing more.
func (ui *UI) keyFresh(h func(http.ResponseWriter, *http.Request, *current)) func(http.ResponseWriter, *http.Request, *current) {
	fresh := ui.fresh(h)
	return func(w http.ResponseWriter, r *http.Request, s *current) {
		if strings.TrimSpace(r.PostFormValue("skip_check_key")) != "" || r.PostFormValue("skip_check_key_generate") != "" {
			fresh(w, r, s)
			return
		}
		h(w, r, s)
	}
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
	if f.KeyGenerate {
		ui.handOver(w, r, s, "apps", secretPage{ID: a.ID, Secret: a.SkipCheckKey, Created: true, Key: true, What: "app", Back: ui.appPath(a.ID)})
		return
	}
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
		if v := appVersion(*old); v != f.Version {
			f.Version = v // saved again, the form writes over
			return errChanged
		}
		a.LoginURL, a.ConsentURL, a.LogoutURL = keptLine(old.LoginURL, a.LoginURL), keptLine(old.ConsentURL, a.ConsentURL), keptLine(old.LogoutURL, a.LogoutURL)
		a.Method = keptLine(old.Method, a.Method)
		if domain.NormalizeFingerprint(old.ClientCertFingerprint) == a.ClientCertFingerprint {
			a.ClientCertFingerprint = old.ClientCertFingerprint
		}
		if !f.AllClaims && sentBack(old.ReceiveClaims, f.Claims) {
			a.ReceiveClaims = old.ReceiveClaims
		}
		// The key, never shown, stays unless typed or made again; the
		// signals, boxes in the domain's order, keep the order held.
		a.SkipCheckURL = keptLine(old.SkipCheckURL, a.SkipCheckURL)
		if a.SkipCheckURL != "" && a.SkipCheckKey == "" {
			a.SkipCheckKey = old.SkipCheckKey
		}
		if len(a.SkipCheckSignals) == len(old.SkipCheckSignals) && !slices.ContainsFunc(a.SkipCheckSignals, func(x string) bool { return !slices.Contains(old.SkipCheckSignals, x) }) {
			a.SkipCheckSignals = old.SkipCheckSignals
		}
		if fields = appChanges(*old, a); len(fields) == 0 {
			return errUnchanged
		}
		*old = a
		return nil
	})
	if errors.Is(err, errUnchanged) {
		http.Redirect(w, r, ui.appPath(id)+"?done=saved", http.StatusSeeOther)
		return
	}
	if err != nil {
		ui.failed(w, r, s, err, appFields, again)
		return
	}
	ui.wrote(r.Context(), s, "apps", id, "update", fields)
	if f.KeyGenerate {
		ui.handOver(w, r, s, "apps", secretPage{ID: id, Secret: a.SkipCheckKey, Key: true, What: "app", Back: ui.appPath(id)})
		return
	}
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
