package admin

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// appJSON is the representation of an app: every field present, null for
// what is absent (Q108).
type appJSON struct {
	ID                    string   `json:"id"`
	LoginURL              string   `json:"loginUrl"`
	ConsentURL            string   `json:"consentUrl"`
	LogoutURL             string   `json:"logoutUrl"`
	Method                string   `json:"method"`
	AuthMode              string   `json:"authMode"`
	AllowedSources        []string `json:"allowedSources"`
	ClientCertFingerprint *string  `json:"clientCertFingerprint"`
	// ReceiveClaims is null for every claim, [] for none.
	ReceiveClaims []string `json:"receiveClaims"`
	// SkipCheckURL is null without the pre-check of a step (phase 4).
	SkipCheckURL *string `json:"skipCheckUrl"`
	// SkipCheckKeySet tells whether the app holds its key, which a read never
	// shows: a write gives it by skipCheckKey. A body may carry it back, read
	// only, ignored.
	SkipCheckKeySet  bool     `json:"skipCheckKeySet"`
	SkipCheckSignals []string `json:"skipCheckSignals"`
}

func appOf(a store.App) appJSON {
	j := appJSON{ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
		AuthMode: a.AuthMode, AllowedSources: []string{}, ReceiveClaims: a.ReceiveClaims,
		SkipCheckKeySet: a.SkipCheckKey != "", SkipCheckSignals: []string{}}
	if a.SkipCheckURL != "" {
		j.SkipCheckURL = &a.SkipCheckURL
	}
	j.SkipCheckSignals = append(j.SkipCheckSignals, a.SkipCheckSignals...)
	for _, p := range a.AllowedSources {
		j.AllowedSources = append(j.AllowedSources, p.String())
	}
	if a.ClientCertFingerprint != "" {
		j.ClientCertFingerprint = &a.ClientCertFingerprint
	}
	return j
}

// The fields of an app: those of Symfony, which a PUT replaces, and those the
// Go adds, which a PUT without them keeps (Q107).
var (
	appSymfonyFields = []string{"loginUrl", "consentUrl", "logoutUrl", "method"}
	appGoFields      = []string{"authMode", "allowedSources", "clientCertFingerprint", "receiveClaims",
		"skipCheckUrl", "skipCheckKey", "skipCheckSignals"}
	appFields = append(append([]string{"id"}, appSymfonyFields...), appGoFields...)
)

// writeMode is what a write does with the fields absent from its body.
type writeMode int

const (
	create  writeMode = iota // the defaults
	replace                  // PUT: the defaults for Symfony's fields, kept for the Go's
	patch                    // PATCH: kept
)

// applyApp writes the fields of b into a, as mode says; a null field takes its
// default.
func applyApp(b body, a *store.App, mode writeMode) error {
	if err := b.unknown(appFields, "skipCheckKeySet"); err != nil {
		return err
	}
	if mode == replace {
		a.LoginURL, a.ConsentURL, a.LogoutURL, a.Method = "", "", "", ""
	}
	for _, f := range []struct {
		name string
		into *string
	}{{"loginUrl", &a.LoginURL}, {"consentUrl", &a.ConsentURL}, {"logoutUrl", &a.LogoutURL}, {"method", &a.Method}} {
		if b.has(f.name) {
			s, err := b.str(f.name)
			if err != nil {
				return err
			}
			*f.into = s
		}
	}
	if b.has("authMode") {
		mode, err := b.str("authMode")
		if err != nil {
			return err
		}
		a.AuthMode = mode
		if b.null("authMode") {
			a.AuthMode = "network"
		}
	}
	if b.has("allowedSources") {
		sources, err := b.strs("allowedSources")
		if err != nil {
			return err
		}
		prefixes, err := domain.ParsePrefixes(sources)
		if err != nil {
			return requestViolations{{Field: "allowedSources", Message: err.Error()}}
		}
		a.AllowedSources = nil
		if len(prefixes) > 0 {
			a.AllowedSources = prefixes
		}
	}
	if b.has("clientCertFingerprint") {
		fp, err := b.str("clientCertFingerprint")
		if err != nil {
			return err
		}
		a.ClientCertFingerprint = domain.NormalizeFingerprint(fp)
	}
	if b.has("receiveClaims") {
		claims, err := b.strs("receiveClaims")
		if err != nil {
			return err
		}
		a.ReceiveClaims = claims // nil, every claim
	}
	// The pre-check of a step (phase 4). The key is written, never read: a
	// write without it keeps the key held; "" or null removes it.
	if b.has("skipCheckUrl") {
		u, err := b.str("skipCheckUrl")
		if err != nil {
			return err
		}
		a.SkipCheckURL = u
	}
	if b.has("skipCheckKey") {
		k, err := b.str("skipCheckKey")
		if err != nil {
			return err
		}
		a.SkipCheckKey = strings.TrimSpace(k)
	}
	if b.has("skipCheckSignals") {
		signals, err := b.strs("skipCheckSignals")
		if err != nil {
			return err
		}
		a.SkipCheckSignals = nil
		if len(signals) > 0 {
			a.SkipCheckSignals = signals
		}
	}
	// Without its URL, an app has neither key nor signals: those the body does
	// not give go with it, those it gives are refused.
	if a.SkipCheckURL == "" {
		if !b.has("skipCheckKey") {
			a.SkipCheckKey = ""
		}
		if !b.has("skipCheckSignals") {
			a.SkipCheckSignals = nil
		}
	}
	return nil
}

// checkPathID refuses an id of the body other than the path's (Q95); the
// id never changes.
func checkPathID(b body, id string) error {
	if !b.has("id") || b.null("id") {
		return nil
	}
	got, err := b.str("id")
	if err != nil {
		return err
	}
	if got != id {
		return domain.Violations{{Field: "id", Message: "is " + quote(got) + ", but the path names " + quote(id) + ": an id never changes"}}
	}
	return nil
}

func quote(s string) string { return `"` + s + `"` }

func (a *API) registerApps() {
	a.Handle("GET "+Prefix+"/apps", Apps, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := page(r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		items := []appJSON{}
		for _, app := range paginate(a.o.Config.Snapshot().Apps, n) {
			items = append(items, appOf(app))
		}
		writeResource(w, http.StatusOK, items)
	}))
	a.Handle("GET "+Prefix+"/apps/{id}", Apps, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app, ok := a.o.Config.Snapshot().App(r.PathValue("id"))
		if !ok {
			a.fail(w, r, "", store.ErrNotFound)
			return
		}
		writeResource(w, http.StatusOK, appOf(app))
	}))
	a.Handle("POST "+Prefix+"/apps", Apps, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		app := store.App{AuthMode: "network"}
		if b.has("id") {
			if app.ID, err = b.str("id"); err != nil {
				a.fail(w, r, "", err)
				return
			}
		}
		if err := applyApp(b, &app, create); err != nil {
			a.fail(w, r, "", err)
			return
		}
		if err := a.o.Writer.CreateApp(r.Context(), author(r), app); err != nil {
			a.fail(w, r, "App "+app.ID, err)
			return
		}
		a.wrote(r, Apps, app.ID, b.fieldsOf(appFields))
		w.Header().Set("Location", Prefix+"/apps/"+app.ID)
		writeResource(w, http.StatusCreated, appOf(app))
	}))
	update := func(mode writeMode) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			b, err := readBody(w, r)
			if err == nil {
				err = checkPathID(b, id)
			}
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			var written store.App
			err = a.o.Writer.UpdateApp(r.Context(), author(r), id, func(app *store.App) error {
				if err := applyApp(b, app, mode); err != nil {
					return err
				}
				written = *app
				return nil
			})
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			a.wrote(r, Apps, id, b.fieldsOf(appFields))
			writeResource(w, http.StatusOK, appOf(written))
		}
	}
	a.Handle("PUT "+Prefix+"/apps/{id}", Apps, update(replace))
	a.Handle("PATCH "+Prefix+"/apps/{id}", Apps, update(patch))
	a.Handle("DELETE "+Prefix+"/apps/{id}", Apps, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := a.o.Writer.DeleteApp(r.Context(), id); err != nil {
			a.fail(w, r, "", err)
			return
		}
		a.wrote(r, Apps, id, nil)
		w.WriteHeader(http.StatusNoContent)
	}))
}

// author is the updated_by of a write of the caller.
func author(r *http.Request) string {
	c, _ := CallerOf(r.Context())
	return "api_client:" + c.Client
}

// wrote tells the audit of a write done.
func (a *API) wrote(r *http.Request, res Resource, id string, fields []string) {
	if a.o.Wrote != nil {
		c, _ := CallerOf(r.Context())
		a.o.Wrote(r.Context(), c.Client, resourceName(res), id, r.Method, slices.Clone(fields))
	}
}

// resourceName is the name of a resource in its path and in the audit.
func resourceName(r Resource) string {
	switch r {
	case Apps:
		return "apps"
	case Flows:
		return "flows"
	case Clients:
		return "oauth2-clients"
	case Settings:
		return "settings"
	case Catalogue:
		return "scopes"
	case Debug:
		return "log-level"
	}
	return string(r)
}

// writeResource writes a representation, as Symfony's API Platform does.
func writeResource(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
