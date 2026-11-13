package adminui

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The screen SSO: the block admin_oidc, which stays out of the screen of the
// settings and of the admin API. Every role reads it, its secret never shown:
// whether one is set alone. The role admin writes it, behind the
// re-authentication; a secret left empty is unchanged, one is forgotten by its
// box. The address of the callback, to declare at the provider, is shown.

// ssoFields are the fields of the form, by the keys of the table.
var ssoFields = []string{"admin_oidc.enabled", "admin_oidc.issuer", "admin_oidc.client_id", "admin_oidc.client_secret", "admin_oidc.scopes",
	"admin_oidc.username_claim", "admin_oidc.required_acr", "admin_oidc.auto_create", "admin_oidc.authorization_endpoint",
	"admin_oidc.token_endpoint", "admin_oidc.jwks_uri"}

// ssoForm is the block as the form shows it, or as it was typed.
type ssoForm struct {
	Enabled, AutoCreate                                   bool
	Issuer, ClientID, Scopes, UsernameClaim, RequiredACR  string
	AuthorizationEndpoint, TokenEndpoint, JWKSURI, Secret string
	ForgetSecret                                          bool
	Version                                               string
}

type ssoPage struct {
	Form   ssoForm
	Errors fieldErrors
	// SecretSet tells whether the block holds a secret, Callback the address
	// to declare at the provider.
	SecretSet bool
	Callback  string
}

// ssoVersion is the version of the block as the form shows it: without its
// secret, which no form holds.
func ssoVersion(o store.AdminOIDC, sealed string) string {
	o.ClientSecret = ""
	return version(struct {
		Block  store.AdminOIDC
		Secret string
	}{o, sealed})
}

// ssoBlock is the block admin_oidc of the moment, and the digest of its
// secret as the table holds it, encrypted, from the same snapshot: a secret
// written by another since the page was shown changes the version of its
// form, the secret never in it (revue R42).
func (ui *UI) ssoBlock() (store.AdminOIDC, string) {
	snap := ui.o.Config.Snapshot()
	return snap.Settings.AdminOIDC, snap.Sealed["admin_oidc.client_secret"]
}

func ssoFormOf(o store.AdminOIDC, sealed string) ssoForm {
	return ssoForm{Enabled: o.Enabled, AutoCreate: o.AutoCreate, Issuer: o.Issuer, ClientID: o.ClientID, Scopes: strings.Join(o.Scopes, " "),
		UsernameClaim: o.UsernameClaim, RequiredACR: strings.Join(o.RequiredACR, " "), AuthorizationEndpoint: o.AuthorizationEndpoint,
		TokenEndpoint: o.TokenEndpoint, JWKSURI: o.JWKSURI, Version: ssoVersion(o, sealed)}
}

func readSSOForm(r *http.Request) ssoForm {
	v := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	return ssoForm{Enabled: r.PostFormValue("admin_oidc.enabled") != "", AutoCreate: r.PostFormValue("admin_oidc.auto_create") != "",
		Issuer: v("admin_oidc.issuer"), ClientID: v("admin_oidc.client_id"), Scopes: v("admin_oidc.scopes"),
		UsernameClaim: v("admin_oidc.username_claim"), RequiredACR: v("admin_oidc.required_acr"),
		AuthorizationEndpoint: v("admin_oidc.authorization_endpoint"), TokenEndpoint: v("admin_oidc.token_endpoint"), JWKSURI: v("admin_oidc.jwks_uri"),
		Secret: r.PostFormValue("admin_oidc.client_secret"), ForgetSecret: r.PostFormValue("forget_secret") != "", Version: v("version")}
}

// changes are the values of the form that differ from the block o, by the
// keys of the table, in the JSON of their types; the secret when typed, or
// forgotten.
func (f ssoForm) changes(o store.AdminOIDC) map[string]json.RawMessage {
	values := map[string]json.RawMessage{}
	set := func(key string, now, typed any) {
		if !reflect.DeepEqual(now, typed) {
			values[key], _ = json.Marshal(typed)
		}
	}
	list := func(l []string) []string { return append([]string{}, l...) }
	set("admin_oidc.enabled", o.Enabled, f.Enabled)
	set("admin_oidc.issuer", o.Issuer, f.Issuer)
	set("admin_oidc.client_id", o.ClientID, f.ClientID)
	set("admin_oidc.scopes", list(o.Scopes), list(words(f.Scopes)))
	set("admin_oidc.username_claim", o.UsernameClaim, f.UsernameClaim)
	set("admin_oidc.required_acr", list(o.RequiredACR), list(words(f.RequiredACR)))
	set("admin_oidc.auto_create", o.AutoCreate, f.AutoCreate)
	set("admin_oidc.authorization_endpoint", o.AuthorizationEndpoint, f.AuthorizationEndpoint)
	set("admin_oidc.token_endpoint", o.TokenEndpoint, f.TokenEndpoint)
	set("admin_oidc.jwks_uri", o.JWKSURI, f.JWKSURI)
	switch {
	case f.ForgetSecret && o.ClientSecret != "":
		values["admin_oidc.client_secret"] = json.RawMessage(`""`)
	case f.Secret != "" && f.Secret != o.ClientSecret:
		values["admin_oidc.client_secret"], _ = json.Marshal(f.Secret)
	}
	return values
}

func (ui *UI) registerSSO() {
	ui.mux.Handle("GET /admin/sso", ui.authed(anyRole, ui.sso))
	if ui.o.Writer != nil {
		ui.mux.Handle("POST /admin/sso", ui.authed(adminRole, ui.fresh(ui.updateSSO)))
	}
}

func (ui *UI) ssoPage(o store.AdminOIDC, f ssoForm, errs fieldErrors) ssoPage {
	return ssoPage{Form: f, Errors: errs, SecretSet: o.ClientSecret != "", Callback: ui.origin + ui.base + "/oidc/callback"}
}

func (ui *UI) sso(w http.ResponseWriter, r *http.Request, s *current) {
	o, sealed := ui.ssoBlock()
	ui.show(w, r, s, http.StatusOK, "sso", "SSO", "sso", ui.ssoPage(o, ssoFormOf(o, sealed), nil))
}

func (ui *UI) updateSSO(w http.ResponseWriter, r *http.Request, s *current) {
	o, sealed := ui.ssoBlock()
	f := readSSOForm(r)
	again := func(status int, errs fieldErrors) {
		f.Secret = "" // never shown back
		ui.show(w, r, s, status, "sso", "SSO", "sso", ui.ssoPage(o, f, errs))
	}
	if now := ssoVersion(o, sealed); now != f.Version {
		f.Version = now // saved again, the form writes over
		ui.failed(w, r, s, errChanged, ssoFields, again)
		return
	}
	values := f.changes(o)
	if len(values) > 0 {
		if err := ui.o.Writer.UpdateSettings(r.Context(), author(s.account.Username), values); err != nil {
			ui.failed(w, r, s, err, ssoFields, again)
			return
		}
		var keys []string
		for _, k := range ssoFields {
			if _, ok := values[k]; ok {
				keys = append(keys, k)
			}
		}
		ui.wrote(r.Context(), s, "settings", "", "update", slices.Clip(keys))
	}
	http.Redirect(w, r, ui.base+"/sso?done=saved", http.StatusSeeOther)
}
