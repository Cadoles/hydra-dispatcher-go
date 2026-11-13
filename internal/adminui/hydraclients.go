package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
)

// The screens of the clients of Hydra (P23), by its admin API: a page of them,
// a client by its id or its name; creation, modification, rotation of its
// secret and deletion, all behind the re-authentication, its addresses of
// return being among what they change. A modification writes the fields of
// the form that change alone, by a JSON Patch: the rest of the client stays
// (Q122). The rules of the ANSSI are named at a creation and at every
// modification, which they refuse while one is broken; a rotation and a
// deletion are always allowed (Q123).

// HydraClients are the clients of Hydra's admin API (hydra.Client).
type HydraClients interface {
	Clients(ctx context.Context, p hydra.ClientsPage) (hydra.ClientList, error)
	OAuthClient(ctx context.Context, id string) (json.RawMessage, error)
	CreateClient(ctx context.Context, body map[string]any) (json.RawMessage, error)
	PatchClient(ctx context.Context, id string, ops []hydra.PatchOp) (json.RawMessage, error)
	DeleteClient(ctx context.Context, id string) error
}

// hydraPageSize is how many clients a page lists.
const hydraPageSize = 50

// hydraFields are the fields of the form, by Hydra's members.
var hydraFields = append([]string{"client_name", "redirect_uris", "post_logout_redirect_uris", "grant_types", "response_types", "scope",
	"audience", "allowed_cors_origins", "token_endpoint_auth_method", "jwks_uri", "skip_consent", "logo_uri", "flows"}, lifespans...)

// box is a choice of the form among several, checked or not.
type box struct {
	Name    string
	Checked bool
}

// boxesOf are the choices offered, then those held besides, for a save to
// lose none.
func boxesOf(offered, held []string) []box {
	var b []box
	for _, o := range offered {
		b = append(b, box{o, slices.Contains(held, o)})
	}
	for _, h := range held {
		if !slices.Contains(offered, h) {
			b = append(b, box{h, true})
		}
	}
	return b
}

// hydraForm is the form of a client: the client as typed, and its choices.
type hydraForm struct {
	hydraClient
	Version                                              string
	RedirectText, PostLogoutText, AudienceText, CORSText string
	Grants, Responses, Methods, FlowBoxes                []box
}

func (ui *UI) hydraFormOf(c hydraClient) hydraForm {
	f := hydraForm{hydraClient: c, Version: version(c), RedirectText: strings.Join(c.RedirectURIs, "\n"),
		PostLogoutText: strings.Join(c.PostLogoutURIs, "\n"), AudienceText: strings.Join(c.Audience, "\n"), CORSText: strings.Join(c.CORS, "\n"),
		Grants: boxesOf(grantTypes, c.GrantTypes), Responses: boxesOf(responseTypes, c.ResponseTypes)}
	for _, m := range authMethods {
		f.Methods = append(f.Methods, box{m, c.AuthMethod == m})
	}
	if c.AuthMethod != "" && !slices.Contains(authMethods, c.AuthMethod) {
		f.Methods = append(f.Methods, box{c.AuthMethod, true})
	}
	var flows []string
	if ui.o.Config != nil {
		for _, fl := range ui.o.Config.Snapshot().Flows {
			flows = append(flows, fl.ID)
		}
	}
	f.FlowBoxes = boxesOf(flows, c.Flows)
	return f
}

// readHydraForm reads the form over the client c as Hydra holds it: what the
// form shows replaced, the rest kept.
func readHydraForm(r *http.Request, c hydraClient) (hydraClient, fieldErrors) {
	v := func(name string) string { return strings.TrimSpace(r.PostFormValue(name)) }
	heldMethod := c.AuthMethod
	// What only lost its spaces stays as Hydra holds it (revue R45).
	c.Name, c.Scope, c.AuthMethod = kept(c.Name, v("client_name")), keptWords(c.Scope, v("scope")), kept(c.AuthMethod, v("token_endpoint_auth_method"))
	c.JWKSURI, c.LogoURI = kept(c.JWKSURI, v("jwks_uri")), kept(c.LogoURI, v("logo_uri"))
	c.RedirectURIs, c.PostLogoutURIs = keptList(c.RedirectURIs, lines(r.PostFormValue("redirect_uris"))), keptList(c.PostLogoutURIs, lines(r.PostFormValue("post_logout_redirect_uris")))
	c.Audience, c.CORS = keptList(c.Audience, lines(r.PostFormValue("audience"))), keptList(c.CORS, lines(r.PostFormValue("allowed_cors_origins")))
	c.GrantTypes, c.ResponseTypes, c.Flows = r.PostForm["grant_types"], r.PostForm["response_types"], r.PostForm["flows"]
	c.SkipConsent = r.PostFormValue("skip_consent") != ""
	errs := fieldErrors{}
	if !slices.Contains(authMethods, c.AuthMethod) && c.AuthMethod != heldMethod {
		errs["token_endpoint_auth_method"] = append(errs["token_endpoint_auth_method"], "is not a method the form offers")
	}
	held := c.Lifespans
	c.Lifespans = map[string]string{}
	for _, l := range lifespans {
		s := v(l)
		switch {
		case s == "" && held[l] != "":
			// Hydra decodes a patch into the client it holds: null and remove
			// leave the lifespan as it was (R43).
			errs[l] = append(errs[l], "is held by Hydra, which never empties it: give a duration")
			s = held[l]
		case s != "":
			if d, err := time.ParseDuration(s); err != nil || d <= 0 {
				errs[l] = append(errs[l], "is not a positive duration: 30m, 1h, 720h")
				continue
			}
		}
		c.Lifespans[l] = s
	}
	if len(errs) > 0 {
		return c, errs
	}
	return c, nil
}

// sameDuration tells whether two lifespans are the same: Hydra writes 30m as
// 30m0s.
func sameDuration(a, b string) bool {
	if a == b {
		return true
	}
	x, errA := time.ParseDuration(a)
	y, errB := time.ParseDuration(b)
	return errA == nil && errB == nil && x == y
}

// list gives l, never nil: Hydra writes [] where the form gives none.
func list(l []string) []string { return append([]string{}, l...) }

// patchOf is the JSON Patch from the client was to the client now: its members
// that change alone, and their names; the metadata only when the flows
// checked change, the rest of them as Hydra holds it (R43).
func patchOf(was, now hydraClient) ([]hydra.PatchOp, []string, error) {
	var ops []hydra.PatchOp
	var fields []string
	set := func(member string, changed bool, value any) {
		if changed {
			ops = append(ops, hydra.PatchOp{Op: "add", Path: "/" + member, Value: value})
			fields = append(fields, member)
		}
	}
	set("client_name", was.Name != now.Name, now.Name)
	set("redirect_uris", !slices.Equal(was.RedirectURIs, now.RedirectURIs), list(now.RedirectURIs))
	set("post_logout_redirect_uris", !slices.Equal(was.PostLogoutURIs, now.PostLogoutURIs), list(now.PostLogoutURIs))
	// Boxes: their order is the form's, not a change (R43).
	set("grant_types", !sameSet(was.GrantTypes, now.GrantTypes), list(now.GrantTypes))
	set("response_types", !sameSet(was.ResponseTypes, now.ResponseTypes), list(now.ResponseTypes))
	set("scope", was.Scope != now.Scope, now.Scope)
	set("audience", !slices.Equal(was.Audience, now.Audience), list(now.Audience))
	set("allowed_cors_origins", !slices.Equal(was.CORS, now.CORS), list(now.CORS))
	set("token_endpoint_auth_method", was.AuthMethod != now.AuthMethod, now.AuthMethod)
	set("jwks_uri", was.JWKSURI != now.JWKSURI, now.JWKSURI)
	set("skip_consent", was.SkipConsent != now.SkipConsent, now.SkipConsent)
	set("logo_uri", was.LogoURI != now.LogoURI, now.LogoURI)
	// A lifespan Hydra holds is never emptied (readHydraForm): a change is a
	// duration.
	for _, l := range lifespans {
		set(l, !sameDuration(was.Lifespans[l], now.Lifespans[l]), now.Lifespans[l])
	}
	if !sameSet(was.Flows, now.Flows) {
		m, err := metadataWith(was.Metadata, now.Flows, true, time.Time{})
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, hydra.PatchOp{Op: "add", Path: "/metadata", Value: m})
		fields = append(fields, "metadata.dispatcher.flows")
	}
	return ops, fields, nil
}

type hydraRow struct {
	hydraClient
	Deviations  int
	SecretSince time.Time
	SecretExact bool
	SecretOld   bool
}

type hydraListPage struct {
	Rows             []hydraRow
	Query, Next      string
	Total            int
	First, Secretful bool
}

type hydraPage struct {
	Form       hydraForm
	Errors     fieldErrors
	Deviations []deviation
	New        bool
	// SecretSince is when its secret was set, SecretExact whether the
	// screen set it, SecretOld past admin.client_secret_max_age.
	SecretSince            time.Time
	SecretExact, SecretOld bool
	// Others are its other metadata, shown.
	Others string
	// Unreadable says why the form does not read it, Secretless whether it
	// has no secret to turn: the page offers its rotation and its deletion
	// alone (revue R43).
	Unreadable string
	Secretless bool
}

func (ui *UI) registerHydraClients() {
	ui.mux.Handle("GET /admin/hydra-clients", ui.authed(anyRole, ui.hydraClients))
	ui.mux.Handle("GET /admin/hydra-clients/{id}", ui.authed(anyRole, ui.hydraClientView))
	ui.mux.Handle("GET /admin/hydra-clients/_new", ui.authed(adminRole, ui.fresh(ui.newHydraClient)))
	ui.mux.Handle("POST /admin/hydra-clients", ui.authed(adminRole, ui.fresh(ui.createHydraClient)))
	ui.mux.Handle("POST /admin/hydra-clients/{id}", ui.authed(adminRole, ui.fresh(ui.updateHydraClient)))
	ui.mux.Handle("GET /admin/hydra-clients/{id}/rotate", ui.authed(adminRole, ui.fresh(ui.confirmHydraClient("rotate"))))
	ui.mux.Handle("POST /admin/hydra-clients/{id}/rotate", ui.authed(adminRole, ui.fresh(ui.rotateHydraClient)))
	ui.mux.Handle("GET /admin/hydra-clients/{id}/delete", ui.authed(adminRole, ui.fresh(ui.confirmHydraClient("delete"))))
	ui.mux.Handle("POST /admin/hydra-clients/{id}/delete", ui.authed(adminRole, ui.fresh(ui.deleteHydraClient)))
}

func (ui *UI) hydraPath(id string) string { return ui.base + "/hydra-clients/" + url.PathEscape(id) }

// secretOld tells whether a secret set at since is past
// admin.client_secret_max_age.
func (ui *UI) secretOld(since time.Time) bool {
	return ui.o.SecretMaxAge > 0 && !since.IsZero() && ui.o.Now().Sub(since) > ui.o.SecretMaxAge
}

// hydraFailed answers an error of Hydra: absent, its refusal under the form
// by again, or Hydra out of reach, its cause in the log.
func (ui *UI) hydraFailed(w http.ResponseWriter, r *http.Request, s *current, err error, again func(int, fieldErrors)) {
	var refused *hydra.RequestError
	switch {
	case errors.As(err, &refused) && refused.Status == http.StatusNotFound:
		ui.status(w, r, http.StatusNotFound, "Not found", "Hydra has no client of this id.", s)
	case errors.As(err, &refused) && again != nil && (refused.Status == http.StatusBadRequest || refused.Status == http.StatusConflict):
		var doc struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(refused.Body, &doc)
		why := doc.Description
		if why == "" {
			why = doc.Error
		}
		again(http.StatusUnprocessableEntity, fieldErrors{"": {"Hydra refuses it: " + httpx.BoundedCause(why)}})
	default:
		ui.hydraFailedLog(r.Context(), err)
		ui.status(w, r, http.StatusServiceUnavailable, "Unavailable", "Hydra cannot be reached now: try again in a moment.", s)
	}
}

// hydraFailedLog writes admin.hydra_failed: the operation, the status and a
// cause without the answer of Hydra, whose error document the log never holds
// (R43, R45); the text of another error. Every screen that calls Hydra logs
// its failures by it.
func (ui *UI) hydraFailedLog(ctx context.Context, err error) {
	if ui.o.Logger == nil {
		return
	}
	op, status, cause := hydra.Failure(err)
	if op == "" {
		cause = httpx.BoundedCause(err.Error())
	}
	ui.o.Logger.ErrorContext(ctx, "admin.hydra_failed", "op", op, "status", status, "cause", cause)
}

func (ui *UI) hydraClients(w http.ResponseWriter, r *http.Request, s *current) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" {
		// An id opens its client; otherwise a name, exact.
		if _, err := ui.o.HydraClients.OAuthClient(r.Context(), q); err == nil {
			http.Redirect(w, r, ui.hydraPath(q), http.StatusSeeOther)
			return
		}
	}
	token := r.URL.Query().Get("page")
	l, err := ui.o.HydraClients.Clients(r.Context(), hydra.ClientsPage{Size: hydraPageSize, Token: token, Name: q})
	if err != nil {
		ui.hydraFailed(w, r, s, err, nil)
		return
	}
	p := hydraListPage{Query: q, Next: l.Next, Total: l.Total, First: token == ""}
	if q != "" {
		// Under a filter, Hydra's X-Total-Count is that of all its clients
		// (R43): those named q are counted on a single page alone.
		p.Total = -1
		if token == "" && l.Next == "" {
			p.Total = len(l.Clients)
		}
	}
	for _, raw := range l.Clients {
		c, err := parseClient(raw)
		if err != nil {
			continue
		}
		if c.Unreadable != "" {
			p.Rows = append(p.Rows, hydraRow{hydraClient: c})
			continue
		}
		row := hydraRow{hydraClient: c, Deviations: len(c.deviations(ui.o.AllowHTTP))}
		if !c.secretless() {
			row.SecretSince, row.SecretExact = c.secretSince()
			row.SecretOld = ui.secretOld(row.SecretSince)
		}
		p.Rows = append(p.Rows, row)
	}
	ui.show(w, r, s, http.StatusOK, "hydra_clients", "Hydra clients", "hydra", p)
}

// hydraClientOf reads the client of the path, or answers why it cannot.
func (ui *UI) hydraClientOf(w http.ResponseWriter, r *http.Request, s *current) (hydraClient, bool) {
	raw, err := ui.o.HydraClients.OAuthClient(r.Context(), r.PathValue("id"))
	if err != nil {
		ui.hydraFailed(w, r, s, err, nil)
		return hydraClient{}, false
	}
	c, err := parseClient(raw)
	if err != nil {
		ui.hydraFailed(w, r, s, err, nil)
		return hydraClient{}, false
	}
	return c, true
}

func (ui *UI) hydraPageOf(c hydraClient, f hydraForm, errs fieldErrors, isNew bool) hydraPage {
	if c.Unreadable != "" {
		return hydraPage{Form: hydraForm{hydraClient: hydraClient{ID: c.ID, Name: c.Name}}, Errors: errs, Unreadable: c.Unreadable, Secretless: c.secretless()}
	}
	p := hydraPage{Form: f, Errors: errs, Deviations: c.deviations(ui.o.AllowHTTP), New: isNew}
	if !isNew && !c.secretless() {
		p.SecretSince, p.SecretExact = c.secretSince()
		p.SecretOld = ui.secretOld(p.SecretSince)
	}
	// Its other metadata: those of the dispatcher apart, which the page
	// shows; metadata that are not an object as Hydra holds them.
	others, ok := metadataOf(c.Metadata)
	if !ok {
		p.Others = string(c.Metadata)
		return p
	}
	if d, ok := others["dispatcher"].(map[string]any); ok {
		delete(d, "flows")
		delete(d, "secret_rotated_at")
		if len(d) == 0 {
			delete(others, "dispatcher")
		}
	}
	if len(others) > 0 {
		b, _ := json.MarshalIndent(others, "", "  ")
		p.Others = string(b)
	}
	return p
}

func (ui *UI) hydraClientView(w http.ResponseWriter, r *http.Request, s *current) {
	c, ok := ui.hydraClientOf(w, r, s)
	if !ok {
		return
	}
	ui.show(w, r, s, http.StatusOK, "hydra_client", "Hydra client "+c.ID, "hydra", ui.hydraPageOf(c, ui.hydraFormOf(c), nil, false))
}

// newClientDefaults are those the form of a new client proposes: the code
// flow, private_key_jwt (R23).
var newClientDefaults = hydraClient{AuthMethod: "private_key_jwt", GrantTypes: []string{"authorization_code", "refresh_token"},
	ResponseTypes: []string{"code"}, Scope: "openid offline", Lifespans: map[string]string{}}

func (ui *UI) newHydraClient(w http.ResponseWriter, r *http.Request, s *current) {
	f := ui.hydraFormOf(newClientDefaults)
	f.Version = ""
	ui.show(w, r, s, http.StatusOK, "hydra_client", "New Hydra client", "hydra", hydraPage{Form: f, New: true})
}

// deviationErrors are the rules a client breaks, by their fields.
func deviationErrors(d []deviation) fieldErrors {
	errs := fieldErrors{}
	for _, x := range d {
		errs[x.Field] = append(errs[x.Field], x.Message)
	}
	return errs
}

func (ui *UI) createHydraClient(w http.ResponseWriter, r *http.Request, s *current) {
	c, errs := readHydraForm(r, newClientDefaults)
	again := func(status int, errs fieldErrors) {
		f := ui.hydraFormOf(c)
		f.Version = ""
		ui.show(w, r, s, status, "hydra_client", "New Hydra client", "hydra", hydraPage{Form: f, Errors: errs, New: true})
	}
	if errs != nil {
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	if d := c.deviations(ui.o.AllowHTTP); len(d) > 0 {
		again(http.StatusUnprocessableEntity, deviationErrors(d))
		return
	}
	body := map[string]any{"client_name": c.Name, "redirect_uris": list(c.RedirectURIs), "post_logout_redirect_uris": list(c.PostLogoutURIs),
		"grant_types": list(c.GrantTypes), "response_types": list(c.ResponseTypes), "scope": c.Scope, "audience": list(c.Audience),
		"allowed_cors_origins": list(c.CORS), "token_endpoint_auth_method": c.AuthMethod, "jwks_uri": c.JWKSURI, "skip_consent": c.SkipConsent,
		"logo_uri": c.LogoURI}
	for _, l := range lifespans {
		if c.Lifespans[l] != "" {
			body[l] = c.Lifespans[l]
		}
	}
	secret := ""
	var rotated time.Time
	if !c.secretless() {
		secret, rotated = domain.NewSecret(), ui.o.Now()
		body["client_secret"] = secret
	}
	if m, _ := metadataWith(nil, c.Flows, true, rotated); len(m) > 0 {
		body["metadata"] = m
	}
	raw, err := ui.o.HydraClients.CreateClient(r.Context(), body)
	if err != nil {
		ui.hydraFailed(w, r, s, err, again)
		return
	}
	created, err := parseClient(raw)
	if err != nil || created.ID == "" {
		ui.hydraFailed(w, r, s, errors.New("hydra gave no client_id"), nil)
		return
	}
	fields := []string{"client_name", "redirect_uris", "grant_types", "token_endpoint_auth_method"}
	if secret != "" {
		fields = append(fields, "client_secret")
	}
	ui.wrote(r.Context(), s, "hydra-clients", created.ID, "create", fields)
	if secret == "" {
		http.Redirect(w, r, ui.hydraPath(created.ID)+"?done=created", http.StatusSeeOther)
		return
	}
	ui.handOver(w, r, s, "hydra", secretPage{ID: created.ID, Secret: secret, Created: true, Back: ui.hydraPath(created.ID), What: "Hydra client"})
}

func (ui *UI) updateHydraClient(w http.ResponseWriter, r *http.Request, s *current) {
	was, ok := ui.hydraClientOf(w, r, s)
	if !ok {
		return
	}
	if was.Unreadable != "" {
		ui.show(w, r, s, http.StatusConflict, "hydra_client", "Hydra client "+was.ID, "hydra", ui.hydraPageOf(was, hydraForm{}, nil, false))
		return
	}
	now, errs := readHydraForm(r, was)
	form := ui.hydraFormOf(now)
	form.Version = version(was)
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "hydra_client", "Hydra client "+was.ID, "hydra", ui.hydraPageOf(now, form, errs, false))
	}
	switch {
	case version(was) != strings.TrimSpace(r.PostFormValue("version")):
		ui.failed(w, r, s, errChanged, hydraFields, again)
		return
	case errs != nil:
		again(http.StatusUnprocessableEntity, errs)
		return
	}
	if d := now.deviations(ui.o.AllowHTTP); len(d) > 0 {
		again(http.StatusUnprocessableEntity, deviationErrors(d))
		return
	}
	ops, fields, err := patchOf(was, now)
	if err != nil {
		again(http.StatusUnprocessableEntity, fieldErrors{"flows": {err.Error()}})
		return
	}
	if len(ops) > 0 {
		if _, err := ui.o.HydraClients.PatchClient(r.Context(), was.ID, ops); err != nil {
			ui.hydraFailed(w, r, s, err, again)
			return
		}
		ui.wrote(r.Context(), s, "hydra-clients", was.ID, "update", fields)
	}
	http.Redirect(w, r, ui.hydraPath(was.ID)+"?done=saved", http.StatusSeeOther)
}

func (ui *UI) hydraConfirm(c hydraClient, action string, errs fieldErrors) confirmPage {
	if action == "rotate" {
		p := confirmPage{Title: "Turn the secret of " + c.ID + "?", Action: ui.hydraPath(c.ID) + "/rotate", Button: "Turn the secret",
			Message: "A new secret replaces the current one at once, shown once on the next page: the client gets no token by the former any more.",
			Back:    ui.hydraPath(c.ID), Errors: errs}
		if c.secretless() {
			p.Action, p.Message = "", "This client authenticates by "+c.AuthMethod+": it has no secret to turn."
		}
		return p
	}
	return confirmPage{Title: "Delete the Hydra client " + c.ID + "?", Action: ui.hydraPath(c.ID) + "/delete", Button: "Delete the client",
		Message: "Its users can no longer log in by it. Its deletion cannot be undone.", Back: ui.hydraPath(c.ID), Errors: errs}
}

func (ui *UI) confirmHydraClient(action string) func(http.ResponseWriter, *http.Request, *current) {
	return func(w http.ResponseWriter, r *http.Request, s *current) {
		c, ok := ui.hydraClientOf(w, r, s)
		if !ok {
			return
		}
		p := ui.hydraConfirm(c, action, nil)
		ui.show(w, r, s, http.StatusOK, "confirm", p.Title, "hydra", p)
	}
}

// rotateHydraClient gives the client a new secret of 256 bits, shown once,
// and the time of it in its metadata: always allowed, a client out of the
// rules of the ANSSI too (Q123).
func (ui *UI) rotateHydraClient(w http.ResponseWriter, r *http.Request, s *current) {
	c, ok := ui.hydraClientOf(w, r, s)
	if !ok {
		return
	}
	again := func(status int, errs fieldErrors) {
		p := ui.hydraConfirm(c, "rotate", errs)
		ui.show(w, r, s, status, "confirm", p.Title, "hydra", p)
	}
	if c.secretless() {
		again(http.StatusConflict, fieldErrors{"": {"This client has no secret to turn."}})
		return
	}
	secret := domain.NewSecret()
	ops := []hydra.PatchOp{{Op: "add", Path: "/client_secret", Value: secret}}
	// Its time in the metadata, the rest of them as Hydra holds it (R43);
	// metadata that cannot hold it are left, the secret turned all the same.
	if m, err := metadataWith(c.Metadata, nil, false, ui.o.Now()); err == nil {
		ops = append(ops, hydra.PatchOp{Op: "add", Path: "/metadata", Value: m})
	}
	if _, err := ui.o.HydraClients.PatchClient(r.Context(), c.ID, ops); err != nil {
		ui.hydraFailed(w, r, s, err, again)
		return
	}
	ui.wrote(r.Context(), s, "hydra-clients", c.ID, "update", []string{"client_secret"})
	ui.handOver(w, r, s, "hydra", secretPage{ID: c.ID, Secret: secret, Back: ui.hydraPath(c.ID), What: "Hydra client"})
}

func (ui *UI) deleteHydraClient(w http.ResponseWriter, r *http.Request, s *current) {
	c, ok := ui.hydraClientOf(w, r, s)
	if !ok {
		return
	}
	if err := ui.o.HydraClients.DeleteClient(r.Context(), c.ID); err != nil {
		ui.hydraFailed(w, r, s, err, func(status int, errs fieldErrors) {
			p := ui.hydraConfirm(c, "delete", errs)
			ui.show(w, r, s, status, "confirm", p.Title, "hydra", p)
		})
		return
	}
	ui.wrote(r.Context(), s, "hydra-clients", c.ID, "delete", nil)
	http.Redirect(w, r, ui.base+"/hydra-clients?done=deleted", http.StatusSeeOther)
}
