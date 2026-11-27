package adminui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// A client of the admin API by its screen (Authentification des
// administrateurs): its secret generated and shown once, on the page that
// follows its creation or its rotation, never typed nor shown again; no
// hash. Every write of a client is sensitive, its scopes included, which
// give it what a role gives an account: they ask for the password again past
// admin.session.reauth_window.

// clientFields are the fields of the form of a client.
var clientFields = []string{"id", "secret", "scopes"}

// scopeBox is a scope of the form of a client.
type scopeBox struct {
	Name    string
	Checked bool
}

// clientVersion is the version of a client as its form shows it: its scopes,
// not its hash, which a rehash changes (Q118).
func clientVersion(c store.APIClient) string {
	return version(struct {
		ID     string
		Scopes []string
	}{c.ID, c.Scopes})
}

type clientRow struct {
	ID     string
	Scopes []string
}

type clientsPage struct{ Clients []clientRow }

type clientPage struct {
	ID, Version string
	Scopes      []scopeBox
	Errors      fieldErrors
	New         bool
}

// secretPage shows the secret of a client, once: What it is, Back its page.
type secretPage struct {
	ID      string `json:"id"`
	Secret  string `json:"secret"`
	What    string `json:"what"`
	Back    string `json:"back"`
	Created bool   `json:"created"`
	// Key is the key of the pre-check of an app, which the database holds
	// encrypted, not as a hash.
	Key bool `json:"key"`
}

// boxes are the scopes of the form: those of the dispatcher, then those the
// client holds besides, for a save to lose none.
func (ui *UI) boxes(held []string) []scopeBox {
	var b []scopeBox
	for _, s := range ui.o.Scopes {
		b = append(b, scopeBox{Name: s, Checked: slices.Contains(held, s)})
	}
	for _, s := range held {
		if !slices.Contains(ui.o.Scopes, s) {
			b = append(b, scopeBox{Name: s, Checked: true})
		}
	}
	return b
}

// readScopes are the scopes checked, in the order of the form.
func readScopes(r *http.Request) []string {
	var scopes []string
	for _, s := range r.PostForm["scope"] {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

func (ui *UI) registerClients() {
	ui.mux.Handle("GET /admin/clients", ui.authed(anyRole, ui.clients))
	ui.mux.Handle("GET /admin/clients/{id}", ui.authed(anyRole, ui.clientView))
	if ui.o.Writer == nil {
		return
	}
	ui.mux.Handle("GET /admin/clients/_new", ui.authed(adminRole, ui.fresh(ui.newClient)))
	ui.mux.Handle("POST /admin/clients", ui.authed(adminRole, ui.fresh(ui.createClient)))
	ui.mux.Handle("POST /admin/clients/{id}", ui.authed(adminRole, ui.fresh(ui.updateClient)))
	ui.mux.Handle("GET /admin/clients/{id}/rotate", ui.authed(adminRole, ui.fresh(ui.confirmClient("rotate"))))
	ui.mux.Handle("POST /admin/clients/{id}/rotate", ui.authed(adminRole, ui.fresh(ui.rotateClient)))
	ui.mux.Handle("GET /admin/clients/{id}/delete", ui.authed(adminRole, ui.fresh(ui.confirmClient("delete"))))
	ui.mux.Handle("POST /admin/clients/{id}/delete", ui.authed(adminRole, ui.fresh(ui.deleteClient)))
}

func (ui *UI) clientPath(id string) string { return ui.base + "/clients/" + url.PathEscape(id) }

func (ui *UI) clients(w http.ResponseWriter, r *http.Request, s *current) {
	p := clientsPage{}
	for _, c := range ui.o.Config.Snapshot().APIClients {
		p.Clients = append(p.Clients, clientRow{ID: c.ID, Scopes: c.Scopes})
	}
	ui.show(w, r, s, http.StatusOK, "clients", "API clients", "clients", p)
}

func (ui *UI) clientView(w http.ResponseWriter, r *http.Request, s *current) {
	c, ok := ui.o.Config.Snapshot().APIClient(r.PathValue("id"))
	if !ok {
		ui.status(w, r, http.StatusNotFound, "Not found", "No API client has this id.", s)
		return
	}
	ui.show(w, r, s, http.StatusOK, "client", "API client "+c.ID, "clients", clientPage{ID: c.ID, Version: clientVersion(c), Scopes: ui.boxes(c.Scopes)})
}

func (ui *UI) newClient(w http.ResponseWriter, r *http.Request, s *current) {
	ui.show(w, r, s, http.StatusOK, "client", "New API client", "clients", clientPage{Scopes: ui.boxes(nil), New: true})
}

// showSecret sends the browser to the secret of a client, the only time it
// is shown (handOver).
func (ui *UI) showSecret(w http.ResponseWriter, r *http.Request, s *current, id, secret string, created bool) {
	ui.handOver(w, r, s, "clients", secretPage{ID: id, Secret: secret, Created: created, What: "API client", Back: ui.clientPath(id)})
}

func (ui *UI) createClient(w http.ResponseWriter, r *http.Request, s *current) {
	id, scopes := strings.TrimSpace(r.PostFormValue("id")), readScopes(r)
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "client", "New API client", "clients", clientPage{ID: id, Scopes: ui.boxes(scopes), Errors: errs, New: true})
	}
	secret := domain.NewSecret()
	hash, err := domain.HashSecret(secret)
	if err != nil {
		ui.failed(w, r, s, err, clientFields, again)
		return
	}
	if err := ui.o.Writer.CreateAPIClient(r.Context(), author(s.account.Username), store.APIClient{ID: id, SecretHash: hash, Scopes: scopes}); err != nil {
		ui.failed(w, r, s, err, clientFields, again)
		return
	}
	ui.wrote(r.Context(), s, "oauth2-clients", id, "create", []string{"id", "secret", "scopes"})
	ui.showSecret(w, r, s, id, secret, true)
}

func (ui *UI) updateClient(w http.ResponseWriter, r *http.Request, s *current) {
	id, scopes, v := r.PathValue("id"), readScopes(r), strings.TrimSpace(r.PostFormValue("version"))
	again := func(status int, errs fieldErrors) {
		ui.show(w, r, s, status, "client", "API client "+id, "clients", clientPage{ID: id, Version: v, Scopes: ui.boxes(scopes), Errors: errs})
	}
	var fields []string
	err := ui.o.Writer.UpdateAPIClient(r.Context(), author(s.account.Username), id, func(c *store.APIClient) error {
		if now := clientVersion(*c); now != v {
			v = now
			return errChanged
		}
		// The same scopes in another order change nothing (revue R45).
		if slices.Equal(slices.Sorted(slices.Values(c.Scopes)), slices.Sorted(slices.Values(scopes))) {
			return errUnchanged
		}
		fields = []string{"scopes"}
		c.Scopes = scopes
		return nil
	})
	if errors.Is(err, errUnchanged) {
		http.Redirect(w, r, ui.clientPath(id)+"?done=saved", http.StatusSeeOther)
		return
	}
	if err != nil {
		ui.failed(w, r, s, err, clientFields, again)
		return
	}
	ui.wrote(r.Context(), s, "oauth2-clients", id, "update", fields)
	http.Redirect(w, r, ui.clientPath(id)+"?done=saved", http.StatusSeeOther)
}

// confirmPage is the page that asks before a sensitive action, its POST at
// Action.
type confirmPage struct {
	Title, Message, Action, Button, Back string
	Errors                               fieldErrors
}

func (ui *UI) clientConfirm(id, action string, errs fieldErrors) confirmPage {
	if action == "rotate" {
		return confirmPage{Title: "Turn the secret of " + id + "?", Action: ui.clientPath(id) + "/rotate", Button: "Turn the secret",
			Message: "A new secret replaces the current one at once: the client asks for tokens with the new one, shown once on the next page. " +
				"Its tokens already issued stay valid until they expire.",
			Back: ui.clientPath(id), Errors: errs}
	}
	return confirmPage{Title: "Delete the API client " + id + "?", Action: ui.clientPath(id) + "/delete", Button: "Delete the client",
		Message: "It can no longer ask for tokens. Its tokens already issued stay valid until they expire. Its deletion cannot be undone.",
		Back:    ui.clientPath(id), Errors: errs}
}

func (ui *UI) confirmClient(action string) func(http.ResponseWriter, *http.Request, *current) {
	return func(w http.ResponseWriter, r *http.Request, s *current) {
		id := r.PathValue("id")
		if _, ok := ui.o.Config.Snapshot().APIClient(id); !ok {
			ui.status(w, r, http.StatusNotFound, "Not found", "No API client has this id.", s)
			return
		}
		p := ui.clientConfirm(id, action, nil)
		ui.show(w, r, s, http.StatusOK, "confirm", p.Title, "clients", p)
	}
}

func (ui *UI) rotateClient(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	again := func(status int, errs fieldErrors) {
		p := ui.clientConfirm(id, "rotate", errs)
		ui.show(w, r, s, status, "confirm", p.Title, "clients", p)
	}
	secret := domain.NewSecret()
	hash, err := domain.HashSecret(secret)
	if err == nil {
		err = ui.o.Writer.UpdateAPIClient(r.Context(), author(s.account.Username), id, func(c *store.APIClient) error {
			c.SecretHash = hash
			return nil
		})
	}
	if err != nil {
		ui.failed(w, r, s, err, nil, again)
		return
	}
	ui.wrote(r.Context(), s, "oauth2-clients", id, "update", []string{"secret"})
	ui.showSecret(w, r, s, id, secret, false)
}

func (ui *UI) deleteClient(w http.ResponseWriter, r *http.Request, s *current) {
	id := r.PathValue("id")
	if err := ui.o.Writer.DeleteAPIClient(r.Context(), id); err != nil {
		ui.failed(w, r, s, err, nil, func(status int, errs fieldErrors) {
			p := ui.clientConfirm(id, "delete", errs)
			ui.show(w, r, s, status, "confirm", p.Title, "clients", p)
		})
		return
	}
	ui.wrote(r.Context(), s, "oauth2-clients", id, "delete", nil)
	http.Redirect(w, r, ui.base+"/clients?done=deleted", http.StatusSeeOther)
}
