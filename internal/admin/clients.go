package admin

import (
	"net/http"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// clientJSON is the representation of an API client: never its secret nor its
// hash.
type clientJSON struct {
	ID     string   `json:"id"`
	Scopes []string `json:"scopes"`
}

func clientOf(c store.APIClient) clientJSON {
	j := clientJSON{ID: c.ID, Scopes: c.Scopes}
	if j.Scopes == nil {
		j.Scopes = []string{}
	}
	return j
}

var clientFields = []string{"id", "secret", "scopes"}

// applyClient writes the fields of b into c. A secret in clear is hashed, a
// bcrypt hash taken as it is; absent from a PUT or a PATCH, the secret stays
// (Q112), and so do the scopes (Q107); a client created without scopes has
// none (Q111).
func applyClient(b body, c *store.APIClient, mode writeMode) error {
	if err := b.unknown(clientFields); err != nil {
		return err
	}
	switch {
	case b.has("secret") && !b.null("secret"):
		secret, err := b.str("secret")
		if err != nil {
			return err
		}
		switch {
		case secret == "":
			return domain.Violations{{Field: "secret", Message: "is required"}}
		case domain.IsHash(secret):
			c.SecretHash = secret // the check bounds its cost
		default:
			if c.SecretHash, err = domain.HashSecret(secret); err != nil {
				return err
			}
		}
	case mode == create || b.null("secret"):
		return domain.Violations{{Field: "secret", Message: "is required"}}
	}
	if b.has("scopes") {
		scopes, err := b.strs("scopes")
		if err != nil {
			return err
		}
		c.Scopes = scopes
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	return nil
}

func (a *API) registerClients() {
	a.Handle("GET "+Prefix+"/oauth2-clients", Clients, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := page(r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		items := []clientJSON{}
		for _, c := range paginate(a.o.Config.Snapshot().APIClients, n) {
			items = append(items, clientOf(c))
		}
		writeResource(w, http.StatusOK, items)
	}))
	a.Handle("GET "+Prefix+"/oauth2-clients/{id}", Clients, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.o.Config.Snapshot().APIClient(r.PathValue("id"))
		if !ok {
			a.fail(w, r, "", store.ErrNotFound)
			return
		}
		writeResource(w, http.StatusOK, clientOf(c))
	}))
	a.Handle("POST "+Prefix+"/oauth2-clients", Clients, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		var c store.APIClient
		if b.has("id") {
			if c.ID, err = b.str("id"); err != nil {
				a.fail(w, r, "", err)
				return
			}
		}
		if err := applyClient(b, &c, create); err != nil {
			a.fail(w, r, "", err)
			return
		}
		if err := a.o.Writer.CreateAPIClient(r.Context(), author(r), c); err != nil {
			a.fail(w, r, "Client "+c.ID, err)
			return
		}
		a.wrote(r, Clients, c.ID, b.fieldsOf(clientFields))
		w.Header().Set("Location", Prefix+"/oauth2-clients/"+c.ID)
		writeResource(w, http.StatusCreated, clientOf(c))
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
			var written store.APIClient
			err = a.o.Writer.UpdateAPIClient(r.Context(), author(r), id, func(c *store.APIClient) error {
				if err := applyClient(b, c, mode); err != nil {
					return err
				}
				written = *c
				return nil
			})
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			a.wrote(r, Clients, id, b.fieldsOf(clientFields))
			writeResource(w, http.StatusOK, clientOf(written))
		}
	}
	a.Handle("PUT "+Prefix+"/oauth2-clients/{id}", Clients, update(replace))
	a.Handle("PATCH "+Prefix+"/oauth2-clients/{id}", Clients, update(patch))
	a.Handle("DELETE "+Prefix+"/oauth2-clients/{id}", Clients, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := a.o.Writer.DeleteAPIClient(r.Context(), id); err != nil {
			a.fail(w, r, "", err)
			return
		}
		a.wrote(r, Clients, id, nil)
		w.WriteHeader(http.StatusNoContent)
	}))
}
