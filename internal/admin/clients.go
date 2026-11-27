package admin

import (
	"net/http"

	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
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

// secretHashOf is the hash of the secret b brings, "" when it brings none: a
// secret in clear is hashed, a bcrypt hash taken as it is. It runs before the
// write: bcrypt under the lock of the writes held the others (revue R35).
func secretHashOf(b body, mode writeMode) (string, error) {
	if err := b.unknown(clientFields); err != nil {
		return "", err
	}
	switch {
	case b.has("secret") && !b.null("secret"):
		secret, err := b.str("secret")
		switch {
		case err != nil:
			return "", err
		case secret == "":
			return "", domain.Violations{{Field: "secret", Message: "is required"}}
		case domain.IsHash(secret):
			return secret, nil // the check bounds its cost
		}
		return domain.HashSecret(secret)
	case mode == create || b.null("secret"):
		return "", domain.Violations{{Field: "secret", Message: "is required"}}
	}
	return "", nil
}

// applyClient writes the fields of b into c, the secret hashed by
// secretHashOf; absent from a PUT or a PATCH, the secret stays (Q112), and so
// do the scopes (Q107); a client created without scopes has none (Q111).
func applyClient(b body, hash string, c *store.APIClient) error {
	if hash != "" {
		c.SecretHash = hash
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
		hash, err := secretHashOf(b, create)
		if err == nil {
			err = applyClient(b, hash, &c)
		}
		if err != nil {
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
			// Hashed out of the lock, its error answered from within the
			// write: an absent client gets its 404 first, as before and as
			// the apps and the flows (revue R38).
			hash, hashErr := secretHashOf(b, mode)
			var written store.APIClient
			err = a.o.Writer.UpdateAPIClient(r.Context(), author(r), id, func(c *store.APIClient) error {
				if hashErr != nil {
					return hashErr
				}
				if err := applyClient(b, hash, c); err != nil {
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
