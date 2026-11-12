package admin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// The catalogue of the scopes (P24), /admin/v1/scopes: the standard scopes of
// the code (Q125, Q130), first, in their order, then those of the business,
// by name. A standard scope is renamed, by PUT or PATCH: its label and those
// of its claims, never a claim more; it is neither created nor deleted. Its
// labels in the representation are those it renames, none for the code's:
// written back, a representation renames nothing.

// scopeJSON is the representation of a scope: every field present.
type scopeJSON struct {
	Name   string            `json:"name"`
	Label  map[string]string `json:"label"`
	Claims []scopeClaimJSON  `json:"claims"`
	// Builtin marks a standard scope of OpenID Connect.
	Builtin bool `json:"builtin"`
}

type scopeClaimJSON struct {
	Claim string            `json:"claim"`
	Label map[string]string `json:"label"`
}

func labelsOf(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// scopeOf is the representation of the scope name, its row row when found.
func scopeOf(name string, row store.Scope, found bool) scopeJSON {
	j := scopeJSON{Name: name, Label: labelsOf(row.Label), Claims: []scopeClaimJSON{}}
	labelOf := func(claim string) map[string]string {
		i := slices.IndexFunc(row.Claims, func(c domain.ScopeClaim) bool { return c.Claim == claim })
		if !found || i < 0 {
			return map[string]string{}
		}
		return labelsOf(row.Claims[i].Label)
	}
	if standard, ok := domain.Standard(name); ok {
		j.Builtin = true
		for _, c := range standard {
			j.Claims = append(j.Claims, scopeClaimJSON{Claim: c, Label: labelOf(c)})
		}
		return j
	}
	for _, c := range row.Claims {
		j.Claims = append(j.Claims, scopeClaimJSON{Claim: c.Claim, Label: labelsOf(c.Label)})
	}
	return j
}

// catalogue is the catalogue of snap: the standard scopes, then those of the
// business.
func catalogue(snap *store.Snapshot) []scopeJSON {
	var l []scopeJSON
	for _, s := range domain.StandardScopes {
		row, found := snap.Scope(s.Name)
		l = append(l, scopeOf(s.Name, row, found))
	}
	for _, row := range snap.Scopes {
		if _, standard := domain.Standard(row.Name); !standard {
			l = append(l, scopeOf(row.Name, row, true))
		}
	}
	return l
}

var scopeFields = []string{"name", "label", "claims"}

// applyScope writes the fields of b into s: absent, a PUT empties them, a
// PATCH keeps them; null is none.
func applyScope(b body, s *store.Scope, mode writeMode) error {
	if err := b.unknown(scopeFields, "builtin"); err != nil {
		return err
	}
	if mode == replace {
		s.Label, s.Claims = nil, nil
	}
	if b.has("label") {
		label, err := b.texts("label")
		if err != nil {
			return err
		}
		s.Label = label
	}
	if b.has("claims") && !b.null("claims") {
		var claims []struct {
			Claim *string            `json:"claim"`
			Label map[string]*string `json:"label"`
		}
		if err := json.Unmarshal(b["claims"], &claims); err != nil || claims == nil {
			return typeError("claims", "array", b["claims"])
		}
		s.Claims = nil
		for _, c := range claims {
			if c.Claim == nil {
				return requestViolations{{Field: "claims", Message: "each item names its claim: {\"claim\": ..., \"label\": {...}}"}}
			}
			label := map[string]string{}
			for locale, t := range c.Label {
				if t != nil && *t != "" {
					label[locale] = *t
				}
			}
			s.Claims = append(s.Claims, domain.ScopeClaim{Claim: *c.Claim, Label: label})
		}
	} else if b.null("claims") {
		s.Claims = nil
	}
	return nil
}

// checkPathName refuses a name of the body other than the path's: a name
// never changes.
func checkPathName(b body, name string) error {
	if !b.has("name") || b.null("name") {
		return nil
	}
	got, err := b.str("name")
	if err != nil {
		return err
	}
	if got != name {
		return domain.Violations{{Field: "name", Message: "is " + quote(got) + ", but the path names " + quote(name) + ": a name never changes"}}
	}
	return nil
}

func (a *API) registerScopes() {
	a.Handle("GET "+Prefix+"/scopes", Catalogue, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := page(r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		writeResource(w, http.StatusOK, append([]scopeJSON{}, paginate(catalogue(a.o.Config.Snapshot()), n)...))
	}))
	a.Handle("GET "+Prefix+"/scopes/{name}", Catalogue, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		row, found := a.o.Config.Snapshot().Scope(name)
		if _, standard := domain.Standard(name); !found && !standard {
			a.fail(w, r, "", store.ErrNotFound)
			return
		}
		writeResource(w, http.StatusOK, scopeOf(name, row, found))
	}))
	a.Handle("POST "+Prefix+"/scopes", Catalogue, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(w, r)
		if err != nil {
			a.fail(w, r, "", err)
			return
		}
		var s store.Scope
		if b.has("name") {
			if s.Name, err = b.str("name"); err != nil {
				a.fail(w, r, "", err)
				return
			}
		}
		if err := applyScope(b, &s, create); err != nil {
			a.fail(w, r, "", err)
			return
		}
		if err := a.o.Writer.CreateScope(r.Context(), author(r), s); err != nil {
			a.fail(w, r, "Scope "+s.Name, err)
			return
		}
		a.wrote(r, Catalogue, s.Name, b.fieldsOf(scopeFields))
		// The name escaped as a segment (R44): x/../email names x/../email,
		// not the standard scope email.
		w.Header().Set("Location", Prefix+"/scopes/"+url.PathEscape(s.Name))
		writeResource(w, http.StatusCreated, scopeOf(s.Name, s, true))
	}))
	update := func(mode writeMode) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			b, err := readBody(w, r)
			if err == nil {
				err = checkPathName(b, name)
			}
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			var written store.Scope
			err = a.o.Writer.UpdateScope(r.Context(), author(r), name, func(s *store.Scope) error {
				if err := applyScope(b, s, mode); err != nil {
					return err
				}
				written = *s
				return nil
			})
			if err != nil {
				a.fail(w, r, "", err)
				return
			}
			a.wrote(r, Catalogue, name, b.fieldsOf(scopeFields))
			writeResource(w, http.StatusOK, scopeOf(name, written, true))
		}
	}
	a.Handle("PUT "+Prefix+"/scopes/{name}", Catalogue, update(replace))
	a.Handle("PATCH "+Prefix+"/scopes/{name}", Catalogue, update(patch))
	a.Handle("DELETE "+Prefix+"/scopes/{name}", Catalogue, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := a.o.Writer.DeleteScope(r.Context(), name); err != nil {
			a.fail(w, r, "", err)
			return
		}
		a.wrote(r, Catalogue, name, nil)
		w.WriteHeader(http.StatusNoContent)
	}))
}
