package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Cadoles/hydra-dispatcher-go/internal/config"
	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
)

// Scope is a row of the catalogue of the scopes (P24): a scope of the
// business, or the labels a standard scope renames (Q125).
type Scope = domain.Scope

// ScopeClaim is a claim of a scope, its label by locale.
type ScopeClaim = domain.ScopeClaim

// ErrStandard refuses to create or delete a standard scope: the code's, it is
// renamed alone.
var ErrStandard = errors.New("a standard scope of OpenID Connect is renamed, never created nor deleted")

// ScopeClaims gives the claims the scope name covers: a standard scope's are
// the code's, a business scope's its row's; false for a scope the catalogue
// does not have.
func (s *Snapshot) ScopeClaims(name string) ([]string, bool) {
	if claims, ok := domain.Standard(name); ok {
		return claims, true
	}
	sc, ok := s.Scope(name)
	if !ok {
		return nil, false
	}
	claims := make([]string, len(sc.Claims))
	for i, c := range sc.Claims {
		claims[i] = c.Claim
	}
	return claims, true
}

// Scope gives the row of the scope name, a business scope's or the labels of
// a standard one.
func (s *Snapshot) Scope(name string) (Scope, bool) {
	i := slices.IndexFunc(s.Scopes, func(sc Scope) bool { return sc.Name == name })
	if i < 0 {
		return Scope{}, false
	}
	return s.Scopes[i], true
}

// empty tells whether the row of a standard scope renames nothing: written,
// it would only hide the code's labels behind none.
func empty(sc Scope) bool {
	if len(sc.Label) > 0 {
		return false
	}
	return !slices.ContainsFunc(sc.Claims, func(c domain.ScopeClaim) bool { return len(c.Label) > 0 })
}

func readScopes(ctx context.Context, q querier) ([]Scope, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, label, claims FROM scope ORDER BY name COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var scopes []Scope
	for rows.Next() {
		var sc Scope
		var label, claims []byte
		if err := rows.Scan(&sc.Name, &label, &claims); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(label, &sc.Label); err != nil {
			return nil, fmt.Errorf("scope %s: label: %w", sc.Name, err)
		}
		if err := json.Unmarshal(claims, &sc.Claims); err != nil {
			return nil, fmt.Errorf("scope %s: claims: %w", sc.Name, err)
		}
		scopes = append(scopes, sc)
	}
	return scopes, rows.Err()
}

func findScope(ctx context.Context, q querier, name string) (Scope, bool, error) {
	scopes, err := readScopes(ctx, q)
	if err != nil {
		return Scope{}, false, err
	}
	i := slices.IndexFunc(scopes, func(sc Scope) bool { return sc.Name == name })
	if i < 0 {
		return Scope{}, false, nil
	}
	return scopes[i], true, nil
}

// putScope writes sc, created or replaced, by the author by; the row of a
// standard scope that renames nothing is deleted, its labels the code's again.
func putScope(ctx context.Context, tx *sql.Tx, sc Scope, by string) error {
	if _, standard := domain.Standard(sc.Name); standard && empty(sc) {
		_, err := tx.ExecContext(ctx, `DELETE FROM scope WHERE name = $1`, sc.Name)
		return err
	}
	label, _ := json.Marshal(nonNilMap(sc.Label))
	claims := sc.Claims
	if claims == nil {
		claims = []domain.ScopeClaim{}
	}
	for i := range claims {
		claims[i].Label = nonNilMap(claims[i].Label)
	}
	data, _ := json.Marshal(claims)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO scope (name, label, claims, updated_at, updated_by) VALUES ($1, $2::jsonb, $3::jsonb, now(), $4)
		ON CONFLICT (name) DO UPDATE SET label = EXCLUDED.label, claims = EXCLUDED.claims, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		sc.Name, string(label), string(data), by); err != nil {
		return fmt.Errorf("scope %s: %w", sc.Name, err)
	}
	return nil
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// CreateScope writes a new scope of the business: ErrExists when its name is
// taken, ErrStandard for the name of a standard scope.
func (p *Postgres) CreateScope(ctx context.Context, by string, sc Scope) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	if _, standard := domain.Standard(sc.Name); standard {
		return ErrStandard
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		if v := domain.Collect(sc.Check); v != nil {
			return v
		}
		if _, found, err := findScope(ctx, tx, sc.Name); err != nil || found {
			return cmpErr(err, ErrExists)
		}
		return putScope(ctx, tx, sc, by)
	})
}

// UpdateScope applies change to the scope name as the database holds it: a
// business scope, ErrNotFound when there is none; a standard scope, its row
// or none yet, whose labels alone change. The name cannot change.
func (p *Postgres) UpdateScope(ctx context.Context, by, name string, change func(*Scope) error) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	_, standard := domain.Standard(name)
	return p.write(ctx, func(tx *sql.Tx) error {
		sc, found, err := findScope(ctx, tx, name)
		if err != nil {
			return err
		}
		if !found && !standard {
			return ErrNotFound
		}
		if !found {
			sc = Scope{Name: name}
		}
		if err := change(&sc); err != nil {
			return err
		}
		if sc.Name != name {
			return domain.Violations{{Field: "name", Message: fmt.Sprintf("is %q, and an update cannot change it to %q", name, sc.Name)}}
		}
		if v := domain.Collect(sc.Check); v != nil {
			return v
		}
		return putScope(ctx, tx, sc, by)
	})
}

// DeleteScope deletes the scope of the business name: ErrNotFound when there
// is none, ErrStandard for a standard scope.
func (p *Postgres) DeleteScope(ctx context.Context, name string) error {
	if _, standard := domain.Standard(name); standard {
		return ErrStandard
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		return deleteRow(ctx, tx, `DELETE FROM scope WHERE name = $1`, name)
	})
}

// scopes is the step of bootstrap for the catalogue of the scopes, as the
// apps': each scope of the seed created, kept or replaced as the mode says;
// those the database holds besides kept, and told.
func (b *bootstrap) scopes(seed config.Seed) error {
	current, err := readScopes(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read scopes: %w", err)
	}
	authors, err := readAuthors(b.ctx, b.tx, "scope", "name")
	if err != nil {
		return fmt.Errorf("read scopes: %w", err)
	}
	seen := map[string]bool{}
	for _, ss := range seed.Scopes {
		sc := ss.Scope()
		if seen[sc.Name] {
			return fmt.Errorf("scope %s: twice in the seed", sc.Name)
		}
		seen[sc.Name] = true
		if v := domain.Collect(sc.Check); v != nil {
			return fmt.Errorf("scope %s: %w", sc.Name, v)
		}
		i := slices.IndexFunc(current, func(c Scope) bool { return c.Name == sc.Name })
		var old Scope
		if i >= 0 {
			old = current[i]
		}
		if !b.decide("scope", sc.Name, i >= 0, authors[sc.Name], []field{
			{name: "label", old: nonNilMap(old.Label), new: nonNilMap(sc.Label)},
			{name: "claims", old: claimsOf(old), new: claimsOf(sc)},
		}) || b.compare {
			continue
		}
		if err := putScope(b.ctx, b.tx, sc, bootstrapBy); err != nil {
			return err
		}
	}
	names := make([]string, len(current))
	for i, c := range current {
		names[i] = c.Name
	}
	b.absent("scope", names, func(name string) bool { return seen[name] })
	return nil
}

// claimsOf are the claims of sc as the table holds them, for a comparison.
func claimsOf(sc Scope) []domain.ScopeClaim {
	out := []domain.ScopeClaim{}
	for _, c := range sc.Claims {
		out = append(out, domain.ScopeClaim{Claim: c.Claim, Label: nonNilMap(c.Label)})
	}
	return out
}
