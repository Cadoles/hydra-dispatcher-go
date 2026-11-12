//go:build integration

package store

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// The writes of the catalogue: a scope of the business created, changed,
// deleted; a standard one renamed, its row gone when it renames nothing,
// never created nor deleted.
func TestScopesOnPostgres(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	groups := Scope{Name: "groups", Label: map[string]string{"fr": "Vos groupes"}, Claims: []ScopeClaim{{Claim: "groups", Label: map[string]string{"fr": "Groupes"}}}}
	if err := p.CreateScope(ctx, "test", groups); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateScope(ctx, "test", groups); !errors.Is(err, ErrExists) {
		t.Errorf("twice: %v", err)
	}
	if err := p.CreateScope(ctx, "test", Scope{Name: "profile"}); !errors.Is(err, ErrStandard) {
		t.Errorf("a standard created: %v", err)
	}
	if err := p.CreateScope(ctx, "test", Scope{Name: "a b"}); !violated(err, "name") {
		t.Errorf("a space: %v", err)
	}
	if err := p.UpdateScope(ctx, "test", "profile", func(s *Scope) error {
		s.Label = map[string]string{"fr": "Qui vous êtes"}
		s.Claims = []ScopeClaim{{Claim: "picture", Label: map[string]string{"fr": "Votre photo"}}}
		return nil
	}); err != nil {
		t.Fatalf("a standard renamed: %v", err)
	}
	if err := p.UpdateScope(ctx, "test", "profile", func(s *Scope) error { s.Claims = append(s.Claims, ScopeClaim{Claim: "groups"}); return nil }); !violated(err, "claims[1]") {
		t.Errorf("a claim added to a standard: %v", err)
	}
	if err := p.UpdateScope(ctx, "test", "nothing", func(*Scope) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("an update of nothing: %v", err)
	}
	snap, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Scopes) != 2 || snap.Scopes[0].Name != "groups" || snap.Scopes[1].Label["fr"] != "Qui vous êtes" {
		t.Errorf("snapshot: %+v", snap.Scopes)
	}
	if claims, ok := snap.ScopeClaims("profile"); !ok || len(claims) != 14 {
		t.Errorf("profile's claims, the code's: %v", claims)
	}
	if claims, ok := snap.ScopeClaims("groups"); !ok || !slices.Equal(claims, []string{"groups"}) {
		t.Errorf("groups' claims: %v", claims)
	}
	if _, ok := snap.ScopeClaims("unknown"); ok {
		t.Error("an unknown scope")
	}
	// Renaming nothing, the row of a standard goes: the code's labels again.
	if err := p.UpdateScope(ctx, "test", "profile", func(s *Scope) error { s.Label, s.Claims = nil, nil; return nil }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM scope WHERE name = 'profile'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("the row of profile: %d %v", n, err)
	}
	if err := p.DeleteScope(ctx, "profile"); !errors.Is(err, ErrStandard) {
		t.Errorf("a standard deleted: %v", err)
	}
	if err := p.DeleteScope(ctx, "groups"); err != nil {
		t.Errorf("groups deleted: %v", err)
	}
	if err := p.DeleteScope(ctx, "groups"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted twice: %v", err)
	}
	// The constraints of 00006.
	for _, q := range []string{
		`INSERT INTO scope (name, label) VALUES ('a', '[]')`,
		`INSERT INTO scope (name, claims) VALUES ('a', '{}')`,
		`INSERT INTO scope (name) VALUES ('a b')`,
		`INSERT INTO scope (name) VALUES ('')`,
	} {
		if _, err := p.db.ExecContext(ctx, q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
}

// bootstrap and diff the scopes of the seed, as the apps.
func TestScopesBootstrap(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	seed := func(label string) string {
		return `
dispatcher:
  scopes:
    - name: groups
      label: { fr: ` + label + `, en: Your groups }
      claims:
        - claim: groups
          label: Groups
    - name: profile
      label: { fr: Qui vous êtes }
`
	}
	changes, err := p.Bootstrap(ctx, loadSeed(t, seed("Vos groupes")), Force, true)
	if err != nil {
		t.Fatal(err)
	}
	created := 0
	for _, c := range changes {
		if c.Kind == "scope" && c.Action == Create {
			created++
		}
	}
	if created != 2 {
		t.Errorf("changes: %+v", changes)
	}
	snap, _ := p.Snapshot(ctx)
	if g, _ := snap.Scope("groups"); g.Claims[0].Label[""] != "Groups" || g.Label["en"] != "Your groups" {
		t.Errorf("groups: %+v", g)
	}
	changes, err = p.Diff(ctx, loadSeed(t, seed("Vos groupes")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if c.Kind == "scope" && c.Action != Same {
			t.Errorf("the same seed: %+v", c)
		}
	}
	if err := p.CreateScope(ctx, "admin:x", Scope{Name: "extra"}); err != nil {
		t.Fatal(err)
	}
	changes, _ = p.Diff(ctx, loadSeed(t, seed("Autres groupes")))
	i := slices.IndexFunc(changes, func(c Change) bool { return c.Kind == "scope" && c.ID == "groups" })
	j := slices.IndexFunc(changes, func(c Change) bool { return c.Kind == "scope" && c.ID == "extra" })
	if i < 0 || changes[i].Action != Update || changes[i].Fields[0].Name != "label" || j < 0 || changes[j].Action != Absent {
		t.Errorf("changes: %+v", changes)
	}
	if _, err := p.Bootstrap(ctx, loadSeed(t, `
dispatcher:
  scopes:
    - name: profile
      claims: [{claim: groups}]
`), Force, true); err == nil {
		t.Error("a claim added to a standard by the seed")
	}
}
