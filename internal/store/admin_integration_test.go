//go:build integration

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/domain"
)

func TestAdminAccounts(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	hash, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Minute)
	if err := p.CreateAdmin(ctx, AdminUser{Username: "alice", PasswordHash: hash, Role: domain.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "bob", OIDCSub: "248289761001", Role: domain.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "alice", Role: domain.RoleViewer}); !errors.Is(err, ErrExists) {
		t.Errorf("a name taken: %v", err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "carol", Role: "super_admin"}); !violated(err, "role") {
		t.Errorf("a role unknown: %v", err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "carol ", Role: domain.RoleViewer}); !violated(err, "username") {
		t.Errorf("a space at the end: %v", err)
	}

	users, err := p.Admins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].Username != "alice" || users[0].PasswordHash != hash || users[0].OIDCSub != "" ||
		users[1].Username != "bob" || users[1].PasswordHash != "" || users[1].OIDCSub != "248289761001" || users[1].Role != domain.RoleViewer ||
		users[0].CreatedAt.Before(start) {
		t.Fatalf("accounts: %+v", users)
	}
	// "" is NULL: the column is unique, and two accounts without a subject
	// would collide.
	var nulls int
	if err := p.db.QueryRow(`SELECT count(*) FROM admin_user WHERE (username = 'alice' AND oidc_sub IS NULL) OR (username = 'bob' AND password_hash IS NULL)`).Scan(&nulls); err != nil || nulls != 2 {
		t.Errorf("NULL for none: %d %v", nulls, err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "carol", Role: domain.RoleViewer}); err != nil {
		t.Errorf("a second account without a subject: %v", err)
	}

	// The last admin keeps its role; a second one frees it.
	demote := func(u *AdminUser) error { u.Role = domain.RoleViewer; return nil }
	if err := p.UpdateAdmin(ctx, "alice", demote); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("the last admin demoted: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "bob", func(u *AdminUser) error { u.Role = domain.RoleAdmin; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateAdmin(ctx, "alice", demote); err != nil {
		t.Errorf("an admin demoted beside another: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "alice", func(u *AdminUser) error { u.PasswordHash = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateAdmin(ctx, "alice", func(u *AdminUser) error { u.Username = "alicia"; return nil }); !violated(err, "username") {
		t.Errorf("a rename: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "alice", func(u *AdminUser) error { u.PasswordHash = "s3cret"; return nil }); !violated(err, "password") {
		t.Errorf("a password in clear: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "nobody", demote); !errors.Is(err, ErrNotFound) {
		t.Errorf("an account unknown: %v", err)
	}
	refused := errors.New("refused")
	if err := p.UpdateAdmin(ctx, "alice", func(*AdminUser) error { return refused }); !errors.Is(err, refused) {
		t.Errorf("the error of change: %v", err)
	}
	users, _ = p.Admins(ctx)
	if users[0].Role != domain.RoleViewer || users[0].PasswordHash != "" || users[1].Role != domain.RoleAdmin {
		t.Errorf("after the updates: %+v", users)
	}
	// The accounts are not the configuration: no instance is told.
	if s := snapshot(t, p); len(s.Apps) != 0 {
		t.Errorf("snapshot: %+v", s)
	}
}

// Two admins demoted at once, from two instances: one of them stays admin.
func TestAdminLastConcurrently(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	q := replica(t, p)
	demote := func(u *AdminUser) error { u.Role = domain.RoleViewer; return nil }
	for i := range 10 {
		exec(t, p, `DELETE FROM admin_user`)
		exec(t, p, `INSERT INTO admin_user (username, role) VALUES ('a', 'admin'), ('b', 'admin')`)
		errs := make(chan error, 2)
		go func() { errs <- p.UpdateAdmin(ctx, "a", demote) }()
		go func() { errs <- q.UpdateAdmin(ctx, "b", demote) }()
		e1, e2 := <-errs, <-errs
		if (e1 == nil) == (e2 == nil) || !errors.Is(errors.Join(e1, e2), ErrLastAdmin) {
			t.Errorf("round %d: %v, %v; want one refused", i, e1, e2)
		}
	}
}

// config diff gives what bootstrap -force would write, reading only: a role
// that may only read runs it, where the dry run of bootstrap, which writes
// then rolls back, is refused.
func TestDiff(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('a', 'http://old/login', 'http://a/consent', 'pwd', '{email}')`)
	exec(t, p, `INSERT INTO flow (id, title, description) VALUES ('legacy', '{"fr": "L"}', '{"fr": "L"}')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ('legacy', 'a', 0)`)
	exec(t, p, `INSERT INTO setting (key, value, updated_by) VALUES ('consent_auto_accept', 'true', 'api_client:ci'), ('remember', 'false', NULL)`)
	exec(t, p, `INSERT INTO api_client (id, secret_hash) VALUES ('c', 'not-a-hash'), ('legacy', 'not-a-hash')`)
	seed := loadSeed(t, `
dispatcher:
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd, receive_claims: [email, name] }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: a, order: 0 }] }
  oauth2_clients:
    - { id: c, secret: s3cret, scopes: [admin:flows, admin:apps] }
  consent_auto_accept: false
  remember: ~
`)
	before := snapshot(t, p)
	dryRun, err := p.Bootstrap(ctx, seed, Force, false)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := p.Diff(ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"update setting consent_auto_accept: value", "reset setting remember: value",
		"update app a: login_url,receive_claims",
		"create flow f", "absent flow legacy",
		"update api_client c: secret,scopes", "absent api_client legacy",
	}
	if got := actions(diff); !slices.Equal(got, want) {
		t.Errorf("diff = %q\nwant %q", got, want)
	}
	if !reflect.DeepEqual(diff, dryRun) {
		t.Errorf("diff and dry run differ:\n%+v\n%+v", diff, dryRun)
	}
	if diff[0].By != "api_client:ci" {
		t.Errorf("author of the setting: %q", diff[0].By)
	}
	if !reflect.DeepEqual(snapshot(t, p), before) {
		t.Error("the diff wrote")
	}

	// A role that may only read.
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	role := "reader_" + hex.EncodeToString(b)
	exec(t, p, `CREATE ROLE `+role+` LOGIN PASSWORD 'reader'`)
	t.Cleanup(func() {
		_, _ = p.db.Exec(`DROP OWNED BY ` + role)
		_, _ = p.db.Exec(`DROP ROLE ` + role)
	})
	exec(t, p, `GRANT USAGE ON SCHEMA public TO `+role)
	exec(t, p, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO `+role)
	u, err := url.Parse(dsnOf(t, p))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "reader")
	reader, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if got, err := reader.Diff(ctx, seed); err != nil || !reflect.DeepEqual(got, diff) {
		t.Errorf("diff as a reader: %v\n%+v", err, got)
	}
	if _, err := reader.Bootstrap(ctx, seed, Force, false); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("dry run as a reader: %v, want permission denied", err)
	}
}

// Q118: the hash replaced while it is still the old one, without a change of
// author; the instances told; a hash changed in between stays.
func TestRehashAPIClient(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	old, err := bcrypt.GenerateFromPassword(domain.BcryptInput("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAPIClient(ctx, "api_client:ci", APIClient{ID: "c", SecretHash: string(old), Scopes: []string{"admin:read"}}); err != nil {
		t.Fatal(err)
	}
	notified := listener(t, p)
	current, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.RehashAPIClient(ctx, "c", string(old), current); err != nil {
		t.Fatal(err)
	}
	if !notified(5 * time.Second) {
		t.Error("the instances not told")
	}
	if c, _ := snapshot(t, p).APIClient("c"); c.SecretHash != current || author(t, p, "api_client", "c") != "api_client:ci" {
		t.Errorf("client %+v, by %q", c, author(t, p, "api_client", "c"))
	}
	if err := p.RehashAPIClient(ctx, "c", string(old), current); !errors.Is(err, ErrNotFound) {
		t.Errorf("the hash changed meanwhile: %v", err)
	}
	if err := p.RehashAPIClient(ctx, "nobody", current, current); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown client: %v", err)
	}
	if err := p.RehashAPIClient(ctx, "c", current, "s3cret"); err == nil {
		t.Error("a secret in clear taken for a hash")
	}
}

// Q120: the sessions of an account stop at its logout, and when its password
// or its role changes; not when its subject at the identity provider does.
func TestAdminSessions(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, u := range []AdminUser{{Username: "alice", Role: domain.RoleAdmin}, {Username: "bob", Role: domain.RoleAdmin}} {
		if err := p.CreateAdmin(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	read := func() AdminUser {
		t.Helper()
		u, ok, err := p.Admin(ctx, "alice")
		if err != nil || !ok {
			t.Fatalf("alice: %v %v", ok, err)
		}
		return u
	}
	// A new account: its sessions are valid after its creation (revue R40).
	if u := read(); u.SessionsValidAfter.IsZero() || u.SessionsValidAfter.After(time.Now()) {
		t.Errorf("a new account: %v", u.SessionsValidAfter)
	}
	before := time.Now()
	if err := p.EndSessions(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	ended := read().SessionsValidAfter
	if ended.Before(before.Add(-time.Second)) || ended.After(time.Now().Add(time.Second)) {
		t.Errorf("logout: %v", ended)
	}
	if err := p.UpdateAdmin(ctx, "alice", func(u *AdminUser) error { u.OIDCSub = "sub-1"; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := read().SessionsValidAfter; !got.Equal(ended) {
		t.Errorf("a subject changed: %v, was %v", got, ended)
	}
	hash, _ := domain.HashSecret("correct horse battery")
	for name, change := range map[string]func(*AdminUser) error{
		"a password": func(u *AdminUser) error { u.PasswordHash = hash; return nil },
		"a role":     func(u *AdminUser) error { u.Role = domain.RoleViewer; return nil },
	} {
		was := read().SessionsValidAfter
		time.Sleep(5 * time.Millisecond)
		if err := p.UpdateAdmin(ctx, "alice", change); err != nil {
			t.Fatal(err)
		}
		if got := read().SessionsValidAfter; !got.After(was) {
			t.Errorf("%s changed: %v, was %v", name, got, was)
		}
	}
	if _, ok, err := p.Admin(ctx, "nobody"); ok || err != nil {
		t.Errorf("nobody: %v %v", ok, err)
	}
	if err := p.EndSessions(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the logout of nobody: %v", err)
	}
}

// The last admin is kept from a deletion as from a demotion; an account
// imported out of the rules is repaired, only what changes being checked.
func TestAdminDelete(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, u := range []AdminUser{{Username: "alice", Role: domain.RoleAdmin}, {Username: "bob", Role: domain.RoleAdmin}, {Username: "victor", Role: domain.RoleViewer}} {
		u.OIDCSub = u.Username
		if err := p.CreateAdmin(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.DeleteAdmin(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("nobody: %v", err)
	}
	if err := p.DeleteAdmin(ctx, "victor"); err != nil {
		t.Errorf("a viewer: %v", err)
	}
	if err := p.DeleteAdmin(ctx, "bob"); err != nil {
		t.Errorf("an admin of two: %v", err)
	}
	if err := p.DeleteAdmin(ctx, "alice"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("the last admin: %v", err)
	}
	if users, err := p.Admins(ctx); err != nil || len(users) != 1 || users[0].Username != "alice" {
		t.Errorf("left: %+v %v", users, err)
	}

	// A name Symfony took, written as the import writes it.
	if _, err := p.db.ExecContext(ctx, `INSERT INTO admin_user (username, role) VALUES ('carol ', 'viewer')`); err != nil {
		t.Fatal(err)
	}
	hash, err := domain.HashSecret("a password long enough")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateAdmin(ctx, "carol ", func(u *AdminUser) error { u.PasswordHash, u.Role = hash, domain.RoleAdmin; return nil }); err != nil {
		t.Errorf("repaired: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "carol ", func(u *AdminUser) error { u.Role = "root"; return nil }); !violated(err, "role") {
		t.Errorf("a role unknown: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "carol ", func(u *AdminUser) error { u.PasswordHash = "$2y$13$short"; return nil }); !violated(err, "password") {
		t.Errorf("a hash broken: %v", err)
	}
}

// An account deleted then created again under its name does not take back
// the sessions of the former: its sessions are valid after its creation
// (revue R40).
func TestAdminRecreated(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, name := range []string{"alice", "bob"} {
		if err := p.CreateAdmin(ctx, AdminUser{Username: name, OIDCSub: name, Role: domain.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
	}
	issued := time.Now() // a session of the former alice
	time.Sleep(10 * time.Millisecond)
	if err := p.DeleteAdmin(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "alice", OIDCSub: "another", Role: domain.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	u, found, err := p.Admin(ctx, "alice")
	if err != nil || !found {
		t.Fatal(found, err)
	}
	if !u.SessionsValidAfter.After(issued) {
		t.Errorf("the former's session is valid: issued %v, valid after %v", issued, u.SessionsValidAfter)
	}
}

// The login by OIDC finds an account by its subject alone.
func TestAdminBySubject(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, u := range []AdminUser{{Username: "alice", OIDCSub: "248289761001", Role: domain.RoleAdmin}, {Username: "248289761001", OIDCSub: "other", Role: domain.RoleViewer}} {
		if err := p.CreateAdmin(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if u, found, err := p.AdminBySubject(ctx, "248289761001"); err != nil || !found || u.Username != "alice" {
		t.Errorf("by subject: %+v %v %v", u, found, err)
	}
	for _, sub := range []string{"", "nobody", "alice"} {
		if u, found, err := p.AdminBySubject(ctx, sub); err != nil || found {
			t.Errorf("%q: %+v %v", sub, u, err)
		}
	}
}

// A subject another account has is refused on its field, not by the
// constraint of the column (revue R41).
func TestAdminSubjectTaken(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, u := range []AdminUser{{Username: "alice", OIDCSub: "sub-a", Role: domain.RoleAdmin}, {Username: "bob", OIDCSub: "sub-b", Role: domain.RoleViewer}} {
		if err := p.CreateAdmin(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.CreateAdmin(ctx, AdminUser{Username: "carol", OIDCSub: "sub-a", Role: domain.RoleViewer}); !violated(err, "oidc_sub") {
		t.Errorf("create: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "bob", func(u *AdminUser) error { u.OIDCSub = "sub-a"; return nil }); !violated(err, "oidc_sub") {
		t.Errorf("update: %v", err)
	}
	if err := p.UpdateAdmin(ctx, "bob", func(u *AdminUser) error { u.Role = domain.RoleAdmin; return nil }); err != nil {
		t.Errorf("its own subject kept: %v", err)
	}
}
