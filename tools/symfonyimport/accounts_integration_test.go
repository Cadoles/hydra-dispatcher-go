//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// database creates an empty database for t, dropped at its end, and gives
// its DSN and a connection.
func database(t *testing.T, prefix string) (string, *sql.DB) {
	t.Helper()
	base, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil || base.Scheme != "postgres" && base.Scheme != "postgresql" {
		t.Fatal("the integration tag needs DATABASE_URL: a postgres:// URL of a Postgres 17 where the tests may create databases")
	}
	admin, err := sql.Open("pgx", base.String())
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := prefix + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	u := *base
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		if _, err := admin.Exec("DROP DATABASE " + name + " WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		_ = admin.Close()
	})
	return u.String(), db
}

// symfonySchema are the tables of Symfony's accounts and clients, as its
// migrations leave them at d66639e.
const symfonySchema = `
CREATE TABLE dispatcher_admin_user (id SERIAL PRIMARY KEY, username VARCHAR(180) NOT NULL UNIQUE, password VARCHAR(255),
  super_admin BOOLEAN NOT NULL DEFAULT FALSE, oidc_sub VARCHAR(255) DEFAULT NULL UNIQUE);
CREATE TABLE dispatcher_oauth2_client (id VARCHAR(256) NOT NULL PRIMARY KEY, secret VARCHAR(512) NOT NULL);
CREATE TABLE dispatcher_group (id VARCHAR(64) NOT NULL PRIMARY KEY, label VARCHAR(128) NOT NULL, scope_key VARCHAR(64) NOT NULL UNIQUE, description TEXT NOT NULL);
CREATE TABLE dispatcher_client_group (client_id VARCHAR(256) NOT NULL, group_id VARCHAR(64) NOT NULL, PRIMARY KEY (client_id, group_id));
INSERT INTO dispatcher_group VALUES ('operator', 'Operator', 'admin:config', ''), ('admin_users', 'Users', 'admin:users', ''), ('audit', 'Audit', 'admin:audit', '');
`

// symfonyHash is a hash as Symfony's NativePasswordHasher writes it, $2y$.
func symfonyHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword(domain.BcryptInput(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(h), "$2a$", "$2y$", 1)
}

func TestAccounts(t *testing.T) {
	ctx := context.Background()
	symfonyDSN, symfony := database(t, "symfony_")
	goDSN, _ := database(t, "dispatcher_import_")
	if _, err := symfony.Exec(symfonySchema); err != nil {
		t.Fatal(err)
	}
	adminHash, opsHash, testHash := symfonyHash(t, "admin"), symfonyHash(t, "ops-s3cret"), symfonyHash(t, "test")
	for _, q := range []string{
		`INSERT INTO dispatcher_admin_user (username, password, super_admin) VALUES ('admin', '` + adminHash + `', TRUE)`,
		`INSERT INTO dispatcher_admin_user (username, password, super_admin, oidc_sub) VALUES ('alice@example.org', NULL, FALSE, 'sub-1')`,
		`INSERT INTO dispatcher_oauth2_client VALUES ('ops', '` + opsHash + `'), ('test', '` + testHash + `'), ('plain', 's3cret'), ('odd', '` + testHash + `')`,
		`INSERT INTO dispatcher_client_group VALUES ('ops', 'operator'), ('ops', 'admin_users'), ('odd', 'audit')`,
	} {
		if _, err := symfony.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	p, err := store.Open(ctx, goDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, kv := range []string{
		"DISPATCHER_CONFIG=", "DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test", "DISPATCHER_SERVER_TRUSTED_PROXIES=10.0.0.10",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24", "DISPATCHER_HYDRA_ADMIN_URL=http://hydra:4445",
		"DISPATCHER_STORE_DSN=" + goDSN, "DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32), "DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	} {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	dsnFile := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(dsnFile, []byte(symfonyDSN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	importRun := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		err := run(ctx, append([]string{"accounts", "-symfony-dsn-file", dsnFile}, args...), &out, &errOut, strings.NewReader(""))
		if strings.Contains(out.String()+errOut.String(), "$2") || strings.Contains(out.String()+errOut.String(), "s3cret") {
			t.Errorf("a hash or a secret written:\n%s\n%s", out.String(), errOut.String())
		}
		return out.String(), errOut.String(), err
	}

	// A dry run: what would be written, nothing written.
	out, errOut, err := importRun("-dry-run")
	want := "create  admin_user admin (admin)\ncreate  admin_user alice@example.org (viewer)\n" +
		"create  api_client odd (no scope)\ncreate  api_client ops (admin:apps admin:flows admin:clients admin:settings admin:read)\n" +
		"skip    api_client plain (its secret is not a hash)\ncreate  api_client test (no scope)\n"
	if err != nil || out != want {
		t.Fatalf("dry run: %v\n%s\nstderr:\n%s", err, out, errOut)
	}
	for _, w := range []string{"API client plain left out: its secret is not a bcrypt hash", `API client odd: the scope "admin:audit"`, "API client test has no scope"} {
		if !strings.Contains(errOut, w) {
			t.Errorf("warnings lack %q:\n%s", w, errOut)
		}
	}
	if users, _ := p.Admins(ctx); len(users) != 0 {
		t.Errorf("the dry run wrote: %+v", users)
	}

	// The import: the hashes as Symfony wrote them, the roles, the scopes,
	// updated_by import.
	if out, errOut, err = importRun(); err != nil || out != want {
		t.Fatalf("import: %v\n%s\n%s", err, out, errOut)
	}
	users, _ := p.Admins(ctx)
	if len(users) != 2 || users[0].Username != "admin" || users[0].Role != domain.RoleAdmin || users[0].PasswordHash != adminHash ||
		!domain.SecretMatches(users[0].PasswordHash, "admin") || users[1].Role != domain.RoleViewer || users[1].PasswordHash != "" || users[1].OIDCSub != "sub-1" {
		t.Errorf("accounts: %+v", users)
	}
	clients, _ := p.APIClients(ctx)
	ids := []string{}
	for _, c := range clients {
		ids = append(ids, c.ID)
	}
	if !slices.Equal(ids, []string{"odd", "ops", "test"}) || clients[1].SecretHash != opsHash || !domain.SecretMatches(clients[1].SecretHash, "ops-s3cret") || len(clients[1].Scopes) != 5 || len(clients[2].Scopes) != 0 {
		t.Errorf("clients: %+v", clients)
	}
	var by string
	godb, err := sql.Open("pgx", goDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = godb.Close() }()
	if err := godb.QueryRow(`SELECT updated_by FROM api_client WHERE id = 'ops'`).Scan(&by); err != nil || by != importAuthor {
		t.Errorf("updated_by %q, %v", by, err)
	}

	// Again: all there, left as it is.
	if out, _, err = importRun(); err != nil || strings.Contains(out, "create") || strings.Count(out, "keep ") != 5 {
		t.Errorf("again: %v\n%s", err, out)
	}

	// All or nothing: a client the Go refuses refuses the import, named,
	// before any write.
	if _, err := symfony.Exec(`INSERT INTO dispatcher_oauth2_client VALUES ('bad/id', '` + testHash + `'), ('new', '` + testHash + `');
		INSERT INTO dispatcher_admin_user (username, password, super_admin) VALUES ('bob', '` + adminHash + `', FALSE)`); err != nil {
		t.Fatal(err)
	}
	_, errOut, err = importRun()
	if !errors.Is(err, errFailed) || !strings.Contains(errOut, `refused: API client "bad/id": id:`) {
		t.Errorf("refused: %v\n%s", err, errOut)
	}
	if users, _ := p.Admins(ctx); len(users) != 2 {
		t.Errorf("an account written before the refusal: %+v", users)
	}

	// An oidc_sub another account of the Go database holds: refused before any
	// write, where the database refused it in the middle of them (revue R38).
	if _, err := symfony.Exec(`DELETE FROM dispatcher_oauth2_client WHERE id = 'bad/id';
		INSERT INTO dispatcher_admin_user (username, super_admin, oidc_sub) VALUES ('carol', FALSE, 'sub-2')`); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAdmin(ctx, store.AdminUser{Username: "zed", OIDCSub: "sub-2", Role: domain.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	_, errOut, err = importRun()
	if !errors.Is(err, errFailed) || !strings.Contains(errOut, `refused: admin account "carol": its oidc_sub is that of the account "zed"`) {
		t.Errorf("an oidc_sub taken: %v\n%s", err, errOut)
	}
	if users, _ := p.Admins(ctx); len(users) != 3 {
		t.Errorf("an account written before the refusal: %+v", users)
	}
	// Corrected, the import goes on: bob and the client new.
	if _, err := symfony.Exec(`UPDATE dispatcher_admin_user SET oidc_sub = 'sub-3' WHERE username = 'carol'`); err != nil {
		t.Fatal(err)
	}
	if out, errOut, err = importRun(); err != nil || !strings.Contains(out, "create  admin_user bob (viewer)") || !strings.Contains(out, "create  api_client new (no scope)") {
		t.Errorf("the import corrected: %v\n%s\n%s", err, out, errOut)
	}
}
