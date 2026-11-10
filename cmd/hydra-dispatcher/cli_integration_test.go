//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// cliDatabase creates a database of its own for t, migrated, dropped at its
// end, and makes the commands open it.
func cliDatabase(t *testing.T) *sql.DB {
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
	name := "dispatcher_cli_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	u := *base
	u.Path = "/" + name
	dsn := u.String()
	db, err := sql.Open("pgx", dsn)
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
	p, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	old := openStore
	openStore = func(ctx context.Context, _ string) (configStore, error) { return store.Open(ctx, dsn) }
	t.Cleanup(func() { openStore = old })
	return db
}

// onPostgres runs a command line on the database of cliDatabase.
func onPostgres(t *testing.T, input string, args ...string) (out, errOut string, err error) {
	t.Helper()
	terminalAnswers(t, false, input)
	var b bytes.Buffer
	dataOut = &b
	t.Cleanup(func() { dataOut = nil })
	errOut = stderrOf(t, func() { err = run(context.Background(), args, os.Stderr) })
	return b.String(), errOut, err
}

func TestCLIOnPostgres(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	db := cliDatabase(t)
	must := func(want error, input string, args ...string) string {
		t.Helper()
		out, errOut, err := onPostgres(t, input, args...)
		if !errors.Is(err, want) || (want == nil) != (err == nil) {
			t.Fatalf("%q: err = %v, want %v\n%s", args, err, want, errOut)
		}
		if strings.Contains(errOut, "$2a$") {
			t.Fatalf("%q: a hash on stderr\n%s", args, errOut)
		}
		return out
	}
	row := func(query string, args ...any) (a, b string) {
		t.Helper()
		if err := db.QueryRow(query, args...).Scan(&a, &b); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return a, b
	}

	// Clients: created with a secret generated, written by cli (Q114).
	secret := strings.TrimSpace(must(nil, "", "client", "create", "ci", "-scopes", "admin:read"))
	hash, by := row(`SELECT secret_hash, updated_by FROM api_client WHERE id = 'ci'`)
	if !domain.SecretMatches(hash, secret) || by != cliAuthor {
		t.Errorf("client created: by %q", by)
	}
	must(errFailed, "", "client", "create", "ci")
	if got := must(nil, "", "client", "list"); got != "ID  SCOPES\nci  admin:read\n" {
		t.Errorf("list: %q", got)
	}
	again := strings.TrimSpace(must(nil, "", "client", "update", "ci", "-new-secret", "-scopes", "admin:flows,admin:read"))
	hash, scopes := row(`SELECT secret_hash, array_to_string(scopes, ',') FROM api_client WHERE id = 'ci'`)
	if domain.SecretMatches(hash, secret) || !domain.SecretMatches(hash, again) || scopes != "admin:flows,admin:read" {
		t.Errorf("client updated: scopes %q", scopes)
	}
	// A write that leaves a configuration serve refuses is refused, as by the
	// admin API: here, the domain's rules.
	must(errFailed, "", "client", "update", "ci", "-scopes", "admin flows")
	must(nil, "", "client", "delete", "ci")
	must(errFailed, "", "client", "delete", "ci")
	if got := must(nil, "", "client", "list", "-format", "json"); got != "[]\n" {
		t.Errorf("list after delete: %q", got)
	}

	// Accounts.
	must(nil, "s3cret\n", "admin", "create", "alice", "-role", "admin", "-password-stdin")
	hash, role := row(`SELECT password_hash, role FROM admin_user WHERE username = 'alice'`)
	if !domain.SecretMatches(hash, "s3cret") || role != "admin" {
		t.Errorf("account created: role %q", role)
	}
	must(errFailed, "", "admin", "update", "alice", "-role", "viewer")
	_, errOut, err := onPostgres(t, "b0b-s3cret\n", "bootstrap", "-create-admin", "carol", "-password-stdin")
	if err != nil || !strings.Contains(errOut, `Admin account "carol" created.`) {
		t.Fatalf("bootstrap: %v\n%s", err, errOut)
	}
	_, errOut, err = onPostgres(t, "", "bootstrap", "-create-admin", "carol")
	if err != nil || !strings.Contains(errOut, `Admin account "carol" exists: left as it is.`) {
		t.Errorf("bootstrap again: %v\n%s", err, errOut)
	}
	must(nil, "", "admin", "update", "alice", "-role", "viewer")
	var users []map[string]any
	if err := json.Unmarshal([]byte(must(nil, "", "admin", "list", "-format", "json")), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0]["username"] != "alice" || users[0]["role"] != "viewer" || users[1]["username"] != "carol" || users[1]["role"] != "admin" || users[1]["password"] != true {
		t.Errorf("accounts: %v", users)
	}
}
