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
	"path/filepath"
	"slices"
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
	must(nil, "s3cret-passw0rd\n", "admin", "create", "alice", "-role", "admin", "-password-stdin")
	hash, role := row(`SELECT password_hash, role FROM admin_user WHERE username = 'alice'`)
	if !domain.SecretMatches(hash, "s3cret-passw0rd") || role != "admin" {
		t.Errorf("account created: role %q", role)
	}
	must(errFailed, "", "admin", "update", "alice", "-role", "viewer")
	_, errOut, err := onPostgres(t, "b0b-s3cret-passw0rd\n", "bootstrap", "-create-admin", "carol", "-password-stdin")
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

// config diff reads the seed against the database as bootstrap -force would;
// config dump writes the database as a seed, which bootstrap -force takes back
// without a change.
func TestConfigOnPostgres(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	cliDatabase(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seed, []byte(`
dispatcher:
  app_auto_select: true
  challenge_ttl: 15m
  consent_auto_accept: true
  supported_locales: [fr, en]
  apps:
    - { id: sql, login_url: http://sql/login, consent_url: http://sql/consent, logout_url: http://sql/logout, method: pwd }
    - id: otp
      login_url: http://otp/login
      consent_url: http://otp/consent
      method: otp
      receive_claims: [email]
      allowed_sources: [10.0.1.0/24, "::ffff:10.0.2.0/120"]
    - { id: none, login_url: http://none/login, consent_url: http://none/consent, method: pwd, receive_claims: [] }
  flows:
    - id: mfa
      title: { fr: "Deux facteurs", en: "Two factors" }
      description: { fr: "SQL puis OTP" }
      icon_url: { fr: http://icons/mfa.svg }
      acr: loa2
      steps: [{ id: sql, order: 0 }, { id: otp, order: 1, subject_check: equal }]
    - { id: off, title: Off, description: D, enabled: false, steps: [{ id: none, order: 3 }] }
  oauth2_clients:
    - { id: ci, secret: s3cret, scopes: [admin:read, admin:flows] }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := func(want error, args ...string) (string, string) {
		t.Helper()
		out, errOut, err := onPostgres(t, "", args...)
		if !errors.Is(err, want) || (want == nil) != (err == nil) {
			t.Fatalf("%q: err = %v, want %v\nstdout:\n%s\nstderr:\n%s", args, err, want, out, errOut)
		}
		return out, errOut
	}
	cmd(nil, "bootstrap", "-config", seed, "-force")
	if out, _ := cmd(nil, "config", "diff", "-config", seed); !strings.HasSuffix(out, "same 10\n") {
		t.Errorf("diff after the bootstrap:\n%s", out)
	}

	// The dump, its clients apart, is a seed that changes nothing.
	dump, _ := cmd(nil, "config", "dump", "-section", "settings,apps,flows")
	if strings.Contains(dump, "oauth2_clients") || strings.Contains(dump, "remember") || !strings.Contains(dump, "receive_claims: null") || !strings.Contains(dump, "receive_claims: []") ||
		!strings.Contains(dump, "challenge_ttl: 900") || !strings.Contains(dump, "10.0.2.0/24") {
		t.Errorf("dump:\n%s", dump)
	}
	dumped := filepath.Join(dir, "dump.yaml")
	if err := os.WriteFile(dumped, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _ := cmd(nil, "config", "diff", "-config", dumped); !strings.HasSuffix(out, "same 9, absent 1\n") || !strings.Contains(out, "absent  api_client ci") {
		t.Errorf("diff of the dump:\n%s", out)
	}
	all, _ := cmd(nil, "config", "dump")
	if !strings.Contains(all, "  oauth2_clients:\n    # secret: not dumped, the seed requires one\n    - id: ci\n") || strings.Contains(all, "$2a$") {
		t.Errorf("dump of the clients:\n%s", all)
	}

	// A write of the CLI: the diff wants to undo it, names its author, exits 1.
	cmd(nil, "client", "update", "ci", "-scopes", "admin:read")
	out, _ := cmd(errFailed, "config", "diff", "-config", seed)
	if !strings.Contains(out, "update  api_client ci (written by cli)\n          scopes: [\"admin:read\"] -> [\"admin:read\",\"admin:flows\"]") {
		t.Errorf("diff after a write:\n%s", out)
	}
	out, _ = cmd(errFailed, "config", "diff", "-config", seed, "-format", "json")
	var changes []map[string]any
	if err := json.Unmarshal([]byte(out), &changes); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(changes, func(c map[string]any) bool { return c["id"] == "ci" })
	if i < 0 || changes[i]["action"] != "update" || changes[i]["by"] != "cli" {
		t.Fatalf("json: %v", changes)
	}
	field := changes[i]["fields"].([]any)[0].(map[string]any)
	if field["name"] != "scopes" || len(field["new"].([]any)) != 2 {
		t.Errorf("json field: %v", field)
	}

	// An error exits 2, not 1: that is the differences.
	_, _, err := onPostgres(t, "", "config", "diff", "-config", filepath.Join(dir, "none.yaml"))
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != 2 {
		t.Errorf("a file missing: %v", err)
	}
}

// A value of the database that names a variable reads back as written, not
// expanded: the dump doubles the dollar the loader reads (revue R37). The
// variables are set, for an expansion to show; the challenge key among them,
// which an API client could have written into a title.
func TestConfigDumpEscapes(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	db := cliDatabase(t)
	t.Setenv("PRICE", "42")
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.yaml")
	dollar := "$"
	ref := func(name string) string { return dollar + dollar + "{" + name + "}" }
	if err := os.WriteFile(seed, []byte(`
dispatcher:
  apps:
    - { id: a, login_url: "http://d/login?x=`+ref("HOME")+`", consent_url: http://d/consent, method: pwd }
  flows:
    - id: f
      title: { fr: "Deux facteurs `+ref("PRICE")+`", en: "`+dollar+ref("PRICE")+`" }
      description: { fr: "`+ref("DISPATCHER_SECRETS_CHALLENGE_KEY")+`" }
      steps: [{ id: a, order: 0 }]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := func(want error, args ...string) string {
		t.Helper()
		out, errOut, err := onPostgres(t, "", args...)
		if !errors.Is(err, want) || (want == nil) != (err == nil) {
			t.Fatalf("%q: err = %v, want %v\n%s\n%s", args, err, want, out, errOut)
		}
		return out
	}
	cmd(nil, "bootstrap", "-config", seed, "-force")
	dump := cmd(nil, "config", "dump", "-section", "apps,flows")
	dumped := filepath.Join(dir, "dump.yaml")
	if err := os.WriteFile(dumped, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := cmd(nil, "config", "diff", "-config", dumped); !strings.HasSuffix(out, "same 2\n") || strings.Contains(out, "42") || strings.Contains(out, "cdcd") {
		t.Errorf("the dump reloaded:\n%s\n%s", out, dump)
	}

	// Symfony's %env( has no escape: the dump names the field and stops.
	if _, err := db.Exec(`UPDATE flow SET description = '{"fr": "%env(SECRET)%"}' WHERE id = 'f'`); err != nil {
		t.Fatal(err)
	}
	_, _, err := onPostgres(t, "", "config", "dump")
	if err == nil || !strings.Contains(err.Error(), "dispatcher.flows[0].description.fr holds %env(") {
		t.Errorf("a %%env( dumped: %v", err)
	}
}
