//go:build integration

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The integration tests need a Postgres where they may create databases:
// the tag without DATABASE_URL fails rather than passing untested.
func TestMain(m *testing.M) {
	if os.Getenv("DATABASE_URL") == "" {
		fmt.Fprintln(os.Stderr, "the integration tag needs DATABASE_URL: a postgres:// URL of a Postgres 17 where the tests may create databases")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// newDatabase opens an empty database of its own for t, dropped at its end.
func newDatabase(t *testing.T) *Postgres {
	t.Helper()
	return newDatabaseWith(t, "")
}

// newDatabaseWith is newDatabase, the database created with options, as
// CREATE DATABASE takes them.
func newDatabaseWith(t *testing.T, options string) *Postgres {
	t.Helper()
	base, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil || base.Scheme != "postgres" && base.Scheme != "postgresql" {
		t.Fatalf("DATABASE_URL is not a postgres:// URL")
	}
	admin, err := sql.Open("pgx", base.String())
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "dispatcher_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec("CREATE DATABASE " + name + " " + options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE " + name + " WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		_ = admin.Close()
	})
	u := *base
	u.Path = "/" + name
	p, err := Open(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// migrated is newDatabase with the schema.
func migrated(t *testing.T) *Postgres {
	t.Helper()
	p := newDatabase(t)
	if _, err := p.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p
}

func exec(t *testing.T, p *Postgres, query string, args ...any) {
	t.Helper()
	if _, err := p.db.Exec(query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(query)[0:3], err)
	}
}

// allMigrations are the migrations of an empty database.
var allMigrations = []string{"00001_schema.sql", "00002_checks.sql", "00003_app_receive_claims.sql", "00004_admin_writes.sql"}

// What the code read of the options of an app becomes its receive_claims, and
// comes back with a rollback: an app restricted before stays restricted.
func TestMigrateOptions(t *testing.T) {
	ctx := context.Background()
	p := newDatabase(t)
	m, err := p.migrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, options) VALUES
		('none', 'x', 'x', 'pwd', '{"theme": "dark"}'),
		('list', 'x', 'x', 'pwd', '{"receive_claims": ["email", 1, "name"]}'),
		('empty', 'x', 'x', 'pwd', '{"receive_claims": []}'),
		('text', 'x', 'x', 'pwd', '{"receive_claims": "email"}'),
		('null', 'x', 'x', 'pwd', '{"receive_claims": null}'),
		('number', 'x', 'x', 'pwd', '{"receive_claims": 1}'),
		('object', 'x', 'x', 'pwd', '{"receive_claims": {"email": true}}'),
		('mixed', 'x', 'x', 'pwd', '{"theme": "dark", "receive_claims": ["z", null, ["y"], "a", "a"]}')`)
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][]string{
		"none": nil, "list": {"email", "name"}, "empty": {}, "text": {}, "null": {}, "number": {}, "object": {}, "mixed": {"z", "a", "a"},
	} {
		if a, _ := s.App(id); !reflect.DeepEqual(a.ReceiveClaims, want) {
			t.Errorf("app %s: ReceiveClaims = %#v, want %#v", id, a.ReceiveClaims, want)
		}
	}
	if _, err := m.DownTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		"none": `{}`, "list": `{"receive_claims": ["email", "name"]}`, "empty": `{"receive_claims": []}`, "null": `{"receive_claims": []}`,
	} {
		var options string
		if err := p.db.QueryRow(`SELECT options::text FROM app WHERE id = $1`, id).Scan(&options); err != nil || options != want {
			t.Errorf("app %s after the rollback: options = %s, %v; want %s", id, options, err, want)
		}
	}
}

// migrate down rolls back one migration at a time, its data kept as Down says,
// down to nothing; a version that does not hold the last one refuses.
func TestMigrateDown(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('a', 'x', 'x', 'pwd', '{email}')`)
	want := slices.Clone(allMigrations)
	slices.Reverse(want)
	for _, name := range want {
		if last, err := p.LastMigration(ctx); err != nil || last != name {
			t.Fatalf("LastMigration = %q, %v; want %s", last, err, name)
		}
		if got, err := p.MigrateDown(ctx); err != nil || got != name {
			t.Fatalf("MigrateDown = %q, %v; want %s", got, err, name)
		}
		if name == "00004_admin_writes.sql" {
			if _, err := p.Snapshot(ctx); err != nil {
				t.Errorf("snapshot after the rollback of %s: %v", name, err)
			}
		}
		if name == "00003_app_receive_claims.sql" {
			var options string
			if err := p.db.QueryRow(`SELECT options::text FROM app WHERE id = 'a'`).Scan(&options); err != nil || options != `{"receive_claims": ["email"]}` {
				t.Errorf("options after the rollback: %s, %v", options, err)
			}
		}
	}
	if tables := publicTables(t, p); !slices.Equal(tables, []string{"dispatcher_schema_version"}) {
		t.Errorf("tables = %q", tables)
	}
	if last, err := p.LastMigration(ctx); err != nil || last != "" {
		t.Errorf("LastMigration with nothing applied = %q, %v", last, err)
	}
	if got, err := p.MigrateDown(ctx); err != nil || got != "" {
		t.Errorf("MigrateDown with nothing applied = %q, %v", got, err)
	}
	if applied, err := p.Migrate(ctx); err != nil || !slices.Equal(applied, allMigrations) {
		t.Fatalf("Migrate after = %q, %v", applied, err)
	}
	// A migration of a later version: what it holds, this one cannot undo.
	exec(t, p, `INSERT INTO dispatcher_schema_version (version_id, is_applied) VALUES (99, true)`)
	if last, err := p.LastMigration(ctx); err != nil || !strings.Contains(last, "99") {
		t.Errorf("LastMigration = %q, %v", last, err)
	}
	if _, err := p.MigrateDown(ctx); err == nil || !strings.Contains(err.Error(), "roll it back with the version that applied it") {
		t.Errorf("MigrateDown of an unknown version: %v", err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Errorf("the refusal changed the schema: %v", err)
	}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	p := newDatabase(t)
	applied, err := p.Migrate(ctx)
	if err != nil || !slices.Equal(applied, allMigrations) {
		t.Fatalf("Migrate = %q, %v", applied, err)
	}
	if applied, err := p.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Errorf("second Migrate = %q, %v; want nothing applied", applied, err)
	}
	want := []string{"admin_user", "api_client", "app", "dispatcher_schema_version", "flow", "flow_step", "scope", "setting"}
	if tables := publicTables(t, p); !slices.Equal(tables, want) {
		t.Errorf("tables = %q, want %q", tables, want)
	}
}

// Another application of the database migrates with goose under its
// defaults: its version table and its lock are not the dispatcher's.
func TestMigrateBesideGoose(t *testing.T) {
	ctx := context.Background()
	p := newDatabase(t)
	exec(t, p, `CREATE TABLE goose_db_version (id SERIAL PRIMARY KEY, version_id BIGINT NOT NULL, is_applied BOOLEAN NOT NULL, tstamp TIMESTAMP DEFAULT now())`)
	exec(t, p, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, true), (1, true), (2, true)`)
	conn, err := p.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// goose's default lock, held by the other application as it migrates.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(4097083626)`); err != nil {
		t.Fatal(err)
	}
	migrateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if applied, err := p.Migrate(migrateCtx); err != nil || !slices.Equal(applied, allMigrations) {
		t.Fatalf("Migrate = %q, %v", applied, err)
	}
	if _, err := p.Snapshot(ctx); err != nil {
		t.Error(err)
	}
	var versions int
	if err := p.db.QueryRow(`SELECT count(*) FROM goose_db_version`).Scan(&versions); err != nil || versions != 3 {
		t.Errorf("the other application's versions: %d, %v", versions, err)
	}
}

// Replicas migrating at once: one applies, the others find nothing to do.
// Without the session lock, they all apply, and all but one fail.
func TestMigrateConcurrently(t *testing.T) {
	p := newDatabase(t)
	type result struct {
		applied []string
		err     error
	}
	results := make(chan result, 3)
	for range 3 {
		go func() {
			applied, err := p.Migrate(context.Background())
			results <- result{applied, err}
		}()
	}
	var appliers int
	for range 3 {
		r := <-results
		switch {
		case r.err != nil:
			t.Error(r.err)
		case slices.Equal(r.applied, allMigrations):
			appliers++
		case len(r.applied) != 0:
			t.Errorf("applied %q", r.applied)
		}
	}
	if appliers != 1 {
		t.Errorf("%d replicas applied the schema, want 1", appliers)
	}
}

// The Down sections drop what Up created: the schema can be built again.
func TestMigrationDown(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method) VALUES ('a', 'http://a', 'http://a', 'pwd')`)
	exec(t, p, `INSERT INTO flow (id) VALUES ('f')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ('f', 'a', 0)`)
	provider, err := p.migrator()
	if err != nil {
		t.Fatal(err)
	}
	if results, err := provider.DownTo(ctx, 0); err != nil || len(results) != len(allMigrations) {
		t.Fatalf("Down: %d migrations, %v", len(results), err)
	}
	if tables := publicTables(t, p); !slices.Equal(tables, []string{"dispatcher_schema_version"}) {
		t.Errorf("tables after Down = %q", tables)
	}
	if applied, err := p.Migrate(ctx); err != nil || !slices.Equal(applied, allMigrations) {
		t.Errorf("Migrate after Down = %q, %v", applied, err)
	}
}

// A table of the schema already there, created by hand: the migration fails
// whole, in its transaction, and leaves nothing of its own.
func TestMigrateOverExistingTable(t *testing.T) {
	p := newDatabase(t)
	exec(t, p, `CREATE TABLE scope (name TEXT)`)
	if _, err := p.Migrate(context.Background()); err == nil || !strings.Contains(err.Error(), `relation "scope" already exists`) {
		t.Fatalf("Migrate = %v, want scope refused", err)
	}
	if tables := publicTables(t, p); !slices.Equal(tables, []string{"dispatcher_schema_version", "scope"}) {
		t.Errorf("tables = %q, want only the versions and the one made by hand", tables)
	}
}

// publicTables lists the tables of the public schema, by name.
func publicTables(t *testing.T, p *Postgres) []string {
	t.Helper()
	rows, err := p.db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name COLLATE "C"`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	return tables
}

// The keys the reader and the engine rely on: a step's app exists (E1005 at
// run time otherwise), a flow takes its steps with it, and holds an app once
// and a position once.
func TestSchemaKeys(t *testing.T) {
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method) VALUES ('a', 'http://a', 'http://a', 'pwd'), ('b', 'http://b', 'http://b', 'otp')`)
	exec(t, p, `INSERT INTO flow (id) VALUES ('f')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ('f', 'a', 0)`)
	for _, refused := range []string{
		`INSERT INTO flow_step (flow_id, app_id, position) VALUES ('f', 'unknown', 1)`,
		`INSERT INTO flow_step (flow_id, app_id, position) VALUES ('f', 'b', 0)`,
		`INSERT INTO flow_step (flow_id, app_id, position) VALUES ('f', 'a', 1)`,
		`DELETE FROM app WHERE id = 'a'`,
	} {
		if _, err := p.db.Exec(refused); err == nil {
			t.Errorf("accepted: %s", refused)
		}
	}
	exec(t, p, `DELETE FROM flow WHERE id = 'f'`)
	var steps int
	if err := p.db.QueryRow(`SELECT count(*) FROM flow_step`).Scan(&steps); err != nil || steps != 0 {
		t.Errorf("%d steps left after their flow, %v", steps, err)
	}
}

// The checks refuse, at the write, the rows the reader cannot take, which
// would refuse the whole snapshot.
func TestSchemaChecks(t *testing.T) {
	p := migrated(t)
	app := `INSERT INTO app (id, login_url, consent_url, method, auth_mode, allowed_sources, receive_claims) VALUES ('a', 'x', 'x', 'pwd', `
	flow := `INSERT INTO flow (id, title, description, icon_url) VALUES ('f', `
	for insert, check := range map[string]string{
		app + `'cert', '{}', NULL)`:                      "app_auth_mode",
		app + `'network', '{NULL}', NULL)`:               "app_allowed_sources",
		app + `'network', '{10.0.0.0/8,NULL}', NULL)`:    "app_allowed_sources",
		app + `'network', '{{10.0.0.0/8}}', NULL)`:       "app_allowed_sources",
		app + `'network', '{}', '{NULL}')`:               "app_receive_claims",
		app + `'network', '{}', '{email,NULL}')`:         "app_receive_claims",
		app + `'network', '{}', '{{email}}')`:            "app_receive_claims",
		flow + `'"SQL"', '{}', NULL)`:                    "flow_title",
		flow + `'{"fr": 1}', '{}', NULL)`:                "flow_title",
		flow + `'{}', 'null', NULL)`:                     "flow_description",
		flow + `'{}', '{"fr": ["a"]}', NULL)`:            "flow_description",
		flow + `'{}', '{}', '"http://icons/a.svg"')`:     "flow_icon_url",
		flow + `'{}', '{}', '{"fr": {"src": "a.svg"}}')`: "flow_icon_url",
	} {
		if _, err := p.db.Exec(insert); err == nil || !strings.Contains(err.Error(), `violates check constraint "`+check+`"`) {
			t.Errorf("%s: err = %v, want %s", insert, err, check)
		}
	}
	for _, insert := range []string{
		app + `'mtls', '{10.0.0.0/8,2001:db8::/32}', '{email,name}')`,
		`INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('b', 'x', 'x', 'pwd', '{}')`,
		`INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('c', 'x', 'x', 'pwd', NULL)`,
		`INSERT INTO flow (id, title, description, icon_url) VALUES ('f1', '{"fr": "SQL", "en": null}', '{}', NULL)`,
		`INSERT INTO flow (id, title, description, icon_url) VALUES ('f2', '{}', '{}', 'null')`,
		`INSERT INTO flow (id, title, description, icon_url) VALUES ('f3', '{}', '{}', '{"fr": "http://icons/a.svg"}')`,
	} {
		if _, err := p.db.Exec(insert); err != nil {
			t.Errorf("%s: %v", insert, err)
		}
	}
}

func TestSnapshotEmpty(t *testing.T) {
	s, err := migrated(t).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Apps) != 0 || len(s.Flows) != 0 || len(s.Warnings) != 0 || !reflect.DeepEqual(s.Settings, DefaultSettings()) {
		t.Errorf("snapshot = %+v", s)
	}
}

func TestSnapshot(t *testing.T) {
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, logout_url, method, allowed_sources, receive_claims) VALUES
		('sql', 'http://sql/login', 'http://sql/consent', 'http://sql/logout', 'pwd', '{10.1.0.0/16,10.2.0.5,2001:db8::/32}',
		 '{email,name}')`)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, auth_mode, client_cert_fingerprint) VALUES
		('otp', 'http://otp/login', 'http://otp/consent', 'otp', 'mtls', 'ab12')`)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('none', 'http://n/login', 'http://n/consent', 'pwd', '{}')`)
	exec(t, p, `INSERT INTO flow (id, title, description, icon_url, enabled, acr) VALUES
		('sql-2fa', '{"fr": "SQL 2FA"}', '{"fr": "Deux facteurs", "en": "Two factors", "de": null, "es": ""}',
		 '{"fr": "http://icons/2fa.svg", "en": ""}', false, 'loa2')`)
	exec(t, p, `INSERT INTO flow (id, title, description) VALUES ('a-sql', '{"en": "SQL"}', '{"en": "Password"}')`)
	// No step; a null or empty text is none, and so is an icon without one.
	exec(t, p, `INSERT INTO flow (id, title, icon_url) VALUES ('b-json-null', '{"fr": null}', 'null'), ('c-empty-icon', '{}', '{"en": ""}')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position, subject_check) VALUES
		('sql-2fa', 'otp', 1, 'equal'), ('a-sql', 'sql', 0, 'none'), ('sql-2fa', 'sql', 0, 'none')`)
	exec(t, p, `INSERT INTO setting (key, value) VALUES
		('consent_auto_accept', 'true'), ('login_remember_for', '3600'), ('hydra_public_url', '"http://public"')`)

	s, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantApps := []App{
		{ID: "none", LoginURL: "http://n/login", ConsentURL: "http://n/consent", Method: "pwd", AuthMode: "network", ReceiveClaims: []string{}},
		{ID: "otp", LoginURL: "http://otp/login", ConsentURL: "http://otp/consent", Method: "otp", AuthMode: "mtls",
			ClientCertFingerprint: "ab12"},
		{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", LogoutURL: "http://sql/logout", Method: "pwd", AuthMode: "network",
			AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.5/32"), netip.MustParsePrefix("2001:db8::/32")},
			ReceiveClaims:  []string{"email", "name"}},
	}
	if !reflect.DeepEqual(s.Apps, wantApps) {
		t.Errorf("apps = %+v\nwant %+v", s.Apps, wantApps)
	}
	if a, ok := s.App("sql"); !ok || a.Method != "pwd" {
		t.Errorf("App(sql) = %+v, %v", a, ok)
	}
	if _, ok := s.App("oidc"); ok {
		t.Error("App(oidc) found")
	}
	wantFlows := []Flow{
		{ID: "a-sql", Title: map[string]string{"en": "SQL"}, Description: map[string]string{"en": "Password"}, Enabled: true,
			Steps: []Step{{AppID: "sql", Position: 0, SubjectCheck: "none"}}},
		{ID: "b-json-null", Title: map[string]string{}, Description: map[string]string{}, Enabled: true},
		{ID: "c-empty-icon", Title: map[string]string{}, Description: map[string]string{}, Enabled: true},
		{ID: "sql-2fa", Title: map[string]string{"fr": "SQL 2FA"}, Description: map[string]string{"fr": "Deux facteurs", "en": "Two factors"},
			IconURL: map[string]string{"fr": "http://icons/2fa.svg"}, ACR: "loa2",
			Steps: []Step{{AppID: "sql", Position: 0, SubjectCheck: "none"}, {AppID: "otp", Position: 1, SubjectCheck: "equal"}}},
	}
	if !reflect.DeepEqual(s.Flows, wantFlows) {
		t.Errorf("flows = %+v\nwant %+v", s.Flows, wantFlows)
	}
	want := DefaultSettings()
	want.ConsentAutoAccept, want.LoginRememberFor = true, time.Hour
	if !reflect.DeepEqual(s.Settings, want) {
		t.Errorf("settings = %+v", s.Settings)
	}
	if !slices.Equal(s.Warnings, []string{`setting "hydra_public_url" is unknown to this version: ignored`}) {
		t.Errorf("warnings = %q", s.Warnings)
	}
}

// Flows come by id in byte order, each with its steps, whatever the collation
// of the database: under ICU or glibc, '-', '_' and case sort otherwise.
func TestSnapshotCollation(t *testing.T) {
	ctx := context.Background()
	p := newDatabaseWith(t, `TEMPLATE template0 LOCALE_PROVIDER icu ICU_LOCALE 'en-US' LOCALE 'C'`)
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sql_2fa", "alpha", "sql-otp", "Zeta", "sql2"} {
		exec(t, p, `INSERT INTO app (id, login_url, consent_url, method) VALUES ($1, 'http://a', 'http://a', 'pwd')`, id)
		exec(t, p, `INSERT INTO flow (id) VALUES ($1)`, id)
		exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ($1, $1, 0)`, id)
	}
	s, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Zeta", "alpha", "sql-otp", "sql2", "sql_2fa"}
	var apps, flows []string
	for i, f := range s.Flows {
		apps, flows = append(apps, s.Apps[i].ID), append(flows, f.ID)
		if len(f.Steps) != 1 || f.Steps[0].AppID != f.ID {
			t.Errorf("flow %s: steps %+v", f.ID, f.Steps)
		}
	}
	if !slices.Equal(apps, want) || !slices.Equal(flows, want) {
		t.Errorf("apps %q, flows %q; want %q", apps, flows, want)
	}
}

// A setting the reader cannot take refuses the whole snapshot: Live keeps the
// previous one, and serve does not start. The table cannot check it: its
// type and its rules are those of the registry.
func TestSnapshotRefused(t *testing.T) {
	for _, tt := range []struct{ insert, want string }{
		{`INSERT INTO setting (key, value) VALUES ('challenge_ttl', '"1h"')`, "setting challenge_ttl"},
		{`INSERT INTO setting (key, value) VALUES ('supported_locales', '["fr", "fr"]')`, `setting supported_locales: "fr" is listed twice`},
		{`INSERT INTO setting (key, value) VALUES ('login_accept_webhook_url', '"ftp://hooks/login"')`, `setting login_accept_webhook_url: has the scheme "ftp"`},
	} {
		p := migrated(t)
		exec(t, p, tt.insert)
		if _, err := p.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Snapshot = %v, want %q", tt.insert, err, tt.want)
		}
	}
}

// The locales are read as the table holds them, a theme's or a newer
// version's: the pages, which know the catalogs, set aside those without one
// (Q92). One not well formed stays an error.
func TestSnapshotLocales(t *testing.T) {
	p := migrated(t)
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('supported_locales', '["fr", "en", "de"]'), ('default_locale', '"de"')`)
	s, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Settings.SupportedLocales, []string{"fr", "en", "de"}) || s.Settings.DefaultLocale != "de" || len(s.Warnings) != 0 {
		t.Errorf("locales %q, default %q, warnings %q", s.Settings.SupportedLocales, s.Settings.DefaultLocale, s.Warnings)
	}
	exec(t, p, `UPDATE setting SET value = '["fr", "de_DE"]' WHERE key = 'supported_locales'`)
	if _, err := p.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), `setting supported_locales: "de_DE" is not a locale in lowercase`) {
		t.Errorf("Snapshot = %v", err)
	}
}
