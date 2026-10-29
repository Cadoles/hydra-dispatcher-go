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
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
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

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	p := newDatabase(t)
	applied, err := p.Migrate(ctx)
	if err != nil || !slices.Equal(applied, []string{"00001_schema.sql"}) {
		t.Fatalf("Migrate = %q, %v", applied, err)
	}
	if applied, err := p.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Errorf("second Migrate = %q, %v; want nothing applied", applied, err)
	}
	rows, err := p.db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`)
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
	want := []string{"admin_user", "api_client", "app", "flow", "flow_step", "goose_db_version", "scope", "setting"}
	if !slices.Equal(tables, want) {
		t.Errorf("tables = %q, want %q", tables, want)
	}
}

// Replicas migrating at once: one applies, the others find nothing to do.
func TestMigrateConcurrently(t *testing.T) {
	p := newDatabase(t)
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := p.Migrate(context.Background())
			errs <- err
		}()
	}
	for range 3 {
		if err := <-errs; err != nil {
			t.Error(err)
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
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, logout_url, method, allowed_sources, options) VALUES
		('sql', 'http://sql/login', 'http://sql/consent', 'http://sql/logout', 'pwd', '{10.1.0.0/16,10.2.0.5}', '{"theme": "dark", "n": 2}')`)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, auth_mode, client_cert_fingerprint) VALUES
		('otp', 'http://otp/login', 'http://otp/consent', 'otp', 'mtls', 'ab12')`)
	exec(t, p, `INSERT INTO flow (id, title, description, icon_url, enabled, acr) VALUES
		('sql-2fa', '{"fr": "SQL 2FA"}', '{"fr": "Deux facteurs", "en": "Two factors"}', '{"fr": "http://icons/2fa.svg"}', false, 'loa2')`)
	exec(t, p, `INSERT INTO flow (id, title, description) VALUES ('a-sql', '{"en": "SQL"}', '{"en": "Password"}')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position, subject_check) VALUES
		('sql-2fa', 'otp', 1, 'equal'), ('a-sql', 'sql', 0, 'none'), ('sql-2fa', 'sql', 0, 'none')`)
	exec(t, p, `INSERT INTO setting (key, value) VALUES
		('consent_auto_accept', 'true'), ('login_remember_for', '3600'), ('hydra_public_url', '"http://public"')`)

	s, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantApps := []App{
		{ID: "otp", LoginURL: "http://otp/login", ConsentURL: "http://otp/consent", Method: "otp", AuthMode: "mtls",
			ClientCertFingerprint: "ab12", Options: map[string]any{}},
		{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", LogoutURL: "http://sql/logout", Method: "pwd", AuthMode: "network",
			AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.5/32")},
			Options:        map[string]any{"theme": "dark", "n": float64(2)}},
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

// A value of the wrong type refuses the snapshot: Live keeps the previous one.
func TestSnapshotBadSetting(t *testing.T) {
	p := migrated(t)
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('challenge_ttl', '"1h"')`)
	if _, err := p.Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "setting challenge_ttl") {
		t.Errorf("Snapshot = %v, want the bad setting", err)
	}
}
