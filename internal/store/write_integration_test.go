//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

func testApp(id string) App {
	return App{ID: id, LoginURL: "http://" + id + "/login", ConsentURL: "http://" + id + "/consent", Method: "pwd", AuthMode: "network"}
}

func testFlow(id string, apps ...string) Flow {
	f := Flow{ID: id, Title: map[string]string{"fr": "F"}, Description: map[string]string{"fr": "D"}, Enabled: true}
	for i, a := range apps {
		f.Steps = append(f.Steps, Step{AppID: a, Position: i, SubjectCheck: "none"})
	}
	return f
}

// author is updated_by of the row id of table.
func author(t *testing.T, p *Postgres, table, id string) string {
	t.Helper()
	var by *string
	key := "id"
	if table == "setting" {
		key = "key"
	}
	if err := p.db.QueryRow(`SELECT updated_by FROM `+table+` WHERE `+key+` = $1`, id).Scan(&by); err != nil {
		t.Fatalf("%s %s: %v", table, id, err)
	}
	if by == nil {
		return "<null>"
	}
	return *by
}

func snapshot(t *testing.T, p *Postgres) *Snapshot {
	t.Helper()
	s, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// violated tells whether err is the violations of fields, in any order.
func violated(err error, fields ...string) bool {
	var v domain.Violations
	if !errors.As(err, &v) || len(v) != len(fields) {
		return false
	}
	for _, f := range fields {
		if !slices.ContainsFunc(v, func(x domain.Violation) bool { return x.Field == f }) {
			return false
		}
	}
	return true
}

func TestWriteApps(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); err != nil {
		t.Fatal(err)
	}
	if a, ok := snapshot(t, p).App("a"); !ok || !reflect.DeepEqual(a, testApp("a")) {
		t.Errorf("app a = %+v, %v", a, ok)
	}
	if by := author(t, p, "app", "a"); by != "admin:alice" {
		t.Errorf("updated_by = %s", by)
	}
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); !errors.Is(err, ErrExists) {
		t.Errorf("app a twice: %v", err)
	}
	bad := testApp("b")
	bad.Method, bad.LoginURL = "", "/login"
	if err := p.CreateApp(ctx, "admin:alice", bad); !violated(err, "method", "login_url") {
		t.Errorf("invalid app: %v", err)
	}
	if err := p.CreateApp(ctx, "", testApp("b")); err == nil || !strings.Contains(err.Error(), "author") {
		t.Errorf("no author: %v", err)
	}

	// PATCH: one field, the others kept.
	if err := p.UpdateApp(ctx, "api_client:c", "a", func(a *App) error {
		a.ReceiveClaims = []string{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if a, _ := snapshot(t, p).App("a"); a.LoginURL != "http://a/login" || a.ReceiveClaims == nil || len(a.ReceiveClaims) != 0 {
		t.Errorf("patched app a = %+v", a)
	}
	if by := author(t, p, "app", "a"); by != "api_client:c" {
		t.Errorf("updated_by = %s", by)
	}
	// PUT: the whole app.
	put := testApp("a")
	put.Method = "otp"
	if err := p.UpdateApp(ctx, "api_client:c", "a", func(a *App) error { *a = put; return nil }); err != nil {
		t.Fatal(err)
	}
	if a, _ := snapshot(t, p).App("a"); !reflect.DeepEqual(a, put) {
		t.Errorf("replaced app a = %+v", a)
	}
	for name, tt := range map[string]struct {
		id     string
		change func(*App) error
		ok     func(error) bool
	}{
		"unknown":       {"x", func(*App) error { return nil }, func(err error) bool { return errors.Is(err, ErrNotFound) }},
		"id changed":    {"a", func(a *App) error { a.ID = "b"; return nil }, func(err error) bool { return violated(err, "id") }},
		"invalid":       {"a", func(a *App) error { a.AuthMode = "cert"; return nil }, func(err error) bool { return violated(err, "auth_mode") }},
		"change failed": {"a", func(*App) error { return errBoom }, func(err error) bool { return errors.Is(err, errBoom) }},
	} {
		if err := p.UpdateApp(ctx, "admin:alice", tt.id, tt.change); !tt.ok(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if a, _ := snapshot(t, p).App("a"); !reflect.DeepEqual(a, put) {
		t.Errorf("app a after the refusals = %+v", a)
	}

	// Referenced by a step: kept, the flows named.
	for _, f := range []string{"g", "f"} {
		if err := p.CreateFlow(ctx, "admin:alice", testFlow(f, "a")); err != nil {
			t.Fatal(err)
		}
	}
	var ref *ReferencedError
	if err := p.DeleteApp(ctx, "a"); !errors.As(err, &ref) || ref.App != "a" || !slices.Equal(ref.Flows, []string{"f", "g"}) {
		t.Errorf("delete a referenced app: %v", err)
	}
	for _, f := range []string{"f", "g"} {
		if err := p.DeleteFlow(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.DeleteApp(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot(t, p).App("a"); ok {
		t.Error("app a still there")
	}
	if err := p.DeleteApp(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete an unknown app: %v", err)
	}
}

var errBoom = errors.New("boom")

func TestWriteFlows(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	for _, a := range []string{"a", "b"} {
		if err := p.CreateApp(ctx, "admin:alice", testApp(a)); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.CreateFlow(ctx, "admin:alice", testFlow("f", "a", "c")); !violated(err, "steps[1]") {
		t.Errorf("step on an unknown app: %v", err)
	}
	if err := p.CreateFlow(ctx, "admin:alice", testFlow("f")); !violated(err, "steps") {
		t.Errorf("flow without steps: %v", err)
	}
	f := testFlow("f", "a")
	f.IconURL, f.ACR = map[string]string{"fr": "http://i/f.svg"}, "loa2"
	if err := p.CreateFlow(ctx, "admin:alice", f); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateFlow(ctx, "admin:alice", testFlow("f", "b")); !errors.Is(err, ErrExists) {
		t.Errorf("flow f twice: %v", err)
	}
	if got := snapshot(t, p).Flows; len(got) != 1 || !reflect.DeepEqual(got[0], f) {
		t.Errorf("flows = %+v", got)
	}

	// The steps replaced, in another order; the rest kept.
	if err := p.UpdateFlow(ctx, "api_client:c", "f", func(f *Flow) error {
		f.Steps = []Step{{AppID: "b", Position: 20, SubjectCheck: "equal"}, {AppID: "a", Position: 10, SubjectCheck: "none"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := snapshot(t, p).Flows[0]
	if want := []Step{{AppID: "a", Position: 10, SubjectCheck: "none"}, {AppID: "b", Position: 20, SubjectCheck: "equal"}}; !reflect.DeepEqual(got.Steps, want) ||
		got.ACR != "loa2" || got.IconURL["fr"] != "http://i/f.svg" {
		t.Errorf("flow f = %+v", got)
	}
	if by := author(t, p, "flow", "f"); by != "api_client:c" {
		t.Errorf("updated_by = %s", by)
	}
	if err := p.UpdateFlow(ctx, "admin:alice", "f", func(f *Flow) error { f.Steps = f.Steps[:1]; f.IconURL = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(t, p).Flows[0]; len(got.Steps) != 1 || got.IconURL != nil {
		t.Errorf("flow f = %+v", got)
	}
	if err := p.UpdateFlow(ctx, "admin:alice", "x", func(*Flow) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("update an unknown flow: %v", err)
	}
	if err := p.UpdateFlow(ctx, "admin:alice", "f", func(f *Flow) error { f.Steps = nil; return nil }); !violated(err, "steps") {
		t.Errorf("steps removed: %v", err)
	}
	if err := p.DeleteFlow(ctx, "f"); err != nil {
		t.Fatal(err)
	}
	var steps int
	if err := p.db.QueryRow(`SELECT count(*) FROM flow_step`).Scan(&steps); err != nil || steps != 0 {
		t.Errorf("%d steps left, %v", steps, err)
	}
	if err := p.DeleteFlow(ctx, "f"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete an unknown flow: %v", err)
	}
}

func TestWriteAPIClients(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	hash, err := domain.HashSecret("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAPIClient(ctx, "cli", APIClient{ID: "c", SecretHash: "s3cret"}); !violated(err, "secret") {
		t.Errorf("secret in clear: %v", err)
	}
	if err := p.CreateAPIClient(ctx, "cli", APIClient{ID: "c", SecretHash: hash}); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAPIClient(ctx, "cli", APIClient{ID: "c", SecretHash: hash}); !errors.Is(err, ErrExists) {
		t.Errorf("client c twice: %v", err)
	}
	if h, scopes := clientHash(t, p, "c"); h != hash || scopes == nil || len(scopes) != 0 {
		t.Errorf("client c = %s, %q", h, scopes)
	}
	if err := p.UpdateAPIClient(ctx, "api_client:admin", "c", func(c *APIClient) error {
		c.Scopes = []string{"admin:flows", "admin:apps"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if h, scopes := clientHash(t, p, "c"); !domain.SecretMatches(h, "s3cret") || !slices.Equal(scopes, []string{"admin:flows", "admin:apps"}) {
		t.Errorf("client c = %s, %q", h, scopes)
	}
	if by := author(t, p, "api_client", "c"); by != "api_client:admin" {
		t.Errorf("updated_by = %s", by)
	}
	if err := p.UpdateAPIClient(ctx, "cli", "c", func(c *APIClient) error { c.Scopes = []string{"admin flows"}; return nil }); !violated(err, "scopes[0]") {
		t.Errorf("scope with a space: %v", err)
	}
	if err := p.DeleteAPIClient(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteAPIClient(ctx, "c"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete an unknown client: %v", err)
	}
}

func values(t *testing.T, kv map[string]any) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m[k] = raw
	}
	return m
}

func rowCount(t *testing.T, p *Postgres, table string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteSettings(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	if err := p.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"app_auto_select": true, "challenge_ttl": 1800})); err != nil {
		t.Fatal(err)
	}
	if s := snapshot(t, p).Settings; !s.AppAutoSelect || s.ChallengeTTL != 30*time.Minute {
		t.Errorf("settings = %+v", s)
	}
	// Unchanged, or the default without a row: nothing written.
	if err := p.UpdateSettings(ctx, "admin:bob", values(t, map[string]any{"challenge_ttl": 1800, "remember": true, "fallback_locale": "en"})); err != nil {
		t.Fatal(err)
	}
	if by, n := author(t, p, "setting", "challenge_ttl"), rowCount(t, p, "setting"); by != "admin:alice" || n != 2 {
		t.Errorf("unchanged values written: updated_by %s, %d rows", by, n)
	}
	// null: the default again, the row gone.
	if err := p.UpdateSettings(ctx, "admin:bob", map[string]json.RawMessage{"challenge_ttl": json.RawMessage("null")}); err != nil {
		t.Fatal(err)
	}
	if s, n := snapshot(t, p).Settings, rowCount(t, p, "setting"); s.ChallengeTTL != time.Hour || n != 1 {
		t.Errorf("reset: %v, %d rows", s.ChallengeTTL, n)
	}
	for name, tt := range map[string]struct {
		values map[string]json.RawMessage
		fields []string
	}{
		"unknown key":      {values(t, map[string]any{"nope": 1}), []string{"nope"}},
		"wrong type":       {values(t, map[string]any{"remember": "yes", "challenge_ttl": 1.5}), []string{"remember", "challenge_ttl"}},
		"zero":             {values(t, map[string]any{"challenge_ttl": 0}), []string{"challenge_ttl"}},
		"together":         {values(t, map[string]any{"supported_locales": []string{"en"}}), []string{"default_locale"}},
		"webhook scheme":   {values(t, map[string]any{"login_accept_webhook_url": "ftp://hooks/login"}), []string{"login_accept_webhook_url"}},
		"trailing content": {map[string]json.RawMessage{"remember": json.RawMessage("true true")}, []string{"remember"}},
	} {
		if err := p.UpdateSettings(ctx, "admin:alice", tt.values); !violated(err, tt.fields...) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := rowCount(t, p, "setting"); n != 1 {
		t.Errorf("%d rows after the refusals", n)
	}

	// A row this version cannot read refuses the writes that leave it, not
	// the one that corrects it.
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('challenge_ttl', '"1h"')`)
	var refused *RefusedError
	if err := p.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"remember": false})); !errors.As(err, &refused) {
		t.Errorf("over an unreadable row: %v", err)
	}
	if err := p.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"challenge_ttl": 600})); err != nil {
		t.Errorf("the correction: %v", err)
	}
	if s := snapshot(t, p).Settings; s.ChallengeTTL != 10*time.Minute {
		t.Errorf("challenge_ttl = %v", s.ChallengeTTL)
	}
}

// A write whose configuration the instance would refuse writes nothing, and
// notifies no one.
func TestWriteRefused(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	checked := 0
	p.SetCheck(func(s *Snapshot) error {
		checked++
		if strings.HasPrefix(s.Settings.LoginAcceptWebhookURL, "http://") {
			return errors.New("setting login_accept_webhook_url: is in http://, which needs tls.allow_http")
		}
		return nil
	})
	committed := 0
	p.OnCommit(func(context.Context) { committed++ })
	listen := listener(t, p)
	err := p.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"login_accept_webhook_url": "http://hooks/login"}))
	var refused *RefusedError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "tls.allow_http") {
		t.Errorf("http webhook: %v", err)
	}
	if n := rowCount(t, p, "setting"); n != 0 || committed != 0 {
		t.Errorf("%d rows, %d commits", n, committed)
	}
	if listen(300 * time.Millisecond) {
		t.Error("a refused write notified")
	}
	if err := p.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"login_accept_webhook_url": "https://hooks/login"})); err != nil {
		t.Fatal(err)
	}
	if !listen(5*time.Second) || committed != 1 || checked != 2 {
		t.Errorf("accepted write: notified no one, or %d commits, %d checks", committed, checked)
	}
}

// listener listens on the channel of the writes, on a connection of its own,
// and tells whether a notification comes within a duration.
func listener(t *testing.T, p *Postgres) func(time.Duration) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsnOf(t, p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		t.Fatal(err)
	}
	return func(d time.Duration) bool {
		waitCtx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		_, err := conn.WaitForNotification(waitCtx)
		return err == nil
	}
}

// dsnOf is the URL of the database of p.
func dsnOf(t *testing.T, p *Postgres) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + databaseName(t, p)
	return u.String()
}

// Two writes valid each, from two instances at once, never leave together a
// configuration serve refuses: the second sees the first.
func TestWriteConcurrently(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	q := replica(t, p)
	for i := range 10 {
		exec(t, p, `DELETE FROM setting`)
		if err := p.UpdateSettings(ctx, "setup", values(t, map[string]any{"supported_locales": []string{"fr", "en", "de"}})); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 2)
		go func() { errs <- p.UpdateSettings(ctx, "a", values(t, map[string]any{"default_locale": "de"})) }()
		go func() {
			errs <- q.UpdateSettings(ctx, "b", values(t, map[string]any{"supported_locales": []string{"fr", "en"}}))
		}()
		e1, e2 := <-errs, <-errs
		if (e1 == nil) == (e2 == nil) || !violated(errors.Join(e1, e2), "default_locale") && !violated(errors.Join(e1, e2), "supported_locales") {
			t.Errorf("round %d: %v, %v; want one refused", i, e1, e2)
		}
		if _, err := p.Snapshot(ctx); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}

	for i := range 10 {
		exec(t, p, `DELETE FROM flow; DELETE FROM app`)
		if err := p.CreateApp(ctx, "setup", testApp("b")); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 2)
		go func() { errs <- p.DeleteApp(ctx, "b") }()
		go func() { errs <- q.CreateFlow(ctx, "b", testFlow("f", "b")) }()
		e1, e2 := <-errs, <-errs
		var ref *ReferencedError
		if (e1 == nil) == (e2 == nil) || !errors.As(errors.Join(e1, e2), &ref) && !violated(errors.Join(e1, e2), "steps[0]") {
			t.Errorf("round %d: %v, %v; want one refused", i, e1, e2)
		}
	}
}

// What a write leaves, the hook of the instance sees at once.
func TestWriteOnCommit(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	live, err := NewLive(ctx, p, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var refreshes atomic.Int32
	p.OnCommit(func(ctx context.Context) {
		refreshes.Add(1)
		if err := live.Refresh(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); err != nil {
		t.Fatal(err)
	}
	if _, ok := live.Snapshot().App("a"); !ok || refreshes.Load() != 1 {
		t.Errorf("app a not in the snapshot of the instance after %d refreshes", refreshes.Load())
	}
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); err == nil || refreshes.Load() != 1 {
		t.Errorf("a refused write: %v, %d refreshes", err, refreshes.Load())
	}
}

// 00004 marks what was there as written by bootstrap, the only writer before,
// and refuses a role, scopes or an id the readers do not take.
func TestMigrateAdminWrites(t *testing.T) {
	ctx := context.Background()
	p := newDatabase(t)
	m, err := p.migrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method) VALUES ('a', 'http://a', 'http://a', 'pwd')`)
	exec(t, p, `INSERT INTO flow (id) VALUES ('f')`)
	exec(t, p, `INSERT INTO api_client (id, secret_hash) VALUES ('c', 'x')`)
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{"app", "a"}, {"flow", "f"}, {"api_client", "c"}} {
		if by := author(t, p, row[0], row[1]); by != "bootstrap" {
			t.Errorf("%s %s: updated_by = %s", row[0], row[1], by)
		}
	}
	for insert, want := range map[string]string{
		`INSERT INTO admin_user (username, role) VALUES ('u', 'super_admin')`:                       "admin_user_role",
		`INSERT INTO api_client (id, secret_hash, scopes) VALUES ('d', 'x', '{NULL}')`:              "api_client_scopes",
		`INSERT INTO api_client (id, secret_hash, scopes) VALUES ('d', 'x', '{{a}}')`:               "api_client_scopes",
		`INSERT INTO api_client (id, secret_hash) VALUES ('` + strings.Repeat("c", 129) + `', 'x')`: "character varying(128)",
	} {
		if _, err := p.db.Exec(insert); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %s", insert, err, want)
		}
	}
	exec(t, p, `INSERT INTO admin_user (username, role) VALUES ('u', 'viewer'), ('v', 'admin')`)
}

// force rewrites what an admin wrote over the seed and names its author, never
// a row of its own; the author of each row it writes is bootstrap (Q100).
func TestBootstrapOverwrites(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	seed := loadSeed(t, `
dispatcher:
  remember: false
  app_auto_select: true
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
    - { id: b, login_url: http://b/login, consent_url: http://b/consent, method: pwd }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: a, order: 0 }] }
  oauth2_clients:
    - { id: c, secret: s3cret }
`)
	if _, err := p.Bootstrap(ctx, seed, Force, true); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{"app", "a"}, {"flow", "f"}, {"api_client", "c"}, {"setting", "remember"}} {
		if by := author(t, p, row[0], row[1]); by != "bootstrap" {
			t.Errorf("%s %s: updated_by = %s", row[0], row[1], by)
		}
	}
	if err := p.UpdateApp(ctx, "admin:alice", "a", func(a *App) error { a.Method = "otp"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateFlow(ctx, "api_client:c", "f", func(f *Flow) error { f.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateAPIClient(ctx, "cli", "c", func(c *APIClient) error { c.Scopes = []string{"admin:apps"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateSettings(ctx, "admin:bob", values(t, map[string]any{"remember": true, "app_auto_select": false})); err != nil {
		t.Fatal(err)
	}
	// The same rows written again by the seed, and one an older version
	// wrote without an author: that of bootstrap.
	exec(t, p, `UPDATE app SET updated_by = NULL, login_url = 'http://b/old' WHERE id = 'b'`)
	seedNull := loadSeed(t, `
dispatcher:
  remember: false
  app_auto_select: ~
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
    - { id: b, login_url: http://b/login, consent_url: http://b/consent, method: pwd }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: a, order: 0 }] }
  oauth2_clients:
    - { id: c, secret: s3cret }
`)
	for _, write := range []bool{false, true} {
		changes, err := p.Bootstrap(ctx, seedNull, Force, write)
		if err != nil {
			t.Fatal(err)
		}
		by := map[string]string{}
		for _, c := range changes {
			by[c.Kind+" "+c.ID] = string(c.Action) + " " + c.By
		}
		want := map[string]string{
			"setting remember": "update admin:bob", "setting app_auto_select": "reset admin:bob",
			"app a": "update admin:alice", "app b": "update ", "flow f": "update api_client:c", "api_client c": "update cli",
		}
		if !reflect.DeepEqual(by, want) {
			t.Errorf("write %v: changes = %q\nwant %q", write, by, want)
		}
	}
	for _, row := range [][2]string{{"app", "a"}, {"app", "b"}, {"flow", "f"}, {"api_client", "c"}, {"setting", "remember"}} {
		if by := author(t, p, row[0], row[1]); by != "bootstrap" {
			t.Errorf("%s %s after force: updated_by = %s", row[0], row[1], by)
		}
	}
	// Without force, nothing replaced: nothing named.
	if err := p.UpdateApp(ctx, "admin:alice", "a", func(a *App) error { a.Method = "otp"; return nil }); err != nil {
		t.Fatal(err)
	}
	changes, err := p.Bootstrap(ctx, seedNull, Missing, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if c.By != "" {
			t.Errorf("missing: %+v", c)
		}
	}
}

// A seed serve would refuse is not written, a dry run says so as the write
// does, and only a write notifies the instances.
func TestBootstrapRefusedSnapshot(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	p.SetCheck(func(s *Snapshot) error {
		if strings.HasPrefix(s.Settings.ConsentAcceptWebhookURL, "http://") {
			return errors.New("setting consent_accept_webhook_url: is in http://, which needs tls.allow_http")
		}
		return nil
	})
	committed := 0
	p.OnCommit(func(context.Context) { committed++ })
	listen := listener(t, p)
	seed := loadSeed(t, `
dispatcher:
  consent_accept_webhook_url: http://hooks/consent
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
`)
	for _, write := range []bool{false, true} {
		_, err := p.Bootstrap(ctx, seed, Force, write)
		var refused *RefusedError
		if !errors.As(err, &refused) || !strings.HasPrefix(err.Error(), "bootstrap: the configuration this write leaves would be refused: setting consent_accept_webhook_url") {
			t.Errorf("write %v: %v", write, err)
		}
	}
	if s := snapshot(t, p); len(s.Apps) != 0 || s.Settings.ConsentAcceptWebhookURL != "" || committed != 0 || listen(300*time.Millisecond) {
		t.Errorf("refused seed: %d apps, webhook %q, %d commits", len(s.Apps), s.Settings.ConsentAcceptWebhookURL, committed)
	}
	ok := loadSeed(t, `
dispatcher:
  consent_accept_webhook_url: https://hooks/consent
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
`)
	if _, err := p.Bootstrap(ctx, ok, Force, false); err != nil || committed != 0 || listen(300*time.Millisecond) {
		t.Errorf("dry run: %v, %d commits", err, committed)
	}
	if _, err := p.Bootstrap(ctx, ok, Force, true); err != nil || committed != 1 || !listen(5*time.Second) {
		t.Errorf("write: %v, %d commits", err, committed)
	}
	if s := snapshot(t, p); len(s.Apps) != 1 {
		t.Errorf("%d apps", len(s.Apps))
	}
}

// A failure of the database while the write reads its configuration back (a
// lock_timeout here) is an error of the database, not a refusal (revue R33):
// the admin API answers 500, not 422.
func TestWriteReadBackFails(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, fmt.Sprintf(`ALTER DATABASE %s SET lock_timeout = '200ms'`, databaseName(t, p)))
	q := replica(t, p) // its connections take the lock_timeout
	locker, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locker.Rollback() }()
	if _, err := locker.Exec(`LOCK TABLE api_client IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	err = q.UpdateSettings(ctx, "admin:alice", values(t, map[string]any{"remember": false}))
	var refused *RefusedError
	if err == nil || errors.As(err, &refused) || !strings.Contains(err.Error(), "lock timeout") {
		t.Errorf("err = %v, want an error of the database, not a refusal", err)
	}
	_ = locker.Rollback()
	if n := rowCount(t, p, "setting"); n != 0 {
		t.Errorf("%d rows written", n)
	}
}
