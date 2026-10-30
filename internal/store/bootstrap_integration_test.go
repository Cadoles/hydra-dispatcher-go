//go:build integration

package store

import (
	"context"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// actions sums up changes as "action kind id" lines, the fields of an update
// or a keep after a colon.
func actions(changes []Change) []string {
	var lines []string
	for _, c := range changes {
		line := string(c.Action) + " " + c.Kind + " " + c.ID
		if len(c.Fields) > 0 {
			var names []string
			for _, f := range c.Fields {
				names = append(names, f.Name)
			}
			line += ": " + strings.Join(names, ",")
		}
		lines = append(lines, line)
	}
	return lines
}

func clientHash(t *testing.T, p *Postgres, id string) (string, []string) {
	t.Helper()
	clients, err := readAPIClients(context.Background(), p.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		if c.id == id {
			return c.secretHash, c.scopes
		}
	}
	t.Fatalf("no API client %s", id)
	return "", nil
}

// hydra-dev's seed, the Symfony dispatcher.yaml, then the same again: the
// second pass changes nothing, with or without force.
func TestBootstrapHydraDev(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	data, err := os.ReadFile("../config/testdata/hydra-dev-dispatcher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed := loadSeed(t, string(data))
	changes, err := p.Bootstrap(ctx, seed, Missing, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"create setting app_auto_select", "create setting consent_auto_accept", "create setting aggregate_amr_from_login_request",
		"create setting login_remember_for",
		"create app hydra-oidc", "create app hydra-sql", "create app hydra-2fa",
		"create flow hydra-oidc", "create flow hydra-sql", "create flow hydra-sql-2fa",
		"create api_client test",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("changes = %q\nwant %q", got, want)
	}

	s, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Settings.LoginRememberFor != 86400*time.Second || s.Settings.AppAutoSelect || len(s.Apps) != 3 || len(s.Flows) != 3 {
		t.Errorf("snapshot = %+v", s)
	}
	sql2fa := s.Flows[slices.IndexFunc(s.Flows, func(f Flow) bool { return f.ID == "hydra-sql-2fa" })]
	if !reflect.DeepEqual(sql2fa.Steps, []Step{{"hydra-sql", 0, "none"}, {"hydra-2fa", 1, "none"}}) || sql2fa.IconURL != nil ||
		sql2fa.Title["fr"] != "Hydra SQL 2FA" || !sql2fa.Enabled {
		t.Errorf("hydra-sql-2fa = %+v", sql2fa)
	}
	if a, _ := s.App("hydra-sql"); a.LogoutURL != "http://sql.hydra.test/logout" || a.AuthMode != "network" || a.AllowedSources != nil {
		t.Errorf("hydra-sql = %+v", a)
	}
	hash, scopes := clientHash(t, p, "test")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("test")) != nil || !slices.Equal(scopes, []string{"admin:flows"}) {
		t.Errorf("client test: hash %q, scopes %q", hash, scopes)
	}

	for _, mode := range []Mode{Missing, Force} {
		changes, err := p.Bootstrap(ctx, seed, mode, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range actions(changes) {
			if !strings.HasPrefix(line, "same ") {
				t.Errorf("mode %d, second pass: %s", mode, line)
			}
		}
	}
	if again, _ := clientHash(t, p, "test"); again != hash {
		t.Error("the unchanged secret was hashed again")
	}
}

// What the database holds otherwise: kept without force, rewritten with it,
// written by neither in a dry run; what the seed lacks stays.
func TestBootstrapModes(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method) VALUES ('a', 'http://old/login', 'http://a/consent', 'pwd')`)
	exec(t, p, `INSERT INTO flow (id, title, description) VALUES ('legacy', '{"fr": "L"}', '{"fr": "L"}')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ('legacy', 'a', 0)`)
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('consent_auto_accept', 'true'), ('remember', 'false'), ('old_key', '1')`)
	exec(t, p, `INSERT INTO api_client (id, secret_hash) VALUES ('c', 'not-a-hash')`)
	seed := loadSeed(t, `
dispatcher:
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd, options: { theme: dark } }
  flows:
    - { id: f, title: F, description: D, steps: [{ id: a, order: 0 }] }
  oauth2_clients:
    - { id: c, secret: s3cret, scopes: [admin:flows, admin:apps] }
  consent_auto_accept: false
  remember: ~
`)

	changes, err := p.Bootstrap(ctx, seed, Missing, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"keep setting consent_auto_accept: value", "keep setting remember", "absent setting old_key",
		"keep app a: login_url,options",
		"create flow f", "absent flow legacy",
		"keep api_client c: secret,scopes",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("missing: changes = %q\nwant %q", got, want)
	}
	s, _ := p.Snapshot(ctx)
	if a, _ := s.App("a"); a.LoginURL != "http://old/login" || !s.Settings.ConsentAutoAccept || s.Settings.Remember || len(s.Flows) != 2 {
		t.Errorf("missing: app a = %+v, settings = %+v, flows = %d", a, s.Settings, len(s.Flows))
	}

	// Force in a dry run: the changes, nothing written.
	changes, err = p.Bootstrap(ctx, seed, Force, false)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"update setting consent_auto_accept: value", "reset setting remember", "absent setting old_key",
		"update app a: login_url,options",
		"same flow f", "absent flow legacy",
		"update api_client c: secret,scopes",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("dry run: changes = %q\nwant %q", got, want)
	}
	if f := changes[0].Fields[0]; f.Old != "true" || f.New != "false" {
		t.Errorf("consent_auto_accept: %s -> %s", f.Old, f.New)
	}
	if f := changes[6].Fields[0]; !f.Secret || f.Old != "" || f.New != "" {
		t.Errorf("secret change = %+v, want no value", f)
	}
	if s, _ := p.Snapshot(ctx); !s.Settings.ConsentAutoAccept {
		t.Error("the dry run wrote")
	}

	if _, err := p.Bootstrap(ctx, seed, Force, true); err != nil {
		t.Fatal(err)
	}
	s, _ = p.Snapshot(ctx)
	a, _ := s.App("a")
	if a.LoginURL != "http://a/login" || a.Options["theme"] != "dark" || s.Settings.ConsentAutoAccept || !s.Settings.Remember || len(s.Flows) != 2 {
		t.Errorf("force: app a = %+v, settings = %+v, flows = %d", a, s.Settings, len(s.Flows))
	}
	if !slices.Equal(s.Warnings, []string{`setting "old_key" is unknown to this version: ignored`}) {
		t.Errorf("warnings = %q", s.Warnings)
	}
	hash, scopes := clientHash(t, p, "c")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cret")) != nil || !slices.Equal(scopes, []string{"admin:flows", "admin:apps"}) {
		t.Errorf("client c: scopes %q", scopes)
	}
}

// Settings that do not hold together refuse the whole bootstrap.
func TestBootstrapRefusedSettings(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	seed := loadSeed(t, `
dispatcher:
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
  supported_locales: [en]
`)
	_, err := p.Bootstrap(ctx, seed, Force, true)
	if err == nil || !strings.Contains(err.Error(), `setting default_locale: "fr" is not in supported_locales`) {
		t.Fatalf("Bootstrap = %v, want the default locale refused", err)
	}
	if s, _ := p.Snapshot(ctx); len(s.Apps) != 0 {
		t.Error("an app was written by the refused bootstrap")
	}
}

// An older version bootstraps on the table of a newer one: the locales it has
// no catalog for are tolerated there, as Snapshot tolerates them, and left as
// they are. The seed's own are not.
func TestBootstrapNewerLocales(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('supported_locales', '["fr", "en", "de"]'), ('default_locale', '"de"')`)
	if _, err := p.Bootstrap(ctx, loadSeed(t, "dispatcher:\n  app_auto_select: true\n"), Force, true); err != nil {
		t.Fatalf("Bootstrap = %v", err)
	}
	var locales string
	if err := p.db.QueryRow(`SELECT value::text FROM setting WHERE key = 'supported_locales'`).Scan(&locales); err != nil || locales != `["fr", "en", "de"]` {
		t.Errorf("supported_locales = %s, %v; want it left as it is", locales, err)
	}
	_, err := p.Bootstrap(ctx, loadSeed(t, "dispatcher:\n  supported_locales: [fr, de]\n"), Force, true)
	if err == nil || !strings.Contains(err.Error(), `setting supported_locales: "de" has no catalog`) {
		t.Errorf("Bootstrap of a locale without a catalog = %v", err)
	}
}

// A duration of the seed that is not whole seconds is refused, not cut.
func TestBootstrapFractionOfASecond(t *testing.T) {
	p := migrated(t)
	_, err := p.Bootstrap(context.Background(), loadSeed(t, "dispatcher:\n  challenge_ttl: 1500ms\n"), Missing, true)
	if err == nil || !strings.Contains(err.Error(), "setting challenge_ttl: must be a whole number of seconds") {
		t.Errorf("Bootstrap = %v", err)
	}
}

// Replicas bootstrapping at once, as serve.bootstrap force has them: the
// lock lets one write, the others find everything there.
func TestBootstrapConcurrently(t *testing.T) {
	p := migrated(t)
	data, err := os.ReadFile("../config/testdata/hydra-dev-dispatcher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed := loadSeed(t, string(data))
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := p.Bootstrap(context.Background(), seed, Force, true)
			errs <- err
		}()
	}
	for range 3 {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
