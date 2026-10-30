//go:build integration

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
		"keep setting consent_auto_accept: value", "keep setting remember: value", "absent setting old_key",
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
		"update setting consent_auto_accept: value", "reset setting remember: value", "absent setting old_key",
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
	// A reset shows the value it drops and the default it gives.
	if f := changes[1].Fields[0]; f.Old != "false" || f.New != "true" {
		t.Errorf("remember: %s -> %s", f.Old, f.New)
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

// Replicas bootstrapping at once, as serve.bootstrap force has them, each on
// its pool: the lock lets one write, the others find everything there.
// Without it, they would all announce the creations, ON CONFLICT hiding the
// race. In repeatable read, the default of some databases, the snapshot of a
// replica that waited would predate the writes of the first.
func TestBootstrapConcurrently(t *testing.T) {
	data, err := os.ReadFile("../config/testdata/hydra-dev-dispatcher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seed := loadSeed(t, string(data))
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) {
			p := migrated(t)
			exec(t, p, fmt.Sprintf(`ALTER DATABASE %s SET default_transaction_isolation = '%s'`, databaseName(t, p), isolation))
			type result struct {
				changes []Change
				err     error
			}
			results := make(chan result, 3)
			for range 3 {
				r := replica(t, p)
				go func() {
					changes, err := r.Bootstrap(context.Background(), seed, Force, true)
					results <- result{changes, err}
				}()
			}
			writers := 0
			for range 3 {
				res := <-results
				if res.err != nil {
					t.Fatal(res.err)
				}
				lines := actions(res.changes)
				if slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "create ") }) {
					writers++
				} else if slices.ContainsFunc(lines, func(l string) bool { return !strings.HasPrefix(l, "same ") }) {
					t.Errorf("a replica after the first: %q", lines)
				}
			}
			if writers != 1 {
				t.Errorf("%d replicas created the seed, want 1", writers)
			}
		})
	}
}

func databaseName(t *testing.T, p *Postgres) string {
	t.Helper()
	var name string
	if err := p.db.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

// replica opens another pool on the database of p, as another replica does:
// its connections take the settings the database has now.
func replica(t *testing.T, p *Postgres) *Postgres {
	t.Helper()
	u, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + databaseName(t, p)
	r, err := Open(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// Every kind of field comes back as written: a second pass, with or without
// force, finds it the same. The numbers of the options too, which jsonb
// writes without exponent.
func TestBootstrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	fingerprint := strings.Repeat("AB:", 31) + "CD"
	seed := loadSeed(t, `
dispatcher:
  apps:
    - id: a
      login_url: http://a/login
      consent_url: http://a/consent
      method: pwd
      allowed_sources: ["10.0.0.1", "::ffff:10.1.0.0/112", "2001:DB8::/32", "10.2.0.1/16"]
      options: { tolerance: 0.0000001, big: 1e21, zero: -0.0, uint: 12345678901234567890, scale: 1.50, nested: { list: [1, "x", ~, true] } }
    - { id: m, login_url: http://m/login, consent_url: http://m/consent, logout_url: http://m/logout, method: otp, auth_mode: mtls, client_cert_fingerprint: "`+fingerprint+`" }
  flows:
    - id: f
      title: F
      description: { fr: D, en: "" }
      icon_url: http://i/f.svg
      acr: gold
      enabled: false
      steps: [{ id: a, order: 0, subject_check: equal }, { id: m, order: 1, subject_check: "claim:email" }]
  oauth2_clients:
    - { id: c, secret: s3cret, scopes: [] }
`)
	if _, err := p.Bootstrap(ctx, seed, Missing, true); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []Mode{Missing, Force} {
		changes, err := p.Bootstrap(ctx, seed, mode, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range changes {
			if c.Action != Same {
				t.Errorf("mode %d, second pass: %s %s %s: %+v", mode, c.Action, c.Kind, c.ID, c.Fields)
			}
		}
	}

	s, err := p.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.App("a")
	var sources []string
	for _, src := range a.AllowedSources {
		sources = append(sources, src.String())
	}
	if !slices.Equal(sources, []string{"10.0.0.1/32", "10.1.0.0/16", "2001:db8::/32", "10.2.0.0/16"}) ||
		a.Options["tolerance"] != json.Number("0.0000001") || a.Options["big"] != json.Number("1000000000000000000000") ||
		a.Options["zero"] != json.Number("0") || a.Options["uint"] != json.Number("12345678901234567890") {
		t.Errorf("app a: sources %q, options %v", sources, a.Options)
	}
	if m, _ := s.App("m"); m.AuthMode != "mtls" || m.ClientCertFingerprint != strings.ToLower(strings.ReplaceAll(fingerprint, ":", "")) ||
		m.AllowedSources != nil || m.LogoutURL != "http://m/logout" {
		t.Errorf("app m = %+v", m)
	}
	want := Flow{
		ID: "f", Title: map[string]string{"": "F"}, Description: map[string]string{"fr": "D"}, IconURL: map[string]string{"": "http://i/f.svg"},
		ACR: "gold", Steps: []Step{{"a", 0, "equal"}, {"m", 1, "claim:email"}},
	}
	if !reflect.DeepEqual(s.Flows, []Flow{want}) {
		t.Errorf("flows = %+v\nwant %+v", s.Flows, want)
	}
}

// Force rewrites the steps of a flow whole, and the scopes of a client while
// it keeps the hash of its unchanged secret. A setting reset takes its
// default, which the next pass finds the same.
func TestBootstrapRewrites(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	const content = `
dispatcher:
  apps:
    - { id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd }
    - { id: b, login_url: http://b/login, consent_url: http://b/consent, method: otp }
    - { id: c, login_url: http://c/login, consent_url: http://c/consent, method: oidc }
  flows:
    - { id: f, title: F, description: D, steps: %s }
  oauth2_clients:
    - { id: client, secret: s3cret, scopes: %s }
  remember: %s
`
	first := fmt.Sprintf(content, "[{ id: a, order: 0 }, { id: b, order: 1, subject_check: equal }, { id: c, order: 2 }]", "[admin:flows]", "false")
	if _, err := p.Bootstrap(ctx, loadSeed(t, first), Missing, true); err != nil {
		t.Fatal(err)
	}
	hash, _ := clientHash(t, p, "client")

	second := loadSeed(t, fmt.Sprintf(content, "[{ id: b, order: 0 }, { id: a, order: 1 }]", "[admin:apps]", "~"))
	changes, err := p.Bootstrap(ctx, second, Force, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"reset setting remember: value", "same app a", "same app b", "same app c",
		"update flow f: steps", "update api_client client: scopes",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("changes = %q\nwant %q", got, want)
	}
	s, _ := p.Snapshot(ctx)
	if !reflect.DeepEqual(s.Flows[0].Steps, []Step{{"b", 0, "none"}, {"a", 1, "none"}}) || !s.Settings.Remember {
		t.Errorf("steps = %+v, remember = %v", s.Flows[0].Steps, s.Settings.Remember)
	}
	if again, scopes := clientHash(t, p, "client"); again != hash || !slices.Equal(scopes, []string{"admin:apps"}) {
		t.Errorf("client: hash kept %v, scopes %q", again == hash, scopes)
	}

	changes, err = p.Bootstrap(ctx, second, Force, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range actions(changes) {
		if !strings.HasPrefix(line, "same ") {
			t.Errorf("third pass: %s", line)
		}
	}
}

// A failure after the first writes leaves nothing behind.
func TestBootstrapRollback(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	exec(t, p, `CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$`)
	exec(t, p, `CREATE TRIGGER refuse BEFORE INSERT ON api_client FOR EACH ROW EXECUTE FUNCTION refuse()`)
	data, err := os.ReadFile("../config/testdata/hydra-dev-dispatcher.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Bootstrap(ctx, loadSeed(t, string(data)), Missing, true); err == nil || !strings.Contains(err.Error(), "API client test: ERROR: refused") {
		t.Fatalf("Bootstrap = %v, want the client refused", err)
	}
	var rows int
	if err := p.db.QueryRow(`SELECT (SELECT count(*) FROM setting) + (SELECT count(*) FROM app) + (SELECT count(*) FROM flow) + (SELECT count(*) FROM flow_step)`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("%d rows left, %v", rows, err)
	}
}

// A secret past the 72 bytes bcrypt reads is hashed first, as Symfony does:
// the next pass finds it the same, as it does against a hash Symfony made.
func TestBootstrapLongSecret(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	seed := loadSeed(t, "dispatcher:\n  oauth2_clients:\n    - { id: c, secret: "+symfonySecret+" }\n")
	if _, err := p.Bootstrap(ctx, seed, Missing, true); err != nil {
		t.Fatal(err)
	}
	if hash, _ := clientHash(t, p, "c"); bcrypt.CompareHashAndPassword([]byte(hash), bcryptInput(symfonySecret)) != nil {
		t.Errorf("hash %q does not check", hash)
	}
	exec(t, p, `UPDATE api_client SET secret_hash = $1`, symfonyHash)
	changes, err := p.Bootstrap(ctx, seed, Force, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := actions(changes); !slices.Equal(got, []string{"same api_client c"}) {
		t.Errorf("changes = %q", got)
	}
}
