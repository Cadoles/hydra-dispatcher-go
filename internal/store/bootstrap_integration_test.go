//go:build integration

package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

// symfonyHash is the hash Symfony's NativePasswordHasher (bcrypt, cost 4)
// gave symfonySecret, 100 bytes long (domain.BcryptInput).
const symfonyHash = "$2y$04$iuml1FnUXrHaDd/Sxqt9UOniJuDi.W.KCQHk3.1uwFwFUwQmLYt5W"

var symfonySecret = strings.Repeat("0123456789", 10)

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
	if !reflect.DeepEqual(sql2fa.Steps, []Step{{AppID: "hydra-sql", Position: 0, SubjectCheck: "none"}, {AppID: "hydra-2fa", Position: 1, SubjectCheck: "none"}}) || sql2fa.IconURL != nil ||
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
	exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('a', 'http://old/login', 'http://a/consent', 'pwd', '{email}')`)
	exec(t, p, `INSERT INTO flow (id, title, description) VALUES ('legacy', '{"fr": "L"}', '{"fr": "L"}')`)
	exec(t, p, `INSERT INTO flow_step (flow_id, app_id, position) VALUES ('legacy', 'a', 0)`)
	exec(t, p, `INSERT INTO setting (key, value) VALUES ('consent_auto_accept', 'true'), ('remember', 'false'), ('old_key', '1')`)
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

	changes, err := p.Bootstrap(ctx, seed, Missing, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"keep setting consent_auto_accept: value", "keep setting remember: value", "absent setting old_key",
		"keep app a: login_url,receive_claims",
		"create flow f", "absent flow legacy",
		"keep api_client c: secret,scopes", "absent api_client legacy",
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
		"update app a: login_url,receive_claims",
		"same flow f", "absent flow legacy",
		"update api_client c: secret,scopes", "absent api_client legacy",
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
	if f := changes[3].Fields[1]; f.Old != `["email"]` || f.New != `["email","name"]` {
		t.Errorf("receive_claims change = %+v", f)
	}
	if s, _ := p.Snapshot(ctx); !s.Settings.ConsentAutoAccept {
		t.Error("the dry run wrote")
	}

	if _, err := p.Bootstrap(ctx, seed, Force, true); err != nil {
		t.Fatal(err)
	}
	s, _ = p.Snapshot(ctx)
	a, _ := s.App("a")
	if a.LoginURL != "http://a/login" || !slices.Equal(a.ReceiveClaims, []string{"email", "name"}) || s.Settings.ConsentAutoAccept || !s.Settings.Remember || len(s.Flows) != 2 {
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
// Without the key, what the database holds stays: a seed reused from Symfony
// undoes no restriction, with or without force, even when it rewrites the app.
// ~ gives every claim back, and says so; a list or [] restricts an app that had
// none. NULL and {} are never taken for one another.
func TestBootstrapReceiveClaims(t *testing.T) {
	ctx := context.Background()
	const app = "{ id: a, login_url: http://a/login, consent_url: http://a/consent, method: pwd%s }"
	seed := func(extra string) config.Seed {
		return loadSeed(t, "dispatcher:\n  apps:\n    - "+fmt.Sprintf(app, extra)+"\n")
	}
	claims := func(p *Postgres) []string {
		s, err := p.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := s.App("a")
		return a.ReceiveClaims
	}
	for _, tc := range []struct {
		name, base, extra string
		// missing and force are the actions, widens that of a ~ on a list.
		missing, force Action
		after          []string
		old, new       string
		widens         bool
	}{
		{"no key, a list", `'{email}'`, "", Same, Same, []string{"email"}, "", "", false},
		{"no key, an empty list", `'{}'`, "", Same, Same, []string{}, "", "", false},
		{"no key, no list", `NULL`, "", Same, Same, nil, "", "", false},
		{"~, a list", `'{email}'`, ", receive_claims: ~", Keep, Update, nil, `["email"]`, "null", true},
		{"~, an empty list", `'{}'`, ", receive_claims: ~", Keep, Update, nil, "[]", "null", true},
		{"~, no list", `NULL`, ", receive_claims: ~", Same, Same, nil, "", "", false},
		{"a list, no list", `NULL`, ", receive_claims: [email]", Keep, Update, []string{"email"}, "null", `["email"]`, false},
		{"[], no list", `NULL`, ", receive_claims: []", Keep, Update, []string{}, "null", "[]", false},
		{"[], a list", `'{email}'`, ", receive_claims: []", Keep, Update, []string{}, `["email"]`, "[]", false},
		{"empty variable, no list", `NULL`, `, receive_claims: "${NO_CLAIMS}"`, Keep, Update, []string{}, "null", "[]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := migrated(t)
			exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('a', 'http://a/login', 'http://a/consent', 'pwd', `+tc.base+`)`)
			s := seed(tc.extra)
			before := claims(p)
			changes, err := p.Bootstrap(ctx, s, Missing, true)
			if err != nil {
				t.Fatal(err)
			}
			if changes[0].Action != tc.missing {
				t.Errorf("without force: %+v, want %s", changes[0], tc.missing)
			}
			if got := claims(p); !reflect.DeepEqual(got, before) {
				t.Errorf("without force, claims %#v, was %#v", got, before)
			}
			changes, err = p.Bootstrap(ctx, s, Force, true)
			if err != nil {
				t.Fatal(err)
			}
			c := changes[0]
			if c.Action != tc.force {
				t.Errorf("force: %+v, want %s", c, tc.force)
			}
			if tc.force == Update && (len(c.Fields) != 1 || c.Fields[0].Old != tc.old || c.Fields[0].New != tc.new || c.Fields[0].WidensClaims() != tc.widens) {
				t.Errorf("force: fields %+v, want %s -> %s, widens %v", c.Fields, tc.old, tc.new, tc.widens)
			}
			if got := claims(p); !reflect.DeepEqual(got, tc.after) {
				t.Errorf("force: claims %#v, want %#v", got, tc.after)
			}
			if changes, err := p.Bootstrap(ctx, s, Force, true); err != nil || changes[0].Action != Same {
				t.Errorf("second force: %+v, %v", changes, err)
			}
		})
	}
	t.Run("no key, another field rewritten", func(t *testing.T) {
		p := migrated(t)
		exec(t, p, `INSERT INTO app (id, login_url, consent_url, method, receive_claims) VALUES ('a', 'http://old/login', 'http://a/consent', 'pwd', '{email}')`)
		changes, err := p.Bootstrap(ctx, seed(""), Force, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := actions(changes); !slices.Equal(got, []string{"update app a: login_url"}) {
			t.Errorf("changes = %q", got)
		}
		if got := claims(p); !slices.Equal(got, []string{"email"}) {
			t.Errorf("claims = %#v", got)
		}
	})
	t.Run("a new app", func(t *testing.T) {
		for extra, want := range map[string][]string{"": nil, ", receive_claims: ~": nil, ", receive_claims: []": {}, ", receive_claims: [email]": {"email"}} {
			p := migrated(t)
			if _, err := p.Bootstrap(ctx, seed(extra), Force, true); err != nil {
				t.Fatal(err)
			}
			if got := claims(p); !reflect.DeepEqual(got, want) {
				t.Errorf("%q: claims = %#v, want %#v", extra, got, want)
			}
		}
	})
}

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

// A locale is any well-formed one (Q92): a table that names a theme's locale,
// or that a newer version wrote, is left as it is by a bootstrap that does not
// set it, and the seed may name one; not one that is not well formed.
func TestBootstrapLocales(t *testing.T) {
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
	if _, err := p.Bootstrap(ctx, loadSeed(t, "dispatcher:\n  supported_locales: [fr, de]\n  default_locale: de\n"), Force, true); err != nil {
		t.Errorf("Bootstrap of a theme's locale = %v", err)
	}
	_, err := p.Bootstrap(ctx, loadSeed(t, "dispatcher:\n  supported_locales: [fr, pt_BR]\n  default_locale: fr\n"), Force, true)
	if err == nil || !strings.Contains(err.Error(), `setting supported_locales: "pt_BR" is not a locale`) {
		t.Errorf("Bootstrap of a locale not well formed = %v", err)
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

// A dry run waits for the bootstrap in progress, as a write does: it shows
// the database that bootstrap leaves, not the one it found.
func TestBootstrapDryRunWaits(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	seed := loadSeed(t, "dispatcher:\n  app_auto_select: true\n")
	other, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback() }()
	if _, err := other.Exec(`SELECT pg_advisory_xact_lock($1)`, int64(bootstrapLock)); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, err := p.Bootstrap(short, seed, Force, false); err == nil || !strings.Contains(err.Error(), "bootstrap: lock:") {
		t.Fatalf("dry run under the lock of another bootstrap = %v, want it to wait", err)
	}
	if err := other.Rollback(); err != nil {
		t.Fatal(err)
	}
	if changes, err := p.Bootstrap(ctx, seed, Force, false); err != nil || !slices.Equal(actions(changes), []string{"create setting app_auto_select"}) {
		t.Errorf("dry run once the lock is free = %q, %v", actions(changes), err)
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
// force, finds it the same.
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
      receive_claims: [email, "given name"]
    - { id: m, login_url: http://m/login, consent_url: http://m/consent, logout_url: http://m/logout, method: otp, auth_mode: mtls, client_cert_fingerprint: "`+fingerprint+`", receive_claims: [] }
    - { id: n, login_url: http://n/login, consent_url: http://n/consent, method: pwd }
  flows:
    - id: f
      title: F
      description: { fr: D, en: "" }
      icon_url: http://i/f.svg
      acr: gold
      enabled: false
      steps: [{ id: a, order: 0, subject_check: equal }, { id: m, order: 1, subject_check: "claim:email" }]
    - { id: g, title: { fr: G, en: G }, description: D, icon_url: { fr: http://i/fr.svg, en: http://i/en.svg }, steps: [{ id: a, order: 0 }] }
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
		!slices.Equal(a.ReceiveClaims, []string{"email", "given name"}) {
		t.Errorf("app a: sources %q, claims %q", sources, a.ReceiveClaims)
	}
	if m, _ := s.App("m"); m.AuthMode != "mtls" || m.ClientCertFingerprint != strings.ToLower(strings.ReplaceAll(fingerprint, ":", "")) ||
		m.AllowedSources != nil || m.LogoutURL != "http://m/logout" || m.ReceiveClaims == nil || len(m.ReceiveClaims) != 0 {
		t.Errorf("app m = %+v", m)
	}
	if n, _ := s.App("n"); n.ReceiveClaims != nil {
		t.Errorf("app n: claims %#v, want nil", n.ReceiveClaims)
	}
	want := []Flow{{
		ID: "f", Title: map[string]string{"": "F"}, Description: map[string]string{"fr": "D"}, IconURL: map[string]string{"": "http://i/f.svg"},
		ACR: "gold", Steps: []Step{{AppID: "a", Position: 0, SubjectCheck: "equal"}, {AppID: "m", Position: 1, SubjectCheck: "claim:email"}},
	}, {
		ID: "g", Title: map[string]string{"fr": "G", "en": "G"}, Description: map[string]string{"": "D"},
		IconURL: map[string]string{"fr": "http://i/fr.svg", "en": "http://i/en.svg"}, Enabled: true, Steps: []Step{{AppID: "a", Position: 0, SubjectCheck: "none"}},
	}}
	if !reflect.DeepEqual(s.Flows, want) {
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
	// Without force, all of it is left as it is.
	changes, err := p.Bootstrap(ctx, second, Missing, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"keep setting remember: value", "same app a", "same app b", "same app c",
		"keep flow f: steps", "keep api_client client: scopes",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("missing: changes = %q\nwant %q", got, want)
	}
	if s, _ := p.Snapshot(ctx); len(s.Flows[0].Steps) != 3 || s.Settings.Remember {
		t.Errorf("missing wrote: steps = %+v, remember = %v", s.Flows[0].Steps, s.Settings.Remember)
	}

	changes, err = p.Bootstrap(ctx, second, Force, true)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"reset setting remember: value", "same app a", "same app b", "same app c",
		"update flow f: steps", "update api_client client: scopes",
	}
	if got := actions(changes); !slices.Equal(got, want) {
		t.Errorf("changes = %q\nwant %q", got, want)
	}
	s, _ := p.Snapshot(ctx)
	if !reflect.DeepEqual(s.Flows[0].Steps, []Step{{AppID: "b", Position: 0, SubjectCheck: "none"}, {AppID: "a", Position: 1, SubjectCheck: "none"}}) || !s.Settings.Remember {
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
	if hash, _ := clientHash(t, p, "c"); bcrypt.CompareHashAndPassword([]byte(hash), domain.BcryptInput(symfonySecret)) != nil {
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
