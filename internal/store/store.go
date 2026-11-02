// Package store is the configuration store: apps, flows, settings and API
// clients, in Postgres. The handlers read an in-memory snapshot of it (Live),
// never the database itself; bootstrap seeds it from the YAML file.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

// versionTable is where goose notes the migrations applied, and migrateLock
// the session lock of the replicas that migrate: the dispatcher's own, not
// goose's defaults, which another application of the database may use.
const (
	versionTable = "dispatcher_schema_version"
	migrateLock  = 0x646973706d696772 // "dispmigr"
)

// Postgres is the database of the configuration.
type Postgres struct {
	db *sql.DB
}

// Open connects to the database at dsn, a postgres:// URL or a pgx
// connection string, and checks that it answers.
func Open(ctx context.Context, dsn string) (*Postgres, error) {
	// Parsed here, not at the first connection: the error names the key.
	// pgx masks the password in it.
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store.dsn: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	// The configuration is read every 60 s and written by bootstrap and the
	// admin: a few connections are plenty.
	db.SetMaxOpenConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	p := &Postgres{db: db}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := p.Ping(pingCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

// Ping checks that the database answers, for /ready.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	return nil
}

func (p *Postgres) Close() error { return p.db.Close() }

// Migrate applies the migrations the database lacks and returns their names.
// A session lock lets several replicas migrate at startup: one applies, the
// others wait for it.
func (p *Postgres) Migrate(ctx context.Context) ([]string, error) {
	provider, err := p.migrator()
	if err != nil {
		return nil, err
	}
	results, err := provider.Up(ctx)
	var applied []string
	for _, r := range results {
		applied = append(applied, r.Source.Path)
	}
	if err != nil {
		return applied, fmt.Errorf("migrate: %w", err)
	}
	return applied, nil
}

// migrator gives the embedded migrations, their version table and their
// session lock.
func (p *Postgres) migrator() (*goose.Provider, error) {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(migrateLock))
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, p.db, fsys, goose.WithTableName(versionTable),
		goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true))
}

// App is a login app.
type App struct {
	ID         string
	LoginURL   string
	ConsentURL string
	// LogoutURL "" leaves the app out of the logout.
	LogoutURL string
	Method    string
	// AuthMode is network (AllowedSources) or mtls (ClientCertFingerprint):
	// how the emulated API knows the app.
	AuthMode              string
	AllowedSources        []netip.Prefix
	ClientCertFingerprint string
	// Options are free JSON, numbers as json.Number: a float64 would round
	// an id of 20 digits.
	Options map[string]any
}

// Flow is a sequence of apps the user may choose.
type Flow struct {
	ID          string
	Title       map[string]string
	Description map[string]string
	// IconURL is nil for no icon.
	IconURL map[string]string
	Enabled bool
	// ACR "" sends none.
	ACR   string
	Steps []Step // by position
}

type Step struct {
	AppID        string `json:"app_id"`
	Position     int    `json:"position"`
	SubjectCheck string `json:"subject_check"` // none, equal or claim:<name>
}

// Snapshot is the configuration at one moment, read in one transaction.
// Nothing changes it: Live replaces it whole.
type Snapshot struct {
	// Apps and Flows are by id in byte order, whatever the collation of the
	// database: the choice page lists the flows the same on every server.
	Apps     []App
	Flows    []Flow
	Settings Settings
	// Warnings are what this version sets aside of the setting table:
	// unknown keys, locales without a catalog. serve adds those of the apps'
	// identification on the emulated API (emulated.Warnings).
	Warnings []string
	apps     map[string]int
}

// NewSnapshot returns the snapshot of apps, flows and settings read
// elsewhere, sorted by id in byte order (tests, other sources).
func NewSnapshot(apps []App, flows []Flow, settings Settings) *Snapshot {
	s := &Snapshot{
		Apps:     slices.SortedFunc(slices.Values(apps), func(a, b App) int { return strings.Compare(a.ID, b.ID) }),
		Flows:    slices.SortedFunc(slices.Values(flows), func(a, b Flow) int { return strings.Compare(a.ID, b.ID) }),
		Settings: settings,
	}
	s.index()
	return s
}

func (s *Snapshot) index() {
	s.apps = make(map[string]int, len(s.Apps))
	for i, a := range s.Apps {
		s.apps[a.ID] = i
	}
}

// App returns the app id.
func (s *Snapshot) App(id string) (App, bool) {
	i, ok := s.apps[id]
	if !ok {
		return App{}, false
	}
	return s.Apps[i], true
}

// querier is a database or a transaction.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Snapshot reads the whole configuration, in a read-only transaction that
// sees one state of the tables.
func (p *Postgres) Snapshot(ctx context.Context) (*Snapshot, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only: nothing to commit
	s := &Snapshot{}
	if s.Apps, err = readApps(ctx, tx); err != nil {
		return nil, fmt.Errorf("read apps: %w", err)
	}
	s.index()
	if s.Flows, err = readFlows(ctx, tx); err != nil {
		return nil, fmt.Errorf("read flows: %w", err)
	}
	rows, err := readSettings(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if s.Settings, s.Warnings, err = settingsFrom(rows); err != nil {
		return nil, err
	}
	return s, nil
}

func readApps(ctx context.Context, q querier) ([]App, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id, login_url, consent_url, coalesce(logout_url, ''), method, auth_mode,
		       allowed_sources::text[], coalesce(client_cert_fingerprint, ''), options
		FROM app ORDER BY id COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := pgtype.NewMap() // its types scan the text[] of the sources
	var apps []App
	for rows.Next() {
		var a App
		var sources []string
		var options []byte
		if err := rows.Scan(&a.ID, &a.LoginURL, &a.ConsentURL, &a.LogoutURL, &a.Method, &a.AuthMode,
			m.SQLScanner(&sources), &a.ClientCertFingerprint, &options); err != nil {
			return nil, err
		}
		for _, src := range sources {
			prefix, err := netip.ParsePrefix(src)
			if err != nil {
				return nil, fmt.Errorf("app %s: allowed source %q: %w", a.ID, src, err)
			}
			a.AllowedSources = append(a.AllowedSources, prefix)
		}
		if err := unmarshalNumbers(options, &a.Options); err != nil {
			return nil, fmt.Errorf("app %s: options: %w", a.ID, err)
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

// unmarshalNumbers is json.Unmarshal with numbers as json.Number, exact.
func unmarshalNumbers(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

func readFlows(ctx context.Context, q querier) ([]Flow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, title, description, icon_url, enabled, coalesce(acr, '') FROM flow ORDER BY id COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var flows []Flow
	for rows.Next() {
		var f Flow
		var title, description, icon []byte
		if err := rows.Scan(&f.ID, &title, &description, &icon, &f.Enabled, &f.ACR); err != nil {
			return nil, err
		}
		for _, l := range []struct {
			name string
			raw  []byte
			into *map[string]string
		}{{"title", title, &f.Title}, {"description", description, &f.Description}, {"icon_url", icon, &f.IconURL}} {
			if l.raw == nil {
				continue // icon_url NULL
			}
			if err := json.Unmarshal(l.raw, l.into); err != nil {
				return nil, fmt.Errorf("flow %s: %s: %w", f.ID, l.name, err)
			}
			// A null or empty text is none, as internal/config drops it from
			// the seed: the page falls back to another locale.
			maps.DeleteFunc(*l.into, func(_, text string) bool { return text == "" })
		}
		if len(f.IconURL) == 0 {
			f.IconURL = nil
		}
		flows = append(flows, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()

	byID := make(map[string]int, len(flows))
	for i, f := range flows {
		byID[f.ID] = i
	}
	steps, err := q.QueryContext(ctx, `SELECT flow_id, app_id, position, subject_check FROM flow_step ORDER BY position`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = steps.Close() }()
	for steps.Next() {
		var flowID string
		var s Step
		if err := steps.Scan(&flowID, &s.AppID, &s.Position, &s.SubjectCheck); err != nil {
			return nil, err
		}
		i, ok := byID[flowID]
		if !ok {
			return nil, fmt.Errorf("step of an unknown flow %q", flowID) // the foreign key forbids it
		}
		flows[i].Steps = append(flows[i].Steps, s)
	}
	return flows, steps.Err()
}

func readSettings(ctx context.Context, q querier) (map[string][]byte, error) {
	rows, err := q.QueryContext(ctx, `SELECT key, value FROM setting`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	settings := map[string][]byte{}
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}
	return settings, rows.Err()
}
