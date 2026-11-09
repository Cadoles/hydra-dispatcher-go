package store

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// Mode is what bootstrap does with what the database already holds.
type Mode int

const (
	// Missing creates what the database lacks and leaves the rest alone.
	Missing Mode = iota
	// Force also rewrites what the database holds of the seed, and resets
	// the settings and the receive_claims the seed sets to ~. Neither deletes
	// anything.
	Force
)

// Action is what bootstrap does with an entry.
type Action string

const (
	Create Action = "create"
	Update Action = "update"
	// Reset deletes a setting's row: it takes its default again.
	Reset Action = "reset"
	// Same is an entry of the seed the database already holds as is.
	Same Action = "same"
	// Keep is an entry of the seed the database holds otherwise, left alone
	// without Force.
	Keep Action = "keep"
	// Absent is an entry of the database the seed lacks: bootstrap never
	// deletes.
	Absent Action = "absent"
)

// Change is an entry and what bootstrap does with it.
type Change struct {
	Kind   string // setting, app, flow or api_client
	ID     string
	Action Action
	// Fields are those an Update, a Reset or a Keep changes, or would change.
	Fields []FieldChange
}

// FieldChange is a field of an entry, before and after, in JSON. Secret is
// set instead for a client secret, never written.
type FieldChange struct {
	Name     string
	Old, New string
	Secret   bool
}

// WidensClaims tells that the change gives every claim to an app that had a
// list, an empty one too.
func (f FieldChange) WidensClaims() bool {
	return f.Name == "receive_claims" && f.New == "null"
}

// bootstrapLock is the advisory lock that serializes bootstraps: replicas
// starting in serve.bootstrap force would otherwise insert the same rows.
const bootstrapLock = 0x6469737061746368 // "dispatch"

// bootstrapBy fills setting.updated_by.
const bootstrapBy = "bootstrap"

// Bootstrap writes seed to the database in mode, in one transaction, and
// returns every change, entries left alone included: settings, apps, flows,
// then API clients, as Symfony wrote them. With write false, nothing is
// written: the changes are those Bootstrap would make. Load has validated
// the seed; the settings it gives are validated as a whole before anything
// is written.
func (p *Postgres) Bootstrap(ctx context.Context, seed config.Seed, mode Mode, write bool) ([]Change, error) {
	// Read committed, whatever the default of the database: each statement
	// then sees what the replica that held the lock committed. In repeatable
	// read, the snapshot would date from the lock statement, before the wait,
	// and the insert of a row that replica wrote would fail.
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // after Commit, a no-op
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(bootstrapLock)); err != nil {
		return nil, fmt.Errorf("bootstrap: lock: %w", err)
	}
	b := &bootstrap{ctx: ctx, tx: tx, mode: mode, write: write}
	for _, step := range []func(config.Seed) error{b.settings, b.apps, b.flows, b.clients} {
		if err := step(seed); err != nil {
			return nil, fmt.Errorf("bootstrap: %w", err)
		}
	}
	if !write {
		return b.changes, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	return b.changes, nil
}

type bootstrap struct {
	ctx     context.Context
	tx      *sql.Tx
	mode    Mode
	write   bool
	changes []Change
}

// decide records the change of an entry the database may hold (old) and the
// seed sets (new), each field by its JSON, and tells whether to write it.
func (b *bootstrap) decide(kind, id string, exists bool, fields []field) bool {
	c := Change{Kind: kind, ID: id, Action: Create}
	if exists {
		for _, f := range fields {
			if fc, changed := f.change(); changed {
				c.Fields = append(c.Fields, fc)
			}
		}
		switch {
		case len(c.Fields) == 0:
			c.Action = Same
		case b.mode == Force:
			c.Action = Update
		default:
			c.Action = Keep
		}
	}
	b.changes = append(b.changes, c)
	return b.write && (c.Action == Create || c.Action == Update)
}

// absent records the entries of the database the seed lacks.
func (b *bootstrap) absent(kind string, ids []string, inSeed func(string) bool) {
	for _, id := range ids {
		if !inSeed(id) {
			b.changes = append(b.changes, Change{Kind: kind, ID: id, Action: Absent})
		}
	}
}

// field is one field of an entry: its value in the database and in the seed.
type field struct {
	name     string
	old, new any
	// secret compares a client secret with its hash.
	secret func() bool
}

func (f field) change() (FieldChange, bool) {
	if f.secret != nil {
		return FieldChange{Name: f.name, Secret: true}, !f.secret()
	}
	o, _ := json.Marshal(f.old)
	n, _ := json.Marshal(f.new)
	return FieldChange{Name: f.name, Old: string(o), New: string(n)}, !bytes.Equal(o, n)
}

func (b *bootstrap) settings(seed config.Seed) error {
	rows, err := readSettings(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	current, _, err := decodeSettings(rows)
	if err != nil {
		return err
	}
	values := seedSettings(seed.SeedSettings)
	next := current
	// changed are the keys whose value the seed sets, or resets.
	var write, reset, changed []setting
	for _, st := range registry {
		_, inDB := rows[st.key]
		switch v, set := values[st.key]; {
		case set:
			reflect.ValueOf(st.field(&next)).Elem().Set(reflect.ValueOf(v))
			before, after := st.encode(&current), st.encode(&next)
			if b.decide("setting", st.key, inDB, []field{{name: "value", old: json.RawMessage(before), new: json.RawMessage(after)}}) {
				write = append(write, st)
			}
			if inDB && b.mode != Force {
				// Left as it is.
				reflect.ValueOf(st.field(&next)).Elem().Set(reflect.ValueOf(st.field(&current)).Elem())
			} else {
				changed = append(changed, st)
			}
		case slices.Contains(seed.NullSettings, st.key):
			c := Change{Kind: "setting", ID: st.key, Action: Same}
			if inDB {
				// The value the row holds, and the default it gives way to.
				defaults := DefaultSettings()
				fc, _ := field{name: "value", old: json.RawMessage(st.encode(&current)), new: json.RawMessage(st.encode(&defaults))}.change()
				c.Action, c.Fields = Keep, []FieldChange{fc}
				if b.mode == Force {
					c.Action = Reset
					reflect.ValueOf(st.field(&next)).Elem().Set(reflect.ValueOf(st.field(&defaults)).Elem())
					reset = append(reset, st)
					changed = append(changed, st)
				}
			}
			b.changes = append(b.changes, c)
		}
	}
	b.absent("setting", slices.Sorted(maps.Keys(rows)), func(key string) bool {
		_, set := values[key]
		return set || slices.Contains(seed.NullSettings, key)
	})
	// What the seed sets, over what the table keeps.
	check := current
	for _, st := range changed {
		reflect.ValueOf(st.field(&check)).Elem().Set(reflect.ValueOf(st.field(&next)).Elem())
	}
	if err := check.Validate(); err != nil {
		return err
	}
	if !b.write {
		return nil
	}
	for _, st := range write {
		if _, err := b.tx.ExecContext(b.ctx, `
			INSERT INTO setting (key, value, updated_at, updated_by) VALUES ($1, $2::jsonb, now(), $3)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			st.key, string(st.encode(&next)), bootstrapBy); err != nil {
			return fmt.Errorf("setting %s: %w", st.key, err)
		}
	}
	for _, st := range reset {
		if _, err := b.tx.ExecContext(b.ctx, `DELETE FROM setting WHERE key = $1`, st.key); err != nil {
			return fmt.Errorf("setting %s: %w", st.key, err)
		}
	}
	return nil
}

// seedSettings gives the settings the seed sets, as the values of their
// fields in Settings.
func seedSettings(s config.SeedSettings) map[string]any {
	values := map[string]any{}
	put := func(key string, set bool, v func() any) {
		if set {
			values[key] = v()
		}
	}
	put("app_auto_select", s.AppAutoSelect != nil, func() any { return *s.AppAutoSelect })
	put("consent_auto_accept", s.ConsentAutoAccept != nil, func() any { return *s.ConsentAutoAccept })
	put("aggregate_amr_from_login_request", s.AggregateAMRFromLoginRequest != nil, func() any { return *s.AggregateAMRFromLoginRequest })
	put("challenge_ttl", s.ChallengeTTL != nil, func() any { return s.ChallengeTTL.Std() })
	put("remember", s.Remember != nil, func() any { return *s.Remember })
	put("login_remember_for", s.LoginRememberFor != nil, func() any { return s.LoginRememberFor.Std() })
	put("consent_remember_for", s.ConsentRememberFor != nil, func() any { return s.ConsentRememberFor.Std() })
	put("login_accept_webhook_url", s.LoginAcceptWebhookURL != nil, func() any { return *s.LoginAcceptWebhookURL })
	put("consent_accept_webhook_url", s.ConsentAcceptWebhookURL != nil, func() any { return *s.ConsentAcceptWebhookURL })
	put("supported_locales", s.SupportedLocales != nil, func() any { return []string(*s.SupportedLocales) })
	put("default_locale", s.DefaultLocale != nil, func() any { return *s.DefaultLocale })
	put("fallback_locale", s.FallbackLocale != nil, func() any { return *s.FallbackLocale })
	return values
}

func (b *bootstrap) apps(seed config.Seed) error {
	current, err := readApps(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read apps: %w", err)
	}
	for _, sa := range seed.Apps {
		a, err := appFromSeed(sa)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(current, func(c App) bool { return c.ID == a.ID })
		var old App
		if i >= 0 {
			old = current[i]
		}
		// Without the key, what the database holds stays: only ~ takes a list
		// back, so that a seed reused from Symfony undoes no restriction.
		if sa.ReceiveClaims == nil && !sa.NullReceiveClaims {
			a.ReceiveClaims = old.ReceiveClaims
		}
		if !b.decide("app", a.ID, i >= 0, []field{
			{name: "login_url", old: old.LoginURL, new: a.LoginURL},
			{name: "consent_url", old: old.ConsentURL, new: a.ConsentURL},
			{name: "logout_url", old: old.LogoutURL, new: a.LogoutURL},
			{name: "method", old: old.Method, new: a.Method},
			{name: "auth_mode", old: old.AuthMode, new: a.AuthMode},
			{name: "allowed_sources", old: old.AllowedSources, new: a.AllowedSources},
			{name: "client_cert_fingerprint", old: old.ClientCertFingerprint, new: a.ClientCertFingerprint},
			{name: "receive_claims", old: old.ReceiveClaims, new: a.ReceiveClaims},
		}) {
			continue
		}
		sources := make([]string, len(a.AllowedSources)) // NOT NULL: never nil
		for i, s := range a.AllowedSources {
			sources[i] = s.String()
		}
		if _, err := b.tx.ExecContext(b.ctx, `
			INSERT INTO app (id, login_url, consent_url, logout_url, method, auth_mode, allowed_sources, client_cert_fingerprint, receive_claims)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7::text[]::cidr[], NULLIF($8, ''), $9::text[])
			ON CONFLICT (id) DO UPDATE SET login_url = EXCLUDED.login_url, consent_url = EXCLUDED.consent_url,
				logout_url = EXCLUDED.logout_url, method = EXCLUDED.method, auth_mode = EXCLUDED.auth_mode,
				allowed_sources = EXCLUDED.allowed_sources, client_cert_fingerprint = EXCLUDED.client_cert_fingerprint,
				receive_claims = EXCLUDED.receive_claims`,
			a.ID, a.LoginURL, a.ConsentURL, a.LogoutURL, a.Method, a.AuthMode, sources, a.ClientCertFingerprint, a.ReceiveClaims); err != nil {
			return fmt.Errorf("app %s: %w", a.ID, err)
		}
	}
	ids := make([]string, len(current))
	for i, a := range current {
		ids[i] = a.ID
	}
	b.absent("app", ids, func(id string) bool {
		return slices.ContainsFunc(seed.Apps, func(a config.SeedApp) bool { return a.ID == id })
	})
	return nil
}

// appFromSeed gives a seed app the form readApps reads.
func appFromSeed(a config.SeedApp) (App, error) {
	sources, err := a.AllowedSources.Prefixes()
	if err != nil {
		return App{}, fmt.Errorf("app %s: %w", a.ID, err)
	}
	if len(sources) == 0 {
		sources = nil
	}
	var claims []string // nil: every claim, and NULL in the database
	if a.ReceiveClaims != nil {
		claims = *a.ReceiveClaims
	}
	return App{
		ID: a.ID, LoginURL: a.LoginURL, ConsentURL: a.ConsentURL, LogoutURL: a.LogoutURL, Method: a.Method,
		AuthMode: a.AuthMode, AllowedSources: sources, ClientCertFingerprint: a.ClientCertFingerprint, ReceiveClaims: claims,
	}, nil
}

func (b *bootstrap) flows(seed config.Seed) error {
	current, err := readFlows(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read flows: %w", err)
	}
	for _, sf := range seed.Flows {
		f := flowFromSeed(sf)
		i := slices.IndexFunc(current, func(c Flow) bool { return c.ID == f.ID })
		var old Flow
		if i >= 0 {
			old = current[i]
		}
		if !b.decide("flow", f.ID, i >= 0, []field{
			{name: "title", old: old.Title, new: f.Title},
			{name: "description", old: old.Description, new: f.Description},
			{name: "icon_url", old: old.IconURL, new: f.IconURL},
			{name: "enabled", old: old.Enabled, new: f.Enabled},
			{name: "acr", old: old.ACR, new: f.ACR},
			{name: "steps", old: old.Steps, new: f.Steps},
		}) {
			continue
		}
		title, _ := json.Marshal(f.Title)
		description, _ := json.Marshal(f.Description)
		var icon *string
		if f.IconURL != nil {
			raw, _ := json.Marshal(f.IconURL)
			s := string(raw)
			icon = &s
		}
		if _, err := b.tx.ExecContext(b.ctx, `
			INSERT INTO flow (id, title, description, icon_url, enabled, acr) VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5, NULLIF($6, ''))
			ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description,
				icon_url = EXCLUDED.icon_url, enabled = EXCLUDED.enabled, acr = EXCLUDED.acr`,
			f.ID, string(title), string(description), icon, f.Enabled, f.ACR); err != nil {
			return fmt.Errorf("flow %s: %w", f.ID, err)
		}
		if _, err := b.tx.ExecContext(b.ctx, `DELETE FROM flow_step WHERE flow_id = $1`, f.ID); err != nil {
			return fmt.Errorf("flow %s: %w", f.ID, err)
		}
		for _, s := range f.Steps {
			if _, err := b.tx.ExecContext(b.ctx, `INSERT INTO flow_step (flow_id, app_id, position, subject_check) VALUES ($1, $2, $3, $4)`,
				f.ID, s.AppID, s.Position, s.SubjectCheck); err != nil {
				return fmt.Errorf("flow %s: step %s: %w", f.ID, s.AppID, err)
			}
		}
	}
	ids := make([]string, len(current))
	for i, f := range current {
		ids[i] = f.ID
	}
	b.absent("flow", ids, func(id string) bool {
		return slices.ContainsFunc(seed.Flows, func(f config.SeedFlow) bool { return f.ID == id })
	})
	return nil
}

// flowFromSeed gives a seed flow the form readFlows reads.
func flowFromSeed(sf config.SeedFlow) Flow {
	f := Flow{
		ID: sf.ID, Title: sf.Title, Description: sf.Description, Enabled: *sf.Enabled, ACR: sf.ACR,
	}
	if len(sf.IconURL) > 0 {
		f.IconURL = sf.IconURL
	}
	for _, s := range sf.Steps {
		f.Steps = append(f.Steps, Step{AppID: s.AppID, Position: s.Position, SubjectCheck: cmp.Or(s.SubjectCheck, "none")})
	}
	slices.SortFunc(f.Steps, func(a, b Step) int { return cmp.Compare(a.Position, b.Position) })
	return f
}

// apiClient is a client of the admin API, as the table holds it.
type apiClient struct {
	id, secretHash string
	scopes         []string
}

func (b *bootstrap) clients(seed config.Seed) error {
	current, err := readAPIClients(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read API clients: %w", err)
	}
	for _, sc := range seed.OAuth2Clients {
		scopes := []string(*sc.Scopes)
		if scopes == nil {
			scopes = []string{}
		}
		i := slices.IndexFunc(current, func(c apiClient) bool { return c.id == sc.ID })
		var old apiClient
		if i >= 0 {
			old = current[i]
		}
		// Once: bcrypt is slow on purpose.
		sameSecret := i >= 0 && bcrypt.CompareHashAndPassword([]byte(old.secretHash), bcryptInput(sc.Secret)) == nil
		if !b.decide("api_client", sc.ID, i >= 0, []field{
			{name: "secret", secret: func() bool { return sameSecret }},
			{name: "scopes", old: old.scopes, new: scopes},
		}) {
			continue
		}
		// An unchanged secret keeps its hash: a new salt would show as a change.
		hash := old.secretHash
		if !sameSecret {
			h, err := bcrypt.GenerateFromPassword(bcryptInput(sc.Secret), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("API client %s: %w", sc.ID, err)
			}
			hash = string(h)
		}
		if _, err := b.tx.ExecContext(b.ctx, `
			INSERT INTO api_client (id, secret_hash, scopes) VALUES ($1, $2, $3::text[])
			ON CONFLICT (id) DO UPDATE SET secret_hash = EXCLUDED.secret_hash, scopes = EXCLUDED.scopes`,
			sc.ID, hash, scopes); err != nil {
			return fmt.Errorf("API client %s: %w", sc.ID, err)
		}
	}
	ids := make([]string, len(current))
	for i, c := range current {
		ids[i] = c.id
	}
	b.absent("api_client", ids, func(id string) bool {
		return slices.ContainsFunc(seed.OAuth2Clients, func(c config.SeedClient) bool { return c.ID == id })
	})
	return nil
}

// bcryptInput is what bcrypt hashes of a client secret, the secret itself up
// to the 72 bytes bcrypt reads. A longer one, or one holding a NUL, is hashed
// first, as Symfony's NativePasswordHasher does: SHA-512 in base64, of which
// bcrypt reads 72 bytes too. Whatever checks a secret against its hash goes
// through it.
func bcryptInput(secret string) []byte {
	if len(secret) <= 72 && !strings.ContainsRune(secret, 0) {
		return []byte(secret)
	}
	sum := sha512.Sum512([]byte(secret))
	return []byte(base64.StdEncoding.EncodeToString(sum[:])[:72])
}

func readAPIClients(ctx context.Context, q querier) ([]apiClient, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, secret_hash, scopes FROM api_client ORDER BY id COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := pgtype.NewMap()
	var clients []apiClient
	for rows.Next() {
		var c apiClient
		if err := rows.Scan(&c.id, &c.secretHash, m.SQLScanner(&c.scopes)); err != nil {
			return nil, err
		}
		if c.scopes == nil {
			c.scopes = []string{}
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}
