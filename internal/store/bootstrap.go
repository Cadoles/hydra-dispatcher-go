package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/jackc/pgx/v5/pgtype"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/secretbox"
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
	// By is the author of the row an Update or a Reset replaces, when it is
	// not bootstrap: an admin's write the seed undoes.
	By string
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

// bootstrapBy fills updated_by.
const bootstrapBy = "bootstrap"

// Bootstrap writes seed to the database in mode, in one transaction, and
// returns every change, entries left alone included: settings, apps, flows,
// then API clients, as Symfony wrote them. Load has validated the seed; the
// settings it gives are validated as a whole before anything is written, and
// the configuration it leaves as serve reads it, as any write's: a seed
// serve would refuse is not written (*RefusedError). With write false,
// nothing is written: the changes are those Bootstrap would make, written
// then rolled back, for a dry run to give the refusals of a write.
func (p *Postgres) Bootstrap(ctx context.Context, seed config.Seed, mode Mode, write bool) ([]Change, error) {
	var b *bootstrap
	err := p.transact(ctx, "bootstrap", write, func(tx *sql.Tx) error {
		b = &bootstrap{ctx: ctx, tx: tx, mode: mode, keys: p.secrets}
		for _, step := range []func(config.Seed) error{b.settings, b.apps, b.flows, b.clients} {
			if err := step(seed); err != nil {
				return fmt.Errorf("bootstrap: %w", err)
			}
		}
		return nil
	})
	var refused *RefusedError
	if errors.As(err, &refused) {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	if err != nil {
		return nil, err
	}
	return b.changes, nil
}

type bootstrap struct {
	ctx  context.Context
	tx   *sql.Tx
	mode Mode
	// keys open and seal the encrypted settings.
	keys *secretbox.Keys
	// compare reads and writes nothing: Diff.
	compare bool
	changes []Change
}

// Diff gives the changes Bootstrap would make in Force mode, reading only, for
// config diff: a READ ONLY transaction in repeatable read, one view of the
// tables, without writeLock or the check of the instance, so that a role that
// can only read runs it. The refusals of a write (a configuration serve would
// refuse, the constraints of the schema) are those of Bootstrap without write,
// which writes then rolls back.
func (p *Postgres) Diff(ctx context.Context, seed config.Seed) ([]Change, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("diff: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	b := &bootstrap{ctx: ctx, tx: tx, mode: Force, compare: true, keys: p.secrets}
	for _, step := range []func(config.Seed) error{b.settings, b.apps, b.flows, b.clients} {
		if err := step(seed); err != nil {
			return nil, fmt.Errorf("diff: %w", err)
		}
	}
	return b.changes, nil
}

// decide records the change of an entry the database may hold (old), written
// by the author by, and the seed sets (new), each field by its JSON, and
// tells whether to write it.
func (b *bootstrap) decide(kind, id string, exists bool, by string, fields []field) bool {
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
			c.By = overwritten(by)
		default:
			c.Action = Keep
		}
	}
	b.changes = append(b.changes, c)
	return c.Action == Create || c.Action == Update
}

// overwritten is the author of a row bootstrap replaces, "" when it is
// bootstrap: a row without one was written by a version before 00004, whose
// only writer was bootstrap.
func overwritten(by string) string {
	if by == bootstrapBy {
		return ""
	}
	return by
}

// readAuthors reads updated_by of the rows of table by their key column,
// bootstrap for NULL: a row without an author was written before 00004.
func readAuthors(ctx context.Context, q querier, table, key string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+key+`, coalesce(updated_by, $1) FROM `+table, bootstrapBy)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	authors := map[string]string{}
	for rows.Next() {
		var id, by string
		if err := rows.Scan(&id, &by); err != nil {
			return nil, err
		}
		authors[id] = by
	}
	return authors, rows.Err()
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

// settingField is the change of the value of a setting, a secret's without
// its values: whether it changes alone.
func settingField(st setting, before, after []byte) field {
	if st.secret {
		return field{name: "value", secret: func() bool { return bytes.Equal(before, after) }}
	}
	return field{name: "value", old: json.RawMessage(before), new: json.RawMessage(after)}
}

func (b *bootstrap) settings(seed config.Seed) error {
	rows, err := readSettings(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	current, _, err := decodeSettings(rows, b.keys)
	if err != nil {
		return err
	}
	authors, err := readAuthors(b.ctx, b.tx, "setting", "key")
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
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
			if b.decide("setting", st.key, inDB, authors[st.key], []field{settingField(st, before, after)}) {
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
				fc, _ := settingField(st, st.encode(&current), st.encode(&defaults)).change()
				c.Action, c.Fields = Keep, []FieldChange{fc}
				if b.mode == Force {
					c.Action, c.By = Reset, overwritten(authors[st.key])
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
	if b.compare {
		return nil
	}
	for _, st := range write {
		if err := putSetting(b.ctx, b.tx, st, &next, bootstrapBy, b.keys); err != nil {
			return err
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
	put("admin_oidc.enabled", s.AdminOIDCEnabled != nil, func() any { return *s.AdminOIDCEnabled })
	put("admin_oidc.issuer", s.AdminOIDCIssuer != nil, func() any { return *s.AdminOIDCIssuer })
	put("admin_oidc.client_id", s.AdminOIDCClientID != nil, func() any { return *s.AdminOIDCClientID })
	put("admin_oidc.client_secret", s.AdminOIDCClientSecret != nil, func() any { return *s.AdminOIDCClientSecret })
	put("admin_oidc.scopes", s.AdminOIDCScopes != nil, func() any { return []string(*s.AdminOIDCScopes) })
	put("admin_oidc.username_claim", s.AdminOIDCUsernameClaim != nil, func() any { return *s.AdminOIDCUsernameClaim })
	put("admin_oidc.required_acr", s.AdminOIDCRequiredACR != nil, func() any { return []string(*s.AdminOIDCRequiredACR) })
	put("admin_oidc.auto_create", s.AdminOIDCAutoCreate != nil, func() any { return *s.AdminOIDCAutoCreate })
	put("admin_oidc.authorization_endpoint", s.AdminOIDCAuthorizationEndpoint != nil, func() any { return *s.AdminOIDCAuthorizationEndpoint })
	put("admin_oidc.token_endpoint", s.AdminOIDCTokenEndpoint != nil, func() any { return *s.AdminOIDCTokenEndpoint })
	put("admin_oidc.jwks_uri", s.AdminOIDCJWKSURI != nil, func() any { return *s.AdminOIDCJWKSURI })
	return values
}

func (b *bootstrap) apps(seed config.Seed) error {
	current, err := readApps(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read apps: %w", err)
	}
	authors, err := readAuthors(b.ctx, b.tx, "app", "id")
	if err != nil {
		return fmt.Errorf("read apps: %w", err)
	}
	for _, sa := range seed.Apps {
		a, err := sa.App()
		if err != nil {
			return fmt.Errorf("app %s: %w", sa.ID, err)
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
		if !b.decide("app", a.ID, i >= 0, authors[a.ID], []field{
			{name: "login_url", old: old.LoginURL, new: a.LoginURL},
			{name: "consent_url", old: old.ConsentURL, new: a.ConsentURL},
			{name: "logout_url", old: old.LogoutURL, new: a.LogoutURL},
			{name: "method", old: old.Method, new: a.Method},
			{name: "auth_mode", old: old.AuthMode, new: a.AuthMode},
			{name: "allowed_sources", old: old.AllowedSources, new: a.AllowedSources},
			{name: "client_cert_fingerprint", old: old.ClientCertFingerprint, new: a.ClientCertFingerprint},
			{name: "receive_claims", old: old.ReceiveClaims, new: a.ReceiveClaims},
		}) || b.compare {
			continue
		}
		if err := putApp(b.ctx, b.tx, a, bootstrapBy); err != nil {
			return err
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

func (b *bootstrap) flows(seed config.Seed) error {
	current, err := readFlows(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read flows: %w", err)
	}
	authors, err := readAuthors(b.ctx, b.tx, "flow", "id")
	if err != nil {
		return fmt.Errorf("read flows: %w", err)
	}
	for _, sf := range seed.Flows {
		f := sf.Flow()
		i := slices.IndexFunc(current, func(c Flow) bool { return c.ID == f.ID })
		var old Flow
		if i >= 0 {
			old = current[i]
		}
		if !b.decide("flow", f.ID, i >= 0, authors[f.ID], []field{
			{name: "title", old: old.Title, new: f.Title},
			{name: "description", old: old.Description, new: f.Description},
			{name: "icon_url", old: old.IconURL, new: f.IconURL},
			{name: "enabled", old: old.Enabled, new: f.Enabled},
			{name: "acr", old: old.ACR, new: f.ACR},
			{name: "steps", old: old.Steps, new: f.Steps},
		}) || b.compare {
			continue
		}
		if err := putFlow(b.ctx, b.tx, f, bootstrapBy); err != nil {
			return err
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

func (b *bootstrap) clients(seed config.Seed) error {
	current, err := readAPIClients(b.ctx, b.tx)
	if err != nil {
		return fmt.Errorf("read API clients: %w", err)
	}
	authors, err := readAuthors(b.ctx, b.tx, "api_client", "id")
	if err != nil {
		return fmt.Errorf("read API clients: %w", err)
	}
	for _, sc := range seed.OAuth2Clients {
		scopes := []string(*sc.Scopes)
		if scopes == nil {
			scopes = []string{}
		}
		i := slices.IndexFunc(current, func(c APIClient) bool { return c.ID == sc.ID })
		var old APIClient
		if i >= 0 {
			old = current[i]
		}
		// Once: bcrypt is slow on purpose.
		sameSecret := i >= 0 && domain.SecretMatches(old.SecretHash, sc.Secret)
		if !b.decide("api_client", sc.ID, i >= 0, authors[sc.ID], []field{
			{name: "secret", secret: func() bool { return sameSecret }},
			{name: "scopes", old: old.Scopes, new: scopes},
		}) || b.compare {
			continue
		}
		// An unchanged secret keeps its hash: a new salt would show as a change.
		c := APIClient{ID: sc.ID, SecretHash: old.SecretHash, Scopes: scopes}
		if !sameSecret {
			if c.SecretHash, err = domain.HashSecret(sc.Secret); err != nil {
				return fmt.Errorf("API client %s: %w", sc.ID, err)
			}
		}
		if err := putAPIClient(b.ctx, b.tx, c, bootstrapBy); err != nil {
			return err
		}
	}
	ids := make([]string, len(current))
	for i, c := range current {
		ids[i] = c.ID
	}
	b.absent("api_client", ids, func(id string) bool {
		return slices.ContainsFunc(seed.OAuth2Clients, func(c config.SeedClient) bool { return c.ID == id })
	})
	return nil
}

func readAPIClients(ctx context.Context, q querier) ([]APIClient, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, secret_hash, scopes FROM api_client ORDER BY id COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := pgtype.NewMap()
	var clients []APIClient
	for rows.Next() {
		var c APIClient
		if err := rows.Scan(&c.ID, &c.SecretHash, m.SQLScanner(&c.Scopes)); err != nil {
			return nil, err
		}
		if c.Scopes == nil {
			c.Scopes = []string{}
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}
