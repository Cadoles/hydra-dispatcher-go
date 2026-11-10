package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

// APIClient is a client of the admin API.
type APIClient = domain.APIClient

// Errors of the writes, which the admin API gives as statuses. A write the
// rules refuse returns domain.Violations, one whose configuration serve
// would refuse a *RefusedError, an app that steps name a *ReferencedError.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

// ReferencedError refuses to delete an app that flows have as a step.
type ReferencedError struct {
	App   string
	Flows []string
}

func (e *ReferencedError) Error() string {
	return fmt.Sprintf("app %s is a step of %s", e.App, strings.Join(e.Flows, ", "))
}

// RefusedError is a write whose configuration serve would refuse, its
// snapshot unreadable or refused by SetCheck: nothing is written, for no
// write to freeze the refreshes of every instance.
type RefusedError struct{ Err error }

func (e *RefusedError) Error() string {
	return "the configuration this write leaves would be refused: " + e.Err.Error()
}

func (e *RefusedError) Unwrap() error { return e.Err }

// writeLock is the advisory lock that serializes the writes, bootstrap's
// included: replicas starting in serve.bootstrap force would otherwise insert
// the same rows, and a write checks the configuration it leaves, which a
// concurrent write would change between the check and the commit. The
// bootstraps of the versions before take it too.
const writeLock = 0x6469737061746368 // "dispatch"

// notifyChannel is the channel the writes notify at their commit, and the
// instances listen to.
const notifyChannel = "dispatcher_config"

// maxAuthor is the length of updated_by.
const maxAuthor = 180

// SetCheck sets what serve refuses of a snapshot beyond what reading refuses
// (webhook.Check, on the instance's configuration): no write commits a
// configuration check refuses. Set before the first write.
func (p *Postgres) SetCheck(check func(*Snapshot) error) { p.check = check }

// OnCommit sets what runs after each write the store commits, bootstrap's
// included: serve refreshes its snapshot, so that a write reads back at once
// on the instance that made it. Set before the first write.
func (p *Postgres) OnCommit(committed func(context.Context)) { p.committed = committed }

// write runs fn in a transaction (transact) and commits it.
func (p *Postgres) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	return p.transact(ctx, "write", true, fn)
}

// transact runs fn in a transaction, under writeLock, in read committed
// whatever the default of the database: each statement sees what the writes
// before committed. In repeatable read, the snapshot would date from the lock
// statement, before the wait, and miss what the write it waited for wrote.
// Then it reads the snapshot the transaction leaves and refuses it as serve
// would. With commit, it notifies the instances, commits, and calls the hook
// of OnCommit; the notification leaves at the commit, never before. Without,
// it rolls back what fn wrote: the dry run of bootstrap gives the refusals
// of a write. op prefixes the errors of the transaction, not those of fn.
func (p *Postgres) transact(ctx context.Context, op string, commit bool, fn func(tx *sql.Tx) error) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = tx.Rollback() }() // after Commit, a no-op
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(writeLock)); err != nil {
		return fmt.Errorf("%s: lock: %w", op, err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := p.checkSnapshot(ctx, tx); err != nil {
		var refused *RefusedError
		if errors.As(err, &refused) {
			return err
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if !commit {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_notify($1, '')`, notifyChannel); err != nil {
		return fmt.Errorf("%s: notify: %w", op, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if p.committed != nil {
		p.committed(ctx)
	}
	return nil
}

// checkSnapshot refuses what tx leaves when serve would refuse it.
// An error of the database while reading (a lock_timeout, a connection lost) is
// not a refusal: the configuration is not at fault (revue R33).
func (p *Postgres) checkSnapshot(ctx context.Context, tx *sql.Tx) error {
	s, err := readSnapshot(ctx, tx)
	var u unreadable
	switch {
	case errors.As(err, &u):
		return &RefusedError{Err: err}
	case err != nil:
		return fmt.Errorf("read the configuration back: %w", err)
	}
	if p.check != nil {
		if err := p.check(s); err != nil {
			return &RefusedError{Err: err}
		}
	}
	return nil
}

// checkAuthor checks what goes to updated_by.
func checkAuthor(by string) error {
	if by == "" || !utf8.ValidString(by) || strings.ContainsRune(by, 0) || utf8.RuneCountInString(by) > maxAuthor {
		return fmt.Errorf("author %q: from 1 to %d characters of UTF-8, without NUL", by, maxAuthor)
	}
	return nil
}

// errIDChanged refuses an update that changes the id of an entity.
func errIDChanged(id, to string) domain.Violations {
	return domain.Violations{{Field: "id", Message: fmt.Sprintf("is %q, and an update cannot change it to %q", id, to)}}
}

// CreateApp writes a new app: ErrExists when its id is taken.
func (p *Postgres) CreateApp(ctx context.Context, by string, a App) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		if v := domain.Collect(a.Check); v != nil {
			return v
		}
		if _, found, err := findApp(ctx, tx, a.ID); err != nil || found {
			return cmpErr(err, ErrExists)
		}
		return putApp(ctx, tx, a, by)
	})
}

// UpdateApp applies change to the app id as the database holds it, and
// writes the result: ErrNotFound when there is none. change replaces it
// whole (PUT) or a few fields (PATCH), in the transaction of the write: two
// updates of the same app never lose one another. The id cannot change.
func (p *Postgres) UpdateApp(ctx context.Context, by, id string, change func(*App) error) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		a, found, err := findApp(ctx, tx, id)
		if err != nil || !found {
			return cmpErr(err, ErrNotFound)
		}
		if err := change(&a); err != nil {
			return err
		}
		if a.ID != id {
			return errIDChanged(id, a.ID)
		}
		if v := domain.Collect(a.Check); v != nil {
			return v
		}
		return putApp(ctx, tx, a, by)
	})
}

// DeleteApp deletes the app id: ErrNotFound when there is none, a
// *ReferencedError when flows have it as a step.
func (p *Postgres) DeleteApp(ctx context.Context, id string) error {
	return p.write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT flow_id FROM flow_step WHERE app_id = $1 ORDER BY flow_id COLLATE "C"`, id)
		if err != nil {
			return err
		}
		var flows []string
		for rows.Next() {
			var f string
			if err := rows.Scan(&f); err != nil {
				_ = rows.Close()
				return err
			}
			flows = append(flows, f)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		if len(flows) > 0 {
			return &ReferencedError{App: id, Flows: flows}
		}
		return deleteRow(ctx, tx, `DELETE FROM app WHERE id = $1`, id)
	})
}

// CreateFlow writes a new flow and its steps: ErrExists when its id is
// taken.
func (p *Postgres) CreateFlow(ctx context.Context, by string, f Flow) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		if err := checkFlow(ctx, tx, f); err != nil {
			return err
		}
		if _, found, err := findFlow(ctx, tx, f.ID); err != nil || found {
			return cmpErr(err, ErrExists)
		}
		return putFlow(ctx, tx, f, by)
	})
}

// UpdateFlow is UpdateApp for a flow and its steps.
func (p *Postgres) UpdateFlow(ctx context.Context, by, id string, change func(*Flow) error) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		f, found, err := findFlow(ctx, tx, id)
		if err != nil || !found {
			return cmpErr(err, ErrNotFound)
		}
		if err := change(&f); err != nil {
			return err
		}
		if f.ID != id {
			return errIDChanged(id, f.ID)
		}
		if err := checkFlow(ctx, tx, f); err != nil {
			return err
		}
		return putFlow(ctx, tx, f, by)
	})
}

// DeleteFlow deletes the flow id and its steps: ErrNotFound when there is
// none.
func (p *Postgres) DeleteFlow(ctx context.Context, id string) error {
	return p.write(ctx, func(tx *sql.Tx) error {
		return deleteRow(ctx, tx, `DELETE FROM flow WHERE id = $1`, id)
	})
}

// checkFlow checks f against the apps the transaction sees.
func checkFlow(ctx context.Context, tx *sql.Tx, f Flow) error {
	apps, err := readApps(ctx, tx)
	if err != nil {
		return err
	}
	known := func(id string) bool { return slices.ContainsFunc(apps, func(a App) bool { return a.ID == id }) }
	if v := domain.Collect(func(fail domain.Fail) { f.Check(fail, known) }); v != nil {
		return v
	}
	return nil
}

// CreateAPIClient writes a new API client, its secret hashed
// (domain.HashSecret): ErrExists when its id is taken.
func (p *Postgres) CreateAPIClient(ctx context.Context, by string, c APIClient) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		if v := domain.Collect(c.Check); v != nil {
			return v
		}
		if _, found, err := findAPIClient(ctx, tx, c.ID); err != nil || found {
			return cmpErr(err, ErrExists)
		}
		return putAPIClient(ctx, tx, c, by)
	})
}

// UpdateAPIClient is UpdateApp for an API client.
func (p *Postgres) UpdateAPIClient(ctx context.Context, by, id string, change func(*APIClient) error) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		c, found, err := findAPIClient(ctx, tx, id)
		if err != nil || !found {
			return cmpErr(err, ErrNotFound)
		}
		if err := change(&c); err != nil {
			return err
		}
		if c.ID != id {
			return errIDChanged(id, c.ID)
		}
		if v := domain.Collect(c.Check); v != nil {
			return v
		}
		return putAPIClient(ctx, tx, c, by)
	})
}

// APIClients reads the API clients, by id, without the rest of the
// configuration: the CLI lists or deletes them on a database whose snapshot
// another row makes unreadable.
func (p *Postgres) APIClients(ctx context.Context) ([]APIClient, error) {
	clients, err := readAPIClients(ctx, p.db)
	if err != nil {
		return nil, fmt.Errorf("read API clients: %w", err)
	}
	return clients, nil
}

// DeleteAPIClient deletes the API client id: ErrNotFound when there is none.
func (p *Postgres) DeleteAPIClient(ctx context.Context, id string) error {
	return p.write(ctx, func(tx *sql.Tx) error {
		return deleteRow(ctx, tx, `DELETE FROM api_client WHERE id = $1`, id)
	})
}

// UpdateSettings writes the settings of values, by key, each in the JSON of
// its type (durations in seconds); null gives a key back its default. Only
// the keys whose value changes are written: a document sent back unchanged
// writes nothing. An unknown key, a value of the wrong type, or settings that
// fail Validate together, are violations under the key.
func (p *Postgres) UpdateSettings(ctx context.Context, by string, values map[string]json.RawMessage) error {
	if err := checkAuthor(by); err != nil {
		return err
	}
	return p.write(ctx, func(tx *sql.Tx) error {
		rows, err := readSettings(ctx, tx)
		if err != nil {
			return fmt.Errorf("read settings: %w", err)
		}
		// The rows this write replaces may be unreadable: it corrects them.
		kept := maps.Clone(rows)
		for key := range values {
			delete(kept, key)
		}
		next, _, err := decodeSettings(kept)
		if err != nil {
			return &RefusedError{Err: err}
		}
		var violations domain.Violations
		var write, reset []setting
		for _, key := range slices.Sorted(maps.Keys(values)) {
			st, ok := lookup(key)
			if !ok {
				violations = append(violations, domain.Violation{Field: key, Message: "is not a setting"})
				continue
			}
			raw, inDB := rows[key]
			if bytes.Equal(bytes.TrimSpace(values[key]), []byte("null")) || values[key] == nil {
				if inDB {
					reset = append(reset, st)
				}
				continue // next has the default
			}
			if err := st.decode(values[key], &next); err != nil {
				violations = append(violations, domain.Violation{Field: key, Message: err.Error()})
				continue
			}
			// What the key holds now: its row, or its default.
			before := DefaultSettings()
			readable := !inDB || st.decode(raw, &before) == nil
			if !readable || !bytes.Equal(st.encode(&before), st.encode(&next)) {
				write = append(write, st)
			}
		}
		violations = append(violations, domain.Collect(next.Check)...)
		if violations != nil {
			return violations
		}
		for _, st := range write {
			if err := putSetting(ctx, tx, st, &next, by); err != nil {
				return err
			}
		}
		for _, st := range reset {
			if _, err := tx.ExecContext(ctx, `DELETE FROM setting WHERE key = $1`, st.key); err != nil {
				return fmt.Errorf("setting %s: %w", st.key, err)
			}
		}
		return nil
	})
}

// cmpErr is err, or found when err is nil: the error of a lookup that found
// what it should not have, or did not find what it should have.
func cmpErr(err, found error) error {
	if err != nil {
		return err
	}
	return found
}

// deleteRow runs a DELETE of one row by id: ErrNotFound when it deletes none.
func deleteRow(ctx context.Context, tx *sql.Tx, query, id string) error {
	r, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n == 0 {
		return cmpErr(err, ErrNotFound)
	}
	return nil
}

func findApp(ctx context.Context, q querier, id string) (App, bool, error) {
	apps, err := readApps(ctx, q)
	if err != nil {
		return App{}, false, fmt.Errorf("read apps: %w", err)
	}
	i := slices.IndexFunc(apps, func(a App) bool { return a.ID == id })
	if i < 0 {
		return App{}, false, nil
	}
	return apps[i], true, nil
}

func findFlow(ctx context.Context, q querier, id string) (Flow, bool, error) {
	flows, err := readFlows(ctx, q)
	if err != nil {
		return Flow{}, false, fmt.Errorf("read flows: %w", err)
	}
	i := slices.IndexFunc(flows, func(f Flow) bool { return f.ID == id })
	if i < 0 {
		return Flow{}, false, nil
	}
	return flows[i], true, nil
}

func findAPIClient(ctx context.Context, q querier, id string) (APIClient, bool, error) {
	clients, err := readAPIClients(ctx, q)
	if err != nil {
		return APIClient{}, false, fmt.Errorf("read API clients: %w", err)
	}
	i := slices.IndexFunc(clients, func(c APIClient) bool { return c.ID == id })
	if i < 0 {
		return APIClient{}, false, nil
	}
	return clients[i], true, nil
}

// putApp writes a, created or replaced, by the author by.
func putApp(ctx context.Context, tx *sql.Tx, a App, by string) error {
	sources := make([]string, len(a.AllowedSources)) // NOT NULL: never nil
	for i, s := range a.AllowedSources {
		sources[i] = s.String()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO app (id, login_url, consent_url, logout_url, method, auth_mode, allowed_sources, client_cert_fingerprint,
			receive_claims, updated_at, updated_by)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7::text[]::cidr[], NULLIF($8, ''), $9::text[], now(), $10)
		ON CONFLICT (id) DO UPDATE SET login_url = EXCLUDED.login_url, consent_url = EXCLUDED.consent_url,
			logout_url = EXCLUDED.logout_url, method = EXCLUDED.method, auth_mode = EXCLUDED.auth_mode,
			allowed_sources = EXCLUDED.allowed_sources, client_cert_fingerprint = EXCLUDED.client_cert_fingerprint,
			receive_claims = EXCLUDED.receive_claims, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		a.ID, a.LoginURL, a.ConsentURL, a.LogoutURL, a.Method, a.AuthMode, sources, a.ClientCertFingerprint, a.ReceiveClaims, by); err != nil {
		return fmt.Errorf("app %s: %w", a.ID, err)
	}
	return nil
}

// putFlow writes f and its steps, created or replaced, by the author by.
func putFlow(ctx context.Context, tx *sql.Tx, f Flow, by string) error {
	texts := func(m map[string]string) string {
		if m == nil {
			m = map[string]string{} // an object: never the JSON null
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	var icon *string
	if f.IconURL != nil {
		s := texts(f.IconURL)
		icon = &s
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO flow (id, title, description, icon_url, enabled, acr, updated_at, updated_by)
		VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5, NULLIF($6, ''), now(), $7)
		ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description,
			icon_url = EXCLUDED.icon_url, enabled = EXCLUDED.enabled, acr = EXCLUDED.acr,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		f.ID, texts(f.Title), texts(f.Description), icon, f.Enabled, f.ACR, by); err != nil {
		return fmt.Errorf("flow %s: %w", f.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM flow_step WHERE flow_id = $1`, f.ID); err != nil {
		return fmt.Errorf("flow %s: %w", f.ID, err)
	}
	for _, s := range f.Steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO flow_step (flow_id, app_id, position, subject_check) VALUES ($1, $2, $3, $4)`,
			f.ID, s.AppID, s.Position, s.SubjectCheck); err != nil {
			return fmt.Errorf("flow %s: step %s: %w", f.ID, s.AppID, err)
		}
	}
	return nil
}

// putAPIClient writes c, created or replaced, by the author by.
func putAPIClient(ctx context.Context, tx *sql.Tx, c APIClient, by string) error {
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{} // NOT NULL
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_client (id, secret_hash, scopes, updated_at, updated_by) VALUES ($1, $2, $3::text[], now(), $4)
		ON CONFLICT (id) DO UPDATE SET secret_hash = EXCLUDED.secret_hash, scopes = EXCLUDED.scopes,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		c.ID, c.SecretHash, scopes, by); err != nil {
		return fmt.Errorf("API client %s: %w", c.ID, err)
	}
	return nil
}

// putSetting writes the value st has in s, by the author by.
func putSetting(ctx context.Context, tx *sql.Tx, st setting, s *Settings, by string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO setting (key, value, updated_at, updated_by) VALUES ($1, $2::jsonb, now(), $3)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		st.key, string(st.encode(s)), by); err != nil {
		return fmt.Errorf("setting %s: %w", st.key, err)
	}
	return nil
}
