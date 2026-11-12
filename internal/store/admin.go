package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
)

// AdminUser is an account of the admin UI.
type AdminUser = domain.AdminUser

// ErrLastAdmin refuses to take the admin role from the last account that has
// it: nobody could give it back but the CLI.
var ErrLastAdmin = errors.New("the last admin account keeps the admin role")

// adminLock serializes the writes of the admin accounts, so that two
// demotions at once leave an admin. Not writeLock: the accounts are not the
// configuration, no instance reads them, and their writes notify none.
const adminLock = 0x61646d696e757372 // "adminusr"

// adminWrite runs fn in a transaction under adminLock, in read committed, and
// commits it.
func (p *Postgres) adminWrite(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("admin account: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // after Commit, a no-op
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(adminLock)); err != nil {
		return fmt.Errorf("admin account: lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("admin account: %w", err)
	}
	return nil
}

// CreateAdmin writes a new admin account: ErrExists when its name is taken,
// domain.Violations when it breaks a rule.
func (p *Postgres) CreateAdmin(ctx context.Context, u AdminUser) error {
	if v := domain.Collect(u.Check); v != nil {
		return v
	}
	return p.adminWrite(ctx, func(tx *sql.Tx) error {
		if _, found, err := findAdmin(ctx, tx, u.Username); err != nil || found {
			return cmpErr(err, ErrExists)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO admin_user (username, password_hash, oidc_sub, role)
			VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4)`, u.Username, u.PasswordHash, u.OIDCSub, u.Role)
		if err != nil {
			return fmt.Errorf("admin account %s: %w", u.Username, err)
		}
		return nil
	})
}

// UpdateAdmin applies change to the account username: ErrNotFound when there
// is none, ErrLastAdmin when it takes the role of the last admin.
func (p *Postgres) UpdateAdmin(ctx context.Context, username string, change func(*AdminUser) error) error {
	return p.adminWrite(ctx, func(tx *sql.Tx) error {
		u, found, err := findAdmin(ctx, tx, username)
		if err != nil || !found {
			return cmpErr(err, ErrNotFound)
		}
		was := u
		if err := change(&u); err != nil {
			return err
		}
		if u.Username != username {
			return domain.Violations{{Field: "username", Message: fmt.Sprintf("is %q, and an update cannot change it to %q", username, u.Username)}}
		}
		if v := domain.Collect(u.Check); v != nil {
			return v
		}
		if was.Role == domain.RoleAdmin && u.Role != domain.RoleAdmin {
			var others int
			err := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_user WHERE role = $1 AND username <> $2`, domain.RoleAdmin, username).Scan(&others)
			if err != nil {
				return fmt.Errorf("admin accounts: %w", err)
			}
			if others == 0 {
				return ErrLastAdmin
			}
		}
		// A password or a role changed stops the sessions of the account
		// (Q120): a stolen session does not outlive the change.
		end := u.PasswordHash != was.PasswordHash || u.Role != was.Role
		_, err = tx.ExecContext(ctx, `UPDATE admin_user SET password_hash = NULLIF($2, ''), oidc_sub = NULLIF($3, ''), role = $4,
			sessions_valid_after = CASE WHEN $5 THEN $6 ELSE sessions_valid_after END
			WHERE username = $1`, username, u.PasswordHash, u.OIDCSub, u.Role, end, time.Now())
		if err != nil {
			return fmt.Errorf("admin account %s: %w", username, err)
		}
		return nil
	})
}

// Admins reads the admin accounts, by name.
func (p *Postgres) Admins(ctx context.Context) ([]AdminUser, error) {
	return readAdmins(ctx, p.db, "")
}

// Admin reads the account username: the admin UI reads it at each request,
// so that a role taken or an account deleted takes effect at once (Q120).
func (p *Postgres) Admin(ctx context.Context, username string) (AdminUser, bool, error) {
	return findAdmin(ctx, p.db, username)
}

// EndSessions stops the sessions of the account username at once, those of
// every browser: its logout (Q120). ErrNotFound when there is none.
func (p *Postgres) EndSessions(ctx context.Context, username string) error {
	return p.adminWrite(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `UPDATE admin_user SET sessions_valid_after = $2 WHERE username = $1`, username, time.Now())
		if err != nil {
			return fmt.Errorf("admin account %s: %w", username, err)
		}
		if n, err := r.RowsAffected(); err != nil || n == 0 {
			return cmpErr(err, ErrNotFound)
		}
		return nil
	})
}

func findAdmin(ctx context.Context, q querier, username string) (AdminUser, bool, error) {
	users, err := readAdmins(ctx, q, username)
	if err != nil || len(users) == 0 {
		return AdminUser{}, false, err
	}
	return users[0], true, nil
}

// readAdmins reads the accounts, the one named username when it is not "".
func readAdmins(ctx context.Context, q querier, username string) ([]AdminUser, error) {
	rows, err := q.QueryContext(ctx, `SELECT username, coalesce(password_hash, ''), coalesce(oidc_sub, ''), role, created_at, sessions_valid_after
		FROM admin_user WHERE $1 = '' OR username = $1 ORDER BY username COLLATE "C"`, username)
	if err != nil {
		return nil, fmt.Errorf("read admin accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var users []AdminUser
	for rows.Next() {
		var u AdminUser
		var ended sql.NullTime
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.OIDCSub, &u.Role, &u.CreatedAt, &ended); err != nil {
			return nil, fmt.Errorf("read admin accounts: %w", err)
		}
		u.SessionsValidAfter = ended.Time
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read admin accounts: %w", err)
	}
	return users, nil
}
