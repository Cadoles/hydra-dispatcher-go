package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	_ "github.com/jackc/pgx/v5/stdlib"

	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// importAuthor is the updated_by of the clients the import writes.
const importAuthor = "import"

// scopeOrder is the order of the scopes of a client imported, that of the
// admin API.
var scopeOrder = []string{"admin:apps", "admin:flows", "admin:clients", "admin:settings", "admin:read"}

// groupScopes are the scopes of the groups of Symfony (Q94 to Q105, point C):
// admin:config and admin:users translated, a scope of the Go kept.
var groupScopes = map[string][]string{
	"admin:config": {"admin:apps", "admin:flows", "admin:settings", "admin:read"},
	"admin:users":  {"admin:clients"},
}

// errFailed is an import refused: its reasons printed, nothing written, exit 1.
var errFailed = errors.New("import refused, nothing written")

// accounts copies the admin accounts and the API clients of the database of
// Symfony into that of the Go, by its store (Q116): each refusal named before
// any write, an account or a client already there left as it is, a client
// whose secret is not a bcrypt hash left out (Q117).
func accounts(ctx context.Context, args []string, stdout, stderr io.Writer, stdin io.Reader) error {
	fs := flag.NewFlagSet("accounts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsnFile := fs.String("symfony-dsn-file", "", "the file of the DSN of Symfony's database (postgres://…): it holds a password")
	dsnStdin := fs.Bool("symfony-dsn-stdin", false, "read that DSN from the standard input")
	configPath := fs.String("config", os.Getenv("DISPATCHER_CONFIG"), "the configuration of the Go dispatcher, for its database (default: $DISPATCHER_CONFIG, else DISPATCHER_* variables only)")
	dryRun := fs.Bool("dry-run", false, "print what would be written, and write nothing")
	if err := parse(fs, args); err != nil {
		return err
	}
	dsn, err := readSecret("the DSN of Symfony's database", *dsnFile, *dsnStdin, stdin)
	if err != nil {
		return err
	}
	cfg, _, err := config.Load(*configPath, os.Environ())
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	users, clients, err := readSymfony(ctx, dsn)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.Store.DSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	plan, err := planImport(ctx, db, users, clients)
	if err != nil {
		return err
	}
	for _, w := range plan.warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if len(plan.refused) > 0 {
		for _, r := range plan.refused {
			fmt.Fprintln(stderr, "refused:", r)
		}
		return errFailed
	}
	if *dryRun {
		for _, e := range plan.entries {
			fmt.Fprintln(stdout, e.line)
		}
		fmt.Fprintln(stderr, "Dry run: nothing written.")
		return nil
	}
	// Each line printed once its write is done: a stop in the middle, the
	// database out of reach, says what was written (revue R38). Played again,
	// the import keeps it and goes on.
	for _, e := range plan.entries {
		if e.write != nil {
			if err := e.write(ctx, db); err != nil && !errors.Is(err, store.ErrExists) {
				return fmt.Errorf("stopped at %q: %w; the lines above were written, play the import again once it is corrected", e.line, err)
			}
		}
		fmt.Fprintln(stdout, e.line)
	}
	fmt.Fprintf(stderr, "Written: %d admin accounts, %d API clients.\n", len(plan.users), len(plan.clients))
	return nil
}

// symfonyUser and symfonyClient are rows of Symfony's database.
type symfonyUser struct {
	username, password, oidcSub string
	superAdmin                  bool
}

type symfonyClient struct {
	id, secret string
	scopeKeys  []string
}

// readSymfony reads the accounts and the clients, with the scope keys of
// their groups, in one read only transaction.
func readSymfony(ctx context.Context, dsn string) ([]symfonyUser, []symfonyClient, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("the Symfony database: %w", err)
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, nil, fmt.Errorf("the Symfony database: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT username, coalesce(password, ''), coalesce(oidc_sub, ''), super_admin
		FROM dispatcher_admin_user ORDER BY username COLLATE "C"`)
	if err != nil {
		return nil, nil, fmt.Errorf("the Symfony admin accounts: %w", err)
	}
	var users []symfonyUser
	for rows.Next() {
		var u symfonyUser
		if err := rows.Scan(&u.username, &u.password, &u.oidcSub, &u.superAdmin); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("the Symfony admin accounts: %w", err)
		}
		users = append(users, u)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("the Symfony admin accounts: %w", err)
	}

	rows, err = tx.QueryContext(ctx, `SELECT c.id, c.secret,
			coalesce(array_agg(g.scope_key ORDER BY g.scope_key) FILTER (WHERE g.scope_key IS NOT NULL), '{}')
		FROM dispatcher_oauth2_client c
		LEFT JOIN dispatcher_client_group cg ON cg.client_id = c.id
		LEFT JOIN dispatcher_group g ON g.id = cg.group_id
		GROUP BY c.id, c.secret ORDER BY c.id COLLATE "C"`)
	if err != nil {
		return nil, nil, fmt.Errorf("the Symfony API clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	m := pgtype.NewMap()
	var clients []symfonyClient
	for rows.Next() {
		var c symfonyClient
		if err := rows.Scan(&c.id, &c.secret, m.SQLScanner(&c.scopeKeys)); err != nil {
			return nil, nil, fmt.Errorf("the Symfony API clients: %w", err)
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("the Symfony API clients: %w", err)
	}
	return users, clients, nil
}

// importPlan is what the import writes, and why not the rest.
type importPlan struct {
	entries  []entry
	users    []store.AdminUser
	clients  []store.APIClient
	warnings []string
	refused  []string
}

// entry is a line of the import, as bootstrap prints its changes, and its
// write, nil for what is kept or left out.
type entry struct {
	line  string
	write func(ctx context.Context, db *store.Postgres) error
}

// planImport translates the rows of Symfony and checks them by the rules of
// the domain, against what the Go database holds already.
func planImport(ctx context.Context, db *store.Postgres, users []symfonyUser, clients []symfonyClient) (*importPlan, error) {
	haveUsers, err := db.Admins(ctx)
	if err != nil {
		return nil, err
	}
	haveClients, err := db.APIClients(ctx)
	if err != nil {
		return nil, err
	}
	p := &importPlan{}
	for _, su := range users {
		u := store.AdminUser{Username: su.username, PasswordHash: su.password, OIDCSub: su.oidcSub, Role: domain.RoleViewer}
		if su.superAdmin {
			u.Role = domain.RoleAdmin
		}
		if v := domain.Collect(u.Check); v != nil {
			for _, x := range v {
				p.refused = append(p.refused, fmt.Sprintf("admin account %q: %s: %s", su.username, x.Field, x.Message))
			}
			continue
		}
		if slices.ContainsFunc(haveUsers, func(h store.AdminUser) bool { return h.Username == u.Username }) {
			p.entries = append(p.entries, entry{line: fmt.Sprintf("keep    admin_user %s (in the Go database already: left as it is)", u.Username)})
			continue
		}
		// The column is unique: the database refused it in the middle of the
		// writes (revue R38).
		if i := slices.IndexFunc(haveUsers, func(h store.AdminUser) bool { return u.OIDCSub != "" && h.OIDCSub == u.OIDCSub }); i >= 0 {
			p.refused = append(p.refused, fmt.Sprintf("admin account %q: its oidc_sub is that of the account %q of the Go database", u.Username, haveUsers[i].Username))
			continue
		}
		p.users = append(p.users, u)
		p.entries = append(p.entries, entry{line: fmt.Sprintf("create  admin_user %s (%s)", u.Username, u.Role),
			write: func(ctx context.Context, db *store.Postgres) error { return db.CreateAdmin(ctx, u) }})
	}
	for _, sc := range clients {
		if !domain.IsHash(sc.secret) {
			// Q117: Symfony's CLI kept it in clear; the client never got a token.
			p.warnings = append(p.warnings, fmt.Sprintf("API client %s left out: its secret is not a bcrypt hash (kept in clear by Symfony's CLI, it never got a token)", sc.id))
			p.entries = append(p.entries, entry{line: fmt.Sprintf("skip    api_client %s (its secret is not a hash)", sc.id)})
			continue
		}
		c := store.APIClient{ID: sc.id, SecretHash: sc.secret, Scopes: []string{}}
		for _, key := range sc.scopeKeys {
			switch scopes, ok := groupScopes[key]; {
			case ok:
				c.Scopes = append(c.Scopes, scopes...)
			case slices.Contains(scopeOrder, key):
				c.Scopes = append(c.Scopes, key)
			default:
				p.warnings = append(p.warnings, fmt.Sprintf("API client %s: the scope %q of a group of Symfony has no match in the Go: left out", sc.id, key))
			}
		}
		c.Scopes = slices.DeleteFunc(slices.Clone(scopeOrder), func(s string) bool { return !slices.Contains(c.Scopes, s) })
		if len(c.Scopes) == 0 {
			p.warnings = append(p.warnings, fmt.Sprintf("API client %s has no scope: it gets no right until one is given (client update -scopes)", sc.id))
		}
		if v := domain.Collect(c.Check); v != nil {
			for _, x := range v {
				p.refused = append(p.refused, fmt.Sprintf("API client %q: %s: %s", sc.id, x.Field, x.Message))
			}
			continue
		}
		if slices.ContainsFunc(haveClients, func(h store.APIClient) bool { return h.ID == c.ID }) {
			p.entries = append(p.entries, entry{line: fmt.Sprintf("keep    api_client %s (in the Go database already: left as it is)", c.ID)})
			continue
		}
		p.clients = append(p.clients, c)
		scopes := strings.Join(c.Scopes, " ")
		if scopes == "" {
			scopes = "no scope"
		}
		p.entries = append(p.entries, entry{line: fmt.Sprintf("create  api_client %s (%s)", c.ID, scopes),
			write: func(ctx context.Context, db *store.Postgres) error { return db.CreateAPIClient(ctx, importAuthor, c) }})
	}
	return p, nil
}
