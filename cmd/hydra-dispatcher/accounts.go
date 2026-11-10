package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/audit"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// cliAuthor is the updated_by of the writes of the CLI (Q114).
const cliAuthor = "cli"

// dataOut is where the commands of the CLI write their data, alone: a list,
// a diff, a dump, a generated secret. Unset, it is os.Stdout, read at each
// write; a test sets it.
var dataOut io.Writer

func out() io.Writer {
	if dataOut != nil {
		return dataOut
	}
	return os.Stdout
}

// subcommand runs the subcommand of args among subs, for client, admin and
// config.
func subcommand(ctx context.Context, name string, subs []command, args []string) error {
	usage := func(w io.Writer) {
		fmt.Fprintf(w, "Usage: hydra-dispatcher %s <command> [flags]\n\nCommands:\n", name)
		for _, c := range subs {
			fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
		}
	}
	if len(args) == 0 {
		usage(os.Stderr)
		return errUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(os.Stderr)
		return nil
	}
	for _, c := range subs {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n", name+" "+args[0])
	usage(os.Stderr)
	return errUsage
}

// parseWithArg parses the flags of a subcommand that takes one argument, an id
// or a name, before or after its flags.
func parseWithArg(fs *flag.FlagSet, args []string, what string) (help bool, arg string, err error) {
	if err := boolValues(fs, args); err != nil {
		return false, "", err
	}
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return true, "", nil
	case err != nil:
		return false, "", errUsage
	case fs.NArg() == 0:
		fmt.Fprintf(fs.Output(), "missing the %s\n", what)
		fs.Usage()
		return false, "", errUsage
	}
	arg = fs.Arg(0)
	if help, err := parseFlags(fs, fs.Args()[1:]); help || err != nil {
		return help, "", err
	}
	return false, arg, nil
}

// cli is what a command of the CLI works with: its store, and the audit of
// its writes. The logs and the audit go to stderr, or to the output of the
// audit the configuration names: stdout holds the data alone.
type cli struct {
	db    configStore
	audit *audit.Log
	logs  loggers
	close func()
}

func openCLI(ctx context.Context, configPath string) (*cli, error) {
	slog.SetDefault(startLogger(os.Stderr))
	cfg, logs, err := loadConfig(configPath, os.Stderr)
	if err != nil {
		return nil, err
	}
	auditLog, drain, err := newAudit(cfg, os.Stderr, logs.app, func() {})
	if err != nil {
		return nil, err
	}
	db, err := openConfig(ctx, cfg)
	if err != nil {
		drain()
		return nil, err
	}
	return &cli{db: db, audit: auditLog, logs: logs, close: func() { _ = db.Close(); drain() }}, nil
}

// refused says why the store refused a write, on stderr, and gives errFailed:
// exit 1 without a fatal line. Any other error is returned as it is.
func refused(err error, what string) error {
	var violations domain.Violations
	var config *store.RefusedError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrExists):
		fmt.Fprintf(os.Stderr, "%s already exists.\n", what)
	case errors.Is(err, store.ErrNotFound):
		fmt.Fprintf(os.Stderr, "%s not found.\n", what)
	case errors.Is(err, store.ErrLastAdmin):
		fmt.Fprintf(os.Stderr, "%s: %v.\n", what, err)
	case errors.As(err, &violations):
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", what, v.Field, v.Message)
		}
	case errors.As(err, &config):
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	default:
		return err
	}
	return errFailed
}

// listFlag is the -scopes of a client: a list separated by commas, and
// whether it was given.
type listFlag struct {
	list []string
	set  bool
}

func (l *listFlag) String() string { return strings.Join(l.list, ",") }

func (l *listFlag) Set(s string) error {
	l.list, l.set = []string{}, true
	for item := range strings.SplitSeq(s, ",") {
		// Once each: a, a gave the client the same scope twice (revue R37).
		if item = strings.TrimSpace(item); item != "" && !slices.Contains(l.list, item) {
			l.list = append(l.list, item)
		}
	}
	return nil
}

// formatFlag is the -format of a list or a diff: text or json.
func formatFlag(fs *flag.FlagSet) *string {
	return fs.String("format", "text", "text, or json for the tools")
}

func checkFormat(fs *flag.FlagSet, format string) error {
	if format != "text" && format != "json" {
		fmt.Fprintf(fs.Output(), "-format %q: text or json\n", format)
		return errUsage
	}
	return nil
}

func writeJSON(v any) error {
	enc := json.NewEncoder(out())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// hashOf is the hash of a secret given: a bcrypt hash is taken as it is, as
// by the admin API.
func hashOf(secret string) (string, error) {
	if domain.IsHash(secret) {
		return secret, nil
	}
	return domain.HashSecret(secret)
}

var clientCommands = []command{
	{"create", "create <id> [-scopes a,b] [-secret-stdin|-secret-file f]: a secret not given is generated and written once", clientCreate},
	{"update", "update <id> [-scopes a,b] [-new-secret|-secret-stdin|-secret-file f]", clientUpdate},
	{"delete", "delete <id> [-yes]", clientDelete},
	{"list", "list [-format text|json]: ids and scopes, never a secret", clientList},
}

// client manages the API clients of the admin API.
func client(ctx context.Context, args []string) error {
	return subcommand(ctx, "client", clientCommands, args)
}

func clientCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client create", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	var scopes listFlag
	fs.Var(&scopes, "scopes", "its scopes, separated by commas (default: none)")
	secret := newSecretInput(fs, "secret")
	help, id, err := parseWithArg(fs, args, "client id")
	if help || err != nil {
		return err
	}
	if err := secret.check(fs); err != nil {
		return err
	}
	value, generated := domain.NewSecret(), true
	if secret.given() {
		if value, err = secret.read(false); err != nil {
			return err
		}
		generated = false
	}
	hash, err := hashOf(value)
	if err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	what := fmt.Sprintf("API client %q", id)
	if scopes.list == nil {
		scopes.list = []string{} // Q111: no scope
	}
	if err := refused(c.db.CreateAPIClient(ctx, cliAuthor, store.APIClient{ID: id, SecretHash: hash, Scopes: scopes.list}), what); err != nil {
		return err
	}
	c.audit.CLIWrote(ctx, "oauth2-clients", id, "client create", []string{"secret", "scopes"})
	if !generated {
		fmt.Fprintf(os.Stderr, "%s created.\n", what)
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s created. Its secret, generated, is on the standard output, shown this once.\n", what)
	_, err = fmt.Fprintln(out(), value)
	return err
}

func clientUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client update", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	var scopes listFlag
	fs.Var(&scopes, "scopes", "its scopes, separated by commas, in place of those it has")
	newSecret := fs.Bool("new-secret", false, "generate a new secret, written once on the standard output")
	secret := newSecretInput(fs, "secret")
	help, id, err := parseWithArg(fs, args, "client id")
	if help || err != nil {
		return err
	}
	if err := secret.check(fs); err != nil {
		return err
	}
	switch {
	case *newSecret && secret.given():
		fmt.Fprintln(fs.Output(), "-new-secret and -secret-stdin or -secret-file are exclusive")
		return errUsage
	case !scopes.set && !*newSecret && !secret.given():
		fmt.Fprintln(fs.Output(), "nothing to update: give -scopes, -new-secret, -secret-stdin or -secret-file")
		return errUsage
	}
	// The secret is read and hashed before the write: bcrypt under the lock
	// of the writes would hold the others.
	var value, hash string
	switch {
	case *newSecret:
		value = domain.NewSecret()
	case secret.given():
		if value, err = secret.read(false); err != nil {
			return err
		}
	}
	if value != "" {
		if hash, err = hashOf(value); err != nil {
			return err
		}
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	var fields []string
	if hash != "" {
		fields = append(fields, "secret")
	}
	if scopes.set {
		fields = append(fields, "scopes")
	}
	what := fmt.Sprintf("API client %q", id)
	err = c.db.UpdateAPIClient(ctx, cliAuthor, id, func(client *store.APIClient) error {
		if hash != "" {
			client.SecretHash = hash
		}
		if scopes.set {
			client.Scopes = scopes.list
		}
		return nil
	})
	if err := refused(err, what); err != nil {
		return err
	}
	c.audit.CLIWrote(ctx, "oauth2-clients", id, "client update", fields)
	if !*newSecret {
		fmt.Fprintf(os.Stderr, "%s updated.\n", what)
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s updated. Its new secret is on the standard output, shown this once.\n", what)
	_, err = fmt.Fprintln(out(), value)
	return err
}

func clientDelete(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client delete", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	yes := fs.Bool("yes", false, "in a terminal, delete without asking")
	help, id, err := parseWithArg(fs, args, "client id")
	if help || err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	what := fmt.Sprintf("API client %q", id)
	clients, err := c.db.APIClients(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(clients, func(c store.APIClient) bool { return c.ID == id }) {
		return refused(store.ErrNotFound, what)
	}
	if !*yes && stdinIsTerminal() && !confirm(stdin, os.Stderr, "Delete "+what+"?") {
		fmt.Fprintln(os.Stderr, "Nothing deleted.")
		return nil
	}
	if err := refused(c.db.DeleteAPIClient(ctx, id), what); err != nil {
		return err
	}
	c.audit.CLIWrote(ctx, "oauth2-clients", id, "client delete", nil)
	fmt.Fprintf(os.Stderr, "%s deleted.\n", what)
	return nil
}

func clientList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client list", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	format := formatFlag(fs)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if err := checkFormat(fs, *format); err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	clients, err := c.db.APIClients(ctx)
	if err != nil {
		return err
	}
	if *format == "json" {
		type row struct {
			ID     string   `json:"id"`
			Scopes []string `json:"scopes"`
		}
		rows := []row{}
		for _, cl := range clients {
			rows = append(rows, row{cl.ID, cl.Scopes})
		}
		return writeJSON(rows)
	}
	if len(clients) == 0 {
		fmt.Fprintln(os.Stderr, "No API clients.")
		return nil
	}
	tw := tabwriter.NewWriter(out(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSCOPES")
	for _, cl := range clients {
		fmt.Fprintf(tw, "%s\t%s\n", cl.ID, strings.Join(cl.Scopes, ","))
	}
	return tw.Flush()
}

var adminCommands = []command{
	{"create", "create <user> -role admin|viewer [-password-stdin|-password-file f]", adminCreate},
	{"update", "update <user> [-role admin|viewer] [-password|-password-stdin|-password-file f]", adminUpdate},
	{"list", "list [-format text|json]: names, roles, never a password", adminList},
}

// adminAccounts manages the accounts of the admin UI.
func adminAccounts(ctx context.Context, args []string) error {
	return subcommand(ctx, "admin", adminCommands, args)
}

func checkRole(fs *flag.FlagSet, role string) error {
	if role != domain.RoleAdmin && role != domain.RoleViewer {
		fmt.Fprintf(fs.Output(), "-role %q: admin or viewer\n", role)
		return errUsage
	}
	return nil
}

func adminCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	role := fs.String("role", "", "admin or viewer, required")
	password := newSecretInput(fs, "password")
	help, username, err := parseWithArg(fs, args, "user name")
	if help || err != nil {
		return err
	}
	if *role == "" {
		fmt.Fprintln(fs.Output(), "missing -role: admin or viewer")
		return errUsage
	}
	if err := checkRole(fs, *role); err != nil {
		return err
	}
	if err := password.check(fs); err != nil {
		return err
	}
	value, err := password.read(true)
	if err != nil {
		return err
	}
	hash, err := domain.HashSecret(value)
	if err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	what := fmt.Sprintf("Admin account %q", username)
	if err := refused(c.db.CreateAdmin(ctx, store.AdminUser{Username: username, PasswordHash: hash, Role: *role}), what); err != nil {
		return err
	}
	c.audit.CLIWrote(ctx, "admin-users", username, "admin create", []string{"role", "password"})
	fmt.Fprintf(os.Stderr, "%s created.\n", what)
	return nil
}

func adminUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin update", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	role := fs.String("role", "", "admin or viewer")
	ask := fs.Bool("password", false, "ask a new password, in a terminal")
	password := newSecretInput(fs, "password")
	help, username, err := parseWithArg(fs, args, "user name")
	if help || err != nil {
		return err
	}
	if err := password.check(fs); err != nil {
		return err
	}
	switch {
	case *ask && password.given():
		fmt.Fprintln(fs.Output(), "-password and -password-stdin or -password-file are exclusive")
		return errUsage
	case *role == "" && !*ask && !password.given():
		fmt.Fprintln(fs.Output(), "nothing to update: give -role, -password, -password-stdin or -password-file")
		return errUsage
	case *role != "":
		if err := checkRole(fs, *role); err != nil {
			return err
		}
	}
	var hash string
	var fields []string
	if *role != "" {
		fields = append(fields, "role")
	}
	if *ask || password.given() {
		value, err := password.read(true)
		if err != nil {
			return err
		}
		if hash, err = domain.HashSecret(value); err != nil {
			return err
		}
		fields = append(fields, "password")
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	what := fmt.Sprintf("Admin account %q", username)
	err = c.db.UpdateAdmin(ctx, username, func(u *store.AdminUser) error {
		if *role != "" {
			u.Role = *role
		}
		if hash != "" {
			u.PasswordHash = hash
		}
		return nil
	})
	if err := refused(err, what); err != nil {
		return err
	}
	c.audit.CLIWrote(ctx, "admin-users", username, "admin update", fields)
	fmt.Fprintf(os.Stderr, "%s updated.\n", what)
	return nil
}

func adminList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin list", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	format := formatFlag(fs)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	if err := checkFormat(fs, *format); err != nil {
		return err
	}
	c, err := openCLI(ctx, *configPath)
	if err != nil {
		return err
	}
	defer c.close()
	users, err := c.db.Admins(ctx)
	if err != nil {
		return err
	}
	if *format == "json" {
		type row struct {
			Username  string    `json:"username"`
			Role      string    `json:"role"`
			Password  bool      `json:"password"`
			OIDC      bool      `json:"oidc"`
			CreatedAt time.Time `json:"created_at"`
		}
		rows := []row{}
		for _, u := range users {
			rows = append(rows, row{u.Username, u.Role, u.PasswordHash != "", u.OIDCSub != "", u.CreatedAt.UTC()})
		}
		return writeJSON(rows)
	}
	if len(users) == 0 {
		fmt.Fprintln(os.Stderr, "No admin accounts.")
		return nil
	}
	yesNo := map[bool]string{true: "yes", false: "no"}
	tw := tabwriter.NewWriter(out(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tROLE\tPASSWORD\tOIDC\tCREATED")
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Username, u.Role, yesNo[u.PasswordHash != ""], yesNo[u.OIDCSub != ""], u.CreatedAt.UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}
