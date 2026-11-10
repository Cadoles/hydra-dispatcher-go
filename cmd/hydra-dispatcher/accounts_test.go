package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// runCLI runs the command line args on the store f, the standard input input
// and, in a terminal, the answers typed without echo; it gives what the
// command wrote on its data output and on stderr.
func runCLI(t *testing.T, f *fakeStore, terminal bool, input string, answers []string, args ...string) (out, errOut string, err error) {
	t.Helper()
	useStore(t, f)
	terminalAnswers(t, terminal, input, answers...)
	var b bytes.Buffer
	dataOut = &b
	t.Cleanup(func() { dataOut = nil })
	errOut = stderrOf(t, func() { err = run(context.Background(), args, os.Stderr) })
	return b.String(), errOut, err
}

func mustHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := domain.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// errOther stands for an error that is neither errUsage nor errFailed: exit 1
// with a fatal line.
var errOther = errors.New("another error")

// cliCase is a command line, the store before, and what it gives.
type cliCase struct {
	args     []string
	terminal bool
	input    string
	answers  []string
	clients  []store.APIClient
	admins   []store.AdminUser
	// err is nil, errUsage (exit 2), errFailed (exit 1) or errOther.
	err error
	// stdout is what it holds, "<secret>" for a secret generated alone on its
	// line; stderr what it contains.
	stdout, stderr string
	calls          []string
	check          func(t *testing.T, f *fakeStore, stdout string)
}

func (tt cliCase) run(t *testing.T) {
	t.Helper()
	keepLoggers(t)
	commandEnv(t)
	f := &fakeStore{clients: tt.clients, admins: tt.admins}
	out, errOut, err := runCLI(t, f, tt.terminal, tt.input, tt.answers, tt.args...)
	switch {
	case tt.err == errOther && (err == nil || errors.Is(err, errUsage) || errors.Is(err, errFailed)):
		t.Errorf("err = %v, want another error\nstderr:\n%s", err, errOut)
	case tt.err != errOther && (!errors.Is(err, tt.err) || (tt.err == nil) != (err == nil)):
		t.Errorf("err = %v, want %v\nstderr:\n%s", err, tt.err, errOut)
	case tt.stdout == "<secret>" && (len(out) != 44 || !strings.HasSuffix(out, "\n")):
		t.Errorf("stdout = %q, want a secret alone", out)
	case tt.stdout != "<secret>" && out != tt.stdout:
		t.Errorf("stdout = %q, want %q", out, tt.stdout)
	case !strings.Contains(errOut, tt.stderr):
		t.Errorf("stderr lacks %q:\n%s", tt.stderr, errOut)
	case tt.calls != nil && !slices.Equal(f.Calls(), tt.calls):
		t.Errorf("calls = %q, want %q", f.Calls(), tt.calls)
	}
	// Neither a secret nor a hash on stderr, where the logs and the audit go.
	if secret := strings.TrimSpace(out); tt.stdout == "<secret>" && strings.Contains(errOut, secret) || strings.Contains(errOut, "$2a$") || strings.Contains(errOut, "s3cret") {
		t.Errorf("stderr holds a secret or a hash:\n%s", errOut)
	}
	if tt.check != nil {
		tt.check(t, f, out)
	}
}

func TestClientCommands(t *testing.T) {
	hash := mustHash(t, "old-s3cret")
	ci := func() []store.APIClient {
		return []store.APIClient{{ID: "ci", SecretHash: hash, Scopes: []string{"admin:read"}}}
	}
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := func(t *testing.T, f *fakeStore, id string) store.APIClient {
		t.Helper()
		i := slices.IndexFunc(f.clients, func(c store.APIClient) bool { return c.ID == id })
		if i < 0 {
			t.Fatalf("no client %s: %+v", id, f.clients)
		}
		return f.clients[i]
	}
	for name, tt := range map[string]cliCase{
		"create, the secret generated": {
			args: []string{"client", "create", "ci"}, stdout: "<secret>", stderr: `API client "ci" created. Its secret, generated, is on the standard output`,
			calls: []string{"create client ci by cli", "close"},
			check: func(t *testing.T, f *fakeStore, out string) {
				c := client(t, f, "ci")
				if !domain.SecretMatches(c.SecretHash, strings.TrimSpace(out)) || c.Scopes == nil || len(c.Scopes) != 0 {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"create, the secret from stdin, flags after": {
			args: []string{"client", "create", "ci", "-scopes", "admin:read, admin:flows", "-secret-stdin"}, input: "s3cret\n",
			stderr: `API client "ci" created.`,
			check: func(t *testing.T, f *fakeStore, _ string) {
				if c := client(t, f, "ci"); !domain.SecretMatches(c.SecretHash, "s3cret") || !slices.Equal(c.Scopes, []string{"admin:read", "admin:flows"}) {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"create, the secret from a file, flags before": {
			args: []string{"client", "create", "-secret-file", secretFile, "ci"}, stderr: `API client "ci" created.`,
			check: func(t *testing.T, f *fakeStore, _ string) {
				if c := client(t, f, "ci"); !domain.SecretMatches(c.SecretHash, "s3cret") {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"create, a hash taken as it is": {
			args: []string{"client", "create", "ci", "-secret-stdin"}, input: hash + "\n", stderr: `API client "ci" created.`,
			check: func(t *testing.T, f *fakeStore, _ string) {
				if c := client(t, f, "ci"); c.SecretHash != hash {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"create, an id taken": {
			args: []string{"client", "create", "ci"}, clients: ci(), err: errFailed, stderr: `API client "ci" already exists.`,
		},
		"create, an id refused": {
			args: []string{"client", "create", ".ci"}, err: errFailed, stderr: `API client ".ci": id: ".ci" is not an id`,
		},
		"create, no id":                  {args: []string{"client", "create"}, err: errUsage, stderr: "missing the client id"},
		"create, two ids":                {args: []string{"client", "create", "a", "b"}, err: errUsage, stderr: "an argument too many, not printed"},
		"update, a value to -new-secret": {args: []string{"client", "update", "ci", "-new-secret=s3cret"}, err: errUsage, stderr: "-new-secret takes no value"},
		"create, a secret twice":         {args: []string{"client", "create", "ci", "-secret-stdin", "-secret-file", secretFile}, err: errUsage},
		"create, -secret refused":        {args: []string{"client", "create", "ci", "-secret", "s3cret"}, err: errUsage},
		"update, the scopes": {
			args: []string{"client", "update", "ci", "-scopes", "admin:flows"}, clients: ci(), stderr: `API client "ci" updated.`,
			calls: []string{"update client ci by cli", "close"},
			check: func(t *testing.T, f *fakeStore, _ string) {
				if c := client(t, f, "ci"); c.SecretHash != hash || !slices.Equal(c.Scopes, []string{"admin:flows"}) {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"update, no scope": {
			args: []string{"client", "update", "ci", "-scopes", ""}, clients: ci(),
			check: func(t *testing.T, f *fakeStore, _ string) {
				if c := client(t, f, "ci"); c.Scopes == nil || len(c.Scopes) != 0 {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"update, a new secret": {
			args: []string{"client", "update", "ci", "-new-secret"}, clients: ci(), stdout: "<secret>", stderr: "Its new secret is on the standard output",
			check: func(t *testing.T, f *fakeStore, out string) {
				if c := client(t, f, "ci"); !domain.SecretMatches(c.SecretHash, strings.TrimSpace(out)) || !slices.Equal(c.Scopes, []string{"admin:read"}) {
					t.Errorf("client = %+v", c)
				}
			},
		},
		"update, nothing":           {args: []string{"client", "update", "ci"}, clients: ci(), err: errUsage, stderr: "nothing to update"},
		"update, two secrets":       {args: []string{"client", "update", "ci", "-new-secret", "-secret-stdin"}, err: errUsage, stderr: "exclusive"},
		"update, unknown":           {args: []string{"client", "update", "nope", "-new-secret"}, err: errFailed, stderr: `API client "nope" not found.`},
		"update, a scope refused":   {args: []string{"client", "update", "ci", "-scopes", "admin flows"}, clients: ci(), err: errFailed, stderr: `scopes[0]: "admin flows" contains a space`},
		"delete, out of a terminal": {args: []string{"client", "delete", "ci"}, clients: ci(), stderr: `API client "ci" deleted.`, calls: []string{"read clients", "delete client ci", "close"}},
		// The prompt alone: the audit, written by its queue, may come before
		// the message.
		"delete, asked, yes": {
			args: []string{"client", "delete", "ci"}, terminal: true, input: "y\n", clients: ci(), stderr: `Delete API client "ci"? [y/N] `,
			calls: []string{"read clients", "delete client ci", "close"},
		},
		"delete, asked, no": {
			args: []string{"client", "delete", "ci"}, terminal: true, input: "\n", clients: ci(), stderr: "Nothing deleted.",
			calls: []string{"read clients", "close"},
		},
		"delete, -yes": {args: []string{"client", "delete", "-yes", "ci"}, terminal: true, clients: ci(), stderr: `API client "ci" deleted.`},
		"delete, unknown, never asked": {
			args: []string{"client", "delete", "nope"}, terminal: true, err: errFailed, stderr: `API client "nope" not found.`,
			calls: []string{"read clients", "close"},
		},
		"list": {
			args: []string{"client", "list"}, clients: append(ci(), store.APIClient{ID: "none", SecretHash: hash, Scopes: []string{}}),
			stdout: "ID    SCOPES\nci    admin:read\nnone  \n",
		},
		"list, empty":         {args: []string{"client", "list"}, stdout: "", stderr: "No API clients."},
		"list, json":          {args: []string{"client", "list", "-format", "json"}, clients: ci(), stdout: "[\n  {\n    \"id\": \"ci\",\n    \"scopes\": [\n      \"admin:read\"\n    ]\n  }\n]\n"},
		"list, json, empty":   {args: []string{"client", "list", "-format", "json"}, stdout: "[]\n"},
		"list, a format":      {args: []string{"client", "list", "-format", "yaml"}, err: errUsage},
		"no subcommand":       {args: []string{"client"}, err: errUsage, stderr: "Usage: hydra-dispatcher client <command>"},
		"unknown subcommand":  {args: []string{"client", "rotate"}, err: errUsage, stderr: `unknown command "client rotate"`},
		"help of the command": {args: []string{"client", "-h"}, stderr: "Usage: hydra-dispatcher client <command>"},
	} {
		t.Run(name, tt.run)
	}
}

// The audit of a write of the CLI: the client cli, the command, the names of
// the fields, never a value.
func TestClientCommandAudit(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	_, errOut, err := runCLI(t, &fakeStore{}, false, "s3cret\n", nil, "client", "create", "ci", "-secret-stdin", "-scopes", "admin:read")
	if err != nil {
		t.Fatal(err)
	}
	var line map[string]any
	for l := range strings.Lines(errOut) {
		if strings.Contains(l, `"msg":"admin.write"`) {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatal(err)
			}
		}
	}
	if line["log_type"] != "audit" || line["client_id"] != "cli" || line["resource"] != "oauth2-clients" || line["id"] != "ci" ||
		line["command"] != "client create" || len(line["fields"].([]any)) != 2 || strings.Contains(errOut, "admin:read") {
		t.Errorf("audit: %v\n%s", line, errOut)
	}
}

func TestAdminCommands(t *testing.T) {
	hash := mustHash(t, "old-s3cret")
	alice := func() []store.AdminUser {
		return []store.AdminUser{{Username: "alice", PasswordHash: hash, Role: domain.RoleAdmin}}
	}
	account := func(t *testing.T, f *fakeStore, name string) store.AdminUser {
		t.Helper()
		i := slices.IndexFunc(f.admins, func(u store.AdminUser) bool { return u.Username == name })
		if i < 0 {
			t.Fatalf("no account %s: %+v", name, f.admins)
		}
		return f.admins[i]
	}
	for name, tt := range map[string]cliCase{
		"create, asked twice": {
			args: []string{"admin", "create", "bob", "-role", "viewer"}, terminal: true, answers: []string{"s3cret", "s3cret"},
			stderr: "Password: \nPassword again: \n", calls: []string{"create admin bob viewer", "close"},
			check: func(t *testing.T, f *fakeStore, _ string) {
				if u := account(t, f, "bob"); !domain.SecretMatches(u.PasswordHash, "s3cret") || u.Role != domain.RoleViewer {
					t.Errorf("account = %+v", u)
				}
			},
		},
		"create, from stdin": {
			args: []string{"admin", "create", "-role", "admin", "-password-stdin", "bob"}, input: "s3cret\n", stderr: `Admin account "bob" created.`,
			check: func(t *testing.T, f *fakeStore, _ string) {
				if u := account(t, f, "bob"); !domain.SecretMatches(u.PasswordHash, "s3cret") || u.Role != domain.RoleAdmin {
					t.Errorf("account = %+v", u)
				}
			},
		},
		"create, a hash is a password": {
			args: []string{"admin", "create", "bob", "-role", "admin", "-password-stdin"}, input: hash + "\n",
			check: func(t *testing.T, f *fakeStore, _ string) {
				if u := account(t, f, "bob"); u.PasswordHash == hash || !domain.SecretMatches(u.PasswordHash, hash) {
					t.Errorf("account = %+v", u)
				}
			},
		},
		"create, the two passwords differ": {
			args: []string{"admin", "create", "bob", "-role", "admin"}, terminal: true, answers: []string{"s3cret", "s3cre"}, err: errOther,
			calls: []string{},
		},
		"create, no role":             {args: []string{"admin", "create", "bob"}, err: errUsage, stderr: "missing -role: admin or viewer"},
		"create, a role unknown":      {args: []string{"admin", "create", "bob", "-role", "super_admin"}, err: errUsage, stderr: `-role "super_admin": admin or viewer`},
		"create, no password, no tty": {args: []string{"admin", "create", "bob", "-role", "admin"}, err: errUsage, stderr: "no password: give -password-stdin or -password-file"},
		"create, -password refused":   {args: []string{"admin", "create", "bob", "-role", "admin", "-password", "x"}, err: errUsage},
		// Symfony's form, the password after the name: refused, not printed
		// (revue R37).
		"create, Symfony's password argument": {args: []string{"admin", "create", "alice", "s3cret-pass", "-role", "admin"}, err: errUsage, stderr: "not printed", calls: []string{}},
		"update, a value to -password":        {args: []string{"admin", "update", "alice", "-password=s3cret-pass"}, err: errUsage, stderr: "-password takes no value", calls: []string{}},
		"update, a value to -password-stdin":  {args: []string{"admin", "update", "alice", "-password-stdin=s3cret-pass"}, err: errUsage, calls: []string{}},
		"create, a name taken":                {args: []string{"admin", "create", "alice", "-role", "admin", "-password-stdin"}, input: "s3cret", admins: alice(), err: errFailed, stderr: `Admin account "alice" already exists.`},
		"create, a name refused":              {args: []string{"admin", "create", "bob ", "-role", "admin", "-password-stdin"}, input: "s3cret", err: errFailed, stderr: `username: "bob " starts or ends with a space`},
		"update, the role of the last":        {args: []string{"admin", "update", "alice", "-role", "viewer"}, admins: alice(), err: errFailed, stderr: `Admin account "alice": the last admin account keeps the admin role.`},
		"update, the password asked": {
			args: []string{"admin", "update", "alice", "-password"}, terminal: true, answers: []string{"s3cret", "s3cret"}, admins: alice(), stderr: `Admin account "alice" updated.`,
			check: func(t *testing.T, f *fakeStore, _ string) {
				if u := account(t, f, "alice"); !domain.SecretMatches(u.PasswordHash, "s3cret") || u.Role != domain.RoleAdmin {
					t.Errorf("account = %+v", u)
				}
			},
		},
		"update, the role": {
			args: []string{"admin", "update", "bob", "-role", "admin"}, admins: append(alice(), store.AdminUser{Username: "bob", Role: domain.RoleViewer}),
			check: func(t *testing.T, f *fakeStore, _ string) {
				if u := account(t, f, "bob"); u.Role != domain.RoleAdmin || u.PasswordHash != "" {
					t.Errorf("account = %+v", u)
				}
			},
		},
		"update, nothing":        {args: []string{"admin", "update", "alice"}, err: errUsage, stderr: "nothing to update"},
		"update, two passwords":  {args: []string{"admin", "update", "alice", "-password", "-password-stdin"}, err: errUsage, stderr: "exclusive"},
		"update, unknown":        {args: []string{"admin", "update", "bob", "-role", "admin"}, admins: alice(), err: errFailed, stderr: `Admin account "bob" not found.`},
		"update, a role unknown": {args: []string{"admin", "update", "alice", "-role", "root"}, err: errUsage},
		"list": {
			args: []string{"admin", "list"}, admins: append(alice(), store.AdminUser{Username: "bob", OIDCSub: "248289761001", Role: domain.RoleViewer}),
			stdout: "USERNAME  ROLE    PASSWORD  OIDC  CREATED\nalice     admin   yes       no    0001-01-01T00:00:00Z\nbob       viewer  no        yes   0001-01-01T00:00:00Z\n",
		},
		"list, json":  {args: []string{"admin", "list", "-format", "json"}, admins: alice(), stdout: "[\n  {\n    \"username\": \"alice\",\n    \"role\": \"admin\",\n    \"password\": true,\n    \"oidc\": false,\n    \"created_at\": \"0001-01-01T00:00:00Z\"\n  }\n]\n"},
		"list, empty": {args: []string{"admin", "list"}, stderr: "No admin accounts."},
	} {
		t.Run(name, tt.run)
	}
}

// bootstrap -create-admin: the name alone, the password never in an argument
// (Q113); an account that exists is left as it is, as Symfony did; nothing is
// asked of a dry run.
func TestBootstrapCreateAdmin(t *testing.T) {
	hash := mustHash(t, "old-s3cret")
	alice := []store.AdminUser{{Username: "alice", PasswordHash: hash, Role: domain.RoleViewer}}
	created := func(t *testing.T, f *fakeStore, _ string) {
		i := slices.IndexFunc(f.admins, func(u store.AdminUser) bool { return u.Username == "alice" })
		if i < 0 || !domain.SecretMatches(f.admins[i].PasswordHash, "s3cret") || f.admins[i].Role != domain.RoleAdmin {
			t.Errorf("accounts = %+v", f.admins)
		}
	}
	for name, tt := range map[string]cliCase{
		"created": {
			args: []string{"bootstrap", "-create-admin", "alice", "-password-stdin"}, input: "s3cret\n",
			stdout: "empty seed, empty database\n", stderr: `Admin account "alice" created.`,
			calls: []string{"read admins", "bootstrap missing write", "create admin alice admin", "close"}, check: created,
		},
		"asked twice": {
			args: []string{"bootstrap", "-create-admin", "alice"}, terminal: true, answers: []string{"s3cret", "s3cret"},
			stdout: "empty seed, empty database\n", stderr: `Admin account "alice" created.`, check: created,
		},
		"exists, nothing asked": {
			args: []string{"bootstrap", "-create-admin", "alice"}, admins: alice,
			stdout: "empty seed, empty database\n", stderr: `Admin account "alice" exists: left as it is.`,
			calls: []string{"read admins", "bootstrap missing write", "close"},
		},
		"dry run, nothing asked": {
			args:   []string{"bootstrap", "-dry-run", "-create-admin", "alice"},
			stdout: "empty seed, empty database\n", stderr: `Admin account "alice" would be created.`,
			calls: []string{"read admins", "bootstrap missing dry", "close"},
		},
		"Symfony's user:pass": {
			args: []string{"bootstrap", "-create-admin", "admin:admin"}, err: errUsage,
			stderr: "-create-admin takes the name alone: the password comes from the terminal, -password-stdin or -password-file", calls: []string{},
		},
		"a password without an account": {args: []string{"bootstrap", "-password-stdin"}, err: errUsage, stderr: "go with -create-admin"},
		"a password after the name":     {args: []string{"bootstrap", "-create-admin", "alice", "s3cret-pass"}, err: errUsage, stderr: "not printed", calls: []string{}},
		"no password out of a terminal": {
			args: []string{"bootstrap", "-create-admin", "alice"}, err: errUsage, stderr: "no password",
			calls: []string{"read admins", "close"},
		},
		"a name refused": {
			args: []string{"bootstrap", "-create-admin", "alice "}, err: errFailed, stderr: `Admin account "alice ": username:`, calls: []string{},
		},
	} {
		t.Run(name, tt.run)
	}

	// -force asked in a terminal, and refused: no account either.
	keepLoggers(t)
	commandEnv(t)
	f := &fakeStore{changes: someChanges}
	_, errOut, err := runCLI(t, f, true, "n\n", []string{"s3cret", "s3cret"}, "bootstrap", "-force", "-create-admin", "alice")
	if err != nil || len(f.admins) != 0 || !strings.Contains(errOut, "Nothing written.") {
		t.Errorf("refused: %v, accounts %+v\n%s", err, f.admins, errOut)
	}
}

// config diff: the changes alone on stdout; exit 0 for nothing to write, 1
// for changes, 2 in error.
func TestConfigCommands(t *testing.T) {
	unchanged := []store.Change{{Kind: "app", ID: "hydra-sql", Action: store.Same}, {Kind: "flow", ID: "legacy", Action: store.Absent}}
	for name, tt := range map[string]struct {
		cliCase
		changes []store.Change
	}{
		"changes":          {cliCase{args: []string{"config", "diff"}, err: errFailed, stdout: printed(someChanges), calls: []string{"diff", "close"}}, someChanges},
		"nothing to write": {cliCase{args: []string{"config", "diff"}, stdout: printed(unchanged)}, unchanged},
		"json": {cliCase{args: []string{"config", "diff", "-format", "json"}, err: errFailed, stdout: `[
  {
    "kind": "setting",
    "id": "remember",
    "action": "reset",
    "fields": [
      {
        "name": "value",
        "old": false,
        "new": true
      }
    ]
  },
  {
    "kind": "api_client",
    "id": "test",
    "action": "keep",
    "fields": [
      {
        "name": "secret",
        "secret": true
      }
    ]
  }
]
`}, []store.Change{someChanges[0], someChanges[2]}},
		"json, nothing": {cliCase{args: []string{"config", "diff", "-format", "json"}, stdout: "[]\n"}, nil},
		"a format":      {cliCase{args: []string{"config", "diff", "-format", "yaml"}, err: errUsage}, nil},
		"a section":     {cliCase{args: []string{"config", "dump", "-section", "apps,accounts"}, err: errUsage, stderr: `-section "accounts"`}, nil},
		"no command":    {cliCase{args: []string{"config"}, err: errUsage, stderr: "Usage: hydra-dispatcher config <command>"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			keepLoggers(t)
			commandEnv(t)
			f := &fakeStore{changes: tt.changes}
			out, errOut, err := runCLI(t, f, false, "", nil, tt.args...)
			if !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) || out != tt.stdout || !strings.Contains(errOut, tt.stderr) ||
				tt.calls != nil && !slices.Equal(f.Calls(), tt.calls) {
				t.Errorf("err = %v, calls = %q, stdout:\n%s\nstderr:\n%s", err, f.Calls(), out, errOut)
			}
		})
	}

	keepLoggers(t)
	commandEnv(t)
	_, _, err := runCLI(t, &fakeStore{bootstrapErr: errors.New("diff: read apps: connection refused")}, false, "", nil, "config", "diff")
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != 2 || errors.Is(err, errFailed) {
		t.Errorf("an error: %v, want exit 2", err)
	}

	// The sections asked alone.
	f := &fakeStore{apps: []store.App{{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", Method: "pwd", AuthMode: "network"}}}
	out, _, err := runCLI(t, f, false, "", nil, "config", "dump", "-section", "apps")
	if err != nil || !strings.HasSuffix(out, "dispatcher:\n  apps:\n    - id: sql\n      login_url: http://sql/login\n      consent_url: http://sql/consent\n      method: pwd\n      auth_mode: network\n      receive_claims: null\n") {
		t.Errorf("dump: %v\n%s", err, out)
	}
}
