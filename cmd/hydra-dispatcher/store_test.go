package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/config"
	"github.com/Cadoles/hydra-dispatcher-go/internal/domain"
	"github.com/Cadoles/hydra-dispatcher-go/internal/secretbox"
	"github.com/Cadoles/hydra-dispatcher-go/internal/store"
)

// The tests of the commands run without Postgres: openStore gives them a
// fake, in the child processes of TestMainProcess too.
func init() {
	openStore = func(context.Context, string) (configStore, error) { return &fakeStore{}, nil }
}

// fakeStore records what the commands ask of the store.
type fakeStore struct {
	mu      sync.Mutex
	calls   []string // migrate, bootstrap <mode> <write>, close
	applied []string
	changes []store.Change
	pingErr error

	// snapshotErr fails Snapshot, the first one of serve included.
	snapshotErr error
	// warnings, apps and debug are those of the snapshots.
	warnings []string
	apps     []store.App
	debug    *store.DebugWindow
	// deadlines are the time left to the first migrate, bootstrap and
	// snapshot, when their context has a deadline.
	deadlines map[string]time.Duration
	// migrateErr and bootstrapErr fail Migrate and Bootstrap.
	migrateErr, bootstrapErr error
	// last is the migration MigrateDown rolls back, "" for none; downErr
	// fails it.
	last    string
	downErr error
	// written are the changes of a write when they differ from those of a
	// dry run: the database changed in between.
	written []store.Change
	// keys are those of SetSecrets; encrypted, the settings it holds
	// encrypted, which Rekey turns to the active key.
	keys      *secretbox.Keys
	encrypted []store.EncryptedSetting
	// check is that of SetCheck, committed that of OnCommit.
	check     func(*store.Snapshot) error
	committed func(context.Context)

	// clients and admins are those the CLI reads and writes, as the store
	// does: its rules, ErrExists, ErrNotFound, ErrLastAdmin. writeErr fails
	// their writes.
	clients  []store.APIClient
	admins   []store.AdminUser
	writeErr error
}

func (f *fakeStore) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeStore) deadline(ctx context.Context, call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := ctx.Deadline(); ok && f.deadlines[call] == 0 {
		if f.deadlines == nil {
			f.deadlines = map[string]time.Duration{}
		}
		f.deadlines[call] = time.Until(d)
	}
}

func (f *fakeStore) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeStore) Snapshot(ctx context.Context) (*store.Snapshot, error) {
	f.deadline(ctx, "snapshot")
	if f.snapshotErr != nil {
		return nil, f.snapshotErr
	}
	snap := store.NewSnapshot(f.apps, nil, store.DefaultSettings())
	snap.Warnings = f.warnings
	snap.Debug = f.debug
	return snap, nil
}

func (f *fakeStore) Ping(context.Context) error { return f.pingErr }

func (f *fakeStore) Close() error {
	f.record("close")
	return nil
}

func (f *fakeStore) Migrate(ctx context.Context) ([]string, error) {
	f.deadline(ctx, "migrate")
	f.record("migrate")
	return f.applied, f.migrateErr
}

func (f *fakeStore) LastMigration(context.Context) (string, error) {
	f.record("last")
	return f.last, nil
}

func (f *fakeStore) MigrateDown(context.Context) (string, error) {
	f.record("down")
	return f.last, f.downErr
}

func (f *fakeStore) Bootstrap(ctx context.Context, _ config.Seed, mode store.Mode, write bool) ([]store.Change, error) {
	f.deadline(ctx, "bootstrap")
	name := map[store.Mode]string{store.Missing: "missing", store.Force: "force"}[mode]
	f.record("bootstrap " + name + " " + map[bool]string{true: "write", false: "dry"}[write])
	switch {
	case f.bootstrapErr != nil:
		return nil, f.bootstrapErr
	case write && f.written != nil:
		return f.written, nil
	}
	return f.changes, nil
}

// SetCheck keeps check, which the fake never calls.
func (f *fakeStore) SetCheck(check func(*store.Snapshot) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.check = check
}

// OnCommit keeps committed, which the fake never calls.
func (f *fakeStore) OnCommit(committed func(context.Context)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.committed = committed
}

// Listen records that serve listens, then waits for the end of ctx.
func (f *fakeStore) Listen(ctx context.Context, _ func(), _ *slog.Logger) {
	f.record("listen")
	<-ctx.Done()
}

// useStore makes openStore give f for the length of t.
func useStore(t *testing.T, f *fakeStore) {
	old := openStore
	openStore = func(context.Context, string) (configStore, error) { return f, nil }
	t.Cleanup(func() { openStore = old })
}

// commandEnv sets the least configuration the commands accept.
func commandEnv(t *testing.T, extra ...string) {
	for _, kv := range append(append(requiredEnv("http://127.0.0.1:1"), configEnv+"="), extra...) {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
}

var someChanges = []store.Change{
	{Kind: "setting", ID: "remember", Action: store.Reset, Fields: []store.FieldChange{{Name: "value", Old: "false", New: "true"}}},
	{Kind: "app", ID: "hydra-sql", Action: store.Update, Fields: []store.FieldChange{
		{Name: "login_url", Old: `"http://old"`, New: `"http://new"`},
		{Name: "receive_claims", Old: `null`, New: `["email"]`},
	}},
	{Kind: "api_client", ID: "test", Action: store.Keep, Fields: []store.FieldChange{{Name: "secret", Secret: true}}},
	{Kind: "flow", ID: "hydra-sql", Action: store.Same},
	{Kind: "flow", ID: "legacy", Action: store.Absent},
}

// widened gives every claim to an app that had a list, and would to another
// without -force.
var widened = []store.Change{
	{Kind: "app", ID: "hydra-otp", Action: store.Update, Fields: []store.FieldChange{{Name: "receive_claims", Old: `["email"]`, New: `null`}}},
	{Kind: "app", ID: "hydra-kept", Action: store.Keep, Fields: []store.FieldChange{{Name: "receive_claims", Old: `[]`, New: `null`}}},
}

func TestPrintChanges(t *testing.T) {
	var out bytes.Buffer
	printChanges(&out, someChanges)
	want := `reset   setting remember (back to its default)
          value: false -> true
update  app hydra-sql
          login_url: "http://old" -> "http://new"
          receive_claims: null -> ["email"]
keep    api_client test (left as it is without -force)
          secret: changed
same    flow hydra-sql
absent  flow legacy (in the database only: kept)
update 1, reset 1, keep 1, same 1, absent 1
`
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
	if writes(someChanges[2:]) || !writes(someChanges[:1]) {
		t.Error("writes: wrong")
	}
	out.Reset()
	printChanges(&out, append(widened[:2:2], store.Change{Kind: "flow", ID: "f", Action: store.Update, Fields: []store.FieldChange{{Name: "icon_url", Old: `{"":"http://i"}`, New: "null"}}}))
	want = `update  app hydra-otp
          receive_claims: ["email"] -> null (every claim)
keep    app hydra-kept (left as it is without -force)
          receive_claims: [] -> null (every claim)
update  flow f
          icon_url: {"":"http://i"} -> null
update 2, keep 1
`
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	printChanges(&out, overwrites)
	want = `update  app hydra-sql (written by admin:alice)
          method: "pwd" -> "otp"
reset   setting remember (back to its default) (written by api_client:c)
          value: false -> true
update 1, reset 1
`
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

// overwrites replace what an admin and an API client wrote.
var overwrites = []store.Change{
	{Kind: "app", ID: "hydra-sql", Action: store.Update, By: "admin:alice", Fields: []store.FieldChange{{Name: "method", Old: `"pwd"`, New: `"otp"`}}},
	{Kind: "setting", ID: "remember", Action: store.Reset, By: "api_client:c", Fields: []store.FieldChange{{Name: "value", Old: "false", New: "true"}}},
}

// A row another than bootstrap wrote, replaced, warns once written, by
// bootstrap or by serve, with its author and without its values (Q100).
func TestOverwritesWarn(t *testing.T) {
	keepLoggers(t)
	const msg = `"msg":"bootstrap.overwrites"`
	warned := func(logs string) bool {
		return strings.Count(logs, msg) == 2 && strings.Contains(logs, `"kind":"app","id":"hydra-sql","action":"update","by":"admin:alice"`) &&
			strings.Contains(logs, `"kind":"setting","id":"remember","action":"reset","by":"api_client:c"`) && !strings.Contains(logs, "otp")
	}
	commandEnv(t)
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"-force"}, true},
		{[]string{"-force", "-dry-run"}, false},
	} {
		stdinFrom(t, "", false)
		useStore(t, &fakeStore{changes: overwrites})
		var err error
		stderr := stderrOf(t, func() {
			_ = stdoutOf(t, func() { err = run(context.Background(), append([]string{"bootstrap"}, tt.args...), io.Discard) })
		})
		if err != nil || warned(stderr) != tt.want || strings.Contains(stderr, msg) != tt.want {
			t.Errorf("bootstrap %q: err = %v, stderr:\n%s", tt.args, err, stderr)
		}
	}
	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_SERVE_BOOTSTRAP=force")
	useStore(t, &fakeStore{changes: overwrites})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	if logs := stdoutOf(t, func() { err = serve(ctx, nil) }); err != nil || !warned(logs) {
		t.Errorf("serve: err = %v, logs:\n%s", err, logs)
	}
}

// The commands give the store what serve refuses of a snapshot on their
// configuration: bootstrap writes no seed serve would refuse.
func TestOpenConfigCheck(t *testing.T) {
	keepLoggers(t)
	hooks := store.DefaultSettings()
	hooks.LoginAcceptWebhookURL = "http://hooks/login"
	snap := store.NewSnapshot(nil, nil, hooks)
	for _, tt := range []struct {
		env  []string
		want string
	}{
		{nil, "tls.allow_http"},
		{[]string{"DISPATCHER_TLS_ALLOW_HTTP=true"}, "secrets.webhook_signing_key"},
		{[]string{"DISPATCHER_TLS_ALLOW_HTTP=true", "DISPATCHER_SECRETS_WEBHOOK_SIGNING_KEY=" + strings.Repeat("ef", 32)}, ""},
	} {
		commandEnv(t, tt.env...)
		stdinFrom(t, "", false)
		f := &fakeStore{}
		useStore(t, f)
		_ = stderrOf(t, func() {
			_ = stdoutOf(t, func() {
				if err := run(context.Background(), []string{"bootstrap"}, io.Discard); err != nil {
					t.Fatal(err)
				}
			})
		})
		if f.check == nil {
			t.Fatalf("%q: no check", tt.env)
		}
		if err := f.check(snap); tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%q: check = %v, want %q", tt.env, err, tt.want)
		}
	}
}

func TestMigrateCommand(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	f := &fakeStore{applied: []string{"00001_schema.sql"}}
	useStore(t, f)
	var err error
	logs := stdoutOf(t, func() { err = run(context.Background(), []string{"migrate"}, io.Discard) })
	if err != nil || !slices.Equal(f.Calls(), []string{"migrate", "close"}) || !strings.Contains(logs, `"msg":"store.migrated"`) ||
		!strings.Contains(logs, `"migration":"00001_schema.sql"`) {
		t.Errorf("err = %v, calls = %q, logs:\n%s", err, f.Calls(), logs)
	}
}

// migrate down rolls back one migration: without a question out of a terminal
// or with -yes, after naming it in one.
func TestMigrateDownCommand(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	const name = "00003_app_receive_claims.sql"
	for _, tt := range []struct {
		name     string
		args     []string
		terminal bool
		answer   string
		last     string
		calls    []string
		log      string
		stderr   string
	}{
		{"out of a terminal", nil, false, "", name, []string{"down", "close"}, `"msg":"store.rolled_back"`, ""},
		{"-yes", []string{"-yes"}, true, "", name, []string{"down", "close"}, `"migration":"` + name + `"`, ""},
		{"confirmed", nil, true, "y\n", name, []string{"last", "down", "close"}, `"msg":"store.rolled_back"`, "Roll back " + name + "? [y/N] "},
		{"declined", nil, true, "n\n", name, []string{"last", "close"}, "", "Roll back " + name + "? [y/N] Nothing rolled back.\n"},
		{"no answer", nil, true, "", name, []string{"last", "close"}, "", "Nothing rolled back.\n"},
		{"nothing applied", nil, true, "", "", []string{"last", "down", "close"}, `"msg":"store.nothing_to_roll_back"`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stdinFrom(t, tt.answer, tt.terminal)
			f := &fakeStore{last: tt.last}
			useStore(t, f)
			var err error
			var logs string
			stderr := stderrOf(t, func() {
				logs = stdoutOf(t, func() { err = run(context.Background(), append([]string{"migrate", "down"}, tt.args...), io.Discard) })
			})
			if err != nil || !slices.Equal(f.Calls(), tt.calls) || !strings.Contains(logs, tt.log) || !strings.HasSuffix(stderr, tt.stderr) {
				t.Errorf("err = %v, calls = %q, logs:\n%s\nstderr:\n%s", err, f.Calls(), logs, stderr)
			}
		})
	}
	// A failure closes the store and reaches the caller; an argument is refused.
	stdinFrom(t, "", false)
	f := &fakeStore{last: name, downErr: errors.New("migrate down: the last migration of the database is unknown to this version")}
	useStore(t, f)
	var err error
	_ = stdoutOf(t, func() { err = run(context.Background(), []string{"migrate", "down"}, io.Discard) })
	if err == nil || !strings.Contains(err.Error(), "unknown to this version") || !slices.Equal(f.Calls(), []string{"down", "close"}) {
		t.Errorf("err = %v, calls = %q", err, f.Calls())
	}
	_ = stderrOf(t, func() {
		if err := run(context.Background(), []string{"migrate", "sideways"}, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("migrate sideways: err = %v", err)
		}
	})
}

// A list that becomes NULL warns once written, by bootstrap or by serve, and
// the warning keeps the list: the database no longer does. A change left as it
// is, or a dry run, writes nothing and does not warn.
func TestWidenedClaimsWarn(t *testing.T) {
	keepLoggers(t)
	const msg, list = `"msg":"bootstrap.claims_widened"`, `"id":"hydra-otp","was":"[\"email\"]"`
	warned := func(logs string) bool {
		return strings.Contains(logs, msg) && strings.Contains(logs, list) && strings.Count(logs, msg) == 1
	}
	commandEnv(t)
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"-force"}, true},
		{[]string{"-force", "-dry-run"}, false},
	} {
		stdinFrom(t, "", false)
		useStore(t, &fakeStore{changes: widened})
		var err error
		stderr := stderrOf(t, func() {
			_ = stdoutOf(t, func() { err = run(context.Background(), append([]string{"bootstrap"}, tt.args...), io.Discard) })
		})
		if err != nil || warned(stderr) != tt.want || strings.Contains(stderr, msg) != tt.want {
			t.Errorf("bootstrap %q: err = %v, stderr:\n%s", tt.args, err, stderr)
		}
	}
	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_SERVE_BOOTSTRAP=force")
	useStore(t, &fakeStore{changes: widened})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	if logs := stdoutOf(t, func() { err = serve(ctx, nil) }); err != nil || !warned(logs) {
		t.Errorf("serve: err = %v, logs:\n%s", err, logs)
	}
}

// stdinFrom makes bootstrap read answers, from a terminal or not.
func stdinFrom(t *testing.T, answers string, terminal bool) {
	oldStdin, oldTerminal := stdin, stdinIsTerminal
	stdin, stdinIsTerminal = strings.NewReader(answers), func() bool { return terminal }
	t.Cleanup(func() { stdin, stdinIsTerminal = oldStdin, oldTerminal })
}

func TestBootstrapCommand(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	unchanged := []store.Change{{Kind: "app", ID: "hydra-sql", Action: store.Same}}
	written := []store.Change{{Kind: "app", ID: "hydra-sql", Action: store.Update, Fields: []store.FieldChange{{Name: "method", Old: `"pwd"`, New: `"otp"`}}}}
	for _, tt := range []struct {
		args     []string
		terminal bool
		answer   string
		changes  []store.Change
		written  []store.Change
		calls    []string
		// stdout is what it holds, stderr what it ends with.
		stdout, stderr string
	}{
		{nil, true, "", someChanges, nil, []string{"bootstrap missing write", "close"}, printed(someChanges), ""},
		{[]string{"-dry-run"}, true, "", someChanges, nil, []string{"bootstrap missing dry", "close"}, printed(someChanges), ""},
		{[]string{"-force", "-dry-run"}, true, "", someChanges, nil, []string{"bootstrap force dry", "close"}, printed(someChanges), ""},
		// Out of a terminal, as in a container, -force writes without asking.
		{[]string{"-force"}, false, "", someChanges, nil, []string{"bootstrap force write", "close"}, printed(someChanges), ""},
		{[]string{"-force", "-yes"}, true, "", someChanges, nil, []string{"bootstrap force write", "close"}, printed(someChanges), ""},
		// In one, it shows the changes and asks, once.
		{[]string{"-force"}, true, "y\n", someChanges, nil, []string{"bootstrap force dry", "bootstrap force write", "close"},
			printed(someChanges), "Write these changes? [y/N] Written.\n"},
		{[]string{"-force"}, true, "n\n", someChanges, nil, []string{"bootstrap force dry", "close"},
			printed(someChanges), "Write these changes? [y/N] Nothing written.\n"},
		// Nothing to write: no question.
		{[]string{"-force"}, true, "", unchanged, nil, []string{"bootstrap force dry", "close"}, printed(unchanged), ""},
		// The database changed after the question: what was written instead.
		{[]string{"-force"}, true, "y\n", someChanges, written, []string{"bootstrap force dry", "bootstrap force write", "close"},
			printed(someChanges) + printed(written), "The database changed after the question; written instead:\n"},
	} {
		stdinFrom(t, tt.answer, tt.terminal)
		f := &fakeStore{changes: tt.changes, written: tt.written}
		useStore(t, f)
		var err error
		var stdout string
		stderr := stderrOf(t, func() {
			stdout = stdoutOf(t, func() { err = run(context.Background(), append([]string{"bootstrap"}, tt.args...), io.Discard) })
		})
		// The configuration warnings go to stderr, the changes alone to stdout.
		if err != nil || !slices.Equal(f.Calls(), tt.calls) || stdout != tt.stdout ||
			!strings.Contains(stderr, `"msg":"config.warning"`) || !strings.HasSuffix(stderr, tt.stderr) {
			t.Errorf("bootstrap %q: err = %v, calls = %q, stdout:\n%s\nstderr:\n%s", tt.args, err, f.Calls(), stdout, stderr)
		}
	}
}

func printed(changes []store.Change) string {
	var b bytes.Buffer
	printChanges(&b, changes)
	return b.String()
}

// A failed bootstrap still closes the store.
func TestBootstrapCommandFails(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	stdinFrom(t, "", false)
	f := &fakeStore{bootstrapErr: errors.New("bootstrap: setting default_locale: \"de\" has no catalog")}
	useStore(t, f)
	var err error
	_ = stderrOf(t, func() { err = run(context.Background(), []string{"bootstrap", "-force"}, io.Discard) })
	if err == nil || !strings.Contains(err.Error(), "has no catalog") || !slices.Equal(f.Calls(), []string{"bootstrap force write", "close"}) {
		t.Errorf("err = %v, calls = %q", err, f.Calls())
	}
}

func TestConfirm(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "YES\n": true, "\n": false, "n\n": false, "": false} {
		var question bytes.Buffer
		if got := confirm(strings.NewReader(answer), &question, "Write?"); got != want || question.String() != "Write? [y/N] " {
			t.Errorf("%q: %v, question %q", answer, got, question.String())
		}
	}
}

// serve migrates and bootstraps before it listens, as serve.migrate and
// serve.bootstrap ask, and closes the store when it stops.
func TestServePreparesStore(t *testing.T) {
	keepLoggers(t)
	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_SERVE_MIGRATE=true", "DISPATCHER_SERVE_BOOTSTRAP=force")
	f := &fakeStore{changes: someChanges}
	useStore(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	logs := stdoutOf(t, func() { err = serve(ctx, nil) })
	if err != nil || !slices.Equal(f.Calls(), []string{"migrate", "bootstrap force write", "listen", "close"}) {
		t.Fatalf("err = %v, calls = %q", err, f.Calls())
	}
	if f.committed == nil || f.check == nil {
		t.Error("serve gave the store no hook of commit, or no check")
	}
	for _, want := range []string{
		`"msg":"bootstrap.change"`, `"kind":"app","id":"hydra-sql","action":"update","fields":["login_url","receive_claims"]`,
		`"msg":"bootstrap.done"`, `"mode":"force","summary":"update 1, reset 1, keep 1, same 1, absent 1"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %s in:\n%s", want, logs)
		}
	}
	// A change left as it is logged, an unchanged one is not; a change
	// without fields has none. The values stay out.
	if strings.Contains(logs, `"action":"same"`) || strings.Index(logs, "bootstrap.done") > strings.Index(logs, "server.started") ||
		!strings.Contains(logs, `"kind":"flow","id":"legacy","action":"absent"}`) || strings.Contains(logs, "http://new") {
		t.Errorf("logs:\n%s", logs)
	}
}

// serve gives its migrations, its bootstrap and its first read a time limit:
// a database that took the connection and no longer answers stops it.
func TestServeStartupDeadlines(t *testing.T) {
	keepLoggers(t)
	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_SERVE_MIGRATE=true", "DISPATCHER_SERVE_BOOTSTRAP=missing")
	f := &fakeStore{}
	useStore(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	_ = stdoutOf(t, func() { err = serve(ctx, nil) })
	if err != nil {
		t.Fatal(err)
	}
	for call, want := range map[string]time.Duration{"migrate": migrateTimeout, "bootstrap": startupTimeout, "snapshot": startupTimeout} {
		if left := f.deadlines[call]; left <= want-5*time.Second || left > want {
			t.Errorf("%s: %v left, want %v", call, left, want)
		}
	}
}

// Without a database, serve does not start.
func TestServeWithoutDatabase(t *testing.T) {
	keepLoggers(t)
	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0")
	old := openStore
	openStore = func(context.Context, string) (configStore, error) {
		return nil, errors.New("database: connection refused")
	}
	t.Cleanup(func() { openStore = old })
	var err error
	logs := stdoutOf(t, func() { err = serve(context.Background(), nil) })
	if err == nil || !strings.Contains(err.Error(), "connection refused") || strings.Contains(logs, "server.started") {
		t.Errorf("err = %v, logs:\n%s", err, logs)
	}
}

func (f *fakeStore) APIClients(context.Context) ([]store.APIClient, error) {
	f.record("read clients")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.clients), nil
}

func (f *fakeStore) CreateAPIClient(_ context.Context, by string, c store.APIClient) error {
	f.record("create client " + c.ID + " by " + by)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.writeErr != nil:
		return f.writeErr
	case slices.ContainsFunc(f.clients, func(x store.APIClient) bool { return x.ID == c.ID }):
		return store.ErrExists
	}
	if v := domain.Collect(c.Check); v != nil {
		return v
	}
	f.clients = append(f.clients, c)
	return nil
}

func (f *fakeStore) UpdateAPIClient(_ context.Context, by, id string, change func(*store.APIClient) error) error {
	f.record("update client " + id + " by " + by)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	c := f.clients[i]
	c.Scopes = slices.Clone(c.Scopes)
	if err := change(&c); err != nil {
		return err
	}
	if v := domain.Collect(c.Check); v != nil {
		return v
	}
	f.clients[i] = c
	return f.writeErr
}

func (f *fakeStore) DeleteAPIClient(_ context.Context, id string) error {
	f.record("delete client " + id)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.clients, func(x store.APIClient) bool { return x.ID == id })
	if i < 0 {
		return store.ErrNotFound
	}
	f.clients = slices.Delete(f.clients, i, i+1)
	return nil
}

func (f *fakeStore) Admins(context.Context) ([]store.AdminUser, error) {
	f.record("read admins")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.admins), nil
}

func (f *fakeStore) CreateAdmin(_ context.Context, u store.AdminUser) error {
	f.record("create admin " + u.Username + " " + u.Role)
	f.mu.Lock()
	defer f.mu.Unlock()
	if v := domain.Collect(u.Check); v != nil {
		return v
	}
	if slices.ContainsFunc(f.admins, func(x store.AdminUser) bool { return x.Username == u.Username }) {
		return store.ErrExists
	}
	u.CreatedAt = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	f.admins = append(f.admins, u)
	return nil
}

func (f *fakeStore) UpdateAdmin(_ context.Context, username string, change func(*store.AdminUser) error) error {
	f.record("update admin " + username)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.admins, func(x store.AdminUser) bool { return x.Username == username })
	if i < 0 {
		return store.ErrNotFound
	}
	u := f.admins[i]
	if err := change(&u); err != nil {
		return err
	}
	if v := domain.Collect(u.Check); v != nil {
		return v
	}
	others := slices.ContainsFunc(f.admins, func(x store.AdminUser) bool { return x.Username != username && x.Role == domain.RoleAdmin })
	if f.admins[i].Role == domain.RoleAdmin && u.Role != domain.RoleAdmin && !others {
		return store.ErrLastAdmin
	}
	f.admins[i] = u
	return nil
}

// Diff gives the changes of a dry run, without writing.
func (f *fakeStore) Diff(ctx context.Context, _ config.Seed) ([]store.Change, error) {
	f.record("diff")
	return f.changes, f.bootstrapErr
}

func (f *fakeStore) Admin(_ context.Context, username string) (store.AdminUser, bool, error) {
	f.record("read admin " + username)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.admins, func(x store.AdminUser) bool { return x.Username == username })
	if i < 0 {
		return store.AdminUser{}, false, nil
	}
	return f.admins[i], true, nil
}

func (f *fakeStore) EndSessions(_ context.Context, username string) error {
	f.record("end sessions " + username)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.admins, func(x store.AdminUser) bool { return x.Username == username })
	if i < 0 {
		return store.ErrNotFound
	}
	f.admins[i].SessionsValidAfter = time.Now()
	return nil
}

func (f *fakeStore) DeleteAdmin(_ context.Context, username string) error {
	f.record("delete admin " + username)
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.admins, func(x store.AdminUser) bool { return x.Username == username })
	if i < 0 {
		return store.ErrNotFound
	}
	f.admins = slices.Delete(f.admins, i, i+1)
	return nil
}

func (f *fakeStore) SetSecrets(keys *secretbox.Keys) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keys
}

func (f *fakeStore) EncryptedSettings(context.Context) ([]store.EncryptedSetting, error) {
	f.record("encrypted settings")
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.encrypted), nil
}

func (f *fakeStore) Rekey(context.Context) ([]string, error) {
	f.record("rekey")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys.Active() == "" {
		return nil, secretbox.ErrNoKey
	}
	var done []string
	for i, e := range f.encrypted {
		if e.KID != f.keys.Active() {
			f.encrypted[i].KID = f.keys.Active()
			done = append(done, e.Key)
		}
	}
	return done, nil
}

func (f *fakeStore) AdminBySubject(_ context.Context, sub string) (store.AdminUser, bool, error) {
	f.record("read admin by subject")
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.IndexFunc(f.admins, func(x store.AdminUser) bool { return sub != "" && x.OIDCSub == sub })
	if i < 0 {
		return store.AdminUser{}, false, nil
	}
	return f.admins[i], true, nil
}
