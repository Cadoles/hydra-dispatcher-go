package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
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
	// warnings are those of the snapshots.
	warnings []string
	// deadlines are the time left to the first migrate, bootstrap and
	// snapshot, when their context has a deadline.
	deadlines map[string]time.Duration
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
	return &store.Snapshot{Settings: store.DefaultSettings(), Warnings: f.warnings}, nil
}

func (f *fakeStore) Ping(context.Context) error { return f.pingErr }

func (f *fakeStore) Close() error {
	f.record("close")
	return nil
}

func (f *fakeStore) Migrate(ctx context.Context) ([]string, error) {
	f.deadline(ctx, "migrate")
	f.record("migrate")
	return f.applied, nil
}

func (f *fakeStore) Bootstrap(ctx context.Context, _ config.Seed, mode store.Mode, write bool) ([]store.Change, error) {
	f.deadline(ctx, "bootstrap")
	name := map[store.Mode]string{store.Missing: "missing", store.Force: "force"}[mode]
	f.record("bootstrap " + name + " " + map[bool]string{true: "write", false: "dry"}[write])
	return f.changes, nil
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
	{Kind: "setting", ID: "remember", Action: store.Reset},
	{Kind: "app", ID: "hydra-sql", Action: store.Update, Fields: []store.FieldChange{{Name: "login_url", Old: `"http://old"`, New: `"http://new"`}}},
	{Kind: "api_client", ID: "test", Action: store.Keep, Fields: []store.FieldChange{{Name: "secret", Secret: true}}},
	{Kind: "flow", ID: "hydra-sql", Action: store.Same},
	{Kind: "flow", ID: "legacy", Action: store.Absent},
}

func TestPrintChanges(t *testing.T) {
	var out bytes.Buffer
	printChanges(&out, someChanges)
	want := `reset   setting remember (back to its default)
update  app hydra-sql
          login_url: "http://old" -> "http://new"
keep    api_client test (left as it is: -force rewrites it)
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

// stdinFrom makes bootstrap read answers, from a terminal or not.
func stdinFrom(t *testing.T, answers string, terminal bool) {
	oldStdin, oldTerminal := stdin, stdinIsTerminal
	stdin, stdinIsTerminal = strings.NewReader(answers), func() bool { return terminal }
	t.Cleanup(func() { stdin, stdinIsTerminal = oldStdin, oldTerminal })
}

func TestBootstrapCommand(t *testing.T) {
	keepLoggers(t)
	commandEnv(t)
	for _, tt := range []struct {
		args     []string
		terminal bool
		answer   string
		calls    []string
	}{
		{nil, true, "", []string{"bootstrap missing write", "close"}},
		{[]string{"-dry-run"}, true, "", []string{"bootstrap missing dry", "close"}},
		{[]string{"-force", "-dry-run"}, true, "", []string{"bootstrap force dry", "close"}},
		// Out of a terminal, as in a container, -force writes without asking.
		{[]string{"-force"}, false, "", []string{"bootstrap force write", "close"}},
		{[]string{"-force", "-yes"}, true, "", []string{"bootstrap force write", "close"}},
		// In one, it shows the changes and asks.
		{[]string{"-force"}, true, "y\n", []string{"bootstrap force dry", "bootstrap force write", "close"}},
		{[]string{"-force"}, true, "n\n", []string{"bootstrap force dry", "close"}},
	} {
		stdinFrom(t, tt.answer, tt.terminal)
		f := &fakeStore{changes: someChanges}
		useStore(t, f)
		var err error
		out := stdoutOf(t, func() { err = run(context.Background(), append([]string{"bootstrap"}, tt.args...), io.Discard) })
		if err != nil || !slices.Equal(f.Calls(), tt.calls) || !strings.Contains(out, "update 1, reset 1") {
			t.Errorf("bootstrap %q: err = %v, calls = %q, output:\n%s", tt.args, err, f.Calls(), out)
		}
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
	if err != nil || !slices.Equal(f.Calls(), []string{"migrate", "bootstrap force write", "close"}) {
		t.Fatalf("err = %v, calls = %q", err, f.Calls())
	}
	for _, want := range []string{
		`"msg":"bootstrap.change"`, `"kind":"app","id":"hydra-sql","action":"update","fields":["login_url"]`,
		`"msg":"bootstrap.done"`, `"mode":"force","summary":"update 1, reset 1, keep 1, same 1, absent 1"`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %s in:\n%s", want, logs)
		}
	}
	// A change left as it is logged, an unchanged one is not.
	if strings.Contains(logs, `"action":"same"`) || strings.Index(logs, "bootstrap.done") > strings.Index(logs, "server.started") {
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
