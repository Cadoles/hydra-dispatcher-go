package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"log/syslog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/audit"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/front"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/metrics"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// requiredEnv is the least configuration serve accepts.
func requiredEnv(hydraAdminURL string) []string {
	return []string{
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES=10.0.0.10",
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=10.0.1.0/24",
		"DISPATCHER_HYDRA_ADMIN_URL=" + hydraAdminURL,
		"DISPATCHER_STORE_DSN=postgres://dispatcher@postgres/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	}
}

// fixedSnapshot is a configuration that does not change.
type fixedSnapshot struct{ s *store.Snapshot }

func (f fixedSnapshot) Snapshot() *store.Snapshot { return f.s }

// testServices are those of a handler without a database: the state store
// in memory, and two apps, one calling from 192.168.5.7.
func testServices(t *testing.T, database httpx.Check) services {
	t.Helper()
	mem := state.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })
	app := store.App{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", AuthMode: "network",
		AllowedSources: []netip.Prefix{netip.MustParsePrefix("192.168.5.7/32")}}
	// Its sources outside every allowlist of the tests.
	far := store.App{ID: "far", LoginURL: "http://far/login", ConsentURL: "http://far/consent", AuthMode: "network",
		AllowedSources: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	return services{metrics: metrics.New(200, nil), audit: audit.New(slog.New(slog.DiscardHandler), []byte("k"), false), database: database, states: mem, config: fixedSnapshot{store.NewSnapshot([]store.App{app, far}, nil, store.DefaultSettings())}}
}

func testConfig(t *testing.T, hydraAdminURL string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("", requiredEnv(hydraAdminURL))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestHandler(t *testing.T) {
	hydraStatus := http.StatusOK
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			t.Errorf("Hydra probed on %s", r.URL.Path)
		}
		w.WriteHeader(hydraStatus)
	}))
	defer hydra.Close()

	var dbErr, stateErr error
	database := func(context.Context) error { return dbErr }

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	newServer := func() (*httptest.Server, services) {
		services := testServices(t, database)
		services.states = pinged{services.states, &stateErr}
		h, err := newHandler(testConfig(t, hydra.URL), logger, logger, services)
		if err != nil {
			t.Fatal(err)
		}
		return httptest.NewServer(h), services
	}
	srv, _ := newServer()

	if err := healthcheck(context.Background(), []string{"-url", srv.URL + "/health"}); err != nil {
		t.Errorf("healthcheck: %v", err)
	}

	// /ready says the state of the instance, whatever its dependencies (Q83): theirs
	// is in its body and in the gauge.
	for _, tt := range []struct {
		hydraStatus                     int
		dbErr, stateErr                 error
		hydraState, dbState, redisState string
	}{
		{http.StatusOK, nil, nil, "ok", "ok", "ok"},
		{http.StatusServiceUnavailable, nil, nil, "unavailable", "ok", "ok"},
		{http.StatusOK, errors.New("database: connection refused"), nil, "ok", "unavailable", "ok"},
		// The state store's PING (P8).
		{http.StatusOK, nil, errors.New("dial tcp redis:6379: connection refused"), "ok", "ok", "unavailable"},
	} {
		hydraStatus, dbErr, stateErr = tt.hydraStatus, tt.dbErr, tt.stateErr
		// One instance per case: the Hydra client reuses its readiness for a second.
		probed, services := newServer()
		resp, err := http.Get(probed.URL + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Status string            `json:"status"`
			Checks map[string]string `json:"checks"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		probed.Close()
		if resp.StatusCode != http.StatusOK || body.Status != "ready" || body.Checks["hydra"] != tt.hydraState || body.Checks["database"] != tt.dbState || body.Checks["state"] != tt.redisState {
			t.Errorf("Hydra %d, database %v, state %v: /ready = %d %s %v, want 200 ready with hydra %s, database %s, state %s",
				tt.hydraStatus, tt.dbErr, tt.stateErr, resp.StatusCode, body.Status, body.Checks, tt.hydraState, tt.dbState, tt.redisState)
		}
		if resp.Header.Get("X-Trace-ID") == "" {
			t.Error("no X-Trace-ID on /ready")
		}
		rec := httptest.NewRecorder()
		services.metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		for check, state := range map[string]string{"hydra": tt.hydraState, "database": tt.dbState, "state": tt.redisState} {
			want := fmt.Sprintf("hydra_dispatcher_ready_check_up{check=%q} %d", check, map[string]int{"ok": 1, "unavailable": 0}[state])
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("no %s in /metrics", want)
			}
		}
	}

	// While the instance drains, /ready answers 503, the rest is served.
	draining := testServices(t, database)
	draining.draining = func() bool { return true }
	hydraStatus, dbErr, stateErr = http.StatusOK, nil, nil
	h, err := newHandler(testConfig(t, hydra.URL), logger, logger, draining)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int{"/ready": http.StatusServiceUnavailable, "/health": http.StatusOK, "/": http.StatusBadRequest} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("draining: %s = %d, want %d", path, rec.Code, want)
		}
	}

	// The pages and the emulated API are served, with the security headers.
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Security-Policy") == "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET / without a challenge: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, err = http.Get(srv.URL + "/admin/oauth2/auth/requests/login?login_challenge=x"); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("emulated API from outside its allowlist: %d", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/health", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /health = %d, want 405", resp.StatusCode)
	}
	if resp, err = http.Get(srv.URL + "/nowhere?login_challenge=secret"); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	// The access line is written after the response: wait for the handlers.
	srv.Close()
	if !strings.Contains(logs.String(), `"route":"unmatched"`) || strings.Contains(logs.String(), "secret") {
		t.Errorf("the 404 was not access-logged as unmatched without its query: %s", logs.String())
	}
}

func TestLogHandler(t *testing.T) {
	var buf bytes.Buffer
	logger, _, _ := newLoggers(&buf, testConfig(t, "http://hydra:4445").Observability)
	logger.Warn("server.started")
	// An event's attribute named like a field of the line is renamed: the
	// line keeps one time, level, log_type, instance and version.
	logger.Error("webhook.failed", "time", "12:00", "level", "debug", "log_type", "audit", "instance", "i", "version", "v")
	// A time in a group is the group's, which LogHandler hands over as a
	// group attribute rather than by WithGroup: neither renamed nor reformatted.
	logger.WithGroup("g").Info("e", slog.Time("time", time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %q", lines)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`).MatchString(line["time"].(string)) {
		t.Errorf("time = %v, want RFC 3339 UTC to the millisecond", line["time"])
	}
	if line["level"] != "warn" || line["version"] != version || line["instance"] == "" || line["log_type"] != "app" || line["msg"] != "server.started" {
		t.Errorf("line = %v", line)
	}
	for _, key := range []string{"time", "level", "log_type", "instance", "version"} {
		if n := strings.Count(lines[1], `"`+key+`":`); n != 1 {
			t.Errorf("%s written %d times: %s", key, n, lines[1])
		}
	}
	if !strings.Contains(lines[1], `"level":"error"`) || !strings.Contains(lines[1], `"log_type":"app"`) ||
		!strings.Contains(lines[1], `"attr_time":"12:00","attr_level":"debug","attr_log_type":"audit","attr_instance":"i","attr_version":"v"`) {
		t.Errorf("line = %s", lines[1])
	}
	if !strings.Contains(lines[2], `"g":{"time":"2026-01-02T03:04:05+01:00"}`) {
		t.Errorf("line = %s", lines[2])
	}
}

// The access log has its own level: log_level does not silence it, nor its
// errors, which the design document has always written.
func TestLoggersLevel(t *testing.T) {
	env := append(requiredEnv("http://127.0.0.1:1"), "DISPATCHER_OBSERVABILITY_LOG_LEVEL=warn")
	cfg, _, err := config.Load("", env)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger, accessLogger, _ := newLoggers(&buf, cfg.Observability)
	logger.Info("flow.started")
	logger.Warn("challenge.invalid")
	h, err := newHandler(cfg, logger, accessLogger, testServices(t, func(context.Context) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nowhere", nil))

	out := buf.String()
	if strings.Contains(out, "flow.started") || !strings.Contains(out, "challenge.invalid") {
		t.Errorf("application log at warn: %s", out)
	}
	if !strings.Contains(out, `"msg":"http.request"`) || !strings.Contains(out, `"log_type":"access"`) || !strings.Contains(out, `"status":404`) {
		t.Errorf("the 404 is missing from the access log at log_level warn: %s", out)
	}
}

// traceparent is honoured from the proxies and the login apps, as RealIP
// tells them, and from them only: no more from every private address, nor
// from the whole allowlist of the emulated API, only the apps' sources
// within it (B2).
func TestHandlerTrace(t *testing.T) {
	// First: the first value of a variable is the one read.
	cfg, _, err := config.Load("", append([]string{"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=192.168.5.0/24"},
		requiredEnv("http://127.0.0.1:1")...))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	h, err := newHandler(cfg, logger, logger, testServices(t, func(context.Context) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	const parent = "4bf92f3577b34da6a3ce929d0e0e4736"
	for _, tt := range []struct {
		name, remote, xff string
		honoured          bool
	}{
		{"login app", "192.168.5.7:1", "", true},
		{"login app behind the proxy", "10.0.0.10:1", "192.168.5.7", true},
		{"the proxy itself", "10.0.0.10:1", "", true},
		{"Internet behind the proxy", "10.0.0.10:1", "203.0.113.7", false},
		{"Internet", "203.0.113.7:1", "", false},
		// Private, but neither a proxy nor a login app: its X-Forwarded-For
		// is not read either.
		{"another private host", "10.0.0.99:1", "", false},
		{"another private host claiming a login app", "10.0.0.99:1", "192.168.5.7", false},
		// In the allowlist of the emulated API, but no app's source.
		{"allowlisted, no app", "192.168.5.8:1", "", false},
		// An app's source, outside the allowlist: its sources do not open
		// the trace to clients the emulated API refuses.
		{"an app's source outside the allowlist", "203.0.113.9:1", "", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/health", nil)
		r.RemoteAddr = tt.remote
		r.Header.Set("Traceparent", "00-"+parent+"-00f067aa0ba902b7-01")
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("X-Trace-ID") == parent; got != tt.honoured {
			t.Errorf("%s: traceparent honoured = %v, want %v", tt.name, got, tt.honoured)
		}
	}
}

// The image's HEALTHCHECK reads DISPATCHER_CONFIG: serve warns when a file
// given by -config alone listens where the probe does not look.
func TestServeHealthcheckWarning(t *testing.T) {
	keepLoggers(t)
	for _, kv := range requiredEnv("http://127.0.0.1:1") {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	dir := t.TempDir()
	listening := filepath.Join(dir, "listen.yaml")
	if err := os.WriteFile(listening, []byte("server:\n  listen: \"127.0.0.1:0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Canceled: serve stops as soon as it listens.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tt := range []struct {
		name, env, listen string
		args              []string
		warned            bool
	}{
		{"-config alone", "", "", []string{"-config", listening}, true},
		{"DISPATCHER_CONFIG", listening, "", nil, false},
		{"both", listening, "", []string{"-config", listening}, false},
		// The probe follows DISPATCHER_SERVER_LISTEN, which wins over the file.
		{"-config alone, listen by the variable", "", "127.0.0.1:0", []string{"-config", empty}, false},
		{"another DISPATCHER_CONFIG", filepath.Join(dir, "missing.yaml"), "", []string{"-config", listening}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(configEnv, tt.env)
			t.Setenv("DISPATCHER_SERVER_LISTEN", tt.listen)
			if tt.listen == "" {
				_ = os.Unsetenv("DISPATCHER_SERVER_LISTEN") // restored by t.Setenv
			}
			var err error
			logs := stdoutOf(t, func() { err = serve(ctx, tt.args) })
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(logs, "healthcheck without -url"); got != tt.warned {
				t.Errorf("warned = %v, want %v; logs:\n%s", got, tt.warned, logs)
			}
		})
	}
}

// state.redis_dsn selects the Redis store (P8), its keys under
// state.key_prefix; empty, the memory store.
func TestNewStateStore(t *testing.T) {
	for _, tt := range []struct {
		c     config.State
		redis bool
	}{
		{config.State{}, false},
		{config.State{RedisDSN: "redis://redis:6379/0", KeyPrefix: "go:", RedisPoolSize: 4}, true},
	} {
		s, err := newStateStore(tt.c)
		if err != nil {
			t.Fatalf("%+v: %v", tt.c, err)
		}
		if _, ok := s.(*state.Redis); ok != tt.redis {
			t.Errorf("%+v: %T", tt.c, s)
		}
		_ = s.Close()
	}
	if _, err := newStateStore(config.State{RedisDSN: "http://redis:6379"}); err == nil {
		t.Error("an http:// DSN accepted")
	}
}

// serve closes the stores it opened, whichever way it ends.
func TestServeClosesStores(t *testing.T) {
	keepLoggers(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	prepare := []string{"DISPATCHER_SERVE_MIGRATE=true", "DISPATCHER_SERVE_BOOTSTRAP=force"}
	for _, tt := range []struct {
		name, listen string
		env          []string
		db           *fakeStore // nil: the database cannot be reached
		fails        bool
	}{
		{"stopped", "127.0.0.1:0", prepare, &fakeStore{}, false},
		{"database unreachable", "127.0.0.1:0", nil, nil, true},
		{"migration failed", "127.0.0.1:0", prepare, &fakeStore{migrateErr: errors.New("migrate: 00002_checks.sql: syntax error")}, true},
		{"bootstrap failed", "127.0.0.1:0", prepare, &fakeStore{bootstrapErr: errors.New("bootstrap: lock: context deadline exceeded")}, true},
		{"no first snapshot", "127.0.0.1:0", nil, &fakeStore{snapshotErr: errors.New("relation \"app\" does not exist")}, true},
		{"address in use", busy.Addr().String(), nil, &fakeStore{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			commandEnv(t, append(tt.env, "DISPATCHER_SERVER_LISTEN="+tt.listen)...)
			oldStore := openStore
			openStore = func(context.Context, string) (configStore, error) {
				if tt.db == nil {
					return nil, errors.New("dial tcp postgres:5432: connection refused")
				}
				return tt.db, nil
			}
			t.Cleanup(func() { openStore = oldStore })
			states := &closedState{}
			oldStates := newStateStore
			newStateStore = func(c config.State) (state.StateStore, error) {
				s, err := oldStates(c)
				states.StateStore = s
				return states, err
			}
			t.Cleanup(func() { newStateStore = oldStates })
			// Canceled: serve stops as soon as it listens.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var err error
			stdoutOf(t, func() { err = serve(ctx, nil) })
			if (err != nil) != tt.fails {
				t.Fatalf("serve = %v, want an error: %v", err, tt.fails)
			}
			if !states.closed.Load() {
				t.Error("state store left open")
			}
			if tt.db != nil && !slices.Contains(tt.db.Calls(), "close") {
				t.Error("configuration store left open")
			}
		})
	}
}

// pinged is a state store whose Ping fails with *err, when set.
type pinged struct {
	state.StateStore
	err *error
}

func (s pinged) Ping(ctx context.Context) error {
	if *s.err != nil {
		return *s.err
	}
	return s.StateStore.Ping(ctx)
}

// closedState tells whether serve closed its state store.
type closedState struct {
	state.StateStore
	closed atomic.Bool
}

func (s *closedState) Close() error {
	s.closed.Store(true)
	return s.StateStore.Close()
}

// Configuration warnings are written whatever log_level, those of the file as
// those of the database: some warn of an allowlist open to every client.
func TestServeWarningsAtErrorLevel(t *testing.T) {
	keepLoggers(t)
	for _, kv := range append(requiredEnv("http://127.0.0.1:1"),
		"DISPATCHER_OBSERVABILITY_LOG_LEVEL=error", "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", configEnv+"=") {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	useStore(t, &fakeStore{warnings: []string{`setting "x" is unknown to this version: ignored`}, apps: []store.App{{ID: "open", AuthMode: "network"}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	logs := stdoutOf(t, func() { err = serve(ctx, nil) })
	// No server.started: log_level still applies to the rest.
	if err != nil || !strings.Contains(logs, `"msg":"config.warning"`) || strings.Contains(logs, "server.started") {
		t.Errorf("err = %v, logs:\n%s", err, logs)
	}
	if !strings.Contains(logs, `"detail":"setting \"x\" is unknown to this version: ignored"`) {
		t.Errorf("the snapshot's warning is missing at log_level error:\n%s", logs)
	}
	// Those of the apps' identification, which serve adds.
	if !strings.Contains(logs, `"detail":"app open has no allowed_sources`) {
		t.Errorf("the app's warning is missing:\n%s", logs)
	}
}

// snapshotSource gives the same snapshot at each read.
type snapshotSource struct{ s *store.Snapshot }

func (s snapshotSource) Snapshot(context.Context) (*store.Snapshot, error) { return s.s, nil }

// The warnings of the apps' identification join a snapshot's own, without
// changing it: a source that gives the same snapshot twice does not get
// them twice.
func TestIdentifiedWarnings(t *testing.T) {
	snap := store.NewSnapshot([]store.App{{ID: "open", AuthMode: "network"}}, nil, store.DefaultSettings())
	snap.Warnings = []string{"a setting"}
	src := identified{Source: snapshotSource{snap}, hosts: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}}
	for range 2 {
		s, err := src.Snapshot(context.Background())
		if err != nil || len(s.Warnings) != 2 || s.Warnings[0] != "a setting" || !strings.HasPrefix(s.Warnings[1], "app open has no allowed_sources") || len(snap.Warnings) != 1 {
			t.Fatalf("warnings %q, the source's %q, err %v", s.Warnings, snap.Warnings, err)
		}
	}
	if _, err := (identified{Source: &fakeStore{snapshotErr: errors.New("down")}}).Snapshot(context.Background()); err == nil {
		t.Error("the source's error lost")
	}
}

// A webhook that could not be called refuses the snapshot, at startup as later on
// (webhook.Check, Q70).
func TestIdentifiedWebhooks(t *testing.T) {
	settings := store.DefaultSettings()
	settings.LoginAcceptWebhookURL = "http://hooks/login"
	src := snapshotSource{store.NewSnapshot(nil, nil, settings)}
	if _, err := (identified{Source: src, signed: true}).Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "tls.allow_http") {
		t.Errorf("err = %v", err)
	}
	if _, err := (identified{Source: src, allowHTTP: true}).Snapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "secrets.webhook_signing_key") {
		t.Errorf("err = %v", err)
	}
	if _, err := (identified{Source: src, allowHTTP: true, signed: true}).Snapshot(context.Background()); err != nil {
		t.Error(err)
	}

	// A local program with secrets in the environment is warned of at each read that
	// changes, as the other warnings of a snapshot (Q87).
	settings.LoginAcceptWebhookURL = "/opt/hooks/login --strict"
	src = snapshotSource{store.NewSnapshot(nil, nil, settings)}
	s, err := (identified{Source: src, secrets: []string{"secrets.cookie_key", "store.dsn"}}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(s.Warnings, func(w string) bool {
		return strings.Contains(w, "setting login_accept_webhook_url runs a local program") && strings.Contains(w, "give secrets.cookie_key, store.dsn by a file")
	}) {
		t.Errorf("warnings %q", s.Warnings)
	}
}

// A locale of the settings the theme has no catalog for is warned of, as the
// other warnings of a snapshot, at each read that changes them (Q92).
func TestIdentifiedLocales(t *testing.T) {
	theme, err := front.LoadTheme("")
	if err != nil {
		t.Fatal(err)
	}
	settings := store.DefaultSettings()
	settings.SupportedLocales = []string{"fr", "en", "de"}
	s, err := (identified{Source: snapshotSource{store.NewSnapshot(nil, nil, settings)}, theme: theme}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Warnings, []string{`setting supported_locales: "de" has no catalog in the theme (en, fr): the pages do not offer it`}) {
		t.Errorf("warnings %q", s.Warnings)
	}
}

// A theme that fails stops serve before the stores, named by its key; one that
// loads is logged with its name and version.
func TestLoadTheme(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := loadTheme(filepath.Join(t.TempDir(), "nope"), logger); err == nil || !strings.HasPrefix(err.Error(), "ui.theme_dir ") {
		t.Errorf("no directory: %v", err)
	}
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("theme.yaml", "name: demo\nversion: 2.1.0\napi: 1\n")
	write("templates/error.html.tmpl", `{{define "content"}}<p style="color: red">{{.Error.Code}}</p>{{end}}`)
	if _, err := loadTheme(dir, logger); err == nil || !strings.Contains(err.Error(), "page error: attribute style on <p>") {
		t.Errorf("the check: %v", err)
	}
	write("templates/error.html.tmpl", `{{define "content"}}<p class="code">{{.T .Error.MessageKey}} {{.Error.Code}} {{.Error.TraceID}}</p>{{end}}`)
	if _, err := loadTheme(dir, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"msg":"theme.loaded","dir":"`+dir+`","theme":"demo","theme_version":"2.1.0","api":1,"locales":["en","fr"]`) {
		t.Errorf("logs: %s", logs.String())
	}
	if theme, err := loadTheme("", logger); err != nil || theme.Dir != "" {
		t.Errorf("embedded theme: %v", err)
	}
}

// Keys of the admin API that cannot sign stop serve before the stores, named
// by their key; good ones are logged by their id, never by their value; without
// a private key, the API is not served, and nothing is read.
func TestServeAdminKeys(t *testing.T) {
	keepLoggers(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_ADMIN_API_PRIVATE_KEY=not a key")
	f := &fakeStore{}
	useStore(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var serveErr error
	_ = stdoutOf(t, func() { serveErr = serve(ctx, nil) })
	if serveErr == nil || !strings.HasPrefix(serveErr.Error(), "admin.api.private_key: ") || len(f.Calls()) != 0 {
		t.Errorf("broken key: err = %v, calls = %q", serveErr, f.Calls())
	}

	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_ADMIN_API_PRIVATE_KEY="+private)
	useStore(t, &fakeStore{})
	logs := stdoutOf(t, func() { serveErr = serve(ctx, nil) })
	if serveErr != nil || !strings.Contains(logs, `"msg":"admin.keys_loaded"`) || !strings.Contains(logs, `"alg":"ES256","previous":0`) ||
		strings.Contains(logs, "PRIVATE KEY") {
		t.Errorf("good key: err = %v, logs:\n%s", serveErr, logs)
	}

	commandEnv(t, "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", "DISPATCHER_ADMIN_API_PRIVATE_KEY=")
	useStore(t, &fakeStore{})
	logs = stdoutOf(t, func() { serveErr = serve(ctx, nil) })
	if serveErr != nil || strings.Contains(logs, "admin.keys_loaded") || !strings.Contains(logs, "admin.api.enabled without admin.api.private_key") {
		t.Errorf("no key: err = %v, logs:\n%s", serveErr, logs)
	}
}

// keepLoggers restores the default loggers, which serve replaces.
func keepLoggers(t *testing.T) {
	defaultLogger, flags, out := slog.Default(), log.Flags(), log.Writer()
	t.Cleanup(func() {
		slog.SetDefault(defaultLogger)
		log.SetFlags(flags)
		log.SetOutput(out)
	})
}

// stdoutOf returns what f writes to os.Stdout, where serve logs.
func stdoutOf(t *testing.T, f func()) string {
	t.Helper()
	return outputOf(t, &os.Stdout, f)
}

// stderrOf returns what f writes to os.Stderr, where bootstrap logs.
func stderrOf(t *testing.T, f func()) string {
	t.Helper()
	return outputOf(t, &os.Stderr, f)
}

// outputOf returns what f writes to *file.
func outputOf(t *testing.T, file **os.File, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := *file
	*file = w
	func() {
		defer func() { *file = old }()
		f()
	}()
	_ = w.Close()
	b, _ := io.ReadAll(r)
	_ = r.Close()
	return string(b)
}

// A warning may explain the configuration error: it is logged before it.
func TestServeConfigWarnings(t *testing.T) {
	var logs bytes.Buffer
	keepLoggers(t)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Setenv("DISPATCHER_SERVER_BASE_URL", "")
	t.Setenv("DISPATCHER_SERVER_BASEURL", "http://typo")
	if err := serve(context.Background(), nil); err == nil || !strings.Contains(logs.String(), "DISPATCHER_SERVER_BASEURL is ignored") {
		t.Errorf("err = %v, logs = %q", err, logs.String())
	}
}

// DEC-1: the challenges are decrypted for Hydra 2.2 and 2.3 when Hydra's
// secrets are given, read on the admin API otherwise.
func TestHydraSource(t *testing.T) {
	for _, tc := range []struct {
		version string
		secrets config.List
		mode    string
	}{
		{"2.1", config.List{"youReallyNeedToChangeThis"}, "fallback"},
		{"2.2", nil, "fallback"},
		{"2.2", config.List{"youReallyNeedToChangeThis"}, "decrypt"},
		{"2.3", config.List{"a-newer-system-secret-01234", "youReallyNeedToChangeThis"}, "decrypt"},
	} {
		source, err := hydraSource(config.Hydra{Version: tc.version, SystemSecrets: tc.secrets, LoginConsentTTL: config.Duration(30 * time.Minute)}, nil)
		if err != nil || hydraMode(source) != tc.mode {
			t.Errorf("%s with %d secrets: %s, %v; want %s", tc.version, len(tc.secrets), hydraMode(source), err, tc.mode)
		}
	}
	if _, err := hydraSource(config.Hydra{Version: "2.2", SystemSecrets: config.List{""}}, nil); err == nil {
		t.Error("an empty secret accepted")
	}
}

// /metrics stays up with Redis and the database down, which a scrape never touches, on
// the main port, behind security.metrics_authorized_hosts (doc, Prometheus).
func TestMetricsRoute(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hydra.Close()
	logger := slog.New(slog.DiscardHandler)
	services := testServices(t, func(context.Context) error { return errors.New("database down") })
	down := errors.New("redis down")
	services.states = pinged{services.states, &down}
	cfg := testConfig(t, hydra.URL)
	h, err := newHandler(cfg, logger, logger, services)
	if err != nil {
		t.Fatal(err)
	}
	get := func(remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := get("10.1.2.3:1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hydra_dispatcher_build_info") || !strings.Contains(rec.Body.String(), `hydra_mode="fallback"`) ||
		!strings.Contains(rec.Body.String(), `state_backend="memory"`) || !strings.Contains(rec.Body.String(), "go_goroutines") || !strings.Contains(rec.Body.String(), "hydra_dispatcher_hydra_in_flight 0") {
		t.Errorf("scrape: %d\n%s", rec.Code, rec.Body)
	}
	if rec := get("203.0.113.9:1"); rec.Code != http.StatusForbidden {
		t.Errorf("outside the allowlist: %d", rec.Code)
	}
	if !strings.Contains(get("10.1.2.3:1").Body.String(), `route="/metrics"`) {
		t.Error("the requests are not counted")
	}
}

// observability.metrics.listen: /metrics on a port of its own, gone from the main one.
func TestMetricsListen(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hydra.Close()
	logger := slog.New(slog.DiscardHandler)
	cfg := testConfig(t, hydra.URL)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Observability.Metrics.Listen = ln.Addr().String()
	_ = ln.Close()
	local := config.List{"127.0.0.1/32"}
	cfg.Security.MetricsAuthorizedHosts = &local
	services := testServices(t, func(context.Context) error { return nil })
	h, err := newHandler(cfg, logger, logger, services)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = "10.1.2.3:1"
	h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK {
		t.Errorf("/metrics still on the main port: %d", rec.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	wait, err := serveMetrics(ctx, cancel, cfg, services.metrics, services.audit, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + cfg.Observability.Metrics.Listen + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hydra_dispatcher_build_info") {
		t.Errorf("dedicated port: %d %s", resp.StatusCode, body)
	}
	cancel()
	if err := wait(); err != nil {
		t.Error(err)
	}
}

// A login app passes on the login_challenge of the URL a browser opened: the challenges a
// client of the Internet forges, relayed by the app from its address, do not stop it for
// all its users (Q80, revue R29). Played here on newHandler, where the limiter is wired.
func TestEmulatedAPINotLimited(t *testing.T) {
	const challenge = "0c34aaee066148adbc0251024fee9bb4"
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"challenge": r.URL.Query().Get("login_challenge"), "client": map[string]any{"client_id": "c1"},
			"request_url": "http://public.hydra.test/oauth2/auth?client_id=c1", "requested_scope": []string{"openid"}, "skip": false, "subject": ""})
	}))
	defer hydra.Close()
	services := testServices(t, func(context.Context) error { return nil })
	app := store.App{ID: "sql", LoginURL: "http://sql/login", ConsentURL: "http://sql/consent", AuthMode: "network",
		AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.0.1.7/32")}}
	step := []store.Step{{AppID: "sql", Position: 1, SubjectCheck: "none"}}
	flows := []store.Flow{{ID: "a", Enabled: true, Title: map[string]string{"en": "A"}, Steps: step}, {ID: "b", Enabled: true, Title: map[string]string{"en": "B"}, Steps: step}}
	services.config = fixedSnapshot{store.NewSnapshot([]store.App{app}, flows, store.DefaultSettings())}
	logger := slog.New(slog.DiscardHandler)
	h, err := newHandler(testConfig(t, hydra.URL), logger, logger, services)
	if err != nil {
		t.Fatal(err)
	}
	do := func(remote, target string) int {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	// A client starts a flow, then hands the app its step challenge, its signature changed.
	if code := do("198.51.100.66:1", "/?login_challenge="+challenge); code != http.StatusOK {
		t.Fatalf("choice page: %d", code)
	}
	forged := flow.Ref(challenge) + strings.Repeat("0", 12)
	for i := range 30 {
		if code := do("10.0.1.7:1", "/admin/oauth2/auth/requests/login?login_challenge="+forged); code != http.StatusNotFound {
			t.Fatalf("call %d of the app: %d", i, code)
		}
	}
}

// observability.audit.output: a file it appends to, one that cannot open stops serve;
// the pseudonym without secrets.audit_key is derived, another key gives another one.
func TestNewAudit(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hydra.Close()
	cfg := testConfig(t, hydra.URL)
	path := filepath.Join(t.TempDir(), "audit.log")
	cfg.Observability.Audit.Output = "file:" + path
	write := func() string {
		log, closer, err := newAudit(cfg, io.Discard, slog.New(slog.DiscardHandler), nil)
		if err != nil {
			t.Fatal(err)
		}
		log.Refused(context.Background(), "metrics")
		closer() // the queue emptied
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	write()
	text := write()
	if strings.Count(text, `"log_type":"audit"`) != 2 || strings.Count(text, `"msg":"security.ip_rejected"`) != 2 {
		t.Errorf("not appended, or not the audit stream: %s", text)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, err %v", info.Mode(), err)
	}
	cfg.Observability.Audit.Output = "file:" + filepath.Join(t.TempDir(), "missing", "audit.log")
	if _, _, err := newAudit(cfg, io.Discard, slog.New(slog.DiscardHandler), nil); err == nil || !strings.Contains(err.Error(), "observability.audit.output") {
		t.Errorf("err = %v", err)
	}
	var out bytes.Buffer
	cfg.Observability.Audit.Output = "stdout"
	log, closer, err := newAudit(cfg, &out, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	log.Refused(context.Background(), "metrics")
	closer()
	if !strings.Contains(out.String(), `"log_type":"audit"`) {
		t.Errorf("stdout: %s", out.String())
	}
}

// The scenario of revue R30: the audit in syslog, a daemon that reads no more. The stop
// gives up the lines left at its deadline, and does not close the output under the
// Write that holds it, syslog.Writer.Close waiting for that Write without end; a daemon
// that reads gets its output closed.
func TestCloseAuditOfABlockedSyslog(t *testing.T) {
	for _, reads := range []bool{false, true} {
		t.Run(fmt.Sprintf("daemon reads %v", reads), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log")
			daemon, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = daemon.Close() }()
			if reads {
				go func() {
					buf := make([]byte, 64<<10)
					for {
						if _, err := daemon.Read(buf); err != nil {
							return
						}
					}
				}()
			}
			s, err := syslog.Dial("unixgram", path, syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "hydra-dispatcher")
			if err != nil {
				t.Fatal(err)
			}
			queue := audit.NewQueue(s, audit.QueueSize, slog.New(slog.DiscardHandler), nil)
			for range 2000 {
				_, _ = queue.Write([]byte(`{"log_type":"audit","msg":"security.ip_rejected"}` + "\n"))
			}
			var closed atomic.Bool
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				closeAudit(ctx, queue, func() { _ = s.Close(); closed.Store(true) })
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("closeAudit still waiting 5 s on: the stop would never end")
			}
			if closed.Load() != reads {
				t.Errorf("output closed: %v, want %v", closed.Load(), reads)
			}
		})
	}
}
