package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// requiredEnv is the least configuration serve accepts.
func requiredEnv(hydraAdminURL string) []string {
	return []string{
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_SERVER_TRUSTED_PROXIES=10.0.0.10",
		"DISPATCHER_HYDRA_ADMIN_URL=" + hydraAdminURL,
		"DISPATCHER_STORE_DSN=postgres://dispatcher@postgres/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	}
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

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	newServer := func() *httptest.Server {
		h, err := newHandler(testConfig(t, hydra.URL), logger, logger)
		if err != nil {
			t.Fatal(err)
		}
		return httptest.NewServer(h)
	}
	srv := newServer()

	if err := healthcheck(context.Background(), []string{"-url", srv.URL + "/health"}); err != nil {
		t.Errorf("healthcheck: %v", err)
	}

	for _, tt := range []struct {
		hydraStatus, want int
		hydraState        string
	}{
		{http.StatusOK, http.StatusOK, "ok"},
		{http.StatusServiceUnavailable, http.StatusServiceUnavailable, "unavailable"},
	} {
		hydraStatus = tt.hydraStatus
		// One instance per case: the Hydra client reuses its readiness for a second.
		probed := newServer()
		resp, err := http.Get(probed.URL + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Checks map[string]string `json:"checks"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		probed.Close()
		if resp.StatusCode != tt.want || body.Checks["hydra"] != tt.hydraState {
			t.Errorf("Hydra %d: /ready = %d %v, want %d with hydra %s", tt.hydraStatus, resp.StatusCode, body.Checks, tt.want, tt.hydraState)
		}
		if resp.Header.Get("X-Trace-ID") == "" {
			t.Error("no X-Trace-ID on /ready")
		}
	}

	resp, err := http.Post(srv.URL+"/health", "text/plain", nil)
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
	h, err := newHandler(cfg, logger, accessLogger)
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
// tells them, and from them only: no more from every private address.
func TestHandlerTrace(t *testing.T) {
	cfg, _, err := config.Load("", append(requiredEnv("http://127.0.0.1:1"),
		"DISPATCHER_SECURITY_EMULATED_API_AUTHORIZED_HOSTS=192.168.5.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	h, err := newHandler(cfg, logger, logger)
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

// Until the Redis store exists, serve refuses a configuration that asks for
// it rather than keep the flows in memory unseen.
func TestServeRedisNotAvailable(t *testing.T) {
	keepLoggers(t)
	for _, kv := range append(requiredEnv("http://127.0.0.1:1"),
		"DISPATCHER_STATE_REDIS_DSN=redis://redis:6379", "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", configEnv+"=") {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	stdoutOf(t, func() { err = serve(ctx, nil) })
	if err == nil || !strings.Contains(err.Error(), "state.redis_dsn") {
		t.Errorf("serve = %v, want the Redis store refused", err)
	}
}

// Configuration warnings are written whatever log_level: some warn of an
// allowlist open to every client.
func TestServeWarningsAtErrorLevel(t *testing.T) {
	keepLoggers(t)
	for _, kv := range append(requiredEnv("http://127.0.0.1:1"),
		"DISPATCHER_OBSERVABILITY_LOG_LEVEL=error", "DISPATCHER_SERVER_LISTEN=127.0.0.1:0", configEnv+"=") {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err error
	logs := stdoutOf(t, func() { err = serve(ctx, nil) })
	// No server.started: log_level still applies to the rest.
	if err != nil || !strings.Contains(logs, `"msg":"config.warning"`) || strings.Contains(logs, "server.started") {
		t.Errorf("err = %v, logs:\n%s", err, logs)
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
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	func() {
		defer func() { os.Stdout = stdout }()
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
