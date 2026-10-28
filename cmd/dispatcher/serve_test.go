package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	cfg := testConfig(t, "http://hydra:4445")
	logger := slog.New(newLogHandler(&buf, cfg.Observability)).With("log_type", "app")
	logger.Warn("server.started")
	// An attribute named like a standard one is left alone, and does not panic.
	logger.Error("webhook.failed", "time", "12:00")
	// So is a time in a group, which LogHandler hands over as a group
	// attribute rather than by WithGroup.
	logger.WithGroup("g").Info("e", slog.Time("time", time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
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
	if len(lines) != 3 || !strings.Contains(lines[1], `"level":"error"`) || !strings.Contains(lines[1], `"time":"12:00"`) ||
		!strings.Contains(lines[2], `"g":{"time":"2026-01-02T03:04:05+01:00"}`) {
		t.Errorf("lines = %q", lines)
	}
}

// A warning may explain the configuration error: it is logged before it.
func TestServeConfigWarnings(t *testing.T) {
	var logs bytes.Buffer
	defaultLogger, flags, out := slog.Default(), log.Flags(), log.Writer()
	t.Cleanup(func() {
		slog.SetDefault(defaultLogger)
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Setenv("DISPATCHER_SERVER_BASE_URL", "")
	t.Setenv("DISPATCHER_SERVER_BASEURL", "http://typo")
	if err := serve(context.Background(), nil); err == nil || !strings.Contains(logs.String(), "DISPATCHER_SERVER_BASEURL is ignored") {
		t.Errorf("err = %v, logs = %q", err, logs.String())
	}
}
