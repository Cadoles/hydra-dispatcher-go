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

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

func testConfig(t *testing.T, hydraAdminURL string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("", []string{
		"DISPATCHER_SERVER_BASE_URL=http://dispatcher.hydra.test",
		"DISPATCHER_HYDRA_ADMIN_URL=" + hydraAdminURL,
		"DISPATCHER_STORE_DSN=postgres://dispatcher@postgres/dispatcher",
		"DISPATCHER_SECRETS_COOKIE_KEY=" + strings.Repeat("ab", 32),
		"DISPATCHER_SECRETS_CHALLENGE_KEY=" + strings.Repeat("cd", 32),
	})
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
	slog.New(newLogHandler(&buf, cfg.Observability)).With("log_type", "app").Info("server.started")

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`).MatchString(line["time"].(string)) {
		t.Errorf("time = %v, want RFC 3339 UTC to the millisecond", line["time"])
	}
	if line["version"] != version || line["instance"] == "" || line["log_type"] != "app" || line["msg"] != "server.started" {
		t.Errorf("line = %v", line)
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
