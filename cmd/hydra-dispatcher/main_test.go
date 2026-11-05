package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
		wantOut string
	}{
		{"no command", nil, errUsage, "Usage: hydra-dispatcher"},
		{"unknown command", []string{"nope"}, errUsage, `unknown command "nope"`},
		{"help", []string{"help"}, nil, "serve"},
		{"bad flag", []string{"serve", "-nope"}, errUsage, ""},
		{"subcommand help", []string{"serve", "-h"}, nil, ""},
		{"version", []string{"version"}, nil, ""},
		// serve dispatcher.yaml would run on the variables alone.
		{"argument", []string{"serve", "dispatcher.yaml"}, errUsage, ""},
		{"argument after the flags", []string{"healthcheck", "-url", "http://127.0.0.1:1/health", "extra"}, errUsage, ""},
		{"version argument", []string{"version", "extra"}, errUsage, ""},
	}
	t.Run("serve with a missing configuration file", func(t *testing.T) {
		err := run(context.Background(), []string{"serve", "-config", "/nonexistent/dispatcher.yaml"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("err = %v, want a configuration error", err)
		}
	})
	// The file the image's HEALTHCHECK reads too.
	t.Run("serve with DISPATCHER_CONFIG", func(t *testing.T) {
		t.Setenv("DISPATCHER_CONFIG", "/nonexistent/from-the-variable.yaml")
		err := run(context.Background(), []string{"serve"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "from-the-variable.yaml") {
			t.Errorf("err = %v, want the file of DISPATCHER_CONFIG read", err)
		}
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			err := run(context.Background(), tt.args, &stderr)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(stderr.String(), tt.wantOut) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantOut)
			}
		})
	}
}

func TestHealthURL(t *testing.T) {
	for listen, want := range map[string]string{
		"":               "http://127.0.0.1:8080/health",
		":9000":          "http://127.0.0.1:9000/health",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/health",
		"[::]:9000":      "http://127.0.0.1:9000/health", // both stacks, and maybe no ::1
		"10.0.0.5:8080":  "http://10.0.0.5:8080/health",
		"[::1]:8080":     "http://[::1]:8080/health",
		"localhost:8080": "http://localhost:8080/health",
	} {
		if got := healthURL(listen); got != want {
			t.Errorf("healthURL(%q) = %s, want %s", listen, got, want)
		}
	}
}

// The HEALTHCHECK of the image passes no -url: the probe follows
// DISPATCHER_SERVER_LISTEN.
func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("probed %s", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	t.Setenv("DISPATCHER_SERVER_LISTEN", srv.Listener.Addr().String())

	if err := healthcheck(context.Background(), nil); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(context.Background(), nil); err == nil {
		t.Error("healthcheck of a 503: want an error")
	}
	if err := healthcheck(context.Background(), []string{"-url", "http://127.0.0.1:1/health"}); err == nil {
		t.Error("healthcheck of a closed port: want an error")
	}

	// With DISPATCHER_CONFIG, the server.listen of the file, read as serve
	// reads it: the variable still wins over the file.
	t.Run("configuration file", func(t *testing.T) {
		status = http.StatusOK
		for _, kv := range requiredEnv("http://127.0.0.1:1") {
			k, v, _ := strings.Cut(kv, "=")
			t.Setenv(k, v)
		}
		t.Setenv("DISPATCHER_SERVER_LISTEN", "")
		_ = os.Unsetenv("DISPATCHER_SERVER_LISTEN") // restored by t.Setenv
		path := filepath.Join(t.TempDir(), "dispatcher.yaml")
		if err := os.WriteFile(path, []byte("server:\n  listen: \""+srv.Listener.Addr().String()+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DISPATCHER_CONFIG", path)
		if err := healthcheck(context.Background(), nil); err != nil {
			t.Errorf("listen of the file: %v", err)
		}
		t.Setenv("DISPATCHER_SERVER_LISTEN", "127.0.0.1:1")
		if err := healthcheck(context.Background(), nil); err == nil {
			t.Error("DISPATCHER_SERVER_LISTEN on a closed port: want an error, it wins over the file")
		}
		// A configuration serve refuses fails the probe, saying why.
		t.Setenv("DISPATCHER_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
		if err := healthcheck(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("missing file: err = %v, want a configuration error", err)
		}
	})
}

// TestMainProcess runs main in a child process, the test binary itself, for
// its exit codes and its stop on SIGTERM.
func TestMainProcess(t *testing.T) {
	if args, ok := os.LookupEnv("HYDRA_DISPATCHER_TEST_MAIN"); ok {
		os.Args = append([]string{"dispatcher"}, strings.Fields(args)...)
		main()
		return
	}
	child := func(args string, env ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMainProcess$")
		cmd.Env = append(os.Environ(), append(env, "HYDRA_DISPATCHER_TEST_MAIN="+args)...)
		return cmd
	}
	exitCode := func(err error) int {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}

	for _, tt := range []struct {
		args string
		want int
	}{
		{"version", 0},
		{"version extra", 2},
		{"help", 0},
		{"", 2},
		{"nope", 2},
		{"serve -nope", 2},
		{"serve dispatcher.yaml", 2},
		{"serve -config /nonexistent/dispatcher.yaml", 1},
		{"healthcheck -url http://127.0.0.1:1/health", 1},
	} {
		if got := exitCode(child(tt.args).Run()); got != tt.want {
			t.Errorf("hydra-dispatcher %s: exit code %d, want %d", tt.args, got, tt.want)
		}
	}

	// Before the configuration is read, lines keep the format of the doc.
	t.Run("startup failure", func(t *testing.T) {
		out, err := child("serve -config /nonexistent/dispatcher.yaml").Output()
		if code := exitCode(err); code != 1 {
			t.Fatalf("exit code %d", code)
		}
		// The last line: config warnings may come first.
		lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
		var line map[string]any
		if err := json.Unmarshal(lines[len(lines)-1], &line); err != nil {
			t.Fatalf("stdout %q: %v", out, err)
		}
		if line["level"] != "error" || line["msg"] != "fatal" || line["log_type"] != "app" || line["version"] != version ||
			line["instance"] == "" || !strings.Contains(line["err"].(string), "configuration") ||
			!regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`).MatchString(line["time"].(string)) {
			t.Errorf("line = %v", line)
		}
	})

	// bootstrap keeps stdout for its changes: its fatal error goes to stderr.
	t.Run("bootstrap failure", func(t *testing.T) {
		cmd := child("bootstrap -config /nonexistent/dispatcher.yaml")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if code := exitCode(err); code != 1 || len(out) > 0 || !strings.Contains(stderr.String(), `"msg":"fatal"`) {
			t.Errorf("exit code %d, stdout %q, stderr %q", code, out, stderr.String())
		}
	})

	t.Run("SIGTERM", func(t *testing.T) {
		cmd := child("serve", append(requiredEnv("http://127.0.0.1:1"), "DISPATCHER_SERVER_LISTEN=127.0.0.1:0")...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer time.AfterFunc(10*time.Second, func() { _ = cmd.Process.Kill() }).Stop()
		var out strings.Builder
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			out.WriteString(lines.Text() + "\n")
			if strings.Contains(lines.Text(), `"msg":"server.started"`) {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
		}
		if code := exitCode(cmd.Wait()); code != 0 || !strings.Contains(out.String(), `"msg":"server.stopped"`) {
			t.Errorf("exit code %d, output:\n%s", code, out.String())
		}
	})

	// After the first signal, a second one stops at once, without waiting
	// for the request in flight: /ready, held by a Hydra that does not answer.
	t.Run("second signal", func(t *testing.T) {
		probed, release := make(chan struct{}, 1), make(chan struct{})
		hydra := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			select {
			case probed <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer hydra.Close()
		defer close(release)

		cmd := child("serve", append(requiredEnv(hydra.URL), "DISPATCHER_SERVER_LISTEN=127.0.0.1:0")...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer time.AfterFunc(10*time.Second, func() { _ = cmd.Process.Kill() }).Stop()
		lines := bufio.NewScanner(stdout)
		var addr string
		for addr == "" && lines.Scan() {
			var line struct{ Msg, Addr string }
			if json.Unmarshal(lines.Bytes(), &line) == nil && line.Msg == "server.started" {
				addr = line.Addr
			}
		}
		go func() {
			if resp, err := http.Get("http://" + addr + "/ready"); err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-probed

		var rest strings.Builder
		done := make(chan error, 1)
		go func() {
			for lines.Scan() {
				rest.WriteString(lines.Text() + "\n")
			}
			done <- cmd.Wait()
		}()
		// The first SIGTERM starts the graceful shutdown, which waits for
		// /ready; any later one, once the signal is let through, kills.
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		var waited error
	signal:
		for {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case waited = <-done:
				break signal
			case <-tick.C:
			}
		}
		var exit *exec.ExitError
		if !errors.As(waited, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || strings.Contains(rest.String(), "server.stopped") {
			t.Errorf("wait = %v, want killed by the second signal, output:\n%s", waited, rest.String())
		}
	})
}
