package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The stop of serve, played on the process: the test binary run as serve, as
// TestMainProcess does, on a fake configuration store (P12b, Q82).

// mainChild runs main as hydra-dispatcher args, through TestMainProcess.
func mainChild(args string, env ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainProcess$")
	cmd.Env = append(os.Environ(), append(env, "HYDRA_DISPATCHER_TEST_MAIN="+args)...)
	return cmd
}

// logLine is what the tests read of a line of the child.
type logLine struct {
	Msg, Addr string
}

// child is a running serve, its stdout read line by line.
type child struct {
	cmd   *exec.Cmd
	mu    sync.Mutex
	out   strings.Builder
	lines chan logLine
	done  chan error // the end of the process, once its stdout is read
}

func startChild(t *testing.T, env ...string) *child {
	t.Helper()
	c := &child{cmd: mainChild("serve", env...), lines: make(chan logLine, 100), done: make(chan error, 1)}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.cmd.Process.Kill() })
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			c.mu.Lock()
			c.out.WriteString(scanner.Text() + "\n")
			c.mu.Unlock()
			var l logLine
			if json.Unmarshal(scanner.Bytes(), &l) == nil {
				select {
				case c.lines <- l:
				default:
				}
			}
		}
		c.done <- c.cmd.Wait()
	}()
	return c
}

// await returns the addr of the first line named msg.
func (c *child) await(t *testing.T, msg string) string {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case l := <-c.lines:
			if l.Msg == msg {
				return l.Addr
			}
		case <-timeout:
			t.Fatalf("no %s within 10 s:\n%s", msg, c.output())
		}
	}
}

func (c *child) output() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

// mute accepts connections and never answers: a collector or a Sentry that hangs.
func mute(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// TestShutdownBudget sends SIGTERM to a serve with a drain, a request that ends within
// the grace, one that does not, and a collector and a Sentry that never answer: /ready
// says 503 during the drain while the requests are served, the first request ends, the
// second is cut and logged, and the process is gone within drain_delay + 10 s.
func TestShutdownBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("a stop of about 10 s")
	}
	const (
		drainDelay = time.Second
		slow       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // Hydra answers 500 in 2 s: E1004, to Sentry
		stuck      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // Hydra never answers
	)
	reached := make(chan string, 2)
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("login_challenge") {
		case slow:
			reached <- slow
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusInternalServerError)
		case stuck:
			reached <- stuck
			<-r.Context().Done()
		}
	}))
	defer hydra.Close()
	sentry, collector := mute(t), mute(t)

	c := startChild(t, append(requiredEnv(hydra.URL),
		"DISPATCHER_SERVER_LISTEN=127.0.0.1:0",
		"DISPATCHER_SERVER_DRAIN_DELAY="+drainDelay.String(),
		"DISPATCHER_HYDRA_TIMEOUT=30s",
		"DISPATCHER_OBSERVABILITY_SENTRY_DSN=http://key@"+sentry+"/1",
		"DISPATCHER_OBSERVABILITY_TRACING_ENABLED=true",
		"DISPATCHER_OBSERVABILITY_TRACING_PROTOCOL=http/protobuf",
		"DISPATCHER_OBSERVABILITY_TRACING_ENDPOINT=http://"+collector+"/v1/traces",
		"DISPATCHER_OBSERVABILITY_TRACING_SAMPLER_RATIO=1",
		"OTEL_EXPORTER_OTLP_ENDPOINT=", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=",
	)...)
	base := "http://" + c.await(t, "server.started")
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	type answer struct {
		status int
		err    error
	}
	request := func(challenge string) chan answer {
		ch := make(chan answer, 1)
		go func() {
			resp, err := client.Get(base + "/?login_challenge=" + challenge)
			if err != nil {
				ch <- answer{err: err}
				return
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			ch <- answer{resp.StatusCode, err}
		}()
		return ch
	}
	slowAnswer, stuckAnswer := request(slow), request(stuck)
	<-reached
	<-reached

	sigterm := time.Now()
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// During the drain, /ready says 503 and the requests are served.
	time.Sleep(drainDelay / 4)
	for path, want := range map[string]int{"/ready": http.StatusServiceUnavailable, "/health": http.StatusOK} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("%s during the drain: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s during the drain: %d, want %d", path, resp.StatusCode, want)
		}
	}
	if time.Since(sigterm) > drainDelay {
		t.Fatal("the probes of the drain came after it")
	}

	if a := <-slowAnswer; a.err != nil || a.status != http.StatusBadGateway {
		t.Errorf("the request that ends within the grace: %d %v, want 502 (E1004)", a.status, a.err)
	}
	if a := <-stuckAnswer; a.err == nil {
		t.Errorf("the request beyond the grace got %d, want its connection cut", a.status)
	}
	var err error
	select {
	case err = <-c.done:
	case <-time.After(drainDelay + 15*time.Second):
		t.Fatalf("still running %v after SIGTERM:\n%s", time.Since(sigterm), c.output())
	}
	took := time.Since(sigterm)
	// drain + 6 s of grace + 1 s for the handlers + 2 s for traces and Sentry together.
	if err != nil || took > drainDelay+10*time.Second || took < drainDelay+shutdownGrace {
		t.Errorf("exit %v after %v, want 0 within %v:\n%s", err, took, drainDelay+10*time.Second, c.output())
	}
	out := c.output()
	for _, want := range []string{`"msg":"server.shutdown_timeout"`, `"msg":"server.stopped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("no %s in:\n%s", want, out)
		}
	}
	t.Logf("stopped %v after SIGTERM", took)
}

// TestServerFails plays the scenario of R29: the main server stops on its own, its
// listening socket shut down for reading under it, accept failing with EINVAL, while
// observability.metrics.listen serves. The process stops, saying why, where it used to
// wait for the server of /metrics forever. The other way round too.
func TestServerFails(t *testing.T) {
	for _, failing := range []string{"server.started", "metrics.started"} {
		t.Run(failing, func(t *testing.T) {
			hydra := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			defer hydra.Close()
			c := startChild(t, append(requiredEnv(hydra.URL),
				"DISPATCHER_SERVER_LISTEN=127.0.0.1:0",
				"DISPATCHER_OBSERVABILITY_METRICS_LISTEN=127.0.0.1:0",
			)...)
			addrs := map[string]string{"metrics.started": c.await(t, "metrics.started")}
			addrs["server.started"] = c.await(t, "server.started")
			_, port, _ := net.SplitHostPort(addrs[failing])

			if err := shutdownListener(c.cmd.Process.Pid, port); err != nil {
				t.Skipf("cannot reach the socket of the child: %v", err)
			}
			var err error
			select {
			case err = <-c.done:
			case <-time.After(5 * time.Second):
				t.Fatalf("serve still runs 5 s after a server failed:\n%s", c.output())
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(c.output(), `"msg":"fatal"`) {
				t.Errorf("exit %v, output:\n%s", err, c.output())
			}
			for name, addr := range addrs {
				if conn, err := net.Dial("tcp", addr); err == nil {
					_ = conn.Close()
					t.Errorf("%s: still listening", name)
				}
			}
		})
	}
}

// shutdownListener shuts down for reading the socket of process pid that listens on
// port, through a copy of its descriptor (pidfd_getfd, which a parent may take from its
// child): the accept of the process then fails with EINVAL.
func shutdownListener(pid int, port string) error {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pidfd) }()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return err
	}
	for _, e := range entries {
		var target int
		if _, err := fmt.Sscan(e.Name(), &target); err != nil {
			continue
		}
		fd, err := unix.PidfdGetfd(pidfd, target, 0)
		if err != nil {
			if errors.Is(err, unix.EPERM) {
				return err
			}
			continue
		}
		sa, err := unix.Getsockname(fd)
		listening, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		if in4, ok := sa.(*unix.SockaddrInet4); err == nil && ok && fmt.Sprint(in4.Port) == port && listening == 1 {
			err = unix.Shutdown(fd, unix.SHUT_RD)
			_ = unix.Close(fd)
			return err
		}
		_ = unix.Close(fd)
	}
	return fmt.Errorf("no socket listening on %s", port)
}
