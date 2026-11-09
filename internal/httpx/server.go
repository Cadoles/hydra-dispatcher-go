package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// NewServer returns a server with the timeouts of the design document. The
// messages of net/http itself (a panic outside Recover, a superfluous
// WriteHeader, an accept error) go to logger as http.server_error.
func NewServer(h http.Handler, logger *slog.Logger, logIP string) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(serverLog{logger, logIP}, "", 0),
	}
}

// serverLog turns each message of net/http into an error record with a
// stable name, instead of an info record whose message is free text; the address of a
// client it cites follows observability.log_ip.
type serverLog struct {
	logger *slog.Logger
	logIP  string
}

// remoteAddress finds an address and its port in a message of net/http.
var remoteAddress = regexp.MustCompile(`\[[0-9a-fA-F:.]+\]:\d+|\b\d{1,3}(?:\.\d{1,3}){3}:\d+`)

func (l serverLog) Write(p []byte) (int, error) {
	detail := remoteAddress.ReplaceAllStringFunc(strings.TrimSpace(string(p)), func(found string) string {
		addr, err := netip.ParseAddrPort(found)
		if err != nil {
			return "unknown"
		}
		if masked := FormatIP(addr.Addr().Unmap(), l.logIP); masked != "" {
			return masked
		}
		return "-"
	})
	l.logger.Error("http.server_error", "detail", detail)
	return len(p), nil
}

// StandardLog sends the package log, which a library may write to, as an event of a
// stable name: msg is never a free sentence (Journalisation). Its text stays in detail,
// bounded.
func StandardLog(logger *slog.Logger) {
	log.SetFlags(0)
	log.SetOutput(standardLog{logger})
}

type standardLog struct{ logger *slog.Logger }

func (l standardLog) Write(p []byte) (int, error) {
	l.logger.Info("log.message", "detail", BoundedCause(strings.TrimSpace(string(p))))
	return len(p), nil
}

// Serve runs srv on ln until ctx ends, then lets in-flight requests finish
// for up to grace. Those still running are then cut, and the error wraps
// context.DeadlineExceeded: their connections are closed, but their handlers
// may still be running when Serve returns.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// InFlight counts the handlers running, so that the stores close after the
// last one: past Serve's grace, the connections are cut but the handlers may
// still run. The zero value is ready to use.
type InFlight struct {
	mu sync.Mutex
	n  int
	// idle is closed when n drops to 0, for the Waits in progress.
	idle chan struct{}
}

// Track counts the requests of h, outermost so as to cover every middleware.
// No handler escapes it once Serve has returned: net/http runs none after
// Shutdown begins (it checks after reading each request), and a handler
// leaves the count before its connection turns idle. A goroutine a handler
// leaves running is not counted.
func (f *InFlight) Track(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.n++
		f.mu.Unlock()
		defer f.leave()
		h.ServeHTTP(w, r)
	})
}

func (f *InFlight) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.n == 0 && f.idle != nil {
		close(f.idle)
		f.idle = nil
	}
}

// Wait returns once no handler runs. If ctx ends first, it returns ctx's
// error and the number of handlers still running.
func (f *InFlight) Wait(ctx context.Context) (int, error) {
	f.mu.Lock()
	if f.n == 0 {
		f.mu.Unlock()
		return 0, nil
	}
	if f.idle == nil {
		f.idle = make(chan struct{})
	}
	idle := f.idle
	f.mu.Unlock()
	select {
	case <-idle:
		return 0, nil
	case <-ctx.Done():
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.n == 0 {
			return 0, nil
		}
		return f.n, ctx.Err()
	}
}

// Check tells whether a dependency is usable.
type Check func(ctx context.Context) error

// ReadyOptions are what /ready knows of the instance besides its checks.
type ReadyOptions struct {
	// Draining tells that the instance stops: /ready answers 503 while the
	// requests are still served (server.drain_delay). Nil: never.
	Draining func() bool
	// Observe gets the result of each check, for a gauge. Nil: none.
	Observe func(check string, ok bool)
}

// Ready answers the state of the instance, not that of its dependencies (Q83):
// 200 once it serves, after the first read of its configuration, 503 while it
// drains. A dependency every instance shares, Hydra, the database or the state
// store, would otherwise take them all out at once: the balancer would answer
// 503 without a page, where Hydra down gives page E1004 and its trace_id, and a
// database down stops nothing, the snapshot in memory serving on.
//
// The checks still run, in parallel within timeout; one still running at
// timeout counts as failed, and a panic fails its check. The body only names
// each check's state: /ready is open to the orchestrator, so error details go
// to the log, once per change of state, since anyone can call it in a loop;
// o.Observe gets each result.
func Ready(checks map[string]Check, timeout time.Duration, logger *slog.Logger, o ReadyOptions) http.Handler {
	var mu sync.Mutex
	failing := make(map[string]bool, len(checks)) // the last answer of each check
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		type result struct {
			name string
			err  error
		}
		results := make(chan result, len(checks)) // a late check never blocks
		for name, check := range checks {
			go func() { results <- result{name, runCheck(ctx, check, logger)} }()
		}
		errs := make(map[string]error, len(checks))
	collect:
		for len(errs) < len(checks) {
			select {
			case res := <-results:
				errs[res.name] = res.err
			case <-ctx.Done():
				break collect
			}
		}
		for name := range checks {
			if _, done := errs[name]; !done {
				errs[name] = fmt.Errorf("no answer within %s: %w", timeout, ctx.Err())
			}
		}

		states := make(map[string]string, len(checks))
		for name, err := range errs {
			states[name] = "ok"
			if err != nil {
				states[name] = "unavailable"
			}
		}
		// A client gone before the answer says nothing of the dependencies;
		// counting it would let a loop of cut probes flip the state.
		if r.Context().Err() == nil {
			mu.Lock()
			for name, err := range errs {
				switch {
				case err != nil && !failing[name]:
					logger.WarnContext(r.Context(), "ready.check_failed", "check", name, "err", err)
				case err == nil && failing[name]:
					logger.InfoContext(r.Context(), "ready.check_recovered", "check", name)
				}
				failing[name] = err != nil
				if o.Observe != nil {
					o.Observe(name, err == nil)
				}
			}
			mu.Unlock()
		}

		status, body := http.StatusOK, "ready"
		if o.Draining != nil && o.Draining() {
			status, body = http.StatusServiceUnavailable, "unavailable"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": body, "checks": states})
	})
}

// runCheck runs check, which Ready calls in a goroutine of its own, out of
// Recover's reach: a panic is logged as Recover does, and fails the check
// instead of the process.
func runCheck(ctx context.Context, check Check, logger *slog.Logger) (err error) {
	defer func() {
		if p := recover(); p != nil {
			logger.ErrorContext(ctx, "http.panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return check(ctx)
}

// Health answers 200 as soon as the process serves, whatever the
// dependencies (those are /ready's business).
func Health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
