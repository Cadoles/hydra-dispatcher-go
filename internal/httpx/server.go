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
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// NewServer returns a server with the timeouts of the design document. The
// messages of net/http itself (a panic outside Recover, a superfluous
// WriteHeader, an accept error) go to logger as http.server_error.
func NewServer(h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(serverLog{logger}, "", 0),
	}
}

// serverLog turns each message of net/http into an error record with a
// stable name, instead of an info record whose message is free text.
type serverLog struct{ logger *slog.Logger }

func (l serverLog) Write(p []byte) (int, error) {
	l.logger.Error("http.server_error", "detail", strings.TrimSpace(string(p)))
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

// Check tells whether a dependency is usable.
type Check func(ctx context.Context) error

// Ready answers 200 when every check passes within timeout, 503 otherwise.
// Checks run in parallel; one still running at timeout counts as failed, and
// a panic fails its check. The body only names each check's state: /ready is
// open to the orchestrator, so error details go to the log, once per change
// of state, since anyone can call it in a loop.
func Ready(checks map[string]Check, timeout time.Duration, logger *slog.Logger) http.Handler {
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
		ready := true
		for name, err := range errs {
			states[name] = "ok"
			if err != nil {
				states[name], ready = "unavailable", false
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
			}
			mu.Unlock()
		}

		status, body := http.StatusOK, "ready"
		if !ready {
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
