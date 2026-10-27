package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// NewServer returns a server with the timeouts of the design document.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// Serve runs srv on ln until ctx ends, then lets in-flight requests finish
// for up to 10 seconds.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Check tells whether a dependency is usable.
type Check func(ctx context.Context) error

// Ready answers 200 when every check passes within timeout, 503 otherwise.
// Checks run in parallel. The body only names each check's state: /ready is
// open to the orchestrator, so error details go to the log.
func Ready(checks map[string]Check, timeout time.Duration, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		var mu sync.Mutex
		var wg sync.WaitGroup
		states := make(map[string]string, len(checks))
		ready := true
		for name, check := range checks {
			wg.Go(func() {
				state := "ok"
				if err := check(ctx); err != nil {
					state = "unavailable"
					logger.WarnContext(r.Context(), "ready.check_failed", "check", name, "err", err)
				}
				mu.Lock()
				defer mu.Unlock()
				states[name] = state
				ready = ready && state == "ok"
			})
		}
		wg.Wait()

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

// Health answers 200 as soon as the process serves, whatever the
// dependencies (those are /ready's business).
func Health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
