// Command dispatcher is the single login app Ory Hydra talks to. It chains
// several real login apps into a flow (MFA, identity provider choice) by
// replaying Hydra's login/consent protocol towards each of them. Go rewrite of
// the Symfony hydra-dispatcher.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
)

// version is injected at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// defaultHealthURL matches the default server.listen.
const defaultHealthURL = "http://127.0.0.1:8080/health"

// errUsage reports a command line error; usage has already been printed.
var errUsage = errors.New("usage error")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"serve", "run the HTTP server", serve},
	{"healthcheck", "probe /health of a local server (container HEALTHCHECK)", healthcheck},
	{"version", "print the version", printVersion},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr)
	stop()
	switch {
	case errors.Is(err, errUsage):
		os.Exit(2)
	case err != nil:
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errUsage
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		usage(stderr)
		return nil
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(ctx, args[1:])
		}
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return errUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dispatcher <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
}

// parseFlags parses a subcommand's flags; -h prints its help and is not an error.
func parseFlags(fs *flag.FlagSet, args []string) (help bool, err error) {
	switch err := fs.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return true, nil
	case err != nil:
		return false, errUsage
	}
	return false, nil
}

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file (default: DISPATCHER_* variables only)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}

	cfg, warnings, err := config.Load(*configPath, os.LookupEnv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	logger := newLogger(cfg.Observability)
	slog.SetDefault(logger)
	for _, w := range warnings {
		logger.Warn("config.warning", "detail", w)
	}

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", srv.Addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Let in-flight requests finish; stores will be closed after this point.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}

func newLogger(o config.Observability) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(o.LogLevel)) // validated by config.Load
	opts := &slog.HandlerOptions{Level: level}
	if o.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func routes() http.Handler {
	mux := http.NewServeMux()
	// Liveness only: answers as soon as the process serves, whatever the
	// dependencies (those belong to /ready).
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	return mux
}

// healthcheck lets a distroless image (no shell, no curl) run a HEALTHCHECK.
func healthcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", defaultHealthURL, "health endpoint to probe")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: status %d", resp.StatusCode)
	}
	return nil
}

func printVersion(_ context.Context, _ []string) error {
	fmt.Println(version)
	return nil
}
