package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
)

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file (default: DISPATCHER_* variables only)")
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}

	cfg, warnings, err := config.Load(*configPath, os.Environ())
	if err != nil {
		// A warning may explain the error: a mistyped variable left a key unset.
		for _, w := range warnings {
			slog.Warn("config.warning", "detail", w)
		}
		return fmt.Errorf("configuration: %w", err)
	}
	logs := newLogHandler(os.Stdout, cfg.Observability)
	logger := slog.New(logs).With("log_type", "app")
	slog.SetDefault(logger)
	for _, w := range warnings {
		logger.Warn("config.warning", "detail", w)
	}

	handler, err := newHandler(cfg, logger, slog.New(logs).With("log_type", "access"))
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}
	logger.Info("server.started", "addr", ln.Addr().String())
	if err := httpx.Serve(ctx, httpx.NewServer(handler), ln); err != nil {
		return err
	}
	// Stores will be closed here, once in-flight requests are done.
	logger.Info("server.stopped")
	return nil
}

// newHandler builds the routes behind the middleware chain every surface
// shares.
func newHandler(cfg *config.Config, logger, accessLogger *slog.Logger) (http.Handler, error) {
	trusted, err := cfg.Server.TrustedProxies.Prefixes()
	if err != nil {
		return nil, err
	}
	loginApps, err := cfg.Security.EmulatedAPIAuthorizedHosts.Prefixes()
	if err != nil {
		return nil, err
	}

	hydraClient, err := hydra.New(cfg.Hydra, cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("hydra client: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /health", httpx.Health())
	mux.Handle("GET /ready", httpx.Ready(map[string]httpx.Check{
		"hydra": hydraClient.Ready,
	}, 2*time.Second, logger))

	return httpx.Chain(httpx.Routes(mux),
		httpx.RealIP(trusted),
		// traceparent is honoured from proxies and login apps only.
		httpx.Trace(append(trusted, loginApps...)),
		httpx.AccessLog(accessLogger, cfg.Observability.AccessLogSample, cfg.Observability.LogIP),
		httpx.Recover(logger),
	), nil
}

// newLogHandler writes one JSON (or text) line per record, stamped with the
// instance and version, and with the trace id and route of request contexts.
func newLogHandler(w io.Writer, o config.Observability) slog.Handler {
	var level slog.Level
	_ = level.UnmarshalText([]byte(o.LogLevel)) // validated by config.Load
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: utcMillis}
	var h slog.Handler = slog.NewJSONHandler(w, opts)
	if o.LogFormat == "text" {
		h = slog.NewTextHandler(w, opts)
	}
	instance, _ := os.Hostname()
	return httpx.LogHandler(h.WithAttrs([]slog.Attr{
		slog.String("instance", instance),
		slog.String("version", version),
	}))
}

// utcMillis writes the record time in RFC 3339, UTC, to the millisecond.
func utcMillis(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
	}
	return a
}
