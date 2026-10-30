package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

// configEnv names the configuration file when -config is not given: the
// image's HEALTHCHECK reads it too, for the server.listen it may set.
const configEnv = "DISPATCHER_CONFIG"

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv(configEnv), configHelp)
	if help, err := parseFlags(fs, args); help || err != nil {
		return err
	}
	cfg, logs, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	logger := logs.app
	// The image's HEALTHCHECK reads DISPATCHER_CONFIG, not -config: a file
	// given by -config alone may listen where the probe does not look.
	if *configPath != os.Getenv(configEnv) {
		switch probe, err := probeURL(); {
		case err != nil:
			logs.warnings.Warn("config.warning", "detail", fmt.Sprintf("healthcheck without -url fails on %s: %v; give the file by %s rather than by -config", configEnv, err, configEnv))
		case probe != healthURL(cfg.Server.Listen):
			logs.warnings.Warn("config.warning", "detail", fmt.Sprintf("server.listen is %q, but healthcheck without -url probes %s; give the file by %s rather than by -config", cfg.Server.Listen, probe, configEnv))
		}
	}

	states, err := newStateStore(cfg.State)
	if err != nil {
		return err
	}
	db, err := openStore(ctx, cfg.Store.DSN)
	if err != nil {
		_ = states.Close()
		return err
	}
	var inFlight httpx.InFlight
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	refreshed := make(chan struct{})
	// The stores close once the configuration is no longer refreshed and no
	// handler runs.
	stop := func() {
		stopRefresh()
		<-refreshed
		closeStores(logger, &inFlight, states, db)
	}
	live, err := startConfig(ctx, cfg, db, logs)
	if err != nil {
		close(refreshed)
		stop()
		return err
	}
	go func() {
		defer close(refreshed)
		live.Run(refreshCtx, store.RefreshEvery)
	}()

	handler, err := newHandler(cfg, logger, logs.access, db.Ping)
	if err != nil {
		stop()
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		stop()
		return err
	}
	logger.Info("server.started", "addr", ln.Addr().String())
	err = httpx.Serve(ctx, httpx.NewServer(inFlight.Track(handler), logger), ln, shutdownGrace)
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("server.shutdown_timeout", "grace", shutdownGrace.String())
		err = nil
	}
	stop()
	if err != nil {
		return err
	}
	logger.Info("server.stopped")
	return nil
}

// loggers are the application, access and warnings loggers of newLoggers.
type loggers struct{ app, access, warnings *slog.Logger }

// loadConfig reads the configuration, makes its application logger the
// default and logs its warnings.
func loadConfig(path string) (*config.Config, loggers, error) {
	cfg, warnings, err := config.Load(path, os.Environ())
	if err != nil {
		// A warning may explain the error: a mistyped variable left a key unset.
		for _, w := range warnings {
			slog.Warn("config.warning", "detail", w)
		}
		return nil, loggers{}, fmt.Errorf("configuration: %w", err)
	}
	var l loggers
	l.app, l.access, l.warnings = newLoggers(os.Stdout, cfg.Observability)
	slog.SetDefault(l.app)
	for _, w := range warnings {
		l.warnings.Warn("config.warning", "detail", w)
	}
	return cfg, l, nil
}

// startConfig applies serve.migrate and serve.bootstrap, then reads the first
// snapshot of the configuration.
func startConfig(ctx context.Context, cfg *config.Config, db configStore, logs loggers) (*store.Live, error) {
	if err := prepareStore(ctx, cfg, db, logs.app); err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	return store.NewLive(readCtx, db, logs.app, logs.warnings)
}

// shutdownGrace is how long in-flight requests may run after SIGTERM, and
// handlersGrace how long the handlers of the requests cut then may still run
// before the stores close. Both stay under the 10 s docker stop waits before
// SIGKILL, so the dispatcher cuts them and says so.
const (
	shutdownGrace = 8 * time.Second
	handlersGrace = time.Second
)

// newStateStore opens the store of the flows in progress: in memory while
// state.redis_dsn is empty. The tests wrap it, to see it closed.
var newStateStore = func(c config.State) (state.StateStore, error) {
	if c.RedisDSN != "" {
		return nil, errors.New("state.redis_dsn: the Redis store is not available yet; leave it empty for the in-memory store")
	}
	return state.NewMemory(), nil
}

// closeStores closes the stores once no handler runs, or once handlersGrace
// is over: a handler still running then gets errors from them.
func closeStores(logger *slog.Logger, inFlight *httpx.InFlight, states state.StateStore, db io.Closer) {
	ctx, cancel := context.WithTimeout(context.Background(), handlersGrace)
	defer cancel()
	if n, err := inFlight.Wait(ctx); err != nil {
		logger.Warn("server.handlers_running", "count", n, "grace", handlersGrace.String())
	}
	if err := states.Close(); err != nil {
		logger.Error("state.close_failed", "err", err)
	}
	if err := db.Close(); err != nil {
		logger.Error("store.close_failed", "err", err)
	}
}

// newHandler builds the routes behind the middleware chain every surface
// shares. database is the check of the configuration store, for /ready.
func newHandler(cfg *config.Config, logger, accessLogger *slog.Logger, database httpx.Check) (http.Handler, error) {
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
		"hydra":    hydraClient.Ready,
		"database": database,
	}, 2*time.Second, logger))

	return httpx.Chain(httpx.Routes(mux),
		httpx.RealIP(trusted),
		// traceparent is honoured from proxies and login apps only. Concat:
		// an append could share the array RealIP holds.
		httpx.Trace(slices.Concat(trusted, loginApps)),
		httpx.AccessLog(accessLogger, cfg.Observability.AccessLogSample, cfg.Observability.LogIP),
		httpx.Recover(logger),
	), nil
}

// newLoggers returns the application, access and warnings loggers. The access
// log has its own level, info: access_log_sample sets its volume, and its
// errors and aborted requests are written whatever log_level. The warnings
// logger, at warn, writes the configuration warnings whatever log_level too,
// those of the file at startup and those of the database's snapshots: some
// warn of an allowlist open to every client.
func newLoggers(w io.Writer, o config.Observability) (app, access, warnings *slog.Logger) {
	var level slog.Level
	_ = level.UnmarshalText([]byte(o.LogLevel)) // validated by config.Load
	app = slog.New(newLogHandler(w, o.LogFormat, level)).With("log_type", "app")
	access = slog.New(newLogHandler(w, o.LogFormat, slog.LevelInfo)).With("log_type", "access")
	warnings = slog.New(newLogHandler(w, o.LogFormat, slog.LevelWarn)).With("log_type", "app")
	return app, access, warnings
}

// newLogHandler writes one JSON (or text) line per record, stamped with the
// instance and version, and with the trace id and route of request contexts.
// Handlers sharing w do not interleave their lines: os.File serializes each
// write.
func newLogHandler(w io.Writer, format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: logFormat}
	var h slog.Handler = slog.NewJSONHandler(w, opts)
	if format == "text" {
		h = slog.NewTextHandler(w, opts)
	}
	instance, _ := os.Hostname()
	// Given through LogHandler, which then renames an event's own instance
	// or version.
	return httpx.LogHandler(h).WithAttrs([]slog.Attr{
		slog.String("instance", instance),
		slog.String("version", version),
	})
}

// logFormat writes the record time in RFC 3339, UTC, to the millisecond, and
// the level in lowercase, as the design document has them. LogHandler
// renames an event's own time or level; without it, such an attribute of
// another kind is left as it is.
func logFormat(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if a.Value.Kind() == slog.KindTime {
			a.Value = slog.StringValue(a.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
		}
	case slog.LevelKey:
		if l, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(strings.ToLower(l.String()))
		}
	}
	return a
}
