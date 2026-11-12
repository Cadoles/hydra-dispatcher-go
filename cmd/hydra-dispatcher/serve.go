package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/admin"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/adminui"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/audit"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/config"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/emulated"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/front"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/hydra/flowcodec"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/limiter"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/metrics"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/remember"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/seal"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/sentrylog"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/state"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/tracing"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/webhook"
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
	cfg, logs, err := loadConfig(*configPath, os.Stdout)
	if err != nil {
		return err
	}
	sentryOptions := cfg.Observability.Sentry
	release := sentryOptions.Release
	if release == "" {
		release = "hydra-dispatcher@" + version
	}
	stateBackend := "memory"
	if cfg.State.RedisDSN != "" {
		stateBackend = "redis"
	}
	tracker, err := sentrylog.New(sentrylog.Options{DSN: sentryOptions.DSN, Environment: sentryOptions.Environment, Release: release,
		SampleRate: sentryOptions.SampleRate, TracesSampleRate: sentryOptions.TracesSampleRate, MaxEventsPerMinute: sentryOptions.MaxEventsPerMinute,
		HydraMode: configuredHydraMode(cfg), StateBackend: stateBackend})
	if err != nil {
		return fmt.Errorf("observability.sentry.dsn: %w", err)
	}
	// What the observers keep is flushed at the end, all at once (Q82).
	flushes := []func(){tracker.Flush}
	defer func() { flushTogether(flushes...) }()
	instance, _ := os.Hostname()
	stopTracing, err := tracing.Setup(ctx, tracing.Options{Enabled: cfg.Observability.Tracing.Enabled, Endpoint: cfg.Observability.Tracing.Endpoint,
		Protocol: cfg.Observability.Tracing.Protocol, SamplerRatio: cfg.Observability.Tracing.SamplerRatio, Version: version,
		Environment: sentryOptions.Environment, Instance: instance, SentryDSN: sentryOptions.DSN, SentryRatio: sentryOptions.TracesSampleRate})
	if err != nil {
		return err
	}
	flushes = append(flushes, stopTracing)
	logs.app = slog.New(tracker.Handler(logs.app.Handler()))
	slog.SetDefault(logs.app)
	httpx.StandardLog(logs.app)
	logger := logs.app
	// A theme that fails stops the start before the stores are touched.
	theme, err := loadTheme(cfg.UI.ThemeDir, logger)
	if err != nil {
		return err
	}
	// So do keys of the admin API that cannot sign or verify.
	adminKeys, err := loadAdminKeys(cfg.Admin, logger)
	if err != nil {
		return err
	}
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
	db, err := openConfig(ctx, cfg)
	if err != nil {
		_ = states.Close()
		return err
	}
	var inFlight httpx.InFlight
	watch := metrics.New(cfg.Observability.Metrics.MaxLabelValues, logger)
	audited, closeAudit, err := newAudit(cfg, os.Stdout, logger, watch.AuditDropped)
	if err != nil {
		_ = states.Close()
		_ = db.Close()
		return err
	}
	// Its queue is emptied at the end, beside the traces and Sentry (Q89).
	flushes = append(flushes, closeAudit)
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	refreshed := make(chan struct{})
	// The stores close once the configuration is no longer refreshed and no
	// handler runs.
	stop := func() {
		stopRefresh()
		<-refreshed
		closeStores(logger, &inFlight, states, db)
	}
	live, err := startConfig(ctx, cfg, db, logs, theme)
	if err != nil {
		close(refreshed)
		stop()
		return err
	}
	watch.ConfigRefreshed(nil)
	live.OnRefresh = watch.ConfigRefreshed
	// A write reads back at once on the instance that made it; those of the
	// other instances show as soon as Listen hears of them (Q99), every
	// RefreshEvery at worst.
	db.OnCommit(func(ctx context.Context) {
		// Bounded as the refreshes of Run: a database frozen after the commit
		// would otherwise hold Live and its refreshes without a word (revue R33).
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitRefreshTimeout)
		defer cancel()
		_ = live.Refresh(refreshCtx) // logged by Refresh
	})
	go func() {
		defer close(refreshed)
		var listening sync.WaitGroup
		listening.Go(func() { db.Listen(refreshCtx, live.Changed, logger) })
		live.Run(refreshCtx, store.RefreshEvery)
		listening.Wait()
	}()

	var draining atomic.Bool
	handler, err := newHandler(cfg, logger, logs.access, services{database: db.Ping, states: states, config: live, metrics: watch, audit: audited, sentry: tracker,
		draining: draining.Load, theme: theme, adminKeys: adminKeys, adminWriter: writerOf(db), adminRehash: rehasherOf(db), accounts: db})
	if err != nil {
		stop()
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		stop()
		return err
	}
	// stopping ends both servers: after the drain that follows SIGTERM, or as soon as
	// one stops on its own, on an accept error say. A server that stops stops the
	// process, which would otherwise wait for the other one forever (R29).
	stopping, stopServers := context.WithCancel(context.WithoutCancel(ctx))
	defer stopServers()
	go drain(ctx, stopping, stopServers, &draining, cfg.Server.DrainDelay.Std())
	stopMetrics, err := serveMetrics(stopping, stopServers, cfg, watch, audited, logger, logs.access)
	if err != nil {
		_ = ln.Close()
		stop()
		return err
	}
	logger.Info("server.started", "addr", ln.Addr().String())
	err = httpx.Serve(stopping, httpx.NewServer(inFlight.Track(handler), logger, cfg.Observability.LogIP), ln, shutdownGrace)
	stopServers()
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("server.shutdown_timeout", "grace", shutdownGrace.String())
		err = nil
	}
	err = errors.Join(err, stopMetrics())
	stop()
	if err != nil {
		return err
	}
	logger.Info("server.stopped")
	return nil
}

// drain answers the first SIGTERM (ctx done): /ready says 503 for delay, the requests
// still served, while an orchestrator stops routing to the instance, then the servers
// stop (Q82). Distroless has no sleep for a preStop hook: the delay is here. A
// server that stops on its own ends it at once.
func drain(ctx, stopping context.Context, stopServers func(), draining *atomic.Bool, delay time.Duration) {
	select {
	case <-stopping.Done():
		return
	case <-ctx.Done():
	}
	draining.Store(true)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-stopping.Done():
	}
	stopServers()
}

// flushTogether runs the flushes of what the observers keep, traces and Sentry, at
// the same time: each is bounded by its own delay, 2 s, and together they take 2 s
// at most, not the sum (Q82).
func flushTogether(flushes ...func()) {
	var wg sync.WaitGroup
	for _, f := range flushes {
		wg.Go(f)
	}
	wg.Wait()
}

// serveMetrics serves /metrics on observability.metrics.listen, a port of its own that
// the ingress does not expose, filtered as on the main one; without that key, it does
// nothing and newHandler routes /metrics. It stops with stopping, and stops the main
// server through stopServers when it stops on its own. The function it returns waits
// for its end, and returns its error.
func serveMetrics(stopping context.Context, stopServers func(), cfg *config.Config, watch *metrics.Metrics, audited *audit.Log, logger, accessLogger *slog.Logger) (func() error, error) {
	addr := cfg.Observability.Metrics.Listen
	if addr == "" {
		return func() error { return nil }, nil
	}
	trusted, err := cfg.Server.TrustedProxies.Prefixes()
	if err != nil {
		return nil, err
	}
	hosts, err := cfg.Security.MetricsAuthorizedHosts.Prefixes()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", watch.Filtered(hosts, cfg.Observability.LogIP, func(c context.Context) { audited.Refused(c, "metrics") }))
	handler := httpx.Chain(httpx.Routes(mux), httpx.RealIP(trusted), httpx.Trace(nil),
		httpx.AccessLog(accessLogger, cfg.Observability.AccessLogSample, cfg.Observability.LogIP), httpx.Recover(logger))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("observability.metrics.listen: %w", err)
	}
	logger.Info("metrics.started", "addr", ln.Addr().String())
	done := make(chan struct{})
	var served error
	go func() {
		defer close(done)
		if err := httpx.Serve(stopping, httpx.NewServer(handler, logger, cfg.Observability.LogIP), ln, shutdownGrace); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			served = fmt.Errorf("observability.metrics.listen: %w", err)
			stopServers()
		}
	}()
	return func() error { <-done; return served }, nil
}

// configuredHydraMode is the mode hydraSource chooses, for what is set before it.
func configuredHydraMode(cfg *config.Config) string {
	if cfg.Hydra.Version != "2.1" && len(cfg.Hydra.SystemSecrets) > 0 {
		return "decrypt"
	}
	return "fallback"
}

// newAudit opens the audit log where observability.audit.output says: stdout beside the
// other two streams, told apart by log_type, a file it appends to, or syslog, the
// failure to open it stopping serve: an audit log must not vanish in silence. Its level
// and format do not follow log_level or log_format: a SIEM reads it, in JSON. Its lines
// go through a bounded queue (Q89): an output that blocks loses lines, counted by
// dropped and told by logger, instead of holding the requests. The function it returns
// empties the queue within auditDrain, then closes the output, unless it still blocks
// (closeAudit).
func newAudit(cfg *config.Config, stdout io.Writer, logger *slog.Logger, dropped func()) (*audit.Log, func(), error) {
	w, closer := stdout, func() {}
	switch out := cfg.Observability.Audit.Output; {
	case out == "syslog":
		s, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "hydra-dispatcher")
		if err != nil {
			return nil, nil, fmt.Errorf("observability.audit.output: %w", err)
		}
		w, closer = s, func() { _ = s.Close() }
	case strings.HasPrefix(out, "file:"):
		f, err := os.OpenFile(strings.TrimPrefix(out, "file:"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("observability.audit.output: %w", err)
		}
		w, closer = f, func() { _ = f.Close() }
	}
	key := cfg.Secrets.AuditKey
	if key == nil {
		mac := hmac.New(sha256.New, cfg.Secrets.ChallengeKey)
		mac.Write([]byte("dispatcher-audit-key"))
		key = mac.Sum(nil)
	}
	queue := audit.NewQueue(w, audit.QueueSize, logger, dropped)
	drain := func() {
		ctx, cancel := context.WithTimeout(context.Background(), auditDrain)
		defer cancel()
		closeAudit(ctx, queue, closer)
	}
	auditLogger := slog.New(newLogHandler(queue, "json", slog.LevelInfo)).With("log_type", "audit")
	return audit.New(auditLogger, key, !cfg.Observability.Audit.PseudonymizeSubject), drain, nil
}

// auditDrain is how long the stop gives the lines of the audit still queued, with the
// traces and Sentry (Q82, Q89).
const auditDrain = 2 * time.Second

// closeAudit empties queue until ctx ends, then closes its output by closer, unless the
// queue's writer is still in a Write of it: a syslog whose daemon reads no more holds
// that Write, syslog.Writer.Close waits for it, and the stop would never end (revue
// R30). The output is left to the end of the process, which follows.
func closeAudit(ctx context.Context, queue *audit.Queue, closer func()) {
	if queue.Close(ctx) {
		closer()
	}
}

// loggers are the application, access and warnings loggers of newLoggers.
type loggers struct{ app, access, warnings *slog.Logger }

// loadConfig reads the configuration, makes its application logger, writing
// to w, the default and logs its warnings.
func loadConfig(path string, w io.Writer) (*config.Config, loggers, error) {
	cfg, warnings, err := config.Load(path, os.Environ())
	if err != nil {
		// A warning may explain the error: a mistyped variable left a key unset.
		for _, w := range warnings {
			slog.Warn("config.warning", "detail", w)
		}
		return nil, loggers{}, fmt.Errorf("configuration: %w", err)
	}
	var l loggers
	l.app, l.access, l.warnings = newLoggers(w, cfg.Observability)
	slog.SetDefault(l.app)
	for _, w := range warnings {
		l.warnings.Warn("config.warning", "detail", w)
	}
	return cfg, l, nil
}

// loadTheme reads and checks the theme of ui.theme_dir, the embedded one for
// "" (Thèmes).
// loadAdminKeys reads the keys of the admin API, nil when it is not served:
// disabled, or enabled without its private key, which config warns of.
func loadAdminKeys(a config.Admin, logger *slog.Logger) (*admin.Keys, error) {
	if !a.API.Enabled || a.API.PrivateKey == "" {
		return nil, nil
	}
	keys, err := admin.ParseKeys(a.API.PrivateKey, a.API.PublicKey, a.API.PublicKeysPrevious)
	if err != nil {
		return nil, err
	}
	logger.Info("admin.keys_loaded", "kid", keys.KeyID(), "alg", keys.Algorithm(), "previous", keys.Previous())
	return keys, nil
}

func loadTheme(dir string, logger *slog.Logger) (*front.Theme, error) {
	theme, err := front.LoadTheme(dir)
	if err == nil {
		err = front.Check(theme)
	}
	if err != nil {
		if dir == "" {
			return nil, fmt.Errorf("pages: %w", err)
		}
		return nil, fmt.Errorf("ui.theme_dir %s: %w", dir, err)
	}
	if dir != "" {
		// version is the binary's, in every line.
		logger.Info("theme.loaded", "dir", dir, "theme", theme.Manifest.Name, "theme_version", theme.Manifest.Version, "api", theme.Manifest.API, "locales", theme.Locales())
	}
	return theme, nil
}

// startConfig applies serve.migrate and serve.bootstrap, then reads the first
// snapshot of the configuration.
func startConfig(ctx context.Context, cfg *config.Config, db configStore, logs loggers, theme *front.Theme) (*store.Live, error) {
	if err := prepareStore(ctx, cfg, db, logs.app); err != nil {
		return nil, err
	}
	hosts, err := cfg.Security.EmulatedAPIAuthorizedHosts.Prefixes()
	if err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	return store.NewLive(readCtx, identified{Source: db, hosts: hosts, allowHTTP: cfg.TLS.AllowHTTP, signed: cfg.Secrets.WebhookSigningKey != nil,
		secrets: cfg.EnvironmentSecrets(), theme: theme}, logs.app, logs.warnings)
}

// identified refuses a snapshot whose webhooks cannot be called (webhook.Check), and
// adds to each one the warnings of the apps'
// identification against security.emulated_api_authorized_hosts, which the
// store does not know (emulated.Warnings), that of a webhook run as a local
// program while secrets come from the environment (webhook.ProgramWarnings),
// those of the locales the theme has no catalog for (Q92), and those of the scopes
// of API clients the admin API does not know (Q96).
type identified struct {
	store.Source
	hosts     []netip.Prefix
	allowHTTP bool
	signed    bool
	// secrets are the secret keys the environment gave.
	secrets []string
	// theme is that of the pages; nil, no warning on the locales.
	theme *front.Theme
}

func (i identified) Snapshot(ctx context.Context) (*store.Snapshot, error) {
	s, err := i.Source.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err := webhookCheck(i.allowHTTP, i.signed)(s); err != nil {
		return nil, err
	}
	// A copy: a source may give the same snapshot twice.
	c := *s
	c.Warnings = append(slices.Clip(s.Warnings), emulated.Warnings(s.Apps, i.hosts)...)
	c.Warnings = append(c.Warnings, webhook.ProgramWarnings(s.Settings, i.secrets)...)
	c.Warnings = append(c.Warnings, admin.Warnings(s.APIClients)...)
	if i.theme != nil {
		c.Warnings = append(c.Warnings, front.LocaleWarnings(i.theme, s.Settings)...)
	}
	return &c, nil
}

// commitRefreshTimeout bounds the refresh of the snapshot after a write of the
// instance, as Run bounds its own.
const commitRefreshTimeout = 10 * time.Second

// store.Postgres writes the resources of the admin API.
var _ admin.Writer = (*store.Postgres)(nil)

// The rehash of rehasherOf, which a type assertion would otherwise miss.
var _ interface {
	RehashAPIClient(ctx context.Context, id, old, new string) error
} = (*store.Postgres)(nil)

// writerOf is the writer of the admin API in db: store.Postgres; nil for a
// store that does not write, the fake of the tests.
func writerOf(db configStore) admin.Writer {
	w, _ := db.(admin.Writer)
	return w
}

// rehasherOf is the rehash of a client's secret by the store (Q118), nil when
// the store does not write.
func rehasherOf(db configStore) func(ctx context.Context, id, old, new string) error {
	if r, ok := db.(interface {
		RehashAPIClient(ctx context.Context, id, old, new string) error
	}); ok {
		return r.RehashAPIClient
	}
	return nil
}

// webhookCheck refuses a snapshot whose webhooks cannot be called
// (webhook.Check): serve at startup and at each refresh, and every write
// before its commit (openConfig).
func webhookCheck(allowHTTP, signed bool) func(*store.Snapshot) error {
	return func(s *store.Snapshot) error {
		return webhook.Check(s.Settings, allowHTTP, signed)
	}
}

// shutdownGrace is how long in-flight requests may run once the drain is over,
// and handlersGrace how long the handlers of the requests cut then may still run
// before the stores close. With the 2 s that traces and Sentry take together
// at most, the stop holds in the 10 s docker stop waits before SIGKILL, the
// dispatcher cutting the requests and saying so; server.drain_delay comes on
// top (Q82).
const (
	shutdownGrace = 6 * time.Second
	handlersGrace = time.Second
)

// newStateStore opens the store of the flows in progress: Redis (or
// Dragonfly) when state.redis_dsn is set, connected at the first call, in
// memory otherwise. The tests wrap it, to see it closed.
var newStateStore = func(c config.State) (state.StateStore, error) {
	if c.RedisDSN != "" {
		return state.NewRedis(c.RedisDSN, c.KeyPrefix, c.RedisPoolSize)
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

// snapshots gives the configuration of the moment: store.Live.
type snapshots interface {
	Snapshot() *store.Snapshot
}

// services are what the handlers use besides the configuration file: the
// check of the configuration store, for /ready, the state store and the
// configuration of the moment.
type services struct {
	database httpx.Check
	states   state.StateStore
	config   snapshots
	// metrics is the catalogue of the instance, audit its audit log.
	metrics *metrics.Metrics
	audit   *audit.Log
	// sentry is nil without a DSN.
	sentry *sentrylog.Tracker
	// draining tells that the instance stops, /ready answering 503; nil: never.
	draining func() bool
	// theme is that of the pages; nil for the embedded one.
	theme *front.Theme
	// adminKeys are those of the admin API; nil, it is not served.
	adminKeys *admin.Keys
	// adminWriter writes its resources; nil, it serves /token alone.
	adminWriter admin.Writer
	// accounts are the admin accounts, the admin UI reads them at each
	// request (Q120).
	accounts adminui.Accounts
	// adminRehash hashes again a secret of another cost (Q118); nil without a
	// store that writes.
	adminRehash func(ctx context.Context, id, old, new string) error
}

// newHandler builds the routes behind the middleware chain every surface
// shares: the probes, the emulated API (P4) and the pages (P5), both on the
// flow engine.
func newHandler(cfg *config.Config, logger, accessLogger *slog.Logger, s services) (http.Handler, error) {
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
	keys := flow.Keys{cfg.Secrets.ChallengeKey}
	for _, k := range cfg.Secrets.ChallengeKeysPrevious {
		keys = append(keys, k)
	}
	source, err := hydraSource(cfg.Hydra, hydraClient)
	if err != nil {
		return nil, err
	}
	logger.Info("hydra.mode", "mode", hydraMode(source), "hydra_version", cfg.Hydra.Version)
	previous := make([][]byte, len(cfg.Secrets.CookieKeysPrevious))
	for i, k := range cfg.Secrets.CookieKeysPrevious {
		previous[i] = k
	}
	memories, err := remember.New(cfg.Secrets.CookieKey, previous...)
	if err != nil {
		return nil, err
	}
	cookieKeys, err := seal.New(cfg.Secrets.CookieKey, previous...)
	if err != nil {
		return nil, err
	}
	webhooks, err := webhook.New(cfg.Webhooks, cfg.TLS.MinVersion, cfg.Secrets.WebhookSigningKey)
	if err != nil {
		return nil, err
	}
	watch := s.metrics
	hydraClient.Observer = watch
	watch.WatchHydraInFlight(hydraClient.InFlight)
	stateBackend := "memory"
	if cfg.State.RedisDSN != "" {
		stateBackend = "redis"
	}
	watch.SetBuild(version, stateBackend, hydraMode(source))
	failures := cfg.Security.FailureRateLimit
	limit := limiter.New(failures.Max, failures.Per.Std(), failures.Block.Std())
	limit.OnBlock = func(c context.Context) {
		logger.WarnContext(c, "security.rate_limited", "ip", httpx.FormatIP(httpx.ClientIP(c), cfg.Observability.LogIP))
		s.audit.Blocked(c)
	}
	limit.OnRefused = func(_ context.Context, surface string) { watch.RateLimited(surface) }
	logSample := httpx.NewSampler(time.Minute)
	watch.LogSample = logSample
	observers := []flow.Observer{watch, s.audit, tracing.Observer{HydraMode: hydraMode(source)}, limit}
	if s.sentry != nil {
		observers = append(observers, s.sentry)
	}
	engine := &flow.Orchestrator{
		Store:                  tracing.States(watch.States(s.states), stateBackend),
		Config:                 s.config,
		Source:                 source,
		Hydra:                  hydraClient,
		Webhooks:               watch.Webhooks(webhooks),
		Observers:              observers,
		BaseURL:                cfg.Server.BaseURL,
		LoginConsentTTL:        cfg.Hydra.LoginConsentTTL.Std(),
		Keys:                   keys,
		PropagateWithoutRecord: cfg.Logout.PropagateWithoutRecord,
		Log:                    logger,
		LogSample:              logSample,
	}
	pages, err := front.New(front.Options{
		Engine:     engine,
		Config:     s.config,
		Remember:   memories,
		BaseURL:    cfg.Server.BaseURL,
		CookiePath: cfg.Server.CookiePath,
		ShowValues: cfg.Consent.ShowValues,
		Logger:     logger,

		SkipUnavailable: watch.SkipUnavailable,

		RememberLastFlow: cfg.UI.RememberLastFlow,
		Guard:            limit.Guard("front"),
		Theme:            s.theme,
		Reload:           cfg.UI.Reload,
	})
	if err != nil {
		return nil, fmt.Errorf("pages: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /health", httpx.Health())
	mux.Handle("GET /ready", httpx.Ready(map[string]httpx.Check{
		"hydra":    hydraClient.Ready,
		"database": s.database,
		"state":    s.states.Ping, // a PING to Redis
	}, 2*time.Second, logger, httpx.ReadyOptions{Draining: s.draining, Observe: watch.ReadyCheck}))
	emulated.Register(mux, emulated.Options{
		Engine:          engine,
		AuthorizedHosts: loginApps,
		LegacyV1Paths:   cfg.EmulatedAPI.LegacyV1Paths,
		Logger:          logger,
		LogIP:           cfg.Observability.LogIP,
		Refused: func(c context.Context) {
			watch.Refused("emulated")
			s.audit.Refused(c, "emulated")
		},
		LogSample: logSample,
	})
	pages.Register(mux)
	if s.adminKeys != nil {
		hosts, err := cfg.Security.AdminAuthorizedHosts.Prefixes()
		if err != nil {
			return nil, err
		}
		adminAPI, err := admin.New(admin.Options{
			Keys: s.adminKeys, Config: s.config, Issuer: cfg.Server.BaseURL, TokenTTL: cfg.Admin.API.TokenTTL.Std(),
			AuthorizedHosts: hosts, RatePerMinute: cfg.Admin.API.RateLimitPerMinute,
			Logger: logger, LogIP: cfg.Observability.LogIP, LogSample: logSample,
			Refused: func(c context.Context) {
				watch.Refused("admin")
				s.audit.Refused(c, "admin")
			},
			RateLimited: func(c context.Context) {
				watch.AdminRateLimited()
				s.audit.AdminRateLimited(c)
			},
			Token:  s.audit.Token,
			Rehash: s.adminRehash,
			Writer: s.adminWriter,
			Wrote:  s.audit.Wrote,
		})
		if err != nil {
			return nil, err
		}
		adminAPI.Register(mux)
	}
	adminHosts, err := cfg.Security.AdminAuthorizedHosts.Prefixes()
	if err != nil {
		return nil, err
	}
	ready := map[string]httpx.Check{"hydra": hydraClient.Ready, "database": s.database, "state": s.states.Ping}
	ui, err := adminui.New(adminui.Options{
		Enabled: cfg.Admin.UI.Enabled, AuthorizedHosts: adminHosts, Accounts: s.accounts, Keys: cookieKeys,
		BaseURL: cfg.Server.BaseURL, CookiePath: cfg.Server.CookiePath,
		IdleTimeout: cfg.Admin.Session.IdleTimeout.Std(), MaxAge: cfg.Admin.Session.MaxAge.Std(), ReauthWindow: cfg.Admin.Session.ReauthWindow.Std(),
		LoginsPerMinute: adminLoginsPerMinute,
		Logger:          logger, LogIP: cfg.Observability.LogIP, LogSample: logSample,
		Refused: func(c context.Context) {
			watch.Refused("admin")
			s.audit.Refused(c, "admin_ui")
		},
		RateLimited: func(c context.Context) {
			watch.AdminRateLimited()
			s.audit.AdminRateLimited(c)
		},
		Login:     s.audit.AdminLogin,
		Logout:    s.audit.AdminLogout,
		Dashboard: func(c context.Context) adminui.Dashboard { return dashboard(c, s.config.Snapshot(), ready) },
		Config:    s.config,
		Writer:    s.adminWriter,
		Scopes:    admin.Scopes,
		Wrote:     s.audit.UIWrote,
		Version:   version,
	})
	if err != nil {
		return nil, err
	}
	ui.Register(mux)
	if cfg.Observability.Metrics.Listen == "" {
		hosts, err := cfg.Security.MetricsAuthorizedHosts.Prefixes()
		if err != nil {
			return nil, err
		}
		mux.Handle("GET /metrics", watch.Filtered(hosts, cfg.Observability.LogIP, func(c context.Context) { s.audit.Refused(c, "metrics") }))
	}

	csp := map[string][]string{}
	for d, sources := range cfg.UI.CSPExtra {
		csp[d] = sources
	}
	return httpx.Chain(httpx.Routes(mux),
		httpx.RealIP(trusted),
		// traceparent is honoured from the proxies and the login apps, by
		// the sources the configuration of the moment declares, within the
		// allowlist of the emulated API (B2): a source outside it, or one
		// written 0.0.0.0/0, would let any client choose its trace id.
		httpx.TraceFrom(func(ip netip.Addr) bool {
			return httpx.Within(trusted, ip) || httpx.Within(loginApps, ip) && appSource(s.config.Snapshot(), ip)
		}),
		tracing.HTTP,
		httpx.SecurityHeaders(httpx.CSP(csp), strings.HasPrefix(cfg.Server.BaseURL, "https://"), cfg.TLS.HSTSIncludeSubdomains),
		watch.HTTP,
		httpx.AccessLog(accessLogger, cfg.Observability.AccessLogSample, cfg.Observability.LogIP),
		httpx.Recover(logger),
		s.sentry.Middleware,
	), nil
}

// adminLoginsPerMinute bounds the attempts of an address at the login of the
// admin UI (Panneau d'administration).
const adminLoginsPerMinute = 10

// dashboard is what the dashboard of the admin UI shows: what /ready checks,
// each within two seconds, and the configuration of the moment.
func dashboard(ctx context.Context, snap *store.Snapshot, checks map[string]httpx.Check) adminui.Dashboard {
	instance, _ := os.Hostname()
	d := adminui.Dashboard{Version: version, Instance: instance, Apps: len(snap.Apps), Flows: len(snap.Flows), APIClients: len(snap.APIClients)}
	for _, f := range snap.Flows {
		if f.Enabled {
			d.FlowsEnabled++
		}
	}
	for _, name := range slices.Sorted(maps.Keys(checks)) {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := checks[name](c)
		cancel()
		dep := adminui.Dependency{Name: name, OK: err == nil}
		if err != nil {
			dep.Detail = "does not answer"
		}
		d.Dependencies = append(d.Dependencies, dep)
	}
	return d
}

// appSource tells whether ip is among the allowed_sources of an app.
func appSource(s *store.Snapshot, ip netip.Addr) bool {
	for _, a := range s.Apps {
		if httpx.Within(a.AllowedSources, ip) {
			return true
		}
	}
	return false
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

// hydraSource is the source of Hydra's requests (Versions Hydra, DEC-1): the
// decryption of the challenges for Hydra 2.2 and 2.3 when Hydra's secrets
// are given, falling back to the admin API; the admin API alone otherwise.
func hydraSource(h config.Hydra, admin flow.AdminReader) (flow.Source, error) {
	fallback := flow.Fallback{Hydra: admin}
	if h.Version == "2.1" || len(h.SystemSecrets) == 0 {
		return fallback, nil
	}
	codec, err := flowcodec.New(flowcodec.Version(h.Version), h.SystemSecrets)
	if err != nil {
		return nil, fmt.Errorf("hydra.system_secrets: %w", err)
	}
	return flow.Decrypt{Codec: codec, Fallback: fallback, TTL: h.LoginConsentTTL.Std()}, nil
}

// hydraMode names the mode of source, for the startup log and hydra_mode.
func hydraMode(source flow.Source) string {
	if _, ok := source.(flow.Decrypt); ok {
		return "decrypt"
	}
	return "fallback"
}
