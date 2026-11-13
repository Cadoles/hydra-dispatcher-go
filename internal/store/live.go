package store

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// RefreshEvery is how often Live reads the configuration again: the writes
// of another replica show within that time.
const RefreshEvery = 60 * time.Second

// refreshTimeout bounds each refresh of Run.
const refreshTimeout = 10 * time.Second

// Source reads a snapshot: Postgres, or a fake in the tests.
type Source interface {
	Snapshot(ctx context.Context) (*Snapshot, error)
}

// Live holds the snapshot the handlers read. It is replaced whole, by Refresh,
// or by Run every RefreshEvery and at each Changed.
type Live struct {
	source   Source
	logger   *slog.Logger
	warnings *slog.Logger
	current  atomic.Pointer[Snapshot]

	// mu runs the refreshes one at a time: a slower read started earlier
	// would otherwise replace a newer snapshot.
	mu     sync.Mutex
	warned []string // the warnings last logged
	failed bool     // the last refresh failed

	// changed holds a refresh Changed asked for, one at most.
	changed chan struct{}

	// OnRefresh, nil for none, is told of each refresh that ended, nil for one that
	// succeeded; not of one the caller canceled. It is set before Run.
	OnRefresh func(err error)
	// OnSnapshot, nil for none, is given each snapshot read, once it is the
	// current one: the window of debug of the level (P25). It is set before Run.
	OnSnapshot func(s *Snapshot)
}

// NewLive reads a first snapshot: without one, nothing can be served. The
// warnings of the snapshots go to warnings, which writes them whatever the
// level of logger: config.warning, as the startup ones.
func NewLive(ctx context.Context, source Source, logger, warnings *slog.Logger) (*Live, error) {
	l := &Live{source: source, logger: logger, warnings: warnings, changed: make(chan struct{}, 1)}
	if err := l.Refresh(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

// Snapshot returns the current snapshot. The caller keeps it for the whole
// request, so that one request sees one configuration.
func (l *Live) Snapshot() *Snapshot { return l.current.Load() }

// Refresh reads the configuration again. On error, the current snapshot
// stays. Refreshes run one at a time.
func (l *Live) Refresh(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := l.source.Snapshot(ctx)
	if err != nil {
		// Canceled by the caller (serve stopping), not past its deadline:
		// the database is not at fault.
		if errors.Is(ctx.Err(), context.Canceled) {
			return err
		}
		if l.OnRefresh != nil {
			l.OnRefresh(err)
		}
		// An error: the replica serves a configuration that no longer
		// follows the database.
		if !l.failed && l.current.Load() != nil {
			l.logger.ErrorContext(ctx, "config.refresh_failed", "cause", err)
		}
		l.failed = true
		return err
	}
	if l.OnRefresh != nil {
		l.OnRefresh(nil)
	}
	if l.failed {
		l.logger.InfoContext(ctx, "config.refresh_recovered")
	}
	l.failed = false
	// Every 60 s: logged when they change only.
	if !slices.Equal(s.Warnings, l.warned) {
		for _, w := range s.Warnings {
			l.warnings.WarnContext(ctx, "config.warning", "detail", w)
		}
		l.warned = s.Warnings
	}
	l.current.Store(s)
	if l.OnSnapshot != nil {
		l.OnSnapshot(s)
	}
	return nil
}

// Changed asks Run for a refresh now: another instance wrote
// (Postgres.Listen). It never waits; the requests made before the refresh
// starts make one refresh, those made during it one more.
func (l *Live) Changed() {
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

// Run refreshes every interval, and at each Changed, until ctx ends.
func (l *Live) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-l.changed:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
		_ = l.Refresh(refreshCtx) // logged by Refresh
		cancel()
	}
}
