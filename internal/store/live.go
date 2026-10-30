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

// Live holds the snapshot the handlers read. It is replaced whole, by Refresh
// or every RefreshEvery while Run runs.
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
}

// NewLive reads a first snapshot: without one, nothing can be served. The
// warnings of the snapshots go to warnings, which writes them whatever the
// level of logger: config.warning, as the startup ones.
func NewLive(ctx context.Context, source Source, logger, warnings *slog.Logger) (*Live, error) {
	l := &Live{source: source, logger: logger, warnings: warnings}
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
		// An error: the replica serves a configuration that no longer
		// follows the database.
		if !l.failed && l.current.Load() != nil {
			l.logger.ErrorContext(ctx, "config.refresh_failed", "cause", err)
		}
		l.failed = true
		return err
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
	return nil
}

// Run refreshes every interval until ctx ends.
func (l *Live) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
			_ = l.Refresh(refreshCtx) // logged by Refresh
			cancel()
		}
	}
}
