package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// QueueSize is how many lines wait for the output at most: a few seconds of a
	// busy instance, a few megabytes.
	QueueSize = 4096
	// reportEvery spaces the lines of the application log that tell of lost lines.
	reportEvery = time.Minute
)

// Queue writes the lines of the audit log in the background, by a bounded queue and
// a single writer (Q89): an output that blocks, a syslog whose daemon reads no more,
// held every request writing a line, without end (revue R29). A line the full queue
// does not take is lost, counted, and the application log says so, one error line a
// minute at most, audit.dropped, which goes to Sentry by its name. Availability comes
// before the completeness of the audit, and the loss shows. An output that fails
// loses its line too, as before (Q75).
//
// A Queue is the io.Writer of the audit's handler: slog writes a record in one Write.
type Queue struct {
	out     io.Writer
	lines   chan []byte
	logger  *slog.Logger
	dropped func()
	every   time.Duration
	now     func() time.Time

	mu     sync.Mutex // closed, and the sends after it
	closed bool
	stop   chan struct{}
	done   chan struct{}

	pending  atomic.Int64 // lost since the last line of the log
	reportMu sync.Mutex
	last     time.Time
}

// NewQueue writes to out the lines given to it, size at most waiting. logger, the
// application log, tells of the lines lost; dropped counts each one, nil for none.
func NewQueue(out io.Writer, size int, logger *slog.Logger, dropped func()) *Queue {
	if dropped == nil {
		dropped = func() {}
	}
	q := &Queue{out: out, lines: make(chan []byte, size), logger: logger, dropped: dropped, every: reportEvery,
		now: time.Now, stop: make(chan struct{}), done: make(chan struct{})}
	go q.run()
	return q
}

// Write queues a copy of p, slog reusing its buffer, and never waits.
func (q *Queue) Write(p []byte) (int, error) {
	q.mu.Lock()
	queued := false
	if !q.closed {
		select {
		case q.lines <- bytes.Clone(p):
			queued = true
		default:
		}
	}
	q.mu.Unlock()
	if !queued {
		q.lose(1)
	}
	return len(p), nil
}

func (q *Queue) run() {
	defer close(q.done)
	tick := time.NewTicker(q.every)
	defer tick.Stop()
	for {
		select {
		case line := <-q.lines:
			_, _ = q.out.Write(line)
		case <-tick.C:
			q.report(false) // the losses of a minute that saw a line already
		case <-q.stop:
			for {
				select {
				case line := <-q.lines:
					_, _ = q.out.Write(line)
				default:
					return
				}
			}
		}
	}
}

// Close writes what waits until ctx ends, the budget of the stop (Q82): what is left
// then is lost and counted, an output that blocks holding the last line. Lines written
// after it are lost. It reports the lines lost, if any.
func (q *Queue) Close(ctx context.Context) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.mu.Unlock()
	close(q.stop)
	select {
	case <-q.done:
	case <-ctx.Done():
		q.lose(len(q.lines))
	}
	q.report(true)
}

// lose counts n lines lost, and tells the log when the last time is a minute away.
func (q *Queue) lose(n int) {
	if n <= 0 {
		return
	}
	for range n {
		q.dropped()
	}
	q.pending.Add(int64(n))
	q.report(false)
}

// report writes audit.dropped with the lines lost since the last one, at most once
// by q.every unless now.
func (q *Queue) report(now bool) {
	q.reportMu.Lock()
	defer q.reportMu.Unlock()
	n := q.pending.Load()
	if n == 0 || !now && !q.last.IsZero() && q.now().Sub(q.last) < q.every {
		return
	}
	q.pending.Add(-n)
	q.last = q.now()
	q.logger.Error("audit.dropped", "count", n)
}
