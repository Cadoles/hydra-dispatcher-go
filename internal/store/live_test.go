package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource serves the snapshot or the error it is given.
type fakeSource struct {
	mu       sync.Mutex
	snapshot *Snapshot
	err      error
}

func (f *fakeSource) Snapshot(context.Context) (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot, f.err
}

func (f *fakeSource) set(s *Snapshot, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshot, f.err = s, err
}

func TestLive(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	src := &fakeSource{err: errors.New("database down")}
	if _, err := NewLive(ctx, src, logger, logger); err == nil {
		t.Fatal("NewLive without a first snapshot: want an error")
	}

	first := &Snapshot{Settings: DefaultSettings(), Warnings: []string{"setting \"x\" is unknown"}}
	src.set(first, nil)
	live, err := NewLive(ctx, src, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	if live.Snapshot() != first {
		t.Fatal("first snapshot not served")
	}

	// A failed refresh keeps the snapshot, and is logged once.
	src.set(first, errors.New("database down"))
	for range 2 {
		if err := live.Refresh(ctx); err == nil {
			t.Fatal("Refresh = nil, want the error")
		}
	}
	if live.Snapshot() != first {
		t.Error("snapshot dropped by a failed refresh")
	}
	second := &Snapshot{Warnings: first.Warnings}
	src.set(second, nil)
	if err := live.Refresh(ctx); err != nil || live.Snapshot() != second {
		t.Fatalf("Refresh = %v, snapshot replaced = %v", err, live.Snapshot() == second)
	}

	out := logs.String()
	for msg, want := range map[string]int{"config.warning": 1, "config.refresh_failed": 1, "config.refresh_recovered": 1} {
		if n := strings.Count(out, "msg="+msg); n != want {
			t.Errorf("%s logged %d times, want %d:\n%s", msg, n, want, out)
		}
	}
	// An error, as the design document has it: the replica no longer follows
	// the database.
	if !strings.Contains(out, `level=ERROR msg=config.refresh_failed cause="database down"`) {
		t.Errorf("config.refresh_failed is not an error with its cause:\n%s", out)
	}
}

// The warnings go to their own logger, which writes them whatever log_level,
// and again whenever they change.
func TestLiveWarnings(t *testing.T) {
	ctx := context.Background()
	var logs, warnings bytes.Buffer
	src := &fakeSource{snapshot: &Snapshot{Warnings: []string{"a"}}}
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	live, err := NewLive(ctx, src, logger, slog.New(slog.NewTextHandler(&warnings, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range [][]string{{"a"}, {"a", "b"}, nil, {"a"}} {
		src.set(&Snapshot{Warnings: w}, nil)
		if err := live.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// a at first, a and b when b comes, nothing when they go, a again.
	out := warnings.String()
	if a, b := strings.Count(out, "detail=a"), strings.Count(out, "detail=b"); a != 3 || b != 1 {
		t.Errorf("a logged %d times, b %d; want 3 and 1:\n%s", a, b, out)
	}
	if logs.Len() != 0 {
		t.Errorf("warnings in the application log:\n%s", logs.String())
	}
}

// A refresh canceled by its caller, as serve stops, says nothing of the
// database: neither logged nor counted as a failure. One past its deadline
// is.
func TestLiveRefreshCanceled(t *testing.T) {
	var logs bytes.Buffer
	src := &fakeSource{snapshot: &Snapshot{}}
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	live, err := NewLive(context.Background(), src, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	src.set(nil, context.Canceled)
	if err := live.Refresh(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh = %v, want context.Canceled", err)
	}
	if strings.Contains(logs.String(), "config.refresh_failed") {
		t.Errorf("canceled refresh logged:\n%s", logs.String())
	}
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	src.set(nil, context.DeadlineExceeded)
	if err := live.Refresh(expired); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Refresh = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(logs.String(), "config.refresh_failed") {
		t.Errorf("refresh past its deadline not logged:\n%s", logs.String())
	}
}

// slowSource answers NewLive with old, holds the next read, of old too, until
// release, and answers the reads after it with new.
type slowSource struct {
	calls    atomic.Int32
	release  chan struct{}
	old, new *Snapshot
}

func (s *slowSource) Snapshot(context.Context) (*Snapshot, error) {
	switch s.calls.Add(1) {
	case 1:
		return s.old, nil
	case 2:
		<-s.release
		return s.old, nil
	default:
		return s.new, nil
	}
}

// A slow refresh started first does not replace the snapshot a later one
// read: refreshes run one at a time, as writes will call Refresh beside Run.
func TestLiveRefreshOneAtATime(t *testing.T) {
	src := &slowSource{release: make(chan struct{}), old: &Snapshot{}, new: &Snapshot{}}
	live, err := NewLive(context.Background(), src, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	slow := make(chan struct{})
	go func() {
		_ = live.Refresh(context.Background())
		close(slow)
	}()
	for src.calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	later := make(chan struct{})
	go func() {
		_ = live.Refresh(context.Background())
		close(later)
	}()
	// Without the lock, the later refresh ends here, before the slow one.
	select {
	case <-later:
	case <-time.After(50 * time.Millisecond):
	}
	close(src.release)
	<-slow
	<-later
	if live.Snapshot() != src.new {
		t.Error("the slow refresh replaced the snapshot of the later one")
	}
}

func TestLiveRun(t *testing.T) {
	src := &fakeSource{snapshot: &Snapshot{}}
	live, err := NewLive(context.Background(), src, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { live.Run(ctx, time.Millisecond); close(done) }()
	next := &Snapshot{}
	src.set(next, nil)
	deadline := time.Now().Add(5 * time.Second)
	for live.Snapshot() != next {
		if time.Now().After(deadline) {
			t.Fatal("Run did not refresh within 5 s")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

// countingSource counts its reads; release, when set, holds each read until
// it receives.
type countingSource struct {
	reads   atomic.Int32
	release chan struct{}
}

func (c *countingSource) Snapshot(context.Context) (*Snapshot, error) {
	if c.reads.Add(1) > 1 && c.release != nil {
		<-c.release
	}
	return &Snapshot{}, nil
}

// Changed refreshes without waiting for the tick; the requests made before a
// refresh starts make one, those made during it one more.
func TestLiveChanged(t *testing.T) {
	src := &countingSource{release: make(chan struct{})}
	live, err := NewLive(context.Background(), src, slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		live.Changed() // before Run: one refresh
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { live.Run(ctx, time.Hour); close(done) }()
	waitReads := func(n int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for src.reads.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("%d reads, want %d", src.reads.Load(), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitReads(2) // the refresh, held
	for range 3 {
		live.Changed() // during it: one more
	}
	src.release <- struct{}{}
	waitReads(3)
	src.release <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	if n := src.reads.Load(); n != 3 {
		t.Errorf("%d reads, want 3", n)
	}
	cancel()
	<-done
}

// stuckSource answers NewLive, then holds every read until its context ends,
// and sends that context's deadline.
type stuckSource struct {
	calls     atomic.Int32
	deadlines chan time.Time
}

func (s *stuckSource) Snapshot(ctx context.Context) (*Snapshot, error) {
	if s.calls.Add(1) == 1 {
		return &Snapshot{}, nil
	}
	deadline, _ := ctx.Deadline()
	select {
	case s.deadlines <- deadline:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// Each refresh of Run has refreshTimeout. Run stops during a refresh, which
// is then not a failure.
func TestLiveRunStops(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	src := &stuckSource{deadlines: make(chan time.Time, 1)}
	live, err := NewLive(context.Background(), src, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { live.Run(ctx, time.Millisecond); close(done) }()
	deadline := <-src.deadlines
	if left := time.Until(deadline); left <= refreshTimeout-time.Second || left > refreshTimeout {
		t.Errorf("refresh deadline in %v, want %v", left, refreshTimeout)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop during a refresh")
	}
	if strings.Contains(logs.String(), "config.refresh_failed") {
		t.Errorf("a refresh stopped with Run logged as failed:\n%s", logs.String())
	}
}

// OnRefresh hears of each refresh that ended, not of one its caller canceled.
func TestLiveOnRefresh(t *testing.T) {
	src := &fakeSource{snapshot: &Snapshot{}}
	logger := slog.New(slog.DiscardHandler)
	live, err := NewLive(context.Background(), src, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	var heard []error
	live.OnRefresh = func(err error) { heard = append(heard, err) }
	if err := live.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	down := errors.New("down")
	src.set(nil, down)
	if err := live.Refresh(context.Background()); !errors.Is(err, down) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = live.Refresh(canceled)
	if len(heard) != 2 || heard[0] != nil || !errors.Is(heard[1], down) {
		t.Errorf("heard %v", heard)
	}
}

// OnSnapshot is given each snapshot read, once it is the current one; not the
// one a failed refresh would have given (P25: the window of debug).
func TestLiveOnSnapshot(t *testing.T) {
	first := &Snapshot{}
	src := &fakeSource{snapshot: first}
	logger := slog.New(slog.DiscardHandler)
	live, err := NewLive(context.Background(), src, logger, logger)
	if err != nil {
		t.Fatal(err)
	}
	var given []*Snapshot
	live.OnSnapshot = func(s *Snapshot) {
		if live.Snapshot() != s {
			t.Error("given before it is the current one")
		}
		given = append(given, s)
	}
	second := &Snapshot{Debug: &DebugWindow{Flow: "main"}}
	src.set(second, nil)
	if err := live.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.set(nil, errors.New("down"))
	_ = live.Refresh(context.Background())
	if len(given) != 1 || given[0] != second {
		t.Errorf("given %v", given)
	}
}
