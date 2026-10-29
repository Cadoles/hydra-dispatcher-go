package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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
	if _, err := NewLive(ctx, src, logger); err == nil {
		t.Fatal("NewLive without a first snapshot: want an error")
	}

	first := &Snapshot{Settings: DefaultSettings(), Warnings: []string{"setting \"x\" is unknown"}}
	src.set(first, nil)
	live, err := NewLive(ctx, src, logger)
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
}

// A refresh canceled by its caller, as serve stops, says nothing of the
// database: neither logged nor counted as a failure. One past its deadline
// is.
func TestLiveRefreshCanceled(t *testing.T) {
	var logs bytes.Buffer
	src := &fakeSource{snapshot: &Snapshot{}}
	live, err := NewLive(context.Background(), src, slog.New(slog.NewTextHandler(&logs, nil)))
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

func TestLiveRun(t *testing.T) {
	src := &fakeSource{snapshot: &Snapshot{}}
	live, err := NewLive(context.Background(), src, slog.New(slog.DiscardHandler))
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
