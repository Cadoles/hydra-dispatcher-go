//go:build integration

package store

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a buffer for the logs of several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// instance is another instance on the database of p: its snapshot, refreshed
// every hour or when it hears of a write, and the logs of its Listen.
type instance struct {
	live *Live
	logs *lockedBuffer
	// listening receives at each call of changed, connections included.
	listening chan struct{}
}

func newInstance(t *testing.T, p *Postgres) *instance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	q := replica(t, p)
	i := &instance{logs: &lockedBuffer{}, listening: make(chan struct{}, 100)}
	logger := slog.New(slog.NewTextHandler(i.logs, nil))
	var err error
	if i.live, err = NewLive(ctx, q, logger, logger); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { i.live.Run(ctx, time.Hour) })
	wg.Go(func() {
		q.Listen(ctx, func() {
			i.live.Changed()
			i.listening <- struct{}{}
		}, logger)
	})
	// Before the replica closes: Listen and Run end first.
	t.Cleanup(func() { cancel(); wg.Wait() })
	select {
	case <-i.listening:
	case <-time.After(5 * time.Second):
		t.Fatalf("Listen did not connect: %s", i.logs)
	}
	return i
}

// within waits up to d for ok.
func within(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// The write of an instance shows on another in less than a second, without
// waiting for the refresh of every minute; the connection lost, the instance
// connects again and catches up with what it missed meanwhile.
func TestListen(t *testing.T) {
	ctx := context.Background()
	p := migrated(t)
	other := newInstance(t, p)
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); err != nil {
		t.Fatal(err)
	}
	if !within(time.Second, func() bool { _, ok := other.live.Snapshot().App("a"); return ok }) {
		t.Fatal("the write was not seen within 1 s")
	}

	// The connection cut: a write meanwhile is seen once Listen is back.
	exec(t, p, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE datname = current_database() AND query = 'LISTEN `+notifyChannel+`'`)
	if !within(5*time.Second, func() bool { return strings.Contains(other.logs.String(), "config.listen_failed") }) {
		t.Fatalf("no config.listen_failed: %s", other.logs)
	}
	if err := p.CreateApp(ctx, "admin:alice", testApp("b")); err != nil {
		t.Fatal(err)
	}
	if !within(5*time.Second, func() bool { _, ok := other.live.Snapshot().App("b"); return ok }) {
		t.Fatalf("the write during the cut was not seen after it: %s", other.logs)
	}
	if !within(5*time.Second, func() bool { return strings.Contains(other.logs.String(), "config.listen_recovered") }) ||
		strings.Count(other.logs.String(), "config.listen_failed") != 1 {
		t.Errorf("logs: %s", other.logs)
	}
	if err := p.DeleteApp(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if !within(time.Second, func() bool { _, ok := other.live.Snapshot().App("a"); return !ok }) {
		t.Error("a write after the reconnection was not seen within 1 s")
	}
}

// A silent connection is pinged, and keeps listening.
func TestListenSilent(t *testing.T) {
	old := listenIdle
	listenIdle = 50 * time.Millisecond
	t.Cleanup(func() { listenIdle = old })
	ctx := context.Background()
	p := migrated(t)
	other := newInstance(t, p)
	time.Sleep(300 * time.Millisecond)
	if err := p.CreateApp(ctx, "admin:alice", testApp("a")); err != nil {
		t.Fatal(err)
	}
	if !within(time.Second, func() bool { _, ok := other.live.Snapshot().App("a"); return ok }) {
		t.Fatalf("the write was not seen within 1 s: %s", other.logs)
	}
	if strings.Contains(other.logs.String(), "config.listen") {
		t.Errorf("logs: %s", other.logs)
	}
}
