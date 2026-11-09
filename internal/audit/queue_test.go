package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuffer is an output the test reads while the queue writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The lines reach the output in order, a copy of what slog gave, all of them once the
// queue is closed.
func TestQueueWrites(t *testing.T) {
	var out syncBuffer
	q := NewQueue(&out, 16, slog.New(slog.DiscardHandler), nil)
	buf := []byte("line 0\n")
	for i := range 10 {
		buf[5] = byte('0' + i)
		_, _ = q.Write(buf) // the caller reuses its buffer, as slog does
	}
	q.Close(context.Background())
	var want strings.Builder
	for i := range 10 {
		fmt.Fprintf(&want, "line %d\n", i)
	}
	if out.String() != want.String() {
		t.Errorf("output %q", out.String())
	}
	_, _ = q.Write([]byte("late\n"))
	if strings.Contains(out.String(), "late") {
		t.Error("a line written after Close reached the output")
	}
}

// blocked is an output that never returns, until released.
type blocked struct{ release chan struct{} }

func (b blocked) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// An output that blocks holds no request: the lines past the queue are lost, counted,
// and the log says so once a minute; Close gives up at its deadline, the lines left
// counted too (Q89).
func TestQueueBlockedOutput(t *testing.T) {
	out := blocked{make(chan struct{})}
	defer close(out.release)
	var logs syncBuffer
	var dropped atomic.Int64
	q := NewQueue(out, 4, slog.New(slog.NewJSONHandler(&logs, nil)), func() { dropped.Add(1) })

	start := time.Now()
	for range 100 {
		_, _ = q.Write([]byte("line\n"))
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("100 writes took %v", took)
	}
	// One line in the writer, four in the queue at most.
	if n := dropped.Load(); n < 95 || n > 96 {
		t.Errorf("%d lines lost, want 95 or 96", n)
	}
	if n := strings.Count(logs.String(), `"msg":"audit.dropped"`); n != 1 {
		t.Errorf("%d lines audit.dropped, want 1 for the minute:\n%s", n, logs.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	q.Close(ctx)
	if took := time.Since(start); took > time.Second {
		t.Errorf("Close took %v", took)
	}
	if n := dropped.Load(); n < 99 {
		t.Errorf("%d lines lost once closed, want those queued too", n)
	}
	var total int64
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var line struct {
			Level, Msg string
			Count      int64
		}
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatal(err)
		}
		if line.Level != "ERROR" || line.Msg != "audit.dropped" {
			t.Errorf("line %s", l)
		}
		total += line.Count
	}
	if total != dropped.Load() {
		t.Errorf("the log tells of %d lines lost, the counter %d", total, dropped.Load())
	}
}

// audit.dropped goes once a minute at most, with the lines lost since the last one.
func TestQueueReportEveryMinute(t *testing.T) {
	var logs syncBuffer
	q := NewQueue(blocked{make(chan struct{})}, 1, slog.New(slog.NewJSONHandler(&logs, nil)), nil)
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	q.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
	q.lose(1)
	advance(10 * time.Second)
	q.lose(2)
	advance(time.Minute)
	q.lose(3)
	counts := []string{}
	for l := range strings.Lines(logs.String()) {
		var line struct{ Count int }
		_ = json.Unmarshal([]byte(l), &line)
		counts = append(counts, fmt.Sprint(line.Count))
	}
	if got := strings.Join(counts, ","); got != "1,5" {
		t.Errorf("counts %s, want 1,5", got)
	}
}

// The scenario of revue R29: a syslog whose daemon reads no more, a unixgram socket no
// one reads. The audit of a request returns at once, where it held it without end.
func TestAuditOfABlockedSyslog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	daemon, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = daemon.Close() }()
	conn, err := net.Dial("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	var dropped atomic.Int64
	q := NewQueue(conn, 64, slog.New(slog.DiscardHandler), func() { dropped.Add(1) })
	l := New(slog.New(slog.NewJSONHandler(q, nil)), []byte("key"), false)

	start := time.Now()
	for range 10000 {
		l.Refused(context.Background(), "emulated")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("10 000 lines of audit took %v", took)
	}
	if dropped.Load() == 0 {
		t.Error("no line lost: the socket did not fill")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	q.Close(ctx)
}
