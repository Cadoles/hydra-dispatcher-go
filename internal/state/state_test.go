package state

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

// clock is a time the tests move by hand.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// openMemory returns a memory store on a clock of its own, and the function
// that moves that clock. Its sweeps never run by themselves.
func openMemory(t *testing.T) (StateStore, func(time.Duration)) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	m := newMemory(c.Now, time.Hour)
	t.Cleanup(func() { _ = m.Close() })
	return m, c.Advance
}

func TestMemory(t *testing.T) {
	testStore(t, openMemory)
}

// testStore checks what every backend promises. open returns an empty store
// and a function that makes its time pass.
func testStore(t *testing.T, open func(t *testing.T) (StateStore, func(time.Duration))) {
	ctx := context.Background()
	const ttl = time.Minute

	t.Run("absent", func(t *testing.T) {
		s, _ := open(t)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get = %v, want ErrNotFound", err)
		}
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Errorf("Delete = %v, want nil", err)
		}
	})

	t.Run("versions", func(t *testing.T) {
		s, _ := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		_, v1 := mustGet(t, s, "flow:a", "one")
		if v1 == 0 {
			t.Fatal("version 0 for an existing key")
		}
		for _, c := range []struct {
			name      string
			ifVersion uint64
		}{
			{"created again", 0},
			{"another version", v1 + 1},
		} {
			if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, c.ifVersion); !errors.Is(err, ErrConflict) {
				t.Errorf("%s: Put = %v, want ErrConflict", c.name, err)
			}
		}
		mustPut(t, s, "flow:a", "two", v1)
		_, v2 := mustGet(t, s, "flow:a", "two")
		if v2 == v1 {
			t.Errorf("version %d kept by a Put", v2)
		}
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the version read before = %v, want ErrConflict", err)
		}
		mustGet(t, s, "flow:a", "two")
		if err := s.Put(ctx, "flow:b", []byte("lost"), ttl, v2); !errors.Is(err, ErrConflict) {
			t.Errorf("Put of an absent key on a version = %v, want ErrConflict", err)
		}
		if _, _, err := s.Get(ctx, "flow:b"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after a refused Put = %v, want ErrNotFound", err)
		}
	})

	t.Run("no key without a TTL", func(t *testing.T) {
		s, _ := open(t)
		for _, d := range []time.Duration{0, -time.Second} {
			if err := s.Put(ctx, "flow:a", []byte("v"), d, 0); !errors.Is(err, ErrNoTTL) {
				t.Errorf("Put with TTL %s = %v, want ErrNoTTL", d, err)
			}
		}
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after the refused Puts = %v, want ErrNotFound", err)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		s, advance := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		_, v1 := mustGet(t, s, "flow:a", "one")
		advance(ttl - time.Second)
		mustGet(t, s, "flow:a", "one")
		advance(time.Second)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get at the TTL = %v, want ErrNotFound", err)
		}
		// Expired is absent: the version read before no longer applies.
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the expired version = %v, want ErrConflict", err)
		}
		mustPut(t, s, "flow:a", "two", 0)
		if _, v2 := mustGet(t, s, "flow:a", "two"); v2 == v1 {
			t.Errorf("version %d given again after the expiry", v2)
		}
	})

	t.Run("a Put sets the TTL again", func(t *testing.T) {
		s, advance := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		advance(ttl - time.Second)
		_, v := mustGet(t, s, "flow:a", "one")
		mustPut(t, s, "flow:a", "two", v)
		advance(ttl - time.Second)
		mustGet(t, s, "flow:a", "two")
	})

	t.Run("delete", func(t *testing.T) {
		s, _ := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		_, v1 := mustGet(t, s, "flow:a", "one")
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Fatalf("Delete = %v", err)
		}
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
		}
		mustPut(t, s, "flow:a", "two", 0)
		_, v2 := mustGet(t, s, "flow:a", "two")
		if v2 == v1 {
			t.Fatalf("version %d given again after Delete", v2)
		}
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the deleted version = %v, want ErrConflict", err)
		}
	})

	t.Run("values are copied", func(t *testing.T) {
		s, _ := open(t)
		val := []byte("one")
		if err := s.Put(ctx, "flow:a", val, ttl, 0); err != nil {
			t.Fatal(err)
		}
		val[0] = 'X'
		got, _ := mustGet(t, s, "flow:a", "one")
		got[0] = 'X'
		mustGet(t, s, "flow:a", "one")
	})

	t.Run("keys are apart", func(t *testing.T) {
		s, _ := open(t)
		mustPut(t, s, "flow:a", "a", 0)
		mustPut(t, s, "flow:b", "b", 0)
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Fatal(err)
		}
		mustGet(t, s, "flow:b", "b")
	})

	t.Run("concurrent read-modify-write", func(t *testing.T) {
		s, _ := open(t)
		var zero [8]byte
		mustPut(t, s, "flow:n", string(zero[:]), 0)
		const writers, increments = 8, 50
		var wg sync.WaitGroup
		var mu sync.Mutex
		conflicts := 0
		for range writers {
			wg.Go(func() {
				for range increments {
					for {
						val, v, err := s.Get(ctx, "flow:n")
						if err != nil {
							t.Error(err)
							return
						}
						next := binary.BigEndian.AppendUint64(nil, binary.BigEndian.Uint64(val)+1)
						err = s.Put(ctx, "flow:n", next, ttl, v)
						if err == nil {
							break
						}
						if !errors.Is(err, ErrConflict) {
							t.Error(err)
							return
						}
						mu.Lock()
						conflicts++
						mu.Unlock()
					}
				}
			})
		}
		wg.Wait()
		val, _, err := s.Get(ctx, "flow:n")
		if err != nil {
			t.Fatal(err)
		}
		if n := binary.BigEndian.Uint64(val); n != writers*increments {
			t.Errorf("counter = %d, want %d: a write was lost", n, writers*increments)
		}
		t.Logf("%d conflicts retried", conflicts)
	})

	t.Run("canceled context", func(t *testing.T) {
		s, _ := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := s.Get(canceled, "flow:a"); !errors.Is(err, context.Canceled) {
			t.Errorf("Get = %v, want context.Canceled", err)
		}
		if err := s.Put(canceled, "flow:b", []byte("v"), ttl, 0); !errors.Is(err, context.Canceled) {
			t.Errorf("Put = %v, want context.Canceled", err)
		}
		if err := s.Delete(canceled, "flow:a"); !errors.Is(err, context.Canceled) {
			t.Errorf("Delete = %v, want context.Canceled", err)
		}
		mustGet(t, s, "flow:a", "one")
	})

	t.Run("closed", func(t *testing.T) {
		s, _ := open(t)
		mustPut(t, s, "flow:a", "one", 0)
		if err := s.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("second Close = %v", err)
		}
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrClosed) {
			t.Errorf("Get = %v, want ErrClosed", err)
		}
		if err := s.Put(ctx, "flow:b", []byte("v"), ttl, 0); !errors.Is(err, ErrClosed) {
			t.Errorf("Put = %v, want ErrClosed", err)
		}
		if err := s.Delete(ctx, "flow:a"); !errors.Is(err, ErrClosed) {
			t.Errorf("Delete = %v, want ErrClosed", err)
		}
	})
}

func mustPut(t *testing.T, s StateStore, key, val string, ifVersion uint64) {
	t.Helper()
	if err := s.Put(context.Background(), key, []byte(val), time.Minute, ifVersion); err != nil {
		t.Fatalf("Put(%s, %q, %d) = %v", key, val, ifVersion, err)
	}
}

func mustGet(t *testing.T, s StateStore, key, want string) ([]byte, uint64) {
	t.Helper()
	val, v, err := s.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get(%s) = %v", key, err)
	}
	if string(val) != want {
		t.Fatalf("Get(%s) = %q, want %q", key, val, want)
	}
	return val, v
}

func TestMemorySweep(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	m := newMemory(c.Now, time.Hour)
	defer func() { _ = m.Close() }()
	mustPut(t, m, "flow:old", "old", 0)
	c.Advance(30 * time.Second)
	mustPut(t, m, "flow:new", "new", 0)
	c.Advance(30 * time.Second)
	m.sweep()
	m.mu.Lock()
	_, old := m.entries["flow:old"]
	_, kept := m.entries["flow:new"]
	m.mu.Unlock()
	if old || !kept {
		t.Errorf("after the sweep: expired key kept = %v, live key kept = %v", old, kept)
	}
}

func TestMemorySweepsByItself(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	m := newMemory(c.Now, time.Millisecond)
	defer func() { _ = m.Close() }()
	mustPut(t, m, "flow:a", "a", 0)
	c.Advance(time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.entries)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("expired key still held after 5 s of sweeps every millisecond")
		}
		time.Sleep(time.Millisecond)
	}
}
