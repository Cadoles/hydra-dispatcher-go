package state

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
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

// openMemory returns a memory store on a clock of its own, the TTL of the
// contract tests, and the function that moves that clock. Its sweeps never
// run by themselves.
func openMemory(t *testing.T) (StateStore, time.Duration, func(time.Duration)) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	m := newMemory(c.Now, time.Hour)
	t.Cleanup(func() { _ = m.Close() })
	return m, time.Minute, c.Advance
}

func TestMemory(t *testing.T) {
	testStore(t, openMemory)
}

// testStore checks what every backend promises. open returns an empty store
// of its own (for Redis, under a key prefix of its own), the TTL to write
// with, and a function that makes the store's time pass: a clock moved by
// hand in memory, a sleep against a real Redis, whose TTL is then short. The
// times keep a quarter of the TTL as a margin, so that a sleep which overruns
// fails nothing; the exact instant of the expiry is a memory test.
func testStore(t *testing.T, open func(t *testing.T) (s StateStore, ttl time.Duration, advance func(time.Duration))) {
	ctx := context.Background()

	t.Run("absent", func(t *testing.T) {
		s, _, _ := open(t)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get = %v, want ErrNotFound", err)
		}
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Errorf("Delete = %v, want nil", err)
		}
	})

	t.Run("versions", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
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
		mustPut(t, s, "flow:a", "two", ttl, v1)
		_, v2 := mustGet(t, s, "flow:a", "two")
		if v2 == v1 {
			t.Errorf("version %d kept by a Put", v2)
		}
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the version read before = %v, want ErrConflict", err)
		}
		mustGet(t, s, "flow:a", "two")
		// Not drawn from the value: the same one written again takes a new
		// version.
		mustPut(t, s, "flow:a", "two", ttl, v2)
		if _, v3 := mustGet(t, s, "flow:a", "two"); v3 == v2 {
			t.Errorf("version %d kept by a Put of the same value", v3)
		}
		if err := s.Put(ctx, "flow:b", []byte("lost"), ttl, v2); !errors.Is(err, ErrConflict) {
			t.Errorf("Put of an absent key on a version = %v, want ErrConflict", err)
		}
		if _, _, err := s.Get(ctx, "flow:b"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after a refused Put = %v, want ErrNotFound", err)
		}
	})

	t.Run("no key without a TTL", func(t *testing.T) {
		s, _, _ := open(t)
		for _, d := range []time.Duration{0, -time.Second} {
			if err := s.Put(ctx, "flow:a", []byte("v"), d, 0); !errors.Is(err, ErrNoTTL) {
				t.Errorf("Put with TTL %s = %v, want ErrNoTTL", d, err)
			}
		}
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after the refused Puts = %v, want ErrNotFound", err)
		}
	})

	// Redis refuses a TTL of 0 ms: the store rounds up instead.
	t.Run("a TTL under a millisecond", func(t *testing.T) {
		s, ttl, advance := open(t)
		if err := s.Put(ctx, "flow:a", []byte("v"), time.Microsecond, 0); err != nil {
			t.Fatalf("Put with TTL 1µs = %v, want it rounded up to 1 ms", err)
		}
		advance(ttl / 4)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get past the TTL = %v, want ErrNotFound", err)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		s, ttl, advance := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
		_, v1 := mustGet(t, s, "flow:a", "one")
		advance(ttl * 3 / 4)
		mustGet(t, s, "flow:a", "one")
		advance(ttl / 2)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get past the TTL = %v, want ErrNotFound", err)
		}
		// Expired is absent: the version read before no longer applies.
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the expired version = %v, want ErrConflict", err)
		}
		mustPut(t, s, "flow:a", "two", ttl, 0)
		if _, v2 := mustGet(t, s, "flow:a", "two"); v2 == v1 {
			t.Errorf("version %d given again after the expiry", v2)
		}
	})

	t.Run("a Put sets the TTL again", func(t *testing.T) {
		s, ttl, advance := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
		advance(ttl * 3 / 4)
		_, v := mustGet(t, s, "flow:a", "one")
		mustPut(t, s, "flow:a", "two", ttl, v)
		advance(ttl * 3 / 4)
		mustGet(t, s, "flow:a", "two")
		advance(ttl / 2)
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get past the second TTL = %v, want ErrNotFound", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
		_, v1 := mustGet(t, s, "flow:a", "one")
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Fatalf("Delete = %v", err)
		}
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
		}
		mustPut(t, s, "flow:a", "two", ttl, 0)
		_, v2 := mustGet(t, s, "flow:a", "two")
		if v2 == v1 {
			t.Fatalf("version %d given again after Delete", v2)
		}
		if err := s.Put(ctx, "flow:a", []byte("lost"), ttl, v1); !errors.Is(err, ErrConflict) {
			t.Errorf("Put on the deleted version = %v, want ErrConflict", err)
		}
	})

	t.Run("values are copied", func(t *testing.T) {
		s, ttl, _ := open(t)
		val := []byte("one")
		if err := s.Put(ctx, "flow:a", val, ttl, 0); err != nil {
			t.Fatal(err)
		}
		val[0] = 'X'
		got, _ := mustGet(t, s, "flow:a", "one")
		got[0] = 'X'
		mustGet(t, s, "flow:a", "one")
	})

	// Empty, whether written nil or not: Redis does not tell them apart.
	t.Run("empty values", func(t *testing.T) {
		s, ttl, _ := open(t)
		for key, val := range map[string][]byte{"flow:nil": nil, "flow:empty": {}} {
			if err := s.Put(ctx, key, val, ttl, 0); err != nil {
				t.Fatalf("Put(%s) = %v", key, err)
			}
			if got, v, err := s.Get(ctx, key); err != nil || len(got) != 0 || v == 0 {
				t.Errorf("Get(%s) = %q, %d, %v; want an empty value", key, got, v, err)
			}
		}
	})

	t.Run("keys are apart", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:a", "a", ttl, 0)
		mustPut(t, s, "flow:b", "b", ttl, 0)
		if err := s.Delete(ctx, "flow:a"); err != nil {
			t.Fatal(err)
		}
		mustGet(t, s, "flow:b", "b")
	})

	// Each round, every writer reads the same version, then all write on it
	// at once: one Put only may win, or a write is lost. They wait for the
	// start by spinning: woken by a channel, they would leave one after the
	// other, and a compare-then-write in two steps would seldom be caught.
	t.Run("concurrent read-modify-write", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:n", "0", ttl, 0)
		const writers, rounds = 8, 100
		for round := range rounds {
			var read, wrote sync.WaitGroup
			var won atomic.Int32
			var start atomic.Bool
			read.Add(writers)
			for range writers {
				wrote.Go(func() {
					val, v, err := s.Get(ctx, "flow:n")
					read.Done()
					if err != nil {
						t.Error(err)
						return
					}
					n, err := strconv.Atoi(string(val))
					if err != nil {
						t.Error(err)
						return
					}
					for !start.Load() {
						runtime.Gosched()
					}
					switch err := s.Put(ctx, "flow:n", []byte(strconv.Itoa(n+1)), ttl, v); {
					case err == nil:
						won.Add(1)
					case !errors.Is(err, ErrConflict):
						t.Error(err)
					}
				})
			}
			read.Wait()
			start.Store(true)
			wrote.Wait()
			if n := won.Load(); n != 1 {
				t.Fatalf("round %d: %d Puts won on the version read, want 1", round, n)
			}
		}
		mustGet(t, s, "flow:n", strconv.Itoa(rounds))
	})

	t.Run("canceled context", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
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
		if _, _, err := s.Get(ctx, "flow:b"); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get after the canceled Put = %v, want ErrNotFound", err)
		}
	})

	t.Run("closed", func(t *testing.T) {
		s, ttl, _ := open(t)
		mustPut(t, s, "flow:a", "one", ttl, 0)
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

	// Close may come while calls run, and twice at once: each call then
	// either ends or fails with ErrClosed.
	t.Run("closed while in use", func(t *testing.T) {
		s, ttl, _ := open(t)
		expected := func(err error) bool {
			if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) || errors.Is(err, ErrClosed) {
				return true
			}
			t.Error(err)
			return false
		}
		const callers = 4
		stop := make(chan struct{})
		var running, calls sync.WaitGroup
		running.Add(callers)
		for range callers {
			calls.Go(func() {
				var once sync.Once // running once a round is done, or on return
				defer once.Do(running.Done)
				for i := 0; ; i++ {
					if i == 1 {
						once.Do(running.Done)
					}
					select {
					case <-stop:
						return
					default:
					}
					_, _, err := s.Get(ctx, "flow:a")
					if !expected(err) || !expected(s.Put(ctx, "flow:a", []byte("v"), ttl, 0)) || !expected(s.Delete(ctx, "flow:a")) {
						return
					}
				}
			})
		}
		running.Wait()
		var closes sync.WaitGroup
		for range 2 {
			closes.Go(func() {
				if err := s.Close(); err != nil {
					t.Errorf("Close = %v", err)
				}
			})
		}
		closes.Wait()
		close(stop)
		calls.Wait()
		if _, _, err := s.Get(ctx, "flow:a"); !errors.Is(err, ErrClosed) {
			t.Errorf("Get once closed = %v, want ErrClosed", err)
		}
	})
}

func mustPut(t *testing.T, s StateStore, key, val string, ttl time.Duration, ifVersion uint64) {
	t.Helper()
	if err := s.Put(context.Background(), key, []byte(val), ttl, ifVersion); err != nil {
		t.Fatalf("Put(%s, %q, %s, %d) = %v", key, val, ttl, ifVersion, err)
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

// The memory store expires a key at its TTL exactly, counted in whole
// milliseconds. Redis keeps a key through its last millisecond: the contract
// leaves that instant out.
func TestMemoryExpiry(t *testing.T) {
	for _, c := range []struct {
		ttl, lives time.Duration
	}{
		{time.Minute, time.Minute},
		{time.Microsecond, time.Millisecond},
		{1500 * time.Microsecond, 2 * time.Millisecond},
	} {
		s, _, advance := openMemory(t)
		mustPut(t, s, "flow:a", "one", c.ttl, 0)
		advance(c.lives - time.Nanosecond)
		mustGet(t, s, "flow:a", "one")
		advance(time.Nanosecond)
		if _, _, err := s.Get(context.Background(), "flow:a"); !errors.Is(err, ErrNotFound) {
			t.Errorf("TTL %s: Get after %s = %v, want ErrNotFound", c.ttl, c.lives, err)
		}
	}
}

func TestMemorySweep(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	m := newMemory(c.Now, time.Hour)
	defer func() { _ = m.Close() }()
	mustPut(t, m, "flow:old", "old", time.Minute, 0)
	c.Advance(30 * time.Second)
	mustPut(t, m, "flow:new", "new", time.Minute, 0)
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
	mustPut(t, m, "flow:a", "a", time.Minute, 0)
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

// Close returns once the sweeps have stopped: no goroutine outlives the
// store.
func TestMemoryCloseStopsSweeps(t *testing.T) {
	m := NewMemory()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.done:
	default:
		t.Error("sweeps still running after Close")
	}
}
