package state

import (
	"context"
	"slices"
	"sync"
	"time"
)

// sweepEvery is how often the memory store drops its expired keys: between
// two sweeps, an expired key is only hidden from reads.
const sweepEvery = 60 * time.Second

// Memory is the store of a single instance: values live in the process,
// unshared and lost on restart. One mutex serializes the calls, which hold it
// for a map access and a copy.
type Memory struct {
	mu      sync.Mutex
	entries map[string]entry
	// version is the last one given, to any key: a deleted key written again
	// takes a new one.
	version uint64
	closed  bool
	now     func() time.Time
	stop    chan struct{}
	done    chan struct{}
}

type entry struct {
	val     []byte
	version uint64
	expires time.Time
}

// NewMemory returns a memory store, whose expired keys are dropped every 60
// seconds until Close.
func NewMemory() *Memory {
	return newMemory(time.Now, sweepEvery)
}

func newMemory(now func() time.Time, every time.Duration) *Memory {
	m := &Memory{
		entries: map[string]entry{},
		now:     now,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go m.sweepLoop(every)
	return m
}

func (m *Memory) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, 0, ErrClosed
	}
	e, ok := m.live(key)
	if !ok {
		return nil, 0, ErrNotFound
	}
	return slices.Clone(e.val), e.version, nil
}

func (m *Memory) Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrNoTTL
	}
	// Whole milliseconds, as Redis keeps them.
	if r := ttl % time.Millisecond; r != 0 {
		ttl += time.Millisecond - r
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	// An expired key counts as absent, as it would in Redis.
	if e, _ := m.live(key); e.version != ifVersion {
		return ErrConflict
	}
	m.version++
	m.entries[key] = entry{val: slices.Clone(val), version: m.version, expires: m.now().Add(ttl)}
	return nil
}

func (m *Memory) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	delete(m.entries, key)
	return nil
}

func (m *Memory) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	return nil
}

// Close stops the sweeps and drops every value.
func (m *Memory) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.entries = nil
	m.mu.Unlock()
	close(m.stop)
	<-m.done
	return nil
}

// live returns the entry of key unless it has expired. The caller holds mu.
func (m *Memory) live(key string) (entry, bool) {
	e, ok := m.entries[key]
	if !ok || !m.now().Before(e.expires) {
		return entry{}, false
	}
	return e, true
}

func (m *Memory) sweepLoop(every time.Duration) {
	defer close(m.done)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.sweep()
		case <-m.stop:
			return
		}
	}
}

// sweep drops the expired keys.
func (m *Memory) sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for key, e := range m.entries {
		if !now.Before(e.expires) {
			delete(m.entries, key)
		}
	}
}
