// Package state keeps the flows in progress: one value per key, each with a
// TTL, written only when the caller still holds the current version. Two
// backends share the interface: memory for a single instance, Redis for
// several replicas (state.redis_dsn).
package state

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is the answer for a key that is absent or expired.
	ErrNotFound = errors.New("state: no such key")
	// ErrConflict is Put's answer when the version given is not the key's
	// current one: another request wrote it since it was read.
	ErrConflict = errors.New("state: version conflict")
	// ErrNoTTL is Put's answer for a TTL of zero or less: no key lives
	// without one.
	ErrNoTTL = errors.New("state: a TTL is required")
	// ErrClosed is the answer of a store once closed.
	ErrClosed = errors.New("state: store closed")
)

// StateStore holds values under keys with a TTL. A version comes with each
// value: it is never 0, changes at every Put, and is not given again to a
// key deleted or expired then written again, so that a Put on a version read
// before cannot overwrite the newer value. The memory store counts its
// versions. A store that cannot keep one counter for all its keys (Redis: a
// Cluster spreads them over slots, a failover may lose the last increments)
// draws them at random on 64 bits: a version given twice is then only
// improbable.
type StateStore interface {
	// Get returns the value of key and its version, or ErrNotFound.
	Get(ctx context.Context, key string) (val []byte, version uint64, err error)
	// Put writes val under key for ttl, if the key's current version is
	// ifVersion: 0 creates a key that must not exist. Otherwise it fails with
	// ErrConflict, and writes nothing. ttl counts in whole milliseconds,
	// rounded up, as Redis keeps it; one of zero or less fails with ErrNoTTL.
	// After any other error, val may have been written or not (a call cut
	// once sent): read the key again before deciding.
	Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error
	// Delete removes key; an absent key is not an error.
	Delete(ctx context.Context, key string) error
	// Close releases the store: after it, Get, Put and Delete fail with
	// ErrClosed, unless their own arguments fail first (a context ended, no
	// TTL). Closing again returns nil.
	Close() error
}
