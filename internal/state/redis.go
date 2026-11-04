package state

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// versionLen is the length of the version written before each value: 16
// hexadecimal characters, a uint64.
const versionLen = 16

// noVersion is the version a Put of a key that must not exist compares to:
// no key holds it, a version being never 0.
var noVersion = formatVersion(0)

// putScript writes ARGV[2] then ARGV[3] under KEYS[1] for ARGV[4]
// milliseconds when the version stored is ARGV[1], or when the key is absent
// and ARGV[1] is noVersion; it answers 1 when written, 0 on a conflict. A
// version stored equal to the new one, ARGV[2], is this very write sent
// again (go-redis resends a command whose answer was lost, MaxRetries): it
// answers 1, written, rather than a conflict on its own write (Q42).
//
// It touches KEYS[1] alone, which Dragonfly requires by default (an
// undeclared key fails the script) and a Redis Cluster too, and compares
// strings only: Redis runs Lua 5.1, whose numbers are doubles, exact up to
// 2^53, and Dragonfly Lua 5.4.
var putScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur then
  local v = string.sub(cur, 1, 16)
  if v == ARGV[2] then
    return 1
  end
  if v ~= ARGV[1] then
    return 0
  end
elseif ARGV[1] ~= '` + noVersion + `' then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2] .. ARGV[3], 'PX', ARGV[4])
return 1
`)

// Redis is the store of several replicas (state.redis_dsn): each key holds
// one string, its version in 16 hexadecimal characters then its value, read
// by one GET and written by putScript. Its versions are drawn at random on
// 64 bits, never 0: a counter would live in a key outside the flow's slot in
// a Redis Cluster, which the script cannot touch, and may go back after a
// Sentinel failover (Stockage de l'état, versions).
type Redis struct {
	client *redis.Client
	prefix string
	closed atomic.Bool
}

// NewRedis returns the store of dsn, a redis://, rediss:// or unix:// URL,
// its keys under prefix (state.key_prefix). poolSize, when above 0, sets the
// size of the pool; 0 leaves go-redis's, 10 connections per CPU, or the
// pool_size of the URL. It connects at the first call.
func NewRedis(dsn, prefix string, poolSize int) (*Redis, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		// Its message may quote the URL, and with it a password.
		return nil, errors.New("state.redis_dsn: not a valid redis://, rediss:// or unix:// URL")
	}
	if poolSize > 0 {
		opt.PoolSize = poolSize
	}
	return &Redis{client: redis.NewClient(opt), prefix: prefix}, nil
}

func (s *Redis) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	if err := s.usable(ctx); err != nil {
		return nil, 0, err
	}
	data, err := s.client.Get(ctx, s.prefix+key).Bytes()
	switch {
	case errors.Is(err, redis.Nil):
		return nil, 0, ErrNotFound
	case err != nil:
		return nil, 0, s.failed(err)
	}
	v, err := parseVersion(data)
	if err != nil {
		return nil, 0, fmt.Errorf("state: key %s: %w", key, err)
	}
	return data[versionLen:], v, nil
}

func (s *Redis) Put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion uint64) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrNoTTL
	}
	return s.put(ctx, key, val, ttl, ifVersion, newVersion())
}

// put runs putScript with the new version given: a call sent again with the
// same one, as go-redis resends it, answers written.
func (s *Redis) put(ctx context.Context, key string, val []byte, ttl time.Duration, ifVersion, version uint64) error {
	// Whole milliseconds, rounded up: PX 0 is refused.
	ms := (ttl + time.Millisecond - 1) / time.Millisecond
	written, err := putScript.Run(ctx, s.client, []string{s.prefix + key},
		formatVersion(ifVersion), formatVersion(version), val, strconv.FormatInt(int64(ms), 10)).Int()
	switch {
	case err != nil:
		// Of unknown outcome: the script may have run, its answer lost.
		return s.failed(err)
	case written != 1:
		return ErrConflict
	}
	return nil
}

func (s *Redis) Delete(ctx context.Context, key string) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	if err := s.client.Del(ctx, s.prefix+key).Err(); err != nil {
		return s.failed(err)
	}
	return nil
}

// Ping is /ready's probe: a PING.
func (s *Redis) Ping(ctx context.Context) error {
	if err := s.usable(ctx); err != nil {
		return err
	}
	if err := s.client.Ping(ctx).Err(); err != nil {
		return s.failed(err)
	}
	return nil
}

// Close closes the pool; a call still running then fails with ErrClosed.
func (s *Redis) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	return s.client.Close()
}

// usable fails a call whose context ended, or on a closed store.
func (s *Redis) usable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed.Load() {
		return ErrClosed
	}
	return nil
}

// failed returns ErrClosed for an error of a store closed meanwhile, err
// otherwise: a connection cut by Close is no unknown outcome to read again.
func (s *Redis) failed(err error) error {
	if s.closed.Load() || errors.Is(err, redis.ErrClosed) {
		return ErrClosed
	}
	return err
}

// newVersion draws a version on 64 bits, never 0.
func newVersion() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:]) // crypto/rand never fails
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v
		}
	}
}

func formatVersion(v uint64) string { return fmt.Sprintf("%016x", v) }

var errMalformed = errors.New("value without its version")

// parseVersion reads the version a stored string starts with.
func parseVersion(data []byte) (uint64, error) {
	if len(data) < versionLen {
		return 0, errMalformed
	}
	v, err := strconv.ParseUint(string(data[:versionLen]), 16, 64)
	if err != nil || v == 0 {
		return 0, errMalformed
	}
	return v, nil
}
