//go:build integration

package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisURLsEnv names the servers the integration tests run the contract on,
// comma-separated: a Redis 7 and a Dragonfly of hydra-dev's version, each a
// container of its own, never the stack's.
const redisURLsEnv = "REDIS_URLS"

// The integration tests need Redis-compatible servers where they may write
// keys of their own: the tag without REDIS_URLS fails rather than passing
// untested.
func TestMain(m *testing.M) {
	if os.Getenv(redisURLsEnv) == "" {
		fmt.Fprintln(os.Stderr, "the integration tag needs "+redisURLsEnv+": redis:// URLs, comma-separated, of a Redis 7 and a Dragonfly the tests may write to")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// redisTTL is the TTL of the contract's writes against a real server: the
// expiry tests sleep for it, with a quarter of it as a margin.
const redisTTL = time.Second

// openRedis returns a store of dsn under a key prefix of its own, closed at
// the end of t.
func openRedis(t *testing.T, dsn string) *Redis {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	s, err := NewRedis(dsn, "dispatcher-test:"+hex.EncodeToString(b)+":", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// servers returns the URLs of REDIS_URLS by the name of their server:
// redis-7.4.2, dragonfly-df-v1.34.1.
func servers(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, dsn := range strings.Split(os.Getenv(redisURLsEnv), ",") {
		if dsn = strings.TrimSpace(dsn); dsn == "" {
			continue
		}
		s := openRedis(t, dsn)
		info, err := s.client.Info(context.Background(), "server").Result()
		if err != nil {
			t.Fatalf("%s: %v", dsn, err)
		}
		name := "redis-unknown"
		for line := range strings.Lines(info) {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "dragonfly_version:"); ok {
				name = "dragonfly-" + v
				break
			}
			if v, ok := strings.CutPrefix(line, "redis_version:"); ok {
				name = "redis-" + v
			}
		}
		out[name] = dsn
	}
	return out
}

func TestRedis(t *testing.T) {
	for name, dsn := range servers(t) {
		t.Run(name, func(t *testing.T) {
			testStore(t, func(t *testing.T) (StateStore, time.Duration, func(time.Duration)) {
				return openRedis(t, dsn), redisTTL, time.Sleep
			})
			testRedis(t, dsn)
		})
	}
}

// testRedis checks what the Redis backend adds to the contract: the form of
// the stored string, the TTL, the prefix, and its script.
func testRedis(t *testing.T, dsn string) {
	ctx := context.Background()

	t.Run("one string, the version then the value, with its TTL", func(t *testing.T) {
		s := openRedis(t, dsn)
		mustPut(t, s, "flow:a", `{"v":1}`, time.Minute, 0)
		_, v := mustGet(t, s, "flow:a", `{"v":1}`)
		raw, err := s.client.Get(ctx, s.prefix+"flow:a").Result()
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("%016x", v) + `{"v":1}`; raw != want {
			t.Errorf("stored %q, want %q", raw, want)
		}
		// I4: no key without a TTL, the one given.
		if ttl, err := s.client.PTTL(ctx, s.prefix+"flow:a").Result(); err != nil || ttl <= 0 || ttl > time.Minute {
			t.Errorf("PTTL = %s, %v; want in (0, 1m]", ttl, err)
		}
		if n, err := s.client.Exists(ctx, "flow:a").Result(); err != nil || n != 0 {
			t.Errorf("key without the prefix: %d, %v", n, err)
		}
	})

	// Q42: go-redis resends a script whose answer was lost; the store then
	// holds the new version, which answers written, not a conflict on its
	// own write.
	t.Run("a script sent again after its write answers written", func(t *testing.T) {
		s := openRedis(t, dsn)
		for _, c := range []struct {
			name      string
			ifVersion uint64
		}{{"creation", 0}, {"update", 0}} {
			ifVersion := c.ifVersion
			if c.name == "update" {
				_, ifVersion = mustGet(t, s, "flow:a", "one")
			}
			version := newVersion()
			for i := range 2 {
				if err := s.put(ctx, "flow:a", []byte("one"), time.Minute, ifVersion, version); err != nil {
					t.Fatalf("%s, sent %d times: %v", c.name, i+1, err)
				}
			}
			if _, v := mustGet(t, s, "flow:a", "one"); v != version {
				t.Errorf("%s: version %x, want %x", c.name, v, version)
			}
		}
		// Another version on the one read before is a conflict all the same.
		if err := s.put(ctx, "flow:a", []byte("two"), time.Minute, 0, newVersion()); !errors.Is(err, ErrConflict) {
			t.Errorf("a creation on an existing key = %v, want ErrConflict", err)
		}
	})

	// Run sends EVALSHA, then EVAL when the server answers NOSCRIPT: a
	// script cache flushed, a server restarted.
	t.Run("the script loaded again after a flush", func(t *testing.T) {
		s := openRedis(t, dsn)
		if err := s.client.ScriptFlush(ctx).Err(); err != nil {
			t.Fatal(err)
		}
		mustPut(t, s, "flow:a", "one", time.Minute, 0)
		mustGet(t, s, "flow:a", "one")
	})

	t.Run("a value without its version", func(t *testing.T) {
		s := openRedis(t, dsn)
		for _, raw := range []string{"short", "000000000000000000", "zzzzzzzzzzzzzzzz{}"} {
			if err := s.client.Set(ctx, s.prefix+"flow:a", raw, time.Minute).Err(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Get(ctx, "flow:a"); err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("Get of %q = %v, want an error", raw, err)
			}
		}
	})

	// Q42, for real (revue R21): the script runs, a proxy cuts the connection
	// instead of forwarding its answer, go-redis sends it again.
	t.Run("a script whose answer is lost answers written", func(t *testing.T) {
		s := openRedis(t, dsn)
		if err := putScript.Load(ctx, s.client).Err(); err != nil {
			t.Fatal(err)
		}
		addr, cut := answerCutter(t, s.client.Options().Addr)
		through, err := NewRedis("redis://"+addr+"/0", s.prefix, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = through.Close() }()
		if err := through.Put(ctx, "flow:a", []byte("one"), time.Minute, 0); err != nil {
			t.Fatalf("Put, its answer lost = %v, want written", err)
		}
		if cut.Load() != 1 {
			t.Fatalf("%d answers cut, want 1", cut.Load())
		}
		mustGet(t, s, "flow:a", "one")
	})

	// Concurrent writers lose nothing: the script is atomic on each server,
	// which Dragonfly's documentation only says in passing. Each write
	// answered written counted once.
	t.Run("concurrent writers lose no write", func(t *testing.T) {
		s := openRedis(t, dsn)
		mustPut(t, s, "flow:n", "0", time.Minute, 0)
		var written, failed atomic.Int64
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				for range 100 {
					data, v, err := s.Get(ctx, "flow:n")
					if err != nil {
						failed.Add(1)
						continue
					}
					n, _ := strconv.Atoi(string(data))
					switch err := s.Put(ctx, "flow:n", []byte(strconv.Itoa(n+1)), time.Minute, v); {
					case err == nil:
						written.Add(1)
					case !errors.Is(err, ErrConflict):
						failed.Add(1)
					}
				}
			})
		}
		wg.Wait()
		data, _, err := s.Get(ctx, "flow:n")
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := strconv.Atoi(string(data)); int64(got) != written.Load() || failed.Load() != 0 {
			t.Errorf("counter %d, %d writes answered written, %d failed", got, written.Load(), failed.Load())
		}
	})

	t.Run("an unreachable server", func(t *testing.T) {
		s, err := NewRedis("redis://127.0.0.1:1", "x:", 1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		for name, err := range map[string]error{
			"Ping": s.Ping(ctx),
			"Put":  s.Put(ctx, "flow:a", []byte("v"), time.Minute, 0),
		} {
			// Of unknown outcome, never a conflict nor a closed store.
			if err == nil || errors.Is(err, ErrConflict) || errors.Is(err, ErrClosed) || errors.Is(err, redis.Nil) {
				t.Errorf("%s = %v, want a connection error", name, err)
			}
		}
	})
}

// answerCutter is a proxy to target that closes the client's connection
// instead of forwarding the first answer to an EVALSHA, the script having run
// on the server. It returns its address and how many answers it cut.
func answerCutter(t *testing.T, target string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cut := &atomic.Int32{}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = client.Close() }()
				server, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				var armed atomic.Bool
				go func() {
					defer func() { _ = server.Close() }()
					buf := make([]byte, 64<<10)
					for {
						n, err := client.Read(buf)
						if err != nil {
							return
						}
						if cut.Load() == 0 && bytes.Contains(bytes.ToLower(buf[:n]), []byte("evalsha")) {
							armed.Store(true)
						}
						if _, err := server.Write(buf[:n]); err != nil {
							return
						}
					}
				}()
				buf := make([]byte, 64<<10)
				for {
					n, err := server.Read(buf)
					if err != nil {
						return
					}
					if armed.Load() && cut.CompareAndSwap(0, 1) {
						return
					}
					if _, err := client.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), cut
}
