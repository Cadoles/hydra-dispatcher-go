package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// What the Redis store decides without a server; the contract against Redis
// 7 and Dragonfly is in redis_integration_test.go (tag integration).
func TestRedisWithoutServer(t *testing.T) {
	ctx := context.Background()
	if _, err := NewRedis("http://user:secret@redis:6379", "", 0); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("NewRedis of an http:// URL = %v, want an error without the password", err)
	}
	for _, c := range []struct {
		dsn  string
		size int
		want int
	}{
		{"redis://127.0.0.1:1", 3, 3},
		{"redis://127.0.0.1:1?pool_size=7", 0, 7},
		{"redis://127.0.0.1:1?pool_size=7", 2, 2},
		{"unix:///run/redis.sock", 4, 4},
	} {
		s, err := NewRedis(c.dsn, "p:", c.size)
		if err != nil {
			t.Fatalf("NewRedis(%s) = %v", c.dsn, err)
		}
		if got := s.client.Options().PoolSize; got != c.want {
			t.Errorf("NewRedis(%s, %d): pool of %d, want %d", c.dsn, c.size, got, c.want)
		}
		_ = s.Close()
	}

	s, err := NewRedis("redis://127.0.0.1:1", "p:", 1)
	if err != nil {
		t.Fatal(err)
	}
	// No TTL, or a context ended, fail before any call.
	for _, d := range []time.Duration{0, -time.Second} {
		if err := s.Put(ctx, "flow:a", nil, d, 0); !errors.Is(err, ErrNoTTL) {
			t.Errorf("Put with TTL %s = %v, want ErrNoTTL", d, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Get(canceled, "flow:a"); !errors.Is(err, context.Canceled) {
		t.Errorf("Get = %v, want context.Canceled", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
	_, _, getErr := s.Get(ctx, "flow:a")
	for name, err := range map[string]error{
		"Get":    getErr,
		"Put":    s.Put(ctx, "flow:a", nil, time.Minute, 0),
		"Delete": s.Delete(ctx, "flow:a"),
		"Ping":   s.Ping(ctx),
	} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s once closed = %v, want ErrClosed", name, err)
		}
	}
}

func TestVersions(t *testing.T) {
	for range 1000 {
		if newVersion() == 0 {
			t.Fatal("version 0 drawn")
		}
	}
	if got := formatVersion(0x1f); got != "000000000000001f" {
		t.Errorf("formatVersion = %q", got)
	}
	if noVersion != "0000000000000000" {
		t.Errorf("noVersion = %q", noVersion)
	}
	for _, c := range []struct {
		data string
		want uint64
		ok   bool
	}{
		{"000000000000001fvalue", 0x1f, true},
		{"ffffffffffffffff", 1<<64 - 1, true},
		{"000000000000001", 0, false},
		{"0000000000000000value", 0, false},
		{"+00000000000001fvalue", 0, false},
		{"zzzzzzzzzzzzzzzz", 0, false},
	} {
		v, err := parseVersion([]byte(c.data))
		if v != c.want || (err == nil) != c.ok {
			t.Errorf("parseVersion(%q) = %x, %v; want %x, ok %v", c.data, v, err, c.want, c.ok)
		}
	}
}
