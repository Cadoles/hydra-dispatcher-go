package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

// The windows of the addresses silent for two windows are forgotten, at most a
// minute after (revue R34).
func TestSweeps(t *testing.T) {
	l := New(10)
	now := time.Unix(1_800_000_000, 0)
	for i := range 3 {
		l.Take(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), now)
	}
	l.Take(netip.MustParseAddr("10.0.1.1"), now.Add(2*Window+time.Second))
	if n := len(l.windows); n != 1 {
		t.Errorf("%d windows kept, want 1", n)
	}
}

func TestRetryAt(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for name, tt := range map[string]struct {
		w    window
		now  time.Time
		want time.Duration // after start
	}{
		"full window":            {window{start: start, cur: 100}, start.Add(10 * time.Second), Window + Window/100},
		"previous full":          {window{start: start, prev: 100, cur: 0}, start, Window / 100},
		"previous half, current": {window{start: start, prev: 100, cur: 49}, start, Window / 2},
		"already free":           {window{start: start, prev: 10}, start.Add(time.Second), time.Second},
	} {
		if got := tt.w.retryAt(tt.now, 100).Sub(start); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}
