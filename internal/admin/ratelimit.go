package admin

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// rateWindow is the window of the limit: a minute, as Symfony's.
const rateWindow = time.Minute

// rateLimiter counts the requests of each address in a sliding window, as
// Symfony's sliding_window policy does: the count of the current window, plus
// that of the previous one weighted by the share of it still in the sliding
// minute. In memory, per instance.
type rateLimiter struct {
	limit int

	mu        sync.Mutex
	windows   map[netip.Addr]*window
	lastSweep time.Time
}

type window struct {
	start     time.Time // of the current window
	prev, cur int
}

// rate is what a request is told of its limit.
type rate struct {
	allowed   bool
	remaining int
	// reset is the end of the current window, or, refused, the moment a
	// request passes again.
	reset time.Time
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, windows: map[netip.Addr]*window{}}
}

// take counts a request of ip at now, unless it passes the limit.
func (l *rateLimiter) take(ip netip.Addr, now time.Time) rate {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	w := l.windows[ip]
	if w == nil {
		w = &window{start: now}
		l.windows[ip] = w
	}
	w.advance(now)
	if w.estimate(now)+1 > float64(l.limit) {
		return rate{remaining: 0, reset: w.retryAt(now, l.limit)}
	}
	w.cur++
	remaining := l.limit - int(math.Ceil(w.estimate(now)))
	return rate{allowed: true, remaining: max(remaining, 0), reset: w.start.Add(rateWindow)}
}

// advance moves the window to the one now falls in.
func (w *window) advance(now time.Time) {
	switch elapsed := now.Sub(w.start); {
	case elapsed < rateWindow:
	case elapsed < 2*rateWindow:
		w.start, w.prev, w.cur = w.start.Add(rateWindow), w.cur, 0
	default:
		w.start, w.prev, w.cur = now, 0, 0
	}
}

// estimate is the count of the sliding minute that ends at now.
func (w *window) estimate(now time.Time) float64 {
	share := 1 - float64(now.Sub(w.start))/float64(rateWindow)
	return float64(w.prev)*share + float64(w.cur)
}

// retryAt is the first moment from now a request passes again.
func (w *window) retryAt(now time.Time, limit int) time.Time {
	room := float64(limit - 1)
	// In the current window, as the previous one weighs less.
	if float64(w.cur) <= room && w.prev > 0 {
		share := 1 - (room-float64(w.cur))/float64(w.prev)
		if at := w.start.Add(time.Duration(share * float64(rateWindow))); at.Before(w.start.Add(rateWindow)) {
			return later(at, now)
		}
	}
	// In the next one, the current one weighing as the previous.
	share := 0.0
	if w.cur > 0 {
		share = max(0, 1-room/float64(w.cur))
	}
	return later(w.start.Add(rateWindow).Add(time.Duration(share*float64(rateWindow))), now)
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// sweep forgets, once a minute, the addresses silent for two windows.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < rateWindow {
		return
	}
	l.lastSweep = now
	for ip, w := range l.windows {
		if now.Sub(w.start) >= 2*rateWindow {
			delete(l.windows, ip)
		}
	}
}
