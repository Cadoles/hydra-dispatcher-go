// Package ratelimit counts the requests of each address in a sliding window,
// as Symfony's sliding_window policy does: the admin API (100 a minute, P15)
// and the login of the admin UI (10 attempts a minute, P20).
package ratelimit

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// Window is the window of the limit: a minute, as Symfony's.
const Window = time.Minute

// Limiter counts the requests of each address in a sliding window, as
// Symfony's sliding_window policy does: the count of the current window, plus
// that of the previous one weighted by the share of it still in the sliding
// minute. In memory, per instance.
type Limiter struct {
	limit int

	mu        sync.Mutex
	windows   map[netip.Addr]*window
	lastSweep time.Time
}

type window struct {
	start     time.Time // of the current window
	prev, cur int
}

// Rate is what a request is told of its limit.
type Rate struct {
	Allowed   bool
	Remaining int
	// Reset is the end of the current window, or, refused, the moment a
	// request passes again.
	Reset time.Time
}

// New allows limit requests of an address in the sliding minute.
func New(limit int) *Limiter {
	return &Limiter{limit: limit, windows: map[netip.Addr]*window{}}
}

// Take counts a request of ip at now, unless it passes the limit.
func (l *Limiter) Take(ip netip.Addr, now time.Time) Rate {
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
		return Rate{Remaining: 0, Reset: w.retryAt(now, l.limit)}
	}
	w.cur++
	remaining := l.limit - int(math.Ceil(w.estimate(now)))
	return Rate{Allowed: true, Remaining: max(remaining, 0), Reset: w.start.Add(Window)}
}

// advance moves the window to the one now falls in.
func (w *window) advance(now time.Time) {
	switch elapsed := now.Sub(w.start); {
	case elapsed < Window:
	case elapsed < 2*Window:
		w.start, w.prev, w.cur = w.start.Add(Window), w.cur, 0
	default:
		w.start, w.prev, w.cur = now, 0, 0
	}
}

// estimate is the count of the sliding minute that ends at now.
func (w *window) estimate(now time.Time) float64 {
	share := 1 - float64(now.Sub(w.start))/float64(Window)
	return float64(w.prev)*share + float64(w.cur)
}

// retryAt is the first moment from now a request passes again.
func (w *window) retryAt(now time.Time, limit int) time.Time {
	room := float64(limit - 1)
	// In the current window, as the previous one weighs less.
	if float64(w.cur) <= room && w.prev > 0 {
		share := 1 - (room-float64(w.cur))/float64(w.prev)
		if at := w.start.Add(time.Duration(share * float64(Window))); at.Before(w.start.Add(Window)) {
			return later(at, now)
		}
	}
	// In the next one, the current one weighing as the previous.
	share := 0.0
	if w.cur > 0 {
		share = max(0, 1-room/float64(w.cur))
	}
	return later(w.start.Add(Window).Add(time.Duration(share*float64(Window))), now)
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// sweep forgets, once a minute, the addresses silent for two windows.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < Window {
		return
	}
	l.lastSweep = now
	for ip, w := range l.windows {
		if now.Sub(w.start) >= 2*Window {
			delete(l.windows, ip)
		}
	}
}
