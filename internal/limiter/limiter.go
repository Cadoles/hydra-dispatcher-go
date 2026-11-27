// Package limiter slows what looks like forging on the pages, by client address: a
// challenge no one issued, an invalid CSRF token. Past max in a window, the address gets
// 429 for a while. It lives in the memory of each instance: with N replicas the real
// threshold rises up to N times, which is accepted, since it brakes and signals and the
// signature is what protects (doc, Durcissements point 4). A challenge expired is
// authentic and proves nothing: it does not count (Q78). Neither does what a client does
// not choose: the calls of the emulated API, whose challenge a login app relays from any
// browser, and a page another site loads in its visitor's browser (Q80, revue R29).
package limiter

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Cadoles/hydra-dispatcher-go/internal/flow"
	"github.com/Cadoles/hydra-dispatcher-go/internal/httpx"
)

// maxEntries bounds the memory: past it, the addresses that no longer count are dropped,
// and if none is, all of them, an attacker's flood of addresses costing only the brake.
const maxEntries = 100_000

type entry struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

// Limiter is security.failure_rate_limit. Observe, a flow.Observer, counts; Guard refuses.
type Limiter struct {
	max        int
	per, block time.Duration
	// Now is the clock, time.Now when nil.
	Now func() time.Time
	// OnBlock, nil for none, hears of an address blocked; OnRefused of each request
	// refused on its surface.
	OnBlock   func(ctx context.Context)
	OnRefused func(ctx context.Context, surface string)

	mu      sync.Mutex
	entries map[netip.Addr]*entry
}

// New allows max failures per window, then blocks for block.
func New(max int, per, block time.Duration) *Limiter {
	return &Limiter{max: max, per: per, block: block, entries: map[netip.Addr]*entry{}}
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// key is what is counted: the address, a whole /64 in IPv6, which one client commonly
// holds; the zero Addr of a client unknown is no one's, and counts nothing.
func key(ip netip.Addr) (netip.Addr, bool) {
	if !ip.IsValid() {
		return ip, false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip, true
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip, false
	}
	return p.Addr(), true
}

// failed tells what in a request counts: one at most by request, on the pages only. On
// the emulated API, the caller is a login app, which passes on the login_challenge of the
// URL a browser opened: counted there, a forged challenge or another app's (EMU-3, EMU-4)
// would let any client of the Internet stop the app for all its users (Q80).
func failed(o flow.Observation) bool {
	if o.Surface == "emulated" {
		return false
	}
	if o.Response.Code == flow.E1008 {
		return true
	}
	return slices.ContainsFunc(o.Reports, func(r flow.Report) bool {
		return r.Event == "challenge.invalid" && r.Detail == "forged"
	})
}

// notCounted marks the context of a request its client did not make: Guard sets it.
type notCounted struct{}

// subrequest tells what a page loads for itself, an <img>, an iframe, a fetch, from the
// fetch metadata browsers send over HTTPS: another site's page, in its visitor's browser,
// would block the visitor's address, and everyone behind it (Q80). The pages of the
// dispatcher load none of the routes Guard covers; a navigation, a form included, is a
// document. Without the header, a client that is no browser, the request counts.
func subrequest(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest != "" && dest != "document"
}

// Observe is flow.Observer.
func (l *Limiter) Observe(ctx context.Context, o flow.Observation) {
	if ctx.Value(notCounted{}) != nil || !failed(o) {
		return
	}
	k, ok := key(httpx.ClientIP(ctx))
	if !ok {
		return
	}
	if l.count(k) && l.OnBlock != nil {
		l.OnBlock(ctx)
	}
}

// count adds a failure and tells whether it starts a block.
func (l *Limiter) count(k netip.Addr) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[k]
	if e == nil {
		if len(l.entries) >= maxEntries {
			l.sweep(now)
		}
		e = &entry{windowStart: now}
		l.entries[k] = e
	}
	if now.Before(e.blockedUntil) {
		return false
	}
	if now.Sub(e.windowStart) >= l.per {
		e.count, e.windowStart = 0, now
	}
	e.count++
	if e.count <= l.max {
		return false
	}
	e.count, e.blockedUntil = 0, now.Add(l.block)
	return true
}

// sweep drops what no longer counts, and everything if that frees nothing.
func (l *Limiter) sweep(now time.Time) {
	for k, e := range l.entries {
		if now.After(e.blockedUntil) && now.Sub(e.windowStart) >= l.per {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= maxEntries {
		clear(l.entries)
	}
}

// retryAfter is how long k stays blocked, 0 when it is not.
func (l *Limiter) retryAfter(k netip.Addr) time.Duration {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[k]; e != nil && now.Before(e.blockedUntil) {
		return e.blockedUntil.Sub(now)
	}
	return 0
}

// Guard refuses a blocked address on surface, with 429 and Retry-After, before anything
// else of the request: no read of Hydra or of the store. RealIP must run outside it. A
// subrequest is refused the same, but what it fails does not count.
func (l *Limiter) Guard(surface string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subrequest(r) {
				r = r.WithContext(context.WithValue(r.Context(), notCounted{}, true))
			}
			if k, ok := key(httpx.ClientIP(r.Context())); ok {
				if wait := l.retryAfter(k); wait > 0 {
					if l.OnRefused != nil {
						l.OnRefused(r.Context(), surface)
					}
					w.Header().Set("Retry-After", strconv.Itoa(int(wait.Round(time.Second)/time.Second)+1))
					w.Header().Set("Cache-Control", "no-store")
					http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
