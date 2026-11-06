package limiter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/flow"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/httpx"
)

// served plays a request from remote through Guard; next, when it runs, observes obs.
func served(l *Limiter, remote string, obs flow.Observation) *httptest.ResponseRecorder {
	h := httpx.Chain(l.Guard("front")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.Observe(r.Context(), obs)
		w.WriteHeader(http.StatusBadRequest)
	})), httpx.RealIP(nil))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

var forged = flow.Observation{Reports: []flow.Report{{Event: "challenge.invalid", Detail: "forged"}}}

// What counts, what does not: the expired are authentic (Q78).
func TestWhatCounts(t *testing.T) {
	for name, tc := range map[string]struct {
		o    flow.Observation
		want bool
	}{
		"forged":             {forged, true},
		"a CSRF invalid":     {flow.Observation{Response: flow.Response{Code: flow.E1008}}, true},
		"EMU-4":              {flow.Observation{Reports: []flow.Report{{Event: "security.ip_rejected"}}}, true},
		"expired":            {flow.Observation{Reports: []flow.Report{{Event: "challenge.invalid", Detail: "expired"}}}, false},
		"a stale generation": {flow.Observation{Reports: []flow.Report{{Event: "challenge.invalid", Detail: "stale_generation"}}}, false},
		"a page E1002":       {flow.Observation{Response: flow.Response{Code: flow.E1002}}, false},
		"a success":          {flow.Observation{Reports: []flow.Report{{Event: "hydra.login_accepted"}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := failed(tc.o); got != tc.want {
				t.Errorf("got %v", got)
			}
		})
	}
}

// 20 failures in a minute pass, the next blocks for 5 minutes; then the address starts
// over. An address is not another's. Hooks hear of it, once for the block.
func TestBlock(t *testing.T) {
	now := time.Unix(10_000, 0)
	l := New(3, time.Minute, 5*time.Minute)
	l.Now = func() time.Time { return now }
	blocks, refused := 0, 0
	l.OnBlock = func(context.Context) { blocks++ }
	l.OnRefused = func(_ context.Context, surface string) {
		refused++
		if surface != "front" {
			t.Errorf("surface %s", surface)
		}
	}
	const a, b = "203.0.113.9:1", "203.0.113.10:1"
	for i := range 4 {
		if rec := served(l, a, forged); rec.Code != http.StatusBadRequest {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	if blocks != 1 {
		t.Errorf("%d blocks", blocks)
	}
	rec := served(l, a, forged)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "301" || refused != 1 {
		t.Errorf("blocked: %d, Retry-After %q, refused %d", rec.Code, rec.Header().Get("Retry-After"), refused)
	}
	if rec := served(l, b, forged); rec.Code != http.StatusBadRequest {
		t.Errorf("another address: %d", rec.Code)
	}
	now = now.Add(5*time.Minute - time.Second)
	if rec := served(l, a, forged); rec.Code != http.StatusTooManyRequests {
		t.Errorf("before the end: %d", rec.Code)
	}
	now = now.Add(time.Second)
	if rec := served(l, a, forged); rec.Code != http.StatusBadRequest {
		t.Errorf("past the block: %d", rec.Code)
	}
	if blocks != 1 {
		t.Errorf("%d blocks", blocks)
	}
}

// Failures spread over windows never block; a success in between changes nothing.
func TestWindow(t *testing.T) {
	now := time.Unix(10_000, 0)
	l := New(2, time.Minute, 5*time.Minute)
	l.Now = func() time.Time { return now }
	for range 10 {
		served(l, "203.0.113.9:1", forged)
		served(l, "203.0.113.9:1", forged)
		now = now.Add(time.Minute)
	}
	if rec := served(l, "203.0.113.9:1", flow.Observation{}); rec.Code != http.StatusBadRequest {
		t.Errorf("status %d", rec.Code)
	}
}

// A client unknown counts for no one: it would block everyone unknown; an IPv6 client is
// its /64, which one client commonly holds.
func TestKeys(t *testing.T) {
	if _, ok := key(netip.Addr{}); ok {
		t.Error("the zero Addr counted")
	}
	a, _ := key(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b, _ := key(netip.MustParseAddr("2001:db8:1:2:bbbb::2"))
	c, _ := key(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Errorf("%s %s %s", a, b, c)
	}
	four, _ := key(netip.MustParseAddr("::ffff:203.0.113.9"))
	if four != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("mapped: %s", four)
	}
	l := New(1, time.Minute, time.Minute)
	for range 5 {
		l.Observe(context.Background(), forged)
	}
	if len(l.entries) != 0 {
		t.Errorf("%d entries for no client", len(l.entries))
	}
}

// The memory stays bounded under a flood of addresses.
func TestBounded(t *testing.T) {
	now := time.Unix(10_000, 0)
	l := New(5, time.Minute, time.Minute)
	l.Now = func() time.Time { return now }
	base := netip.MustParseAddr("10.0.0.0")
	for range maxEntries + 10 {
		base = base.Next()
		l.count(base)
	}
	if len(l.entries) > maxEntries {
		t.Errorf("%d entries", len(l.entries))
	}
}
