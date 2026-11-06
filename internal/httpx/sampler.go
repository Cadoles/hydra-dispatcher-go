package httpx

import (
	"context"
	"sync"
	"time"
)

// Sampler keeps the log lines a client can make endless to one by key and by window. It
// holds at most maxSampled keys, then starts over: at worst, a few more lines.
type Sampler struct {
	every time.Duration
	// Now is the clock, time.Now when nil.
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

const maxSampled = 10_000

// NewSampler lets one line by key through every every.
func NewSampler(every time.Duration) *Sampler {
	return &Sampler{every: every, seen: map[string]time.Time{}}
}

// Allow tells whether a line of key goes; a nil Sampler lets everything through.
func (s *Sampler) Allow(key string) bool {
	if s == nil {
		return true
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.seen[key]; ok && now.Sub(last) < s.every {
		return false
	}
	if len(s.seen) >= maxSampled {
		clear(s.seen)
	}
	s.seen[key] = now
	return true
}

// AllowClient is Allow by event and by the client of the request.
func (s *Sampler) AllowClient(ctx context.Context, event string) bool {
	if s == nil {
		return true
	}
	return s.Allow(event + "|" + ClientIP(ctx).String())
}
