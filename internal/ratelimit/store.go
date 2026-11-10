package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Store is the pluggable backend for the windowed byte-quota counters that must
// be coordinated across replicas. Implementations expire (reset) a counter once
// its window has elapsed since the window started. A purely local deployment
// uses the in-memory implementation; a horizontally-scaled deployment supplies
// a shared implementation (for example, one backed by the S3/shared-object
// store that the cache HA path already uses) so all replicas debit one budget.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Add atomically adds delta to the counter at key and returns the resulting
	// total for the current window. delta may be zero to read-after-roll.
	Add(ctx context.Context, key string, delta int64, window time.Duration) (total int64, err error)
	// Current returns the counter's value for the current window (zero when
	// absent or the window has elapsed).
	Current(ctx context.Context, key string, window time.Duration) (total int64, err error)
}

// windowStart exposes the start time of a key's current window, used to compute
// a window-end timestamp for snapshots. It is optional; stores that cannot
// report it (e.g. a remote object store) simply do not implement it.
type windowStart interface {
	windowStart(key string) (time.Time, bool)
}

// memStore is the default in-memory Store. It is sufficient for single-replica
// deployments and is the test/dev default; multi-replica deployments override
// it with a shared implementation.
type memStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*memCounter
}

type memCounter struct {
	value int64
	start time.Time
}

func newMemStore(now func() time.Time) *memStore {
	if now == nil {
		now = time.Now
	}
	return &memStore{now: now, entries: make(map[string]*memCounter)}
}

// rolled returns the (window-rolled) counter for key, creating it on first use.
// Caller holds mu.
func (s *memStore) rolled(key string, window time.Duration) *memCounter {
	now := s.now()
	c, ok := s.entries[key]
	if !ok {
		c = &memCounter{start: now}
		s.entries[key] = c
		return c
	}
	if window > 0 && now.Sub(c.start) >= window {
		c.value = 0
		c.start = now
	}
	return c
}

func (s *memStore) Add(_ context.Context, key string, delta int64, window time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.rolled(key, window)
	c.value += delta
	return c.value, nil
}

func (s *memStore) Current(_ context.Context, key string, window time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.rolled(key, window)
	return c.value, nil
}

func (s *memStore) windowStart(key string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.entries[key]; ok {
		return c.start, true
	}
	return time.Time{}, false
}
