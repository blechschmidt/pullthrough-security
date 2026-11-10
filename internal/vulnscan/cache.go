package vulnscan

import (
	"sort"
	"sync"
	"time"
)

// resultCache caches scan Reports keyed by artifact content digest. Entries carry
// an expiry (the configured TTL); a stale entry is retained until evicted so it
// can serve as an offline fallback when the scanner backend is unreachable. The
// cache is bounded by a maximum entry count, evicting the least-recently-stored
// entries first.
type resultCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	maxSize int
	now     func() time.Time
}

type cacheEntry struct {
	report   *Report
	storedAt time.Time
	expireAt time.Time
}

// newResultCache builds a result cache with the given TTL and capacity. A
// non-positive maxSize defaults to 4096; a non-positive TTL means entries never
// expire (always fresh).
func newResultCache(ttl time.Duration, maxSize int) *resultCache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &resultCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
	}
}

// get returns the cached report for digest. fresh reports whether the entry is
// within its TTL; a stale entry is still returned (ok=true) so the caller can use
// it as an offline fallback.
func (c *resultCache) get(digest string) (report *Report, fresh, ok bool) {
	if digest == "" {
		return nil, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[digest]
	if !present {
		return nil, false, false
	}
	fresh = c.ttl <= 0 || c.now().Before(e.expireAt)
	return e.report, fresh, true
}

// put stores a report under digest, evicting the oldest entries when over
// capacity.
func (c *resultCache) put(digest string, report *Report) {
	if digest == "" || report == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	exp := now.Add(c.ttl)
	if c.ttl <= 0 {
		exp = time.Time{}
	}
	c.entries[digest] = &cacheEntry{report: report, storedAt: now, expireAt: exp}
	c.evictLocked()
}

// delete removes a cached report (used when an artifact is quarantined/evicted).
func (c *resultCache) delete(digest string) {
	c.mu.Lock()
	delete(c.entries, digest)
	c.mu.Unlock()
}

// evictLocked drops the oldest-stored entries until the cache is within capacity.
func (c *resultCache) evictLocked() {
	overflow := len(c.entries) - c.maxSize
	if overflow <= 0 {
		return
	}
	type aged struct {
		key string
		at  time.Time
	}
	all := make([]aged, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, aged{k, e.storedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < overflow && i < len(all); i++ {
		delete(c.entries, all[i].key)
	}
}

// snapshot reports the current cached reports (most-recently-stored first) for
// the admin/observability surfaces, along with the entry count.
func (c *resultCache) snapshot() []*Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	type aged struct {
		report *Report
		at     time.Time
	}
	all := make([]aged, 0, len(c.entries))
	for _, e := range c.entries {
		all = append(all, aged{e.report, e.storedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	out := make([]*Report, len(all))
	for i, a := range all {
		out[i] = a.report
	}
	return out
}

// size returns the number of cached entries.
func (c *resultCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
