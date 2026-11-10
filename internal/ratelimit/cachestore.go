package ratelimit

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// CacheStore adapts a cache.Store (e.g. the S3/object-storage store the cache HA
// path uses) into a ratelimit.Store, so horizontally-scaled replicas coordinate
// their byte quotas through the shared object store they already operate.
//
// Counters are persisted as small blobs holding the decimal byte total; the blob
// Record's CreatedAt anchors the rolling window. A per-process mutex makes
// read-modify-write atomic within a replica; coordination across replicas is
// eventually consistent (the object store offers no atomic increment), which is
// acceptable for a cumulative byte budget — a brief overlap can let a tenant
// exceed its quota by at most the bytes of the requests racing across replicas,
// after which all replicas observe the breach and reject.
type CacheStore struct {
	store cache.Store
	now   func() time.Time

	mu sync.Mutex
}

// NewCacheStore wraps a cache.Store as a ratelimit.Store. now may be nil
// (defaults to time.Now).
func NewCacheStore(store cache.Store, now func() time.Time) *CacheStore {
	if now == nil {
		now = time.Now
	}
	return &CacheStore{store: store, now: now}
}

// Add atomically (within this replica) adds delta and returns the window total.
func (c *CacheStore) Add(ctx context.Context, key string, delta int64, window time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	value, start, found := c.read(ctx, key)
	now := c.now()
	if !found || (window > 0 && now.Sub(start) >= window) {
		value = 0
		start = now
	}
	value += delta
	if err := c.write(ctx, key, value, start); err != nil {
		return 0, err
	}
	return value, nil
}

// Current returns the window total without modifying it.
func (c *CacheStore) Current(ctx context.Context, key string, window time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	value, start, found := c.read(ctx, key)
	if !found {
		return 0, nil
	}
	if window > 0 && c.now().Sub(start) >= window {
		return 0, nil
	}
	return value, nil
}

// read loads the counter and its window start. A parse failure is treated as an
// absent counter (self-healing) rather than a hard error.
func (c *CacheStore) read(ctx context.Context, key string) (value int64, start time.Time, found bool) {
	rc, rec, err := c.store.Get(ctx, key)
	if err != nil {
		return 0, time.Time{}, false
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 64))
	if err != nil {
		return 0, time.Time{}, false
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(data)), 10, 64)
	if err != nil {
		return 0, time.Time{}, false
	}
	return n, rec.CreatedAt, true
}

// write persists the counter, anchoring the window at start via CreatedAt.
func (c *CacheStore) write(ctx context.Context, key string, value int64, start time.Time) error {
	rec := cache.Record{
		Key:         key,
		Origin:      "ratelimit",
		ContentType: "text/plain",
		CreatedAt:   start,
		ModTime:     c.now(),
		AccessedAt:  c.now(),
	}
	_, err := c.store.Put(ctx, rec, bytes.NewReader([]byte(strconv.FormatInt(value, 10))))
	return err
}

// ensure the adapter satisfies the Store interface.
var _ Store = (*CacheStore)(nil)
