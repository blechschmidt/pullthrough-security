package cache

import (
	"container/list"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// defaultAccessPersistInterval throttles how often a read persists its updated
// last-access timestamp to the store. LRU ordering is always maintained in
// memory; persistence only matters for preserving order across a restart, so
// rewriting the metadata file on every single read would be wasteful.
const defaultAccessPersistInterval = time.Minute

// Loader fetches content for a key from upstream when it is absent from the
// cache. It returns the content stream and the metadata to persist with it. If
// the returned reader implements io.Closer it is closed after being stored.
type Loader func(ctx context.Context) (io.Reader, map[string]string, error)

// FilesystemOptions configures a FilesystemCache.
type FilesystemOptions struct {
	// Dir is the cache root directory. Required when Store is nil.
	Dir string
	// Store overrides the storage backend. When nil, a FilesystemStore rooted
	// at Dir is created. Supplying a Store is the extension point for S3/object
	// storage backends.
	Store Store
	// MaxSizeBytes bounds the total size of cached content. When the limit is
	// exceeded after a write, least-recently-used entries are evicted until the
	// cache is back under the limit. Zero means unbounded.
	MaxSizeBytes int64
	// TTL is the maximum age (from creation) of an entry before it is treated as
	// absent and eligible for removal. Zero disables TTL expiry.
	TTL time.Duration
	// JanitorInterval is how often a background sweep removes expired entries.
	// It only runs when TTL > 0. Defaults to TTL when unset.
	JanitorInterval time.Duration
	// AccessPersistInterval throttles persistence of last-access timestamps.
	// Defaults to one minute.
	AccessPersistInterval time.Duration
	// SharedStore enables high-availability mode for a Store shared by multiple
	// proxy replicas (e.g. the S3 backend). When set, a read that misses the
	// local in-memory index falls back to the durable store before reporting a
	// miss, so a replica serves content another replica wrote after this one
	// warmed its index. With a single-writer filesystem store this is
	// unnecessary; leave it false. Size-based LRU eviction is best-effort and
	// uncoordinated across replicas in this mode — manage retention via the
	// object store's lifecycle policies instead of MaxSizeBytes.
	SharedStore bool
	// Now overrides the clock; used in tests. Defaults to time.Now.
	Now func() time.Time
	// Pins reports the keys releases have pinned (Task 180): they are never
	// evicted for size, never expire, and Delete refuses them (see pins.go).
	// It is consulted from the first moment — the size bound is enforced while
	// the index is warmed — so a deployment with pins passes it here rather
	// than installing it later with SetPinChecker.
	Pins PinChecker
}

// FilesystemCache is a content-addressable Cache that layers an in-memory index,
// an LRU + max-size + TTL eviction policy, single-flight upstream loading, and
// hit/miss metrics on top of a pluggable Store.
//
// It satisfies the Cache interface and additionally exposes GetOrLoad for
// single-flight population and Metrics for observability.
type FilesystemCache struct {
	store                 Store
	maxSize               int64
	ttl                   time.Duration
	accessPersistInterval time.Duration
	sharedStore           bool
	now                   func() time.Time
	metrics               *Metrics
	sf                    *singleflight

	mu    sync.Mutex
	ll    *list.List               // most-recently-used at the front
	index map[string]*list.Element // key -> element holding *idxEntry
	total int64

	// pins holds the PinChecker (as a pinHolder); see pins.go.
	pins atomic.Value

	janitorStop chan struct{}
	janitorDone chan struct{}
}

// idxEntry is the in-memory index record for a cached blob.
type idxEntry struct {
	key         string
	size        int64
	createdAt   time.Time
	accessedAt  time.Time
	persistedAt time.Time // last time accessedAt was flushed to the store
	hits        int64     // process-local access count, drives LFU eviction
}

var _ Cache = (*FilesystemCache)(nil)

// NewFilesystemCache constructs a cache over the configured (or filesystem)
// store, warms its index from any pre-existing entries, and starts the TTL
// janitor when a TTL is set.
func NewFilesystemCache(opts FilesystemOptions) (*FilesystemCache, error) {
	store := opts.Store
	if store == nil {
		fs, err := NewFilesystemStore(opts.Dir)
		if err != nil {
			return nil, err
		}
		store = fs
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	accessInterval := opts.AccessPersistInterval
	if accessInterval <= 0 {
		accessInterval = defaultAccessPersistInterval
	}

	c := &FilesystemCache{
		store:                 store,
		maxSize:               opts.MaxSizeBytes,
		ttl:                   opts.TTL,
		accessPersistInterval: accessInterval,
		sharedStore:           opts.SharedStore,
		now:                   now,
		metrics:               &Metrics{},
		sf:                    newSingleflight(),
		ll:                    list.New(),
		index:                 make(map[string]*list.Element),
	}
	if opts.Pins != nil {
		c.SetPinChecker(opts.Pins)
	}

	if err := c.warmIndex(); err != nil {
		return nil, err
	}

	if c.ttl > 0 {
		interval := opts.JanitorInterval
		if interval <= 0 {
			interval = c.ttl
		}
		c.janitorStop = make(chan struct{})
		c.janitorDone = make(chan struct{})
		go c.janitor(interval)
	}

	return c, nil
}

// Metrics returns a snapshot of cache activity counters.
func (c *FilesystemCache) Metrics() MetricsSnapshot { return c.metrics.Snapshot() }

// CompactionStats reports the transparent storage-efficiency layer's statistics
// (Task 125) when the underlying store is a compacting store, else a disabled
// snapshot. It is the seam the admin API and the Prometheus bridge read.
func (c *FilesystemCache) CompactionStats() CompactionStats {
	if src, ok := c.store.(CompactionStatSource); ok {
		return src.CompactionStats()
	}
	return CompactionStats{Enabled: false, Codec: "none"}
}

// Entries returns a Stat for every cached blob, for administrative inspection.
// The order is unspecified. It reflects the durable store, so it includes
// entries written by a prior process that have not yet been read this run.
func (c *FilesystemCache) Entries(ctx context.Context) ([]Stat, error) {
	records, err := c.store.List(ctx)
	if err != nil {
		return nil, err
	}
	stats := make([]Stat, 0, len(records))
	for _, rec := range records {
		stats = append(stats, rec.toStat())
	}
	return stats, nil
}

// GCEntry is a rich, garbage-collection-facing view of a single cached blob. It
// carries enough state for the cache lifecycle manager (Task 39) to make eviction
// and retention decisions: size, age, recency, access frequency, whether a fetch
// is in flight for the key, and the full metadata map (for pin/reference rules).
type GCEntry struct {
	// Key is the cache key (content address or logical coordinate).
	Key string
	// Size is the content length in bytes.
	Size int64
	// CreatedAt is when the entry was first written; it drives FIFO and TTL.
	CreatedAt time.Time
	// AccessedAt is the last read time; it drives LRU.
	AccessedAt time.Time
	// AccessCount is the process-local read count; it drives LFU. It is reset on
	// restart and not shared across replicas, so LFU is best-effort in HA mode.
	AccessCount int64
	// InFlight reports whether a single-flight fetch is currently populating this
	// key. An in-flight entry must never be evicted (no eviction mid-stream).
	InFlight bool
	// Metadata is the entry's full metadata map (origin, content-type, pin marker,
	// tenant, ...), consulted by pin and reference-retention rules.
	Metadata map[string]string
}

// GCEntries returns a GC-facing view of every cached blob. It reads the durable
// store as the source of truth (so it includes entries written by a prior
// process or a peer replica) and overlays the live in-memory recency/frequency
// and the current single-flight in-flight set. It is the seam the cache
// lifecycle manager (Task 39) reads to plan eviction.
func (c *FilesystemCache) GCEntries(ctx context.Context) ([]GCEntry, error) {
	records, err := c.store.List(ctx)
	if err != nil {
		return nil, err
	}
	inflight := c.sf.keys()
	c.mu.Lock()
	out := make([]GCEntry, 0, len(records))
	for _, rec := range records {
		e := GCEntry{
			Key:        rec.Key,
			Size:       rec.Size,
			CreatedAt:  rec.CreatedAt,
			AccessedAt: rec.AccessedAt,
			Metadata:   rec.toStat().Metadata,
		}
		if elem, ok := c.index[rec.Key]; ok {
			ent := elem.Value.(*idxEntry)
			// The live in-memory recency is fresher than the throttled durable
			// timestamp; prefer it so LRU does not act on stale access times.
			if ent.accessedAt.After(e.AccessedAt) {
				e.AccessedAt = ent.accessedAt
			}
			e.AccessCount = ent.hits
		}
		if _, ok := inflight[rec.Key]; ok {
			e.InFlight = true
		}
		out = append(out, e)
	}
	c.mu.Unlock()
	return out, nil
}

// InFlightKeys returns the set of keys with a single-flight fetch in progress.
// The GC consults it to avoid evicting an artifact that is mid-fetch.
func (c *FilesystemCache) InFlightKeys() map[string]struct{} { return c.sf.keys() }

// OpenRaw opens the content stream and Stat for key straight from the durable
// store, bypassing the in-memory index: it does not promote the entry in LRU
// order, does not apply TTL expiry, and does not touch hit/miss metrics. It is
// the read seam for the background integrity scan (Task 107), which must re-read
// every blob to re-verify its digest without distorting the live cache's
// recency or hit-ratio accounting. The caller must Close the returned reader.
func (c *FilesystemCache) OpenRaw(ctx context.Context, key string) (io.ReadCloser, Stat, error) {
	rc, rec, err := c.store.Get(ctx, key)
	if err != nil {
		return nil, Stat{}, err
	}
	return rc, rec.toStat(), nil
}

// warmIndex rebuilds the in-memory index from the store, ordering the LRU list
// by last-access time (most recent at the front).
func (c *FilesystemCache) warmIndex() error {
	records, err := c.store.List(context.Background())
	if err != nil {
		return err
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AccessedAt.Before(records[j].AccessedAt)
	})
	for _, rec := range records {
		ent := &idxEntry{
			key:         rec.Key,
			size:        rec.Size,
			createdAt:   rec.CreatedAt,
			accessedAt:  rec.AccessedAt,
			persistedAt: rec.AccessedAt,
		}
		// Pushing in ascending access order leaves the most-recent at the front.
		c.index[rec.Key] = c.ll.PushFront(ent)
		c.total += rec.Size
	}
	// Enforce the size bound immediately in case it shrank since last run.
	if evicted := c.evictForSize(); len(evicted) > 0 {
		ctx := context.Background()
		for _, k := range evicted {
			_ = c.store.Delete(ctx, k)
		}
		c.metrics.incEvictions(int64(len(evicted)))
	}
	return nil
}

// Get implements Cache.
func (c *FilesystemCache) Get(ctx context.Context, key string) (*Entry, error) {
	entry, err := c.getEntry(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.metrics.incMisses(1)
		} else {
			c.metrics.incErrors(1)
		}
		return nil, err
	}
	c.metrics.incHits(1)
	c.metrics.addBytesServed(entry.Stat.Size)
	return entry, nil
}

// Put implements Cache.
func (c *FilesystemCache) Put(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error) {
	stat, err := c.putContent(ctx, key, r, metadata)
	if err != nil {
		c.metrics.incErrors(1)
		return nil, err
	}
	c.metrics.incPuts(1)
	c.metrics.addBytesWritten(stat.Size)
	return stat, nil
}

// Stat implements Cache.
func (c *FilesystemCache) Stat(ctx context.Context, key string) (*Stat, error) {
	stat, err := c.statRecord(ctx, key)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			c.metrics.incErrors(1)
		}
		return nil, err
	}
	return stat, nil
}

// Delete implements Cache.
func (c *FilesystemCache) Delete(ctx context.Context, key string) error {
	if c.isPinned(key) && !pinOverride(ctx) {
		return pinnedError(key)
	}
	c.mu.Lock()
	elem, inIndex := c.index[key]
	if inIndex {
		c.dropLocked(elem)
	}
	c.mu.Unlock()

	err := c.store.Delete(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if inIndex {
				// Index and store disagreed; the index entry is now cleaned up.
				c.metrics.incDeletes(1)
				return nil
			}
			return ErrNotFound
		}
		c.metrics.incErrors(1)
		return err
	}
	c.metrics.incDeletes(1)
	return nil
}

// Close stops the janitor and closes the underlying store.
func (c *FilesystemCache) Close() error {
	if c.janitorStop != nil {
		close(c.janitorStop)
		<-c.janitorDone
		c.janitorStop = nil
	}
	return c.store.Close()
}

// GetOrLoad returns the cached entry for key, fetching it via loader on a miss.
// Concurrent calls for the same key are coalesced so loader runs at most once,
// preventing duplicate upstream fetches (the "thundering herd" problem). Each
// caller receives its own independent content stream.
func (c *FilesystemCache) GetOrLoad(ctx context.Context, key string, loader Loader) (*Entry, error) {
	if entry, err := c.getEntry(ctx, key); err == nil {
		c.metrics.incHits(1)
		c.metrics.addBytesServed(entry.Stat.Size)
		return entry, nil
	} else if !errors.Is(err, ErrNotFound) {
		c.metrics.incErrors(1)
		return nil, err
	}
	c.metrics.incMisses(1)

	_, err, shared := c.sf.Do(key, func() (*Stat, error) {
		// Another flight may have populated the key between our miss and our
		// acquiring leadership; re-check before fetching upstream.
		if stat, serr := c.statRecord(ctx, key); serr == nil {
			return stat, nil
		} else if !errors.Is(serr, ErrNotFound) {
			return nil, serr
		}

		r, metadata, lerr := loader(ctx)
		if lerr != nil {
			return nil, lerr
		}
		if rc, ok := r.(io.Closer); ok {
			defer rc.Close()
		}
		c.metrics.incLoads(1)
		stat, perr := c.putContent(ctx, key, r, metadata)
		if perr != nil {
			return nil, perr
		}
		c.metrics.incPuts(1)
		c.metrics.addBytesWritten(stat.Size)
		return stat, nil
	})
	if err != nil {
		c.metrics.incErrors(1)
		return nil, err
	}
	if shared {
		c.metrics.incCoalesced(1)
	}

	entry, err := c.getEntry(ctx, key)
	if err != nil {
		c.metrics.incErrors(1)
		return nil, err
	}
	c.metrics.addBytesServed(entry.Stat.Size)
	return entry, nil
}

// getEntry is the metrics-free core of Get. It updates LRU order and applies TTL
// expiry but does not touch counters.
func (c *FilesystemCache) getEntry(ctx context.Context, key string) (*Entry, error) {
	c.mu.Lock()
	elem, ok := c.index[key]
	if !ok {
		if !c.sharedStore {
			c.mu.Unlock()
			return nil, ErrNotFound
		}
		c.mu.Unlock()
		// Shared (HA) mode: another replica may have written this key after we
		// warmed our index. Consult the durable store and adopt it locally.
		rec, serr := c.store.Stat(ctx, key)
		if serr != nil {
			return nil, serr // ErrNotFound or a real error
		}
		c.mu.Lock()
		if elem, ok = c.index[key]; !ok {
			elem = c.adoptLocked(rec)
		}
	}
	ent := elem.Value.(*idxEntry)
	now := c.now()
	if c.isExpired(ent, now) {
		c.dropLocked(elem)
		c.mu.Unlock()
		_ = c.store.Delete(ctx, key)
		c.metrics.incExpired(1)
		return nil, ErrNotFound
	}
	ent.accessedAt = now
	ent.hits++
	c.ll.MoveToFront(elem)
	persist := now.Sub(ent.persistedAt) >= c.accessPersistInterval
	if persist {
		ent.persistedAt = now
	}
	c.mu.Unlock()

	rc, rec, err := c.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.forgetIndex(key) // index/store drift; reconcile
		}
		return nil, err
	}
	if persist {
		_ = c.store.SetAccessed(ctx, key, now) // best effort
	}
	stat := rec.toStat()
	return &Entry{Stat: stat, Content: rc}, nil
}

// statRecord is the metrics-free core of Stat. It applies TTL expiry but does
// not promote the entry in LRU order (a metadata peek is not a use).
func (c *FilesystemCache) statRecord(ctx context.Context, key string) (*Stat, error) {
	c.mu.Lock()
	elem, ok := c.index[key]
	if !ok {
		if !c.sharedStore {
			c.mu.Unlock()
			return nil, ErrNotFound
		}
		c.mu.Unlock()
		// Shared (HA) mode: fall back to the durable store before reporting a
		// miss so a concurrent write by another replica is visible.
		rec, serr := c.store.Stat(ctx, key)
		if serr != nil {
			return nil, serr
		}
		c.mu.Lock()
		if elem, ok = c.index[key]; !ok {
			elem = c.adoptLocked(rec)
		}
	}
	ent := elem.Value.(*idxEntry)
	if c.isExpired(ent, c.now()) {
		c.dropLocked(elem)
		c.mu.Unlock()
		_ = c.store.Delete(ctx, key)
		c.metrics.incExpired(1)
		return nil, ErrNotFound
	}
	c.mu.Unlock()

	rec, err := c.store.Stat(ctx, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			c.forgetIndex(key)
		}
		return nil, err
	}
	stat := rec.toStat()
	return &stat, nil
}

// putContent is the metrics-free core of Put. It writes through to the store,
// updates the index, and enforces the size bound, deleting evicted blobs.
func (c *FilesystemCache) putContent(ctx context.Context, key string, r io.Reader, metadata map[string]string) (*Stat, error) {
	if key == "" {
		return nil, errors.New("cache: Put requires a non-empty key")
	}
	now := c.now()
	rec := recordFromMetadata(key, metadata, now)

	// Preserve the original creation time when overwriting an existing entry.
	c.mu.Lock()
	if elem, ok := c.index[key]; ok {
		rec.CreatedAt = elem.Value.(*idxEntry).createdAt
	}
	c.mu.Unlock()

	stored, err := c.store.Put(ctx, rec, r)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.upsertLocked(stored, now)
	evicted := c.evictForSize()
	c.mu.Unlock()

	for _, k := range evicted {
		_ = c.store.Delete(ctx, k)
	}
	if len(evicted) > 0 {
		c.metrics.incEvictions(int64(len(evicted)))
	}

	stat := stored.toStat()
	return &stat, nil
}

// isExpired reports whether ent is older than the configured TTL. A pinned
// entry never expires.
func (c *FilesystemCache) isExpired(ent *idxEntry, now time.Time) bool {
	if c.ttl <= 0 {
		return false
	}
	return now.Sub(ent.createdAt) > c.ttl && !c.isPinned(ent.key)
}

// upsertLocked inserts or refreshes the index entry for a stored record and
// keeps the running total in sync. Callers must hold c.mu.
func (c *FilesystemCache) upsertLocked(rec Record, now time.Time) {
	if elem, ok := c.index[rec.Key]; ok {
		ent := elem.Value.(*idxEntry)
		c.total += rec.Size - ent.size
		ent.size = rec.Size
		ent.createdAt = rec.CreatedAt
		ent.accessedAt = now
		ent.persistedAt = now
		c.ll.MoveToFront(elem)
		return
	}
	ent := &idxEntry{
		key:         rec.Key,
		size:        rec.Size,
		createdAt:   rec.CreatedAt,
		accessedAt:  now,
		persistedAt: now,
	}
	c.index[rec.Key] = c.ll.PushFront(ent)
	c.total += rec.Size
}

// adoptLocked inserts an index entry for a record discovered in the shared store
// (HA mode), preserving its persisted timestamps so TTL expiry and LRU ordering
// remain correct. It returns the new list element. Callers must hold c.mu.
func (c *FilesystemCache) adoptLocked(rec Record) *list.Element {
	ent := &idxEntry{
		key:         rec.Key,
		size:        rec.Size,
		createdAt:   rec.CreatedAt,
		accessedAt:  rec.AccessedAt,
		persistedAt: rec.AccessedAt,
	}
	elem := c.ll.PushFront(ent)
	c.index[rec.Key] = elem
	c.total += rec.Size
	return elem
}

// evictForSize removes least-recently-used entries until the total is within the
// size bound, returning the evicted keys for the caller to delete from the store
// (outside the lock). An entry larger than the whole budget is retained rather
// than evicting it pointlessly. Callers must hold c.mu.
func (c *FilesystemCache) evictForSize() []string {
	if c.maxSize <= 0 {
		return nil
	}
	var evicted []string
	// Walk from the least-recently-used end towards the front. The front entry
	// — the one just written or read — is never evicted, as before pins existed
	// (an entry larger than the whole budget is kept rather than evicted
	// pointlessly). A pinned entry is never a victim (Task 180): it is moved to
	// just behind the front, out of the way, so that later walks do not pass
	// over it again; where a pinned entry sits in the recency order does not
	// matter, as it is evicted from nowhere. The budget bounds the walk to one
	// pass over the list however entries move; and as the walk runs under the
	// cache's lock on every write, it passes over at most maxPinnedSkips
	// pinned entries — with more pinned bytes than the bound, the next write
	// goes on where this one stopped, instead of every write walking them all.
	front := c.ll.Front()
	elem := c.ll.Back()
	skipped := 0
	for budget := c.ll.Len(); elem != nil && elem != front && c.total > c.maxSize && budget > 0; budget-- {
		prev := elem.Prev()
		ent := elem.Value.(*idxEntry)
		if c.isPinned(ent.key) {
			if skipped++; skipped > maxPinnedSkips {
				break
			}
			c.ll.MoveAfter(elem, front)
		} else {
			c.dropLocked(elem)
			evicted = append(evicted, ent.key)
		}
		elem = prev
	}
	return evicted
}

// maxPinnedSkips bounds the pinned entries one eviction walk passes over.
var maxPinnedSkips = 4096

// pinHolder boxes a PinChecker so atomic.Value always stores one concrete type.
type pinHolder struct{ p PinChecker }

// SetPinChecker installs the release pin set (Task 180). It may be called at
// any time; the size bound is re-enforced on the next write.
func (c *FilesystemCache) SetPinChecker(p PinChecker) {
	c.pins.Store(pinHolder{p: p})
}

// isPinned reports whether a release pinned key.
func (c *FilesystemCache) isPinned(key string) bool {
	h, _ := c.pins.Load().(pinHolder)
	return h.p != nil && h.p.IsPinned(key)
}

// dropLocked removes an element from both the list and the index and updates the
// running total. Callers must hold c.mu.
func (c *FilesystemCache) dropLocked(elem *list.Element) {
	ent := elem.Value.(*idxEntry)
	c.ll.Remove(elem)
	delete(c.index, ent.key)
	c.total -= ent.size
}

// forgetIndex removes a key from the index if present, reconciling a divergence
// where the store reports a key the index still believes exists.
func (c *FilesystemCache) forgetIndex(key string) {
	c.mu.Lock()
	if elem, ok := c.index[key]; ok {
		c.dropLocked(elem)
	}
	c.mu.Unlock()
}

// janitor periodically removes expired entries until stopped.
func (c *FilesystemCache) janitor(interval time.Duration) {
	defer close(c.janitorDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.janitorStop:
			return
		case <-ticker.C:
			c.sweepExpired()
		}
	}
}

// sweepExpired collects and removes all currently expired entries.
func (c *FilesystemCache) sweepExpired() {
	now := c.now()
	c.mu.Lock()
	var expired []string
	for elem := c.ll.Back(); elem != nil; {
		prev := elem.Prev()
		ent := elem.Value.(*idxEntry)
		if c.isExpired(ent, now) {
			c.dropLocked(elem)
			expired = append(expired, ent.key)
		}
		elem = prev
	}
	c.mu.Unlock()

	if len(expired) == 0 {
		return
	}
	ctx := context.Background()
	for _, k := range expired {
		_ = c.store.Delete(ctx, k)
	}
	c.metrics.incExpired(int64(len(expired)))
}
