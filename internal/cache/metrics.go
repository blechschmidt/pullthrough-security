package cache

import "sync/atomic"

// Metrics records cache activity using lock-free counters so it can be sampled
// concurrently with cache operations. A zero Metrics is ready to use; callers
// typically obtain one via the cache and read it with Snapshot.
type Metrics struct {
	hits      atomic.Int64
	misses    atomic.Int64
	loads     atomic.Int64
	coalesced atomic.Int64
	puts      atomic.Int64
	deletes   atomic.Int64
	evictions atomic.Int64
	expired   atomic.Int64
	errors    atomic.Int64

	bytesWritten atomic.Int64
	bytesServed  atomic.Int64
}

// MetricsSnapshot is an immutable point-in-time view of a Metrics.
type MetricsSnapshot struct {
	// Hits is the number of reads served from the cache.
	Hits int64
	// Misses is the number of reads for an absent (or expired) key.
	Misses int64
	// Loads is the number of upstream fetches performed via GetOrLoad.
	Loads int64
	// Coalesced is the number of concurrent GetOrLoad calls that were merged
	// into another in-flight load instead of fetching upstream themselves.
	Coalesced int64
	// Puts is the number of successful writes.
	Puts int64
	// Deletes is the number of successful deletions.
	Deletes int64
	// Evictions is the number of entries removed by the max-size LRU policy.
	Evictions int64
	// Expired is the number of entries removed by the TTL policy.
	Expired int64
	// Errors is the number of operations that failed for reasons other than a
	// cache miss.
	Errors int64
	// BytesWritten is the total content bytes written to the store.
	BytesWritten int64
	// BytesServed is the total content bytes returned to readers.
	BytesServed int64
}

// HitRatio returns hits / (hits + misses), or 0 when there have been no reads.
func (s MetricsSnapshot) HitRatio() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total)
}

// Snapshot returns a consistent-enough copy of the counters for reporting.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Hits:         m.hits.Load(),
		Misses:       m.misses.Load(),
		Loads:        m.loads.Load(),
		Coalesced:    m.coalesced.Load(),
		Puts:         m.puts.Load(),
		Deletes:      m.deletes.Load(),
		Evictions:    m.evictions.Load(),
		Expired:      m.expired.Load(),
		Errors:       m.errors.Load(),
		BytesWritten: m.bytesWritten.Load(),
		BytesServed:  m.bytesServed.Load(),
	}
}

func (m *Metrics) incHits(n int64)         { m.hits.Add(n) }
func (m *Metrics) incMisses(n int64)       { m.misses.Add(n) }
func (m *Metrics) incLoads(n int64)        { m.loads.Add(n) }
func (m *Metrics) incCoalesced(n int64)    { m.coalesced.Add(n) }
func (m *Metrics) incPuts(n int64)         { m.puts.Add(n) }
func (m *Metrics) incDeletes(n int64)      { m.deletes.Add(n) }
func (m *Metrics) incEvictions(n int64)    { m.evictions.Add(n) }
func (m *Metrics) incExpired(n int64)      { m.expired.Add(n) }
func (m *Metrics) incErrors(n int64)       { m.errors.Add(n) }
func (m *Metrics) addBytesWritten(n int64) { m.bytesWritten.Add(n) }
func (m *Metrics) addBytesServed(n int64)  { m.bytesServed.Add(n) }
