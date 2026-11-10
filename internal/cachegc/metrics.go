package cachegc

import "sync/atomic"

// Metrics records cumulative cache garbage-collection activity using lock-free
// counters so it can be sampled concurrently with GC runs. A zero Metrics is
// ready to use.
type Metrics struct {
	runs           atomic.Int64
	dryRuns        atomic.Int64
	evicted        atomic.Int64
	expiredEvicted atomic.Int64
	bytesReclaimed atomic.Int64
	deleteErrors   atomic.Int64
	highWatermark  atomic.Int64 // times a finished run was still above the high watermark
}

func (m *Metrics) incRuns()                  { m.runs.Add(1) }
func (m *Metrics) incDryRuns()               { m.dryRuns.Add(1) }
func (m *Metrics) addEvicted(n int64)        { m.evicted.Add(n) }
func (m *Metrics) addExpiredEvicted(n int64) { m.expiredEvicted.Add(n) }
func (m *Metrics) addBytesReclaimed(n int64) { m.bytesReclaimed.Add(n) }
func (m *Metrics) addDeleteErrors(n int64)   { m.deleteErrors.Add(n) }
func (m *Metrics) incHighWatermark()         { m.highWatermark.Add(1) }

// Snapshot is an immutable point-in-time view of the GC subsystem: the
// cumulative counters plus the state of the most recent run, suitable for the
// admin API and the Prometheus bridge.
type Snapshot struct {
	// Enabled reports whether the GC subsystem is active.
	Enabled bool `json:"enabled"`
	// Policy is the configured eviction policy (lru|lfu|fifo).
	Policy string `json:"policy"`
	// IntervalSeconds is the periodic sweep interval (0 = on-demand only).
	IntervalSeconds float64 `json:"intervalSeconds"`
	// DryRun reports whether the periodic sweep runs in report-only mode.
	DryRun bool `json:"dryRun"`

	// Cumulative counters.
	Runs                int64 `json:"runs"`
	DryRuns             int64 `json:"dryRuns"`
	EvictedTotal        int64 `json:"evictedTotal"`
	ExpiredEvictedTotal int64 `json:"expiredEvictedTotal"`
	BytesReclaimedTotal int64 `json:"bytesReclaimedTotal"`
	DeleteErrorsTotal   int64 `json:"deleteErrorsTotal"`
	AboveHighWatermark  int64 `json:"aboveHighWatermarkTotal"`

	// Most-recent run state (zero before the first run).
	CapacityBytes      int64   `json:"capacityBytes"`
	HighWatermarkBytes int64   `json:"highWatermarkBytes"`
	LowWatermarkBytes  int64   `json:"lowWatermarkBytes"`
	UsedBytes          int64   `json:"usedBytes"`
	Entries            int     `json:"entries"`
	UtilizationPct     float64 `json:"utilizationPct"`
	LastEvicted        int     `json:"lastEvicted"`
	LastBytesReclaimed int64   `json:"lastBytesReclaimed"`
	LastDurationMillis int64   `json:"lastDurationMillis"`
	LastWasAboveHigh   bool    `json:"lastWasAboveHigh"`
	ConsecutiveAbove   int     `json:"consecutiveAboveHigh"`
}

// Snapshot returns the cumulative counters (the run-state fields are filled in by
// the Engine, which owns the last-report state under its own lock).
func (m *Metrics) snapshot() Snapshot {
	return Snapshot{
		Runs:                m.runs.Load(),
		DryRuns:             m.dryRuns.Load(),
		EvictedTotal:        m.evicted.Load(),
		ExpiredEvictedTotal: m.expiredEvicted.Load(),
		BytesReclaimedTotal: m.bytesReclaimed.Load(),
		DeleteErrorsTotal:   m.deleteErrors.Load(),
		AboveHighWatermark:  m.highWatermark.Load(),
	}
}
