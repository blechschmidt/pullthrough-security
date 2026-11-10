package cachegc

import "time"

// EvictionReason classifies why an entry was selected for eviction.
type EvictionReason string

const (
	// ReasonTTL marks an entry removed because it exceeded its (per-tenant or
	// default) time-to-live. TTL eviction runs regardless of cache utilization.
	ReasonTTL EvictionReason = "ttl-expired"
	// ReasonWatermark marks an entry removed by the size watermark policy because
	// the cache was above its high watermark; the eviction order is the configured
	// LRU/LFU/FIFO policy.
	ReasonWatermark EvictionReason = "high-watermark"
)

// EvictionRecord describes a single entry the GC evicted (or, in dry-run, would
// evict).
type EvictionRecord struct {
	Key         string         `json:"key"`
	Size        int64          `json:"size"`
	Tenant      string         `json:"tenant,omitempty"`
	Reason      EvictionReason `json:"reason"`
	AgeSeconds  float64        `json:"ageSeconds"`
	IdleSeconds float64        `json:"idleSeconds"`
	AccessCount int64          `json:"accessCount"`
	// Error is non-empty when the actual delete failed (always empty in dry-run).
	Error string `json:"error,omitempty"`
}

// RetentionRecord describes an entry the GC deliberately protected from eviction
// even though it was an eviction candidate (expired, or there was size pressure).
// It makes the pin/reference-count safety auditable.
type RetentionRecord struct {
	Key    string `json:"key"`
	Size   int64  `json:"size"`
	Tenant string `json:"tenant,omitempty"`
	// Reason explains the protection ("pinned", "referenced: <source>",
	// "in-flight fetch", "recently accessed (min-idle guard)").
	Reason string `json:"reason"`
	// Expired reports whether the protected entry was also past its TTL (so an
	// operator can see retention is overriding expiry).
	Expired bool `json:"expired"`
}

// Report is the outcome of a single GC pass: what the cache looked like, what was
// (or would be) evicted, and what was deliberately retained. In dry-run mode the
// Evicted list is exactly what a real run would delete, so the report is an
// accurate preview.
type Report struct {
	StartedAt time.Time     `json:"startedAt"`
	Duration  time.Duration `json:"durationNanos"`
	DryRun    bool          `json:"dryRun"`
	Policy    string        `json:"policy"`

	// Cache state observed at the start of the pass.
	Entries   int   `json:"entries"`
	UsedBytes int64 `json:"usedBytes"`

	// Watermark math (zero when no capacity is configured, i.e. TTL-only mode).
	CapacityBytes      int64   `json:"capacityBytes"`
	HighWatermarkBytes int64   `json:"highWatermarkBytes"`
	LowWatermarkBytes  int64   `json:"lowWatermarkBytes"`
	UtilizationPct     float64 `json:"utilizationPct"`
	// AboveHighWatermark reports whether utilization remained at or above the high
	// watermark after the pass completed (the condition that drives an alert).
	AboveHighWatermark bool `json:"aboveHighWatermark"`

	// Outcome.
	EvictedCount   int   `json:"evictedCount"`
	BytesReclaimed int64 `json:"bytesReclaimed"`
	RetainedCount  int   `json:"retainedCount"`
	Errors         int   `json:"errors"`

	// Detail lists (capped for transport; the *Count fields are exact).
	Evicted  []EvictionRecord  `json:"evicted"`
	Retained []RetentionRecord `json:"retained"`
}

// maxReportItems bounds the per-list detail a Report carries so a sweep over a
// very large cache does not produce an unbounded payload. The *Count summary
// fields remain exact.
const maxReportItems = 1000
