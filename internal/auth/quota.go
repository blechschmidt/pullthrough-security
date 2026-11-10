package auth

import (
	"sync"
	"time"
)

// Quota bounds a team's consumption within a rolling window. A zero limit means
// "unlimited" for that dimension; a zero Window means counters accumulate
// without ever resetting (a hard cumulative cap).
type Quota struct {
	// MaxRequests caps pull requests admitted per window (0 = unlimited).
	MaxRequests int64
	// MaxBytes caps bytes served per window (0 = unlimited).
	MaxBytes int64
	// Window is the period after which counters reset (0 = never reset).
	Window time.Duration
}

// unlimited reports whether the quota imposes no limits at all.
func (q Quota) unlimited() bool {
	return q.MaxRequests == 0 && q.MaxBytes == 0
}

// Usage is a point-in-time snapshot of a team's consumption.
type Usage struct {
	Team        string
	Requests    int64
	Bytes       int64
	MaxRequests int64
	MaxBytes    int64
	WindowStart time.Time
	WindowEnds  time.Time // zero when the window never resets
}

// counter is the mutable per-team accounting state.
type counter struct {
	requests    int64
	bytes       int64
	windowStart time.Time
}

// QuotaManager tracks per-team consumption and admits or rejects requests
// against configured quotas. It is safe for concurrent use. A nil
// *QuotaManager is a valid no-op that admits everything, so quota enforcement
// can be disabled without nil checks at call sites.
type QuotaManager struct {
	mu       sync.Mutex
	limits   map[string]Quota
	def      Quota
	counters map[string]*counter
	now      func() time.Time
}

// QuotaOptions configures a QuotaManager.
type QuotaOptions struct {
	// PerTeam maps team name to its quota. Teams absent from the map use
	// Default.
	PerTeam map[string]Quota
	// Default applies to any team without an explicit quota. The zero value is
	// "unlimited".
	Default Quota
	// Now overrides the clock (for tests).
	Now func() time.Time
}

// NewQuotaManager constructs a QuotaManager.
func NewQuotaManager(opts QuotaOptions) *QuotaManager {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	limits := make(map[string]Quota, len(opts.PerTeam))
	for k, v := range opts.PerTeam {
		limits[k] = v
	}
	return &QuotaManager{
		limits:   limits,
		def:      opts.Default,
		counters: make(map[string]*counter),
		now:      now,
	}
}

// quotaFor returns the effective quota for a team.
func (m *QuotaManager) quotaFor(team string) Quota {
	if q, ok := m.limits[team]; ok {
		return q
	}
	return m.def
}

// rollWindow resets the counter when its window has elapsed. Caller holds mu.
func (m *QuotaManager) rollWindow(c *counter, q Quota, now time.Time) {
	if q.Window <= 0 {
		return
	}
	if c.windowStart.IsZero() {
		c.windowStart = now
		return
	}
	if now.Sub(c.windowStart) >= q.Window {
		c.requests = 0
		c.bytes = 0
		c.windowStart = now
	}
}

// getCounter returns the (window-rolled) counter for a team, creating it on
// first use. Caller holds mu.
func (m *QuotaManager) getCounter(team string, q Quota, now time.Time) *counter {
	c, ok := m.counters[team]
	if !ok {
		c = &counter{windowStart: now}
		m.counters[team] = c
	}
	m.rollWindow(c, q, now)
	return c
}

// Reserve admits one request for the team, incrementing the request counter. It
// returns false with a human-readable reason when admitting the request would
// exceed the request count limit, or when the byte limit is already exhausted.
// A nil manager admits everything.
func (m *QuotaManager) Reserve(team string) (allowed bool, reason string) {
	if m == nil {
		return true, ""
	}
	q := m.quotaFor(team)
	if q.unlimited() {
		return true, ""
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	c := m.getCounter(team, q, now)

	if q.MaxBytes > 0 && c.bytes >= q.MaxBytes {
		return false, "byte quota exhausted"
	}
	if q.MaxRequests > 0 && c.requests >= q.MaxRequests {
		return false, "request quota exhausted"
	}
	c.requests++
	return true, ""
}

// RecordBytes adds served bytes to the team's counter (called after a response
// is streamed). A nil manager is a no-op.
func (m *QuotaManager) RecordBytes(team string, n int64) {
	if m == nil || n <= 0 {
		return
	}
	q := m.quotaFor(team)
	if q.MaxBytes == 0 {
		return // bytes are not limited; no need to account
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.getCounter(team, q, m.now())
	c.bytes += n
}

// Snapshot returns the current usage for a team.
func (m *QuotaManager) Snapshot(team string) Usage {
	q := m.quotaFor(team)
	u := Usage{Team: team, MaxRequests: q.MaxRequests, MaxBytes: q.MaxBytes}
	if m == nil {
		return u
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	c := m.getCounter(team, q, now)
	u.Requests = c.requests
	u.Bytes = c.bytes
	u.WindowStart = c.windowStart
	if q.Window > 0 && !c.windowStart.IsZero() {
		u.WindowEnds = c.windowStart.Add(q.Window)
	}
	return u
}
