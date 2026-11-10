package cachegc

import (
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// EvictionPolicy selects the order in which non-protected, non-expired entries
// are evicted when the cache is above its high watermark.
type EvictionPolicy string

const (
	// PolicyLRU evicts the least-recently-accessed entry first.
	PolicyLRU EvictionPolicy = "lru"
	// PolicyLFU evicts the least-frequently-accessed entry first, breaking ties by
	// least-recently-accessed.
	PolicyLFU EvictionPolicy = "lfu"
	// PolicyFIFO evicts the oldest entry (by creation time) first.
	PolicyFIFO EvictionPolicy = "fifo"
)

// normalizePolicy coerces an arbitrary string to a known policy, defaulting to
// LRU for an empty or unrecognized value.
func normalizePolicy(s string) EvictionPolicy {
	switch EvictionPolicy(strings.ToLower(strings.TrimSpace(s))) {
	case PolicyLFU:
		return PolicyLFU
	case PolicyFIFO:
		return PolicyFIFO
	default:
		return PolicyLRU
	}
}

// ValidPolicy reports whether s names a recognized eviction policy (empty is
// valid and means LRU).
func ValidPolicy(s string) bool {
	switch EvictionPolicy(strings.ToLower(strings.TrimSpace(s))) {
	case "", PolicyLRU, PolicyLFU, PolicyFIFO:
		return true
	default:
		return false
	}
}

// candidate is the planner's per-entry working state.
type candidate struct {
	entry     cache.GCEntry
	tenant    string
	expired   bool
	protected bool
	reason    string // protection reason when protected
}

// plan computes the eviction decisions for a set of entries at time now. It is a
// pure function of the engine's configuration and reference sources (no IO), so
// it is the unit the tests exercise for ordering, pin/retention, reference
// safety, and dry-run accuracy. It returns the report scaffolding (cache state,
// watermark math, evicted/retained lists) without performing any deletion.
func (e *Engine) plan(entries []cache.GCEntry, now time.Time) Report {
	policy := normalizePolicy(string(e.cfg.Policy))
	rep := Report{
		StartedAt: now,
		DryRun:    e.cfg.DryRun,
		Policy:    string(policy),
		Entries:   len(entries),
	}

	cands := make([]candidate, 0, len(entries))
	var used int64
	for _, en := range entries {
		used += en.Size
		c := candidate{entry: en, tenant: e.tenantOf(en)}
		c.protected, c.reason = e.protection(en, now)
		if ttl := e.ttlFor(c.tenant); ttl > 0 && now.Sub(en.CreatedAt) >= ttl {
			c.expired = true
		}
		cands = append(cands, c)
	}
	rep.UsedBytes = used

	// Watermark math. A zero capacity disables size-driven eviction (TTL-only).
	capacity := e.cfg.CapacityBytes
	rep.CapacityBytes = capacity
	if capacity > 0 {
		rep.HighWatermarkBytes = int64(float64(capacity) * e.highPct)
		rep.LowWatermarkBytes = int64(float64(capacity) * e.lowPct)
		rep.UtilizationPct = float64(used) / float64(capacity) * 100
	}

	remaining := used
	deleteBudget := e.cfg.MaxDeletesPerRun // 0 == unlimited
	budgetLeft := func() bool { return deleteBudget == 0 || rep.EvictedCount < deleteBudget }

	// Track whether there is (or was) eviction pressure, so retained candidates
	// are only reported when retention actually overrode an eviction.
	aboveHigh := capacity > 0 && used > rep.HighWatermarkBytes
	anyExpired := false
	for _, c := range cands {
		if c.expired {
			anyExpired = true
			break
		}
	}
	pressure := aboveHigh || anyExpired

	evict := func(c candidate, reason EvictionReason) {
		rep.Evicted = append(rep.Evicted, toEvictionRecord(c, reason, now))
		rep.EvictedCount++
		rep.BytesReclaimed += c.entry.Size
		remaining -= c.entry.Size
	}

	// Phase 1 — TTL expiry. Expired, non-protected entries are always removed,
	// independent of utilization. Protected expired entries are retained (pins and
	// references win over TTL) and recorded as such.
	for _, c := range cands {
		if !c.expired {
			continue
		}
		if c.protected {
			rep.Retained = append(rep.Retained, toRetentionRecord(c))
			continue
		}
		if !budgetLeft() {
			break
		}
		evict(c, ReasonTTL)
	}

	// Phase 2 — high-watermark eviction. Only when capacity is configured and the
	// (post-TTL) size is still above the high watermark: evict non-protected,
	// non-expired entries in policy order until at or below the low watermark, the
	// candidates are exhausted, or the per-run delete budget is spent.
	if capacity > 0 && remaining > rep.HighWatermarkBytes {
		survivors := make([]candidate, 0, len(cands))
		for _, c := range cands {
			if c.expired {
				continue // already handled (evicted or retained) in phase 1
			}
			if c.protected {
				continue // collected below into Retained under pressure
			}
			survivors = append(survivors, c)
		}
		orderCandidates(survivors, policy)
		for _, c := range survivors {
			if remaining <= rep.LowWatermarkBytes || !budgetLeft() {
				break
			}
			evict(c, ReasonWatermark)
		}
	}

	// Record protected entries that survived under pressure (pin/reference-count
	// safety made auditable). Expired-but-protected entries were already recorded
	// in phase 1; avoid double-counting them here.
	if pressure {
		for _, c := range cands {
			if c.protected && !c.expired {
				rep.Retained = append(rep.Retained, toRetentionRecord(c))
			}
		}
	}
	rep.RetainedCount = len(rep.Retained)

	// Finalize watermark/utilization state as it stands after planned eviction.
	// The Engine recomputes this after executing real deletions (some may fail);
	// for a dry-run this preview value stands.
	if capacity > 0 {
		rep.AboveHighWatermark = remaining >= rep.HighWatermarkBytes
	}
	return rep
}

// protection evaluates whether an entry must be retained and why. The ordering
// is deliberate: an in-flight fetch is the hardest constraint (never evict
// mid-stream), then the active-stream safety window, then out-of-band references,
// then static pins.
func (e *Engine) protection(en cache.GCEntry, now time.Time) (bool, string) {
	if en.InFlight {
		return true, "in-flight fetch"
	}
	if e.cfg.MinIdle > 0 && now.Sub(en.AccessedAt) < e.cfg.MinIdle {
		return true, "recently accessed (min-idle guard)"
	}
	for _, src := range e.sources {
		if ok, why := src.Referenced(en); ok {
			if e.cfg.AllowEvictPinned && src.Name() == "pin" {
				// Operator explicitly permits evicting metadata-pinned entries.
				continue
			}
			return true, why
		}
	}
	return false, ""
}

// tenantOf derives the owning tenant for an entry: the explicit tenant metadata
// when present, else the leading path segment of a namespaced cache key.
func (e *Engine) tenantOf(en cache.GCEntry) string {
	if t := strings.TrimSpace(en.Metadata[cache.MetaTenant]); t != "" {
		return t
	}
	if i := strings.IndexByte(en.Key, '/'); i > 0 {
		return en.Key[:i]
	}
	return ""
}

// ttlFor returns the effective TTL for a tenant: the per-tenant override when set
// (including an explicit zero, which disables TTL for that tenant), else the
// default TTL.
func (e *Engine) ttlFor(tenant string) time.Duration {
	if tenant != "" && e.cfg.TenantTTLs != nil {
		if ttl, ok := e.cfg.TenantTTLs[tenant]; ok {
			return ttl
		}
	}
	return e.cfg.DefaultTTL
}

// orderCandidates sorts the eviction candidates so the first element is the one
// to evict first under the given policy. The sort is stable on key as a final
// tiebreaker for deterministic plans.
func orderCandidates(cs []candidate, policy EvictionPolicy) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i].entry, cs[j].entry
		switch policy {
		case PolicyFIFO:
			if !a.CreatedAt.Equal(b.CreatedAt) {
				return a.CreatedAt.Before(b.CreatedAt)
			}
		case PolicyLFU:
			if a.AccessCount != b.AccessCount {
				return a.AccessCount < b.AccessCount
			}
			if !a.AccessedAt.Equal(b.AccessedAt) {
				return a.AccessedAt.Before(b.AccessedAt)
			}
		default: // PolicyLRU
			if !a.AccessedAt.Equal(b.AccessedAt) {
				return a.AccessedAt.Before(b.AccessedAt)
			}
		}
		return a.Key < b.Key
	})
}

func toEvictionRecord(c candidate, reason EvictionReason, now time.Time) EvictionRecord {
	return EvictionRecord{
		Key:         c.entry.Key,
		Size:        c.entry.Size,
		Tenant:      c.tenant,
		Reason:      reason,
		AgeSeconds:  now.Sub(c.entry.CreatedAt).Seconds(),
		IdleSeconds: now.Sub(c.entry.AccessedAt).Seconds(),
		AccessCount: c.entry.AccessCount,
	}
}

func toRetentionRecord(c candidate) RetentionRecord {
	return RetentionRecord{
		Key:     c.entry.Key,
		Size:    c.entry.Size,
		Tenant:  c.tenant,
		Reason:  c.reason,
		Expired: c.expired,
	}
}
