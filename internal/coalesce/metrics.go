package coalesce

import "time"

// Snapshot is an immutable view of the coalescer's cumulative counters and live
// gauges, taken at scrape/inspection time. It is read by the Prometheus bridge
// and the admin API.
type Snapshot struct {
	// Enabled reports whether the layer is active.
	Enabled bool `json:"enabled"`

	// Lookups is the total number of Do calls handled while enabled.
	Lookups int64 `json:"lookups"`
	// Coalesced is the number of calls that joined an in-flight leader instead of
	// issuing their own upstream fetch (the core dedup win).
	Coalesced int64 `json:"coalesced"`
	// Leads is the number of calls that ran the load themselves (leaders).
	Leads int64 `json:"leads"`
	// NegativeHits is the number of calls served from the negative cache without
	// contacting the upstream.
	NegativeHits int64 `json:"negativeHits"`
	// NegativeStored is the number of distinct negative entries written.
	NegativeStored int64 `json:"negativeStored"`
	// NegativeEvictions is the number of negative entries dropped by the LRU bound.
	NegativeEvictions int64 `json:"negativeEvictions"`
	// NegativeExpired is the number of negative entries observed expired on lookup.
	NegativeExpired int64 `json:"negativeExpired"`
	// Overloaded is the number of calls rejected because MaxInflight was reached.
	Overloaded int64 `json:"overloaded"`

	// InFlight is the current number of distinct leader fetches running.
	InFlight int `json:"inFlight"`
	// NegativeEntries is the current size of the negative cache.
	NegativeEntries int `json:"negativeEntries"`

	// ByKind breaks negative-cache activity down by failure class.
	ByKind map[string]KindStat `json:"byKind,omitempty"`

	// Configuration echoed for the admin surface.
	NegativeTTL        time.Duration `json:"negativeTtl"`
	MaxNegativeEntries int           `json:"maxNegativeEntries"`
	MaxInflight        int           `json:"maxInflight"`
	Backoff5xxBase     time.Duration `json:"backoff5xxBase"`
	Backoff5xxMax      time.Duration `json:"backoff5xxMax"`
}

// KindStat is the per-failure-class negative-cache breakdown.
type KindStat struct {
	Stored  int64 `json:"stored"`
	Hits    int64 `json:"hits"`
	Evicted int64 `json:"evicted"`
}

// DedupRatio is the fraction of upstream-bound pull-path decisions that were
// satisfied by joining an in-flight fetch rather than issuing a new one:
// coalesced / (coalesced + leads). It is 0 when no decisions have been made.
func (s Snapshot) DedupRatio() float64 {
	denom := s.Coalesced + s.Leads
	if denom == 0 {
		return 0
	}
	return float64(s.Coalesced) / float64(denom)
}

// Metrics returns a Snapshot of the coalescer's counters and gauges. It is safe
// to call concurrently. A nil coalescer reports a disabled snapshot.
func (c *Coalescer[T]) Metrics() Snapshot {
	if c == nil {
		return Snapshot{Enabled: false}
	}
	s := Snapshot{
		Enabled:            c.cfg.Enabled,
		Lookups:            c.m.lookups.Load(),
		Coalesced:          c.m.coalesced.Load(),
		Leads:              c.m.leads.Load(),
		NegativeHits:       c.m.negHits.Load(),
		NegativeStored:     c.m.negStored.Load(),
		NegativeEvictions:  c.m.negEvictions.Load(),
		NegativeExpired:    c.m.negExpired.Load(),
		Overloaded:         c.m.overloaded.Load(),
		NegativeTTL:        c.cfg.NegativeTTL,
		MaxNegativeEntries: c.cfg.MaxNegativeEntries,
		MaxInflight:        c.cfg.MaxInflight,
		Backoff5xxBase:     c.cfg.Backoff5xxBase,
		Backoff5xxMax:      c.cfg.Backoff5xxMax,
	}
	c.mu.Lock()
	s.InFlight = c.inflight
	s.NegativeEntries = c.negLRU.Len()
	if len(c.byKind) > 0 {
		s.ByKind = make(map[string]KindStat, len(c.byKind))
		for k, kc := range c.byKind {
			s.ByKind[k] = KindStat{Stored: kc.stored, Hits: kc.hits, Evicted: kc.evicted}
		}
	}
	c.mu.Unlock()
	return s
}
