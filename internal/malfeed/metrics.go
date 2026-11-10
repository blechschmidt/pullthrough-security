package malfeed

// Snapshot is an immutable copy of the gate's cumulative counters and current
// freshness, read by the Prometheus bridge at scrape time. All counters are
// monotonic except the gauges (EntriesLoaded, RefreshAgeSeconds, Stale).
type Snapshot struct {
	// EntriesLoaded is the number of known-malicious records currently loaded.
	EntriesLoaded int
	// EntriesByEcosystem partitions EntriesLoaded by canonical ecosystem.
	EntriesByEcosystem map[string]int
	// Checks is the total number of coordinates evaluated by the gate.
	Checks uint64
	// Blocks is the total number of pulls blocked (concrete match or fail-closed).
	Blocks uint64
	// BlocksByEcosystem partitions concrete-match blocks by canonical ecosystem.
	BlocksByEcosystem map[string]uint64
	// StaleBlocks is the number of pulls blocked solely due to a stale feed
	// (fail-closed); StaleServes is unmatched pulls served while stale (fail-open).
	StaleBlocks uint64
	StaleServes uint64
	// Refreshes / RefreshFailures count background+on-demand refresh attempts.
	Refreshes       uint64
	RefreshFailures uint64
	// RefreshAgeSeconds is the time since the last successful refresh; -1 when the
	// feed has never loaded.
	RefreshAgeSeconds float64
	// Stale reports the current staleness.
	Stale bool
}

// Metrics returns the current counter/gauge snapshot. Safe on a nil Service
// (returns the zero snapshot with initialized maps).
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{EntriesByEcosystem: map[string]int{}, BlocksByEcosystem: map[string]uint64{}}
	}
	st := s.Status()

	s.blocksByEco.mu.Lock()
	blocksByEco := make(map[string]uint64, len(s.blocksByEco.m))
	for k, v := range s.blocksByEco.m {
		blocksByEco[k] = v
	}
	s.blocksByEco.mu.Unlock()

	age := -1.0
	if st.LastRefresh != nil {
		age = st.RefreshAgeSeconds
	}

	return Snapshot{
		EntriesLoaded:      st.Entries,
		EntriesByEcosystem: st.EntriesByEcosystem,
		Checks:             s.checks.Load(),
		Blocks:             s.blocks.Load(),
		BlocksByEcosystem:  blocksByEco,
		StaleBlocks:        s.staleBlocks.Load(),
		StaleServes:        s.staleServes.Load(),
		Refreshes:          s.refreshes.Load(),
		RefreshFailures:    s.refreshFails.Load(),
		RefreshAgeSeconds:  age,
		Stale:              st.Stale,
	}
}

// Enabled reports whether the gate is active (a non-nil Service). It satisfies
// the admin inspector contract.
func (s *Service) Enabled() bool { return s != nil }
