package rebuildverify

// VerdictCounts tallies verifications by terminal verdict for one ecosystem.
type VerdictCounts struct {
	Reproducible uint64 `json:"reproducible"`
	Mismatch     uint64 `json:"mismatch"`
	Unsupported  uint64 `json:"unsupported"`
	Unattested   uint64 `json:"unattested"`
}

func (c *VerdictCounts) add(v Verdict) {
	switch v {
	case VerdictReproducible:
		c.Reproducible++
	case VerdictMismatch:
		c.Mismatch++
	case VerdictUnsupported:
		c.Unsupported++
	case VerdictUnattested:
		c.Unattested++
	}
}

// Total returns the sum across verdicts.
func (c VerdictCounts) Total() uint64 {
	return c.Reproducible + c.Mismatch + c.Unsupported + c.Unattested
}

// Snapshot is the cumulative, scrape-time view of the gate's activity used by the
// Prometheus metrics bridge and the admin surface. Counters are monotonic.
type Snapshot struct {
	Verifications uint64                   `json:"verifications"`
	Reproducible  uint64                   `json:"reproducible"`
	Mismatch      uint64                   `json:"mismatch"`
	Unsupported   uint64                   `json:"unsupported"`
	Unattested    uint64                   `json:"unattested"`
	BuildsRun     uint64                   `json:"buildsRun"`
	BuildErrors   uint64                   `json:"buildErrors"`
	AsyncLaunched uint64                   `json:"asyncLaunched"`
	CacheHits     uint64                   `json:"cacheHits"`
	CacheSize     int                      `json:"cacheSize"`
	InFlight      int                      `json:"inFlight"`
	ByEcosystem   map[string]VerdictCounts `json:"byEcosystem,omitempty"`
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// per-ecosystem verdict breakdown. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Verifications: s.verifications.Load(),
		Reproducible:  s.reproducible.Load(),
		Mismatch:      s.mismatchN.Load(),
		Unsupported:   s.unsupported.Load(),
		Unattested:    s.unattested.Load(),
		BuildsRun:     s.buildsRun.Load(),
		BuildErrors:   s.buildErrors.Load(),
		AsyncLaunched: s.asyncLaunched.Load(),
		CacheHits:     s.cacheHits.Load(),
		CacheSize:     s.store.len(),
		ByEcosystem:   make(map[string]VerdictCounts),
	}
	s.mu.Lock()
	snap.InFlight = len(s.inflight)
	for eco, vc := range s.byEco {
		snap.ByEcosystem[eco] = *vc
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO: the effective configuration plus cumulative
// tallies, the registered builders, and the recent results.
type Status struct {
	Enabled       bool                     `json:"enabled"`
	Mode          Mode                     `json:"mode"`
	Async         bool                     `json:"async"`
	MaxConcurrent int                      `json:"maxConcurrent"`
	TenantModes   int                      `json:"tenantModes"`
	Builders      []string                 `json:"builders,omitempty"`
	Verifications uint64                   `json:"verifications"`
	Reproducible  uint64                   `json:"reproducible"`
	Mismatch      uint64                   `json:"mismatch"`
	Unsupported   uint64                   `json:"unsupported"`
	Unattested    uint64                   `json:"unattested"`
	BuildsRun     uint64                   `json:"buildsRun"`
	BuildErrors   uint64                   `json:"buildErrors"`
	CacheHits     uint64                   `json:"cacheHits"`
	CacheSize     int                      `json:"cacheSize"`
	InFlight      int                      `json:"inFlight"`
	ByEcosystem   map[string]VerdictCounts `json:"byEcosystem,omitempty"`
	Recent        []Result                 `json:"recent,omitempty"`
}

// Status returns the effective configuration plus cumulative tallies and the
// recent results for the admin surface. Safe on a nil Service. The limit bounds
// the recent-results list (0 = all retained).
func (s *Service) Status(limit int) Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:       s.cfg.Enabled,
		Mode:          s.cfg.Mode,
		Async:         s.cfg.Async,
		MaxConcurrent: s.cfg.MaxConcurrent,
		TenantModes:   len(s.cfg.Tenants),
		Builders:      s.Builders(),
		Verifications: snap.Verifications,
		Reproducible:  snap.Reproducible,
		Mismatch:      snap.Mismatch,
		Unsupported:   snap.Unsupported,
		Unattested:    snap.Unattested,
		BuildsRun:     snap.BuildsRun,
		BuildErrors:   snap.BuildErrors,
		CacheHits:     snap.CacheHits,
		CacheSize:     snap.CacheSize,
		InFlight:      snap.InFlight,
		ByEcosystem:   snap.ByEcosystem,
		Recent:        s.recent.snapshot(limit),
	}
}

// Recent returns up to limit recent terminal results, newest first.
func (s *Service) Recent(limit int) []Result {
	if s == nil {
		return nil
	}
	return s.recent.snapshot(limit)
}
