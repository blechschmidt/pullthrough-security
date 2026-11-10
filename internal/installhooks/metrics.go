package installhooks

// Snapshot is the cumulative, scrape-time view of the gate's activity used by
// the Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	Scanned        uint64
	HooksFound     uint64
	FlaggedArts    uint64
	FindingsTotal  uint64
	Blocked        uint64
	Warned         uint64
	FindingsByRule map[string]uint64
	ScannedByEco   map[string]uint64
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// per-rule / per-ecosystem breakdowns. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Scanned:        s.scanned.Load(),
		HooksFound:     s.hooksFound.Load(),
		FlaggedArts:    s.flaggedArts.Load(),
		FindingsTotal:  s.findingsTotal.Load(),
		Blocked:        s.blocked.Load(),
		Warned:         s.warned.Load(),
		FindingsByRule: make(map[string]uint64),
		ScannedByEco:   make(map[string]uint64),
	}
	s.mu.Lock()
	for rule, n := range s.byRule {
		snap.FindingsByRule[rule] = n
	}
	for eco, n := range s.byEco {
		snap.ScannedByEco[eco] = n
	}
	s.mu.Unlock()
	return snap
}

// RuleView is one rule's static description plus its live finding count, for the
// admin status surface.
type RuleView struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Findings uint64   `json:"findings"`
}

// Status is the admin status DTO for the install-hook gate: the effective
// configuration plus cumulative tallies and the active rule catalog.
type Status struct {
	Enabled        bool              `json:"enabled"`
	FailSeverity   Severity          `json:"failSeverity"`
	WarnSeverity   Severity          `json:"warnSeverity,omitempty"`
	Action         Action            `json:"action"`
	TenantOverride int               `json:"tenantOverrides"`
	Scanned        uint64            `json:"scanned"`
	HooksFound     uint64            `json:"hooksFound"`
	FlaggedArts    uint64            `json:"flaggedArtifacts"`
	FindingsTotal  uint64            `json:"findingsTotal"`
	Blocked        uint64            `json:"blocked"`
	Warned         uint64            `json:"warned"`
	Rules          []RuleView        `json:"rules"`
	ScannedByEco   map[string]uint64 `json:"scannedByEcosystem,omitempty"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	st := Status{
		Enabled:        s.cfg.Enabled,
		FailSeverity:   s.cfg.FailSeverity,
		WarnSeverity:   s.cfg.WarnSeverity,
		Action:         s.cfg.Action,
		TenantOverride: len(s.cfg.Tenants),
		Scanned:        snap.Scanned,
		HooksFound:     snap.HooksFound,
		FlaggedArts:    snap.FlaggedArts,
		FindingsTotal:  snap.FindingsTotal,
		Blocked:        snap.Blocked,
		Warned:         snap.Warned,
		ScannedByEco:   snap.ScannedByEco,
	}
	for i := range s.rules {
		r := &s.rules[i]
		st.Rules = append(st.Rules, RuleView{
			ID:       r.ID,
			Title:    r.Title,
			Severity: r.Severity,
			Findings: snap.FindingsByRule[r.ID],
		})
	}
	return st
}
