package mlguard

// Snapshot is the cumulative, scrape-time view of the gate's activity used by the
// Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	Scanned        uint64 // pickle files disassembled
	Safetensors    uint64 // safetensors files recognized/preferred
	FlaggedArts    uint64
	FindingsTotal  uint64
	Blocked        uint64
	Warned         uint64
	FindingsByRule map[string]uint64
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// per-rule breakdown. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Scanned:        s.scanned.Load(),
		Safetensors:    s.safetensors.Load(),
		FlaggedArts:    s.flaggedArts.Load(),
		FindingsTotal:  s.findingsTotal.Load(),
		Blocked:        s.blocked.Load(),
		Warned:         s.warned.Load(),
		FindingsByRule: make(map[string]uint64),
	}
	s.mu.Lock()
	for rule, n := range s.byRule {
		snap.FindingsByRule[rule] = n
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO for the ML weight-scanning gate.
type Status struct {
	Enabled           bool     `json:"enabled"`
	FailSeverity      Severity `json:"failSeverity"`
	WarnSeverity      Severity `json:"warnSeverity,omitempty"`
	Action            Action   `json:"action"`
	PreferSafetensors bool     `json:"preferSafetensors"`
	TenantOverrides   int      `json:"tenantOverrides"`
	Scanned           uint64   `json:"scanned"`
	Safetensors       uint64   `json:"safetensors"`
	FlaggedArts       uint64   `json:"flaggedArtifacts"`
	FindingsTotal     uint64   `json:"findingsTotal"`
	Blocked           uint64   `json:"blocked"`
	Warned            uint64   `json:"warned"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:           s.cfg.Enabled,
		FailSeverity:      s.cfg.FailSeverity,
		WarnSeverity:      s.cfg.WarnSeverity,
		Action:            s.cfg.Action,
		PreferSafetensors: s.cfg.PreferSafetensors,
		TenantOverrides:   len(s.cfg.Tenants),
		Scanned:           snap.Scanned,
		Safetensors:       snap.Safetensors,
		FlaggedArts:       snap.FlaggedArts,
		FindingsTotal:     snap.FindingsTotal,
		Blocked:           snap.Blocked,
		Warned:            snap.Warned,
	}
}
