package actionpin

// Snapshot is the cumulative, scrape-time view of the gate's activity used by
// the Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	Scanned        uint64
	FilesScanned   uint64
	RefsScanned    uint64
	FlaggedSets    uint64
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
		FilesScanned:   s.filesScanned.Load(),
		RefsScanned:    s.refsScanned.Load(),
		FlaggedSets:    s.flaggedSets.Load(),
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

// Status is the admin status DTO for the gate: the effective configuration plus
// cumulative tallies.
type Status struct {
	Enabled        bool              `json:"enabled"`
	FailSeverity   Severity          `json:"failSeverity"`
	WarnSeverity   Severity          `json:"warnSeverity,omitempty"`
	Action         Action            `json:"action"`
	RequirePinning bool              `json:"requirePinning"`
	AllowedOwners  []string          `json:"allowedOwners,omitempty"`
	TenantOverride int               `json:"tenantOverrides"`
	Scanned        uint64            `json:"scanned"`
	FilesScanned   uint64            `json:"filesScanned"`
	RefsScanned    uint64            `json:"referencesScanned"`
	FlaggedSets    uint64            `json:"flaggedSets"`
	FindingsTotal  uint64            `json:"findingsTotal"`
	Blocked        uint64            `json:"blocked"`
	Warned         uint64            `json:"warned"`
	FindingsByRule map[string]uint64 `json:"findingsByRule,omitempty"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:        s.cfg.Enabled,
		FailSeverity:   s.cfg.FailSeverity,
		WarnSeverity:   s.cfg.WarnSeverity,
		Action:         s.cfg.Action,
		RequirePinning: s.cfg.RequirePinning,
		AllowedOwners:  s.cfg.AllowedOwners,
		TenantOverride: len(s.cfg.Tenants),
		Scanned:        snap.Scanned,
		FilesScanned:   snap.FilesScanned,
		RefsScanned:    snap.RefsScanned,
		FlaggedSets:    snap.FlaggedSets,
		FindingsTotal:  snap.FindingsTotal,
		Blocked:        snap.Blocked,
		Warned:         snap.Warned,
		FindingsByRule: snap.FindingsByRule,
	}
}
