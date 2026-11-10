package contentscan

// Snapshot is the cumulative, scrape-time view of the gate's activity used by the
// Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	Scanned       uint64 // artifacts inspected (recognized archive, unpacked)
	FilesScanned  uint64
	FlaggedArts   uint64 // artifacts with at least one finding
	FindingsTotal uint64
	Blocked       uint64
	Downgraded    uint64
	Annotated     uint64
	Truncated     uint64
	TimedOut      uint64
	ByCategory    map[string]uint64
	ByEcosystem   map[string]uint64
}

// Metrics returns a consistent snapshot of the counters plus the per-category and
// per-ecosystem breakdowns. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{ByCategory: map[string]uint64{}, ByEcosystem: map[string]uint64{}}
	}
	snap := Snapshot{
		Scanned:       s.scanned.Load(),
		FilesScanned:  s.filesTotal.Load(),
		FlaggedArts:   s.flaggedArts.Load(),
		FindingsTotal: s.findingTotal.Load(),
		Blocked:       s.blocked.Load(),
		Downgraded:    s.downgraded.Load(),
		Annotated:     s.annotated.Load(),
		Truncated:     s.truncated.Load(),
		TimedOut:      s.timedOut.Load(),
		ByCategory:    make(map[string]uint64),
		ByEcosystem:   make(map[string]uint64),
	}
	s.mu.Lock()
	for k, v := range s.byCat {
		snap.ByCategory[k] = v
	}
	for k, v := range s.byEco {
		snap.ByEcosystem[k] = v
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO for the content-analysis gate.
type Status struct {
	Enabled       bool     `json:"enabled"`
	Action        Action   `json:"action"`
	FailSeverity  Severity `json:"failSeverity"`
	Ecosystems    []string `json:"ecosystems"`
	Scanned       uint64   `json:"scanned"`
	FilesScanned  uint64   `json:"filesScanned"`
	FlaggedArts   uint64   `json:"flaggedArtifacts"`
	FindingsTotal uint64   `json:"findings"`
	Blocked       uint64   `json:"blocked"`
	Downgraded    uint64   `json:"downgraded"`
	Annotated     uint64   `json:"annotated"`
	Truncated     uint64   `json:"truncated"`
	TimedOut      uint64   `json:"timedOut"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:       s.cfg.Enabled,
		Action:        s.cfg.Action,
		FailSeverity:  s.cfg.FailSeverity,
		Ecosystems:    append([]string(nil), s.cfg.Ecosystems...),
		Scanned:       snap.Scanned,
		FilesScanned:  snap.FilesScanned,
		FlaggedArts:   snap.FlaggedArts,
		FindingsTotal: snap.FindingsTotal,
		Blocked:       snap.Blocked,
		Downgraded:    snap.Downgraded,
		Annotated:     snap.Annotated,
		Truncated:     snap.Truncated,
		TimedOut:      snap.TimedOut,
	}
}
