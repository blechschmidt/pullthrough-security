package avscan

// Snapshot is the cumulative, scrape-time view of the gate's activity used by
// the Prometheus metrics bridge. Counters are monotonic.
type Snapshot struct {
	Scanned          uint64 // artifacts with a completed verdict
	Clean            uint64
	Infected         uint64
	Truncated        uint64
	Unavailable      uint64 // scans where the engine could not be reached
	BytesScanned     uint64
	Quarantined      uint64
	Blocked          uint64
	Annotated        uint64
	Degraded         uint64 // fail-open admissions without a verdict
	InfectedBySignat map[string]uint64
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// per-signature breakdown. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Scanned:          s.scanned.Load(),
		Clean:            s.clean.Load(),
		Infected:         s.infected.Load(),
		Truncated:        s.truncated.Load(),
		Unavailable:      s.unavailable.Load(),
		BytesScanned:     s.bytesTotal.Load(),
		Quarantined:      s.quarantined.Load(),
		Blocked:          s.blocked.Load(),
		Annotated:        s.annotated.Load(),
		Degraded:         s.degraded.Load(),
		InfectedBySignat: make(map[string]uint64),
	}
	s.mu.Lock()
	for sig, n := range s.bySignature {
		snap.InfectedBySignat[sig] = n
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO for the antivirus content-scanning gate.
type Status struct {
	Enabled      bool   `json:"enabled"`
	Engine       string `json:"engine"`
	Action       Action `json:"action"`
	FailOpen     bool   `json:"failOpen"`
	MaxScanBytes int64  `json:"maxScanBytes"`
	TimeoutSecs  int64  `json:"timeoutSeconds"`
	Scanned      uint64 `json:"scanned"`
	Clean        uint64 `json:"clean"`
	Infected     uint64 `json:"infected"`
	Truncated    uint64 `json:"truncated"`
	Unavailable  uint64 `json:"unavailable"`
	BytesScanned uint64 `json:"bytesScanned"`
	Quarantined  uint64 `json:"quarantined"`
	Blocked      uint64 `json:"blocked"`
	Annotated    uint64 `json:"annotated"`
	Degraded     uint64 `json:"degraded"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	return Status{
		Enabled:      s.cfg.Enabled,
		Engine:       s.engine.Name(),
		Action:       s.cfg.Action,
		FailOpen:     s.cfg.FailOpen,
		MaxScanBytes: s.cfg.MaxScanBytes,
		TimeoutSecs:  int64(s.cfg.Timeout.Seconds()),
		Scanned:      snap.Scanned,
		Clean:        snap.Clean,
		Infected:     snap.Infected,
		Truncated:    snap.Truncated,
		Unavailable:  snap.Unavailable,
		BytesScanned: snap.BytesScanned,
		Quarantined:  snap.Quarantined,
		Blocked:      snap.Blocked,
		Annotated:    snap.Annotated,
		Degraded:     snap.Degraded,
	}
}
