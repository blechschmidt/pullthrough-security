package buildprov

// EcoCounts tallies build-provenance verification outcomes for one ecosystem.
type EcoCounts struct {
	// Checked is the number of artifacts the gate evaluated.
	Checked uint64 `json:"checked"`
	// Present / Verified / SourceVerified / Mismatch mirror the report signals.
	Present        uint64 `json:"present"`
	Verified       uint64 `json:"verified"`
	SourceVerified uint64 `json:"sourceVerified"`
	Mismatch       uint64 `json:"mismatch"`
}

// Snapshot is a point-in-time view of the subsystem's cumulative counters,
// surfaced through the metrics layer and the admin API. Counters are monotonic.
type Snapshot struct {
	Verifications     int64                `json:"verifications"`
	CacheHits         int64                `json:"cacheHits"`
	Errors            int64                `json:"errors"`
	AttestationsCheck int64                `json:"attestationsChecked"`
	Present           int64                `json:"present"`
	Verified          int64                `json:"verified"`
	SourceVerified    int64                `json:"sourceVerified"`
	Mismatch          int64                `json:"mismatch"`
	Blocked           int64                `json:"blocked"`
	Warned            int64                `json:"warned"`
	Quarantined       int64                `json:"quarantined"`
	CacheEntries      int                  `json:"cacheEntries"`
	ByEcosystem       map[string]EcoCounts `json:"byEcosystem,omitempty"`
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// per-ecosystem breakdown. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Verifications:     s.counters.verifications.Load(),
		CacheHits:         s.counters.cacheHits.Load(),
		Errors:            s.counters.errors.Load(),
		AttestationsCheck: s.counters.attestationsCheck.Load(),
		Present:           s.counters.present.Load(),
		Verified:          s.counters.verified.Load(),
		SourceVerified:    s.counters.sourceVerified.Load(),
		Mismatch:          s.counters.mismatch.Load(),
		Blocked:           s.counters.blocked.Load(),
		Warned:            s.counters.warned.Load(),
		Quarantined:       s.counters.quarantined.Load(),
		CacheEntries:      s.cache.size(),
		ByEcosystem:       make(map[string]EcoCounts),
	}
	s.mu.Lock()
	for eco, c := range s.byEco {
		snap.ByEcosystem[eco] = *c
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO: the effective configuration plus cumulative
// tallies and the recent verification reports.
type Status struct {
	Enabled              bool                 `json:"enabled"`
	Mode                 Mode                 `json:"mode"`
	Action               string               `json:"action"`
	FailSeverity         string               `json:"failSeverity"`
	WarnSeverity         string               `json:"warnSeverity"`
	RequireProvenance    bool                 `json:"requireProvenance"`
	RequireTrustedSource bool                 `json:"requireTrustedSource"`
	Offline              bool                 `json:"offline"`
	TenantModes          int                  `json:"tenantModes"`
	TrustRootsConfigured bool                 `json:"trustRootsConfigured"`
	IdentitiesConfigured int                  `json:"identitiesConfigured"`
	Verifications        int64                `json:"verifications"`
	Present              int64                `json:"present"`
	Verified             int64                `json:"verified"`
	SourceVerified       int64                `json:"sourceVerified"`
	Mismatch             int64                `json:"mismatch"`
	Blocked              int64                `json:"blocked"`
	Warned               int64                `json:"warned"`
	Quarantined          int64                `json:"quarantined"`
	CacheHits            int64                `json:"cacheHits"`
	Errors               int64                `json:"errors"`
	CacheEntries         int                  `json:"cacheEntries"`
	ByEcosystem          map[string]EcoCounts `json:"byEcosystem,omitempty"`
	Recent               []*Report            `json:"recent,omitempty"`
}

// Status returns the effective configuration plus cumulative tallies and the
// recent verification reports for the admin surface. Safe on a nil Service. The
// limit bounds the recent-reports list (0 => all retained).
func (s *Service) Status(limit int) Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	recent := s.Reports()
	if limit > 0 && len(recent) > limit {
		recent = recent[:limit]
	}
	return Status{
		Enabled:              s.Enabled(),
		Mode:                 s.cfg.Mode,
		Action:               string(s.cfg.Action),
		FailSeverity:         string(s.cfg.FailSeverity),
		WarnSeverity:         string(s.cfg.WarnSeverity),
		RequireProvenance:    s.cfg.RequireProvenance,
		RequireTrustedSource: s.cfg.RequireTrustedSource,
		Offline:              s.cfg.Offline,
		TenantModes:          len(s.cfg.Tenants),
		TrustRootsConfigured: s.cfg.Roots != nil,
		IdentitiesConfigured: len(s.cfg.Identities),
		Verifications:        snap.Verifications,
		Present:              snap.Present,
		Verified:             snap.Verified,
		SourceVerified:       snap.SourceVerified,
		Mismatch:             snap.Mismatch,
		Blocked:              snap.Blocked,
		Warned:               snap.Warned,
		Quarantined:          snap.Quarantined,
		CacheHits:            snap.CacheHits,
		Errors:               snap.Errors,
		CacheEntries:         snap.CacheEntries,
		ByEcosystem:          snap.ByEcosystem,
		Recent:               recent,
	}
}
