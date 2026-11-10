package pypiattest

// EcoCounts tallies PyPI-attestation verification outcomes for one ecosystem.
type EcoCounts struct {
	// Checked is the number of distributions the gate evaluated.
	Checked uint64 `json:"checked"`
	// Present / Verified / PublisherTrusted / DigestMismatch mirror the report signals.
	Present          uint64 `json:"present"`
	Verified         uint64 `json:"verified"`
	PublisherTrusted uint64 `json:"publisherTrusted"`
	DigestMismatch   uint64 `json:"digestMismatch"`
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
	PublisherTrusted  int64                `json:"publisherTrusted"`
	DigestMismatch    int64                `json:"digestMismatch"`
	Transparency      int64                `json:"transparencyVerified"`
	Blocked           int64                `json:"blocked"`
	Downgraded        int64                `json:"downgraded"`
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
		PublisherTrusted:  s.counters.publisherTrusted.Load(),
		DigestMismatch:    s.counters.digestMismatch.Load(),
		Transparency:      s.counters.transparency.Load(),
		Blocked:           s.counters.blocked.Load(),
		Downgraded:        s.counters.downgraded.Load(),
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
	Enabled                 bool                 `json:"enabled"`
	Action                  string               `json:"action"`
	FailSeverity            string               `json:"failSeverity"`
	WarnSeverity            string               `json:"warnSeverity"`
	RequireAttestation      bool                 `json:"requireAttestation"`
	RequireTrustedPublisher bool                 `json:"requireTrustedPublisher"`
	RequireInclusionProof   bool                 `json:"requireInclusionProof"`
	Offline                 bool                 `json:"offline"`
	TenantActions           int                  `json:"tenantActions"`
	TrustRootsConfigured    bool                 `json:"trustRootsConfigured"`
	IdentitiesConfigured    int                  `json:"identitiesConfigured"`
	RekorKeysConfigured     int                  `json:"rekorKeysConfigured"`
	Verifications           int64                `json:"verifications"`
	Present                 int64                `json:"present"`
	Verified                int64                `json:"verified"`
	PublisherTrusted        int64                `json:"publisherTrusted"`
	DigestMismatch          int64                `json:"digestMismatch"`
	Transparency            int64                `json:"transparencyVerified"`
	Blocked                 int64                `json:"blocked"`
	Downgraded              int64                `json:"downgraded"`
	CacheHits               int64                `json:"cacheHits"`
	Errors                  int64                `json:"errors"`
	CacheEntries            int                  `json:"cacheEntries"`
	ByEcosystem             map[string]EcoCounts `json:"byEcosystem,omitempty"`
	Recent                  []*Report            `json:"recent,omitempty"`
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
		Enabled:                 s.Enabled(),
		Action:                  string(s.cfg.Action),
		FailSeverity:            string(s.cfg.FailSeverity),
		WarnSeverity:            string(s.cfg.WarnSeverity),
		RequireAttestation:      s.cfg.RequireAttestation,
		RequireTrustedPublisher: s.cfg.RequireTrustedPublisher,
		RequireInclusionProof:   s.cfg.RequireInclusionProof,
		Offline:                 s.cfg.Offline,
		TenantActions:           len(s.cfg.Tenants),
		TrustRootsConfigured:    s.cfg.Roots != nil,
		IdentitiesConfigured:    len(s.cfg.Identities),
		RekorKeysConfigured:     len(s.cfg.RekorKeys),
		Verifications:           snap.Verifications,
		Present:                 snap.Present,
		Verified:                snap.Verified,
		PublisherTrusted:        snap.PublisherTrusted,
		DigestMismatch:          snap.DigestMismatch,
		Transparency:            snap.Transparency,
		Blocked:                 snap.Blocked,
		Downgraded:              snap.Downgraded,
		CacheHits:               snap.CacheHits,
		Errors:                  snap.Errors,
		CacheEntries:            snap.CacheEntries,
		ByEcosystem:             snap.ByEcosystem,
		Recent:                  recent,
	}
}
