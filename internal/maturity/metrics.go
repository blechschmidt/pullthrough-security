package maturity

import "time"

// Snapshot is the cumulative, scrape-time view of the gate's activity used by the
// Prometheus metrics bridge. Counters are monotonic; CoolingCurrent is a gauge.
type Snapshot struct {
	Checks       uint64
	Blocks       uint64
	Allowlisted  uint64
	Unknown      uint64
	CoolingNow   int
	ChecksByEco  map[string]uint64
	BlocksByEco  map[string]uint64
	CoolingByEco map[string]int
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// current cooling registry, partitioned by ecosystem. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	now := s.now()
	snap := Snapshot{
		Checks:       s.checks.Load(),
		Blocks:       s.blocks.Load(),
		Allowlisted:  s.allowed.Load(),
		Unknown:      s.unknown.Load(),
		ChecksByEco:  make(map[string]uint64),
		BlocksByEco:  make(map[string]uint64),
		CoolingByEco: make(map[string]int),
	}
	s.mu.Lock()
	for eco, c := range s.byEco {
		snap.ChecksByEco[eco] = c.checks
		snap.BlocksByEco[eco] = c.blocked
	}
	for _, e := range s.cooling {
		if now.Before(e.publishedAt.Add(e.cooldown)) {
			snap.CoolingNow++
			snap.CoolingByEco[e.coord.Ecosystem]++
		}
	}
	s.mu.Unlock()
	return snap
}

// Status is the admin status DTO for the maturity gate.
type Status struct {
	Enabled                bool               `json:"enabled"`
	DefaultCooldownSeconds float64            `json:"defaultCooldownSeconds"`
	EcosystemsSeconds      map[string]float64 `json:"ecosystemsSeconds,omitempty"`
	FailClosedOnUnknown    bool               `json:"failClosedOnUnknown"`
	AllowlistSize          int                `json:"allowlistSize"`
	TenantOverrides        int                `json:"tenantOverrides"`
	Checks                 uint64             `json:"checks"`
	Blocks                 uint64             `json:"blocks"`
	Allowlisted            uint64             `json:"allowlisted"`
	Unknown                uint64             `json:"unknown"`
	CoolingNow             int                `json:"coolingNow"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	st := Status{
		Enabled:                true,
		DefaultCooldownSeconds: s.cfg.DefaultCooldown.Seconds(),
		FailClosedOnUnknown:    s.cfg.FailClosedOnUnknown,
		AllowlistSize:          len(s.cfg.Allowlist),
		TenantOverrides:        len(s.cfg.Tenants),
		Checks:                 s.checks.Load(),
		Blocks:                 s.blocks.Load(),
		Allowlisted:            s.allowed.Load(),
		Unknown:                s.unknown.Load(),
	}
	if len(s.cfg.Ecosystems) > 0 {
		st.EcosystemsSeconds = make(map[string]float64, len(s.cfg.Ecosystems))
		for eco, d := range s.cfg.Ecosystems {
			st.EcosystemsSeconds[eco] = d.Seconds()
		}
	}
	st.CoolingNow = s.Metrics().CoolingNow
	return st
}

// CoolingView is one currently-cooling coordinate with its live time-remaining,
// for the admin "currently cooling" list.
type CoolingView struct {
	Tenant           string    `json:"tenant,omitempty"`
	Ecosystem        string    `json:"ecosystem"`
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	PublishedAt      time.Time `json:"publishedAt"`
	CooldownSeconds  float64   `json:"cooldownSeconds"`
	AgeSeconds       float64   `json:"ageSeconds"`
	RemainingSeconds float64   `json:"remainingSeconds"`
	AvailableAt      time.Time `json:"availableAt"`
	FirstSeen        time.Time `json:"firstSeen"`
}

// Cooling returns the coordinates currently held in their cooldown window,
// ordered by ascending time-remaining (soonest to mature first). Matured entries
// are pruned. limit<=0 returns all. Safe on a nil Service.
func (s *Service) Cooling(limit int) []CoolingView {
	if s == nil {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	out := make([]CoolingView, 0, len(s.cooling))
	for k, e := range s.cooling {
		avail := e.publishedAt.Add(e.cooldown)
		if !now.Before(avail) {
			delete(s.cooling, k)
			continue
		}
		out = append(out, CoolingView{
			Tenant:           e.tenant,
			Ecosystem:        e.coord.Ecosystem,
			Name:             e.coord.Name,
			Version:          e.coord.Version,
			PublishedAt:      e.publishedAt,
			CooldownSeconds:  e.cooldown.Seconds(),
			AgeSeconds:       now.Sub(e.publishedAt).Seconds(),
			RemainingSeconds: avail.Sub(now).Seconds(),
			AvailableAt:      avail,
			FirstSeen:        e.firstSeen,
		})
	}
	s.mu.Unlock()
	sortCooling(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
