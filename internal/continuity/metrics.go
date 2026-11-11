package continuity

import (
	"sort"
	"strings"
	"time"
)

// Snapshot is the cumulative, scrape-time view of the gate's activity for the
// Prometheus metrics bridge. Counters are monotonic; KnownCoordinates and
// PendingNow are gauges.
type Snapshot struct {
	Checks           uint64
	FirstUse         uint64
	Drifts           uint64
	Blocks           uint64
	Warns            uint64
	Unknown          uint64
	Allowlisted      uint64
	KnownCoordinates int
	PendingNow       int
	ChecksByEco      map[string]uint64
	DriftsByEco      map[string]uint64
	BlocksByEco      map[string]uint64
}

// Metrics returns a consistent snapshot of the cumulative counters and the
// current store size, partitioned by ecosystem. Safe on a nil Service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Checks:      s.checks.Load(),
		FirstUse:    s.firstUse.Load(),
		Drifts:      s.drifts.Load(),
		Blocks:      s.blocks.Load(),
		Warns:       s.warns.Load(),
		Unknown:     s.unknown.Load(),
		Allowlisted: s.allowlists.Load(),
		ChecksByEco: make(map[string]uint64),
		DriftsByEco: make(map[string]uint64),
		BlocksByEco: make(map[string]uint64),
	}
	s.mu.Lock()
	snap.KnownCoordinates = len(s.records)
	for _, r := range s.records {
		if len(r.Pending) > 0 {
			snap.PendingNow++
		}
	}
	s.mu.Unlock()
	s.ecoMu.Lock()
	for eco, c := range s.byEco {
		snap.ChecksByEco[eco] = c.checks
		snap.DriftsByEco[eco] = c.drift
		snap.BlocksByEco[eco] = c.blocked
	}
	s.ecoMu.Unlock()
	return snap
}

// Status is the admin status DTO for the continuity gate: the effective
// configuration plus cumulative tallies.
type Status struct {
	Enabled            bool              `json:"enabled"`
	DefaultDisposition string            `json:"defaultDisposition"`
	CooldownSeconds    float64           `json:"cooldownSeconds"`
	EcosystemOverrides map[string]string `json:"ecosystemDispositions,omitempty"`
	TenantOverrides    int               `json:"tenantOverrides"`
	AllowlistSize      int               `json:"allowlistSize"`
	KnownCoordinates   int               `json:"knownCoordinates"`
	Checks             uint64            `json:"checks"`
	FirstUse           uint64            `json:"firstUse"`
	Drifts             uint64            `json:"drifts"`
	Blocks             uint64            `json:"blocks"`
	Warns              uint64            `json:"warns"`
	Unknown            uint64            `json:"unknown"`
	Allowlisted        uint64            `json:"allowlisted"`
	PendingNow         int               `json:"pendingNow"`
}

// Status returns the effective configuration plus cumulative tallies for the
// admin surface. Safe on a nil Service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	snap := s.Metrics()
	st := Status{
		Enabled:            true,
		DefaultDisposition: string(s.cfg.DefaultDisposition),
		CooldownSeconds:    s.cfg.Cooldown.Seconds(),
		TenantOverrides:    len(s.cfg.Tenants),
		AllowlistSize:      len(s.cfg.Allowlist),
		KnownCoordinates:   snap.KnownCoordinates,
		Checks:             snap.Checks,
		FirstUse:           snap.FirstUse,
		Drifts:             snap.Drifts,
		Blocks:             snap.Blocks,
		Warns:              snap.Warns,
		Unknown:            snap.Unknown,
		Allowlisted:        snap.Allowlisted,
		PendingNow:         snap.PendingNow,
	}
	if len(s.cfg.Ecosystems) > 0 {
		st.EcosystemOverrides = make(map[string]string, len(s.cfg.Ecosystems))
		for eco, d := range s.cfg.Ecosystems {
			st.EcosystemOverrides[eco] = string(NormalizeDisposition(string(d)))
		}
	}
	return st
}

// PendingView is one coordinate with a currently-untrusted (within-cooldown) new
// maintainer, for the admin "drifting now" list.
type PendingView struct {
	Ecosystem        string    `json:"ecosystem"`
	Name             string    `json:"name"`
	LastVersion      string    `json:"lastVersion,omitempty"`
	Pending          []string  `json:"pending"`
	TrustedCount     int       `json:"trustedCount"`
	FirstSeen        time.Time `json:"firstSeen"`
	LastSeen         time.Time `json:"lastSeen"`
	RemainingSeconds float64   `json:"remainingSeconds"`
	DriftEvents      int       `json:"driftEvents"`
}

// Pending returns the coordinates with currently-untrusted new maintainers (a new
// publisher principal observed but not yet aged past the trust cooldown), ordered
// by ascending time-remaining. limit<=0 returns all. Safe on a nil Service.
func (s *Service) Pending(limit int) []PendingView {
	if s == nil {
		return nil
	}
	now := s.now()
	cooldown := s.cfg.Cooldown
	s.mu.Lock()
	out := make([]PendingView, 0)
	for _, r := range s.records {
		if len(r.Pending) == 0 {
			continue
		}
		pending := make([]string, 0, len(r.Pending))
		var remaining time.Duration
		for p, firstSeen := range r.Pending {
			pending = append(pending, p)
			if rem := firstSeen.Add(cooldown).Sub(now); rem > remaining {
				remaining = rem
			}
		}
		if remaining < 0 {
			remaining = 0
		}
		sort.Strings(pending)
		out = append(out, PendingView{
			Ecosystem:        r.Ecosystem,
			Name:             r.Name,
			LastVersion:      r.LastVersion,
			Pending:          pending,
			TrustedCount:     len(r.Trusted),
			FirstSeen:        r.FirstSeen,
			LastSeen:         r.LastSeen,
			RemainingSeconds: remaining.Seconds(),
			DriftEvents:      r.DriftEvents,
		})
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].RemainingSeconds != out[j].RemainingSeconds {
			return out[i].RemainingSeconds < out[j].RemainingSeconds
		}
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// KeyPrincipalFromIdentity renders a signature-verified signer identity (the
// cosign certificate identity / GPG key id and OIDC issuer surfaced by the
// signature-verification path) as a continuity key principal, so a publishing-key
// rotation registers as an ownership-change signal alongside the registry
// maintainer roster. It returns "" when no identity is available.
func KeyPrincipalFromIdentity(identity, issuer string) string {
	identity = strings.TrimSpace(identity)
	issuer = strings.TrimSpace(issuer)
	if identity == "" {
		return ""
	}
	if issuer != "" {
		return identity + " (" + issuer + ")"
	}
	return identity
}
