package sbomdiff

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// Config configures the SBOM-diff / dependency-drift subsystem (Task 64).
type Config struct {
	// Enabled turns on snapshot recording, drift evaluation, the admin surface,
	// and the Prometheus metrics.
	Enabled bool
	// HistorySize is the number of recent version snapshots retained per
	// coordinate (default 16).
	HistorySize int
	// MaxCoordinates bounds the number of distinct coordinate histories retained
	// (default 4096); the least-recently-updated coordinate is evicted first.
	MaxCoordinates int
	// Action is the admission action taken when a diff's drift score meets
	// BlockThreshold: warn, block, or quarantine. Default warn (observe-and-alert).
	Action policy.Action
	// WarnThreshold is the drift score at or above which a pull is warned on
	// (X-Sbom-Drift headers) even when Action would not block (default 25).
	WarnThreshold float64
	// BlockThreshold is the drift score at or above which Action is applied
	// (default 60).
	BlockThreshold float64
	// SignificantThreshold is the drift score at or above which a diff is
	// considered significant — it drives the EventSbomDrift notification and the
	// admission signal fed to the policy engine (default 40).
	SignificantThreshold float64
	// Weights tunes the drift-scoring model; zero fields fall back to defaults.
	Weights Weights
}

// withDefaults fills zero-valued config fields with their defaults.
func (c Config) withDefaults() Config {
	if c.HistorySize <= 0 {
		c.HistorySize = 16
	}
	if c.MaxCoordinates <= 0 {
		c.MaxCoordinates = 4096
	}
	if c.Action == "" {
		c.Action = policy.ActionWarn
	}
	if c.WarnThreshold == 0 {
		c.WarnThreshold = 25
	}
	if c.BlockThreshold == 0 {
		c.BlockThreshold = 60
	}
	if c.SignificantThreshold == 0 {
		c.SignificantThreshold = 40
	}
	c.Weights = c.Weights.withDefaults()
	return c
}

// DriftResult is the outcome of recording and evaluating a new version snapshot.
type DriftResult struct {
	// Diff is the comparison against the prior version; nil when no prior version
	// was held (the first time a coordinate is seen).
	Diff *Diff
	// Compared is true when a prior version existed and a diff was produced.
	Compared bool
	// Action is the admission action the drift warrants (none/warn/block/
	// quarantine). It is never escalated beyond the configured Action.
	Action policy.Action
	// Code is a short machine token for the decision ("drift-block",
	// "drift-warn", or "" when allowed).
	Code string
	// Reason is a human-readable explanation suitable for headers, audit, and
	// notifications.
	Reason string
	// Significant mirrors Diff.Significant for convenient gating of notifications.
	Significant bool
}

// Service records resolved SBOM snapshots into a bounded per-coordinate history,
// computes version-to-version drift, and turns a drift score into an admission
// signal. It is safe for concurrent use; a nil *Service is inert (every method is
// a no-op / disabled), so call sites need no nil guards beyond Enabled.
type Service struct {
	cfg     Config
	store   *Store
	license LicenseDispositioner

	observed    atomic.Int64
	compared    atomic.Int64
	significant atomic.Int64
	warned      atomic.Int64
	blocked     atomic.Int64
	quarantined atomic.Int64

	mu           sync.Mutex
	driftByEco   map[string]int64
	recentDrifts []DriftRecord
}

// DriftRecord is a retained significant-drift event for the admin surface.
type DriftRecord struct {
	Tenant      string  `json:"tenant,omitempty"`
	Ecosystem   string  `json:"ecosystem"`
	Coordinate  string  `json:"coordinate"`
	FromVersion string  `json:"fromVersion"`
	ToVersion   string  `json:"toVersion"`
	DriftScore  float64 `json:"driftScore"`
	Action      string  `json:"action"`
	AddedDeps   int     `json:"addedDeps"`
	NewVulns    int     `json:"newVulnerabilities"`
	NewLicenses int     `json:"newLicenses"`
	NewNS       int     `json:"newNamespaces"`
}

const maxRecentDrifts = 256

// NewService constructs the subsystem. license may be nil to disable license
// cross-referencing (new licenses are still surfaced without a disposition).
func NewService(cfg Config, license LicenseDispositioner) *Service {
	cfg = cfg.withDefaults()
	return &Service{
		cfg:        cfg,
		store:      NewStore(cfg.HistorySize, cfg.MaxCoordinates),
		license:    license,
		driftByEco: make(map[string]int64),
	}
}

// Enabled reports whether the subsystem is active.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Action returns the configured enforcement action for block-threshold drift.
func (s *Service) Action() policy.Action {
	if s == nil {
		return policy.ActionWarn
	}
	return s.cfg.Action
}

// Store exposes the underlying history store for on-demand diffs (admin/CLI).
func (s *Service) Store() *Store {
	if s == nil {
		return nil
	}
	return s.store
}

// Observe records a new version snapshot and evaluates the drift it introduces
// relative to the immediately-prior version. It always records the snapshot (so
// the history is complete) and returns a DriftResult describing any admission
// action warranted. On the first sighting of a coordinate it records the baseline
// and returns an allow result with Compared=false.
func (s *Service) Observe(snap Snapshot) DriftResult {
	if !s.Enabled() {
		return DriftResult{Action: policy.ActionAllow}
	}
	s.observed.Add(1)

	prior, ok := s.store.Record(snap)
	if !ok {
		return DriftResult{Action: policy.ActionAllow}
	}

	diff := compute(prior, snap, computeOptions{
		weights:     s.cfg.Weights,
		significant: s.cfg.SignificantThreshold,
		license:     s.license,
	})
	s.compared.Add(1)

	res := DriftResult{Diff: diff, Compared: true, Significant: diff.Significant, Action: policy.ActionAllow}
	switch {
	case diff.DriftScore >= s.cfg.BlockThreshold:
		res.Action = s.cfg.Action
		res.Code = "drift-block"
		res.Reason = driftReason(diff)
	case diff.DriftScore >= s.cfg.WarnThreshold:
		res.Action = policy.ActionWarn
		res.Code = "drift-warn"
		res.Reason = driftReason(diff)
	}

	switch res.Action {
	case policy.ActionWarn:
		s.warned.Add(1)
	case policy.ActionBlock:
		s.blocked.Add(1)
	case policy.ActionQuarantine:
		s.quarantined.Add(1)
	}

	if diff.Significant {
		s.significant.Add(1)
		s.recordSignificant(diff, res.Action)
	}
	return res
}

// Diff computes an on-demand diff between two recorded versions of a coordinate
// (the admin "what changed since the version I last approved?" query). It does
// not record anything or affect metrics. ok is false when either version is not
// in the retained history.
func (s *Service) Diff(tenant, ecosystem, coordinate, fromVersion, toVersion string) (*Diff, bool) {
	if s == nil {
		return nil, false
	}
	from, okA := s.store.Snapshot(tenant, ecosystem, coordinate, fromVersion)
	to, okB := s.store.Snapshot(tenant, ecosystem, coordinate, toVersion)
	if !okA || !okB {
		return nil, false
	}
	return compute(from, to, computeOptions{
		weights:     s.cfg.Weights,
		significant: s.cfg.SignificantThreshold,
		license:     s.license,
	}), true
}

// DiffLatest computes the diff for the two most recent distinct versions of a
// coordinate. ok is false when fewer than two versions are held.
func (s *Service) DiffLatest(tenant, ecosystem, coordinate string) (*Diff, bool) {
	if s == nil {
		return nil, false
	}
	prev, cur, ok := s.store.Latest(tenant, ecosystem, coordinate)
	if !ok {
		return nil, false
	}
	return compute(prev, cur, computeOptions{
		weights:     s.cfg.Weights,
		significant: s.cfg.SignificantThreshold,
		license:     s.license,
	}), true
}

// recordSignificant appends a significant-drift event to the bounded admin log
// and bumps the per-ecosystem tally.
func (s *Service) recordSignificant(diff *Diff, action policy.Action) {
	rec := DriftRecord{
		Tenant:      diff.Tenant,
		Ecosystem:   diff.Ecosystem,
		Coordinate:  diff.Coordinate,
		FromVersion: diff.From.Version,
		ToVersion:   diff.To.Version,
		DriftScore:  diff.DriftScore,
		Action:      string(action),
		AddedDeps:   len(diff.AddedDeps),
		NewVulns:    len(diff.NewVulnerabilities),
		NewLicenses: len(diff.NewLicenses),
		NewNS:       len(diff.NewNamespaces),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.driftByEco[diff.Ecosystem]++
	s.recentDrifts = append(s.recentDrifts, rec)
	if len(s.recentDrifts) > maxRecentDrifts {
		s.recentDrifts = s.recentDrifts[len(s.recentDrifts)-maxRecentDrifts:]
	}
}

// driftReason renders a concise, deterministic explanation of a drift score.
func driftReason(diff *Diff) string {
	var parts []string
	if n := len(diff.NewVulnerabilities); n > 0 {
		parts = append(parts, plural(n, "new vulnerability", "new vulnerabilities"))
	}
	if n := countDeniedReview(diff.NewLicenses); n > 0 {
		parts = append(parts, plural(n, "new non-compliant license", "new non-compliant licenses"))
	}
	if n := len(diff.NewNamespaces); n > 0 {
		parts = append(parts, plural(n, "new namespace", "new namespaces"))
	}
	if n := len(diff.AddedDeps); n > 0 {
		parts = append(parts, plural(n, "added dependency", "added dependencies"))
	}
	detail := "footprint change"
	if len(parts) > 0 {
		detail = strings.Join(parts, ", ")
	}
	return "dependency drift " + diff.From.Version + " → " + diff.To.Version + ": " + detail
}

func countDeniedReview(ls []LicenseChange) int {
	n := 0
	for _, l := range ls {
		if l.Disposition == "denied" || l.Disposition == "deny" || l.Disposition == "review" {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	// Small dependency-free integer formatter for reason strings.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Snapshot is the cumulative metrics view for the admin API and Prometheus.
type Stats struct {
	Enabled              bool             `json:"enabled"`
	Action               string           `json:"action"`
	WarnThreshold        float64          `json:"warnThreshold"`
	BlockThreshold       float64          `json:"blockThreshold"`
	SignificantThreshold float64          `json:"significantThreshold"`
	HistorySize          int              `json:"historySize"`
	Coordinates          int              `json:"coordinates"`
	Observed             int64            `json:"observed"`
	Compared             int64            `json:"compared"`
	Significant          int64            `json:"significant"`
	Warned               int64            `json:"warned"`
	Blocked              int64            `json:"blocked"`
	Quarantined          int64            `json:"quarantined"`
	DriftByEcosystem     map[string]int64 `json:"driftByEcosystem,omitempty"`
	RecentDrifts         []DriftRecord    `json:"recentDrifts,omitempty"`
}

// Metrics returns the cumulative counters. recentLimit bounds the recent-drift
// list (0 = all retained).
func (s *Service) Metrics(recentLimit int) Stats {
	if s == nil {
		return Stats{}
	}
	snap := Stats{
		Enabled:              s.cfg.Enabled,
		Action:               string(s.cfg.Action),
		WarnThreshold:        s.cfg.WarnThreshold,
		BlockThreshold:       s.cfg.BlockThreshold,
		SignificantThreshold: s.cfg.SignificantThreshold,
		HistorySize:          s.cfg.HistorySize,
		Coordinates:          s.store.Len(),
		Observed:             s.observed.Load(),
		Compared:             s.compared.Load(),
		Significant:          s.significant.Load(),
		Warned:               s.warned.Load(),
		Blocked:              s.blocked.Load(),
		Quarantined:          s.quarantined.Load(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.driftByEco) > 0 {
		snap.DriftByEcosystem = make(map[string]int64, len(s.driftByEco))
		for k, v := range s.driftByEco {
			snap.DriftByEcosystem[k] = v
		}
	}
	recent := s.recentDrifts
	if recentLimit > 0 && len(recent) > recentLimit {
		recent = recent[len(recent)-recentLimit:]
	}
	if len(recent) > 0 {
		snap.RecentDrifts = make([]DriftRecord, len(recent))
		// Newest-first for the admin table.
		for i, r := range recent {
			snap.RecentDrifts[len(recent)-1-i] = r
		}
	}
	return snap
}

// Coordinates returns the tracked coordinates (admin listing).
func (s *Service) Coordinates(limit int) []CoordinateRef {
	if s == nil {
		return nil
	}
	return s.store.Coordinates(limit)
}

// EcosystemDrift returns the per-ecosystem significant-drift tallies sorted by
// ecosystem, for metric binding.
func (s *Service) EcosystemDrift() []struct {
	Ecosystem string
	Count     int64
} {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]struct {
		Ecosystem string
		Count     int64
	}, 0, len(s.driftByEco))
	for k, v := range s.driftByEco {
		out = append(out, struct {
			Ecosystem string
			Count     int64
		}{k, v})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out
}
