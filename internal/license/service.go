package license

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// Config configures the license-compliance Service: a base policy applied to all
// tenants, optional per-tenant override policies, and license-drift detection.
type Config struct {
	// Base is the default policy applied to every tenant (and to anonymous /
	// unmapped requests).
	Base PolicyConfig
	// Tenants maps a tenant identifier (the authenticated principal's team) to an
	// override policy. An override is merged onto the base: its allow/deny/review/
	// exception lists are unioned with the base's, and any non-empty scalar field
	// (unknown/default/action/reviewAction/driftAction) replaces the base value.
	// This expresses requirements like "deny the GPL family only for proprietary
	// tenants" without restating the whole policy.
	Tenants map[string]PolicyConfig
	// DriftDetection enables cross-version license-drift tracking.
	DriftDetection bool
	// DriftMaxEvents bounds how many recent drift events are retained for the admin
	// surface (0 = default 256).
	DriftMaxEvents int
	// RecentMax bounds how many recent non-allow decisions are retained for the
	// admin surface (0 = default 256).
	RecentMax int
}

// Component is the unit the gate evaluates: a concrete versioned package (or the
// primary artifact) and its declared SPDX license expression. Expression is empty
// when the artifact declared no license (NOASSERTION).
type Component struct {
	Ecosystem  string
	Name       string
	Version    string
	Expression string
	// Primary marks the artifact being pulled (as opposed to a transitively
	// declared dependency). Drift is tracked only for primary components, whose
	// versions the proxy actually observes end-to-end.
	Primary bool
}

// Coordinate renders a "name@version" string for a component.
func (c Component) Coordinate() string {
	switch {
	case c.Name != "" && c.Version != "":
		return c.Name + "@" + c.Version
	case c.Name != "":
		return c.Name
	default:
		return c.Expression
	}
}

// Finding is a single component-level license issue (or drift signal) contributing
// to a decision.
type Finding struct {
	Component   string   `json:"component"`
	Expression  string   `json:"expression,omitempty"`
	Outcome     string   `json:"outcome"`
	License     string   `json:"license,omitempty"`
	Category    string   `json:"category,omitempty"`
	Exception   string   `json:"exception,omitempty"`
	Drift       bool     `json:"drift,omitempty"`
	FromLicense string   `json:"fromLicense,omitempty"`
	FromVersion string   `json:"fromVersion,omitempty"`
	Reason      string   `json:"reason"`
	Licenses    []string `json:"licenses,omitempty"`
}

// Decision is the admission outcome for an artifact's license set.
type Decision struct {
	Action   policy.Action `json:"action"`
	Code     string        `json:"code"` // ok|denied|review|unknown|drift
	Reason   string        `json:"reason"`
	Tenant   string        `json:"tenant,omitempty"`
	Findings []Finding     `json:"findings,omitempty"`
	// Worst is the most severe per-component outcome that drove the decision.
	Worst Outcome `json:"-"`
}

// Allowed reports whether the decision permits serving without an enforced block.
func (d Decision) Allowed() bool { return !d.Action.Blocked() }

// DecisionRecord is a retained recent decision for the admin surface.
type DecisionRecord struct {
	Time     time.Time     `json:"time"`
	Tenant   string        `json:"tenant,omitempty"`
	Action   policy.Action `json:"action"`
	Code     string        `json:"code"`
	Reason   string        `json:"reason"`
	Findings []Finding     `json:"findings,omitempty"`
}

// Snapshot is a point-in-time view of the subsystem's cumulative counters.
type Snapshot struct {
	Evaluated       int64            `json:"evaluated"`
	Allowed         int64            `json:"allowed"`
	Denied          int64            `json:"denied"`
	Flagged         int64            `json:"flagged"`
	UnknownTotal    int64            `json:"unknownTotal"`
	DriftDetected   int64            `json:"driftDetected"`
	DeniedByLicense map[string]int64 `json:"deniedByLicense,omitempty"`
	Tenants         int              `json:"tenants"`
	DriftEvents     int              `json:"driftEvents"`
}

// Service is the license-compliance gate. It is safe for concurrent use.
type Service struct {
	base    compiledPolicy
	tenants map[string]compiledPolicy
	drift   *driftTracker
	logger  *slog.Logger
	now     func() time.Time

	// policySummary is a static description of the effective policy for the admin
	// surface, computed once at construction.
	summary PolicySummary

	recentMu  sync.Mutex
	recent    []DecisionRecord
	recentMax int

	counters struct {
		evaluated     atomic.Int64
		allowed       atomic.Int64
		denied        atomic.Int64
		flagged       atomic.Int64
		unknownTotal  atomic.Int64
		driftDetected atomic.Int64
	}
	deniedMu        sync.Mutex
	deniedByLicense map[string]int64
}

// NewService validates the configuration and constructs a Service.
func NewService(cfg Config, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	base, err := compilePolicy(cfg.Base)
	if err != nil {
		return nil, err
	}
	tenants := make(map[string]compiledPolicy, len(cfg.Tenants))
	for name, override := range cfg.Tenants {
		key := strings.TrimSpace(name)
		if key == "" {
			return nil, fmt.Errorf("license: a tenant override has an empty name")
		}
		merged := mergeConfig(cfg.Base, override)
		cp, err := compilePolicy(merged)
		if err != nil {
			return nil, fmt.Errorf("license: tenant %q: %w", key, err)
		}
		tenants[key] = cp
	}

	recentMax := cfg.RecentMax
	if recentMax <= 0 {
		recentMax = 256
	}

	s := &Service{
		base:            base,
		tenants:         tenants,
		logger:          logger,
		now:             time.Now,
		recentMax:       recentMax,
		deniedByLicense: map[string]int64{},
	}
	if cfg.DriftDetection {
		s.drift = newDriftTracker(cfg.DriftMaxEvents)
	}
	s.summary = buildPolicySummary(cfg)
	return s, nil
}

// mergeConfig produces a tenant's effective policy by overlaying an override on
// the base: lists are unioned (preserving order, dropping duplicates) and any
// non-empty scalar field on the override replaces the base value.
func mergeConfig(base, override PolicyConfig) PolicyConfig {
	out := PolicyConfig{
		Allow:           unionAppend(base.Allow, override.Allow),
		Deny:            unionAppend(base.Deny, override.Deny),
		Review:          unionAppend(base.Review, override.Review),
		AllowExceptions: unionAppend(base.AllowExceptions, override.AllowExceptions),
		Unknown:         base.Unknown,
		Default:         base.Default,
		Action:          base.Action,
		ReviewAction:    base.ReviewAction,
		DriftAction:     base.DriftAction,
	}
	if v := strings.TrimSpace(override.Unknown); v != "" {
		out.Unknown = v
	}
	if v := strings.TrimSpace(override.Default); v != "" {
		out.Default = v
	}
	if v := strings.TrimSpace(override.Action); v != "" {
		out.Action = v
	}
	if v := strings.TrimSpace(override.ReviewAction); v != "" {
		out.ReviewAction = v
	}
	if v := strings.TrimSpace(override.DriftAction); v != "" {
		out.DriftAction = v
	}
	return out
}

// unionAppend appends the entries of b not already present (case-insensitively)
// in a, returning a new slice.
func unionAppend(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, e := range list {
			t := strings.TrimSpace(e)
			if t == "" {
				continue
			}
			k := strings.ToLower(t)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, t)
		}
	}
	return out
}

// policyFor resolves the effective compiled policy for a tenant, falling back to
// the base policy when the tenant has no override.
func (s *Service) policyFor(tenant string) compiledPolicy {
	if cp, ok := s.tenants[strings.TrimSpace(tenant)]; ok {
		return cp
	}
	return s.base
}

// Disposition classifies a single SPDX license expression under the tenant's
// effective policy and returns "allowed", "review", "denied", or "unknown". It is
// a read-only classification: unlike Evaluate it records no metrics, no drift, and
// no recent-decision history, so a caller (e.g. the SBOM-diff subsystem's
// newly-introduced-license cross-reference, Task 64) can classify many licenses
// without polluting the gate's evaluation counters. A nil service or empty
// expression returns "".
func (s *Service) Disposition(tenant, expression string) string {
	if s == nil {
		return ""
	}
	expr := strings.TrimSpace(expression)
	if expr == "" {
		return ""
	}
	le := s.evalComponent(s.policyFor(tenant), expr)
	return le.outcome.String()
}

// Evaluate assesses a tenant's set of license-bearing components and returns the
// admission decision. It records drift for primary components, advances the
// cumulative counters, and retains non-allow decisions for the admin surface.
func (s *Service) Evaluate(tenant string, comps []Component) Decision {
	if s == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok"}
	}
	pol := s.policyFor(tenant)
	s.counters.evaluated.Add(1)

	worst := OutcomeAllowed
	var worstLeaf leafEval
	var findings []Finding
	driftSeen := false

	for _, c := range comps {
		expr := strings.TrimSpace(c.Expression)
		le := s.evalComponent(pol, expr)

		// License drift (primary components only).
		var ev DriftEvent
		hasDrift := false
		if s.drift != nil && c.Primary {
			ev, hasDrift = s.drift.observe(c.Ecosystem, c.Name, c.Version, normalizeLicense(expr), s.now())
			if hasDrift {
				driftSeen = true
				s.counters.driftDetected.Add(1)
			}
		}

		if le.outcome == OutcomeUnknown {
			s.counters.unknownTotal.Add(1)
		}
		if le.outcome == OutcomeDenied {
			s.incDenied(le.license)
		}
		if le.outcome > worst {
			worst = le.outcome
			worstLeaf = le
		}

		if le.outcome != OutcomeAllowed || hasDrift {
			findings = append(findings, buildFinding(c, expr, le, hasDrift, ev))
		}
	}

	action := pol.actionFor(worst)
	code := codeFor(worst)
	reason := reasonFor(worst, worstLeaf, len(comps))

	if driftSeen {
		action = mostSevere(action, pol.drift)
		if code == "ok" {
			code = "drift"
			reason = driftReason(findings)
		}
	}

	d := Decision{
		Action:   action,
		Code:     code,
		Reason:   reason,
		Tenant:   strings.TrimSpace(tenant),
		Findings: findings,
		Worst:    worst,
	}
	s.account(d)
	return d
}

// evalComponent evaluates one component's expression string, mapping an empty or
// unparsable expression to the policy's unknown disposition.
func (s *Service) evalComponent(pol compiledPolicy, expr string) leafEval {
	if expr == "" {
		return leafEval{outcome: pol.unknown, license: "NOASSERTION", category: CategoryUnknown}
	}
	parsed, err := ParseExpression(expr)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("license: unparsable SPDX expression treated as unknown", "expression", expr, "error", err)
		}
		return leafEval{outcome: pol.unknown, license: expr, category: CategoryUnknown}
	}
	return pol.evaluate(parsed.root)
}

// account advances the cumulative decision counters and retains the record.
func (s *Service) account(d Decision) {
	switch {
	case d.Action.Blocked():
		s.counters.denied.Add(1)
	case d.Code == "ok":
		s.counters.allowed.Add(1)
	default:
		s.counters.flagged.Add(1)
	}
	if d.Code != "ok" {
		s.retain(d)
	}
}

// retain stores a recent non-allow decision (bounded ring) for the admin surface.
func (s *Service) retain(d Decision) {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	s.recent = append(s.recent, DecisionRecord{
		Time:     s.now(),
		Tenant:   d.Tenant,
		Action:   d.Action,
		Code:     d.Code,
		Reason:   d.Reason,
		Findings: d.Findings,
	})
	if len(s.recent) > s.recentMax {
		s.recent = s.recent[len(s.recent)-s.recentMax:]
	}
}

// incDenied advances the per-license denied counter.
func (s *Service) incDenied(license string) {
	if license == "" {
		license = "NOASSERTION"
	}
	s.deniedMu.Lock()
	s.deniedByLicense[license]++
	s.deniedMu.Unlock()
}

// --- finding / reason construction -----------------------------------------

func buildFinding(c Component, expr string, le leafEval, drift bool, ev DriftEvent) Finding {
	f := Finding{
		Component:  c.Coordinate(),
		Expression: expr,
		Outcome:    le.outcome.String(),
		License:    le.license,
		Exception:  le.exception,
		Drift:      drift,
	}
	if le.category != "" && le.category != CategoryUnknown {
		f.Category = string(le.category)
	}
	if parsed, err := ParseExpression(expr); err == nil {
		f.Licenses = parsed.Licenses()
	}
	if drift {
		f.FromLicense = ev.FromLicense
		f.FromVersion = ev.FromVersion
	}
	f.Reason = findingReason(c, le, drift, ev)
	return f
}

func findingReason(c Component, le leafEval, drift bool, ev DriftEvent) string {
	var parts []string
	switch le.outcome {
	case OutcomeDenied:
		cat := ""
		if le.category != "" && le.category != CategoryUnknown {
			cat = " (" + string(le.category) + ")"
		}
		parts = append(parts, fmt.Sprintf("license %s%s is denied by policy", le.license, cat))
	case OutcomeReview:
		parts = append(parts, fmt.Sprintf("license %s requires manual review", le.license))
	case OutcomeUnknown:
		parts = append(parts, fmt.Sprintf("license %q is unknown/unrecognized (NOASSERTION) and requires review", le.license))
	}
	if drift {
		parts = append(parts, fmt.Sprintf("license drift: %s changed from %s (%s) to %s (%s)",
			c.Name, ev.FromLicense, ev.FromVersion, ev.ToLicense, ev.ToVersion))
	}
	return strings.Join(parts, "; ")
}

func codeFor(o Outcome) string {
	switch o {
	case OutcomeDenied:
		return "denied"
	case OutcomeReview:
		return "review"
	case OutcomeUnknown:
		return "unknown"
	default:
		return "ok"
	}
}

func reasonFor(o Outcome, le leafEval, n int) string {
	switch o {
	case OutcomeDenied:
		cat := ""
		if le.category != "" && le.category != CategoryUnknown {
			cat = " (" + string(le.category) + ")"
		}
		return fmt.Sprintf("artifact denied by license policy: %s%s is on the deny list", le.license, cat)
	case OutcomeReview:
		return fmt.Sprintf("artifact flagged for license review: %s requires manual approval", le.license)
	case OutcomeUnknown:
		return fmt.Sprintf("artifact flagged: license %q is unknown/NOASSERTION and requires review", le.license)
	default:
		return fmt.Sprintf("license compliant (%d component license(s) evaluated)", n)
	}
}

func driftReason(findings []Finding) string {
	for _, f := range findings {
		if f.Drift {
			return fmt.Sprintf("license drift detected: %s license changed from %s (%s) to %s — possible supply-chain risk",
				f.Component, f.FromLicense, f.FromVersion, f.License)
		}
	}
	return "license drift detected — possible supply-chain risk"
}

// mostSevere returns the more restrictive of two actions
// (allow < warn < block < quarantine).
func mostSevere(a, b policy.Action) policy.Action {
	if actionRank(b) > actionRank(a) {
		return b
	}
	return a
}

func actionRank(a policy.Action) int {
	switch a {
	case policy.ActionQuarantine:
		return 3
	case policy.ActionBlock:
		return 2
	case policy.ActionWarn:
		return 1
	default:
		return 0
	}
}

// --- admin / metrics surface -----------------------------------------------

// Metrics returns a snapshot of the cumulative counters.
func (s *Service) Metrics() Snapshot {
	s.deniedMu.Lock()
	byLic := make(map[string]int64, len(s.deniedByLicense))
	for k, v := range s.deniedByLicense {
		byLic[k] = v
	}
	s.deniedMu.Unlock()

	driftEvents := 0
	if s.drift != nil {
		driftEvents = len(s.drift.recentEvents())
	}
	return Snapshot{
		Evaluated:       s.counters.evaluated.Load(),
		Allowed:         s.counters.allowed.Load(),
		Denied:          s.counters.denied.Load(),
		Flagged:         s.counters.flagged.Load(),
		UnknownTotal:    s.counters.unknownTotal.Load(),
		DriftDetected:   s.counters.driftDetected.Load(),
		DeniedByLicense: byLic,
		Tenants:         len(s.tenants),
		DriftEvents:     driftEvents,
	}
}

// Drifts returns the retained license-drift events, most recent first.
func (s *Service) Drifts() []DriftEvent {
	if s.drift == nil {
		return nil
	}
	return s.drift.recentEvents()
}

// RecentDecisions returns the retained non-allow decisions, most recent first.
func (s *Service) RecentDecisions() []DecisionRecord {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	out := make([]DecisionRecord, len(s.recent))
	for i, r := range s.recent {
		out[len(s.recent)-1-i] = r
	}
	return out
}

// DriftEnabled reports whether license-drift tracking is active.
func (s *Service) DriftEnabled() bool { return s.drift != nil }

// PolicySummary returns the static policy description for the admin surface.
func (s *Service) Summary() PolicySummary { return s.summary }

// PolicySummary is a read-only description of the effective license policy for
// the admin/observability surfaces.
type PolicySummary struct {
	Allow           []string                 `json:"allow,omitempty"`
	Deny            []string                 `json:"deny,omitempty"`
	Review          []string                 `json:"review,omitempty"`
	AllowExceptions []string                 `json:"allowExceptions,omitempty"`
	Unknown         string                   `json:"unknown"`
	Default         string                   `json:"default"`
	Action          string                   `json:"action"`
	ReviewAction    string                   `json:"reviewAction"`
	DriftAction     string                   `json:"driftAction"`
	DriftDetection  bool                     `json:"driftDetection"`
	Tenants         map[string]TenantSummary `json:"tenants,omitempty"`
}

// TenantSummary describes a tenant override's distinguishing entries.
type TenantSummary struct {
	Allow  []string `json:"allow,omitempty"`
	Deny   []string `json:"deny,omitempty"`
	Review []string `json:"review,omitempty"`
	Action string   `json:"action,omitempty"`
}

func buildPolicySummary(cfg Config) PolicySummary {
	norm := func(s, def string) string {
		if strings.TrimSpace(s) == "" {
			return def
		}
		return strings.ToLower(strings.TrimSpace(s))
	}
	sum := PolicySummary{
		Allow:           append([]string(nil), cfg.Base.Allow...),
		Deny:            append([]string(nil), cfg.Base.Deny...),
		Review:          append([]string(nil), cfg.Base.Review...),
		AllowExceptions: append([]string(nil), cfg.Base.AllowExceptions...),
		Unknown:         norm(cfg.Base.Unknown, "review"),
		Default:         norm(cfg.Base.Default, "allow"),
		Action:          norm(cfg.Base.Action, "block"),
		ReviewAction:    norm(cfg.Base.ReviewAction, "warn"),
		DriftAction:     norm(cfg.Base.DriftAction, "warn"),
		DriftDetection:  cfg.DriftDetection,
	}
	if len(cfg.Tenants) > 0 {
		sum.Tenants = make(map[string]TenantSummary, len(cfg.Tenants))
		names := make([]string, 0, len(cfg.Tenants))
		for name := range cfg.Tenants {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ov := cfg.Tenants[name]
			sum.Tenants[name] = TenantSummary{
				Allow:  append([]string(nil), ov.Allow...),
				Deny:   append([]string(nil), ov.Deny...),
				Review: append([]string(nil), ov.Review...),
				Action: strings.ToLower(strings.TrimSpace(ov.Action)),
			}
		}
	}
	return sum
}
