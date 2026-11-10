// Package depfirewall implements the dependency-firewall admission gate (Task
// 65): an explicit, auditable version-policy enforcer on the pull path. It is the
// enterprise control that turns the proxy into a guarantee that CI can only fetch
// versions an operator (or a committed lockfile) has approved.
//
// A tenant expresses policy as a set of Rules keyed by (ecosystem, coordinate).
// Each rule combines four orthogonal constraints, any of which may be present:
//
//   - Pinned   — an exact-version allowlist (the artifact's version must be one
//     of these spellings).
//   - Ranges   — semver range expressions the version must satisfy (e.g.
//     ">=1.2.0 <2.0.0", "^1.4.0").
//   - MinVersion — a minimum-version floor, to block known-bad earlier ranges.
//   - Denied   — an explicit denylist of exact versions that are always refused.
//
// Denied is evaluated first and always blocks. The positive constraints
// (Pinned/Ranges/MinVersion) are then ANDed: a version must satisfy every
// constraint that is present. A rule carrying only metadata (no constraints)
// admits any version of that coordinate — an explicit "this package is governed
// but currently unrestricted" statement.
//
// For coordinates with NO matching rule, the per-tenant DefaultAction decides:
// "allow" (the firewall enforces only explicit rules) or "block" (deny-by-default
// — only governed coordinates pass, the strict mode a tenant uses to pin its
// entire transitive graph from a lockfile). Tenant rules take precedence over
// global rules; a tenant with no policy falls back to the global policy.
//
// Rules can be imported wholesale from common lockfiles (package-lock.json,
// requirements.txt, go.sum, Cargo.lock) so a tenant can pin its exact resolved
// graph in one upload (see lockfile.go).
//
// The Service is self-contained (standard library only), concurrency-safe, and
// supports runtime rule mutation from the admin API. A nil *Service is a valid
// no-op gate, so call sites need no nil check.
package depfirewall

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Action is the disposition for a coordinate that has no matching rule.
type Action string

const (
	// ActionAllow admits any coordinate without a matching rule (the firewall
	// enforces only the explicit rules it has).
	ActionAllow Action = "allow"
	// ActionBlock refuses any coordinate without a matching rule (deny-by-default,
	// "lockfile is the allowlist" strict mode).
	ActionBlock Action = "block"
)

// Coordinate is the per-pull input the gate evaluates: a concrete
// (ecosystem, name, version). Version is empty for index/listing requests, which
// have no single artifact to gate and are always admitted.
type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

// Rule is the version policy for one (ecosystem, name) coordinate. The zero
// value (no constraints) governs the coordinate but restricts nothing.
type Rule struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Pinned     []string `json:"pinned,omitempty"`
	Ranges     []string `json:"ranges,omitempty"`
	MinVersion string   `json:"minVersion,omitempty"`
	Denied     []string `json:"denied,omitempty"`
	// Source records where the rule came from (config, admin, or a named lockfile)
	// for audit and admin display.
	Source string `json:"source,omitempty"`
	// Note is an optional operator annotation.
	Note string `json:"note,omitempty"`

	// parsedRanges is the compiled form of Ranges, populated by compile.
	parsedRanges []rangeSet
}

// compile validates and pre-parses the rule's ranges. It returns an error for a
// malformed range so a bad rule is rejected at load/import time.
func (r *Rule) compile() error {
	r.parsedRanges = r.parsedRanges[:0]
	for _, expr := range r.Ranges {
		rs, err := parseRange(expr)
		if err != nil {
			return fmt.Errorf("rule %s/%s: %w", r.Ecosystem, r.Name, err)
		}
		r.parsedRanges = append(r.parsedRanges, rs)
	}
	return nil
}

// Constrained reports whether the rule actually restricts versions (as opposed
// to merely declaring the coordinate governed).
func (r *Rule) Constrained() bool {
	return len(r.Pinned) > 0 || len(r.Ranges) > 0 || r.MinVersion != "" || len(r.Denied) > 0
}

// Decision is the outcome of Check. Only Blocked is load-bearing for the pull
// path; the remaining fields explain the verdict for the response body, audit
// log, notification, and admin view.
type Decision struct {
	// Blocked reports that the pull must be refused.
	Blocked bool
	// Allowed reports an explicit allow under a matching rule (informational).
	Allowed bool
	// Governed reports that a rule matched the coordinate.
	Governed bool
	// Code is a short machine-readable verdict code (see the violation* consts).
	Code string
	// Reason is a human-readable explanation.
	Reason string
	// RuleSource is the matched rule's Source (when Governed).
	RuleSource string
	// Allowed-set summary for actionable error messages.
	Pinned     []string
	Ranges     []string
	MinVersion string
}

// Violation codes surfaced in Decision.Code, the audit reason, and headers.
const (
	codeDenied       = "denied"       // version on the explicit denylist
	codeNotPinned    = "not-pinned"   // version not in the exact-pin allowlist
	codeOutOfRange   = "out-of-range" // version satisfies no allowed range
	codeBelowFloor   = "below-floor"  // version below the minimum-version floor
	codeUnparsable   = "unparsable"   // candidate version could not be parsed
	codeDefaultBlock = "not-governed" // no matching rule and default action is block
)

// TenantPolicy is one tenant's firewall configuration: a default action for
// ungoverned coordinates plus the rule set keyed by ruleKey(ecosystem, name).
type TenantPolicy struct {
	DefaultAction Action
	rules         map[string]*Rule
}

// Config configures the Service.
type Config struct {
	// DefaultAction applies to a coordinate with no matching rule when no tenant
	// override is set (default ActionAllow). Set ActionBlock for a globally strict
	// deny-by-default firewall.
	DefaultAction Action
	// Rules are the global (all-tenant) rules.
	Rules []Rule
	// Tenants holds per-tenant policy keyed by tenant id (team).
	Tenants map[string]TenantConfig
}

// TenantConfig is the configuration form of a tenant policy (rules as a slice).
type TenantConfig struct {
	// DefaultAction overrides the global default for this tenant. Empty inherits.
	DefaultAction Action
	// Rules are the tenant-scoped rules; they take precedence over global rules
	// for the same (ecosystem, name).
	Rules []Rule
}

// Service is the dependency-firewall admission gate.
type Service struct {
	mu            sync.RWMutex
	defaultAction Action
	global        map[string]*Rule
	tenants       map[string]*TenantPolicy

	// Cumulative counters (atomic so the hot path needs no lock for tallies).
	checks  atomic.Uint64
	blocks  atomic.Uint64
	allowed atomic.Uint64

	// Per-ecosystem and per-violation-code tallies, guarded by mu.
	byEco  map[string]*ecoCounters
	byCode map[string]uint64
}

type ecoCounters struct {
	checks  uint64
	blocked uint64
}

// NewService constructs a Service from cfg, compiling and validating every rule.
// It returns an error if any rule has a malformed range so a misconfigured
// firewall fails loudly rather than silently mis-enforcing.
func NewService(cfg Config) (*Service, error) {
	s := &Service{
		defaultAction: normalizeAction(cfg.DefaultAction, ActionAllow),
		global:        make(map[string]*Rule),
		tenants:       make(map[string]*TenantPolicy),
		byEco:         make(map[string]*ecoCounters),
		byCode:        make(map[string]uint64),
	}
	for i := range cfg.Rules {
		r := cfg.Rules[i]
		if err := s.putRuleLocked(s.global, &r); err != nil {
			return nil, err
		}
	}
	for id, tc := range cfg.Tenants {
		tp := &TenantPolicy{
			DefaultAction: normalizeAction(tc.DefaultAction, ""),
			rules:         make(map[string]*Rule),
		}
		for i := range tc.Rules {
			r := tc.Rules[i]
			if err := s.putRuleLocked(tp.rules, &r); err != nil {
				return nil, fmt.Errorf("tenant %q: %w", id, err)
			}
		}
		s.tenants[id] = tp
	}
	return s, nil
}

// Enabled reports whether the gate is wired. The admin/metrics surfaces use it.
func (s *Service) Enabled() bool { return s != nil }

// Check evaluates a coordinate for the given tenant and returns the firewall
// decision. A nil *Service or a version-less (listing) request always admits.
func (s *Service) Check(tenant string, c Coordinate) Decision {
	if s == nil {
		return Decision{}
	}
	c.Ecosystem = normalizeEco(c.Ecosystem)
	if c.Name == "" || c.Version == "" {
		// No concrete artifact to gate (an index/listing request).
		return Decision{}
	}

	s.checks.Add(1)
	s.mu.RLock()
	rule, defaultAction := s.lookupLocked(tenant, c)
	s.mu.RUnlock()
	s.incEcoChecks(c.Ecosystem)

	if rule == nil {
		if defaultAction == ActionBlock {
			d := Decision{
				Blocked: true,
				Code:    codeDefaultBlock,
				Reason:  fmt.Sprintf("no dependency-firewall rule approves %s/%s and the firewall is deny-by-default", c.Ecosystem, c.Name),
			}
			s.recordBlock(c.Ecosystem, d.Code)
			return d
		}
		return Decision{}
	}

	d := evaluate(c, rule)
	if d.Blocked {
		s.recordBlock(c.Ecosystem, d.Code)
	} else {
		s.allowed.Add(1)
	}
	return d
}

// evaluate applies a matched rule's constraints to a concrete coordinate.
func evaluate(c Coordinate, rule *Rule) Decision {
	base := Decision{
		Governed:   true,
		RuleSource: rule.Source,
		Pinned:     rule.Pinned,
		Ranges:     rule.Ranges,
		MinVersion: rule.MinVersion,
	}
	nv := normalizeVersion(c.Version)

	// 1. Explicit denylist always blocks, regardless of any positive constraint.
	for _, d := range rule.Denied {
		if normalizeVersion(d) == nv {
			base.Blocked = true
			base.Code = codeDenied
			base.Reason = fmt.Sprintf("version %s of %s/%s is on the dependency-firewall denylist", c.Version, c.Ecosystem, c.Name)
			return base
		}
	}

	parsed := parseVersion(c.Version)

	// 2. Exact-pin allowlist: the version must be one of the pinned spellings.
	if len(rule.Pinned) > 0 {
		matched := false
		for _, p := range rule.Pinned {
			if normalizeVersion(p) == nv {
				matched = true
				break
			}
		}
		if !matched {
			base.Blocked = true
			base.Code = codeNotPinned
			base.Reason = fmt.Sprintf("version %s of %s/%s is not in the pinned-version allowlist (%s)",
				c.Version, c.Ecosystem, c.Name, strings.Join(rule.Pinned, ", "))
			return base
		}
	}

	// 3. Allowed semver ranges: the version must satisfy at least one.
	if len(rule.parsedRanges) > 0 {
		if !parsed.valid {
			base.Blocked = true
			base.Code = codeUnparsable
			base.Reason = fmt.Sprintf("version %s of %s/%s could not be parsed for range evaluation", c.Version, c.Ecosystem, c.Name)
			return base
		}
		ok := false
		for _, rs := range rule.parsedRanges {
			if rs.satisfies(parsed) {
				ok = true
				break
			}
		}
		if !ok {
			base.Blocked = true
			base.Code = codeOutOfRange
			base.Reason = fmt.Sprintf("version %s of %s/%s satisfies no approved range (%s)",
				c.Version, c.Ecosystem, c.Name, strings.Join(rule.Ranges, " || "))
			return base
		}
	}

	// 4. Minimum-version floor: block known-bad earlier ranges.
	if rule.MinVersion != "" {
		floor := parseVersion(rule.MinVersion)
		if !parsed.valid {
			base.Blocked = true
			base.Code = codeUnparsable
			base.Reason = fmt.Sprintf("version %s of %s/%s could not be parsed against the minimum-version floor", c.Version, c.Ecosystem, c.Name)
			return base
		}
		if floor.valid && compareVer(parsed, floor) < 0 {
			base.Blocked = true
			base.Code = codeBelowFloor
			base.Reason = fmt.Sprintf("version %s of %s/%s is below the minimum-version floor %s",
				c.Version, c.Ecosystem, c.Name, rule.MinVersion)
			return base
		}
	}

	base.Allowed = true
	if rule.Constrained() {
		base.Reason = fmt.Sprintf("version %s of %s/%s is approved by the dependency firewall", c.Version, c.Ecosystem, c.Name)
	} else {
		base.Reason = fmt.Sprintf("%s/%s is governed by the dependency firewall with no version restriction", c.Ecosystem, c.Name)
	}
	return base
}

// lookupLocked resolves the matching rule and effective default action for a
// coordinate, with tenant rules taking precedence over global rules and the
// tenant default action overriding the global one. The caller holds (at least) a
// read lock.
func (s *Service) lookupLocked(tenant string, c Coordinate) (*Rule, Action) {
	key := ruleKey(c.Ecosystem, c.Name)
	defaultAction := s.defaultAction
	if tp, ok := s.tenants[tenant]; ok {
		if tp.DefaultAction != "" {
			defaultAction = tp.DefaultAction
		}
		if r, ok := tp.rules[key]; ok {
			return r, defaultAction
		}
	}
	if r, ok := s.global[key]; ok {
		return r, defaultAction
	}
	return nil, defaultAction
}

// putRuleLocked validates and inserts a rule into a rule map. The caller is
// responsible for synchronization (constructor under no contention, or holding
// s.mu for runtime mutation).
func (s *Service) putRuleLocked(m map[string]*Rule, r *Rule) error {
	r.Ecosystem = normalizeEco(r.Ecosystem)
	r.Name = strings.TrimSpace(r.Name)
	if r.Ecosystem == "" || r.Name == "" {
		return fmt.Errorf("dependency-firewall rule requires ecosystem and name")
	}
	if err := r.compile(); err != nil {
		return err
	}
	m[ruleKey(r.Ecosystem, r.Name)] = r
	return nil
}

func (s *Service) incEcoChecks(eco string) {
	s.mu.Lock()
	e := s.byEco[eco]
	if e == nil {
		e = &ecoCounters{}
		s.byEco[eco] = e
	}
	e.checks++
	s.mu.Unlock()
}

func (s *Service) recordBlock(eco, code string) {
	s.blocks.Add(1)
	s.mu.Lock()
	e := s.byEco[eco]
	if e == nil {
		e = &ecoCounters{}
		s.byEco[eco] = e
	}
	e.blocked++
	s.byCode[code]++
	s.mu.Unlock()
}

func normalizeAction(a, fallback Action) Action {
	switch Action(strings.ToLower(strings.TrimSpace(string(a)))) {
	case ActionAllow:
		return ActionAllow
	case ActionBlock:
		return ActionBlock
	default:
		return fallback
	}
}

func normalizeEco(eco string) string {
	return strings.ToLower(strings.TrimSpace(eco))
}

func ruleKey(eco, name string) string {
	return eco + "\x00" + strings.ToLower(name)
}

// sortRules orders rules by (ecosystem, name) for stable admin presentation.
func sortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Ecosystem != rules[j].Ecosystem {
			return rules[i].Ecosystem < rules[j].Ecosystem
		}
		return strings.ToLower(rules[i].Name) < strings.ToLower(rules[j].Name)
	})
}
