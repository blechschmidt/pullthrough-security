// Package remediation implements the automated dependency-remediation advisor
// (Task 121). Given a blocked or flagged artifact — one the proxy's admission
// gates refused or annotated because it is vulnerable, license-non-compliant,
// still within its release-cooldown window, or firewalled by a version-pinning
// rule — the advisor computes concrete, machine-checkable upgrade advice:
//
//   - the nearest safe upgrade version that clears every failing gate without
//     tripping a new one,
//   - the exact set of findings (CVEs/advisories, denied licenses, ...) that
//     version resolves relative to the flagged version,
//   - the residual findings the upgrade does NOT fix, and
//   - any new findings the upgrade would introduce.
//
// The advisor does not re-implement any gate logic. It pulls the candidate
// versions from the upstream registry via a pluggable VersionLister and scores
// each candidate through a pluggable Evaluator — the production Evaluator
// (see evaluator.go) simply fans a candidate coordinate out to the already-built
// vulnscan/VEX, license, release-cooldown, and dependency-firewall services and
// normalizes their verdicts into a gate-independent Finding set. This keeps the
// core advisor a pure, deterministic function of (version list, per-version
// findings), trivially unit-testable with scripted fakes, and guarantees the
// advice an operator sees is exactly what the live gates would decide.
//
// The result is emitted as structured JSON (the Advice type), rendered as a
// human-readable table (see markdown.go / Table), folded into the per-coordinate
// security dossier's "suggested fix" panel, and threaded into SARIF fix
// suggestions so a CI pull-request annotation can say not just "this is
// vulnerable" but "upgrade to X to fix it".
package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GateKind identifies the admission gate a finding originated from. The values
// line up with the proxy's findings-layer gate vocabulary so advice and SARIF
// annotations stay legible across subsystems.
type GateKind string

const (
	GateVuln        GateKind = "vulnscan"
	GateLicense     GateKind = "license"
	GateMaturity    GateKind = "maturity"
	GateDepFirewall GateKind = "depfirewall"
)

// Coordinate is a concrete, versioned package under evaluation.
type Coordinate struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// String renders the canonical "ecosystem/name@version" coordinate.
func (c Coordinate) String() string {
	var b strings.Builder
	if c.Ecosystem != "" {
		b.WriteString(c.Ecosystem)
		b.WriteByte('/')
	}
	b.WriteString(c.Name)
	if c.Version != "" {
		b.WriteByte('@')
		b.WriteString(c.Version)
	}
	return b.String()
}

// Finding is one normalized gate finding on a specific version. It is the
// gate-independent projection the advisor compares across versions: Gate+ID is
// its identity, Blocking records whether the finding would refuse admission (vs.
// merely warn), and the optional fields carry presentation detail.
type Finding struct {
	Gate     GateKind `json:"gate"`
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	Title    string   `json:"title,omitempty"`
	Blocking bool     `json:"blocking"`
	// FixedIn lists upstream versions that fix this finding, when the gate knows
	// them (vulnscan advisories carry fixed-version ranges). It is advisory only:
	// the advisor still verifies a candidate by evaluating it, never by trusting
	// a fixed-version claim.
	FixedIn []string `json:"fixedIn,omitempty"`
}

// key is the cross-version identity of a finding (gate + advisory/license/code),
// used for the resolved/residual/introduced set algebra.
func (f Finding) key() string { return string(f.Gate) + "\x00" + f.ID }

// CandidateResult is the evaluation of one version: every gate finding that
// version carries. A version with no Blocking finding (within the considered
// gates) is a safe upgrade target.
type CandidateResult struct {
	Coordinate Coordinate `json:"coordinate"`
	Findings   []Finding  `json:"findings,omitempty"`
}

// blocking returns the subset of findings that would refuse admission, limited
// to the gate set when non-empty.
func (r CandidateResult) blocking(gates gateSet) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if !f.Blocking {
			continue
		}
		if gates.active() && !gates.has(f.Gate) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Evaluator scores a candidate version by running it through the admission
// gates and returning the normalized findings. Implementations must be safe for
// concurrent use. The production implementation (GateEvaluator) fans out to the
// live gate services; tests inject a scripted fake.
type Evaluator interface {
	Evaluate(ctx context.Context, tenant string, c Coordinate) (CandidateResult, error)
}

// VersionLister returns the set of versions the upstream registry publishes for
// a package, newest-or-oldest order unimportant (the advisor sorts). A returned
// slice need not be filtered or sorted.
type VersionLister interface {
	Versions(ctx context.Context, ecosystem, name string) ([]string, error)
}

// Status is the machine token summarizing the advisor's conclusion.
type Status string

const (
	// StatusAlreadySafe: the flagged version carries no blocking finding within
	// the considered gates, so there is nothing to remediate.
	StatusAlreadySafe Status = "already-safe"
	// StatusSafeUpgrade: a safe upgrade target was found (see Recommendation).
	StatusSafeUpgrade Status = "safe-upgrade-found"
	// StatusNoSafeVersion: newer versions exist but none clears every failing
	// gate without introducing a new blocking finding.
	StatusNoSafeVersion Status = "no-safe-version"
	// StatusNoCandidates: the registry exposes no newer version to upgrade to.
	StatusNoCandidates Status = "no-candidates"
)

// Request parameterizes an advisory computation.
type Request struct {
	// Tenant scopes the tenant-aware gates (license, depfirewall, maturity).
	Tenant string
	// Ecosystem, Name, Version identify the flagged artifact to remediate.
	Ecosystem string
	Name      string
	Version   string
	// Gates restricts which gates are considered when deciding "safe"; empty
	// means all gates the evaluator reports. A caller remediating only a vuln
	// block, for instance, can pass {GateVuln} so a pre-existing (unrelated)
	// license warning does not veto an otherwise-clean upgrade.
	Gates []GateKind
	// MaxCandidates bounds how many newer versions are evaluated (newest-first is
	// NOT used — candidates are walked oldest-safe-first so the *nearest* safe
	// upgrade is found; the bound caps upstream/scan load). Zero uses the default.
	MaxCandidates int
	// IncludePrerelease considers prerelease versions (1.2.0-rc1) as candidates.
	// Off by default: production upgrades should target stable releases.
	IncludePrerelease bool
}

// Recommendation is the advisor's chosen upgrade target and its delta vs. the
// flagged version.
type Recommendation struct {
	Version    string `json:"version"`
	Coordinate string `json:"coordinate"`
	// Clean reports the target carries no findings at all (not merely no blocking
	// ones).
	Clean bool `json:"clean"`
	// ResolvedFindings are flagged-version findings the upgrade clears.
	ResolvedFindings []Finding `json:"resolvedFindings,omitempty"`
	// ResidualFindings are flagged-version findings still present at the target
	// (they persist across the upgrade).
	ResidualFindings []Finding `json:"residualFindings,omitempty"`
	// IntroducedFindings are findings new at the target (not present on the
	// flagged version). For a recommended (safe) target these are non-blocking by
	// construction, but they are surfaced so the operator sees the trade.
	IntroducedFindings []Finding `json:"introducedFindings,omitempty"`
	// FixDescription is the one-line human/SARIF remediation sentence.
	FixDescription string `json:"fixDescription"`
}

// Candidate is a per-version summary of every evaluated version, so an operator
// (or the what-if surface) can see the whole upgrade ladder, not just the pick.
type Candidate struct {
	Version    string    `json:"version"`
	Safe       bool      `json:"safe"`
	Blocking   int       `json:"blocking"`
	Total      int       `json:"total"`
	Resolved   []Finding `json:"resolved,omitempty"`
	Introduced []Finding `json:"introduced,omitempty"`
}

// Advice is the structured remediation verdict for one flagged artifact.
type Advice struct {
	Tenant             string          `json:"tenant,omitempty"`
	Ecosystem          string          `json:"ecosystem"`
	Name               string          `json:"name"`
	CurrentVersion     string          `json:"currentVersion"`
	Coordinate         string          `json:"coordinate"`
	Status             Status          `json:"status"`
	Summary            string          `json:"summary"`
	FailingGates       []GateKind      `json:"failingGates,omitempty"`
	CurrentFindings    []Finding       `json:"currentFindings,omitempty"`
	Recommendation     *Recommendation `json:"recommendation,omitempty"`
	Candidates         []Candidate     `json:"candidates,omitempty"`
	VersionsConsidered int             `json:"versionsConsidered"`
	GeneratedAt        time.Time       `json:"generatedAt"`
}

// defaultMaxCandidates bounds how many newer versions the advisor evaluates when
// a request does not specify its own limit. Each candidate may incur a live
// upstream fetch and scan, so the bound protects the registry and the advisor's
// latency; in practice the nearest safe upgrade is found within the first few.
const defaultMaxCandidates = 25

// Advisor computes remediation advice from a version list and a per-version
// gate evaluator. It owns no state beyond its injected collaborators and is safe
// for concurrent use.
type Advisor struct {
	lister  VersionLister
	eval    Evaluator
	maxCand int
	now     func() time.Time
}

// Option customizes an Advisor.
type Option func(*Advisor)

// WithMaxCandidates sets the default candidate bound (a Request may still
// override it). A non-positive value is ignored.
func WithMaxCandidates(n int) Option {
	return func(a *Advisor) {
		if n > 0 {
			a.maxCand = n
		}
	}
}

// WithClock injects the clock (for deterministic tests).
func WithClock(now func() time.Time) Option {
	return func(a *Advisor) {
		if now != nil {
			a.now = now
		}
	}
}

// NewAdvisor constructs an Advisor over a version lister and a gate evaluator.
// Both are required; a nil collaborator makes Advise return an error rather than
// panic, so a half-wired deployment degrades to a clear 503 rather than a crash.
func NewAdvisor(lister VersionLister, eval Evaluator, opts ...Option) *Advisor {
	a := &Advisor{lister: lister, eval: eval, maxCand: defaultMaxCandidates, now: time.Now}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Advise computes the remediation advice for the flagged artifact described by
// req. It evaluates the flagged version to establish the baseline findings,
// pulls and orders the upstream version list, then walks the newer versions from
// nearest to furthest, evaluating each until it finds the first that clears every
// failing gate without introducing a new blocking finding. Every evaluated
// version is summarized in Candidates so the full upgrade ladder is visible.
func (a *Advisor) Advise(ctx context.Context, req Request) (*Advice, error) {
	if a == nil || a.lister == nil || a.eval == nil {
		return nil, fmt.Errorf("remediation: advisor is not fully configured")
	}
	eco := strings.TrimSpace(req.Ecosystem)
	name := strings.TrimSpace(req.Name)
	version := strings.TrimSpace(req.Version)
	if eco == "" || name == "" {
		return nil, fmt.Errorf("remediation: ecosystem and name are required")
	}
	if version == "" {
		return nil, fmt.Errorf("remediation: the flagged version is required")
	}
	gates := newGateSet(req.Gates)
	maxCand := req.MaxCandidates
	if maxCand <= 0 {
		maxCand = a.maxCand
	}

	current := Coordinate{Ecosystem: eco, Name: name, Version: version}
	adv := &Advice{
		Tenant:         req.Tenant,
		Ecosystem:      eco,
		Name:           name,
		CurrentVersion: version,
		Coordinate:     current.String(),
		GeneratedAt:    a.now().UTC(),
	}

	// Baseline: evaluate the flagged version so the resolved/residual delta is
	// computed against what the gates actually say today, not a stale verdict.
	baseRes, err := a.eval.Evaluate(ctx, req.Tenant, current)
	if err != nil {
		return nil, fmt.Errorf("remediation: evaluating flagged version %s: %w", current, err)
	}
	adv.CurrentFindings = baseRes.Findings
	baseBlocking := baseRes.blocking(gates)
	adv.FailingGates = failingGates(baseBlocking)

	if len(baseBlocking) == 0 {
		adv.Status = StatusAlreadySafe
		adv.Summary = fmt.Sprintf("%s has no blocking findings; no upgrade is required.", current)
		return adv, nil
	}

	// Pull and order the upstream version ladder above the flagged version.
	all, err := a.lister.Versions(ctx, eco, name)
	if err != nil {
		return nil, fmt.Errorf("remediation: listing versions for %s/%s: %w", eco, name, err)
	}
	candidates := newerVersions(all, version, req.IncludePrerelease)
	if len(candidates) > maxCand {
		candidates = candidates[:maxCand]
	}
	if len(candidates) == 0 {
		adv.Status = StatusNoCandidates
		adv.Summary = fmt.Sprintf("%s is blocked by %s but the registry exposes no newer version to upgrade to.",
			current, gateList(adv.FailingGates))
		return adv, nil
	}

	baseKeys := findingKeys(baseRes.Findings)
	for _, cv := range candidates {
		cand := Coordinate{Ecosystem: eco, Name: name, Version: cv}
		res, err := a.eval.Evaluate(ctx, req.Tenant, cand)
		if err != nil {
			// A single candidate's evaluation failure (transient upstream error)
			// must not abort the whole advisory: record it as an opaque candidate
			// and keep walking. The operator still gets advice for the rest.
			adv.Candidates = append(adv.Candidates, Candidate{Version: cv, Safe: false})
			adv.VersionsConsidered++
			continue
		}
		adv.VersionsConsidered++
		blocking := res.blocking(gates)
		resolved, _, introduced := diffFindings(baseKeys, baseRes.Findings, res.Findings)
		adv.Candidates = append(adv.Candidates, Candidate{
			Version:    cv,
			Safe:       len(blocking) == 0,
			Blocking:   len(blocking),
			Total:      len(res.Findings),
			Resolved:   resolved,
			Introduced: introduced,
		})
		if len(blocking) == 0 && adv.Recommendation == nil {
			adv.Recommendation = a.buildRecommendation(current, cand, baseRes.Findings, res.Findings, baseBlocking)
			// Nearest safe upgrade found. We still finish summarizing the already
			// evaluated candidates (the loop simply won't evaluate further ones).
			break
		}
	}

	if adv.Recommendation != nil {
		adv.Status = StatusSafeUpgrade
		adv.Summary = adv.Recommendation.FixDescription
	} else {
		adv.Status = StatusNoSafeVersion
		adv.Summary = fmt.Sprintf("%s is blocked by %s; none of the %d newer version(s) evaluated clears every failing gate.",
			current, gateList(adv.FailingGates), adv.VersionsConsidered)
	}
	return adv, nil
}

// buildRecommendation assembles the Recommendation for a chosen safe target,
// computing the resolved/residual/introduced deltas and the human/SARIF fix
// sentence.
func (a *Advisor) buildRecommendation(current, target Coordinate, baseFindings, targetFindings, baseBlocking []Finding) *Recommendation {
	baseKeys := findingKeys(baseFindings)
	resolved, residual, introduced := diffFindings(baseKeys, baseFindings, targetFindings)
	rec := &Recommendation{
		Version:            target.Version,
		Coordinate:         target.String(),
		Clean:              len(targetFindings) == 0,
		ResolvedFindings:   resolved,
		ResidualFindings:   residual,
		IntroducedFindings: introduced,
	}
	rec.FixDescription = fixSentence(current, target, baseBlocking, resolved, introduced)
	return rec
}

// --- finding set algebra -----------------------------------------------------

// findingKeys indexes a finding slice by cross-version key.
func findingKeys(fs []Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.key()] = true
	}
	return m
}

// diffFindings partitions the base/target finding sets into:
//   - resolved:   present on base, absent on target (the upgrade clears them),
//   - residual:   present on both (persist across the upgrade),
//   - introduced: present on target, absent on base (new at the target).
//
// Order follows the input slices so output is deterministic.
func diffFindings(baseKeys map[string]bool, base, target []Finding) (resolved, residual, introduced []Finding) {
	targetKeys := findingKeys(target)
	for _, f := range base {
		if targetKeys[f.key()] {
			residual = append(residual, f)
		} else {
			resolved = append(resolved, f)
		}
	}
	for _, f := range target {
		if !baseKeys[f.key()] {
			introduced = append(introduced, f)
		}
	}
	return resolved, residual, introduced
}

// failingGates returns the sorted, de-duplicated set of gates that produced a
// blocking finding.
func failingGates(blocking []Finding) []GateKind {
	seen := map[GateKind]bool{}
	var out []GateKind
	for _, f := range blocking {
		if !seen[f.Gate] {
			seen[f.Gate] = true
			out = append(out, f.Gate)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// gateList renders a gate set for a human sentence.
func gateList(gates []GateKind) string {
	if len(gates) == 0 {
		return "an admission gate"
	}
	parts := make([]string, len(gates))
	for i, g := range gates {
		parts[i] = string(g)
	}
	return strings.Join(parts, "+")
}

// fixSentence composes the one-line remediation statement surfaced in the table,
// the dossier panel, and the SARIF fix description.
func fixSentence(current, target Coordinate, baseBlocking, resolved, introduced []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Upgrade %s/%s from %s to %s", current.Ecosystem, current.Name, current.Version, target.Version)
	if ids := blockingResolvedIDs(baseBlocking, resolved); len(ids) > 0 {
		fmt.Fprintf(&b, " to resolve %s", strings.Join(ids, ", "))
	} else {
		b.WriteString(" to clear the failing gate(s)")
	}
	if len(introduced) > 0 {
		fmt.Fprintf(&b, " (introduces %d new non-blocking finding(s))", len(introduced))
	}
	b.WriteByte('.')
	return b.String()
}

// blockingResolvedIDs lists the identifiers of the originally-blocking findings
// the upgrade resolves, so the fix sentence names the CVEs/licenses it fixes.
func blockingResolvedIDs(baseBlocking, resolved []Finding) []string {
	resolvedKeys := findingKeys(resolved)
	var ids []string
	seen := map[string]bool{}
	for _, f := range baseBlocking {
		if resolvedKeys[f.key()] && f.ID != "" && !seen[f.ID] {
			seen[f.ID] = true
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// --- gate set ----------------------------------------------------------------

// gateSet is the optional restriction of considered gates.
type gateSet map[GateKind]bool

func newGateSet(gates []GateKind) gateSet {
	if len(gates) == 0 {
		return nil
	}
	s := make(gateSet, len(gates))
	for _, g := range gates {
		s[g] = true
	}
	return s
}

func (s gateSet) active() bool        { return len(s) > 0 }
func (s gateSet) has(g GateKind) bool { return s[g] }
