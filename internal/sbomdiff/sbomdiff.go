// Package sbomdiff computes a structured, explainable diff between two versions
// of the same package coordinate using the CycloneDX SBOMs the vulnerability and
// findings subsystems already produce (Task 64).
//
// For a given (tenant, ecosystem, coordinate) it answers the supply-chain
// question "what changed between version A and version B?":
//
//   - the transitive dependency set delta — added, removed, and version-bumped
//     dependencies;
//   - newly-introduced licenses (cross-referenced against the license-compliance
//     policy so a freshly-pulled GPL dependency is surfaced, not just any new
//     license);
//   - newly-introduced namespaces/maintainers (the organisation or scope a
//     dependency belongs to — a strong signal of a dependency-confusion or
//     hijack attempt when a quiet package suddenly depends on a never-before-seen
//     org);
//   - net-new vulnerabilities (advisories affecting version B that did not affect
//     version A, taken from the already-computed scan reports — no re-scan).
//
// From those deltas it derives a single explainable "drift risk" score so a
// quiet, well-behaved package that suddenly pulls in a large or suspicious new
// dependency footprint can be flagged or quarantined.
//
// The package re-uses the existing SBOM extraction (internal/vulnscan) and never
// re-implements a manifest parser; it is otherwise dependency-light (it imports
// internal/policy for the admission Action type) and fully deterministic so its
// output can be golden-tested and rendered into a stable report.
package sbomdiff

import (
	"sort"
	"strings"
	"time"
)

// Dep is a single dependency component captured from an artifact's SBOM. It is
// the unit the dependency-set diff operates on. Name is the fully-qualified
// component name (group/name when the ecosystem namespaces components); Namespace
// is the owning organisation/scope used for the maintainer/namespace diff.
type Dep struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	License   string `json:"license,omitempty"`
	Scope     string `json:"scope,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// key is the identity of a dependency for set comparison: its name, independent
// of version, lowercased so a case-only difference is not a spurious add/remove.
func (d Dep) key() string { return strings.ToLower(strings.TrimSpace(d.Name)) }

// VulnRef is a minimal reference to a vulnerability affecting an artifact,
// captured from a scan report so a later diff can compute the net-new set without
// re-scanning.
type VulnRef struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity,omitempty"`
	Package  string  `json:"package,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
}

// Snapshot is the resolved SBOM of one version of a coordinate, reduced to the
// fields the diff needs. It is what the per-coordinate history store persists.
type Snapshot struct {
	Tenant     string    `json:"tenant,omitempty"`
	Ecosystem  string    `json:"ecosystem"`
	Coordinate string    `json:"coordinate"`
	Version    string    `json:"version"`
	Digest     string    `json:"digest,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
	// PrimaryLicense is the artifact's own declared SPDX license expression.
	PrimaryLicense string `json:"primaryLicense,omitempty"`
	// Deps are the transitive dependency components, sorted by key.
	Deps []Dep `json:"deps"`
	// Vulns are the advisories affecting this version at observation time, sorted
	// by id.
	Vulns []VulnRef `json:"vulns,omitempty"`
}

// normalize canonicalizes a snapshot in place: it trims and sorts the dependency
// and vulnerability slices so two snapshots of the same content compare equal and
// the diff is deterministic regardless of SBOM component order.
func (s *Snapshot) normalize() {
	s.Ecosystem = strings.ToLower(strings.TrimSpace(s.Ecosystem))
	s.Coordinate = strings.TrimSpace(s.Coordinate)
	s.Version = strings.TrimSpace(s.Version)
	sort.SliceStable(s.Deps, func(i, j int) bool {
		if s.Deps[i].key() != s.Deps[j].key() {
			return s.Deps[i].key() < s.Deps[j].key()
		}
		return s.Deps[i].Version < s.Deps[j].Version
	})
	sort.SliceStable(s.Vulns, func(i, j int) bool {
		return s.Vulns[i].ID < s.Vulns[j].ID
	})
}

// depIndex builds a name→Dep lookup for set comparison. When an SBOM lists the
// same dependency name twice (an unusual but possible shape) the first entry
// wins, which is stable after normalize sorted by (key, version).
func (s Snapshot) depIndex() map[string]Dep {
	m := make(map[string]Dep, len(s.Deps))
	for _, d := range s.Deps {
		if _, ok := m[d.key()]; !ok {
			m[d.key()] = d
		}
	}
	return m
}

// namespaceSet returns the distinct (lowercased) namespaces present across a
// snapshot's dependencies.
func (s Snapshot) namespaceSet() map[string]string {
	m := make(map[string]string)
	for _, d := range s.Deps {
		ns := strings.TrimSpace(d.Namespace)
		if ns == "" {
			continue
		}
		m[strings.ToLower(ns)] = ns
	}
	return m
}

// vulnSet returns the distinct (uppercased) advisory ids present in a snapshot.
func (s Snapshot) vulnSet() map[string]VulnRef {
	m := make(map[string]VulnRef, len(s.Vulns))
	for _, v := range s.Vulns {
		id := strings.ToUpper(strings.TrimSpace(v.ID))
		if id == "" {
			continue
		}
		if _, ok := m[id]; !ok {
			m[id] = v
		}
	}
	return m
}

// VersionBump records a dependency whose resolved version changed between the two
// artifact versions. Direction is "up", "down", or "changed" when the order
// cannot be determined.
type VersionBump struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace,omitempty"`
	FromVersion string `json:"fromVersion"`
	ToVersion   string `json:"toVersion"`
	Direction   string `json:"direction"`
}

// LicenseChange records a license that appears in version B but not version A,
// together with the disposition the license-compliance policy assigns it
// ("allowed", "review", "denied", "unknown", or "" when no policy is wired). A
// newly-introduced "denied" or "review" license is the high-signal case.
type LicenseChange struct {
	Component   string `json:"component,omitempty"`
	License     string `json:"license"`
	Disposition string `json:"disposition,omitempty"`
}

// VersionRef identifies one side of a diff.
type VersionRef struct {
	Version    string    `json:"version"`
	Digest     string    `json:"digest,omitempty"`
	ObservedAt time.Time `json:"observedAt,omitempty"`
	DepCount   int       `json:"depCount"`
	VulnCount  int       `json:"vulnCount"`
}

// Contribution is one explainable term of the drift-risk score: a factor, how
// many of it were observed, and the points it added.
type Contribution struct {
	Factor string  `json:"factor"`
	Count  int     `json:"count"`
	Points float64 `json:"points"`
}

// Diff is the structured comparison of two versions of a coordinate.
type Diff struct {
	Tenant     string     `json:"tenant,omitempty"`
	Ecosystem  string     `json:"ecosystem"`
	Coordinate string     `json:"coordinate"`
	From       VersionRef `json:"from"`
	To         VersionRef `json:"to"`

	AddedDeps          []Dep           `json:"addedDeps"`
	RemovedDeps        []Dep           `json:"removedDeps"`
	VersionBumps       []VersionBump   `json:"versionBumps"`
	NewLicenses        []LicenseChange `json:"newLicenses"`
	NewNamespaces      []string        `json:"newNamespaces"`
	NewVulnerabilities []VulnRef       `json:"newVulnerabilities"`

	// DriftScore is the composite 0..100 drift-risk score derived from the deltas
	// above; Contributions explains how it was reached.
	DriftScore    float64        `json:"driftScore"`
	Contributions []Contribution `json:"contributions,omitempty"`
	// Significant is true when DriftScore meets the configured significance
	// threshold; it drives notification and the admission signal.
	Significant bool `json:"significant"`
}

// Empty reports whether the diff found no material change at all.
func (d *Diff) Empty() bool {
	return len(d.AddedDeps) == 0 && len(d.RemovedDeps) == 0 && len(d.VersionBumps) == 0 &&
		len(d.NewLicenses) == 0 && len(d.NewNamespaces) == 0 && len(d.NewVulnerabilities) == 0
}

// LicenseDispositioner resolves the policy disposition of a license expression
// for a tenant. It is satisfied by an adapter over the license-compliance service
// (internal/license); a nil dispositioner disables license cross-referencing (new
// licenses are still surfaced, just without a disposition). Keeping it an
// interface keeps this package decoupled from the license policy internals and
// testable in isolation.
type LicenseDispositioner interface {
	// Disposition returns "allowed", "review", "denied", or "unknown" for the
	// given SPDX license expression under the tenant's effective policy.
	Disposition(tenant, expression string) string
}

// Weights tunes the contribution of each delta category to the drift-risk score.
// Zero-valued weights fall back to the defaults in DefaultWeights.
type Weights struct {
	PerAddedDep      float64 `yaml:"perAddedDep" json:"perAddedDep"`
	PerNewNamespace  float64 `yaml:"perNewNamespace" json:"perNewNamespace"`
	PerVersionBump   float64 `yaml:"perVersionBump" json:"perVersionBump"`
	PerRemovedDep    float64 `yaml:"perRemovedDep" json:"perRemovedDep"`
	NewLicenseAllow  float64 `yaml:"newLicenseAllow" json:"newLicenseAllow"`
	NewLicenseReview float64 `yaml:"newLicenseReview" json:"newLicenseReview"`
	NewLicenseDeny   float64 `yaml:"newLicenseDeny" json:"newLicenseDeny"`
	VulnCritical     float64 `yaml:"vulnCritical" json:"vulnCritical"`
	VulnHigh         float64 `yaml:"vulnHigh" json:"vulnHigh"`
	VulnMedium       float64 `yaml:"vulnMedium" json:"vulnMedium"`
	VulnLow          float64 `yaml:"vulnLow" json:"vulnLow"`
}

// DefaultWeights is the built-in scoring model. Vulnerabilities and policy-denied
// licenses dominate; a large fan-out of new dependencies and never-before-seen
// namespaces accumulate steadily so a sudden footprint expansion stands out.
func DefaultWeights() Weights {
	return Weights{
		PerAddedDep:      3,
		PerNewNamespace:  8,
		PerVersionBump:   1,
		PerRemovedDep:    0.5,
		NewLicenseAllow:  2,
		NewLicenseReview: 12,
		NewLicenseDeny:   30,
		VulnCritical:     50,
		VulnHigh:         28,
		VulnMedium:       10,
		VulnLow:          3,
	}
}

// withDefaults returns w with any zero field replaced by the default, so an
// operator can override a single weight without restating the whole model.
func (w Weights) withDefaults() Weights {
	d := DefaultWeights()
	if w.PerAddedDep == 0 {
		w.PerAddedDep = d.PerAddedDep
	}
	if w.PerNewNamespace == 0 {
		w.PerNewNamespace = d.PerNewNamespace
	}
	if w.PerVersionBump == 0 {
		w.PerVersionBump = d.PerVersionBump
	}
	if w.PerRemovedDep == 0 {
		w.PerRemovedDep = d.PerRemovedDep
	}
	if w.NewLicenseAllow == 0 {
		w.NewLicenseAllow = d.NewLicenseAllow
	}
	if w.NewLicenseReview == 0 {
		w.NewLicenseReview = d.NewLicenseReview
	}
	if w.NewLicenseDeny == 0 {
		w.NewLicenseDeny = d.NewLicenseDeny
	}
	if w.VulnCritical == 0 {
		w.VulnCritical = d.VulnCritical
	}
	if w.VulnHigh == 0 {
		w.VulnHigh = d.VulnHigh
	}
	if w.VulnMedium == 0 {
		w.VulnMedium = d.VulnMedium
	}
	if w.VulnLow == 0 {
		w.VulnLow = d.VulnLow
	}
	return w
}

// computeOptions carry the cross-referencing collaborators into Compute.
type computeOptions struct {
	weights     Weights
	significant float64
	license     LicenseDispositioner
}

// Compute produces the diff from version A (from) to version B (to). Both
// snapshots are normalized first, so the caller may pass them in any component
// order. The license dispositioner, when non-nil, classifies each newly-
// introduced license; the weights and significance threshold drive the drift
// score. Compute is pure and deterministic.
func compute(from, to Snapshot, opt computeOptions) *Diff {
	from.normalize()
	to.normalize()
	w := opt.weights.withDefaults()

	d := &Diff{
		Tenant:     to.Tenant,
		Ecosystem:  to.Ecosystem,
		Coordinate: to.Coordinate,
		From: VersionRef{
			Version: from.Version, Digest: from.Digest, ObservedAt: from.ObservedAt,
			DepCount: len(from.Deps), VulnCount: len(from.Vulns),
		},
		To: VersionRef{
			Version: to.Version, Digest: to.Digest, ObservedAt: to.ObservedAt,
			DepCount: len(to.Deps), VulnCount: len(to.Vulns),
		},
		AddedDeps:          []Dep{},
		RemovedDeps:        []Dep{},
		VersionBumps:       []VersionBump{},
		NewLicenses:        []LicenseChange{},
		NewNamespaces:      []string{},
		NewVulnerabilities: []VulnRef{},
	}

	fromDeps := from.depIndex()
	toDeps := to.depIndex()

	// Dependency set delta: added / removed / version-bumped.
	for _, dep := range to.Deps {
		prev, ok := fromDeps[dep.key()]
		if !ok {
			d.AddedDeps = append(d.AddedDeps, dep)
			continue
		}
		if strings.TrimSpace(prev.Version) != strings.TrimSpace(dep.Version) {
			d.VersionBumps = append(d.VersionBumps, VersionBump{
				Name:        dep.Name,
				Namespace:   dep.Namespace,
				FromVersion: prev.Version,
				ToVersion:   dep.Version,
				Direction:   bumpDirection(prev.Version, dep.Version),
			})
		}
	}
	for _, dep := range from.Deps {
		if _, ok := toDeps[dep.key()]; !ok {
			d.RemovedDeps = append(d.RemovedDeps, dep)
		}
	}

	// Newly-introduced namespaces (maintainer/org footprint expansion).
	fromNS := from.namespaceSet()
	for _, ns := range sortedValues(to.namespaceSet()) {
		if _, ok := fromNS[strings.ToLower(ns)]; !ok {
			d.NewNamespaces = append(d.NewNamespaces, ns)
		}
	}

	// Newly-introduced licenses, classified against the policy.
	d.NewLicenses = newLicenses(from, to, d.Tenant, opt.license)

	// Net-new vulnerabilities (present in B, absent in A).
	fromVulns := from.vulnSet()
	for _, v := range to.Vulns {
		id := strings.ToUpper(strings.TrimSpace(v.ID))
		if id == "" {
			continue
		}
		if _, ok := fromVulns[id]; !ok {
			d.NewVulnerabilities = append(d.NewVulnerabilities, v)
		}
	}

	d.scoreDrift(w)
	d.Significant = d.DriftScore >= opt.significant
	return d
}

// newLicenses computes the set of license tokens present in version B but not
// version A (the primary license plus every dependency-declared license),
// classifying each via the dispositioner when supplied.
func newLicenses(from, to Snapshot, tenant string, disp LicenseDispositioner) []LicenseChange {
	prior := map[string]struct{}{}
	addPrior := func(expr string) {
		for _, lic := range splitLicenses(expr) {
			prior[strings.ToLower(lic)] = struct{}{}
		}
	}
	addPrior(from.PrimaryLicense)
	for _, dep := range from.Deps {
		addPrior(dep.License)
	}

	var out []LicenseChange
	seen := map[string]struct{}{}
	consider := func(component, expr string) {
		for _, lic := range splitLicenses(expr) {
			lc := strings.ToLower(lic)
			if _, ok := prior[lc]; ok {
				continue
			}
			if _, ok := seen[lc]; ok {
				continue
			}
			seen[lc] = struct{}{}
			change := LicenseChange{Component: component, License: lic}
			if disp != nil {
				change.Disposition = disp.Disposition(tenant, lic)
			}
			out = append(out, change)
		}
	}
	consider(to.Coordinate, to.PrimaryLicense)
	for _, dep := range to.Deps {
		consider(dep.Name, dep.License)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].License < out[j].License })
	if out == nil {
		out = []LicenseChange{}
	}
	return out
}

// scoreDrift computes the composite drift score and its explainable
// contributions, clamping the total to [0,100].
func (d *Diff) scoreDrift(w Weights) {
	add := func(factor string, count int, perPoint float64) {
		if count <= 0 || perPoint == 0 {
			return
		}
		d.Contributions = append(d.Contributions, Contribution{
			Factor: factor, Count: count, Points: float64(count) * perPoint,
		})
	}
	add("added-dependencies", len(d.AddedDeps), w.PerAddedDep)
	add("new-namespaces", len(d.NewNamespaces), w.PerNewNamespace)
	add("version-bumps", len(d.VersionBumps), w.PerVersionBump)
	add("removed-dependencies", len(d.RemovedDeps), w.PerRemovedDep)

	var allow, review, deny int
	for _, l := range d.NewLicenses {
		switch l.Disposition {
		case "denied", "deny":
			deny++
		case "review":
			review++
		default:
			allow++
		}
	}
	add("new-licenses-denied", deny, w.NewLicenseDeny)
	add("new-licenses-review", review, w.NewLicenseReview)
	add("new-licenses-allowed", allow, w.NewLicenseAllow)

	var crit, high, med, low int
	for _, v := range d.NewVulnerabilities {
		switch normalizeSeverity(v.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}
	add("new-vulns-critical", crit, w.VulnCritical)
	add("new-vulns-high", high, w.VulnHigh)
	add("new-vulns-medium", med, w.VulnMedium)
	add("new-vulns-low", low, w.VulnLow)

	var total float64
	for _, c := range d.Contributions {
		total += c.Points
	}
	if total > 100 {
		total = 100
	}
	// Round to one decimal for stable, human-readable output.
	d.DriftScore = float64(int(total*10+0.5)) / 10
}

// splitLicenses breaks a (possibly compound) SPDX expression into its individual
// license tokens, dropping operators and parentheses, so a newly-introduced
// operand of a compound expression is detected. It is intentionally lenient — the
// authoritative parse lives in internal/license; here we only need the token set.
func splitLicenses(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	repl := strings.NewReplacer("(", " ", ")", " ")
	expr = repl.Replace(expr)
	var out []string
	for _, tok := range strings.Fields(expr) {
		switch strings.ToUpper(tok) {
		case "AND", "OR", "WITH":
			continue
		}
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// bumpDirection classifies a version change as up/down/changed using a numeric
// dotted-segment comparison, falling back to "changed" for non-numeric versions.
func bumpDirection(from, to string) string {
	cmp, ok := compareVersions(from, to)
	if !ok {
		return "changed"
	}
	switch {
	case cmp < 0:
		return "up"
	case cmp > 0:
		return "down"
	default:
		return "changed"
	}
}

// normalizeSeverity lowercases and canonicalizes a severity label.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	default:
		return "low"
	}
}

// sortedValues returns the values of a lowercased→original map sorted by their
// lowercased key for deterministic output.
func sortedValues(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}
