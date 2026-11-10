package findings

import (
	"sort"
	"strconv"
	"strings"
)

// This file implements the central finding de-duplication layer (Task 165).
//
// Multiple admission gates can independently emit findings that describe the
// same underlying supply-chain issue for the same artifact: an exposed
// credential may be reported by both the Git commit secret scanner (Task 29) and
// the package-payload content-analysis gate (Task 138); a vulnerable component
// may be surfaced by the vulnerability scanner and, again, by the remediation
// advisor (Task 121) when it annotates the same component with a fix. Left
// un-collapsed, those duplicates inflate the risk picture, triple-count in SARIF
// and the dossier, and bury the operator in redundant rows.
//
// Deduplicate collapses such duplicates by a stable identity key —
// (coordinate, digest, category, locator) — into a single canonical finding,
// while preserving the provenance of every contributing gate in Finding.Sources
// so no attribution is lost. It runs before risk scoring, SARIF export and
// dossier assembly so every downstream consumer sees the collapsed set.

// Category is the gate-independent classification a finding is de-duplicated
// within. Two findings only ever collapse when they share a category, so the key
// deliberately groups by *what kind of issue* a finding describes rather than by
// which gate reported it — that is what lets a secret found by two different
// gates, or a CVE reported by two different gates, fold into one row.
type Category string

const (
	CategoryVulnerability Category = "vulnerability"
	CategorySecret        Category = "secret"
	CategoryLicense       Category = "license"
	CategorySignature     Category = "signature"
	CategoryProvenance    Category = "provenance"
	CategoryNameguard     Category = "nameguard"
	CategoryMalware       Category = "malware"
	CategoryContent       Category = "content"
	CategoryInstallHook   Category = "install-hook"
	CategoryMaintainer    Category = "maintainer"
	CategoryCommit        Category = "commit"
	CategoryRisk          Category = "risk"
	CategoryPolicy        Category = "policy"
	CategoryOther         Category = "other"
)

// categoryOf derives the canonical category for a finding. It keys primarily off
// the stable rule id (and, for content-analysis findings, the gate-reported
// sub-category property), so that cross-gate duplicates of the same issue land in
// the same category: a contentscan finding whose category is "secret" is treated
// as a CategorySecret and can therefore collapse with a secretscan finding on the
// same file.
func categoryOf(f *Finding) Category {
	switch f.RuleID {
	case RuleVulnerableDependency, RuleSuppressedVuln:
		return CategoryVulnerability
	case RuleExposedSecret:
		return CategorySecret
	case RuleLicenseNonCompliant, RuleLicenseDrift:
		return CategoryLicense
	case RuleUnverifiedSignature:
		return CategorySignature
	case RuleUnverifiedProvenance, RuleMaliciousCommit,
		RuleProvenanceSourceMismatch, RuleUnverifiedBuildProvenance,
		RulePyPIDigestMismatch, RuleUnverifiedPyPIAttestation,
		RuleReproducibilityMismatch:
		return CategoryProvenance
	case RuleTyposquat, RuleDependencyConfusion, RuleHomoglyph, RuleNameSuspicious:
		return CategoryNameguard
	case RuleMalwareDetected:
		return CategoryMalware
	case RuleSuspiciousContent:
		// A content-analysis "secret" sub-category is the same issue a dedicated
		// secret scanner reports, so route it to CategorySecret to allow the two to
		// collapse; everything else stays content.
		if sub, _ := f.Properties["category"].(string); strings.EqualFold(strings.TrimSpace(sub), "secret") {
			return CategorySecret
		}
		return CategoryContent
	case RuleRiskyInstallScript:
		return CategoryInstallHook
	case RuleMaintainerDrift:
		return CategoryMaintainer
	case RuleSuspiciousCommit:
		return CategoryCommit
	case RuleRiskThreshold:
		return CategoryRisk
	case RulePolicyViolation:
		return CategoryPolicy
	}
	// Fall back to the gate so an unknown rule still groups sensibly.
	switch f.Gate {
	case GateVulnscan, GateVEX:
		return CategoryVulnerability
	case GateSecretscan:
		return CategorySecret
	case GateLicense:
		return CategoryLicense
	case GateSigverify:
		return CategorySignature
	case GateNameguard:
		return CategoryNameguard
	case GateAVScan:
		return CategoryMalware
	case GateContentScan:
		return CategoryContent
	default:
		return CategoryOther
	}
}

// locatorOf derives the within-category locator that distinguishes one logical
// issue from another of the same category on the same artifact. It is
// deliberately independent of which gate produced the finding so two gates'
// reports of the same issue share a locator:
//
//   - a vulnerability is located by its advisory id + affected component (the
//     CVE is identical whichever gate reported it);
//   - a secret / content / install-hook finding is located by its file + line
//     (the place), not by the gate-specific detection rule, so a secret found by
//     secretscan and by contentscan on the same file collapses;
//   - everything else is located by its identifier + file + line.
func locatorOf(cat Category, f *Finding) string {
	switch cat {
	case CategoryVulnerability:
		return strings.ToUpper(strings.TrimSpace(f.Identifier)) + "@" + strings.ToLower(f.Location.Coordinate)
	case CategorySecret, CategoryContent, CategoryInstallHook:
		return strings.ToLower(f.Location.File) + ":" + strconv.Itoa(f.Location.Line)
	default:
		return strings.ToLower(strings.TrimSpace(f.Identifier)) + "|" +
			strings.ToLower(f.Location.File) + ":" + strconv.Itoa(f.Location.Line)
	}
}

// dedupKey composes the full de-duplication identity:
// (coordinate, digest, category, locator). The coordinate falls back to the
// document artifact when the finding does not key to a sub-component, and the
// digest is the document artifact's content digest, so findings for different
// versions/digests of the same package never collapse into each other.
func dedupKey(d *Document, f *Finding) (Category, string) {
	coord := f.Location.Coordinate
	if coord == "" {
		coord = d.Artifact.Coordinate
	}
	cat := categoryOf(f)
	loc := locatorOf(cat, f)
	key := strings.ToLower(coord) + "\x00" +
		strings.ToLower(d.Artifact.Digest) + "\x00" +
		string(cat) + "\x00" + loc
	return cat, key
}

// DedupStats summarizes one de-duplication pass for metrics and logging.
type DedupStats struct {
	// Input is the number of findings before de-duplication.
	Input int
	// Output is the number of findings after (one per distinct identity).
	Output int
	// Collapsed is the number of duplicate findings removed (Input - Output).
	Collapsed int
	// Groups is the number of distinct logical findings (== Output).
	Groups int
	// CollapsedByCategory counts removed duplicates per category.
	CollapsedByCategory map[Category]int
}

// severityRank orders the canonical severity vocabulary from most to least
// severe, so the representative of a collapsed group is the strongest signal.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default: // SeverityNone / unknown
		return 0
	}
}

// Deduplicate collapses duplicate findings in the document in place, returning
// the pass statistics. Findings sharing a (coordinate, digest, category,
// locator) identity are merged into a single representative — the strongest,
// most-visible signal of the group — whose Sources list records every
// contributing gate. The representative's position is the first appearance of
// its group, so the overall finding order (and therefore SARIF/dossier ordering)
// stays deterministic.
//
// Representative selection within a group is deterministic: highest canonical
// severity first, then a non-suppressed finding ahead of a suppressed one (a
// live detection dominates an adjudicated duplicate so a real issue is never
// hidden by a coincidental suppression), then the earliest original position.
func (d *Document) Deduplicate() DedupStats {
	stats := DedupStats{Input: len(d.Findings), CollapsedByCategory: map[Category]int{}}
	if len(d.Findings) < 2 {
		// Still stamp a single-element Source so provenance is uniform downstream.
		for i := range d.Findings {
			if d.Findings[i].Sources == nil {
				d.Findings[i].Sources = []Source{sourceOf(&d.Findings[i])}
			}
		}
		stats.Output = len(d.Findings)
		stats.Groups = stats.Output
		return stats
	}

	type group struct {
		order   int   // first-appearance index, for stable output ordering
		members []int // indices into d.Findings
		cat     Category
	}
	groups := make(map[string]*group)
	var order []string
	for i := range d.Findings {
		cat, key := dedupKey(d, &d.Findings[i])
		g, ok := groups[key]
		if !ok {
			g = &group{order: i, cat: cat}
			groups[key] = g
			order = append(order, key)
		}
		g.members = append(g.members, i)
	}

	// Preserve first-appearance ordering of the groups.
	sort.SliceStable(order, func(a, b int) bool {
		return groups[order[a]].order < groups[order[b]].order
	})

	out := make([]Finding, 0, len(groups))
	for _, key := range order {
		g := groups[key]
		if len(g.members) == 1 {
			f := d.Findings[g.members[0]]
			if f.Sources == nil {
				f.Sources = []Source{sourceOf(&f)}
			}
			out = append(out, f)
			continue
		}
		merged := mergeGroup(d, g.members)
		stats.CollapsedByCategory[g.cat] += len(g.members) - 1
		out = append(out, merged)
	}

	d.Findings = out
	stats.Output = len(out)
	stats.Groups = len(out)
	stats.Collapsed = stats.Input - stats.Output
	return stats
}

// sourceOf projects a finding to its own provenance Source.
func sourceOf(f *Finding) Source {
	return Source{
		Gate:       f.Gate,
		RuleID:     f.RuleID,
		Severity:   f.Severity,
		Identifier: f.Identifier,
		Suppressed: f.Suppressed,
	}
}

// mergeGroup collapses a multi-member group into one representative finding,
// preserving every member's provenance in Sources.
func mergeGroup(d *Document, members []int) Finding {
	// Order members by representative preference without disturbing d.Findings.
	ranked := append([]int(nil), members...)
	sort.SliceStable(ranked, func(a, b int) bool {
		fa, fb := &d.Findings[ranked[a]], &d.Findings[ranked[b]]
		if ra, rb := severityRank(fa.Severity), severityRank(fb.Severity); ra != rb {
			return ra > rb
		}
		if fa.Suppressed != fb.Suppressed {
			return !fa.Suppressed // non-suppressed first
		}
		return ranked[a] < ranked[b] // earliest original position
	})

	rep := d.Findings[ranked[0]]

	// Collect provenance in original member order so the contributor list reads
	// in the gate order the document was assembled in.
	seen := make(map[Gate]bool, len(members))
	sources := make([]Source, 0, len(members))
	var fix *SuggestedFix
	for _, idx := range members {
		f := &d.Findings[idx]
		if f.Fix != nil && fix == nil {
			fix = f.Fix
		}
		src := sourceOf(f)
		if seen[src.Gate] {
			continue
		}
		seen[src.Gate] = true
		sources = append(sources, src)
		// Fold gate-specific properties the representative lacks so no detail is
		// lost when a duplicate is dropped.
		if idx != ranked[0] {
			mergeProps(&rep, f)
		}
	}
	rep.Sources = sources
	if rep.Fix == nil {
		rep.Fix = fix
	}
	return rep
}

// mergeProps copies property keys present on src but absent on the
// representative, so a collapsed duplicate's gate-specific detail survives.
func mergeProps(rep *Finding, src *Finding) {
	if len(src.Properties) == 0 {
		return
	}
	if rep.Properties == nil {
		rep.Properties = make(map[string]any, len(src.Properties))
	}
	for k, v := range src.Properties {
		if _, exists := rep.Properties[k]; !exists {
			rep.Properties[k] = v
		}
	}
}
