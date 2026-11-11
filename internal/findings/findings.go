// Package findings provides a unified, gate-agnostic findings-aggregation layer
// for the pull-through proxy (Task 42). It normalizes the verdicts of every
// security admission gate — vulnerability/OSV scanning, VEX adjudication,
// license compliance, secret detection, signature/attestation verification,
// nameguard (typosquatting / dependency-confusion), the unified risk score, and
// the policy-as-code engine — into a single canonical findings model, and
// exports that model as SARIF 2.1.0.
//
// SARIF (Static Analysis Results Interchange Format) is the lingua franca CI
// systems speak: GitHub code scanning and GitLab both ingest a SARIF document to
// decorate pull/merge requests with inline annotations and to fail a pipeline on
// policy violations. By emitting one SARIF log that fuses all of the proxy's
// gates, a customer's CI can call the proxy once, retrieve the findings for an
// artifact (or a batch of artifacts for an air-gapped import preflight), and
// surface supply-chain risk natively in their review workflow.
//
// The package is deliberately decoupled from the concrete gate packages: the
// canonical normalization consumes the same plain, self-describing admission
// document the policy-as-code and risk-scoring engines already evaluate
// (policyengine.Input), plus a couple of neutral signal structs for the risk and
// policy verdicts. It therefore imports no scanner/license/sigverify internals,
// stays trivially unit-testable, and the SARIF rendering is a pure function of
// the canonical model.
package findings

import "time"

// Gate identifies the admission gate a finding originated from. The values are
// stable, lowercase identifiers reused as SARIF rule-id prefixes and result
// property tags.
type Gate string

const (
	GateVulnscan      Gate = "vulnscan"
	GateVEX           Gate = "vex"
	GateLicense       Gate = "license"
	GateSecretscan    Gate = "secretscan"
	GateSigverify     Gate = "sigverify"
	GateNameguard     Gate = "nameguard"
	GateRiskscore     Gate = "riskscore"
	GatePolicyEngine  Gate = "policyengine"
	GateProvenance    Gate = "provenance"
	GateInstallHooks  Gate = "installhooks"
	GateAVScan        Gate = "avscan"
	GateContentScan   Gate = "contentscan"
	GateLLMPkgScan    Gate = "llmpkgscan"
	GateRebuildVerify Gate = "rebuildverify"
	GateBuildProv     Gate = "buildprov"
	GatePyPIAttest    Gate = "pypiattest"
	GateContinuity    Gate = "continuity"
	GateCommitScan    Gate = "commitscan"
	GateActionPin     Gate = "actionpin"
)

// Severity is the canonical, gate-independent severity vocabulary. Each gate's
// native severity is mapped onto this scale during normalization, and this scale
// is then mapped onto a SARIF result level (see Level and severityOrder).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityNone     Severity = "none"
)

// Level is a SARIF result level. The SARIF 2.1.0 specification defines exactly
// these four values for result.level and reportingConfiguration.level.
type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelNote    Level = "note"
	LevelNone    Level = "none"
)

// Artifact identifies the subject an aggregated findings document describes. The
// coordinate is the canonical "name@version" rendering used as the primary SARIF
// location; the commit/repository fields, when known (via build-provenance
// association), let a finding be keyed to the source revision so CI can annotate
// the originating commit rather than only the package.
type Artifact struct {
	Ecosystem     string `json:"ecosystem,omitempty"`
	Backend       string `json:"backend,omitempty"`
	Name          string `json:"name,omitempty"`
	Version       string `json:"version,omitempty"`
	Digest        string `json:"digest,omitempty"`
	Coordinate    string `json:"coordinate,omitempty"`
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
}

// Location keys a finding to a concrete place: a package coordinate (the
// default), a file within the artifact (secret findings), and/or a source commit
// and repository (provenance-linked findings). All fields are optional; an
// empty Location falls back to the document's artifact coordinate.
type Location struct {
	// Coordinate is the package coordinate the finding applies to, e.g.
	// "npm/lodash@4.17.21". Defaults to the document artifact's coordinate.
	Coordinate string `json:"coordinate,omitempty"`
	// File is a path within the artifact (used by secret findings).
	File string `json:"file,omitempty"`
	// Line is a 1-based line number within File, when known.
	Line int `json:"line,omitempty"`
	// CommitSHA / RepositoryURL key the finding to its source revision when the
	// artifact has an established build-provenance association.
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
}

// Finding is one normalized, gate-independent result. It carries everything the
// SARIF renderer needs: the catalog rule it instantiates (RuleID), the effective
// severity/level, a stable identifier for fingerprinting and deduplication, a
// human-readable message, its location, and optional structured properties.
type Finding struct {
	// RuleID is the catalog rule this finding instantiates (see rules.go). It is
	// the stable, finite taxonomy key SARIF consumers group and configure by.
	RuleID string `json:"ruleId"`
	// Gate is the originating admission gate.
	Gate Gate `json:"gate"`
	// Severity is the canonical severity; Level is its SARIF mapping. Level is
	// resolved from Severity during normalization but stored explicitly so a
	// gate can override the rule's default configuration per finding.
	Severity Severity `json:"severity"`
	Level    Level    `json:"level"`
	// Identifier is a stable, gate-specific identity for the finding — a CVE id, a
	// secret rule id, a denied SPDX license, the squatted name. It feeds the SARIF
	// partial fingerprint so the same issue is recognized across scans.
	Identifier string `json:"identifier,omitempty"`
	// Title is a short one-line summary; Message is the full human-readable text
	// rendered into the SARIF result message.
	Title   string `json:"title"`
	Message string `json:"message"`
	// Location keys the finding to a package coordinate / file / commit.
	Location Location `json:"location"`
	// Suppressed marks a finding that a VEX statement (or equivalent) has
	// adjudicated away; it is still emitted (for transparency) but flagged as a
	// SARIF suppression so CI does not fail on it. Justification explains why.
	Suppressed    bool   `json:"suppressed,omitempty"`
	Justification string `json:"justification,omitempty"`
	// Properties carries gate-specific structured detail surfaced in the SARIF
	// result's property bag (CVSS score, advisory URL, distance, etc.).
	Properties map[string]any `json:"properties,omitempty"`
	// Fix is an optional remediation suggestion attached by the dependency-
	// remediation advisor (Task 121). When set it renders as a SARIF result "fix"
	// so a CI pull-request annotation can propose the concrete upgrade that clears
	// the finding, not merely report it.
	Fix *SuggestedFix `json:"fix,omitempty"`
	// Sources records the provenance of every gate that contributed to this
	// finding (Task 165). It is populated by Deduplicate when two or more gates
	// emitted the same logical finding (same coordinate+digest+category+locator) —
	// e.g. a secret surfaced by both commit scanning and content analysis, or a
	// vulnerability surfaced by both the scanner and the remediation advisor. A
	// single-gate finding carries exactly one Source (itself); a collapsed finding
	// carries one Source per contributing gate, so no gate's attribution is lost
	// when duplicates are merged. It is nil on a freshly-normalized, un-deduped
	// document.
	Sources []Source `json:"sources,omitempty"`
}

// Source is the provenance of one gate's contribution to a (possibly merged)
// finding. Deduplicate preserves one Source per contributing gate so a collapsed
// finding still records that, say, both secretscan and contentscan independently
// detected the same exposed credential.
type Source struct {
	// Gate is the contributing admission gate.
	Gate Gate `json:"gate"`
	// RuleID is the catalog rule the contributing finding instantiated (it can
	// differ from the merged finding's rule — e.g. contentscan/suspicious-content
	// contributing to a secretscan/exposed-credential finding of the same file).
	RuleID string `json:"ruleId,omitempty"`
	// Severity is the canonical severity the contributing gate assigned.
	Severity Severity `json:"severity,omitempty"`
	// Identifier is the contributing gate's stable identity for the finding.
	Identifier string `json:"identifier,omitempty"`
	// Suppressed reports whether this specific contribution was adjudicated away
	// (e.g. the vulnscan contribution was VEX-suppressed while another gate's was
	// not).
	Suppressed bool `json:"suppressed,omitempty"`
}

// SuggestedFix is a human-readable remediation suggestion for a finding — the
// neutral projection the remediation advisor populates and the SARIF renderer
// turns into a result-level fix object.
type SuggestedFix struct {
	// Description is the one-line remediation sentence, e.g.
	// "Upgrade npm/lodash from 4.17.4 to 4.17.21 to resolve CVE-2021-23337.".
	Description string `json:"description"`
	// Version is the suggested target version, when the fix is a version upgrade.
	Version string `json:"version,omitempty"`
}

// Document is the canonical aggregated findings model for a single artifact: the
// subject it describes plus every normalized finding across all gates. It is the
// unit the store retains and the SARIF renderer consumes.
type Document struct {
	Tenant      string    `json:"tenant,omitempty"`
	Artifact    Artifact  `json:"artifact"`
	Findings    []Finding `json:"findings"`
	GeneratedAt time.Time `json:"generatedAt"`
}

// RiskSignal is the neutral projection of the unified risk-scoring verdict
// (riskscore.Assessment) the caller supplies so the findings layer need not
// import the riskscore package. When the band met or exceeded the admission
// threshold (Exceeds), normalization emits a risk-threshold finding.
type RiskSignal struct {
	Score   int
	Band    string
	Exceeds bool
	Action  string // off|warn|block
	Summary string
}

// PolicySignal is the neutral projection of a policy-as-code verdict
// (policyengine.Result). Each matched rule with a non-allow effect becomes a
// policy-violation finding.
type PolicySignal struct {
	Action  string // allow|warn|deny
	Reason  string
	Matches []PolicyMatch
}

// PolicyMatch is one matched policy rule.
type PolicyMatch struct {
	RuleID string
	Action string // warn|deny
	Reason string
}

// HasBlocking reports whether the document contains at least one non-suppressed
// finding whose level is error — the signal a CI gate uses to fail a build.
func (d *Document) HasBlocking() bool {
	for i := range d.Findings {
		f := &d.Findings[i]
		if !f.Suppressed && f.Level == LevelError {
			return true
		}
	}
	return false
}

// Counts tallies findings by canonical severity (suppressed findings excluded),
// for summaries and metrics.
func (d *Document) Counts() map[Severity]int {
	out := make(map[Severity]int, 6)
	for i := range d.Findings {
		f := &d.Findings[i]
		if f.Suppressed {
			continue
		}
		out[f.Severity]++
	}
	return out
}
