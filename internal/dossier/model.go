package dossier

import (
	"strings"
	"time"
)

// Verdict values for the synthesized triage headline.
const (
	VerdictBlock   = "block"
	VerdictWarn    = "warn"
	VerdictAdmit   = "admit"
	VerdictUnknown = "unknown"
)

// Dossier is the complete, opinionated security story for one artifact
// coordinate: a fixed projection folding every wired subsystem's view of the
// artifact into one card. Every section is a pointer that is nil when its source
// is disabled or had nothing for the coordinate; consult Sources to tell those
// apart.
type Dossier struct {
	// Identity.
	Tenant     string `json:"tenant,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Coordinate string `json:"coordinate"`
	Digest     string `json:"digest,omitempty"`
	Backend    string `json:"backend,omitempty"`

	GeneratedAt time.Time `json:"generatedAt"`

	// Headline is the synthesized at-a-glance triage verdict.
	Headline Headline `json:"headline"`

	// Sections — each nil when absent.
	Provenance   *ProvenanceSection   `json:"provenance,omitempty"`
	Risk         *RiskSection         `json:"risk,omitempty"`
	Findings     *FindingsSection     `json:"findings,omitempty"`
	Vulns        *VulnSection         `json:"vulnerabilities,omitempty"`
	License      *LicenseSection      `json:"license,omitempty"`
	Signature    *SignatureSection    `json:"signature,omitempty"`
	Reproduce    *ReproSection        `json:"reproducibleBuild,omitempty"`
	SbomDrift    *SbomDriftSection    `json:"sbomDrift,omitempty"`
	Approvals    *ApprovalsSection    `json:"approvals,omitempty"`
	Attest       *AttestSection       `json:"attestation,omitempty"`
	Timeline     *TimelineSection     `json:"timeline,omitempty"`
	SuggestedFix *SuggestedFixSection `json:"suggestedFix,omitempty"`
	Suppression  *SuppressionSection  `json:"suppressionHistory,omitempty"`
	// LLMPackageScan is the sandboxed LLM package-content scan verdict (Task 173).
	LLMPackageScan *LLMPackageScanSection `json:"llmPackageScan,omitempty"`

	// Sources records the per-subsystem fan-out outcome so a reader can
	// distinguish "no problem found" from "source was unavailable".
	Sources []SourceStatus `json:"sources"`
	// Partial is true when at least one source timed out or errored, so the
	// dossier is incomplete.
	Partial bool `json:"partial"`
}

// SourceStatus is the outcome of one fan-out leg.
type SourceStatus struct {
	Source string `json:"source"`
	Status string `json:"status"` // ok|empty|disabled|timeout|error
	Detail string `json:"detail,omitempty"`
	TookMS int64  `json:"tookMs"`
}

// Headline is the synthesized triage verdict that summarizes the whole card.
type Headline struct {
	Verdict   string   `json:"verdict"`   // block|warn|admit|unknown
	Blocking  bool     `json:"blocking"`  // a blocking condition is present
	RiskScore int      `json:"riskScore"` // 0 when no risk assessment exists
	RiskBand  string   `json:"riskBand,omitempty"`
	Reasons   []string `json:"reasons,omitempty"` // top drivers, worst-first
	Summary   string   `json:"summary"`           // one-line human summary
}

// ProvenanceSection captures where the artifact came from: the proven (or
// claimed) source commit/repository and the inbound build-provenance signals.
type ProvenanceSection struct {
	SourceCommit  string `json:"sourceCommit,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// CommitFromGraph reports the commit was resolved via the provenance graph's
	// package->commit association (Task 33) rather than a verified attestation.
	CommitFromGraph bool `json:"commitFromGraph,omitempty"`

	// Inbound build-provenance (Task 72) headline signals.
	HasProvenance      bool   `json:"hasProvenance"`
	ProvenanceVerified bool   `json:"provenanceVerified"`
	SourceVerified     bool   `json:"sourceVerified"`
	ProvenanceMismatch bool   `json:"provenanceMismatch"`
	BuilderID          string `json:"builderId,omitempty"`
	WorkflowRef        string `json:"workflowRef,omitempty"`

	// Inbound PyPI PEP 740 attestation (Task 146) headline signals.
	HasPyPIAttestation      bool   `json:"hasPypiAttestation,omitempty"`
	PyPIAttestationVerified bool   `json:"pypiAttestationVerified,omitempty"`
	PyPIPublisherTrusted    bool   `json:"pypiPublisherTrusted,omitempty"`
	PyPIDigestMismatch      bool   `json:"pypiDigestMismatch,omitempty"`
	PyPIPublisher           string `json:"pypiPublisher,omitempty"`

	// DirectDependents / DownstreamPaths quantify the downstream blast radius.
	DirectDependents int `json:"directDependents"`
	DownstreamPaths  int `json:"downstreamPaths"`
}

// RiskSection is the unified explainable risk score (Task 37).
type RiskSection struct {
	Score         int          `json:"score"`
	Band          string       `json:"band,omitempty"`
	Block         bool         `json:"block"`
	Warn          bool         `json:"warn"`
	Summary       string       `json:"summary,omitempty"`
	Contributions []RiskDriver `json:"contributions,omitempty"`
	ScoredAt      time.Time    `json:"scoredAt,omitempty"`
}

// RiskDriver is one contributing signal in the risk breakdown.
type RiskDriver struct {
	Signal       string  `json:"signal"`
	Contribution float64 `json:"contribution"`
	Detail       string  `json:"detail,omitempty"`
}

// FindingsSection summarizes the unified admission findings (Task 42).
type FindingsSection struct {
	Total    int            `json:"total"`
	Blocking int            `json:"blocking"`
	Worst    string         `json:"worstSeverity,omitempty"`
	ByGate   map[string]int `json:"byGate,omitempty"`
	Items    []FindingItem  `json:"items,omitempty"`
}

// FindingItem is one finding surfaced on the card (worst-first, bounded).
type FindingItem struct {
	RuleID     string `json:"ruleId,omitempty"`
	Gate       string `json:"gate"`
	Severity   string `json:"severity,omitempty"`
	Title      string `json:"title,omitempty"`
	Identifier string `json:"identifier,omitempty"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

// VulnSection is the vulnerability + VEX rollup (Task 15/27).
type VulnSection struct {
	Total       int      `json:"total"`
	Critical    int      `json:"critical"`
	High        int      `json:"high"`
	Medium      int      `json:"medium"`
	Low         int      `json:"low"`
	MaxCVSS     float64  `json:"maxCvss"`
	MaxSeverity string   `json:"maxSeverity,omitempty"`
	Quarantined bool     `json:"quarantined"`
	VEXSuppress int      `json:"vexSuppressed"`
	CVEs        []string `json:"cves,omitempty"`
}

// LicenseSection captures the license disposition, derived from the license
// admission gate's findings (Task 28).
type LicenseSection struct {
	Disposition string   `json:"disposition"` // allowed|review|denied|unknown
	Licenses    []string `json:"licenses,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// SignatureSection is the signature/attestation verification status (Task 23).
type SignatureSection struct {
	Verified            bool      `json:"verified"`            // assumed true absent a sigverify finding
	Status              string    `json:"status"`              // verified|unverified
	VerifiedSignature   bool      `json:"verifiedSignature"`   // from a sigverify report
	VerifiedAttestation bool      `json:"verifiedAttestation"` // from a sigverify report
	Source              string    `json:"source,omitempty"`
	VerifiedAt          time.Time `json:"verifiedAt,omitempty"`
}

// ReproSection is the reproducible-build verification verdict (Task 68).
type ReproSection struct {
	Verdict       string    `json:"verdict"` // reproducible|mismatch|unsupported|unattested
	Reproducible  bool      `json:"reproducible"`
	Mismatch      bool      `json:"mismatch"`
	Pending       bool      `json:"pending,omitempty"`
	CommitSHA     string    `json:"commitSha,omitempty"`
	RepositoryURL string    `json:"repositoryUrl,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	ComputedAt    time.Time `json:"computedAt,omitempty"`
}

// SbomDriftSection is the latest dependency-drift report (Task 64).
type SbomDriftSection struct {
	FromVersion string  `json:"fromVersion,omitempty"`
	ToVersion   string  `json:"toVersion,omitempty"`
	DriftScore  float64 `json:"driftScore"`
	Significant bool    `json:"significant"`
	AddedDeps   int     `json:"addedDeps"`
	RemovedDeps int     `json:"removedDeps"`
	NewVulns    int     `json:"newVulnerabilities"`
}

// ApprovalsSection is the break-glass / quarantine-review history (Task 50).
type ApprovalsSection struct {
	Active  int            `json:"active"`  // currently-effective grants
	Pending int            `json:"pending"` // requests awaiting decision
	History []ApprovalItem `json:"history,omitempty"`
}

// ApprovalItem is one approval record on the card.
type ApprovalItem struct {
	Gate      string    `json:"gate,omitempty"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	Requester string    `json:"requester,omitempty"`
	GrantedAt time.Time `json:"grantedAt,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// AttestSection records the proxy's own outbound attestation for the artifact (Task 46).
type AttestSection struct {
	Present       bool      `json:"present"`
	BundleDigest  string    `json:"bundleDigest,omitempty"`
	PredicateType string    `json:"predicateType,omitempty"`
	SubjectDigest string    `json:"subjectDigest,omitempty"`
	KeyID         string    `json:"keyId,omitempty"`
	CreatedAt     time.Time `json:"createdAt,omitempty"`
	// Rekor records the transparency-log pointer for the attestation when it was
	// submitted to a Sigstore Rekor log (Task 142): the log index and whether the
	// inclusion proof / SET verified. Nil when submission is disabled or pending.
	Rekor *RekorSection `json:"rekor,omitempty"`
}

// RekorSection is the transparency-log entry pointer surfaced on the dossier
// (Task 142).
type RekorSection struct {
	LogIndex               int64     `json:"logIndex"`
	LogID                  string    `json:"logId,omitempty"`
	UUID                   string    `json:"uuid,omitempty"`
	URL                    string    `json:"url,omitempty"`
	IntegratedTime         time.Time `json:"integratedTime,omitempty"`
	InclusionProofVerified bool      `json:"inclusionProofVerified"`
	SETVerified            bool      `json:"setVerified"`
}

// TimelineSection is the correlated forensic event chain for the coordinate (Task 77).
type TimelineSection struct {
	Total     int             `json:"total"`
	Returned  int             `json:"returned"`
	Truncated bool            `json:"truncated"`
	Provable  bool            `json:"provable"` // at least one event carries a Merkle proof
	Events    []TimelineEvent `json:"events,omitempty"`
}

// SuggestedFixSection is the automated dependency-remediation advisor's verdict
// for the coordinate (Task 121): the nearest safe upgrade and what it resolves.
type SuggestedFixSection struct {
	// Status mirrors the advisor's Status token (safe-upgrade-found,
	// no-safe-version, no-candidates, already-safe).
	Status string `json:"status"`
	// RecommendedVersion is the nearest safe upgrade, when one was found.
	RecommendedVersion string `json:"recommendedVersion,omitempty"`
	// FixDescription is the one-line remediation sentence.
	FixDescription string `json:"fixDescription,omitempty"`
	// Resolved/Residual/Introduced tally the delta the upgrade produces.
	Resolved   int `json:"resolved"`
	Residual   int `json:"residual"`
	Introduced int `json:"introduced"`
	// ResolvedFindings names the findings the upgrade clears (short labels).
	ResolvedFindings []string `json:"resolvedFindings,omitempty"`
	// VersionsConsidered is how many newer versions the advisor evaluated.
	VersionsConsidered int `json:"versionsConsidered"`
}

// SuppressionSection is the immutable suppression audit trail for the coordinate
// (Task 165): every finding that a gate suppressed or downgraded away from a
// build-failing verdict, with who/what suppressed it, under which mechanism, and
// why. It makes the "why was this not blocked?" question answerable directly from
// the 360 view and is sourced from the suppression ledger (which also mirrors
// each entry into the tamper-evident audit log).
type SuppressionSection struct {
	// Total is the number of distinct suppressions recorded for the coordinate.
	Total int `json:"total"`
	// ByMechanism tallies suppressions by mechanism (vex|reachability|policy|
	// break-glass).
	ByMechanism map[string]int `json:"byMechanism,omitempty"`
	// Items are the suppression entries, newest-first and bounded.
	Items []SuppressionEntry `json:"items,omitempty"`
}

// SuppressionEntry is one suppression surfaced on the card.
type SuppressionEntry struct {
	Mechanism     string    `json:"mechanism"`
	Actor         string    `json:"actor,omitempty"`
	Category      string    `json:"category,omitempty"`
	RuleID        string    `json:"ruleId,omitempty"`
	Identifier    string    `json:"identifier,omitempty"`
	Gate          string    `json:"gate,omitempty"`
	Justification string    `json:"justification,omitempty"`
	Time          time.Time `json:"time"`
	LastSeen      time.Time `json:"lastSeen,omitempty"`
	Count         uint64    `json:"count,omitempty"`
}

// LLMPackageScanSection is the sandboxed LLM package-content scan's verdict on
// the coordinate's artifact (Task 173): what a language model concluded from
// reading the unpacked package, how the gate reads that conclusion under its
// current configuration, and what the proxy established by itself.
//
// Reasons and Evidence are MODEL OUTPUT about untrusted content, and each
// excerpt is a quote from the package. They are material for an analyst to
// weigh — never instructions — and every renderer presents them inertly (see
// mdCode). Everything else in the section is the proxy's own statement.
type LLMPackageScanSection struct {
	// Verdict is the model's categorical answer (malicious|suspicious|benign);
	// Confidence is its confidence in it, 0..1.
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	// Disposition is how the gate reads the verdict under its current thresholds
	// and deterministic checks; Reason is the proxy's one-line explanation.
	Disposition string `json:"disposition"`
	Reason      string `json:"reason,omitempty"`
	// Action is the gate's configured action (annotate|block|quarantine); Refused
	// reports whether a pull of this artifact is refused right now.
	Action  string `json:"action,omitempty"`
	Refused bool   `json:"refused"`
	// Reasons are the reasons the model stated (model output).
	Reasons []string `json:"reasons,omitempty"`
	// Evidence are the places in the package the model cited.
	Evidence []LLMEvidence `json:"evidence,omitempty"`
	// PromptInjection reports that the package content addresses the scanner — a
	// deterministic indicator the proxy checks itself; InjectionRules names the
	// rules that matched.
	PromptInjection bool     `json:"promptInjection,omitempty"`
	InjectionRules  []string `json:"injectionRules,omitempty"`
	// StructuralRisk reports an archive built to attack an extractor; Anomalies
	// lists what was found (member names are quoted package content).
	StructuralRisk bool     `json:"structuralRisk,omitempty"`
	Anomalies      []string `json:"anomalies,omitempty"`
	// Truncated reports that the verdict rests on an incomplete view of the
	// package; Coverage says what was not examined.
	Truncated bool     `json:"truncated,omitempty"`
	Coverage  []string `json:"coverage,omitempty"`
	// Format is the container format that was unpacked ("tar.gz", "deb",
	// "oci-image", "file", …). ReadAs says how the artifact was read when that is
	// not as an ordinary archive in full: "image", "single file", "image layer"
	// (a layer pulled and examined on its own), "metadata only" (the artifact is
	// larger than the scan limit and only its inventory and the content within
	// the limit were judged).
	Format string `json:"format,omitempty"`
	ReadAs string `json:"readAs,omitempty"`
	// Where the verdict came from.
	Digest        string    `json:"digest,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	Model         string    `json:"model,omitempty"`
	PromptVersion int       `json:"promptVersion,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	FilesScanned  int       `json:"filesScanned,omitempty"`
	ScannedAt     time.Time `json:"scannedAt,omitempty"`
	// Artifacts is how many distinct artifacts (digests) under this coordinate
	// have a verdict, and Flagged how many of those the gate reads as malicious or
	// suspicious. The section describes the worst of them.
	Artifacts int `json:"artifacts"`
	Flagged   int `json:"flagged"`
}

// LLMEvidence is one location the model cited.
type LLMEvidence struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	// Excerpt is the text the model quoted (package content).
	Excerpt string `json:"excerpt,omitempty"`
	// Verified reports that the proxy found the quoted text at that place in the
	// unpacked package. An unverified citation is the model's claim alone.
	Verified bool `json:"verified"`
}

// TimelineEvent is one entry in the embedded timeline.
type TimelineEvent struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Category string    `json:"category,omitempty"`
	Decision string    `json:"decision,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	AuditSeq uint64    `json:"auditSeq,omitempty"`
}

// severityRank orders canonical severities for "worst-of" reduction.
var severityRank = map[string]int{
	"none": 0, "": 0, "unknown": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

func worseSeverity(cur, next string) string {
	c, n := strings.ToLower(cur), strings.ToLower(next)
	if severityRank[n] > severityRank[c] {
		return n
	}
	if c == "" {
		return n
	}
	return c
}

// synthesizeHeadline folds the populated sections into a single triage verdict.
// It is computed after all fan-out legs join, so it reads a stable dossier.
func synthesizeHeadline(d *Dossier) Headline {
	h := Headline{Verdict: VerdictUnknown}
	var any bool

	// Risk drives the headline score/band even when not blocking.
	if d.Risk != nil {
		any = true
		h.RiskScore = d.Risk.Score
		h.RiskBand = d.Risk.Band
		if d.Risk.Block {
			h.Blocking = true
			h.Reasons = append(h.Reasons, "risk band "+d.Risk.Band+" exceeds the block threshold")
		} else if d.Risk.Warn {
			h.Reasons = append(h.Reasons, "risk band "+d.Risk.Band+" exceeds the warn threshold")
		}
	}

	if d.Vulns != nil {
		any = true
		if d.Vulns.Quarantined {
			h.Blocking = true
			h.Reasons = append(h.Reasons, "quarantined by the vulnerability gate")
		}
		if d.Vulns.Critical > 0 || d.Vulns.High > 0 {
			h.Reasons = append(h.Reasons, vulnReason(d.Vulns))
		}
	}

	if l := d.LLMPackageScan; l != nil {
		any = true
		// "Reads as", not "the model judged": the disposition is the model's
		// answer after the thresholds and the proxy's own checks, and the two can
		// differ (a package the model passed can be held for addressing it).
		switch {
		case l.Refused:
			h.Blocking = true
			h.Reasons = append(h.Reasons, "the LLM package-content scan reads the package as "+l.Disposition)
		case l.Disposition == "malicious" || l.Disposition == "suspicious":
			h.Reasons = append(h.Reasons, "the LLM package-content scan reads the package as "+l.Disposition+" (served: not enforced by the configured action)")
		}
	}

	if d.Findings != nil {
		any = true
		if d.Findings.Blocking > 0 {
			h.Blocking = true
			h.Reasons = append(h.Reasons, pluralize(d.Findings.Blocking, "blocking admission finding"))
		}
	}

	if d.License != nil {
		any = true
		switch d.License.Disposition {
		case "denied":
			h.Blocking = true
			h.Reasons = append(h.Reasons, "denied license: "+strings.Join(d.License.Licenses, ", "))
		case "review":
			h.Reasons = append(h.Reasons, "license requires review: "+strings.Join(d.License.Licenses, ", "))
		}
	}

	if d.Signature != nil {
		any = true
		if !d.Signature.Verified {
			h.Reasons = append(h.Reasons, "signature is unverified")
		}
	}

	if d.Provenance != nil {
		any = true
		if d.Provenance.ProvenanceMismatch {
			h.Blocking = true
			h.Reasons = append(h.Reasons, "build-provenance source mismatch")
		}
	}

	if d.Reproduce != nil {
		any = true
		if d.Reproduce.Mismatch {
			h.Blocking = true
			h.Reasons = append(h.Reasons, "reproducible-build digest mismatch")
		}
	}

	if d.SbomDrift != nil {
		any = true
		if d.SbomDrift.Significant {
			h.Reasons = append(h.Reasons, "significant SBOM drift (score "+trimFloat(d.SbomDrift.DriftScore)+")")
		}
	}

	if d.Approvals != nil && d.Approvals.Active > 0 {
		any = true
		h.Reasons = append(h.Reasons, pluralize(d.Approvals.Active, "active break-glass exception"))
	}

	// Resolve the verdict.
	switch {
	case h.Blocking:
		h.Verdict = VerdictBlock
	case len(h.Reasons) > 0:
		h.Verdict = VerdictWarn
	case any:
		h.Verdict = VerdictAdmit
	default:
		h.Verdict = VerdictUnknown
	}
	h.Summary = headlineSummary(d, h)
	return h
}

func headlineSummary(d *Dossier, h Headline) string {
	coord := d.Coordinate
	if d.Ecosystem != "" {
		coord = d.Ecosystem + "/" + coord
	}
	switch h.Verdict {
	case VerdictBlock:
		return coord + " would be BLOCKED: " + firstReason(h.Reasons)
	case VerdictWarn:
		return coord + " admitted with warnings: " + firstReason(h.Reasons)
	case VerdictAdmit:
		return coord + " is clean across all wired security gates"
	default:
		return "no security signal recorded for " + coord
	}
}

func firstReason(rs []string) string {
	if len(rs) == 0 {
		return ""
	}
	return rs[0]
}

func vulnReason(v *VulnSection) string {
	parts := make([]string, 0, 2)
	if v.Critical > 0 {
		parts = append(parts, pluralize(v.Critical, "critical vulnerability"))
	}
	if v.High > 0 {
		parts = append(parts, pluralize(v.High, "high vulnerability"))
	}
	return strings.Join(parts, ", ")
}
