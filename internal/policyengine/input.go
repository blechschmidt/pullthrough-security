package policyengine

// This file defines the structured admission input document. It deliberately
// uses plain, self-describing structs (no imports of the concrete gate packages
// vulnscan/license/sigverify/secretscan/nameguard/provenance) so the engine
// stays decoupled and unit-testable in isolation, mirroring the admin package's
// "narrow interface" philosophy. The wiring layer (cmd/pullthrough) is
// responsible for translating each gate's report into these structs.
//
// Each optional section is a pointer: a nil section is omitted from the rendered
// document so that `has(input.vuln)` is a meaningful presence test in rules, and
// absent sub-fields evaluate to a clean false/zero rather than erroring.

// Input is the aggregate admission signal document evaluated by policy rules.
type Input struct {
	Artifact      ArtifactInput       `json:"artifact"`
	Tenant        string              `json:"tenant,omitempty"`
	Vuln          *VulnInput          `json:"vuln,omitempty"`
	License       *LicenseInput       `json:"license,omitempty"`
	Signature     *SignatureInput     `json:"signature,omitempty"`
	Secret        *SecretInput        `json:"secret,omitempty"`
	Nameguard     *NameguardInput     `json:"nameguard,omitempty"`
	Provenance    *ProvenanceInput    `json:"provenance,omitempty"`
	InstallHooks  *InstallHooksInput  `json:"installHooks,omitempty"`
	MLGuard       *MLGuardInput       `json:"mlGuard,omitempty"`
	AVScan        *AVScanInput        `json:"avScan,omitempty"`
	ContentScan   *ContentScanInput   `json:"contentScan,omitempty"`
	RepoHealth    *RepoHealthInput    `json:"repoHealth,omitempty"`
	SbomDrift     *SbomDriftInput     `json:"sbomDrift,omitempty"`
	RebuildVerify *RebuildVerifyInput `json:"rebuildVerify,omitempty"`
	BuildProv     *BuildProvInput     `json:"buildProv,omitempty"`
	PyPIAttest    *PyPIAttestInput    `json:"pypiAttest,omitempty"`
	Incident      *IncidentInput      `json:"incident,omitempty"`
	Continuity    *ContinuityInput    `json:"continuity,omitempty"`
}

// ContinuityInput projects the maintainer/publisher continuity verdict (Task 91):
// whether the publisher principals observed for a coordinate (the maintainer
// roster, publishing namespace, and signing-key identity) changed relative to the
// durable trust-on-first-use known-maintainer set. A drift on a previously-seen
// package — a brand-new maintainer, a rotated signing key, or a new namespace
// owner — is the classic precursor to an account-takeover / hijack, and a rule can
// deny on `has(input.continuity) && input.continuity.drift`.
type ContinuityInput struct {
	// Evaluated is true when the gate derived a publisher identity and compared it.
	Evaluated bool `json:"evaluated"`
	// Drift — one or more previously-unseen publisher principals appeared.
	Drift bool `json:"drift"`
	// FirstUse — this was the first observation (TOFU established); not a drift.
	FirstUse bool `json:"firstUse"`
	// Disposition is the effective per-(tenant, ecosystem) disposition
	// (observe|warn|block).
	Disposition string `json:"disposition,omitempty"`
	// Added / Removed are the changed publisher principals.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// NewMaintainers is the count of newly-appeared principals.
	NewMaintainers int `json:"newMaintainers"`
	// TrustedCount is the size of the established trusted set.
	TrustedCount int `json:"trustedCount"`
	// PreviousVersion / Version bracket the change.
	PreviousVersion string `json:"previousVersion,omitempty"`
	Version         string `json:"version,omitempty"`
	// CooldownActive — the new maintainer is still within its trust cooldown.
	CooldownActive bool `json:"cooldownActive"`
	// Reason is a human-readable explanation of the verdict.
	Reason string `json:"reason,omitempty"`
}

func (c *ContinuityInput) document() map[string]any {
	return map[string]any{
		"evaluated":       c.Evaluated,
		"drift":           c.Drift,
		"firstUse":        c.FirstUse,
		"disposition":     c.Disposition,
		"added":           toAnyStrings(c.Added),
		"removed":         toAnyStrings(c.Removed),
		"newMaintainers":  int64(c.NewMaintainers),
		"trustedCount":    int64(c.TrustedCount),
		"previousVersion": c.PreviousVersion,
		"version":         c.Version,
		"cooldownActive":  c.CooldownActive,
	}
}

// IncidentInput projects the active emergency-lockdown / global kill-switch
// posture (Task 74) into the admission document. It lets operator-authored rules
// react to an active incident — most usefully `has(input.incident) &&
// input.incident.strict` to deny anything borderline org-wide for the duration of
// the incident — without re-editing each gate's own config. A nil section means
// no lockdown is engaged.
type IncidentInput struct {
	// Active is always true when this section is present (a nil section means no
	// lockdown), included so rules can test it explicitly.
	Active bool `json:"active"`
	// Mode is the lockdown posture: "freeze", "strict", or "block".
	Mode string `json:"mode"`
	// Strict is a convenience flag (Mode == "strict"): the hardened, enforce-
	// everything posture that asks every observe-mode gate to block.
	Strict bool `json:"strict"`
	// IncidentID is the operator-supplied incident identifier.
	IncidentID string `json:"incidentId,omitempty"`
}

func (i *IncidentInput) document() map[string]any {
	return map[string]any{
		"active":     i.Active,
		"mode":       i.Mode,
		"strict":     i.Strict,
		"incidentId": i.IncidentID,
	}
}

// BuildProvInput projects the inbound build-provenance verification verdict (Task
// 72): whether an upstream-published build-provenance attestation (npm provenance
// / GitHub artifact attestation) was found, cryptographically verified, and tied
// to a trusted signer — and, decisively, whether the source commit/repository the
// signed attestation PROVES disagrees with the commit/repository the package
// metadata CLAIMS (a mismatch a rule can deny on). It complements the signature
// gate's SignatureInput (which establishes authenticity) by binding the artifact
// to its exact source build.
type BuildProvInput struct {
	// Checked is true when the gate evaluated the artifact.
	Checked bool `json:"checked"`
	// Source records where the provenance came from (npm-provenance|github-attestations).
	Source string `json:"source,omitempty"`
	// Present — an inbound provenance attestation was discovered.
	Present bool `json:"present"`
	// Verified — a SLSA-provenance attestation verified cryptographically and bound
	// this artifact's digest.
	Verified bool `json:"verified"`
	// SourceVerified — the verifying attestation additionally chained to a trusted
	// root with an allowed identity (the proven source is authenticated).
	SourceVerified bool `json:"sourceVerified"`
	// Mismatch — the proven source disagrees with the claimed package-to-commit
	// association.
	Mismatch bool `json:"mismatch"`
	// CommitSHA / RepositoryURL / Builder identify the PROVEN source.
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	Builder       string `json:"builder,omitempty"`
	// WorkflowRef is the signer identity (the CI workflow) that built the artifact.
	WorkflowRef string `json:"workflowRef,omitempty"`
	// ClaimedCommitSHA / ClaimedRepositoryURL are the metadata-claimed source the
	// proven source was cross-checked against.
	ClaimedCommitSHA     string `json:"claimedCommitSha,omitempty"`
	ClaimedRepositoryURL string `json:"claimedRepositoryUrl,omitempty"`
	// MaxSeverity is the worst finding severity; Error is set on an infra failure.
	MaxSeverity string `json:"maxSeverity,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (b *BuildProvInput) document() map[string]any {
	return map[string]any{
		"checked":              b.Checked,
		"source":               b.Source,
		"present":              b.Present,
		"verified":             b.Verified,
		"sourceVerified":       b.SourceVerified,
		"mismatch":             b.Mismatch,
		"commitSha":            b.CommitSHA,
		"repositoryUrl":        b.RepositoryURL,
		"builder":              b.Builder,
		"workflowRef":          b.WorkflowRef,
		"claimedCommitSha":     b.ClaimedCommitSHA,
		"claimedRepositoryUrl": b.ClaimedRepositoryURL,
		"maxSeverity":          b.MaxSeverity,
		"error":                b.Error,
	}
}

// PyPIAttestInput projects the inbound PyPI PEP 740 digital-attestation verdict
// (Task 146): whether a Trusted-Publisher attestation was found for a served
// wheel/sdist, cryptographically verified, bound the served distribution's sha256
// digest, and — decisively — whether a cryptographically-valid attestation
// attests a DIFFERENT digest than the one served (a rule can deny on
// `has(input.pypiAttest) && input.pypiAttest.digestMismatch`). It complements the
// signature gate (authenticity) and the npm/GitHub build-provenance gate with the
// verification model PyPI itself publishes.
type PyPIAttestInput struct {
	// Checked is true when the gate evaluated the distribution.
	Checked bool `json:"checked"`
	// Source records where the material came from (pypi-attestations).
	Source string `json:"source,omitempty"`
	// Present — a PEP 740 attestation was discovered.
	Present bool `json:"present"`
	// Verified — an attestation cryptographically verified and bound this
	// distribution's digest.
	Verified bool `json:"verified"`
	// PublisherTrusted — the verifying attestation additionally chained to a trusted
	// Fulcio root with an allowed Trusted-Publisher identity.
	PublisherTrusted bool `json:"publisherTrusted"`
	// DigestMismatch — a valid attestation attests a different digest than served.
	DigestMismatch bool `json:"digestMismatch"`
	// TransparencyVerified — a verified attestation carried a verifiable Rekor
	// inclusion proof / SET.
	TransparencyVerified bool `json:"transparencyVerified"`
	// PublisherKind / Repository / Workflow describe the declared Trusted Publisher.
	PublisherKind string `json:"publisherKind,omitempty"`
	Repository    string `json:"repository,omitempty"`
	Workflow      string `json:"workflow,omitempty"`
	// Identity / Issuer are the authenticated signer identity and OIDC issuer.
	Identity string `json:"identity,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	// MaxSeverity is the worst finding severity; Error is set on an infra failure.
	MaxSeverity string `json:"maxSeverity,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (p *PyPIAttestInput) document() map[string]any {
	return map[string]any{
		"checked":              p.Checked,
		"source":               p.Source,
		"present":              p.Present,
		"verified":             p.Verified,
		"publisherTrusted":     p.PublisherTrusted,
		"digestMismatch":       p.DigestMismatch,
		"transparencyVerified": p.TransparencyVerified,
		"publisherKind":        p.PublisherKind,
		"repository":           p.Repository,
		"workflow":             p.Workflow,
		"identity":             p.Identity,
		"issuer":               p.Issuer,
		"maxSeverity":          p.MaxSeverity,
		"error":                p.Error,
	}
}

// RebuildVerifyInput projects the reproducible-build verification verdict (Task
// 68): whether the upstream-served artifact could be deterministically rebuilt
// from its attested source commit and the rebuilt digest compared. A confirmed
// mismatch is a strong supply-chain-tampering signal a rule can deny on.
type RebuildVerifyInput struct {
	// Evaluated is true when a terminal verdict is available (not still pending).
	Evaluated bool `json:"evaluated"`
	// Verdict is reproducible|mismatch|unsupported|unattested.
	Verdict string `json:"verdict,omitempty"`
	// Reproducible / Mismatch are the two decisive verdicts surfaced as booleans.
	Reproducible bool `json:"reproducible"`
	Mismatch     bool `json:"mismatch"`
	// CommitSHA / RepositoryURL identify the attested source the rebuild ran from.
	CommitSHA     string `json:"commitSha,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// Builder names the builder that performed (or would perform) the rebuild.
	Builder string `json:"builder,omitempty"`
	// UpstreamDigest / RebuiltDigest are the two compared digests.
	UpstreamDigest string `json:"upstreamDigest,omitempty"`
	RebuiltDigest  string `json:"rebuiltDigest,omitempty"`
	// Reason is a human-readable explanation of the verdict.
	Reason string `json:"reason,omitempty"`
}

func (b *RebuildVerifyInput) document() map[string]any {
	return map[string]any{
		"evaluated":      b.Evaluated,
		"verdict":        b.Verdict,
		"reproducible":   b.Reproducible,
		"mismatch":       b.Mismatch,
		"commitSha":      b.CommitSHA,
		"repositoryUrl":  b.RepositoryURL,
		"builder":        b.Builder,
		"upstreamDigest": b.UpstreamDigest,
		"rebuiltDigest":  b.RebuiltDigest,
	}
}

// SbomDriftInput projects the SBOM diff & dependency-drift verdict (Task 64) for
// the policy engine: the version-to-version footprint change of the pulled
// coordinate and its derived drift-risk score, so a rule can deny a pull that
// suddenly grows a large or suspicious new dependency footprint.
type SbomDriftInput struct {
	// Evaluated is true when a prior version existed and a diff was computed.
	Evaluated bool `json:"evaluated"`
	// FromVersion / ToVersion are the two versions compared.
	FromVersion string `json:"fromVersion,omitempty"`
	ToVersion   string `json:"toVersion,omitempty"`
	// DriftScore is the composite 0..100 drift-risk score.
	DriftScore float64 `json:"driftScore"`
	// Significant is true when the score met the significance threshold.
	Significant bool `json:"significant"`
	// AddedDeps / RemovedDeps / VersionBumps summarize the dependency-set delta.
	AddedDeps    int `json:"addedDeps"`
	RemovedDeps  int `json:"removedDeps"`
	VersionBumps int `json:"versionBumps"`
	// NewNamespaces is the count of never-before-seen dependency namespaces.
	NewNamespaces int `json:"newNamespaces"`
	// NewLicenses / NewDeniedLicenses count newly-introduced licenses overall and
	// those the license policy denies or flags for review.
	NewLicenses       int `json:"newLicenses"`
	NewDeniedLicenses int `json:"newDeniedLicenses"`
	// NewVulnerabilities is the count of advisories affecting the new version but
	// not the prior one.
	NewVulnerabilities int `json:"newVulnerabilities"`
}

func (d *SbomDriftInput) document() map[string]any {
	return map[string]any{
		"evaluated":          d.Evaluated,
		"fromVersion":        d.FromVersion,
		"toVersion":          d.ToVersion,
		"driftScore":         d.DriftScore,
		"significant":        d.Significant,
		"addedDeps":          int64(d.AddedDeps),
		"removedDeps":        int64(d.RemovedDeps),
		"versionBumps":       int64(d.VersionBumps),
		"newNamespaces":      int64(d.NewNamespaces),
		"newLicenses":        int64(d.NewLicenses),
		"newDeniedLicenses":  int64(d.NewDeniedLicenses),
		"newVulnerabilities": int64(d.NewVulnerabilities),
	}
}

// ArtifactInput identifies the artifact under admission.
type ArtifactInput struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Backend   string `json:"backend,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// VulnInput summarizes the vulnerability-scan result (Task 15/18) after VEX
// adjudication (Task 27).
type VulnInput struct {
	Scanned       bool          `json:"scanned"`
	Scanner       string        `json:"scanner,omitempty"`
	MaxSeverity   string        `json:"maxSeverity,omitempty"`
	MaxCVSS       float64       `json:"maxCvss,omitempty"`
	Total         int           `json:"total"`
	CriticalCount int           `json:"criticalCount"`
	HighCount     int           `json:"highCount"`
	MediumCount   int           `json:"mediumCount"`
	LowCount      int           `json:"lowCount"`
	UnknownCount  int           `json:"unknownCount"`
	VEXSuppressed int           `json:"vexSuppressed"`
	VEXEscalated  int           `json:"vexEscalated"`
	Offline       bool          `json:"offline"`
	Error         string        `json:"error,omitempty"`
	Findings      []VulnFinding `json:"findings,omitempty"`
	// CriticalNotAffected counts critical findings adjudicated VEX not_affected.
	CriticalNotAffected int `json:"criticalNotAffected"`

	// Reachability analysis (Task 118). ReachabilityEnabled reports whether the
	// scan annotated findings with reachability; the counts tally findings by
	// reachability verdict, and ReachableSuppressed/ReachDowngraded tally how many
	// unreachable findings policy excluded from gating or down-ranked. Rules can key
	// on these to require, e.g., that a blocking critical be reachable.
	ReachabilityEnabled bool `json:"reachabilityEnabled"`
	ReachableCount      int  `json:"reachableCount"`
	UnreachableCount    int  `json:"unreachableCount"`
	ReachUnknownCount   int  `json:"reachUnknownCount"`
	ReachSuppressed     int  `json:"reachSuppressed"`
	ReachDowngraded     int  `json:"reachDowngraded"`
}

// VulnFinding is a single vulnerability surfaced to rules.
type VulnFinding struct {
	ID               string   `json:"id,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	CVSS             float64  `json:"cvss,omitempty"`
	Package          string   `json:"package,omitempty"`
	Version          string   `json:"version,omitempty"`
	Fixed            []string `json:"fixed,omitempty"`
	VEXStatus        string   `json:"vexStatus,omitempty"`
	VEXJustification string   `json:"vexJustification,omitempty"`
	Suppressed       bool     `json:"suppressed"`
	// Reachability is the finding's static-reachability verdict (reachable /
	// unreachable / unknown), empty when reachability analysis is disabled.
	// ReachSuppressed marks a finding excluded from gating because it was proven
	// unreachable and policy suppresses unreachable findings.
	Reachability    string `json:"reachability,omitempty"`
	ReachSuppressed bool   `json:"reachSuppressed,omitempty"`
}

// LicenseInput summarizes the license-compliance verdict (Task 28).
type LicenseInput struct {
	Evaluated      bool             `json:"evaluated"`
	Action         string           `json:"action,omitempty"` // allow|warn|block|quarantine
	Code           string           `json:"code,omitempty"`   // ok|denied|review|unknown|drift
	Allowed        bool             `json:"allowed"`
	Worst          string           `json:"worst,omitempty"`
	DriftDetected  bool             `json:"driftDetected"`
	DeniedLicenses []string         `json:"deniedLicenses,omitempty"`
	Findings       []LicenseFinding `json:"findings,omitempty"`
}

// LicenseFinding is a single component-level license issue.
type LicenseFinding struct {
	Component string `json:"component,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	License   string `json:"license,omitempty"`
	Category  string `json:"category,omitempty"`
	Drift     bool   `json:"drift,omitempty"`
}

// SignatureInput summarizes signature/attestation verification (Task 23).
type SignatureInput struct {
	Checked         bool   `json:"checked"`
	Source          string `json:"source,omitempty"`
	HasSignature    bool   `json:"hasSignature"`
	HasAttestation  bool   `json:"hasAttestation"`
	Verified        bool   `json:"verified"` // a signature verified
	Attested        bool   `json:"attested"` // an attestation verified
	CryptoValid     bool   `json:"cryptoValid"`
	Keyless         bool   `json:"keyless"`
	ChainTrusted    bool   `json:"chainTrusted"`
	IdentityTrusted bool   `json:"identityTrusted"`
	RekorVerified   bool   `json:"rekorVerified"`
	SLSAProvenance  bool   `json:"slsaProvenance"`
	Identity        string `json:"identity,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	MaxSeverity     string `json:"maxSeverity,omitempty"` // worst finding severity
	Error           string `json:"error,omitempty"`
}

// SecretInput summarizes deterministic secret-scan risk (Task 29).
type SecretInput struct {
	Scanned      bool            `json:"scanned"`
	FindingCount int             `json:"findingCount"`
	MaxSeverity  string          `json:"maxSeverity,omitempty"`
	Risk         int             `json:"risk"` // ordinal risk score (0..)
	Findings     []SecretFinding `json:"findings,omitempty"`
}

// SecretFinding is a single detected secret (match redacted upstream).
type SecretFinding struct {
	RuleID   string `json:"ruleId,omitempty"`
	Severity string `json:"severity,omitempty"`
	File     string `json:"file,omitempty"`
}

// NameguardInput summarizes typosquat / dependency-confusion detection (Task 19).
type NameguardInput struct {
	Scanned             bool               `json:"scanned"`
	FindingCount        int                `json:"findingCount"`
	MaxSeverity         string             `json:"maxSeverity,omitempty"`
	Typosquat           bool               `json:"typosquat"`
	DependencyConfusion bool               `json:"dependencyConfusion"`
	Homoglyph           bool               `json:"homoglyph"`
	Kinds               []string           `json:"kinds,omitempty"`
	Findings            []NameguardFinding `json:"findings,omitempty"`
}

// NameguardFinding is a single name-based suspicion.
type NameguardFinding struct {
	Kind     string `json:"kind,omitempty"`
	Severity string `json:"severity,omitempty"`
	Name     string `json:"name,omitempty"`
	Similar  string `json:"similar,omitempty"`
	Distance int    `json:"distance,omitempty"`
}

// ProvenanceInput summarizes package-to-commit provenance association (Task 8),
// joined with the source commit's scan verdict.
type ProvenanceInput struct {
	Found             bool   `json:"found"`
	Confidence        string `json:"confidence,omitempty"` // attested|claimed|heuristic
	SignatureVerified bool   `json:"signatureVerified"`
	ChainTrusted      bool   `json:"chainTrusted"`
	CommitSHA         string `json:"commitSha,omitempty"`
	RepositoryURL     string `json:"repositoryUrl,omitempty"`
	HasVerdict        bool   `json:"hasVerdict"`
	RiskScore         int    `json:"riskScore"`
	Malicious         bool   `json:"malicious"`
	HighestSeverity   string `json:"highestSeverity,omitempty"`
}

// InstallHooksInput summarizes the static install-script / lifecycle-hook risk
// analysis (Task 62): npm preinstall/install/postinstall, Python setup.py /
// pyproject build hooks, RubyGems native extensions + post_install_message, and
// Cargo build.rs, scored against deterministic high-risk patterns.
type InstallHooksInput struct {
	Scanned      bool                 `json:"scanned"`
	HookCount    int                  `json:"hookCount"`
	FindingCount int                  `json:"findingCount"`
	MaxSeverity  string               `json:"maxSeverity,omitempty"`
	Risk         int                  `json:"risk"` // ordinal 0..100 contribution
	Findings     []InstallHookFinding `json:"findings,omitempty"`
}

// InstallHookFinding is a single matched high-risk pattern in an install hook.
type InstallHookFinding struct {
	RuleID   string `json:"ruleId,omitempty"`
	Severity string `json:"severity,omitempty"`
	Hook     string `json:"hook,omitempty"` // e.g. "npm:postinstall"
	File     string `json:"file,omitempty"`
}

// MLGuardInput summarizes the ML weight-scanning gate (Task 110): the static
// pickle-opcode disassembly of a Hugging Face model/dataset weight file. A rule
// can deny on, e.g. `has(input.mlGuard) && input.mlGuard.unsafe` or key on the
// format to require safetensors.
type MLGuardInput struct {
	// Scanned is true when a pickle-format weight file was disassembled.
	Scanned bool `json:"scanned"`
	// Format is the recognized weight format ("pickle"|"safetensors"|"gguf"|...).
	Format string `json:"format,omitempty"`
	// SafeFormat is true for safetensors (tensor-only, no executable opcodes).
	SafeFormat bool `json:"safeFormat"`
	// Unsafe is true when at least one unsafe-import finding was raised.
	Unsafe       bool             `json:"unsafe"`
	FindingCount int              `json:"findingCount"`
	MaxSeverity  string           `json:"maxSeverity,omitempty"`
	Risk         int              `json:"risk"` // ordinal 0..100 contribution
	Imports      []string         `json:"imports,omitempty"`
	Findings     []MLGuardFinding `json:"findings,omitempty"`
}

// MLGuardFinding is a single flagged pickle import.
type MLGuardFinding struct {
	RuleID   string `json:"ruleId,omitempty"`
	Severity string `json:"severity,omitempty"`
	Import   string `json:"import,omitempty"`
	Stream   string `json:"stream,omitempty"`
}

func (m *MLGuardInput) document() map[string]any {
	findings := make([]map[string]any, 0, len(m.Findings))
	for _, f := range m.Findings {
		findings = append(findings, map[string]any{
			"ruleId":   f.RuleID,
			"severity": f.Severity,
			"import":   f.Import,
			"stream":   f.Stream,
		})
	}
	return map[string]any{
		"scanned":      m.Scanned,
		"format":       m.Format,
		"safeFormat":   m.SafeFormat,
		"unsafe":       m.Unsafe,
		"findingCount": m.FindingCount,
		"maxSeverity":  m.MaxSeverity,
		"risk":         m.Risk,
		"imports":      m.Imports,
		"findings":     findings,
	}
}

// AVScanInput summarizes the antivirus content-scanning gate (Task 136): the
// byte-level malware scan of a fetched artifact payload. A rule can deny on,
// e.g. `has(input.avScan) && input.avScan.infected`.
type AVScanInput struct {
	// Scanned is true when the engine returned a completed verdict.
	Scanned bool `json:"scanned"`
	// Engine is the scanning backend (e.g. "clamav").
	Engine string `json:"engine,omitempty"`
	// Infected is true when a malware signature matched.
	Infected bool `json:"infected"`
	// Signature is the matched malware signature name.
	Signature string `json:"signature,omitempty"`
	// Unavailable is true when the engine could not be reached (degraded scan).
	Unavailable bool `json:"unavailable,omitempty"`
	// Truncated is true when only a size-bounded prefix was scanned.
	Truncated    bool            `json:"truncated,omitempty"`
	FindingCount int             `json:"findingCount"`
	MaxSeverity  string          `json:"maxSeverity,omitempty"`
	Risk         int             `json:"risk"` // ordinal 0..100 contribution
	Findings     []AVScanFinding `json:"findings,omitempty"`
}

// AVScanFinding is a single antivirus detection.
type AVScanFinding struct {
	RuleID    string `json:"ruleId,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func (a *AVScanInput) document() map[string]any {
	findings := make([]map[string]any, 0, len(a.Findings))
	for _, f := range a.Findings {
		findings = append(findings, map[string]any{
			"ruleId":    f.RuleID,
			"severity":  f.Severity,
			"signature": f.Signature,
		})
	}
	return map[string]any{
		"scanned":      a.Scanned,
		"engine":       a.Engine,
		"infected":     a.Infected,
		"signature":    a.Signature,
		"unavailable":  a.Unavailable,
		"truncated":    a.Truncated,
		"findingCount": a.FindingCount,
		"maxSeverity":  a.MaxSeverity,
		"risk":         a.Risk,
		"findings":     findings,
	}
}

// ContentScanInput summarizes the package-payload static content-analysis gate
// (Task 138): the deterministic unpack-and-scan of a served source package's
// files for embedded native binaries, high-entropy blobs, obfuscated JavaScript,
// dynamic code-execution sinks, and in-source secrets. A rule can deny on, e.g.
// `has(input.contentScan) && input.contentScan.maxSeverity == "high"` or on a
// category appearing in `input.contentScan.categories`.
type ContentScanInput struct {
	// Scanned is true when the artifact was a recognized archive the gate unpacked.
	Scanned bool `json:"scanned"`
	// Action is the configured gate action ("annotate"|"downgrade"|"block").
	Action string `json:"action,omitempty"`
	// FilesScanned counts the archive entries examined.
	FilesScanned int `json:"filesScanned"`
	// Truncated/TimedOut report that a scan budget bound was hit.
	Truncated    bool   `json:"truncated,omitempty"`
	TimedOut     bool   `json:"timedOut,omitempty"`
	FindingCount int    `json:"findingCount"`
	MaxSeverity  string `json:"maxSeverity,omitempty"`
	Risk         int    `json:"risk"` // ordinal 0..100 contribution
	// Categories lists the distinct finding categories present (e.g.
	// "embedded-binary", "dynamic-exec"), for policy keying.
	Categories []string             `json:"categories,omitempty"`
	Findings   []ContentScanFinding `json:"findings,omitempty"`
}

// ContentScanFinding is a single flagged content pattern in a package file.
type ContentScanFinding struct {
	RuleID   string `json:"ruleId,omitempty"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
}

func (c *ContentScanInput) document() map[string]any {
	findings := make([]map[string]any, 0, len(c.Findings))
	for _, f := range c.Findings {
		findings = append(findings, map[string]any{
			"ruleId":   f.RuleID,
			"category": f.Category,
			"severity": f.Severity,
			"file":     f.File,
			"line":     f.Line,
		})
	}
	cats := make([]any, 0, len(c.Categories))
	for _, cat := range c.Categories {
		cats = append(cats, cat)
	}
	return map[string]any{
		"scanned":      c.Scanned,
		"action":       c.Action,
		"filesScanned": c.FilesScanned,
		"truncated":    c.Truncated,
		"timedOut":     c.TimedOut,
		"findingCount": c.FindingCount,
		"maxSeverity":  c.MaxSeverity,
		"risk":         c.Risk,
		"categories":   cats,
		"findings":     findings,
	}
}

// RepoHealthInput summarizes the source-repository health signals (Task 63)
// derived from the package's associated Git repository (via the provenance
// association). The signals are OpenSSF Scorecard-style and offline-derivable:
// branch-protection presence, signed-commit ratio, CI and security-policy
// presence, maintainer count / bus factor, recent activity, and dependency-update
// automation. Resolved is false when no local clone of the source repository was
// available (air-gapped and not mirrored), in which case the signal contributes
// nothing to admission decisions.
type RepoHealthInput struct {
	Evaluated         bool     `json:"evaluated"`
	Resolved          bool     `json:"resolved"`
	RepositoryURL     string   `json:"repositoryUrl,omitempty"`
	CommitSHA         string   `json:"commitSha,omitempty"`
	Health            int      `json:"health"` // 0..100 (higher = healthier)
	Risk              int      `json:"risk"`   // 0..100 (inverse of health)
	Grade             string   `json:"grade,omitempty"`
	BranchProtection  bool     `json:"branchProtection"`
	SignedCommitRatio float64  `json:"signedCommitRatio"`
	HasCI             bool     `json:"hasCi"`
	HasSecurityPolicy bool     `json:"hasSecurityPolicy"`
	Maintainers       int      `json:"maintainers"`
	BusFactor         int      `json:"busFactor"`
	LastActivityDays  int      `json:"lastActivityDays"`
	DepAutomation     bool     `json:"depAutomation"`
	Online            bool     `json:"online"`
	Weak              []string `json:"weak,omitempty"`
	Error             string   `json:"error,omitempty"`
}

// Document renders the Input as the nested map[string]any the expression
// evaluator walks. Optional sections are included only when present. Aggregate
// convenience fields (e.g. vuln.hasCritical) are computed here so that common
// rules need neither comprehensions nor manual counting.
func (in Input) Document() map[string]any {
	doc := map[string]any{
		"artifact": map[string]any{
			"ecosystem": in.Artifact.Ecosystem,
			"backend":   in.Artifact.Backend,
			"name":      in.Artifact.Name,
			"version":   in.Artifact.Version,
			"digest":    in.Artifact.Digest,
		},
		"tenant": in.Tenant,
	}
	if in.Vuln != nil {
		doc["vuln"] = in.Vuln.document()
	}
	if in.License != nil {
		doc["license"] = in.License.document()
	}
	if in.Signature != nil {
		doc["signature"] = in.Signature.document()
	}
	if in.Secret != nil {
		doc["secret"] = in.Secret.document()
	}
	if in.Nameguard != nil {
		doc["nameguard"] = in.Nameguard.document()
	}
	if in.Provenance != nil {
		doc["provenance"] = in.Provenance.document()
	}
	if in.InstallHooks != nil {
		doc["installHooks"] = in.InstallHooks.document()
	}
	if in.MLGuard != nil {
		doc["mlGuard"] = in.MLGuard.document()
	}
	if in.AVScan != nil {
		doc["avScan"] = in.AVScan.document()
	}
	if in.ContentScan != nil {
		doc["contentScan"] = in.ContentScan.document()
	}
	if in.RepoHealth != nil {
		doc["repoHealth"] = in.RepoHealth.document()
	}
	if in.SbomDrift != nil {
		doc["sbomDrift"] = in.SbomDrift.document()
	}
	if in.RebuildVerify != nil {
		doc["rebuildVerify"] = in.RebuildVerify.document()
	}
	if in.BuildProv != nil {
		doc["buildProv"] = in.BuildProv.document()
	}
	if in.PyPIAttest != nil {
		doc["pypiAttest"] = in.PyPIAttest.document()
	}
	if in.Incident != nil {
		doc["incident"] = in.Incident.document()
	}
	if in.Continuity != nil {
		doc["continuity"] = in.Continuity.document()
	}
	return doc
}

func (v *VulnInput) document() map[string]any {
	findings := make([]any, 0, len(v.Findings))
	for _, f := range v.Findings {
		findings = append(findings, map[string]any{
			"id":               f.ID,
			"severity":         f.Severity,
			"cvss":             f.CVSS,
			"package":          f.Package,
			"version":          f.Version,
			"fixed":            toAnyStrings(f.Fixed),
			"vexStatus":        f.VEXStatus,
			"vexJustification": f.VEXJustification,
			"suppressed":       f.Suppressed,
			"reachability":     f.Reachability,
			"reachSuppressed":  f.ReachSuppressed,
		})
	}
	// A critical CVE is "unresolved" when it is neither VEX-suppressed nor
	// adjudicated not_affected; this is the signal most deny rules key on.
	criticalUnresolved := v.CriticalCount - v.CriticalNotAffected
	if criticalUnresolved < 0 {
		criticalUnresolved = 0
	}
	return map[string]any{
		"scanned":               v.Scanned,
		"scanner":               v.Scanner,
		"maxSeverity":           v.MaxSeverity,
		"maxCvss":               v.MaxCVSS,
		"total":                 int64(v.Total),
		"criticalCount":         int64(v.CriticalCount),
		"highCount":             int64(v.HighCount),
		"mediumCount":           int64(v.MediumCount),
		"lowCount":              int64(v.LowCount),
		"unknownCount":          int64(v.UnknownCount),
		"vexSuppressed":         int64(v.VEXSuppressed),
		"vexEscalated":          int64(v.VEXEscalated),
		"criticalNotAffected":   int64(v.CriticalNotAffected),
		"criticalUnresolved":    int64(criticalUnresolved),
		"hasCritical":           v.CriticalCount > 0,
		"hasHigh":               v.HighCount > 0,
		"hasUnresolvedCritical": criticalUnresolved > 0,
		"offline":               v.Offline,
		"error":                 v.Error,
		"findings":              findings,
		"reachabilityEnabled":   v.ReachabilityEnabled,
		"reachableCount":        int64(v.ReachableCount),
		"unreachableCount":      int64(v.UnreachableCount),
		"reachUnknownCount":     int64(v.ReachUnknownCount),
		"reachSuppressed":       int64(v.ReachSuppressed),
		"reachDowngraded":       int64(v.ReachDowngraded),
	}
}

func (l *LicenseInput) document() map[string]any {
	findings := make([]any, 0, len(l.Findings))
	for _, f := range l.Findings {
		findings = append(findings, map[string]any{
			"component": f.Component,
			"outcome":   f.Outcome,
			"license":   f.License,
			"category":  f.Category,
			"drift":     f.Drift,
		})
	}
	return map[string]any{
		"evaluated":      l.Evaluated,
		"action":         l.Action,
		"code":           l.Code,
		"allowed":        l.Allowed,
		"denied":         l.Code == "denied",
		"worst":          l.Worst,
		"driftDetected":  l.DriftDetected,
		"deniedLicenses": toAnyStrings(l.DeniedLicenses),
		"findings":       findings,
	}
}

func (s *SignatureInput) document() map[string]any {
	return map[string]any{
		"checked":         s.Checked,
		"source":          s.Source,
		"hasSignature":    s.HasSignature,
		"hasAttestation":  s.HasAttestation,
		"verified":        s.Verified,
		"attested":        s.Attested,
		"cryptoValid":     s.CryptoValid,
		"keyless":         s.Keyless,
		"chainTrusted":    s.ChainTrusted,
		"identityTrusted": s.IdentityTrusted,
		"rekorVerified":   s.RekorVerified,
		"slsaProvenance":  s.SLSAProvenance,
		"identity":        s.Identity,
		"issuer":          s.Issuer,
		"maxSeverity":     s.MaxSeverity,
		"error":           s.Error,
	}
}

func (s *SecretInput) document() map[string]any {
	findings := make([]any, 0, len(s.Findings))
	for _, f := range s.Findings {
		findings = append(findings, map[string]any{
			"ruleId":   f.RuleID,
			"severity": f.Severity,
			"file":     f.File,
		})
	}
	return map[string]any{
		"scanned":      s.Scanned,
		"findingCount": int64(s.FindingCount),
		"maxSeverity":  s.MaxSeverity,
		"risk":         int64(s.Risk),
		"hasFindings":  s.FindingCount > 0,
		"findings":     findings,
	}
}

func (n *NameguardInput) document() map[string]any {
	findings := make([]any, 0, len(n.Findings))
	for _, f := range n.Findings {
		findings = append(findings, map[string]any{
			"kind":     f.Kind,
			"severity": f.Severity,
			"name":     f.Name,
			"similar":  f.Similar,
			"distance": int64(f.Distance),
		})
	}
	return map[string]any{
		"scanned":             n.Scanned,
		"findingCount":        int64(n.FindingCount),
		"maxSeverity":         n.MaxSeverity,
		"typosquat":           n.Typosquat,
		"dependencyConfusion": n.DependencyConfusion,
		"homoglyph":           n.Homoglyph,
		"hasFindings":         n.FindingCount > 0,
		"kinds":               toAnyStrings(n.Kinds),
		"findings":            findings,
	}
}

func (p *ProvenanceInput) document() map[string]any {
	return map[string]any{
		"found":             p.Found,
		"confidence":        p.Confidence,
		"signatureVerified": p.SignatureVerified,
		"chainTrusted":      p.ChainTrusted,
		"commitSha":         p.CommitSHA,
		"repositoryUrl":     p.RepositoryURL,
		"hasVerdict":        p.HasVerdict,
		"riskScore":         int64(p.RiskScore),
		"malicious":         p.Malicious,
		"highestSeverity":   p.HighestSeverity,
		"attested":          p.Confidence == "attested",
	}
}

func (h *InstallHooksInput) document() map[string]any {
	findings := make([]any, 0, len(h.Findings))
	rules := make([]string, 0, len(h.Findings))
	for _, f := range h.Findings {
		findings = append(findings, map[string]any{
			"ruleId":   f.RuleID,
			"severity": f.Severity,
			"hook":     f.Hook,
			"file":     f.File,
		})
		rules = appendUniqueStr(rules, f.RuleID)
	}
	return map[string]any{
		"scanned":      h.Scanned,
		"hookCount":    int64(h.HookCount),
		"findingCount": int64(h.FindingCount),
		"maxSeverity":  h.MaxSeverity,
		"risk":         int64(h.Risk),
		"hasFindings":  h.FindingCount > 0,
		"hasHooks":     h.HookCount > 0,
		"rules":        toAnyStrings(rules),
		"findings":     findings,
	}
}

func (h *RepoHealthInput) document() map[string]any {
	return map[string]any{
		"evaluated":         h.Evaluated,
		"resolved":          h.Resolved,
		"repositoryUrl":     h.RepositoryURL,
		"commitSha":         h.CommitSHA,
		"health":            int64(h.Health),
		"risk":              int64(h.Risk),
		"grade":             h.Grade,
		"branchProtection":  h.BranchProtection,
		"signedCommitRatio": h.SignedCommitRatio,
		"hasCi":             h.HasCI,
		"hasSecurityPolicy": h.HasSecurityPolicy,
		"maintainers":       int64(h.Maintainers),
		"busFactor":         int64(h.BusFactor),
		"lastActivityDays":  int64(h.LastActivityDays),
		"depAutomation":     h.DepAutomation,
		"online":            h.Online,
		"weak":              toAnyStrings(h.Weak),
	}
}

func appendUniqueStr(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func toAnyStrings(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
