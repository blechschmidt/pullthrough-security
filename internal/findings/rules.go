package findings

import (
	"sort"
	"strings"
)

// The rule catalog is the finite, stable taxonomy SARIF consumers group and
// configure findings by. Each gate maps onto a small number of rules; the
// dynamic specifics of a given finding (which CVE, which license, which name)
// live in the result's message, identifier, and properties rather than in the
// rule id, so the catalog stays bounded and a CI policy that configures
// "vulnscan/vulnerable-dependency = error" applies uniformly.

// Rule is one catalog entry: its stable id, a display name, short/full
// descriptions, a help URI, the default SARIF level, and grouping tags.
type Rule struct {
	ID       string
	Gate     Gate
	Name     string
	Short    string
	Full     string
	HelpURI  string
	HelpText string
	Default  Level
	Tags     []string
	// External names the upstream standard/database a consumer can consult for
	// the underlying issue (surfaced in the rule property bag).
	External string
}

// Stable rule identifiers. They are "<gate>/<slug>" so the originating gate is
// legible in CI annotations and the namespace cannot collide.
const (
	RuleVulnerableDependency      = "vulnscan/vulnerable-dependency"
	RuleSuppressedVuln            = "vex/suppressed-vulnerability"
	RuleLicenseNonCompliant       = "license/non-compliant"
	RuleLicenseDrift              = "license/drift"
	RuleExposedSecret             = "secretscan/exposed-credential"
	RuleUnverifiedSignature       = "sigverify/unverified-signature"
	RuleTyposquat                 = "nameguard/typosquat"
	RuleDependencyConfusion       = "nameguard/dependency-confusion"
	RuleHomoglyph                 = "nameguard/homoglyph"
	RuleNameSuspicious            = "nameguard/suspicious-name"
	RuleRiskThreshold             = "riskscore/threshold-exceeded"
	RulePolicyViolation           = "policyengine/policy-violation"
	RuleUnverifiedProvenance      = "provenance/unverified"
	RuleMaliciousCommit           = "provenance/malicious-commit"
	RuleRiskyInstallScript        = "installhooks/risky-install-script"
	RuleMalwareDetected           = "avscan/malware-detected"
	RuleSuspiciousContent         = "contentscan/suspicious-content"
	RuleReproducibilityMismatch   = "rebuildverify/reproducibility-mismatch"
	RuleProvenanceSourceMismatch  = "buildprov/source-mismatch"
	RuleUnverifiedBuildProvenance = "buildprov/unverified-provenance"
	RulePyPIDigestMismatch        = "pypiattest/digest-mismatch"
	RuleUnverifiedPyPIAttestation = "pypiattest/unverified-attestation"
	RuleMaintainerDrift           = "continuity/maintainer-drift"
	RuleSuspiciousCommit          = "commitscan/suspicious-commit"
	RuleUnpinnedAction            = "actionpin/unpinned-action"
	RuleDisallowedActionOwner     = "actionpin/disallowed-owner"
)

// helpURIBase is the documentation anchor base every rule's HelpURI derives
// from, so an operator following a CI annotation lands on the gate's docs.
const helpURIBase = "https://github.com/blechschmidt/pullthrough-security/blob/main/docs/findings.md"

// catalog is the full rule set, keyed by id. Rendering emits only the rules a
// document actually references, in canonical order (catalogOrder).
var catalog = map[string]Rule{
	RuleVulnerableDependency: {
		ID: RuleVulnerableDependency, Gate: GateVulnscan, Name: "VulnerableDependency",
		Short:    "A known vulnerability (CVE/advisory) affects this artifact.",
		Full:     "The vulnerability-scanning gate generated an SBOM for the artifact and matched one or more of its components against a vulnerability database (OSV by default). Each result names the advisory, the affected component, and the fixed versions when known.",
		HelpURI:  helpURIBase + "#vulnerable-dependency",
		HelpText: "Upgrade the affected component to a fixed version, or apply a VEX statement if the artifact is not affected.",
		Default:  LevelError, Tags: []string{"security", "vulnerability", "supply-chain"},
		External: "https://osv.dev/",
	},
	RuleSuppressedVuln: {
		ID: RuleSuppressedVuln, Gate: GateVEX, Name: "SuppressedVulnerability",
		Short:    "A vulnerability adjudicated not-affected/fixed by a VEX statement.",
		Full:     "A known vulnerability matched the artifact but a VEX (Vulnerability Exploitability eXchange) statement adjudicated it away (not_affected or fixed). It is reported for transparency and flagged as a SARIF suppression so CI does not fail on it.",
		HelpURI:  helpURIBase + "#suppressed-vulnerability",
		HelpText: "No action required; review the VEX justification if the suppression is unexpected.",
		Default:  LevelNote, Tags: []string{"security", "vulnerability", "vex"},
		External: "https://openvex.dev/",
	},
	RuleLicenseNonCompliant: {
		ID: RuleLicenseNonCompliant, Gate: GateLicense, Name: "NonCompliantLicense",
		Short:    "A component license violates the configured compliance policy.",
		Full:     "The license-compliance gate evaluated the artifact's SPDX licenses against the allow/deny/review policy and found a denied (or review-required) license.",
		HelpURI:  helpURIBase + "#non-compliant-license",
		HelpText: "Remove or replace the offending dependency, or add the license to the allow list / review queue if it is acceptable for this tenant.",
		Default:  LevelError, Tags: []string{"license", "compliance", "supply-chain"},
		External: "https://spdx.org/licenses/",
	},
	RuleLicenseDrift: {
		ID: RuleLicenseDrift, Gate: GateLicense, Name: "LicenseDrift",
		Short:    "A component's license changed from a previously observed value.",
		Full:     "The license gate detected that a component's declared license differs from the value recorded on a prior pull — a supply-chain signal worth review even when the new license is itself allowed.",
		HelpURI:  helpURIBase + "#license-drift",
		HelpText: "Confirm the license change is legitimate and update the recorded baseline.",
		Default:  LevelWarning, Tags: []string{"license", "compliance", "drift"},
		External: "https://spdx.org/licenses/",
	},
	RuleExposedSecret: {
		ID: RuleExposedSecret, Gate: GateSecretscan, Name: "ExposedCredential",
		Short:    "A credential or secret was detected in the artifact's contents.",
		Full:     "The deterministic secret-detection pass matched a high-entropy or pattern-based credential (API key, token, private key) in the artifact's files. The matched value is redacted; the location points at the file.",
		HelpURI:  helpURIBase + "#exposed-credential",
		HelpText: "Revoke and rotate the exposed credential immediately, then remove it from the source.",
		Default:  LevelError, Tags: []string{"security", "secret", "credential"},
	},
	RuleUnverifiedSignature: {
		ID: RuleUnverifiedSignature, Gate: GateSigverify, Name: "UnverifiedSignature",
		Short:    "The artifact's authenticity could not be cryptographically verified.",
		Full:     "The signature/attestation gate could not establish a trusted cosign signature or SLSA provenance attestation for the artifact (missing, untrusted identity, broken chain, or a verification error).",
		HelpURI:  helpURIBase + "#unverified-signature",
		HelpText: "Require the publisher to sign the artifact (keyless or keyed cosign) and configure the trusted identity/issuer.",
		Default:  LevelError, Tags: []string{"security", "signature", "attestation", "slsa"},
		External: "https://docs.sigstore.dev/",
	},
	RuleTyposquat: {
		ID: RuleTyposquat, Gate: GateNameguard, Name: "Typosquat",
		Short:    "The package name closely resembles a popular package (typosquatting).",
		Full:     "The nameguard gate found the requested package name to be a near-miss of a well-known package, the hallmark of a typosquatting attack.",
		HelpURI:  helpURIBase + "#typosquat",
		HelpText: "Confirm the intended package name; the look-alike may be malicious.",
		Default:  LevelError, Tags: []string{"security", "typosquat", "supply-chain"},
	},
	RuleDependencyConfusion: {
		ID: RuleDependencyConfusion, Gate: GateNameguard, Name: "DependencyConfusion",
		Short:    "The package name shadows an internal/private package namespace.",
		Full:     "The nameguard gate found the requested public package name to collide with a configured internal namespace — the dependency-confusion attack pattern.",
		HelpURI:  helpURIBase + "#dependency-confusion",
		HelpText: "Scope the internal package or pin its source so the public look-alike cannot be substituted.",
		Default:  LevelError, Tags: []string{"security", "dependency-confusion", "supply-chain"},
	},
	RuleHomoglyph: {
		ID: RuleHomoglyph, Gate: GateNameguard, Name: "Homoglyph",
		Short:    "The package name contains homoglyph/confusable characters.",
		Full:     "The nameguard gate found visually-confusable (homoglyph) characters in the package name, which can disguise a malicious look-alike.",
		HelpURI:  helpURIBase + "#homoglyph",
		HelpText: "Confirm the package name uses the expected characters.",
		Default:  LevelWarning, Tags: []string{"security", "homoglyph", "supply-chain"},
	},
	RuleNameSuspicious: {
		ID: RuleNameSuspicious, Gate: GateNameguard, Name: "SuspiciousName",
		Short:    "The package name was flagged as suspicious by name-based heuristics.",
		Full:     "The nameguard gate flagged the requested package name through a heuristic other than the specific typosquat/confusion/homoglyph rules.",
		HelpURI:  helpURIBase + "#suspicious-name",
		HelpText: "Review the flagged name against the intended dependency.",
		Default:  LevelWarning, Tags: []string{"security", "supply-chain"},
	},
	RuleRiskThreshold: {
		ID: RuleRiskThreshold, Gate: GateRiskscore, Name: "RiskThresholdExceeded",
		Short:    "The artifact's composite supply-chain risk score met the admission threshold.",
		Full:     "The unified risk-scoring engine folded every gate signal into a composite 0-100 score whose band met or exceeded the configured admission threshold. The message names the top risk drivers.",
		HelpURI:  helpURIBase + "#risk-threshold-exceeded",
		HelpText: "Address the top contributing signals named in the message to lower the composite score below the threshold.",
		Default:  LevelWarning, Tags: []string{"security", "risk", "supply-chain"},
	},
	RulePolicyViolation: {
		ID: RulePolicyViolation, Gate: GatePolicyEngine, Name: "PolicyViolation",
		Short:    "The artifact violated an operator-authored admission policy rule.",
		Full:     "The policy-as-code engine evaluated the operator's declarative rules over the aggregated gate signals and a rule fired with a non-allow effect.",
		HelpURI:  helpURIBase + "#policy-violation",
		HelpText: "Review the named policy rule and the signals that triggered it.",
		Default:  LevelError, Tags: []string{"policy", "admission", "supply-chain"},
	},
	RuleUnverifiedProvenance: {
		ID: RuleUnverifiedProvenance, Gate: GateProvenance, Name: "UnverifiedProvenance",
		Short:    "The artifact has no verified build-provenance association to a source commit.",
		Full:     "The provenance gate could not establish (or could not fully trust) a build-provenance link from the artifact to its source commit.",
		HelpURI:  helpURIBase + "#unverified-provenance",
		HelpText: "Publish signed build provenance (e.g. GitHub build provenance attestations) so the artifact can be traced to a trusted commit.",
		Default:  LevelWarning, Tags: []string{"provenance", "slsa", "supply-chain"},
	},
	RuleMaliciousCommit: {
		ID: RuleMaliciousCommit, Gate: GateProvenance, Name: "MaliciousSourceCommit",
		Short:    "The artifact's source commit was assessed malicious by the commit scanner.",
		Full:     "The artifact is associated with a source commit that the LLM/deterministic commit-scanning pipeline flagged as malicious.",
		HelpURI:  helpURIBase + "#malicious-source-commit",
		HelpText: "Do not consume this artifact; investigate the flagged source commit.",
		Default:  LevelError, Tags: []string{"security", "provenance", "malicious"},
	},
	RuleSuspiciousCommit: {
		ID: RuleSuspiciousCommit, Gate: GateCommitScan, Name: "SuspiciousSourceCommit",
		Short:    "A watched repository's commit was flagged by the continuous commit scanner.",
		Full:     "The continuous Git commit scanner (webhook/polling-driven) scanned a new commit in a watched repository and the LLM/deterministic pipeline flagged a supply-chain risk — malicious code, an embedded credential, obfuscation, a suspicious dependency, data exfiltration, a backdoor, or build tampering. The finding is keyed by repository and commit SHA.",
		HelpURI:  helpURIBase + "#suspicious-source-commit",
		HelpText: "Investigate the flagged commit in the named repository before any artifact built from it is consumed; the category and detail are in the result properties.",
		Default:  LevelWarning, Tags: []string{"security", "commit", "supply-chain"},
	},
	RuleRiskyInstallScript: {
		ID: RuleRiskyInstallScript, Gate: GateInstallHooks, Name: "RiskyInstallScript",
		Short:    "A package install/lifecycle hook contains a high-risk pattern.",
		Full:     "The install-hook analysis gate statically extracted the package's install/lifecycle scripts (npm pre/post-install, Python setup.py / pyproject build hooks, RubyGems native extensions and post-install message, Cargo build.rs) and matched a high-risk pattern — network egress during install, base64-decoded eval, shell/process spawning, writes outside the package directory, environment-variable exfiltration, or an obfuscated one-liner. No script was executed.",
		HelpURI:  helpURIBase + "#risky-install-script",
		HelpText: "Review the flagged install hook; legitimate packages rarely fetch remote code or exfiltrate the environment at install time. The matched rule and an excerpt are in the result properties.",
		Default:  LevelError, Tags: []string{"security", "install-script", "supply-chain"},
	},
	RuleMalwareDetected: {
		ID: RuleMalwareDetected, Gate: GateAVScan, Name: "MalwareDetected",
		Short:    "The artifact payload matched an antivirus malware signature.",
		Full:     "The antivirus content-scanning gate streamed the fetched artifact's bytes (package archive, wheel, jar, OCI layer blob, ML weight file, or Git LFS object) through the configured AV engine (ClamAV via the clamd INSTREAM protocol) and the engine matched a known-malware signature. Unlike the coordinate-level OSV malware feed, this is a byte-level detection of the payload actually served.",
		HelpURI:  helpURIBase + "#malware-detected",
		HelpText: "Treat the artifact as malicious: do not consume it. The matched signature name is in the result properties. Verify the engine's signature database is current and, if the detection is a confirmed false positive, allow the coordinate through the break-glass approval workflow.",
		Default:  LevelError, Tags: []string{"security", "malware", "antivirus", "supply-chain"},
	},
	RuleSuspiciousContent: {
		ID: RuleSuspiciousContent, Gate: GateContentScan, Name: "SuspiciousContent",
		Short:    "A package file contains statically-suspicious content.",
		Full:     "The package-payload content-analysis gate unpacked the served source artifact and applied deterministic heuristics to its files, flagging one or more of: a high-entropy embedded blob (a packed or encrypted payload), an unexpectedly embedded native binary in a nominally-source package, obfuscated or minified-plus-eval JavaScript, a dynamic code-execution sink (eval/exec, base64-decode-then-run, or a remote script piped into a shell), or an in-source credential/secret. No code was executed.",
		HelpURI:  helpURIBase + "#suspicious-content",
		HelpText: "Review the flagged file(s); the category, rule, and a redacted excerpt are in the result properties. A native binary or packed blob inside a source package, obfuscated code, or an in-source secret rarely has a legitimate reason to ship in a published package.",
		Default:  LevelWarning, Tags: []string{"security", "content-analysis", "obfuscation", "secret", "supply-chain"},
	},
	RuleReproducibilityMismatch: {
		ID: RuleReproducibilityMismatch, Gate: GateRebuildVerify, Name: "ReproducibilityMismatch",
		Short:    "The artifact could not be reproduced from its attested source commit.",
		Full:     "The reproducible-build verification gate rebuilt the artifact from its attested source commit (via the provenance association) inside a sandboxed, pinned toolchain and the rebuilt artifact's digest did NOT match the upstream-served artifact. The served binary therefore does not provably derive from the attested source — a strong supply-chain-tampering or build-injection indicator.",
		HelpURI:  helpURIBase + "#reproducibility-mismatch",
		HelpText: "Do not consume this artifact until the mismatch is explained: confirm the source commit, the build toolchain version, and the build flags, and investigate whether the upstream binary was tampered with after building.",
		Default:  LevelError, Tags: []string{"security", "reproducible-build", "provenance", "supply-chain"},
		External: "https://reproducible-builds.org/",
	},
	RuleProvenanceSourceMismatch: {
		ID: RuleProvenanceSourceMismatch, Gate: GateBuildProv, Name: "BuildProvenanceSourceMismatch",
		Short:    "The signed build provenance proves a different source than the package metadata claims.",
		Full:     "The inbound build-provenance gate verified the upstream-published build-provenance attestation (npm provenance / GitHub artifact attestation) and cryptographically bound the package version to a source repository and commit. That PROVEN source disagrees with the commit/repository the package metadata CLAIMS — a strong supply-chain signal that the published metadata misrepresents where the artifact was built.",
		HelpURI:  helpURIBase + "#build-provenance-source-mismatch",
		HelpText: "Do not consume this artifact until the discrepancy is explained: the signed attestation and the package metadata name different source commits/repositories. Confirm the real source of the release.",
		Default:  LevelError, Tags: []string{"security", "provenance", "slsa", "supply-chain"},
		External: "https://slsa.dev/provenance/v1",
	},
	RuleUnverifiedBuildProvenance: {
		ID: RuleUnverifiedBuildProvenance, Gate: GateBuildProv, Name: "UnverifiedBuildProvenance",
		Short:    "An inbound build-provenance attestation was present but could not be verified.",
		Full:     "The inbound build-provenance gate found an upstream-published build-provenance attestation for the artifact but could not establish trust in it: the DSSE signature did not validate against its signing certificate, the attestation did not bind this artifact's digest, or (when a trusted signer is required) its signer was not trusted.",
		HelpURI:  helpURIBase + "#unverified-build-provenance",
		HelpText: "Confirm the artifact's published build provenance is intact and signed by a trusted identity; a present-but-invalid attestation can indicate tampering.",
		Default:  LevelWarning, Tags: []string{"security", "provenance", "slsa", "supply-chain"},
	},
	RuleUnpinnedAction: {
		ID: RuleUnpinnedAction, Gate: GateActionPin, Name: "UnpinnedAction",
		Short:    "A GitHub Actions reference is pinned to a mutable ref, not a commit SHA.",
		Full:     "The GitHub Actions pinning gate parsed the `uses:` references in a repository's .github/workflows/*.yml and composite action.yml files and found a third-party action or reusable workflow pinned to a mutable git ref — a branch name or a floating tag such as @v4 — or to no ref at all, rather than to a full 40-character commit SHA. A mutable ref can be moved by whoever controls the upstream tag/branch to point at arbitrary code that then runs with the workflow's credentials (the tj-actions/changed-files compromise, CVE-2025-30066). No workflow was executed.",
		HelpURI:  helpURIBase + "#unpinned-action",
		HelpText: "Pin the action to a full 40-character commit SHA (e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`) instead of a tag or branch. The offending reference and its pinning classification are in the result properties.",
		Default:  LevelWarning, Tags: []string{"security", "github-actions", "pinning", "supply-chain"},
		External: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
	},
	RuleDisallowedActionOwner: {
		ID: RuleDisallowedActionOwner, Gate: GateActionPin, Name: "DisallowedActionOwner",
		Short:    "A GitHub Actions reference targets an owner/org outside the allowlist.",
		Full:     "The GitHub Actions pinning gate found a `uses:` reference to an action or reusable workflow whose owner/org is not among the configured permitted owners. Restricting workflows to a vetted set of action publishers shrinks the third-party supply-chain surface that runs with the workflow's credentials.",
		HelpURI:  helpURIBase + "#disallowed-action-owner",
		HelpText: "Replace the action with one from a permitted owner, or add the owner to the allowlist if it is trusted. The offending reference and its owner are in the result properties.",
		Default:  LevelError, Tags: []string{"security", "github-actions", "allowlist", "supply-chain"},
		External: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
	},
	RulePyPIDigestMismatch: {
		ID: RulePyPIDigestMismatch, Gate: GatePyPIAttest, Name: "PyPIAttestationDigestMismatch",
		Short:    "A valid PyPI PEP 740 attestation attests a different distribution digest than the one served.",
		Full:     "The inbound PyPI PEP 740 attestation gate verified a Trusted-Publisher digital attestation for this distribution and found it cryptographically valid, but the sha256 digest it attests does not match the digest of the wheel/sdist the proxy served. The served file is not the file the publisher attested — a strong tampering / substitution signal.",
		HelpURI:  helpURIBase + "#pypi-attestation-digest-mismatch",
		HelpText: "Do not consume this artifact until the discrepancy is explained: a valid publisher attestation exists but it is for a different distribution digest. Re-pull from a trusted mirror and confirm the file was not substituted.",
		Default:  LevelError, Tags: []string{"security", "provenance", "pypi", "pep740", "supply-chain"},
		External: "https://peps.python.org/pep-0740/",
	},
	RuleUnverifiedPyPIAttestation: {
		ID: RuleUnverifiedPyPIAttestation, Gate: GatePyPIAttest, Name: "UnverifiedPyPIAttestation",
		Short:    "A PyPI PEP 740 attestation was present but could not be verified.",
		Full:     "The inbound PyPI PEP 740 attestation gate found a Trusted-Publisher digital attestation for the distribution but could not establish trust in it: the DSSE signature did not validate against its signing certificate, no verifying attestation bound this distribution's sha256 digest, or (when a trusted publisher is required) its publisher was not trusted.",
		HelpURI:  helpURIBase + "#unverified-pypi-attestation",
		HelpText: "Confirm the distribution's published PEP 740 attestation is intact and signed by a trusted Trusted-Publisher identity; a present-but-invalid attestation can indicate tampering.",
		Default:  LevelWarning, Tags: []string{"security", "provenance", "pypi", "pep740", "supply-chain"},
		External: "https://peps.python.org/pep-0740/",
	},
	RuleMaintainerDrift: {
		ID: RuleMaintainerDrift, Gate: GateContinuity, Name: "MaintainerDrift",
		Short:    "The package's maintainer/publisher identity changed from the known-trusted set.",
		Full:     "The maintainer/publisher continuity gate compared the publisher principals observed for this coordinate (the registry maintainer roster, the publishing namespace owner, and any signing-key identity) against the durable trust-on-first-use known-maintainer set, and found one or more previously-unseen principals on an already-known package. A brand-new maintainer, a rotated publishing key, or a new namespace owner is the classic precursor to an account-takeover or package hijack (event-stream, ua-parser-js, coa, rc).",
		HelpURI:  helpURIBase + "#maintainer-drift",
		HelpText: "Confirm the maintainer/publisher change is legitimate (an intentional ownership transfer, not a hijacked account); pin the version or add the new maintainer to the continuity allowlist once verified.",
		Default:  LevelWarning, Tags: []string{"security", "supply-chain", "maintainer", "account-takeover"},
	},
}

// catalogOrder is the canonical rule ordering used when emitting the SARIF
// driver rule list, so output is deterministic regardless of finding order.
var catalogOrder = []string{
	RuleVulnerableDependency,
	RuleSuppressedVuln,
	RuleLicenseNonCompliant,
	RuleLicenseDrift,
	RuleExposedSecret,
	RuleUnverifiedSignature,
	RuleTyposquat,
	RuleDependencyConfusion,
	RuleHomoglyph,
	RuleNameSuspicious,
	RuleRiskThreshold,
	RulePolicyViolation,
	RuleUnverifiedProvenance,
	RuleMaliciousCommit,
	RuleRiskyInstallScript,
	RuleMalwareDetected,
	RuleSuspiciousContent,
	RuleReproducibilityMismatch,
	RuleProvenanceSourceMismatch,
	RuleUnverifiedBuildProvenance,
	RulePyPIDigestMismatch,
	RuleUnverifiedPyPIAttestation,
	RuleMaintainerDrift,
	RuleSuspiciousCommit,
	RuleUnpinnedAction,
	RuleDisallowedActionOwner,
}

// CatalogGates returns the distinct set of gates that own at least one rule in
// the catalog, in canonical (catalogOrder) order. It is the authoritative list
// of SARIF-emitting admission gates and anchors the generated gate reference
// (internal/gatedoc): a new gate+rule added to the catalog without a matching
// documentation entry fails the gatedoc consistency test.
func CatalogGates() []Gate {
	seen := make(map[Gate]bool, len(catalog))
	gates := make([]Gate, 0, len(catalog))
	for _, id := range orderedRuleIDs() {
		r := catalog[id]
		if seen[r.Gate] {
			continue
		}
		seen[r.Gate] = true
		gates = append(gates, r.Gate)
	}
	return gates
}

// RulesForGate returns the catalog rules owned by gate g, in canonical
// (catalogOrder) order. The returned slice is freshly allocated; callers may
// retain it. It lets the gate-reference generator derive a gate's SARIF rule
// ids and finding categories directly from the live catalog, so those columns
// cannot drift from the SARIF export.
func RulesForGate(g Gate) []Rule {
	out := make([]Rule, 0, 2)
	for _, id := range orderedRuleIDs() {
		r := catalog[id]
		if r.Gate != g {
			continue
		}
		out = append(out, r)
	}
	return out
}

// orderedRuleIDs returns every catalog rule id in canonical order: the ids in
// catalogOrder first, then any catalog entry missing from catalogOrder appended
// in sorted order. This mirrors the defensive ordering in SARIFFromDocuments so
// the accessors above enumerate the full catalog even if catalogOrder drifts.
func orderedRuleIDs() []string {
	ids := make([]string, 0, len(catalog))
	placed := make(map[string]bool, len(catalog))
	for _, id := range catalogOrder {
		if _, ok := catalog[id]; ok && !placed[id] {
			placed[id] = true
			ids = append(ids, id)
		}
	}
	var extra []string
	for id := range catalog {
		if !placed[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	return append(ids, extra...)
}

// ruleFor returns the catalog entry for id, or a synthetic fallback rule so an
// unknown id can never produce an invalid SARIF document (every result must
// reference a defined rule).
func ruleFor(id string) Rule {
	if r, ok := catalog[id]; ok {
		return r
	}
	return Rule{ID: id, Name: id, Short: id, HelpURI: helpURIBase, Default: LevelWarning}
}

// severityToLevel maps a canonical severity onto a SARIF result level. Critical
// and high are build-failing errors; medium is a warning; low/info are notes;
// none maps to none.
func severityToLevel(s Severity) Level {
	switch s {
	case SeverityCritical, SeverityHigh:
		return LevelError
	case SeverityMedium:
		return LevelWarning
	case SeverityLow, SeverityInfo:
		return LevelNote
	case SeverityNone:
		return LevelNone
	default:
		return LevelWarning
	}
}

// RuleHelp returns the remediation guidance ("what to do") and documentation URI
// for a catalog rule id. The bool is false for an unknown id. It lets surfaces
// outside this package (e.g. the tenant self-service portal) explain to a
// developer why a coordinate was flagged and how to resolve it, without
// duplicating the rule catalog.
func RuleHelp(ruleID string) (text, uri string, ok bool) {
	r, found := catalog[ruleID]
	if !found {
		return "", "", false
	}
	return r.HelpText, r.HelpURI, true
}

// normalizeSeverity coerces an arbitrary gate severity string onto the canonical
// vocabulary, tolerating the various spellings the gates use (e.g. "moderate",
// "negligible", "informational").
func normalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low", "minor":
		return SeverityLow
	case "info", "informational", "negligible", "none-info":
		return SeverityInfo
	case "", "none", "unknown":
		return SeverityNone
	default:
		return SeverityNone
	}
}
