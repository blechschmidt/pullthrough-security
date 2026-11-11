# Admission gate reference (generated)

<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with `make gate-reference-gen`.
     Source of truth: internal/gatedoc (catalog) + internal/findings (rule catalog). -->

This reference is generated from the in-code admission-gate catalog
(`internal/gatedoc`) joined with the SARIF rule catalog
(`internal/findings`), so it always matches the running code. A CI
staleness gate (`make gate-reference-check`) fails if this file drifts
from the catalog, and a consistency test ties every SARIF-emitting gate and
every documented config path back to the code.

Gates run in a fixed pipeline order across three trigger points: **pull
admission (pre-fetch)** gates inspect the coordinate before the artifact is
fetched; **serveCacheable (post-fetch)** gates inspect the fetched content; and
**commit pipeline** gates run in the separate Git commit-scanning subsystem.
Each gate folds its verdict into the shared admission signal set, which the
policy engine and risk-scoring engine then evaluate.

Actions are the gate's own admission vocabulary; the exact config field (usually
`action` or `mode`) is under the listed config path — see the
[configuration reference](configuration-reference.md). Finding categories and
SARIF rule ids are shown for gates that emit canonical findings; gates marked as
a signal or hard block feed the policy/risk engines or refuse the pull inline and
have no SARIF rule of their own. For finding remediation guidance see
[findings.md](findings.md).

## Gates

| Gate | Package | Trigger | Actions | Config path | Finding categories | SARIF rule IDs | Metric prefix |
|------|---------|---------|---------|-------------|--------------------|----------------|---------------|
| `nameguard` | `internal/nameguard` | pull admission (pre-fetch) | `warn`, `block`, `quarantine` | `nameguard` | Typosquat, DependencyConfusion, Homoglyph, SuspiciousName | `nameguard/typosquat`, `nameguard/dependency-confusion`, `nameguard/homoglyph`, `nameguard/suspicious-name` | `pullthrough_nameguard_*` |
| `continuity` | `internal/continuity` | pull admission (pre-fetch) | `observe`, `warn`, `block` | `continuity` | MaintainerDrift | `continuity/maintainer-drift` | `pullthrough_continuity_*` |
| `depfirewall` | `internal/depfirewall` | pull admission (pre-fetch) | `allow`, `block` | `depfirewall` | version-pin / allowlist / version-floor violation (hard admission block) | — | `pullthrough_depfirewall_*` |
| `malfeed` | `internal/malfeed` | pull admission (pre-fetch) | `block (fail-open \| fail-closed)` | `malfeed` | known-malicious-package match (hard admission block) | — | `pullthrough_malfeed_*` |
| `maturity` | `internal/maturity` | pull admission (pre-fetch) | `block (version-cooldown)` | `maturity` | release younger than the configured cooldown (hard admission block) | — | `pullthrough_maturity_*` |
| `sigverify` | `internal/sigverify` | serveCacheable (post-fetch) | `warn`, `block`, `quarantine` | `sigverify` | UnverifiedSignature | `sigverify/unverified-signature` | `pullthrough_sigverify_*` |
| `buildprov` | `internal/buildprov` | serveCacheable (post-fetch) | `observe \| enforce`, `warn`, `block`, `quarantine` | `buildProv` | BuildProvenanceSourceMismatch, UnverifiedBuildProvenance | `buildprov/source-mismatch`, `buildprov/unverified-provenance` | `pullthrough_buildprov_*` |
| `rebuildverify` | `internal/rebuildverify` | serveCacheable (post-fetch) | `observe \| enforce` | `rebuildVerify` | ReproducibilityMismatch | `rebuildverify/reproducibility-mismatch` | `pullthrough_rebuildverify_*` |
| `pypiattest` | `internal/pypiattest` | serveCacheable (post-fetch) | `annotate`, `downgrade`, `block` | `pypiAttestation` | PyPIAttestationDigestMismatch, UnverifiedPyPIAttestation | `pypiattest/digest-mismatch`, `pypiattest/unverified-attestation` | `pullthrough_pypi_attestation_*` |
| `vulnscan` | `internal/vulnscan` | serveCacheable (post-fetch) | `warn`, `block`, `quarantine` | `vulnerabilities` | VulnerableDependency | `vulnscan/vulnerable-dependency` | `pullthrough_vuln_*` |
| `vex` | `internal/vulnscan` | serveCacheable (post-fetch) | `suppress (transparency)` | `vulnerabilities.vex` | SuppressedVulnerability | `vex/suppressed-vulnerability` | `pullthrough_vex_*` |
| `reachability` | `internal/vulnscan` | serveCacheable (post-fetch) | `annotate`, `downgrade`, `suppress` | `vulnerabilities.reachability` | reachable / unreachable / unknown attribute on vulnscan findings (no own SARIF rule) | — | — (no dedicated family) |
| `license` | `internal/license` | serveCacheable (post-fetch) | `warn`, `block`, `quarantine` | `license` | NonCompliantLicense, LicenseDrift | `license/non-compliant`, `license/drift` | `pullthrough_license_*` |
| `sbomdiff` | `internal/sbomdiff` | serveCacheable (post-fetch) | `warn`, `block`, `quarantine` | `sbomDiff` | significant dependency-drift between versions (policy-engine signal, no SARIF rule) | — | `pullthrough_sbomdiff_*` |
| `installhooks` | `internal/installhooks` | serveCacheable (post-fetch) | `warn`, `block` | `installHooks` | RiskyInstallScript | `installhooks/risky-install-script` | `pullthrough_installhooks_*` |
| `contentscan` | `internal/contentscan` | serveCacheable (post-fetch) | `annotate`, `downgrade`, `block` | `contentScan` | SuspiciousContent | `contentscan/suspicious-content` | `pullthrough_contentscan_*` |
| `mlguard` | `internal/mlguard` | serveCacheable (post-fetch) | `warn`, `block` | `mlGuard` | unsafe ML-weight deserialization (pickle-*) findings (policy-engine signal, no SARIF rule) | — | `pullthrough_mlguard_*` |
| `avscan` | `internal/avscan` | serveCacheable (post-fetch) | `annotate`, `quarantine`, `block` | `avScan` | MalwareDetected | `avscan/malware-detected` | `pullthrough_avscan_*` |
| `llmpkgscan` | `internal/llmpkgscan` | serveCacheable (post-fetch) | `annotate`, `block`, `quarantine`, `fail-open \| fail-closed (when unscanned)` | `llmPackageScan` | LLMMaliciousPackage, LLMSuspiciousPackage, LLMScanIncomplete | `llmpkgscan/malicious-package`, `llmpkgscan/suspicious-package`, `llmpkgscan/scan-incomplete` | `pullthrough_llmpkgscan_*` |
| `reposcore` | `internal/reposcore` | serveCacheable (post-fetch) | `signal-only (never blocks)` | `repoScore` | source-repository health grade feeding riskscore/policyengine (no SARIF rule) | — | `pullthrough_reposcore_*` |
| `provenance` | `internal/provenance` | serveCacheable (post-fetch) | `warn`, `block` | `provenance` | UnverifiedProvenance, MaliciousSourceCommit | `provenance/unverified`, `provenance/malicious-commit` | — (no dedicated family) |
| `policyengine` | `internal/policyengine` | serveCacheable (post-fetch) | `allow`, `warn`, `deny`, `mode: enforce \| audit` | `policyEngine` | PolicyViolation | `policyengine/policy-violation` | `pullthrough_policyengine_*` |
| `riskscore` | `internal/riskscore` | serveCacheable (post-fetch) | `off`, `warn`, `block` | `riskScore` | RiskThresholdExceeded | `riskscore/threshold-exceeded` | `pullthrough_riskscore_*` |
| `commitscan` | `internal/scan/commit` | commit pipeline | `warn \| block (by failOn severity)` | `scanning.commit` | SuspiciousSourceCommit | `commitscan/suspicious-commit` | `pullthrough_commitscan_*` |
| `secretscan` | `internal/scan/commit` | commit pipeline | `warn \| block (by failOn severity)` | `scanning.secrets` | ExposedCredential | `secretscan/exposed-credential` | `pullthrough_secrets_*` |
| `actionpin` | `internal/actionpin` | commit pipeline | `warn`, `block` | `scanning.actions` | UnpinnedAction, DisallowedActionOwner | `actionpin/unpinned-action`, `actionpin/disallowed-owner` | — (no dedicated family) |

_26 admission gates documented; 19 emit SARIF findings, 7 are signal/hard-block gates._
