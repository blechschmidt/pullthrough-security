// Package gatedoc is the single, in-code source of truth for the proxy's
// admission-gate reference documentation (docs/gates-reference.md). The proxy
// has grown to ~25 supply-chain admission gates, each with its own package,
// trigger point, action vocabulary, config knobs, finding taxonomy, and metrics.
// Rather than let a hand-written table drift from the code, this package holds a
// declarative catalog of every gate and a generator that renders it as Markdown,
// mirroring internal/config.GenerateReference and the chaos resilience-matrix
// generator.
//
// Drift is prevented on two axes:
//
//   - A committed-doc staleness gate (`make gate-reference-check`, wired into CI)
//     fails when docs/gates-reference.md no longer matches GenerateReference().
//   - A consistency test (gatedoc_test.go) anchors the catalog to the live
//     findings rule catalog (findings.CatalogGates) and the config schema
//     (config.YAMLPathExists), so a gate added to either without a documentation
//     entry — or a documentation entry naming a config path or SARIF gate that no
//     longer exists — fails the build.
//
// The SARIF rule-id and finding-category columns for a findings-backed gate are
// derived from the live findings catalog at render time, so they can never
// disagree with the SARIF the proxy actually emits.
package gatedoc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// Trigger identifies where in the request lifecycle a gate runs.
type Trigger string

const (
	// TriggerPreFetch runs in handleBackend before the artifact is fetched, on
	// the coordinate (name/version) alone.
	TriggerPreFetch Trigger = "pull admission (pre-fetch)"
	// TriggerServe runs in serveCacheable after the artifact bytes are fetched,
	// on the content.
	TriggerServe Trigger = "serveCacheable (post-fetch)"
	// TriggerCommit runs in the Git commit-scan pipeline (webhook/polling driven),
	// not on the pull path.
	TriggerCommit Trigger = "commit pipeline"
)

// Gate is one admission gate's documentation descriptor. Operational metadata
// (package, trigger, actions, config path, metric prefix) is curated here; the
// SARIF rule-id and finding-category columns are derived from the findings
// catalog when FindingsGate is non-empty.
type Gate struct {
	// Name is the gate's stable identifier, matching its gateTrace label and (for
	// findings-backed gates) its findings.Gate value.
	Name string
	// Package is the implementing package's import path under internal/.
	Package string
	// Trigger is where the gate runs in the request lifecycle.
	Trigger Trigger
	// Actions is the gate's supported admission action vocabulary.
	Actions []string
	// ConfigPath is the dotted YAML key that configures the gate. It must resolve
	// in the config schema (enforced by the consistency test).
	ConfigPath string
	// MetricPrefix is the gate's Prometheus metric family prefix, or "" when the
	// gate has no dedicated family (its activity rolls up elsewhere).
	MetricPrefix string
	// FindingsGate links the gate to the findings SARIF catalog. When non-empty,
	// the generator derives the SARIF rule ids and finding categories from
	// findings.RulesForGate; the curated Categories field must then be empty.
	FindingsGate findings.Gate
	// Categories documents the finding/decision outputs for a gate that does NOT
	// emit canonical findings (FindingsGate == ""): a hard admission block, a
	// policy-engine signal, or a risk signal with no SARIF rule.
	Categories []string
	// Summary is a one-line description of what the gate inspects.
	Summary string
}

// catalog is the full, ordered admission-gate set. Order follows the runtime
// pipeline: coordinate-level pre-fetch gates, then content gates in
// serveCacheable, then the separate Git commit-scan gates. The consistency test
// asserts every findings.CatalogGates() value appears here exactly once.
var catalog = []Gate{
	// --- pull admission, pre-fetch (coordinate-level) -----------------------
	{
		Name: "nameguard", Package: "internal/nameguard", Trigger: TriggerPreFetch,
		Actions: []string{"warn", "block", "quarantine"}, ConfigPath: "nameguard",
		MetricPrefix: "pullthrough_nameguard_", FindingsGate: findings.GateNameguard,
		Summary: "Typosquatting, dependency-confusion, and homoglyph detection on the requested package name.",
	},
	{
		Name: "continuity", Package: "internal/continuity", Trigger: TriggerPreFetch,
		Actions: []string{"observe", "warn", "block"}, ConfigPath: "continuity",
		MetricPrefix: "pullthrough_continuity_", FindingsGate: findings.GateContinuity,
		Summary: "Trust-on-first-use maintainer/publisher continuity monitoring; flags ownership/key changes.",
	},
	{
		Name: "depfirewall", Package: "internal/depfirewall", Trigger: TriggerPreFetch,
		Actions: []string{"allow", "block"}, ConfigPath: "depfirewall",
		MetricPrefix: "pullthrough_depfirewall_",
		Categories:   []string{"version-pin / allowlist / version-floor violation (hard admission block)"},
		Summary:      "Dependency firewall: per-tenant version pinning, allowlists, version floors, and denylists.",
	},
	{
		Name: "malfeed", Package: "internal/malfeed", Trigger: TriggerPreFetch,
		Actions: []string{"block (fail-open | fail-closed)"}, ConfigPath: "malfeed",
		MetricPrefix: "pullthrough_malfeed_",
		Categories:   []string{"known-malicious-package match (hard admission block)"},
		Summary:      "Known-malicious package blocking from ingested OpenSSF/OSV malware feeds.",
	},
	{
		Name: "maturity", Package: "internal/maturity", Trigger: TriggerPreFetch,
		Actions: []string{"block (version-cooldown)"}, ConfigPath: "maturity",
		MetricPrefix: "pullthrough_maturity_",
		Categories:   []string{"release younger than the configured cooldown (hard admission block)"},
		Summary:      "Release-maturity / version-cooldown gate; blocks brand-new releases until they age.",
	},
	// --- content gates, serveCacheable (post-fetch) -------------------------
	{
		Name: "sigverify", Package: "internal/sigverify", Trigger: TriggerServe,
		Actions: []string{"warn", "block", "quarantine"}, ConfigPath: "sigverify",
		MetricPrefix: "pullthrough_sigverify_", FindingsGate: findings.GateSigverify,
		Summary: "Sigstore/cosign signature and SLSA attestation verification (incl. Rekor transparency, PQC).",
	},
	{
		Name: "buildprov", Package: "internal/buildprov", Trigger: TriggerServe,
		Actions: []string{"observe | enforce", "warn", "block", "quarantine"}, ConfigPath: "buildProv",
		MetricPrefix: "pullthrough_buildprov_", FindingsGate: findings.GateBuildProv,
		Summary: "Inbound npm/GitHub/GitLab/Bitbucket build-provenance attestation verification and source binding.",
	},
	{
		Name: "rebuildverify", Package: "internal/rebuildverify", Trigger: TriggerServe,
		Actions: []string{"observe | enforce"}, ConfigPath: "rebuildVerify",
		MetricPrefix: "pullthrough_rebuildverify_", FindingsGate: findings.GateRebuildVerify,
		Summary: "Reproducible-build verification: rebuild from the attested source commit and compare digests.",
	},
	{
		Name: "pypiattest", Package: "internal/pypiattest", Trigger: TriggerServe,
		Actions: []string{"annotate", "downgrade", "block"}, ConfigPath: "pypiAttestation",
		MetricPrefix: "pullthrough_pypi_attestation_", FindingsGate: findings.GatePyPIAttest,
		Summary: "Inbound PyPI PEP 740 Trusted-Publisher digital-attestation verification and digest binding.",
	},
	{
		Name: "vulnscan", Package: "internal/vulnscan", Trigger: TriggerServe,
		Actions: []string{"warn", "block", "quarantine"}, ConfigPath: "vulnerabilities",
		MetricPrefix: "pullthrough_vuln_", FindingsGate: findings.GateVulnscan,
		Summary: "SBOM generation and OSV vulnerability scanning of the artifact's components.",
	},
	{
		Name: "vex", Package: "internal/vulnscan", Trigger: TriggerServe,
		Actions: []string{"suppress (transparency)"}, ConfigPath: "vulnerabilities.vex",
		MetricPrefix: "pullthrough_vex_", FindingsGate: findings.GateVEX,
		Summary: "VEX-based suppression of vulnscan findings adjudicated not-affected/fixed.",
	},
	{
		Name: "reachability", Package: "internal/vulnscan", Trigger: TriggerServe,
		Actions: []string{"annotate", "downgrade", "suppress"}, ConfigPath: "vulnerabilities.reachability",
		MetricPrefix: "",
		Categories:   []string{"reachable / unreachable / unknown attribute on vulnscan findings (no own SARIF rule)"},
		Summary:      "Reachability-aware prioritization of vulnscan findings via static import analysis.",
	},
	{
		Name: "license", Package: "internal/license", Trigger: TriggerServe,
		Actions: []string{"warn", "block", "quarantine"}, ConfigPath: "license",
		MetricPrefix: "pullthrough_license_", FindingsGate: findings.GateLicense,
		Summary: "License-compliance scanning and enforcement against the allow/deny/review policy.",
	},
	{
		Name: "sbomdiff", Package: "internal/sbomdiff", Trigger: TriggerServe,
		Actions: []string{"warn", "block", "quarantine"}, ConfigPath: "sbomDiff",
		MetricPrefix: "pullthrough_sbomdiff_",
		Categories:   []string{"significant dependency-drift between versions (policy-engine signal, no SARIF rule)"},
		Summary:      "SBOM diff / dependency-drift gate comparing an artifact version to its predecessor.",
	},
	{
		Name: "installhooks", Package: "internal/installhooks", Trigger: TriggerServe,
		Actions: []string{"warn", "block"}, ConfigPath: "installHooks",
		MetricPrefix: "pullthrough_installhooks_", FindingsGate: findings.GateInstallHooks,
		Summary: "Static install-script / lifecycle-hook risk analysis (network egress, eval, exfiltration).",
	},
	{
		Name: "contentscan", Package: "internal/contentscan", Trigger: TriggerServe,
		Actions: []string{"annotate", "downgrade", "block"}, ConfigPath: "contentScan",
		MetricPrefix: "pullthrough_contentscan_", FindingsGate: findings.GateContentScan,
		Summary: "Package-payload static content analysis (embedded binaries, entropy blobs, obfuscation, secrets).",
	},
	{
		Name: "mlguard", Package: "internal/mlguard", Trigger: TriggerServe,
		Actions: []string{"warn", "block"}, ConfigPath: "mlGuard",
		MetricPrefix: "pullthrough_mlguard_",
		Categories:   []string{"unsafe ML-weight deserialization (pickle-*) findings (policy-engine signal, no SARIF rule)"},
		Summary:      "ML model-weight scanning gate for unsafe pickle opcodes and non-safetensors formats.",
	},
	{
		Name: "avscan", Package: "internal/avscan", Trigger: TriggerServe,
		Actions: []string{"annotate", "quarantine", "block"}, ConfigPath: "avScan",
		MetricPrefix: "pullthrough_avscan_", FindingsGate: findings.GateAVScan,
		Summary: "ClamAV/antivirus byte-level content scanning of fetched artifact payloads.",
	},
	{
		Name: "llmpkgscan", Package: "internal/llmpkgscan", Trigger: TriggerServe,
		Actions: []string{"annotate", "block", "quarantine", "fail-open | fail-closed (when unscanned)"}, ConfigPath: "llmPackageScan",
		MetricPrefix: "pullthrough_llmpkgscan_", FindingsGate: findings.GateLLMPkgScan,
		Summary: "Sandboxed LLM review of the unpacked package contents (read-only tools, no execution); verdict cached per sha256 digest + model + prompt version.",
	},
	{
		Name: "reposcore", Package: "internal/reposcore", Trigger: TriggerServe,
		Actions: []string{"signal-only (never blocks)"}, ConfigPath: "repoScore",
		MetricPrefix: "pullthrough_reposcore_",
		Categories:   []string{"source-repository health grade feeding riskscore/policyengine (no SARIF rule)"},
		Summary:      "OpenSSF Scorecard-style source-repository health signal provider.",
	},
	{
		Name: "provenance", Package: "internal/provenance", Trigger: TriggerServe,
		Actions: []string{"warn", "block"}, ConfigPath: "provenance",
		MetricPrefix: "", FindingsGate: findings.GateProvenance,
		Summary: "Package-to-commit provenance association; bridges a malicious source-commit verdict onto the pull path.",
	},
	{
		Name: "policyengine", Package: "internal/policyengine", Trigger: TriggerServe,
		Actions: []string{"allow", "warn", "deny", "mode: enforce | audit"}, ConfigPath: "policyEngine",
		MetricPrefix: "pullthrough_policyengine_", FindingsGate: findings.GatePolicyEngine,
		Summary: "Policy-as-code (CEL-subset) engine evaluating operator rules over every gate's aggregated signals.",
	},
	{
		Name: "riskscore", Package: "internal/riskscore", Trigger: TriggerServe,
		Actions: []string{"off", "warn", "block"}, ConfigPath: "riskScore",
		MetricPrefix: "pullthrough_riskscore_", FindingsGate: findings.GateRiskscore,
		Summary: "Unified supply-chain risk-scoring engine folding every gate signal into a 0-100 banded score.",
	},
	// --- Git commit-scan pipeline (separate subsystem) ----------------------
	{
		Name: "commitscan", Package: "internal/scan/commit", Trigger: TriggerCommit,
		Actions: []string{"warn | block (by failOn severity)"}, ConfigPath: "scanning.commit",
		MetricPrefix: "pullthrough_commitscan_", FindingsGate: findings.GateCommitScan,
		Summary: "LLM-backed + deterministic Git commit scanning for malicious-code, backdoor, and tampering risk.",
	},
	{
		Name: "secretscan", Package: "internal/scan/commit", Trigger: TriggerCommit,
		Actions: []string{"warn | block (by failOn severity)"}, ConfigPath: "scanning.secrets",
		MetricPrefix: "pullthrough_secrets_", FindingsGate: findings.GateSecretscan,
		Summary: "Deterministic secret/credential detection over scanned Git commits.",
	},
	{
		Name: "actionpin", Package: "internal/actionpin", Trigger: TriggerCommit,
		Actions: []string{"warn", "block"}, ConfigPath: "scanning.actions",
		MetricPrefix: "", FindingsGate: findings.GateActionPin,
		Summary: "GitHub Actions uses:-pinning and permitted-owner gate over changed workflow files.",
	},
}

// Catalog returns the ordered admission-gate catalog. The returned slice is a
// copy; callers may not mutate the package's state through it.
func Catalog() []Gate {
	out := make([]Gate, len(catalog))
	copy(out, catalog)
	return out
}

// RuleIDs returns the SARIF rule ids a gate emits, derived from the live
// findings catalog. It is empty for a decision-only gate (FindingsGate == "").
func (g Gate) RuleIDs() []string {
	if g.FindingsGate == "" {
		return nil
	}
	rules := findings.RulesForGate(g.FindingsGate)
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// FindingCategories returns the gate's emitted finding categories. For a
// findings-backed gate these are the catalog rule display names (derived live);
// for a decision-only gate they are the curated Categories descriptions.
func (g Gate) FindingCategories() []string {
	if g.FindingsGate == "" {
		return g.Categories
	}
	rules := findings.RulesForGate(g.FindingsGate)
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		name := r.Name
		if name == "" {
			name = r.ID
		}
		names = append(names, name)
	}
	return names
}

const docHeader = `# Admission gate reference (generated)

<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with ` + "`make gate-reference-gen`" + `.
     Source of truth: internal/gatedoc (catalog) + internal/findings (rule catalog). -->

This reference is generated from the in-code admission-gate catalog
(` + "`internal/gatedoc`" + `) joined with the SARIF rule catalog
(` + "`internal/findings`" + `), so it always matches the running code. A CI
staleness gate (` + "`make gate-reference-check`" + `) fails if this file drifts
from the catalog, and a consistency test ties every SARIF-emitting gate and
every documented config path back to the code.

Gates run in a fixed pipeline order across three trigger points: **pull
admission (pre-fetch)** gates inspect the coordinate before the artifact is
fetched; **serveCacheable (post-fetch)** gates inspect the fetched content; and
**commit pipeline** gates run in the separate Git commit-scanning subsystem.
Each gate folds its verdict into the shared admission signal set, which the
policy engine and risk-scoring engine then evaluate.

Actions are the gate's own admission vocabulary; the exact config field (usually
` + "`action`" + ` or ` + "`mode`" + `) is under the listed config path — see the
[configuration reference](configuration-reference.md). Finding categories and
SARIF rule ids are shown for gates that emit canonical findings; gates marked as
a signal or hard block feed the policy/risk engines or refuse the pull inline and
have no SARIF rule of their own. For finding remediation guidance see
[findings.md](findings.md).

`

// GenerateReference renders the admission-gate reference as Markdown. Output is
// deterministic (catalog declaration order, no map iteration), so repeated runs
// are byte-identical and the staleness gate is stable.
func GenerateReference() string {
	var b strings.Builder
	b.WriteString(docHeader)

	// Summary table.
	b.WriteString("## Gates\n\n")
	b.WriteString("| Gate | Package | Trigger | Actions | Config path | Finding categories | SARIF rule IDs | Metric prefix |\n")
	b.WriteString("|------|---------|---------|---------|-------------|--------------------|----------------|---------------|\n")
	for _, g := range catalog {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | `%s` | %s | %s | %s |\n",
			g.Name,
			g.Package,
			string(g.Trigger),
			cell(joinCode(g.Actions)),
			g.ConfigPath,
			cell(mdList(g.FindingCategories())),
			cell(joinCode(g.RuleIDs())),
			metricCell(g.MetricPrefix),
		)
	}
	b.WriteString("\n")

	// Count summary so a reader (and the field-count test) can see coverage.
	sarif := 0
	for _, g := range catalog {
		if g.FindingsGate != "" {
			sarif++
		}
	}
	fmt.Fprintf(&b, "_%d admission gates documented; %d emit SARIF findings, %d are signal/hard-block gates._\n",
		len(catalog), sarif, len(catalog)-sarif)

	return b.String()
}

// mdList renders a list of strings as a single table cell, comma-separated.
func mdList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, ", ")
}

// joinCode renders a list of tokens as inline-code, comma-separated.
func joinCode(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = "`" + it + "`"
	}
	return strings.Join(out, ", ")
}

// cell renders a table cell, falling back to an em dash when empty so the table
// stays visually quiet for the common "none" case. Pipe characters are escaped.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// metricCell renders a metric prefix, showing an em dash and note for gates with
// no dedicated family.
func metricCell(prefix string) string {
	if prefix == "" {
		return "— (no dedicated family)"
	}
	return "`" + prefix + "*`"
}

// sortedNames returns the catalog gate names sorted, used by tests.
func sortedNames() []string {
	names := make([]string, len(catalog))
	for i, g := range catalog {
		names[i] = g.Name
	}
	sort.Strings(names)
	return names
}
