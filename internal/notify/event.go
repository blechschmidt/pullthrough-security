// Package notify implements a pluggable event-notification subsystem that
// dispatches structured alerts on security-relevant events in the proxy: policy
// blocks, new vulnerability findings, LLM commit-scan findings above a severity,
// provenance verification failures, quarantine actions, and re-scan-detected
// regressions (Task 18).
//
// The subsystem is built around three pieces that compose cleanly:
//
//   - Event: a plain, transport-agnostic description of what happened (a Type, a
//     Severity, a title/summary, and a small ordered set of structured fields).
//     Producing an Event requires nothing from this package's consumers beyond
//     primitives, so the subsystems that emit (policy engine, scan pipeline,
//     provenance verifier, vulnscan) never take a dependency on a sink type.
//   - Emitter: the narrow interface those producers emit to. A *Notifier
//     implements it; a nil Emitter (feature disabled) is a no-op at the call site.
//   - Sink: a delivery destination (a generic HTTP webhook or a Slack incoming
//     webhook). The Notifier routes each event to the sinks configured for its
//     type, applies a severity floor, redacts sensitive fields, and delivers
//     asynchronously with bounded retries so the request path is never blocked.
//
// All exported types are safe for concurrent use. A nil *Notifier is a valid,
// no-op Emitter so notification can be disabled without nil checks at call sites.
package notify

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EventType enumerates the security-relevant occurrences the subsystem alerts
// on. The values are stable, lowercase identifiers suitable for routing keys,
// metric labels, and webhook payloads.
type EventType string

const (
	// EventPolicyBlock is an admission-policy block (Task 9): an artifact was
	// refused by a denylist/allowlist, risk-score, or malicious-commit rule.
	EventPolicyBlock EventType = "policy_block"
	// EventVulnerability is a vulnerability finding from the SBOM/OSV gate
	// (Task 15) that warned on, blocked, or quarantined an artifact.
	EventVulnerability EventType = "vulnerability"
	// EventCommitScan is an LLM commit-scan verdict (Task 7) at or above the
	// configured notification severity (or flagged malicious).
	EventCommitScan EventType = "commit_scan"
	// EventCostBudget is a per-tenant LLM commit-scan cost-budget exhaustion
	// (Task 78): a tenant reached its scanning cost ceiling and scans were degraded
	// (fail-open: admitted without an LLM scan; fail-closed: blocked).
	EventCostBudget EventType = "cost_budget"
	// EventProvenanceFailure is a provenance verification failure (Task 8): a
	// required signature did not verify or an attestation did not chain to a
	// trusted root.
	EventProvenanceFailure EventType = "provenance_failure"
	// EventLicense is a license-compliance gate decision (Task 28) that warned on,
	// blocked, or quarantined an artifact whose SPDX license violated policy, or
	// whose license changed across versions (drift).
	EventLicense EventType = "license"
	// EventQuarantine is a quarantine action: an artifact was made unservable and
	// evicted from the cache.
	EventQuarantine EventType = "quarantine"
	// EventRescanRegression is a regression detected by the continuous re-scan
	// subsystem (Task 18): a previously-clean cached artifact became vulnerable
	// against a newly-disclosed CVE.
	EventRescanRegression EventType = "rescan_regression"
	// EventRiskScore is a unified-risk-score threshold crossing (Task 37): an
	// artifact's composite supply-chain risk score met or exceeded the configured
	// admission band, warning on or blocking the pull.
	EventRiskScore EventType = "risk_score"
	// EventUpstreamCircuitOpen is a health-aware-routing event (Task 38): a mirror
	// endpoint's circuit breaker tripped open after repeated failures and the
	// mirror was removed from rotation, with traffic failing over to the remaining
	// healthy mirrors.
	EventUpstreamCircuitOpen EventType = "upstream_circuit_open"
	// EventAnomaly is a behavioral-anomaly detection (Task 43): a tenant/identity's
	// pull traffic crossed a graded anomaly threshold — a distinct-package fan-out
	// spike, a burst of new namespaces, an off-hours burst, rapid 404 enumeration,
	// or anomalous egress volume versus its rolling baseline — signaling possible
	// credential compromise or exfiltration rather than a single bad artifact.
	EventAnomaly EventType = "anomaly"
	// EventMaliciousBlock is a known-malicious-package block (Task 48): a pull was
	// refused because its concrete coordinate (ecosystem, name, version) is listed
	// in a curated malware dataset (OpenSSF/OSV malicious-packages or a GitHub
	// Advisory malware entry) — a crypto-miner, credential stealer, or install-
	// script backdoor — or, under a fail-closed policy, because that feed was stale
	// and could not be confirmed current.
	EventMaliciousBlock EventType = "malicious_block"
	// EventApproval is a quarantine-review / break-glass workflow event (Task 50):
	// a blocked or quarantined artifact gained a time-boxed, tenant+coordinate-
	// scoped approval exception (a grant), had a grant auto-revoke on expiry
	// (re-quarantine), was denied (the block confirmed), or first entered the
	// pending-review queue. It lets operators route human-in-the-loop decisions to
	// the same sinks as the gates whose blocks they override.
	EventApproval EventType = "approval"
	// EventCacheGC is a cache-lifecycle event (Task 39): the content cache remained
	// at or above its high watermark after a garbage-collection sweep, meaning
	// reclaimable space is exhausted (everything else is pinned, referenced, or
	// in-flight) and the cache may need a larger capacity or relaxed retention.
	EventCacheGC EventType = "cache_gc"
	// EventExtension is a custom WASM extension-gate decision (Task 59): an
	// operator-supplied sandboxed module warned on or blocked an artifact. It
	// carries the module name, decision, and reason so operators can attribute a
	// gate action to a specific extension.
	EventExtension EventType = "extension"
	// EventMaturity is a release-maturity / version-cooldown block (Task 61): a
	// pull was quarantined because the requested version was published less than the
	// configured cooldown window ago (or, under a fail-closed policy, because its
	// publish timestamp could not be determined). It defends against fast-moving
	// supply-chain attacks where a malicious version is published and yanked within
	// hours, before it can age into the cache.
	EventMaturity EventType = "maturity"
	// EventInstallHooks is a risky install-script / lifecycle-hook block or warning
	// (Task 62): a package's automatically-run install hooks (npm pre/post-install,
	// Python setup.py / pyproject build hooks, RubyGems native extensions or
	// post-install message, Cargo build.rs) statically matched a high-risk pattern
	// (network egress, base64-decoded eval, shell spawning, env-var exfiltration,
	// writes outside the package dir, or obfuscation). No script was executed.
	EventInstallHooks EventType = "install_hooks"
	// EventMLGuard is an ML weight-scanning block or warning (Task 110): a Hugging
	// Face model/dataset pickle weight file (.bin/.pkl/.pt/.ckpt) statically
	// disassembled to carry an unsafe import (os.system, subprocess, builtins.eval,
	// a socket) invoked via __reduce__ — a malicious-model code-execution payload.
	// Nothing was unpickled.
	EventMLGuard EventType = "ml_guard"
	// EventContentScan is a package-payload static content-analysis finding (Task
	// 138): the unpack-and-scan of a served source package (npm tarball, pip
	// sdist/wheel, gem/composer/cargo/nuget archive) flagged an embedded native
	// binary, a high-entropy/packed blob, obfuscated JavaScript, a dynamic
	// code-execution sink, or an in-source secret. No code was executed.
	EventContentScan EventType = "content_scan"
	// EventAVScan is an antivirus content-scan detection (Task 136): a fetched
	// artifact's payload (archive, wheel, jar, OCI layer blob, ML weight file, or
	// Git LFS object), streamed through the configured AV engine (ClamAV via
	// clamd INSTREAM), matched a malware signature. The artifact was
	// annotated/quarantined/blocked per policy.
	EventAVScan EventType = "av_scan"
	// EventLLMPackageScan is a verdict of the sandboxed LLM package-content scan
	// gate (Task 173): a language model reviewed the unpacked contents of a served
	// package — through read-only tools, executing nothing — and judged it
	// malicious or suspicious, or the package made itself unscannable. The artifact
	// was annotated/quarantined/blocked per policy.
	EventLLMPackageScan EventType = "llm_package_scan"
	// EventSbomDrift is a significant dependency-drift event (Task 64): a new
	// version of a package introduced a materially larger or more suspicious
	// dependency footprint than the version before it — added transitive
	// dependencies, never-before-seen namespaces, newly-introduced non-compliant
	// licenses, or net-new vulnerabilities — pushing its computed "drift risk"
	// score over the significance threshold. It flags a quiet, well-behaved
	// package that suddenly changed shape, a classic hijack / dependency-confusion
	// tell.
	EventSbomDrift EventType = "sbom_drift"
	// EventDepFirewall is a dependency-firewall block (Task 65): a pull was refused
	// because the requested version fell outside the tenant's approved set — not on
	// the pinned-version allowlist, satisfying no allowed semver range, below the
	// minimum-version floor, on the explicit denylist, or (in deny-by-default mode)
	// an ungoverned coordinate. It is the auditable signal that CI tried to fetch a
	// version an operator did not approve.
	EventDepFirewall EventType = "depfirewall"
	// EventRebuildVerify is a reproducible-build verification event (Task 68): the
	// proxy rebuilt an artifact from its attested source commit inside a sandboxed,
	// pinned toolchain and the rebuilt digest did NOT match the upstream-served
	// artifact (a confirmed mismatch) — or, in enforce mode, that mismatch caused
	// the artifact to be quarantined. The served binary does not provably derive
	// from the attested source, a strong supply-chain-tampering / build-injection
	// indicator.
	EventRebuildVerify EventType = "rebuild_verify"
	// EventSnapshot is an organization snapshot / freeze / rollback event (Task 70):
	// a point-in-time dependency snapshot was captured, the organization was frozen
	// or unfrozen to a snapshot, an instant rollback to the last-known-good snapshot
	// was executed, or the freeze gate blocked/quarantined a pull whose coordinate
	// fell outside the active frozen set (or whose served digest differed from the
	// frozen one). It is the auditable signal for supply-chain time-machine actions.
	EventSnapshot EventType = "snapshot"
	// EventBuildProvenance is an inbound build-provenance verification event (Task
	// 72): the proxy verified an upstream-published build-provenance attestation
	// (npm provenance / GitHub artifact attestation) and either could not establish
	// it, or — decisively — found that the source commit/repository the signed
	// attestation PROVES disagrees with the commit/repository the package metadata
	// CLAIMS. The latter is a strong supply-chain signal that the published metadata
	// misrepresents where the artifact was built; in enforce mode it quarantines the
	// artifact.
	EventBuildProvenance EventType = "build_provenance"
	// EventLockdown is an emergency-lockdown / global kill-switch incident-response
	// transition (Task 74): an operator engaged, cleared, or the TTL auto-expired an
	// org-wide lockdown (freeze / strict / targeted-block). It is the auditable,
	// alertable signal that the proxy's posture was tightened (or relaxed) during an
	// active supply-chain incident — the highest-signal operational event, carrying
	// the operator-supplied incident ID and reason.
	EventLockdown EventType = "lockdown"
	// EventMeteringBudget is a per-tenant usage-budget threshold crossing (Task 84):
	// a tenant's metered consumption (served bytes or estimated scan/LLM cost)
	// reached or exceeded its configured chargeback ceiling. It is the auditable,
	// alertable signal an operator uses to attribute and cap proxy cost; it does not
	// itself block pulls (metering is observe-and-account, not an admission gate).
	EventMeteringBudget EventType = "metering_budget"
	// EventEgressBlocked is an outbound-egress / SSRF guard denial (Task 89): the
	// transport-level egress guard refused a fetch whose destination violated the
	// scheme/host allowlist or resolved to a private/link-local/loopback/metadata
	// IP range (including after a redirect or a DNS rebind). It is the auditable,
	// alertable signal that the proxy was steered — or attempted to be steered —
	// at an internal target, the canonical confused-deputy SSRF indicator.
	EventEgressBlocked EventType = "egress_blocked"
	// EventMaintainerDrift is a maintainer/publisher continuity event (Task 91): the
	// publisher principals observed for a coordinate (registry maintainer roster,
	// publishing namespace owner, signing-key identity) changed relative to the
	// durable trust-on-first-use known-maintainer set. A brand-new maintainer, a
	// rotated publishing key, or a new namespace owner on an already-known package is
	// the classic precursor to an account-takeover / hijack (event-stream,
	// ua-parser-js); under a block disposition the still-untrusted version is refused.
	EventMaintainerDrift EventType = "maintainer_drift"
	// EventGitOps is a GitOps policy/config reconciliation event (Task 93): the
	// proxy synced its policy/config bundles from the version-controlled source of
	// truth and either applied a change (auto or post-approval), detected drift /
	// surfaced a pending change for approval, refused an unverified bundle, or rolled
	// back to the last-known-good revision. It is the auditable, alertable signal
	// that the proxy's policy posture changed from version control rather than by a
	// live edit — the GitOps control-plane's counterpart to a deploy notification.
	EventGitOps EventType = "gitops"
	// EventTest is a synthetic event produced by the admin "send test
	// notification" endpoint to validate sink configuration end-to-end.
	EventTest EventType = "test"

	// EventCacheIntegrity is a cache content-integrity violation (Task 107): a
	// stored blob's bytes no longer match the content digest recorded when it was
	// written (tampering or bit-rot). The entry is quarantined and the next pull
	// self-heals from upstream.
	EventCacheIntegrity EventType = "cache_integrity"
	// EventTLSPinViolation is an upstream TLS certificate/CA pin violation (Task
	// 128): a connection to a pinned upstream registry presented a certificate
	// chain that satisfied none of the configured pins (leaf-SPKI, full-cert, or
	// CA fingerprints). Under enforce mode the connection was aborted fail-closed
	// so the artifact could not be fetched; under report-only mode it was allowed
	// but recorded. It is the auditable, alertable signal of a possible MITM /
	// compromised-CA attack on the upstream itself, or of an un-staged certificate
	// rotation.
	EventTLSPinViolation EventType = "tls_pin_violation"
	// EventKeyExpiry is a credential/signing-key expiry warning (Task 148): a
	// piece of long-lived trust material — the audit HMAC/Merkle keys, the cache
	// key-encryption key, an outbound attestation signing key, an upstream
	// credential, or a pinned TLS certificate/CA — is within its configured
	// warning window of expiry (or already expired), so an operator can rotate it
	// before it lapses and breaks signing/verification or upstream fetches.
	EventKeyExpiry EventType = "key_expiry"
	// EventKeyRotated is a credential/signing-key rotation event (Task 148): a
	// piece of trust material was rotated to a new primary key, optionally opening
	// a dual-key overlap window during which the previous key is still accepted.
	EventKeyRotated EventType = "key_rotated"

	// EventReleaseTag is a tracked repository's release tag that was moved to
	// another commit or deleted (Task 180). A tag that moves after publication
	// is the classic sign of a tampered release; the release it named stays
	// pinned.
	EventReleaseTag EventType = "release_tag"

	// EventReleasePin is a release whose dependencies could not all be pinned,
	// an object served with a digest other than the lock file records, or a
	// pinned object lost to an integrity failure (Task 180).
	EventReleasePin EventType = "release_pin"

	// EventRepositoryScan is a dependency of a tracked repository that the LLM
	// package-content scan judged malicious — or suspicious, under the
	// quarantine action — in a release, at the default branch's head, or in a
	// revision scanned on request (Task 181).
	EventRepositoryScan EventType = "repository_scan"

	// EventRepositoryUpdate is a maintenance run of a tracked repository that
	// could not move its maintenance branch: the branch holds commits the
	// updater did not push, or the push failed (Task 182).
	EventRepositoryUpdate EventType = "repository_update"
)

// allEventTypes is the canonical set, used for validation and "route all"
// defaults. EventTest is intentionally excluded from routing defaults: a test
// notification targets a sink directly rather than flowing through routes.
var allEventTypes = []EventType{
	EventPolicyBlock,
	EventVulnerability,
	EventCommitScan,
	EventProvenanceFailure,
	EventLicense,
	EventQuarantine,
	EventRescanRegression,
	EventRiskScore,
	EventUpstreamCircuitOpen,
	EventAnomaly,
	EventMaliciousBlock,
	EventApproval,
	EventCacheGC,
	EventExtension,
	EventMaturity,
	EventInstallHooks,
	EventMLGuard,
	EventAVScan,
	EventContentScan,
	EventLLMPackageScan,
	EventSbomDrift,
	EventDepFirewall,
	EventRebuildVerify,
	EventSnapshot,
	EventBuildProvenance,
	EventLockdown,
	EventMeteringBudget,
	EventEgressBlocked,
	EventMaintainerDrift,
	EventGitOps,
	EventCacheIntegrity,
	EventTLSPinViolation,
	EventKeyExpiry,
	EventKeyRotated,
	EventReleaseTag,
	EventReleasePin,
	EventRepositoryScan,
	EventRepositoryUpdate,
}

// AllEventTypes returns the routable event types (excluding the synthetic test
// type), in a stable order.
func AllEventTypes() []EventType {
	out := make([]EventType, len(allEventTypes))
	copy(out, allEventTypes)
	return out
}

// ValidEventType reports whether s names a recognized, routable event type.
func ValidEventType(s string) bool {
	switch EventType(strings.ToLower(strings.TrimSpace(s))) {
	case EventPolicyBlock, EventVulnerability, EventCommitScan,
		EventProvenanceFailure, EventLicense, EventQuarantine, EventRescanRegression,
		EventRiskScore, EventUpstreamCircuitOpen, EventAnomaly, EventMaliciousBlock,
		EventApproval, EventCacheGC, EventExtension, EventMaturity, EventInstallHooks,
		EventMLGuard, EventAVScan, EventContentScan, EventLLMPackageScan,
		EventSbomDrift, EventDepFirewall, EventRebuildVerify, EventSnapshot,
		EventBuildProvenance, EventLockdown, EventMeteringBudget, EventEgressBlocked,
		EventMaintainerDrift, EventGitOps, EventCacheIntegrity, EventTLSPinViolation,
		EventKeyExpiry, EventKeyRotated, EventReleaseTag, EventReleasePin, EventRepositoryScan,
		EventRepositoryUpdate:
		return true
	default:
		return false
	}
}

// Severity orders events so a single severity floor can filter low-signal noise
// while letting critical alerts through. It mirrors the severity vocabulary used
// elsewhere in the proxy (vulnscan, nameguard, commit scan).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank orders severities; an unknown value ranks as info so it can never
// silently satisfy a high floor.
func (s Severity) rank() int {
	switch Severity(strings.ToLower(strings.TrimSpace(string(s)))) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.rank() >= min.rank() }

// NormalizeSeverity coerces an arbitrary string to a known Severity, defaulting
// to info (so a typo never escalates an alert past a severity floor).
func NormalizeSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// ValidSeverity reports whether s is a recognized severity (empty is valid and
// means "info" / no floor).
func ValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(SeverityInfo), string(SeverityLow), string(SeverityMedium),
		string(SeverityHigh), string(SeverityCritical):
		return true
	default:
		return false
	}
}

// Event is a transport-agnostic description of a security-relevant occurrence.
// It is the unit a producer emits and a sink renders. Producers should avoid
// placing raw secrets in any field; the Notifier additionally redacts
// sensitive-looking fields before delivery as defense in depth.
type Event struct {
	// Type categorizes the event for routing and filtering.
	Type EventType `json:"type"`
	// Severity drives the severity floor and the visual treatment in rich sinks.
	Severity Severity `json:"severity"`
	// Time is when the event occurred; set to now by the Notifier when zero.
	Time time.Time `json:"time"`
	// Title is a short, human-readable headline (e.g. "Artifact blocked by policy").
	Title string `json:"title"`
	// Summary is a one-to-two sentence explanation suitable for a chat message.
	Summary string `json:"summary,omitempty"`

	// The coordinate fields below are populated when relevant to the event.

	// Ecosystem is the package ecosystem (npm, pip, cargo, go, nuget, docker, git).
	Ecosystem string `json:"ecosystem,omitempty"`
	// Backend is the upstream/backend name the artifact was routed to.
	Backend string `json:"backend,omitempty"`
	// Artifact is the affected coordinate, e.g. "npm left-pad@1.0.0" or a digest.
	Artifact string `json:"artifact,omitempty"`
	// Subject is the authenticated actor associated with the triggering request,
	// when known.
	Subject string `json:"subject,omitempty"`

	// Fields carries event-specific structured detail (advisory id, risk score,
	// reason code, ...). It is rendered as additional key/value pairs by sinks and
	// is the surface the redactor scrubs. Keep values primitive (rendered as
	// strings).
	Fields map[string]string `json:"fields,omitempty"`
}

// WithField returns ev with key=value added to Fields (lazily allocating the
// map), so producers can attach event-specific detail fluently. Empty keys or
// values are ignored.
func (ev Event) WithField(key, value string) Event { return ev.withField(key, value) }

// withField returns ev with key=value added to Fields (lazily allocating the
// map). Empty keys or values are ignored so optional detail does not produce
// empty pairs.
func (ev Event) withField(key, value string) Event {
	if key == "" || value == "" {
		return ev
	}
	if ev.Fields == nil {
		ev.Fields = make(map[string]string, 4)
	}
	ev.Fields[key] = value
	return ev
}

// sortedFieldKeys returns the field keys in deterministic order so payloads (and
// tests asserting on them) are stable regardless of map iteration order.
func (ev Event) sortedFieldKeys() []string {
	keys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- producer-facing constructors ------------------------------------------
//
// These helpers let the emitting subsystems build a well-formed Event from
// primitives without importing their own domain types into this package (which
// would invert the dependency and risk a cycle).

// PolicyBlockEvent describes an admission-policy block.
func PolicyBlockEvent(ecosystem, backend, artifact, code, reason string) Event {
	return Event{
		Type:      EventPolicyBlock,
		Severity:  SeverityHigh,
		Title:     "Artifact blocked by admission policy",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("code", code)
}

// ProvenanceFailureEvent describes a provenance signature/attestation failure
// that caused a block.
func ProvenanceFailureEvent(ecosystem, backend, artifact, code, reason string) Event {
	return Event{
		Type:      EventProvenanceFailure,
		Severity:  SeverityHigh,
		Title:     "Provenance verification failed",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("code", code)
}

// VulnerabilityEvent describes a vulnerability-gate finding. action is the gate
// outcome ("warn", "block", or "quarantine"); sev is the highest finding
// severity.
func VulnerabilityEvent(sev Severity, ecosystem, backend, artifact, advisory, action, reason string) Event {
	title := "Vulnerable artifact " + actionVerb(action)
	return Event{
		Type:      EventVulnerability,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("advisory", advisory).withField("action", action)
}

// QuarantineEvent describes a quarantine action against an artifact.
func QuarantineEvent(sev Severity, ecosystem, backend, artifact, advisory, reason string) Event {
	return Event{
		Type:      EventQuarantine,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     "Artifact quarantined",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("advisory", advisory)
}

// LicenseViolationEvent describes a license-compliance gate decision. action is
// the gate outcome ("warn", "block", or "quarantine"); code is the decision code
// ("denied", "review", "unknown", or "drift"); license is the offending /
// representative SPDX license; sev is the alert severity.
func LicenseViolationEvent(sev Severity, ecosystem, backend, artifact, license, action, code, reason string) Event {
	title := "License policy " + actionVerb(action) + " artifact"
	if code == "drift" {
		title = "License drift detected"
	}
	return Event{
		Type:      EventLicense,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("license", license).withField("action", action).withField("code", code)
}

// CommitScanEvent describes an LLM commit-scan verdict worth alerting on.
func CommitScanEvent(sev Severity, repository, sha string, riskScore int, malicious bool, summary string) Event {
	title := "Commit scan finding"
	if malicious {
		title = "Malicious commit detected"
	}
	ev := Event{
		Type:     EventCommitScan,
		Severity: NormalizeSeverity(string(sev)),
		Title:    title,
		Summary:  summary,
		Artifact: commitCoordinate(repository, sha),
	}
	ev = ev.withField("riskScore", strconv.Itoa(riskScore))
	if malicious {
		ev = ev.withField("malicious", "true")
	}
	return ev.withField("commit", shortSHA(sha)).withField("repository", repository)
}

// CostBudgetEvent describes a per-tenant LLM commit-scan cost-budget exhaustion
// (Task 78). failOpen reports the degradation mode chosen by policy.
func CostBudgetEvent(tenant string, failOpen bool) Event {
	mode := "fail-closed (pulls blocked)"
	sev := SeverityHigh
	if failOpen {
		mode = "fail-open (admitted without LLM scan)"
		sev = SeverityMedium
	}
	if tenant == "" {
		tenant = "(none)"
	}
	return Event{
		Type:     EventCostBudget,
		Severity: sev,
		Title:    "LLM commit-scan budget exhausted",
		Summary:  "tenant " + tenant + " reached its commit-scan cost ceiling; " + mode,
	}.withField("tenant", tenant).withField("mode", mode)
}

// RescanRegressionEvent describes a CVE-drift regression: a cached artifact that
// became vulnerable against a newly-disclosed advisory.
func RescanRegressionEvent(sev Severity, ecosystem, artifact, advisory, reason string) Event {
	return Event{
		Type:      EventRescanRegression,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     "Cached artifact became vulnerable (CVE drift)",
		Summary:   reason,
		Ecosystem: ecosystem,
		Artifact:  artifact,
	}.withField("advisory", advisory)
}

// CacheIntegrityEvent describes a cache content-integrity violation: a stored
// blob whose bytes no longer match its recorded content digest. source is where
// it was caught ("serve" or "scan"); key is the cache key; expected/computed are
// the digests; quarantined reports whether the entry was removed.
func CacheIntegrityEvent(sev Severity, key, expected, computed, source string, quarantined bool) Event {
	summary := "cached blob failed content-digest verification (" + source + "); " +
		"the content-addressable store has been tampered with or has suffered bit-rot"
	ev := Event{
		Type:     EventCacheIntegrity,
		Severity: NormalizeSeverity(string(sev)),
		Title:    "Cache integrity violation",
		Summary:  summary,
		Artifact: key,
	}
	ev = ev.withField("expected", expected).withField("computed", computed).withField("source", source)
	if quarantined {
		ev = ev.withField("quarantined", "true")
	} else {
		ev = ev.withField("quarantined", "false")
	}
	return ev
}

// KeyExpiryEvent describes a piece of long-lived trust material approaching (or
// past) its expiry (Task 148). materialID is the stable slot id (e.g.
// "cache.kek"); kind classifies it ("cache-kek", "tls-cert", …); keyID is the
// non-secret key identifier if known; status is the graded band ("warning",
// "critical", "expired"); daysLeft is the whole days until expiry (negative when
// expired); expiresAt is the effective expiry instant. The event never carries
// key bytes or secret values.
func KeyExpiryEvent(sev Severity, materialID, kind, keyID, status string, daysLeft int, expiresAt time.Time) Event {
	summary := "signing/encryption key or credential is approaching expiry; rotate it before it lapses to avoid broken signing, verification, or upstream fetches"
	if status == "expired" {
		summary = "signing/encryption key or credential has expired; rotate it immediately to restore signing, verification, or upstream fetches"
	}
	ev := Event{
		Type:     EventKeyExpiry,
		Severity: NormalizeSeverity(string(sev)),
		Title:    "Key/credential approaching expiry",
		Summary:  summary,
		Subject:  materialID,
	}
	ev = ev.withField("material", materialID).
		withField("kind", kind).
		withField("status", status).
		withField("daysLeft", strconv.Itoa(daysLeft))
	if keyID != "" {
		ev = ev.withField("keyId", keyID)
	}
	if !expiresAt.IsZero() {
		ev = ev.withField("expiresAt", expiresAt.UTC().Format(time.RFC3339))
	}
	return ev
}

// KeyRotatedEvent describes a completed rotation of a piece of trust material
// (Task 148). materialID is the slot id; newKeyID is the new primary key id;
// rewrapped is the number of objects re-wrapped (for KEK-style rotations, else
// zero). It is informational.
func KeyRotatedEvent(materialID, newKeyID string, rewrapped int) Event {
	ev := Event{
		Type:     EventKeyRotated,
		Severity: SeverityInfo,
		Title:    "Key/credential rotated",
		Summary:  "a signing/encryption key or credential was rotated to a new primary key",
		Subject:  materialID,
	}
	ev = ev.withField("material", materialID).withField("action", "rotated")
	if newKeyID != "" {
		ev = ev.withField("newKeyId", newKeyID)
	}
	if rewrapped > 0 {
		ev = ev.withField("rewrapped", strconv.Itoa(rewrapped))
	}
	return ev
}

// RiskScoreEvent describes a unified-risk-score threshold crossing. action is
// the admission outcome ("warn" or "block"); band is the artifact's risk band
// ("medium"|"high"|"critical"); score is the 0..100 composite.
func RiskScoreEvent(sev Severity, ecosystem, backend, artifact, band string, score int, action, reason string) Event {
	title := "Risk-score threshold crossed"
	if strings.EqualFold(action, "block") {
		title = "Artifact blocked by risk score"
	}
	return Event{
		Type:      EventRiskScore,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("band", band).withField("score", strconv.Itoa(score)).withField("action", action)
}

// ExtensionEvent describes a custom WASM extension-gate decision (Task 59).
// decision is "warn" or "block"; module names the extension that produced it;
// reason is the module's human-readable explanation.
func ExtensionEvent(sev Severity, ecosystem, backend, artifact, module, decision, reason string) Event {
	title := "Extension gate warning"
	if strings.EqualFold(decision, "block") {
		title = "Artifact blocked by an extension gate"
	}
	return Event{
		Type:      EventExtension,
		Severity:  NormalizeSeverity(string(sev)),
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("module", module).withField("decision", decision)
}

// AnomalyEvent describes a behavioral-anomaly detection on a tenant/identity's
// pull traffic. detector names the strongest triggering detector, level is the
// graded anomaly level, score is the 0..100 composite, and action is the
// response taken (observe|warn|block). The scope (tenant/identity) is carried as
// the subject so an operator can pivot to the offending credential.
func AnomalyEvent(sev Severity, scope, detector, level string, score float64, action, reason string) Event {
	title := "Behavioral anomaly detected on pull traffic"
	if strings.EqualFold(action, "block") {
		title = "Pull traffic soft-blocked by anomaly detection"
	}
	return Event{
		Type:     EventAnomaly,
		Severity: NormalizeSeverity(string(sev)),
		Title:    title,
		Summary:  reason,
		Subject:  scope,
	}.withField("detector", detector).
		withField("level", level).
		withField("score", strconv.Itoa(int(score))).
		withField("action", action)
}

// MaliciousBlockEvent describes a known-malicious-package block (Task 48). code
// is the block code ("malicious" for a concrete coordinate match, "feed-stale"
// for a fail-closed staleness block); advisory is the matched advisory id (empty
// for a staleness block); categories names the malware class(es) when known.
func MaliciousBlockEvent(ecosystem, backend, artifact, advisory, code, categories, reason string) Event {
	title := "Known-malicious package blocked"
	if code == "feed-stale" {
		title = "Pull blocked: known-malicious feed is stale (fail-closed)"
	}
	return Event{
		Type:      EventMaliciousBlock,
		Severity:  SeverityCritical,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("advisory", advisory).withField("code", code).withField("categories", categories)
}

// MaturityEvent describes a release-maturity / version-cooldown block (Task 61).
// remaining is the time left until the version ages past the cooldown window;
// cooldown is the window that applied; unknown reports that the block is due to an
// undeterminable publish timestamp under a fail-closed policy rather than a known
// too-new version. A too-new version is medium severity (a deliberate hold, not a
// confirmed bad artifact); an unknown-timestamp fail-closed block is low.
func MaturityEvent(ecosystem, backend, artifact string, remaining, cooldown time.Duration, unknown bool, reason string) Event {
	sev := SeverityMedium
	code := "cooling"
	title := "Newly-published version held by release cooldown"
	if unknown {
		sev = SeverityLow
		code = "publish-time-unknown"
		title = "Pull held: publish timestamp unknown (cooldown fail-closed)"
	}
	return Event{
		Type:      EventMaturity,
		Severity:  sev,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("code", code).
		withField("cooldown", cooldown.String()).
		withField("remaining", remaining.String())
}

// MaintainerDriftEvent describes a maintainer/publisher continuity drift (Task
// 91): one or more previously-unseen publisher principals (added) appeared for an
// already-known package. disposition is the gate's action (observe|warn|block); a
// block is high severity (the new maintainer is refused while untrusted), warn is
// medium, and an observe-only record is low.
func MaintainerDriftEvent(ecosystem, backend, artifact, disposition string, added []string, previousVersion, version, reason string) Event {
	sev := SeverityLow
	title := "Maintainer/publisher change observed"
	switch strings.ToLower(strings.TrimSpace(disposition)) {
	case "block":
		sev = SeverityHigh
		title = "Maintainer drift blocked: new publisher untrusted"
	case "warn":
		sev = SeverityMedium
		title = "Maintainer/publisher change detected"
	}
	return Event{
		Type:      EventMaintainerDrift,
		Severity:  sev,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("disposition", disposition).
		withField("added", strings.Join(added, ", ")).
		withField("previousVersion", previousVersion).
		withField("version", version)
}

// DepFirewallEvent describes a dependency-firewall block (Task 65). code is the
// machine-readable violation (not-pinned / out-of-range / below-floor / denied /
// not-governed); reason explains the verdict. A firewall block is medium
// severity: a deliberate policy refusal of an unapproved version, not a confirmed
// malicious artifact.
func DepFirewallEvent(ecosystem, backend, artifact, code, reason string) Event {
	return Event{
		Type:      EventDepFirewall,
		Severity:  SeverityMedium,
		Title:     "Pull blocked by the dependency firewall (version policy)",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("code", code)
}

// InstallHooksEvent describes a risky install-script / lifecycle-hook decision
// (Task 62). action is "block" or "warn"; severity is the worst matched-pattern
// severity (so a severity-filtered route delivers only what matters); hookCount
// and findingCount summarize the analysis; rule names the highest-severity rule.
func InstallHooksEvent(severity Severity, ecosystem, backend, artifact, action, rule string, hookCount, findingCount int, reason string) Event {
	title := "Risky install hook detected"
	if action == "block" {
		title = "Install hook blocked: high-risk pattern"
	}
	return Event{
		Type:      EventInstallHooks,
		Severity:  severity,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("rule", rule).
		withField("hooks", strconv.Itoa(hookCount)).
		withField("findings", strconv.Itoa(findingCount))
}

// MLGuardEvent describes an ML weight-scanning decision (Task 110). action is
// "block" or "warn"; severity is the worst finding's severity; format is the
// recognized weight format; imports names the flagged unsafe imports; findingCount
// summarizes the scan.
func MLGuardEvent(severity Severity, ecosystem, backend, artifact, action, format, imports string, findingCount int, reason string) Event {
	title := "Unsafe ML weight pickle detected"
	if action == "block" {
		title = "ML weight blocked: unsafe pickle opcodes"
	}
	return Event{
		Type:      EventMLGuard,
		Severity:  severity,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("format", format).
		withField("imports", imports).
		withField("findings", strconv.Itoa(findingCount))
}

// AVScanEvent describes an antivirus content-scan detection (Task 136). action is
// the detection action taken ("annotate", "quarantine", or "block"); signature
// is the matched malware signature name; engine is the scanning backend (e.g.
// "clamav"); reason is the human-readable explanation.
func AVScanEvent(severity Severity, ecosystem, backend, artifact, action, engine, signature, reason string) Event {
	title := "Malware detected in artifact payload"
	switch action {
	case "quarantine":
		title = "Malware quarantined: artifact payload infected"
	case "block":
		title = "Malware blocked: artifact payload infected"
	}
	return Event{
		Type:      EventAVScan,
		Severity:  severity,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("engine", engine).
		withField("signature", signature)
}

// LLMPackageScanEvent describes a verdict of the sandboxed LLM package-content
// scan gate (Task 173). disposition is how the gate read the verdict
// ("malicious", "suspicious" or "unscanned"); action is what it did ("annotate",
// "block", "quarantine", "fail-open" or "fail-closed"); model is the model that
// judged; confidence is its confidence in the verdict; reason is the one-line
// explanation. The reason is the proxy's own sentence — the model's free-text
// reasons, which are shaped by the package under review, are deliberately not
// carried into an alert.
func LLMPackageScanEvent(severity Severity, ecosystem, backend, artifact, disposition, action, model string, confidence float64, reason string) Event {
	title := "LLM content scan flagged a package"
	switch {
	case disposition == "malicious" && (action == "block" || action == "quarantine"):
		title = "Package blocked: LLM content scan judged it malicious"
	case disposition == "malicious":
		title = "LLM content scan judged a package malicious"
	case disposition == "suspicious" && action == "quarantine":
		title = "Package held for review: LLM content scan judged it suspicious"
	case disposition == "suspicious":
		title = "LLM content scan judged a package suspicious"
	case disposition == "unscanned":
		title = "Package could not be examined by the LLM content scan"
	}
	return Event{
		Type:      EventLLMPackageScan,
		Severity:  severity,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("disposition", disposition).
		withField("action", action).
		withField("model", model).
		withField("confidence", strconv.FormatFloat(confidence, 'f', 2, 64))
}

// LLMPackageBudgetEvent describes an exhausted LLM package-scan cost budget
// (Task 173). scope is "tenant" or "global"; failOpen reports whether unscanned
// artifacts are being served (true) or refused (false) while it lasts.
func LLMPackageBudgetEvent(scope, tenant string, failOpen bool) Event {
	mode := "fail-closed (unscanned pulls refused)"
	sev := SeverityHigh
	if failOpen {
		mode = "fail-open (artifacts served without an LLM verdict)"
		sev = SeverityMedium
	}
	if tenant == "" {
		tenant = "(none)"
	}
	summary := "the global LLM package-scan cost ceiling was reached; " + mode
	if scope == "tenant" {
		summary = "tenant " + tenant + " reached its LLM package-scan cost ceiling; " + mode
	}
	return Event{
		Type:     EventCostBudget,
		Severity: sev,
		Title:    "LLM package-scan budget exhausted",
		Summary:  summary,
	}.withField("scope", scope).withField("tenant", tenant).withField("mode", mode)
}

// ContentScanEvent describes a package-payload static content-analysis finding
// (Task 138). action is the gate action ("annotate", "downgrade", or "block");
// category is the worst finding's category (e.g. "embedded-binary"); the counts
// summarize the scan; severity is the worst finding's severity so a
// severity-filtered route delivers only the findings that matter.
func ContentScanEvent(severity Severity, ecosystem, backend, artifact, action, category string, fileCount, findingCount int, reason string) Event {
	title := "Suspicious package content detected"
	if action == "block" {
		title = "Package blocked: suspicious content"
	}
	return Event{
		Type:      EventContentScan,
		Severity:  severity,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("category", category).
		withField("files", strconv.Itoa(fileCount)).
		withField("findings", strconv.Itoa(findingCount))
}

// SbomDriftEvent describes a significant dependency-drift event (Task 64) between
// two versions of a coordinate. action is the admission action the drift
// warranted ("warn", "block", or "quarantine"); score is the 0..100 drift-risk
// score; the counts summarize the footprint change. The severity escalates with
// the action so a severity-filtered route delivers only the drift that mattered:
// a quarantine/block is high, a warn is medium.
func SbomDriftEvent(ecosystem, backend, artifact, fromVersion, toVersion, action string, score float64, addedDeps, newVulns, newLicenses, newNamespaces int, reason string) Event {
	sev := SeverityMedium
	switch strings.ToLower(action) {
	case "block", "quarantine":
		sev = SeverityHigh
	}
	return Event{
		Type:      EventSbomDrift,
		Severity:  sev,
		Title:     "Significant dependency drift detected",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("fromVersion", fromVersion).
		withField("toVersion", toVersion).
		withField("driftScore", strconv.FormatFloat(score, 'f', -1, 64)).
		withField("addedDeps", strconv.Itoa(addedDeps)).
		withField("newVulnerabilities", strconv.Itoa(newVulns)).
		withField("newLicenses", strconv.Itoa(newLicenses)).
		withField("newNamespaces", strconv.Itoa(newNamespaces))
}

// RebuildVerifyEvent describes a reproducible-build verification outcome (Task
// 68). action is "mismatch" (observe-mode confirmed mismatch) or "quarantine"
// (enforce-mode block); the digests are the two compared values. A quarantine is
// high-severity; a bare mismatch is also high (it is always a tampering signal).
func RebuildVerifyEvent(ecosystem, backend, artifact, commitSHA, upstreamDigest, rebuiltDigest, action, reason string) Event {
	title := "Reproducible-build mismatch: artifact does not derive from attested source"
	if action == "quarantine" {
		title = "Reproducible-build mismatch: artifact quarantined"
	}
	return Event{
		Type:      EventRebuildVerify,
		Severity:  SeverityHigh,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", action).
		withField("commit", commitSHA).
		withField("upstreamDigest", upstreamDigest).
		withField("rebuiltDigest", rebuiltDigest)
}

// BuildProvenanceEvent describes an inbound build-provenance verification outcome
// (Task 72). code is the finding kind (e.g. "source-mismatch",
// "unverified-provenance"); action is "warn" (observe) or "block"/"quarantine"
// (enforce). A source mismatch is high-severity (the metadata misrepresents the
// build source); other findings are medium.
func BuildProvenanceEvent(ecosystem, backend, artifact, code, action, provenCommit, claimedCommit, reason string) Event {
	sev := SeverityMedium
	if code == "source-mismatch" || action == "block" || action == "quarantine" {
		sev = SeverityHigh
	}
	title := "Inbound build-provenance check failed"
	if code == "source-mismatch" {
		title = "Build-provenance source mismatch: artifact does not derive from the claimed source"
	}
	return Event{
		Type:      EventBuildProvenance,
		Severity:  sev,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("code", code).
		withField("action", action).
		withField("provenCommit", provenCommit).
		withField("claimedCommit", claimedCommit)
}

// SnapshotActionEvent describes an organization snapshot lifecycle action (Task
// 70): "captured", "frozen", "unfrozen", or "rollback". A freeze or rollback is
// high-severity (it changes what every client may pull org-wide); a bare capture
// is informational. snapshotID/name identify the snapshot; by is the actor.
func SnapshotActionEvent(action, snapshotID, name, by, reason string, entryCount int) Event {
	sev := SeverityInfo
	title := "Dependency snapshot captured"
	switch strings.ToLower(action) {
	case "frozen":
		sev = SeverityHigh
		title = "Organization frozen to dependency snapshot"
	case "unfrozen":
		sev = SeverityMedium
		title = "Organization dependency freeze lifted"
	case "rollback":
		sev = SeverityHigh
		title = "Instant rollback to last-known-good snapshot"
	}
	return Event{
		Type:     EventSnapshot,
		Severity: sev,
		Title:    title,
		Summary:  reason,
		Subject:  by,
	}.withField("action", action).
		withField("snapshotId", snapshotID).
		withField("snapshotName", name).
		withField("entries", strconv.Itoa(entryCount))
}

// SnapshotFreezeBlockEvent describes the freeze gate refusing a pull (Task 70):
// the requested coordinate fell outside the active frozen set, or its served
// digest differed from the frozen one. code is "not-in-frozen-set" or
// "digest-mismatch". A freeze block is high severity — during an active freeze
// (often an incident), an out-of-set pull is exactly what the operator wants
// surfaced.
func SnapshotFreezeBlockEvent(ecosystem, backend, artifact, code, snapshotID, reason string) Event {
	return Event{
		Type:      EventSnapshot,
		Severity:  SeverityHigh,
		Title:     "Pull blocked by the organization freeze (snapshot)",
		Summary:   reason,
		Ecosystem: ecosystem,
		Backend:   backend,
		Artifact:  artifact,
	}.withField("action", "freeze-block").
		withField("code", code).
		withField("snapshotId", snapshotID)
}

// LockdownEvent describes an emergency-lockdown / global kill-switch transition
// (Task 74). action is the transition ("engaged", "cleared", or "expired"); mode
// is the lockdown posture ("freeze", "strict", or "block"); incidentID and reason
// are the mandatory operator-supplied context. Engaging is critical severity (the
// proxy's posture was tightened during an active incident); clearing/expiring is
// high. targets counts the coordinates a targeted block denies.
func LockdownEvent(action, mode, incidentID, operator, reason string, targets int) Event {
	sev := SeverityHigh
	title := "Emergency lockdown " + action
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "engaged":
		sev = SeverityCritical
		title = "Emergency lockdown ENGAGED (" + mode + ")"
	case "cleared":
		title = "Emergency lockdown cleared"
	case "expired":
		title = "Emergency lockdown auto-expired"
	}
	return Event{
		Type:     EventLockdown,
		Severity: sev,
		Title:    title,
		Summary:  reason,
		Subject:  operator,
	}.withField("action", action).
		withField("mode", mode).
		withField("incidentId", incidentID).
		withField("targets", strconv.Itoa(targets))
}

// GitOpsEvent describes a GitOps policy/config reconciliation transition (Task 93).
// action is the transition ("applied", "drift", "verify_failed", or "rolled_back");
// revision is the source-of-truth revision (Git commit SHA / digest); origin is the
// source description; changed is the number of config settings affected. An applied
// change or a rollback (the posture actually moved) is high-severity; a detected
// drift / pending change is medium; a refused unverified bundle is high (a signed
// source of truth failed its integrity check).
func GitOpsEvent(action, revision, origin string, changed int, reason string) Event {
	sev := SeverityMedium
	title := "GitOps reconciliation"
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "applied":
		sev = SeverityHigh
		title = "GitOps config change applied"
	case "rolled_back":
		sev = SeverityHigh
		title = "GitOps rollback to last-known-good"
	case "verify_failed":
		sev = SeverityHigh
		title = "GitOps bundle failed verification"
	case "drift":
		title = "GitOps drift detected"
	}
	ev := Event{
		Type:     EventGitOps,
		Severity: sev,
		Title:    title,
		Summary:  reason,
	}.withField("action", action).
		withField("revision", revision).
		withField("changed", strconv.Itoa(changed))
	if origin != "" {
		ev = ev.withField("origin", origin)
	}
	return ev
}

// ApprovalEvent describes a quarantine-review / break-glass workflow state change
// (Task 50). action is the transition ("requested", "granted", "denied", or
// "expired"); gate names the admission gate whose block is under review; subject
// is the operator who decided (empty for an automatic expiry or a fresh request).
// A grant or expiry is high-severity (it changes whether a blocked artifact is
// served); a request or denial is medium.
func ApprovalEvent(action, gate, ecosystem, artifact, subject, reason string) Event {
	sev := SeverityMedium
	title := "Quarantine review " + approvalVerb(action)
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "granted":
		sev = SeverityHigh
		title = "Break-glass approval granted"
	case "expired":
		sev = SeverityHigh
		title = "Break-glass approval expired (re-quarantined)"
	case "denied":
		title = "Quarantine review denied (block confirmed)"
	case "requested":
		title = "Quarantine review requested"
	}
	return Event{
		Type:      EventApproval,
		Severity:  sev,
		Title:     title,
		Summary:   reason,
		Ecosystem: ecosystem,
		Artifact:  artifact,
		Subject:   subject,
	}.withField("action", action).withField("gate", gate)
}

// approvalVerb maps an approval transition to a past-tense verb for headlines.
func approvalVerb(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "granted":
		return "granted"
	case "denied":
		return "denied"
	case "expired":
		return "expired"
	case "requested":
		return "requested"
	default:
		return "updated"
	}
}

// CacheHighWatermarkEvent describes the cache remaining above its high watermark
// after a GC sweep: reclaimable space is exhausted. usedBytes/capacityBytes and
// the reclaimed amount give operators the magnitude at a glance.
func CacheHighWatermarkEvent(usedBytes, capacityBytes, reclaimedBytes int64, utilizationPct float64, summary string) Event {
	return Event{
		Type:     EventCacheGC,
		Severity: SeverityHigh,
		Title:    "Cache above high watermark after GC",
		Summary:  summary,
	}.withField("usedBytes", strconv.FormatInt(usedBytes, 10)).
		withField("capacityBytes", strconv.FormatInt(capacityBytes, 10)).
		withField("reclaimedBytes", strconv.FormatInt(reclaimedBytes, 10)).
		withField("utilizationPct", strconv.FormatInt(int64(utilizationPct), 10))
}

// MeteringBudgetEvent describes a per-tenant usage-budget threshold crossing
// (Task 84). dimension is the metered dimension that crossed ("bytes" for served
// bytes, "scanCost" for estimated scan/LLM cost); used and limit are the current
// value and the configured ceiling in that dimension's native units. A budget
// crossing is high severity: it is the operator's cue to investigate or cap a
// tenant's consumption, though metering never blocks pulls itself.
func MeteringBudgetEvent(tenant, dimension string, used, limit int64) Event {
	if tenant == "" {
		tenant = "(none)"
	}
	label := "served bytes"
	if dimension == "scanCost" {
		label = "estimated scan cost"
	}
	return Event{
		Type:     EventMeteringBudget,
		Severity: SeverityHigh,
		Title:    "Tenant usage budget threshold reached",
		Summary: "tenant " + tenant + " reached its " + label + " budget (" +
			strconv.FormatInt(used, 10) + " of " + strconv.FormatInt(limit, 10) + ")",
		Subject: tenant,
	}.withField("tenant", tenant).
		withField("dimension", dimension).
		withField("used", strconv.FormatInt(used, 10)).
		withField("limit", strconv.FormatInt(limit, 10))
}

// TestEvent is the synthetic event delivered by the admin test endpoint.
func TestEvent() Event {
	return Event{
		Type:     EventTest,
		Severity: SeverityInfo,
		Title:    "pullthrough test notification",
		Summary:  "This is a test notification confirming your notification sink is reachable and correctly configured.",
	}
}

// actionVerb maps a gate action to a past-tense verb for headlines.
func actionVerb(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block":
		return "blocked"
	case "quarantine":
		return "quarantined"
	case "warn":
		return "flagged"
	default:
		return "detected"
	}
}

// commitCoordinate renders a "repo@sha" coordinate, tolerating empty parts.
func commitCoordinate(repository, sha string) string {
	switch {
	case repository != "" && sha != "":
		return repository + "@" + shortSHA(sha)
	case sha != "":
		return shortSHA(sha)
	default:
		return repository
	}
}

// shortSHA abbreviates a commit SHA for display.
func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// Emitter is the narrow interface security subsystems emit events to. The
// *Notifier implements it. Implementations must be safe for concurrent use and
// must not block the caller (delivery is asynchronous).
type Emitter interface {
	Emit(ctx context.Context, ev Event)
}

// ReleaseTagEvent describes a tracked repository's release tag that moved or
// disappeared (Task 180). event is "moved" or "deleted"; from and to are the
// commits (to is empty for a deletion).
func ReleaseTagEvent(sev Severity, repo, tag, event, from, to, summary string) Event {
	ev := Event{
		Type:     EventReleaseTag,
		Severity: NormalizeSeverity(string(sev)),
		Title:    "Release tag " + event,
		Summary:  summary,
		Artifact: repo + "@" + tag,
	}
	ev = ev.withField("repository", repo).withField("tag", tag).withField("event", event)
	if from != "" {
		ev = ev.withField("from", from)
	}
	if to != "" {
		ev = ev.withField("to", to)
	}
	return ev
}

// RepositoryScanEvent describes a dependency of a tracked repository that the
// LLM package-content scan flagged (Task 181): the repository, the commit and
// what it is (a release's tags, the default branch), the dependency, how the
// gate reads it and under which action. summary is the proxy's sentence; the
// model's own words are never put in a notification.
func RepositoryScanEvent(sev Severity, repo, commit, ref, coordinate, disposition, action, model, summary string) Event {
	title := "Repository dependency judged " + disposition + " by the LLM content scan"
	ev := Event{
		Type:     EventRepositoryScan,
		Severity: NormalizeSeverity(string(sev)),
		Title:    title,
		Summary:  summary,
		Artifact: coordinate,
	}
	ev = ev.withField("repository", repo).withField("disposition", disposition).withField("action", action)
	if commit != "" {
		ev = ev.withField("commit", commit)
	}
	if ref != "" {
		ev = ev.withField("ref", ref)
	}
	if model != "" {
		ev = ev.withField("model", model)
	}
	return ev
}

// RepositoryUpdateEvent builds a repository_update event: a maintenance run
// whose branch could not be moved (Task 182). summary is the proxy's own
// sentence; repository-controlled names in it are already plain text.
func RepositoryUpdateEvent(sev Severity, repo, branch, commit, status, summary string) Event {
	ev := Event{
		Type:     EventRepositoryUpdate,
		Severity: NormalizeSeverity(string(sev)),
		Title:    "Repository maintenance branch: " + status,
		Summary:  summary,
		Artifact: repo + "@" + branch,
	}
	ev = ev.withField("repository", repo).withField("branch", branch).withField("status", status)
	if commit != "" {
		ev = ev.withField("commit", commit)
	}
	return ev
}

// ReleasePinEvent describes a release pinning problem (Task 180): a release
// not fully pinned, a digest mismatch against the lock file, or a pinned
// object lost. status names the problem; artifact the object, when one.
func ReleasePinEvent(sev Severity, repo, commit, status, artifact, summary string) Event {
	ev := Event{
		Type:     EventReleasePin,
		Severity: NormalizeSeverity(string(sev)),
		Title:    "Release pinning: " + status,
		Summary:  summary,
		Artifact: artifact,
	}
	if ev.Artifact == "" {
		ev.Artifact = repo
		if commit != "" {
			ev.Artifact += "@" + commit
		}
	}
	ev = ev.withField("repository", repo).withField("status", status)
	if commit != "" {
		ev = ev.withField("commit", commit)
	}
	return ev
}
