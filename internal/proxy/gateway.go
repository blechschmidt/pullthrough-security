// Package proxy implements the core gateway layer. It accepts inbound client
// requests over HTTP (and, in a later task, Git-over-SSH), routes them to the
// appropriate upstream Backend, mediates the caching subsystem, and runs the
// security/scanning and provenance pipelines before serving content.
//
// The gateway is deliberately backend-agnostic: it depends only on the
// interfaces defined in the cache, backends, scan, and provenance packages.
package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/avscan"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/fips"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/pypiattest"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/scan"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// Dependencies bundles the collaborators a Gateway needs. Scanner, Provenance,
// SSHServer, Enforcer, and Audit are optional and may be nil.
type Dependencies struct {
	Logger     *slog.Logger
	Cache      cache.Cache
	Backends   *backends.Registry
	Scanner    scan.Scanner
	Provenance provenance.Resolver
	// Policy, when set, gates serving of resolved artifacts on scan verdicts and
	// provenance (the admission middleware, Task 9). A blocked artifact is refused
	// before any cache lookup or upstream fetch. When nil, admission gating is
	// disabled and every resolved artifact is served.
	Policy *policy.Engine
	// Vulnerabilities, when set, generates a CycloneDX SBOM for each cached
	// artifact, resolves it against a vulnerability database (OSV by default), and
	// gates serving on the result (Task 15). Unlike the provenance policy, this gate
	// runs after the artifact is cached (its content must be read to build the
	// SBOM); a quarantine decision evicts the offending content from the cache. When
	// nil, vulnerability gating is disabled.
	Vulnerabilities *vulnscan.Service
	// License, when set, evaluates each cached artifact's SPDX license (read from
	// the SBOM the vulnerability subsystem generates, or extracted on demand)
	// against an allow/deny/review policy with per-tenant overrides and gates
	// serving on the result (Task 28). It runs after the vulnerability gate so it
	// can reuse that SBOM; a denied license is warned on, blocked, or quarantined
	// per policy. When nil, license gating is disabled.
	License *license.Service
	// NameGuard, when set, inspects resolved package coordinates for typosquatting
	// and dependency-confusion risk (Task 19) before any upstream fetch or cache
	// fill. A flagged name is warned on or blocked per the configured thresholds.
	// When nil, name-based admission checking is disabled.
	NameGuard *nameguard.Service
	// Continuity, when set, is the maintainer/publisher continuity monitoring gate
	// (Task 91). It tracks the publisher identity (maintainer roster, namespace
	// owner, signing-key identity) of each (ecosystem, name) coordinate over time
	// with trust-on-first-use, and raises a maintainer_drift signal — and, under a
	// block disposition, refuses the pull — when a previously-unseen maintainer/key/
	// namespace appears for an already-known package (the account-takeover / hijack
	// precursor). When nil, continuity monitoring is disabled.
	Continuity *continuity.Service
	// Malfeed, when set, is the known-malicious-package admission gate (Task 48).
	// It matches a pull's concrete coordinate (ecosystem, name, version) against
	// curated malware datasets (OpenSSF/OSV malicious-packages and GitHub Advisory
	// malware entries) and hard-blocks any listed crypto-miner, credential stealer,
	// or install-script backdoor before any upstream fetch or cache fill. Distinct
	// from NameGuard (heuristics) and Vulnerabilities (CVEs), it matches concrete
	// known-bad coordinates. When nil, known-malicious blocking is disabled.
	Malfeed *malfeed.Service
	// Maturity, when set, is the release-maturity / version-cooldown admission gate
	// (Task 61). It quarantines a newly-published package version until it ages
	// past a configurable cooldown window — derived from the upstream registry's
	// publish timestamp — blunting fast-moving supply-chain attacks where a
	// malicious version is published and yanked within hours. It runs after the
	// name and known-malicious gates, fails open when the publish timestamp is
	// unknown (unless configured fail-closed), and composes with the break-glass
	// workflow so an operator can release a still-cooling version. When nil,
	// release-cooldown gating is disabled.
	Maturity *maturity.Service
	// DepFirewall, when set, is the dependency-firewall version-pinning & allowlist
	// enforcement gate (Task 65). It resolves a pull's concrete (ecosystem, name,
	// version) against the active per-tenant rule set — pinned exact versions,
	// allowed semver ranges, minimum-version floors, and explicit denylists — and
	// refuses any version outside the approved set with an actionable reason. Rules
	// can be imported wholesale from a lockfile so CI can only fetch
	// lockfile-resolved versions. It runs early (right after the name guard, before
	// the heavier scanning gates) and composes with the break-glass workflow so an
	// operator can grant a one-off exception. When nil, version-policy enforcement
	// is disabled.
	DepFirewall *depfirewall.Service
	// InstallHooks, when set, is the install-script / lifecycle-hook risk-analysis
	// gate (Task 62). It statically extracts a package's automatically-run install
	// hooks (npm pre/post-install scripts, Python setup.py / pyproject build hooks,
	// RubyGems native extensions + post-install message, Cargo build.rs) and scores
	// them against deterministic high-risk patterns — network egress during
	// install, base64-decoded eval, shell/process spawning, writes outside the
	// package directory, environment-variable exfiltration, and obfuscated
	// one-liners — without ever executing anything. Its findings feed the policy and
	// risk engines and the SARIF findings layer; a finding meeting the tenant's
	// threshold warns on or blocks (and evicts) the artifact. When nil, install-hook
	// analysis is disabled.
	InstallHooks *installhooks.Service
	// MLGuard, when set, is the ML model weight-scanning gate (Task 110). For a
	// Hugging Face model/dataset pull it statically disassembles a pickle-based
	// weight file (.bin/.pkl/.pt/.pth/.ckpt, unwrapping the PyTorch ZIP container)
	// and flags imports of code-execution / network / filesystem primitives invoked
	// via __reduce__ — the malicious-model attack vector — without ever unpickling
	// anything. Its findings feed the policy and risk engines and the SARIF layer; a
	// finding meeting the tenant threshold warns on or blocks (and quarantines) the
	// weight, and a served pickle may carry an advisory preferring safetensors. When
	// nil, ML weight scanning is disabled.
	MLGuard *mlguard.Service
	// AVScan, when set, is the antivirus content-scanning gate (Task 136). It
	// streams a fetched artifact's payload (package archives, wheels, jars, OCI
	// layer blobs, ML weight files, Git LFS objects) through a configurable AV
	// engine — primarily ClamAV over the clamd INSTREAM protocol — and, on a
	// positive byte-level malware detection, annotates/quarantines/blocks the
	// artifact. Its findings feed the policy and risk engines, the SARIF layer, and
	// the notification pipeline. When nil, antivirus scanning is disabled.
	AVScan *avscan.Service
	// ContentScan, when set, is the package-payload static content-analysis gate
	// (Task 138). It unpacks a cached source artifact (npm tarball, pip sdist/wheel,
	// gem/composer/cargo/nuget archive) and applies deterministic heuristics to its
	// files — embedded native binaries, high-entropy/packed blobs, obfuscated
	// JavaScript, dynamic code-execution sinks, and in-source secrets (reusing the
	// Task 29 detectors) — never executing anything. Its per-file findings feed the
	// policy and risk engines, the SARIF layer, and the notification pipeline, and a
	// finding meeting the fail threshold can block per policy. When nil, package
	// content analysis is disabled.
	ContentScan *contentscan.Service
	// LLMPkgScan, when set, is the sandboxed LLM package-content scan gate (Task
	// 173). It unpacks a cached package artifact into a bounded, read-only,
	// in-memory tree and has a language model judge it malicious / suspicious /
	// benign — through a fixed set of read-only tools (list, read, grep) or a
	// prioritized single-shot bundle; package code is never executed and the model
	// has no network or host access. Package content is handled as untrusted data
	// throughout (prompt-injection defenses, a strict verdict schema, deterministic
	// cross-checks), and a scan that fails for any reason is "unscanned", never
	// benign. Verdicts are cached by artifact digest + model + prompt version;
	// concurrent scans of one digest are coalesced and spend is bounded by a
	// per-tenant / global budget. Its verdict feeds the policy and risk engines,
	// the SARIF layer, the dossier and the notification pipeline, and per the
	// configured action it annotates, blocks or quarantines. When nil, LLM package
	// scanning is disabled.
	LLMPkgScan *llmpkgscan.Service
	// Sigverify, when set, cryptographically verifies cosign signatures and SLSA
	// provenance attestations (OCI) and Sigstore publish attestations (npm/pip)
	// before serving (Task 23). An artifact whose authenticity cannot be
	// established is warned on or blocked per the configured thresholds; a blocked
	// artifact is evicted from the cache. When nil, signature verification is off.
	Sigverify *sigverify.Service
	// PolicyEngine, when set, is the declarative policy-as-code admission engine
	// (Task 32). It runs as the final aggregating gate, evaluating operator-
	// authored CEL rules over the signals the preceding gates produced for this
	// request. It layers on top of the hard-coded gates (it can deny an otherwise-
	// allowed artifact but never re-admit a blocked one). When nil, only the
	// hard-coded gates apply.
	PolicyEngine *policyengine.Engine
	// RiskScore, when set, is the unified supply-chain risk-scoring engine (Task
	// 37). It runs after the policy-as-code gate over the same accumulated
	// admission signals, computing a single composite, explainable risk score and
	// band per artifact. With an admission threshold configured (warn/block above
	// a band) it composes with — rather than replaces — the policy engine; with the
	// threshold off it scores and records for observability only. When nil, risk
	// scoring is disabled.
	RiskScore *riskscore.Engine
	// RepoScore, when set, is the source-repository health signal provider (Task
	// 63). It derives OpenSSF Scorecard-style health signals (branch-protection
	// presence, signed-commit ratio, CI and security-policy presence, maintainer
	// count / bus factor, recent activity, dependency-update automation) for the
	// repository the artifact was built from — taken from the provenance
	// association — using an already-mirrored local clone (offline/air-gap
	// friendly). It runs as a signal provider before the policy/risk gates,
	// folding a per-repo health/risk score into the admission accumulator they
	// consume; it never blocks a pull on its own. When nil, repository-health
	// scoring is disabled.
	RepoScore *reposcore.Service
	// SbomDiff, when set, is the SBOM diff & dependency-drift subsystem (Task 64).
	// After the vulnerability/license gates have produced the artifact's SBOM, it
	// reduces that SBOM (plus the scan's vulnerabilities) to a per-version snapshot,
	// records it in a bounded per-coordinate history, and diffs the new version
	// against the prior one — surfacing added/removed/version-bumped transitive
	// dependencies, newly-introduced licenses (cross-referenced against the license
	// policy), never-before-seen namespaces, and net-new vulnerabilities. It derives
	// a "drift risk" score that it folds into the admission accumulator (a policy/
	// risk signal) and, when configured to enforce, warns on or blocks (and evicts)
	// a quiet package that suddenly grows a large or suspicious new dependency
	// footprint. It runs after the content gates and before the aggregating policy/
	// risk gates. When nil, drift tracking is disabled.
	SbomDiff *sbomdiff.Service
	// RebuildVerify, when set, is the reproducible-build verification gate (Task
	// 68). After the signature gate, for an artifact already mapped to a source Git
	// commit by the provenance subsystem, it performs (asynchronously and
	// non-blocking by default) a deterministic rebuild-from-source via a pluggable,
	// sandboxed, air-gap-aware Builder and compares the rebuilt digest against the
	// upstream-served artifact. The verdict — reproducible | mismatch | unsupported
	// | unattested — feeds the policy and risk engines and the SARIF findings layer;
	// in the optional enforce mode a confirmed mismatch quarantines the artifact
	// (composing with the break-glass workflow). Builders skip gracefully when the
	// toolchain is unavailable (fail-open). When nil, reproducible-build
	// verification is disabled.
	RebuildVerify *rebuildverify.Service
	// BuildProv, when set, is the inbound build-provenance verification gate (Task
	// 72). After the signature gate it fetches the upstream-published build
	// provenance (npm provenance / GitHub artifact attestation), cryptographically
	// binds the package version to its source repository + commit + CI workflow, and
	// cross-checks that proven commit against the package-to-commit association the
	// provenance subsystem (Task 8) reported — flagging a disagreement (metadata
	// claims one source, the signed attestation proves another). Its signals feed the
	// policy/risk engines and the SARIF findings layer; in enforce mode a failing
	// finding (notably a confirmed source mismatch) quarantines the artifact
	// (composing with the break-glass workflow). When nil, inbound build-provenance
	// verification is disabled.
	BuildProv *buildprov.Service
	// PyPIAttest, when set, is the inbound PyPI PEP 740 digital-attestation
	// verification gate (Task 146). For a served pip/PyPI wheel/sdist it fetches the
	// distribution's PEP 740 provenance (Integrity API / JSON-index "provenance"
	// field), cryptographically verifies the enclosed Sigstore attestations against
	// the Fulcio/Rekor trust root, and binds the attested sha256 digest to the
	// served artifact. It feeds the policy/risk engines and the SARIF/dossier layers;
	// per the configured action it annotates, downgrades, or blocks the pull. When
	// nil, PyPI attestation verification is disabled.
	PyPIAttest *pypiattest.Service
	// Snapshot, when set, is the organization-wide dependency snapshot, freeze &
	// instant-rollback subsystem (Task 70). It plays two roles on the pull path:
	// (1) an early freeze gate, right after the dependency firewall, that — when a
	// freeze is active and enforcement is on — refuses any pull whose concrete
	// (ecosystem, name, version) is outside the frozen snapshot's set, or whose
	// served digest differs from the frozen one (composing with the break-glass
	// workflow); and (2) a post-admission recorder that folds every served
	// coordinate's resolved state (digest, source commit, verdict, risk band,
	// attestation-bundle digest) into the live state from which point-in-time
	// snapshots are captured. When nil, snapshotting and freezing are disabled.
	Snapshot *snapshot.Service
	// Lockdown, when set, is the emergency-lockdown / global kill-switch incident-
	// response control (Task 74). It is consulted as the very FIRST check on the pull
	// path, ahead of every other admission gate: a targeted `block` lockdown denies a
	// specific (eco,name[,version]) coordinate everywhere; a `freeze` lockdown serves
	// only already-cached artifacts and refuses every new upstream fetch (enforced at
	// the fetch boundary); a `strict` lockdown is surfaced as an admission signal that
	// asks the policy/risk engines to harden. Transitions are durable, coord-guarded
	// (Task 56), TTL'd with auto-expiry, recorded to the Merkle audit log, and compose
	// with the break-glass workflow. When nil, no lockdown control is active.
	Lockdown *lockdown.Service
	// Extension, when set, is the sandboxed WebAssembly extensibility manager
	// (Task 59). It runs as the final, operator-extensible admission gate after the
	// policy and risk gates, invoking operator-supplied wasm modules over the same
	// aggregated signal view (plus the composite risk score) and applying their
	// combined allow/warn/block verdict under strict CPU/memory/time/fuel limits
	// with no host filesystem or network access. Like the policy and risk gates it
	// composes with — never re-admits past — the hard-coded gates. When nil (or no
	// modules are configured) extension gating is disabled.
	Extension *extension.Manager
	// Anomaly, when set, is the behavioral anomaly-detection engine (Task 43). It
	// observes the pull stream per tenant/identity and flags traffic patterns —
	// distinct-package fan-out spikes, bursts of new namespaces, off-hours bursts,
	// rapid 404 enumeration, and anomalous egress volume — that signal credential
	// compromise or exfiltration rather than a single bad artifact. It emits graded
	// notifications and, when soft-blocking is configured, sheds further requests
	// from an identity that is currently behaving anomalously. When nil, behavioral
	// anomaly detection is disabled.
	Anomaly *anomaly.Engine
	// Coalescer, when set, is the pull-path request coalescer and negative cache
	// (Task 36). It collapses concurrent cache-miss requests for the same
	// (tenant-scoped) artifact key onto a single upstream fetch and remembers
	// terminal upstream failures (404/410/auth) for a short TTL, with jittered
	// backoff for transient 5xx, so a thundering herd never reaches the upstream.
	// When nil, each miss fetches independently (the cache's own single-flight
	// still applies).
	Coalescer *coalesce.Coalescer[*cache.Entry]
	// ProvGraph, when set, ingests each served artifact — together with its source
	// commit, SBOM dependencies, CVE findings, and signature status — into the
	// supply-chain provenance graph (Task 33), which powers the admin blast-radius
	// / reverse-dependency / path-to-commit queries and visualization. Ingestion is
	// best-effort and never blocks or fails a pull. When nil, no graph is built.
	ProvGraph *provgraph.Service
	// Findings, when set, is the unified SARIF findings-aggregation store (Task
	// 42). After the admission gates run, the gateway normalizes the per-request
	// accumulated signals (plus the policy and risk verdicts) into a canonical
	// findings document and records it here, keyed by (tenant, coordinate), so the
	// admin SARIF endpoint and CLI can later serve an artifact's findings to a CI
	// pipeline. Recording is best-effort and never affects serving. When nil, no
	// findings are retained.
	Findings *findings.Store
	// FindingsMetrics, when set, accumulates the finding de-duplication counters
	// (Task 165) exported as the pullthrough_findings_dedup_* family. The gateway
	// de-duplicates each normalized findings document before recording it, folding
	// the pass statistics here. When nil, de-duplication still runs; only the
	// metrics are skipped.
	FindingsMetrics *findings.Metrics
	// Suppressions, when set, is the immutable suppression audit trail (Task 165).
	// After normalizing and de-duplicating a findings document, the gateway records
	// every suppressed finding (VEX adjudication, reachability downgrade, policy
	// downgrade) into this ledger, which is queryable per coordinate and mirrored
	// into the tamper-evident audit log. Recording is best-effort. When nil, no
	// suppression audit trail is kept.
	Suppressions *findings.SuppressionLedger
	// SIEM, when set, is the outbound SIEM / log-forwarding integration (Task
	// 119). After the admission gates run and a findings document is recorded, the
	// gateway forwards its findings to the configured external SIEM sinks (Splunk
	// HEC, syslog/CEF). Forwarding is asynchronous, best-effort, and never blocks
	// or fails a pull. When nil, no findings are forwarded. (Audit records are
	// forwarded independently, via a decorating audit sink wired at the audit log.)
	SIEM SIEMForwarder
	// SimReplay, when set, is the policy & risk what-if capture recorder (Task 47).
	// After the admission gates run, the gateway records the per-request admission
	// document (sampled and redacted) together with the verdict the live config
	// produced into a bounded ring buffer, so an operator can later replay the
	// captured traffic through a candidate configuration and diff the outcome.
	// Capture is best-effort and never affects serving. When nil, nothing is
	// captured and the CLI's file-input replay path still works independently.
	SimReplay *simreplay.Recorder
	// Attestor, when set, is the outbound SLSA/in-toto attestation engine (Task
	// 46). After an artifact clears every admission gate and is about to be served,
	// the gateway assembles a signed in-toto statement binding the served digest to
	// its source commit, the verdicts it passed, and the proxy's identity, retains
	// it for the OCI referrers endpoint / admin / CLI export, and embeds its bundle
	// digest in the audit log. This makes the proxy a provenance ATTESTER that
	// downstream CI can require. Production is best-effort and never affects
	// serving. When nil, no outbound attestation is produced.
	Attestor *attestbundle.Service
	// Approvals, when set, is the human-in-the-loop quarantine-review / break-glass
	// approval workflow (Task 50). When an admission gate is about to block or
	// quarantine an artifact (vulnscan quarantine, CVE-drift, malfeed, sigverify
	// failure, hard policy block), the gate consults this workflow first: an active,
	// time-boxed, tenant+coordinate+gate-scoped break-glass grant lets the artifact
	// be served instead of refused; otherwise a pending review is recorded for an
	// operator to approve or confirm. When nil, gates block unconditionally.
	Approvals *approvals.Service
	// SSHServer, when set, is a Git-over-SSH listener started alongside the HTTP
	// gateway and stopped when the gateway shuts down.
	SSHServer SSHServer
	// Interceptor, when set, is the TLS-interception forward-proxy listener
	// (Task 100) started alongside the HTTP gateway. It decrypts intercepted
	// client TLS, maps the real upstream host to a backend, rewrites the request
	// into the /v1 route space, and dispatches it back through this same gateway
	// handler — so the full caching + admission pipeline applies unchanged. When
	// nil, only explicit package-source (/v1) access is served.
	Interceptor Interceptor
	// Enforcer applies client authentication, RBAC authorization, and per-team
	// quotas to inbound backend requests. When nil, access control is disabled
	// (every request is served as an anonymous principal).
	Enforcer *auth.Enforcer
	// RateLimit enforces per-tenant and global request-rate, upstream-concurrency,
	// and byte-quota policies (Task 24). It runs inside the access-control envelope
	// so the tenant is resolved from the authenticated principal. When nil, rate
	// limiting is disabled.
	RateLimit *ratelimit.Limiter
	// Audit, when set, records a tamper-evident entry for every pull, cache
	// hit/miss, and authorization decision.
	Audit *audit.Logger
	// Notify, when set, dispatches structured security alerts (policy blocks,
	// vulnerability findings, provenance failures, quarantine actions) to the
	// configured webhook/Slack sinks (Task 21). Emission is asynchronous and never
	// blocks the request path. When nil, alerting is disabled.
	Notify notify.Emitter
	// Ecosystems maps a backend/upstream name to its ecosystem type
	// (pip|npm|cargo|go|nuget|docker|git), used by RBAC and audit. A name absent
	// from the map falls back to the name itself.
	Ecosystems map[string]string
	// Metrics, when set, records request, upstream-latency, bytes-served, and
	// policy-decision telemetry. When nil, recording is a no-op.
	Metrics MetricsRecorder
	// Metering, when set, accounts per-tenant usage (requests, bytes served split
	// by cache-hit vs upstream fetch, cache-fill storage footprint, admission-scan
	// invocations and estimated cost, and gate refusals) for chargeback reporting
	// (Task 84). When nil, accounting is a no-op.
	Metering MeteringRecorder
	// Tracer, when set, emits OpenTelemetry spans for the full latency breakdown
	// of a pull — ingress, auth, rate limiting, cache lookup, upstream fetch,
	// every admission gate, and response — and propagates W3C trace context
	// (Task 41). A nil Tracer is a valid no-op, so disabling tracing needs no nil
	// checks at call sites.
	Tracer *tracing.Tracer
	// MetricsHandler, when set, is mounted at Options.MetricsPath to serve the
	// Prometheus exposition format (typically metrics.Collector.Handler()).
	MetricsHandler http.Handler
	// AdminHandler, when set, is mounted under Options.AdminPrefix to serve the
	// operator REST API and dashboard.
	AdminHandler http.Handler
	// PortalHandler, when set, is mounted under Options.PortalUIPrefix and
	// Options.PortalAPIPrefix to serve the tenant self-service read-only security
	// portal (Task 71): a non-admin surface hard-scoped to the caller's tenant.
	PortalHandler http.Handler
	// WebhookHandler, when set, is mounted at Options.WebhookPath to receive push
	// webhooks for the continuous commit scanner (Task 108). It sits outside the
	// /v1 client access-control envelope and authenticates deliveries itself via
	// the GitHub-style HMAC signature.
	WebhookHandler http.Handler
	// PullObserver, when set, receives a best-effort notification for each
	// artifact successfully served on the cacheable pull path, feeding the
	// predictive cache pre-warming subsystem's historical pull telemetry (Task
	// 134). Synthetic pre-warm fetches are excluded. Observation never blocks or
	// fails a pull. When nil, no pull telemetry is collected.
	PullObserver PullObserver
	// CacheFed, when set and enabled, is the cross-proxy peer cache-federation
	// layer (Task 143). On a local cache miss — after the lockdown freeze check
	// but before the upstream fetch — the cacheable pull path consults healthy
	// sibling peers for the artifact by content digest; a verified peer hit fills
	// the local cache (and still runs every admission gate) instead of reaching
	// the upstream, reducing egress and warming time. Peer bytes are re-verified
	// against the expected digest on receipt and never trusted blindly. The
	// gateway also mounts the authenticated peer HEAD/GET endpoint so siblings can
	// read this instance's already-gated cache. When nil or disabled, every miss
	// goes straight to the upstream.
	CacheFed *cachefed.Federation
	// DownloadLog, when set and enabled, is the download log (Task 176): the
	// record of which package was downloaded from which client address. The
	// gateway adds one entry per request for an installable artifact — served,
	// refused by a gate, or failed — with the client address (see
	// Options.ClientIP), the resolved package coordinate, the outcome, and the
	// authenticated identity when there is one. Recording is an in-memory append
	// after the response is written and never affects serving. A nil log is a
	// valid no-op.
	DownloadLog *downloadlog.Log
	// UserLinks, when set, is the personal-links subsystem (Task 177): cache
	// users sign in through an OIDC identity provider and are handed personal
	// cache links — the package-source URLs under a path prefix that is theirs
	// ("/u/<token>/v1/<upstream>/…") — so that a download is attributed to a
	// person and not only to an address. The gateway serves that prefix (taking
	// it off the path at the edge and putting it back into the links of the
	// response), resolves a request's link to the user it stands for — in the
	// path or presented as a credential — and mounts the self-service page. A
	// nil service is the feature switched off.
	UserLinks *userlinks.Service
}

// SSHServer is an auxiliary listener (Git-over-SSH) run for the lifetime of the
// gateway. Run must block until ctx is canceled, then return.
type SSHServer interface {
	Run(ctx context.Context) error
}

// Interceptor is the TLS-interception forward-proxy listener (Task 100). Run
// binds listenAddr, dispatches decrypted/host-routed requests into serve (the
// gateway handler), and blocks until ctx is canceled, then returns. serve
// receives requests whose path has been rewritten into the "/v1/<backend>/..."
// route space.
type Interceptor interface {
	Run(ctx context.Context, listenAddr string, serve http.Handler) error
}

// Options configures Gateway behavior derived from config.
type Options struct {
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	// TLSCertFile and TLSKeyFile enable TLS termination at the gateway. When both
	// are set, the gateway serves HTTPS; when both are empty it serves plain
	// HTTP. Setting only one is a configuration error (rejected by New).
	TLSCertFile string
	TLSKeyFile  string
	// CacheNamespacing, when true, partitions cache entries by the requesting
	// principal's team namespace so tenants cannot observe one another's cached
	// content. It trades cross-tenant deduplication for isolation; leave false
	// for a shared cache of (immutable, content-addressed) public artifacts.
	CacheNamespacing bool
	// TLSClientAuth configures inbound client-certificate handling for SPIFFE/SVID
	// mutual-TLS workload identity (Task 58). tls.RequestClientCert requests a
	// client certificate opportunistically (either-or with token/OIDC auth);
	// tls.RequireAnyClientCert requires one (mTLS-required mode). Verification of
	// the chain against the SPIFFE trust bundle is performed in the application
	// layer (the spiffe authenticator in the auth chain), so the trust bundle can
	// be hot-reloaded without restarting the listener. The zero value
	// (tls.NoClientCert) leaves mTLS off. It is only honored when TLS termination
	// is enabled (TLSCertFile/TLSKeyFile set).
	TLSClientAuth tls.ClientAuthType
	// MetricsPath is the path the Prometheus exposition is served on (e.g.
	// "/metrics"). Empty disables the endpoint even if a handler is supplied.
	MetricsPath string
	// AdminPrefix is the path prefix the admin surface is mounted under (e.g.
	// "/admin"). Empty disables it even if a handler is supplied.
	AdminPrefix string
	// PortalUIPrefix and PortalAPIPrefix are the path prefixes the tenant
	// self-service portal's front-end page and JSON API are mounted under (e.g.
	// "/portal" and "/api/portal"). Empty disables the portal even if a handler is
	// supplied.
	PortalUIPrefix  string
	PortalAPIPrefix string
	// InterceptAddr is the listen address for the TLS-interception forward proxy
	// (Task 100). It is honored only when Dependencies.Interceptor is set.
	InterceptAddr string
	// WebhookPath is the path the continuous commit scanner's push-webhook
	// receiver is mounted at (e.g. "/webhooks/git"). Empty disables the endpoint
	// even if a handler is supplied.
	WebhookPath string
	// FIPSEnabled, when true, restricts inbound TLS termination to the FIPS 140-3
	// approved floor: a TLS 1.2 minimum and the approved AES-GCM cipher suites
	// (Task 120). It is independent of whether the binary links the validated Go
	// FIPS module; it applies the approved parameters defensively in all builds.
	FIPSEnabled bool
	// RegistryRoot, when non-nil and naming at least one upstream, additionally
	// serves the Docker/OCI Registry v2 API at the host root ("/v2/..."), the only
	// place container clients can address a registry. Requests are mapped onto
	// the regular "/v1/<upstream>/v2/..." route space. See RegistryRoot.
	RegistryRoot *RegistryRoot
	// ClientIP resolves the address a request is attributed to. With trusted
	// reverse proxies configured it reads the client address they forwarded
	// (X-Forwarded-For) instead of the TCP peer, which behind a load balancer is
	// the balancer for every request. The audit trail, anomaly scoping and the
	// download log all use the address it returns. Nil trusts no proxy: the
	// address is always the TCP peer.
	ClientIP *clientip.Resolver
	// PublicURL is the proxy's externally reachable base URL (server.publicUrl),
	// and LinkBackends names the backends whose protocol adapter writes links to
	// its own mount into the documents it serves — an npm packument's tarball
	// URLs, a PyPI page's file links, a Terraform provider's download URL.
	// Together they are what the personal-link edge needs to recognise such a
	// link in a response and give it the personal prefix (Task 177). They are
	// used for nothing else.
	PublicURL    string
	LinkBackends map[string]bool
}

// Gateway is the core proxy. It is constructed via New and started with Run.
type Gateway struct {
	deps   Dependencies
	opts   Options
	server *http.Server
	// serve holds cumulative counters for the Range/partial-content streaming
	// serve path (Task 75), surfaced via ServeMetrics.
	serve *serveStats
	// personal counts what the personal-link edge did (Task 177), surfaced via
	// PersonalLinkMetrics.
	personal personalStats
}

// New validates dependencies and constructs a Gateway.
func New(deps Dependencies, opts Options) (*Gateway, error) {
	if deps.Logger == nil {
		return nil, errors.New("proxy: logger is required")
	}
	if deps.Cache == nil {
		return nil, errors.New("proxy: cache is required")
	}
	if deps.Backends == nil {
		return nil, errors.New("proxy: backend registry is required")
	}
	if opts.HTTPAddr == "" {
		return nil, errors.New("proxy: HTTPAddr is required")
	}
	if (opts.TLSCertFile == "") != (opts.TLSKeyFile == "") {
		return nil, errors.New("proxy: TLS requires both TLSCertFile and TLSKeyFile, or neither")
	}
	if opts.TLSClientAuth != tls.NoClientCert && opts.TLSCertFile == "" {
		return nil, errors.New("proxy: mutual-TLS client auth requires TLS termination (TLSCertFile/TLSKeyFile)")
	}

	g := &Gateway{deps: deps, opts: opts, serve: &serveStats{}}
	g.server = &http.Server{
		Addr:         opts.HTTPAddr,
		Handler:      g.routes(),
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		ErrorLog:     slog.NewLogLogger(deps.Logger.Handler(), slog.LevelError),
	}
	if opts.TLSCertFile != "" {
		// Enforce a modern floor for inbound TLS termination.
		g.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		// Under FIPS mode, additionally pin the configurable cipher suites to the
		// FIPS 140-3 approved AES-GCM set (the TLS 1.2 floor already matches the
		// approved floor).
		if opts.FIPSEnabled {
			g.server.TLSConfig = fips.HardenServerTLSConfig(g.server.TLSConfig)
		}
		// Request or require a client certificate for mTLS workload identity. The
		// certificate is validated against the SPIFFE trust bundle in the auth
		// chain (so the bundle stays hot-reloadable), hence no ClientCAs here.
		if opts.TLSClientAuth != tls.NoClientCert {
			g.server.TLSConfig.ClientAuth = opts.TLSClientAuth
		}
	}
	return g, nil
}

// Handler returns the gateway's fully-wired HTTP handler — the same one the
// embedded server serves — so it can be driven in-process (e.g. by the red-team
// gate-efficacy harness in internal/redteam, Task 76, or by integration tests)
// without binding a network listener. Each call builds a fresh handler tree.
func (g *Gateway) Handler() http.Handler { return g.routes() }

// routes builds the HTTP handler. Backend traffic is served under
// "/v1/<backend>/...". Operational endpoints live at the root.
func (g *Gateway) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealth)
	mux.HandleFunc("/readyz", g.handleReady)
	backend := g.withClientSource(g.withTracing(g.withAccessControl(g.withRateLimit(http.HandlerFunc(g.handleBackend)))))
	mux.Handle("/v1/", backend)

	// Host-root Docker/OCI Registry v2 alias. Container clients always insert
	// "/v2/" directly after the registry host, so they cannot reach the
	// path-prefixed mount; the alias rewrites each request onto
	// "/v1/<upstream>/v2/..." and reuses the very same handler chain, so the
	// access-control envelope and every admission gate apply unchanged.
	var registry http.Handler
	if rr := g.opts.RegistryRoot; rr != nil && len(rr.Upstreams) > 0 {
		registry = g.handleRegistryRoot(backend)
		mux.Handle(registryRootPrefix, registry)
	}

	// Personal cache links (Task 177): the same package sources under a path
	// prefix that names a user, "/u/<token>/v1/<upstream>/…". The prefix is
	// taken off here and the request handed to the very handler chains above,
	// so a personal request passes the same access control and the same gates;
	// what differs is who it is recorded as. The self-service page where users
	// sign in and manage their links is mounted next to it; it authenticates its
	// users itself.
	if links := g.deps.UserLinks; links.Enabled() {
		mux.Handle(links.PathPrefix()+"/", g.handlePersonalPath(backend, registry))
		mux.Handle(links.UIPath(), links.Handler())
		mux.Handle(links.UIPath()+"/", links.Handler())
	}

	// Operational telemetry: the Prometheus endpoint and the admin API/dashboard.
	// Both are optional and mounted only when wired and enabled. They sit outside
	// the /v1 client access-control envelope (the admin surface carries its own
	// bearer-token guard; the metrics endpoint is intended for a trusted scrape
	// network).
	if g.deps.MetricsHandler != nil && g.opts.MetricsPath != "" {
		mux.Handle(g.opts.MetricsPath, g.deps.MetricsHandler)
	}
	// The continuous commit scanner's push-webhook receiver. It carries its own
	// HMAC-signature authentication, so it sits outside the /v1 client envelope
	// (the external Git host posting here has no proxy client credentials).
	if g.deps.WebhookHandler != nil && g.opts.WebhookPath != "" {
		mux.Handle(g.opts.WebhookPath, g.deps.WebhookHandler)
	}
	// The cross-proxy peer cache-federation endpoint (Task 143). It carries its
	// own shared-secret bearer authentication (and fails closed when serving is
	// disabled or no secret is configured), so it sits outside the /v1 client
	// envelope — sibling proxies authenticate as peers, not as package clients.
	if g.deps.CacheFed.Enabled() {
		// A peer is served the cache by key, with no admission gate in between:
		// the guard keeps this proxy from handing out bytes it has itself judged
		// malicious (see PeerServeGuard).
		mux.Handle(cachefed.BasePath, g.deps.CacheFed.Handler(g.deps.Cache, g.PeerServeGuard))
	}
	if g.deps.AdminHandler != nil && g.opts.AdminPrefix != "" {
		prefix := strings.TrimRight(g.opts.AdminPrefix, "/")
		mux.Handle(prefix, g.deps.AdminHandler)
		mux.Handle(prefix+"/", g.deps.AdminHandler)
	}
	// The self-service portal serves its front-end under one prefix and its scoped
	// JSON API under another; both route into the same handler (a single mux with
	// absolute paths), so mount it under each subtree.
	if g.deps.PortalHandler != nil {
		for _, prefix := range []string{g.opts.PortalUIPrefix, g.opts.PortalAPIPrefix} {
			prefix = strings.TrimRight(prefix, "/")
			if prefix == "" {
				continue
			}
			mux.Handle(prefix, g.deps.PortalHandler)
			mux.Handle(prefix+"/", g.deps.PortalHandler)
		}
	}
	return g.withRequestLogging(mux)
}

// Run starts the HTTP server and blocks until ctx is canceled, then performs a
// graceful shutdown bounded by ShutdownTimeout.
func (g *Gateway) Run(ctx context.Context) error {
	// The SSH gateway, when configured, shares the gateway lifecycle: it is
	// started here and torn down when ctx is canceled. A fatal SSH error cancels
	// the shared context so the HTTP server also shuts down.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var sshErr error
	sshDone := make(chan struct{})
	if g.deps.SSHServer != nil {
		go func() {
			defer close(sshDone)
			if err := g.deps.SSHServer.Run(ctx); err != nil {
				g.deps.Logger.Error("git ssh gateway stopped with error", "error", err)
				sshErr = err
				cancel()
			}
		}()
	} else {
		close(sshDone)
	}

	// The TLS-interception forward proxy (Task 100), when configured, shares the
	// gateway lifecycle like the SSH listener. It dispatches decrypted requests
	// back through this gateway's own handler tree (the same one the HTTP server
	// serves), so interception reuses the full middleware + admission pipeline.
	var interceptErr error
	interceptDone := make(chan struct{})
	if g.deps.Interceptor != nil {
		handler := g.routes()
		go func() {
			defer close(interceptDone)
			if err := g.deps.Interceptor.Run(ctx, g.opts.InterceptAddr, handler); err != nil {
				g.deps.Logger.Error("tls-intercept forward proxy stopped with error", "error", err)
				interceptErr = err
				cancel()
			}
		}()
	} else {
		close(interceptDone)
	}

	errCh := make(chan error, 1)
	tlsEnabled := g.opts.TLSCertFile != ""
	go func() {
		g.deps.Logger.Info("http gateway listening",
			"addr", g.opts.HTTPAddr,
			"tls", tlsEnabled,
			"backends", g.deps.Backends.Names())
		var err error
		if tlsEnabled {
			err = g.server.ListenAndServeTLS(g.opts.TLSCertFile, g.opts.TLSKeyFile)
		} else {
			err = g.server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		g.deps.Logger.Info("shutting down http gateway")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), g.opts.ShutdownTimeout)
		defer shutdownCancel()
		if err := g.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy: graceful shutdown failed: %w", err)
		}
		<-sshDone
		<-interceptDone
		if sshErr != nil {
			return sshErr
		}
		return interceptErr
	}
}

// handleBackend resolves the backend from the path prefix and serves the
// request through the cache (filling it transparently from upstream on a miss).
func (g *Gateway) handleBackend(w http.ResponseWriter, r *http.Request) {
	name, rest, ok := splitBackendPath(r.URL.Path)
	if !ok {
		http.Error(w, "missing backend in path; expected /v1/<backend>/...", http.StatusBadRequest)
		return
	}
	// A request that came in through a personal link (Task 177) has its links
	// to this backend's mount rewritten on the way out; tell the edge which
	// mount that is.
	notePersonalBackend(r.Context(), name)

	// What a backend serves is package content or an index of it — never a
	// page. In a browser it must not run as one on the proxy's origin, which is
	// also that of the admin console and of the personal-links page: a file
	// from a repository, served with its upstream's media type (text/html,
	// image/svg+xml), could otherwise act there with the user's session — and
	// create a link and read it. Package managers pay no attention to either
	// header.
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Meter the response for per-backend request-count and bytes-served metrics.
	mw := &meteredWriter{ResponseWriter: w, status: http.StatusOK}
	w = mw
	defer func() {
		g.metrics().IncRequest(name, r.Method, strconv.Itoa(mw.status))
		g.metrics().AddBytesServed(name, mw.bytes)
		// Account the request to its tenant for per-tenant usage/chargeback (Task 84).
		// Bytes-served (split by cache outcome) and storage footprint are metered at
		// the serve points below, where the cache status is known.
		g.meterRequest(r, name)
		// Add the request to the download log (Task 176) now that its outcome,
		// status and byte count are final. A no-op for anything that is not a
		// package download.
		g.recordDownload(r, mw)
	}()

	backend, found := g.deps.Backends.Get(name)
	if !found {
		http.Error(w, fmt.Sprintf("unknown backend %q", name), http.StatusNotFound)
		return
	}

	// A "." or ".." path segment never reaches a backend. No client sends one —
	// it arrives only in an encoded spelling, which the mux does not canonicalize
	// — and the upstream would resolve it into a different path than the one the
	// backend parsed, classified and gated: an endpoint the backend refuses to
	// forward (a registry's token endpoint), a payload under a path that reads as
	// an index. The request is sent upstream with the proxy's credentials, so
	// this is refused here, for every backend, rather than left to each one.
	if backends.HasDotSegment(rest) {
		http.Error(w, `invalid request path: "." and ".." segments are not accepted`, http.StatusBadRequest)
		return
	}

	// Some protocols (Git smart HTTP) cannot be expressed through Resolve/Fetch:
	// they negotiate over POST with a streaming body. Such backends implement
	// HTTPHandler and own the raw request, including method handling.
	if h, ok := backend.(backends.HTTPHandler); ok {
		// Such a backend never goes through Resolve, so the download log asks it
		// what the request is: a fetch of content, or protocol chatter.
		if d, ok := backend.(backends.DownloadDescriber); ok && g.deps.DownloadLog.Enabled() {
			if dl, ok := d.DescribeDownload(r, rest); ok {
				pullRecordFrom(r.Context()).describeDownload(name, g.ecosystemFor(name), dl)
				// A gate the backend runs itself (the Git backend's content gate
				// on LFS objects) reports its refusal through the request context:
				// it never passes gateTrace.
				ctx := r.Context()
				r = r.WithContext(backends.WithRefusalRecorder(ctx, func(gate string) { refused(ctx, gate) }))
			}
		}
		h.ServeBackendHTTP(w, r, rest)
		return
	}

	// A pull-through proxy serves idempotent reads only. Publishing/uploads are
	// out of scope for this core and handled (if at all) by specific backends.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := &backends.Request{
		Method: r.Method,
		Path:   rest,
		Query:  r.URL.Query(),
		Header: r.Header,
	}

	resolveCtx, resolveSpan := g.startSpan(r.Context(), "backend.resolve",
		tracing.String("pullthrough.backend", name))
	resolved, err := backend.Resolve(resolveCtx, req)
	if err != nil {
		resolveSpan.RecordError(err)
		resolveSpan.End()
		if errors.Is(err, backends.ErrNotSupported) {
			http.Error(w, "request not supported by backend", http.StatusNotImplemented)
			return
		}
		g.deps.Logger.Error("resolve failed", "backend", name, "path", rest, "error", err)
		http.Error(w, "failed to resolve upstream resource", http.StatusBadGateway)
		return
	}
	resolveSpan.SetAttributes(tracing.Bool("pullthrough.cacheable", resolved.Cacheable))
	resolveSpan.End()

	// From here on the request has a name: note what it resolved to, for the
	// download log and for the audit record of the pull.
	pullRecordFrom(r.Context()).describe(name, g.ecosystemFor(name), resolved)
	notePersonalResolved(r.Context(), resolved)

	// Enrich the request-level span with the resolved package coordinates so a
	// trace is searchable by what was actually pulled.
	tracing.SpanFromContext(r.Context()).SetAttributes(nonEmptyAttrs(
		tracing.StringIf("pullthrough.package.name", resolved.Coordinate.Name),
		tracing.StringIf("pullthrough.package.version", resolved.Coordinate.Version),
		tracing.StringIf("pullthrough.package.digest", resolved.Digest),
		tracing.StringIf("pullthrough.upstream.url", resolved.UpstreamURL),
	)...)

	// Partition the cache key by tenant when namespacing is enabled, so a
	// tenant cannot probe another's cache or have its content served from a
	// peer's namespace.
	if g.opts.CacheNamespacing && resolved.Cacheable {
		if p, ok := auth.FromContext(r.Context()); ok {
			resolved.CacheKey = p.Namespace() + "/" + resolved.CacheKey
		}
	}

	// Attach the per-request signal accumulator the policy-as-code engine
	// (Task 32) reads. Each gate below records its summary into it; the engine
	// runs last, over the aggregate. No-op when the engine is not configured.
	r = g.withAdmissionSignals(r, name, g.ecosystemFor(name), resolved)

	// Emergency lockdown / global kill-switch (Task 74) is consulted as the very
	// FIRST admission check, ahead of every other gate. A targeted `block` lockdown
	// denies a specific coordinate everywhere (the fast path for a freshly-disclosed
	// malicious package, ahead of the malfeed feed refresh) and composes with the
	// break-glass workflow; a `strict` lockdown is recorded as an incident signal the
	// aggregating policy/risk engines harden on; a `freeze` lockdown is enforced at
	// the upstream-fetch boundary (cache hits still serve). Recording the incident
	// signal first means every downstream gate and the findings export see it.
	g.recordLockdownSignal(r)
	if !g.gateTrace(r, "lockdown", func(rr *http.Request) bool {
		return g.gateLockdown(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Record the unified findings document (Task 42) on every exit path of the
	// gated pull — admitted or blocked — so a CI pipeline can retrieve the SARIF
	// findings that explain a block as readily as those on an admitted artifact.
	// The gates above record their signals into the accumulator before they return,
	// so the deferred capture sees whatever was computed up to the exit point.
	defer g.recordFindings(r)

	// Capture the admission document and its live verdict into the what-if replay
	// ring buffer (Task 47) on every exit path, so an operator can later replay
	// captured traffic through a candidate policy/risk configuration. Like the
	// findings capture above, it runs deferred so it sees the signals every gate
	// recorded up to the exit point. No-op when the recorder is absent/disabled.
	defer g.captureSimReplay(r)

	// Inspect the package name for typosquatting / dependency-confusion risk
	// (Task 19) before anything else: it needs no content and no version, so a
	// look-alike or namespace-shadowing name is refused at the earliest point,
	// before any upstream fetch or cache fill.
	if !g.gateTrace(r, "nameguard", func(rr *http.Request) bool {
		return g.gateNameguard(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Maintainer/publisher continuity monitoring (Task 91): right after the name
	// guard — and like it needing no artifact content — compare the coordinate's
	// current publisher identity (maintainer roster, namespace owner, signing-key
	// identity) against the durable trust-on-first-use known-maintainer set. A
	// previously-unseen maintainer/key/namespace on an already-known package raises
	// a maintainer_drift signal for the policy/risk/findings layers and, under a
	// block disposition, refuses the still-untrusted version (the account-takeover /
	// hijack precursor). It composes with the break-glass workflow.
	if !g.gateTrace(r, "continuity", func(rr *http.Request) bool {
		return g.gateContinuity(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Enforce the dependency firewall (Task 65) right after the name guard, before
	// any heavier scanning gate: resolve the concrete (ecosystem, name, version)
	// against the tenant's explicit version policy (pinned versions, allowed semver
	// ranges, minimum-version floors, denylists, or a deny-by-default lockfile
	// allowlist) and refuse a version outside the approved set before any upstream
	// fetch or cache fill. It composes with the break-glass workflow.
	if !g.gateTrace(r, "depfirewall", func(rr *http.Request) bool {
		return g.gateDepFirewall(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Organization freeze gate (Task 70): when the org is frozen to a point-in-time
	// snapshot, refuse any pull whose concrete (ecosystem, name, version) is outside
	// the frozen set, or whose served digest differs from the frozen one. It runs
	// right after the dependency firewall — both are coordinate-set gates needing no
	// content — and composes with the break-glass workflow. This is what makes an
	// instant rollback bite: pinning the org to the last-known-good snapshot forces
	// every client back to the previously-served safe digests and blocks the
	// newly-published malicious version.
	if !g.gateTrace(r, "snapshot", func(rr *http.Request) bool {
		return g.gateSnapshotFreeze(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Hard-block known-malicious coordinates (Task 48) immediately after the
	// name heuristics: this is an exact (ecosystem, name, version) match against
	// curated malware datasets, so a confirmed crypto-miner / credential-stealer /
	// backdoor is refused before any upstream fetch or cache fill, with the
	// advisory id and reason in the response.
	if !g.gateTrace(r, "malfeed", func(rr *http.Request) bool {
		return g.gateMalfeed(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Release-maturity / version-cooldown gate (Task 61): quarantine a version
	// published less than the configured cooldown window ago, derived from the
	// upstream registry's publish timestamp. It runs after the name and
	// known-malicious gates (a known-bad coordinate should be refused outright,
	// not merely held) and before policy, fails open on an unknown timestamp, and
	// composes with the break-glass workflow.
	if !g.gateTrace(r, "maturity", func(rr *http.Request) bool {
		return g.gateMaturity(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Apply the admission policy between resolution and retrieval, so a blocked
	// artifact never reaches the cache or upstream. A blocked decision has already
	// written the response.
	if !g.gateTrace(r, "policy", func(rr *http.Request) bool {
		return g.gatePolicy(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Behavioral anomaly soft-block gate (Task 43): if this identity's recent pull
	// traffic already tripped the anomaly detectors into a block standing, shed
	// further requests early with a 429 before serving more. The gate reads the
	// accumulated per-scope status (the soft-block is driven by prior
	// observations); observe-only and warn-only deployments never block here.
	if !g.gateTrace(r, "anomaly", func(rr *http.Request) bool {
		return g.gateAnomaly(w, rr, name, g.ecosystemFor(name))
	}) {
		return
	}

	if resolved.Cacheable {
		g.serveCacheable(w, r, name, backend, resolved)
		return
	}
	g.serveDirect(w, r, name, backend, resolved)
}

// serveCacheable serves a cacheable resource through the content cache. On a
// miss it fetches upstream exactly once (single-flight via the cache's
// GetOrLoad), streaming the bytes through to the store; it then serves the
// response streamed from the cache. Concurrent identical requests coalesce onto
// the one in-flight upstream fetch.
func (g *Gateway) serveCacheable(w http.ResponseWriter, r *http.Request, name string, backend backends.Backend, resolved *backends.Resolved) {
	ctx := r.Context()

	var (
		loaded  bool  // whether this request triggered the upstream fetch (cache miss)
		loadErr error // typed error from the loader, preserved through GetOrLoad
	)
	// The cache-fetch span covers the cache lookup and (on a miss) the upstream
	// fetch; the upstream fetch is its own client-kind child so the two are
	// distinguishable in the trace.
	cacheCtx, cacheSpan := g.startSpan(ctx, "cache.fetch",
		tracing.String("pullthrough.cache.key", resolved.CacheKey))

	loader := func(lctx context.Context) (io.Reader, map[string]string, error) {
		loaded = true
		// Emergency freeze lockdown (Task 74): the loader only runs on a cache miss,
		// which is exactly the upstream fetch a freeze must forbid. Refuse it here so a
		// freeze serves already-cached artifacts but never reaches out to an upstream.
		if g.lockdownBlocksFetch() {
			loadErr = lockdownFreezeError{}
			return nil, nil, loadErr
		}
		// Peer cache federation (Task 143): on a local miss, try a sibling proxy's
		// cache before reaching the upstream. A verified peer hit is streamed into
		// the local cache exactly like an upstream fetch — it still flows through
		// the fill-time digest verifier below and every post-fill admission gate —
		// so federation reduces egress without weakening any guarantee. Peer bytes
		// are additionally re-verified against the expected digest by the federation
		// layer itself. A peer miss or any peer error falls through to the upstream.
		if content, meta, ok := g.fetchFromPeer(lctx, resolved); ok {
			return content, meta, nil
		}
		_, fetchSpan := g.deps.Tracer.Start(cacheCtx, "upstream.fetch",
			tracing.WithSpanKind(tracing.SpanKindClient),
			tracing.WithAttributes(
				tracing.String("pullthrough.upstream.url", resolved.UpstreamURL),
				tracing.String("pullthrough.backend", name)))
		defer fetchSpan.End()
		start := time.Now()
		result, err := backend.Fetch(lctx, resolved)
		g.metrics().ObserveUpstreamLatency(name, time.Since(start).Seconds(), err == nil)
		if err != nil {
			fetchSpan.RecordError(err)
			loadErr = err
			return nil, nil, err
		}
		if result.NotModified || result.Content == nil {
			// A cold fill sets no validator, so 304/empty is an upstream protocol
			// violation rather than a real revalidation.
			loadErr = fmt.Errorf("proxy: upstream returned no content for %s", resolved.UpstreamURL)
			fetchSpan.RecordError(loadErr)
			return nil, nil, loadErr
		}
		if result.Size >= 0 {
			fetchSpan.SetAttributes(tracing.Int64("pullthrough.upstream.bytes", result.Size))
		}
		// Stream the body to the cache through a content-digest verifier when the
		// resolution stage knows the expected digest (Task 75). The hash is computed
		// incrementally as the store copies the body to its staging file, so the
		// body is never fully buffered in RAM; on EOF a mismatch is substituted for
		// the EOF, failing the cache Put before the entry is committed. A tampered or
		// truncated upstream response therefore cannot poison the cache. Verification
		// is opt-in: an empty or unsupported digest leaves the body unwrapped.
		content := result.Content
		if verifier, on := newDigestVerifier(content, resolved.Digest, func() {
			g.serve.digestMismatch.Add(1)
		}); on {
			content = verifier
		}
		return content, metadataForFetch(resolved, result), nil
	}

	// Coalesce concurrent misses for this artifact onto a single upstream fetch
	// and consult the negative cache (Task 36). The coalesce key encodes the
	// tenant/auth scope so a private artifact fetched with one tenant's
	// credentials is never shared with — or negatively cached against — another.
	// The leader fills the cache via GetOrLoad and serves its own stream; each
	// waiter re-opens an independent stream from the now-filled cache. When no
	// coalescer is wired, Do degrades to a direct GetOrLoad.
	coalKey := g.coalesceKey(r, resolved.CacheKey)
	entry, info, err := g.coalescer().Do(ctx, coalKey,
		func(fctx context.Context) (*cache.Entry, error) {
			return g.deps.Cache.GetOrLoad(fctx, resolved.CacheKey, loader)
		},
		func(fctx context.Context) (*cache.Entry, error) {
			return g.deps.Cache.Get(fctx, resolved.CacheKey)
		},
	)
	if err != nil {
		fetchErr := firstNonNil(loadErr, err)
		// A freeze lockdown refused the upstream fetch on this cache miss: render the
		// actionable freeze response rather than a generic upstream error.
		if _, frozen := fetchErr.(lockdownFreezeError); frozen {
			cacheSpan.End()
			pullRecordFrom(ctx).blockedBy("lockdown")
			writeLockdownFreezeError(w, r, g, name, g.ecosystemFor(name), resolved)
			return
		}
		cacheSpan.RecordError(fetchErr)
		cacheSpan.End()
		g.writeFetchError(w, r, name, resolved, fetchErr)
		return
	}
	defer entry.Content.Close()
	pullRecordFrom(ctx).setSize(entry.Stat.Size)

	// Record how the artifact was obtained and close the cache span before the
	// admission gates run (each gate is its own span). The same hit/miss is set
	// on the request-level span so a trace is filterable by cache outcome.
	cacheStatus := "HIT"
	switch {
	case loaded:
		cacheStatus = "MISS"
	case info.Coalesced:
		cacheStatus = "COALESCED-HIT"
	}
	cacheSpan.SetAttributes(tracing.String("pullthrough.cache.status", cacheStatus))
	cacheSpan.End()
	tracing.SpanFromContext(r.Context()).SetAttributes(tracing.String("pullthrough.cache.status", cacheStatus))

	// Signature/attestation gate (Task 23): verify cosign signatures and SLSA
	// provenance attestations before the bytes are served. A blocked or
	// quarantined artifact is refused here and evicted from the cache so an
	// unverified image/package is neither served nor retained.
	if !g.gateTrace(r, "sigverify", func(rr *http.Request) bool {
		return g.gateSigverify(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Inbound build-provenance gate (Task 72): fetch the upstream-published build
	// provenance (npm provenance / GitHub artifact attestation), cryptographically
	// bind the package version to its source repo + commit + CI workflow, and
	// cross-check that proven commit against the package-to-commit association the
	// provenance subsystem reported. It runs right after the signature gate (both
	// establish source authenticity) and folds its signals into the admission
	// accumulator. Non-blocking in observe mode; in enforce mode a confirmed source
	// mismatch is refused here.
	if !g.gateTrace(r, "buildprov", func(rr *http.Request) bool {
		return g.gateBuildProv(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Reproducible-build verification gate (Task 68): for an artifact already mapped
	// to a source commit, asynchronously rebuild it from source (via a sandboxed,
	// air-gap-aware builder) and compare digests. It runs right after the signature
	// gate (both establish artifact authenticity/integrity) and folds its verdict
	// into the admission accumulator for the policy/risk gates below. Non-blocking by
	// default; in enforce mode a confirmed mismatch is refused here.
	if !g.gateTrace(r, "rebuildverify", func(rr *http.Request) bool {
		return g.gateRebuildVerify(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Inbound PyPI PEP 740 digital-attestation gate (Task 146): for a served
	// pip/PyPI distribution, fetch and verify the publisher's PEP 740 attestations
	// and bind the attested sha256 digest to the served artifact. It runs alongside
	// the signature / build-provenance gates (all establish artifact authenticity)
	// and folds its verdict into the admission accumulator. Per its configured
	// action it annotates, downgrades, or — on a digest mismatch — blocks here.
	if !g.gateTrace(r, "pypiattest", func(rr *http.Request) bool {
		return g.gatePyPIAttest(w, rr, name, g.ecosystemFor(name), resolved)
	}) {
		return
	}

	// Terraform/OpenTofu providers verify their SHASUMS signature and per-ZIP
	// SHA-256 inside the backend (Task 53); fold that verification status into the
	// admission signal accumulator so the policy and risk gates below see it.
	g.recordTerraformSignature(r.Context(), resolved, entry)

	// Vulnerability gate (Task 15): the artifact is now in the cache, so its SBOM
	// can be generated and resolved against the vulnerability database. A blocked or
	// quarantined artifact is refused here, before its bytes are streamed to the
	// client (a quarantine additionally evicts it from the cache).
	if !g.gateTrace(r, "vulnscan", func(rr *http.Request) bool {
		return g.gateVulnerabilities(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// License-compliance gate (Task 28): evaluate the artifact's SPDX license
	// (reusing the SBOM the vulnerability gate just generated, or extracting it on
	// demand) against the allow/deny/review policy. A denied license is refused
	// here before its bytes are served (a quarantine additionally evicts it).
	if !g.gateTrace(r, "license", func(rr *http.Request) bool {
		return g.gateLicense(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Install-script / lifecycle-hook risk gate (Task 62): statically extract the
	// package's install hooks from the cached archive and score them against the
	// deterministic high-risk pattern set. It runs after the content gates (it
	// needs the artifact bytes) and before the policy/risk gates so its signal
	// feeds them; a finding meeting the tenant threshold blocks (and evicts) here.
	// SBOM diff & dependency-drift gate (Task 64): reduce the SBOM the
	// vulnerability/license gates produced (plus the scan's vulnerabilities) to a
	// per-version snapshot, record it in the bounded per-coordinate history, and
	// diff the new version against the prior one. Its drift score feeds the
	// policy/risk gates and, when configured to enforce, can block/quarantine a
	// quiet package that suddenly grows a large or suspicious dependency footprint.
	if !g.gateTrace(r, "sbomdiff", func(rr *http.Request) bool {
		return g.gateSbomDiff(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	if !g.gateTrace(r, "installhooks", func(rr *http.Request) bool {
		return g.gateInstallHooks(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Package-payload static content-analysis gate (Task 138): unpack the cached
	// source artifact (npm tarball, pip sdist/wheel, gem/composer/cargo/nuget
	// archive) and apply deterministic heuristics to its files — embedded native
	// binaries, high-entropy/packed blobs, obfuscated JavaScript, dynamic
	// code-execution sinks, and in-source secrets (reusing the Task 29 detectors)
	// — never executing anything. It runs alongside the other content gates (it
	// needs the artifact bytes, already in the cache) and before the policy/risk
	// gates so its per-file findings feed them; a finding meeting the fail
	// threshold blocks (and evicts) here under the block action.
	if !g.gateTrace(r, "contentscan", func(rr *http.Request) bool {
		return g.gateContentScan(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// ML model weight-scanning gate (Task 110): for a Hugging Face pull, statically
	// disassemble a pickle-based weight file's opcode stream and refuse (and
	// quarantine) one carrying an unsafe import invoked via __reduce__ — the
	// malicious-model code-execution vector — never unpickling anything. It runs
	// alongside the other content gates and before the policy/risk gates so its
	// signal feeds them; safetensors is recognized as the safe format.
	if !g.gateTrace(r, "mlguard", func(rr *http.Request) bool {
		return g.gateMLGuard(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Antivirus content-scanning gate (Task 136): stream the cached artifact's
	// bytes through the configured AV engine (ClamAV via clamd INSTREAM) and, on a
	// positive byte-level malware detection, annotate / quarantine (refuse + evict)
	// / block the artifact per policy. It runs alongside the other content gates
	// (it needs the artifact bytes, already in the cache) and before the policy/
	// risk gates so its signal feeds them; it degrades gracefully (fail-open or
	// fail-closed per config) when the engine is unreachable.
	if !g.gateTrace(r, "avscan", func(rr *http.Request) bool {
		return g.gateAVScan(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Sandboxed LLM package-content scan gate (Task 173): have a language model
	// read the unpacked package (bounded read-only tools or a prioritized bundle;
	// nothing is executed) and return a malicious / suspicious / benign verdict,
	// cached by artifact digest so a cache hit consults the stored verdict instead
	// of scanning again. It is deliberately the last content gate: the
	// deterministic ones above are cheap and anything they refuse never costs a
	// model call. It still runs before the policy/risk gates, which consume its
	// signal, and before the first byte is served. A malicious verdict under the
	// block or quarantine action is refused here with the standard policy headers
	// and the artifact is evicted; an artifact that could not be scanned follows
	// the configured fail mode and is never treated as clean.
	if !g.gateTrace(r, "llmpkgscan", func(rr *http.Request) bool {
		return g.gateLLMPkgScan(w, rr, name, g.ecosystemFor(name), resolved, entry)
	}) {
		return
	}

	// Source-repository health provider (Task 63): derive OpenSSF Scorecard-style
	// health signals for the repository this artifact was built from (from the
	// provenance association above) and fold them into the admission accumulator so
	// the policy and risk gates can key on them. It is a signal provider, not a
	// gate — it never blocks — so it is invoked directly rather than via gateTrace.
	g.gateRepoScore(w, r, name, g.ecosystemFor(name))

	// Policy-as-code gate (Task 32): the final aggregating decision over every
	// signal the gates above recorded for this request. A deny is refused here
	// before the bytes are served.
	if !g.gateTrace(r, "policyengine", func(rr *http.Request) bool {
		return g.gatePolicyEngine(w, rr, name, g.ecosystemFor(name))
	}) {
		return
	}

	// Unified risk-scoring gate (Task 37): fold every gate signal into one
	// composite, explainable score and band, recorded for trend visibility and
	// metrics. When an admission threshold is configured it may warn on or block
	// the artifact here; otherwise it is observe-only.
	if !g.gateTrace(r, "riskscore", func(rr *http.Request) bool {
		return g.gateRiskScore(w, rr, name, g.ecosystemFor(name))
	}) {
		return
	}

	// WASM extensibility gate (Task 59): the final, operator-extensible admission
	// stage. It runs the tenant's sandboxed wasm modules over the same aggregated
	// signals (plus the risk score) and may warn on or block the artifact here.
	if !g.gateTrace(r, "extension", func(rr *http.Request) bool {
		return g.gateExtension(w, rr, name, g.ecosystemFor(name))
	}) {
		return
	}

	// The artifact is admitted: fold what we learned about it (provenance,
	// dependencies, vulnerabilities, signatures) into the supply-chain graph
	// (Task 33). Best-effort and after admission, so it never affects serving.
	g.ingestProvGraph(r, g.ecosystemFor(name), resolved)

	// Issue the proxy's outbound supply-chain attestation for the admitted
	// artifact (Task 46): a signed in-toto/SLSA statement binding the served digest
	// to its source commit, the verdicts it passed, and the proxy identity, with
	// its bundle digest embedded in the audit log. Best-effort and after admission,
	// so it never affects serving.
	g.recordAttestation(r, name, g.ecosystemFor(name))

	// Fold the served coordinate's resolved state (digest, source commit, verdict,
	// risk band, attestation-bundle digest) into the organization snapshot live
	// state (Task 70), from which point-in-time snapshots are captured on demand or
	// on a schedule. Best-effort and after admission, so it never affects serving.
	g.recordSnapshot(r, name, g.ecosystemFor(name))

	// X-Cache reflects how the artifact was obtained (computed above): MISS when
	// this request ran the upstream fetch, COALESCED-HIT when it joined another
	// in-flight fetch, and HIT when it came straight from the cache.
	g.serveEntry(w, r, entry, cacheStatus)

	// Account the served bytes to the tenant, split by whether they came from the
	// cache or required an upstream fetch, and (on a miss) the storage footprint the
	// tenant caused by filling the cache (Task 84).
	g.meterTraffic(r, entry.Stat.Size, cacheStatus != "MISS")
	if cacheStatus == "MISS" {
		g.meterStorage(r, entry.Stat.Size)
	}

	// Fold the successful pull into the behavioral anomaly detectors (Task 43):
	// the artifact coordinate feeds distinct-package fan-out and new-namespace
	// detection, and the served size feeds the egress-volume baseline.
	g.observeAnomaly(r, name, g.ecosystemFor(name), resolved, entry.Stat.Size, false)

	// Report the served pull to the predictive cache pre-warming subsystem (Task
	// 134), which learns historical pull patterns and attributes this hit to a
	// prior pre-warm when applicable. Best-effort; never affects serving. The
	// subsystem's own synthetic pre-warm fetches are excluded inside observePull.
	g.observePull(r, name, resolved, cacheStatus, entry.Stat.Size)
}

// serveDirect serves a non-cacheable resource (e.g. a mutable index document)
// by streaming it live from upstream. It forwards the client's If-None-Match so
// the upstream can answer 304, saving bandwidth, which is relayed to the client.
func (g *Gateway) serveDirect(w http.ResponseWriter, r *http.Request, name string, backend backends.Backend, resolved *backends.Resolved) {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		resolved.IfNoneMatch = inm
	}

	start := time.Now()
	result, err := backend.Fetch(r.Context(), resolved)
	g.metrics().ObserveUpstreamLatency(name, time.Since(start).Seconds(), err == nil)
	if err != nil {
		g.writeFetchError(w, r, name, resolved, err)
		return
	}
	if result.NotModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if result.Content == nil {
		http.Error(w, "upstream returned no content", http.StatusBadGateway)
		return
	}
	defer result.Content.Close()

	// Sandboxed LLM package-content scan gate (Tasks 173, 174) on the response
	// that is not cached. A resource a backend does not cache is not thereby
	// harmless — a snapshot jar, an image manifest pulled by tag, a script on a
	// moving branch, an installer on a path the adapter does not know — and a
	// gate that only saw cached artifacts would have a hole exactly that shape.
	// The first bytes decide whether there is anything to examine; if there is,
	// the response is held until the verdict exists and only then written.
	body, ok := g.gateTraceDirect(w, r, name, resolved, result)
	if !ok {
		return
	}
	defer body.cleanup()
	pullRecordFrom(r.Context()).setSize(body.size)

	h := w.Header()
	if result.Header != nil {
		upstream.PropagateResponseHeaders(h, result.Header)
	}
	if result.MediaType != "" {
		h.Set("Content-Type", result.MediaType)
	}
	if body.size >= 0 {
		h.Set("Content-Length", strconv.FormatInt(body.size, 10))
	}
	if etag := result.Header.Get("ETag"); etag != "" {
		h.Set("ETag", etag)
	}
	h.Set("X-Cache", "BYPASS")

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	n, err := io.Copy(w, body.content)
	if err != nil {
		g.deps.Logger.Warn("streaming upstream response failed",
			"backend", name, "upstream", resolved.UpstreamURL, "error", err)
	}
	// A non-cacheable resource is always streamed live from upstream (Task 84).
	g.meterTraffic(r, n, false)
}

// gateTraceDirect runs the LLM package-scan gate on a non-cacheable response
// under a gate span, like gateTrace does for the cached path.
func (g *Gateway) gateTraceDirect(w http.ResponseWriter, r *http.Request, name string, resolved *backends.Resolved, result *backends.FetchResult) (directBody, bool) {
	var body directBody
	ok := g.gateTrace(r, "llmpkgscan", func(rr *http.Request) bool {
		var allowed bool
		body, allowed = g.gateLLMPkgScanDirect(w, rr, name, g.ecosystemFor(name), resolved, result.Content, result.Size)
		return allowed
	})
	return body, ok
}

// serveEntry writes a cache entry to the client, applying conditional-request
// handling (If-None-Match / If-Modified-Since) so unchanged resources return
// 304 Not Modified, and honoring HTTP Range requests (RFC 7233) so large
// artifacts can be fetched in resumable/parallel byte ranges (Task 75).
//
// When the cached content stream supports random access (the filesystem store
// hands back an *os.File), range handling is delegated to http.ServeContent,
// which emits 206 Partial Content with a correct Content-Range on a satisfiable
// range, 416 on an unsatisfiable one, honors If-Range, and advertises
// Accept-Ranges. When the stream is forward-only (e.g. an object-storage body)
// and a range is requested, the body is spooled to a temp file to obtain random
// access — a bounded-memory "spill to disk" the caller is metered on. A plain
// (non-range) request always streams straight through with bounded memory.
func (g *Gateway) serveEntry(w http.ResponseWriter, r *http.Request, entry *cache.Entry, cacheStatus string) {
	etag := entry.Stat.Metadata[cache.MetaETag]
	if etag == "" {
		etag = deriveETag(entry.Stat)
	}

	h := w.Header()
	h.Set("ETag", etag)
	h.Set("X-Cache", cacheStatus)
	if ct := entry.Stat.Metadata[cache.MetaContentType]; ct != "" {
		h.Set("Content-Type", ct)
	}
	if !entry.Stat.ModTime.IsZero() {
		h.Set("Last-Modified", entry.Stat.ModTime.UTC().Format(http.TimeFormat))
	}
	// Advertise byte-range support so clients (Docker, package managers, download
	// managers) know they may request partial content and resume interrupted
	// transfers against this content-addressable, immutable artifact.
	h.Set("Accept-Ranges", "bytes")

	// Replay the response headers the backend declared part of this artifact's
	// protocol contract (backends.SetResponseHeader). They were persisted with the
	// entry, so a cache hit carries them exactly like the original fetch did.
	// Headers the proxy computes itself, and hop-by-hop headers, are never taken
	// from the cache.
	if declared := backends.ResponseHeaders(entry.Stat.Metadata); len(declared) > 0 {
		replay := make(http.Header, len(declared))
		for name, value := range declared {
			replay.Set(name, value)
		}
		upstream.PropagateResponseHeaders(h, replay)
	}

	if etagMatches(r.Header.Get("If-None-Match"), etag) ||
		notModifiedSince(r.Header.Get("If-Modified-Since"), entry.Stat.ModTime) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	hasRange := r.Header.Get("Range") != ""
	if hasRange {
		g.serve.rangeRequests.Add(1)
	}

	// Obtain a seekable view of the content so ServeContent can satisfy ranges.
	rs, seekable := entry.Content.(io.ReadSeeker)
	if !seekable {
		if !hasRange {
			// No range requested: stream straight through with bounded memory; the
			// forward-only body needs no random access and no spill.
			g.streamFull(w, r, entry)
			return
		}
		// A range was requested but the body is forward-only. Spill it to a temp
		// file to gain random access, counting the event. This keeps memory bounded
		// (the copy goes to disk, not RAM) at the cost of one extra disk pass.
		spooled, cleanup, err := spoolToTemp(entry.Content)
		if err != nil {
			g.deps.Logger.Warn("range spill-to-disk failed; serving full body",
				"key", entry.Stat.Key, "error", err)
			g.streamFull(w, r, entry)
			return
		}
		defer cleanup()
		g.serve.spillToDisk.Add(1)
		rs = spooled
	}

	// Delegate RFC 7233 range handling to the standard library: 206 + Content-Range
	// on a satisfiable range, 416 on an unsatisfiable one, 200 on a full body or an
	// If-Range validator mismatch. The name argument is empty because Content-Type
	// is already set (from cached metadata) when known. We must not pre-set
	// Content-Length here: ServeContent computes it from the (possibly partial)
	// range it serves.
	sc := &statusCapture{ResponseWriter: w}
	http.ServeContent(sc, r, "", entry.Stat.ModTime, rs)
	switch sc.status {
	case http.StatusPartialContent:
		g.serve.partialServed.Add(1)
	case http.StatusRequestedRangeNotSatisfiable:
		g.serve.unsatisfiable.Add(1)
	}
	g.serve.streamedBytes.Add(sc.bytes)
}

// streamFull writes the entire entry body as a 200 OK with bounded memory. It is
// the path for plain (non-range) requests and for the rare case where a
// forward-only body cannot be spilled to disk to satisfy a range.
func (g *Gateway) streamFull(w http.ResponseWriter, r *http.Request, entry *cache.Entry) {
	w.Header().Set("Content-Length", strconv.FormatInt(entry.Stat.Size, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	n, err := io.Copy(w, entry.Content)
	g.serve.streamedBytes.Add(n)
	if err != nil {
		// The client likely disconnected mid-stream; the cache entry is intact.
		g.deps.Logger.Debug("streaming cache entry to client failed", "error", err)
	}
}

// writeFetchError maps a fetch/load failure onto an appropriate client status:
// an upstream StatusError is relayed with its status (and, for a redirect, the
// mount-mapped Location the backend supplied); the cancellation of this
// request is silent; the cancellation of a fetch this request merely shared is
// a retryable 503; everything else is a 502 Bad Gateway.
func (g *Gateway) writeFetchError(w http.ResponseWriter, r *http.Request, name string, resolved *backends.Resolved, err error) {
	if errors.Is(r.Context().Err(), context.Canceled) {
		return // this request's client went away; there is no one to answer
	}
	if errors.Is(err, context.Canceled) {
		// The fetch was cancelled, but not by this request: its client is still
		// here. Concurrent requests for one artifact share a single upstream
		// fetch, which runs on behalf of the request that started it; when that
		// request's client hangs up, the fetch ends for everyone who was waiting
		// on it. Returning without a word — right for a client that left — would
		// have the server answer this one with an empty "200 OK": an empty
		// artifact under a success status. Say what happened instead. The
		// request is safe to repeat, and the repeat starts a fetch of its own.
		w.Header().Set("Retry-After", "1")
		http.Error(w, "the upstream fetch this request was waiting for was interrupted; retry", http.StatusServiceUnavailable)
		return
	}
	if errors.Is(err, coalesce.ErrOverloaded) {
		// Too many distinct upstream fetches are already in flight; shed load with
		// a retryable status rather than spawning another origin request.
		w.Header().Set("Retry-After", "1")
		http.Error(w, "upstream fetch capacity exceeded, retry shortly", http.StatusServiceUnavailable)
		return
	}
	if se, ok := backends.AsStatusError(err); ok {
		// A 404/410 is the signature of a name-enumeration sweep; feed it to the
		// anomaly detectors (Task 43) so a burst of negative lookups from one
		// identity is flagged even though no artifact was ever served.
		if se.Status == http.StatusNotFound || se.Status == http.StatusGone {
			g.observeAnomaly(r, name, g.ecosystemFor(name), resolved, 0, true)
		}
		// An upstream redirect the proxy did not follow is relayed with the target
		// the backend mapped onto its own mount, so the client can follow it back
		// through the proxy. Without one the bare status is relayed, as before.
		if se.Location != "" && se.Status >= 300 && se.Status < 400 {
			w.Header().Set("Location", se.Location)
		}
		http.Error(w, fmt.Sprintf("upstream returned status %d", se.Status), se.Status)
		return
	}
	g.deps.Logger.Error("upstream fetch failed",
		"backend", name, "upstream", resolved.UpstreamURL, "error", err)
	http.Error(w, "upstream fetch failed", http.StatusBadGateway)
}

// metadataForFetch builds the cache metadata to persist alongside the fetched
// content, promoting the well-known origin/content-type/etag keys.
func metadataForFetch(resolved *backends.Resolved, result *backends.FetchResult) map[string]string {
	meta := make(map[string]string, len(resolved.Metadata)+3)
	for k, v := range resolved.Metadata {
		meta[k] = v
	}
	meta[cache.MetaOrigin] = resolved.UpstreamURL
	if ct := result.MediaType; ct != "" {
		meta[cache.MetaContentType] = ct
	}
	if result.Header != nil {
		if etag := result.Header.Get("ETag"); etag != "" {
			meta[cache.MetaETag] = etag
		}
		// The verification headers a backend attaches to a fetched artifact
		// describe the content itself (which digest or signature the proxy checked
		// before admitting it), so they are as true on a cache hit as on the fetch
		// that produced them. Persist them with the entry; serveEntry replays them.
		// Without this they were set on the fetch result and then dropped, because
		// a cacheable artifact is always served from its cache entry.
		for _, name := range verificationResponseHeaders {
			backends.SetResponseHeader(meta, name, result.Header.Get(name))
		}
	}
	return meta
}

// verificationResponseHeaders are the proxy-generated response headers that
// report how an artifact was verified. They are a property of the content, not
// of one upstream response, so they are persisted with the cache entry (see
// metadataForFetch). Arbitrary upstream headers are deliberately not: replaying
// a Date, an Age or a Set-Cookie for as long as an artifact stays cached would be
// wrong. A backend that needs another header to survive caching declares it
// explicitly with backends.SetResponseHeader.
var verificationResponseHeaders = []string{
	"X-Checksum-Verified",
	"X-Content-Hash-Verified",
	"X-Tree-Hash-Verified",
	"X-Signature-Verified",
	"X-Repository-Signature",
	"X-Terraform-Signature",
}

// deriveETag synthesizes a stable validator for a cache entry whose upstream
// supplied no ETag. It is derived from the (content-addressable) cache key and
// size, so it is stable for an immutable artifact and marked weak because it is
// not a direct hash of the served bytes.
func deriveETag(stat cache.Stat) string {
	sum := sha256.Sum256([]byte(stat.Key))
	return fmt.Sprintf("W/%q", hex.EncodeToString(sum[:8])+"-"+strconv.FormatInt(stat.Size, 10))
}

// etagMatches implements If-None-Match comparison (RFC 7232 §3.2) using weak
// comparison: a list of validators (or "*") matches when any opaque tag equals
// the entry's, ignoring an optional weak ("W/") prefix.
func etagMatches(ifNoneMatch, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "" || etag == "" {
		return false
	}
	if ifNoneMatch == "*" {
		return true
	}
	target := opaqueTag(etag)
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if opaqueTag(strings.TrimSpace(candidate)) == target {
			return true
		}
	}
	return false
}

// opaqueTag strips an optional weak prefix from an entity tag for weak
// comparison.
func opaqueTag(tag string) string {
	return strings.TrimPrefix(tag, "W/")
}

// notModifiedSince reports whether the entry's modification time is not newer
// than the client's If-Modified-Since timestamp.
func notModifiedSince(ifModifiedSince string, modTime time.Time) bool {
	ifModifiedSince = strings.TrimSpace(ifModifiedSince)
	if ifModifiedSince == "" || modTime.IsZero() {
		return false
	}
	since, err := http.ParseTime(ifModifiedSince)
	if err != nil {
		return false
	}
	// Truncate to second precision: HTTP dates carry no sub-second component.
	return !modTime.Truncate(time.Second).After(since)
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleReady reports readiness, requiring at least one backend to be
// registered.
func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
	if g.deps.Backends.Len() == 0 {
		http.Error(w, "no backends registered", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

// splitBackendPath extracts the backend name and remaining path from a URL of
// the form "/v1/<backend>/<rest>".
func splitBackendPath(p string) (name, rest string, ok bool) {
	trimmed := strings.TrimPrefix(p, "/v1/")
	if trimmed == p { // prefix was absent
		return "", "", false
	}
	name, rest, found := strings.Cut(trimmed, "/")
	if name == "" {
		return "", "", false
	}
	if !found {
		rest = ""
	}
	return name, "/" + rest, true
}

// withTracing is the outermost middleware on the /v1 client path. It extracts
// any inbound W3C trace context, starts the request-level (server) span, and
// stores it as the enrichable active span so downstream handlers (auth, resolve,
// the admission gates) can attach attributes to it. Child spans for each stage
// parent from this one, giving operators the full latency breakdown of a pull.
// A nil Tracer makes this a transparent pass-through.
func (g *Gateway) withTracing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.deps.Tracer == nil {
			next.ServeHTTP(w, r)
			return
		}
		// Continue an inbound distributed trace when the client propagated one.
		ctx := tracing.Extract(r.Context(), tracing.HeaderCarrier(r.Header))
		name, _, _ := splitBackendPath(r.URL.Path)
		ctx, span := g.deps.Tracer.Start(ctx, "pull "+name,
			tracing.WithSpanKind(tracing.SpanKindServer),
			tracing.WithAttributes(
				tracing.String("http.request.method", r.Method),
				tracing.String("url.path", r.URL.Path),
				tracing.String("pullthrough.backend", name),
				tracing.String("pullthrough.ecosystem", g.ecosystemFor(name)),
				tracing.String("network.peer.address", clientIP(r)),
			))
		defer span.End()
		ctx = tracing.ContextWithSpan(ctx, span)

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))

		span.SetAttributes(tracing.Int("http.response.status_code", sw.status))
		if sw.status >= http.StatusInternalServerError {
			span.SetStatus(tracing.StatusError, http.StatusText(sw.status))
		} else {
			span.SetStatus(tracing.StatusOK, "")
		}
	})
}

// nonEmptyAttrs drops attributes with an empty key (produced by
// tracing.StringIf for absent optional values) so the request-level span is not
// seeded with blank coordinate attributes.
func nonEmptyAttrs(attrs ...tracing.Attr) []tracing.Attr {
	out := attrs[:0]
	for _, a := range attrs {
		if a.Key != "" {
			out = append(out, a)
		}
	}
	return out
}

// startSpan starts a child span from ctx, seeded with attrs. It is a thin,
// nil-safe wrapper over the tracer so call sites need no nil checks (a nil
// Tracer returns ctx unchanged and a nil *Span).
func (g *Gateway) startSpan(ctx context.Context, name string, attrs ...tracing.Attr) (context.Context, *tracing.Span) {
	return g.deps.Tracer.Start(ctx, name, tracing.WithAttributes(attrs...))
}

// gateTrace runs a named admission gate under a child span, threading the span
// context into the request so the gate's audit/notify entries correlate to it,
// and records the gate's allow/deny verdict as a span attribute. It returns the
// gate's result unchanged. With tracing disabled it simply invokes fn(r).
func (g *Gateway) gateTrace(r *http.Request, gate string, fn func(*http.Request) bool) bool {
	if g.deps.Tracer == nil {
		allowed := fn(r)
		if !allowed {
			// Attribute the refusal to its tenant/gate for per-tenant usage (Task 84).
			g.meterBlock(r, gate)
			// And name the refusing gate in the download log (Task 176).
			noteRefusal(r, gate)
		}
		return allowed
	}
	ctx, span := g.deps.Tracer.Start(r.Context(), "gate."+gate)
	defer span.End()
	allowed := fn(r.WithContext(ctx))
	span.SetAttributes(
		tracing.String("pullthrough.gate", gate),
		tracing.Bool("pullthrough.gate.allowed", allowed),
	)
	if !allowed {
		span.SetStatus(tracing.StatusError, "blocked")
		g.meterBlock(r, gate)
		noteRefusal(r, gate)
	}
	return allowed
}

// withRequestLogging wraps a handler with structured access logging.
func (g *Gateway) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		g.deps.Logger.Debug("request",
			"method", r.Method,
			// A personal link's token is part of the path and is a credential:
			// it is not written into the log.
			"path", redactPersonalPath(r.URL.Path, g.deps.UserLinks.PathPrefix()),
			"status", sw.status,
			"duration", time.Since(start))
	})
}

// statusWriter captures the response status code for logging.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer's Flusher so streaming responses
// (e.g. the admin SecOps server-sent-event feed) can push data incrementally
// through this logging wrapper. It is a no-op if the underlying writer does not
// support flushing.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
