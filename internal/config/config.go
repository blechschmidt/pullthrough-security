// Package config defines the proxy's configuration schema and loads it from a
// YAML file with environment-variable overrides. Secrets (credentials, API
// keys) may be supplied inline, via ${ENV_VAR} references, or via dedicated
// environment variables so they need not be committed to disk.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/fips"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/secrets"
	"github.com/blechschmidt/pullthrough-security/internal/siem"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/tlspin"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration document.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Cache    CacheConfig    `yaml:"cache"`
	Outbound OutboundConfig `yaml:"outbound"`
	// Egress configures the SSRF / outbound-egress guard (Task 89): a transport-
	// level defense-in-depth control on every upstream fetch that enforces a
	// scheme allowlist (https-only by default), an optional per-instance/per-tenant
	// host/domain/CIDR allowlist, denial of any request resolving to a private/
	// link-local/loopback/unique-local/CGNAT/metadata IP range (re-validated before
	// connect to defeat DNS-rebinding), and a redirect policy re-checking every hop
	// under a max-redirect cap. On by default with secure defaults.
	Egress     EgressConfig              `yaml:"egress"`
	Upstreams  map[string]UpstreamConfig `yaml:"upstreams"`
	Git        GitConfig                 `yaml:"git"`
	Scanning   ScanningConfig            `yaml:"scanning"`
	Provenance ProvenanceConfig          `yaml:"provenance"`
	// Provgraph configures the supply-chain provenance & dependency graph store
	// (Task 33): an in-memory graph built from package pulls, provenance links,
	// SBOM components, CVE findings, and signature status, queried for blast
	// radius / reverse dependencies / path-to-commit and visualized in the admin
	// UI. It is read-only and cheap, so it is enabled by default.
	Provgraph ProvgraphConfig `yaml:"provgraph"`
	Policy    PolicyConfig    `yaml:"policy"`
	// PolicyEngine configures the declarative policy-as-code admission engine
	// (Task 32): externally-authored CEL-subset rule bundles evaluated against an
	// aggregated admission input document, layered on top of the hard-coded Policy
	// gate so operators can express composite rules without recompiling.
	PolicyEngine PolicyEngineConfig `yaml:"policyEngine"`
	// Vulnerabilities configures SBOM generation and the OSV/Trivy/Grype
	// vulnerability-scanning admission gate (Task 15).
	Vulnerabilities VulnConfig `yaml:"vulnerabilities"`
	// License configures the license-compliance admission gate (Task 28): it
	// reuses the SBOM the vulnerability subsystem generates to evaluate each
	// artifact's SPDX license against an allow/deny/review policy.
	License LicenseConfig `yaml:"license"`
	// Nameguard configures typosquatting and dependency-confusion detection on
	// package coordinates at pull time (Task 19).
	Nameguard NameguardConfig `yaml:"nameguard"`
	// Malfeed configures the known-malicious-package admission gate (Task 48): it
	// ingests curated malware datasets (OpenSSF/OSV malicious-packages and GitHub
	// Advisory malware entries) and hard-blocks pulls of concrete coordinates
	// listed as actively malicious.
	Malfeed MalfeedConfig `yaml:"malfeed"`
	// Maturity configures the release-maturity / version-cooldown admission gate
	// (Task 61): it quarantines newly-published package versions until they age
	// past a configurable cooldown window, a control against fast-moving
	// supply-chain attacks where a malicious version is yanked within hours.
	Maturity MaturityConfig `yaml:"maturity"`
	// Continuity configures the maintainer/publisher continuity monitoring gate
	// (Task 91): a trust-on-first-use ownership-change gate that flags a new
	// maintainer, rotated signing key, or new namespace owner appearing for an
	// already-known package — the account-takeover / hijack precursor.
	Continuity ContinuityConfig `yaml:"continuity"`
	// DepFirewall configures the dependency-firewall version-pinning & allowlist
	// enforcement gate (Task 65): per-tenant rules (pinned exact versions, allowed
	// semver ranges, minimum-version floors, explicit denylists) keyed by
	// (ecosystem, coordinate), optionally imported wholesale from a lockfile, so CI
	// can only fetch operator-approved versions.
	DepFirewall DepFirewallConfig `yaml:"depfirewall"`
	// InstallHooks configures the install-script / lifecycle-hook risk-analysis
	// gate (Task 62): it statically extracts a package's automatically-run install
	// hooks (npm pre/post-install, Python setup.py / pyproject build hooks, RubyGems
	// native extensions + post-install message, Cargo build.rs) and blocks/warns on
	// deterministic high-risk patterns without executing anything.
	InstallHooks InstallHooksConfig `yaml:"installHooks"`
	// MLGuard configures the ML model weight-scanning gate (Task 110): for a
	// Hugging Face model/dataset pull it statically disassembles a pickle-based
	// weight file (.bin/.pkl/.pt/.pth/.ckpt) and blocks/warns on imports of
	// code-execution / network / filesystem primitives invoked via __reduce__ — the
	// malicious-model attack vector — while recognizing and preferring safetensors.
	MLGuard MLGuardConfig `yaml:"mlGuard"`
	// AVScan configures the antivirus content-scanning gate (Task 136): it streams
	// a fetched artifact's payload (archives, wheels, jars, container layer blobs,
	// ML weights, LFS objects) through a configurable AV engine — primarily ClamAV
	// over the clamd INSTREAM protocol — and annotates/quarantines/blocks the
	// artifact on a positive byte-level malware detection.
	AVScan AVScanConfig `yaml:"avScan"`
	// ContentScan configures the package-payload static content-analysis gate
	// (Task 138): it unpacks a cached source artifact (npm tarball, pip
	// sdist/wheel, gem/composer/cargo/nuget archive) and applies deterministic
	// heuristics to its files — high-entropy/packed blobs, embedded native
	// binaries, obfuscated JavaScript, dynamic code-execution sinks, and in-source
	// secrets — never executing anything.
	ContentScan ContentScanConfig `yaml:"contentScan"`
	// LLMPackageScan configures the sandboxed LLM package-content scan gate (Task
	// 173): a language model reviews the unpacked contents of a downloaded package
	// — through read-only tools over an in-memory tree, executing nothing — and
	// returns a malicious/suspicious/benign verdict before the artifact is served.
	// The verdict is cached per artifact sha256 digest + model + prompt version.
	LLMPackageScan LLMPackageScanConfig `yaml:"llmPackageScan"`
	// Sigverify configures cryptographic signature & attestation verification
	// (cosign/Sigstore) as a pull-path admission gate (Task 23).
	Sigverify SigverifyConfig `yaml:"sigverify"`
	// Notifications configures the event-notification subsystem (webhooks +
	// Slack) that alerts on security-relevant events (Task 21).
	Notifications NotifyConfig `yaml:"notifications"`

	// RateLimit configures per-tenant and global request-rate, upstream-
	// concurrency, and byte-quota enforcement (Task 24).
	RateLimit RateLimitConfig `yaml:"rateLimit"`

	// Coalesce configures pull-path request coalescing (singleflight) and bounded
	// negative caching (Task 36): concurrent cache-miss requests for the same
	// tenant-scoped artifact key collapse onto a single upstream fetch, and
	// terminal upstream failures (404/410/auth) are remembered for a short TTL
	// with jittered backoff for transient 5xx.
	Coalesce CoalesceConfig `yaml:"coalesce"`

	// CacheGC configures the cache lifecycle manager (Task 39): a background
	// garbage-collection / eviction / retention engine that keeps the
	// content-addressable cache (local and S3-backed) bounded via size watermarks
	// (LRU/LFU/FIFO), per-artifact/per-tenant TTLs, pin/protect rules, and
	// reference-count retention, with a dry-run mode and high-watermark alerting.
	CacheGC CacheGCConfig `yaml:"cacheGc"`

	Observability ObservabilityConfig `yaml:"observability"`

	// AdminAuth configures enterprise SSO (OIDC/OAuth2 authorization-code login
	// with PKCE for the UI, bearer/JWT validation for the API) and fine-grained
	// RBAC (viewer/operator/approver/admin) over the admin surface (Task 51).
	// Disabled by default, leaving the legacy observability.adminToken behavior
	// intact for existing deployments.
	AdminAuth AdminAuthConfig `yaml:"adminAuth"`

	// Tracing configures OpenTelemetry distributed tracing (Task 41): a
	// vendored-thin OTLP/HTTP exporter, W3C trace-context propagation through the
	// pull & admission pipeline and into background workers, and span emission for
	// the full latency breakdown of a pull. Disabled by default; active only when
	// enabled and an OTLP endpoint is configured.
	Tracing TracingConfig `yaml:"tracing"`

	// Telemetry groups additional OTLP signal-export configuration that
	// complements tracing: today the OTLP structured-log export pipeline (Task
	// 160), which ships the proxy's operational logs to a collector correlated
	// with the active trace/span. Disabled by default.
	Telemetry TelemetryConfig `yaml:"telemetry"`

	// Compliance configures the continuous-compliance scorecard (Task 35): a
	// periodically-computed posture report aggregating the security gates'
	// signals into a SLSA/SOC2-style control checklist, exposed over the admin
	// API (JSON/Markdown/HTML), as a signed exportable artifact, and as per-
	// control Prometheus gauges.
	Compliance ComplianceConfig `yaml:"compliance"`

	// RiskScore configures the unified supply-chain risk-scoring engine (Task 37):
	// it aggregates the admission gates' signals into a single composite, weighted
	// risk score (0..100) and band per artifact, emits an explainable breakdown,
	// and optionally warns/blocks above a configurable band, composing with (not
	// replacing) the policy-as-code engine.
	RiskScore RiskScoreConfig `yaml:"riskScore"`

	// RepoScore configures the source-repository health signal provider (Task 63):
	// it derives OpenSSF Scorecard-style health signals (branch-protection
	// presence, signed-commit ratio, CI and security-policy presence, maintainer
	// count / bus factor, recent activity, dependency-update automation) for the
	// repository an artifact was built from and feeds a per-repo health/risk score
	// into the policy and risk engines.
	RepoScore RepoScoreConfig `yaml:"repoScore"`

	// SbomDiff configures the SBOM diff & dependency-drift subsystem (Task 64): it
	// persists a bounded per-coordinate history of resolved SBOMs and, when a new
	// version is pulled, computes the added/removed/version-bumped dependencies,
	// newly-introduced licenses/namespaces, and net-new vulnerabilities versus the
	// prior version, deriving a "drift risk" score that feeds an optional admission
	// signal and quarantines a quiet package that suddenly grows a large or
	// suspicious new dependency footprint.
	SbomDiff SbomDiffConfig `yaml:"sbomDiff"`

	// Remediation configures the automated dependency-remediation advisor (Task
	// 121): given a blocked/flagged artifact it computes the nearest safe upgrade
	// version that clears the failing gate(s), the findings that version resolves,
	// and any it introduces, reusing the live vulnscan/VEX, license, release-
	// cooldown, and dependency-firewall gates to score candidate versions pulled
	// from the upstream registry.
	Remediation RemediationConfig `yaml:"remediation"`

	// RebuildVerify configures the reproducible-build verification gate (Task 68):
	// it rebuilds an artifact from its attested source commit (via a pluggable,
	// sandboxed, air-gap-aware builder) and compares the rebuilt digest against the
	// upstream-served artifact, emitting a reproducible|mismatch|unsupported|
	// unattested verdict that feeds the policy and risk engines.
	RebuildVerify RebuildVerifyConfig `yaml:"rebuildVerify"`

	// BuildProv configures the inbound build-provenance verification gate (Task 72):
	// it consumes upstream-published build provenance (npm provenance / GitHub
	// artifact attestations) to cryptographically bind a package version to its
	// source repo + commit + CI workflow, then cross-checks that proven commit
	// against the package-to-commit association from the provenance subsystem and
	// flags mismatches.
	BuildProv BuildProvConfig `yaml:"buildProv"`

	// PyPIAttest configures the inbound PyPI PEP 740 digital-attestation
	// verification gate (Task 146).
	PyPIAttest PyPIAttestConfig `yaml:"pypiAttestation"`

	// Snapshot configures the organization-wide dependency snapshot, freeze &
	// instant-rollback subsystem (Task 70): point-in-time, signed, content-addressed
	// captures of the resolved dependency state actually served, with a freeze gate
	// that pins the org to a snapshot and a one-action rollback to the last-known-good
	// snapshot.
	Snapshot SnapshotConfig `yaml:"snapshot"`

	// Lockdown configures the emergency-lockdown / global kill-switch incident-
	// response control (Task 74): the org-wide freeze/strict/targeted-block posture
	// consulted as the FIRST check on the pull path, its durable state file, and the
	// TTL applied to an engagement.
	Lockdown LockdownConfig `yaml:"lockdown"`

	// AdmissionWebhook configures the Kubernetes ValidatingAdmissionWebhook /
	// in-cluster enforcement server (Task 111): an HTTPS admission endpoint that
	// reuses the per-coordinate security dossier / risk verdict (Task 87/37) to
	// admit or reject Pod image references at deploy time, extending supply-chain
	// enforcement from the pull path to the cluster runtime. Off by default; it is
	// started as an additional listener when enabled, and integrates with the
	// emergency-lockdown kill-switch (Task 74).
	AdmissionWebhook AdmissionWebhookConfig `yaml:"admissionWebhook"`

	// Gitops configures the GitOps policy & config synchronization subsystem
	// (Task 93): continuous reconciliation of the proxy's policy/config bundles
	// from a version-controlled source of truth (a Git repository, an OCI artifact,
	// or — air-gap friendly — a local pre-fetched bundle), with signature/digest
	// verification, configcheck validation, simreplay blast-radius preview, and
	// either auto-apply or dual-control "suggest" mode plus rollback.
	Gitops GitopsConfig `yaml:"gitops"`

	// Extensions configures the sandboxed WebAssembly extensibility mechanism
	// (Task 59): operator-supplied wasm modules invoked as a final, late-stage
	// admission gate over the aggregated signal set, under strict CPU/memory/time/
	// fuel limits with no host filesystem or network access. Inert until modules
	// are configured.
	Extensions ExtensionConfig `yaml:"extensions"`

	// Findings configures the unified SARIF findings-aggregation layer (Task 42):
	// it normalizes every admission gate's verdict into one canonical model,
	// retains the most recent findings per artifact, and exports them as SARIF
	// 2.1.0 over the admin API and a CLI subcommand so a customer's CI can decorate
	// pull requests and fail builds on supply-chain findings natively.
	Findings FindingsConfig `yaml:"findings"`

	// Attest configures the outbound SLSA/in-toto attestation engine (Task 46): the
	// proxy signs a supply-chain attestation bundle for every artifact it serves,
	// binding the served digest to its source commit, the admission verdicts it
	// passed, and the proxy identity; serves it via an OCI referrers-style endpoint
	// and an admin/CLI export; and embeds the bundle digest in the audit log so the
	// proxy becomes a provenance attester downstream CI can require.
	Attest AttestConfig `yaml:"attest"`

	// Transparency configures transparency-log (Sigstore Rekor) integration
	// (Task 142): submitting the proxy's signed attestations to a public Rekor log
	// and recording the returned log index + inclusion proof (outbound), and
	// requiring a verified inclusion proof on the inbound signature gate.
	Transparency TransparencyConfig `yaml:"transparency"`

	// Anomaly configures behavioral anomaly detection on the pull stream (Task 43):
	// online rolling-window/EWMA detectors that flag distinct-package fan-out
	// spikes, bursts of new namespaces, off-hours bursts, rapid 404 enumeration,
	// and anomalous egress volume per tenant/identity — signals of credential
	// compromise or exfiltration that no single-artifact gate can see — feeding the
	// notify subsystem and optionally soft-blocking the offending identity.
	Anomaly AnomalyConfig `yaml:"anomaly"`

	// Approvals configures the human-in-the-loop quarantine-review & break-glass
	// approval workflow (Task 50): when an admission gate blocks/quarantines an
	// artifact (vulnscan quarantine, CVE-drift, malfeed, sigverify failure, hard
	// policy block), an operator can grant a time-boxed, tenant+coordinate+gate-
	// scoped exception or confirm the block, instead of editing policy config.
	// Disabled by default (gates block unconditionally until an operator opts in).
	Approvals ApprovalsConfig `yaml:"approvals"`

	// Metering configures the per-tenant usage-metering & chargeback subsystem
	// (Task 84): a low-overhead in-process accumulator, fed by taps on the pull
	// path/cache/scan gates, that attributes proxy cost per tenant (bytes served
	// split by cache-hit vs upstream fetch, cache-fill storage, request counts by
	// backend/ecosystem, admission-scan invocations and estimated cost, and
	// quarantine/block counts), with durable periodic rollups, an admin Usage tab
	// and report endpoints, and optional per-tenant budget-threshold alerts.
	Metering MeteringConfig `yaml:"metering"`

	// DownloadLog configures the download log (Task 176): a bounded, queryable
	// record of which package was downloaded from which client address — and by
	// which authenticated identity, when there is one — shown in the admin UI's
	// Downloads tab and served by the admin API. It answers "who has this
	// package?" when a package turns out to be malicious, and "what did this
	// host pull?" when a host is compromised. Requests refused by an admission
	// gate are recorded as well. It is cheap and bounded (a fixed number of
	// entries, a retention period), so it is enabled by default.
	DownloadLog DownloadLogConfig `yaml:"downloadLog"`

	// UserLinks configures personal cache links (Task 177): cache users sign in
	// through an OIDC identity provider and are handed their own address for
	// every package source — the ordinary one under a path prefix that names
	// them ("/u/<token>/v1/<upstream>/…") — so that the download log attributes
	// a download to a person and not only to a client address. The link's token
	// is equally accepted as an HTTP credential. Off by default: it needs an
	// identity provider, or an administrator who issues links.
	UserLinks UserLinksConfig `yaml:"userLinks"`

	// Repositories configures the repository registry (Task 180): repositories
	// whose tags the proxy tracks, and whose releases it pins. Every
	// tag-to-commit association ever seen is kept in an append-only history;
	// when a tag appears or moves, the lock files at the commit are read and
	// every dependency they pin is fetched through the gated serve pipeline
	// and pinned in the cache, so that the release stays reproducible from it.
	// Off by default.
	Repositories RepositoriesConfig `yaml:"repositories"`

	// Secrets configures the master key used to decrypt secret values stored
	// encrypted at rest.
	Secrets SecretsConfig `yaml:"secrets"`
	// Auth configures client authentication, RBAC, multi-tenancy, and quotas.
	Auth AuthConfig `yaml:"auth"`
	// ClientAuth configures additional client-authentication paths layered on top
	// of Auth — currently SPIFFE/SVID mutual-TLS workload identity (Task 58),
	// which maps a verified client-certificate SPIFFE ID to a tenant + roles.
	ClientAuth ClientAuthConfig `yaml:"clientAuth"`
	// Audit configures the tamper-evident audit log.
	Audit AuditConfig `yaml:"audit"`

	// Backup configures the disaster-recovery backup/restore subsystem (Task 44):
	// consistent, manifest-described, optionally-encrypted snapshots of the cache
	// and all sidecar metadata stores, an optional scheduled-backup loop, and the
	// backup-age/last-success metrics used for RPO alerting.
	Backup BackupConfig `yaml:"backup"`

	// SimReplay configures the policy & risk what-if simulation/replay harness
	// (Task 47): a sampled, redacted ring buffer of recent admission inputs and
	// their live verdicts that an operator can replay through a candidate
	// policyengine/riskscore configuration — via the `simulate` CLI or the admin
	// endpoint — to preview admit↔block flips, risk-band shifts, new policy
	// violations, and per-tenant blast radius before rolling a change out.
	SimReplay SimReplayConfig `yaml:"simReplay"`

	// Coordination configures distributed coordination & leader election for
	// scheduled background jobs in HA (multi-replica) deployments (Task 56). When
	// enabled, each replica only runs a given scheduled job (CVE-drift re-scan,
	// backup scheduler, malfeed feed refresh, audit Merkle checkpoint signing)
	// while it holds the job's named lease, so N replicas no longer duplicate work,
	// race on quarantine state, double-write backups, or emit N× notifications.
	// Disabled by default, preserving single-node behavior.
	Coordination CoordinationConfig `yaml:"coordination"`

	// FIPS configures the FIPS 140-3 compliant cryptographic operating mode
	// (Task 120): when enabled it enforces an approved-only crypto posture across
	// TLS termination, signature verification, audit-log hashing, and cache
	// content addressing, and fails fast at startup if the validated Go FIPS
	// 140-3 cryptographic module is required but not active. Disabled by default
	// so existing non-regulated deployments are unaffected.
	FIPS FIPSConfig `yaml:"fips"`

	// SIEM configures the outbound SIEM / log-forwarding integration (Task 119):
	// a pluggable forwarder that streams the tamper-evident audit-log records and
	// admission-gate findings to external SIEMs (Splunk HTTP Event Collector and a
	// generic syslog/CEF TCP/UDP sink) with batching, retry/backoff, TLS, and a
	// bounded in-memory queue with optional disk spill so forwarding failures never
	// block the pull path. Disabled by default; the local audit log's hash-chain
	// integrity is unaffected whether it is on or off. See docs/siem.md.
	SIEM SIEMConfig `yaml:"siem"`

	// Prewarm configures the optional predictive cache pre-warming subsystem (Task
	// 134): it analyses historical pull telemetry to forecast likely near-future
	// pulls (new patch/minor releases of frequently-pulled coordinates and
	// transitive dependencies of recently-pulled top-level packages) and
	// proactively fetches + admission-gates them during off-peak windows, so cache
	// hits and gate verdicts are ready before the first client request. It is
	// leader-election aware (only one node pre-warms in HA), rate/concurrency
	// bounded, respects the SSRF egress allowlist and the emergency kill-switch,
	// and never serves an artifact that fails an admission gate. Disabled by
	// default.
	Prewarm PrewarmConfig `yaml:"prewarm"`

	// CacheFed configures cross-proxy peer cache federation (Task 143): an
	// optional read-through layer that lets a cluster of proxy instances satisfy a
	// local cache miss from a sibling peer's cache — over a lightweight
	// authenticated HEAD/GET-by-digest protocol — before reaching the upstream,
	// reducing egress and cache warming time. Peer bytes are never trusted blindly:
	// every response is re-verified against the expected content digest on receipt
	// and re-run through the local admission gates, and only already-gated/cacheable
	// artifacts are exchanged between peers. Healthy peers are selected with a
	// per-peer timeout, request hedging, and circuit-breaking. Disabled by default.
	CacheFed CacheFedConfig `yaml:"cacheFed"`

	// SBOMExport configures the outbound SBOM/findings federation subsystem (Task
	// 153): it renders the proxy's generated CycloneDX SBOMs (optionally enriched
	// with admission-gate vulnerability findings) and pushes them to external
	// supply-chain graph systems — an OWASP Dependency-Track server (PUT
	// /api/v1/bom with API-key auth and project auto-create) and/or a GUAC
	// collector ingestion endpoint. A periodic sweep is leader-gated so only one HA
	// node exports; credentials are resolved via the secrets provider. Disabled by
	// default.
	SBOMExport SBOMExportConfig `yaml:"sbomExport"`

	// KeyRotation configures the credential & signing-key rotation/expiry
	// subsystem (Task 148): a leader-gated scanner that monitors the proxy's
	// long-lived trust material — audit HMAC/Merkle keys, the cache
	// key-encryption key, outbound attestation signing keys, upstream credentials,
	// and pinned TLS certificates/CAs — grades each one's remaining lifetime,
	// emits warnings via the notification subsystem and a
	// pullthrough_key_expiry_seconds gauge before material expires, and drives the
	// rotations that can be performed safely in place (today the cache KEK) with
	// dual-key overlap windows. Enabled by default; purely observational until an
	// operator rotates, so it never blocks a pull.
	KeyRotation KeyRotationConfig `yaml:"keyRotation"`

	// WebAuthn (Task 161) adds FIDO2 passkey step-up authentication as a required
	// second factor for the most sensitive admin operations — break-glass
	// quarantine approvals (Task 50), emergency lockdown / kill-switch toggles
	// (Task 74), policy-preset apply (Task 88), and key-rotation triggers
	// (Task 148). When enabled and enforcing, those endpoints require a fresh,
	// short-TTL WebAuthn assertion carried in an X-StepUp-Token header, minted by a
	// successful assertion ceremony. Disabled by default; requires the admin SSO/
	// RBAC layer so each ceremony is bound to a real identity.
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
}

// CacheFedConfig configures cross-proxy peer cache federation (Task 143).
type CacheFedConfig struct {
	// Enabled turns the whole subsystem on. When false the proxy neither consults
	// peers on a miss nor answers sibling requests.
	Enabled bool `yaml:"enabled"`
	// Serve controls whether this instance answers sibling HEAD/GET requests from
	// its local cache. Independent of the read-through client. Defaults to true
	// when Enabled. Serving requires a non-empty auth secret; without one it stays
	// off (fail-closed) so the endpoint is never unauthenticated.
	Serve *bool `yaml:"serve"`
	// Peers is the static roster of sibling proxy base URLs. A peer whose name
	// matches this node's coordination NodeID is skipped so a node never federates
	// to itself.
	Peers []CacheFedPeer `yaml:"peers"`
	// Auth configures the shared bearer token presented to and required from peers.
	Auth CacheFedAuthConfig `yaml:"auth"`
	// MaxPeerFanout caps how many peers a single miss may query concurrently.
	// Defaults to 2.
	MaxPeerFanout int `yaml:"maxPeerFanout"`
	// PeerTimeout bounds the time to receive response headers from one peer (not
	// the subsequent body stream). Defaults to 3s.
	PeerTimeout time.Duration `yaml:"peerTimeout"`
	// HedgeDelay staggers the fan-out: the first peer is queried immediately and
	// each subsequent candidate HedgeDelay later, so a slow peer does not hold up a
	// request a fast one could answer. Zero launches all candidates at once.
	// Defaults to 150ms.
	HedgeDelay time.Duration `yaml:"hedgeDelay"`
	// RequireDigest refuses to consult peers unless an expected content digest is
	// known, guaranteeing every peer response can be re-verified against an
	// authoritative baseline (defending against a malicious peer, not just transit
	// corruption). Strongly recommended; defaults to true.
	RequireDigest *bool `yaml:"requireDigest"`
	// FailureThreshold is the number of consecutive peer failures that trips a
	// peer's circuit breaker (shedding it). Defaults to 3.
	FailureThreshold int `yaml:"failureThreshold"`
	// SuccessThreshold is the number of consecutive half-open probe successes that
	// closes a tripped peer's breaker. Defaults to 2.
	SuccessThreshold int `yaml:"successThreshold"`
	// OpenTimeout is how long a tripped peer is shed before a trial probe is
	// admitted. Defaults to 30s.
	OpenTimeout time.Duration `yaml:"openTimeout"`
	// HalfOpenMaxProbes caps the trial probes admitted while a breaker is
	// half-open. Defaults to 1.
	HalfOpenMaxProbes int `yaml:"halfOpenMaxProbes"`
}

// CacheFedPeer is one sibling proxy in the federation roster.
type CacheFedPeer struct {
	// Name is a stable identifier for the peer (defaults to the URL host) used in
	// logs, metric labels, and NodeID self-exclusion.
	Name string `yaml:"name"`
	// URL is the peer's base URL (scheme + host), e.g. https://proxy-b.internal:8443.
	URL string `yaml:"url"`
}

// CacheFedAuthConfig configures the shared secret for the peer protocol.
type CacheFedAuthConfig struct {
	// SecretRef is the shared bearer token (or a secretRef such as
	// env://CACHEFED_TOKEN / vault://... resolved at startup) presented to and
	// required from peers. It must be identical across every federated instance.
	SecretRef string `yaml:"secretRef"`
}

// ServeOrDefault resolves the tri-state Serve flag (default true).
func (c CacheFedConfig) ServeOrDefault() bool {
	if c.Serve == nil {
		return true
	}
	return *c.Serve
}

// RequireDigestOrDefault resolves the tri-state RequireDigest flag (default true).
func (c CacheFedConfig) RequireDigestOrDefault() bool {
	if c.RequireDigest == nil {
		return true
	}
	return *c.RequireDigest
}

// KeyRotationConfig configures the credential & signing-key rotation/expiry
// subsystem (Task 148).
type KeyRotationConfig struct {
	// Enabled turns on the leader-gated expiry scanner, the
	// pullthrough_key_expiry_seconds gauge, and the admin/ptctl rotation surface.
	// On by default: scanning is cheap, read-only, and never blocks a pull.
	Enabled bool `yaml:"enabled"`
	// ScanInterval is how often the expiry scanner runs. Defaults to 6h.
	ScanInterval time.Duration `yaml:"scanInterval"`
	// WarnThreshold grades material within this long of its effective expiry as a
	// warning. Defaults to 336h (14 days).
	WarnThreshold time.Duration `yaml:"warnThreshold"`
	// CriticalThreshold grades material within this long of its effective expiry
	// as critical. Defaults to 72h (3 days).
	CriticalThreshold time.Duration `yaml:"criticalThreshold"`
	// OverlapWindow is the default dual-key overlap window applied when the
	// subsystem drives a staged rotation: the duration a retired key is still
	// accepted so in-flight artifacts verify. Defaults to 24h.
	OverlapWindow time.Duration `yaml:"overlapWindow"`
	// Certificates lists x509 certificate/CA files to monitor for NotAfter expiry
	// (e.g. the certificates whose fingerprints are pinned for upstream egress in
	// outbound.tls.pins). Each is reported as a monitored material.
	Certificates []MonitoredCertConfig `yaml:"certificates"`
	// Policies attach a soft rotation policy (a maximum age) to material that has
	// no inherent cryptographic expiry — audit HMAC/checkpoint keys, attestation
	// signing keys — so the scanner can still warn when they grow stale.
	Policies []KeyRotationPolicyConfig `yaml:"policies"`
}

// WebAuthnConfig configures WebAuthn/passkey step-up authentication (Task 161).
type WebAuthnConfig struct {
	// Enabled is the master switch. When false the subsystem is a no-op: no
	// ceremonies are served and no endpoint is gated.
	Enabled bool `yaml:"enabled"`
	// Enforce gates whether the protected admin endpoints are actually blocked
	// without a fresh step-up assertion. When Enabled but not Enforce, admins can
	// enroll and exercise ceremonies (a safe rollout), but endpoints are not yet
	// gated. Defaults to true when Enabled (set to false to stage a rollout).
	Enforce *bool `yaml:"enforce"`
	// RPID is the Relying Party ID — the effective registrable domain of the admin
	// UI (e.g. "example.com" or "admin.example.com"). Required when enabled.
	RPID string `yaml:"rpId"`
	// RPName is a human-readable Relying Party display name shown by the browser
	// during enrolment. Defaults to "Pullthrough Admin".
	RPName string `yaml:"rpName"`
	// Origins is the allowlist of acceptable WebAuthn client-data origins
	// (e.g. "https://admin.example.com"). At least one is required when enabled.
	Origins []string `yaml:"origins"`
	// RequireUserVerification demands the authenticator's user-verification flag
	// (PIN/biometric), not merely user presence, on every ceremony. Defaults true.
	RequireUserVerification *bool `yaml:"requireUserVerification"`
	// ChallengeTTL bounds how long an issued ceremony challenge remains valid.
	// Defaults to 2m.
	ChallengeTTL time.Duration `yaml:"challengeTtl"`
	// StepUpTTL bounds the freshness window of a minted step-up token — how long
	// after an assertion a protected mutation may be performed. Defaults to 5m.
	StepUpTTL time.Duration `yaml:"stepUpTtl"`
	// AllowUnverifiedAttestation accepts attestation formats the verifier cannot
	// cryptographically check (flagging the credential as unverified) rather than
	// rejecting the enrolment. Defaults true, since the trust anchor at enrolment
	// is the authenticated admin session, not a manufacturer attestation CA.
	AllowUnverifiedAttestation *bool `yaml:"allowUnverifiedAttestation"`
	// ProtectedActions overrides the default set of step-up-gated endpoint paths
	// (relative to the admin mount prefix). Empty uses the built-in default:
	// break-glass approve/deny, lockdown engage/clear, preset apply, key rotate.
	ProtectedActions []string `yaml:"protectedActions"`
	// StorePath is the JSON sidecar file backing the registered-credential set.
	// Empty keeps credentials in memory only (lost on restart).
	StorePath string `yaml:"storePath"`
}

// EnforceOrDefault reports whether enforcement is on, defaulting to true when
// the subsystem is enabled and the field is unset.
func (w WebAuthnConfig) EnforceOrDefault() bool {
	if w.Enforce == nil {
		return true
	}
	return *w.Enforce
}

// RequireUserVerificationOrDefault reports whether UV is required, defaulting to
// true when unset.
func (w WebAuthnConfig) RequireUserVerificationOrDefault() bool {
	if w.RequireUserVerification == nil {
		return true
	}
	return *w.RequireUserVerification
}

// AllowUnverifiedAttestationOrDefault reports whether unverifiable attestation
// formats are accepted, defaulting to true when unset.
func (w WebAuthnConfig) AllowUnverifiedAttestationOrDefault() bool {
	if w.AllowUnverifiedAttestation == nil {
		return true
	}
	return *w.AllowUnverifiedAttestation
}

// MonitoredCertConfig identifies one certificate file to monitor for expiry.
type MonitoredCertConfig struct {
	// ID is the stable material id, e.g. "tls.upstream.github".
	ID string `yaml:"id"`
	// Path is the PEM certificate file on disk; its first CERTIFICATE block is read.
	Path string `yaml:"path"`
	// Kind is "tls-cert" (default) or "ca-certificate".
	Kind string `yaml:"kind"`
	// Description is an optional operator-facing label.
	Description string `yaml:"description"`
}

// KeyRotationPolicyConfig attaches a soft rotation policy to a material.
type KeyRotationPolicyConfig struct {
	// Material is the material id or kind the policy applies to, e.g. "audit-hmac".
	Material string `yaml:"material"`
	// RotateEvery is the maximum age before the material should be rotated.
	RotateEvery time.Duration `yaml:"rotateEvery"`
}

// FIPSConfig configures the FIPS 140-3 compliant cryptographic operating mode
// (Task 120). The actual approved-algorithm enforcement is performed by the Go
// FIPS 140-3 Cryptographic Module (built with GOFIPS140, activated with
// GODEBUG=fips140=on); this configuration wires the proxy's intent and the
// startup fail-fast posture. See docs/fips-compliance.md.
type FIPSConfig struct {
	// Enabled turns on FIPS 140-3 approved-crypto enforcement. When true the
	// proxy restricts TLS termination to the approved TLS 1.2+ AES-GCM cipher
	// suites, rejects a configured TLS floor below 1.2 anywhere, and (unless
	// requireModule is false) requires the validated FIPS module to be active.
	// Defaults to false.
	Enabled bool `yaml:"enabled"`
	// RequireModule, when true (the default when enabled is set), makes startup
	// fail fast unless the Go FIPS 140-3 cryptographic module is active in the
	// process — i.e. the binary was built with GOFIPS140 (see `make build-fips`)
	// and started with GODEBUG=fips140=on. This prevents an operator from
	// believing a deployment is FIPS compliant when it is running the standard
	// crypto. Set it explicitly to false to run approved-algorithm enforcement
	// (TLS hardening, config validation) without the validated module, e.g. for
	// local testing on a non-FIPS toolchain. Ignored when enabled is false.
	RequireModule *bool `yaml:"requireModule"`
}

// RequireModuleOrDefault reports whether the validated FIPS module must be
// active. It defaults to true when unset, so enabling FIPS without the module
// is an explicit, deliberate opt-out rather than a silent downgrade.
func (f FIPSConfig) RequireModuleOrDefault() bool {
	if f.RequireModule == nil {
		return true
	}
	return *f.RequireModule
}

// ServerConfig configures the HTTP/SSH gateway listeners.
type ServerConfig struct {
	// HTTPAddr is the listen address for the HTTP gateway, e.g. ":8080".
	HTTPAddr string `yaml:"httpAddr"`
	// PublicURL is the externally reachable base URL of the proxy, e.g.
	// "https://proxy.example.com". Package-manager backends use it to rewrite
	// index documents (npm packuments, PyPI Simple pages, cargo config, NuGet
	// service index) so clients fetch dependent artifacts back through the proxy.
	// When empty, rewritten links are root-relative ("/v1/<backend>/..."), which
	// works for most clients but is fragile behind path-rewriting load balancers;
	// setting an absolute PublicURL is recommended in production.
	PublicURL string `yaml:"publicUrl"`
	// SSHAddr is the listen address for the Git-over-SSH gateway, e.g. ":2222".
	// Empty disables the SSH listener.
	SSHAddr string `yaml:"sshAddr"`
	// ReadTimeout and WriteTimeout bound request handling.
	ReadTimeout  time.Duration `yaml:"readTimeout"`
	WriteTimeout time.Duration `yaml:"writeTimeout"`
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration `yaml:"shutdownTimeout"`
	// TLSCertFile and TLSKeyFile enable TLS termination at the HTTP gateway.
	// Set both to serve HTTPS; leave both empty to serve plain HTTP (e.g. when
	// TLS is terminated by an upstream load balancer).
	TLSCertFile string `yaml:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile"`
	// Intercept configures the optional TLS-interception (MITM) forward-proxy
	// listener. When disabled (the default), the proxy serves only in explicit
	// package-source mode (clients point at "https://proxy/v1/<backend>/"). When
	// enabled, clients instead point at the proxy as an ordinary HTTP forwarding
	// proxy (HTTP_PROXY/HTTPS_PROXY); the proxy terminates TLS with a locally
	// trusted CA, maps the real upstream host to a configured backend, and runs
	// the same caching + admission pipeline — no per-tool reconfiguration needed
	// beyond trusting the CA.
	Intercept InterceptConfig `yaml:"intercept"`
	// Registry configures the host-root Docker/OCI Registry v2 alias ("/v2/...").
	// Container clients (Docker, containerd, podman, skopeo, the Helm OCI client)
	// always insert "/v2/" directly after the registry host and therefore cannot
	// address the path-prefixed "/v1/<upstream>/v2/" mount; the alias serves the
	// same upstreams at the host root, through the same access-control and
	// admission pipeline.
	Registry RegistryConfig `yaml:"registry"`
	// TrustedProxies lists the reverse proxies — load balancers, ingress
	// controllers — that sit between clients and this listener, as IP addresses
	// or CIDR prefixes ("10.0.0.0/8", "192.168.1.10", "fd00::/8"). When a request
	// arrives from one of them, the client address is taken from the
	// X-Forwarded-For header it appended (the right-most entry that is not itself
	// a trusted proxy) instead of from the TCP connection, so the download log,
	// the audit log and anomaly detection attribute traffic to the real client
	// rather than to the balancer.
	//
	// The header is believed only from these peers: with the list empty (the
	// default) it is never read, and a client connecting directly cannot attribute
	// its requests to another address. List only infrastructure that overwrites or
	// appends to the header itself; never a network that clients are on.
	TrustedProxies []string `yaml:"trustedProxies"`
}

// RegistryConfig configures the host-root Docker/OCI Registry v2 alias. It only
// has an effect when at least one registry upstream (type "docker", or type
// "helm" with settings.oci: "true") is configured.
type RegistryConfig struct {
	// Enabled toggles the alias. It defaults to true (nil): the alias adds an
	// address for upstreams that are already configured, not a new capability, and
	// without it no container client can pull through the proxy unless an external
	// reverse proxy rewrites "/v2/" for it. Set false to serve registry upstreams
	// only under "/v1/<upstream>/v2/".
	Enabled *bool `yaml:"enabled"`
	// DefaultUpstream names the registry upstream that serves requests whose
	// repository carries no upstream prefix, i.e. registry-mirror mode: a Docker
	// daemon with `"registry-mirrors": ["https://proxy.example.com"]` requests
	// "/v2/library/alpine/..." and is served by this upstream. When empty, only
	// upstream-prefixed repositories ("proxy.example.com/<upstream>/<repository>")
	// and requests carrying containerd's "ns" mirror hint are served.
	DefaultUpstream string `yaml:"defaultUpstream"`
}

// EnabledOrDefault resolves the tri-state Enabled flag (default true).
func (c RegistryConfig) EnabledOrDefault() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// IsRegistryUpstream reports whether an upstream speaks the Docker/OCI Registry
// v2 API and can therefore be reached through the host-root "/v2/" alias: a
// "docker" upstream, or a "helm" upstream in OCI mode.
func (u UpstreamConfig) IsRegistryUpstream() bool {
	switch u.Type {
	case "docker":
		return true
	case "helm":
		return strings.EqualFold(strings.TrimSpace(u.Settings["oci"]), "true")
	default:
		return false
	}
}

// InterceptConfig configures TLS interception (Tasks 100 and 172): serving
// clients that address the upstream registries themselves — pypi.org,
// registry.npmjs.org — instead of the proxy. It is additive and independent of
// the explicit /v1 access mode, which is always available. Two ways of getting
// such a client's connections to the proxy are supported, each with listeners
// of its own; either or both may be configured:
//
//   - forward proxy (listenAddr): the client is configured to use the proxy as
//     its HTTP(S) proxy (HTTPS_PROXY/HTTP_PROXY) and sends a CONNECT for the
//     upstream host;
//   - NAT (nat.httpsAddr, nat.httpAddr): the client is not configured at all;
//     the network sends its connections to the upstream hosts to the proxy — a
//     NAT redirect on a gateway, or DNS answering the upstream hosts with the
//     proxy's address — and the proxy routes each by the host the client asked
//     for (TLS server name, HTTP Host header).
//
// Either way the proxy terminates TLS with a certificate for the upstream host
// minted by its own CA (which clients must trust), maps the host and path to a
// configured upstream, and runs the request through the same caching and
// admission pipeline as an explicit request.
type InterceptConfig struct {
	// Enabled turns interception on.
	Enabled bool `yaml:"enabled"`
	// ListenAddr is the listen address of the forward proxy, e.g. ":3128":
	// clients set HTTPS_PROXY/HTTP_PROXY to it. Empty runs no forward proxy (NAT
	// mode only); at least one of listenAddr, nat.httpsAddr and nat.httpAddr
	// must be set when interception is enabled.
	ListenAddr string `yaml:"listenAddr"`
	// NAT configures NAT mode: listeners for connections the network redirects
	// to the proxy, so clients need no proxy configuration at all.
	NAT InterceptNATConfig `yaml:"nat"`
	// CACertFile and CAKeyFile are the PEM paths of the signing CA used to mint
	// per-host leaf certificates for intercepted TLS connections. Clients must
	// trust CACertFile. Required when Enabled.
	CACertFile string `yaml:"caCertFile"`
	CAKeyFile  string `yaml:"caKeyFile"`
	// GenerateCA, when true, generates a fresh CA at CACertFile/CAKeyFile if they
	// do not already exist (persisted for reuse across restarts). When false,
	// absent CA files are a startup error.
	GenerateCA bool `yaml:"generateCa"`
	// CAOrganization and CACommonName set the subject of a generated CA.
	CAOrganization string `yaml:"caOrganization"`
	CACommonName   string `yaml:"caCommonName"`
	// LeafTTL bounds the validity of minted leaf certificates (default 90 days).
	// Leaves are minted on demand and cached only in memory.
	LeafTTL time.Duration `yaml:"leafTtl"`
	// CertCacheSize bounds the in-memory minted-leaf cache (default 1024).
	CertCacheSize int `yaml:"certCacheSize"`
	// Hosts maps additional upstream hosts to a configured upstream (the key in
	// the `upstreams` map), for interception. Every enabled upstream's URL is
	// mapped automatically — its host and, when it has one, its path
	// ("deb.debian.org/debian") — together with the hosts a stock client of the
	// ecosystem uses for the same public registry (repo.maven.apache.org for
	// Maven Central, index.rubygems.org for rubygems.org, …). Use this for
	// anything else a client fetches from directly, or to override. A key is a
	// host, a "*.suffix" wildcard, or either followed by a path prefix
	// ("deb.debian.org/debian-security"), which is taken off before the
	// upstream sees the path.
	Hosts map[string]string `yaml:"hosts"`
	// PassthroughUnmatched, when true, passes connections to hosts that are not
	// configured for interception on undecrypted: a CONNECT is tunnelled to its
	// target, and a NAT connection to its original destination (which only a
	// NAT redirect records — on Linux, from connection tracking; without one the
	// connection is refused). When false (the default, secure), such connections
	// are refused so the proxy carries only configured traffic.
	PassthroughUnmatched bool `yaml:"passthroughUnmatched"`
	// AllowPlainHTTP, when true, also intercepts absolute-form plain-HTTP
	// requests to configured hosts on the forward proxy (APT and YUM
	// repositories are commonly configured with http:// URLs). HTTPS CONNECT
	// interception is always enabled, and the NAT HTTP listener serves plain
	// HTTP whenever it is configured.
	AllowPlainHTTP bool `yaml:"allowPlainHttp"`
}

// InterceptNATConfig configures NAT mode (Task 172): the listeners that receive
// the connections the network redirects to the proxy.
type InterceptNATConfig struct {
	// HTTPSAddr receives redirected TLS connections — what clients send to port
	// 443 of an upstream host — e.g. ":443" on the address DNS answers the
	// upstream hosts with, or ":8443" behind a rule redirecting port 443 there.
	// Each connection is routed by the server name (SNI) its TLS handshake asks
	// for. Empty runs no NAT TLS listener.
	HTTPSAddr string `yaml:"httpsAddr"`
	// HTTPAddr receives redirected plain-HTTP connections (port 80), routed by
	// their Host header. Empty runs no NAT HTTP listener.
	HTTPAddr string `yaml:"httpAddr"`
}

// Listening reports whether the configuration runs any interception listener.
func (c InterceptConfig) Listening() bool {
	return strings.TrimSpace(c.ListenAddr) != "" || strings.TrimSpace(c.NAT.HTTPSAddr) != "" ||
		strings.TrimSpace(c.NAT.HTTPAddr) != ""
}

// LoggingConfig configures structured logging.
type LoggingConfig struct {
	Level     string `yaml:"level"`  // debug|info|warn|error
	Format    string `yaml:"format"` // json|text
	AddSource bool   `yaml:"addSource"`
}

// CacheConfig configures the caching subsystem.
type CacheConfig struct {
	// Backend selects the cache implementation: "memory", "filesystem", or "s3".
	// The "s3" backend stores content in S3-compatible object storage so multiple
	// proxy replicas can share one cache for horizontally-scaled (HA) deployments.
	Backend string `yaml:"backend"`
	// Dir is the cache root directory for the filesystem backend.
	Dir string `yaml:"dir"`
	// S3 configures the S3-compatible object-storage backend (backend: "s3").
	S3 S3CacheConfig `yaml:"s3"`
	// MaxSizeBytes optionally bounds total cache size (0 = unbounded).
	// When exceeded, least-recently-used entries are evicted.
	MaxSizeBytes int64 `yaml:"maxSizeBytes"`
	// TTL optionally bounds entry age; expired entries are treated as absent
	// and removed (0 = no expiry).
	TTL time.Duration `yaml:"ttl"`
	// Sealed enables offline ("air-gapped") mode: the proxy serves only content
	// already in the cache and never reaches upstreams. Cacheable artifacts are
	// served from the cache (a miss is terminal, not a trigger to fetch) and live
	// upstream fetches are refused. Pair it with a pre-warmed or imported cache.
	Sealed bool `yaml:"sealed"`
	// Integrity configures read-time content-integrity verification and the
	// admin-triggered background integrity scan.
	Integrity IntegrityConfig `yaml:"integrity"`
	// Compression configures the optional transparent storage-efficiency layer
	// (compression + cross-artifact chunk deduplication, Task 125).
	Compression CompressionConfig `yaml:"compression"`
	// Encryption configures the optional at-rest encryption envelope (Task 141):
	// transparent AES-256-GCM encryption of cached artifact bytes using per-object
	// data keys wrapped by a configured key-encryption key.
	Encryption EncryptionConfig `yaml:"encryption"`
	// Tiering configures the optional hot/cold tiered storage layer (Task 154):
	// it keeps hot artifacts on the primary (fast) backend and demotes cold,
	// idle artifacts to a slower/cheaper backend, promoting them back on a read.
	Tiering TieringConfig `yaml:"tiering"`
}

// TieringConfig configures the optional tiered cache storage layer (Task 154).
// When enabled, the primary cache backend (filesystem or s3) becomes the fast
// "hot" tier and a second, slower/cheaper backend is configured as the "cold"
// tier. A leader-gated background sweep demotes hot artifacts that have gone
// idle (or that overflow the hot-tier size cap) to the cold tier, and reads of a
// cold artifact transparently promote it back to hot. The layer sits beneath the
// compression (Task 125) and encryption (Task 141) decorators and preserves the
// digest-over-plaintext invariant: it only moves already-transformed bytes
// between tiers and the content digest is unchanged by a tier move. It applies
// only to the filesystem and s3 backends (the in-memory backend has no durable
// store to tier).
type TieringConfig struct {
	// Enabled turns the layer on. Off by default.
	Enabled bool `yaml:"enabled"`
	// Cold configures the slower/cheaper backend that idle artifacts are demoted
	// to. Required when enabled, and must be distinct from the hot (primary)
	// backend's location.
	Cold TierBackendConfig `yaml:"cold"`
	// PromoteOnRead copies a cold artifact back to the hot tier when it is read,
	// so a resurgent artifact migrates back to fast storage. Defaults to true;
	// set it explicitly to false to leave cold reads on the cold tier.
	PromoteOnRead *bool `yaml:"promoteOnRead"`
	// DemoteAfterIdle is the idle window after which a hot artifact becomes a
	// demotion candidate (not read for at least this long). Defaults to 24h.
	// Set to 0 to disable idle-based demotion (then only hotMaxBytes drives it).
	DemoteAfterIdle time.Duration `yaml:"demoteAfterIdle"`
	// HotMaxBytes is a soft cap on the hot tier's total bytes; when exceeded the
	// sweep demotes least-recently-used hot artifacts until the tier is back under
	// the cap. 0 (default) leaves the hot tier unbounded (idle-based demotion
	// only).
	HotMaxBytes int64 `yaml:"hotMaxBytes"`
	// MinAccessesToStayHot protects a hot artifact read at least this many times
	// from idle-based demotion (capacity pressure can still demote it). 0 (default)
	// disables the frequency override.
	MinAccessesToStayHot int64 `yaml:"minAccessesToStayHot"`
	// SweepInterval is the cadence of the background demotion sweep. Defaults to
	// 10m. Set to 0 to disable the background sweep (demotion then runs only when
	// triggered via `ptctl cache-tiering sweep`).
	SweepInterval time.Duration `yaml:"sweepInterval"`
}

// TierBackendConfig configures one tier's durable backend (the cold tier of the
// tiered cache storage layer).
type TierBackendConfig struct {
	// Backend selects the cold-tier store: "filesystem" or "s3".
	Backend string `yaml:"backend"`
	// Dir is the cold-tier root directory for the filesystem backend.
	Dir string `yaml:"dir"`
	// S3 configures the cold-tier S3-compatible object-storage backend.
	S3 S3CacheConfig `yaml:"s3"`
}

// PromoteOnReadEnabled reports whether cold reads promote back to the hot tier,
// defaulting to true when the operator left the field unset.
func (t TieringConfig) PromoteOnReadEnabled() bool {
	return t.PromoteOnRead == nil || *t.PromoteOnRead
}

// EncryptionConfig configures the transparent at-rest encryption envelope
// (Task 141). When enabled, every artifact byte written to the durable store
// (filesystem or S3) is encrypted with AES-256-GCM using a fresh per-object
// data-encryption key (DEK); the DEK is wrapped by a key-encryption key (KEK)
// resolved through the secrets provider abstraction (Task 133) and stored, with
// a per-object nonce, in the object's metadata sidecar. The KEK never touches
// disk. The layer composes with cache.compression (it sits beneath it, so
// compression and dedup still operate on plaintext) and preserves the
// digest-over-plaintext invariant, so integrity verification (Task 107) and
// range serving (Task 75) are unaffected. It applies only to the filesystem and
// S3 backends (the in-memory backend has no durable store to encrypt).
type EncryptionConfig struct {
	// Enabled turns the layer on. Off by default.
	Enabled bool `yaml:"enabled"`
	// KeyID is the stable, operator-chosen label for the active (primary) KEK. It
	// is recorded in each object's sidecar so the right key is found to unwrap it,
	// and it is the HKDF salt when keyEncoding is "passphrase". Required when
	// enabled.
	KeyID string `yaml:"keyId"`
	// KeyRef is a secretRef ("env://", "file://", "vault://path#key") or inline
	// value resolving to the primary KEK material. Required when enabled.
	KeyRef string `yaml:"keyRef"`
	// KeyEncoding interprets the resolved KEK material: "base64" (default; 32 raw
	// bytes), "hex" (32 raw bytes), "raw" (exactly 32 bytes), or "passphrase" (an
	// arbitrary string stretched to 32 bytes with HKDF-SHA256).
	KeyEncoding string `yaml:"keyEncoding"`
	// PreviousKeys lists KEKs retained only to decrypt objects written under a
	// prior key, so a KEK rotation can proceed incrementally. They are never used
	// to wrap new objects. Run `ptctl cache-encryption rotate` to re-wrap existing
	// objects to the active key, after which the old key can be removed.
	PreviousKeys []EncryptionKeyConfig `yaml:"previousKeys"`
	// FrameSizeBytes is the streaming AEAD frame size. Defaults to 64 KiB.
	FrameSizeBytes int `yaml:"frameSizeBytes"`
}

// EncryptionKeyConfig is one retained decrypt-only KEK (see
// EncryptionConfig.PreviousKeys).
type EncryptionKeyConfig struct {
	// KeyID is the label this key was recorded under in object sidecars.
	KeyID string `yaml:"keyId"`
	// KeyRef resolves to the key material (see EncryptionConfig.KeyRef).
	KeyRef string `yaml:"keyRef"`
	// KeyEncoding interprets the material (see EncryptionConfig.KeyEncoding).
	KeyEncoding string `yaml:"keyEncoding"`
}

// CompressionConfig configures the transparent cache storage-efficiency layer
// (Task 125): zstd compression of compressible blobs and optional chunk-level
// deduplication across artifacts, applied between the generic caching layer and
// the durable store (filesystem or S3). It is invisible to the serve path —
// reads decompress/reassemble transparently and the content digest recorded for
// integrity verification (Task 107) and range serving (Task 75) is always over
// the original, uncompressed bytes. It applies only to the filesystem and S3
// backends (the in-memory backend has no durable store to compact).
type CompressionConfig struct {
	// Enabled turns the layer on. Off by default: it is an opt-in efficiency
	// feature that trades CPU for a smaller on-disk / S3 footprint.
	Enabled bool `yaml:"enabled"`
	// Codec selects the compression algorithm: "zstd" (default) or "none" (no
	// compression; only meaningful together with dedup).
	Codec string `yaml:"codec"`
	// Level is the zstd compression level (1=fastest .. 19=smallest). Defaults
	// to 3, a good balance of speed and ratio for pull-through workloads.
	Level int `yaml:"level"`
	// MinSizeBytes skips compression for blobs smaller than this many bytes (the
	// framing overhead is not worth it). Defaults to 256.
	MinSizeBytes int64 `yaml:"minSizeBytes"`
	// Dedup enables cross-artifact chunk-level deduplication. It requires a
	// single-writer store and is therefore supported only on the filesystem
	// backend; it is rejected on the S3 backend, whose shared-bucket model has no
	// safe cross-writer reference count. Off by default.
	Dedup bool `yaml:"dedup"`
	// SpoolDir stages the compression path's temporary output so the physical
	// length and digest are known before the backend write. Defaults to the OS
	// temporary directory.
	SpoolDir string `yaml:"spoolDir"`
}

// IntegrityConfig configures defense against cache tampering and bit-rot in the
// content-addressable store (Task 107). The store records a content digest for
// every blob it writes; with verification enabled, served bytes are streamed
// through that digest and a mismatch quarantines the entry, emits an audit event
// + metric + notification, and lets the next pull self-heal by re-fetching from
// upstream.
type IntegrityConfig struct {
	// VerifyOnServe streams every fully-served immutable blob through its stored
	// content digest and quarantines a mismatch. Defaults to true. It adds a hash
	// computation over served bytes (bounded memory, no extra I/O pass); disable
	// only if that CPU cost is unacceptable and tampering is defended elsewhere.
	VerifyOnServe bool `yaml:"verifyOnServe"`
	// NotifySeverity is the severity of the notification emitted when corruption
	// is detected (info|low|medium|high|critical). Defaults to "critical" —
	// silent corruption of the content store is a serious supply-chain event.
	NotifySeverity string `yaml:"notifySeverity"`
}

// S3CacheConfig configures the S3-compatible object-storage cache backend. The
// same content-addressing, single-flight de-duplication, sealed-mode, and
// metrics behavior as the filesystem backend applies; the difference is that the
// durable store lives in a shared bucket, so multiple proxy replicas pointed at
// the same bucket/prefix share one cache.
type S3CacheConfig struct {
	// Endpoint is the S3-compatible service endpoint, e.g.
	// "https://s3.us-east-1.amazonaws.com", "http://minio.minio.svc:9000", or
	// "https://storage.googleapis.com". Empty defaults to the AWS endpoint for
	// Region.
	Endpoint string `yaml:"endpoint"`
	// Region is the signing region (default "us-east-1"). MinIO/GCS accept any
	// stable value.
	Region string `yaml:"region"`
	// Bucket is the target bucket (required).
	Bucket string `yaml:"bucket"`
	// Prefix isolates this cache within a shared bucket, e.g. "proxy/cache/".
	Prefix string `yaml:"prefix"`
	// AccessKeyID and SecretAccessKey are the static credentials. They support
	// ${ENV_VAR} expansion and "enc:v1:" encryption so they need not be committed
	// to disk; in Kubernetes they are typically injected from a Secret via env.
	AccessKeyID     string `yaml:"accessKeyId"`
	SecretAccessKey string `yaml:"secretAccessKey"`
	// SessionToken is optional, for temporary/STS credentials.
	SessionToken string `yaml:"sessionToken"`
	// UsePathStyle selects path-style addressing ("{endpoint}/{bucket}/{key}").
	// MinIO and most non-AWS implementations require it; recommended on for broad
	// compatibility.
	UsePathStyle bool `yaml:"usePathStyle"`
	// InsecureSkipVerify disables TLS verification of the endpoint (self-signed
	// MinIO in test only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// MaxRetries bounds automatic retries of transient (5xx/network) failures
	// (default 2).
	MaxRetries int `yaml:"maxRetries"`
	// SpoolDir is the directory used to spool streamed upload bodies so their
	// length/digest can be computed for a signed PUT. Defaults to the OS temp dir;
	// set it to a path on a sized volume when caching very large artifacts.
	SpoolDir string `yaml:"spoolDir"`
	// SharedMode enables HA store-fallback reads so a replica serves content
	// another replica wrote after it warmed its index. It defaults to true for the
	// s3 backend; set it to false only for a single-replica deployment that wants
	// strict in-memory-index semantics.
	SharedMode *bool `yaml:"sharedMode"`
}

// IsSharedMode reports whether HA store-fallback reads are enabled (defaulting
// to true for the s3 backend).
func (s S3CacheConfig) IsSharedMode() bool {
	return s.SharedMode == nil || *s.SharedMode
}

// OutboundConfig configures the shared outbound HTTP client the proxy uses to
// fetch from upstreams: connection pooling, timeouts, the default TLS trust
// policy, and the User-Agent. It applies to every HTTP-based upstream unless an
// upstream supplies its own TLS override. Zero-valued fields fall back to the
// outbound client's built-in defaults.
type OutboundConfig struct {
	// UserAgent is sent on every outbound request. Empty uses the built-in
	// default.
	UserAgent string `yaml:"userAgent"`
	// DialTimeout bounds establishing a TCP connection to an upstream.
	DialTimeout time.Duration `yaml:"dialTimeout"`
	// ResponseHeaderTimeout bounds waiting for upstream response headers.
	ResponseHeaderTimeout time.Duration `yaml:"responseHeaderTimeout"`
	// IdleConnTimeout bounds how long idle keep-alive connections are retained.
	IdleConnTimeout time.Duration `yaml:"idleConnTimeout"`
	// TLSHandshakeTimeout bounds the outbound TLS handshake.
	TLSHandshakeTimeout time.Duration `yaml:"tlsHandshakeTimeout"`
	// MaxIdleConns and MaxIdleConnsPerHost bound the connection pool. They default
	// to 100 and 16 respectively. Under high client concurrency against a small
	// number of upstreams, raising MaxIdleConnsPerHost is the single most effective
	// knob for connection reuse: when it is too low, idle keep-alive connections
	// are closed instead of pooled and the next request must redial.
	MaxIdleConns        int `yaml:"maxIdleConns"`
	MaxIdleConnsPerHost int `yaml:"maxIdleConnsPerHost"`
	// MaxConnsPerHost bounds the total connections (active + idle) per upstream
	// host. 0 (the default) means unlimited, letting the upstream rather than a
	// client-side cap govern throughput; set a positive value to shield a fragile
	// upstream from connection storms.
	MaxConnsPerHost int `yaml:"maxConnsPerHost"`
	// KeepAlive is the TCP keep-alive probe interval for outbound connections.
	// Empty uses the built-in default (30s); a negative value disables keep-alive
	// probes. This governs dead-peer detection, not connection reuse.
	KeepAlive time.Duration `yaml:"keepAlive"`
	// ExpectContinueTimeout bounds waiting for an upstream's 100-continue response
	// after sending request headers with Expect: 100-continue. Empty defaults to
	// 1s.
	ExpectContinueTimeout time.Duration `yaml:"expectContinueTimeout"`
	// DisableKeepAlives, when true, disables connection reuse entirely: every
	// request dials a fresh connection and closes it afterward. Intended for
	// debugging; it defeats the connection pool and should stay false in
	// production.
	DisableKeepAlives bool `yaml:"disableKeepAlives"`
	// DisableHTTP2, when true, suppresses the opportunistic HTTP/2 upgrade on TLS
	// upstreams (the transport otherwise sets ForceAttemptHTTP2). Use only to work
	// around an upstream with a broken HTTP/2 implementation.
	DisableHTTP2 bool `yaml:"disableHTTP2"`
	// TLS is the default outbound TLS trust policy.
	TLS TLSConfig `yaml:"tls"`
}

// TLSConfig configures outbound TLS verification for upstream connections. The
// empty value verifies upstream certificates against the system trust store
// with a TLS 1.2 floor.
type TLSConfig struct {
	// CACertFile is a PEM bundle of additional root CAs trusted for verifying
	// upstream certificates, in addition to the system pool. Useful for private
	// registries fronted by an internal CA.
	CACertFile string `yaml:"caCertFile"`
	// InsecureSkipVerify disables upstream certificate verification. It is unsafe
	// and intended only for testing against self-signed endpoints.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// MinVersion is the minimum acceptable TLS version: "1.0", "1.1", "1.2", or
	// "1.3". Empty defaults to "1.2".
	MinVersion string `yaml:"minVersion"`
	// Pins, when non-empty, enables certificate/CA pinning for connections
	// governed by this TLS policy (Task 128): the peer's certificate chain must
	// match at least one pin in addition to passing ordinary verification, so a
	// MITM or mis-issued/compromised-CA certificate that still chains to a trusted
	// root is rejected. List multiple pins (e.g. current + next) to stage a key or
	// CA rotation without downtime. Each entry is "<kind>:<sha256>" where kind is:
	//
	//	spki-sha256  SHA-256 of the leaf cert's DER SubjectPublicKeyInfo (RFC 7469;
	//	             recommended — survives re-issue under the same key)
	//	cert-sha256  SHA-256 of the full DER leaf certificate (strictest)
	//	ca-sha256    SHA-256 of a DER CA certificate that must appear in the chain
	//	             (survives leaf rotation under the same CA)
	//
	// The hash is 64 hex characters or the base64 of 32 raw bytes; the RFC 7469
	// "sha256//<base64>" syntax is accepted as an alias for spki-sha256. Pinning
	// is most meaningful as a per-upstream (or per-mirror) override; a global pin
	// under outbound.tls would apply to every host and is rarely useful.
	Pins []string `yaml:"pins"`
	// PinReportOnly, when true, logs/audits/counts pin mismatches (and raises an
	// alert) but still allows the connection, so a candidate pin set can be
	// validated against live traffic before enforcement. Default false (enforce,
	// fail-closed). Ignored when Pins is empty.
	PinReportOnly bool `yaml:"pinReportOnly"`
}

// EgressConfig configures the SSRF / outbound-egress guard (Task 89). The empty
// value is a disabled guard; Default() enables it with secure settings (https-
// only, private-network block, 5-hop redirect cap). The host allowlist is
// optional: an empty Allowlist enforces only the scheme and IP-range floors
// (already blocking SSRF-to-internal while permitting any public host), and a
// non-empty Allowlist switches the guard to deny-by-default for hosts.
type EgressConfig struct {
	// Enabled activates the guard. When false the proxy fetches with no egress
	// validation (the historical behavior).
	Enabled bool `yaml:"enabled"`
	// HTTPSOnly restricts outbound fetches to https. Ignored when AllowedSchemes is
	// set. Defaults to true.
	HTTPSOnly bool `yaml:"httpsOnly"`
	// AllowedSchemes is an explicit scheme allowlist (e.g. ["https","http"]). When
	// empty, the policy is https-only if HTTPSOnly, else https+http.
	AllowedSchemes []string `yaml:"allowedSchemes"`
	// Allowlist is the global host/domain/CIDR allowlist. Entries may be an exact
	// host ("registry.npmjs.org"), a domain suffix (".npmjs.org" or "*.npmjs.org"),
	// or a CIDR / IP literal ("10.0.0.0/8", "192.0.2.1").
	Allowlist []string `yaml:"allowlist"`
	// BlockPrivateNetworks denies any request resolving to a private, link-local,
	// loopback, unique-local, CGNAT, unspecified, multicast, or cloud-metadata IP.
	// Defaults to true.
	BlockPrivateNetworks bool `yaml:"blockPrivateNetworks"`
	// AllowedDestinationCIDRs are explicit exceptions to BlockPrivateNetworks, for
	// an operator fronting an internal mirror at a known private range.
	AllowedDestinationCIDRs []string `yaml:"allowedDestinationCidrs"`
	// FollowRedirects permits following upstream redirects (each hop re-checked).
	// Defaults to true.
	FollowRedirects bool `yaml:"followRedirects"`
	// MaxRedirects caps the redirect chain. Zero uses the built-in default (5).
	MaxRedirects int `yaml:"maxRedirects"`
	// Tenants maps a tenant (auth team) to a per-tenant policy override.
	Tenants map[string]EgressTenantConfig `yaml:"tenants"`
}

// EgressTenantConfig overrides the egress policy for one tenant. The allowlist is
// additive to the global allowlist; the IP-range floor is always instance-global.
type EgressTenantConfig struct {
	// Allowlist adds permitted host/domain/CIDR entries for this tenant.
	Allowlist []string `yaml:"allowlist"`
	// HTTPSOnly, when set, overrides the global scheme policy for this tenant.
	HTTPSOnly *bool `yaml:"httpsOnly"`
}

// UpstreamConfig describes a single upstream registry/repository to proxy.
type UpstreamConfig struct {
	// Type is the protocol/backend type:
	// git|pip|npm|cargo|go|nuget|maven|rubygems|composer|helm|apt|deb|yum|rpm|docker|terraform|conan|conda|cran|hex|bazel|julia|cpan|swift|dart|pub|huggingface|openvsx|nix|jsr|hackage|homebrew|ansible|puppet|generic.
	// "generic" is a config-driven pull-through backend for ecosystems without a
	// dedicated adapter; it requires a `generic:` block (see the Generic field).
	Type string `yaml:"type"`
	// URL is the upstream base URL.
	URL string `yaml:"url"`
	// Credentials authenticate to the upstream when required.
	Credentials Credentials `yaml:"credentials"`
	// TLS, when set, overrides the global Outbound.TLS policy for this upstream
	// (e.g. a private mirror that uses an internal CA). Upstreams that share the
	// same effective TLS policy also share a connection pool.
	TLS *TLSConfig `yaml:"tls"`
	// Enabled allows disabling an upstream without removing its config.
	Enabled *bool `yaml:"enabled"`
	// Mirrors is an optional ordered list of additional, equivalent upstream
	// endpoints (registry/index mirrors). When non-empty the upstream's URL is the
	// primary (highest-priority) endpoint and these are consulted in order on
	// failover. Each mirror must serve content-addressable bytes identical to the
	// primary; the proxy's digest verification holds regardless of which mirror
	// served them. Applies to the HTTP package ecosystems and Docker/OCI; ignored
	// for git upstreams.
	Mirrors []MirrorConfig `yaml:"mirrors"`
	// Failover tunes the per-endpoint circuit breaker and active health probing
	// used when Mirrors is set. Optional; sensible defaults apply.
	Failover FailoverConfig `yaml:"failover"`
	// Settings carries optional ecosystem-specific tuning keyed by a documented
	// string. All keys have sensible defaults so this is usually omitted. Known
	// keys:
	//
	//	pip:   "filesUrl"    artifact host base (default https://files.pythonhosted.org)
	//	       "fileHosts"   comma-separated allowlist of artifact hosts to proxy
	//	cargo: "downloadUrl" crate download host base (default https://crates.io)
	//	helm:  "oci"         "true" to serve OCI-registry-hosted charts
	//	                     (helm pull oci://) instead of the classic chart-
	//	                     repository protocol (index.yaml + .tgz)
	//	apt:   "gpgKeyFile"  path to an ASCII-armored public keyring that the
	//	                     Debian/APT Release (InRelease/Release.gpg) signature is
	//	                     validated against; "gpgKey" supplies the key inline.
	//	yum:   "gpgKeyFile"  path to an ASCII-armored public keyring that the
	//	                     RPM/YUM repomd.xml (repomd.xml.asc) signature is
	//	                     validated against; "gpgKey" supplies the key inline.
	//	nix:   "trustedPublicKeys"
	//	                     Nix binary-cache signing keys (each "name:base64", in the
	//	                     nix.conf trusted-public-keys form) that a narinfo's
	//	                     ed25519 signature is verified against; space-, comma- or
	//	                     newline-separated. When unset, narinfos are served
	//	                     without signature verification.
	//	homebrew: "bottleRegistryUrl"
	//	                     OCI registry base Homebrew bottles are fetched from
	//	                     (default https://ghcr.io); only bottle URLs on this host
	//	                     are rewritten through the proxy.
	//
	// See the internal/backends/pkgmgr package for the full set.
	Settings map[string]string `yaml:"settings"`
	// Generic holds the declarative route definition for an upstream of
	// Type "generic" (Task 147): a config-driven pull-through backend for an
	// ecosystem that has no dedicated adapter. It is required for (and only used
	// by) type "generic" and is validated at load time (bad regexps, incoherent
	// verify rules, unknown gate names, and rewrite-plus-cacheable routes are
	// rejected before rollout). See internal/backends/generic and
	// docs/generic-backend.md.
	Generic *generic.BackendConfig `yaml:"generic"`
}

// MirrorConfig describes one additional upstream endpoint that mirrors the
// primary URL of an UpstreamConfig (Task 38). Mirrors are tried in declaration
// order after the primary when health-aware failover kicks in.
type MirrorConfig struct {
	// ID is a stable label for the mirror in metrics and the admin API. When
	// empty it defaults to the URL's host.
	ID string `yaml:"id"`
	// URL is the mirror's base URL. Required.
	URL string `yaml:"url"`
	// Credentials, when set, authenticate to this mirror specifically (overriding
	// the upstream's credentials). Leave empty to inherit the upstream's
	// credentials, which is correct when mirrors share an account or are public.
	Credentials Credentials `yaml:"credentials"`
	// TLS, when set, overrides the outbound TLS policy for this mirror (e.g. a
	// private mirror behind an internal CA). When empty the mirror shares the
	// primary upstream's effective TLS policy and connection pool.
	TLS *TLSConfig `yaml:"tls"`
}

// FailoverConfig tunes the upstream circuit breaker and optional active health
// probing for an upstream that declares mirrors (Task 38). All fields are
// optional; zero values fall back to the upstreampool package defaults.
type FailoverConfig struct {
	// FailureThreshold is the number of consecutive failed requests that trips a
	// mirror's circuit breaker open (default 5).
	FailureThreshold int `yaml:"failureThreshold"`
	// SuccessThreshold is the number of consecutive successful trial requests in
	// the half-open state that closes the breaker (default 2).
	SuccessThreshold int `yaml:"successThreshold"`
	// OpenTimeout is how long a breaker stays open before admitting a half-open
	// trial request (default 30s).
	OpenTimeout time.Duration `yaml:"openTimeout"`
	// HalfOpenMaxProbes bounds the concurrent trial requests admitted while a
	// breaker is half-open (default 1).
	HalfOpenMaxProbes int `yaml:"halfOpenMaxProbes"`
	// Probe configures optional lightweight active health probing.
	Probe ProbeConfig `yaml:"probe"`
}

// ProbeConfig configures optional active health probing of mirror endpoints
// (Task 38). When disabled, health is tracked passively from real request
// outcomes only.
type ProbeConfig struct {
	// Enabled turns on background active probing.
	Enabled bool `yaml:"enabled"`
	// Interval is the time between probe sweeps (default 15s).
	Interval time.Duration `yaml:"interval"`
	// Timeout bounds a single probe request (default 5s).
	Timeout time.Duration `yaml:"timeout"`
	// Path is the request path probed on each endpoint base (default "/"). For an
	// OCI registry the version-probe endpoint "/v2/" is a good lightweight choice.
	Path string `yaml:"path"`
}

// Credentials holds upstream authentication material. Values support
// ${ENV_VAR} expansion so secrets can be injected from the environment.
type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Token    string `yaml:"token"`
}

// GitConfig configures the Git pull-through proxy (smart HTTP + SSH).
type GitConfig struct {
	// MirrorDir enables mirror-mode caching. When set (and the git binary is
	// available), the proxy maintains local bare mirrors so packs/objects are
	// cached, and the SSH endpoint can serve from them. Empty disables mirroring:
	// HTTP smart requests stream straight through to the HTTPS upstream and the
	// SSH endpoint is unavailable.
	MirrorDir string `yaml:"mirrorDir"`
	// RefreshInterval bounds how often a mirror is refreshed from upstream; within
	// the window cached refs/objects are served without contacting upstream.
	// Defaults to 1 minute when zero.
	RefreshInterval time.Duration `yaml:"refreshInterval"`
	// FetchTimeout bounds a single clone/fetch from upstream (default 10m).
	FetchTimeout time.Duration `yaml:"fetchTimeout"`
	// InfoRefsTTL caches smart-HTTP ref advertisements in pass-through (non-mirror)
	// mode for this duration. 0 disables advertisement caching.
	InfoRefsTTL time.Duration `yaml:"infoRefsTtl"`
	// GitBinary overrides the git executable path (default: "git" on PATH).
	GitBinary string `yaml:"gitBinary"`
	// SSH configures the inbound Git-over-SSH endpoint. It is active only when
	// server.sshAddr is set and mirroring is enabled.
	SSH GitSSHConfig `yaml:"ssh"`
	// LFS configures transparent Git LFS (Large File Storage) pull-through and
	// large-object caching over the smart-HTTP endpoint.
	LFS GitLFSConfig `yaml:"lfs"`
}

// GitLFSConfig configures the Git LFS batch-API proxy and content-addressable
// large-object cache (Task 123). When enabled, the proxy negotiates the LFS
// batch API with upstream, rewrites download actions to point back at itself,
// and streams LFS blobs through the cache keyed by their sha256 OID, verifying
// OID and size on fetch.
type GitLFSConfig struct {
	// Enabled turns on Git LFS proxying for git upstreams. When false the
	// /info/lfs/* endpoints are not served (clients fall back to a plain clone
	// error) and no LFS objects are cached. Defaults to false.
	Enabled bool `yaml:"enabled"`
	// MaxObjectBytes caps the size of a single LFS object the proxy will fetch
	// and cache. A larger object is refused rather than cached. 0 selects the
	// built-in default (5 GiB). Negative is invalid.
	MaxObjectBytes int64 `yaml:"maxObjectBytes"`
	// ScanMaxBytes bounds how many bytes of a freshly-fetched LFS blob are run
	// through the commit-scan content gates (e.g. secret detection). Blobs larger
	// than this are cached and served but not content-scanned, so a pathological
	// multi-gigabyte binary cannot stall the pull path. 0 selects the built-in
	// default (5 MiB). Negative is invalid.
	ScanMaxBytes int64 `yaml:"scanMaxBytes"`
	// BlockOnFindings makes the content gate fail closed: when the scan of an LFS
	// blob yields any finding (e.g. an embedded secret) the object is refused and
	// evicted from the cache rather than served with the finding recorded.
	// Defaults to false (findings are recorded/metered but the object is served).
	BlockOnFindings bool `yaml:"blockOnFindings"`
}

// GitSSHConfig configures the inbound Git-over-SSH endpoint.
type GitSSHConfig struct {
	// HostKeyFile is the PEM-encoded server host key. When empty an ephemeral key
	// is generated at startup (set this in production for a stable host key).
	HostKeyFile string `yaml:"hostKeyFile"`
	// AuthorizedKeysFile is an OpenSSH authorized_keys file of permitted client
	// public keys.
	AuthorizedKeysFile string `yaml:"authorizedKeysFile"`
	// AuthorizedKeys is an inline list of OpenSSH-format client public keys.
	AuthorizedKeys []string `yaml:"authorizedKeys"`
	// NoClientAuth disables client authentication (trusted networks only). The
	// proxy is read-only regardless.
	NoClientAuth bool `yaml:"noClientAuth"`
}

// ScanningConfig configures the security scanning pipeline.
type ScanningConfig struct {
	Enabled bool `yaml:"enabled"`
	// Provider selects the LLM provider: "claude", "codex", or "none".
	Provider string `yaml:"provider"`
	// Model is the provider-specific model identifier. For LLM commit scanning it
	// is superseded by Commit.TriageModel / Commit.DeepModel; kept for backward
	// compatibility and other scanner types.
	Model string `yaml:"model"`
	// APIKey authenticates to the LLM provider (supports ${ENV_VAR}).
	APIKey string `yaml:"apiKey"`
	// BaseURL optionally overrides the provider API endpoint (e.g. a gateway).
	BaseURL string `yaml:"baseUrl"`
	// APIVersion selects Azure OpenAI mode for the "openai" provider: the value is
	// sent as the "api-version" query parameter and the key via the "api-key"
	// header. Ignored by other providers.
	APIVersion string `yaml:"apiVersion"`
	// ReasoningEffort, for the "openai" provider, is forwarded as
	// "reasoning_effort" (e.g. "low"/"medium"/"high") on the deep (Thinking) pass
	// for OpenAI reasoning models. Empty omits it. Ignored by other providers.
	ReasoningEffort string `yaml:"reasoningEffort"`
	// Timeout bounds a single provider HTTP attempt. Zero uses the provider
	// default. Applies to the "openai" provider.
	Timeout time.Duration `yaml:"timeout"`
	// FailOn is the minimum severity that blocks admission:
	// info|low|medium|high|critical.
	FailOn string `yaml:"failOn"`
	// Commit configures the LLM-backed Git commit scanning pipeline (Task 7).
	Commit CommitScanConfig `yaml:"commit"`
	// Secrets configures the deterministic secret/credential-detection pass that
	// augments commit scanning (Task 29). It runs offline alongside the LLM call
	// and feeds the policy gate, so live credentials in a commit can block the
	// associated package/Docker pulls even when no LLM is available.
	Secrets SecretScanConfig `yaml:"secrets"`
	// Actions configures the deterministic GitHub Actions pinning / provenance
	// gate (Task 115). It runs offline alongside the commit scan, parsing the
	// `uses:` references in changed .github/workflows/*.yml and composite
	// action.yml files and flagging/blocking actions pinned to mutable refs
	// (branches or floating tags) rather than full commit SHAs, plus references to
	// disallowed owners when an allowlist is configured.
	Actions ActionPinConfig `yaml:"actions"`
	// Watch configures the continuous webhook/polling-driven incremental Git
	// commit scanner (Task 108): it watches a set of repositories, detects new
	// commits via a push webhook and/or polling, and scans only the commits not
	// already scanned, persisting a per-repo cursor so progress survives restarts.
	Watch GitScanConfig `yaml:"watch"`
}

// ActionPinConfig configures the GitHub Actions pinning / provenance gate
// (Task 115). It inspects the `uses:` references in a commit's changed workflow
// and composite-action files and enforces supply-chain hygiene on them.
type ActionPinConfig struct {
	// Enabled turns on the gate. When nil it defaults to whether commit scanning
	// is enabled (the gate is cheap and offline, like the secret pass).
	Enabled *bool `yaml:"enabled"`
	// FailSeverity is the minimum finding severity that triggers Action (block or
	// warn): info|low|medium|high|critical. Default "high" — a disallowed owner
	// (high) blocks while a mutable-ref pin (medium) only warns.
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold. Default "medium". Empty disables warnings.
	WarnSeverity string `yaml:"warnSeverity"`
	// Action is applied when a finding meets FailSeverity: "block" or "warn".
	// Default "block".
	Action string `yaml:"action"`
	// RequirePinning enables the pinning-hygiene checks (mutable-ref / unpinned).
	// When nil it defaults to true. Set false to enforce only the owner allowlist.
	RequirePinning *bool `yaml:"requirePinning"`
	// AllowedOwners is the optional allowlist of permitted action owners/orgs
	// (case-insensitive, e.g. "actions", "github"). Empty permits any owner; a
	// reference to an owner not in a non-empty list is flagged/blocked.
	AllowedOwners []string `yaml:"allowedOwners"`
	// MaxFindings caps the findings recorded per commit (0 => default 200).
	MaxFindings int `yaml:"maxFindings"`
	// Tenants holds per-tenant threshold/action overrides keyed by tenant id.
	Tenants map[string]ActionPinTenantConfig `yaml:"tenants"`
}

// ActionPinTenantConfig overrides the gate's thresholds for a single tenant.
type ActionPinTenantConfig struct {
	FailSeverity string `yaml:"failSeverity"`
	WarnSeverity string `yaml:"warnSeverity"`
	Action       string `yaml:"action"`
}

// GitScanConfig configures continuous, incremental Git commit scanning (Task 108).
type GitScanConfig struct {
	// Enabled turns on the continuous watcher. It requires the commit-scanning
	// pipeline to be available (an LLM provider and/or the deterministic secret
	// detector) and the git binary for commit enumeration.
	Enabled bool `yaml:"enabled"`
	// StateDir is the directory for persistent per-repository scan cursors. Empty
	// keeps cursors in memory only (lost on restart, re-baselining each repo).
	StateDir string `yaml:"stateDir"`
	// MirrorDir is the directory under which the watcher keeps bare mirrors of the
	// watched repositories for commit enumeration. Required when Enabled.
	MirrorDir string `yaml:"mirrorDir"`
	// PollInterval is the period between polling sweeps of every watched repo.
	// Zero disables polling (webhook-only operation).
	PollInterval time.Duration `yaml:"pollInterval"`
	// MaxCommitsPerScan caps the commits scanned for one repo in one cycle. Zero
	// defaults to 500. Remaining history is picked up on subsequent cycles.
	MaxCommitsPerScan int `yaml:"maxCommitsPerScan"`
	// Backfill, when true, scans a repository's history on first sighting (bounded
	// by MaxCommitsPerScan per cycle). When false, a first sighting records the
	// current tips without scanning history (only later commits are scanned).
	Backfill bool `yaml:"backfill"`
	// WebhookSecret is the shared secret for GitHub-style HMAC-SHA256 payload
	// signature verification (the X-Hub-Signature-256 header; supports ${ENV_VAR}).
	// Empty disables verification, strongly discouraged outside a trusted network.
	WebhookSecret string `yaml:"webhookSecret"`
	// WebhookPath is the HTTP path the push-webhook receiver is mounted at.
	// Defaults to "/webhooks/git". It sits outside the /v1 client access-control
	// envelope and is authenticated by the HMAC signature.
	WebhookPath string `yaml:"webhookPath"`
	// AllowUnconfiguredWebhooks, when true, lets a push webhook for a repository
	// not listed in Repos be scanned ad hoc. Off by default so the watcher only
	// ever touches an explicitly allowed set.
	AllowUnconfiguredWebhooks bool `yaml:"allowUnconfiguredWebhooks"`
	// Repos is the set of watched repositories.
	Repos []WatchRepoConfig `yaml:"repos"`
}

// WatchRepoConfig is one repository the continuous commit scanner watches.
type WatchRepoConfig struct {
	// Name is the stable identifier for the repo in cursors, findings, logs, and
	// webhook routing. Required and unique.
	Name string `yaml:"name"`
	// URL is the clone URL (HTTPS or SSH). Required.
	URL string `yaml:"url"`
	// Branches restricts scanning to these branch short-names (e.g. ["main"]).
	// Empty tracks the repository's default branch.
	Branches []string `yaml:"branches"`
	// FullName is the "owner/repo" slug used to route an inbound GitHub webhook to
	// this repo (matched against repository.full_name) in addition to the URL.
	FullName string `yaml:"fullName"`
	// Username and Token are optional HTTPS credentials (support ${ENV_VAR}),
	// injected when fetching and never logged or sent to the model.
	Username string `yaml:"username"`
	Token    string `yaml:"token"`
}

// validate checks the continuous-commit-scanning configuration. It is a no-op
// when disabled.
func (g GitScanConfig) validate() error {
	if !g.Enabled {
		return nil
	}
	if g.PollInterval < 0 {
		return fmt.Errorf("config: scanning.watch.pollInterval must not be negative")
	}
	if g.MaxCommitsPerScan < 0 {
		return fmt.Errorf("config: scanning.watch.maxCommitsPerScan must not be negative")
	}
	if g.WebhookPath != "" && !strings.HasPrefix(g.WebhookPath, "/") {
		return fmt.Errorf("config: scanning.watch.webhookPath must start with %q", "/")
	}
	if strings.TrimSpace(g.MirrorDir) == "" {
		return fmt.Errorf("config: scanning.watch.mirrorDir is required when the watcher is enabled")
	}
	names := make(map[string]bool, len(g.Repos))
	for i, r := range g.Repos {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("config: scanning.watch.repos[%d] is missing a name", i)
		}
		if names[r.Name] {
			return fmt.Errorf("config: scanning.watch.repos: duplicate name %q", r.Name)
		}
		names[r.Name] = true
		if strings.TrimSpace(r.URL) == "" {
			return fmt.Errorf("config: scanning.watch.repos[%q] is missing a url", r.Name)
		}
	}
	if len(g.Repos) == 0 && !g.AllowUnconfiguredWebhooks {
		return fmt.Errorf("config: scanning.watch is enabled but has no repos (and allowUnconfiguredWebhooks is false)")
	}
	return nil
}

// SecretScanConfig configures the deterministic secret-detection pass (Task 29).
type SecretScanConfig struct {
	// Enabled turns on deterministic secret detection. When nil it defaults to
	// enabled wherever commit scanning is enabled (it is cheap and offline);
	// set it explicitly to false to disable.
	Enabled *bool `yaml:"enabled"`
	// DisableBuiltinRules drops the built-in high-confidence ruleset so only
	// Rules apply.
	DisableBuiltinRules bool `yaml:"disableBuiltinRules"`
	// Rules is an additional/override ruleset loaded from config. A rule whose ID
	// matches a built-in replaces it.
	Rules []SecretRuleConfig `yaml:"rules"`
	// Entropy configures the generic Shannon-entropy heuristic.
	Entropy SecretEntropyConfig `yaml:"entropy"`
	// Allowlist suppresses known false positives and test fixtures.
	Allowlist SecretAllowlistConfig `yaml:"allowlist"`
	// RevealPrefix is how many leading characters of a secret are kept when
	// redacting a finding (0..8; default 4).
	RevealPrefix int `yaml:"revealPrefix"`
	// MaxFindingsPerFile caps findings per file (0 = default 100).
	MaxFindingsPerFile int `yaml:"maxFindingsPerFile"`
}

// validate checks the secret-detection configuration: severities, and that
// every configured rule has an ID and a compilable pattern with non-negative
// group, plus that allowlist regexes compile. It is a no-op when disabled.
func (s SecretScanConfig) validate() error {
	if s.Enabled != nil && !*s.Enabled {
		return nil
	}
	validSev := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "info", "low", "medium", "high", "critical":
			return nil
		default:
			return fmt.Errorf("config: invalid %s %q", field, v)
		}
	}
	if err := validSev("scanning.secrets.entropy.severity", s.Entropy.Severity); err != nil {
		return err
	}
	ids := make(map[string]bool, len(s.Rules))
	for i, r := range s.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("config: scanning.secrets.rules[%d] is missing an id", i)
		}
		if ids[r.ID] {
			return fmt.Errorf("config: scanning.secrets.rules: duplicate id %q", r.ID)
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("config: scanning.secrets.rules[%q] is missing a pattern", r.ID)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("config: scanning.secrets.rules[%q] has an invalid pattern: %w", r.ID, err)
		}
		if r.Group < 0 {
			return fmt.Errorf("config: scanning.secrets.rules[%q] has a negative group", r.ID)
		}
		if err := validSev(fmt.Sprintf("scanning.secrets.rules[%q].severity", r.ID), r.Severity); err != nil {
			return err
		}
	}
	for i, p := range s.Allowlist.Paths {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("config: scanning.secrets.allowlist.paths[%d] (%q): %w", i, p, err)
		}
	}
	for i, p := range s.Allowlist.Patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("config: scanning.secrets.allowlist.patterns[%d] (%q): %w", i, p, err)
		}
	}
	return nil
}

// SecretRuleConfig is a configurable secret-detection rule.
type SecretRuleConfig struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Pattern     string   `yaml:"pattern"`
	Group       int      `yaml:"group"`
	Keywords    []string `yaml:"keywords"`
	MinEntropy  float64  `yaml:"minEntropy"`
}

// SecretEntropyConfig configures the generic high-entropy heuristic.
type SecretEntropyConfig struct {
	// Enabled toggles the heuristic; when nil it defaults to on.
	Enabled       *bool   `yaml:"enabled"`
	MinLength     int     `yaml:"minLength"`
	MaxLength     int     `yaml:"maxLength"`
	Base64Entropy float64 `yaml:"base64Entropy"`
	HexEntropy    float64 `yaml:"hexEntropy"`
	Severity      string  `yaml:"severity"`
}

// SecretAllowlistConfig suppresses known false positives for secret detection.
type SecretAllowlistConfig struct {
	// DisableBuiltins drops the built-in fixture-path and placeholder patterns.
	DisableBuiltins bool `yaml:"disableBuiltins"`
	// Paths are regexes matched against the file path.
	Paths []string `yaml:"paths"`
	// Patterns are regexes matched against the raw matched secret.
	Patterns []string `yaml:"patterns"`
	// StopWords are case-insensitive substrings that exempt a whole line.
	StopWords []string `yaml:"stopWords"`
	// Fingerprints is a baseline of accepted finding fingerprints to suppress.
	Fingerprints []string `yaml:"fingerprints"`
}

// CommitScanConfig tunes the LLM Git-commit scanning pipeline.
type CommitScanConfig struct {
	// TriageModel is the cheap model used to triage every commit; DeepModel is
	// the capable model used when triage escalates. Empty values fall back to the
	// pipeline defaults (Claude Haiku for triage, Claude Opus for deep analysis).
	TriageModel string `yaml:"triageModel"`
	DeepModel   string `yaml:"deepModel"`
	// EscalateAtScore is the triage risk score (0-100) at or above which deep
	// analysis runs. 0 always escalates; >100 never does.
	EscalateAtScore int `yaml:"escalateAtScore"`
	// MaxDiffTokens is the per-request token budget; larger diffs are chunked.
	MaxDiffTokens int `yaml:"maxDiffTokens"`
	// MaxChunks caps chunks per commit (0 = unbounded).
	MaxChunks int `yaml:"maxChunks"`
	// MaxRetries bounds transient-error retries per provider call.
	MaxRetries int `yaml:"maxRetries"`
	// Workers is the number of asynchronous scan workers; QueueSize bounds the
	// async submission queue.
	Workers   int `yaml:"workers"`
	QueueSize int `yaml:"queueSize"`
	// StoreDir is the directory for persistent verdict storage. Empty keeps
	// verdicts in memory only (lost on restart).
	StoreDir string `yaml:"storeDir"`

	// InjectionRiskFloor is the minimum risk score a detected prompt-injection
	// attempt in a commit raises the verdict to (Task 78). 0 uses the built-in
	// default (50).
	InjectionRiskFloor int `yaml:"injectionRiskFloor"`

	// RetentionTTL prunes cached verdicts older than this age on a schedule,
	// complementing the cache retention engine (Task 39/78). 0 disables pruning.
	RetentionTTL time.Duration `yaml:"retentionTtl"`
	// RetentionInterval is the period between verdict-retention sweeps; defaults
	// to 1h when RetentionTTL is set.
	RetentionInterval time.Duration `yaml:"retentionInterval"`

	// Consensus lists additional providers that participate in the deep
	// (escalated) pass for multi-provider quorum (Task 78). When non-empty, a
	// 'malicious' verdict only blocks a pull when a quorum of providers agree.
	Consensus []ConsensusProviderConfig `yaml:"consensus"`
	// Quorum is the minimum number of agreeing malicious votes required to block
	// under consensus. 0 defaults to a strict majority of the participating
	// providers (primary + consensus members).
	Quorum int `yaml:"quorum"`

	// Budget configures per-tenant token/cost budgeting for LLM scanning (Task 78).
	Budget CommitBudgetConfig `yaml:"budget"`
}

// ConsensusProviderConfig is one additional provider in a multi-provider
// consensus deep pass (Task 78).
type ConsensusProviderConfig struct {
	// Provider selects the LLM provider implementation ("claude"). Others are
	// reserved for future use.
	Provider string `yaml:"provider"`
	// Model is the model ID this consensus member uses for the deep pass.
	Model string `yaml:"model"`
	// APIKey authenticates to the provider (supports ${ENV_VAR}). Empty falls back
	// to the provider's default environment variable.
	APIKey string `yaml:"apiKey"`
	// BaseURL optionally overrides the provider API endpoint.
	BaseURL string `yaml:"baseUrl"`
}

// CommitBudgetConfig configures per-tenant token/cost budgeting (Task 78).
type CommitBudgetConfig struct {
	// Enabled turns on per-tenant cost budgeting.
	Enabled bool `yaml:"enabled"`
	// DefaultCeilingUSD is the per-tenant spend ceiling per window. 0 (with no
	// per-tenant override) means unlimited but still tracked.
	DefaultCeilingUSD float64 `yaml:"defaultCeilingUsd"`
	// TenantCeilingsUSD overrides DefaultCeilingUSD for specific tenants.
	TenantCeilingsUSD map[string]float64 `yaml:"tenantCeilingsUsd"`
	// Window is the rolling period after which a tenant's usage resets; defaults
	// to 24h.
	Window time.Duration `yaml:"window"`
	// FailOpen selects the exhaustion behavior: true admits the pull without an
	// LLM scan (relying on the deterministic passes); false blocks it (fail-closed).
	FailOpen bool `yaml:"failOpen"`
	// Pricing overrides the built-in per-model price table (USD per 1M tokens),
	// keyed by model ID.
	Pricing map[string]ModelPriceConfig `yaml:"pricing"`
}

// ModelPriceConfig is a per-model price override in USD per one million tokens.
type ModelPriceConfig struct {
	InputPerMTok  float64 `yaml:"inputPerMTok"`
	OutputPerMTok float64 `yaml:"outputPerMTok"`
}

// ProvenanceConfig configures provenance association.
type ProvenanceConfig struct {
	Enabled bool `yaml:"enabled"`
	// RequireAttested rejects artifacts lacking verified provenance.
	RequireAttested bool `yaml:"requireAttested"`
	// GitHubToken authenticates provenance lookups against GitHub
	// (supports ${ENV_VAR}).
	GitHubToken string `yaml:"githubToken"`
	// GitHubAPIBase overrides the GitHub API base URL (default
	// "https://api.github.com"); set for GitHub Enterprise.
	GitHubAPIBase string `yaml:"githubApiBase"`
	// StoreDir is the directory for persisting resolved package->commit links.
	// Empty keeps links in memory only (lost on restart).
	StoreDir string `yaml:"storeDir"`
	// TrustRootsFile is a PEM bundle of certificate authorities that signing
	// certificates must chain to for an attestation to be considered fully
	// attested (e.g. the Sigstore Fulcio root, or a corporate CA). When empty,
	// the system trust store is used; attestations whose signers do not chain to
	// a trusted root are downgraded to "claimed" confidence rather than rejected.
	TrustRootsFile string `yaml:"trustRootsFile"`
	// UseSystemTrustRoots, when true and TrustRootsFile is empty, uses the system
	// certificate pool as the attestation trust anchor. Defaults to false so chain
	// trust is only asserted against an explicitly configured root.
	UseSystemTrustRoots bool `yaml:"useSystemTrustRoots"`
	// Pins are operator-asserted package -> source-commit associations for
	// coordinates no attestation or registry metadata covers (most ecosystems
	// publish neither; internal packages often have no public metadata at all).
	// A pin is authoritative for the coordinates it matches and its commit's scan
	// verdict gates the package through the admission policy exactly as an
	// attested link would. It is an assertion, not evidence: a pinned link has
	// "claimed" confidence and never satisfies requireAttested.
	Pins []ProvenancePin `yaml:"pins"`
}

// ProvenancePin is one operator-asserted package -> source-commit association.
type ProvenancePin struct {
	// Ecosystem is the upstream type the pin applies to (e.g. "npm", "pip",
	// "docker"). Empty or "*" applies it to every ecosystem.
	Ecosystem string `yaml:"ecosystem"`
	// Name is the package name exactly as the backend reports it, matched
	// case-insensitively (e.g. "@scope/pkg", "org.apache.commons:commons-lang3",
	// "library/alpine"). Required; patterns are not accepted.
	Name string `yaml:"name"`
	// Version is the exact version the pin applies to. Empty or "*" applies it to
	// every version of the package.
	Version string `yaml:"version"`
	// Repository is the canonical source repository URL, shown next to the commit.
	Repository string `yaml:"repository"`
	// Commit is the full source commit hash (40 hex characters, or 64 for a
	// SHA-256 repository). Required.
	Commit string `yaml:"commit"`
}

// ProvgraphConfig configures the supply-chain provenance & dependency graph
// (Task 33).
type ProvgraphConfig struct {
	// Enabled turns on graph ingestion, the query/export admin API, and the
	// force-directed visualization. When false, no graph is built and the admin
	// surface reports the feature as disabled.
	Enabled bool `yaml:"enabled"`
}

// ComplianceConfig configures the continuous-compliance scorecard (Task 35).
type ComplianceConfig struct {
	// Enabled turns on periodic scorecard computation, the admin report endpoints,
	// the signed-export artifact, and the per-control Prometheus gauges. Enabled by
	// default: the scorecard is read-only and cheap, sampling the gates' existing
	// counters.
	Enabled bool `yaml:"enabled"`
	// Interval is how often the scorecard is recomputed in the background. Zero
	// uses a built-in default (5m). The scorecard is also computed once at startup.
	Interval time.Duration `yaml:"interval"`
	// MaxAuditSealAge bounds how stale the latest audit checkpoint may be before
	// the audit-transparency control warns (beyond it) and fails (beyond 2x). Zero
	// uses a built-in default (1h).
	MaxAuditSealAge time.Duration `yaml:"maxAuditSealAge"`
	// SigningKey is a PEM-encoded private key (inline or ${ENV}) used to sign the
	// exportable report artifact for auditors. ECDSA, RSA, and Ed25519 are
	// supported; the matching public key verifies the report.
	SigningKey string `yaml:"signingKey"`
	// SigningKeyFile is a path to the PEM signing key, used when SigningKey is
	// empty.
	SigningKeyFile string `yaml:"signingKeyFile"`
	// Controls holds per-control overrides keyed by control ID (e.g.
	// "signature-verification"). See internal/compliance.ControlConfig.
	Controls map[string]ComplianceControlConfig `yaml:"controls"`
}

// ComplianceControlConfig overrides one control on the scorecard. It mirrors
// internal/compliance.ControlConfig; the wiring layer translates it.
type ComplianceControlConfig struct {
	// Disabled removes the control from the scorecard entirely (status n/a).
	Disabled bool `yaml:"disabled"`
	// Required, when set, controls whether a disabled underlying subsystem fails
	// the control (true) or yields n/a (false). Unset keeps the built-in default.
	Required *bool `yaml:"required"`
	// Weight overrides the control's weight in the overall score (<=0 keeps the
	// default).
	Weight float64 `yaml:"weight"`
	// PassThreshold and WarnThreshold override the coverage thresholds (0 keeps the
	// default).
	PassThreshold float64 `yaml:"passThreshold"`
	WarnThreshold float64 `yaml:"warnThreshold"`
}

// RiskScoreConfig configures the unified risk-scoring engine (Task 37).
type RiskScoreConfig struct {
	// Enabled turns on scoring, the admin surface, the per-band Prometheus gauges,
	// and (when an action is configured) the admission threshold. Enabled by
	// default in observe-only mode: scoring is read-only and cheap, sampling the
	// signals the gates already produce, and never blocks until thresholdAction is
	// set to warn/block.
	Enabled bool `yaml:"enabled"`
	// HistorySize bounds the retained recent-assessment ring for the trend view.
	// Zero uses a built-in default.
	HistorySize int `yaml:"historySize"`
	// ThresholdBand is the minimum risk band that triggers ThresholdAction
	// (low|medium|high|critical). Empty uses a built-in default (high).
	ThresholdBand string `yaml:"thresholdBand"`
	// ThresholdAction is what to do at/above ThresholdBand (off|warn|block). Empty
	// uses off (observe-only).
	ThresholdAction string `yaml:"thresholdAction"`
	// Weights overrides the per-signal weighting model. A wholly-zero block keeps
	// the built-in default weights.
	Weights RiskScoreWeights `yaml:"weights"`
	// Bands overrides the score cutoffs for each band. A wholly-zero block keeps
	// the built-in defaults (25/50/75).
	Bands RiskScoreBands `yaml:"bands"`
	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]RiskScoreTenantConfig `yaml:"tenants"`
}

// RiskScoreWeights mirrors internal/riskscore.Weights; the wiring layer
// translates it. Weights are relative and normalized by the applicable signals.
type RiskScoreWeights struct {
	Vulnerability float64 `yaml:"vulnerability"`
	Signature     float64 `yaml:"signature"`
	License       float64 `yaml:"license"`
	Nameguard     float64 `yaml:"nameguard"`
	Secret        float64 `yaml:"secret"`
	Provenance    float64 `yaml:"provenance"`
	Quarantine    float64 `yaml:"quarantine"`
	InstallHooks  float64 `yaml:"installHooks"`
	RepoHealth    float64 `yaml:"repoHealth"`
	// LLMPackageScan weights the sandboxed LLM package-content scan verdict
	// (Task 173).
	LLMPackageScan float64 `yaml:"llmPackageScan"`
}

// RiskScoreBands mirrors internal/riskscore.BandThresholds (inclusive lower
// score bounds for the medium/high/critical bands).
type RiskScoreBands struct {
	Medium   int `yaml:"medium"`
	High     int `yaml:"high"`
	Critical int `yaml:"critical"`
}

// RiskScoreTenantConfig overrides the scoring model for a single tenant. A
// nil/zero sub-block inherits the global default for that part.
type RiskScoreTenantConfig struct {
	Weights         *RiskScoreWeights `yaml:"weights"`
	Bands           *RiskScoreBands   `yaml:"bands"`
	ThresholdBand   string            `yaml:"thresholdBand"`
	ThresholdAction string            `yaml:"thresholdAction"`
}

// RepoScoreConfig configures the source-repository health signal provider (Task
// 63). The wiring layer (cmd/pullthrough) translates it into
// internal/reposcore.Config. Repository health is derived from already-mirrored
// local clones, so it is offline/air-gap friendly; on-demand cloning of
// not-yet-mirrored source repositories is opt-in via AllowFetch.
type RepoScoreConfig struct {
	// Enabled turns on the provider, its admin surface, and the Prometheus
	// metrics. Off by default: it requires a writable cache directory and (for
	// most artifacts) on-demand cloning, so it is opt-in.
	Enabled bool `yaml:"enabled"`
	// CacheDir is the directory under which source-repository clones and their
	// derived facts are kept. Defaults to "<cacheDir>/reposcore" when empty.
	CacheDir string `yaml:"cacheDir"`
	// AllowFetch permits on-demand cloning of source repositories that are not yet
	// mirrored locally. Leave false for a strict air-gapped deployment, where only
	// repositories already present on disk are scored.
	AllowFetch bool `yaml:"allowFetch"`
	// Window bounds how many recent commits the history walk examines (default
	// 200).
	Window int `yaml:"window"`
	// CloneDepth bounds the shallow-clone history depth (default 256; negative
	// clones full history).
	CloneDepth int `yaml:"cloneDepth"`
	// CacheTTL is how long a derived report is reused (Go duration; default 6h).
	CacheTTL time.Duration `yaml:"cacheTtl"`
	// FetchTimeout bounds a single on-demand clone (Go duration; default 60s).
	FetchTimeout time.Duration `yaml:"fetchTimeout"`
	// AnalyzeTimeout bounds a single repository analysis (Go duration; default
	// 20s).
	AnalyzeTimeout time.Duration `yaml:"analyzeTimeout"`
	// GitBinary is the git executable (default "git").
	GitBinary string `yaml:"gitBinary"`
	// Weights overrides the per-sub-signal weighting model. A wholly-zero block
	// keeps the built-in defaults.
	Weights RepoScoreWeights `yaml:"weights"`
	// Tenants holds per-tenant weighting overrides keyed by tenant id (team).
	Tenants map[string]RepoScoreTenantConfig `yaml:"tenants"`
}

// RepoScoreWeights mirrors internal/reposcore.Weights; the wiring layer
// translates it. Weights are relative and normalized by the applicable signals.
type RepoScoreWeights struct {
	BranchProtection float64 `yaml:"branchProtection"`
	SignedCommits    float64 `yaml:"signedCommits"`
	CI               float64 `yaml:"ci"`
	SecurityPolicy   float64 `yaml:"securityPolicy"`
	Maintainers      float64 `yaml:"maintainers"`
	Activity         float64 `yaml:"activity"`
	DepAutomation    float64 `yaml:"depAutomation"`
}

// RepoScoreTenantConfig overrides the weighting model for a single tenant. A
// nil/zero sub-block inherits the global default.
type RepoScoreTenantConfig struct {
	Weights *RepoScoreWeights `yaml:"weights"`
}

// ExtensionConfig configures the WASM extensibility mechanism (Task 59). The
// wiring layer (cmd/pullthrough) translates it into internal/extension.Config. It
// is inert until at least one module is configured.
type ExtensionConfig struct {
	// Enabled gates whether the extension manager is built and wired as a gate.
	// On by default but inert: with no modules configured it does nothing.
	Enabled bool `yaml:"enabled"`
	// Defaults supplies the per-module resource-limit defaults applied to any
	// module that leaves a limit unset.
	Defaults ExtensionLimits `yaml:"defaults"`
	// Modules is the ordered set of extension modules; order is the per-tenant
	// evaluation order.
	Modules []ExtensionModuleConfig `yaml:"modules"`
}

// ExtensionLimits mirrors internal/extension.Limits with YAML-friendly,
// explicitly-unit-suffixed fields. A zero field inherits the built-in default.
type ExtensionLimits struct {
	// TimeoutMs is the per-invocation wall-clock CPU/time budget in milliseconds.
	TimeoutMs int `yaml:"timeoutMs"`
	// MemoryBytes caps the module's linear memory (rounded up to 64 KiB pages).
	MemoryBytes int64 `yaml:"memoryBytes"`
	// Fuel is the optional function-call budget; zero disables fuel metering.
	Fuel int64 `yaml:"fuel"`
	// MaxOutputBytes caps the verdict bytes read back from a module.
	MaxOutputBytes int `yaml:"maxOutputBytes"`
}

// ExtensionModuleConfig describes one operator-supplied extension module.
type ExtensionModuleConfig struct {
	// Name is the module's stable identifier (metrics label, audit detail, admin).
	Name string `yaml:"name"`
	// Path is the filesystem path to the module's .wasm binary.
	Path string `yaml:"path"`
	// Tenants restricts the module to the listed tenant ids (team names); empty
	// applies it to every tenant.
	Tenants []string `yaml:"tenants"`
	// FailClosed blocks the artifact when the module times out, exhausts fuel,
	// traps, or returns a malformed verdict; false (the default) fails open.
	FailClosed bool `yaml:"failClosed"`
	// Limits overrides the resource envelope for this module.
	Limits ExtensionLimits `yaml:"limits"`
}

// AnomalyConfig configures behavioral anomaly detection on pull traffic (Task
// 43). It is on by default in observe-only mode (warn-level notifications, no
// soft-blocking) so it is non-disruptive until an operator opts into blocking.
type AnomalyConfig struct {
	// Enabled turns on the detectors, the admin surface, the per-detector
	// Prometheus metrics, and (when blockLevel is set) the soft-block gate.
	Enabled bool `yaml:"enabled"`
	// Window is the trailing duration over which the rolling-window detectors
	// aggregate (e.g. "1m"). Zero uses a built-in default (1m).
	Window time.Duration `yaml:"window"`
	// WarnLevel is the minimum anomaly level that emits a graded notification
	// (low|medium|high). Empty uses a built-in default (medium).
	WarnLevel string `yaml:"warnLevel"`
	// BlockLevel is the minimum anomaly level at which an offending identity is
	// soft-blocked (HTTP 429). Empty or "none" disables soft-blocking entirely
	// (observe + notify only).
	BlockLevel string `yaml:"blockLevel"`
	// Thresholds overrides the per-detector cutoffs. A wholly-zero block keeps the
	// built-in defaults.
	Thresholds AnomalyThresholds `yaml:"thresholds"`
	// OffHoursStart/OffHoursEnd bound the off-hours interval as hours [0,23] in
	// the configured time zone. start == end disables off-hours detection; start >
	// end wraps past midnight (e.g. 20→6).
	OffHoursStart int `yaml:"offHoursStart"`
	OffHoursEnd   int `yaml:"offHoursEnd"`
	// Timezone names the IANA location the off-hours boundaries are interpreted in
	// (e.g. "America/New_York"). Empty uses UTC.
	Timezone string `yaml:"timezone"`
	// HistorySize bounds the retained recent-trigger ring for the admin trend
	// view. Zero uses a built-in default.
	HistorySize int `yaml:"historySize"`
	// AlertCooldown is the minimum spacing between notifications for one scope at
	// the same level (escalations always alert). Zero uses a built-in default.
	AlertCooldown time.Duration `yaml:"alertCooldown"`
	// MaxScopes caps the number of tracked tenant/identity scopes. Zero uses a
	// built-in default.
	MaxScopes int `yaml:"maxScopes"`
	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]AnomalyTenantConfig `yaml:"tenants"`
}

// AnomalyThresholds mirrors internal/anomaly.Tunables; the wiring layer
// translates it. Each detector has a warn cutoff (signal becomes noteworthy) and
// a high cutoff (fully anomalous). A wholly-zero block keeps the defaults.
type AnomalyThresholds struct {
	FanoutWarn       int     `yaml:"fanoutWarn"`
	FanoutHigh       int     `yaml:"fanoutHigh"`
	NewNamespaceWarn int     `yaml:"newNamespaceWarn"`
	NewNamespaceHigh int     `yaml:"newNamespaceHigh"`
	OffHoursWarn     int     `yaml:"offHoursWarn"`
	OffHoursHigh     int     `yaml:"offHoursHigh"`
	EnumerationWarn  int     `yaml:"enumerationWarn"`
	EnumerationHigh  int     `yaml:"enumerationHigh"`
	EgressZWarn      float64 `yaml:"egressZWarn"`
	EgressZHigh      float64 `yaml:"egressZHigh"`
}

// AnomalyTenantConfig overrides the anomaly model for a single tenant. A
// nil/empty sub-block inherits the global default for that part.
type AnomalyTenantConfig struct {
	Thresholds *AnomalyThresholds `yaml:"thresholds"`
	WarnLevel  string             `yaml:"warnLevel"`
	BlockLevel string             `yaml:"blockLevel"`
}

// ApprovalsConfig configures the quarantine-review & break-glass approval
// workflow (Task 50). It is disabled by default: with it off, an admission gate
// that blocks/quarantines an artifact refuses it unconditionally (the prior
// behavior). When enabled, a blocked pull opens a pending review an operator can
// approve (granting a time-boxed, tenant+coordinate+gate-scoped exception) or
// deny (confirming the block).
type ApprovalsConfig struct {
	// Enabled turns on the workflow, the admin surface, the metrics, and the
	// pull-path consult.
	Enabled bool `yaml:"enabled"`
	// RequiredApprovers is the number of DISTINCT approver identities a break-glass
	// grant requires (dual control). Values < 1 are treated as 1.
	RequiredApprovers int `yaml:"requiredApprovers"`
	// GrantTTL bounds how long a break-glass grant stays active before it
	// auto-revokes and the artifact is re-quarantined. Zero uses a built-in
	// default (1h).
	GrantTTL time.Duration `yaml:"grantTtl"`
	// RequestTTL bounds how long an unreviewed pending request lives before it
	// auto-expires. Zero uses a built-in default (72h).
	RequestTTL time.Duration `yaml:"requestTtl"`
	// SweepInterval is how often the background loop revokes due grants and stale
	// pending requests. Zero uses a built-in default (1m).
	SweepInterval time.Duration `yaml:"sweepInterval"`
	// MaxRequests bounds the retained request set (oldest terminal records trimmed
	// first). Zero uses a built-in default (1000).
	MaxRequests int `yaml:"maxRequests"`
	// StorePath is the JSON file the request store is persisted to so pending
	// reviews and active grants survive a restart. Empty keeps the store in memory.
	StorePath string `yaml:"storePath"`
}

// MeteringConfig configures the per-tenant usage-metering & chargeback subsystem
// (Task 84).
type MeteringConfig struct {
	// Enabled turns on the accumulator, its pull-path taps, the rollup scheduler,
	// the admin Usage tab/endpoints, and the per-tenant metrics.
	Enabled bool `yaml:"enabled"`
	// RetentionHours bounds how many hours of rollup history are retained. Zero
	// uses a built-in default (336h = 14 days).
	RetentionHours int `yaml:"retentionHours"`
	// RollupInterval is the periodic snapshot cadence (hourly by default). Reports
	// aggregate these rollups to the requested hourly/daily granularity. Zero uses
	// a built-in default (1h).
	RollupInterval time.Duration `yaml:"rollupInterval"`
	// StatePath is the JSON file the rollup history is persisted to so usage
	// survives a restart. Empty keeps the history in memory only.
	StatePath string `yaml:"statePath"`
	// DefaultScanCostMicros is the estimated cost charged per admission scan, in
	// micro-units of an operator-chosen currency, absent a per-gate override. Zero
	// uses a built-in default.
	DefaultScanCostMicros int64 `yaml:"defaultScanCostMicros"`
	// ScanCostMicros overrides the estimated per-scan cost by gate (e.g. a costlier
	// LLM commit scan vs a cheap signature check).
	ScanCostMicros map[string]int64 `yaml:"scanCostMicros"`
	// Budgets are optional per-tenant consumption ceilings, keyed by tenant; the
	// "*" key sets a default applied to any tenant without an explicit entry.
	// Crossing a ceiling fires a one-shot notify alert.
	Budgets map[string]MeteringBudget `yaml:"budgets"`
}

// MeteringBudget is a per-tenant consumption ceiling. A zero field means "no
// limit for that dimension".
type MeteringBudget struct {
	// MaxBytes caps cumulative served bytes (cache-hit + upstream).
	MaxBytes int64 `yaml:"maxBytes"`
	// MaxScanCostMicros caps the cumulative estimated scan/LLM cost.
	MaxScanCostMicros int64 `yaml:"maxScanCostMicros"`
}

// DownloadLogConfig configures the download log (Task 176). See
// docs/download-log.md.
type DownloadLogConfig struct {
	// Enabled turns the log on: package downloads are recorded with the client
	// address they came from, and the admin UI's Downloads tab and the
	// /api/downloads endpoints serve them. Defaults to true.
	Enabled bool `yaml:"enabled"`
	// MaxEntries is how many entries the log holds; when full, the oldest entry
	// is dropped. An entry typically costs under a kilobyte of memory, and never
	// more than a few (every field is length-bounded). Zero uses
	// the built-in default (50000).
	MaxEntries int `yaml:"maxEntries"`
	// Retention is how long an entry is kept before it is dropped, in memory and
	// on disk. Client addresses are personal data in most jurisdictions; this is
	// the control that keeps the log from becoming an indefinite record of them.
	// Defaults to 720h (30 days). "0s" disables time-based expiry, leaving only
	// the MaxEntries bound.
	Retention time.Duration `yaml:"retention"`
	// Path is the file the log is persisted to (JSON Lines, one entry per line,
	// mode 0600) so it survives a restart. Empty keeps the log in memory only.
	// Each proxy instance needs its own file: in a multi-replica deployment every
	// replica logs the downloads it served. The directory must be one the proxy
	// can create files in — the log is kept within its bounds by replacing the
	// file through a temporary one next to it — or the proxy refuses to start.
	Path string `yaml:"path"`
	// IncludeMetadata also records requests for metadata documents — package
	// indexes, version lists, checksum files — and not only for the packages
	// themselves. Off by default: metadata requests outnumber downloads many
	// times over and say what a client looked up, not what it installed.
	IncludeMetadata bool `yaml:"includeMetadata"`
}

// MaxEntriesOrDefault returns the log capacity, applying the built-in default
// when unset.
func (d DownloadLogConfig) MaxEntriesOrDefault() int {
	if d.MaxEntries <= 0 {
		return downloadlog.DefaultMaxEntries
	}
	return d.MaxEntries
}

// PolicyConfig configures the admission-policy engine (Task 9), which gates
// serving of artifacts on their scan verdict (Task 7) and provenance (Task 8).
type PolicyConfig struct {
	// Enabled turns on admission gating. When false, every resolved artifact is
	// served regardless of risk/provenance (scanning and provenance still run for
	// observability if enabled).
	Enabled bool `yaml:"enabled"`
	// FailClosed blocks artifacts when the provenance/scan assessment cannot be
	// performed (e.g. a backend outage). Defaults to false (fail open with a
	// warning) so a transient outage does not halt all pulls.
	FailClosed bool `yaml:"failClosed"`
	// Default is the baseline policy applied to every ecosystem without an explicit
	// entry under Ecosystems.
	Default PolicyRule `yaml:"default"`
	// Ecosystems holds per-ecosystem policies. An entry fully replaces Default for
	// that ecosystem (keyed by ecosystem type: npm, pip, cargo, go, nuget, docker).
	Ecosystems map[string]PolicyRule `yaml:"ecosystems"`
}

// PolicyRule is a single admission policy. See internal/policy.Rule for the
// precise semantics of each field; actions are "allow", "warn", or "block"
// (empty means "allow", i.e. the check is disabled).
type PolicyRule struct {
	// BlockAtRiskScore blocks artifacts whose source-commit risk score is at or
	// above this value (1..100; 0 disables).
	BlockAtRiskScore int `yaml:"blockAtRiskScore"`
	// WarnAtRiskScore warns at or above this value but below the block threshold
	// (1..100; 0 disables).
	WarnAtRiskScore int `yaml:"warnAtRiskScore"`
	// BlockMalicious blocks any artifact whose source commit was flagged malicious.
	BlockMalicious bool `yaml:"blockMalicious"`
	// OnMissingProvenance is applied when no provenance can be established.
	OnMissingProvenance string `yaml:"onMissingProvenance"`
	// OnMissingScan is applied when provenance exists but the source commit is
	// unscanned.
	OnMissingScan string `yaml:"onMissingScan"`
	// RequireSignature blocks artifacts whose provenance signature did not verify.
	RequireSignature bool `yaml:"requireSignature"`
	// RequireAttested blocks artifacts that are not fully attested (verified
	// signature chaining to a trusted root).
	RequireAttested bool `yaml:"requireAttested"`
	// MinConfidence is the minimum provenance confidence ("heuristic" < "claimed" <
	// "attested"). Below it, OnLowConfidence applies.
	MinConfidence string `yaml:"minConfidence"`
	// OnLowConfidence is applied when confidence is below MinConfidence.
	OnLowConfidence string `yaml:"onLowConfidence"`
	// Allowlist, when non-empty, restricts admission to package-name glob patterns;
	// any other name is blocked.
	Allowlist []string `yaml:"allowlist"`
	// Denylist blocks package names matching any glob pattern (evaluated first).
	Denylist []string `yaml:"denylist"`
}

// PolicyEngineConfig configures the declarative policy-as-code admission engine
// (Task 32). The engine loads operator-authored rule bundles from Dir, evaluates
// them against a structured input document aggregating every gate's signals, and
// returns an allow/warn/deny decision. It complements the hard-coded Policy gate.
type PolicyEngineConfig struct {
	// Enabled turns on the policy-as-code engine. When false, only the hard-coded
	// Policy gate applies.
	Enabled bool `yaml:"enabled"`
	// Dir is the directory of policy bundle files (*.yaml/*.yml/*.json). May be
	// empty when relying solely on the embedded default bundle.
	Dir string `yaml:"dir"`
	// Mode is "enforce" (deny decisions block admission) or "audit" (dry-run:
	// would-be decisions are logged and counted but never block). Default
	// "enforce".
	Mode string `yaml:"mode"`
	// DefaultAction is the decision when no rule matches: "allow", "warn", or
	// "deny". Default "allow".
	DefaultAction string `yaml:"defaultAction"`
	// IncludeDefaultBundle layers the engine's embedded conservative default
	// bundle underneath operator bundles so a fresh deployment has sensible
	// guardrails. Default true.
	IncludeDefaultBundle *bool `yaml:"includeDefaultBundle"`
	// ReloadInterval, when > 0, polls Dir and hot-reloads on any change. 0
	// disables polling (reload still available via the admin API / SIGHUP).
	ReloadInterval time.Duration `yaml:"reloadInterval"`
}

// VulnConfig configures the vulnerability-scanning subsystem (Task 15): for each
// cached package and image the proxy parses metadata/lockfiles into a CycloneDX
// SBOM, resolves it against a vulnerability database, and gates admission on the
// result. Scan results are cached by content digest with the configured TTL and
// an offline fallback.
type VulnConfig struct {
	// Enabled turns on SBOM generation and vulnerability gating. When false, no
	// scanning is performed and artifacts are served without a vulnerability check.
	Enabled bool `yaml:"enabled"`
	// Scanner selects the database backend: "osv" (default), "trivy", or "grype".
	// Only "osv" is built in; the others are reserved for the pluggable interface.
	Scanner string `yaml:"scanner"`
	// OSVBaseURL overrides the OSV.dev API endpoint (default https://api.osv.dev),
	// e.g. an internal mirror.
	OSVBaseURL string `yaml:"osvBaseUrl"`
	// CacheTTL bounds how long a scan result is fresh before re-scan (default 24h;
	// 0 means never expire).
	CacheTTL time.Duration `yaml:"cacheTtl"`
	// CacheMaxEntries bounds the in-memory scan-result cache (0 = default).
	CacheMaxEntries int `yaml:"cacheMaxEntries"`
	// Timeout bounds a single artifact scan (default 30s; 0 = no extra deadline).
	Timeout time.Duration `yaml:"timeout"`
	// Offline forces cache-only operation: the scanner backend is never contacted
	// (air-gapped deployments fed by a pre-warmed result cache).
	Offline bool `yaml:"offline"`
	// Action is applied when a finding meets the fail threshold: "warn", "block",
	// or "quarantine" (default "block").
	Action string `yaml:"action"`
	// FailSeverity is the minimum severity that triggers Action
	// (none|low|medium|high|critical; default "high"). Empty disables severity
	// gating.
	FailSeverity string `yaml:"failSeverity"`
	// FailCVSS is the minimum CVSS base score (0..10) that triggers Action; a
	// finding trips the gate if it meets either FailSeverity or FailCVSS. 0
	// disables CVSS-based gating.
	FailCVSS float64 `yaml:"failCvss"`
	// WarnSeverity is the minimum severity that triggers a warning below the fail
	// threshold. Empty disables severity-based warnings.
	WarnSeverity string `yaml:"warnSeverity"`
	// FailOnError blocks an artifact whose scan could not be performed and has no
	// cached fallback (fail-closed). Default false serves with a warning.
	FailOnError bool `yaml:"failOnError"`
	// IgnoreIDs is an allowlist of advisory IDs/aliases to exclude from gating
	// (accepted risks / false positives).
	IgnoreIDs []string `yaml:"ignoreIds"`

	// RescanInterval enables the continuous re-scan of cached artifacts against
	// newly-disclosed CVEs (Task 18): every interval the proxy re-runs the OSV
	// pipeline over each cached artifact's stored SBOM (without re-downloading) and
	// quarantines any that cross the policy threshold. Zero disables the periodic
	// schedule (on-demand re-scans via the admin API still work). A typical value
	// is 6h–24h.
	RescanInterval time.Duration `yaml:"rescanInterval"`
	// RescanWorkers bounds how many artifacts are re-resolved concurrently within a
	// sweep (0 = default 4).
	RescanWorkers int `yaml:"rescanWorkers"`

	// VEX configures Vulnerability Exploitability eXchange ingestion (Task 27): the
	// proxy correlates VEX statements (OpenVEX and CSAF formats) against scan
	// findings so a not_affected/fixed declaration suppresses a finding while an
	// affected declaration raises its severity.
	VEX VEXConfig `yaml:"vex"`

	// Reachability configures reachability-aware vulnerability prioritization
	// (Task 118): static import analysis of the pulled artifact's source classifies
	// each finding reachable/unreachable/unknown, and unreachable findings can be
	// downgraded or suppressed by policy instead of blocking.
	Reachability ReachabilityConfig `yaml:"reachability"`
}

// ReachabilityConfig configures static reachability analysis for the scanning
// gate (Task 118). It is fully offline (import analysis of the artifact's own
// source) and conservative: a finding is only ever treated as unreachable when
// the artifact's source was fully analyzed and the vulnerable module/package is
// provably not imported by the artifact's own code; every ambiguous case stays
// "unknown" and gates normally. Supported for the Go (module graph / import
// analysis) and npm (package.json / source import resolution) ecosystems; all
// others are annotated "unknown".
type ReachabilityConfig struct {
	// Enabled turns on reachability analysis and annotation. When false, findings
	// carry no reachability attribute and gate exactly as before.
	Enabled bool `yaml:"enabled"`
	// UnreachableAction selects how a finding proven unreachable is treated:
	// "annotate" (default — record the attribute only), "downgrade" (lower its
	// severity one bucket for gating and counts), or "suppress" (exclude it from
	// gating, retained for transparency). Reachable and unknown findings are never
	// altered.
	UnreachableAction string `yaml:"unreachableAction"`
}

// VEXConfig configures VEX-based vulnerability suppression for the scanning gate
// (Task 27). Statements are loaded from a directory of OpenVEX/CSAF documents
// (offline-friendly, the air-gapped source) and/or fetched per-artifact over HTTP.
type VEXConfig struct {
	// Enabled turns on VEX processing. When false, scan findings are gated as-is.
	Enabled bool `yaml:"enabled"`
	// Dir is a directory of VEX documents (*.json / *.vex / *.vex.json), loaded at
	// startup and re-readable; the air-gapped statement source. Documents that fail
	// to parse are logged and skipped, never blocking the rest.
	Dir string `yaml:"dir"`
	// FetchURL is an optional URL template fetched per artifact to retrieve scoped
	// VEX statements. It may contain {ecosystem}, {name}, {version}, and {digest}
	// placeholders. Ignored when the vulnerability subsystem is offline (air-gapped).
	FetchURL string `yaml:"fetchUrl"`
	// Export configures outbound VEX authoring (Task 137): generating signed
	// OpenVEX documents and CycloneDX VEX/VDR BOMs from the proxy's triage posture.
	Export VEXExportConfig `yaml:"export"`
}

// VEXExportConfig configures outbound VEX document generation and export (Task
// 137). As operators triage findings — not_affected/justification suppression
// decisions (the VEX corpus), VEX-adjudicated findings, and break-glass approval
// grants — the proxy can emit OpenVEX documents and CycloneDX VEX/VDR BOMs per
// coordinate or for a whole snapshot, optionally cosign-signed, via the
// `ptctl vex export` subcommand and the admin GET /api/vex/export endpoint.
type VEXExportConfig struct {
	// Enabled turns on outbound VEX authoring. When false the export endpoint and
	// ptctl subcommand report the surface absent.
	Enabled bool `yaml:"enabled"`
	// Author is the OpenVEX "author" / CycloneDX metadata author stamped into every
	// exported document. Defaults to "pullthrough-security".
	Author string `yaml:"author"`
	// IDNamespace is the base URI exported OpenVEX document @id values are minted
	// under. Defaults to "https://pullthrough.security/vex".
	IDNamespace string `yaml:"idNamespace"`
	// SigningKey is an inline PEM private key (PKCS#8 / EC / PKCS#1) used to sign
	// exported documents (a detached cosign-compatible signature), as an
	// alternative to SigningKeyFile. May be a "${ENV_VAR}" or "enc:v1:" reference.
	// When neither is set, the outbound-attestation signing key is reused, falling
	// back to the audit transparency signing key; absent all of these, export still
	// works but unsigned.
	SigningKey string `yaml:"signingKey"`
	// SigningKeyFile is a PEM private-key file used to sign exported documents.
	SigningKeyFile string `yaml:"signingKeyFile"`
}

// LicenseConfig configures the license-compliance admission gate (Task 28). The
// gate reads per-component SPDX license identifiers from the artifact's SBOM
// (generated by the vulnerability subsystem, or extracted on demand) and
// evaluates them against a base policy with optional per-tenant overrides. It is
// fully offline: the SPDX catalog and policy are local, so no network access is
// required (air-gapped friendly).
type LicenseConfig struct {
	// Enabled turns on license evaluation and gating. When false, no license check
	// is performed.
	Enabled bool `yaml:"enabled"`
	// Policy is the base license policy applied to every tenant.
	Policy LicensePolicyConfig `yaml:",inline"`
	// Tenants maps a tenant identifier (the authenticated principal's team) to an
	// override policy merged onto the base: allow/deny/review/exception lists are
	// unioned with the base's and any set scalar replaces the base value. This
	// expresses requirements like "deny the GPL family only for proprietary
	// tenants" without restating the whole policy.
	Tenants map[string]LicensePolicyConfig `yaml:"tenants"`
	// DriftDetection enables cross-version license-drift tracking: a package whose
	// declared license changes between versions is surfaced as a high-signal
	// supply-chain risk indicator.
	DriftDetection bool `yaml:"driftDetection"`
	// DriftMaxEvents bounds how many recent drift events are retained for the admin
	// surface (0 = default 256).
	DriftMaxEvents int `yaml:"driftMaxEvents"`
}

// LicensePolicyConfig is the operator-facing license policy. A list entry may be
// an exact SPDX id (case-insensitive), a glob with '*' (e.g. "GPL-*"), or an
// "@family" category keyword ("@permissive", "@weak-copyleft",
// "@strong-copyleft", "@network-copyleft", "@copyleft", "@public-domain",
// "@proprietary", "@unknown"). Deny takes precedence over review, which takes
// precedence over allow when an id matches several lists.
type LicensePolicyConfig struct {
	// Allow, Deny, Review list the permitted, prohibited, and
	// permitted-after-review SPDX ids / globs / families.
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
	Review []string `yaml:"review"`
	// AllowExceptions lists SPDX exception ids (the operand of WITH) that downgrade
	// an otherwise-denied license to allowed (e.g. "Classpath-exception-2.0").
	AllowExceptions []string `yaml:"allowExceptions"`
	// Unknown is the disposition for an unrecognized / NOASSERTION license
	// ("allow"|"review"|"deny"; default "review").
	Unknown string `yaml:"unknown"`
	// Default is the disposition for a recognized license matching no list
	// ("allow"|"review"|"deny"; default "allow").
	Default string `yaml:"default"`
	// Action is applied when the effective license is denied
	// ("warn"|"block"|"quarantine"; default "block").
	Action string `yaml:"action"`
	// ReviewAction is applied when the effective license is review/unknown
	// ("warn"|"block"|"quarantine"; default "warn").
	ReviewAction string `yaml:"reviewAction"`
	// DriftAction is applied when license drift is detected
	// ("warn"|"block"|"quarantine"; default "warn").
	DriftAction string `yaml:"driftAction"`
}

// NameguardConfig configures the typosquatting & dependency-confusion guard
// (Task 19): at pull time the proxy inspects a package's coordinate name for
// edit-distance similarity to popular names, collision with configured internal
// namespaces, and homoglyph / mixed-script characters, then warns or blocks per
// the configured severity thresholds. The reference lists are keyed by ecosystem
// (pip, npm, cargo, nuget, go).
type NameguardConfig struct {
	// Enabled turns on name-based admission checking. When false, package names are
	// not inspected and every coordinate is served.
	Enabled bool `yaml:"enabled"`
	// InternalNamespaces maps an ecosystem to the private/internal package names and
	// namespace prefixes a public-registry name must not shadow. An entry ending in
	// "*" or "/", or an npm "@scope" with no package, is a namespace prefix;
	// otherwise an exact package name.
	InternalNamespaces map[string][]string `yaml:"internalNamespaces"`
	// PopularNames maps an ecosystem to popular/allowlisted names that typosquats are
	// measured against. Merged with the built-in seed lists unless DisableBuiltins.
	PopularNames map[string][]string `yaml:"popularNames"`
	// Allowlist maps an ecosystem to legitimate names that must never be flagged
	// (near-neighbors of a popular name). Merged with built-ins unless DisableBuiltins.
	Allowlist map[string][]string `yaml:"allowlist"`
	// DisableBuiltins suppresses the built-in popular/allowlist seed data, using only
	// operator-supplied lists.
	DisableBuiltins bool `yaml:"disableBuiltins"`
	// DistanceThreshold is the maximum Damerau-Levenshtein distance treated as a
	// typosquat of a popular name (default 2). The effective threshold is reduced for
	// short names to limit false positives.
	DistanceThreshold int `yaml:"distanceThreshold"`
	// MinNameLength is the shortest name subjected to distance-based checks (default 4).
	MinNameLength int `yaml:"minNameLength"`
	// Action is applied when a finding meets FailSeverity: "warn", "block", or
	// "quarantine" (default "block").
	Action string `yaml:"action"`
	// FailSeverity is the minimum finding severity that triggers Action
	// (none|low|medium|high|critical; default "high").
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity that triggers a warning below the fail
	// threshold (default "medium"). Empty disables warnings.
	WarnSeverity string `yaml:"warnSeverity"`
	// DetectHomoglyphs enables non-ASCII / mixed-script look-alike detection
	// (default true when the subsystem is enabled).
	DetectHomoglyphs *bool `yaml:"detectHomoglyphs"`
}

// MalfeedConfig configures the known-malicious-package admission gate (Task 48).
// Unlike nameguard (heuristics) and vulnscan (CVEs), this gate matches concrete
// known-bad coordinates from curated malware datasets (OpenSSF/OSV
// malicious-packages and GitHub Advisory malware entries) and hard-blocks the
// pull with the advisory id and reason. Data can come from live HTTP feeds
// (refreshed periodically with ETag/conditional fetch) and/or an offline signed
// bundle imported at startup for air-gapped deployments.
type MalfeedConfig struct {
	// Enabled turns on the gate. When false, coordinates are not matched against
	// the malware datasets and every pull proceeds.
	Enabled bool `yaml:"enabled"`
	// Sources are the upstream malware feeds to ingest on refresh. Each serves a
	// single OSV record or a JSON array of OSV records.
	Sources []MalfeedSourceConfig `yaml:"sources"`
	// RefreshInterval is the period between background feed refreshes. 0 disables
	// the background loop (data then comes only from the offline bundle or an
	// on-demand admin refresh).
	RefreshInterval time.Duration `yaml:"refreshInterval"`
	// StaleAfter marks the loaded data stale this long after the last successful
	// refresh. 0 disables staleness checking (the gate then only ever blocks
	// concrete matches).
	StaleAfter time.Duration `yaml:"staleAfter"`
	// FailClosed makes the gate block pulls while the feed is stale, trading
	// availability for safety. The default (false) fails open: a stale feed still
	// blocks concrete matches but never blocks an unmatched pull.
	FailClosed bool `yaml:"failClosed"`
	// Timeout bounds a single feed fetch (default 30s).
	Timeout time.Duration `yaml:"timeout"`
	// BundlePath is an optional offline signed bundle (see the `malfeed export`
	// CLI) imported at startup, before any network refresh, for air-gapped
	// operation.
	BundlePath string `yaml:"bundlePath"`
	// BundlePublicKeyFile is a PEM-encoded Ed25519 public key that the imported
	// bundle's signature must verify against. When empty the bundle is accepted on
	// an integrity check against its embedded key only (origin unpinned).
	BundlePublicKeyFile string `yaml:"bundlePublicKeyFile"`
}

// MaturityConfig configures the release-maturity / version-cooldown admission
// gate (Task 61). The gate derives each version's publish timestamp from the
// upstream registry metadata and quarantines it until age >= the applicable
// cooldown. Cooldowns resolve by specificity then scope: a tenant ecosystem
// override, then a global ecosystem override, then a tenant default, then the
// global default. An allowlisted coordinate bypasses the gate; a still-cooling
// block composes with the break-glass approval workflow.
type MaturityConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics.
	// On by default but inert until a positive cooldown is configured (the default
	// cooldown is zero, which admits every version).
	Enabled bool `yaml:"enabled"`
	// DefaultCooldown is the global cooldown applied when no per-ecosystem or
	// per-tenant override matches. Zero (the default) disables the gate globally.
	DefaultCooldown time.Duration `yaml:"defaultCooldown"`
	// Ecosystems overrides the cooldown per canonical ecosystem
	// (npm/pip/cargo/go/nuget/maven/rubygems/composer). An entry of "0s" explicitly
	// disables the cooldown for that ecosystem.
	Ecosystems map[string]time.Duration `yaml:"ecosystems"`
	// Tenants holds per-tenant cooldown overrides keyed by tenant id (team).
	Tenants map[string]MaturityTenantConfig `yaml:"tenants"`
	// Allowlist is the set of trusted package coordinates/scopes that bypass the
	// cooldown. Forms: "name", "eco:name", "@scope/" (npm scope prefix), "prefix*"
	// (name glob), each optionally "eco:"-scoped.
	Allowlist []string `yaml:"allowlist"`
	// FailClosedOnUnknown blocks a pull whose publish timestamp cannot be
	// determined. The default (false) fails open: an undeterminable timestamp
	// admits the pull rather than penalize an undatable package.
	FailClosedOnUnknown bool `yaml:"failClosedOnUnknown"`
	// Timeout bounds a single upstream metadata lookup used to derive a publish
	// timestamp (default 10s).
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL bounds how long a resolved (immutable) publish timestamp is cached
	// (default 6h).
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// NegativeCacheTTL bounds how long an unknown/failed resolution is cached
	// before retry (default 15m).
	NegativeCacheTTL time.Duration `yaml:"negativeCacheTTL"`
	// CacheSize bounds the resolved-timestamp cache (default 4096 entries).
	CacheSize int `yaml:"cacheSize"`
	// UserAgent is sent with metadata lookups; some registries reject an empty
	// User-Agent. Empty uses a built-in default.
	UserAgent string `yaml:"userAgent"`
	// BaseURLs overrides the registry base URL per canonical ecosystem, for private
	// mirrors. An absent entry uses the public registry default.
	BaseURLs map[string]string `yaml:"baseURLs"`
}

// MaturityTenantConfig overrides the cooldown model for a single tenant. A
// zero/absent field inherits the global setting for that part.
type MaturityTenantConfig struct {
	// DefaultCooldown overrides the global default for this tenant. Unset (zero)
	// inherits the global default.
	DefaultCooldown time.Duration `yaml:"defaultCooldown"`
	// Ecosystems overrides the cooldown for specific ecosystems for this tenant.
	Ecosystems map[string]time.Duration `yaml:"ecosystems"`
	// Allowlist adds tenant-scoped trusted coordinates/scopes.
	Allowlist []string `yaml:"allowlist"`
}

// ContinuityConfig configures the maintainer/publisher continuity monitoring gate
// (Task 91): a trust-on-first-use ownership-change gate. It records the publisher
// principals (registry maintainer roster, publishing namespace owner, signing-key
// identity) of each (ecosystem, name) coordinate the first time it is pulled, and
// raises a maintainer_drift signal — and, under a block disposition, refuses the
// pull — when a previously-unseen maintainer/key/namespace appears for an
// already-known package. A cooldown holds a newly-appeared maintainer untrusted
// before it is folded into the known set.
type ContinuityConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics. On
	// by default but observe-only until a positive cooldown and a block/warn
	// disposition are configured.
	Enabled bool `yaml:"enabled"`
	// DefaultDisposition is the action on detected drift when no per-ecosystem /
	// per-tenant override matches: "observe" (default), "warn", or "block".
	DefaultDisposition string `yaml:"defaultDisposition"`
	// Ecosystems overrides the disposition per canonical ecosystem.
	Ecosystems map[string]string `yaml:"ecosystems"`
	// Tenants holds per-tenant disposition/cooldown overrides keyed by tenant id.
	Tenants map[string]ContinuityTenantConfig `yaml:"tenants"`
	// Cooldown is the trust-cooldown window: a newly-appeared maintainer is held
	// untrusted (drift active) for this long before it is folded into the known set.
	// Zero trusts a new maintainer immediately (drift is still signalled once).
	Cooldown time.Duration `yaml:"cooldown"`
	// Allowlist is the set of trusted coordinates/scopes that bypass the gate.
	// Forms mirror the maturity gate: "name", "eco:name", "@scope/", "prefix*".
	Allowlist []string `yaml:"allowlist"`
	// StorePath is the JSON file backing the durable known-maintainer set. Empty
	// keeps state in memory only (lost on restart).
	StorePath string `yaml:"storePath"`
	// Timeout bounds a single upstream metadata lookup (default 10s).
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL bounds how long a resolved publisher identity is cached (default 1h).
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// NegativeCacheTTL bounds how long an unknown/failed resolution is cached before
	// retry (default 15m).
	NegativeCacheTTL time.Duration `yaml:"negativeCacheTTL"`
	// CacheSize bounds the resolved-identity cache (default 4096 entries).
	CacheSize int `yaml:"cacheSize"`
	// MaxRecords bounds the durable known-maintainer-set store (default 50000).
	MaxRecords int `yaml:"maxRecords"`
	// UserAgent is sent with metadata lookups; empty uses a built-in default.
	UserAgent string `yaml:"userAgent"`
	// BaseURLs overrides the registry base URL per canonical ecosystem for private
	// mirrors. An absent entry uses the public registry default.
	BaseURLs map[string]string `yaml:"baseURLs"`
}

// ContinuityTenantConfig overrides the continuity disposition/cooldown model for a
// single tenant. A zero/absent field inherits the global setting for that part.
type ContinuityTenantConfig struct {
	// Disposition overrides the global default disposition for this tenant. Empty
	// inherits.
	Disposition string `yaml:"disposition"`
	// Ecosystems overrides the disposition for specific ecosystems for this tenant.
	Ecosystems map[string]string `yaml:"ecosystems"`
	// Cooldown overrides the global trust cooldown for this tenant. Zero inherits.
	Cooldown time.Duration `yaml:"cooldown"`
	// Allowlist adds tenant-scoped trusted coordinates/scopes.
	Allowlist []string `yaml:"allowlist"`
}

// DepFirewallConfig configures the dependency-firewall version-pinning &
// allowlist enforcement gate (Task 65). The gate resolves each pull's concrete
// (ecosystem, name, version) against an active rule set and blocks any version
// outside the approved set, with an actionable reason. Rules combine four
// orthogonal constraints (pinned exact versions, allowed semver ranges, a
// minimum-version floor, and an explicit denylist), ANDed together; the denylist
// is checked first and always blocks. Tenant rules override global rules for the
// same coordinate. For an ungoverned coordinate the (per-tenant or global)
// defaultAction decides: "allow" (enforce only explicit rules) or "block"
// (deny-by-default — the strict mode used to pin an entire lockfile graph).
type DepFirewallConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics.
	// Off by default: the firewall enforces only what an operator configures, so it
	// must be explicitly switched on.
	Enabled bool `yaml:"enabled"`
	// DefaultAction is the disposition for a coordinate with no matching rule:
	// "allow" (default) or "block" (deny-by-default). A per-tenant override takes
	// precedence.
	DefaultAction string `yaml:"defaultAction"`
	// Rules are the global (all-tenant) version-policy rules.
	Rules []DepFirewallRule `yaml:"rules"`
	// Tenants holds per-tenant policy overrides keyed by tenant id (team).
	Tenants map[string]DepFirewallTenantConfig `yaml:"tenants"`
}

// DepFirewallRule is one version-policy rule keyed by (ecosystem, name).
type DepFirewallRule struct {
	// Ecosystem is the canonical ecosystem label (npm/pip/cargo/go/nuget/...).
	Ecosystem string `yaml:"ecosystem"`
	// Name is the package coordinate within the ecosystem.
	Name string `yaml:"name"`
	// Pinned is an exact-version allowlist; the pulled version must be one of them.
	Pinned []string `yaml:"pinned"`
	// Ranges are semver range expressions (e.g. ">=1.2.0 <2.0.0", "^1.4.0"); the
	// version must satisfy at least one.
	Ranges []string `yaml:"ranges"`
	// MinVersion is a minimum-version floor; versions below it are blocked.
	MinVersion string `yaml:"minVersion"`
	// Denied is an explicit denylist of exact versions that are always refused.
	Denied []string `yaml:"denied"`
	// Note is an optional operator annotation surfaced in the admin view.
	Note string `yaml:"note"`
}

// DepFirewallTenantConfig overrides the firewall policy for a single tenant.
type DepFirewallTenantConfig struct {
	// DefaultAction overrides the global default for this tenant ("allow"/"block").
	// Empty inherits the global default.
	DefaultAction string `yaml:"defaultAction"`
	// Rules are tenant-scoped rules; they take precedence over global rules for the
	// same (ecosystem, name).
	Rules []DepFirewallRule `yaml:"rules"`
}

// InstallHooksConfig configures the install-script / lifecycle-hook risk-analysis
// gate (Task 62). The gate statically extracts a package's automatically-run
// install hooks and scores them against a fixed catalog of deterministic
// high-risk patterns (network egress during install, base64-decoded eval,
// shell/process spawning, writes outside the package directory, environment-
// variable exfiltration, obfuscated one-liners, and native-build steps). Nothing
// is executed. A finding whose severity meets failSeverity warns on or blocks the
// artifact per action; a per-tenant override may tighten or relax the thresholds.
type InstallHooksConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics.
	// On by default; it inspects only install-hook-bearing ecosystems
	// (npm/pip/cargo/rubygems) and is inert for others.
	Enabled bool `yaml:"enabled"`
	// FailSeverity is the minimum finding severity that triggers Action
	// (none|low|medium|high|critical; default "high").
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold (default "medium"). Empty disables warnings.
	WarnSeverity string `yaml:"warnSeverity"`
	// Action is applied when a finding meets FailSeverity: "block" (refuse and
	// evict) or "warn" (advisory). Default "block".
	Action string `yaml:"action"`
	// DisabledRules names built-in rule ids to turn off (e.g. "native-extension"
	// for a tenant that legitimately ships many native deps).
	DisabledRules []string `yaml:"disabledRules"`
	// Rules adds or overrides detection rules. A rule whose id matches a built-in
	// replaces it; a new id is appended.
	Rules []InstallHookRuleConfig `yaml:"rules"`
	// MaxFindingsPerHook caps findings recorded per hook (0 => default 50).
	MaxFindingsPerHook int `yaml:"maxFindingsPerHook"`
	// Tenants holds per-tenant threshold overrides keyed by tenant id (team).
	Tenants map[string]InstallHooksTenantConfig `yaml:"tenants"`
}

// InstallHookRuleConfig is an operator-supplied detection rule (or an override of
// a built-in by matching id).
type InstallHookRuleConfig struct {
	ID       string `yaml:"id"`
	Title    string `yaml:"title"`
	Severity string `yaml:"severity"`
	Pattern  string `yaml:"pattern"`
}

// InstallHooksTenantConfig overrides the gate's thresholds for a single tenant. A
// zero/empty field inherits the global setting for that part.
type InstallHooksTenantConfig struct {
	FailSeverity string `yaml:"failSeverity"`
	WarnSeverity string `yaml:"warnSeverity"`
	Action       string `yaml:"action"`
}

// MLGuardConfig configures the ML model weight-scanning gate (Task 110). The gate
// statically disassembles a Hugging Face pickle-based weight file's opcode stream
// (unwrapping the PyTorch ZIP container) and flags imports of code-execution /
// network / filesystem primitives invoked via __reduce__ — the malicious-model
// attack vector — without ever unpickling anything. A finding whose severity meets
// failSeverity warns on or blocks (and quarantines) the weight per action;
// safetensors is recognized as the safe format and always admitted.
type MLGuardConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics. On
	// by default; it inspects only the Hugging Face ecosystem's pickle weight files
	// and is inert for other ecosystems and non-weight files.
	Enabled bool `yaml:"enabled"`
	// FailSeverity is the minimum finding severity that triggers Action
	// (info|low|medium|high|critical; default "high").
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold (default "medium"). Empty disables warnings.
	WarnSeverity string `yaml:"warnSeverity"`
	// Action is applied when a finding meets FailSeverity: "block" (refuse and
	// evict/quarantine) or "warn" (advisory). Default "block".
	Action string `yaml:"action"`
	// PreferSafetensors flags a served pickle weight with an advisory header
	// recommending the safer safetensors format. Default true.
	PreferSafetensors *bool `yaml:"preferSafetensors"`
	// MaxScanBytes bounds the bytes buffered per weight file for disassembly
	// (0 => default 256 MiB). A larger file is scanned up to the bound and flagged.
	MaxScanBytes int `yaml:"maxScanBytes"`
	// MaxZipEntries bounds the pickle entries scanned inside a PyTorch ZIP container
	// (0 => default 64).
	MaxZipEntries int `yaml:"maxZipEntries"`
	// Tenants holds per-tenant threshold overrides keyed by tenant id (team).
	Tenants map[string]MLGuardTenantConfig `yaml:"tenants"`
}

// MLGuardTenantConfig overrides the ML weight gate's thresholds for a single
// tenant. A zero/empty field inherits the global setting.
type MLGuardTenantConfig struct {
	FailSeverity string `yaml:"failSeverity"`
	WarnSeverity string `yaml:"warnSeverity"`
	Action       string `yaml:"action"`
}

// AVScanConfig configures the antivirus content-scanning gate (Task 136). It
// streams a fetched artifact's payload (package archives, wheels, jars, OCI
// layer blobs, ML weight files, Git LFS objects) through a configurable malware
// engine — primarily ClamAV over the clamd INSTREAM protocol on a TCP or UNIX
// socket — and, on a positive byte-level detection, annotates/quarantines/blocks
// the artifact and emits a finding into the dossier/risk/SARIF/notification
// pipeline. It complements the coordinate-level OSV malware feed (Task 48) with
// real payload inspection and is ecosystem-agnostic.
type AVScanConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics.
	// Off by default (opt-in): it requires a reachable AV engine.
	Enabled bool `yaml:"enabled"`
	// Engine selects the scanning backend. Only "clamav" (clamd INSTREAM) is built
	// in. Default "clamav".
	Engine string `yaml:"engine"`
	// Address is the clamd endpoint: a "host:port" / "tcp://host:port" TCP socket,
	// or a "unix:///path" / filesystem-path UNIX socket. Required when enabled.
	Address string `yaml:"address"`
	// Action is applied on a positive detection: "annotate" (record + serve),
	// "quarantine" (refuse + evict from cache) or "block" (refuse, keep cached).
	// Default "quarantine".
	Action string `yaml:"action"`
	// MaxScanBytes bounds the bytes streamed to the engine per artifact
	// (0 => default 128 MiB). A larger artifact is scanned up to the bound and
	// flagged truncated.
	MaxScanBytes int64 `yaml:"maxScanBytes"`
	// Timeout bounds a single scan including connecting to the engine
	// (0 => default 60s).
	Timeout time.Duration `yaml:"timeout"`
	// FailOpen controls behaviour when the engine is unreachable or errors: true
	// admits the artifact (graceful degradation), false refuses it (fail-closed).
	// Default true.
	FailOpen *bool `yaml:"failOpen"`
}

// ContentScanConfig configures the package-payload static content-analysis gate
// (Task 138). It unpacks a cached source artifact and applies deterministic,
// no-execution heuristics to its files: high-entropy/packed blobs, unexpectedly
// embedded native binaries, obfuscated or minified-plus-eval JavaScript, dynamic
// code-execution sinks, and in-source credentials/secrets (reusing the Task 29
// detectors). Findings flow into the dossier/risk/SARIF/notification pipeline and
// are acted on per the configured action. Every dimension of work is bounded by a
// scan budget so a hostile or huge artifact cannot exhaust memory or stall the
// pull path.
type ContentScanConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics. On
	// by default but observe-only (annotate) unless the action is raised.
	Enabled bool `yaml:"enabled"`
	// Action is applied when a finding meets FailSeverity: "annotate" (record +
	// serve), "downgrade" (record + serve, findings downgraded one severity rank)
	// or "block" (refuse + evict). Default "annotate".
	Action string `yaml:"action"`
	// FailSeverity is the minimum finding severity that triggers the block action
	// (none|low|medium|high|critical; default "high").
	FailSeverity string `yaml:"failSeverity"`
	// Ecosystems restricts scanning to these ecosystems (npm, pip, cargo,
	// rubygems, composer, nuget). Empty selects the built-in source-package set.
	Ecosystems []string `yaml:"ecosystems"`

	// Per-heuristic toggles (each default on). DisableX turns a dimension off for a
	// corpus where it is noisy. The pointer form distinguishes "unset" (default on)
	// from an explicit false.
	DetectEntropy *bool `yaml:"detectEntropy"`
	DetectBinary  *bool `yaml:"detectBinary"`
	DetectJS      *bool `yaml:"detectJavaScript"`
	DetectExec    *bool `yaml:"detectDynamicExec"`
	DetectSecrets *bool `yaml:"detectSecrets"`

	// EntropyThreshold is the byte-level Shannon entropy (bits/byte, 0..8) at or
	// above which a blob is flagged (0 => default 7.2).
	EntropyThreshold float64 `yaml:"entropyThreshold"`
	// MinEntropyBlobBytes is the smallest file size considered for the entropy
	// heuristic (0 => default 1024).
	MinEntropyBlobBytes int64 `yaml:"minEntropyBlobBytes"`

	// Scan budget bounds (0 => the built-in default for each).
	MaxArchiveBytes     int64         `yaml:"maxArchiveBytes"`
	MaxFileBytes        int64         `yaml:"maxFileBytes"`
	MaxFiles            int           `yaml:"maxFiles"`
	MaxScanBytesPerFile int64         `yaml:"maxScanBytesPerFile"`
	MaxFindings         int           `yaml:"maxFindings"`
	MaxFindingsPerFile  int           `yaml:"maxFindingsPerFile"`
	Timeout             time.Duration `yaml:"timeout"`
}

// LLMPackageScanConfig configures the sandboxed LLM package-content scan gate
// (Task 173). On the pull path, after the deterministic content gates, the gate
// unpacks the fetched artifact into a bounded, read-only, in-memory tree and has
// a language model review it — install scripts, lifecycle hooks, build files and
// entry points first. The model can list, read and search that tree and nothing
// else: no package code is ever executed, and it has no network or host access.
// It must answer with a strict JSON verdict; anything else is a scan error and is
// handled by FailMode, never read as "benign".
//
// Scans cost money and time, so each artifact is scanned once: the verdict is
// stored under the artifact's sha256 digest together with the model and the
// prompt version, concurrent requests for one digest share a scan, and a cost
// budget bounds the spend.
type LLMPackageScanConfig struct {
	// Enabled turns on the gate, its admin surface, and the Prometheus metrics.
	// Off by default: it needs an LLM provider and spends money per artifact.
	Enabled bool `yaml:"enabled"`
	// Provider selects the LLM provider: "claude", "openai" or "codex". Empty
	// inherits scanning.provider (and with it scanning.apiKey / baseUrl /
	// apiVersion / reasoningEffort), so a deployment that already scans commits
	// only needs to set enabled.
	Provider string `yaml:"provider"`
	// Model is the provider-specific model identifier. Empty uses the provider's
	// default deep-analysis model (scanning.commit.deepModel when the provider is
	// inherited and that is set).
	Model string `yaml:"model"`
	// APIKey authenticates to the provider. It accepts a secretRef (env://,
	// file://, vault://), ${ENV_VAR} and enc:v1: like every other credential.
	// Empty inherits scanning.apiKey when the provider is the same.
	APIKey string `yaml:"apiKey"`
	// BaseURL optionally overrides the provider API endpoint (e.g. a gateway).
	// Empty inherits scanning.baseUrl when the provider is the same.
	BaseURL string `yaml:"baseUrl"`
	// APIVersion selects Azure OpenAI mode for the "openai" provider.
	APIVersion string `yaml:"apiVersion"`
	// ReasoningEffort, for the "openai" provider, is forwarded as
	// "reasoning_effort" when Thinking is on.
	ReasoningEffort string `yaml:"reasoningEffort"`
	// Mode selects how the model is shown the package: "tools" (list/read/grep
	// over the unpacked tree), "bundle" (one prompt holding the highest-priority
	// files — for a gateway whose model has no function calling), or "auto"
	// (tools when the provider supports them, else bundle). Default "auto".
	Mode string `yaml:"mode"`
	// Thinking requests extended reasoning. When unset it is on for the models
	// known to support it and off otherwise.
	Thinking *bool `yaml:"thinking"`

	// Action is applied to a verdict: "annotate" (record + serve), "block" (refuse
	// a malicious artifact with a 403 and quarantine it — evict it from the cache
	// — while serving a suspicious one with an advisory) or "quarantine" (as block,
	// and additionally hold a suspicious artifact until an operator releases it
	// through the break-glass approval workflow). Default "block".
	Action string `yaml:"action"`
	// FailMode is applied when no verdict could be obtained (provider down,
	// timeout, budget exhausted, unparseable answer, artifact too large or not
	// unpackable): "open" serves the artifact unscanned, "closed" refuses it.
	// Default "open".
	FailMode string `yaml:"failMode"`
	// Oversize is applied to an artifact larger than limits.maxArtifactBytes (for
	// an OCI image: to each layer larger than that). "fail" does not scan it at
	// all: it is reported "oversized" and failMode decides, so a verdict is always
	// a verdict on every byte served. "metadata-only" has the model judge what can
	// be established within the limits — the file inventory, the install-time
	// scripts and manifests in the first maxArtifactBytes, an image's config and
	// history — and records the verdict with scope "metadata-only", flagged
	// truncated, with a finding saying the artifact was only partly examined. A
	// malicious metadata-only verdict is enforced like any other; a benign one is
	// evidence about what was read, not a statement about the rest. Default
	// "fail".
	Oversize string `yaml:"oversize"`
	// MaliciousThreshold is the minimum confidence (0..1] at which a "malicious"
	// verdict is acted on as malicious; below it the artifact is treated as
	// suspicious. Default 0.7.
	MaliciousThreshold float64 `yaml:"maliciousThreshold"`
	// SuspiciousThreshold is the minimum confidence (0..1] at which a "suspicious"
	// verdict is flagged; below it the artifact is treated as benign. Default 0.5.
	SuspiciousThreshold float64 `yaml:"suspiciousThreshold"`

	// Timeout is the wall-clock bound on one scan, queueing included. The client
	// waits this long, at most, for the first byte of an unscanned artifact; keep
	// it below server.writeTimeout and above your package manager's patience.
	// Default 2m.
	Timeout time.Duration `yaml:"timeout"`
	// RequestTimeout bounds a single provider HTTP attempt (the "openai"
	// provider). Zero uses the provider default.
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// MaxRetries is the number of extra attempts after a transient provider
	// error (0 => 1; negative disables retries).
	MaxRetries int `yaml:"maxRetries"`
	// MaxConcurrent bounds the scans in flight (0 => 4). Each holds the unpacked
	// package in memory.
	MaxConcurrent int `yaml:"maxConcurrent"`

	// Include is the set of ecosystems scanned (upstream types, e.g. npm, pip,
	// docker). Empty selects the built-in set, which is every ecosystem the proxy
	// fronts — each package backend, docker (OCI images), huggingface, generic —
	// plus "git-lfs" for Git LFS objects. "git" is not an ecosystem of this gate:
	// the commits of a clone or fetch are the LLM commit scan's (scanning.*).
	Include []string `yaml:"include"`
	// Exclude removes ecosystems from the scanned set; it always wins. With an
	// empty include this is how a single ecosystem is left out.
	Exclude []string `yaml:"exclude"`
	// ExcludeUpstreams names upstreams (keys of `upstreams`) whose artifacts are
	// never scanned, whatever their ecosystem. A scan sends package contents to
	// the LLM provider, so list here any private registry whose packages must not
	// leave your network; public registries of the same ecosystem are still
	// scanned. An unknown name is a configuration error, not a silent no-op.
	ExcludeUpstreams []string `yaml:"excludeUpstreams"`

	// StoreDir is the directory verdicts are persisted in, one file per artifact
	// digest. Empty keeps verdicts in memory only: every artifact is then scanned
	// (and paid for) again after a restart.
	StoreDir string `yaml:"storeDir"`
	// CacheTTL expires a stored verdict after this age, so the artifact is scanned
	// again. Zero keeps verdicts indefinitely.
	CacheTTL time.Duration `yaml:"cacheTtl"`
	// ErrorTTL is how long a failed scan is remembered before the same artifact is
	// tried again (0 => 5m).
	ErrorTTL time.Duration `yaml:"errorTtl"`

	// Limits bounds one scan.
	Limits LLMPackageScanLimits `yaml:"limits"`
	// Budget bounds provider spend.
	Budget LLMPackageScanBudget `yaml:"budget"`
}

// LLMPackageScanLimits bounds one LLM package-content scan (Task 173). Every
// quantity here is controlled by whoever published the package; 0 selects the
// default shown.
type LLMPackageScanLimits struct {
	// MaxArtifactBytes is the largest (compressed) artifact scanned. A larger one
	// is not scanned at all and is handled by failMode.
	MaxArtifactBytes int64 `yaml:"maxArtifactBytes"`
	// MaxUnpackedBytes caps the decompressed bytes produced while unpacking.
	MaxUnpackedBytes int64 `yaml:"maxUnpackedBytes"`
	// MaxFileBytes caps the bytes retained per file; a larger file is cut.
	MaxFileBytes int64 `yaml:"maxFileBytes"`
	// MaxFiles caps the archive members examined.
	MaxFiles int `yaml:"maxFiles"`
	// MaxDepth caps the directory depth of a member's path.
	MaxDepth int `yaml:"maxDepth"`
	// MaxCompressionRatio is the decompression-bomb guard (decompressed :
	// compressed).
	MaxCompressionRatio float64 `yaml:"maxCompressionRatio"`
	// MaxPromptBytes bounds the package material in the first prompt.
	MaxPromptBytes int `yaml:"maxPromptBytes"`
	// MaxToolResultBytes bounds one tool result; MaxToolBytes bounds all of them.
	MaxToolResultBytes int `yaml:"maxToolResultBytes"`
	MaxToolBytes       int `yaml:"maxToolBytes"`
	// MaxTurns caps model turns; MaxToolCalls caps tool invocations.
	MaxTurns     int `yaml:"maxTurns"`
	MaxToolCalls int `yaml:"maxToolCalls"`
	// MaxOutputTokens bounds one model response; MaxTotalTokens bounds the tokens
	// one scan may consume across all turns.
	MaxOutputTokens int `yaml:"maxOutputTokens"`
	MaxTotalTokens  int `yaml:"maxTotalTokens"`
}

// LLMPackageScanBudget bounds what the LLM package-content scan may spend on
// the provider (Task 173). When a ceiling is reached, further artifacts are not
// scanned until the window resets; failMode decides whether they are served.
type LLMPackageScanBudget struct {
	// Enabled turns on budget enforcement.
	Enabled bool `yaml:"enabled"`
	// GlobalCeilingUSD caps spend across all tenants per window (0 = unlimited).
	GlobalCeilingUSD float64 `yaml:"globalCeilingUsd"`
	// TenantCeilingUSD caps each tenant's spend per window (0 = unlimited).
	TenantCeilingUSD float64 `yaml:"tenantCeilingUsd"`
	// TenantCeilingsUSD overrides TenantCeilingUSD for specific tenants.
	TenantCeilingsUSD map[string]float64 `yaml:"tenantCeilingsUsd"`
	// Window is the period after which usage resets (0 => 24h).
	Window time.Duration `yaml:"window"`
	// Pricing overrides the built-in per-model price table (USD per 1M tokens),
	// keyed by model ID.
	Pricing map[string]ModelPriceConfig `yaml:"pricing"`
}

// validUpstreamTypes is the set of upstream (ecosystem) types the proxy fronts.
var validUpstreamTypes = map[string]bool{
	"git": true, "pip": true, "npm": true, "cargo": true,
	"go": true, "nuget": true, "docker": true, "maven": true,
	"rubygems": true, "composer": true, "helm": true,
	"apt": true, "deb": true, "yum": true, "rpm": true,
	"terraform": true, "conan": true, "swift": true,
	"dart": true, "pub": true, "huggingface": true,
	"conda": true, "cran": true, "hex": true,
	"bazel": true, "julia": true, "cpan": true,
	"openvsx": true, "nix": true, "generic": true,
	"jsr": true, "hackage": true, "homebrew": true,
	"ansible": true, "puppet": true,
}

// UpstreamTypes returns every upstream type the configuration accepts, aliases
// included ("apt" and "deb"), sorted. It exists so that catalogs keyed by
// upstream type — the LLM-scan coverage table, for one — can be held to the
// full set by a test: a type added here without an entry there fails the build.
func UpstreamTypes() []string {
	out := make([]string, 0, len(validUpstreamTypes))
	for t := range validUpstreamTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// llmEcosystemGitLFS is the LLM package-scan gate's ecosystem key for Git LFS
// objects (llmpkgscan.EcosystemGitLFS). It is not an upstream type: LFS objects
// are served by "git" upstreams, whose clones and fetches belong to the commit
// scan instead.
const llmEcosystemGitLFS = "git-lfs"

// knownEcosystem reports whether e names an ecosystem the LLM package-scan gate
// can be scoped to: an upstream type, one of the aliases the gate accepts, or
// "git-lfs".
func knownEcosystem(e string) bool {
	ce := canonLLMEcosystem(e)
	return ce == llmEcosystemGitLFS || validUpstreamTypes[ce]
}

// llmPackageScanProviders is the set of provider identifiers the gate accepts.
var llmPackageScanProviders = map[string]bool{"claude": true, "openai": true, "codex": true}

// EffectiveLLMPackageScan returns the LLM package-scan configuration with the
// values it inherits from the commit-scanning block filled in: an empty provider
// takes scanning.provider, and — when the provider is the same — an empty API
// key, base URL, API version or reasoning effort takes scanning's. It is the
// single place that inheritance is decided, shared by validation, preflight and
// the wiring layer.
func (c *Config) EffectiveLLMPackageScan() LLMPackageScanConfig {
	l := c.LLMPackageScan
	l.Provider = strings.ToLower(strings.TrimSpace(l.Provider))
	scanProvider := strings.ToLower(strings.TrimSpace(c.Scanning.Provider))
	inherited := false
	if l.Provider == "" && llmPackageScanProviders[scanProvider] {
		l.Provider = scanProvider
		inherited = true
	}
	// "codex" is the OpenAI-compatible provider under another name.
	same := inherited || (l.Provider != "" && providerFamily(l.Provider) == providerFamily(scanProvider))
	if same {
		if strings.TrimSpace(l.APIKey) == "" {
			l.APIKey = c.Scanning.APIKey
		}
		if strings.TrimSpace(l.BaseURL) == "" {
			l.BaseURL = c.Scanning.BaseURL
		}
		if strings.TrimSpace(l.APIVersion) == "" {
			l.APIVersion = c.Scanning.APIVersion
		}
		if strings.TrimSpace(l.ReasoningEffort) == "" {
			l.ReasoningEffort = c.Scanning.ReasoningEffort
		}
		if l.RequestTimeout == 0 {
			l.RequestTimeout = c.Scanning.Timeout
		}
	}
	if strings.TrimSpace(l.Model) == "" && inherited {
		l.Model = strings.TrimSpace(c.Scanning.Commit.DeepModel)
	}
	return l
}

// llmPackageScanDefaultEcosystems mirrors the gate's built-in ecosystem set
// (llmpkgscan.DefaultEcosystems), used when llmPackageScan.include is empty:
// every ecosystem the proxy fronts whose artifacts reach a client through the
// gate, plus Git LFS objects. "git" is deliberately absent — clones and fetches
// are the LLM commit scan's to judge.
var llmPackageScanDefaultEcosystems = []string{
	"npm", "pip", "cargo", "go", "nuget", "maven", "rubygems", "composer",
	"helm", "apt", "yum", "terraform", "conan", "conda", "cran", "cpan",
	"hex", "bazel", "julia", "jsr", "hackage", "nix", "homebrew", "ansible",
	"puppet", "swift", "dart", "openvsx", "huggingface", "docker", "generic",
	llmEcosystemGitLFS,
}

// LLMPackageScanDefaultEcosystems returns the ecosystems the LLM package scan
// covers when llmPackageScan.include is empty. It exists so the mirror above
// can be held to the gate's own list by a test outside this package.
func LLMPackageScanDefaultEcosystems() []string {
	return append([]string(nil), llmPackageScanDefaultEcosystems...)
}

// providerFamily folds provider aliases onto the client that serves them.
func providerFamily(p string) string {
	if p == "codex" {
		return "openai"
	}
	return p
}

// validateLLMPackageScan checks the LLM package-content scan gate configuration:
// a usable provider, valid action / fail mode / mode enums, thresholds within
// (0,1], non-negative timeouts, limits within their hard bounds, known
// ecosystems, and a sane budget.
func (c *Config) validateLLMPackageScan() error {
	if !c.LLMPackageScan.Enabled {
		return nil
	}
	l := c.EffectiveLLMPackageScan()
	if l.Provider == "" {
		return fmt.Errorf("config: llmPackageScan.provider is required when the gate is enabled (claude|openai|codex), or configure scanning.provider to inherit it")
	}
	if !llmPackageScanProviders[l.Provider] {
		return fmt.Errorf("config: llmPackageScan.provider must be claude|openai|codex, got %q", l.Provider)
	}
	if u := strings.TrimSpace(l.BaseURL); u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("config: llmPackageScan.baseUrl must be an absolute http(s) URL, got %q", l.BaseURL)
	}
	switch strings.ToLower(strings.TrimSpace(l.Mode)) {
	case "", "auto", "tools", "bundle":
	default:
		return fmt.Errorf("config: llmPackageScan.mode must be auto|tools|bundle, got %q", l.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(l.Action)) {
	case "", "annotate", "quarantine", "block":
	default:
		return fmt.Errorf("config: llmPackageScan.action must be annotate|quarantine|block, got %q", l.Action)
	}
	switch strings.ToLower(strings.TrimSpace(l.FailMode)) {
	case "", "open", "closed":
	default:
		return fmt.Errorf("config: llmPackageScan.failMode must be open|closed, got %q", l.FailMode)
	}
	switch strings.ToLower(strings.TrimSpace(l.Oversize)) {
	case "", "fail", "metadata-only":
	default:
		return fmt.Errorf("config: llmPackageScan.oversize must be fail|metadata-only, got %q", l.Oversize)
	}
	if l.MaliciousThreshold < 0 || l.MaliciousThreshold > 1 {
		return fmt.Errorf("config: llmPackageScan.maliciousThreshold must be within (0,1], got %g", l.MaliciousThreshold)
	}
	if l.SuspiciousThreshold < 0 || l.SuspiciousThreshold > 1 {
		return fmt.Errorf("config: llmPackageScan.suspiciousThreshold must be within (0,1], got %g", l.SuspiciousThreshold)
	}
	if l.Timeout < 0 || l.RequestTimeout < 0 || l.CacheTTL < 0 || l.ErrorTTL < 0 {
		return fmt.Errorf("config: llmPackageScan durations (timeout, requestTimeout, cacheTtl, errorTtl) must not be negative")
	}
	if l.MaxConcurrent < 0 {
		return fmt.Errorf("config: llmPackageScan.maxConcurrent must not be negative, got %d", l.MaxConcurrent)
	}
	for _, list := range []struct {
		name string
		ecos []string
	}{{"include", l.Include}, {"exclude", l.Exclude}} {
		for _, e := range list.ecos {
			if !knownEcosystem(e) {
				return fmt.Errorf("config: llmPackageScan.%s contains unknown ecosystem %q", list.name, e)
			}
		}
	}
	for _, name := range l.ExcludeUpstreams {
		// A typo here would send a private registry's packages to the provider, so
		// it is an error rather than a warning.
		if _, ok := c.Upstreams[strings.TrimSpace(name)]; !ok {
			return fmt.Errorf("config: llmPackageScan.excludeUpstreams names upstream %q, which is not defined under upstreams", name)
		}
	}
	if err := l.Limits.validate(); err != nil {
		return err
	}
	b := l.Budget
	if b.GlobalCeilingUSD < 0 || b.TenantCeilingUSD < 0 || b.Window < 0 {
		return fmt.Errorf("config: llmPackageScan.budget ceilings and window must not be negative")
	}
	for tenant, v := range b.TenantCeilingsUSD {
		if v < 0 {
			return fmt.Errorf("config: llmPackageScan.budget.tenantCeilingsUsd[%q] must not be negative", tenant)
		}
	}
	for model, p := range b.Pricing {
		if p.InputPerMTok < 0 || p.OutputPerMTok < 0 {
			return fmt.Errorf("config: llmPackageScan.budget.pricing[%q] must not be negative", model)
		}
	}
	return nil
}

// Hard bounds on the LLM package-scan limits. They mirror the gate's own
// (internal/llmpkgscan), which the configuration package deliberately does not
// import: doing so would link the LLM provider SDK into every tool that only
// reads configuration. A cross-check test in cmd/pullthrough keeps the two in
// agreement.
const (
	llmPkgScanMinPromptBytes     = 4 << 10
	llmPkgScanMinToolResultBytes = 1 << 10
	llmPkgScanMaxTurns           = 64
	llmPkgScanMaxToolCalls       = 512
	llmPkgScanMinOutputTokens    = 256
)

// validate checks the limits. A zero field is "use the default" and always
// valid; only an explicit out-of-range value is rejected.
func (l LLMPackageScanLimits) validate() error {
	if l.MaxArtifactBytes < 0 || l.MaxUnpackedBytes < 0 || l.MaxFileBytes < 0 {
		return fmt.Errorf("config: llmPackageScan.limits byte bounds must not be negative")
	}
	if l.MaxFiles < 0 || l.MaxDepth < 0 {
		return fmt.Errorf("config: llmPackageScan.limits.maxFiles and maxDepth must not be negative")
	}
	if l.MaxCompressionRatio != 0 && l.MaxCompressionRatio < 1 {
		return fmt.Errorf("config: llmPackageScan.limits.maxCompressionRatio must be at least 1, got %g", l.MaxCompressionRatio)
	}
	if l.MaxPromptBytes != 0 && l.MaxPromptBytes < llmPkgScanMinPromptBytes {
		return fmt.Errorf("config: llmPackageScan.limits.maxPromptBytes must be at least %d, got %d", llmPkgScanMinPromptBytes, l.MaxPromptBytes)
	}
	if l.MaxToolResultBytes != 0 && l.MaxToolResultBytes < llmPkgScanMinToolResultBytes {
		return fmt.Errorf("config: llmPackageScan.limits.maxToolResultBytes must be at least %d, got %d", llmPkgScanMinToolResultBytes, l.MaxToolResultBytes)
	}
	if l.MaxToolBytes < 0 || (l.MaxToolBytes != 0 && l.MaxToolResultBytes != 0 && l.MaxToolBytes < l.MaxToolResultBytes) {
		return fmt.Errorf("config: llmPackageScan.limits.maxToolBytes must not be smaller than maxToolResultBytes")
	}
	if l.MaxTurns < 0 || l.MaxTurns > llmPkgScanMaxTurns {
		return fmt.Errorf("config: llmPackageScan.limits.maxTurns must be within [1,%d], got %d", llmPkgScanMaxTurns, l.MaxTurns)
	}
	if l.MaxToolCalls < 0 || l.MaxToolCalls > llmPkgScanMaxToolCalls {
		return fmt.Errorf("config: llmPackageScan.limits.maxToolCalls must be within [0,%d], got %d", llmPkgScanMaxToolCalls, l.MaxToolCalls)
	}
	if l.MaxOutputTokens != 0 && l.MaxOutputTokens < llmPkgScanMinOutputTokens {
		return fmt.Errorf("config: llmPackageScan.limits.maxOutputTokens must be at least %d, got %d", llmPkgScanMinOutputTokens, l.MaxOutputTokens)
	}
	if l.MaxTotalTokens < 0 || (l.MaxTotalTokens != 0 && l.MaxOutputTokens != 0 && l.MaxTotalTokens < l.MaxOutputTokens) {
		return fmt.Errorf("config: llmPackageScan.limits.maxTotalTokens must not be smaller than maxOutputTokens")
	}
	return nil
}

// MalfeedSourceConfig describes one upstream malware feed.
type MalfeedSourceConfig struct {
	// URL is the HTTP(S) endpoint serving the OSV-formatted feed.
	URL string `yaml:"url"`
	// Name labels the source for provenance/logging. Defaults to the URL.
	Name string `yaml:"name"`
}

// SigverifyConfig configures the Sigstore/cosign signature & attestation
// verification gate (Task 23): before an artifact is cached/served the proxy
// verifies cosign signatures and SLSA provenance attestations for OCI images and
// Sigstore publish attestations for npm/pip packages, then warns or blocks per
// the configured thresholds. Trust is established either keyless (a Fulcio root +
// allowed OIDC identities, optionally with a Rekor inclusion proof) or keyed
// (operator-configured public keys). For air-gapped deployments the trust
// material is loaded from a portable trust bundle.
type SigverifyConfig struct {
	// Enabled turns on signature/attestation verification. When false, artifacts
	// are served without an authenticity check.
	Enabled bool `yaml:"enabled"`
	// Ecosystems selects which ecosystems are verified (docker, npm, pip). Empty
	// defaults to docker only.
	Ecosystems []string `yaml:"ecosystems"`

	// Action is applied when a finding meets FailSeverity: "warn" (advisory),
	// "block", or "quarantine" (required/enforcing). Default "block".
	Action string `yaml:"action"`
	// FailSeverity is the minimum finding severity that triggers Action
	// (none|low|medium|high|critical; default "high").
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity that triggers a warning below the fail
	// threshold (default "medium"). Empty disables warnings.
	WarnSeverity string `yaml:"warnSeverity"`

	// RequireSignature treats an unsigned artifact as a (high-severity) finding.
	RequireSignature bool `yaml:"requireSignature"`
	// RequireAttestation additionally requires a verified SLSA provenance
	// attestation, not merely a signature.
	RequireAttestation bool `yaml:"requireAttestation"`
	// RequireRekorProof requires keyless signatures to carry a verified Rekor
	// transparency-log inclusion proof.
	RequireRekorProof bool `yaml:"requireRekorProof"`
	// FailOnError blocks an artifact whose verification could not be performed
	// (an infrastructure error); default serves with a warning (fail-open).
	FailOnError bool `yaml:"failOnError"`

	// TrustRootsFile is a PEM bundle of Fulcio root CA certificates for keyless
	// certificate-chain trust.
	TrustRootsFile string `yaml:"trustRootsFile"`
	// UseSystemTrustRoots uses the host trust store when no TrustRootsFile is set.
	UseSystemTrustRoots bool `yaml:"useSystemTrustRoots"`
	// RekorKeyFiles are PEM public-key files of trusted Rekor transparency logs,
	// used to verify Signed Entry Timestamps.
	RekorKeyFiles []string `yaml:"rekorKeyFiles"`
	// Keys are operator-configured public keys for keyed verification.
	Keys []SigverifyKey `yaml:"keys"`
	// Identities is the allowed keyless signer policy (OIDC issuer + identity
	// pattern). Empty means any identity chaining to a trusted root is accepted.
	Identities []SigverifyIdentity `yaml:"identities"`

	// NPMRegistryURL is the npm registry whose publish-attestations endpoint is
	// queried (default "https://registry.npmjs.org").
	NPMRegistryURL string `yaml:"npmRegistryUrl"`
	// PyPIURL is the PyPI base whose PEP 740 provenance is queried (default
	// "https://pypi.org").
	PyPIURL string `yaml:"pypiUrl"`

	// Offline forces air-gapped operation: the trust material must come from
	// TrustBundleFile rather than inline files.
	Offline bool `yaml:"offline"`
	// TrustBundleFile is a portable trust bundle (see internal/sigverify) carrying
	// roots, Rekor keys, public keys, and the identity policy for air-gapped use.
	TrustBundleFile string `yaml:"trustBundleFile"`
	// TrustBundleDigest, when set, is the expected "sha256:<hex>" digest the
	// bundle is verified against on load (out-of-band integrity check).
	TrustBundleDigest string `yaml:"trustBundleDigest"`

	// CacheTTL bounds how long a verification result is reused (0 = never expire).
	CacheTTL time.Duration `yaml:"cacheTtl"`
	// CacheMaxEntries bounds the verification-result cache (0 = default).
	CacheMaxEntries int `yaml:"cacheMaxEntries"`

	// PQC configures optional post-quantum / hybrid signature verification
	// (ML-DSA / FIPS 204, SLH-DSA / FIPS 205, and hybrid classical+PQC), Task 151.
	PQC SigverifyPQCConfig `yaml:"pqc"`
}

// SigverifyPQCConfig configures post-quantum and hybrid signature verification
// for the signature gate (Task 151). It is OFF by default: the PQC provider
// (cloudflare/circl) implements the standardized algorithms but is not a FIPS
// 140-3 validated cryptographic module, so under FIPS mode enabling it fails
// startup preflight with a clear message rather than silently running a
// non-validated provider.
type SigverifyPQCConfig struct {
	// Enabled turns on post-quantum / hybrid signature verification. When false,
	// a presented PQC/hybrid signature is reported but never establishes trust
	// (classical-only behavior).
	Enabled bool `yaml:"enabled"`
	// Policy selects how PQC/hybrid algorithms participate in the trust decision:
	//   - "classical-only": accept only classical signatures (PQC/hybrid reported
	//     but never trusted);
	//   - "allow-hybrid" (default): accept classical, hybrid, and pure PQC;
	//   - "require-pqc": demand post-quantum protection — a classical-only trusted
	//     signature is flagged quantum-vulnerable.
	Policy string `yaml:"policy"`
}

// SigverifyKey is an operator-configured public key for keyed verification.
type SigverifyKey struct {
	// Name identifies the key for reporting (e.g. "release-signing-key").
	Name string `yaml:"name"`
	// File is a path to a PEM public key (or certificate). PEM is the inline form.
	File string `yaml:"file"`
	PEM  string `yaml:"pem"`
}

// SigverifyIdentity is an allowed keyless signer: an OIDC issuer (exact match
// when set) and an anchored regular expression the certificate identity must
// match.
type SigverifyIdentity struct {
	Issuer         string `yaml:"issuer"`
	SubjectPattern string `yaml:"subjectPattern"`
}

// NotifyConfig configures the notification & alerting subsystem (Task 21): a
// pluggable event-notification layer that dispatches structured alerts on
// security-relevant events (policy blocks, vulnerability findings, malicious
// commit-scan verdicts, provenance failures, quarantine actions, and CVE-drift
// regressions) to generic HTTP webhook and Slack incoming-webhook sinks.
// Delivery is asynchronous and bounded so notifications never block the request
// path.
type NotifyConfig struct {
	// Enabled turns on the subsystem. When false, no notifications are sent.
	Enabled bool `yaml:"enabled"`
	// Workers is the number of asynchronous delivery workers (default 2).
	Workers int `yaml:"workers"`
	// QueueSize bounds the async delivery queue; when full, a notification is
	// dropped rather than blocking the request path (default 256).
	QueueSize int `yaml:"queueSize"`
	// MaxRetries is the number of additional delivery attempts after the first on
	// a retryable (5xx/429/network) failure (default 3).
	MaxRetries int `yaml:"maxRetries"`
	// RetryBaseDelay is the base of the exponential backoff between retries
	// (default 500ms); RetryMaxDelay caps it (default 30s).
	RetryBaseDelay time.Duration `yaml:"retryBaseDelay"`
	RetryMaxDelay  time.Duration `yaml:"retryMaxDelay"`
	// Timeout bounds a single delivery attempt (default 10s).
	Timeout time.Duration `yaml:"timeout"`
	// MinSeverity is the global severity floor; events below it are never
	// delivered (none|low|medium|high|critical; empty means no floor).
	MinSeverity string `yaml:"minSeverity"`
	// RedactFields are extra field-key substrings to scrub from payloads in
	// addition to the built-in credential set.
	RedactFields []string `yaml:"redactFields"`
	// Sinks are the configured delivery destinations.
	Sinks []NotifySinkConfig `yaml:"sinks"`
	// Routes map event types and severities to sinks. When empty, every event
	// type is delivered to every sink at MinSeverity.
	Routes []NotifyRouteConfig `yaml:"routes"`
}

// NotifySinkConfig configures one notification delivery destination.
type NotifySinkConfig struct {
	// Name uniquely identifies the sink (routing, metrics, the test endpoint).
	Name string `yaml:"name"`
	// Kind selects the implementation: "webhook" or "slack".
	Kind string `yaml:"kind"`
	// URL is the destination endpoint (the webhook URL or Slack incoming-webhook
	// URL). It supports ${ENV_VAR} expansion and "enc:v1:" encryption so the
	// (secret) Slack/webhook URL need not be committed to disk.
	URL string `yaml:"url"`
	// Headers are extra HTTP headers for the generic webhook sink (e.g. an
	// authorization or HMAC-signature header). Ignored by the Slack sink.
	Headers map[string]string `yaml:"headers"`
	// Channel, Username, and IconEmoji are optional Slack display overrides.
	Channel   string `yaml:"channel"`
	Username  string `yaml:"username"`
	IconEmoji string `yaml:"iconEmoji"`
	// InsecureSkipVerify disables TLS verification of the endpoint (test only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
}

// NotifyRouteConfig binds one or more sinks to the event types and minimum
// severity they should receive.
type NotifyRouteConfig struct {
	// Sinks are the sink names this route delivers to.
	Sinks []string `yaml:"sinks"`
	// EventTypes restricts the route to these event types (policy_block,
	// vulnerability, commit_scan, provenance_failure, quarantine,
	// rescan_regression); empty matches all.
	EventTypes []string `yaml:"eventTypes"`
	// MinSeverity is the route's severity floor in addition to the global one.
	MinSeverity string `yaml:"minSeverity"`
}

// SIEMConfig configures the outbound SIEM / log-forwarding subsystem (Task 119):
// a forwarder that streams tamper-evident audit records and admission-gate
// findings to external SIEMs. Delivery is asynchronous, batched, and bounded so
// a slow or unreachable SIEM never blocks the pull path, and the local audit
// log's hash chain is never touched (the forwarder taps records read-only after
// they are durably committed).
type SIEMConfig struct {
	// Enabled turns on the subsystem. When false, nothing is forwarded.
	Enabled bool `yaml:"enabled"`
	// QueueSize bounds the in-memory delivery queue; overflow spills to disk when
	// spill is enabled, otherwise it is dropped (default 1024).
	QueueSize int `yaml:"queueSize"`
	// BatchSize is the maximum number of events delivered in one request/batch
	// (default 100).
	BatchSize int `yaml:"batchSize"`
	// BatchTimeout is the maximum time a partial batch waits before being
	// flushed; it also drives the periodic flush of spilled events (default 5s).
	BatchTimeout time.Duration `yaml:"batchTimeout"`
	// MaxRetries is the number of additional attempts after the first on a
	// retryable (5xx/429/network) failure (default 3).
	MaxRetries int `yaml:"maxRetries"`
	// RetryBaseDelay is the base of the exponential backoff between retries
	// (default 500ms); RetryMaxDelay caps it (default 30s).
	RetryBaseDelay time.Duration `yaml:"retryBaseDelay"`
	RetryMaxDelay  time.Duration `yaml:"retryMaxDelay"`
	// Timeout bounds a single batch-delivery attempt (default 10s).
	Timeout time.Duration `yaml:"timeout"`
	// MinSeverity is the severity floor; events below it are never forwarded
	// (info|low|medium|high|critical; empty means info, i.e. forward all).
	MinSeverity string `yaml:"minSeverity"`
	// ForwardAudit and ForwardFindings select which internal streams are
	// forwarded. Both default to true when the subsystem is enabled.
	ForwardAudit    *bool `yaml:"forwardAudit"`
	ForwardFindings *bool `yaml:"forwardFindings"`
	// Spill configures the bounded disk-spill overflow queue.
	Spill SIEMSpillConfig `yaml:"spill"`
	// OCSF configures the Open Cybersecurity Schema Framework output encoder
	// shared by all sinks of kind "ocsf".
	OCSF SIEMOCSFConfig `yaml:"ocsf"`
	// Sinks are the configured forwarding destinations.
	Sinks []SIEMSinkConfig `yaml:"sinks"`
}

// SBOMExportConfig configures the outbound SBOM/findings federation subsystem
// (Task 153). When Enabled, at least one sink (dependencyTrack or guac) must be
// enabled. Credentials (dependencyTrack.apiKey, guac.token) accept a secretRef.
type SBOMExportConfig struct {
	// Enabled turns on the subsystem. When false, nothing is exported.
	Enabled bool `yaml:"enabled"`
	// IncludeFindings embeds admission-gate vulnerability findings into the
	// exported BOMs as a CycloneDX vulnerabilities array. Defaults to true when the
	// subsystem is enabled.
	IncludeFindings *bool `yaml:"includeFindings"`
	// MinSeverity drops embedded findings below this floor
	// (info|low|medium|high|critical; empty means keep all). It only affects the
	// embedded vulnerabilities, never the SBOM components.
	MinSeverity string `yaml:"minSeverity"`
	// Interval drives the periodic, leader-gated export sweep. A zero/omitted value
	// disables the automatic sweep (export then runs only on an explicit
	// `ptctl sbom-export run` trigger). Default 0.
	Interval time.Duration `yaml:"interval"`
	// MaxRetries is the number of additional attempts after the first on a
	// retryable (5xx/429/network) upload failure (default 3).
	MaxRetries int `yaml:"maxRetries"`
	// RetryBaseDelay is the base of the exponential backoff between retries
	// (default 500ms); RetryMaxDelay caps it (default 30s).
	RetryBaseDelay time.Duration `yaml:"retryBaseDelay"`
	RetryMaxDelay  time.Duration `yaml:"retryMaxDelay"`
	// Timeout bounds a single upload attempt (default 30s).
	Timeout time.Duration `yaml:"timeout"`
	// DependencyTrack configures the OWASP Dependency-Track sink.
	DependencyTrack SBOMExportDependencyTrackConfig `yaml:"dependencyTrack"`
	// GUAC configures the GUAC collector ingestion sink.
	GUAC SBOMExportGUACConfig `yaml:"guac"`
}

// IncludeFindingsOrDefault reports whether findings are embedded, defaulting to
// true when unset.
func (s SBOMExportConfig) IncludeFindingsOrDefault() bool {
	if s.IncludeFindings == nil {
		return true
	}
	return *s.IncludeFindings
}

// SBOMExportDependencyTrackConfig configures the OWASP Dependency-Track sink. It
// uploads one CycloneDX BOM per coordinate via PUT {url}/api/v1/bom.
type SBOMExportDependencyTrackConfig struct {
	// Enabled turns on the Dependency-Track sink.
	Enabled bool `yaml:"enabled"`
	// URL is the base URL of the Dependency-Track API server, e.g.
	// https://dtrack.example.com (required when enabled).
	URL string `yaml:"url"`
	// APIKey is the Dependency-Track API key, sent as the X-Api-Key header
	// (required when enabled; accepts a secretRef).
	APIKey string `yaml:"apiKey"`
	// AutoCreate requests that Dependency-Track create the project on first upload
	// if it does not exist. Defaults to true when the sink is enabled.
	AutoCreate *bool `yaml:"autoCreate"`
	// ParentProject optionally nests auto-created projects under a parent project
	// by name.
	ParentProject string `yaml:"parentProject"`
	// TLSSkipVerify disables TLS certificate verification for the Dependency-Track
	// endpoint (self-signed internal servers only).
	TLSSkipVerify bool `yaml:"tlsSkipVerify"`
}

// AutoCreateOrDefault reports whether project auto-create is requested,
// defaulting to true when unset.
func (d SBOMExportDependencyTrackConfig) AutoCreateOrDefault() bool {
	if d.AutoCreate == nil {
		return true
	}
	return *d.AutoCreate
}

// SBOMExportGUACConfig configures the GUAC collector ingestion sink.
type SBOMExportGUACConfig struct {
	// Enabled turns on the GUAC sink.
	Enabled bool `yaml:"enabled"`
	// URL is the GUAC collector HTTP ingestion endpoint (required when enabled).
	URL string `yaml:"url"`
	// Token is an optional bearer token for the ingestion endpoint (accepts a
	// secretRef).
	Token string `yaml:"token"`
	// DocumentType selects the emitted document form: "cyclonedx" (default) posts
	// the raw CycloneDX BOM; "intoto" wraps the BOM as an in-toto statement
	// predicate.
	DocumentType string `yaml:"documentType"`
	// TLSSkipVerify disables TLS certificate verification for the GUAC endpoint
	// (self-signed internal servers only).
	TLSSkipVerify bool `yaml:"tlsSkipVerify"`
}

// SIEMOCSFConfig configures the OCSF output encoder (Task 139). It applies to
// every sink of kind "ocsf" and normalizes audit records and gate findings into
// OCSF event classes (Detection Finding, Vulnerability Finding, Compliance
// Finding, Authentication, API Activity) for ingestion by OCSF-aware platforms
// such as AWS Security Lake and Snowflake.
type SIEMOCSFConfig struct {
	// SchemaVersion is the OCSF schema version stamped into metadata.version
	// (default 1.1.0).
	SchemaVersion string `yaml:"schemaVersion"`
	// ClassMap overrides the built-in category->class routing. Each key is an
	// event category — the gate name for findings (e.g. "vulnscan", "license") or
	// the audit event type for audit records (e.g. "auth", "policy_decision") —
	// and each value names an OCSF class: "detection_finding",
	// "vulnerability_finding", "compliance_finding", "authentication", or
	// "api_activity".
	ClassMap map[string]string `yaml:"classMap"`
	// ProductName and VendorName populate OCSF metadata.product (defaults
	// "pullthrough-security" / "Blechschmidt").
	ProductName string `yaml:"productName"`
	VendorName  string `yaml:"vendorName"`
}

// ForwardAuditOrDefault reports whether audit records are forwarded, defaulting
// to true when unset.
func (s SIEMConfig) ForwardAuditOrDefault() bool {
	if s.ForwardAudit == nil {
		return true
	}
	return *s.ForwardAudit
}

// ForwardFindingsOrDefault reports whether gate findings are forwarded,
// defaulting to true when unset.
func (s SIEMConfig) ForwardFindingsOrDefault() bool {
	if s.ForwardFindings == nil {
		return true
	}
	return *s.ForwardFindings
}

// SIEMSpillConfig configures the bounded, file-backed overflow queue that
// absorbs bursts exceeding the in-memory queue without losing events or growing
// memory without bound. It survives a restart.
type SIEMSpillConfig struct {
	// Enabled turns on disk spill for queue overflow.
	Enabled bool `yaml:"enabled"`
	// File is the spill file path (required when enabled).
	File string `yaml:"file"`
	// MaxBytes caps the on-disk spill size; further overflow is dropped. A
	// non-positive value disables the cap (default 0 = capped by nothing, so set
	// it in production).
	MaxBytes int64 `yaml:"maxBytes"`
}

// SIEMSinkConfig configures one SIEM forwarding destination. Which fields apply
// depends on kind.
type SIEMSinkConfig struct {
	// Name uniquely identifies the sink (metrics labels, logs).
	Name string `yaml:"name"`
	// Kind selects the implementation: "splunk_hec", "syslog", or "ocsf".
	Kind string `yaml:"kind"`

	// --- Splunk HEC (kind: splunk_hec) and OCSF HTTP (kind: ocsf) ---
	// URL is the destination endpoint. For HEC a bare base URL has the standard
	// "/services/collector/event" path appended; for OCSF it is used verbatim.
	// Supports ${ENV} and "enc:v1:".
	URL string `yaml:"url"`
	// Token is the bearer/HEC token. For HEC it is sent as "Authorization: Splunk
	// <token>"; for OCSF it is sent as "Authorization: Bearer <token>" unless
	// authHeader/authScheme override it. Supports ${ENV} expansion and "enc:v1:"
	// encryption so it need not be committed.
	Token string `yaml:"token"`
	// AuthHeader and AuthScheme (kind: ocsf only) override how the token is sent:
	// authHeader is the header name (default "Authorization") and authScheme is
	// the value prefix (default "Bearer"; set to "" for a bare token).
	AuthHeader string `yaml:"authHeader"`
	AuthScheme string `yaml:"authScheme"`
	// Index, Source, SourceType, Host populate the HEC event envelope when set.
	Index      string `yaml:"index"`
	Source     string `yaml:"source"`
	SourceType string `yaml:"sourceType"`
	Host       string `yaml:"host"`
	// Headers are additional static HTTP headers (rarely needed).
	Headers map[string]string `yaml:"headers"`

	// --- Syslog / CEF (kind: syslog) ---
	// Address is the collector "host:port".
	Address string `yaml:"address"`
	// Network is "tcp", "udp", or "tcp+tls" (default "tcp").
	Network string `yaml:"network"`
	// Facility is the syslog facility number 0..23 (default 16 = local0).
	Facility int `yaml:"facility"`
	// Hostname overrides the syslog HOSTNAME field (default: OS hostname).
	Hostname string `yaml:"hostname"`
	// AppName is the syslog APP-NAME (default "pullthrough").
	AppName string `yaml:"appName"`
	// Vendor, Product, Version populate the CEF header prefix.
	Vendor  string `yaml:"vendor"`
	Product string `yaml:"product"`
	Version string `yaml:"version"`

	// --- TLS (HEC and syslog tcp+tls) ---
	TLS SIEMTLSConfig `yaml:"tls"`
}

// SIEMTLSConfig configures TLS for the HEC and syslog(+TLS) sinks.
type SIEMTLSConfig struct {
	// InsecureSkipVerify disables certificate verification (test only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// CAFile is a PEM bundle of additional root CAs to trust (e.g. an internal
	// SIEM's private CA).
	CAFile string `yaml:"caFile"`
	// ServerName overrides the SNI / verified certificate name.
	ServerName string `yaml:"serverName"`
	// MinVersion is the minimum TLS version ("1.2" or "1.3"; default 1.2).
	MinVersion string `yaml:"minVersion"`
}

// PrewarmConfig configures the predictive cache pre-warming subsystem (Task
// 134). The zero value is disabled. Operational defaults for the unset fields
// are applied downstream in prewarm.New.
type PrewarmConfig struct {
	// Enabled turns the subsystem on. When false, no history is collected and no
	// pre-warming runs.
	Enabled bool `yaml:"enabled"`
	// Interval is the periodic prediction + pre-warm cycle cadence (default 1h).
	Interval time.Duration `yaml:"interval"`
	// OffPeakStart and OffPeakEnd bound the daily window (in OffPeakTimezone) in
	// which pre-warming may run, as "HH:MM". Both empty means any time; a window
	// may wrap midnight (e.g. start "22:00", end "05:00"). On-demand runs via the
	// admin API bypass the window.
	OffPeakStart string `yaml:"offPeakStart"`
	OffPeakEnd   string `yaml:"offPeakEnd"`
	// OffPeakTimezone is an IANA timezone for the window (default "UTC").
	OffPeakTimezone string `yaml:"offPeakTimezone"`
	// MaxConcurrency bounds parallel pre-warm fetches (default 2).
	MaxConcurrency int `yaml:"maxConcurrency"`
	// MaxPerCycle caps how many predicted targets are fetched per cycle (default
	// 50), bounding a single cycle's upstream load.
	MaxPerCycle int `yaml:"maxPerCycle"`
	// RatePerMinute caps the pre-warm fetch rate across a cycle; 0 (default) means
	// unlimited (still bounded by MaxConcurrency and MaxPerCycle).
	RatePerMinute int `yaml:"ratePerMinute"`
	// MinPulls is the minimum observed pulls for a coordinate before its patch/
	// minor releases are forecast (default 3).
	MinPulls int `yaml:"minPulls"`
	// RecencyWindow bounds how recently a coordinate must have been pulled to be
	// considered (default 168h / 7d). Zero disables the recency filter.
	RecencyWindow time.Duration `yaml:"recencyWindow"`
	// PatchLookahead is how many successive patch versions to predict past the
	// highest observed version (default 2).
	PatchLookahead int `yaml:"patchLookahead"`
	// PredictMinor also predicts the next minor release's initial (.0) version.
	PredictMinor bool `yaml:"predictMinor"`
	// TransitiveDeps expands recently-pulled top-level packages to their direct
	// dependencies (requires the provenance/dependency graph, provgraph).
	TransitiveDeps bool `yaml:"transitiveDeps"`
	// HistorySize bounds the distinct coordinates tracked in the learned history
	// (default 4096).
	HistorySize int `yaml:"historySize"`
	// HistoryPath, when set, persists the learned history to this file so patterns
	// survive a restart.
	HistoryPath string `yaml:"historyPath"`
}

// ObservabilityConfig configures the metrics, health, and admin surfaces.
type ObservabilityConfig struct {
	// Metrics enables the Prometheus metrics endpoint.
	Metrics bool `yaml:"metrics"`
	// MetricsPath is the path the metrics are exposed on (default "/metrics").
	MetricsPath string `yaml:"metricsPath"`
	// Admin enables the admin REST API and web dashboard.
	Admin bool `yaml:"admin"`
	// AdminPathPrefix is the path prefix the admin surface is mounted under
	// (default "/admin").
	AdminPathPrefix string `yaml:"adminPathPrefix"`
	// AdminToken, when set, requires callers to present it as a bearer token
	// ("Authorization: Bearer <token>") to reach the admin surface. It supports
	// ${ENV_VAR} expansion so it need not be committed to disk. Empty leaves the
	// admin surface unauthenticated (intended for trusted networks only).
	AdminToken string `yaml:"adminToken"`

	// Portal enables the tenant self-service read-only security portal (Task 71),
	// a non-admin surface hard-scoped to the caller's own tenant. It requires
	// adminAuth (OIDC and/or static tokens) to identify the tenant and is mounted
	// separately from the privileged admin UI.
	Portal bool `yaml:"portal"`
	// PortalPathPrefix is the path prefix the portal is mounted under
	// (default "/portal").
	PortalPathPrefix string `yaml:"portalPathPrefix"`

	// MCP enables the read-only Model Context Protocol server (Task 79), an MCP
	// (JSON-RPC 2.0) endpoint mounted under the admin API at /api/mcp that exposes
	// the proxy's supply-chain security knowledge to AI agents. It reuses the admin
	// RBAC layer (the read capability) and is hard-scoped to the caller's tenant.
	// Enabled by default whenever the admin surface is on.
	MCP bool `yaml:"mcp"`
	// MCPMaxDetailItems bounds the number of detail records (findings,
	// vulnerabilities, timeline events, dependents) any single MCP tool returns,
	// so a hostile or careless call cannot make the proxy marshal an unbounded
	// payload. Defaults to 100.
	MCPMaxDetailItems int `yaml:"mcpMaxDetailItems"`

	// GRPC enables the read-only gRPC/Connect security API (Task 159): a
	// Connect-compatible handler (speaking gRPC, gRPC-Web, and HTTP/JSON) mounted
	// under the admin API at /api/grpc that projects the same security data model
	// as the GraphQL federated query API (Task 67) and the MCP server (Task 79) —
	// coordinate dossier lookup, findings/corpus queries, risk verdicts,
	// provenance-graph edges, and the compliance scorecard. It reuses the admin
	// RBAC layer (the read capability) and is hard-scoped to the caller's tenant.
	// Off by default (opt-in); requires the admin surface.
	GRPC bool `yaml:"grpc"`
	// GRPCMaxDetailItems bounds the number of detail records (findings,
	// vulnerabilities, dependents, risk contributions) any single gRPC RPC
	// returns. Defaults to 100.
	GRPCMaxDetailItems int `yaml:"grpcMaxDetailItems"`

	// Profiling exposes the net/http/pprof runtime-profiling endpoints (CPU,
	// heap, goroutine, block, mutex) and the runtime/trace execution-trace
	// capture under the admin API at <adminPrefix>/api/debug/pprof/. The
	// endpoints inherit the admin authentication + RBAC (they require the
	// operator capability), so they are never exposed on a separate or
	// unauthenticated listener. Off by default: a CPU profile or trace holds the
	// profiler for its duration and the endpoints reveal detailed runtime
	// internals, so an operator opts in explicitly. Requires the admin surface.
	Profiling bool `yaml:"profiling"`
	// ProfilingBlockRate configures runtime.SetBlockProfileRate when profiling is
	// enabled: the approximate nanoseconds of blocking between sampled events.
	// 0 (the default) leaves block profiling off (zero overhead); a positive
	// value such as 10000 enables low-overhead sampling so /debug/pprof/block
	// returns data.
	ProfilingBlockRate int `yaml:"profilingBlockRate"`
	// ProfilingMutexFraction configures runtime.SetMutexProfileFraction when
	// profiling is enabled: on average 1/N mutex-contention events are reported.
	// 0 (the default) leaves mutex profiling off; a value such as 100 enables
	// low-overhead sampling so /debug/pprof/mutex returns data.
	ProfilingMutexFraction int `yaml:"profilingMutexFraction"`
}

// MCPMaxDetailItemsOrDefault returns the per-tool MCP detail cap, defaulting to
// 100 when unset.
func (o ObservabilityConfig) MCPMaxDetailItemsOrDefault() int {
	if o.MCPMaxDetailItems <= 0 {
		return 100
	}
	return o.MCPMaxDetailItems
}

// GRPCMaxDetailItemsOrDefault returns the per-RPC gRPC detail cap, defaulting to
// 100 when unset.
func (o ObservabilityConfig) GRPCMaxDetailItemsOrDefault() int {
	if o.GRPCMaxDetailItems <= 0 {
		return 100
	}
	return o.GRPCMaxDetailItems
}

// PortalPrefixOrDefault returns the portal mount prefix, defaulting to "/portal".
func (o ObservabilityConfig) PortalPrefixOrDefault() string {
	p := strings.TrimRight(strings.TrimSpace(o.PortalPathPrefix), "/")
	if p == "" {
		return "/portal"
	}
	return p
}

// AdminAuthConfig configures OIDC/OAuth2 SSO and RBAC for the admin API/UI
// (Task 51). When Enabled is false the admin surface keeps its prior behavior
// (the legacy observability.adminToken bearer check, or open on a trusted
// network). When Enabled is true, the admin surface requires an authenticated
// identity whose mapped role grants the capability each endpoint demands.
type AdminAuthConfig struct {
	// Enabled turns on SSO/RBAC enforcement for the admin surface.
	Enabled bool `yaml:"enabled"`

	// OIDC configures authorization-code login (UI) and bearer-JWT validation
	// (API). Optional: a deployment may run in static-only (air-gapped) mode by
	// configuring StaticTokens without OIDC.
	OIDC AdminOIDCConfig `yaml:"oidc"`

	// StaticTokens are bearer tokens mapped to roles for the documented
	// offline/static mode (no IdP reachable).
	StaticTokens []AdminStaticTokenConfig `yaml:"staticTokens"`

	// AllowLegacyToken keeps honoring observability.adminToken (granting the
	// admin role) alongside SSO/RBAC. Defaults to true so enabling adminAuth on a
	// deployment that relied on the legacy token does not lock operators out.
	AllowLegacyToken *bool `yaml:"allowLegacyToken"`

	// SessionKey signs the admin session and login-flow cookies (HMAC-SHA256). It
	// is required when OIDC is enabled and must carry at least 16 bytes. Supports
	// ${ENV} and enc:v1: values.
	SessionKey string `yaml:"sessionKey"`
	// SessionTTL bounds an SSO session's lifetime (default 8h).
	SessionTTL time.Duration `yaml:"sessionTtl"`
	// CookieName overrides the session cookie name.
	CookieName string `yaml:"cookieName"`
	// InsecureCookies disables the Secure cookie flag (plain-HTTP local/testing
	// only). Cookies are Secure by default.
	InsecureCookies bool `yaml:"insecureCookies"`

	// RoleBindings map IdP group/role names to a canonical role
	// (viewer|operator|approver|admin). A group already named like a canonical
	// role needs no binding.
	RoleBindings map[string]string `yaml:"roleBindings"`
	// DefaultRole is granted to an authenticated caller that matches no binding
	// (empty denies such callers).
	DefaultRole string `yaml:"defaultRole"`
}

// AdminOIDCConfig configures the OIDC/OAuth2 provider for the admin surface.
type AdminOIDCConfig struct {
	// Enabled turns on OIDC login + bearer validation.
	Enabled bool `yaml:"enabled"`
	// Issuer is the IdP issuer URL ("iss"). Required when enabled.
	Issuer string `yaml:"issuer"`
	// ClientID is the registered OAuth2 client id. Required when enabled.
	ClientID string `yaml:"clientId"`
	// ClientSecret authenticates a confidential client at the token endpoint
	// (empty = public client, PKCE only). Supports ${ENV} and enc:v1:.
	ClientSecret string `yaml:"clientSecret"`
	// RedirectURL is this proxy's externally reachable callback URL. Required
	// when enabled (e.g. https://proxy.example.com/admin/auth/callback).
	RedirectURL string `yaml:"redirectUrl"`
	// Scopes requested at login (default "openid profile email groups").
	Scopes []string `yaml:"scopes"`
	// Audience is the expected "aud" for admin API bearer JWTs (default ClientID).
	Audience string `yaml:"audience"`

	// DiscoveryURL overrides the well-known discovery document URL. When the
	// explicit endpoints and a key source below are all set, discovery is skipped.
	DiscoveryURL string `yaml:"discoveryUrl"`
	// AuthorizationEndpoint/TokenEndpoint/EndSessionEndpoint pin the OAuth2
	// endpoints (else they are discovered).
	AuthorizationEndpoint string `yaml:"authorizationEndpoint"`
	TokenEndpoint         string `yaml:"tokenEndpoint"`
	EndSessionEndpoint    string `yaml:"endSessionEndpoint"`
	// JWKSURL is the issuer's JWK Set endpoint (else discovered).
	JWKSURL string `yaml:"jwksUrl"`
	// JWKS is an inline JWK Set document for air-gapped key pinning.
	JWKS string `yaml:"jwks"`

	// SubjectClaim/GroupsClaim name the claims for the subject and group/role
	// membership (defaults "sub"/"groups").
	SubjectClaim string `yaml:"subjectClaim"`
	GroupsClaim  string `yaml:"groupsClaim"`
	// TenantClaim names the claim carrying the caller's tenant/team. It scopes the
	// tenant self-service portal (Task 71). Default "team".
	TenantClaim string `yaml:"tenantClaim"`

	// JWKSCacheTTL bounds JWKS caching (default 15m); Leeway tolerates clock skew
	// on exp/nbf (default 60s).
	JWKSCacheTTL time.Duration `yaml:"jwksCacheTtl"`
	Leeway       time.Duration `yaml:"leeway"`
}

// AdminStaticTokenConfig is a static admin bearer token bound to roles.
type AdminStaticTokenConfig struct {
	// Name is the subject recorded in audit entries for this token.
	Name string `yaml:"name"`
	// Tenant binds the token to a tenant (team), scoping the self-service portal
	// (Task 71). Required for a tenant-viewer token to surface any data.
	Tenant string `yaml:"tenant"`
	// Roles are the canonical roles granted
	// (viewer|operator|approver|admin|tenant-viewer).
	Roles []string `yaml:"roles"`
	// Token is the plaintext secret (>=16 bytes of entropy). Supports ${ENV} and
	// enc:v1:. Mutually exclusive with TokenHash.
	Token string `yaml:"token"`
	// TokenHash is a precomputed "sha256:<hex>" digest so plaintext need not
	// touch disk. Mutually exclusive with Token.
	TokenHash string `yaml:"tokenHash"`
}

// TracingConfig configures OpenTelemetry distributed tracing (Task 41). Tracing
// is active only when Enabled is true and Endpoint is non-empty; otherwise it is
// the no-op opt-out (the default when no collector is deployed).
type TracingConfig struct {
	// Enabled turns tracing on. Even when true, tracing stays inert unless an
	// Endpoint is also configured, so a half-configured block fails safe.
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP collector address. It may be a base URL
	// ("http://otel-collector:4318", which has "/v1/traces" appended) or a full
	// traces URL. A scheme-less value ("collector:4318") is given http:// when
	// Insecure is set, else https://. Supports ${ENV_VAR} expansion.
	Endpoint string `yaml:"endpoint"`
	// Insecure selects http:// over https:// for a scheme-less endpoint.
	Insecure bool `yaml:"insecure"`
	// TLSSkipVerify disables server-certificate verification when exporting over
	// HTTPS (test/dev only).
	TLSSkipVerify bool `yaml:"tlsSkipVerify"`
	// ServiceName is the OTLP service.name resource attribute. Defaults to
	// "pullthrough".
	ServiceName string `yaml:"serviceName"`
	// ServiceVersion and Environment populate the standard service.version and
	// deployment.environment resource attributes when set.
	ServiceVersion string `yaml:"serviceVersion"`
	Environment    string `yaml:"environment"`
	// SamplerRatio is the head-sampling probability for locally-rooted traces
	// (0..1). A remote parent's sampling decision is always honored (parent-based
	// sampling). Defaults to 1.0 (sample everything) when tracing is enabled.
	SamplerRatio float64 `yaml:"samplerRatio"`
	// ResourceAttributes are extra OTLP resource attributes (e.g. cluster, region)
	// attached to every span.
	ResourceAttributes map[string]string `yaml:"resourceAttributes"`
	// Headers are sent on every OTLP export request (e.g. an ingest token).
	// Values support ${ENV_VAR} expansion.
	Headers map[string]string `yaml:"headers"`
	// Timeout bounds a single OTLP export request. Defaults to 10s.
	Timeout time.Duration `yaml:"timeout"`
	// BatchTimeout is the maximum delay before a non-full span batch is flushed.
	// Defaults to 5s.
	BatchTimeout time.Duration `yaml:"batchTimeout"`
	// MaxQueueSize bounds the in-memory span queue; spans are dropped (and
	// counted) when it is full so a slow collector never stalls the request path.
	// Defaults to 2048.
	MaxQueueSize int `yaml:"maxQueueSize"`
	// MaxBatchSize bounds the spans sent per export request. Defaults to 512.
	MaxBatchSize int `yaml:"maxBatchSize"`
}

// Active reports whether the tracing configuration would produce a live tracer.
func (t TracingConfig) Active() bool { return t.Enabled && t.Endpoint != "" }

// TelemetryConfig groups signal-export configuration that complements the
// distributed tracing block (Task 41) and the SIEM/OCSF forwarders (Tasks
// 119/139). Today it carries the OTLP structured-log export pipeline (Task 160);
// it is the natural home for future OTLP signals (e.g. metrics export).
type TelemetryConfig struct {
	// OTLPLogs configures first-class OTLP log export: the proxy's structured
	// operational logs (every slog record) are shipped over OTLP/HTTP to a
	// collector, correlated with the active trace/span ids so logs and spans join
	// in backends such as Tempo/Loki/Grafana.
	OTLPLogs OTLPLogsConfig `yaml:"otlpLogs"`
}

// OTLPLogsConfig configures the OTLP structured-log export pipeline (Task 160).
// Export is active only when Enabled is true and Endpoint is non-empty; otherwise
// it is the no-op opt-out (the default when no collector is deployed). The
// pipeline buffers, batches, retries with exponential backoff, and overflows to a
// bounded disk spill, mirroring the SIEM forwarder's resilience so a slow or
// unreachable collector never stalls the logging path.
type OTLPLogsConfig struct {
	// Enabled turns OTLP log export on. Even when true it stays inert unless an
	// Endpoint is configured, so a half-configured block fails safe.
	Enabled bool `yaml:"enabled"`
	// Endpoint is the OTLP collector address. It may be a base URL
	// ("http://otel-collector:4318", which has "/v1/logs" appended) or a full logs
	// URL. A scheme-less value ("collector:4318") is given http:// when Insecure is
	// set, else https://. Supports ${ENV_VAR} expansion.
	Endpoint string `yaml:"endpoint"`
	// Insecure selects http:// over https:// for a scheme-less endpoint.
	Insecure bool `yaml:"insecure"`
	// TLSSkipVerify disables server-certificate verification when exporting over
	// HTTPS (test/dev only).
	TLSSkipVerify bool `yaml:"tlsSkipVerify"`
	// ServiceName is the OTLP service.name resource attribute. Defaults to
	// "pullthrough" (and to the tracing service name when that is set and this is
	// not, so logs and spans share one service identity).
	ServiceName string `yaml:"serviceName"`
	// Environment populates the deployment.environment resource attribute.
	Environment string `yaml:"environment"`
	// Tenant populates a "tenant" resource attribute identifying the owning tenant
	// of this proxy instance in a multi-tenant fleet.
	Tenant string `yaml:"tenant"`
	// ResourceAttributes are extra OTLP resource attributes (e.g. cluster, region)
	// attached to every exported batch.
	ResourceAttributes map[string]string `yaml:"resourceAttributes"`
	// Headers are sent on every OTLP export request (e.g. an ingest token). Values
	// support ${ENV_VAR} expansion and secretRef resolution.
	Headers map[string]string `yaml:"headers"`
	// MinLevel is the minimum log level exported to the collector
	// (debug/info/warn/error). Independent of logging.level, so an operator can log
	// everything to stderr while forwarding only warnings and above. Defaults to
	// info.
	MinLevel string `yaml:"minLevel"`
	// Timeout bounds a single OTLP export request. Defaults to 10s.
	Timeout time.Duration `yaml:"timeout"`
	// BatchTimeout is the maximum delay before a non-full log batch is flushed.
	// Defaults to 5s.
	BatchTimeout time.Duration `yaml:"batchTimeout"`
	// MaxQueueSize bounds the in-memory log queue; records are spilled then dropped
	// (both counted) when it is full so a slow collector never stalls logging.
	// Defaults to 2048.
	MaxQueueSize int `yaml:"maxQueueSize"`
	// MaxBatchSize bounds the records sent per export request. Defaults to 512.
	MaxBatchSize int `yaml:"maxBatchSize"`
	// MaxRetries is the number of redelivery attempts for a transient export
	// failure (429/5xx/network). Defaults to 3.
	MaxRetries int `yaml:"maxRetries"`
	// RetryBaseDelay and RetryMaxDelay bound the exponential backoff between retry
	// attempts. Default to 500ms and 30s.
	RetryBaseDelay time.Duration `yaml:"retryBaseDelay"`
	RetryMaxDelay  time.Duration `yaml:"retryMaxDelay"`
	// SpillFile, when set, enables a bounded file-backed overflow queue absorbing
	// bursts beyond MaxQueueSize and surviving restarts.
	SpillFile string `yaml:"spillFile"`
	// SpillMaxBytes caps the spill file's on-disk size (non-positive = uncapped).
	SpillMaxBytes int64 `yaml:"spillMaxBytes"`
}

// Active reports whether the OTLP-logs configuration would produce a live
// exporter.
func (o OTLPLogsConfig) Active() bool { return o.Enabled && strings.TrimSpace(o.Endpoint) != "" }

// SecretsConfig configures the at-rest encryption master key. The key is
// resolved from, in order: the KeyEnv environment variable, the KeyFile, or a
// passphrase stretched with scrypt. When none is set, encryption is disabled
// and any encrypted ("enc:v1:") value in the config is a hard error.
type SecretsConfig struct {
	// KeyEnv names an environment variable holding a 32-byte master key encoded
	// as hex or base64. Defaults to "PTS_SECRETS_KEY".
	KeyEnv string `yaml:"keyEnv"`
	// KeyFile is a path to a file containing the master key (raw 32 bytes or a
	// hex/base64 encoding).
	KeyFile string `yaml:"keyFile"`
	// Passphrase derives the key via scrypt together with Salt. Supports
	// ${ENV_VAR}. Lower assurance than a random KeyFile/KeyEnv; intended for
	// development.
	Passphrase string `yaml:"passphrase"`
	// Salt is the (non-secret but stable) scrypt salt for Passphrase.
	Salt string `yaml:"salt"`
	// Vault configures the HashiCorp Vault secrets provider used to resolve
	// "vault://path#key" references in credential fields (Task 133). It is inert
	// unless Enabled.
	Vault VaultConfig `yaml:"vault"`
}

// VaultConfig configures the HashiCorp Vault secrets provider (Task 133). When
// enabled, credential fields may use the "vault://<path>#<key>" reference syntax
// and are resolved from Vault's KV v2 engine at startup; a background refresher
// renews the auth lease and re-reads cached secrets so long-lived processes
// survive token expiry and observe rotations. The env:// and file:// reference
// providers are always available and need no configuration.
type VaultConfig struct {
	// Enabled registers the Vault provider. When false, a "vault://" reference in
	// any field is a hard error at load time (misconfiguration, not a silent
	// pass-through of the literal reference).
	Enabled bool `yaml:"enabled"`
	// Address is the Vault API base URL, e.g. "https://vault.internal:8200".
	Address string `yaml:"address"`
	// Namespace is the optional Vault Enterprise namespace.
	Namespace string `yaml:"namespace"`
	// KVMount is the KV v2 secrets-engine mount path. Defaults to "secret".
	KVMount string `yaml:"kvMount"`
	// AuthMethod selects how the proxy authenticates to Vault: "token" or
	// "approle". Defaults to "token".
	AuthMethod string `yaml:"authMethod"`
	// Token is the Vault token for the "token" auth method. Supports ${ENV_VAR}
	// expansion and enc:v1: encryption; prefer sourcing it from the environment.
	Token string `yaml:"token"`
	// RoleID and SecretID are the AppRole login credentials for the "approle"
	// auth method. Both support ${ENV_VAR} and enc:v1:.
	RoleID   string `yaml:"roleId"`
	SecretID string `yaml:"secretId"`
	// ApproleMount is the AppRole auth mount path. Defaults to "approle".
	ApproleMount string `yaml:"approleMount"`
	// RefreshInterval is how often the background refresher renews the auth lease
	// and re-reads cached secrets. Defaults to 1m; values below 10s are clamped.
	RefreshInterval time.Duration `yaml:"refreshInterval"`
	// RequestTimeout bounds a single Vault API call. Defaults to 10s.
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// CACertFile is a PEM bundle trusted for the Vault TLS connection.
	CACertFile string `yaml:"caCertFile"`
	// TLSSkipVerify disables Vault TLS verification (test/bootstrap only).
	TLSSkipVerify bool `yaml:"tlsSkipVerify"`
}

// AuthConfig configures client access control.
type AuthConfig struct {
	// Enabled turns on authentication and authorization. When false, the proxy
	// serves all requests anonymously (trusted-network mode).
	Enabled bool `yaml:"enabled"`
	// AllowAnonymous permits unauthenticated requests, binding them to the
	// AnonymousTeam/AnonymousRoles identity (subject "anonymous"). Useful for
	// gradual rollout or read-mostly public mirrors with quotas.
	AllowAnonymous bool `yaml:"allowAnonymous"`
	// AnonymousTeam and AnonymousRoles define the identity assigned to
	// unauthenticated requests when AllowAnonymous is true.
	AnonymousTeam  string   `yaml:"anonymousTeam"`
	AnonymousRoles []string `yaml:"anonymousRoles"`
	// CacheNamespacing partitions cached content per team (tenant isolation).
	CacheNamespacing bool `yaml:"cacheNamespacing"`
	// Tokens are static API tokens.
	Tokens []TokenConfig `yaml:"tokens"`
	// Roles define the RBAC roles referenced by tokens/teams/OIDC.
	Roles []RoleConfig `yaml:"roles"`
	// Teams configures per-tenant settings (currently quotas).
	Teams map[string]TeamConfig `yaml:"teams"`
	// DefaultQuota applies to teams without an explicit quota (zero =
	// unlimited).
	DefaultQuota QuotaConfig `yaml:"defaultQuota"`
	// OIDC configures bearer-JWT authentication against an identity provider.
	OIDC OIDCConfig `yaml:"oidc"`
}

// TokenConfig declares a static API token. Provide exactly one of Token (the
// secret, which may be a "${ENV_VAR}" reference or an "enc:v1:" encrypted value)
// or TokenHash ("sha256:<hex>") so the plaintext need never be stored.
type TokenConfig struct {
	Name      string   `yaml:"name"`
	Team      string   `yaml:"team"`
	Roles     []string `yaml:"roles"`
	Token     string   `yaml:"token"`
	TokenHash string   `yaml:"tokenHash"`
}

// RoleConfig defines an RBAC role granting access to ecosystems and/or
// upstreams. Use ["*"] for unrestricted access on a dimension; an empty list
// matches nothing (least privilege).
type RoleConfig struct {
	Name       string   `yaml:"name"`
	Ecosystems []string `yaml:"ecosystems"`
	Upstreams  []string `yaml:"upstreams"`
}

// TeamConfig holds per-tenant settings.
type TeamConfig struct {
	Quota QuotaConfig `yaml:"quota"`
	// RateLimit overrides the default rate-limit policy for this tenant (Task 24).
	// Zero fields fall through to the global RateLimit.Default policy semantics
	// (a zero dimension is unlimited).
	RateLimit RateLimitPolicyConfig `yaml:"rateLimit"`
}

// CoalesceConfig configures the pull-path request coalescer and negative cache
// (Task 36). It is a pure performance/resilience layer and is enabled by default;
// the cache's content-addressing and the security gates are unaffected by it.
// FindingsConfig configures the SARIF findings-aggregation layer (Task 42). The
// layer is a passive observability surface — it never affects admission — so it
// is enabled by default whenever the pull path runs the admission gates.
type FindingsConfig struct {
	// Enabled turns on findings retention and the SARIF export endpoint/CLI. When
	// false, the admin endpoint reports the surface absent and nothing is retained
	// (the CLI's file-input mode still works, as it needs no live store).
	Enabled bool `yaml:"enabled"`
	// MaxEntries bounds the number of retained per-artifact findings documents
	// (oldest-evicted). A non-positive value uses the built-in default (2048).
	MaxEntries int `yaml:"maxEntries"`
	// Dedup enables the central finding de-duplication layer (Task 165): before a
	// findings document is recorded (and thus before SARIF export, the dossier, and
	// SIEM forwarding read it), overlapping findings for the same
	// coordinate+digest+category+locator — e.g. a secret reported by both the Git
	// commit scanner and the content-analysis gate — are collapsed into one
	// canonical finding that preserves every contributing gate's provenance. It is
	// a passive normalization that never changes an admission verdict, so it is
	// enabled by default; set to false to retain the raw, un-collapsed finding set.
	Dedup *bool `yaml:"dedup"`
	// SuppressionTrail enables the immutable suppression audit trail (Task 165):
	// every finding a gate suppressed or downgraded (VEX adjudication, reachability
	// downgrade, policy downgrade, break-glass approval) is recorded with who/what
	// suppressed it and why, queryable per coordinate and mirrored into the
	// tamper-evident audit log. Enabled by default; set to false to disable the
	// ledger and its audit mirroring.
	SuppressionTrail *bool `yaml:"suppressionTrail"`
	// MaxSuppressions bounds the suppression audit trail (oldest-evicted). A
	// non-positive value uses the built-in default (8192).
	MaxSuppressions int `yaml:"maxSuppressions"`
}

// DedupEnabled reports whether the finding de-duplication layer is on,
// defaulting to true when unset.
func (f FindingsConfig) DedupEnabled() bool {
	if f.Dedup == nil {
		return true
	}
	return *f.Dedup
}

// SuppressionTrailEnabled reports whether the suppression audit trail is on,
// defaulting to true when unset.
func (f FindingsConfig) SuppressionTrailEnabled() bool {
	if f.SuppressionTrail == nil {
		return true
	}
	return *f.SuppressionTrail
}

// SimReplayConfig configures the policy & risk what-if simulation/replay harness
// (Task 47). When enabled, the proxy captures a sampled, redacted ring buffer of
// recent admission inputs together with the verdict each produced live, so an
// operator can replay them through a candidate configuration and diff the
// outcome. The CLI `simulate` subcommand works against an exported capture file
// even when this is disabled; this config only governs the live in-process
// recorder and its admin surface.
type SimReplayConfig struct {
	// Enabled turns on the live capture recorder and the admin endpoint. When
	// false, no traffic is captured and the admin surface reports itself absent.
	Enabled bool `yaml:"enabled"`
	// Capacity bounds the ring buffer (oldest-evicted). A non-positive value uses
	// the built-in default (1024).
	Capacity int `yaml:"capacity"`
	// SampleRate captures one in every N observed pulls (deterministic, counter-
	// based). A value <= 1 captures every pull.
	SampleRate int `yaml:"sampleRate"`
	// Redact, when true (the default), strips sensitive leaf fields (secret file
	// paths, signer identity/issuer, source repo URL/commit) from each captured
	// input. Redaction preserves the scalar signals the engines score on, so a
	// redacted record still replays to the same verdict. Set Redact:false in the
	// YAML to retain raw inputs (not recommended for buffers shipped off-box).
	Redact *bool `yaml:"redact"`
}

// AttestConfig configures the outbound SLSA/in-toto attestation engine (Task 46):
// the proxy signs an attestation bundle for every artifact it admits and serves,
// exposes it via an OCI referrers-style endpoint + admin/CLI export, and embeds
// the bundle digest in the audit log. It requires a signing key; by default it
// reuses the audit-log checkpoint signing key so no extra key material is needed.
type AttestConfig struct {
	// Enabled turns on outbound attestation. It additionally requires a signing key
	// (an explicit one here, or the audit transparency signing key). When false, no
	// attestation is produced and the admin surface reports itself absent.
	Enabled bool `yaml:"enabled"`
	// MaxEntries bounds retained bundles (oldest-evicted). <=0 uses the default
	// (2048).
	MaxEntries int `yaml:"maxEntries"`
	// AttesterID is the logical identity recorded as the attester in every
	// predicate (the SLSA builder.id analogue). Defaults to "pullthrough-proxy".
	AttesterID string `yaml:"attesterId"`
	// Instance optionally identifies the specific deployment/host in the predicate
	// (e.g. a pod name or region). Empty omits it.
	Instance string `yaml:"instance"`
	// SigningKey is an inline PEM private key (PKCS#8 / EC / PKCS#1) used to sign
	// attestations, as an alternative to SigningKeyFile. May be a "${ENV_VAR}" or
	// "enc:v1:" reference. When neither SigningKey nor SigningKeyFile is set, the
	// audit transparency signing key is reused.
	SigningKey string `yaml:"signingKey"`
	// SigningKeyFile is a PEM private-key file used to sign attestations.
	SigningKeyFile string `yaml:"signingKeyFile"`
}

// TransparencyConfig configures Sigstore transparency-log integration (Task
// 142). Today it carries the Rekor sub-config; it is nested so future
// transparency mechanisms (e.g. a witness/cosignature network) can be added
// without a flat namespace.
type TransparencyConfig struct {
	// Rekor configures the Sigstore Rekor transparency log.
	Rekor RekorConfig `yaml:"rekor"`
}

// RekorConfig configures the Rekor transparency-log client and inclusion-proof
// verification. Submission is OFF by default (it reaches an external service and
// publishes the attestation publicly); inbound inclusion-proof verification is
// opt-in per the gate's security posture.
type RekorConfig struct {
	// Enabled turns on the transparency-log subsystem. When false, nothing is
	// submitted and the inbound gate performs no inclusion-proof check.
	Enabled bool `yaml:"enabled"`
	// URL is the Rekor base URL. Empty uses the public instance
	// (https://rekor.sigstore.dev). Point it at a private log for enterprise use.
	URL string `yaml:"url"`
	// Submit, when true, submits every signed outbound attestation (the per-served
	// artifact bundle, Task 46) to the log and records the returned log index +
	// inclusion proof. Best-effort: a submission failure never blocks serving.
	Submit bool `yaml:"submit"`
	// RequireInclusionProof, when true, makes the inbound signature gate (Task 23)
	// require that a presented keyless signature/attestation carry a Rekor
	// inclusion proof that verifies to a trusted log root. It is stronger than
	// sigverify.requireRekorProof (which checks only the Signed Entry Timestamp).
	RequireInclusionProof bool `yaml:"requireInclusionProof"`
	// Timeout bounds a single submission (default 15s).
	Timeout time.Duration `yaml:"timeout"`
	// PublicKeyFiles are PEM public-key files of trusted Rekor logs, used to verify
	// Signed Entry Timestamps on both the submit and verify paths. When empty the
	// sigverify gate's configured rekorKeyFiles are reused.
	PublicKeyFiles []string `yaml:"publicKeyFiles"`
}

type CoalesceConfig struct {
	// Enabled turns on request coalescing and negative caching. When false, each
	// cache miss fetches upstream independently (the cache's own single-flight
	// still de-duplicates concurrent identical fills, but there is no negative
	// cache, no cross-time dedup, and no in-flight ceiling).
	Enabled bool `yaml:"enabled"`
	// NegativeTTL is how long a terminal upstream failure (404/410/auth) is
	// remembered so a burst of requests for a missing artifact does not repeatedly
	// hit the upstream. Default 30s; keep it short so a transiently-missing
	// artifact is not shadowed for long once it appears upstream.
	NegativeTTL time.Duration `yaml:"negativeTtl"`
	// MaxNegativeEntries bounds the negative cache (LRU eviction). Default 4096;
	// 0 uses the default, a negative value is rejected.
	MaxNegativeEntries int `yaml:"maxNegativeEntries"`
	// MaxInflight caps the number of distinct in-flight upstream fetches. A new
	// fetch beyond the cap is shed with 503 (callers joining an existing in-flight
	// fetch are never rejected). 0 means unbounded.
	MaxInflight int `yaml:"maxInflight"`
	// Backoff5xxBase and Backoff5xxMax bound the jittered backoff window applied to
	// transient (5xx / throttle / network) negative entries. Defaults 1s and 5s.
	Backoff5xxBase time.Duration `yaml:"backoff5xxBase"`
	Backoff5xxMax  time.Duration `yaml:"backoff5xxMax"`
}

// CacheGCConfig configures the cache lifecycle manager / garbage collector
// (Task 39). It bounds the content-addressable cache without operator
// intervention and is enabled by default; it is a pure lifecycle layer and never
// affects content-addressing or the security gates.
type CacheGCConfig struct {
	// Enabled turns on the background GC sweeps. When false the engine is still
	// constructed so the admin API can run on-demand/dry-run sweeps, but it never
	// sweeps on its own.
	Enabled bool `yaml:"enabled"`
	// Interval is the period between automatic sweeps (default 1h). Zero disables
	// the schedule, leaving on-demand sweeps via the admin API.
	Interval time.Duration `yaml:"interval"`
	// CapacityBytes is the cache size used for the high/low watermark math. When 0
	// it falls back to cache.maxSizeBytes; when both are 0, size-driven eviction is
	// disabled and only TTLs apply.
	CapacityBytes int64 `yaml:"capacityBytes"`
	// HighWatermarkPct and LowWatermarkPct are fractions (0..1] of the capacity. A
	// sweep that finds utilization above the high watermark evicts down to the low
	// watermark. Defaults: 0.9 and 0.7. Low must be below high.
	HighWatermarkPct float64 `yaml:"highWatermarkPct"`
	LowWatermarkPct  float64 `yaml:"lowWatermarkPct"`
	// Policy selects eviction ordering under size pressure: "lru" (default),
	// "lfu", or "fifo".
	Policy string `yaml:"policy"`
	// DefaultTTL is the maximum age (from creation) before an entry is eligible for
	// TTL eviction regardless of utilization. Zero disables the default TTL. When 0
	// it falls back to cache.ttl.
	DefaultTTL time.Duration `yaml:"defaultTtl"`
	// TenantTTLs overrides DefaultTTL per tenant (an explicit zero disables TTL for
	// that tenant).
	TenantTTLs map[string]time.Duration `yaml:"tenantTtls"`
	// MinIdle protects entries accessed within this window from eviction, a safety
	// margin so an artifact being actively streamed to a client is never evicted
	// out from under the read (default 1m). Zero disables the guard.
	MinIdle time.Duration `yaml:"minIdle"`
	// MaxDeletesPerRun bounds how many entries a single sweep evicts (0 =
	// unlimited), spreading a large reclaim across sweeps.
	MaxDeletesPerRun int `yaml:"maxDeletesPerRun"`
	// AllowEvictPinned permits evicting metadata-pinned entries (it does not affect
	// reference-count or quarantine retention). Off by default.
	AllowEvictPinned bool `yaml:"allowEvictPinned"`
	// DryRun makes the periodic sweep report-only: it plans and reports evictions
	// but deletes nothing. On-demand admin runs can still delete.
	DryRun bool `yaml:"dryRun"`
}

// RateLimitConfig configures the rate-limiting / quota / concurrency subsystem
// (Task 24).
type RateLimitConfig struct {
	// Enabled turns on rate-limit enforcement. When false the middleware is not
	// installed and every request passes unmetered.
	Enabled bool `yaml:"enabled"`
	// Global is the process-wide policy applied to every request in addition to
	// the per-tenant policy (a zero dimension is unlimited).
	Global RateLimitPolicyConfig `yaml:"global"`
	// Default is the policy for tenants without an explicit per-team override.
	Default RateLimitPolicyConfig `yaml:"default"`
	// Shared, when true and the cache backend is the shared S3/object store,
	// coordinates byte quotas across replicas through that store rather than
	// per-replica in-memory counters.
	Shared bool `yaml:"shared"`
}

// RateLimitPolicyConfig is a single rate-limit policy. A zero value on any
// dimension disables that dimension.
type RateLimitPolicyConfig struct {
	// RPS is the sustained request rate (requests/second; 0 = unlimited).
	RPS float64 `yaml:"rps"`
	// Burst is the token-bucket capacity (0 derives it from RPS).
	Burst int `yaml:"burst"`
	// MaxConcurrent caps simultaneous in-flight pulls (0 = unlimited).
	MaxConcurrent int `yaml:"maxConcurrent"`
	// ByteQuota caps bytes served per Window (0 = unlimited).
	ByteQuota int64 `yaml:"byteQuota"`
	// Window is the byte-quota rolling window (0 = 30 days when ByteQuota > 0).
	Window time.Duration `yaml:"window"`
}

// QuotaConfig bounds a team's consumption within Window (0 = never resets). A
// zero limit means unlimited on that dimension.
type QuotaConfig struct {
	MaxRequests int64         `yaml:"maxRequests"`
	MaxBytes    int64         `yaml:"maxBytes"`
	Window      time.Duration `yaml:"window"`
}

// OIDCConfig configures OIDC/JWT bearer authentication.
type OIDCConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// JWKSURL is the issuer's JWK Set endpoint. Mutually usable with JWKS.
	JWKSURL string `yaml:"jwksUrl"`
	// JWKS is an inline JWK Set document (JSON) for air-gapped/pinned setups.
	JWKS string `yaml:"jwks"`
	// Claim name overrides (defaults: sub, team, roles).
	SubjectClaim string `yaml:"subjectClaim"`
	TeamClaim    string `yaml:"teamClaim"`
	RolesClaim   string `yaml:"rolesClaim"`
	// RoleMap translates IdP group/role names to proxy role names.
	RoleMap map[string]string `yaml:"roleMap"`
	// JWKSCacheTTL bounds caching of fetched keys (default 15m); Leeway
	// tolerates clock skew on exp/nbf (default 60s).
	JWKSCacheTTL time.Duration `yaml:"jwksCacheTtl"`
	Leeway       time.Duration `yaml:"leeway"`
}

// ClientAuthConfig groups optional client-authentication paths beyond the
// token/OIDC auth configured under Auth.
type ClientAuthConfig struct {
	// MTLS configures SPIFFE/SVID mutual-TLS workload-identity authentication
	// (Task 58).
	MTLS MTLSConfig `yaml:"mtls"`
}

// MTLSConfig configures SPIFFE/SVID mutual-TLS workload-identity client
// authentication (Task 58). When enabled, the gateway requests (or, in required
// mode, requires) a client certificate, validates its chain against the
// configured trust bundle, extracts the SPIFFE ID from the certificate SAN URI,
// and maps it to a tenant + roles via Rules. It composes with the token/OIDC
// auth under Auth: by default a client may present either a token or a
// certificate; in required mode the TLS handshake demands a certificate.
//
// Enabling mTLS requires Auth.Enabled (the access-control enforcer and its RBAC
// roles, which the mapped capabilities reference) and TLS termination at the
// gateway (server.tlsCertFile / server.tlsKeyFile).
type MTLSConfig struct {
	// Enabled turns on the mTLS workload-identity authenticator.
	Enabled bool `yaml:"enabled"`
	// Required, when true, switches the gateway into mTLS-required mode: the TLS
	// handshake demands a client certificate (clients presenting none are
	// rejected at the transport layer). When false (the default), a certificate
	// is requested opportunistically and token/OIDC auth still works (either-or).
	Required bool `yaml:"required"`
	// TrustBundle is the path to the trust bundle of SPIFFE CA roots. It is read
	// from disk (offline/air-gapped friendly) and may be a concatenation of PEM
	// CERTIFICATE blocks or a SPIFFE Trust Bundle JSON document (see
	// TrustBundleFormat).
	TrustBundle string `yaml:"trustBundle"`
	// TrustBundleFormat selects how TrustBundle is decoded: "auto" (default,
	// sniffs PEM vs JSON), "pem", or "spiffe".
	TrustBundleFormat string `yaml:"trustBundleFormat"`
	// TrustDomain is the default SPIFFE trust domain assigned to roots that carry
	// no domain of their own (a PEM bundle, or a single-domain SPIFFE JSON
	// document). Required unless the bundle is a federated SPIFFE document naming
	// every domain.
	TrustDomain string `yaml:"trustDomain"`
	// AllowedTrustDomains optionally restricts which trust domains are accepted,
	// even when present in the bundle (defense in depth for federated bundles).
	// Empty accepts any domain the bundle knows.
	AllowedTrustDomains []string `yaml:"allowedTrustDomains"`
	// ReloadInterval polls the trust-bundle file for changes and hot-reloads it
	// without a restart. Zero disables polling (reload only on restart).
	ReloadInterval time.Duration `yaml:"reloadInterval"`
	// ExpiryWarning sizes the "certificate expiring soon" gauge window. Defaults
	// to 720h (30 days).
	ExpiryWarning time.Duration `yaml:"expiryWarning"`
	// DefaultTenant is assigned to a matched SPIFFE ID whose rule names no
	// tenant. Empty leaves such a principal team-less.
	DefaultTenant string `yaml:"defaultTenant"`
	// Rules is the ordered identity-mapping policy: each maps SPIFFE IDs matching
	// a glob (or "re:<regexp>") pattern to a tenant and a set of roles. First
	// match wins.
	Rules []MTLSRuleConfig `yaml:"rules"`
	// TenantOverrides maps a tenant name to override rules consulted after a
	// global rule selects that tenant; the first override match replaces the role
	// set, letting a specific workload within a tenant be granted elevated
	// capabilities.
	TenantOverrides map[string][]MTLSRuleConfig `yaml:"tenantOverrides"`
}

// MTLSRuleConfig is one identity-mapping rule (SPIFFE-ID pattern -> tenant +
// roles).
type MTLSRuleConfig struct {
	// Pattern matches the canonical SPIFFE ID string. A glob by default ('*'
	// within a path segment, '**' across segments); prefix with "re:" for a Go
	// regular expression.
	Pattern string `yaml:"pattern"`
	// Tenant is the team the matched identity belongs to.
	Tenant string `yaml:"tenant"`
	// Roles are the RBAC role names (capabilities) granted to the identity; they
	// must be defined under auth.roles.
	Roles []string `yaml:"roles"`
}

// AuditConfig configures the tamper-evident audit log.
type AuditConfig struct {
	// Enabled turns on audit logging.
	Enabled bool `yaml:"enabled"`
	// File is the append-only log path. Empty with Enabled keeps records in
	// memory only (lost on restart) — for tests/dev.
	File string `yaml:"file"`
	// HMACKey keys the tamper-evident hash chain. It may be a "${ENV_VAR}"
	// reference or an "enc:v1:" encrypted value. Required when Enabled.
	HMACKey string `yaml:"hmacKey"`
	// HMACKeyEnv names an environment variable holding the HMAC key, as an
	// alternative to HMACKey.
	HMACKeyEnv string `yaml:"hmacKeyEnv"`

	// Transparency configures the Merkle transparency layer (signed checkpoints,
	// inclusion/consistency proofs) layered on top of the hash chain. When the
	// audit log is enabled the transparency layer is enabled too; these fields
	// tune sealing and optional checkpoint signing.
	Transparency AuditTransparencyConfig `yaml:"transparency"`
}

// AuditTransparencyConfig configures the Merkle transparency log: periodic signed
// checkpoints (signed tree heads) over the hash-chained records, persisted
// out-of-band so a retroactive edit or deletion is detectable even without the
// HMAC key.
type AuditTransparencyConfig struct {
	// Disabled turns off the transparency layer even when audit logging is on,
	// leaving only the hash chain. The default (false) keeps it enabled.
	Disabled bool `yaml:"disabled"`
	// Origin identifies the log in its checkpoints (defaults to
	// "pullthrough-audit"); it binds a checkpoint to this specific log.
	Origin string `yaml:"origin"`
	// CheckpointFile is where sealed checkpoints are persisted (newline-delimited
	// JSON). Defaults to the audit File with a ".checkpoints" suffix when File is
	// set; checkpoints are kept in memory only when neither is set.
	CheckpointFile string `yaml:"checkpointFile"`
	// SealEvery seals a checkpoint automatically after this many appended records
	// (defaults to 1000). Set negative to disable size-triggered sealing.
	SealEvery int `yaml:"sealEvery"`
	// SealInterval also seals on a fixed wall-clock interval (e.g. "5m"); zero
	// disables interval sealing. A final checkpoint is always sealed at shutdown.
	SealInterval time.Duration `yaml:"sealInterval"`
	// SigningKeyFile is a PEM private key (PKCS#8 / EC / PKCS#1) used to sign
	// checkpoints. Optional: unsigned checkpoints are still tamper-evident
	// against an attacker without the HMAC key. The corresponding public key is
	// the same kind of trust material the signature-verification gate uses.
	SigningKeyFile string `yaml:"signingKeyFile"`
	// SigningKey is an inline PEM private key, as an alternative to
	// SigningKeyFile (may be a "${ENV_VAR}" or "enc:v1:" reference).
	SigningKey string `yaml:"signingKey"`
}

// BackupConfig configures the disaster-recovery backup/restore subsystem
// (Task 44). The CLI subcommands (`backup`/`restore`) and the admin-triggered
// backup all read this section to locate the destination directory, encryption
// material, and which sidecar metadata stores to include. The metadata store
// paths themselves are not restated here — they are derived from the existing
// audit/provenance/VEX/policy/commit-scan configuration — so this section only
// tunes scheduling, output, retention, and encryption.
type BackupConfig struct {
	// Dir is the directory scheduled and admin-triggered backups are written to.
	// Each run produces "pullthrough-backup-<RFC3339>.tar" (plus a ".sha256"
	// manifest-digest sidecar). Required for scheduled/admin backups; the CLI
	// `backup -out` flag overrides it.
	Dir string `yaml:"dir"`
	// Interval, when > 0, enables the background scheduled-backup loop at this
	// period (e.g. "6h"). Zero leaves backups on-demand via the CLI/admin path.
	Interval time.Duration `yaml:"interval"`
	// Retain bounds how many timestamped snapshots are kept in Dir after a
	// scheduled/admin backup; older ones are pruned. Zero (default) keeps all.
	Retain int `yaml:"retain"`
	// Encrypt wraps every scheduled/admin snapshot in the streaming AES-256-GCM
	// envelope. Requires either Passphrase or KeyFile.
	Encrypt bool `yaml:"encrypt"`
	// Passphrase is the encryption passphrase (stretched with scrypt). It may be a
	// "${ENV_VAR}" reference or an "enc:v1:" encrypted value. Mutually exclusive
	// with KeyFile.
	Passphrase string `yaml:"passphrase"`
	// KeyFile is a file holding a 32-byte raw key (hex or base64) for AES-256, for
	// KMS/HSM-managed key workflows. Mutually exclusive with Passphrase.
	KeyFile string `yaml:"keyFile"`
	// IncludeCache, when false, omits the content-addressable cache from scheduled
	// backups (metadata-only snapshots, useful when the cache is reproducible by
	// re-pulling). Defaults to true.
	IncludeCache *bool `yaml:"includeCache"`
	// AlertAfter is the backup age beyond which the deployment is considered to
	// have breached its RPO; it is exposed for alerting and documented in the
	// runbook. Informational (the Prometheus alert rule encodes the threshold).
	AlertAfter time.Duration `yaml:"alertAfter"`
}

// IncludeCacheOrDefault reports whether the cache should be included in
// scheduled backups, defaulting to true when unset.
func (b BackupConfig) IncludeCacheOrDefault() bool {
	return b.IncludeCache == nil || *b.IncludeCache
}

// CoordinationConfig configures distributed coordination & leader election for
// scheduled background jobs in HA deployments (Task 56). When disabled (the
// default) every scheduler runs unconditionally — correct for a single replica.
// When enabled, a scheduler only runs while this replica holds the named lease;
// the lease has a TTL and is renewed by a heartbeat, so a crashed leader's lease
// expires and another replica takes over.
type CoordinationConfig struct {
	// Enabled turns on lease-based leader election. Leave it off for single-replica
	// deployments.
	Enabled bool `yaml:"enabled"`
	// Mode selects the lease backend: "memory" (in-process; single replica only),
	// "s3" (shared object store — the natural choice alongside the s3 cache), or
	// "file" (a shared POSIX volume). Empty defaults to "memory".
	Mode string `yaml:"mode"`
	// NodeID uniquely identifies this replica in lease records. Empty defaults to
	// "<hostname>-<pid>"; in Kubernetes set it to the pod name via the downward API.
	NodeID string `yaml:"nodeId"`
	// LeaseTTL is how long an acquired lease stays valid without a heartbeat before
	// another replica may take it over. Empty defaults to 30s.
	LeaseTTL time.Duration `yaml:"leaseTtl"`
	// RenewInterval is how often the leader heartbeats to extend its lease; it must
	// be comfortably below LeaseTTL. Empty defaults to LeaseTTL/3.
	RenewInterval time.Duration `yaml:"renewInterval"`
	// RetryInterval is how often a follower re-attempts acquisition. Empty defaults
	// to RenewInterval.
	RetryInterval time.Duration `yaml:"retryInterval"`
	// JobTTLs optionally overrides LeaseTTL per named job (e.g. "backup",
	// "cve-drift-rescan", "malfeed-refresh", "audit-checkpoint").
	JobTTLs map[string]time.Duration `yaml:"jobTtls"`
	// S3 configures the "s3" backend. When Bucket is empty the s3 backend inherits
	// the cache's S3 connection settings (cache.s3), so an HA deployment already on
	// the shared s3 cache needs only `mode: s3`.
	S3 CoordinationS3Config `yaml:"s3"`
	// Dir is the shared lease directory for the "file" backend.
	Dir string `yaml:"dir"`
}

// CoordinationS3Config holds the object-store connection settings for the s3
// coordination backend. Every field is optional; unset connection fields fall
// back to the cache S3 backend (cache.s3), so leases live in the same bucket.
type CoordinationS3Config struct {
	Endpoint           string `yaml:"endpoint"`
	Region             string `yaml:"region"`
	Bucket             string `yaml:"bucket"`
	Prefix             string `yaml:"prefix"`
	AccessKeyID        string `yaml:"accessKeyId"`
	SecretAccessKey    string `yaml:"secretAccessKey"`
	SessionToken       string `yaml:"sessionToken"`
	UsePathStyle       bool   `yaml:"usePathStyle"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	MaxRetries         int    `yaml:"maxRetries"`
}

// IsEnabled reports whether the upstream is enabled (defaulting to true when
// unset).
func (u UpstreamConfig) IsEnabled() bool {
	return u.Enabled == nil || *u.Enabled
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Server: ServerConfig{
			HTTPAddr:        ":8080",
			SSHAddr:         "",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    5 * time.Minute,
			ShutdownTimeout: 30 * time.Second,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Cache: CacheConfig{
			Backend: "memory",
			Dir:     "/var/lib/pullthrough/cache",
			Integrity: IntegrityConfig{
				VerifyOnServe:  true,
				NotifySeverity: "critical",
			},
			Compression: CompressionConfig{
				Enabled:      false,
				Codec:        "zstd",
				Level:        3,
				MinSizeBytes: 256,
				Dedup:        false,
			},
			Tiering: TieringConfig{
				Enabled:         false,
				DemoteAfterIdle: 24 * time.Hour,
				SweepInterval:   10 * time.Minute,
			},
		},
		Upstreams: map[string]UpstreamConfig{},
		Egress: EgressConfig{
			// On by default with secure defaults: https-only, deny resolution to any
			// internal/metadata range, follow at most 5 redirects (each re-checked).
			// The host allowlist is left empty (unenforced) so enabling the guard
			// does not require enumerating every public registry up front — the
			// scheme and IP-range floors already block SSRF-to-internal. Operators
			// fronting an internal http mirror configure egress.allowlist /
			// allowedDestinationCidrs (or disable the guard) deliberately.
			Enabled:              true,
			HTTPSOnly:            true,
			BlockPrivateNetworks: true,
			FollowRedirects:      true,
			MaxRedirects:         5,
		},
		Scanning: ScanningConfig{
			Enabled:  false,
			Provider: "none",
			FailOn:   "high",
			// The GitHub Actions pinning gate (Task 115) defaults: block a disallowed
			// owner (high), warn on a mutable-ref pin (medium). Enabled/RequirePinning
			// are pointers left nil here so they inherit (scanning.enabled / true) and
			// are resolved in the wiring layer.
			Actions: ActionPinConfig{
				FailSeverity: "high",
				WarnSeverity: "medium",
				Action:       "block",
				MaxFindings:  200,
			},
		},
		Provenance: ProvenanceConfig{
			Enabled: false,
		},
		Provgraph: ProvgraphConfig{
			Enabled: true,
		},
		Compliance: ComplianceConfig{
			Enabled: true,
		},
		RiskScore: RiskScoreConfig{
			Enabled: true,
		},
		Extensions: ExtensionConfig{
			// On by default but inert until an operator configures modules.
			Enabled: true,
		},
		Malfeed: MalfeedConfig{
			// On by default but inert until feeds or an offline bundle are configured:
			// with no data the matcher is empty and the gate fails open, so it never
			// blocks a pull until an operator supplies a malware dataset. Fail-open on
			// staleness keeps availability the default; set malfeed.failClosed to trade
			// it for safety.
			Enabled:         true,
			RefreshInterval: 6 * time.Hour,
			StaleAfter:      24 * time.Hour,
		},
		Maturity: MaturityConfig{
			// On by default but inert: the default cooldown is zero, so every version
			// is admitted until an operator sets maturity.defaultCooldown (or a
			// per-ecosystem / per-tenant cooldown). Fails open on an undeterminable
			// publish timestamp to keep availability the default.
			Enabled:          true,
			Timeout:          10 * time.Second,
			CacheTTL:         6 * time.Hour,
			NegativeCacheTTL: 15 * time.Minute,
			CacheSize:        4096,
		},
		Continuity: ContinuityConfig{
			// On by default but observe-only: it records the trust-on-first-use
			// maintainer set and surfaces drift as a signal without ever blocking a
			// pull until an operator raises continuity.defaultDisposition to warn/block
			// (and sets a cooldown). Fails open when the publisher cannot be determined.
			Enabled:            true,
			DefaultDisposition: "observe",
			Cooldown:           7 * 24 * time.Hour,
			Timeout:            10 * time.Second,
			CacheTTL:           time.Hour,
			NegativeCacheTTL:   15 * time.Minute,
			CacheSize:          4096,
			MaxRecords:         50000,
		},
		DepFirewall: DepFirewallConfig{
			// Off by default: the dependency firewall enforces only what an operator
			// configures (explicit rules and/or an imported lockfile), so it must be
			// switched on deliberately. The default action admits ungoverned
			// coordinates so enabling the gate with no rules is a no-op until policy
			// is added.
			Enabled:       false,
			DefaultAction: "allow",
		},
		InstallHooks: InstallHooksConfig{
			// On by default with a sane block-at-high / warn-at-medium policy; it only
			// inspects install-hook-bearing ecosystems and never executes anything.
			Enabled:            true,
			FailSeverity:       "high",
			WarnSeverity:       "medium",
			Action:             "block",
			MaxFindingsPerHook: 50,
		},
		MLGuard: MLGuardConfig{
			// On by default with a block-at-high / warn-at-medium policy; it only
			// inspects Hugging Face pickle weight files and never unpickles anything.
			Enabled:       true,
			FailSeverity:  "high",
			WarnSeverity:  "medium",
			Action:        "block",
			MaxScanBytes:  256 << 20,
			MaxZipEntries: 64,
		},
		AVScan: AVScanConfig{
			// Off by default (requires a reachable AV engine). When enabled it
			// quarantines on detection and fails open if the engine is unreachable.
			Enabled:      false,
			Engine:       "clamav",
			Action:       "quarantine",
			MaxScanBytes: 128 << 20,
			Timeout:      60 * time.Second,
			// FailOpen left nil => treated as true at service-build time.
		},
		ContentScan: ContentScanConfig{
			// On by default but observe-only: the default action is annotate, so the
			// gate records and alerts on findings without ever blocking a pull until an
			// operator raises contentScan.action to downgrade/block. All heuristics are
			// active (left nil => on at service-build time); the budget defaults are
			// filled by the service layer.
			Enabled:      true,
			Action:       "annotate",
			FailSeverity: "high",
		},
		LLMPackageScan: LLMPackageScanConfig{
			// Off by default: it needs an LLM provider and spends money per
			// artifact. When enabled it blocks (and quarantines) what the model
			// judges malicious and fails open when no verdict can be obtained.
			Enabled:             false,
			Mode:                "auto",
			Action:              "block",
			FailMode:            "open",
			Oversize:            "fail",
			MaliciousThreshold:  0.7,
			SuspiciousThreshold: 0.5,
			Timeout:             2 * time.Minute,
			MaxRetries:          1,
			MaxConcurrent:       4,
			ErrorTTL:            5 * time.Minute,
			Limits: LLMPackageScanLimits{
				MaxArtifactBytes:    64 << 20,
				MaxUnpackedBytes:    256 << 20,
				MaxFileBytes:        1 << 20,
				MaxFiles:            5000,
				MaxDepth:            32,
				MaxCompressionRatio: 200,
				MaxPromptBytes:      120 << 10,
				MaxToolResultBytes:  24 << 10,
				MaxToolBytes:        256 << 10,
				MaxTurns:            8,
				MaxToolCalls:        24,
				MaxOutputTokens:     16000,
				MaxTotalTokens:      600000,
			},
			Budget: LLMPackageScanBudget{
				Window: 24 * time.Hour,
			},
		},
		Findings: FindingsConfig{
			Enabled: true,
		},
		SbomDiff: SbomDiffConfig{
			// On by default but observe-and-alert only: the default action is warn,
			// so it records history and surfaces drift without ever blocking a pull
			// until an operator raises sbomDiff.action to block/quarantine.
			Enabled:        true,
			HistorySize:    16,
			MaxCoordinates: 4096,
			Action:         "warn",
		},
		Remediation: RemediationConfig{
			// On by default: read-only, on-demand advice that never blocks a pull.
			Enabled:       true,
			MaxCandidates: 25,
		},
		RebuildVerify: RebuildVerifyConfig{
			// On by default but observe-only: it records reproducibility verdicts and
			// feeds the policy/risk engines without ever blocking a pull until an
			// operator raises rebuildVerify.mode to enforce. Async and air-gapped
			// (AllowFetch off) by default.
			Enabled:       true,
			Mode:          "observe",
			MaxConcurrent: 2,
			CacheSize:     4096,
			RecentSize:    100,
		},
		BuildProv: BuildProvConfig{
			// On by default but observe-only: it verifies inbound build provenance and
			// cross-checks the proven source commit against the package-to-commit
			// association, feeding the policy/risk engines without ever blocking a pull
			// until an operator raises buildProv.mode to enforce.
			Enabled:      true,
			Mode:         "observe",
			Action:       "quarantine",
			FailSeverity: "high",
			WarnSeverity: "medium",
			CacheSize:    1024,
		},
		PyPIAttest: PyPIAttestConfig{
			// On by default but annotate-only: it verifies inbound PyPI PEP 740
			// attestations and binds the attested digest to the served artifact,
			// feeding the policy/risk engines without ever blocking a pull until an
			// operator raises pypiAttestation.action to downgrade or block.
			Enabled:      true,
			Action:       "annotate",
			FailSeverity: "high",
			WarnSeverity: "medium",
			CacheSize:    1024,
		},
		SimReplay: SimReplayConfig{
			Enabled: true,
		},
		Coordination: CoordinationConfig{
			// Off by default: a single replica needs no coordination. Enable it for
			// multi-replica (HA) deployments. The TTLs below apply once enabled.
			Enabled:       false,
			Mode:          "memory",
			LeaseTTL:      30 * time.Second,
			RenewInterval: 10 * time.Second,
			RetryInterval: 10 * time.Second,
		},
		CacheFed: CacheFedConfig{
			// Off by default: peer federation is only useful in a multi-replica
			// deployment and reaches out to sibling instances, so it is opt-in. The
			// tunables below apply once enabled. Serve and RequireDigest default on
			// (resolved via their OrDefault helpers).
			Enabled:           false,
			MaxPeerFanout:     2,
			PeerTimeout:       3 * time.Second,
			HedgeDelay:        150 * time.Millisecond,
			FailureThreshold:  3,
			SuccessThreshold:  2,
			OpenTimeout:       30 * time.Second,
			HalfOpenMaxProbes: 1,
		},
		SBOMExport: SBOMExportConfig{
			// Off by default: it reaches out to external systems and needs credentials.
			// The retry/timeout tunables below apply once enabled; IncludeFindings and
			// the Dependency-Track AutoCreate flag default on via their OrDefault
			// helpers.
			Enabled:        false,
			MaxRetries:     3,
			RetryBaseDelay: 500 * time.Millisecond,
			RetryMaxDelay:  30 * time.Second,
			Timeout:        30 * time.Second,
		},
		DownloadLog: DownloadLogConfig{
			// On by default: recording a download is an in-memory append, the log is
			// bounded in entries and in time, and "which address pulled this
			// package" is the first question of every supply-chain incident. It is
			// kept in memory until an operator names a file to persist it to.
			Enabled:    true,
			MaxEntries: downloadlog.DefaultMaxEntries,
			Retention:  downloadlog.DefaultRetention,
		},
		UserLinks: defaultUserLinks(),
		KeyRotation: KeyRotationConfig{
			// On by default: expiry scanning is cheap, read-only, and never blocks a
			// pull. It only acts on material the deployment actually configures
			// (cache KEK, monitored certificates, policy-covered keys), so an
			// install with none is inert.
			Enabled:           true,
			ScanInterval:      6 * time.Hour,
			WarnThreshold:     14 * 24 * time.Hour,
			CriticalThreshold: 3 * 24 * time.Hour,
			OverlapWindow:     24 * time.Hour,
		},
		Attest: AttestConfig{
			// On by default: when the audit log is signed (transparency signing key),
			// the proxy reuses that key to attest served artifacts at no extra config.
			// With no signing key available the wiring logs that it stays inactive.
			Enabled: true,
		},
		Transparency: TransparencyConfig{
			// Off by default: submission reaches an external service and publishes the
			// attestation publicly, and inclusion-proof verification needs trusted log
			// keys, so both are opt-in.
			Rekor: RekorConfig{
				URL:     "https://rekor.sigstore.dev",
				Timeout: 15 * time.Second,
			},
		},
		Anomaly: AnomalyConfig{
			// On by default in observe-only mode: the detectors are cheap, run off
			// metadata the pull path already has, and never block until an operator
			// sets blockLevel. Off-hours detection defaults to a typical overnight
			// window in UTC.
			Enabled:       true,
			OffHoursStart: 20,
			OffHoursEnd:   6,
		},
		Approvals: ApprovalsConfig{
			// Off by default: break-glass overrides and a pending-review queue are a
			// deliberate operational choice. With it off, gates block unconditionally.
			Enabled:           false,
			RequiredApprovers: 1,
			GrantTTL:          time.Hour,
			RequestTTL:        72 * time.Hour,
			SweepInterval:     time.Minute,
		},
		Coalesce: CoalesceConfig{
			Enabled:        true,
			NegativeTTL:    30 * time.Second,
			Backoff5xxBase: 1 * time.Second,
			Backoff5xxMax:  5 * time.Second,
		},
		CacheGC: CacheGCConfig{
			Enabled:          true,
			Interval:         1 * time.Hour,
			HighWatermarkPct: 0.9,
			LowWatermarkPct:  0.7,
			Policy:           "lru",
			MinIdle:          1 * time.Minute,
		},
		Observability: ObservabilityConfig{
			Metrics:         true,
			MetricsPath:     "/metrics",
			Admin:           true,
			AdminPathPrefix: "/admin",
			MCP:             true,
		},
		Tracing: TracingConfig{
			Enabled:      false,
			ServiceName:  "pullthrough",
			SamplerRatio: 1.0,
			Timeout:      10 * time.Second,
			BatchTimeout: 5 * time.Second,
			MaxQueueSize: 2048,
			MaxBatchSize: 512,
		},
	}
}

// Load reads configuration from path (if non-empty), layering it on top of the
// defaults, then applies environment-variable expansion and overrides, and
// finally validates the result.
func Load(path string) (*Config, error) {
	cfg, err := loadEffective(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadEffective produces the effective, fully-resolved configuration — defaults
// layered with the on-disk document (strict: unknown keys are rejected), then
// ${ENV} expansion, PTS_* overrides, and enc:v1 decryption — but WITHOUT the
// semantic Validate() pass. Load runs Validate on top of it; the drift detector
// reuses it to recompute the effective fingerprint of the on-disk file on demand.
// The result is byte-for-byte identical to what Load returns, so a fingerprint
// taken here matches one taken over a Load result for the same inputs.
func loadEffective(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: reading %q: %w", path, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("config: parsing %q: %w", path, err)
		}
	}

	expandSecrets(&cfg)
	applyEnvOverrides(&cfg)

	if err := decryptSecrets(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// buildCipher resolves the at-rest encryption master key from the Secrets
// config and returns a Cipher, or nil when no key source is configured.
func (c *Config) buildCipher() (*secrets.Cipher, error) {
	s := c.Secrets
	keyEnv := s.KeyEnv
	if keyEnv == "" {
		keyEnv = "PTS_SECRETS_KEY"
	}
	key, err := secrets.LoadKeyFromEnvOrFile(keyEnv, s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: secrets key: %w", err)
	}
	if key == nil && strings.TrimSpace(s.Passphrase) != "" {
		if strings.TrimSpace(s.Salt) == "" {
			return nil, fmt.Errorf("config: secrets.passphrase requires secrets.salt")
		}
		key, err = secrets.DeriveKey(s.Passphrase, []byte(s.Salt))
		if err != nil {
			return nil, fmt.Errorf("config: deriving secrets key: %w", err)
		}
	}
	if key == nil {
		return nil, nil // encryption disabled
	}
	return secrets.NewCipher(key)
}

// decryptSecrets transparently decrypts every secret field that carries the
// "enc:v1:" prefix using the configured master key. Plaintext values pass
// through unchanged, so encrypted and cleartext secrets may be mixed during a
// migration. An encrypted value with no configured key is a hard error rather
// than a silent passthrough of ciphertext.
func decryptSecrets(cfg *Config) error {
	cipher, err := cfg.buildCipher()
	if err != nil {
		return err
	}

	resolve := func(field, value string) (string, error) {
		if !secrets.IsEncrypted(value) {
			return value, nil
		}
		out, derr := cipher.Resolve(value)
		if derr != nil {
			return "", fmt.Errorf("config: decrypting %s: %w", field, derr)
		}
		return out, nil
	}

	type ref struct {
		name string
		ptr  *string
	}
	var refs []ref
	refs = append(refs,
		ref{"scanning.apiKey", &cfg.Scanning.APIKey},
		ref{"llmPackageScan.apiKey", &cfg.LLMPackageScan.APIKey},
		ref{"scanning.watch.webhookSecret", &cfg.Scanning.Watch.WebhookSecret},
		ref{"provenance.githubToken", &cfg.Provenance.GitHubToken},
		ref{"observability.adminToken", &cfg.Observability.AdminToken},
		ref{"adminAuth.sessionKey", &cfg.AdminAuth.SessionKey},
		ref{"adminAuth.oidc.clientSecret", &cfg.AdminAuth.OIDC.ClientSecret},
		ref{"audit.hmacKey", &cfg.Audit.HMACKey},
		ref{"audit.transparency.signingKey", &cfg.Audit.Transparency.SigningKey},
		ref{"attest.signingKey", &cfg.Attest.SigningKey},
		ref{"vex.export.signingKey", &cfg.Vulnerabilities.VEX.Export.SigningKey},
		ref{"backup.passphrase", &cfg.Backup.Passphrase},
		ref{"cache.s3.accessKeyId", &cfg.Cache.S3.AccessKeyID},
		ref{"cache.s3.secretAccessKey", &cfg.Cache.S3.SecretAccessKey},
		ref{"cache.s3.sessionToken", &cfg.Cache.S3.SessionToken},
		ref{"coordination.s3.accessKeyId", &cfg.Coordination.S3.AccessKeyID},
		ref{"coordination.s3.secretAccessKey", &cfg.Coordination.S3.SecretAccessKey},
		ref{"coordination.s3.sessionToken", &cfg.Coordination.S3.SessionToken},
		ref{"userLinks.sessionKey", &cfg.UserLinks.SessionKey},
		ref{"userLinks.oidc.clientSecret", &cfg.UserLinks.OIDC.ClientSecret},
		ref{"userLinks.store.s3.accessKeyId", &cfg.UserLinks.Store.S3.AccessKeyID},
		ref{"userLinks.store.s3.secretAccessKey", &cfg.UserLinks.Store.S3.SecretAccessKey},
		ref{"userLinks.store.s3.sessionToken", &cfg.UserLinks.Store.S3.SessionToken},
		ref{"secrets.vault.token", &cfg.Secrets.Vault.Token},
		ref{"secrets.vault.roleId", &cfg.Secrets.Vault.RoleID},
		ref{"secrets.vault.secretId", &cfg.Secrets.Vault.SecretID},
	)
	for name, up := range cfg.Upstreams {
		up := up
		// Take addresses into the map by reassigning after resolution below.
		u, e1 := resolve("upstreams."+name+".credentials.username", up.Credentials.Username)
		if e1 != nil {
			return e1
		}
		p, e2 := resolve("upstreams."+name+".credentials.password", up.Credentials.Password)
		if e2 != nil {
			return e2
		}
		t, e3 := resolve("upstreams."+name+".credentials.token", up.Credentials.Token)
		if e3 != nil {
			return e3
		}
		up.Credentials.Username, up.Credentials.Password, up.Credentials.Token = u, p, t
		for i := range up.Mirrors {
			mu, em1 := resolve(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.username", name, i), up.Mirrors[i].Credentials.Username)
			if em1 != nil {
				return em1
			}
			mp, em2 := resolve(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.password", name, i), up.Mirrors[i].Credentials.Password)
			if em2 != nil {
				return em2
			}
			mt, em3 := resolve(fmt.Sprintf("upstreams.%s.mirrors[%d].credentials.token", name, i), up.Mirrors[i].Credentials.Token)
			if em3 != nil {
				return em3
			}
			up.Mirrors[i].Credentials.Username, up.Mirrors[i].Credentials.Password, up.Mirrors[i].Credentials.Token = mu, mp, mt
		}
		cfg.Upstreams[name] = up
	}
	for i := range cfg.Auth.Tokens {
		refs = append(refs, ref{
			fmt.Sprintf("auth.tokens[%d].token", i), &cfg.Auth.Tokens[i].Token,
		})
	}
	for i := range cfg.Scanning.Watch.Repos {
		refs = append(refs,
			ref{fmt.Sprintf("scanning.watch.repos[%d].username", i), &cfg.Scanning.Watch.Repos[i].Username},
			ref{fmt.Sprintf("scanning.watch.repos[%d].token", i), &cfg.Scanning.Watch.Repos[i].Token},
		)
	}
	for i := range cfg.AdminAuth.StaticTokens {
		refs = append(refs, ref{
			fmt.Sprintf("adminAuth.staticTokens[%d].token", i), &cfg.AdminAuth.StaticTokens[i].Token,
		})
	}
	for i := range cfg.Notifications.Sinks {
		refs = append(refs, ref{
			fmt.Sprintf("notifications.sinks[%d].url", i), &cfg.Notifications.Sinks[i].URL,
		})
	}
	for i := range cfg.SIEM.Sinks {
		refs = append(refs,
			ref{fmt.Sprintf("siem.sinks[%d].url", i), &cfg.SIEM.Sinks[i].URL},
			ref{fmt.Sprintf("siem.sinks[%d].token", i), &cfg.SIEM.Sinks[i].Token},
		)
	}
	for _, r := range refs {
		out, rerr := resolve(r.name, *r.ptr)
		if rerr != nil {
			return rerr
		}
		*r.ptr = out
	}
	return nil
}

// expandSecrets resolves ${ENV_VAR} references in credential/secret fields.
func expandSecrets(cfg *Config) {
	cfg.Scanning.APIKey = os.ExpandEnv(cfg.Scanning.APIKey)
	cfg.LLMPackageScan.APIKey = os.ExpandEnv(cfg.LLMPackageScan.APIKey)
	for i := range cfg.Scanning.Commit.Consensus {
		cfg.Scanning.Commit.Consensus[i].APIKey = os.ExpandEnv(cfg.Scanning.Commit.Consensus[i].APIKey)
	}
	cfg.Scanning.Watch.WebhookSecret = os.ExpandEnv(cfg.Scanning.Watch.WebhookSecret)
	for i := range cfg.Scanning.Watch.Repos {
		cfg.Scanning.Watch.Repos[i].Username = os.ExpandEnv(cfg.Scanning.Watch.Repos[i].Username)
		cfg.Scanning.Watch.Repos[i].Token = os.ExpandEnv(cfg.Scanning.Watch.Repos[i].Token)
	}
	cfg.Provenance.GitHubToken = os.ExpandEnv(cfg.Provenance.GitHubToken)
	cfg.Observability.AdminToken = os.ExpandEnv(cfg.Observability.AdminToken)
	cfg.AdminAuth.SessionKey = os.ExpandEnv(cfg.AdminAuth.SessionKey)
	cfg.AdminAuth.OIDC.ClientSecret = os.ExpandEnv(cfg.AdminAuth.OIDC.ClientSecret)
	for i := range cfg.AdminAuth.StaticTokens {
		cfg.AdminAuth.StaticTokens[i].Token = os.ExpandEnv(cfg.AdminAuth.StaticTokens[i].Token)
	}
	cfg.Secrets.Passphrase = os.ExpandEnv(cfg.Secrets.Passphrase)
	cfg.Secrets.Vault.Token = os.ExpandEnv(cfg.Secrets.Vault.Token)
	cfg.Secrets.Vault.RoleID = os.ExpandEnv(cfg.Secrets.Vault.RoleID)
	cfg.Secrets.Vault.SecretID = os.ExpandEnv(cfg.Secrets.Vault.SecretID)
	cfg.Audit.HMACKey = os.ExpandEnv(cfg.Audit.HMACKey)
	cfg.Audit.Transparency.SigningKey = os.ExpandEnv(cfg.Audit.Transparency.SigningKey)
	cfg.Backup.Passphrase = os.ExpandEnv(cfg.Backup.Passphrase)
	cfg.Compliance.SigningKey = os.ExpandEnv(cfg.Compliance.SigningKey)
	cfg.Cache.S3.AccessKeyID = os.ExpandEnv(cfg.Cache.S3.AccessKeyID)
	cfg.Cache.S3.SecretAccessKey = os.ExpandEnv(cfg.Cache.S3.SecretAccessKey)
	cfg.Cache.S3.SessionToken = os.ExpandEnv(cfg.Cache.S3.SessionToken)
	cfg.Coordination.S3.AccessKeyID = os.ExpandEnv(cfg.Coordination.S3.AccessKeyID)
	cfg.Coordination.S3.SecretAccessKey = os.ExpandEnv(cfg.Coordination.S3.SecretAccessKey)
	cfg.Coordination.S3.SessionToken = os.ExpandEnv(cfg.Coordination.S3.SessionToken)
	cfg.UserLinks.SessionKey = os.ExpandEnv(cfg.UserLinks.SessionKey)
	cfg.UserLinks.OIDC.ClientSecret = os.ExpandEnv(cfg.UserLinks.OIDC.ClientSecret)
	cfg.UserLinks.Store.S3.AccessKeyID = os.ExpandEnv(cfg.UserLinks.Store.S3.AccessKeyID)
	cfg.UserLinks.Store.S3.SecretAccessKey = os.ExpandEnv(cfg.UserLinks.Store.S3.SecretAccessKey)
	cfg.UserLinks.Store.S3.SessionToken = os.ExpandEnv(cfg.UserLinks.Store.S3.SessionToken)
	cfg.Tracing.Endpoint = os.ExpandEnv(cfg.Tracing.Endpoint)
	for k, v := range cfg.Tracing.Headers {
		cfg.Tracing.Headers[k] = os.ExpandEnv(v)
	}
	cfg.Telemetry.OTLPLogs.Endpoint = os.ExpandEnv(cfg.Telemetry.OTLPLogs.Endpoint)
	for k, v := range cfg.Telemetry.OTLPLogs.Headers {
		cfg.Telemetry.OTLPLogs.Headers[k] = os.ExpandEnv(v)
	}
	for i := range cfg.Auth.Tokens {
		cfg.Auth.Tokens[i].Token = os.ExpandEnv(cfg.Auth.Tokens[i].Token)
	}
	for i := range cfg.Notifications.Sinks {
		cfg.Notifications.Sinks[i].URL = os.ExpandEnv(cfg.Notifications.Sinks[i].URL)
	}
	for i := range cfg.SIEM.Sinks {
		cfg.SIEM.Sinks[i].URL = os.ExpandEnv(cfg.SIEM.Sinks[i].URL)
		cfg.SIEM.Sinks[i].Token = os.ExpandEnv(cfg.SIEM.Sinks[i].Token)
	}
	for name, up := range cfg.Upstreams {
		up.Credentials.Username = os.ExpandEnv(up.Credentials.Username)
		up.Credentials.Password = os.ExpandEnv(up.Credentials.Password)
		up.Credentials.Token = os.ExpandEnv(up.Credentials.Token)
		for i := range up.Mirrors {
			up.Mirrors[i].Credentials.Username = os.ExpandEnv(up.Mirrors[i].Credentials.Username)
			up.Mirrors[i].Credentials.Password = os.ExpandEnv(up.Mirrors[i].Credentials.Password)
			up.Mirrors[i].Credentials.Token = os.ExpandEnv(up.Mirrors[i].Credentials.Token)
		}
		cfg.Upstreams[name] = up
	}
}

// applyEnvOverrides lets a small set of top-level settings be overridden by
// environment variables. This is convenient for containerized deployments.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PTS_HTTP_ADDR"); v != "" {
		cfg.Server.HTTPAddr = v
	}
	if v := os.Getenv("PTS_SSH_ADDR"); v != "" {
		cfg.Server.SSHAddr = v
	}
	if v := os.Getenv("PTS_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("PTS_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("PTS_CACHE_BACKEND"); v != "" {
		cfg.Cache.Backend = v
	}
	if v := os.Getenv("PTS_CACHE_DIR"); v != "" {
		cfg.Cache.Dir = v
	}
	if v := os.Getenv("PTS_CACHE_S3_ENDPOINT"); v != "" {
		cfg.Cache.S3.Endpoint = v
	}
	if v := os.Getenv("PTS_CACHE_S3_REGION"); v != "" {
		cfg.Cache.S3.Region = v
	}
	if v := os.Getenv("PTS_CACHE_S3_BUCKET"); v != "" {
		cfg.Cache.S3.Bucket = v
	}
	if v := os.Getenv("PTS_CACHE_S3_PREFIX"); v != "" {
		cfg.Cache.S3.Prefix = v
	}
	if v := os.Getenv("PTS_CACHE_S3_ACCESS_KEY_ID"); v != "" {
		cfg.Cache.S3.AccessKeyID = v
	}
	if v := os.Getenv("PTS_CACHE_S3_SECRET_ACCESS_KEY"); v != "" {
		cfg.Cache.S3.SecretAccessKey = v
	}
	if v := os.Getenv("PTS_CACHE_S3_SESSION_TOKEN"); v != "" {
		cfg.Cache.S3.SessionToken = v
	}
	if v := os.Getenv("PTS_SCAN_API_KEY"); v != "" {
		cfg.Scanning.APIKey = v
	}
	if v := os.Getenv("PTS_LLM_PACKAGE_SCAN_API_KEY"); v != "" {
		cfg.LLMPackageScan.APIKey = v
	}
	if v := os.Getenv("PTS_ADMIN_TOKEN"); v != "" {
		cfg.Observability.AdminToken = v
	}
	if v := os.Getenv("PTS_SCAN_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Scanning.Enabled = b
		}
	}
	// Distributed tracing (Task 41). Setting an endpoint via env auto-enables
	// tracing, which is the convenient container pattern: a deployment opts in by
	// pointing PTS_TRACING_ENDPOINT at its collector. The standard OTEL_*
	// variables are honored as a fallback so the proxy plays well with sidecar
	// auto-instrumentation conventions.
	if v := os.Getenv("PTS_TRACING_ENDPOINT"); v != "" {
		cfg.Tracing.Endpoint = v
		cfg.Tracing.Enabled = true
	} else if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		cfg.Tracing.Endpoint = v
		cfg.Tracing.Enabled = true
	}
	if v := os.Getenv("PTS_TRACING_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Tracing.Enabled = b
		}
	}
	if v := os.Getenv("PTS_TRACING_INSECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Tracing.Insecure = b
		}
	}
	if v := os.Getenv("PTS_TRACING_SAMPLER_RATIO"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Tracing.SamplerRatio = f
		}
	}
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		cfg.Tracing.ServiceName = v
	}
	// OTLP structured-log export (Task 160). Mirrors the tracing env ergonomics:
	// setting the endpoint auto-enables export. The standard OTEL logs endpoint
	// variable is honored as a fallback so a sidecar-instrumented deployment
	// exports logs without proxy-specific configuration.
	if v := os.Getenv("PTS_OTLP_LOGS_ENDPOINT"); v != "" {
		cfg.Telemetry.OTLPLogs.Endpoint = v
		cfg.Telemetry.OTLPLogs.Enabled = true
	} else if v := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"); v != "" {
		cfg.Telemetry.OTLPLogs.Endpoint = v
		cfg.Telemetry.OTLPLogs.Enabled = true
	}
	if v := os.Getenv("PTS_OTLP_LOGS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Telemetry.OTLPLogs.Enabled = b
		}
	}
	if v := os.Getenv("PTS_OTLP_LOGS_INSECURE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Telemetry.OTLPLogs.Insecure = b
		}
	}
	if v := os.Getenv("PTS_OTLP_LOGS_MIN_LEVEL"); v != "" {
		cfg.Telemetry.OTLPLogs.MinLevel = v
	}
}

// Validate checks the configuration for internal consistency.
func (c *Config) Validate() error {
	if c.Server.HTTPAddr == "" {
		return fmt.Errorf("config: server.httpAddr must not be empty")
	}
	if err := c.validateIntercept(); err != nil {
		return err
	}
	if err := c.validateRegistry(); err != nil {
		return err
	}
	if err := c.validateProvenancePins(); err != nil {
		return err
	}

	switch c.Cache.Backend {
	case "memory":
	case "filesystem":
		if strings.TrimSpace(c.Cache.Dir) == "" {
			return fmt.Errorf("config: cache.dir is required for filesystem backend")
		}
	case "s3":
		if err := c.validateS3Cache(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("config: unknown cache.backend %q", c.Cache.Backend)
	}

	if err := c.validateCompression(); err != nil {
		return err
	}

	if err := c.validateEncryption(); err != nil {
		return err
	}

	if err := c.validateTiering(); err != nil {
		return err
	}

	if err := validateTLSMinVersion(c.Outbound.TLS.MinVersion); err != nil {
		return fmt.Errorf("config: outbound.tls: %w", err)
	}
	if err := validateTLSPins(c.Outbound.TLS.Pins); err != nil {
		return fmt.Errorf("config: outbound.tls: %w", err)
	}

	// An enabled-but-endpointless tracing block is the documented inert state
	// (the opt-out default), so it is not a fatal error; only a nonsensical
	// sampler ratio is rejected.
	if c.Tracing.Enabled && (c.Tracing.SamplerRatio < 0 || c.Tracing.SamplerRatio > 1) {
		return fmt.Errorf("config: tracing.samplerRatio must be within [0,1], got %g", c.Tracing.SamplerRatio)
	}

	if err := c.validateOTLPLogs(); err != nil {
		return err
	}

	validTypes := validUpstreamTypes
	for name, up := range c.Upstreams {
		if !validTypes[up.Type] {
			return fmt.Errorf("config: upstream %q has unknown type %q", name, up.Type)
		}
		if strings.TrimSpace(up.URL) == "" {
			return fmt.Errorf("config: upstream %q has empty url", name)
		}
		if err := validateUpstreamURL(up.Type, up.URL); err != nil {
			return fmt.Errorf("config: upstream %q: %w", name, err)
		}
		// A generic backend is defined entirely by its declarative route block,
		// which is validated here so an unsafe/incoherent config is rejected before
		// rollout (the same Validate the backend runs at construction). A non-generic
		// upstream that carries a stray generic block is flagged as a likely mistake.
		if up.Type == "generic" {
			if err := up.Generic.Validate(name); err != nil {
				return fmt.Errorf("config: upstream %q: %w", name, err)
			}
		} else if up.Generic != nil {
			return fmt.Errorf("config: upstream %q has a 'generic' block but type is %q (the generic block only applies to type \"generic\")", name, up.Type)
		}
		if up.TLS != nil {
			if err := validateTLSMinVersion(up.TLS.MinVersion); err != nil {
				return fmt.Errorf("config: upstream %q tls: %w", name, err)
			}
			if err := validateTLSPins(up.TLS.Pins); err != nil {
				return fmt.Errorf("config: upstream %q tls: %w", name, err)
			}
		}
		if len(up.Mirrors) > 0 && up.Type == "git" {
			return fmt.Errorf("config: upstream %q: mirrors are not supported for git upstreams", name)
		}
		mirrorIDs := make(map[string]bool, len(up.Mirrors))
		for i, m := range up.Mirrors {
			if strings.TrimSpace(m.URL) == "" {
				return fmt.Errorf("config: upstream %q mirror %d has empty url", name, i)
			}
			if err := validateUpstreamURL(up.Type, m.URL); err != nil {
				return fmt.Errorf("config: upstream %q mirror %d: %w", name, i, err)
			}
			if m.TLS != nil {
				if err := validateTLSMinVersion(m.TLS.MinVersion); err != nil {
					return fmt.Errorf("config: upstream %q mirror %d tls: %w", name, i, err)
				}
				if err := validateTLSPins(m.TLS.Pins); err != nil {
					return fmt.Errorf("config: upstream %q mirror %d tls: %w", name, i, err)
				}
			}
			if m.ID != "" {
				if mirrorIDs[m.ID] {
					return fmt.Errorf("config: upstream %q has duplicate mirror id %q", name, m.ID)
				}
				mirrorIDs[m.ID] = true
			}
		}
		if up.Failover.OpenTimeout < 0 {
			return fmt.Errorf("config: upstream %q failover.openTimeout must not be negative", name)
		}
		if up.Failover.Probe.Interval < 0 || up.Failover.Probe.Timeout < 0 {
			return fmt.Errorf("config: upstream %q failover.probe interval/timeout must not be negative", name)
		}
	}

	if c.Scanning.Enabled {
		switch c.Scanning.Provider {
		case "claude", "openai", "codex":
		case "", "none":
			return fmt.Errorf("config: scanning.enabled requires a provider")
		default:
			return fmt.Errorf("config: unknown scanning.provider %q", c.Scanning.Provider)
		}
	}
	if c.Scanning.Timeout < 0 {
		return fmt.Errorf("config: scanning.timeout must not be negative")
	}
	if c.Scanning.BaseURL != "" &&
		!strings.HasPrefix(c.Scanning.BaseURL, "http://") &&
		!strings.HasPrefix(c.Scanning.BaseURL, "https://") {
		return fmt.Errorf("config: scanning.baseUrl must be an absolute http(s) URL")
	}
	switch strings.ToLower(strings.TrimSpace(c.Scanning.ReasoningEffort)) {
	case "", "minimal", "low", "medium", "high":
	default:
		return fmt.Errorf("config: invalid scanning.reasoningEffort %q", c.Scanning.ReasoningEffort)
	}
	for i, cm := range c.Scanning.Commit.Consensus {
		switch cm.Provider {
		case "", "claude", "openai", "codex":
		default:
			return fmt.Errorf("config: unknown scanning.commit.consensus[%d].provider %q", i, cm.Provider)
		}
		if cm.BaseURL != "" &&
			!strings.HasPrefix(cm.BaseURL, "http://") &&
			!strings.HasPrefix(cm.BaseURL, "https://") {
			return fmt.Errorf("config: scanning.commit.consensus[%d].baseUrl must be an absolute http(s) URL", i)
		}
	}

	if c.Scanning.FailOn != "" {
		switch c.Scanning.FailOn {
		case "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("config: invalid scanning.failOn %q", c.Scanning.FailOn)
		}
	}

	if err := c.Scanning.Secrets.validate(); err != nil {
		return err
	}
	if err := c.Scanning.Watch.validate(); err != nil {
		return err
	}

	if c.Observability.Metrics && c.Observability.MetricsPath != "" &&
		!strings.HasPrefix(c.Observability.MetricsPath, "/") {
		return fmt.Errorf("config: observability.metricsPath must start with %q", "/")
	}
	if c.Observability.Admin && c.Observability.AdminPathPrefix != "" &&
		!strings.HasPrefix(c.Observability.AdminPathPrefix, "/") {
		return fmt.Errorf("config: observability.adminPathPrefix must start with %q", "/")
	}
	if c.Observability.Portal {
		if c.Observability.PortalPathPrefix != "" && !strings.HasPrefix(c.Observability.PortalPathPrefix, "/") {
			return fmt.Errorf("config: observability.portalPathPrefix must start with %q", "/")
		}
		if !c.AdminAuth.Enabled {
			return fmt.Errorf("config: observability.portal requires adminAuth.enabled (it identifies the caller's tenant)")
		}
		// The portal's UI prefix and admin prefix must not collide.
		if c.Observability.PortalPrefixOrDefault() == c.Observability.AdminPrefixOrDefault() {
			return fmt.Errorf("config: observability.portalPathPrefix must differ from observability.adminPathPrefix")
		}
	}

	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateClientAuth(); err != nil {
		return err
	}
	if err := c.validateAudit(); err != nil {
		return err
	}
	if err := c.validatePolicy(); err != nil {
		return err
	}
	if err := c.validatePolicyEngine(); err != nil {
		return err
	}
	if err := c.validateVulnerabilities(); err != nil {
		return err
	}
	if err := c.validateLicense(); err != nil {
		return err
	}
	if err := c.validateNameguard(); err != nil {
		return err
	}
	if err := c.validateMaturity(); err != nil {
		return err
	}
	if err := c.validateContinuity(); err != nil {
		return err
	}
	if err := c.validateDepFirewall(); err != nil {
		return err
	}
	if err := c.validateLockdown(); err != nil {
		return err
	}
	if err := c.validateAdmissionWebhook(); err != nil {
		return err
	}
	if err := c.validateSnapshot(); err != nil {
		return err
	}
	if err := c.validateGitops(); err != nil {
		return err
	}
	if err := c.validateBuildProv(); err != nil {
		return err
	}
	if err := c.validatePyPIAttest(); err != nil {
		return err
	}
	if err := c.validateRebuildVerify(); err != nil {
		return err
	}
	if err := c.validateSbomDiff(); err != nil {
		return err
	}
	if err := c.validateRemediation(); err != nil {
		return err
	}
	if err := c.validateInstallHooks(); err != nil {
		return err
	}
	if err := c.validateActionPin(); err != nil {
		return err
	}
	if err := c.validateMLGuard(); err != nil {
		return err
	}
	if err := c.validateAVScan(); err != nil {
		return err
	}
	if err := c.validateContentScan(); err != nil {
		return err
	}
	if err := c.validateLLMPackageScan(); err != nil {
		return err
	}
	if err := c.validateMalfeed(); err != nil {
		return err
	}
	if err := c.validateSigverify(); err != nil {
		return err
	}
	if err := c.validateTransparency(); err != nil {
		return err
	}
	if err := c.validateNotifications(); err != nil {
		return err
	}
	if err := c.validateRateLimit(); err != nil {
		return err
	}
	if err := c.validateCoalesce(); err != nil {
		return err
	}
	if err := c.validateCacheGC(); err != nil {
		return err
	}
	if err := c.validateBackup(); err != nil {
		return err
	}
	if err := c.validateAdminAuth(); err != nil {
		return err
	}
	if err := c.validateCoordination(); err != nil {
		return err
	}
	if err := c.validateMetering(); err != nil {
		return err
	}
	if err := c.validateDownloadLog(); err != nil {
		return err
	}
	if err := c.validateUserLinks(); err != nil {
		return err
	}
	if err := c.validateRepositories(); err != nil {
		return err
	}
	if err := c.validateTrustedProxies(); err != nil {
		return err
	}
	if err := c.validateEgress(); err != nil {
		return err
	}
	if err := c.validateFIPS(); err != nil {
		return err
	}
	if err := c.validateSIEM(); err != nil {
		return err
	}
	if err := c.validateGitLFS(); err != nil {
		return err
	}
	if err := c.validateSecrets(); err != nil {
		return err
	}
	if err := c.validatePrewarm(); err != nil {
		return err
	}
	if err := c.validateCacheFed(); err != nil {
		return err
	}
	if err := c.validateKeyRotation(); err != nil {
		return err
	}
	if err := c.validateSBOMExport(); err != nil {
		return err
	}
	if err := c.validateWebAuthn(); err != nil {
		return err
	}

	return nil
}

// validateWebAuthn checks the WebAuthn/passkey step-up configuration (Task 161).
// It is a no-op when webauthn.enabled is false.
func (c *Config) validateWebAuthn() error {
	w := c.WebAuthn
	if !w.Enabled {
		return nil
	}
	if strings.TrimSpace(w.RPID) == "" {
		return fmt.Errorf("config: webauthn.rpId is required when webauthn is enabled")
	}
	if len(w.Origins) == 0 {
		return fmt.Errorf("config: webauthn.origins must list at least one allowed origin when enabled")
	}
	for i, o := range w.Origins {
		o = strings.TrimSpace(o)
		if o == "" {
			return fmt.Errorf("config: webauthn.origins[%d] must not be empty", i)
		}
		if !strings.HasPrefix(o, "https://") && !strings.HasPrefix(o, "http://localhost") {
			return fmt.Errorf("config: webauthn.origins[%d] %q must be an https:// origin (http is allowed only for localhost)", i, o)
		}
	}
	if w.ChallengeTTL < 0 || w.StepUpTTL < 0 {
		return fmt.Errorf("config: webauthn TTLs must not be negative")
	}
	if w.StepUpTTL > 0 && w.StepUpTTL > time.Hour {
		return fmt.Errorf("config: webauthn.stepUpTtl must not exceed 1h (step-up assertions are meant to be fresh)")
	}
	for i, p := range w.ProtectedActions {
		if !strings.HasPrefix(strings.TrimSpace(p), "/api/") {
			return fmt.Errorf("config: webauthn.protectedActions[%d] %q must be an admin API path beginning with /api/", i, p)
		}
	}
	return nil
}

// validateSBOMExport checks the outbound SBOM/findings federation configuration
// (Task 153). It is a no-op when sbomExport.enabled is false.
func (c *Config) validateSBOMExport() error {
	s := c.SBOMExport
	if !s.Enabled {
		return nil
	}
	if s.MaxRetries < 0 {
		return fmt.Errorf("config: sbomExport.maxRetries must not be negative")
	}
	if s.Interval < 0 || s.Timeout < 0 || s.RetryBaseDelay < 0 || s.RetryMaxDelay < 0 {
		return fmt.Errorf("config: sbomExport durations must not be negative")
	}
	if s.MinSeverity != "" && !siem.ValidSeverity(s.MinSeverity) {
		return fmt.Errorf("config: invalid sbomExport.minSeverity %q (want info|low|medium|high|critical)", s.MinSeverity)
	}
	dt := s.DependencyTrack
	guac := s.GUAC
	if !dt.Enabled && !guac.Enabled {
		return fmt.Errorf("config: sbomExport.enabled requires at least one sink (sbomExport.dependencyTrack or sbomExport.guac)")
	}
	if dt.Enabled {
		if strings.TrimSpace(dt.URL) == "" {
			return fmt.Errorf("config: sbomExport.dependencyTrack.enabled requires a url")
		}
		if !strings.HasPrefix(dt.URL, "http://") && !strings.HasPrefix(dt.URL, "https://") {
			return fmt.Errorf("config: sbomExport.dependencyTrack.url must be an absolute http(s) URL")
		}
		if strings.TrimSpace(dt.APIKey) == "" {
			return fmt.Errorf("config: sbomExport.dependencyTrack.enabled requires an apiKey")
		}
	}
	if guac.Enabled {
		if strings.TrimSpace(guac.URL) == "" {
			return fmt.Errorf("config: sbomExport.guac.enabled requires a url")
		}
		if !strings.HasPrefix(guac.URL, "http://") && !strings.HasPrefix(guac.URL, "https://") {
			return fmt.Errorf("config: sbomExport.guac.url must be an absolute http(s) URL")
		}
		switch guac.DocumentType {
		case "", "cyclonedx", "intoto":
		default:
			return fmt.Errorf("config: sbomExport.guac.documentType %q unsupported (want cyclonedx or intoto)", guac.DocumentType)
		}
	}
	return nil
}

// validateKeyRotation checks the credential & signing-key rotation/expiry
// configuration (Task 148). It is a no-op when keyRotation.enabled is false;
// otherwise it rejects negative durations, a critical threshold larger than the
// warning threshold (which would make the critical band unreachable), monitored
// certificates missing an id or path, and non-positive rotation policy windows.
func (c *Config) validateKeyRotation() error {
	k := c.KeyRotation
	if !k.Enabled {
		return nil
	}
	if k.ScanInterval < 0 || k.WarnThreshold < 0 || k.CriticalThreshold < 0 || k.OverlapWindow < 0 {
		return fmt.Errorf("config: keyRotation durations must not be negative")
	}
	if k.WarnThreshold > 0 && k.CriticalThreshold > k.WarnThreshold {
		return fmt.Errorf("config: keyRotation.criticalThreshold (%s) must not exceed keyRotation.warnThreshold (%s)", k.CriticalThreshold, k.WarnThreshold)
	}
	seen := make(map[string]bool, len(k.Certificates))
	for i, mc := range k.Certificates {
		if strings.TrimSpace(mc.ID) == "" {
			return fmt.Errorf("config: keyRotation.certificates[%d].id must not be empty", i)
		}
		if strings.TrimSpace(mc.Path) == "" {
			return fmt.Errorf("config: keyRotation.certificates[%d].path must not be empty", i)
		}
		if seen[mc.ID] {
			return fmt.Errorf("config: keyRotation.certificates has duplicate id %q", mc.ID)
		}
		seen[mc.ID] = true
		switch mc.Kind {
		case "", "tls-cert", "ca-certificate":
		default:
			return fmt.Errorf("config: keyRotation.certificates[%d].kind %q must be one of tls-cert, ca-certificate", i, mc.Kind)
		}
	}
	for i, p := range k.Policies {
		if strings.TrimSpace(p.Material) == "" {
			return fmt.Errorf("config: keyRotation.policies[%d].material must not be empty", i)
		}
		if p.RotateEvery <= 0 {
			return fmt.Errorf("config: keyRotation.policies[%d].rotateEvery must be positive", i)
		}
	}
	return nil
}

// validateCacheFed checks the cross-proxy peer cache-federation configuration
// (Task 143). It is a no-op when cacheFed.enabled is false; otherwise it rejects
// negative/zero bounds, structurally invalid peer URLs, and duplicate peer names
// so a misconfiguration is caught at load time with a precise message.
func (c *Config) validateCacheFed() error {
	cf := c.CacheFed
	if !cf.Enabled {
		return nil
	}
	if cf.MaxPeerFanout < 0 {
		return fmt.Errorf("config: cacheFed.maxPeerFanout must not be negative")
	}
	if cf.PeerTimeout < 0 || cf.HedgeDelay < 0 || cf.OpenTimeout < 0 {
		return fmt.Errorf("config: cacheFed durations must not be negative")
	}
	if cf.FailureThreshold < 0 || cf.SuccessThreshold < 0 || cf.HalfOpenMaxProbes < 0 {
		return fmt.Errorf("config: cacheFed circuit-breaker thresholds must not be negative")
	}
	seen := make(map[string]bool, len(cf.Peers))
	for i, p := range cf.Peers {
		raw := strings.TrimSpace(p.URL)
		if raw == "" {
			return fmt.Errorf("config: cacheFed.peers[%d].url is required", i)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("config: cacheFed.peers[%d].url %q is invalid: %w", i, raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("config: cacheFed.peers[%d].url %q must be http or https", i, raw)
		}
		if u.Host == "" {
			return fmt.Errorf("config: cacheFed.peers[%d].url %q has no host", i, raw)
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = u.Host
		}
		if seen[name] {
			return fmt.Errorf("config: cacheFed.peers has a duplicate name %q", name)
		}
		seen[name] = true
	}
	return nil
}

// validatePrewarm checks the predictive cache pre-warming configuration (Task
// 134). It is a no-op when prewarm.enabled is false; otherwise it rejects
// negative bounds and a malformed off-peak window, so a misconfiguration is
// caught at load time with a precise message.
func (c *Config) validatePrewarm() error {
	p := c.Prewarm
	if !p.Enabled {
		return nil
	}
	if p.Interval < 0 || p.RecencyWindow < 0 {
		return fmt.Errorf("config: prewarm.interval and prewarm.recencyWindow must not be negative")
	}
	if p.MaxConcurrency < 0 || p.MaxPerCycle < 0 || p.RatePerMinute < 0 ||
		p.MinPulls < 0 || p.PatchLookahead < 0 || p.HistorySize < 0 {
		return fmt.Errorf("config: prewarm numeric bounds (maxConcurrency, maxPerCycle, ratePerMinute, minPulls, patchLookahead, historySize) must not be negative")
	}
	if (strings.TrimSpace(p.OffPeakStart) == "") != (strings.TrimSpace(p.OffPeakEnd) == "") {
		return fmt.Errorf("config: prewarm.offPeakStart and prewarm.offPeakEnd must both be set or both empty")
	}
	if err := validatePrewarmHHMM("prewarm.offPeakStart", p.OffPeakStart); err != nil {
		return err
	}
	if err := validatePrewarmHHMM("prewarm.offPeakEnd", p.OffPeakEnd); err != nil {
		return err
	}
	if tz := strings.TrimSpace(p.OffPeakTimezone); tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			return fmt.Errorf("config: prewarm.offPeakTimezone %q: %w", tz, err)
		}
	}
	return nil
}

// validatePrewarmHHMM checks an optional "HH:MM" time-of-day value.
func validatePrewarmHHMM(field, v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return fmt.Errorf("config: %s %q must be HH:MM", field, v)
	}
	h, herr := strconv.Atoi(parts[0])
	m, merr := strconv.Atoi(parts[1])
	if herr != nil || merr != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return fmt.Errorf("config: %s %q must be a valid 24-hour HH:MM time", field, v)
	}
	return nil
}

// validateGitLFS checks the Git LFS pull-through configuration (Task 123). It is
// a no-op when git.lfs.enabled is false; otherwise it rejects negative size
// bounds which would make the fetch/scan limits nonsensical.
func (c *Config) validateGitLFS() error {
	if !c.Git.LFS.Enabled {
		return nil
	}
	if c.Git.LFS.MaxObjectBytes < 0 {
		return fmt.Errorf("config: git.lfs.maxObjectBytes must not be negative")
	}
	if c.Git.LFS.ScanMaxBytes < 0 {
		return fmt.Errorf("config: git.lfs.scanMaxBytes must not be negative")
	}
	return nil
}

// validateSIEM checks the SIEM / log-forwarding subsystem configuration (Task
// 119). It is a no-op when siem.enabled is false. Per-sink constraints mirror
// the siem package's own validator so a misconfiguration is caught at load time
// with a precise message.
// validateOTLPLogs checks the OTLP structured-log export block (Task 160). An
// enabled-but-endpointless block is the documented inert state (surfaced as a
// check warning), so it is not fatal; only negative tuning values and an invalid
// MinLevel are rejected.
func (c *Config) validateOTLPLogs() error {
	o := c.Telemetry.OTLPLogs
	if !o.Enabled {
		return nil
	}
	if o.MaxQueueSize < 0 || o.MaxBatchSize < 0 || o.MaxRetries < 0 {
		return fmt.Errorf("config: telemetry.otlpLogs.maxQueueSize, maxBatchSize, and maxRetries must not be negative")
	}
	if o.Timeout < 0 || o.BatchTimeout < 0 || o.RetryBaseDelay < 0 || o.RetryMaxDelay < 0 {
		return fmt.Errorf("config: telemetry.otlpLogs durations must not be negative")
	}
	switch strings.ToLower(strings.TrimSpace(o.MinLevel)) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("config: invalid telemetry.otlpLogs.minLevel %q (want debug|info|warn|error)", o.MinLevel)
	}
	return nil
}

func (c *Config) validateSIEM() error {
	if !c.SIEM.Enabled {
		return nil
	}
	if c.SIEM.QueueSize < 0 || c.SIEM.BatchSize < 0 || c.SIEM.MaxRetries < 0 {
		return fmt.Errorf("config: siem.queueSize, siem.batchSize, and siem.maxRetries must not be negative")
	}
	if c.SIEM.BatchTimeout < 0 || c.SIEM.Timeout < 0 || c.SIEM.RetryBaseDelay < 0 || c.SIEM.RetryMaxDelay < 0 {
		return fmt.Errorf("config: siem durations must not be negative")
	}
	if !siem.ValidSeverity(c.SIEM.MinSeverity) {
		return fmt.Errorf("config: invalid siem.minSeverity %q", c.SIEM.MinSeverity)
	}
	if c.SIEM.Spill.Enabled && strings.TrimSpace(c.SIEM.Spill.File) == "" {
		return fmt.Errorf("config: siem.spill.enabled requires siem.spill.file")
	}
	if len(c.SIEM.Sinks) == 0 {
		return fmt.Errorf("config: siem.enabled requires at least one sink in siem.sinks")
	}
	seen := make(map[string]bool, len(c.SIEM.Sinks))
	for i, s := range c.SIEM.Sinks {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("config: siem.sinks[%d].name is required", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("config: duplicate siem sink name %q", s.Name)
		}
		seen[s.Name] = true
		if !siem.ValidKind(s.Kind) {
			return fmt.Errorf("config: siem.sinks[%d] has unknown kind %q (want splunk_hec, syslog, or ocsf)", i, s.Kind)
		}
		switch s.Kind {
		case "ocsf":
			if strings.TrimSpace(s.URL) == "" {
				return fmt.Errorf("config: siem ocsf sink %q requires a url", s.Name)
			}
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				return fmt.Errorf("config: siem ocsf sink %q url must be an absolute http(s) URL", s.Name)
			}
		case "splunk_hec":
			if strings.TrimSpace(s.URL) == "" {
				return fmt.Errorf("config: siem hec sink %q requires a url", s.Name)
			}
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				return fmt.Errorf("config: siem hec sink %q url must be an absolute http(s) URL", s.Name)
			}
			if strings.TrimSpace(s.Token) == "" {
				return fmt.Errorf("config: siem hec sink %q requires a token", s.Name)
			}
		case "syslog":
			if strings.TrimSpace(s.Address) == "" {
				return fmt.Errorf("config: siem syslog sink %q requires an address", s.Name)
			}
			switch s.Network {
			case "", "tcp", "udp", "tcp+tls":
			default:
				return fmt.Errorf("config: siem syslog sink %q has invalid network %q (want tcp, udp, or tcp+tls)", s.Name, s.Network)
			}
			if s.Facility < 0 || s.Facility > 23 {
				return fmt.Errorf("config: siem syslog sink %q facility %d out of range 0..23", s.Name, s.Facility)
			}
		}
		switch s.TLS.MinVersion {
		case "", "1.2", "1.3":
		default:
			return fmt.Errorf("config: siem sink %q tls.minVersion %q unsupported (want 1.2 or 1.3)", s.Name, s.TLS.MinVersion)
		}
	}
	for category, className := range c.SIEM.OCSF.ClassMap {
		if !siem.ValidOCSFClass(className) {
			return fmt.Errorf("config: siem.ocsf.classMap category %q maps to unknown class %q (want detection_finding, vulnerability_finding, compliance_finding, authentication, or api_activity)", category, className)
		}
	}
	return nil
}

// validateFIPS rejects configuration that would select a non-approved
// cryptographic primitive while FIPS mode is enabled (Task 120). It is a no-op
// when fips.enabled is false. The runtime-module requirement (fips.requireModule)
// is checked at process startup, not here, because it depends on the live
// crypto/fips140 module state rather than the static config.
func (c *Config) validateFIPS() error {
	if !c.FIPS.Enabled {
		return nil
	}
	// A TLS floor below 1.2 selects non-approved constructions; reject it on any
	// listener/client whose floor is explicitly configured. An unset floor ("")
	// is permitted — the proxy applies an approved TLS 1.2 floor itself.
	if !fips.TLSMinVersionApproved(c.Outbound.TLS.MinVersion) {
		return fmt.Errorf("config: fips.enabled requires outbound.tls.minVersion >= 1.2, got %q", c.Outbound.TLS.MinVersion)
	}
	for name, up := range c.Upstreams {
		if up.TLS != nil && !fips.TLSMinVersionApproved(up.TLS.MinVersion) {
			return fmt.Errorf("config: fips.enabled requires upstream %q tls.minVersion >= 1.2, got %q", name, up.TLS.MinVersion)
		}
		for i, m := range up.Mirrors {
			if m.TLS != nil && !fips.TLSMinVersionApproved(m.TLS.MinVersion) {
				return fmt.Errorf("config: fips.enabled requires upstream %q mirror %d tls.minVersion >= 1.2, got %q", name, i, m.TLS.MinVersion)
			}
		}
	}
	return nil
}

// validateProvenancePins checks the operator-asserted package -> commit pins:
// each needs an exact package name and a full commit hash, no two may assert the
// same coordinate, and pins require the provenance subsystem that serves them.
// The checks mirror provenance.NewPinSet so a bad pin is reported by
// `verify-config` rather than at startup.
func (c *Config) validateProvenancePins() error {
	pins := c.Provenance.Pins
	if len(pins) == 0 {
		return nil
	}
	if !c.Provenance.Enabled {
		return fmt.Errorf("config: provenance.pins is set but provenance.enabled is false (pins are served by the provenance subsystem)")
	}
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "*" {
			return ""
		}
		return s
	}
	seen := make(map[string]int, len(pins))
	for i, p := range pins {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return fmt.Errorf("config: provenance.pins[%d].name is required", i)
		}
		if strings.ContainsAny(name, "*?") {
			return fmt.Errorf("config: provenance.pins[%d].name %q must be an exact package name, not a pattern", i, name)
		}
		commit := strings.TrimSpace(p.Commit)
		if !isFullCommitHash(commit) {
			return fmt.Errorf("config: provenance.pins[%d].commit %q must be a full 40- or 64-character hex commit hash", i, commit)
		}
		version := strings.TrimSpace(p.Version)
		if version == "*" {
			version = ""
		}
		key := norm(p.Ecosystem) + "\x00" + strings.ToLower(name) + "\x00" + version
		if j, dup := seen[key]; dup {
			return fmt.Errorf("config: provenance.pins[%d] duplicates provenance.pins[%d] (same ecosystem, name and version)", i, j)
		}
		seen[key] = i
	}
	return nil
}

// isFullCommitHash reports whether s is a full Git commit hash (40 hex
// characters for SHA-1, 64 for SHA-256).
func isFullCommitHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// validateRegistry checks the host-root Docker/OCI Registry v2 alias
// configuration: a named default upstream must exist, be enabled, and speak the
// Registry v2 API, and no other gateway surface may be mounted inside the "/v2/"
// path space the alias owns.
func (c *Config) validateRegistry() error {
	rc := c.Server.Registry
	if !rc.EnabledOrDefault() {
		if strings.TrimSpace(rc.DefaultUpstream) != "" {
			return fmt.Errorf("config: server.registry.defaultUpstream is set but server.registry.enabled is false")
		}
		return nil
	}

	hasRegistry := false
	for _, up := range c.Upstreams {
		if up.IsEnabled() && up.IsRegistryUpstream() {
			hasRegistry = true
			break
		}
	}

	if name := strings.TrimSpace(rc.DefaultUpstream); name != "" {
		up, ok := c.Upstreams[name]
		switch {
		case !ok:
			return fmt.Errorf("config: server.registry.defaultUpstream references unknown upstream %q", name)
		case !up.IsEnabled():
			return fmt.Errorf("config: server.registry.defaultUpstream references disabled upstream %q", name)
		case !up.IsRegistryUpstream():
			return fmt.Errorf("config: server.registry.defaultUpstream %q is not a registry upstream (want type docker, or type helm with settings.oci: \"true\")", name)
		}
	}

	if !hasRegistry {
		return nil // the alias is not mounted, so nothing can collide with it
	}
	for _, mount := range []struct{ label, path string }{
		{"observability.metricsPath", c.Observability.MetricsPath},
		{"observability.adminPathPrefix", c.Observability.AdminPathPrefix},
		{"observability.portalPathPrefix", c.Observability.PortalPathPrefix},
		{"scanning.watch.webhookPath", c.Scanning.Watch.WebhookPath},
	} {
		p := strings.TrimRight(strings.TrimSpace(mount.path), "/")
		if p == "/v2" || strings.HasPrefix(p, "/v2/") {
			return fmt.Errorf("config: %s %q collides with the host-root registry alias at /v2/ (move it, or set server.registry.enabled: false)", mount.label, p)
		}
	}
	return nil
}

// validateIntercept checks the TLS-interception configuration (Tasks 100 and
// 172). It is a no-op when interception is disabled.
func (c *Config) validateIntercept() error {
	ic := c.Server.Intercept
	if !ic.Enabled {
		return nil
	}
	if !ic.Listening() {
		return fmt.Errorf("config: server.intercept needs a listener when interception is enabled: " +
			"listenAddr (forward proxy), nat.httpsAddr and/or nat.httpAddr (NAT mode)")
	}
	// Every listener needs an address of its own.
	addrs := []struct{ name, addr string }{
		{"server.httpAddr", c.Server.HTTPAddr},
		{"server.sshAddr", c.Server.SSHAddr},
		{"server.intercept.listenAddr", ic.ListenAddr},
		{"server.intercept.nat.httpsAddr", ic.NAT.HTTPSAddr},
		{"server.intercept.nat.httpAddr", ic.NAT.HTTPAddr},
	}
	for i, a := range addrs {
		if strings.TrimSpace(a.addr) == "" {
			continue
		}
		for _, b := range addrs[i+1:] {
			if strings.TrimSpace(b.addr) != "" && sameListenAddr(a.addr, b.addr) {
				return fmt.Errorf("config: %s must differ from %s (both are %q)", b.name, a.name, b.addr)
			}
		}
	}
	if strings.TrimSpace(ic.CACertFile) == "" || strings.TrimSpace(ic.CAKeyFile) == "" {
		return fmt.Errorf("config: server.intercept requires both caCertFile and caKeyFile")
	}
	if ic.LeafTTL < 0 {
		return fmt.Errorf("config: server.intercept.leafTtl must not be negative")
	}
	if ic.CertCacheSize < 0 {
		return fmt.Errorf("config: server.intercept.certCacheSize must not be negative")
	}
	for host, backend := range ic.Hosts {
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("config: server.intercept.hosts has an empty host key")
		}
		if _, _, ok := intercept.ParseRule(host); !ok {
			return fmt.Errorf("config: server.intercept.hosts[%q] does not name a host", host)
		}
		if strings.TrimSpace(backend) == "" {
			return fmt.Errorf("config: server.intercept.hosts[%q] has an empty backend", host)
		}
		if _, ok := c.Upstreams[backend]; !ok {
			return fmt.Errorf("config: server.intercept.hosts[%q] references unknown upstream %q", host, backend)
		}
	}
	return nil
}

// sameListenAddr reports whether two listen addresses would bind the same port:
// the same port, and the same host or an unspecified one on either side.
func sameListenAddr(a, b string) bool {
	if strings.TrimSpace(a) == strings.TrimSpace(b) {
		return true
	}
	ha, pa, errA := net.SplitHostPort(strings.TrimSpace(a))
	hb, pb, errB := net.SplitHostPort(strings.TrimSpace(b))
	if errA != nil || errB != nil || pa != pb {
		return false
	}
	unspecified := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || unspecified(ha) || unspecified(hb)
}

// validateEgress checks the SSRF / outbound-egress guard configuration (Task 89):
// well-formed allowlist/exception CIDRs, a non-negative redirect cap, and known
// scheme names.
func (c *Config) validateEgress() error {
	e := c.Egress
	if !e.Enabled {
		return nil
	}
	if e.MaxRedirects < 0 {
		return fmt.Errorf("config: egress.maxRedirects must not be negative")
	}
	for _, s := range e.AllowedSchemes {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "http", "https":
		default:
			return fmt.Errorf("config: egress.allowedSchemes contains unsupported scheme %q (want http or https)", s)
		}
	}
	if err := validateEgressEntries("egress.allowlist", e.Allowlist); err != nil {
		return err
	}
	for _, raw := range e.AllowedDestinationCIDRs {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") && net.ParseIP(entry) == nil {
			return fmt.Errorf("config: egress.allowedDestinationCidrs entry %q is not a CIDR or IP", raw)
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("config: egress.allowedDestinationCidrs: %w", err)
			}
		}
	}
	for tenant, tc := range e.Tenants {
		if err := validateEgressEntries(fmt.Sprintf("egress.tenants.%s.allowlist", tenant), tc.Allowlist); err != nil {
			return err
		}
	}
	return nil
}

// validateEgressEntries checks that each allowlist entry is a parseable exact
// host, domain suffix, CIDR, or IP literal.
func validateEgressEntries(field string, entries []string) error {
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("config: %s: %w", field, err)
			}
		}
	}
	return nil
}

// validateDownloadLog checks the download-log configuration (Task 176): a
// capacity within the supported range and a non-negative retention.
func (c *Config) validateDownloadLog() error {
	d := c.DownloadLog
	if d.MaxEntries < 0 {
		return fmt.Errorf("config: downloadLog.maxEntries must not be negative")
	}
	if d.MaxEntries > downloadlog.MaxMaxEntries {
		return fmt.Errorf("config: downloadLog.maxEntries must be at most %d (the log is held in memory; forward the audit log to a SIEM for a longer history)", downloadlog.MaxMaxEntries)
	}
	if d.Retention < 0 {
		return fmt.Errorf("config: downloadLog.retention must not be negative (0s disables time-based expiry)")
	}
	return nil
}

// validateTrustedProxies checks that every server.trustedProxies entry is an IP
// address or a CIDR prefix. A typo here must fail loudly: an entry that was
// silently dropped would leave every download attributed to the load balancer.
func (c *Config) validateTrustedProxies() error {
	for i, entry := range c.Server.TrustedProxies {
		if strings.TrimSpace(entry) == "" {
			return fmt.Errorf("config: server.trustedProxies[%d] is empty", i)
		}
		if _, err := clientip.ParsePrefix(entry); err != nil {
			return fmt.Errorf("config: server.trustedProxies[%d] %q is not an IP address or CIDR prefix", i, entry)
		}
	}
	return nil
}

// validateMetering checks the per-tenant usage-metering configuration (Task 84):
// non-negative retention/interval/cost values and non-negative budget ceilings.
func (c *Config) validateMetering() error {
	m := c.Metering
	if !m.Enabled {
		return nil
	}
	if m.RetentionHours < 0 {
		return fmt.Errorf("config: metering.retentionHours must not be negative")
	}
	if m.RollupInterval < 0 {
		return fmt.Errorf("config: metering.rollupInterval must not be negative")
	}
	if m.DefaultScanCostMicros < 0 {
		return fmt.Errorf("config: metering.defaultScanCostMicros must not be negative")
	}
	for gate, cost := range m.ScanCostMicros {
		if cost < 0 {
			return fmt.Errorf("config: metering.scanCostMicros[%q] must not be negative", gate)
		}
	}
	for tenant, b := range m.Budgets {
		if b.MaxBytes < 0 || b.MaxScanCostMicros < 0 {
			return fmt.Errorf("config: metering.budgets[%q] ceilings must not be negative", tenant)
		}
	}
	return nil
}

// validateCoordination checks the HA coordination configuration: a recognized
// backend mode, sane (non-negative) lease durations with the heartbeat below the
// TTL, and the backend-specific requirements (a lease directory for the file
// backend; a reachable bucket for the s3 backend, inherited from the cache when
// unset).
func (c *Config) validateCoordination() error {
	co := c.Coordination
	if !co.Enabled {
		return nil
	}
	if co.LeaseTTL < 0 || co.RenewInterval < 0 || co.RetryInterval < 0 {
		return fmt.Errorf("config: coordination lease durations must not be negative")
	}
	ttl := co.LeaseTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	if co.RenewInterval > 0 && co.RenewInterval >= ttl {
		return fmt.Errorf("config: coordination.renewInterval (%s) must be below leaseTtl (%s)", co.RenewInterval, ttl)
	}
	for job, d := range co.JobTTLs {
		if d < 0 {
			return fmt.Errorf("config: coordination.jobTtls[%q] must not be negative", job)
		}
	}
	switch strings.ToLower(strings.TrimSpace(co.Mode)) {
	case "", "memory":
		// In-process backend: valid, but only correct for a single replica. Higher
		// layers log a warning so an operator does not silently get no coordination.
	case "file":
		if strings.TrimSpace(co.Dir) == "" {
			return fmt.Errorf("config: coordination.dir is required when coordination.mode is \"file\"")
		}
	case "s3":
		// The s3 backend inherits the cache S3 settings when its own are unset, so a
		// bucket must be configured in one place or the other.
		if strings.TrimSpace(co.S3.Bucket) == "" && strings.TrimSpace(c.Cache.S3.Bucket) == "" {
			return fmt.Errorf("config: coordination.mode \"s3\" requires a bucket (coordination.s3.bucket or cache.s3.bucket)")
		}
	default:
		return fmt.Errorf("config: coordination.mode must be one of memory|s3|file, got %q", co.Mode)
	}
	return nil
}

// validateAdminAuth checks the admin SSO/RBAC configuration (Task 51): role
// names must be canonical, an enabled config must offer at least one usable
// mechanism, OIDC needs an issuer/clientId/redirectUrl and a session key, and
// static tokens need a name, at least one role, and exactly one secret form.
func (c *Config) validateAdminAuth() error {
	a := c.AdminAuth
	if !a.Enabled {
		return nil
	}

	canonical := map[string]bool{"viewer": true, "operator": true, "approver": true, "admin": true}
	checkRole := func(field, role string) error {
		if !canonical[strings.ToLower(strings.TrimSpace(role))] {
			return fmt.Errorf("config: %s: unknown role %q (want viewer|operator|approver|admin)", field, role)
		}
		return nil
	}

	for group, role := range a.RoleBindings {
		if err := checkRole(fmt.Sprintf("adminAuth.roleBindings[%q]", group), role); err != nil {
			return err
		}
	}
	if a.DefaultRole != "" {
		if err := checkRole("adminAuth.defaultRole", a.DefaultRole); err != nil {
			return err
		}
	}

	legacy := a.AllowLegacyToken == nil || *a.AllowLegacyToken
	hasLegacy := legacy && strings.TrimSpace(c.Observability.AdminToken) != ""
	hasMechanism := a.OIDC.Enabled || len(a.StaticTokens) > 0 || hasLegacy
	if !hasMechanism {
		return fmt.Errorf("config: adminAuth.enabled requires at least one of oidc, staticTokens, or the legacy observability.adminToken")
	}

	if a.OIDC.Enabled {
		o := a.OIDC
		if strings.TrimSpace(o.Issuer) == "" {
			return fmt.Errorf("config: adminAuth.oidc.issuer is required when oidc is enabled")
		}
		if strings.TrimSpace(o.ClientID) == "" {
			return fmt.Errorf("config: adminAuth.oidc.clientId is required when oidc is enabled")
		}
		if strings.TrimSpace(o.RedirectURL) == "" {
			return fmt.Errorf("config: adminAuth.oidc.redirectUrl is required when oidc is enabled")
		}
		if len(strings.TrimSpace(a.SessionKey)) < 16 {
			return fmt.Errorf("config: adminAuth.sessionKey must be at least 16 bytes when oidc is enabled")
		}
	}

	for i, t := range a.StaticTokens {
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("config: adminAuth.staticTokens[%d].name is required", i)
		}
		if len(t.Roles) == 0 {
			return fmt.Errorf("config: adminAuth.staticTokens[%q]: at least one role is required", t.Name)
		}
		for _, role := range t.Roles {
			if err := checkRole(fmt.Sprintf("adminAuth.staticTokens[%q].roles", t.Name), role); err != nil {
				return err
			}
		}
		hasTok := strings.TrimSpace(t.Token) != ""
		hasHash := strings.TrimSpace(t.TokenHash) != ""
		if hasTok == hasHash {
			return fmt.Errorf("config: adminAuth.staticTokens[%q]: set exactly one of token or tokenHash", t.Name)
		}
	}
	return nil
}

// validateBackup checks the disaster-recovery backup configuration: a scheduled
// backup needs a destination directory; encryption needs exactly one of a
// passphrase or a key file; and no duration/count may be negative.
func (c *Config) validateBackup() error {
	b := c.Backup
	if b.Interval < 0 {
		return fmt.Errorf("backup.interval must not be negative")
	}
	if b.Retain < 0 {
		return fmt.Errorf("backup.retain must not be negative")
	}
	if b.AlertAfter < 0 {
		return fmt.Errorf("backup.alertAfter must not be negative")
	}
	if b.Interval > 0 && strings.TrimSpace(b.Dir) == "" {
		return fmt.Errorf("backup.dir is required when backup.interval enables scheduled backups")
	}
	if b.Encrypt {
		hasPass := strings.TrimSpace(b.Passphrase) != ""
		hasKey := strings.TrimSpace(b.KeyFile) != ""
		if hasPass == hasKey {
			return fmt.Errorf("backup.encrypt requires exactly one of backup.passphrase or backup.keyFile")
		}
	}
	return nil
}

// validateCacheGC checks the cache lifecycle/GC configuration: sane watermark
// fractions (low below high, both in (0,1]), a recognized eviction policy, and
// no negative durations or counts.
func (c *Config) validateCacheGC() error {
	g := c.CacheGC
	if !g.Enabled {
		return nil
	}
	if g.Interval < 0 {
		return fmt.Errorf("config: cacheGc.interval must not be negative, got %s", g.Interval)
	}
	if g.CapacityBytes < 0 {
		return fmt.Errorf("config: cacheGc.capacityBytes must not be negative, got %d", g.CapacityBytes)
	}
	if g.DefaultTTL < 0 {
		return fmt.Errorf("config: cacheGc.defaultTtl must not be negative, got %s", g.DefaultTTL)
	}
	if g.MinIdle < 0 {
		return fmt.Errorf("config: cacheGc.minIdle must not be negative, got %s", g.MinIdle)
	}
	if g.MaxDeletesPerRun < 0 {
		return fmt.Errorf("config: cacheGc.maxDeletesPerRun must not be negative, got %d", g.MaxDeletesPerRun)
	}
	if g.Policy != "" && !cachegc.ValidPolicy(g.Policy) {
		return fmt.Errorf("config: cacheGc.policy must be one of lru|lfu|fifo, got %q", g.Policy)
	}
	high, low := g.HighWatermarkPct, g.LowWatermarkPct
	if high < 0 || high > 1 {
		return fmt.Errorf("config: cacheGc.highWatermarkPct must be in (0,1], got %.3f", high)
	}
	if low < 0 || low > 1 {
		return fmt.Errorf("config: cacheGc.lowWatermarkPct must be in (0,1], got %.3f", low)
	}
	if high > 0 && low > 0 && low >= high {
		return fmt.Errorf("config: cacheGc.lowWatermarkPct (%.3f) must be below highWatermarkPct (%.3f)", low, high)
	}
	for tenant, ttl := range g.TenantTTLs {
		if ttl < 0 {
			return fmt.Errorf("config: cacheGc.tenantTtls[%q] must not be negative, got %s", tenant, ttl)
		}
	}
	return nil
}

// validateCoalesce checks the pull-path coalescer configuration for
// nonsensical (negative) values and a coherent backoff window.
func (c *Config) validateCoalesce() error {
	cl := c.Coalesce
	if !cl.Enabled {
		return nil
	}
	if cl.NegativeTTL < 0 {
		return fmt.Errorf("config: coalesce.negativeTtl must not be negative, got %s", cl.NegativeTTL)
	}
	if cl.MaxNegativeEntries < 0 {
		return fmt.Errorf("config: coalesce.maxNegativeEntries must not be negative, got %d", cl.MaxNegativeEntries)
	}
	if cl.MaxInflight < 0 {
		return fmt.Errorf("config: coalesce.maxInflight must not be negative, got %d", cl.MaxInflight)
	}
	if cl.Backoff5xxBase < 0 {
		return fmt.Errorf("config: coalesce.backoff5xxBase must not be negative, got %s", cl.Backoff5xxBase)
	}
	if cl.Backoff5xxMax < 0 {
		return fmt.Errorf("config: coalesce.backoff5xxMax must not be negative, got %s", cl.Backoff5xxMax)
	}
	if cl.Backoff5xxMax > 0 && cl.Backoff5xxBase > 0 && cl.Backoff5xxMax < cl.Backoff5xxBase {
		return fmt.Errorf("config: coalesce.backoff5xxMax (%s) must not be less than backoff5xxBase (%s)",
			cl.Backoff5xxMax, cl.Backoff5xxBase)
	}
	return nil
}

// validateRateLimit checks the rate-limit policies for nonsensical (negative)
// values, including every per-team override.
func (c *Config) validateRateLimit() error {
	if !c.RateLimit.Enabled {
		return nil
	}
	if err := validateRateLimitPolicy("rateLimit.global", c.RateLimit.Global); err != nil {
		return err
	}
	if err := validateRateLimitPolicy("rateLimit.default", c.RateLimit.Default); err != nil {
		return err
	}
	for name, t := range c.Auth.Teams {
		if err := validateRateLimitPolicy(fmt.Sprintf("auth.teams.%s.rateLimit", name), t.RateLimit); err != nil {
			return err
		}
	}
	return nil
}

// validateRateLimitPolicy rejects negative values on any policy dimension.
func validateRateLimitPolicy(field string, p RateLimitPolicyConfig) error {
	if p.RPS < 0 {
		return fmt.Errorf("config: %s.rps must not be negative", field)
	}
	if p.Burst < 0 {
		return fmt.Errorf("config: %s.burst must not be negative", field)
	}
	if p.MaxConcurrent < 0 {
		return fmt.Errorf("config: %s.maxConcurrent must not be negative", field)
	}
	if p.ByteQuota < 0 {
		return fmt.Errorf("config: %s.byteQuota must not be negative", field)
	}
	if p.Window < 0 {
		return fmt.Errorf("config: %s.window must not be negative", field)
	}
	return nil
}

// validateSigverify checks the signature-verification gate configuration: a valid
// action, severity buckets, recognized ecosystems, and that an air-gapped
// (offline) deployment is given a trust bundle.
func (c *Config) validateSigverify() error {
	s := c.Sigverify
	if !s.Enabled {
		return nil
	}
	if !policy.ValidAction(s.Action) {
		return fmt.Errorf("config: sigverify.action %q is invalid (want warn|block|quarantine)", s.Action)
	}
	for field, sev := range map[string]string{
		"failSeverity": s.FailSeverity,
		"warnSeverity": s.WarnSeverity,
	} {
		if !validVulnSeverity(sev) {
			return fmt.Errorf("config: sigverify.%s %q is invalid (want none|low|medium|high|critical)", field, sev)
		}
	}
	for _, eco := range s.Ecosystems {
		switch strings.ToLower(strings.TrimSpace(eco)) {
		case "docker", "oci", "npm", "pip", "pypi":
		default:
			return fmt.Errorf("config: sigverify.ecosystems contains unsupported ecosystem %q (want docker|npm|pip)", eco)
		}
	}
	for i, k := range s.Keys {
		if strings.TrimSpace(k.File) == "" && strings.TrimSpace(k.PEM) == "" {
			return fmt.Errorf("config: sigverify.keys[%d] requires a file or pem", i)
		}
	}
	if s.Offline && strings.TrimSpace(s.TrustBundleFile) == "" {
		return fmt.Errorf("config: sigverify.offline requires sigverify.trustBundleFile")
	}
	if s.CacheTTL < 0 {
		return fmt.Errorf("config: sigverify.cacheTtl must not be negative, got %s", s.CacheTTL)
	}
	if !sigverify.ValidPQCPolicy(s.PQC.Policy) {
		return fmt.Errorf("config: sigverify.pqc.policy %q is invalid (want classical-only|allow-hybrid|require-pqc)", s.PQC.Policy)
	}
	// Post-quantum support under FIPS mode: the PQC provider is not a FIPS 140-3
	// validated module, so fail preflight with a clear message rather than
	// silently disabling PQC or running a non-validated provider (Task 151/120).
	if s.PQC.Enabled && c.FIPS.Enabled && !sigverify.PQCProviderFIPSValidated {
		return fmt.Errorf("config: sigverify.pqc.enabled is incompatible with fips.enabled: the post-quantum provider %q is not a FIPS 140-3 validated cryptographic module; disable sigverify.pqc or fips to proceed", sigverify.PQCProviderName)
	}
	return nil
}

// validateTransparency checks the Sigstore Rekor transparency-log configuration:
// a well-formed log URL and a non-negative timeout. Public-key files are
// validated at load time (where read errors surface), not here.
func (c *Config) validateTransparency() error {
	r := c.Transparency.Rekor
	if !r.Enabled {
		return nil
	}
	if u := strings.TrimSpace(r.URL); u != "" {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("config: transparency.rekor.url %q must be an http(s) URL", r.URL)
		}
	}
	if r.Timeout < 0 {
		return fmt.Errorf("config: transparency.rekor.timeout must not be negative, got %s", r.Timeout)
	}
	return nil
}

// validateNotifications checks the notification subsystem configuration:
// non-negative numeric knobs, a valid global severity floor, well-formed sinks
// (unique names, known kinds, http(s) URLs), and routes that reference defined
// sinks with valid event types/severities.
func (c *Config) validateNotifications() error {
	n := c.Notifications
	if !n.Enabled {
		return nil
	}
	if n.Workers < 0 {
		return fmt.Errorf("config: notifications.workers must not be negative, got %d", n.Workers)
	}
	if n.QueueSize < 0 {
		return fmt.Errorf("config: notifications.queueSize must not be negative, got %d", n.QueueSize)
	}
	if n.MaxRetries < 0 {
		return fmt.Errorf("config: notifications.maxRetries must not be negative, got %d", n.MaxRetries)
	}
	if !notify.ValidSeverity(n.MinSeverity) {
		return fmt.Errorf("config: notifications.minSeverity %q is invalid (want none|low|medium|high|critical)", n.MinSeverity)
	}
	if len(n.Sinks) == 0 {
		return fmt.Errorf("config: notifications.enabled requires at least one sink")
	}
	names := make(map[string]bool, len(n.Sinks))
	for i, s := range n.Sinks {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			return fmt.Errorf("config: notifications.sinks[%d] has an empty name", i)
		}
		if names[name] {
			return fmt.Errorf("config: notifications duplicate sink name %q", name)
		}
		names[name] = true
		switch strings.ToLower(strings.TrimSpace(s.Kind)) {
		case "webhook", "slack":
		default:
			return fmt.Errorf("config: notifications.sinks[%q] has unknown kind %q (want webhook|slack)", name, s.Kind)
		}
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("config: notifications.sinks[%q] has an empty url", name)
		}
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("config: notifications.sinks[%q] url must be http(s)", name)
		}
	}
	for i, r := range n.Routes {
		if len(r.Sinks) == 0 {
			return fmt.Errorf("config: notifications.routes[%d] references no sinks", i)
		}
		for _, sn := range r.Sinks {
			if !names[sn] {
				return fmt.Errorf("config: notifications.routes[%d] references undefined sink %q", i, sn)
			}
		}
		if !notify.ValidSeverity(r.MinSeverity) {
			return fmt.Errorf("config: notifications.routes[%d].minSeverity %q is invalid", i, r.MinSeverity)
		}
		for _, t := range r.EventTypes {
			if !notify.ValidEventType(t) {
				return fmt.Errorf("config: notifications.routes[%d] has unknown event type %q", i, t)
			}
		}
	}
	return nil
}

// validateNameguard checks the typosquatting/dependency-confusion guard
// configuration: a valid action, recognized severity buckets, and non-negative
// numeric knobs.
func (c *Config) validateNameguard() error {
	n := c.Nameguard
	if !n.Enabled {
		return nil
	}
	if !policy.ValidAction(n.Action) {
		return fmt.Errorf("config: nameguard.action %q is invalid (want warn|block|quarantine)", n.Action)
	}
	for field, sev := range map[string]string{
		"failSeverity": n.FailSeverity,
		"warnSeverity": n.WarnSeverity,
	} {
		if !nameguard.ValidSeverity(sev) {
			return fmt.Errorf("config: nameguard.%s %q is invalid (want none|low|medium|high|critical)", field, sev)
		}
	}
	if n.DistanceThreshold < 0 {
		return fmt.Errorf("config: nameguard.distanceThreshold must not be negative, got %d", n.DistanceThreshold)
	}
	if n.MinNameLength < 0 {
		return fmt.Errorf("config: nameguard.minNameLength must not be negative, got %d", n.MinNameLength)
	}
	return nil
}

// validateMaturity checks the release-maturity / version-cooldown gate
// configuration: non-negative durations and bounds for every cooldown and cache
// setting (a negative cooldown is meaningless).
func (c *Config) validateMaturity() error {
	m := c.Maturity
	if !m.Enabled {
		return nil
	}
	if m.DefaultCooldown < 0 {
		return fmt.Errorf("config: maturity.defaultCooldown must not be negative, got %s", m.DefaultCooldown)
	}
	for eco, d := range m.Ecosystems {
		if d < 0 {
			return fmt.Errorf("config: maturity.ecosystems[%q] must not be negative, got %s", eco, d)
		}
	}
	for tenant, t := range m.Tenants {
		if t.DefaultCooldown < 0 {
			return fmt.Errorf("config: maturity.tenants[%q].defaultCooldown must not be negative, got %s", tenant, t.DefaultCooldown)
		}
		for eco, d := range t.Ecosystems {
			if d < 0 {
				return fmt.Errorf("config: maturity.tenants[%q].ecosystems[%q] must not be negative, got %s", tenant, eco, d)
			}
		}
	}
	if m.Timeout < 0 {
		return fmt.Errorf("config: maturity.timeout must not be negative, got %s", m.Timeout)
	}
	if m.CacheTTL < 0 {
		return fmt.Errorf("config: maturity.cacheTTL must not be negative, got %s", m.CacheTTL)
	}
	if m.NegativeCacheTTL < 0 {
		return fmt.Errorf("config: maturity.negativeCacheTTL must not be negative, got %s", m.NegativeCacheTTL)
	}
	if m.CacheSize < 0 {
		return fmt.Errorf("config: maturity.cacheSize must not be negative, got %d", m.CacheSize)
	}
	return nil
}

// validateContinuity checks the maintainer/publisher continuity gate
// configuration: a known disposition (global, per-ecosystem, per-tenant) and
// non-negative durations/bounds.
func (c *Config) validateContinuity() error {
	cc := c.Continuity
	if !cc.Enabled {
		return nil
	}
	validDisp := func(d string) bool {
		switch strings.ToLower(strings.TrimSpace(d)) {
		case "", "observe", "warn", "block":
			return true
		default:
			return false
		}
	}
	if !validDisp(cc.DefaultDisposition) {
		return fmt.Errorf("config: continuity.defaultDisposition must be observe|warn|block, got %q", cc.DefaultDisposition)
	}
	for eco, d := range cc.Ecosystems {
		if !validDisp(d) {
			return fmt.Errorf("config: continuity.ecosystems[%q] must be observe|warn|block, got %q", eco, d)
		}
	}
	for tenant, t := range cc.Tenants {
		if !validDisp(t.Disposition) {
			return fmt.Errorf("config: continuity.tenants[%q].disposition must be observe|warn|block, got %q", tenant, t.Disposition)
		}
		for eco, d := range t.Ecosystems {
			if !validDisp(d) {
				return fmt.Errorf("config: continuity.tenants[%q].ecosystems[%q] must be observe|warn|block, got %q", tenant, eco, d)
			}
		}
		if t.Cooldown < 0 {
			return fmt.Errorf("config: continuity.tenants[%q].cooldown must not be negative, got %s", tenant, t.Cooldown)
		}
	}
	if cc.Cooldown < 0 {
		return fmt.Errorf("config: continuity.cooldown must not be negative, got %s", cc.Cooldown)
	}
	if cc.Timeout < 0 {
		return fmt.Errorf("config: continuity.timeout must not be negative, got %s", cc.Timeout)
	}
	if cc.CacheTTL < 0 {
		return fmt.Errorf("config: continuity.cacheTTL must not be negative, got %s", cc.CacheTTL)
	}
	if cc.NegativeCacheTTL < 0 {
		return fmt.Errorf("config: continuity.negativeCacheTTL must not be negative, got %s", cc.NegativeCacheTTL)
	}
	if cc.CacheSize < 0 {
		return fmt.Errorf("config: continuity.cacheSize must not be negative, got %d", cc.CacheSize)
	}
	if cc.MaxRecords < 0 {
		return fmt.Errorf("config: continuity.maxRecords must not be negative, got %d", cc.MaxRecords)
	}
	return nil
}

// validateDepFirewall checks the dependency-firewall gate configuration: a valid
// default action (global and per-tenant) and well-formed rules (each carries an
// ecosystem and name). Range-expression validity is enforced when the service is
// constructed, where a malformed range is fatal.
func (c *Config) validateDepFirewall() error {
	d := c.DepFirewall
	if !d.Enabled {
		return nil
	}
	if err := validateDepFirewallAction("depfirewall.defaultAction", d.DefaultAction); err != nil {
		return err
	}
	for i, r := range d.Rules {
		if err := validateDepFirewallRule(fmt.Sprintf("depfirewall.rules[%d]", i), r); err != nil {
			return err
		}
	}
	for tenant, t := range d.Tenants {
		if err := validateDepFirewallAction(fmt.Sprintf("depfirewall.tenants[%q].defaultAction", tenant), t.DefaultAction); err != nil {
			return err
		}
		for i, r := range t.Rules {
			if err := validateDepFirewallRule(fmt.Sprintf("depfirewall.tenants[%q].rules[%d]", tenant, i), r); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateDepFirewallAction accepts an empty (inherit) value or one of the two
// recognized dispositions.
func validateDepFirewallAction(field, action string) error {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "allow", "block":
		return nil
	default:
		return fmt.Errorf("config: %s must be \"allow\" or \"block\", got %q", field, action)
	}
}

// validateDepFirewallRule requires an ecosystem and name on every rule.
func validateDepFirewallRule(field string, r DepFirewallRule) error {
	if strings.TrimSpace(r.Ecosystem) == "" {
		return fmt.Errorf("config: %s.ecosystem must not be empty", field)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("config: %s.name must not be empty", field)
	}
	return nil
}

// validateInstallHooks checks the install-script / lifecycle-hook risk gate
// configuration: valid severity thresholds (warn must not exceed fail), a valid
// action, well-formed custom rule patterns, and valid per-tenant overrides.
func (c *Config) validateInstallHooks() error {
	h := c.InstallHooks
	if !h.Enabled {
		return nil
	}
	validSev := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "info", "low", "medium", "high", "critical":
			return nil
		default:
			return fmt.Errorf("config: invalid %s %q", field, v)
		}
	}
	sevRank := func(v string) int {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "info":
			return 1
		case "low":
			return 2
		case "medium":
			return 3
		case "high":
			return 4
		case "critical":
			return 5
		default:
			return 0
		}
	}
	validAction := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "block", "warn":
			return nil
		default:
			return fmt.Errorf("config: %s must be block|warn, got %q", field, v)
		}
	}
	if err := validSev("installHooks.failSeverity", h.FailSeverity); err != nil {
		return err
	}
	if err := validSev("installHooks.warnSeverity", h.WarnSeverity); err != nil {
		return err
	}
	if h.WarnSeverity != "" && h.FailSeverity != "" && sevRank(h.WarnSeverity) > sevRank(h.FailSeverity) {
		return fmt.Errorf("config: installHooks.warnSeverity %q must not exceed failSeverity %q", h.WarnSeverity, h.FailSeverity)
	}
	if err := validAction("installHooks.action", h.Action); err != nil {
		return err
	}
	if h.MaxFindingsPerHook < 0 {
		return fmt.Errorf("config: installHooks.maxFindingsPerHook must not be negative, got %d", h.MaxFindingsPerHook)
	}
	seen := make(map[string]bool, len(h.Rules))
	for i, r := range h.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("config: installHooks.rules[%d] is missing an id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("config: installHooks.rules: duplicate id %q", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("config: installHooks.rules[%q] is missing a pattern", r.ID)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("config: installHooks.rules[%q] has an invalid pattern: %w", r.ID, err)
		}
		if err := validSev(fmt.Sprintf("installHooks.rules[%q].severity", r.ID), r.Severity); err != nil {
			return err
		}
	}
	for tenant, t := range h.Tenants {
		if err := validSev(fmt.Sprintf("installHooks.tenants[%q].failSeverity", tenant), t.FailSeverity); err != nil {
			return err
		}
		if err := validSev(fmt.Sprintf("installHooks.tenants[%q].warnSeverity", tenant), t.WarnSeverity); err != nil {
			return err
		}
		if err := validAction(fmt.Sprintf("installHooks.tenants[%q].action", tenant), t.Action); err != nil {
			return err
		}
	}
	return nil
}

// validateActionPin checks the GitHub Actions pinning gate configuration: valid
// severity thresholds (warn must not exceed fail), a valid action, non-negative
// finding cap, non-empty allowlist entries, and valid per-tenant overrides. The
// gate's enablement is a pointer that defaults in the wiring layer, so this
// validates the fields whenever they are present rather than gating on Enabled.
func (c *Config) validateActionPin() error {
	a := c.Scanning.Actions
	validSev := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "info", "low", "medium", "high", "critical":
			return nil
		default:
			return fmt.Errorf("config: invalid %s %q", field, v)
		}
	}
	sevRank := func(v string) int {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "info":
			return 1
		case "low":
			return 2
		case "medium":
			return 3
		case "high":
			return 4
		case "critical":
			return 5
		default:
			return 0
		}
	}
	validAction := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "block", "warn":
			return nil
		default:
			return fmt.Errorf("config: %s must be block|warn, got %q", field, v)
		}
	}
	if err := validSev("scanning.actions.failSeverity", a.FailSeverity); err != nil {
		return err
	}
	if err := validSev("scanning.actions.warnSeverity", a.WarnSeverity); err != nil {
		return err
	}
	if a.WarnSeverity != "" && a.FailSeverity != "" && sevRank(a.WarnSeverity) > sevRank(a.FailSeverity) {
		return fmt.Errorf("config: scanning.actions.warnSeverity %q must not exceed failSeverity %q", a.WarnSeverity, a.FailSeverity)
	}
	if err := validAction("scanning.actions.action", a.Action); err != nil {
		return err
	}
	if a.MaxFindings < 0 {
		return fmt.Errorf("config: scanning.actions.maxFindings must not be negative, got %d", a.MaxFindings)
	}
	for i, o := range a.AllowedOwners {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("config: scanning.actions.allowedOwners[%d] must not be empty", i)
		}
	}
	for tenant, t := range a.Tenants {
		if err := validSev(fmt.Sprintf("scanning.actions.tenants[%q].failSeverity", tenant), t.FailSeverity); err != nil {
			return err
		}
		if err := validSev(fmt.Sprintf("scanning.actions.tenants[%q].warnSeverity", tenant), t.WarnSeverity); err != nil {
			return err
		}
		if err := validAction(fmt.Sprintf("scanning.actions.tenants[%q].action", tenant), t.Action); err != nil {
			return err
		}
	}
	return nil
}

// validateMLGuard checks the ML weight-scanning gate configuration: valid
// severity thresholds (warn must not exceed fail), a valid action, non-negative
// scan bounds, and valid per-tenant overrides.
func (c *Config) validateMLGuard() error {
	m := c.MLGuard
	if !m.Enabled {
		return nil
	}
	validSev := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "info", "low", "medium", "high", "critical":
			return nil
		default:
			return fmt.Errorf("config: invalid %s %q", field, v)
		}
	}
	sevRank := func(v string) int {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "info":
			return 1
		case "low":
			return 2
		case "medium":
			return 3
		case "high":
			return 4
		case "critical":
			return 5
		default:
			return 0
		}
	}
	validAction := func(field, v string) error {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "block", "warn":
			return nil
		default:
			return fmt.Errorf("config: %s must be block|warn, got %q", field, v)
		}
	}
	if err := validSev("mlGuard.failSeverity", m.FailSeverity); err != nil {
		return err
	}
	if err := validSev("mlGuard.warnSeverity", m.WarnSeverity); err != nil {
		return err
	}
	if m.WarnSeverity != "" && m.FailSeverity != "" && sevRank(m.WarnSeverity) > sevRank(m.FailSeverity) {
		return fmt.Errorf("config: mlGuard.warnSeverity %q must not exceed failSeverity %q", m.WarnSeverity, m.FailSeverity)
	}
	if err := validAction("mlGuard.action", m.Action); err != nil {
		return err
	}
	if m.MaxScanBytes < 0 {
		return fmt.Errorf("config: mlGuard.maxScanBytes must not be negative, got %d", m.MaxScanBytes)
	}
	if m.MaxZipEntries < 0 {
		return fmt.Errorf("config: mlGuard.maxZipEntries must not be negative, got %d", m.MaxZipEntries)
	}
	for tenant, t := range m.Tenants {
		if err := validSev(fmt.Sprintf("mlGuard.tenants[%q].failSeverity", tenant), t.FailSeverity); err != nil {
			return err
		}
		if err := validSev(fmt.Sprintf("mlGuard.tenants[%q].warnSeverity", tenant), t.WarnSeverity); err != nil {
			return err
		}
		if err := validAction(fmt.Sprintf("mlGuard.tenants[%q].action", tenant), t.Action); err != nil {
			return err
		}
	}
	return nil
}

// validateAVScan checks the antivirus content-scanning gate configuration: a
// known engine, a valid action, a non-empty engine address, and non-negative
// bounds/timeout.
func (c *Config) validateAVScan() error {
	a := c.AVScan
	if !a.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(a.Action)) {
	case "", "annotate", "quarantine", "block":
	default:
		return fmt.Errorf("config: avScan.action must be annotate|quarantine|block, got %q", a.Action)
	}
	switch strings.ToLower(strings.TrimSpace(a.Engine)) {
	case "", "clamav":
	default:
		return fmt.Errorf("config: avScan.engine %q is not supported (only \"clamav\")", a.Engine)
	}
	if strings.TrimSpace(a.Address) == "" {
		return fmt.Errorf("config: avScan.address is required when the gate is enabled (clamd host:port or unix socket path)")
	}
	if a.MaxScanBytes < 0 {
		return fmt.Errorf("config: avScan.maxScanBytes must not be negative, got %d", a.MaxScanBytes)
	}
	if a.Timeout < 0 {
		return fmt.Errorf("config: avScan.timeout must not be negative")
	}
	return nil
}

// validateContentScan checks the package-content analysis gate configuration: a
// valid action and fail-severity, a recognized ecosystem set, an entropy
// threshold in range, and non-negative budget bounds.
func (c *Config) validateContentScan() error {
	cs := c.ContentScan
	if !cs.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(cs.Action)) {
	case "", "annotate", "downgrade", "block":
	default:
		return fmt.Errorf("config: contentScan.action must be annotate|downgrade|block, got %q", cs.Action)
	}
	if cs.FailSeverity != "" {
		switch strings.ToLower(strings.TrimSpace(cs.FailSeverity)) {
		case "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("config: contentScan.failSeverity must be info|low|medium|high|critical, got %q", cs.FailSeverity)
		}
	}
	known := map[string]bool{"npm": true, "pip": true, "pypi": true, "python": true,
		"cargo": true, "crates": true, "rust": true, "rubygems": true, "gem": true, "ruby": true,
		"composer": true, "packagist": true, "php": true, "nuget": true, "dotnet": true}
	for _, e := range cs.Ecosystems {
		if !known[strings.ToLower(strings.TrimSpace(e))] {
			return fmt.Errorf("config: contentScan.ecosystems contains unsupported ecosystem %q", e)
		}
	}
	if cs.EntropyThreshold < 0 || cs.EntropyThreshold > 8 {
		return fmt.Errorf("config: contentScan.entropyThreshold must be in [0,8], got %.3f", cs.EntropyThreshold)
	}
	if cs.MinEntropyBlobBytes < 0 || cs.MaxArchiveBytes < 0 || cs.MaxFileBytes < 0 || cs.MaxScanBytesPerFile < 0 {
		return fmt.Errorf("config: contentScan byte bounds must not be negative")
	}
	if cs.MaxFiles < 0 || cs.MaxFindings < 0 || cs.MaxFindingsPerFile < 0 {
		return fmt.Errorf("config: contentScan count bounds must not be negative")
	}
	if cs.Timeout < 0 {
		return fmt.Errorf("config: contentScan.timeout must not be negative")
	}
	return nil
}

// SbomDiffConfig configures the SBOM diff & dependency-drift subsystem (Task 64).
// The subsystem records a bounded per-coordinate history of resolved SBOMs and,
// on each new version, diffs the transitive dependency set, the declared licenses
// (cross-referenced against the license policy), the dependency namespaces, and
// the known vulnerabilities against the prior version, scoring the change as a
// 0..100 "drift risk". A score at or above warnThreshold annotates the response;
// at or above blockThreshold the configured action (warn|block|quarantine) is
// taken; at or above significantThreshold the diff is reported via EventSbomDrift
// and surfaced as an admission signal to the policy engine.
type SbomDiffConfig struct {
	// Enabled turns on snapshot recording, drift evaluation, the admin surface,
	// and the Prometheus metrics. On by default but observe-and-alert only: the
	// default action is warn, so it never blocks a pull until an operator raises
	// the action to block/quarantine.
	Enabled bool `yaml:"enabled"`
	// HistorySize is the number of recent version snapshots retained per
	// coordinate (default 16). A larger history allows diffing further back (the
	// "since the version I last approved" query).
	HistorySize int `yaml:"historySize"`
	// MaxCoordinates bounds the number of distinct coordinate histories retained
	// (default 4096); the least-recently-updated coordinate is evicted first.
	MaxCoordinates int `yaml:"maxCoordinates"`
	// Action is taken when a diff's drift score reaches blockThreshold:
	// warn|block|quarantine (default warn).
	Action string `yaml:"action"`
	// WarnThreshold is the drift score at/above which a pull is annotated with the
	// X-Sbom-Drift headers even when the action would not block (default 25).
	WarnThreshold float64 `yaml:"warnThreshold"`
	// BlockThreshold is the drift score at/above which Action is applied
	// (default 60).
	BlockThreshold float64 `yaml:"blockThreshold"`
	// SignificantThreshold is the drift score at/above which a diff is reported
	// (EventSbomDrift) and exposed as an admission signal (default 40).
	SignificantThreshold float64 `yaml:"significantThreshold"`
	// Weights overrides the per-factor drift-score weights; a zero field inherits
	// the built-in default for that factor.
	Weights SbomDriftWeights `yaml:"weights"`
}

// SbomDriftWeights overrides individual terms of the drift-score model. Each zero
// field inherits the subsystem default, so an operator can retune a single factor
// without restating the whole model.
type SbomDriftWeights struct {
	PerAddedDep      float64 `yaml:"perAddedDep"`
	PerNewNamespace  float64 `yaml:"perNewNamespace"`
	PerVersionBump   float64 `yaml:"perVersionBump"`
	PerRemovedDep    float64 `yaml:"perRemovedDep"`
	NewLicenseAllow  float64 `yaml:"newLicenseAllow"`
	NewLicenseReview float64 `yaml:"newLicenseReview"`
	NewLicenseDeny   float64 `yaml:"newLicenseDeny"`
	VulnCritical     float64 `yaml:"vulnCritical"`
	VulnHigh         float64 `yaml:"vulnHigh"`
	VulnMedium       float64 `yaml:"vulnMedium"`
	VulnLow          float64 `yaml:"vulnLow"`
}

// RemediationConfig configures the automated dependency-remediation advisor
// (Task 121). The advisor is read-only and on-demand: it never blocks a pull. It
// pulls candidate versions from the upstream registry and scores each through
// the already-built admission gates to find the nearest safe upgrade.
type RemediationConfig struct {
	// Enabled turns on the advisor's admin endpoint (/api/remediation/advise),
	// the `ptctl remediate` subcommand, the dossier "suggested fix" panel, and
	// SARIF fix-suggestion annotation. On by default.
	Enabled bool `yaml:"enabled"`
	// MaxCandidates bounds how many newer versions a single advisory evaluates
	// (default 25). Each candidate may incur a live upstream fetch and scan, so a
	// smaller bound trades upgrade reach for lower load and latency.
	MaxCandidates int `yaml:"maxCandidates"`
	// IncludePrerelease lets advisories consider prerelease versions (e.g.
	// 2.0.0-rc1) as upgrade targets. Off by default: production upgrades should
	// target stable releases.
	IncludePrerelease bool `yaml:"includePrerelease"`
	// UserAgent is sent on the version-list requests to upstream registries. An
	// empty value uses a built-in default.
	UserAgent string `yaml:"userAgent"`
	// BaseURLs overrides the version-list registry base URL per canonical
	// ecosystem (npm/pip/cargo/go/nuget/rubygems/composer/maven), for private
	// mirrors or air-gapped deployments. An absent entry uses the public default.
	BaseURLs map[string]string `yaml:"baseURLs"`
}

// RebuildVerifyConfig configures the reproducible-build verification gate (Task
// 68). It is on by default but observe-only (mode "observe"): it records and
// surfaces verdicts and feeds them to the policy/risk engines without ever
// blocking a pull until an operator raises the mode to "enforce". Verification is
// asynchronous (non-blocking) and air-gap aware — it skips gracefully (verdict
// "unsupported") when the build toolchain or source repository is unavailable.
type RebuildVerifyConfig struct {
	// Enabled turns on verification, the admission signal, the admin surface, and
	// the Prometheus metrics.
	Enabled bool `yaml:"enabled"`
	// Mode is observe|enforce. observe (default) records the verdict and feeds the
	// policy/risk engines; enforce additionally quarantines an artifact on a
	// confirmed mismatch (composing with the break-glass workflow).
	Mode string `yaml:"mode"`
	// Async runs verification in a bounded background goroutine so a pull is never
	// blocked waiting on a rebuild (default true). Set false to verify inline.
	Async *bool `yaml:"async"`
	// MaxConcurrent bounds in-flight background rebuilds (default 2).
	MaxConcurrent int `yaml:"maxConcurrent"`
	// BuildTimeout bounds a single background rebuild (default 10m).
	BuildTimeout time.Duration `yaml:"buildTimeout"`
	// CacheSize bounds the per-(coordinate,digest) result cache (default 4096).
	CacheSize int `yaml:"cacheSize"`
	// RecentSize bounds the recent-result ring shown in the admin surface (default
	// 100).
	RecentSize int `yaml:"recentSize"`
	// RepoCacheDir is the clone cache root for the source-repository locator. When
	// empty it defaults to <cache.dir>/rebuildverify. The locator reuses the same
	// air-gap-aware mirror mechanism as the repo-health subsystem.
	RepoCacheDir string `yaml:"repoCacheDir"`
	// GitBinary overrides the git executable used by the locator (default "git").
	GitBinary string `yaml:"gitBinary"`
	// AllowFetch lets the locator clone/fetch source repositories on demand; false
	// (default) is strict air-gapped (serve only pre-mirrored clones).
	AllowFetch bool `yaml:"allowFetch"`
	// CloneDepth bounds the locator's clone depth (0 => default, negative => full).
	CloneDepth int `yaml:"cloneDepth"`
	// FetchTimeout bounds an on-demand clone/fetch (default 60s).
	FetchTimeout time.Duration `yaml:"fetchTimeout"`
	// Tenants holds per-tenant mode overrides keyed by tenant id (team).
	Tenants map[string]RebuildVerifyTenantConfig `yaml:"tenants"`
}

// RebuildVerifyTenantConfig overrides the enforcement mode for a single tenant.
type RebuildVerifyTenantConfig struct {
	// Mode overrides the global mode (observe|enforce) for this tenant.
	Mode string `yaml:"mode"`
}

// validateRebuildVerify checks the reproducible-build verification configuration:
// a valid (global and per-tenant) mode and non-negative bounds.
func (c *Config) validateRebuildVerify() error {
	b := c.RebuildVerify
	if !b.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(b.Mode)) {
	case "", "observe", "enforce":
	default:
		return fmt.Errorf("config: rebuildVerify.mode must be observe|enforce, got %q", b.Mode)
	}
	for tenant, t := range b.Tenants {
		switch strings.ToLower(strings.TrimSpace(t.Mode)) {
		case "", "observe", "enforce":
		default:
			return fmt.Errorf("config: rebuildVerify.tenants[%q].mode must be observe|enforce, got %q", tenant, t.Mode)
		}
	}
	if b.MaxConcurrent < 0 {
		return fmt.Errorf("config: rebuildVerify.maxConcurrent must not be negative, got %d", b.MaxConcurrent)
	}
	if b.CacheSize < 0 {
		return fmt.Errorf("config: rebuildVerify.cacheSize must not be negative, got %d", b.CacheSize)
	}
	if b.RecentSize < 0 {
		return fmt.Errorf("config: rebuildVerify.recentSize must not be negative, got %d", b.RecentSize)
	}
	if b.BuildTimeout < 0 {
		return fmt.Errorf("config: rebuildVerify.buildTimeout must not be negative, got %s", b.BuildTimeout)
	}
	if b.FetchTimeout < 0 {
		return fmt.Errorf("config: rebuildVerify.fetchTimeout must not be negative, got %s", b.FetchTimeout)
	}
	return nil
}

// BuildProvConfig configures the inbound build-provenance verification gate (Task
// 72). It is on by default but observe-only (mode "observe"): it verifies
// upstream-published build provenance (npm provenance / GitHub artifact
// attestations), binds a package version to its source repo + commit + CI
// workflow, and cross-checks that proven commit against the package-to-commit
// association from the provenance subsystem (Task 8) — surfacing mismatches and
// feeding the policy/risk engines — without blocking a pull until an operator
// raises the mode to "enforce". For air-gapped deployments the trust material
// (Fulcio roots, allowed identities) is loaded from the same portable trust
// bundle the signature gate uses.
type BuildProvConfig struct {
	// Enabled turns on verification, the admission signal, the admin surface, and
	// the Prometheus metrics.
	Enabled bool `yaml:"enabled"`
	// Mode is observe|enforce. observe (default) records findings and feeds the
	// policy/risk engines; enforce additionally quarantines an artifact whose worst
	// finding (notably a confirmed source mismatch) meets the fail threshold
	// (composing with the break-glass workflow).
	Mode string `yaml:"mode"`
	// Action applied in enforce mode when a finding meets failSeverity: warn|block|
	// quarantine (default quarantine, so a refused artifact is evicted).
	Action string `yaml:"action"`
	// FailSeverity is the minimum finding severity that triggers Action in enforce
	// mode (default high). A source mismatch is critical and always meets it.
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity surfaced as a warning (default medium).
	WarnSeverity string `yaml:"warnSeverity"`
	// RequireProvenance treats the absence of any inbound provenance attestation as
	// a finding. Off by default (most packages publish none).
	RequireProvenance bool `yaml:"requireProvenance"`
	// RequireTrustedSource treats a digest-bound, cryptographically-valid
	// attestation whose signer is not trusted as a finding. Off by default;
	// meaningful only when trust material is configured.
	RequireTrustedSource bool `yaml:"requireTrustedSource"`
	// FailOnError blocks (in enforce mode) when provenance material cannot be
	// fetched/parsed (fail-closed); false serves with a warning (fail-open, default).
	FailOnError bool `yaml:"failOnError"`
	// NPMRegistryURL is the registry root the npm provenance source queries
	// (default "https://registry.npmjs.org").
	NPMRegistryURL string `yaml:"npmRegistryUrl"`
	// GitHubAPIURL is the GitHub API base for the artifact-attestation source
	// (default "https://api.github.com"); GitHubToken authenticates it when set.
	GitHubAPIURL string `yaml:"githubApiUrl"`
	GitHubToken  string `yaml:"githubToken"`
	// EnableGitHubSource enables the GitHub artifact-attestation source (in addition
	// to npm provenance). Off by default (npm provenance is the primary inbound
	// source; the GitHub source needs network access to the GitHub API).
	EnableGitHubSource bool `yaml:"enableGithubSource"`
	// GitLabAPIURL/GitLabHost/GitLabToken configure the GitLab CI/CD provenance
	// source (defaults "https://gitlab.com" / "gitlab.com"); set all three for a
	// self-hosted instance. EnableGitLabSource turns it on (off by default).
	GitLabAPIURL       string `yaml:"gitlabApiUrl"`
	GitLabHost         string `yaml:"gitlabHost"`
	GitLabToken        string `yaml:"gitlabToken"`
	EnableGitLabSource bool   `yaml:"enableGitlabSource"`
	// BitbucketAPIURL/BitbucketHost/BitbucketToken configure the Bitbucket
	// Pipelines provenance source (defaults "https://api.bitbucket.org" /
	// "bitbucket.org"). EnableBitbucketSource turns it on (off by default).
	BitbucketAPIURL       string `yaml:"bitbucketApiUrl"`
	BitbucketHost         string `yaml:"bitbucketHost"`
	BitbucketToken        string `yaml:"bitbucketToken"`
	EnableBitbucketSource bool   `yaml:"enableBitbucketSource"`
	// Forges holds per-forge trust material (Fulcio/CA roots + allowed OIDC-issuer
	// identities) so GitLab and Bitbucket provenance is verified under their own
	// trust roots and issuers, independently of the shared npm/GitHub material.
	Forges []BuildProvForgeConfig `yaml:"forges"`
	// Timeout bounds an outbound attestation fetch (default 15s).
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL bounds how long a verification result is reused (0 = never expire);
	// CacheSize bounds the result cache (0 => 1024).
	CacheTTL  time.Duration `yaml:"cacheTtl"`
	CacheSize int           `yaml:"cacheSize"`
	// TrustBundlePath / TrustBundleDigest load the offline trust material (Fulcio
	// roots, Rekor keys, named keys, allowed identities) for air-gapped deployments.
	// The digest, when set, is verified on load.
	TrustBundlePath   string `yaml:"trustBundlePath"`
	TrustBundleDigest string `yaml:"trustBundleDigest"`
	// Offline marks the deployment air-gapped (informational for reporting).
	Offline bool `yaml:"offline"`
	// Identities is the allowed keyless-signer policy (OIDC issuer + subject regex)
	// used to establish SourceVerified, mirroring the signature gate's config.
	Identities []SigverifyIdentity `yaml:"identities"`
	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]BuildProvTenantConfig `yaml:"tenants"`
}

// BuildProvForgeConfig declares the trust material for a single source-control /
// CI forge (github|gitlab|bitbucket, or a self-hosted id). It mirrors the
// signature gate's trust-material model so operators configure per-forge Fulcio
// roots and allowed OIDC issuers the same way everywhere. The gate verifies an
// attestation discovered from a forge against this material rather than the
// shared default, so (for example) a self-hosted GitLab running its own Sigstore
// is trusted under its own root without widening trust for other forges.
type BuildProvForgeConfig struct {
	// Name is the forge id this trust applies to (github|gitlab|bitbucket or a
	// self-hosted id); it must match the forge the attestation was discovered from.
	Name string `yaml:"name"`
	// TrustRootsFile is a PEM bundle of the forge's Fulcio/CA roots. When unset and
	// UseSystemTrustRoots is false the forge's attestations cannot be source-verified.
	TrustRootsFile string `yaml:"trustRootsFile"`
	// UseSystemTrustRoots uses the host system root pool for this forge.
	UseSystemTrustRoots bool `yaml:"useSystemTrustRoots"`
	// TrustBundlePath/TrustBundleDigest load the forge's trust material from a
	// portable offline trust bundle (air-gapped), taking precedence over
	// TrustRootsFile/RekorKeyFiles/Identities when set.
	TrustBundlePath   string `yaml:"trustBundlePath"`
	TrustBundleDigest string `yaml:"trustBundleDigest"`
	// RekorKeyFiles are PEM Rekor public keys for the forge's transparency log.
	RekorKeyFiles []string `yaml:"rekorKeyFiles"`
	// Identities is the forge's allowed keyless-signer policy (its OIDC issuer +
	// subject regex), e.g. issuer "https://gitlab.com" for GitLab CI/CD.
	Identities []SigverifyIdentity `yaml:"identities"`
}

// BuildProvTenantConfig overrides the mode (and provenance requirement) for a
// single tenant.
type BuildProvTenantConfig struct {
	// Mode overrides the global mode (observe|enforce) for this tenant.
	Mode string `yaml:"mode"`
	// RequireProvenance, when set, overrides the global requirement for this tenant.
	RequireProvenance *bool `yaml:"requireProvenance"`
}

// validateBuildProv checks the inbound build-provenance configuration: valid
// (global and per-tenant) mode, action, and severities, and non-negative bounds.
func (c *Config) validateBuildProv() error {
	b := c.BuildProv
	if !b.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(b.Mode)) {
	case "", "observe", "enforce":
	default:
		return fmt.Errorf("config: buildProv.mode must be observe|enforce, got %q", b.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(b.Action)) {
	case "", "warn", "block", "quarantine":
	default:
		return fmt.Errorf("config: buildProv.action must be warn|block|quarantine, got %q", b.Action)
	}
	if !buildprovValidSeverity(b.FailSeverity) {
		return fmt.Errorf("config: buildProv.failSeverity must be none|low|medium|high|critical, got %q", b.FailSeverity)
	}
	if !buildprovValidSeverity(b.WarnSeverity) {
		return fmt.Errorf("config: buildProv.warnSeverity must be none|low|medium|high|critical, got %q", b.WarnSeverity)
	}
	for tenant, t := range b.Tenants {
		switch strings.ToLower(strings.TrimSpace(t.Mode)) {
		case "", "observe", "enforce":
		default:
			return fmt.Errorf("config: buildProv.tenants[%q].mode must be observe|enforce, got %q", tenant, t.Mode)
		}
	}
	if b.CacheSize < 0 {
		return fmt.Errorf("config: buildProv.cacheSize must not be negative, got %d", b.CacheSize)
	}
	if b.Timeout < 0 {
		return fmt.Errorf("config: buildProv.timeout must not be negative, got %s", b.Timeout)
	}
	for i, id := range b.Identities {
		if strings.TrimSpace(id.SubjectPattern) == "" && strings.TrimSpace(id.Issuer) == "" {
			return fmt.Errorf("config: buildProv.identities[%d] must set issuer or subjectPattern", i)
		}
	}
	seenForge := make(map[string]bool, len(b.Forges))
	for i, f := range b.Forges {
		name := strings.ToLower(strings.TrimSpace(f.Name))
		if name == "" {
			return fmt.Errorf("config: buildProv.forges[%d] must set name (github|gitlab|bitbucket or a self-hosted id)", i)
		}
		if seenForge[name] {
			return fmt.Errorf("config: buildProv.forges has duplicate entry %q", name)
		}
		seenForge[name] = true
		for j, id := range f.Identities {
			if strings.TrimSpace(id.SubjectPattern) == "" && strings.TrimSpace(id.Issuer) == "" {
				return fmt.Errorf("config: buildProv.forges[%d].identities[%d] must set issuer or subjectPattern", i, j)
			}
		}
	}
	return nil
}

func buildprovValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// PyPIAttestConfig configures the inbound PyPI PEP 740 digital-attestation
// verification gate (Task 146). For a served pip/PyPI wheel/sdist it fetches the
// distribution's PEP 740 provenance (the Integrity API / JSON-index "provenance"
// field), cryptographically verifies the enclosed Sigstore attestations against
// the Fulcio/Rekor trust root, and binds the attested sha256 digest to the served
// artifact. It complements the signature gate (sigverify) and the npm/GitHub
// build-provenance gate (buildProv) with the verification model PyPI publishes.
// On by default but annotate-only (never blocks) until an operator raises the
// action.
type PyPIAttestConfig struct {
	// Enabled turns on verification, the admission signal, and the Prometheus
	// metrics.
	Enabled bool `yaml:"enabled"`
	// Action is taken when a finding meets failSeverity: annotate|downgrade|block.
	//   - annotate (default): never block; record findings, attach headers, feed the
	//     policy/risk engines.
	//   - downgrade: serve, but mark the pull as a warning (headers + audit + notify).
	//   - block: refuse the pull (403) and evict the artifact (composing with the
	//     break-glass workflow).
	Action string `yaml:"action"`
	// FailSeverity is the minimum finding severity that triggers Action (default
	// high). A digest mismatch is critical and always meets it.
	FailSeverity string `yaml:"failSeverity"`
	// WarnSeverity is the minimum severity surfaced as a downgrade when the action
	// would otherwise allow (default medium).
	WarnSeverity string `yaml:"warnSeverity"`
	// RequireAttestation treats the absence of any PEP 740 attestation as a finding.
	// Off by default (most PyPI releases publish none yet).
	RequireAttestation bool `yaml:"requireAttestation"`
	// RequireTrustedPublisher treats a digest-bound, cryptographically-valid
	// attestation whose Trusted Publisher is not trusted as a finding. Off by
	// default; meaningful only when trust material is configured.
	RequireTrustedPublisher bool `yaml:"requireTrustedPublisher"`
	// RequireInclusionProof treats a verified attestation lacking a verifiable Rekor
	// transparency-log inclusion proof / SET as a finding. Off by default;
	// meaningful only when rekorKeyFiles are configured.
	RequireInclusionProof bool `yaml:"requireInclusionProof"`
	// FailOnError applies Action (fail-closed) when attestation material cannot be
	// fetched/parsed; false serves without the gate (fail-open, default).
	FailOnError bool `yaml:"failOnError"`
	// IndexURL is the PyPI JSON Simple-index root used to resolve a distribution's
	// filename and provenance presence (default "https://pypi.org").
	IndexURL string `yaml:"indexUrl"`
	// IntegrityURL is the PyPI Integrity-API root the provenance object is fetched
	// from (defaults to IndexURL). The provenance URL is constructed from the
	// resolved filename, never followed from the index verbatim, so a malicious
	// upstream cannot redirect the proxy's egress.
	IntegrityURL string `yaml:"integrityUrl"`
	// Timeout bounds an outbound provenance fetch (default 15s).
	Timeout time.Duration `yaml:"timeout"`
	// CacheTTL bounds how long a verification result is reused (0 = never expire);
	// CacheSize bounds the result cache (0 => 1024).
	CacheTTL  time.Duration `yaml:"cacheTtl"`
	CacheSize int           `yaml:"cacheSize"`
	// TrustBundlePath / TrustBundleDigest load the offline trust material (Fulcio
	// roots, Rekor keys, named keys, allowed identities) for air-gapped deployments.
	// The digest, when set, is verified on load.
	TrustBundlePath   string `yaml:"trustBundlePath"`
	TrustBundleDigest string `yaml:"trustBundleDigest"`
	// TrustRootsFile is a PEM bundle of the Fulcio/CA roots the signing certificate
	// must chain to (alternative to a trust bundle). RekorKeyFiles are PEM Rekor
	// public keys for transparency-log verification.
	TrustRootsFile string   `yaml:"trustRootsFile"`
	RekorKeyFiles  []string `yaml:"rekorKeyFiles"`
	// Offline marks the deployment air-gapped (informational for reporting).
	Offline bool `yaml:"offline"`
	// Identities is the allowed Trusted-Publisher policy (OIDC issuer + subject
	// regex) used to establish PublisherTrusted, mirroring the signature gate.
	Identities []SigverifyIdentity `yaml:"identities"`
	// Tenants holds per-tenant action overrides keyed by tenant id (team).
	Tenants map[string]PyPIAttestTenantConfig `yaml:"tenants"`
}

// PyPIAttestTenantConfig overrides the action for a single tenant.
type PyPIAttestTenantConfig struct {
	// Action overrides the global action (annotate|downgrade|block) for this tenant.
	Action string `yaml:"action"`
}

// validatePyPIAttest checks the inbound PyPI-attestation configuration: valid
// (global and per-tenant) action and severities, and non-negative bounds.
func (c *Config) validatePyPIAttest() error {
	p := c.PyPIAttest
	if !p.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(p.Action)) {
	case "", "annotate", "downgrade", "block":
	default:
		return fmt.Errorf("config: pypiAttestation.action must be annotate|downgrade|block, got %q", p.Action)
	}
	if !buildprovValidSeverity(p.FailSeverity) {
		return fmt.Errorf("config: pypiAttestation.failSeverity must be none|low|medium|high|critical, got %q", p.FailSeverity)
	}
	if !buildprovValidSeverity(p.WarnSeverity) {
		return fmt.Errorf("config: pypiAttestation.warnSeverity must be none|low|medium|high|critical, got %q", p.WarnSeverity)
	}
	for tenant, t := range p.Tenants {
		switch strings.ToLower(strings.TrimSpace(t.Action)) {
		case "", "annotate", "downgrade", "block":
		default:
			return fmt.Errorf("config: pypiAttestation.tenants[%q].action must be annotate|downgrade|block, got %q", tenant, t.Action)
		}
	}
	if p.CacheSize < 0 {
		return fmt.Errorf("config: pypiAttestation.cacheSize must not be negative, got %d", p.CacheSize)
	}
	if p.Timeout < 0 {
		return fmt.Errorf("config: pypiAttestation.timeout must not be negative, got %s", p.Timeout)
	}
	for i, id := range p.Identities {
		if strings.TrimSpace(id.SubjectPattern) == "" && strings.TrimSpace(id.Issuer) == "" {
			return fmt.Errorf("config: pypiAttestation.identities[%d] must set issuer or subjectPattern", i)
		}
	}
	return nil
}

// SnapshotConfig configures the organization-wide dependency snapshot, freeze &
// instant-rollback subsystem (Task 70). It is off by default: the subsystem
// captures and gates only what an operator turns on. When enabled it records the
// served dependency state, exposes the admin "Snapshots" surface (create/diff/
// freeze/rollback), and — when freezeEnforce is set and a freeze is active —
// gates pulls against the frozen set.
type SnapshotConfig struct {
	// Enabled turns on capture, the admin surface, the scheduler, and the metrics.
	Enabled bool `yaml:"enabled"`
	// Dir is the directory snapshots, the index, and the freeze state are persisted
	// under. When empty it defaults to <cache.dir>/snapshots. An empty cache dir
	// keeps everything in memory (lost on restart).
	Dir string `yaml:"dir"`
	// MaxLiveEntries bounds the in-memory live-state map (distinct coordinates);
	// 0 uses the default (50000).
	MaxLiveEntries int `yaml:"maxLiveEntries"`
	// MaxSnapshots bounds the retained snapshot manifests; 0 uses the default (200).
	MaxSnapshots int `yaml:"maxSnapshots"`
	// ScheduleInterval, when > 0, takes an automatic snapshot on this cadence
	// (coord-guarded for HA). 0 disables scheduled snapshots.
	ScheduleInterval time.Duration `yaml:"scheduleInterval"`
	// FreezeEnforce lets the freeze gate actually block/quarantine pulls outside an
	// active frozen set. When false (default) the gate is observe-only: it records
	// what it would have blocked but serves the pull — a safety valve for staging a
	// freeze before enforcing it.
	FreezeEnforce bool `yaml:"freezeEnforce"`
}

// validateSnapshot checks the snapshot subsystem configuration: non-negative
// bounds and interval.
func (c *Config) validateSnapshot() error {
	s := c.Snapshot
	if !s.Enabled {
		return nil
	}
	if s.MaxLiveEntries < 0 {
		return fmt.Errorf("config: snapshot.maxLiveEntries must not be negative, got %d", s.MaxLiveEntries)
	}
	if s.MaxSnapshots < 0 {
		return fmt.Errorf("config: snapshot.maxSnapshots must not be negative, got %d", s.MaxSnapshots)
	}
	if s.ScheduleInterval < 0 {
		return fmt.Errorf("config: snapshot.scheduleInterval must not be negative, got %s", s.ScheduleInterval)
	}
	return nil
}

// LockdownConfig configures the emergency-lockdown / global kill-switch incident-
// response control (Task 74). It is off by default: the subsystem only exposes the
// FIRST-check gate and admin surface once an operator turns it on. The kill-switch
// itself is engaged at runtime (admin API / ptctl), never from config — config only
// sets the durable state file and the TTL bounds.
type LockdownConfig struct {
	// Enabled turns on the FIRST-check pull-path gate, the admin/ptctl surface, and
	// the metrics. The active lockdown posture is set at runtime, not here.
	Enabled bool `yaml:"enabled"`
	// StorePath is the JSON file the active lockdown state is persisted to so a
	// lockdown survives a restart and (on shared storage) is read by every replica.
	// Empty defaults to <cache.dir>/lockdown.json; with no cache dir it stays in
	// memory (lost on restart).
	StorePath string `yaml:"storePath"`
	// DefaultTTL is applied when an engagement omits a TTL. A lockdown ALWAYS carries
	// a TTL with auto-expiry so a forgotten incident self-heals. 0 uses 1h.
	DefaultTTL time.Duration `yaml:"defaultTtl"`
	// MaxTTL caps an operator-supplied TTL. 0 means no cap.
	MaxTTL time.Duration `yaml:"maxTtl"`
}

// validateLockdown checks the emergency-lockdown configuration: non-negative TTLs
// and an ordered default/max.
func (c *Config) validateLockdown() error {
	l := c.Lockdown
	if !l.Enabled {
		return nil
	}
	if l.DefaultTTL < 0 {
		return fmt.Errorf("config: lockdown.defaultTtl must not be negative, got %s", l.DefaultTTL)
	}
	if l.MaxTTL < 0 {
		return fmt.Errorf("config: lockdown.maxTtl must not be negative, got %s", l.MaxTTL)
	}
	if l.MaxTTL > 0 && l.DefaultTTL > 0 && l.DefaultTTL > l.MaxTTL {
		return fmt.Errorf("config: lockdown.defaultTtl (%s) must not exceed lockdown.maxTtl (%s)", l.DefaultTTL, l.MaxTTL)
	}
	return nil
}

// AdmissionWebhookConfig configures the Kubernetes ValidatingAdmissionWebhook
// in-cluster enforcement server (Task 111). It is off by default. When enabled,
// an HTTPS listener serves AdmissionReview requests for Pod creates/updates,
// resolves the proxy's per-coordinate security verdict (dossier/riskscore) for
// each container image, and admits or denies the Pod accordingly.
type AdmissionWebhookConfig struct {
	// Enabled turns on the webhook listener, its handler, and the metrics.
	Enabled bool `yaml:"enabled"`
	// Addr is the HTTPS listen address. Empty defaults to ":8443".
	Addr string `yaml:"addr"`
	// Path is the URL path the ValidatingWebhookConfiguration targets. Empty
	// defaults to "/validate".
	Path string `yaml:"path"`
	// HealthPath / ReadyPath serve liveness/readiness probes. Empty defaults to
	// "/healthz" / "/readyz".
	HealthPath string `yaml:"healthPath"`
	ReadyPath  string `yaml:"readyPath"`
	// TLSCertFile / TLSKeyFile is the serving certificate the API server connects
	// to (its issuing CA must be wired as the ValidatingWebhookConfiguration's
	// caBundle). Required when Enabled.
	TLSCertFile string `yaml:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile"`
	// ClientCAFile, when set, requires and verifies the API server's client
	// certificate (mutual TLS). Optional.
	ClientCAFile string `yaml:"clientCaFile"`
	// FailurePolicy governs behavior when a verdict cannot be computed for an
	// image: "open" admits, "closed" denies. Empty defaults to "open". Set this
	// consistently with the ValidatingWebhookConfiguration's own failurePolicy.
	FailurePolicy string `yaml:"failurePolicy"`
	// BlockAction / WarnAction / UnknownAction map a dossier verdict
	// (block|warn|admit|unknown) to an admission outcome (admit|deny|warn). Empty
	// defaults: block->deny, warn->admit, unknown->admit.
	BlockAction   string `yaml:"blockAction"`
	WarnAction    string `yaml:"warnAction"`
	UnknownAction string `yaml:"unknownAction"`
	// MinRiskScoreToDeny denies any image whose dossier risk score is at or above
	// it, independent of the headline verdict. 0 disables the ceiling.
	MinRiskScoreToDeny int `yaml:"minRiskScoreToDeny"`
	// EnforceLockdown wires the emergency-lockdown kill-switch (Task 74): a
	// targeted block denies matching images, and while any lockdown is engaged an
	// "unknown" image is denied regardless of UnknownAction. Default true.
	EnforceLockdown *bool `yaml:"enforceLockdown"`
	// DefaultEcosystem labels image coordinates for the dossier lookup. Empty
	// defaults to "docker".
	DefaultEcosystem string `yaml:"defaultEcosystem"`
	// Tenant scopes the tenant-bearing dossier sources. Empty aggregates across
	// tenants (the usual cluster-wide posture).
	Tenant string `yaml:"tenant"`
	// StripRegistryHost drops a leading registry host from the image repository
	// when building the lookup coordinate. Default true.
	StripRegistryHost *bool `yaml:"stripRegistryHost"`
	// IgnoreNamespaces are admitted without inspection (kube-system, etc.).
	IgnoreNamespaces []string `yaml:"ignoreNamespaces"`
	// IgnoreImages are image-reference prefixes always admitted (cluster
	// infrastructure images the proxy never fronts).
	IgnoreImages []string `yaml:"ignoreImages"`
	// AnnotateWarnings attaches a per-image advisory to the AdmissionResponse
	// warnings for a warn verdict. Default true.
	AnnotateWarnings *bool `yaml:"annotateWarnings"`
	// Timeout bounds the per-image verdict lookup. 0 uses 5s.
	Timeout time.Duration `yaml:"timeout"`
	// Dossier, when its url is set, resolves verdicts over HTTP from a remote
	// proxy's admin dossier endpoint instead of in-process (for a split
	// deployment where the webhook runs separately from the proxy).
	Dossier AdmissionDossierSourceConfig `yaml:"dossier"`
}

// AdmissionDossierSourceConfig configures a remote HTTP verdict source for the
// admission webhook. When URL is empty the webhook resolves verdicts in-process
// from the shared dossier builder.
type AdmissionDossierSourceConfig struct {
	// URL is the proxy admin API base, e.g.
	// "https://pullthrough.pullthrough.svc/admin".
	URL string `yaml:"url"`
	// Token is the admin bearer / read-capability token.
	Token string `yaml:"token"`
	// CACertFile pins the proxy's serving CA for the TLS connection.
	CACertFile string `yaml:"caCertFile"`
	// InsecureSkipVerify disables TLS verification (test/dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// Timeout bounds a single dossier request. 0 uses 5s.
	Timeout time.Duration `yaml:"timeout"`
}

// validateAdmissionWebhook checks the Kubernetes admission-webhook configuration
// (Task 111): a serving certificate when enabled, a recognized failure policy and
// verdict-action mapping, and a coherent risk ceiling.
func (c *Config) validateAdmissionWebhook() error {
	w := c.AdmissionWebhook
	if !w.Enabled {
		return nil
	}
	// A split deployment (remote dossier URL) still needs a serving cert for the
	// API server to connect to.
	if strings.TrimSpace(w.TLSCertFile) == "" || strings.TrimSpace(w.TLSKeyFile) == "" {
		return fmt.Errorf("config: admissionWebhook.tlsCertFile and admissionWebhook.tlsKeyFile are required when the webhook is enabled")
	}
	switch strings.ToLower(strings.TrimSpace(w.FailurePolicy)) {
	case "", "open", "closed", "ignore", "fail":
	default:
		return fmt.Errorf("config: admissionWebhook.failurePolicy %q is invalid (want open|closed)", w.FailurePolicy)
	}
	for field, v := range map[string]string{
		"blockAction":   w.BlockAction,
		"warnAction":    w.WarnAction,
		"unknownAction": w.UnknownAction,
	} {
		if strings.TrimSpace(v) == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "admit", "deny", "warn":
		default:
			return fmt.Errorf("config: admissionWebhook.%s %q is invalid (want admit|deny|warn)", field, v)
		}
	}
	if w.MinRiskScoreToDeny < 0 || w.MinRiskScoreToDeny > 100 {
		return fmt.Errorf("config: admissionWebhook.minRiskScoreToDeny must be within [0,100], got %d", w.MinRiskScoreToDeny)
	}
	if w.Timeout < 0 {
		return fmt.Errorf("config: admissionWebhook.timeout must not be negative, got %s", w.Timeout)
	}
	if w.Dossier.Timeout < 0 {
		return fmt.Errorf("config: admissionWebhook.dossier.timeout must not be negative, got %s", w.Dossier.Timeout)
	}
	return nil
}

// GitopsConfig configures the GitOps policy & config synchronization subsystem
// (Task 93). It is off by default: an operator opts in by pointing it at a source
// of truth. When enabled, the reconciler fetches the desired-state bundle on the
// configured interval (coord-guarded so only the HA leader reconciles), verifies
// it, validates and previews it, and either applies it (mode "apply") or surfaces
// it for dual-control approval (mode "suggest").
type GitopsConfig struct {
	// Enabled turns on reconciliation, the scheduler, the admin/ptctl surface, and
	// the metrics.
	Enabled bool `yaml:"enabled"`
	// Mode is "apply" (auto-reconcile) or "suggest" (dual-control via approvals).
	// Empty defaults to "suggest" — the safe default that never changes live config
	// without a human in the loop.
	Mode string `yaml:"mode"`
	// Interval is the reconcile cadence. 0 uses 5m.
	Interval time.Duration `yaml:"interval"`
	// StorePath is the JSON file the durable reconciliation state (last revision,
	// apply history, pending change) is persisted to. Empty defaults to
	// <cache.dir>/gitops.json; with no cache dir it stays in memory.
	StorePath string `yaml:"storePath"`
	// FailClosed refuses to apply when verification is configured but the bundle
	// does not verify. When false the failure is recorded but the change still
	// reconciles (observe-the-signature mode).
	FailClosed bool `yaml:"failClosed"`
	// Source selects and configures the source of truth.
	Source GitopsSourceConfig `yaml:"source"`
	// Verify configures bundle integrity/authenticity checking.
	Verify GitopsVerifyConfig `yaml:"verify"`
}

// GitopsSourceConfig selects the desired-state source: "local" (a pre-fetched
// bundle on disk, the air-gap path) or "git" (a remote repository the proxy
// fetches via the host git binary).
type GitopsSourceConfig struct {
	// Type is "local" or "git".
	Type string `yaml:"type"`
	// Path is the bundle file (local) or — for git — the bundle path within the
	// repository.
	Path string `yaml:"path"`
	// Git holds the remote-repository settings (used when Type is "git").
	Git GitopsGitConfig `yaml:"git"`
}

// GitopsGitConfig configures a remote-Git source of truth.
type GitopsGitConfig struct {
	// URL is the repository to clone (https or ssh).
	URL string `yaml:"url"`
	// Ref is the branch/tag/commit to read (defaults to the remote HEAD).
	Ref string `yaml:"ref"`
	// WorkDir is the local directory the repo is cloned into and kept in sync.
	// Empty defaults to <cache.dir>/gitops-repo.
	WorkDir string `yaml:"workDir"`
}

// GitopsVerifyConfig configures bundle verification: an optional pinned content
// digest (air-gap friendly) and an optional trusted public key against which a
// detached signature is checked (reusing the audit/attestbundle key conventions).
type GitopsVerifyConfig struct {
	// PublicKey is an inline PEM-encoded trusted public key.
	PublicKey string `yaml:"publicKey"`
	// PublicKeyFile is a path to a PEM-encoded trusted public key.
	PublicKeyFile string `yaml:"publicKeyFile"`
	// ExpectedDigest pins the SHA-256 of the desired-state bundle document (hex,
	// optionally "sha256:"-prefixed).
	ExpectedDigest string `yaml:"expectedDigest"`
}

// validateGitops checks the GitOps subsystem configuration: a valid mode, a
// non-negative interval, and a coherent source selection.
func (c *Config) validateGitops() error {
	g := c.Gitops
	if !g.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(g.Mode)) {
	case "", "apply", "suggest":
	default:
		return fmt.Errorf("config: gitops.mode must be apply or suggest, got %q", g.Mode)
	}
	if g.Interval < 0 {
		return fmt.Errorf("config: gitops.interval must not be negative, got %s", g.Interval)
	}
	switch strings.ToLower(strings.TrimSpace(g.Source.Type)) {
	case "", "local":
		if strings.TrimSpace(g.Source.Path) == "" {
			return fmt.Errorf("config: gitops.source.path is required for a local source")
		}
	case "git":
		if strings.TrimSpace(g.Source.Git.URL) == "" {
			return fmt.Errorf("config: gitops.source.git.url is required for a git source")
		}
		if strings.TrimSpace(g.Source.Path) == "" {
			return fmt.Errorf("config: gitops.source.path (the bundle path within the repo) is required for a git source")
		}
	default:
		return fmt.Errorf("config: gitops.source.type must be local or git, got %q", g.Source.Type)
	}
	if g.Verify.PublicKey != "" && g.Verify.PublicKeyFile != "" {
		return fmt.Errorf("config: set only one of gitops.verify.publicKey or gitops.verify.publicKeyFile")
	}
	return nil
}

// validateSbomDiff checks the SBOM-diff subsystem configuration: a valid action,
// non-negative sizes/weights, and ordered thresholds (warn <= significant <=
// block).
func (c *Config) validateSbomDiff() error {
	d := c.SbomDiff
	if !d.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(d.Action)) {
	case "", "warn", "block", "quarantine":
	default:
		return fmt.Errorf("config: sbomDiff.action must be warn|block|quarantine, got %q", d.Action)
	}
	if d.HistorySize < 0 {
		return fmt.Errorf("config: sbomDiff.historySize must not be negative, got %d", d.HistorySize)
	}
	if d.MaxCoordinates < 0 {
		return fmt.Errorf("config: sbomDiff.maxCoordinates must not be negative, got %d", d.MaxCoordinates)
	}
	for name, v := range map[string]float64{
		"warnThreshold":        d.WarnThreshold,
		"blockThreshold":       d.BlockThreshold,
		"significantThreshold": d.SignificantThreshold,
	} {
		if v < 0 || v > 100 {
			return fmt.Errorf("config: sbomDiff.%s must be within [0,100], got %v", name, v)
		}
	}
	if d.WarnThreshold > 0 && d.BlockThreshold > 0 && d.WarnThreshold > d.BlockThreshold {
		return fmt.Errorf("config: sbomDiff.warnThreshold %v must not exceed blockThreshold %v", d.WarnThreshold, d.BlockThreshold)
	}
	return nil
}

// validateRemediation checks the remediation-advisor configuration: a
// non-negative candidate bound and well-formed registry base-URL overrides.
func (c *Config) validateRemediation() error {
	d := c.Remediation
	if !d.Enabled {
		return nil
	}
	if d.MaxCandidates < 0 {
		return fmt.Errorf("config: remediation.maxCandidates must not be negative, got %d", d.MaxCandidates)
	}
	for eco, u := range d.BaseURLs {
		if strings.TrimSpace(u) == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("config: remediation.baseURLs[%q] must be an http(s) URL, got %q", eco, u)
		}
	}
	return nil
}

// validateMalfeed checks the known-malicious-package gate configuration: valid
// feed source URLs, non-negative durations, and an existing bundle/key file when
// configured.
func (c *Config) validateMalfeed() error {
	m := c.Malfeed
	if !m.Enabled {
		return nil
	}
	for i, src := range m.Sources {
		if strings.TrimSpace(src.URL) == "" {
			return fmt.Errorf("config: malfeed.sources[%d].url is required", i)
		}
		u, err := url.Parse(src.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: malfeed.sources[%d].url %q must be a valid http(s) URL", i, src.URL)
		}
	}
	if m.RefreshInterval < 0 {
		return fmt.Errorf("config: malfeed.refreshInterval must not be negative, got %s", m.RefreshInterval)
	}
	if m.StaleAfter < 0 {
		return fmt.Errorf("config: malfeed.staleAfter must not be negative, got %s", m.StaleAfter)
	}
	if m.Timeout < 0 {
		return fmt.Errorf("config: malfeed.timeout must not be negative, got %s", m.Timeout)
	}
	if m.BundlePath != "" {
		if _, err := os.Stat(m.BundlePath); err != nil {
			return fmt.Errorf("config: malfeed.bundlePath %q is not readable: %w", m.BundlePath, err)
		}
	}
	if m.BundlePublicKeyFile != "" {
		if _, err := os.Stat(m.BundlePublicKeyFile); err != nil {
			return fmt.Errorf("config: malfeed.bundlePublicKeyFile %q is not readable: %w", m.BundlePublicKeyFile, err)
		}
	}
	return nil
}

// validateS3Cache checks the S3 object-storage cache backend configuration:
// bucket, credentials, retry bound, and a parseable endpoint.
func (c *Config) validateS3Cache() error {
	return validateS3CacheConfig("cache.s3", c.Cache.S3)
}

// validateS3CacheConfig checks one S3 object-storage backend configuration under
// the given config path prefix (so it is reusable for both the primary s3
// backend and the tiered cache's cold tier).
func validateS3CacheConfig(prefix string, s S3CacheConfig) error {
	if strings.TrimSpace(s.Bucket) == "" {
		return fmt.Errorf("config: %s.bucket is required for the s3 backend", prefix)
	}
	if strings.TrimSpace(s.AccessKeyID) == "" || strings.TrimSpace(s.SecretAccessKey) == "" {
		return fmt.Errorf("config: %s requires accessKeyId and secretAccessKey", prefix)
	}
	if s.MaxRetries < 0 {
		return fmt.Errorf("config: %s.maxRetries must not be negative, got %d", prefix, s.MaxRetries)
	}
	if ep := strings.TrimSpace(s.Endpoint); ep != "" {
		probe := ep
		if !strings.Contains(probe, "://") {
			probe = "https://" + probe
		}
		if _, err := url.Parse(probe); err != nil {
			return fmt.Errorf("config: %s.endpoint %q is not a valid URL: %w", prefix, s.Endpoint, err)
		}
	}
	return nil
}

// validateTiering checks the hot/cold tiered storage layer (Task 154).
func (c *Config) validateTiering() error {
	tc := c.Cache.Tiering
	if !tc.Enabled {
		return nil
	}
	if c.Cache.Backend == "memory" {
		return fmt.Errorf("config: cache.tiering is not supported with the in-memory backend (no durable store to tier)")
	}
	switch strings.ToLower(strings.TrimSpace(tc.Cold.Backend)) {
	case "filesystem":
		if strings.TrimSpace(tc.Cold.Dir) == "" {
			return fmt.Errorf("config: cache.tiering.cold.dir is required for the filesystem cold tier")
		}
		// A filesystem cold tier sharing the hot tier's directory would alias the
		// two tiers and corrupt the one-tier-per-artifact invariant.
		if c.Cache.Backend == "filesystem" && strings.TrimSpace(tc.Cold.Dir) == strings.TrimSpace(c.Cache.Dir) {
			return fmt.Errorf("config: cache.tiering.cold.dir must differ from cache.dir (the hot tier)")
		}
	case "s3":
		if err := validateS3CacheConfig("cache.tiering.cold.s3", tc.Cold.S3); err != nil {
			return err
		}
	case "":
		return fmt.Errorf("config: cache.tiering.cold.backend is required when tiering is enabled (filesystem or s3)")
	default:
		return fmt.Errorf("config: unknown cache.tiering.cold.backend %q (use filesystem or s3)", tc.Cold.Backend)
	}
	if tc.DemoteAfterIdle < 0 {
		return fmt.Errorf("config: cache.tiering.demoteAfterIdle must not be negative, got %s", tc.DemoteAfterIdle)
	}
	if tc.HotMaxBytes < 0 {
		return fmt.Errorf("config: cache.tiering.hotMaxBytes must not be negative, got %d", tc.HotMaxBytes)
	}
	if tc.MinAccessesToStayHot < 0 {
		return fmt.Errorf("config: cache.tiering.minAccessesToStayHot must not be negative, got %d", tc.MinAccessesToStayHot)
	}
	if tc.SweepInterval < 0 {
		return fmt.Errorf("config: cache.tiering.sweepInterval must not be negative, got %s", tc.SweepInterval)
	}
	if tc.DemoteAfterIdle == 0 && tc.HotMaxBytes == 0 {
		return fmt.Errorf("config: cache.tiering is enabled but has no demotion trigger (set demoteAfterIdle or hotMaxBytes)")
	}
	return nil
}

// validateCompression checks the transparent storage-efficiency layer (Task 125).
func (c *Config) validateCompression() error {
	cc := c.Cache.Compression
	if !cc.Enabled {
		return nil
	}
	if c.Cache.Backend == "memory" {
		return fmt.Errorf("config: cache.compression is not supported with the in-memory backend (no durable store to compact)")
	}
	switch strings.ToLower(strings.TrimSpace(cc.Codec)) {
	case "", "none", "zstd":
	default:
		return fmt.Errorf("config: cache.compression.codec %q is unsupported (use zstd or none)", cc.Codec)
	}
	if cc.Level < 0 || cc.Level > 19 {
		return fmt.Errorf("config: cache.compression.level must be within [1,19] (0 = default), got %d", cc.Level)
	}
	if cc.MinSizeBytes < 0 {
		return fmt.Errorf("config: cache.compression.minSizeBytes must not be negative, got %d", cc.MinSizeBytes)
	}
	codecOff := strings.EqualFold(strings.TrimSpace(cc.Codec), "none") || strings.TrimSpace(cc.Codec) == ""
	if codecOff && !cc.Dedup {
		return fmt.Errorf("config: cache.compression is enabled but does nothing (codec is none and dedup is off)")
	}
	if cc.Dedup && c.Cache.Backend != "filesystem" {
		return fmt.Errorf("config: cache.compression.dedup is only supported on the filesystem backend (the s3 backend's shared-bucket model has no safe cross-writer reference count)")
	}
	return nil
}

// validateEncryption checks the at-rest encryption envelope (Task 141). KEK
// material is resolved later (via secretRefs) and validated for length at store
// construction; here we check the structural configuration.
func (c *Config) validateEncryption() error {
	ec := c.Cache.Encryption
	if !ec.Enabled {
		return nil
	}
	if c.Cache.Backend == "memory" {
		return fmt.Errorf("config: cache.encryption is not supported with the in-memory backend (no durable store to encrypt)")
	}
	if strings.TrimSpace(ec.KeyID) == "" {
		return fmt.Errorf("config: cache.encryption.keyId is required when encryption is enabled")
	}
	if strings.TrimSpace(ec.KeyRef) == "" {
		return fmt.Errorf("config: cache.encryption.keyRef is required when encryption is enabled")
	}
	if err := validateKeyEncoding("cache.encryption.keyEncoding", ec.KeyEncoding); err != nil {
		return err
	}
	if ec.FrameSizeBytes < 0 {
		return fmt.Errorf("config: cache.encryption.frameSizeBytes must not be negative, got %d", ec.FrameSizeBytes)
	}
	seen := map[string]bool{strings.TrimSpace(ec.KeyID): true}
	for i, pk := range ec.PreviousKeys {
		id := strings.TrimSpace(pk.KeyID)
		if id == "" {
			return fmt.Errorf("config: cache.encryption.previousKeys[%d].keyId is required", i)
		}
		if seen[id] {
			return fmt.Errorf("config: cache.encryption.previousKeys[%d].keyId %q duplicates another configured key id", i, id)
		}
		seen[id] = true
		if strings.TrimSpace(pk.KeyRef) == "" {
			return fmt.Errorf("config: cache.encryption.previousKeys[%d].keyRef is required", i)
		}
		if err := validateKeyEncoding(fmt.Sprintf("cache.encryption.previousKeys[%d].keyEncoding", i), pk.KeyEncoding); err != nil {
			return err
		}
	}
	return nil
}

// validateKeyEncoding checks a KEK key-encoding selector.
func validateKeyEncoding(field, enc string) error {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "base64", "hex", "raw", "passphrase":
		return nil
	default:
		return fmt.Errorf("config: %s %q is invalid (want base64, hex, raw, or passphrase)", field, enc)
	}
}

// validateVulnerabilities checks the vulnerability-scanning configuration: a
// supported scanner backend, a valid action, severity buckets, and the CVSS
// range.
func (c *Config) validateVulnerabilities() error {
	v := c.Vulnerabilities
	if !v.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(v.Scanner)) {
	case "", "osv":
	case "trivy", "grype":
		return fmt.Errorf("config: vulnerabilities.scanner %q is reserved for the pluggable interface but not yet built in (use \"osv\")", v.Scanner)
	default:
		return fmt.Errorf("config: unknown vulnerabilities.scanner %q (want osv)", v.Scanner)
	}
	if !policy.ValidAction(v.Action) {
		return fmt.Errorf("config: vulnerabilities.action %q is invalid (want warn|block|quarantine)", v.Action)
	}
	for field, sev := range map[string]string{
		"failSeverity": v.FailSeverity,
		"warnSeverity": v.WarnSeverity,
	} {
		if !validVulnSeverity(sev) {
			return fmt.Errorf("config: vulnerabilities.%s %q is invalid (want none|low|medium|high|critical)", field, sev)
		}
	}
	if v.FailCVSS < 0 || v.FailCVSS > 10 {
		return fmt.Errorf("config: vulnerabilities.failCvss must be in 0..10, got %g", v.FailCVSS)
	}
	if strings.TrimSpace(v.FailSeverity) == "" && v.FailCVSS == 0 && strings.TrimSpace(v.WarnSeverity) == "" {
		return fmt.Errorf("config: vulnerabilities.enabled requires at least one of failSeverity, failCvss, or warnSeverity")
	}
	if v.RescanInterval < 0 {
		return fmt.Errorf("config: vulnerabilities.rescanInterval must not be negative, got %s", v.RescanInterval)
	}
	if v.RescanWorkers < 0 {
		return fmt.Errorf("config: vulnerabilities.rescanWorkers must not be negative, got %d", v.RescanWorkers)
	}
	if v.VEX.Enabled {
		if strings.TrimSpace(v.VEX.Dir) == "" && strings.TrimSpace(v.VEX.FetchURL) == "" {
			return fmt.Errorf("config: vulnerabilities.vex.enabled requires at least one of vex.dir or vex.fetchUrl")
		}
		if u := strings.TrimSpace(v.VEX.FetchURL); u != "" &&
			!strings.Contains(u, "{name}") && !strings.Contains(u, "{digest}") {
			return fmt.Errorf("config: vulnerabilities.vex.fetchUrl %q must contain a {name} or {digest} placeholder", u)
		}
	}
	if v.Reachability.Enabled {
		switch strings.ToLower(strings.TrimSpace(v.Reachability.UnreachableAction)) {
		case "", "annotate", "downgrade", "suppress":
		default:
			return fmt.Errorf("config: vulnerabilities.reachability.unreachableAction %q is invalid (want annotate|downgrade|suppress)", v.Reachability.UnreachableAction)
		}
	}
	return nil
}

// validateLicense checks the license-compliance configuration: valid actions and
// dispositions on the base policy and every tenant override. The detailed
// validation of list entries (SPDX glob/family keywords) happens when the service
// is built, which surfaces a startup error.
func (c *Config) validateLicense() error {
	l := c.License
	if !l.Enabled {
		return nil
	}
	if err := validateLicensePolicy("license", l.Policy); err != nil {
		return err
	}
	if l.DriftMaxEvents < 0 {
		return fmt.Errorf("config: license.driftMaxEvents must not be negative, got %d", l.DriftMaxEvents)
	}
	for tenant, override := range l.Tenants {
		if strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("config: license.tenants has an entry with an empty tenant name")
		}
		if err := validateLicensePolicy("license.tenants."+tenant, override); err != nil {
			return err
		}
	}
	return nil
}

// validateLicensePolicy checks the action and disposition fields of a license
// policy block. Empty fields are valid (they take the documented default, or for
// a tenant override inherit the base value).
func validateLicensePolicy(prefix string, p LicensePolicyConfig) error {
	for field, action := range map[string]string{
		"action":       p.Action,
		"reviewAction": p.ReviewAction,
		"driftAction":  p.DriftAction,
	} {
		if a := strings.TrimSpace(action); a != "" && !policy.ValidAction(a) {
			return fmt.Errorf("config: %s.%s %q is invalid (want warn|block|quarantine)", prefix, field, action)
		}
	}
	for field, disp := range map[string]string{
		"unknown": p.Unknown,
		"default": p.Default,
	} {
		if d := strings.ToLower(strings.TrimSpace(disp)); d != "" && d != "allow" && d != "review" && d != "deny" {
			return fmt.Errorf("config: %s.%s %q is invalid (want allow|review|deny)", prefix, field, disp)
		}
	}
	return nil
}

// validVulnSeverity reports whether s is a recognized vulnerability severity
// bucket (empty is valid and means the threshold is disabled).
func validVulnSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// validatePolicy checks the admission-policy configuration: valid action strings,
// risk-score ranges, confidence levels, and threshold ordering.
func (c *Config) validatePolicy() error {
	if !c.Policy.Enabled {
		return nil
	}
	if err := validatePolicyRule("policy.default", c.Policy.Default); err != nil {
		return err
	}
	for eco, rule := range c.Policy.Ecosystems {
		if err := validatePolicyRule("policy.ecosystems."+eco, rule); err != nil {
			return err
		}
	}
	return nil
}

// validatePolicyRule validates a single policy rule.
func validatePolicyRule(ctx string, r PolicyRule) error {
	for field, action := range map[string]string{
		"onMissingProvenance": r.OnMissingProvenance,
		"onMissingScan":       r.OnMissingScan,
		"onLowConfidence":     r.OnLowConfidence,
	} {
		if !policy.ValidAction(action) {
			return fmt.Errorf("config: %s.%s has invalid action %q (want allow|warn|block)", ctx, field, action)
		}
	}
	for field, score := range map[string]int{
		"blockAtRiskScore": r.BlockAtRiskScore,
		"warnAtRiskScore":  r.WarnAtRiskScore,
	} {
		if score < 0 || score > 100 {
			return fmt.Errorf("config: %s.%s must be in 0..100, got %d", ctx, field, score)
		}
	}
	if r.BlockAtRiskScore > 0 && r.WarnAtRiskScore > 0 && r.WarnAtRiskScore > r.BlockAtRiskScore {
		return fmt.Errorf("config: %s.warnAtRiskScore (%d) must not exceed blockAtRiskScore (%d)",
			ctx, r.WarnAtRiskScore, r.BlockAtRiskScore)
	}
	switch strings.ToLower(strings.TrimSpace(r.MinConfidence)) {
	case "", "heuristic", "claimed", "attested":
	default:
		return fmt.Errorf("config: %s.minConfidence %q is invalid (want heuristic|claimed|attested)", ctx, r.MinConfidence)
	}
	return nil
}

// validatePolicyEngine checks the policy-as-code engine configuration. It does
// not parse the bundle files themselves (that happens at engine load, which
// surfaces precise per-rule errors); it only checks the scalar options.
func (c *Config) validatePolicyEngine() error {
	pe := c.PolicyEngine
	if !pe.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(pe.Mode)) {
	case "", "enforce", "audit":
	default:
		return fmt.Errorf("config: policyEngine.mode %q is invalid (want enforce|audit)", pe.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(pe.DefaultAction)) {
	case "", "allow", "warn", "deny":
	default:
		return fmt.Errorf("config: policyEngine.defaultAction %q is invalid (want allow|warn|deny)", pe.DefaultAction)
	}
	if pe.ReloadInterval < 0 {
		return fmt.Errorf("config: policyEngine.reloadInterval must not be negative")
	}
	return nil
}

// validateAuth checks the access-control configuration for internal
// consistency: defined role names, token shape, role references, and OIDC
// completeness.
func (c *Config) validateAuth() error {
	a := c.Auth
	if !a.Enabled {
		return nil
	}

	roleNames := make(map[string]bool, len(a.Roles))
	for _, role := range a.Roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return fmt.Errorf("config: auth.roles has an entry with empty name")
		}
		if roleNames[name] {
			return fmt.Errorf("config: auth duplicate role %q", name)
		}
		roleNames[name] = true
	}

	checkRoles := func(ctx string, roles []string) error {
		for _, r := range roles {
			if !roleNames[r] {
				return fmt.Errorf("config: %s references undefined role %q", ctx, r)
			}
		}
		return nil
	}

	seenTokenNames := make(map[string]bool, len(a.Tokens))
	for i, t := range a.Tokens {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return fmt.Errorf("config: auth.tokens[%d] has empty name", i)
		}
		if seenTokenNames[name] {
			return fmt.Errorf("config: auth duplicate token name %q", name)
		}
		seenTokenNames[name] = true
		if (strings.TrimSpace(t.Token) == "") == (strings.TrimSpace(t.TokenHash) == "") {
			return fmt.Errorf("config: auth.tokens[%q] must set exactly one of token or tokenHash", name)
		}
		if err := checkRoles(fmt.Sprintf("auth.tokens[%q]", name), t.Roles); err != nil {
			return err
		}
	}

	if err := checkRoles("auth.anonymousRoles", a.AnonymousRoles); err != nil {
		return err
	}

	if a.OIDC.Enabled {
		if strings.TrimSpace(a.OIDC.Issuer) == "" {
			return fmt.Errorf("config: auth.oidc.issuer is required when oidc is enabled")
		}
		if strings.TrimSpace(a.OIDC.JWKSURL) == "" && strings.TrimSpace(a.OIDC.JWKS) == "" {
			return fmt.Errorf("config: auth.oidc requires jwksUrl or jwks")
		}
	}

	// A personal cache link (Task 177) authenticates its user like a token does,
	// so a deployment whose every client is a signed-in user needs nothing else.
	if len(a.Tokens) == 0 && !a.OIDC.Enabled && !a.AllowAnonymous && !c.ClientAuth.MTLS.Enabled && !c.UserLinks.Enabled {
		return fmt.Errorf("config: auth.enabled but no tokens, oidc, mTLS, personal links (userLinks), or anonymous access configured (proxy would reject all requests)")
	}
	return nil
}

// validateClientAuth checks the SPIFFE/mTLS client-auth configuration (Task 58).
func (c *Config) validateClientAuth() error {
	m := c.ClientAuth.MTLS
	if !m.Enabled {
		return nil
	}
	if !c.Auth.Enabled {
		return fmt.Errorf("config: clientAuth.mtls.enabled requires auth.enabled (the RBAC enforcer and roles)")
	}
	if strings.TrimSpace(m.TrustBundle) == "" {
		return fmt.Errorf("config: clientAuth.mtls.trustBundle is required when mTLS is enabled")
	}
	switch strings.ToLower(strings.TrimSpace(m.TrustBundleFormat)) {
	case "", "auto", "pem", "spiffe":
	default:
		return fmt.Errorf("config: clientAuth.mtls.trustBundleFormat %q is invalid (want auto|pem|spiffe)", m.TrustBundleFormat)
	}
	// A PEM bundle (or the default auto, which may resolve to PEM) needs a
	// default trust domain to associate its roots with.
	format := strings.ToLower(strings.TrimSpace(m.TrustBundleFormat))
	if (format == "" || format == "auto" || format == "pem") && strings.TrimSpace(m.TrustDomain) == "" {
		return fmt.Errorf("config: clientAuth.mtls.trustDomain is required for a pem/auto trust bundle")
	}
	if len(m.Rules) == 0 {
		return fmt.Errorf("config: clientAuth.mtls requires at least one mapping rule")
	}
	roleNames := make(map[string]bool, len(c.Auth.Roles))
	for _, role := range c.Auth.Roles {
		roleNames[strings.TrimSpace(role.Name)] = true
	}
	checkRule := func(ctx string, r MTLSRuleConfig) error {
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("config: %s has an empty pattern", ctx)
		}
		for _, role := range r.Roles {
			if !roleNames[strings.TrimSpace(role)] {
				return fmt.Errorf("config: %s references undefined role %q", ctx, role)
			}
		}
		return nil
	}
	for i, r := range m.Rules {
		if err := checkRule(fmt.Sprintf("clientAuth.mtls.rules[%d]", i), r); err != nil {
			return err
		}
	}
	for tenant, rules := range m.TenantOverrides {
		for i, r := range rules {
			if err := checkRule(fmt.Sprintf("clientAuth.mtls.tenantOverrides[%q][%d]", tenant, i), r); err != nil {
				return err
			}
		}
	}
	// mTLS terminates at the gateway, so TLS must be configured there.
	if strings.TrimSpace(c.Server.TLSCertFile) == "" || strings.TrimSpace(c.Server.TLSKeyFile) == "" {
		return fmt.Errorf("config: clientAuth.mtls requires server.tlsCertFile and server.tlsKeyFile (mTLS terminates at the gateway)")
	}
	return nil
}

// validateAudit checks the audit configuration.
func (c *Config) validateAudit() error {
	if !c.Audit.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Audit.HMACKey) == "" && strings.TrimSpace(c.Audit.HMACKeyEnv) == "" {
		return fmt.Errorf("config: audit.enabled requires audit.hmacKey or audit.hmacKeyEnv for tamper evidence")
	}
	return nil
}

// validateUpstreamURL checks an upstream URL. All ecosystems require an http(s)
// URL except Git, which additionally accepts ssh:// and the scp-like
// "[user@]host:path" syntax for upstreams reached over SSH (mirror mode).
func validateUpstreamURL(typ, raw string) error {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return nil
	}
	if typ == "git" {
		if strings.HasPrefix(raw, "ssh://") {
			return nil
		}
		// scp-like: "[user@]host:path" — a colon that precedes the first slash and
		// is not a scheme separator.
		if !strings.Contains(raw, "://") {
			colon := strings.Index(raw, ":")
			slash := strings.Index(raw, "/")
			if colon > 0 && (slash < 0 || colon < slash) {
				return nil
			}
		}
		return fmt.Errorf("url must be http(s), ssh://, or user@host:path, got %q", raw)
	}
	return fmt.Errorf("url must be http(s), got %q", raw)
}

// validateTLSMinVersion checks that an outbound TLS minimum-version string is
// one the upstream client understands (empty means the default 1.2).
func validateTLSMinVersion(v string) error {
	switch strings.TrimSpace(v) {
	case "", "1.0", "1.1", "1.2", "1.3":
		return nil
	default:
		return fmt.Errorf("unsupported minVersion %q (want 1.0, 1.1, 1.2, or 1.3)", v)
	}
}

// validateTLSPins rejects a malformed certificate pin at config-load time so an
// operator learns of a typo before the first handshake to the pinned upstream
// (where an enforced pin fails closed). An empty list disables pinning.
func validateTLSPins(pins []string) error {
	if len(pins) == 0 {
		return nil
	}
	if _, err := tlspin.ParsePins(pins); err != nil {
		return err
	}
	return nil
}

// MetricsPathOrDefault returns the configured metrics path or the default.
func (o ObservabilityConfig) MetricsPathOrDefault() string {
	if o.MetricsPath == "" {
		return "/metrics"
	}
	return o.MetricsPath
}

// AdminPrefixOrDefault returns the configured admin path prefix or the default,
// always without a trailing slash.
func (o ObservabilityConfig) AdminPrefixOrDefault() string {
	p := o.AdminPathPrefix
	if p == "" {
		p = "/admin"
	}
	return strings.TrimRight(p, "/")
}

// RepositoriesConfig configures the repository registry: per-repository tag
// tracking and permanent release-artifact pinning (Task 180).
type RepositoriesConfig struct {
	// Enabled turns the registry on.
	Enabled bool `yaml:"enabled"`
	// StateDir holds the registry's state: API registrations, the
	// append-only tag histories, the release manifests (and with them the
	// pins). Defaults to "<cache.dir>/repositories" for the filesystem cache;
	// required otherwise. In a multi-replica deployment it must be a directory
	// every replica mounts: the pins in it protect the shared cache on every
	// replica.
	StateDir string `yaml:"stateDir"`
	// MirrorDir holds a bare mirror of each repository. Defaults to
	// "<stateDir>/mirrors".
	MirrorDir string `yaml:"mirrorDir"`
	// PollInterval is the period between syncs of every repository's tags.
	// Defaults to 5m; "0s" leaves tracking to webhooks and manual syncs.
	PollInterval *time.Duration `yaml:"pollInterval"`
	// WebhookPath is where push webhooks are received (default
	// "/webhooks/repos"). Point the Git host's push webhook here; tag pushes
	// sync the repository at once.
	WebhookPath string `yaml:"webhookPath"`
	// WebhookSecret verifies the webhook's HMAC-SHA256 signature
	// (X-Hub-Signature-256), like scanning.watch.webhookSecret. A secret
	// reference is accepted. Without a secret the webhook is not served:
	// tags are tracked by polling (and `ptctl repos sync`) only.
	WebhookSecret string `yaml:"webhookSecret"`
	// BackfillTags is how many of the tags found when a repository is first
	// synced are pinned, the most recently committed first. -1 pins all, 0
	// none (each can be pinned on request). Every tag is recorded in the
	// history either way. Default 10.
	BackfillTags *int `yaml:"backfillTags"`
	// AllowedSchemes are the repository URL schemes accepted (default https
	// and ssh; scp-like user@host:path counts as ssh).
	AllowedSchemes []string `yaml:"allowedSchemes"`
	// Roles are the access-control roles (auth.roles) the release pinner
	// holds when it fetches a repository's dependencies, for a repository
	// that names none of its own. With auth enabled, a dependency from an
	// upstream no role grants is refused, as a client's pull would be: the
	// lock files name the registries, and must not reach an upstream the
	// operator has not granted. Required with auth enabled unless every
	// repository names its roles.
	Roles []string `yaml:"roles"`
	// Pinning tunes how releases are pinned.
	Pinning ReleasePinningConfig `yaml:"pinning"`
	// Scan tunes the LLM malicious-behaviour scan of every dependency the
	// repositories' lock files pin (Task 181). It runs through the LLM
	// package-content scan gate (llmPackageScan), its verdict cache, cost
	// budget and concurrency limits, and only when that gate is enabled.
	Scan RepositoryScanConfig `yaml:"scan"`
	// Updates configures the maintenance updater (Task 182): a branch per
	// repository with the dependency updates that are compatible with the
	// declared constraints and vetted — every admission gate, the dependency
	// firewall, the maturity cooldown, and a benign LLM package-scan verdict
	// for the exact bytes.
	Updates RepositoryUpdatesConfig `yaml:"updates"`
	// Repos are the repositories registered by configuration. More can be
	// registered through the admin API (`ptctl repos add`).
	Repos []RepositoryConfig `yaml:"repos"`
}

// RepositoryUpdatesConfig configures the maintenance updater.
type RepositoryUpdatesConfig struct {
	// Enabled turns the updater on: scheduled runs on the HA leader, and
	// runs on request (`ptctl repos update`). It needs llmPackageScan.enabled:
	// only a candidate the LLM package-content scan judged benign is proposed.
	Enabled bool `yaml:"enabled"`
	// Interval is the period between scheduled runs of each repository
	// (default 24h). A negative value runs on request only.
	Interval time.Duration `yaml:"interval"`
	// Branch is the maintenance branch (default "pullthrough/maintenance").
	// It is rebuilt on top of the default branch's head at every run.
	Branch string `yaml:"branch"`
	// MaxBump bounds the updates of a dependency whose manifests declare no
	// constraint: "minor" (the default: stay within the same major version)
	// or "patch" (patch updates only). A declared constraint (a package.json
	// range, a Cargo.toml requirement, a requirements.in specifier, a Go
	// module's major version) always decides when there is one.
	MaxBump string `yaml:"maxBump"`
	// IncludeDev updates development dependencies too (default true).
	IncludeDev *bool `yaml:"includeDev"`
	// MaxCandidates is how many compatible newer versions of one dependency
	// are vetted, newest first, before it is given up (default 3): each may
	// cost an LLM scan.
	MaxCandidates int `yaml:"maxCandidates"`
	// MaxUpdates bounds the updates of one run (default 50).
	MaxUpdates int `yaml:"maxUpdates"`
	// Concurrency is how many dependencies are examined at a time (default 2).
	Concurrency int `yaml:"concurrency"`
	// AuthorName and AuthorEmail are the commits' author and committer
	// (default "pullthrough-security" <pullthrough@localhost>).
	AuthorName  string `yaml:"authorName"`
	AuthorEmail string `yaml:"authorEmail"`
	// SigningKey signs the commits (git's SSH signature format, gpg.format=ssh):
	// an OpenSSH private key (ed25519, ECDSA or RSA), as a secret reference.
	// Empty leaves the commits unsigned. SigningKeyPassphrase decrypts it.
	SigningKey           string `yaml:"signingKey"`
	SigningKeyPassphrase string `yaml:"signingKeyPassphrase"`
	// PullRequests opens (or updates) a pull/merge request per repository
	// whose updates block names a forge and a token reference.
	PullRequests RepositoryPullRequestsConfig `yaml:"pullRequests"`
	// Sandbox runs the real package manager when an update needs the lock
	// file re-resolved: a network-less container whose only registry is the
	// proxy. Without a runtime such updates are skipped.
	Sandbox RepositoryUpdateSandboxConfig `yaml:"sandbox"`
	// RunTimeout bounds one run (default 2h).
	RunTimeout time.Duration `yaml:"runTimeout"`
}

// RepositoryPullRequestsConfig configures the maintenance pull requests.
type RepositoryPullRequestsConfig struct {
	// Enabled opens them (default false).
	Enabled bool `yaml:"enabled"`
	// Labels are added to each; Draft opens them as drafts.
	Labels []string `yaml:"labels"`
	Draft  bool     `yaml:"draft"`
}

// RepositoryUpdateSandboxConfig configures the sandboxed package managers.
type RepositoryUpdateSandboxConfig struct {
	// Runtime is the container runtime: "docker" or "podman". Empty turns
	// the sandbox off.
	Runtime string `yaml:"runtime"`
	// Images overrides the tools' images (npm, cargo, go); the defaults are
	// the client lab's.
	Images map[string]string `yaml:"images"`
	// Timeout bounds one run of a tool (default 10m); Memory its container's
	// memory (default "2g").
	Timeout time.Duration `yaml:"timeout"`
	Memory  string        `yaml:"memory"`
	// User is the "uid:gid" the tool runs as (default 65534:65534).
	User string `yaml:"user"`
	// TempDir holds the jobs' files; it must be a directory the runtime can
	// bind-mount (default the system's temporary directory).
	TempDir string `yaml:"tempDir"`
	// Forwarder is the statically linked binary run in the container to relay
	// the tool's requests to the proxy (default this executable).
	Forwarder string `yaml:"forwarder"`
}

// RepositoryUpdateConfig is one repository's maintenance settings.
type RepositoryUpdateConfig struct {
	// Disabled turns the updater off for the repository.
	Disabled bool `yaml:"disabled"`
	// Branch overrides repositories.updates.branch.
	Branch string `yaml:"branch"`
	// MaxBump overrides repositories.updates.maxBump.
	MaxBump string `yaml:"maxBump"`
	// Ignore lists what is never proposed: "type/name" (every version),
	// "type/name@version", or "type/name@<constraint>" in the ecosystem's
	// syntax ("npm/lodash@>=5", "pip/django@>=5.0"); "*" matches any type and
	// a name may end in "*".
	Ignore []string `yaml:"ignore"`
	// Forge is "github" or "gitlab": where the pull/merge request is opened.
	Forge string `yaml:"forge"`
	// ForgeAPI is the API base URL (default https://api.github.com,
	// https://gitlab.com/api/v4).
	ForgeAPI string `yaml:"forgeApi"`
	// ForgeRepo is "owner/name" (GitHub) or the project path (GitLab);
	// default: read from the repository's URL.
	ForgeRepo string `yaml:"forgeRepo"`
	// ForgeTokenRef is the secret reference of the forge API token, resolved
	// at each run.
	ForgeTokenRef string `yaml:"forgeTokenRef"`
}

// RepositoryScanConfig tunes the dependency scans of tracked repositories.
type RepositoryScanConfig struct {
	// Enabled turns the scans on (default true; they also need
	// llmPackageScan.enabled). Off, nothing is scanned and the release
	// pinner refuses a dependency the LLM gate refuses, as before.
	Enabled *bool `yaml:"enabled"`
	// Releases scans each release manifest once it is pinned (default
	// true). The release pinner then pins the bytes of a dependency the LLM
	// gate refuses — they are kept for forensics, and refused to every
	// client while the verdict stands — and the scan marks the release
	// "contains malicious dependency" and reports it.
	Releases *bool `yaml:"releases"`
	// DefaultBranch scans the default branch's head when it moves (a push
	// webhook or a poll) and every interval (default true).
	DefaultBranch *bool `yaml:"defaultBranch"`
	// Interval is how often the default branch's head is scanned again when
	// it has not moved (default 24h; "0s" keeps the default, a negative
	// value scans it only when it moves). A rescan costs no model call for
	// bytes that already have a verdict.
	Interval time.Duration `yaml:"interval"`
	// Workers is how many revisions are scanned at a time (default 1);
	// Concurrency how many dependencies of one revision (default 2). The
	// LLM gate's own maxConcurrent and per-tenant share bound the model
	// calls on top of these.
	Workers     int `yaml:"workers"`
	Concurrency int `yaml:"concurrency"`
	// RetryInterval is the wait before dependencies left unscanned for a
	// passing reason (a provider failure, a busy scanner, a spent budget)
	// are tried again; it doubles per attempt (default 1h). MaxAttempts
	// bounds the attempts (default 5).
	RetryInterval time.Duration `yaml:"retryInterval"`
	MaxAttempts   int           `yaml:"maxAttempts"`
}

// ScanEnabledOrDefault reports whether dependency scans are on (default true).
func (s RepositoryScanConfig) ScanEnabledOrDefault() bool { return s.Enabled == nil || *s.Enabled }

// ReleasePinningConfig tunes release pinning.
type ReleasePinningConfig struct {
	// Workers is how many releases are pinned at a time (default 2).
	Workers int `yaml:"workers"`
	// Concurrency is how many dependencies of a release are fetched at a time
	// (default 4).
	Concurrency int `yaml:"concurrency"`
	// MaxDependencies bounds the dependencies of one release (default
	// 10000); a release with more is not fully pinned.
	MaxDependencies int `yaml:"maxDependencies"`
	// MaxObjectsPerDependency bounds the cache objects one dependency expands
	// to — the manifests and layers of a container image, the wheels of a
	// Python release (default 256).
	MaxObjectsPerDependency int `yaml:"maxObjectsPerDependency"`
	// IncludeDev pins development dependencies too (default true): a build
	// needs them.
	IncludeDev *bool `yaml:"includeDev"`
	// Platforms selects the platforms ("linux/amd64", "linux/arm64/v8") of
	// container image indexes and Terraform providers. Empty pins every
	// platform an image index lists, and linux/amd64 providers.
	Platforms []string `yaml:"platforms"`
	// RetryInterval is the wait before what a release could not pin is tried
	// again; it doubles with each attempt (default 1h). MaxAttempts bounds
	// the attempts (default 5); `ptctl repos pin` starts over.
	RetryInterval time.Duration `yaml:"retryInterval"`
	MaxAttempts   int           `yaml:"maxAttempts"`
	// SpoolDir holds the temporary copy of a Go module zip while its module
	// hash is computed. Empty is the system's temporary directory.
	SpoolDir string `yaml:"spoolDir"`
}

// RepositoryConfig registers one repository.
type RepositoryConfig struct {
	// Name identifies the repository: lower-case letters, digits, '.', '_'
	// and '-'.
	Name string `yaml:"name"`
	// URL is the clone URL: https://…, ssh://… or user@host:path.
	URL string `yaml:"url"`
	// Username is the HTTPS user name sent with the credential (default
	// "x-access-token").
	Username string `yaml:"username"`
	// CredentialsRef is a secret reference — env://VAR, file:///path,
	// vault://mount/path#key — resolved through the secrets provider whenever
	// the repository is fetched; never the secret itself.
	CredentialsRef string `yaml:"credentialsRef"`
	// Tenant owns the repository: its releases are visible to that tenant
	// only, and its dependencies are fetched as that tenant.
	Tenant string `yaml:"tenant"`
	// Lockfiles are globs of the lock files that make up a release
	// ("package-lock.json", "services/*/go.*"); empty takes every lock file
	// outside vendored code and test fixtures.
	Lockfiles []string `yaml:"lockfiles"`
	// Tags are globs of the tags tracked ("v*"); empty tracks every tag.
	Tags []string `yaml:"tags"`
	// Upstreams maps an upstream type to the upstream the repository's
	// dependencies of that type are fetched through, when the registry a lock
	// file names is not enough to choose (several upstreams of the type).
	Upstreams map[string]string `yaml:"upstreams"`
	// FullName ("owner/repo") routes push webhooks to the repository in
	// addition to its URL.
	FullName string `yaml:"fullName"`
	// BackfillTags overrides repositories.backfillTags for this repository.
	BackfillTags *int `yaml:"backfillTags"`
	// Roles overrides repositories.roles for this repository.
	Roles []string `yaml:"roles"`
	// Branch is the branch whose head the dependency scan follows (default:
	// the repository's default branch, as its remote's HEAD names it).
	Branch string `yaml:"branch"`
	// Updates holds the repository's maintenance settings (Task 182).
	Updates *RepositoryUpdateConfig `yaml:"updates"`
}

// RepositoriesStateDir returns the registry's state directory: the configured
// one, or "<cache.dir>/repositories" for the filesystem cache.
func (c *Config) RepositoriesStateDir() string {
	if d := strings.TrimSpace(c.Repositories.StateDir); d != "" {
		return d
	}
	if c.Cache.Backend == "filesystem" && strings.TrimSpace(c.Cache.Dir) != "" {
		return filepath.Join(c.Cache.Dir, "repositories")
	}
	return ""
}

// RepositoriesMirrorDir returns the directory of the registry's mirrors.
func (c *Config) RepositoriesMirrorDir() string {
	if d := strings.TrimSpace(c.Repositories.MirrorDir); d != "" {
		return d
	}
	if st := c.RepositoriesStateDir(); st != "" {
		return filepath.Join(st, "mirrors")
	}
	return ""
}

// RepositoriesPollInterval returns the poll period (default 5m).
func (c *Config) RepositoriesPollInterval() time.Duration {
	if c.Repositories.PollInterval == nil {
		return 5 * time.Minute
	}
	return *c.Repositories.PollInterval
}

// RepositoriesWebhookPath returns the webhook path (default "/webhooks/repos").
func (c *Config) RepositoriesWebhookPath() string {
	if p := strings.TrimSpace(c.Repositories.WebhookPath); p != "" {
		return p
	}
	return "/webhooks/repos"
}

// validateRepositories checks the repository registry configuration.
func (c *Config) validateRepositories() error {
	r := c.Repositories
	if !r.Enabled {
		return nil
	}
	if c.RepositoriesStateDir() == "" {
		return fmt.Errorf("config: repositories.stateDir is required unless the cache is a filesystem cache (it then defaults to <cache.dir>/repositories)")
	}
	if c.Cache.Backend == "memory" {
		return fmt.Errorf("config: repositories needs a durable cache (filesystem or s3): pins in the in-memory cache would not outlive the process")
	}
	if p := c.RepositoriesPollInterval(); p < 0 || (p > 0 && p < 10*time.Second) {
		return fmt.Errorf("config: repositories.pollInterval must be 0 (off) or at least 10s, got %s", p)
	}
	wp := c.RepositoriesWebhookPath()
	if !strings.HasPrefix(wp, "/") || strings.HasPrefix(wp, "/v1/") || wp == "/v1" {
		return fmt.Errorf("config: repositories.webhookPath %q must be an absolute path outside /v1/", wp)
	}
	if c.Scanning.Watch.Enabled && wp == c.Scanning.Watch.WebhookPath {
		return fmt.Errorf("config: repositories.webhookPath and scanning.watch.webhookPath must differ")
	}
	if r.BackfillTags != nil && *r.BackfillTags < -1 {
		return fmt.Errorf("config: repositories.backfillTags must be -1 (all), 0 (none) or a count")
	}
	for _, sch := range r.AllowedSchemes {
		switch strings.ToLower(strings.TrimSpace(sch)) {
		case "https", "ssh", "http", "git", "file":
		default:
			return fmt.Errorf("config: repositories.allowedSchemes: unknown scheme %q", sch)
		}
	}
	pc := r.Pinning
	if pc.Workers < 0 || pc.Concurrency < 0 || pc.MaxDependencies < 0 || pc.MaxObjectsPerDependency < 0 || pc.MaxAttempts < 0 || pc.RetryInterval < 0 {
		return fmt.Errorf("config: repositories.pinning values must not be negative")
	}
	for _, p := range pc.Platforms {
		parts := strings.Split(strings.TrimSpace(p), "/")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("config: repositories.pinning.platforms: %q is not os/arch[/variant]", p)
		}
	}
	sc := r.Scan
	if sc.Workers < 0 || sc.Concurrency < 0 || sc.MaxAttempts < 0 || sc.RetryInterval < 0 {
		return fmt.Errorf("config: repositories.scan values must not be negative (interval excepted)")
	}
	if sc.Interval > 0 && sc.Interval < time.Minute {
		return fmt.Errorf("config: repositories.scan.interval must be at least 1m (or negative: only when the head moves), got %s", sc.Interval)
	}
	if err := c.validateRepositoryUpdates(); err != nil {
		return err
	}
	definedRole := map[string]bool{}
	for _, role := range c.Auth.Roles {
		definedRole[strings.TrimSpace(role.Name)] = true
	}
	checkRoles := func(where string, roles []string) error {
		if !c.Auth.Enabled {
			return nil
		}
		for _, role := range roles {
			if !definedRole[strings.TrimSpace(role)] {
				return fmt.Errorf("config: %s references undefined role %q (auth.roles)", where, role)
			}
		}
		return nil
	}
	if err := checkRoles("repositories.roles", r.Roles); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, repo := range r.Repos {
		if strings.TrimSpace(repo.Name) == "" || strings.TrimSpace(repo.URL) == "" {
			return fmt.Errorf("config: repositories.repos[%d] needs a name and a url", i)
		}
		if err := checkRoles(fmt.Sprintf("repositories.repos %q roles", repo.Name), repo.Roles); err != nil {
			return err
		}
		if c.Auth.Enabled && len(repo.Roles) == 0 && len(r.Roles) == 0 {
			return fmt.Errorf("config: repositories.repos %q: auth is enabled, and the release pinner needs roles to fetch the repository's dependencies with: set repositories.roles or the repository's roles", repo.Name)
		}
		if seen[repo.Name] {
			return fmt.Errorf("config: repositories.repos: %q is registered twice", repo.Name)
		}
		if b := strings.TrimSpace(repo.Branch); b != "" && (strings.HasPrefix(b, "-") || strings.ContainsAny(b, " \t\r\n:~^?*[\\") || strings.Contains(b, "..")) {
			return fmt.Errorf("config: repositories.repos %q: branch %q is not a branch name", repo.Name, repo.Branch)
		}
		seen[repo.Name] = true
		for t, up := range repo.Upstreams {
			u, ok := c.Upstreams[up]
			if !ok {
				return fmt.Errorf("config: repositories.repos %q: upstreams.%s names upstream %q, which is not configured", repo.Name, t, up)
			}
			if !sameUpstreamType(u.Type, t) {
				return fmt.Errorf("config: repositories.repos %q: upstreams.%s names upstream %q of type %q", repo.Name, t, up, u.Type)
			}
		}
	}
	return nil
}

// validateRepositoryUpdates checks the maintenance updater's configuration.
func (c *Config) validateRepositoryUpdates() error {
	u := c.Repositories.Updates
	for _, repo := range c.Repositories.Repos {
		if ru := repo.Updates; ru != nil {
			if err := validateRepositoryUpdate(repo.Name, ru); err != nil {
				return err
			}
		}
	}
	if !u.Enabled {
		return nil
	}
	if !c.LLMPackageScan.Enabled {
		return fmt.Errorf("config: repositories.updates needs llmPackageScan.enabled: an update is proposed only once the LLM package-content scan judged its exact bytes benign")
	}
	if u.Interval > 0 && u.Interval < time.Minute {
		return fmt.Errorf("config: repositories.updates.interval must be at least 1m (or negative: on request only), got %s", u.Interval)
	}
	if b := strings.TrimSpace(u.Branch); b != "" && !validGitBranch(b) {
		return fmt.Errorf("config: repositories.updates.branch %q is not a branch name", u.Branch)
	}
	switch strings.TrimSpace(u.MaxBump) {
	case "", "minor", "patch":
	default:
		return fmt.Errorf("config: repositories.updates.maxBump must be minor or patch, got %q", u.MaxBump)
	}
	if u.MaxCandidates < 0 || u.MaxUpdates < 0 || u.Concurrency < 0 || u.RunTimeout < 0 || u.Sandbox.Timeout < 0 {
		return fmt.Errorf("config: repositories.updates values must not be negative (interval excepted)")
	}
	if strings.ContainsAny(u.AuthorName, "<>\n\r\x00") || strings.ContainsAny(u.AuthorEmail, "<>\n\r\x00 ") {
		return fmt.Errorf("config: repositories.updates.authorName and authorEmail must not contain '<', '>' or line breaks")
	}
	switch strings.TrimSpace(u.Sandbox.Runtime) {
	case "", "docker", "podman":
	default:
		return fmt.Errorf("config: repositories.updates.sandbox.runtime must be docker or podman, got %q", u.Sandbox.Runtime)
	}
	for tool, img := range u.Sandbox.Images {
		switch tool {
		case "npm", "cargo", "go", "uv":
		default:
			return fmt.Errorf("config: repositories.updates.sandbox.images: unknown tool %q (npm, cargo, go, uv)", tool)
		}
		if strings.TrimSpace(img) == "" || strings.HasPrefix(img, "-") || strings.ContainsAny(img, " \t\r\n") {
			return fmt.Errorf("config: repositories.updates.sandbox.images.%s is not an image reference", tool)
		}
	}
	return nil
}

// validateRepositoryUpdate checks one repository's maintenance settings.
func validateRepositoryUpdate(name string, ru *RepositoryUpdateConfig) error {
	if b := strings.TrimSpace(ru.Branch); b != "" && !validGitBranch(b) {
		return fmt.Errorf("config: repositories.repos %q: updates.branch %q is not a branch name", name, ru.Branch)
	}
	switch strings.TrimSpace(ru.MaxBump) {
	case "", "minor", "patch":
	default:
		return fmt.Errorf("config: repositories.repos %q: updates.maxBump must be minor or patch, got %q", name, ru.MaxBump)
	}
	switch strings.ToLower(strings.TrimSpace(ru.Forge)) {
	case "", "github", "gitlab":
	default:
		return fmt.Errorf("config: repositories.repos %q: updates.forge must be github or gitlab, got %q", name, ru.Forge)
	}
	if ref := strings.TrimSpace(ru.ForgeTokenRef); ref != "" && !strings.Contains(ref, "://") {
		return fmt.Errorf("config: repositories.repos %q: updates.forgeTokenRef must be a secret reference (env://, file://, vault://…#key), never the token itself", name)
	}
	for _, ig := range ru.Ignore {
		if t, rest, ok := strings.Cut(strings.TrimSpace(ig), "/"); !ok || t == "" || rest == "" {
			return fmt.Errorf("config: repositories.repos %q: updates.ignore entry %q is not type/name[@version-or-constraint]", name, ig)
		}
	}
	return nil
}

// validGitBranch reports whether b can be a branch name the updater pushes.
func validGitBranch(b string) bool {
	if b == "" || len(b) > 200 || strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".lock") || strings.HasSuffix(b, ".") || strings.Contains(b, "..") || strings.Contains(b, "//") {
		return false
	}
	for _, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/+-", r)) {
			return false
		}
	}
	return true
}

// sameUpstreamType compares upstream types, aliases resolved.
func sameUpstreamType(a, b string) bool {
	canon := func(t string) string {
		t = strings.ToLower(strings.TrimSpace(t))
		switch t {
		case "deb":
			return "apt"
		case "rpm":
			return "yum"
		case "pub":
			return "dart"
		}
		return t
	}
	return canon(a) == canon(b)
}
