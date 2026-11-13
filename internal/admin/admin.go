// Package admin exposes an operator-facing surface for the pull-through proxy:
// a small JSON REST API for inspecting cache contents, scan verdicts,
// provenance links, and the effective policy/configuration, plus a minimal
// embedded web dashboard built on top of that API.
//
// The package is deliberately decoupled from the concrete subsystems: it talks
// to them through narrow interfaces (CacheInspector, ScanInspector,
// provenance.Resolver, BackendLister), so any of them may be absent and the
// surface degrades gracefully rather than failing. This mirrors the proxy's
// existing "optional dependency" pattern.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/avscan"
	"github.com/blechschmidt/pullthrough-security/internal/backup"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/compliance"
	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/egress"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
	"github.com/blechschmidt/pullthrough-security/internal/gitops"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// CacheInspector is the cache surface the admin API needs: listing, stating,
// and deleting entries. Both cache implementations satisfy it.
type CacheInspector interface {
	Entries(ctx context.Context) ([]cache.Stat, error)
	Stat(ctx context.Context, key string) (*cache.Stat, error)
	Delete(ctx context.Context, key string) error
}

// CacheMetricsSource optionally reports cumulative cache activity counters.
type CacheMetricsSource interface {
	Metrics() cache.MetricsSnapshot
}

// ScanInspector is the commit-scan surface: reading persisted verdicts and the
// live async queue depth. The commit.Scanner satisfies it.
type ScanInspector interface {
	Verdict(ctx context.Context, sha string) (*commit.Verdict, error)
	Verdicts(ctx context.Context) ([]*commit.Verdict, error)
	QueueDepth() int
	PendingCount() int
}

// CommitScanController is the commit-scan hardening control surface (Task 78):
// reading the hardening configuration (cache signature, consensus quorum, budget
// policy, retention) and per-tenant cost budgets, and operating on budget
// ceilings and the verdict cache. *commit.Scanner satisfies it.
type CommitScanController interface {
	HardeningStatus() commit.HardeningStatus
	BudgetSnapshot() []commit.TenantBudget
	SetBudget(tenant string, ceilingUSD float64) error
	PruneVerdicts(ctx context.Context) (int, error)
}

// BackendLister reports the configured upstream/backend names.
type BackendLister interface {
	Names() []string
}

// VulnInspector is the vulnerability-scan surface: listing cached scan Reports,
// fetching one by content digest, the cumulative metrics, and the artifacts the
// continuous re-scan subsystem has quarantined. The vulnscan Service satisfies it.
type VulnInspector interface {
	Reports() []*vulnscan.Report
	Report(digest string) (*vulnscan.Report, bool)
	Metrics() vulnscan.Snapshot
	Quarantined() []vulnscan.QuarantineEntry
	ReleaseQuarantine(digest string) bool
	// VEX surface (Task 27): the loaded VEX corpus and its statistics.
	VEXEnabled() bool
	VEXStats() vulnscan.VEXStats
	VEXStatements() []vulnscan.VEXStatement
}

// LicenseInspector is the license-compliance surface (Task 28): the cumulative
// metrics, the effective policy, recent non-allow decisions, and detected license
// drift. The license Service satisfies it.
type LicenseInspector interface {
	Metrics() license.Snapshot
	Summary() license.PolicySummary
	Drifts() []license.DriftEvent
	RecentDecisions() []license.DecisionRecord
	DriftEnabled() bool
}

// SigverifyInspector is the signature-verification surface (Task 23): listing
// cached verification reports, fetching one by content digest, and the
// cumulative metrics. The sigverify Service satisfies it.
type SigverifyInspector interface {
	Reports() []*sigverify.Report
	Report(digest string) (*sigverify.Report, bool)
	Metrics() sigverify.Snapshot
}

// RescanInspector is the continuous re-scan surface (Task 18): inspecting the last
// sweep, the artifacts whose risk changed, the configured interval, and triggering
// an on-demand sweep. The vulnscan Rescanner satisfies it.
type RescanInspector interface {
	LastSummary() vulnscan.RescanSummary
	RiskChanges() []vulnscan.RiskChange
	Interval() time.Duration
	Trigger(ctx context.Context) (vulnscan.RescanSummary, error)
}

// NotifyInspector is the notification-subsystem surface the admin API exposes
// (Task 21): listing configured sinks, reading cumulative delivery metrics, and
// sending a synchronous test notification. The notify.Notifier satisfies it.
type NotifyInspector interface {
	Sinks() []notify.SinkInfo
	Metrics() notify.Snapshot
	Test(ctx context.Context, sink string) ([]notify.TestResult, error)
}

// RateLimitInspector is the rate-limit surface the admin API exposes (Task 24):
// reading the live policy/usage snapshot and updating a tenant's (or the global)
// policy at runtime. The ratelimit.Limiter satisfies it.
type RateLimitInspector interface {
	Metrics() ratelimit.Snapshot
	SetPolicy(tenant string, p ratelimit.Policy) error
	SetGlobalPolicy(p ratelimit.Policy) error
}

// UpstreamPoolInspector is the health-aware upstream-routing surface the admin
// API exposes (Task 38): the per-backend mirror-pool snapshots (endpoint health,
// circuit state, failover counts) plus operator overrides to force-drain a
// mirror, clear (close) a circuit, or trip (open) one. The upstreampool.Manager
// satisfies it.
type UpstreamPoolInspector interface {
	Snapshots() []upstreampool.Snapshot
	SetDrained(backend, endpoint string, drained bool) error
	ResetCircuit(backend, endpoint string) error
	OpenCircuit(backend, endpoint string) error
}

// EgressInspector is the SSRF / outbound-egress guard surface the admin API
// exposes (Task 89): the effective egress policy and counters, plus runtime
// allowlist mutation. *egress.Guard satisfies it.
type EgressInspector interface {
	Snapshot() egress.Snapshot
	AddAllowlistEntry(entry string) error
	RemoveAllowlistEntry(entry string) bool
}

// CoalesceInspector is the pull-path coalescer surface the admin API exposes
// (Task 36): the live coalescing/negative-cache snapshot (dedup ratio, in-flight
// fetches, negative-cache hits/evictions/entries, per-failure-class breakdown),
// plus a way to flush the negative cache. The coalesce.Coalescer satisfies it.
type CoalesceInspector interface {
	Metrics() coalesce.Snapshot
	PurgeNegativeCache() int
}

// CacheGCInspector is the cache lifecycle/garbage-collection surface the admin
// API exposes (Task 39): the cumulative GC snapshot (utilization vs watermark,
// bytes reclaimed, eviction counts), the most recent run report, and a way to
// trigger an on-demand sweep (optionally dry-run) to preview or force eviction.
// The cachegc.Engine satisfies it.
type CacheGCInspector interface {
	Snapshot() cachegc.Snapshot
	LastReport() (cachegc.Report, bool)
	Run(ctx context.Context, dryRun bool) (cachegc.Report, error)
}

// IntegrityInspector is the read-time cache-integrity surface the admin API
// exposes (Task 107): the current verification counters, the most recent
// background integrity-scan report, and a way to trigger an on-demand scan that
// re-verifies every cached blob's content digest and quarantines any corruption
// it finds. The cache.IntegrityCache wrapper satisfies it.
type IntegrityInspector interface {
	IntegrityMetrics() cache.IntegrityMetricsSnapshot
	LastScan() (cache.IntegrityReport, bool)
	ScanIntegrity(ctx context.Context) (cache.IntegrityReport, error)
}

// CompactionInspector is the transparent storage-efficiency surface the admin
// API exposes (Task 125): the cumulative compression/dedup statistics used to
// report on-disk / S3 space savings. The cache.FilesystemCache (and its
// decorators) satisfy it via CompactionStats.
type CompactionInspector interface {
	CompactionStats() cache.CompactionStats
}

// EncryptionInspector is the at-rest encryption surface the admin API exposes
// (Task 141): the encryption status/statistics and a trigger to rotate the
// key-encryption key (re-wrapping every object's data key to the active KEK
// without re-encrypting payloads). The cache.FilesystemCache (and its
// decorators) satisfy it by forwarding to the encryption layer.
type EncryptionInspector interface {
	EncryptionStats() cache.EncryptionStats
	RotateKEK(ctx context.Context) (cache.KEKRotationReport, error)
}

// TieringInspector is the hot/cold tiered storage surface the admin API exposes
// (Task 154): the tiering status/statistics (promotions, demotions, tier-hit
// ratios, per-tier object/byte gauges) and a trigger to run a demotion sweep on
// demand. The cache.TieredStore satisfies it.
type TieringInspector interface {
	TieredStats() cache.TieredStats
	SweepTiers(ctx context.Context) (cache.TierSweepReport, error)
}

// AuditInspector is the tamper-evident audit-log surface (Task 31): the chain/
// transparency statistics, the latest signed checkpoint, and inclusion/
// consistency proofs a client can independently verify. The audit.Logger
// satisfies it.
type AuditInspector interface {
	Stats() audit.Stats
	TransparencyEnabled() bool
	LatestCheckpoint() (audit.Checkpoint, bool)
	InclusionProof(seq uint64) (audit.InclusionProof, error)
	ConsistencyProof(from, to uint64) (audit.ConsistencyProof, error)
	RecordVerificationFailure()
}

// PolicyEngineInspector is the declarative policy-as-code surface (Task 32):
// the cumulative metrics, the loaded bundles, an on-demand reload, and a
// dry-run "test a policy against a sample input" evaluation. The
// policyengine.Engine satisfies it.
type PolicyEngineInspector interface {
	Snapshot() policyengine.Snapshot
	Bundles() []policyengine.BundleInfo
	Mode() policyengine.Mode
	Dir() string
	Reload() error
	TestEvaluate(in policyengine.Input) policyengine.Result
}

// ComplianceInspector is the continuous-compliance scorecard surface (Task 35):
// the latest computed scorecard, an on-demand recomputation, a signed exportable
// report artifact, and the signing key id. The compliance.Service satisfies it.
type ComplianceInspector interface {
	Latest() compliance.Scorecard
	Recompute() compliance.Scorecard
	Export() (compliance.SignedReport, error)
	SignerKeyID() string
}

// RiskScoreInspector is the unified risk-scoring surface (Task 37): the
// cumulative engine snapshot (per-band counts, threshold, weighting model) and
// the recent explainable assessments for the trend view and drill-down. The
// riskscore.Engine satisfies it.
type RiskScoreInspector interface {
	Enabled() bool
	Snapshot() riskscore.Snapshot
	Recent(limit int) []riskscore.Assessment
}

// RepoScoreInspector is the source-repository health surface (Task 63): the
// cumulative provider status (per-grade resolved-repo counts, average health,
// resolve/cache tallies, the weighting model) plus the recent explainable
// per-repo reports for the drill-down. The reposcore.Service satisfies it.
type RepoScoreInspector interface {
	Enabled() bool
	Status(limit int) reposcore.Status
	Recent(limit int) []reposcore.Report
}

// SbomDiffInspector is the SBOM diff & dependency-drift surface (Task 64): the
// cumulative drift metrics, the tracked coordinates and their retained versions,
// and the on-demand version-to-version diff ("what changed since the version I
// last approved?"). The sbomdiff.Service satisfies it.
type SbomDiffInspector interface {
	Enabled() bool
	Metrics(recentLimit int) sbomdiff.Stats
	Coordinates(limit int) []sbomdiff.CoordinateRef
	Diff(tenant, ecosystem, coordinate, fromVersion, toVersion string) (*sbomdiff.Diff, bool)
	DiffLatest(tenant, ecosystem, coordinate string) (*sbomdiff.Diff, bool)
}

// RemediationInspector is the automated dependency-remediation advisor surface
// (Task 121): given a flagged artifact it computes the nearest safe upgrade, the
// findings that version resolves, and any it introduces. The remediation.Service
// satisfies it.
type RemediationInspector interface {
	Enabled() bool
	Advise(ctx context.Context, req remediation.Request) (*remediation.Advice, error)
}

// RebuildVerifyInspector is the reproducible-build verification surface (Task
// 68): the effective configuration plus cumulative per-verdict/per-ecosystem
// tallies and the recent verification results. The rebuildverify.Service
// satisfies it.
type RebuildVerifyInspector interface {
	Enabled() bool
	Status(limit int) rebuildverify.Status
}

// BuildProvInspector is the inbound build-provenance surface (Task 72): the
// effective configuration plus cumulative per-outcome/per-ecosystem tallies and
// the recent verification reports (present / verified / source-verified /
// mismatch). The buildprov.Service satisfies it.
type BuildProvInspector interface {
	Enabled() bool
	Status(limit int) buildprov.Status
}

// ExtensionInspector is the WASM extensibility surface (Task 59): the manager
// snapshot (per-module config, load state, and cumulative metrics) plus a
// Reload trigger for hot-reloading the modules from disk. The extension.Manager
// satisfies it.
type ExtensionInspector interface {
	Enabled() bool
	Snapshot() extension.Snapshot
	Reload(ctx context.Context) error
}

// AnomalyInspector is the behavioral-anomaly-detection surface (Task 43): the
// cumulative engine snapshot (per-level/per-detector counters, current per-scope
// standings) and the recent triggers for the trend view. The anomaly.Engine
// satisfies it.
type AnomalyInspector interface {
	Enabled() bool
	Snapshot() anomaly.Snapshot
	Recent(limit int) []anomaly.Trigger
}

// MalfeedInspector is the known-malicious-package gate surface (Task 48): the
// current status (loaded-entry counts, freshness, fail-open/closed policy), a
// search over the loaded entries, and an on-demand feed refresh. The
// malfeed.Service satisfies it.
type MalfeedInspector interface {
	Enabled() bool
	Status() malfeed.Status
	Search(query, ecosystem string, limit int) []malfeed.Entry
	Refresh(ctx context.Context) error
}

// MaturityInspector is the release-maturity / version-cooldown gate surface
// (Task 61): the effective cooldown configuration plus cumulative tallies, and
// the list of coordinates currently held in their cooldown window with the time
// remaining until each is released. The maturity.Service satisfies it.
type MaturityInspector interface {
	Enabled() bool
	Status() maturity.Status
	Cooling(limit int) []maturity.CoolingView
}

// ContinuityInspector is the maintainer/publisher continuity gate surface (Task
// 91): the effective disposition/cooldown configuration plus cumulative tallies,
// and the list of coordinates with a currently-untrusted (within-cooldown) new
// maintainer. The continuity.Service satisfies it.
type ContinuityInspector interface {
	Enabled() bool
	Status() continuity.Status
	Pending(limit int) []continuity.PendingView
}

// InstallHooksInspector is the install-script / lifecycle-hook risk gate surface
// (Task 62): the effective threshold configuration, the active rule catalog with
// per-rule finding counts, and cumulative scan/block tallies. The
// installhooks.Service satisfies it.
type InstallHooksInspector interface {
	Enabled() bool
	Status() installhooks.Status
}

// AVScanInspector exposes the antivirus content-scanning gate's status (Task
// 136) to the admin API.
type AVScanInspector interface {
	Enabled() bool
	Status() avscan.Status
}

// ContentScanInspector exposes the package-payload static content-analysis gate's
// status (Task 138) to the admin API: the effective action/threshold/ecosystem
// configuration plus cumulative scan/finding tallies.
type ContentScanInspector interface {
	Enabled() bool
	Status() contentscan.Status
}

// DepFirewallController is the dependency-firewall gate surface (Task 65): the
// effective status plus cumulative tallies, the configured rules (global and
// per-tenant), and runtime mutation — create/update/delete a rule, set the
// deny/allow default action, and import rules from a lockfile. The
// depfirewall.Service satisfies it.
type DepFirewallController interface {
	Enabled() bool
	Status() depfirewall.Status
	Rules(tenant string) []depfirewall.RuleView
	SetRule(tenant string, r depfirewall.Rule) error
	DeleteRule(tenant, ecosystem, name string) bool
	SetDefaultAction(tenant string, action depfirewall.Action) error
	ImportLockfile(tenant, format string, content []byte, replace bool) (depfirewall.ImportResult, error)
}

// SnapshotController is the organization snapshot / freeze / rollback surface
// (Task 70): list/get snapshots, capture a new one, diff two, mark a snapshot
// known-good, freeze/unfreeze the org to a snapshot, and execute an instant
// rollback to the last-known-good snapshot. The snapshot.Service satisfies it.
type SnapshotController interface {
	Enabled() bool
	List() []snapshot.Summary
	Get(id string) (*snapshot.Manifest, bool)
	Diff(fromID, toID string) (*snapshot.Diff, bool)
	Take(opts snapshot.TakeOptions) (*snapshot.Manifest, error)
	MarkGood(id string, good bool) error
	Freeze(opts snapshot.FreezeOptions) (snapshot.FreezeState, error)
	Unfreeze(by string) (snapshot.FreezeState, error)
	Rollback(by, reason string) (snapshot.FreezeState, *snapshot.Manifest, error)
	FreezeState() snapshot.FreezeState
	Metrics() snapshot.Metrics
}

// LockdownController is the emergency-lockdown / global kill-switch surface (Task
// 74): the current incident posture (mode, reason, incident ID, TTL remaining,
// targets) plus the two operator transitions — engage a freeze/strict/targeted-
// block lockdown, and clear it. The lockdown.Service satisfies it.
type LockdownController interface {
	Enabled() bool
	Status() lockdown.Status
	Engage(ctx context.Context, in lockdown.EngageInput) (lockdown.Status, error)
	Clear(ctx context.Context, in lockdown.ClearInput) (lockdown.Status, error)
	Metrics() lockdown.Snapshot
}

// GitopsController is the GitOps policy & config synchronization surface (Task 93):
// read the reconciliation status (last commit, drift, pending change, apply
// history), force an immediate sync, and roll back to the last-known-good applied
// revision. The gitops.Service satisfies it.
type GitopsController interface {
	Enabled() bool
	Status() gitops.Status
	Sync(ctx context.Context, by string) (gitops.Outcome, error)
	Rollback(ctx context.Context, by, reason string) (gitops.RollbackResult, error)
	Metrics() gitops.Snapshot
}

// TracingInspector is the distributed-tracing surface (Task 41): the effective
// tracing configuration plus the live OTLP exporter counters (spans started,
// sampled, exported, dropped). The wiring adapts the tracing.Provider to it.
type TracingInspector interface {
	Status() tracing.Status
}

// ProvenanceLister optionally lists the established package->commit links joined
// with their source commit's scan verdict, for the consumed-packages view. The
// provenance.Service satisfies it.
type ProvenanceLister interface {
	LinksWithVerdicts(ctx context.Context) ([]*provenance.EnrichedLink, error)
}

// ProvgraphInspector is the supply-chain graph surface (Task 33): graph-size
// stats, a full JSON export for the force-directed visualization and offline
// analysis, and the blast-radius / reverse-dependency / path-to-commit read
// queries. The provgraph.Service satisfies it.
type ProvgraphInspector interface {
	Snapshot() provgraph.Snapshot
	Export() provgraph.Document
	BlastRadius(kind provgraph.SeedKind, id string) (provgraph.BlastResult, error)
	ReverseDependencies(ecosystem, name, version string) (provgraph.DepResult, error)
	PathToCommit(ecosystem, name, version string) (provgraph.PathResult, error)
}

// BackupController is the disaster-recovery backup surface (Task 44): the last
// backup's age/success status (the RPO signal) and a way to trigger an on-demand
// backup into the configured destination. The backup.Scheduler satisfies it.
type BackupController interface {
	Enabled() bool
	Status() backup.Snapshot
	RunOnce(ctx context.Context) error
}

// CoordinationInspector is the HA distributed-coordination surface (Task 56): the
// local per-job leadership/lease state (for this replica) and the observed
// cross-replica leaseholders read live from the coordination backend, so an
// operator can confirm exactly one replica leads each scheduled job. The
// coord.Service satisfies it.
type CoordinationInspector interface {
	Enabled() bool
	NodeID() string
	Snapshot() coord.Snapshot
	Leaseholders(ctx context.Context) []coord.Leaseholder
}

// Info is a static, read-only snapshot of the effective configuration and
// policy. It is supplied at construction so the admin API can present the
// operator with what the proxy is enforcing without reaching back into config.
type Info struct {
	Version                   string `json:"version"`
	CacheBackend              string `json:"cacheBackend"`
	CacheSealed               bool   `json:"cacheSealed"`
	ScanningEnabled           bool   `json:"scanningEnabled"`
	ScanProvider              string `json:"scanProvider,omitempty"`
	ScanFailOn                string `json:"scanFailOn,omitempty"`
	ProvenanceEnabled         bool   `json:"provenanceEnabled"`
	ProvenanceRequireAttested bool   `json:"provenanceRequireAttested"`
	VulnEnabled               bool   `json:"vulnEnabled"`
	VulnScanner               string `json:"vulnScanner,omitempty"`
	VulnAction                string `json:"vulnAction,omitempty"`
	VulnFailSeverity          string `json:"vulnFailSeverity,omitempty"`
	LicenseEnabled            bool   `json:"licenseEnabled"`
	LicenseAction             string `json:"licenseAction,omitempty"`
	// Crypto describes the active FIPS 140-3 cryptographic operating mode (Task
	// 120), so operators can confirm the enforced posture from the admin API.
	Crypto    CryptoInfo     `json:"crypto"`
	Upstreams []UpstreamInfo `json:"upstreams,omitempty"`
}

// CryptoInfo is a read-only snapshot of the proxy's cryptographic operating
// mode, surfaced via the admin API (Task 120).
type CryptoInfo struct {
	// Mode is "fips" when approved-crypto enforcement is enabled, else "standard".
	Mode string `json:"mode"`
	// FIPSEnabled reports whether FIPS enforcement (fips.enabled) is on.
	FIPSEnabled bool `json:"fipsEnabled"`
	// ModuleActive reports whether the Go FIPS 140-3 cryptographic module is
	// active in the process (built with GOFIPS140, run with GODEBUG=fips140=on).
	ModuleActive bool `json:"moduleActive"`
	// ModuleEnforced reports whether the module is in enforcing ("only") mode.
	ModuleEnforced bool `json:"moduleEnforced"`
	// Module is the validated module name + version, e.g.
	// "Go Cryptographic Module v1.0.0".
	Module string `json:"module,omitempty"`
	// BuildVariant is the compile-time crypto build variant: "fips" or "standard".
	BuildVariant string `json:"buildVariant"`
}

// UpstreamInfo describes a configured upstream for the policy/overview views.
type UpstreamInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Options configures a Server. Cache is required; the rest are optional.
type Options struct {
	Logger          *slog.Logger
	PathPrefix      string // e.g. "/admin"; defaults to "/admin"
	Token           string // optional bearer token guarding the surface
	Cache           CacheInspector
	CacheMetrics    CacheMetricsSource
	Scan            ScanInspector
	CommitScan      CommitScanController
	Provenance      provenance.Resolver
	ProvenanceLinks ProvenanceLister
	Provgraph       ProvgraphInspector
	Vulnerabilities VulnInspector
	License         LicenseInspector
	Rescan          RescanInspector
	Sigverify       SigverifyInspector
	Notify          NotifyInspector
	RateLimit       RateLimitInspector
	Coalesce        CoalesceInspector
	CacheGC         CacheGCInspector
	Integrity       IntegrityInspector
	Compaction      CompactionInspector
	Encryption      EncryptionInspector
	Tiering         TieringInspector
	// CacheIntegrityVerifyOnServe reports whether read-time (serve-path)
	// verification is enabled, for display in the integrity status endpoint.
	CacheIntegrityVerifyOnServe bool
	Audit                       AuditInspector
	PolicyEngine                PolicyEngineInspector
	Compliance                  ComplianceInspector
	RiskScore                   RiskScoreInspector
	RepoScore                   RepoScoreInspector
	SbomDiff                    SbomDiffInspector
	Remediation                 RemediationInspector
	RebuildVerify               RebuildVerifyInspector
	BuildProv                   BuildProvInspector
	Extension                   ExtensionInspector
	Anomaly                     AnomalyInspector
	Approvals                   ApprovalsInspector
	Malfeed                     MalfeedInspector
	Maturity                    MaturityInspector
	Continuity                  ContinuityInspector
	DepFirewall                 DepFirewallController
	Snapshot                    SnapshotController
	Lockdown                    LockdownController
	Gitops                      GitopsController
	Prewarm                     PrewarmController
	SBOMExport                  SBOMExportController
	InstallHooks                InstallHooksInspector
	AVScan                      AVScanInspector
	ContentScan                 ContentScanInspector
	LLMPkgScan                  LLMPkgScanInspector
	UpstreamPool                UpstreamPoolInspector
	Egress                      EgressInspector
	Backup                      BackupController
	Tracing                     TracingInspector
	Findings                    FindingsInspector
	SimReplay                   SimReplayInspector
	Attest                      AttestInspector
	Coordination                CoordinationInspector
	KeyRotation                 KeyRotationInspector
	SecOps                      SecOpsInspector
	QueryAPI                    QueryAPIInspector
	MCP                         MCPInspector
	GRPC                        GRPCHandler
	Timeline                    TimelineInspector
	Dossier                     DossierInspector
	Metering                    MeteringInspector
	DownloadLog                 DownloadLogInspector
	// Repos is the repository registry (Task 180): tracked repositories,
	// their tag histories and pinned releases. Nil when disabled.
	Repos     RepoRegistry
	Intercept InterceptInspector
	UserLinks UserLinksManager
	Config    ConfigInspector
	Presets   PresetController
	VEXExport VEXExporter
	Backends  BackendLister
	Info      Info

	// Profiling, when Enabled, exposes the net/http/pprof and runtime/trace
	// execution-trace endpoints under <prefix>/api/debug/pprof/, guarded by the
	// same authentication and RBAC as the rest of the admin API (the operate
	// capability). Off by default.
	Profiling ProfilingOptions

	// AdminAuth, when set, enforces OIDC/OAuth2 SSO + fine-grained RBAC across
	// the admin surface, superseding the legacy static Token. When nil the server
	// falls back to the Token check (or open access if Token is also empty).
	AdminAuth *adminauth.Service
	// AuditLog records authenticated admin mutations so they are attributable to
	// a real identity. Optional.
	AuditLog AdminEventLogger

	// WebAuthn, when set and enforcing, gates the most sensitive admin mutations
	// (break-glass approvals, lockdown toggles, preset apply, key rotation) behind
	// a fresh FIDO2 passkey step-up assertion, and serves the enrolment/assertion
	// ceremonies (Task 161). Requires AdminAuth so each ceremony is bound to a real
	// identity. Optional; nil disables step-up entirely.
	WebAuthn WebAuthnController
}

// Server serves the admin API and dashboard.
type Server struct {
	opts   Options
	prefix string
	logger *slog.Logger
	mux    *http.ServeMux
}

// New constructs a Server. It returns an error if no cache inspector is
// supplied, since cache inspection is the minimum useful surface.
func New(opts Options) (*Server, error) {
	if opts.Cache == nil {
		return nil, errors.New("admin: a CacheInspector is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	prefix := strings.TrimRight(opts.PathPrefix, "/")
	if prefix == "" {
		prefix = "/admin"
	}
	s := &Server{opts: opts, prefix: prefix, logger: opts.Logger}
	// Configure the process-wide block/mutex profilers before wiring routes so
	// the corresponding pprof endpoints return data once mounted.
	opts.Profiling.applyProfilingRates()
	s.mux = s.routes()
	return s, nil
}

// Prefix returns the path prefix the server is mounted under (no trailing slash).
func (s *Server) Prefix() string { return s.prefix }

// Handler returns the http.Handler for the admin surface. When an adminauth
// Service is configured it enforces OIDC/OAuth2 SSO + RBAC; otherwise it falls
// back to the legacy static bearer-token check.
func (s *Server) Handler() http.Handler {
	if s.opts.AdminAuth != nil {
		return s.rbac(s.opts.AdminAuth, s.mux)
	}
	return s.authenticated(s.mux)
}

// routes wires the API and static dashboard under the configured prefix. More
// specific API patterns take precedence over the static catch-all by virtue of
// net/http.ServeMux's longest-match rule.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+s.prefix+"/api/overview", s.handleOverview)
	mux.HandleFunc("GET "+s.prefix+"/api/policy", s.handlePolicy)
	mux.HandleFunc("GET "+s.prefix+"/api/cache", s.handleCacheList)
	mux.HandleFunc("GET "+s.prefix+"/api/cache/entry", s.handleCacheEntry)
	mux.HandleFunc("DELETE "+s.prefix+"/api/cache/entry", s.handleCacheDelete)
	mux.HandleFunc("GET "+s.prefix+"/api/scans", s.handleScanList)
	mux.HandleFunc("GET "+s.prefix+"/api/scans/entry", s.handleScanEntry)
	mux.HandleFunc("GET "+s.prefix+"/api/commitscan", s.handleCommitScanStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/commitscan/budget", s.handleCommitScanSetBudget)
	mux.HandleFunc("POST "+s.prefix+"/api/commitscan/prune", s.handleCommitScanPrune)
	mux.HandleFunc("GET "+s.prefix+"/api/provenance", s.handleProvenance)
	mux.HandleFunc("GET "+s.prefix+"/api/provenance/links", s.handleProvenanceLinks)
	mux.HandleFunc("GET "+s.prefix+"/api/provgraph", s.handleProvgraphStats)
	mux.HandleFunc("GET "+s.prefix+"/api/provgraph/export", s.handleProvgraphExport)
	mux.HandleFunc("GET "+s.prefix+"/api/provgraph/blast", s.handleProvgraphBlast)
	mux.HandleFunc("GET "+s.prefix+"/api/provgraph/reverse", s.handleProvgraphReverse)
	mux.HandleFunc("GET "+s.prefix+"/api/provgraph/path", s.handleProvgraphPath)
	mux.HandleFunc("GET "+s.prefix+"/api/vulns", s.handleVulnList)
	mux.HandleFunc("GET "+s.prefix+"/api/vulns/entry", s.handleVulnEntry)
	mux.HandleFunc("GET "+s.prefix+"/api/sbom", s.handleSBOM)
	mux.HandleFunc("GET "+s.prefix+"/api/rescan", s.handleRescanStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/rescan", s.handleRescanTrigger)
	mux.HandleFunc("GET "+s.prefix+"/api/quarantine", s.handleQuarantineList)
	mux.HandleFunc("DELETE "+s.prefix+"/api/quarantine/entry", s.handleQuarantineRelease)
	mux.HandleFunc("GET "+s.prefix+"/api/vex", s.handleVEXList)
	mux.HandleFunc("GET "+s.prefix+"/api/vex/export", s.handleVEXExport)
	mux.HandleFunc("GET "+s.prefix+"/api/licenses", s.handleLicenseStatus)
	mux.HandleFunc("GET "+s.prefix+"/api/sigverify", s.handleSigverifyList)
	mux.HandleFunc("GET "+s.prefix+"/api/sigverify/entry", s.handleSigverifyEntry)
	mux.HandleFunc("GET "+s.prefix+"/api/notify", s.handleNotifyStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/notify/test", s.handleNotifyTest)
	mux.HandleFunc("GET "+s.prefix+"/api/ratelimit", s.handleRateLimitStatus)
	mux.HandleFunc("PUT "+s.prefix+"/api/ratelimit/policy", s.handleRateLimitSetPolicy)
	mux.HandleFunc("GET "+s.prefix+"/api/coalesce", s.handleCoalesceStatus)
	mux.HandleFunc("DELETE "+s.prefix+"/api/coalesce/negative", s.handleCoalescePurge)
	mux.HandleFunc("GET "+s.prefix+"/api/cachegc", s.handleCacheGCStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/cachegc/run", s.handleCacheGCRun)
	mux.HandleFunc("GET "+s.prefix+"/api/integrity", s.handleIntegrityStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/integrity/scan", s.handleIntegrityScan)
	mux.HandleFunc("GET "+s.prefix+"/api/cache/compaction", s.handleCacheCompaction)
	mux.HandleFunc("GET "+s.prefix+"/api/cache/encryption", s.handleCacheEncryption)
	mux.HandleFunc("POST "+s.prefix+"/api/cache/encryption/rotate", s.handleCacheEncryptionRotate)
	mux.HandleFunc("GET "+s.prefix+"/api/cache/tiering", s.handleCacheTiering)
	mux.HandleFunc("POST "+s.prefix+"/api/cache/tiering/sweep", s.handleCacheTieringSweep)
	mux.HandleFunc("GET "+s.prefix+"/api/keys/status", s.handleKeysStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/keys/rotate", s.handleKeysRotate)
	mux.HandleFunc("GET "+s.prefix+"/api/webauthn", s.handleWebAuthnStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
	mux.HandleFunc("POST "+s.prefix+"/api/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
	mux.HandleFunc("POST "+s.prefix+"/api/webauthn/assert/begin", s.handleWebAuthnAssertBegin)
	mux.HandleFunc("POST "+s.prefix+"/api/webauthn/assert/finish", s.handleWebAuthnAssertFinish)
	mux.HandleFunc("DELETE "+s.prefix+"/api/webauthn/credential", s.handleWebAuthnRemoveCredential)
	mux.HandleFunc("GET "+s.prefix+"/api/policyengine", s.handlePolicyEngineStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/policyengine/test", s.handlePolicyEngineTest)
	mux.HandleFunc("POST "+s.prefix+"/api/policyengine/reload", s.handlePolicyEngineReload)
	mux.HandleFunc("GET "+s.prefix+"/api/audit", s.handleAuditStatus)
	mux.HandleFunc("GET "+s.prefix+"/api/audit/checkpoint", s.handleAuditCheckpoint)
	mux.HandleFunc("GET "+s.prefix+"/api/audit/proof", s.handleAuditInclusionProof)
	mux.HandleFunc("GET "+s.prefix+"/api/audit/consistency", s.handleAuditConsistencyProof)
	mux.HandleFunc("GET "+s.prefix+"/api/compliance", s.handleCompliance)
	mux.HandleFunc("POST "+s.prefix+"/api/compliance/refresh", s.handleComplianceRefresh)
	mux.HandleFunc("GET "+s.prefix+"/api/compliance/report.html", s.handleComplianceHTML)
	mux.HandleFunc("GET "+s.prefix+"/api/compliance/export", s.handleComplianceExport)
	mux.HandleFunc("GET "+s.prefix+"/api/backup", s.handleBackupStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/backup/run", s.handleBackupRun)
	mux.HandleFunc("GET "+s.prefix+"/api/riskscore", s.handleRiskScore)
	mux.HandleFunc("GET "+s.prefix+"/api/reposcore", s.handleRepoScore)
	mux.HandleFunc("GET "+s.prefix+"/api/sbomdiff", s.handleSbomDiff)
	mux.HandleFunc("GET "+s.prefix+"/api/sbomdiff/diff", s.handleSbomDiffDiff)
	mux.HandleFunc("GET "+s.prefix+"/api/remediation/advise", s.handleRemediationAdvise)
	mux.HandleFunc("GET "+s.prefix+"/api/rebuildverify", s.handleRebuildVerify)
	mux.HandleFunc("GET "+s.prefix+"/api/buildprov", s.handleBuildProv)
	mux.HandleFunc("GET "+s.prefix+"/api/extensions", s.handleExtensions)
	mux.HandleFunc("POST "+s.prefix+"/api/extensions/reload", s.handleExtensionsReload)
	mux.HandleFunc("GET "+s.prefix+"/api/anomaly", s.handleAnomaly)
	mux.HandleFunc("GET "+s.prefix+"/api/approvals", s.handleApprovalsList)
	mux.HandleFunc("POST "+s.prefix+"/api/approvals/approve", s.handleApprovalApprove)
	mux.HandleFunc("POST "+s.prefix+"/api/approvals/deny", s.handleApprovalDeny)
	mux.HandleFunc("GET "+s.prefix+"/api/malfeed", s.handleMalfeed)
	mux.HandleFunc("POST "+s.prefix+"/api/malfeed/refresh", s.handleMalfeedRefresh)
	mux.HandleFunc("GET "+s.prefix+"/api/maturity", s.handleMaturity)
	mux.HandleFunc("GET "+s.prefix+"/api/continuity", s.handleContinuity)
	mux.HandleFunc("GET "+s.prefix+"/api/depfirewall", s.handleDepFirewall)
	mux.HandleFunc("POST "+s.prefix+"/api/depfirewall/rules", s.handleDepFirewallSetRule)
	mux.HandleFunc("POST "+s.prefix+"/api/depfirewall/rules/delete", s.handleDepFirewallDeleteRule)
	mux.HandleFunc("POST "+s.prefix+"/api/depfirewall/default", s.handleDepFirewallDefault)
	mux.HandleFunc("POST "+s.prefix+"/api/depfirewall/import", s.handleDepFirewallImport)
	mux.HandleFunc("GET "+s.prefix+"/api/snapshots", s.handleSnapshotList)
	mux.HandleFunc("GET "+s.prefix+"/api/snapshots/get", s.handleSnapshotGet)
	mux.HandleFunc("GET "+s.prefix+"/api/snapshots/diff", s.handleSnapshotDiff)
	mux.HandleFunc("POST "+s.prefix+"/api/snapshots/create", s.handleSnapshotCreate)
	mux.HandleFunc("POST "+s.prefix+"/api/snapshots/markgood", s.handleSnapshotMarkGood)
	mux.HandleFunc("POST "+s.prefix+"/api/snapshots/freeze", s.handleSnapshotFreeze)
	mux.HandleFunc("POST "+s.prefix+"/api/snapshots/unfreeze", s.handleSnapshotUnfreeze)
	mux.HandleFunc("POST "+s.prefix+"/api/snapshots/rollback", s.handleSnapshotRollback)
	mux.HandleFunc("GET "+s.prefix+"/api/lockdown", s.handleLockdown)
	mux.HandleFunc("POST "+s.prefix+"/api/lockdown/engage", s.handleLockdownEngage)
	mux.HandleFunc("POST "+s.prefix+"/api/lockdown/clear", s.handleLockdownClear)
	mux.HandleFunc("GET "+s.prefix+"/api/gitops", s.handleGitops)
	mux.HandleFunc("POST "+s.prefix+"/api/gitops/sync", s.handleGitopsSync)
	mux.HandleFunc("POST "+s.prefix+"/api/gitops/rollback", s.handleGitopsRollback)
	mux.HandleFunc("GET "+s.prefix+"/api/prewarm", s.handlePrewarm)
	mux.HandleFunc("POST "+s.prefix+"/api/prewarm/run", s.handlePrewarmRun)
	mux.HandleFunc("GET "+s.prefix+"/api/sbomexport", s.handleSBOMExport)
	mux.HandleFunc("POST "+s.prefix+"/api/sbomexport/run", s.handleSBOMExportRun)
	mux.HandleFunc("GET "+s.prefix+"/api/installhooks", s.handleInstallHooks)
	mux.HandleFunc("GET "+s.prefix+"/api/avscan", s.handleAVScan)
	mux.HandleFunc("GET "+s.prefix+"/api/contentscan", s.handleContentScan)
	mux.HandleFunc("GET "+s.prefix+"/api/llmpkgscan", s.handleLLMPkgScan)
	mux.HandleFunc("GET "+s.prefix+"/api/llmpkgscan/verdicts", s.handleLLMPkgScanVerdicts)
	mux.HandleFunc("GET "+s.prefix+"/api/tracing", s.handleTracing)
	mux.HandleFunc("GET "+s.prefix+"/api/findings", s.handleFindingsList)
	mux.HandleFunc("GET "+s.prefix+"/api/findings/sarif", s.handleFindingsSARIF)
	mux.HandleFunc("GET "+s.prefix+"/api/simreplay", s.handleSimReplayStatus)
	mux.HandleFunc("GET "+s.prefix+"/api/simreplay/capture", s.handleSimReplayCapture)
	mux.HandleFunc("POST "+s.prefix+"/api/simreplay/simulate", s.handleSimReplaySimulate)
	mux.HandleFunc("POST "+s.prefix+"/api/simreplay/reset", s.handleSimReplayReset)
	mux.HandleFunc("GET "+s.prefix+"/api/attest", s.handleAttestList)
	mux.HandleFunc("GET "+s.prefix+"/api/attest/bundle", s.handleAttestBundle)
	mux.HandleFunc("GET "+s.prefix+"/api/attest/referrers", s.handleAttestReferrers)
	mux.HandleFunc("GET "+s.prefix+"/api/coordination", s.handleCoordination)
	mux.HandleFunc("GET "+s.prefix+"/api/secops/summary", s.handleSecOpsSummary)
	mux.HandleFunc("GET "+s.prefix+"/api/secops/stream", s.handleSecOpsStream)
	mux.HandleFunc("POST "+s.prefix+"/api/query", s.handleQueryRun)
	mux.HandleFunc("GET "+s.prefix+"/api/query/schema", s.handleQuerySchema)
	mux.HandleFunc("GET "+s.prefix+"/api/query/metrics", s.handleQueryMetrics)
	mux.HandleFunc("POST "+s.prefix+"/api/mcp", s.handleMCP)
	mux.HandleFunc("GET "+s.prefix+"/api/mcp", s.handleMCPInfo)
	// Read-only gRPC/Connect security API (Task 159). Mounted as a subtree under
	// /api/grpc so Connect's "/pkg.Service/Method" paths inherit the admin RBAC.
	s.registerGRPC(mux)
	// Forensic incident timeline (Task 77).
	mux.HandleFunc("GET "+s.prefix+"/api/timeline", s.handleTimeline)
	mux.HandleFunc("GET "+s.prefix+"/api/dossier", s.handleDossier)
	// Per-tenant usage metering & chargeback (Task 84).
	mux.HandleFunc("GET "+s.prefix+"/api/metering", s.handleMeteringStatus)
	mux.HandleFunc("GET "+s.prefix+"/api/metering/usage", s.handleMeteringUsage)
	// Download log (Task 176): which package was downloaded from which address.
	mux.HandleFunc("GET "+s.prefix+"/api/downloads", s.handleDownloads)
	mux.HandleFunc("GET "+s.prefix+"/api/downloads/summary", s.handleDownloadsSummary)
	// Repository registry (Task 180): tag tracking and release pinning.
	mux.HandleFunc("GET "+s.prefix+"/api/repos", s.handleReposList)
	mux.HandleFunc("POST "+s.prefix+"/api/repos", s.handleReposAdd)
	mux.HandleFunc("GET "+s.prefix+"/api/repos/show", s.handleReposShow)
	mux.HandleFunc("GET "+s.prefix+"/api/repos/tags", s.handleReposTags)
	mux.HandleFunc("GET "+s.prefix+"/api/repos/verify", s.handleReposVerify)
	mux.HandleFunc("GET "+s.prefix+"/api/repos/releases", s.handleReposReleases)
	mux.HandleFunc("GET "+s.prefix+"/api/repos/lookup", s.handleReposLookup)
	mux.HandleFunc("POST "+s.prefix+"/api/repos/sync", s.handleReposSync)
	mux.HandleFunc("POST "+s.prefix+"/api/repos/pin", s.handleReposPin)
	mux.HandleFunc("POST "+s.prefix+"/api/repos/remove", s.handleReposRemove)
	// TLS interception and NAT mode (Task 172): the listeners, the routing
	// table, the hostnames to send to the proxy, and the CA to trust.
	mux.HandleFunc("GET "+s.prefix+"/api/intercept", s.handleIntercept)
	mux.HandleFunc("GET "+s.prefix+"/api/intercept/ca.crt", s.handleInterceptCA)
	// Personal cache links (Task 177): who holds which link, and the means to
	// end one.
	mux.HandleFunc("GET "+s.prefix+"/api/userlinks", s.handleUserLinks)
	mux.HandleFunc("POST "+s.prefix+"/api/userlinks/revoke", s.handleUserLinksRevoke)
	mux.HandleFunc("POST "+s.prefix+"/api/userlinks/issue", s.handleUserLinksIssue)
	// Configuration validation, preflight & drift detection (Task 85).
	mux.HandleFunc("GET "+s.prefix+"/api/config/validate", s.handleConfigValidate)
	mux.HandleFunc("POST "+s.prefix+"/api/config/validate", s.handleConfigValidate)
	mux.HandleFunc("GET "+s.prefix+"/api/config/drift", s.handleConfigDrift)
	// Curated compliance policy presets (Task 88).
	mux.HandleFunc("GET "+s.prefix+"/api/presets", s.handlePresetsList)
	mux.HandleFunc("GET "+s.prefix+"/api/presets/diff", s.handlePresetsDiff)
	mux.HandleFunc("POST "+s.prefix+"/api/presets/apply", s.handlePresetsApply)
	mux.HandleFunc("GET "+s.prefix+"/api/upstreams", s.handleUpstreamPoolStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/upstreams/drain", s.handleUpstreamPoolDrain)
	mux.HandleFunc("POST "+s.prefix+"/api/upstreams/circuit", s.handleUpstreamPoolCircuit)
	// SSRF / outbound-egress guard (Task 89).
	mux.HandleFunc("GET "+s.prefix+"/api/egress", s.handleEgressStatus)
	mux.HandleFunc("POST "+s.prefix+"/api/egress/test", s.handleEgressTest)
	mux.HandleFunc("POST "+s.prefix+"/api/egress/allowlist", s.handleEgressAllowlist)
	// Runtime profiling (Task 105): net/http/pprof + execution-trace capture.
	// Mounted under the /api/ subtree so it inherits the admin auth/RBAC
	// middleware; registered only when explicitly enabled.
	if s.opts.Profiling.Enabled {
		s.registerProfiling(mux)
	}
	// OIDC/OAuth2 SSO endpoints (registered only when adminauth is configured).
	// They sit outside the /api/ prefix so the RBAC middleware lets them through
	// to guard themselves.
	if s.opts.AdminAuth != nil {
		mux.HandleFunc("GET "+s.prefix+"/auth/userinfo", s.opts.AdminAuth.HandleUserinfo)
		if s.opts.AdminAuth.OIDCEnabled() {
			mux.HandleFunc("GET "+s.prefix+"/auth/login", s.opts.AdminAuth.HandleLogin)
			mux.HandleFunc("GET "+s.prefix+"/auth/callback", s.opts.AdminAuth.HandleCallback)
			mux.HandleFunc(s.prefix+"/auth/logout", s.opts.AdminAuth.HandleLogout)
		}
	}
	// Static dashboard (and redirect of the bare prefix to its trailing-slash
	// form so relative API fetches resolve correctly).
	mux.HandleFunc(s.prefix, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.prefix+"/", http.StatusMovedPermanently)
	})
	mux.HandleFunc(s.prefix+"/", s.handleStatic)
	return mux
}

// authenticated wraps next with constant-time bearer-token checking when a
// token is configured. Only the JSON API is guarded; the static dashboard
// assets are left open (they carry no secrets) so a browser can load the page
// and then prompt the operator for a token, which the dashboard sends as a
// bearer header on its API calls. With no token the whole surface is open
// (trusted-network mode).
func (s *Server) authenticated(next http.Handler) http.Handler {
	token := s.opts.Token
	if token == "" {
		return next
	}
	apiPrefix := s.prefix + "/api/"
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			got := []byte(r.Header.Get("Authorization"))
			if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="pullthrough-admin"`)
				s.writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	resp := overviewResponse{
		Info:     s.opts.Info,
		Backends: s.backendNames(),
	}
	if s.opts.CacheMetrics != nil {
		m := s.opts.CacheMetrics.Metrics()
		resp.Cache = &cacheMetricsDTO{
			Hits:         m.Hits,
			Misses:       m.Misses,
			HitRatio:     m.HitRatio(),
			Loads:        m.Loads,
			Puts:         m.Puts,
			Evictions:    m.Evictions,
			Expired:      m.Expired,
			Errors:       m.Errors,
			BytesWritten: m.BytesWritten,
			BytesServed:  m.BytesServed,
		}
	}
	if entries, err := s.opts.Cache.Entries(r.Context()); err == nil {
		var total int64
		for _, e := range entries {
			total += e.Size
		}
		resp.CacheEntryCount = len(entries)
		resp.CacheTotalBytes = total
	}
	if s.opts.Scan != nil {
		resp.Scan = &scanSummaryDTO{
			QueueDepth: s.opts.Scan.QueueDepth(),
			Pending:    s.opts.Scan.PendingCount(),
		}
		if verdicts, err := s.opts.Scan.Verdicts(r.Context()); err == nil {
			resp.Scan.Total = len(verdicts)
			for _, v := range verdicts {
				if v.Malicious {
					resp.Scan.Malicious++
				}
			}
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.opts.Info)
}

func (s *Server) handleCacheList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.opts.Cache.Entries(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing cache: "+err.Error())
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	items := make([]cacheEntryDTO, 0, len(entries))
	for _, e := range entries {
		dto := cacheEntryToDTO(e)
		if q != "" && !strings.Contains(strings.ToLower(dto.Key), q) &&
			!strings.Contains(strings.ToLower(dto.Origin), q) {
			continue
		}
		items = append(items, dto)
	}
	// Most-recently-modified first for a stable, useful ordering.
	sort.Slice(items, func(i, j int) bool { return items[i].ModTime.After(items[j].ModTime) })

	total := len(items)
	if limit := parseLimit(r, 200); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	s.writeJSON(w, http.StatusOK, cacheListResponse{Total: total, Returned: len(items), Items: items})
}

func (s *Server) handleCacheEntry(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		s.writeError(w, http.StatusBadRequest, "missing key parameter")
		return
	}
	stat, err := s.opts.Cache.Stat(r.Context(), key)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "no cache entry for key")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, cacheEntryToDTO(*stat))
}

func (s *Server) handleCacheDelete(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		s.writeError(w, http.StatusBadRequest, "missing key parameter")
		return
	}
	if err := s.opts.Cache.Delete(r.Context(), key); err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "no cache entry for key")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("admin deleted cache entry", "key", key)
	s.writeJSON(w, http.StatusOK, map[string]string{"deleted": key})
}

func (s *Server) handleScanList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Scan == nil {
		s.writeJSON(w, http.StatusOK, scanListResponse{Enabled: false})
		return
	}
	verdicts, err := s.opts.Scan.Verdicts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing verdicts: "+err.Error())
		return
	}
	items := make([]scanSummaryItemDTO, 0, len(verdicts))
	for _, v := range verdicts {
		items = append(items, scanVerdictToSummary(v))
	}
	// Highest risk first; ties broken by most recent scan.
	sort.Slice(items, func(i, j int) bool {
		if items[i].RiskScore != items[j].RiskScore {
			return items[i].RiskScore > items[j].RiskScore
		}
		return items[i].ScannedAt.After(items[j].ScannedAt)
	})
	total := len(items)
	if limit := parseLimit(r, 200); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	s.writeJSON(w, http.StatusOK, scanListResponse{
		Enabled:    true,
		Total:      total,
		Returned:   len(items),
		QueueDepth: s.opts.Scan.QueueDepth(),
		Items:      items,
	})
}

func (s *Server) handleScanEntry(w http.ResponseWriter, r *http.Request) {
	if s.opts.Scan == nil {
		s.writeError(w, http.StatusNotFound, "commit scanning is not enabled")
		return
	}
	sha := r.URL.Query().Get("sha")
	if sha == "" {
		s.writeError(w, http.StatusBadRequest, "missing sha parameter")
		return
	}
	v, err := s.opts.Scan.Verdict(r.Context(), sha)
	if err != nil {
		if errors.Is(err, commit.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "no verdict for commit (it may not have been scanned yet)")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleProvenance(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provenance == nil {
		s.writeError(w, http.StatusNotFound, "provenance resolution is not enabled")
		return
	}
	q := r.URL.Query()
	art := provenance.Artifact{
		Ecosystem: q.Get("ecosystem"),
		Name:      q.Get("name"),
		Version:   q.Get("version"),
		Digest:    q.Get("digest"),
	}
	if art.Name == "" && art.Digest == "" {
		s.writeError(w, http.StatusBadRequest, "provide at least a name or digest")
		return
	}
	link, err := s.opts.Provenance.Resolve(r.Context(), art)
	if err != nil {
		if errors.Is(err, provenance.ErrNoProvenance) {
			s.writeError(w, http.StatusNotFound, "no provenance association found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, provenanceLinkToDTO(link))
}

// handleProvenanceLinks lists the established package->commit associations joined
// with their source commit's scan verdict — the "what have we consumed, where did
// it come from, and is it risky" view.
func (s *Server) handleProvenanceLinks(w http.ResponseWriter, r *http.Request) {
	if s.opts.ProvenanceLinks == nil {
		s.writeJSON(w, http.StatusOK, provenanceLinksResponse{Enabled: false})
		return
	}
	links, err := s.opts.ProvenanceLinks.LinksWithVerdicts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing provenance links: "+err.Error())
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	items := make([]enrichedLinkDTO, 0, len(links))
	for _, l := range links {
		dto := enrichedLinkToDTO(l)
		if q != "" && !strings.Contains(strings.ToLower(dto.Name), q) &&
			!strings.Contains(strings.ToLower(dto.RepositoryURL), q) {
			continue
		}
		items = append(items, dto)
	}
	total := len(items)
	if limit := parseLimit(r, 200); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	s.writeJSON(w, http.StatusOK, provenanceLinksResponse{
		Enabled: true, Total: total, Returned: len(items), Items: items,
	})
}

// handleVulnList lists the cached vulnerability scan reports (most-recent first),
// with optional substring filtering by package name or advisory id.
func (s *Server) handleVulnList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil {
		s.writeJSON(w, http.StatusOK, vulnListResponse{Enabled: false})
		return
	}
	reports := s.opts.Vulnerabilities.Reports()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	items := make([]vulnSummaryDTO, 0, len(reports))
	for _, rep := range reports {
		dto := vulnReportToSummary(rep)
		if q != "" && !strings.Contains(strings.ToLower(dto.Package), q) &&
			!strings.Contains(strings.ToLower(dto.Digest), q) {
			continue
		}
		items = append(items, dto)
	}
	total := len(items)
	if limit := parseLimit(r, 200); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	m := s.opts.Vulnerabilities.Metrics()
	s.writeJSON(w, http.StatusOK, vulnListResponse{
		Enabled:  true,
		Total:    total,
		Returned: len(items),
		Metrics:  &m,
		Items:    items,
	})
}

// handleVulnEntry returns the full scan report (including findings) for a digest.
func (s *Server) handleVulnEntry(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil {
		s.writeError(w, http.StatusNotFound, "vulnerability scanning is not enabled")
		return
	}
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		s.writeError(w, http.StatusBadRequest, "missing digest parameter")
		return
	}
	report, ok := s.opts.Vulnerabilities.Report(digest)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no scan report for digest (the artifact may not have been pulled yet)")
		return
	}
	s.writeJSON(w, http.StatusOK, report)
}

// handleSBOM serves the CycloneDX SBOM for an artifact identified by content
// digest. The response is the raw CycloneDX 1.5 JSON document so it can be fed
// directly to downstream SBOM tooling.
func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil {
		s.writeError(w, http.StatusNotFound, "vulnerability scanning is not enabled")
		return
	}
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		s.writeError(w, http.StatusBadRequest, "missing digest parameter")
		return
	}
	report, ok := s.opts.Vulnerabilities.Report(digest)
	if !ok || report.SBOM == nil {
		s.writeError(w, http.StatusNotFound, "no SBOM for digest (the artifact may not have been scanned yet)")
		return
	}
	// Emit the CycloneDX document directly with its conventional media type.
	s.writeCycloneDX(w, report.SBOM)
}

// rescanStatusResponse reports the continuous re-scan subsystem's state and the
// artifacts whose risk changed in the most recent sweep.
type rescanStatusResponse struct {
	Enabled     bool                    `json:"enabled"`
	IntervalSec float64                 `json:"intervalSeconds"`
	Last        *vulnscan.RescanSummary `json:"last,omitempty"`
	Changes     []vulnscan.RiskChange   `json:"changes"`
}

// handleRescanStatus reports the last sweep and the artifacts whose risk changed.
func (s *Server) handleRescanStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Rescan == nil {
		s.writeJSON(w, http.StatusOK, rescanStatusResponse{Enabled: false, Changes: []vulnscan.RiskChange{}})
		return
	}
	last := s.opts.Rescan.LastSummary()
	changes := s.opts.Rescan.RiskChanges()
	if changes == nil {
		changes = []vulnscan.RiskChange{}
	}
	s.writeJSON(w, http.StatusOK, rescanStatusResponse{
		Enabled:     true,
		IntervalSec: s.opts.Rescan.Interval().Seconds(),
		Last:        &last,
		Changes:     changes,
	})
}

// handleRescanTrigger runs an on-demand re-scan sweep and returns its summary.
func (s *Server) handleRescanTrigger(w http.ResponseWriter, r *http.Request) {
	if s.opts.Rescan == nil {
		s.writeError(w, http.StatusNotFound, "continuous re-scan is not enabled")
		return
	}
	summary, err := s.opts.Rescan.Trigger(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "re-scan could not be triggered: "+err.Error())
		return
	}
	s.logger.Info("admin: on-demand cve re-scan triggered",
		"rescanned", summary.Rescanned, "changed", summary.Changed,
		"newlyVulnerable", summary.NewlyVulnerable)
	s.writeJSON(w, http.StatusOK, summary)
}

// quarantineListResponse lists artifacts currently held unservable by the
// continuous re-scan subsystem.
type quarantineListResponse struct {
	Enabled bool                       `json:"enabled"`
	Total   int                        `json:"total"`
	Items   []vulnscan.QuarantineEntry `json:"items"`
}

// handleQuarantineList lists the currently-quarantined artifacts.
func (s *Server) handleQuarantineList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil {
		s.writeJSON(w, http.StatusOK, quarantineListResponse{Enabled: false, Items: []vulnscan.QuarantineEntry{}})
		return
	}
	items := s.opts.Vulnerabilities.Quarantined()
	if items == nil {
		items = []vulnscan.QuarantineEntry{}
	}
	s.writeJSON(w, http.StatusOK, quarantineListResponse{Enabled: true, Total: len(items), Items: items})
}

// handleQuarantineRelease lifts an artifact's quarantine (operator override after
// triage). The next pull re-scans the artifact from scratch.
func (s *Server) handleQuarantineRelease(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil {
		s.writeError(w, http.StatusNotFound, "vulnerability scanning is not enabled")
		return
	}
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		s.writeError(w, http.StatusBadRequest, "missing digest parameter")
		return
	}
	if !s.opts.Vulnerabilities.ReleaseQuarantine(digest) {
		s.writeError(w, http.StatusNotFound, "digest is not quarantined")
		return
	}
	s.logger.Info("admin: quarantine released", "digest", digest)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "released", "digest": digest})
}

// vexListResponse is the payload for GET {prefix}/api/vex: the loaded VEX corpus
// statistics, the cumulative suppression/escalation counters, and (optionally
// filtered) statements.
type vexListResponse struct {
	Enabled    bool                    `json:"enabled"`
	Stats      vulnscan.VEXStats       `json:"stats"`
	Suppressed int64                   `json:"suppressedTotal"`
	Escalated  int64                   `json:"escalatedTotal"`
	Total      int                     `json:"total"`
	Returned   int                     `json:"returned"`
	Statements []vulnscan.VEXStatement `json:"statements"`
}

// handleVEXList reports the VEX-suppression subsystem state: the loaded corpus,
// the cumulative suppressed/escalated counts, and the statements (optionally
// filtered by a substring of the vulnerability id via ?q=).
func (s *Server) handleVEXList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Vulnerabilities == nil || !s.opts.Vulnerabilities.VEXEnabled() {
		s.writeJSON(w, http.StatusOK, vexListResponse{Enabled: false, Statements: []vulnscan.VEXStatement{}})
		return
	}
	stmts := s.opts.Vulnerabilities.VEXStatements()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	items := make([]vulnscan.VEXStatement, 0, len(stmts))
	for _, st := range stmts {
		if q != "" && !strings.Contains(strings.ToLower(st.Vulnerability), q) {
			continue
		}
		items = append(items, st)
	}
	total := len(items)
	if limit := parseLimit(r, 500); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	m := s.opts.Vulnerabilities.Metrics()
	s.writeJSON(w, http.StatusOK, vexListResponse{
		Enabled:    true,
		Stats:      s.opts.Vulnerabilities.VEXStats(),
		Suppressed: m.VEXSuppressed,
		Escalated:  m.VEXEscalated,
		Total:      total,
		Returned:   len(items),
		Statements: items,
	})
}

// licenseStatusResponse reports the license-compliance gate's configuration,
// cumulative metrics, recent non-allow decisions, and detected license drift.
type licenseStatusResponse struct {
	Enabled   bool                     `json:"enabled"`
	Metrics   *license.Snapshot        `json:"metrics,omitempty"`
	Policy    *license.PolicySummary   `json:"policy,omitempty"`
	Decisions []license.DecisionRecord `json:"decisions"`
	Drift     []license.DriftEvent     `json:"drift"`
}

// handleLicenseStatus reports the license gate's policy, metrics, recent
// decisions, and license-drift events.
func (s *Server) handleLicenseStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.License == nil {
		s.writeJSON(w, http.StatusOK, licenseStatusResponse{
			Enabled:   false,
			Decisions: []license.DecisionRecord{},
			Drift:     []license.DriftEvent{},
		})
		return
	}
	m := s.opts.License.Metrics()
	summary := s.opts.License.Summary()
	decisions := s.opts.License.RecentDecisions()
	if limit := parseLimit(r, 200); limit > 0 && len(decisions) > limit {
		decisions = decisions[:limit]
	}
	if decisions == nil {
		decisions = []license.DecisionRecord{}
	}
	drift := s.opts.License.Drifts()
	if drift == nil {
		drift = []license.DriftEvent{}
	}
	s.writeJSON(w, http.StatusOK, licenseStatusResponse{
		Enabled:   true,
		Metrics:   &m,
		Policy:    &summary,
		Decisions: decisions,
		Drift:     drift,
	})
}

// notifyStatusResponse reports the notification subsystem's configuration and
// cumulative delivery telemetry.
type notifyStatusResponse struct {
	Enabled bool              `json:"enabled"`
	Sinks   []notify.SinkInfo `json:"sinks"`
	Metrics *notify.Snapshot  `json:"metrics,omitempty"`
}

// handleNotifyStatus reports the configured sinks and delivery metrics.
func (s *Server) handleNotifyStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Notify == nil {
		s.writeJSON(w, http.StatusOK, notifyStatusResponse{Enabled: false, Sinks: []notify.SinkInfo{}})
		return
	}
	sinks := s.opts.Notify.Sinks()
	if sinks == nil {
		sinks = []notify.SinkInfo{}
	}
	m := s.opts.Notify.Metrics()
	s.writeJSON(w, http.StatusOK, notifyStatusResponse{Enabled: true, Sinks: sinks, Metrics: &m})
}

// notifyTestResponse wraps the per-sink results of a test notification.
type notifyTestResponse struct {
	Results []notify.TestResult `json:"results"`
}

// handleNotifyTest sends a synchronous test notification to one sink (when the
// "sink" query parameter is set) or to every configured sink, returning the
// per-sink delivery result so an operator can validate sink configuration
// end-to-end. The endpoint reports HTTP 200 with the per-sink outcomes even when
// a delivery failed (the failure is in the body), so the caller can distinguish
// "no such sink" (404) from "sink unreachable" (200 with ok:false).
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if s.opts.Notify == nil {
		s.writeError(w, http.StatusNotFound, "notifications are not enabled")
		return
	}
	sink := r.URL.Query().Get("sink")
	results, err := s.opts.Notify.Test(r.Context(), sink)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.logger.Info("admin: test notification sent", "sink", sink, "results", len(results))
	s.writeJSON(w, http.StatusOK, notifyTestResponse{Results: results})
}

// rateLimitStatusResponse reports the rate limiter's live policy/usage snapshot.
type rateLimitStatusResponse struct {
	Enabled  bool                `json:"enabled"`
	Snapshot *ratelimit.Snapshot `json:"snapshot,omitempty"`
}

// handleRateLimitStatus reports the global policy, per-tenant policies, live
// usage (in-flight concurrency, bytes consumed), and cumulative allow/throttle
// counters (Task 24).
func (s *Server) handleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.RateLimit == nil {
		s.writeJSON(w, http.StatusOK, rateLimitStatusResponse{Enabled: false})
		return
	}
	snap := s.opts.RateLimit.Metrics()
	s.writeJSON(w, http.StatusOK, rateLimitStatusResponse{Enabled: true, Snapshot: &snap})
}

// coalesceStatusResponse reports the pull-path coalescer's live snapshot,
// including the derived dedup ratio.
type coalesceStatusResponse struct {
	Enabled    bool               `json:"enabled"`
	DedupRatio float64            `json:"dedupRatio"`
	Snapshot   *coalesce.Snapshot `json:"snapshot,omitempty"`
}

// handleCoalesceStatus reports request-coalescing and negative-cache telemetry
// (Task 36): coalesced hits, leads, the dedup ratio, in-flight fetches, negative
// cache hits/evictions/entries, and the per-failure-class breakdown.
func (s *Server) handleCoalesceStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Coalesce == nil {
		s.writeJSON(w, http.StatusOK, coalesceStatusResponse{Enabled: false})
		return
	}
	snap := s.opts.Coalesce.Metrics()
	s.writeJSON(w, http.StatusOK, coalesceStatusResponse{
		Enabled:    snap.Enabled,
		DedupRatio: snap.DedupRatio(),
		Snapshot:   &snap,
	})
}

// handleCoalescePurge flushes the negative cache, letting an operator clear a
// stuck negative result (e.g. after a missing artifact is published upstream)
// without waiting for the TTL. It reports how many entries were removed.
func (s *Server) handleCoalescePurge(w http.ResponseWriter, r *http.Request) {
	if s.opts.Coalesce == nil {
		s.writeError(w, http.StatusNotFound, "coalescer not enabled")
		return
	}
	removed := s.opts.Coalesce.PurgeNegativeCache()
	s.writeJSON(w, http.StatusOK, map[string]int{"purged": removed})
}

// rateLimitSetPolicyRequest updates one tenant's (or the global) rate-limit
// policy at runtime. Set Global true to update the process-wide policy; otherwise
// Tenant names the tenant whose policy is replaced.
type rateLimitSetPolicyRequest struct {
	Tenant string           `json:"tenant"`
	Global bool             `json:"global"`
	Policy ratelimit.Policy `json:"policy"`
}

// handleRateLimitSetPolicy replaces a tenant's (or the global) policy at runtime.
// The change takes effect immediately while preserving the live bucket/concurrency
// state, so an operator can tighten or relax limits without a restart.
func (s *Server) handleRateLimitSetPolicy(w http.ResponseWriter, r *http.Request) {
	if s.opts.RateLimit == nil {
		s.writeError(w, http.StatusNotFound, "rate limiting is not enabled")
		return
	}
	var req rateLimitSetPolicyRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Global {
		if err := s.opts.RateLimit.SetGlobalPolicy(req.Policy); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Info("admin: global rate-limit policy updated", "policy", req.Policy)
		s.writeJSON(w, http.StatusOK, map[string]any{"updated": "global", "policy": req.Policy})
		return
	}
	if strings.TrimSpace(req.Tenant) == "" {
		s.writeError(w, http.StatusBadRequest, "provide a tenant, or set global:true")
		return
	}
	if err := s.opts.RateLimit.SetPolicy(req.Tenant, req.Policy); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("admin: tenant rate-limit policy updated", "tenant", req.Tenant, "policy", req.Policy)
	s.writeJSON(w, http.StatusOK, map[string]any{"updated": req.Tenant, "policy": req.Policy})
}

// auditStatusResponse reports the tamper-evident audit log's state (Task 31).
type auditStatusResponse struct {
	Enabled             bool              `json:"enabled"`
	TransparencyEnabled bool              `json:"transparencyEnabled"`
	Stats               *audit.Stats      `json:"stats,omitempty"`
	LatestCheckpoint    *audit.Checkpoint `json:"latestCheckpoint,omitempty"`
}

// handleAuditStatus reports the chain length, tree size, checkpoint count, last
// seal time, and verification-failure count, plus the latest signed checkpoint.
func (s *Server) handleAuditStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Audit == nil {
		s.writeJSON(w, http.StatusOK, auditStatusResponse{Enabled: false})
		return
	}
	stats := s.opts.Audit.Stats()
	resp := auditStatusResponse{
		Enabled:             true,
		TransparencyEnabled: s.opts.Audit.TransparencyEnabled(),
		Stats:               &stats,
	}
	if cp, ok := s.opts.Audit.LatestCheckpoint(); ok {
		resp.LatestCheckpoint = &cp
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleAuditCheckpoint returns the latest sealed checkpoint (signed tree head)
// so a client can pin a trusted root for later inclusion-proof verification.
func (s *Server) handleAuditCheckpoint(w http.ResponseWriter, r *http.Request) {
	if s.opts.Audit == nil || !s.opts.Audit.TransparencyEnabled() {
		s.writeError(w, http.StatusNotFound, "audit transparency log is not enabled")
		return
	}
	cp, ok := s.opts.Audit.LatestCheckpoint()
	if !ok {
		s.writeError(w, http.StatusNotFound, "no checkpoint has been sealed yet")
		return
	}
	s.writeJSON(w, http.StatusOK, cp)
}

// handleAuditInclusionProof returns an inclusion proof for the record with the
// given 1-based sequence number, anchored to the latest signed checkpoint when
// the record is covered by it. The proof is self-verified server-side; a failure
// indicates internal log corruption and bumps the verification-failure metric.
func (s *Server) handleAuditInclusionProof(w http.ResponseWriter, r *http.Request) {
	if s.opts.Audit == nil || !s.opts.Audit.TransparencyEnabled() {
		s.writeError(w, http.StatusNotFound, "audit transparency log is not enabled")
		return
	}
	seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
	if err != nil || seq == 0 {
		s.writeError(w, http.StatusBadRequest, "missing or invalid seq parameter (must be a positive integer)")
		return
	}
	proof, err := s.opts.Audit.InclusionProof(seq)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if verr := audit.VerifyInclusion(proof); verr != nil {
		s.opts.Audit.RecordVerificationFailure()
		s.logger.Error("admin: audit inclusion proof failed self-verification", "seq", seq, "error", verr)
		s.writeError(w, http.StatusInternalServerError, "generated inclusion proof failed verification: "+verr.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, proof)
}

// handleAuditConsistencyProof returns a consistency proof between two log sizes
// (from < to; to omitted or 0 means the current size), proving the earlier log
// is an append-only prefix of the later one.
func (s *Server) handleAuditConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if s.opts.Audit == nil || !s.opts.Audit.TransparencyEnabled() {
		s.writeError(w, http.StatusNotFound, "audit transparency log is not enabled")
		return
	}
	from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from == 0 {
		s.writeError(w, http.StatusBadRequest, "missing or invalid from parameter (must be a positive integer)")
		return
	}
	var to uint64
	if v := r.URL.Query().Get("to"); v != "" {
		to, err = strconv.ParseUint(v, 10, 64)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid to parameter")
			return
		}
	}
	proof, err := s.opts.Audit.ConsistencyProof(from, to)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if verr := audit.VerifyConsistency(proof); verr != nil {
		s.opts.Audit.RecordVerificationFailure()
		s.logger.Error("admin: audit consistency proof failed self-verification", "from", from, "to", to, "error", verr)
		s.writeError(w, http.StatusInternalServerError, "generated consistency proof failed verification: "+verr.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, proof)
}

// sigverifyListResponse lists the cached signature-verification reports.
type sigverifyListResponse struct {
	Enabled  bool                  `json:"enabled"`
	Total    int                   `json:"total"`
	Returned int                   `json:"returned"`
	Metrics  *sigverify.Snapshot   `json:"metrics,omitempty"`
	Items    []sigverifySummaryDTO `json:"items"`
}

// sigverifySummaryDTO is the compact per-artifact verification summary.
type sigverifySummaryDTO struct {
	Ecosystem           string `json:"ecosystem"`
	Package             string `json:"package,omitempty"`
	Version             string `json:"version,omitempty"`
	Digest              string `json:"digest,omitempty"`
	Source              string `json:"source,omitempty"`
	VerifiedSignature   bool   `json:"verifiedSignature"`
	VerifiedAttestation bool   `json:"verifiedAttestation"`
	Findings            int    `json:"findings"`
	WorstSeverity       string `json:"worstSeverity,omitempty"`
}

// handleSigverifyList lists cached verification reports (most-recent first), with
// optional substring filtering by package name or digest.
func (s *Server) handleSigverifyList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Sigverify == nil {
		s.writeJSON(w, http.StatusOK, sigverifyListResponse{Enabled: false, Items: []sigverifySummaryDTO{}})
		return
	}
	reports := s.opts.Sigverify.Reports()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	items := make([]sigverifySummaryDTO, 0, len(reports))
	for _, rep := range reports {
		dto := sigverifyReportToSummary(rep)
		if q != "" && !strings.Contains(strings.ToLower(dto.Package), q) &&
			!strings.Contains(strings.ToLower(dto.Digest), q) {
			continue
		}
		items = append(items, dto)
	}
	total := len(items)
	if limit := parseLimit(r, 200); limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	m := s.opts.Sigverify.Metrics()
	s.writeJSON(w, http.StatusOK, sigverifyListResponse{
		Enabled:  true,
		Total:    total,
		Returned: len(items),
		Metrics:  &m,
		Items:    items,
	})
}

// handleSigverifyEntry returns the full verification report for a content digest.
func (s *Server) handleSigverifyEntry(w http.ResponseWriter, r *http.Request) {
	if s.opts.Sigverify == nil {
		s.writeError(w, http.StatusNotFound, "signature verification is not enabled")
		return
	}
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		s.writeError(w, http.StatusBadRequest, "missing digest parameter")
		return
	}
	report, ok := s.opts.Sigverify.Report(digest)
	if !ok {
		s.writeError(w, http.StatusNotFound, "no verification report for digest (the artifact may not have been pulled yet)")
		return
	}
	s.writeJSON(w, http.StatusOK, report)
}

// sigverifyReportToSummary projects a verification report to its summary DTO.
func sigverifyReportToSummary(rep *sigverify.Report) sigverifySummaryDTO {
	dto := sigverifySummaryDTO{
		Ecosystem:           rep.Artifact.Ecosystem,
		Package:             rep.Artifact.Name,
		Version:             rep.Artifact.Version,
		Digest:              rep.Artifact.Digest,
		Source:              rep.Source,
		VerifiedSignature:   rep.VerifiedSignature,
		VerifiedAttestation: rep.VerifiedAttestation,
		Findings:            len(rep.Findings),
	}
	if worst := rep.Worst(); worst != nil {
		dto.WorstSeverity = string(worst.Severity)
	}
	return dto
}

// --- helpers ----------------------------------------------------------------

func (s *Server) backendNames() []string {
	if s.opts.Backends == nil {
		return nil
	}
	return s.opts.Backends.Names()
}

func parseLimit(r *http.Request, def int) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}
