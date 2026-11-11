package main

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/avscan"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/ansible"
	"github.com/blechschmidt/pullthrough-security/internal/backends/apt"
	"github.com/blechschmidt/pullthrough-security/internal/backends/bazel"
	"github.com/blechschmidt/pullthrough-security/internal/backends/composer"
	"github.com/blechschmidt/pullthrough-security/internal/backends/conan"
	"github.com/blechschmidt/pullthrough-security/internal/backends/conda"
	"github.com/blechschmidt/pullthrough-security/internal/backends/cpan"
	"github.com/blechschmidt/pullthrough-security/internal/backends/cran"
	"github.com/blechschmidt/pullthrough-security/internal/backends/dart"
	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
	"github.com/blechschmidt/pullthrough-security/internal/backends/hackage"
	"github.com/blechschmidt/pullthrough-security/internal/backends/helm"
	"github.com/blechschmidt/pullthrough-security/internal/backends/hex"
	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/backends/jsr"
	"github.com/blechschmidt/pullthrough-security/internal/backends/maven"
	"github.com/blechschmidt/pullthrough-security/internal/backends/nix"
	"github.com/blechschmidt/pullthrough-security/internal/backends/openvsx"
	"github.com/blechschmidt/pullthrough-security/internal/backends/puppet"
	"github.com/blechschmidt/pullthrough-security/internal/backends/rubygems"
	"github.com/blechschmidt/pullthrough-security/internal/backends/swift"
	"github.com/blechschmidt/pullthrough-security/internal/backends/terraform"
	"github.com/blechschmidt/pullthrough-security/internal/backends/yum"
	"github.com/blechschmidt/pullthrough-security/internal/backup"
	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/compliance"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/egress"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/fips"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/gitops"
	"github.com/blechschmidt/pullthrough-security/internal/grpcapi"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/k8swebhook"
	"github.com/blechschmidt/pullthrough-security/internal/keyrotation"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/mcpserver"
	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/otlplog"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/portal"
	"github.com/blechschmidt/pullthrough-security/internal/presets"
	"github.com/blechschmidt/pullthrough-security/internal/prewarm"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/pypiattest"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
	"github.com/blechschmidt/pullthrough-security/internal/sbomexport"
	"github.com/blechschmidt/pullthrough-security/internal/scan"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/secops"
	"github.com/blechschmidt/pullthrough-security/internal/secrets"
	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
	"github.com/blechschmidt/pullthrough-security/internal/siem"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
	"github.com/blechschmidt/pullthrough-security/internal/tlspin"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
	"github.com/blechschmidt/pullthrough-security/internal/vexexport"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
	"github.com/blechschmidt/pullthrough-security/internal/webauthn"
)

// observability bundles the wired telemetry surfaces handed to the gateway: the
// metrics recorder/endpoint and the admin API/dashboard. Any field may be nil
// (or empty) when the corresponding feature is disabled, in which case the
// gateway simply does not mount it.
type observability struct {
	recorder       proxyMetricsRecorder
	collector      *metrics.Collector // concrete collector, for post-gateway binds; nil when metrics disabled
	metricsHandler http.Handler
	metricsPath    string
	adminHandler   http.Handler
	adminPrefix    string
	portalHandler  http.Handler
	portalUIPrefix string
	portalAPIPath  string
	metering       *metering.Meter    // per-tenant usage accumulator (Task 84); always non-nil
	webhook        *k8swebhook.Server // Kubernetes admission webhook (Task 111); nil when disabled
}

// proxyMetricsRecorder is the gateway's recorder surface, restated here so the
// metrics.Collector can be passed as a true-nil interface when metrics are
// disabled (a typed-nil *Collector would defeat the gateway's nil check).
type proxyMetricsRecorder interface {
	IncRequest(backend, method, code string)
	ObserveUpstreamLatency(backend string, seconds float64, ok bool)
	AddBytesServed(backend string, n int64)
	IncPolicyDecision(ecosystem, action string)
}

// cacheMetricsSource is the optional cache surface that reports cumulative
// activity counters. The filesystem cache satisfies it; the in-memory cache does
// not, so the bridge is registered only when present.
type cacheMetricsSource interface {
	Metrics() cache.MetricsSnapshot
}

// buildObservability constructs the metrics collector (binding the cache and
// scan subsystems as scrape-time callbacks) and the admin API/dashboard, each
// gated on its config toggle. It never fails: an observability surface is
// auxiliary, so a missing optional dependency degrades the surface rather than
// preventing startup.
func buildObservability(
	cfg *config.Config,
	configSvc *config.Service,
	registry *backends.Registry,
	cacheImpl cache.Cache,
	scanner scan.Scanner,
	secretDetector *secretscan.Detector,
	provService *provenance.Service,
	provResolver provenance.Resolver,
	vulnService *vulnscan.Service,
	nameGuard *nameguard.Service,
	malfeedSvc *malfeed.Service,
	maturitySvc *maturity.Service,
	continuitySvc *continuity.Service,
	depFirewallSvc *depfirewall.Service,
	installHooksSvc *installhooks.Service,
	mlGuardSvc *mlguard.Service,
	avScanSvc *avscan.Service,
	contentScanSvc *contentscan.Service,
	llmPkgScanSvc *llmpkgscan.Service,
	sigVerify *sigverify.Service,
	licenseService *license.Service,
	pacEngine *policyengine.Engine,
	rescanner *vulnscan.Rescanner,
	notifier *notify.Notifier,
	siemFwd *siem.Forwarder,
	rateLimiter *ratelimit.Limiter,
	auditLog *audit.Logger,
	provGraph *provgraph.Service,
	coalescer *coalesce.Coalescer[*cache.Entry],
	complianceSvc *compliance.Service,
	riskEngine *riskscore.Engine,
	repoScoreSvc *reposcore.Service,
	sbomDiffSvc *sbomdiff.Service,
	rebuildVerifySvc *rebuildverify.Service,
	buildProvSvc *buildprov.Service,
	pypiAttestSvc *pypiattest.Service,
	extManager *extension.Manager,
	anomalyEngine *anomaly.Engine,
	approvalsSvc *approvals.Service,
	poolMgr *upstreampool.Manager,
	egressGuard *egress.Guard,
	pinGuard *tlspin.Guard,
	connMetrics *upstream.ConnMetrics,
	cacheGC *cachegc.Engine,
	backupScheduler *backup.Scheduler,
	findingsStore *findings.Store,
	findingsMetrics *findings.Metrics,
	suppressionLedger *findings.SuppressionLedger,
	simReplayRecorder *simreplay.Recorder,
	attestor *attestbundle.Service,
	snapshotSvc *snapshot.Service,
	lockdownSvc *lockdown.Service,
	gitopsSvc *gitops.Service,
	prewarmSvc *prewarm.Service,
	sbomExporter *sbomexport.Service,
	tracerProvider *tracing.Provider,
	logPipeline *otlplog.Pipeline,
	coordSvc *coord.Service,
	clientMTLS *clientMTLS,
	secretsResolver *secrets.Resolver,
	rekorMetrics *rekor.Metrics,
	cacheFed *cachefed.Federation,
	keyRotationSvc *keyrotation.Service,
	webAuthnSvc *webauthn.Service,
	logger *slog.Logger,
) observability {
	var obs observability

	commitScanner, _ := scanner.(*commit.Scanner)

	// Build the admin SSO/RBAC service once (Task 51) so both the metrics bridge
	// and the admin server share it. On a configuration/discovery error we log and
	// continue without SSO rather than aborting the proxy; the admin server then
	// falls back to the legacy admin-token check (the documented air-gapped path).
	var adminAuthSvc *adminauth.Service
	if cfg.AdminAuth.Enabled {
		svc, err := buildAdminAuth(cfg, logger)
		if err != nil {
			logger.Warn("admin SSO/RBAC disabled (falling back to legacy admin token)", "error", err)
		} else {
			adminAuthSvc = svc
		}
	}

	// Build the unified Security Operations (SOC) read-model (Task 60). It taps
	// the live notification event stream for the rolling-window verdict feed and
	// reads the subsystem read-models (riskscore/anomaly/approvals/findings) for
	// the posture summary — no source of truth is duplicated. It is always
	// constructed (even with everything disabled it yields a valid, empty
	// summary), and tapped onto the notifier so the live feed reflects every
	// emitted security event.
	secopsProviders := secops.Providers{}
	if riskEngine != nil {
		secopsProviders.Risk = riskEngine
	}
	if anomalyEngine != nil {
		secopsProviders.Anomaly = anomalyEngine
	}
	if approvalsSvc != nil {
		secopsProviders.Approvals = approvalsSvc
	}
	if findingsStore != nil {
		secopsProviders.Findings = findingsStore
	}
	if keyRotationSvc != nil {
		secopsProviders.KeyRotation = keyRotationSvc
	}
	secopsHub := secops.NewHub(secops.Options{Providers: secopsProviders})
	notifier.Tap(secopsHub.Observe)

	// Build the per-tenant usage-metering & chargeback accumulator (Task 84). Like
	// the SOC read-model it is always constructed (a disabled config yields a no-op
	// meter) and tapped onto the notifier so quarantine events are attributed to
	// tenants. When enabled it also runs the periodic rollup scheduler and receives
	// budget-threshold alerts through the notifier.
	meter := metering.New(metering.Config{
		Enabled:               cfg.Metering.Enabled,
		RetentionHours:        cfg.Metering.RetentionHours,
		RollupInterval:        cfg.Metering.RollupInterval,
		StatePath:             cfg.Metering.StatePath,
		DefaultScanCostMicros: cfg.Metering.DefaultScanCostMicros,
		ScanCostMicros:        cfg.Metering.ScanCostMicros,
		Budgets:               meteringBudgets(cfg.Metering.Budgets),
		Notifier:              notifier,
	})
	notifier.Tap(meter.Observe)
	meter.Start()
	obs.metering = meter

	// Build the read-only forensic incident-timeline engine (Task 77). It
	// correlates the heterogeneous records already produced across the audit log
	// (Merkle), the SOC feed, anomaly triggers, the approval/break-glass workflow,
	// lockdown actions, and admission findings into one ordered, deduplicated
	// timeline. Like the SOC and query layers it owns no state and is always
	// constructed; a nil provider simply contributes nothing.
	timelineProviders := timeline.Providers{}
	if auditLog != nil {
		timelineProviders.Audit = auditLog
	}
	timelineProviders.SecOps = secopsHub
	if anomalyEngine != nil {
		timelineProviders.Anomaly = anomalyEngine
	}
	if approvalsSvc != nil {
		timelineProviders.Approvals = approvalsSvc
	}
	if lockdownSvc != nil {
		timelineProviders.Lockdown = lockdownSvc
	}
	if findingsStore != nil {
		timelineProviders.Findings = findingsStore
	}
	timelineEngine := timeline.New(timeline.Config{AdminPrefix: cfg.Observability.AdminPrefixOrDefault()}, timelineProviders)

	// Build the read-only federated query engine (Task 67). It joins the
	// per-coordinate security facts spread across the subsystems' read-models
	// into a single queryable model. Each provider is wired only when its
	// subsystem is enabled so the join degrades gracefully (a nil provider
	// contributes nothing). It is always constructed: with nothing wired it
	// answers queries over an empty model.
	queryProviders := queryapi.Providers{SecOps: secopsHub}
	if findingsStore != nil {
		queryProviders.Findings = findingsStore
	}
	if riskEngine != nil {
		queryProviders.Risk = riskEngine
	}
	if vulnService != nil {
		queryProviders.Vuln = vulnService
	}
	if approvalsSvc != nil {
		queryProviders.Approvals = approvalsSvc
	}
	if provGraph != nil {
		queryProviders.Provgraph = provGraph
	}
	if snapshotSvc != nil {
		queryProviders.Snapshot = snapshotSvc
	}
	queryProviders.Timeline = timelineEngine
	if meter.Enabled() {
		queryProviders.Metering = meter
	}
	// Dossier (Task 87) field set: surface source-commit/provenance, reproducible
	// build, and SBOM drift for ad-hoc querying too.
	if buildProvSvc != nil {
		queryProviders.BuildProv = buildProvSvc
	}
	if rebuildVerifySvc != nil {
		queryProviders.Rebuild = rebuildVerifySvc
	}
	if sbomDiffSvc != nil {
		queryProviders.SbomDrift = sbomDiffSvc
	}
	queryEngine := queryapi.New(queryapi.Config{}, queryProviders)

	// Build the read-only MCP server (Task 79). It projects over the federated
	// query engine (reusing its field registry and cost bounds) and enriches each
	// tool with detail from the backing subsystems when they are wired. It is
	// mounted under the admin API at /api/mcp and hard-scoped to the caller's
	// tenant. Constructed only when the admin surface and the MCP toggle are on.
	var mcpSrv *mcpserver.Server
	if cfg.Observability.Admin && cfg.Observability.MCP {
		mcpCfg := mcpserver.Config{
			Backend:        queryEngine,
			Version:        version,
			MaxDetailItems: cfg.Observability.MCPMaxDetailItemsOrDefault(),
			Timeline:       timelineEngine,
		}
		if findingsStore != nil {
			mcpCfg.Findings = findingsStore
		}
		if provGraph != nil {
			mcpCfg.Provgraph = provGraph
		}
		if attestor != nil {
			mcpCfg.Attest = attestor
		}
		if vulnService != nil {
			mcpCfg.Vuln = vulnService
		}
		if riskEngine != nil {
			mcpCfg.Risk = riskEngine
		}
		mcpSrv = mcpserver.New(mcpCfg)
	}

	// Build the read-only gRPC/Connect security API (Task 159). Like the MCP
	// server it projects over the federated query engine and enriches each RPC
	// with detail from the backing subsystems when wired, but it also reuses the
	// dossier builder for the per-coordinate "360 view" RPC. It is mounted under
	// the admin API at /api/grpc and hard-scoped to the caller's tenant.
	// Constructed only when the admin surface and the gRPC toggle are on.
	var grpcSrv *grpcapi.Server
	if cfg.Observability.Admin && cfg.Observability.GRPC {
		grpcCfg := grpcapi.Config{
			Backend:        queryEngine,
			Version:        version,
			MaxDetailItems: cfg.Observability.GRPCMaxDetailItemsOrDefault(),
		}
		if findingsStore != nil {
			grpcCfg.Findings = findingsStore
		}
		if provGraph != nil {
			grpcCfg.Provgraph = provGraph
		}
		if attestor != nil {
			grpcCfg.Attest = attestor
		}
		if vulnService != nil {
			grpcCfg.Vuln = vulnService
		}
		if riskEngine != nil {
			grpcCfg.Risk = riskEngine
		}
		if complianceSvc != nil {
			grpcCfg.Compliance = complianceSvc
		}
		grpcRemediationSvc := buildRemediation(cfg, vulnService, licenseService, maturitySvc, depFirewallSvc)
		grpcCfg.Dossier = newDossierBuilder(findingsStore, riskEngine, vulnService, sigVerify, buildProvSvc, pypiAttestSvc, provGraph, rebuildVerifySvc, sbomDiffSvc, approvalsSvc, attestor, timelineEngine, grpcRemediationSvc, suppressionLedger, llmPkgScanSvc)
		grpcSrv = grpcapi.New(grpcCfg)
	}

	// Outbound VEX authoring (Task 137): built once so both the metrics bridge and
	// the admin export endpoint share the same service (and its cumulative
	// counters). Nil when disabled.
	vexExporter := buildVEXExporter(cfg, vulnService, findingsStore, approvalsSvc, snapshotSvc, logger)

	if cfg.Observability.Metrics {
		collector := metrics.NewCollector()
		bindCacheMetrics(collector, cacheImpl)
		bindIntegrityMetrics(collector, cacheImpl)
		bindCompactionMetrics(collector, cacheImpl)
		bindEncryptionMetrics(collector, cacheImpl)
		bindTieredMetrics(collector, cacheImpl)
		bindMavenMetrics(collector, registry)
		bindGitLFSMetrics(collector, registry)
		bindRubygemsMetrics(collector, registry)
		bindComposerMetrics(collector, registry)
		bindHelmMetrics(collector, registry)
		bindAptMetrics(collector, registry)
		bindYumMetrics(collector, registry)
		bindTerraformMetrics(collector, registry)
		bindConanMetrics(collector, registry)
		bindCondaMetrics(collector, registry)
		bindCranMetrics(collector, registry)
		bindCpanMetrics(collector, registry)
		bindHexMetrics(collector, registry)
		bindJsrMetrics(collector, registry)
		bindHackageMetrics(collector, registry)
		bindBazelMetrics(collector, registry)
		bindHuggingfaceMetrics(collector, registry)
		bindOpenVSXMetrics(collector, registry)
		bindSwiftMetrics(collector, registry)
		bindDartMetrics(collector, registry)
		bindNixMetrics(collector, registry)
		bindHomebrewMetrics(collector, registry)
		bindAnsibleMetrics(collector, registry)
		bindPuppetMetrics(collector, registry)
		bindGenericMetrics(collector, registry)
		bindScanMetrics(collector, commitScanner)
		bindSecretscanMetrics(collector, secretDetector)
		bindVulnMetrics(collector, vulnService)
		bindLicenseMetrics(collector, licenseService)
		bindNameguardMetrics(collector, nameGuard)
		bindMalfeedMetrics(collector, malfeedSvc)
		bindMaturityMetrics(collector, maturitySvc)
		bindContinuityMetrics(collector, continuitySvc)
		bindDepFirewallMetrics(collector, depFirewallSvc)
		bindSnapshotMetrics(collector, snapshotSvc)
		bindLockdownMetrics(collector, lockdownSvc)
		bindGitopsMetrics(collector, gitopsSvc)
		bindInstallHooksMetrics(collector, installHooksSvc)
		bindMLGuardMetrics(collector, mlGuardSvc)
		bindAVScanMetrics(collector, avScanSvc)
		bindContentScanMetrics(collector, contentScanSvc)
		bindLLMPkgScanMetrics(collector, llmPkgScanSvc)
		bindFindingsDedupMetrics(collector, findingsMetrics, suppressionLedger)
		bindSigverifyMetrics(collector, sigVerify)
		bindPolicyEngineMetrics(collector, pacEngine)
		if cfg.Notifications.Enabled {
			bindNotifyMetrics(collector, notifier)
		}
		bindSIEMMetrics(collector, siemFwd)
		bindSecretsMetrics(collector, secretsResolver)
		bindPrewarmMetrics(collector, prewarmSvc)
		bindSBOMExportMetrics(collector, sbomExporter)
		bindRateLimitMetrics(collector, rateLimiter)
		bindAuditMetrics(collector, auditLog)
		bindProvgraphMetrics(collector, provGraph)
		bindCoalesceMetrics(collector, coalescer)
		bindComplianceMetrics(collector, complianceSvc)
		bindRiskScoreMetrics(collector, riskEngine)
		bindRepoScoreMetrics(collector, repoScoreSvc)
		bindSbomDiffMetrics(collector, sbomDiffSvc)
		bindRebuildVerifyMetrics(collector, rebuildVerifySvc)
		bindBuildProvMetrics(collector, buildProvSvc)
		bindPyPIAttestMetrics(collector, pypiAttestSvc)
		bindExtensionMetrics(collector, extManager)
		bindAnomalyMetrics(collector, anomalyEngine)
		bindApprovalsMetrics(collector, approvalsSvc)
		bindUpstreamPoolMetrics(collector, poolMgr)
		bindEgressMetrics(collector, egressGuard)
		bindTLSPinMetrics(collector, pinGuard)
		bindUpstreamConnMetrics(collector, connMetrics)
		bindCacheGCMetrics(collector, cacheGC)
		bindBackupMetrics(collector, backupScheduler)
		bindAttestMetrics(collector, attestor)
		bindRekorMetrics(collector, rekorMetrics)
		bindCacheFedMetrics(collector, cacheFed)
		bindKeyRotationMetrics(collector, keyRotationSvc)
		bindWebAuthnMetrics(collector, webAuthnSvc)
		bindSimReplayMetrics(collector, simReplayRecorder)
		bindTracingMetrics(collector, tracerProvider)
		bindOTLPLogsMetrics(collector, logPipeline)
		bindCoordinationMetrics(collector, coordSvc)
		bindAdminAuthMetrics(collector, adminAuthSvc)
		bindClientMTLSMetrics(collector, clientMTLS)
		bindSecOpsMetrics(collector, secopsHub)
		bindMeteringMetrics(collector, meter)
		bindQueryAPIMetrics(collector, queryEngine)
		bindMCPServerMetrics(collector, mcpSrv)
		bindGRPCServerMetrics(collector, grpcSrv)
		bindConfigDriftMetrics(collector, configSvc)
		bindVEXExportMetrics(collector, vexExporter)
		obs.recorder = collector
		obs.collector = collector
		obs.metricsHandler = collector.Handler()
		obs.metricsPath = cfg.Observability.MetricsPathOrDefault()
		logger.Info("metrics endpoint enabled", "path", obs.metricsPath)
	}

	if cfg.Observability.Admin {
		srv, err := buildAdminServer(cfg, configSvc, registry, cacheImpl, commitScanner, provService, provResolver, vulnService, sigVerify, licenseService, pacEngine, rescanner, notifier, rateLimiter, auditLog, provGraph, coalescer, complianceSvc, riskEngine, repoScoreSvc, sbomDiffSvc, rebuildVerifySvc, buildProvSvc, pypiAttestSvc, extManager, anomalyEngine, approvalsSvc, malfeedSvc, maturitySvc, continuitySvc, depFirewallSvc, installHooksSvc, avScanSvc, contentScanSvc, llmPkgScanSvc, poolMgr, egressGuard, cacheGC, backupScheduler, findingsStore, suppressionLedger, simReplayRecorder, attestor, snapshotSvc, lockdownSvc, gitopsSvc, prewarmSvc, sbomExporter, tracerProvider, coordSvc, secopsHub, keyRotationSvc, webAuthnSvc, queryEngine, timelineEngine, mcpSrv, grpcSrv, meter, adminAuthSvc, vexExporter, logger)
		if err != nil {
			// Cache inspection is the admin minimum; if it cannot be wired we log and
			// run without the surface rather than aborting the whole proxy.
			logger.Warn("admin surface disabled", "error", err)
		} else {
			obs.adminHandler = srv.Handler()
			obs.adminPrefix = srv.Prefix()
			logger.Info("admin api/dashboard enabled",
				"prefix", obs.adminPrefix,
				"sso", adminAuthSvc != nil,
				"oidc", adminAuthSvc != nil && adminAuthSvc.OIDCEnabled(),
				"authenticated", adminAuthSvc != nil || cfg.Observability.AdminToken != "")
		}
	}

	// Tenant self-service read-only portal (Task 71). It is a separate surface
	// from the admin UI, hard-scoped to the caller's tenant. It requires an
	// adminauth Service to identify the tenant; without one it cannot enforce
	// isolation, so it is left disabled with a clear log line.
	if cfg.Observability.Portal {
		if adminAuthSvc == nil {
			logger.Warn("self-service portal disabled: it requires adminAuth (oidc and/or static tokens) to identify the caller's tenant")
		} else if psrv, err := buildPortalServer(cfg, registry, adminAuthSvc, riskEngine, findingsStore, approvalsSvc, attestor, meter, logger); err != nil {
			logger.Warn("self-service portal disabled", "error", err)
		} else {
			obs.portalHandler = psrv.Handler()
			obs.portalUIPrefix = psrv.UIPrefix()
			obs.portalAPIPath = psrv.APIPrefix()
			logger.Info("tenant self-service portal enabled",
				"uiPrefix", obs.portalUIPrefix, "apiPrefix", obs.portalAPIPath)
		}
	}

	// Kubernetes admission webhook (Task 111): an in-cluster enforcement listener
	// that reuses the dossier verdict to admit/deny Pod image references. It runs
	// as an additional listener in run(); the lockdown kill-switch (Task 74) is
	// folded in via the adapter so a targeted block denies matching images and any
	// active lockdown flips un-vetted images to deny.
	if cfg.AdmissionWebhook.Enabled {
		remediationSvc := buildRemediation(cfg, vulnService, licenseService, maturitySvc, depFirewallSvc)
		builder := newDossierBuilder(findingsStore, riskEngine, vulnService, sigVerify, buildProvSvc, pypiAttestSvc, provGraph, rebuildVerifySvc, sbomDiffSvc, approvalsSvc, attestor, timelineEngine, remediationSvc, suppressionLedger, llmPkgScanSvc)
		wh, err := buildAdmissionWebhook(cfg, builder, lockdownSvc, logger)
		if err != nil {
			logger.Error("admission webhook disabled (construction failed)", "error", err)
		} else {
			obs.webhook = wh
			if obs.collector != nil {
				bindWebhookMetrics(obs.collector, wh.Handler())
			}
			logger.Info("kubernetes admission webhook enabled",
				"addr", cfg.AdmissionWebhook.Addr, "failurePolicy", cfg.AdmissionWebhook.FailurePolicy)
		}
	}

	return obs
}

// buildAdmissionWebhook constructs the Kubernetes ValidatingAdmissionWebhook
// server (Task 111). The verdict source is in-process (the shared dossier
// builder) by default, or a remote HTTP source when admissionWebhook.dossier.url
// is set (a split deployment). The emergency-lockdown service (Task 74) is wired
// as the kill-switch oracle.
func buildAdmissionWebhook(cfg *config.Config, builder *dossier.Builder, lockdownSvc *lockdown.Service, logger *slog.Logger) (*k8swebhook.Server, error) {
	w := cfg.AdmissionWebhook

	var source k8swebhook.VerdictSource
	if url := strings.TrimSpace(w.Dossier.URL); url != "" {
		s, err := k8swebhook.NewHTTPSource(k8swebhook.HTTPSourceConfig{
			BaseURL:            url,
			Token:              w.Dossier.Token,
			CACertFile:         w.Dossier.CACertFile,
			InsecureSkipVerify: w.Dossier.InsecureSkipVerify,
			Timeout:            w.Dossier.Timeout,
		})
		if err != nil {
			return nil, err
		}
		source = s
	} else {
		source = k8swebhook.NewBuilderSource(builder)
	}

	enforceLockdown := true
	if w.EnforceLockdown != nil {
		enforceLockdown = *w.EnforceLockdown
	}
	wcfg := k8swebhook.Config{
		Enabled:            true,
		Addr:               w.Addr,
		Path:               w.Path,
		HealthPath:         w.HealthPath,
		ReadyPath:          w.ReadyPath,
		TLSCertFile:        w.TLSCertFile,
		TLSKeyFile:         w.TLSKeyFile,
		ClientCAFile:       w.ClientCAFile,
		FailurePolicy:      w.FailurePolicy,
		BlockAction:        w.BlockAction,
		WarnAction:         w.WarnAction,
		UnknownAction:      w.UnknownAction,
		MinRiskScoreToDeny: w.MinRiskScoreToDeny,
		EnforceLockdown:    enforceLockdown,
		DefaultEcosystem:   w.DefaultEcosystem,
		Tenant:             w.Tenant,
		StripRegistryHost:  w.StripRegistryHost,
		IgnoreNamespaces:   w.IgnoreNamespaces,
		IgnoreImages:       w.IgnoreImages,
		AnnotateWarnings:   w.AnnotateWarnings,
		Timeout:            w.Timeout,
	}
	return k8swebhook.NewServer(wcfg, source, k8swebhook.NewLockdownAdapter(lockdownSvc), logger)
}

// buildPortalServer wires the tenant self-service portal (Task 71) against the
// per-tenant read models. Any data source may be nil; the corresponding surface
// degrades to "not available" rather than failing.
func buildPortalServer(
	cfg *config.Config,
	registry *backends.Registry,
	adminAuthSvc *adminauth.Service,
	riskEngine *riskscore.Engine,
	findingsStore *findings.Store,
	approvalsSvc *approvals.Service,
	attestor *attestbundle.Service,
	meter *metering.Meter,
	logger *slog.Logger,
) (*portal.Server, error) {
	opts := portal.Options{
		Logger:       logger,
		PathPrefix:   cfg.Observability.PortalPrefixOrDefault(),
		Auth:         adminAuthSvc,
		ProxyBaseURL: cfg.Server.PublicURL,
		Version:      version,
	}
	// Onboarding snippets target the configured, enabled upstreams.
	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() {
			continue
		}
		opts.Backends = append(opts.Backends, onboard.Backend{Name: name, Type: up.Type, URL: up.URL})
	}
	if riskEngine != nil {
		opts.Verdicts = riskEngine
	}
	if findingsStore != nil {
		opts.Findings = findingsStore
	}
	if approvalsSvc != nil {
		opts.Approvals = approvalsSvc
	}
	if attestor != nil {
		opts.Attest = attestor
	}
	if meter.Enabled() {
		opts.Metering = meter
	}
	return portal.New(opts)
}

// bindServeMetrics registers the gateway's Range/partial-content streaming
// counters (Task 75) as scrape-time callbacks. The gateway is constructed after
// the collector, so this is called from main once both exist. It is a no-op when
// either is nil (metrics disabled).
func bindServeMetrics(c *metrics.Collector, gw *proxy.Gateway) {
	if c == nil || gw == nil {
		return
	}
	c.BindCounter("pullthrough_range_requests_total",
		"Total client requests carrying an HTTP Range header on the cache serve path.",
		func() float64 { return float64(gw.ServeMetrics().RangeRequests) })
	c.BindCounter("pullthrough_range_partial_served_total",
		"Total responses answered as 206 Partial Content for a satisfiable byte range.",
		func() float64 { return float64(gw.ServeMetrics().PartialServed) })
	c.BindCounter("pullthrough_range_unsatisfiable_total",
		"Total responses answered as 416 Range Not Satisfiable for an out-of-bounds range.",
		func() float64 { return float64(gw.ServeMetrics().Unsatisfiable) })
	c.BindCounter("pullthrough_range_spill_to_disk_total",
		"Total times a forward-only cache body was spooled to a temp file to satisfy a byte range.",
		func() float64 { return float64(gw.ServeMetrics().SpillToDisk) })
	c.BindCounter("pullthrough_streamed_bytes_total",
		"Total body bytes streamed to clients from the cache serve path (full and partial).",
		func() float64 { return float64(gw.ServeMetrics().StreamedBytes) })
	c.BindCounter("pullthrough_stream_digest_mismatch_total",
		"Total upstream streams rejected mid-fill because the content digest did not match the expected value.",
		func() float64 { return float64(gw.ServeMetrics().DigestMismatch) })
}

// bindCacheMetrics registers the cache's cumulative counters as scrape-time
// callbacks so the single source of truth (the cache's own atomics) is read live
// on each scrape rather than duplicated.
func bindCacheMetrics(c *metrics.Collector, cacheImpl cache.Cache) {
	src, ok := cacheImpl.(cacheMetricsSource)
	if !ok {
		return
	}
	c.BindCounter("pullthrough_cache_hits_total",
		"Total cache reads served from the cache.",
		func() float64 { return float64(src.Metrics().Hits) })
	c.BindCounter("pullthrough_cache_misses_total",
		"Total cache reads for an absent or expired key.",
		func() float64 { return float64(src.Metrics().Misses) })
	c.BindGauge("pullthrough_cache_hit_ratio",
		"Cache hit ratio over all reads (0..1).",
		func() float64 { return src.Metrics().HitRatio() })
	c.BindCounter("pullthrough_cache_loads_total",
		"Total upstream loads performed to fill the cache.",
		func() float64 { return float64(src.Metrics().Loads) })
	c.BindCounter("pullthrough_cache_evictions_total",
		"Total entries removed by the max-size LRU policy.",
		func() float64 { return float64(src.Metrics().Evictions) })
	c.BindCounter("pullthrough_cache_expired_total",
		"Total entries removed by the TTL policy.",
		func() float64 { return float64(src.Metrics().Expired) })
	c.BindCounter("pullthrough_cache_written_bytes_total",
		"Total content bytes written to the cache store.",
		func() float64 { return float64(src.Metrics().BytesWritten) })
	c.BindCounter("pullthrough_cache_served_bytes_total",
		"Total content bytes served from the cache store.",
		func() float64 { return float64(src.Metrics().BytesServed) })
	c.BindCounter("pullthrough_cache_errors_total",
		"Total cache store operations that failed for a reason other than a miss (e.g. backend/object-storage I/O errors).",
		func() float64 { return float64(src.Metrics().Errors) })
	c.BindCounter("pullthrough_cache_coalesced_total",
		"Total concurrent loads merged into another in-flight upstream fetch instead of duplicating it.",
		func() float64 { return float64(src.Metrics().Coalesced) })
}

// integrityMetricsSource is the cache's read-time integrity counter surface
// (Task 107). The IntegrityCache wrapper satisfies it.
type integrityMetricsSource interface {
	IntegrityMetrics() cache.IntegrityMetricsSnapshot
}

// bindIntegrityMetrics registers the content-integrity verification counters
// (verifications performed and mismatches detected) as scrape-time gauges read
// live from the cache wrapper. Absent when the cache is not integrity-wrapped.
func bindIntegrityMetrics(c *metrics.Collector, cacheImpl cache.Cache) {
	src, ok := cacheImpl.(integrityMetricsSource)
	if !ok {
		return
	}
	c.BindCounter("pullthrough_integrity_verifications_total",
		"Total content-integrity verifications performed (read-time plus background scan), whether they passed or failed.",
		func() float64 { return float64(src.IntegrityMetrics().Verifications) })
	c.BindCounter("pullthrough_integrity_failures_total",
		"Total content-integrity verifications that detected a digest mismatch (tampering or bit-rot).",
		func() float64 { return float64(src.IntegrityMetrics().Failures) })
}

// bindCompactionMetrics registers the transparent storage-efficiency layer's
// counters and ratio (Task 125) as scrape-time callbacks read live from the
// cache wrapper. Absent when the compaction layer is disabled (the snapshot
// reports Enabled=false and the metrics report zero).
func bindCompactionMetrics(c *metrics.Collector, cacheImpl cache.Cache) {
	src, ok := cacheImpl.(cache.CompactionStatSource)
	if !ok {
		return
	}
	c.BindGauge("pullthrough_cache_compression_ratio",
		"Ratio of logical (uncompressed) bytes to physical bytes written through the cache compaction layer (>1 means a net saving; 0 when the layer is disabled or idle).",
		func() float64 { return src.CompactionStats().CompressionRatio })
	c.BindCounter("pullthrough_cache_compression_logical_bytes_total",
		"Total uncompressed content bytes written through the cache compaction layer.",
		func() float64 { return float64(src.CompactionStats().LogicalBytes) })
	c.BindCounter("pullthrough_cache_compression_physical_bytes_total",
		"Total bytes actually written to the backend after compression and deduplication.",
		func() float64 { return float64(src.CompactionStats().PhysicalBytes) })
	c.BindCounter("pullthrough_cache_compression_saved_bytes_total",
		"Total bytes saved by compression and deduplication (logical minus physical).",
		func() float64 { return float64(src.CompactionStats().SavedBytes) })
	c.BindCounter("pullthrough_cache_dedup_savings_bytes",
		"Total logical bytes that did not need to be written because the chunk was already present (cross-artifact deduplication).",
		func() float64 { return float64(src.CompactionStats().DedupSavingsBytes) })
	c.BindGauge("pullthrough_cache_dedup_unique_chunks",
		"Current number of distinct deduplicated chunks held in the cache.",
		func() float64 { return float64(src.CompactionStats().UniqueChunks) })
}

// bindEncryptionMetrics registers the at-rest encryption envelope's counters
// (Task 141) as scrape-time callbacks read live from the cache wrapper. Absent
// when the encryption layer is disabled (the snapshot reports Enabled=false and
// the metrics report zero).
func bindEncryptionMetrics(c *metrics.Collector, cacheImpl cache.Cache) {
	src, ok := cacheImpl.(cache.EncryptionStatSource)
	if !ok {
		return
	}
	c.BindGauge("pullthrough_cache_encryption_enabled",
		"1 when the at-rest cache encryption envelope is active, 0 otherwise.",
		func() float64 {
			if src.EncryptionStats().Enabled {
				return 1
			}
			return 0
		})
	c.BindCounter("pullthrough_cache_encryption_objects_encrypted_total",
		"Total objects encrypted and written through the at-rest cache encryption layer.",
		func() float64 { return float64(src.EncryptionStats().ObjectsEncrypted) })
	c.BindCounter("pullthrough_cache_encryption_objects_decrypted_total",
		"Total objects fully decrypted and served through the at-rest cache encryption layer.",
		func() float64 { return float64(src.EncryptionStats().ObjectsDecrypted) })
	c.BindCounter("pullthrough_cache_encryption_bytes_encrypted_total",
		"Total plaintext bytes encrypted at rest.",
		func() float64 { return float64(src.EncryptionStats().BytesEncrypted) })
	c.BindCounter("pullthrough_cache_encryption_bytes_decrypted_total",
		"Total plaintext bytes produced by decrypting cached objects.",
		func() float64 { return float64(src.EncryptionStats().BytesDecrypted) })
	c.BindCounter("pullthrough_cache_encryption_deks_wrapped_total",
		"Total data-encryption keys wrapped by a key-encryption key (on write and on rotation re-wrap).",
		func() float64 { return float64(src.EncryptionStats().DEKsWrapped) })
	c.BindCounter("pullthrough_cache_encryption_decrypt_failures_total",
		"Total decryption/authentication failures (missing key-encryption key, tampering, or bit-rot).",
		func() float64 { return float64(src.EncryptionStats().DecryptFailures) })
	c.BindCounter("pullthrough_cache_encryption_rewrapped_objects_total",
		"Total objects whose data key was re-wrapped to a new key-encryption key by a rotation.",
		func() float64 { return float64(src.EncryptionStats().RewrappedObjects) })
	c.BindCounter("pullthrough_cache_encryption_rotations_total",
		"Total completed key-encryption-key rotations.",
		func() float64 { return float64(src.EncryptionStats().Rotations) })
}

// bindTieredMetrics registers the hot/cold tiered storage layer's counters and
// gauges (Task 154) as scrape-time callbacks read live from the tiered store.
// Absent when no tiering layer is composed into the cache stack.
func bindTieredMetrics(c *metrics.Collector, cacheImpl cache.Cache) {
	ts, ok := cache.TieredStoreOf(cacheImpl)
	if !ok {
		return
	}
	c.BindGauge("pullthrough_cache_tier_enabled",
		"1 when the hot/cold tiered cache storage layer is active, 0 otherwise.",
		func() float64 { return 1 })
	c.BindCounter("pullthrough_cache_tier_promotions_total",
		"Total artifacts promoted from the cold tier to the hot tier on a read hit.",
		func() float64 { return float64(ts.TieredStats().Promotions) })
	c.BindCounter("pullthrough_cache_tier_demotions_total",
		"Total artifacts demoted from the hot tier to the cold tier by the background sweep.",
		func() float64 { return float64(ts.TieredStats().Demotions) })
	c.BindCounter("pullthrough_cache_tier_promote_failures_total",
		"Total promote-on-read tier moves that failed.",
		func() float64 { return float64(ts.TieredStats().PromoteFailures) })
	c.BindCounter("pullthrough_cache_tier_demote_failures_total",
		"Total demotion tier moves that failed.",
		func() float64 { return float64(ts.TieredStats().DemoteFailures) })
	c.BindCounter("pullthrough_cache_tier_hot_hits_total",
		"Total reads served from an artifact residing on the hot tier at lookup time.",
		func() float64 { return float64(ts.TieredStats().HotHits) })
	c.BindCounter("pullthrough_cache_tier_cold_hits_total",
		"Total reads served from an artifact residing on the cold tier at lookup time.",
		func() float64 { return float64(ts.TieredStats().ColdHits) })
	c.BindGauge("pullthrough_cache_tier_hot_hit_ratio",
		"Fraction of tier-resolved reads served from the hot tier (hotHits/(hotHits+coldHits)).",
		func() float64 { return ts.TieredStats().HotTierHitRatio })
	c.BindCounter("pullthrough_cache_tier_sweeps_total",
		"Total completed background tier-demotion sweeps.",
		func() float64 { return float64(ts.TieredStats().Sweeps) })
	c.BindGaugeVec("pullthrough_cache_tier_objects",
		"Current number of cached artifacts held in each tier.",
		[]string{"tier"},
		func() []metrics.LabeledValue {
			st := ts.TieredStats()
			return []metrics.LabeledValue{
				{Labels: []string{"hot"}, Value: float64(st.HotObjects)},
				{Labels: []string{"cold"}, Value: float64(st.ColdObjects)},
			}
		})
	c.BindGaugeVec("pullthrough_cache_tier_bytes",
		"Current physical bytes held in each tier.",
		[]string{"tier"},
		func() []metrics.LabeledValue {
			st := ts.TieredStats()
			return []metrics.LabeledValue{
				{Labels: []string{"hot"}, Value: float64(st.HotBytes)},
				{Labels: []string{"cold"}, Value: float64(st.ColdBytes)},
			}
		})
}

// bindMavenMetrics surfaces the Maven backends' supply-chain telemetry —
// checksum verifications and mismatches, missing sidecars, POM parses, snapshot
// resolution, and POM/path coordinate mismatches — as labeled counters keyed by
// backend. Values are read live from each backend's atomics at scrape time. With
// no Maven upstreams configured the metrics are simply absent.
func bindMavenMetrics(c *metrics.Collector, registry *backends.Registry) {
	mavenBackends := func() map[string]*maven.Backend {
		out := make(map[string]*maven.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if mb, ok := backends.Unwrap(b).(*maven.Backend); ok {
					out[name] = mb
				}
			}
		}
		return out
	}

	// Bridge one logical counter across all Maven backends, labeled by backend,
	// reading the named field from each backend's Snapshot.
	bridge := func(metric, help string, field func(maven.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := mavenBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, mb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(mb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_maven_artifacts_verified_total",
		"Maven artifacts whose content was verified against an upstream checksum sidecar, by backend.",
		func(s maven.Snapshot) float64 { return s.ArtifactsVerified })
	bridge("pullthrough_maven_checksum_mismatches_total",
		"Maven artifacts whose content failed checksum verification and were refused, by backend.",
		func(s maven.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_maven_sidecar_missing_total",
		"Maven artifacts served without any usable upstream checksum sidecar, by backend.",
		func(s maven.Snapshot) float64 { return s.SidecarMissing })
	bridge("pullthrough_maven_poms_parsed_total",
		"Maven POMs successfully parsed for coordinate/license enrichment, by backend.",
		func(s maven.Snapshot) float64 { return s.POMsParsed })
	bridge("pullthrough_maven_pom_parse_errors_total",
		"Maven POMs that failed to parse, by backend.",
		func(s maven.Snapshot) float64 { return s.POMParseErrors })
	bridge("pullthrough_maven_coordinate_mismatches_total",
		"Maven POMs whose declared GAV disagreed with their repository path, by backend.",
		func(s maven.Snapshot) float64 { return s.CoordinateMismatch })
	bridge("pullthrough_maven_snapshot_metadata_total",
		"Maven snapshot maven-metadata.xml documents served, by backend.",
		func(s maven.Snapshot) float64 { return s.SnapshotMetadata })
	bridge("pullthrough_maven_release_metadata_total",
		"Maven release maven-metadata.xml documents served, by backend.",
		func(s maven.Snapshot) float64 { return s.ReleaseMetadata })
}

// bindGitLFSMetrics surfaces the Git LFS pull-through telemetry (Task 123) —
// batch negotiations, per-object cache hits/misses, bytes fetched/served,
// OID/size integrity rejections, and content-gate findings/blocks — as labeled
// counters keyed by git backend. Values are read live from each backend's
// atomics at scrape time. With no git upstreams (or LFS disabled) the metrics
// are simply absent.
func bindGitLFSMetrics(c *metrics.Collector, registry *backends.Registry) {
	gitBackends := func() map[string]*git.Backend {
		out := make(map[string]*git.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if gb, ok := backends.Unwrap(b).(*git.Backend); ok {
					out[name] = gb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(git.LFSSnapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := gitBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, gb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(gb.LFSMetrics())})
			}
			return out
		})
	}

	bridge("pullthrough_lfs_batch_requests_total",
		"Git LFS batch-API negotiations handled, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.BatchRequests) })
	bridge("pullthrough_lfs_batch_objects_total",
		"Git LFS objects negotiated across all batch requests, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.BatchObjects) })
	bridge("pullthrough_lfs_object_requests_total",
		"Git LFS per-object transfer (download) requests handled, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.ObjectRequests) })
	bridge("pullthrough_lfs_cache_hits_total",
		"Git LFS object requests served from the content-addressable cache, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.CacheHits) })
	bridge("pullthrough_lfs_cache_misses_total",
		"Git LFS object requests that triggered an upstream fetch, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.CacheMisses) })
	bridge("pullthrough_lfs_fetched_bytes_total",
		"Git LFS object bytes downloaded from upstream, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.BytesFetched) })
	bridge("pullthrough_lfs_served_bytes_total",
		"Git LFS object bytes written to clients, including partial (range) responses, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.BytesServed) })
	bridge("pullthrough_lfs_oid_mismatches_total",
		"Git LFS fetches rejected because the content sha256 did not match the requested OID, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.OIDMismatches) })
	bridge("pullthrough_lfs_size_mismatches_total",
		"Git LFS fetches rejected because the content length did not match the declared size, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.SizeMismatches) })
	bridge("pullthrough_lfs_gate_findings_total",
		"Git LFS blob content-gate findings (e.g. embedded secrets), by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.GateFindings) })
	bridge("pullthrough_lfs_gate_blocked_total",
		"Git LFS objects refused because of a content-gate finding, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.GateBlocked) })
	bridge("pullthrough_lfs_errors_total",
		"Git LFS pull-through errors (upstream/transport/oversize) on the object path, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.Errors) })
	bridge("pullthrough_lfs_uploads_rejected_total",
		"Git LFS batch upload operations rejected by the read-only proxy, by backend.",
		func(s git.LFSSnapshot) float64 { return float64(s.RejectedUpload) })
}

// bindRubygemsMetrics surfaces the RubyGems backends' supply-chain telemetry —
// .gem checksum verifications and mismatches, missing checksums, compact-index
// /info parses, and index/legacy documents served — as labeled counters keyed by
// backend. Values are read live from each backend's atomics at scrape time. With
// no RubyGems upstreams configured the metrics are simply absent.
func bindRubygemsMetrics(c *metrics.Collector, registry *backends.Registry) {
	rubygemsBackends := func() map[string]*rubygems.Backend {
		out := make(map[string]*rubygems.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if rb, ok := backends.Unwrap(b).(*rubygems.Backend); ok {
					out[name] = rb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(rubygems.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := rubygemsBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, rb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(rb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_rubygems_gems_verified_total",
		"RubyGems .gem files whose content was verified against the compact-index SHA-256 checksum, by backend.",
		func(s rubygems.Snapshot) float64 { return s.GemsVerified })
	bridge("pullthrough_rubygems_checksum_mismatches_total",
		"RubyGems .gem files whose content failed checksum verification and were refused, by backend.",
		func(s rubygems.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_rubygems_checksum_missing_total",
		"RubyGems .gem files served without a recoverable compact-index checksum, by backend.",
		func(s rubygems.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_rubygems_info_parsed_total",
		"RubyGems compact-index /info documents successfully parsed for checksum recovery, by backend.",
		func(s rubygems.Snapshot) float64 { return s.InfoParsed })
	bridge("pullthrough_rubygems_info_parse_errors_total",
		"RubyGems compact-index /info documents that failed to parse, by backend.",
		func(s rubygems.Snapshot) float64 { return s.InfoParseErrors })
	bridge("pullthrough_rubygems_index_served_total",
		"RubyGems compact-index documents (/versions, /names, /info) served, by backend.",
		func(s rubygems.Snapshot) float64 { return s.IndexServed })
	bridge("pullthrough_rubygems_legacy_served_total",
		"RubyGems legacy Marshal index / dependency-API documents served, by backend.",
		func(s rubygems.Snapshot) float64 { return s.LegacyServed })
}

// bindComposerMetrics surfaces the Composer backends' supply-chain telemetry —
// dist SHA-1 verifications and mismatches, missing shasums, and v2 metadata
// parses/serves — as labeled counters keyed by backend, read live at scrape time.
// With no Composer upstreams configured the metrics are simply absent.
func bindComposerMetrics(c *metrics.Collector, registry *backends.Registry) {
	composerBackends := func() map[string]*composer.Backend {
		out := make(map[string]*composer.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if cb, ok := backends.Unwrap(b).(*composer.Backend); ok {
					out[name] = cb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(composer.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := composerBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, cb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(cb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_composer_dist_verified_total",
		"Composer dist archives whose content was verified against the metadata SHA-1 shasum, by backend.",
		func(s composer.Snapshot) float64 { return s.DistVerified })
	bridge("pullthrough_composer_checksum_mismatches_total",
		"Composer dist archives whose content failed checksum verification and were refused, by backend.",
		func(s composer.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_composer_checksum_missing_total",
		"Composer dist archives served without a recoverable metadata shasum, by backend.",
		func(s composer.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_composer_metadata_parsed_total",
		"Composer v2 metadata documents successfully parsed, by backend.",
		func(s composer.Snapshot) float64 { return s.MetadataParsed })
	bridge("pullthrough_composer_metadata_parse_errors_total",
		"Composer v2 metadata documents that failed to parse, by backend.",
		func(s composer.Snapshot) float64 { return s.MetadataErrors })
	bridge("pullthrough_composer_metadata_served_total",
		"Composer metadata/root/provider documents served, by backend.",
		func(s composer.Snapshot) float64 { return s.MetadataServed })
}

// bindHelmMetrics surfaces the Helm backends' supply-chain telemetry — chart
// .tgz SHA-256 verifications and mismatches, missing index digests, index.yaml
// parses/serves, provenance sidecars served, and OCI-hosted charts served — as
// labeled counters keyed by backend, read live at scrape time. With no Helm
// upstreams configured the metrics are simply absent.
func bindHelmMetrics(c *metrics.Collector, registry *backends.Registry) {
	helmBackends := func() map[string]*helm.Backend {
		out := make(map[string]*helm.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if hb, ok := backends.Unwrap(b).(*helm.Backend); ok {
					out[name] = hb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(helm.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := helmBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, hb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(hb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_helm_charts_verified_total",
		"Helm chart .tgz archives whose content was verified against the repository-index SHA-256 digest, by backend.",
		func(s helm.Snapshot) float64 { return s.ChartsVerified })
	bridge("pullthrough_helm_checksum_mismatches_total",
		"Helm chart archives whose content failed checksum verification and were refused, by backend.",
		func(s helm.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_helm_checksum_missing_total",
		"Helm chart archives served without a recoverable repository-index digest, by backend.",
		func(s helm.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_helm_index_parsed_total",
		"Helm index.yaml documents successfully parsed for chart-digest recovery, by backend.",
		func(s helm.Snapshot) float64 { return s.IndexParsed })
	bridge("pullthrough_helm_index_parse_errors_total",
		"Helm index.yaml documents that failed to parse, by backend.",
		func(s helm.Snapshot) float64 { return s.IndexErrors })
	bridge("pullthrough_helm_index_served_total",
		"Helm index.yaml documents served to clients, by backend.",
		func(s helm.Snapshot) float64 { return s.IndexServed })
	bridge("pullthrough_helm_provenance_served_total",
		"Helm chart provenance (.prov) sidecars served, by backend.",
		func(s helm.Snapshot) float64 { return s.ProvenanceServed })
	bridge("pullthrough_helm_oci_charts_served_total",
		"OCI-registry-hosted Helm chart manifests served via the OCI path, by backend.",
		func(s helm.Snapshot) float64 { return s.OCIChartsServed })
}

// bindTerraformMetrics surfaces the Terraform/OpenTofu backends' supply-chain
// telemetry — provider ZIP SHA-256 verifications and mismatches against the
// signed SHASUMS manifest, SHASUMS GPG-signature outcomes, module source archives
// fetched and cached, descriptors/version-lists served, and pass-throughs — as
// labeled counters keyed by backend, read live at scrape time. With no Terraform
// upstreams configured the metrics are simply absent.
func bindTerraformMetrics(c *metrics.Collector, registry *backends.Registry) {
	terraformBackends := func() map[string]*terraform.Backend {
		out := make(map[string]*terraform.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if tb, ok := backends.Unwrap(b).(*terraform.Backend); ok {
					out[name] = tb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(terraform.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := terraformBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, tb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(tb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_terraform_providers_verified_total",
		"Terraform provider ZIPs whose content was verified against the signed SHASUMS manifest, by backend.",
		func(s terraform.Snapshot) float64 { return s.ProvidersVerified })
	bridge("pullthrough_terraform_checksum_mismatches_total",
		"Terraform provider ZIPs whose content failed SHA-256 verification and were refused, by backend.",
		func(s terraform.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_terraform_checksum_missing_total",
		"Terraform provider ZIPs served without a recoverable SHASUMS digest, by backend.",
		func(s terraform.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_terraform_signature_verified_total",
		"Terraform SHASUMS manifests whose GPG signature verified against a registry-asserted key, by backend.",
		func(s terraform.Snapshot) float64 { return s.SignatureVerified })
	bridge("pullthrough_terraform_signature_failed_total",
		"Terraform SHASUMS manifests whose GPG signature failed verification and were refused, by backend.",
		func(s terraform.Snapshot) float64 { return s.SignatureFailed })
	bridge("pullthrough_terraform_signature_missing_total",
		"Terraform provider downloads served without a verifiable SHASUMS signature, by backend.",
		func(s terraform.Snapshot) float64 { return s.SignatureMissing })
	bridge("pullthrough_terraform_provider_downloads_total",
		"Terraform provider package descriptors served, by backend.",
		func(s terraform.Snapshot) float64 { return s.ProviderDownloads })
	bridge("pullthrough_terraform_provider_versions_total",
		"Terraform provider version-list documents served, by backend.",
		func(s terraform.Snapshot) float64 { return s.ProviderVersions })
	bridge("pullthrough_terraform_module_archives_total",
		"Terraform module source archives fetched and cached, by backend.",
		func(s terraform.Snapshot) float64 { return s.ModuleArchives })
	bridge("pullthrough_terraform_module_downloads_total",
		"Terraform module download descriptors (X-Terraform-Get) served, by backend.",
		func(s terraform.Snapshot) float64 { return s.ModuleDownloads })
	bridge("pullthrough_terraform_module_versions_total",
		"Terraform module version-list documents served, by backend.",
		func(s terraform.Snapshot) float64 { return s.ModuleVersions })
	bridge("pullthrough_terraform_artifacts_passthrough_total",
		"Terraform artifacts whose URLs were passed through unrewritten (non-HTTP getter or no public base), by backend.",
		func(s terraform.Snapshot) float64 { return s.ModuleArchivePassed })
	bridge("pullthrough_terraform_json_parse_errors_total",
		"Terraform provider/module descriptors that failed to parse, by backend.",
		func(s terraform.Snapshot) float64 { return s.JSONParseErrors })
}

// bindConanMetrics surfaces the Conan backends' supply-chain telemetry — files
// served and verified against conanmanifest.txt, checksum mismatches, missing
// manifests, conaninfo descriptors, and discovery/listing documents — as labeled
// counters keyed by backend. Values are read live from each backend's atomics at
// scrape time. With no Conan upstreams configured the metrics are simply absent.
func bindConanMetrics(c *metrics.Collector, registry *backends.Registry) {
	conanBackends := func() map[string]*conan.Backend {
		out := make(map[string]*conan.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if cb, ok := backends.Unwrap(b).(*conan.Backend); ok {
					out[name] = cb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(conan.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := conanBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, cb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(cb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_conan_files_verified_total",
		"Conan content files whose MD5 was verified against the revision's conanmanifest.txt (or, for the .tgz archives it does not list, the upstream's X-Checksum-Md5), by backend.",
		func(s conan.Snapshot) float64 { return s.FilesVerified })
	bridge("pullthrough_conan_checksum_mismatches_total",
		"Conan content files whose content failed MD5 verification and were refused, by backend.",
		func(s conan.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_conan_manifest_missing_total",
		"Conan content files served unverified because the upstream declared no MD5 for them (no conanmanifest.txt entry and no X-Checksum-Md5), by backend.",
		func(s conan.Snapshot) float64 { return s.ManifestMissing })
	bridge("pullthrough_conan_files_served_total",
		"Conan recipe/package content files served, by backend.",
		func(s conan.Snapshot) float64 { return s.FilesServed })
	bridge("pullthrough_conan_conaninfo_served_total",
		"Conan package conaninfo.txt descriptors served, by backend.",
		func(s conan.Snapshot) float64 { return s.ConanInfoServed })
	bridge("pullthrough_conan_file_listings_total",
		"Conan per-revision file-listing documents served, by backend.",
		func(s conan.Snapshot) float64 { return s.FileListingServed })
	bridge("pullthrough_conan_metadata_served_total",
		"Conan discovery documents (latest/revisions/search/ping/users) served, by backend.",
		func(s conan.Snapshot) float64 { return s.MetadataServed })
}

// bindCondaMetrics surfaces the Conda backends' supply-chain telemetry —
// packages served and verified against the subdir's repodata.json, checksum
// mismatches, missing digests, repodata fetches, and index documents — as
// labeled counters keyed by backend. Values are read live from each backend's
// atomics at scrape time. With no Conda channels configured the metrics are
// simply absent.
func bindCondaMetrics(c *metrics.Collector, registry *backends.Registry) {
	condaBackends := func() map[string]*conda.Backend {
		out := make(map[string]*conda.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if cb, ok := backends.Unwrap(b).(*conda.Backend); ok {
					out[name] = cb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(conda.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := condaBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, cb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(cb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_conda_packages_verified_total",
		"Conda packages whose digest was verified against the subdir's repodata.json, by backend.",
		func(s conda.Snapshot) float64 { return s.PackagesVerified })
	bridge("pullthrough_conda_checksum_mismatches_total",
		"Conda packages whose content failed digest verification and were refused, by backend.",
		func(s conda.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_conda_checksum_missing_total",
		"Conda packages served without a usable repodata.json digest, by backend.",
		func(s conda.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_conda_packages_served_total",
		"Conda package archives served, by backend.",
		func(s conda.Snapshot) float64 { return s.PackagesServed })
	bridge("pullthrough_conda_repodata_fetched_total",
		"Conda repodata.json indices fetched to resolve a package digest, by backend.",
		func(s conda.Snapshot) float64 { return s.RepodataFetched })
	bridge("pullthrough_conda_index_served_total",
		"Conda repodata/channeldata index documents served, by backend.",
		func(s conda.Snapshot) float64 { return s.IndexServed })
}

// bindCranMetrics surfaces the CRAN (R) backends' supply-chain telemetry —
// tarballs served and verified against the sibling PACKAGES index, checksum
// mismatches, missing digests, index fetches, and index documents — as labeled
// counters keyed by backend, read live at scrape time. With no CRAN repositories
// configured the metrics are simply absent.
func bindCranMetrics(c *metrics.Collector, registry *backends.Registry) {
	cranBackends := func() map[string]*cran.Backend {
		out := make(map[string]*cran.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if cb, ok := backends.Unwrap(b).(*cran.Backend); ok {
					out[name] = cb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(cran.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := cranBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, cb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(cb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_cran_packages_verified_total",
		"CRAN tarballs whose MD5 was verified against the sibling PACKAGES index, by backend.",
		func(s cran.Snapshot) float64 { return s.PackagesVerified })
	bridge("pullthrough_cran_checksum_mismatches_total",
		"CRAN tarballs whose content failed MD5 verification and were refused, by backend.",
		func(s cran.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_cran_checksum_missing_total",
		"CRAN tarballs served without a usable PACKAGES digest, by backend.",
		func(s cran.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_cran_packages_served_total",
		"CRAN package tarballs served, by backend.",
		func(s cran.Snapshot) float64 { return s.PackagesServed })
	bridge("pullthrough_cran_packages_fetched_total",
		"CRAN PACKAGES indices fetched to resolve a tarball digest, by backend.",
		func(s cran.Snapshot) float64 { return s.PackagesFetched })
	bridge("pullthrough_cran_index_served_total",
		"CRAN PACKAGES index documents served, by backend.",
		func(s cran.Snapshot) float64 { return s.IndexServed })
}

// bindCpanMetrics surfaces the CPAN (Perl) backends' supply-chain telemetry —
// distribution tarballs served and verified against the sibling CHECKSUMS file's
// SHA-256, checksum mismatches, missing digests, CHECKSUMS fetches, and module /
// sidecar index documents — as labeled counters keyed by backend, read live at
// scrape time. With no CPAN repositories configured the metrics are simply absent.
func bindCpanMetrics(c *metrics.Collector, registry *backends.Registry) {
	cpanBackends := func() map[string]*cpan.Backend {
		out := make(map[string]*cpan.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if cb, ok := backends.Unwrap(b).(*cpan.Backend); ok {
					out[name] = cb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(cpan.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := cpanBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, cb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(cb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_cpan_distributions_verified_total",
		"CPAN distribution tarballs whose SHA-256 was verified against the sibling CHECKSUMS file, by backend.",
		func(s cpan.Snapshot) float64 { return s.DistributionsVerified })
	bridge("pullthrough_cpan_checksum_mismatches_total",
		"CPAN distribution tarballs whose content failed SHA-256 verification and were refused, by backend.",
		func(s cpan.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_cpan_checksum_missing_total",
		"CPAN distribution tarballs served without a usable CHECKSUMS digest, by backend.",
		func(s cpan.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_cpan_distributions_served_total",
		"CPAN distribution tarballs served, by backend.",
		func(s cpan.Snapshot) float64 { return s.DistributionsServed })
	bridge("pullthrough_cpan_checksums_fetched_total",
		"CPAN CHECKSUMS files fetched to resolve a distribution digest, by backend.",
		func(s cpan.Snapshot) float64 { return s.ChecksumsFetched })
	bridge("pullthrough_cpan_index_served_total",
		"CPAN module/sidecar index documents served, by backend.",
		func(s cpan.Snapshot) float64 { return s.IndexServed })
}

// bindHexMetrics surfaces the Hex (Elixir) backends' supply-chain telemetry —
// release tarballs served and verified against the sibling /packages/<name>
// resource's outer_checksum, checksum mismatches, missing digests, resource
// fetches, signed registry documents, and /installs/ pass-through — as labeled
// counters keyed by backend, read live at scrape time. With no Hex repositories
// configured the metrics are simply absent.
func bindHexMetrics(c *metrics.Collector, registry *backends.Registry) {
	hexBackends := func() map[string]*hex.Backend {
		out := make(map[string]*hex.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if hb, ok := backends.Unwrap(b).(*hex.Backend); ok {
					out[name] = hb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(hex.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := hexBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, hb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(hb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_hex_tarballs_verified_total",
		"Hex release tarballs whose SHA-256 was verified against the sibling /packages resource's outer_checksum, by backend.",
		func(s hex.Snapshot) float64 { return s.TarballsVerified })
	bridge("pullthrough_hex_checksum_mismatches_total",
		"Hex tarballs whose content failed SHA-256 verification and were refused, by backend.",
		func(s hex.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_hex_checksum_missing_total",
		"Hex tarballs served without a usable outer_checksum, by backend.",
		func(s hex.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_hex_tarballs_served_total",
		"Hex release tarballs served, by backend.",
		func(s hex.Snapshot) float64 { return s.TarballsServed })
	bridge("pullthrough_hex_resources_fetched_total",
		"Hex /packages resources fetched to resolve a tarball's outer_checksum, by backend.",
		func(s hex.Snapshot) float64 { return s.ResourceFetched })
	bridge("pullthrough_hex_registry_served_total",
		"Hex signed registry resources (names/versions/packages) served, by backend.",
		func(s hex.Snapshot) float64 { return s.RegistryServed })
	bridge("pullthrough_hex_installs_served_total",
		"Hex /installs/ files (Hex and Rebar self-install lists, signatures, and builds) passed through live, by backend.",
		func(s hex.Snapshot) float64 { return s.InstallsServed })
}

// bindJsrMetrics surfaces the JSR backends' supply-chain telemetry — module
// files served and verified against the version manifest's SHA-256, checksum
// mismatches, missing digests, version-metadata fetches, and metadata documents
// served and URL-rewritten — as labeled counters keyed by backend, read live at
// scrape time. With no JSR registries configured the metrics are simply absent.
func bindJsrMetrics(c *metrics.Collector, registry *backends.Registry) {
	jsrBackends := func() map[string]*jsr.Backend {
		out := make(map[string]*jsr.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if jb, ok := backends.Unwrap(b).(*jsr.Backend); ok {
					out[name] = jb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(jsr.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := jsrBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, jb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(jb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_jsr_modules_verified_total",
		"JSR module files whose SHA-256 was verified against the version manifest, by backend.",
		func(s jsr.Snapshot) float64 { return s.ModulesVerified })
	bridge("pullthrough_jsr_checksum_mismatches_total",
		"JSR module files whose content failed SHA-256 verification and were refused, by backend.",
		func(s jsr.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_jsr_checksum_missing_total",
		"JSR module files served without a usable manifest digest, by backend.",
		func(s jsr.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_jsr_modules_served_total",
		"JSR module files served, by backend.",
		func(s jsr.Snapshot) float64 { return s.ModulesServed })
	bridge("pullthrough_jsr_version_meta_fetched_total",
		"JSR version-metadata documents fetched to resolve a module file's digest, by backend.",
		func(s jsr.Snapshot) float64 { return s.VersionMetaFetched })
	bridge("pullthrough_jsr_metadata_served_total",
		"JSR metadata documents (package/version meta) served, by backend.",
		func(s jsr.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_jsr_metadata_rewritten_total",
		"JSR metadata documents whose embedded upstream URLs were rewritten to the proxy, by backend.",
		func(s jsr.Snapshot) float64 { return s.MetadataRewritten })
}

// bindHackageMetrics surfaces the Hackage (Haskell) backends' supply-chain
// telemetry — sdist tarballs served and verified against the TUF target
// metadata's SHA-256, checksum mismatches, missing digests, target-metadata
// fetches, and index/TUF/cabal documents served — as labeled counters keyed by
// backend, read live at scrape time. With no Hackage repositories configured the
// metrics are simply absent.
func bindHackageMetrics(c *metrics.Collector, registry *backends.Registry) {
	hackageBackends := func() map[string]*hackage.Backend {
		out := make(map[string]*hackage.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if hb, ok := backends.Unwrap(b).(*hackage.Backend); ok {
					out[name] = hb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(hackage.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := hackageBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, hb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(hb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_hackage_sdists_verified_total",
		"Hackage sdist tarballs whose SHA-256 was verified against the TUF target metadata, by backend.",
		func(s hackage.Snapshot) float64 { return s.SdistsVerified })
	bridge("pullthrough_hackage_checksum_mismatches_total",
		"Hackage sdists whose content failed SHA-256 verification and were refused, by backend.",
		func(s hackage.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_hackage_checksum_missing_total",
		"Hackage sdists served without a usable declared digest, by backend.",
		func(s hackage.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_hackage_sdists_served_total",
		"Hackage sdist tarballs served, by backend.",
		func(s hackage.Snapshot) float64 { return s.SdistsServed })
	bridge("pullthrough_hackage_targets_fetched_total",
		"Hackage package.json TUF target documents fetched to resolve an sdist's digest, by backend.",
		func(s hackage.Snapshot) float64 { return s.TargetsFetched })
	bridge("pullthrough_hackage_index_served_total",
		"Hackage index/TUF/cabal documents served, by backend.",
		func(s hackage.Snapshot) float64 { return s.IndexServed })
}

// bindOpenVSXMetrics surfaces the OpenVSX (VS Code extension marketplace)
// backends' supply-chain telemetry — .vsix archives served and verified against
// the sibling .sha256 sidecar, checksum mismatches, missing digests, sidecar
// fetches, and metadata/gallery documents served and URL-rewritten — as labeled
// counters keyed by backend, read live at scrape time. With no OpenVSX
// registries configured the metrics are simply absent.
func bindOpenVSXMetrics(c *metrics.Collector, registry *backends.Registry) {
	openvsxBackends := func() map[string]*openvsx.Backend {
		out := make(map[string]*openvsx.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if ob, ok := backends.Unwrap(b).(*openvsx.Backend); ok {
					out[name] = ob
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(openvsx.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := openvsxBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, ob := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(ob.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_openvsx_vsix_verified_total",
		"OpenVSX .vsix extension archives whose SHA-256 was verified against the sibling .sha256 sidecar, by backend.",
		func(s openvsx.Snapshot) float64 { return s.VsixVerified })
	bridge("pullthrough_openvsx_checksum_mismatches_total",
		"OpenVSX .vsix archives whose content failed SHA-256 verification and were refused, by backend.",
		func(s openvsx.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_openvsx_checksum_missing_total",
		"OpenVSX .vsix archives served without a usable .sha256 sidecar, by backend.",
		func(s openvsx.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_openvsx_vsix_served_total",
		"OpenVSX .vsix extension archives served, by backend.",
		func(s openvsx.Snapshot) float64 { return s.VsixServed })
	bridge("pullthrough_openvsx_sha256_fetched_total",
		"OpenVSX .sha256 sidecars fetched to resolve a .vsix archive's digest, by backend.",
		func(s openvsx.Snapshot) float64 { return s.SHA256Fetched })
	bridge("pullthrough_openvsx_metadata_served_total",
		"OpenVSX metadata/query documents served, by backend.",
		func(s openvsx.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_openvsx_metadata_rewritten_total",
		"OpenVSX metadata/gallery documents whose embedded upstream URLs were rewritten through the proxy, by backend.",
		func(s openvsx.Snapshot) float64 { return s.MetadataRewrite })
	bridge("pullthrough_openvsx_gallery_served_total",
		"OpenVSX VS Code gallery-protocol documents served, by backend.",
		func(s openvsx.Snapshot) float64 { return s.GalleryServed })
}

// bindBazelMetrics surfaces the Bazel registry backends' supply-chain telemetry
// — module source archives served and verified against source.json's SRI
// integrity, integrity mismatches, missing integrities, source.json fetches and
// URL rewrites, and registry/module metadata documents served — as labeled
// counters keyed by backend, read live at scrape time. With no Bazel registries
// configured the metrics are simply absent.
func bindBazelMetrics(c *metrics.Collector, registry *backends.Registry) {
	bazelBackends := func() map[string]*bazel.Backend {
		out := make(map[string]*bazel.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if bb, ok := backends.Unwrap(b).(*bazel.Backend); ok {
					out[name] = bb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(bazel.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := bazelBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, bb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(bb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_bazel_archives_verified_total",
		"Bazel module source archives whose digest was verified against source.json's SRI integrity, by backend.",
		func(s bazel.Snapshot) float64 { return s.ArchivesVerified })
	bridge("pullthrough_bazel_checksum_mismatches_total",
		"Bazel source archives whose content failed integrity verification and were refused, by backend.",
		func(s bazel.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_bazel_checksum_missing_total",
		"Bazel source archives served without a usable source.json integrity, by backend.",
		func(s bazel.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_bazel_archives_served_total",
		"Bazel module source archives served, by backend.",
		func(s bazel.Snapshot) float64 { return s.ArchivesServed })
	bridge("pullthrough_bazel_source_fetched_total",
		"Bazel source.json descriptors fetched to resolve an archive URL and integrity, by backend.",
		func(s bazel.Snapshot) float64 { return s.SourceFetched })
	bridge("pullthrough_bazel_source_rewritten_total",
		"Bazel source.json descriptors whose archive URL was rewritten to the proxy, by backend.",
		func(s bazel.Snapshot) float64 { return s.SourceRewritten })
	bridge("pullthrough_bazel_index_served_total",
		"Bazel registry/module metadata documents served, by backend.",
		func(s bazel.Snapshot) float64 { return s.IndexServed })
}

// bindHuggingfaceMetrics surfaces the Hugging Face backends' supply-chain
// telemetry — resolve blobs served and verified against the advertised SHA-256,
// checksum mismatches, LFS objects resolved, git-lfs pointers observed,
// safetensors vs pickle weights served, and metadata documents — as labeled
// counters keyed by backend, read live at scrape time. With no Hugging Face
// upstreams configured the metrics are simply absent.
func bindHuggingfaceMetrics(c *metrics.Collector, registry *backends.Registry) {
	hfBackends := func() map[string]*huggingface.Backend {
		out := make(map[string]*huggingface.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if hb, ok := backends.Unwrap(b).(*huggingface.Backend); ok {
					out[name] = hb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(huggingface.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := hfBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, hb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(hb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_huggingface_files_served_total",
		"Hugging Face repository blobs served, by backend.",
		func(s huggingface.Snapshot) float64 { return s.FilesServed })
	bridge("pullthrough_huggingface_files_verified_total",
		"Hugging Face blobs whose SHA-256 verified against the resolve response's advertised content hash, by backend.",
		func(s huggingface.Snapshot) float64 { return s.FilesVerified })
	bridge("pullthrough_huggingface_checksum_mismatches_total",
		"Hugging Face blobs whose content failed SHA-256 verification and were refused, by backend.",
		func(s huggingface.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_huggingface_checksum_missing_total",
		"Hugging Face blobs served without a usable upstream content hash, by backend.",
		func(s huggingface.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_huggingface_lfs_resolved_total",
		"Hugging Face Git LFS objects resolved through the CDN redirect, by backend.",
		func(s huggingface.Snapshot) float64 { return s.LFSResolved })
	bridge("pullthrough_huggingface_pointers_total",
		"Hugging Face git-lfs pointer bodies observed on the resolve path, by backend.",
		func(s huggingface.Snapshot) float64 { return s.PointersSeen })
	bridge("pullthrough_huggingface_safetensors_served_total",
		"Hugging Face safetensors (safe, tensor-only) weight files served, by backend.",
		func(s huggingface.Snapshot) float64 { return s.SafetensorsServed })
	bridge("pullthrough_huggingface_pickle_served_total",
		"Hugging Face pickle-based weight files (.bin/.pkl/.pt/.ckpt) served, by backend.",
		func(s huggingface.Snapshot) float64 { return s.PickleServed })
	bridge("pullthrough_huggingface_metadata_served_total",
		"Hugging Face /api metadata documents served, by backend.",
		func(s huggingface.Snapshot) float64 { return s.MetadataServed })
}

// bindSwiftMetrics surfaces the Swift Package Registry backends' supply-chain
// telemetry — source-archive SHA-256 verifications and mismatches, archives
// served without a usable metadata checksum, release-metadata lookups, manifests
// served, and discovery documents served — as labeled counters keyed by backend,
// read live at scrape time. With no Swift upstreams configured the metrics are
// simply absent.
func bindSwiftMetrics(c *metrics.Collector, registry *backends.Registry) {
	swiftBackends := func() map[string]*swift.Backend {
		out := make(map[string]*swift.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if sb, ok := backends.Unwrap(b).(*swift.Backend); ok {
					out[name] = sb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(swift.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := swiftBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, sb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(sb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_swift_archives_verified_total",
		"Swift source archives whose SHA-256 was verified against the release metadata, by backend.",
		func(s swift.Snapshot) float64 { return s.ArchivesVerified })
	bridge("pullthrough_swift_checksum_mismatches_total",
		"Swift source archives whose content failed SHA-256 verification and were refused, by backend.",
		func(s swift.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_swift_checksum_missing_total",
		"Swift source archives served without a usable metadata checksum, by backend.",
		func(s swift.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_swift_archives_served_total",
		"Swift source archives served, by backend.",
		func(s swift.Snapshot) float64 { return s.ArchivesServed })
	bridge("pullthrough_swift_metadata_fetched_total",
		"Swift release-metadata documents fetched to resolve an archive checksum, by backend.",
		func(s swift.Snapshot) float64 { return s.MetadataFetched })
	bridge("pullthrough_swift_manifests_served_total",
		"Swift Package.swift manifests served, by backend.",
		func(s swift.Snapshot) float64 { return s.ManifestsServed })
	bridge("pullthrough_swift_metadata_served_total",
		"Swift discovery documents (release list, release metadata, identifiers) served, by backend.",
		func(s swift.Snapshot) float64 { return s.MetadataServed })
}

// bindDartMetrics surfaces the Dart/pub backends' supply-chain telemetry —
// package-archive SHA-256 verifications and mismatches, archives served without a
// usable content hash, list-versions documents rewritten and served, and
// advisories served — as labeled counters keyed by backend, read live at scrape
// time. With no Dart upstreams configured the metrics are simply absent.
func bindDartMetrics(c *metrics.Collector, registry *backends.Registry) {
	dartBackends := func() map[string]*dart.Backend {
		out := make(map[string]*dart.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if db, ok := backends.Unwrap(b).(*dart.Backend); ok {
					out[name] = db
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(dart.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := dartBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, db := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(db.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_dart_archives_verified_total",
		"Dart package archives whose SHA-256 was verified against the list-versions document, by backend.",
		func(s dart.Snapshot) float64 { return s.ArchivesVerified })
	bridge("pullthrough_dart_checksum_mismatches_total",
		"Dart package archives whose content failed SHA-256 verification and were refused, by backend.",
		func(s dart.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_dart_checksum_missing_total",
		"Dart package archives served without a usable content hash, by backend.",
		func(s dart.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_dart_archives_served_total",
		"Dart package archives served, by backend.",
		func(s dart.Snapshot) float64 { return s.ArchivesServed })
	bridge("pullthrough_dart_versions_rewritten_total",
		"Dart list-versions documents whose archive_url fields were rewritten through the proxy, by backend.",
		func(s dart.Snapshot) float64 { return s.VersionsRewritten })
	bridge("pullthrough_dart_versions_served_total",
		"Dart list-versions documents served, by backend.",
		func(s dart.Snapshot) float64 { return s.VersionsServed })
	bridge("pullthrough_dart_advisories_served_total",
		"Dart security-advisories documents served, by backend.",
		func(s dart.Snapshot) float64 { return s.AdvisoriesServed })
}

// bindNixMetrics surfaces the Nix binary-cache backends' supply-chain telemetry —
// NAR archives served and verified against the SHA-256 content address in their
// URL, file-hash mismatches, NARs served without a verifiable address, narinfo
// documents served, narinfo signatures verified/rejected/unverified against the
// trusted public keys, narinfo URL rewrites, and nix-cache-info descriptors — as
// labeled counters keyed by backend, read live at scrape time. With no Nix caches
// configured the metrics are simply absent.
func bindNixMetrics(c *metrics.Collector, registry *backends.Registry) {
	nixBackends := func() map[string]*nix.Backend {
		out := make(map[string]*nix.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if nb, ok := backends.Unwrap(b).(*nix.Backend); ok {
					out[name] = nb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(nix.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := nixBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, nb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(nb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_nix_nars_served_total",
		"Nix NAR archives served, by backend.",
		func(s nix.Snapshot) float64 { return s.NarsServed })
	bridge("pullthrough_nix_nars_verified_total",
		"Nix NARs whose SHA-256 verified against the content address named in their URL, by backend.",
		func(s nix.Snapshot) float64 { return s.NarsVerified })
	bridge("pullthrough_nix_file_hash_mismatches_total",
		"Nix NARs whose content failed SHA-256 content-address verification and were refused, by backend.",
		func(s nix.Snapshot) float64 { return s.FileHashMismatch })
	bridge("pullthrough_nix_file_hash_missing_total",
		"Nix NARs served without a verifiable SHA-256 content address, by backend.",
		func(s nix.Snapshot) float64 { return s.FileHashMissing })
	bridge("pullthrough_nix_narinfo_served_total",
		"Nix narinfo documents served, by backend.",
		func(s nix.Snapshot) float64 { return s.NarInfoServed })
	bridge("pullthrough_nix_narinfo_signature_valid_total",
		"Nix narinfos whose ed25519 signature verified against a trusted public key, by backend.",
		func(s nix.Snapshot) float64 { return s.NarInfoSigValid })
	bridge("pullthrough_nix_narinfo_signature_invalid_total",
		"Nix narinfos rejected for lacking a valid signature from a trusted public key, by backend.",
		func(s nix.Snapshot) float64 { return s.NarInfoSigInvalid })
	bridge("pullthrough_nix_narinfo_unverified_total",
		"Nix narinfos served without signature verification (no trusted keys configured), by backend.",
		func(s nix.Snapshot) float64 { return s.NarInfoUnverified })
	bridge("pullthrough_nix_narinfo_rewritten_total",
		"Nix narinfos whose URL field was rewritten to route NAR downloads through the proxy, by backend.",
		func(s nix.Snapshot) float64 { return s.NarInfoRewritten })
	bridge("pullthrough_nix_cache_info_served_total",
		"Nix nix-cache-info descriptors served, by backend.",
		func(s nix.Snapshot) float64 { return s.CacheInfoServed })
}

// bindHomebrewMetrics surfaces the Homebrew backends' supply-chain telemetry —
// formula metadata documents served and rewritten, other metadata proxied, OCI
// manifests proxied from the bottle registry, bottle OCI blobs served and
// verified against the SHA-256 content address in their URL, bottle digest
// mismatches refused, ghcr bearer tokens obtained, and how the formula version
// of each registry-native bottle request was established (learned from the
// manifest, recovered from the formula API, or the digest-derived fallback) —
// as labeled counters keyed by backend, read live at scrape time. With no
// Homebrew upstreams configured the metrics are simply absent.
func bindHomebrewMetrics(c *metrics.Collector, registry *backends.Registry) {
	homebrewBackends := func() map[string]*homebrew.Backend {
		out := make(map[string]*homebrew.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if hb, ok := backends.Unwrap(b).(*homebrew.Backend); ok {
					out[name] = hb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(homebrew.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := homebrewBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, hb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(hb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_homebrew_formula_served_total",
		"Homebrew formula index/per-formula documents served, by backend.",
		func(s homebrew.Snapshot) float64 { return s.FormulaServed })
	bridge("pullthrough_homebrew_formula_rewritten_total",
		"Homebrew formula documents whose bottle download URLs were rewritten through the proxy, by backend.",
		func(s homebrew.Snapshot) float64 { return s.FormulaRewritten })
	bridge("pullthrough_homebrew_metadata_served_total",
		"Homebrew formulae.brew.sh documents (casks, JWS variants) proxied byte-exact, by backend.",
		func(s homebrew.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_homebrew_bottles_served_total",
		"Homebrew bottle OCI blobs served, by backend.",
		func(s homebrew.Snapshot) float64 { return s.BottlesServed })
	bridge("pullthrough_homebrew_bottles_verified_total",
		"Homebrew bottles whose SHA-256 verified against the content address named in their URL, by backend.",
		func(s homebrew.Snapshot) float64 { return s.BottlesVerified })
	bridge("pullthrough_homebrew_bottle_hash_mismatches_total",
		"Homebrew bottles whose content failed SHA-256 content-address verification and were refused, by backend.",
		func(s homebrew.Snapshot) float64 { return s.BottleHashMismatch })
	bridge("pullthrough_homebrew_tokens_fetched_total",
		"Homebrew bottle-registry (ghcr) bearer tokens obtained via the Docker Registry v2 handshake, by backend.",
		func(s homebrew.Snapshot) float64 { return s.TokensFetched })
	bridge("pullthrough_homebrew_manifests_served_total",
		"Homebrew bottle OCI manifests / image indexes proxied from the bottle registry (the brew client's HOMEBREW_ARTIFACT_DOMAIN path), by backend.",
		func(s homebrew.Snapshot) float64 { return s.ManifestsServed })
	bridge("pullthrough_homebrew_bottle_version_manifest_total",
		"Homebrew registry-native bottle requests whose formula version was learned from the OCI image index, by backend.",
		func(s homebrew.Snapshot) float64 { return s.VersionFromManifest })
	bridge("pullthrough_homebrew_bottle_version_formula_api_total",
		"Homebrew registry-native bottle requests whose formula version was recovered from the formula JSON API, by backend.",
		func(s homebrew.Snapshot) float64 { return s.VersionFromFormulaAPI })
	bridge("pullthrough_homebrew_bottle_version_fallback_total",
		"Homebrew registry-native bottle requests whose formula version was unknown and gated under the digest-derived stand-in, by backend.",
		func(s homebrew.Snapshot) float64 { return s.VersionFromDigest })
}

// bindAnsibleMetrics surfaces the Ansible Galaxy backends' supply-chain
// telemetry — collection artifacts served and verified against the version-
// detail document's SHA-256, checksum mismatches, missing digests, version-
// detail fetches, and metadata documents served and URL-rewritten — as labeled
// counters keyed by backend, read live at scrape time. With no Galaxy upstreams
// configured the metrics are simply absent.
func bindAnsibleMetrics(c *metrics.Collector, registry *backends.Registry) {
	ansibleBackends := func() map[string]*ansible.Backend {
		out := make(map[string]*ansible.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if ab, ok := backends.Unwrap(b).(*ansible.Backend); ok {
					out[name] = ab
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(ansible.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := ansibleBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, ab := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(ab.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_ansible_artifacts_verified_total",
		"Ansible Galaxy collection artifacts whose SHA-256 was verified against the version-detail document, by backend.",
		func(s ansible.Snapshot) float64 { return s.ArtifactsVerified })
	bridge("pullthrough_ansible_checksum_mismatches_total",
		"Ansible Galaxy collection artifacts whose content failed SHA-256 verification and were refused, by backend.",
		func(s ansible.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_ansible_checksum_missing_total",
		"Ansible Galaxy collection artifacts served without a usable published digest, by backend.",
		func(s ansible.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_ansible_artifacts_served_total",
		"Ansible Galaxy collection artifacts served, by backend.",
		func(s ansible.Snapshot) float64 { return s.ArtifactsServed })
	bridge("pullthrough_ansible_version_meta_fetched_total",
		"Ansible Galaxy version-detail documents fetched to resolve a collection artifact's digest, by backend.",
		func(s ansible.Snapshot) float64 { return s.VersionMetaFetched })
	bridge("pullthrough_ansible_metadata_served_total",
		"Ansible Galaxy metadata documents (collection index/versions/version-detail/role) served, by backend.",
		func(s ansible.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_ansible_metadata_rewritten_total",
		"Ansible Galaxy metadata documents whose embedded upstream URLs were rewritten to the proxy, by backend.",
		func(s ansible.Snapshot) float64 { return s.MetadataRewritten })
}

// bindPuppetMetrics surfaces the Puppet Forge backends' supply-chain telemetry —
// release tarballs served and verified against the release metadata's
// file_sha256 (or legacy file_md5), checksum mismatches, missing digests, MD5
// fallbacks, release-metadata fetches, and metadata documents served and
// URL-rewritten — as labeled counters keyed by backend, read live at scrape
// time. With no Forge upstreams configured the metrics are simply absent.
func bindPuppetMetrics(c *metrics.Collector, registry *backends.Registry) {
	puppetBackends := func() map[string]*puppet.Backend {
		out := make(map[string]*puppet.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if pb, ok := backends.Unwrap(b).(*puppet.Backend); ok {
					out[name] = pb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(puppet.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := puppetBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, pb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(pb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_puppet_releases_verified_total",
		"Puppet Forge release tarballs whose digest was verified against the release metadata, by backend.",
		func(s puppet.Snapshot) float64 { return s.ReleasesVerified })
	bridge("pullthrough_puppet_checksum_mismatches_total",
		"Puppet Forge release tarballs whose content failed digest verification and were refused, by backend.",
		func(s puppet.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_puppet_checksum_missing_total",
		"Puppet Forge release tarballs served without a usable published digest, by backend.",
		func(s puppet.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_puppet_md5_fallback_total",
		"Puppet Forge release tarballs verified against the legacy MD5 because no SHA-256 was published, by backend.",
		func(s puppet.Snapshot) float64 { return s.MD5Fallback })
	bridge("pullthrough_puppet_releases_served_total",
		"Puppet Forge release tarballs served, by backend.",
		func(s puppet.Snapshot) float64 { return s.ReleasesServed })
	bridge("pullthrough_puppet_release_meta_fetched_total",
		"Puppet Forge release-metadata documents fetched to resolve a release tarball's digest, by backend.",
		func(s puppet.Snapshot) float64 { return s.ReleaseMetaFetch })
	bridge("pullthrough_puppet_metadata_served_total",
		"Puppet Forge metadata documents (module/release/listing) served, by backend.",
		func(s puppet.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_puppet_metadata_rewritten_total",
		"Puppet Forge metadata documents whose embedded upstream URLs were rewritten to the proxy, by backend.",
		func(s puppet.Snapshot) float64 { return s.MetadataRewritten })
}

// bindGenericMetrics surfaces the config-driven generic backends' supply-chain
// telemetry (Task 147) — artifacts served and verified against a declared content
// digest, checksum mismatches, verified routes served without a usable digest,
// sidecars fetched, metadata documents served/rewritten, and requests rejected
// for matching no route — as labeled counters keyed by backend, read live at
// scrape time. With no generic upstreams configured the metrics are simply absent.
func bindGenericMetrics(c *metrics.Collector, registry *backends.Registry) {
	genericBackends := func() map[string]*generic.Backend {
		out := make(map[string]*generic.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if gb, ok := backends.Unwrap(b).(*generic.Backend); ok {
					out[name] = gb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(generic.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := genericBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, gb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(gb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_generic_artifacts_served_total",
		"Generic-backend cacheable artifacts served, by backend.",
		func(s generic.Snapshot) float64 { return s.ArtifactsServed })
	bridge("pullthrough_generic_artifacts_verified_total",
		"Generic-backend artifacts whose content digest verified against the declared value, by backend.",
		func(s generic.Snapshot) float64 { return s.ArtifactsVerified })
	bridge("pullthrough_generic_checksum_mismatches_total",
		"Generic-backend artifacts whose content failed digest verification and were refused, by backend.",
		func(s generic.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_generic_checksum_missing_total",
		"Generic-backend verified-route artifacts served without a usable declared digest (fail-open), by backend.",
		func(s generic.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_generic_sidecars_fetched_total",
		"Generic-backend checksum sidecars fetched to resolve an artifact's digest, by backend.",
		func(s generic.Snapshot) float64 { return s.SidecarsFetched })
	bridge("pullthrough_generic_metadata_served_total",
		"Generic-backend metadata/listing documents served, by backend.",
		func(s generic.Snapshot) float64 { return s.MetadataServed })
	bridge("pullthrough_generic_metadata_rewritten_total",
		"Generic-backend metadata documents whose embedded upstream URLs were rewritten through the proxy, by backend.",
		func(s generic.Snapshot) float64 { return s.MetadataRewrite })
	bridge("pullthrough_generic_unmatched_total",
		"Generic-backend requests rejected because no configured route matched the path, by backend.",
		func(s generic.Snapshot) float64 { return s.Unmatched })
}

// bindAptMetrics surfaces the Debian/APT backends' supply-chain telemetry — .deb
// SHA-256 verifications and mismatches, missing digests, Packages-index parses and
// Release-anchored verifications, Release documents served, and GPG-signature
// outcomes — as labeled counters keyed by backend, read live at scrape time. With
// no APT upstreams configured the metrics are simply absent.
func bindAptMetrics(c *metrics.Collector, registry *backends.Registry) {
	aptBackends := func() map[string]*apt.Backend {
		out := make(map[string]*apt.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if ab, ok := backends.Unwrap(b).(*apt.Backend); ok {
					out[name] = ab
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(apt.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := aptBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, ab := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(ab.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_apt_debs_verified_total",
		"Debian .deb packages whose content was verified against the chain-declared SHA-256 digest, by backend.",
		func(s apt.Snapshot) float64 { return s.DebsVerified })
	bridge("pullthrough_apt_checksum_mismatches_total",
		"Debian .deb packages whose content failed checksum verification and were refused, by backend.",
		func(s apt.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_apt_checksum_missing_total",
		"Debian .deb packages served without a recorded digest from a parsed Packages index, by backend.",
		func(s apt.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_apt_packages_parsed_total",
		"Debian Packages indices successfully parsed for per-.deb digest recovery, by backend.",
		func(s apt.Snapshot) float64 { return s.PackagesParsed })
	bridge("pullthrough_apt_packages_parse_errors_total",
		"Debian Packages indices that failed to decompress or parse, by backend.",
		func(s apt.Snapshot) float64 { return s.PackagesErrors })
	bridge("pullthrough_apt_index_verified_total",
		"Debian Packages indices verified against the suite Release SHA-256, by backend.",
		func(s apt.Snapshot) float64 { return s.IndexVerified })
	bridge("pullthrough_apt_index_mismatches_total",
		"Debian Packages indices whose content failed Release verification and were refused, by backend.",
		func(s apt.Snapshot) float64 { return s.IndexMismatch })
	bridge("pullthrough_apt_release_served_total",
		"Debian Release/InRelease documents served to clients, by backend.",
		func(s apt.Snapshot) float64 { return s.ReleaseServed })
	bridge("pullthrough_apt_signature_verified_total",
		"Debian Release/InRelease GPG signatures validated against a trusted key, by backend.",
		func(s apt.Snapshot) float64 { return s.SignatureVerified })
	bridge("pullthrough_apt_signature_failures_total",
		"Debian Release/InRelease GPG signatures that failed validation and were refused, by backend.",
		func(s apt.Snapshot) float64 { return s.SignatureFailures })
	bridge("pullthrough_apt_signature_skipped_total",
		"Debian Release/InRelease documents served without GPG enforcement (no keyring configured), by backend.",
		func(s apt.Snapshot) float64 { return s.SignatureSkipped })
}

// bindYumMetrics surfaces the RPM/YUM backends' supply-chain telemetry — .rpm
// checksum verifications and mismatches, missing digests, primary.xml/repomd.xml
// parses and repodata verifications, repomd documents served, and GPG-signature
// outcomes — as labeled counters keyed by backend, read live at scrape time. With
// no YUM upstreams configured the metrics are simply absent.
func bindYumMetrics(c *metrics.Collector, registry *backends.Registry) {
	yumBackends := func() map[string]*yum.Backend {
		out := make(map[string]*yum.Backend)
		for _, name := range registry.Names() {
			if b, ok := registry.Get(name); ok {
				if yb, ok := backends.Unwrap(b).(*yum.Backend); ok {
					out[name] = yb
				}
			}
		}
		return out
	}

	bridge := func(metric, help string, field func(yum.Snapshot) float64) {
		c.BindCounterVec(metric, help, []string{"backend"}, func() []metrics.LabeledValue {
			bs := yumBackends()
			out := make([]metrics.LabeledValue, 0, len(bs))
			for name, yb := range bs {
				out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: field(yb.Metrics().Stats())})
			}
			return out
		})
	}

	bridge("pullthrough_yum_rpms_verified_total",
		"RPM packages whose content was verified against the chain-declared digest, by backend.",
		func(s yum.Snapshot) float64 { return s.RPMsVerified })
	bridge("pullthrough_yum_checksum_mismatches_total",
		"RPM packages whose content failed checksum verification and were refused, by backend.",
		func(s yum.Snapshot) float64 { return s.ChecksumMismatch })
	bridge("pullthrough_yum_checksum_missing_total",
		"RPM packages served without a recorded digest from a parsed primary.xml, by backend.",
		func(s yum.Snapshot) float64 { return s.ChecksumMissing })
	bridge("pullthrough_yum_primary_parsed_total",
		"RPM primary.xml documents successfully parsed for per-.rpm digest recovery, by backend.",
		func(s yum.Snapshot) float64 { return s.PrimaryParsed })
	bridge("pullthrough_yum_primary_parse_errors_total",
		"RPM primary.xml documents that failed to decompress or parse, by backend.",
		func(s yum.Snapshot) float64 { return s.PrimaryErrors })
	bridge("pullthrough_yum_repomd_parsed_total",
		"RPM repomd.xml documents successfully parsed, by backend.",
		func(s yum.Snapshot) float64 { return s.RepomdParsed })
	bridge("pullthrough_yum_repomd_parse_errors_total",
		"RPM repomd.xml documents that failed to parse, by backend.",
		func(s yum.Snapshot) float64 { return s.RepomdErrors })
	bridge("pullthrough_yum_repodata_verified_total",
		"RPM repodata files verified against the repomd.xml digest, by backend.",
		func(s yum.Snapshot) float64 { return s.RepodataVerified })
	bridge("pullthrough_yum_repodata_mismatches_total",
		"RPM repodata files whose content failed repomd.xml verification and were refused, by backend.",
		func(s yum.Snapshot) float64 { return s.RepodataMismatch })
	bridge("pullthrough_yum_repomd_served_total",
		"RPM repomd.xml documents served to clients, by backend.",
		func(s yum.Snapshot) float64 { return s.RepomdServed })
	bridge("pullthrough_yum_signature_verified_total",
		"RPM repomd.xml GPG signatures validated against a trusted key, by backend.",
		func(s yum.Snapshot) float64 { return s.SignatureVerified })
	bridge("pullthrough_yum_signature_failures_total",
		"RPM repomd.xml GPG signatures that failed validation and were refused, by backend.",
		func(s yum.Snapshot) float64 { return s.SignatureFailures })
	bridge("pullthrough_yum_signature_skipped_total",
		"RPM repomd.xml documents served without GPG enforcement (no keyring configured), by backend.",
		func(s yum.Snapshot) float64 { return s.SignatureSkipped })
}

// bindScanMetrics registers the commit scanner's live queue gauges so operators
// can alert on a backing-up scan pipeline.
func bindScanMetrics(c *metrics.Collector, scanner *commit.Scanner) {
	if scanner == nil {
		return
	}
	c.BindGauge("pullthrough_scan_queue_depth",
		"Number of commits currently waiting in the async scan queue.",
		func() float64 { return float64(scanner.QueueDepth()) })
	c.BindGauge("pullthrough_scan_pending",
		"Number of commits queued or in-flight for scanning.",
		func() float64 { return float64(scanner.PendingCount()) })

	// Bind the Task 78 per-provider latency/token/cost metrics onto the shared
	// registry, then hand the recorder to the pipeline. The pipeline was built
	// before the registry existed, so it ran with a no-op recorder until now.
	pipeline := scanner.Pipeline()
	if pipeline == nil {
		return
	}
	cm := commit.NewMetrics(c.Registry())
	pipeline.SetMetrics(cm)
	cm.BindBudget(c.Registry(), pipeline.Budgeter())
}

// bindSecretscanMetrics registers the deterministic secret detector's counters
// (Task 29). The per-rule counter is labeled so operators can chart which
// credential formats are being caught, and a suppressed counter surfaces
// allowlist/baseline activity.
func bindSecretscanMetrics(c *metrics.Collector, d *secretscan.Detector) {
	if d == nil {
		return
	}
	c.BindCounter("pullthrough_secrets_diffs_scanned_total",
		"Total commit diffs inspected by the deterministic secret detector.",
		func() float64 { return float64(d.Metrics().DiffsScanned) })
	c.BindCounter("pullthrough_secrets_lines_scanned_total",
		"Total added diff lines inspected by the deterministic secret detector.",
		func() float64 { return float64(d.Metrics().LinesScanned) })
	c.BindCounter("pullthrough_secrets_found_total",
		"Total secret findings emitted by the deterministic secret detector.",
		func() float64 { return float64(d.Metrics().FindingsTotal) })
	c.BindCounter("pullthrough_secrets_suppressed_total",
		"Total secret matches suppressed by the allowlist/baseline.",
		func() float64 { return float64(d.Metrics().Suppressed) })
	c.BindCounterVec("pullthrough_secrets_found_by_rule_total",
		"Secret findings emitted, labeled by the detection rule that fired.",
		[]string{"rule"},
		func() []metrics.LabeledValue {
			snap := d.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ByRule))
			for rule, n := range snap.ByRule {
				out = append(out, metrics.LabeledValue{Labels: []string{rule}, Value: float64(n)})
			}
			return out
		})
}

// bindVulnMetrics registers the vulnerability scanner's cumulative counters and
// live gauges so operators can chart SBOM/CVE activity and alert on a failing
// scan backend.
func bindVulnMetrics(c *metrics.Collector, svc *vulnscan.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_vuln_scans_total",
		"Total artifact vulnerability scans performed (cache misses).",
		func() float64 { return float64(svc.Metrics().ScansTotal) })
	c.BindCounter("pullthrough_vuln_scan_errors_total",
		"Total vulnerability scans that failed to reach the database backend.",
		func() float64 { return float64(svc.Metrics().ScanErrors) })
	c.BindCounter("pullthrough_vuln_scan_cache_hits_total",
		"Total scans served from the result cache without re-querying the database.",
		func() float64 { return float64(svc.Metrics().CacheHits) })
	c.BindCounter("pullthrough_vuln_offline_fallbacks_total",
		"Total scans served from a stale cached result because the backend was unreachable.",
		func() float64 { return float64(svc.Metrics().OfflineFallbacks) })
	c.BindCounter("pullthrough_vuln_blocked_total",
		"Total artifacts blocked by the vulnerability gate.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_vuln_warned_total",
		"Total artifacts served with a vulnerability warning.",
		func() float64 { return float64(svc.Metrics().Warned) })
	c.BindCounter("pullthrough_vuln_quarantined_total",
		"Total artifacts quarantined (blocked and evicted) by the vulnerability gate.",
		func() float64 { return float64(svc.Metrics().Quarantined) })
	c.BindCounter("pullthrough_vulnerabilities_critical_total",
		"Total critical-severity vulnerabilities found across scanned artifacts.",
		func() float64 { return float64(svc.Metrics().VulnCritical) })
	c.BindCounter("pullthrough_vulnerabilities_high_total",
		"Total high-severity vulnerabilities found across scanned artifacts.",
		func() float64 { return float64(svc.Metrics().VulnHigh) })
	c.BindCounter("pullthrough_vulnerabilities_medium_total",
		"Total medium-severity vulnerabilities found across scanned artifacts.",
		func() float64 { return float64(svc.Metrics().VulnMedium) })
	c.BindCounter("pullthrough_vulnerabilities_low_total",
		"Total low-severity vulnerabilities found across scanned artifacts.",
		func() float64 { return float64(svc.Metrics().VulnLow) })
	c.BindGauge("pullthrough_vuln_scan_cache_entries",
		"Number of artifacts with a cached scan result.",
		func() float64 { return float64(svc.Metrics().CacheEntries) })

	// Continuous re-scan / CVE-drift telemetry (Task 18).
	c.BindCounter("pullthrough_rescans_total",
		"Total cached-artifact re-scans performed against the vulnerability database (CVE drift).",
		func() float64 { return float64(svc.Metrics().RescansTotal) })
	c.BindCounter("pullthrough_newly_vulnerable_total",
		"Total cached artifacts that became newly vulnerable (above policy threshold) on re-scan and were quarantined.",
		func() float64 { return float64(svc.Metrics().NewlyVulnerableTotal) })
	c.BindGauge("pullthrough_last_rescan_timestamp",
		"Unix timestamp (seconds) of the last completed re-scan sweep (0 if none).",
		func() float64 { return float64(svc.Metrics().LastRescanUnix) })
	c.BindGauge("pullthrough_quarantined_artifacts",
		"Number of artifacts currently quarantined by the continuous re-scan subsystem.",
		func() float64 { return float64(svc.Metrics().QuarantinedEntries) })

	// VEX-based suppression / escalation telemetry (Task 27).
	c.BindCounter("pullthrough_vex_suppressed_total",
		"Total scan findings suppressed (dropped from gating) by a VEX not_affected/fixed statement.",
		func() float64 { return float64(svc.Metrics().VEXSuppressed) })
	c.BindCounter("pullthrough_vex_escalated_total",
		"Total scan findings whose severity was raised by a VEX affected statement.",
		func() float64 { return float64(svc.Metrics().VEXEscalated) })
	c.BindGauge("pullthrough_vex_statements",
		"Number of VEX statements currently loaded in the suppression store.",
		func() float64 { return float64(svc.Metrics().VEXStatements) })
	c.BindGauge("pullthrough_vex_documents",
		"Number of VEX documents currently loaded in the suppression store.",
		func() float64 { return float64(svc.Metrics().VEXDocuments) })
	c.BindGauge("pullthrough_vex_malformed_documents",
		"Number of VEX documents that failed to parse on the last load and were skipped.",
		func() float64 { return float64(svc.Metrics().VEXMalformed) })
}

// bindLicenseMetrics registers the license-compliance gate's cumulative counters
// so operators can chart allowed/denied/flagged pulls, alert on a spike of denied
// licenses, and track license-drift detections (Task 28). The per-license denied
// counter is labeled so operators can see which licenses are being rejected.
func bindLicenseMetrics(c *metrics.Collector, svc *license.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_license_evaluated_total",
		"Total artifacts evaluated by the license-compliance gate.",
		func() float64 { return float64(svc.Metrics().Evaluated) })
	c.BindCounter("pullthrough_license_allowed_total",
		"Total artifacts allowed by the license-compliance gate.",
		func() float64 { return float64(svc.Metrics().Allowed) })
	c.BindCounter("pullthrough_license_denied_total",
		"Total artifacts blocked or quarantined by the license-compliance gate.",
		func() float64 { return float64(svc.Metrics().Denied) })
	c.BindCounter("pullthrough_license_flagged_total",
		"Total artifacts flagged (warned) for license review or an unknown license.",
		func() float64 { return float64(svc.Metrics().Flagged) })
	c.BindCounter("pullthrough_license_unknown_total",
		"Total component licenses that were unknown / NOASSERTION.",
		func() float64 { return float64(svc.Metrics().UnknownTotal) })
	c.BindCounter("pullthrough_license_drift_total",
		"Total license-drift events detected (a package's license changed across versions).",
		func() float64 { return float64(svc.Metrics().DriftDetected) })
	c.BindCounterVec("pullthrough_license_denied_by_license_total",
		"Artifacts denied by the license gate, labeled by the offending SPDX license.",
		[]string{"license"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.DeniedByLicense))
			for lic, n := range snap.DeniedByLicense {
				out = append(out, metrics.LabeledValue{Labels: []string{lic}, Value: float64(n)})
			}
			return out
		})
}

// bindPolicyEngineMetrics registers the declarative policy-as-code engine's
// cumulative counters (Task 32): rule evaluations, the allow/warn/deny split,
// audit-mode would-be denies, rule-evaluation errors, reloads, and per-rule deny
// reasons. The labeled deny-reason metric lets operators see which rules drive
// the most blocks.
func bindPolicyEngineMetrics(c *metrics.Collector, e *policyengine.Engine) {
	if e == nil {
		return
	}
	c.BindCounter("pullthrough_policyengine_evaluations_total",
		"Total admission evaluations performed by the policy-as-code engine.",
		func() float64 { return float64(e.Snapshot().Evaluations) })
	c.BindCounter("pullthrough_policyengine_allowed_total",
		"Total artifacts allowed by the policy-as-code engine.",
		func() float64 { return float64(e.Snapshot().Allowed) })
	c.BindCounter("pullthrough_policyengine_warned_total",
		"Total artifacts warned on by the policy-as-code engine.",
		func() float64 { return float64(e.Snapshot().Warned) })
	c.BindCounter("pullthrough_policyengine_denied_total",
		"Total artifacts denied by the policy-as-code engine (would-be denies in audit mode included).",
		func() float64 { return float64(e.Snapshot().Denied) })
	c.BindCounter("pullthrough_policyengine_audited_denies_total",
		"Total would-be denies admitted because the engine is in audit (dry-run) mode.",
		func() float64 { return float64(e.Snapshot().AuditedDenies) })
	c.BindCounter("pullthrough_policyengine_rule_errors_total",
		"Total rule predicate evaluation errors (treated as non-matching).",
		func() float64 { return float64(e.Snapshot().RuleErrors) })
	c.BindCounter("pullthrough_policyengine_reloads_total",
		"Total successful policy-bundle reloads.",
		func() float64 { return float64(e.Snapshot().Reloads) })
	c.BindCounter("pullthrough_policyengine_reload_failures_total",
		"Total failed policy-bundle reloads (previous policy retained).",
		func() float64 { return float64(e.Snapshot().ReloadFailures) })
	c.BindGauge("pullthrough_policyengine_rules_loaded",
		"Number of compiled rules currently loaded.",
		func() float64 { return float64(e.Snapshot().RulesLoaded) })
	c.BindCounterVec("pullthrough_policyengine_deny_reasons_total",
		"Artifacts denied by the policy-as-code engine, labeled by the rule that drove the block.",
		[]string{"rule"},
		func() []metrics.LabeledValue {
			snap := e.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.DenyByRule))
			for rule, n := range snap.DenyByRule {
				out = append(out, metrics.LabeledValue{Labels: []string{rule}, Value: float64(n)})
			}
			return out
		})
	c.BindCounterVec("pullthrough_policyengine_rule_matches_total",
		"Rule matches recorded by the policy-as-code engine, labeled by rule id.",
		[]string{"rule"},
		func() []metrics.LabeledValue {
			snap := e.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.MatchByRule))
			for rule, n := range snap.MatchByRule {
				out = append(out, metrics.LabeledValue{Labels: []string{rule}, Value: float64(n)})
			}
			return out
		})
}

// bindNameguardMetrics registers the typosquatting / dependency-confusion guard's
// cumulative counters so operators can chart flagged pulls and alert on a spike of
// dependency-confusion or homoglyph attempts (Task 19).
func bindNameguardMetrics(c *metrics.Collector, svc *nameguard.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_nameguard_inspected_total",
		"Total package coordinates inspected by the name guard.",
		func() float64 { return float64(svc.Metrics().Inspected) })
	c.BindCounter("pullthrough_nameguard_flagged_total",
		"Total coordinates that produced at least one typosquat/confusion finding.",
		func() float64 { return float64(svc.Metrics().Flagged) })
	c.BindCounter("pullthrough_nameguard_blocked_total",
		"Total pulls blocked (or quarantined) by the name guard.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_nameguard_warned_total",
		"Total pulls served with a name-guard warning.",
		func() float64 { return float64(svc.Metrics().Warned) })
	c.BindCounter("pullthrough_nameguard_typosquat_total",
		"Total typosquat findings (edit-distance/substitution similarity to a popular name).",
		func() float64 { return float64(svc.Metrics().Typosquat) })
	c.BindCounter("pullthrough_nameguard_dependency_confusion_total",
		"Total dependency-confusion findings (public name shadowing a configured internal namespace).",
		func() float64 { return float64(svc.Metrics().DependencyConfusion) })
	c.BindCounter("pullthrough_nameguard_homoglyph_total",
		"Total homoglyph / mixed-script findings in package names.",
		func() float64 { return float64(svc.Metrics().Homoglyph) })
	c.BindCounter("pullthrough_nameguard_namespace_mismatch_total",
		"Total scope/namespace near-miss findings.",
		func() float64 { return float64(svc.Metrics().NamespaceMismatch) })
	c.BindCounter("pullthrough_nameguard_new_package_total",
		"Total brand-new-package findings (when an age oracle is configured).",
		func() float64 { return float64(svc.Metrics().NewPackage) })
}

// bindMaturityMetrics registers the release-maturity / version-cooldown gate's
// cumulative counters and gauges (Task 61): coordinates checked, blocks (held in
// cooldown), allowlisted bypasses, and unknown-timestamp resolutions — overall
// and per ecosystem — plus a gauge of the coordinates currently cooling. This
// lets operators chart cooldown holds per ecosystem and alert on a spike of
// newly-published versions. Safe with a nil service (disabled).
func bindMaturityMetrics(c *metrics.Collector, svc *maturity.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_maturity_checks_total",
		"Total coordinates evaluated by the release-maturity (version-cooldown) gate.",
		func() float64 { return float64(svc.Metrics().Checks) })
	c.BindCounter("pullthrough_maturity_cooling_total",
		"Total pulls blocked by the release-maturity gate (version still within its cooldown window, or fail-closed unknown timestamp).",
		func() float64 { return float64(svc.Metrics().Blocks) })
	c.BindCounter("pullthrough_maturity_allowlisted_total",
		"Total pulls that bypassed the release-maturity gate via the trusted allowlist.",
		func() float64 { return float64(svc.Metrics().Allowlisted) })
	c.BindCounter("pullthrough_maturity_unknown_total",
		"Total pulls whose publish timestamp could not be determined by the release-maturity gate.",
		func() float64 { return float64(svc.Metrics().Unknown) })
	c.BindGauge("pullthrough_maturity_cooling_current",
		"Coordinates currently held in their cooldown window by the release-maturity gate.",
		func() float64 { return float64(svc.Metrics().CoolingNow) })
	// Per-ecosystem checks as labeled counters.
	c.Registry().RegisterFuncVec("pullthrough_maturity_checks_by_ecosystem_total",
		"Release-maturity gate checks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ChecksByEco))
			for eco, n := range snap.ChecksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	// Per-ecosystem cooldown blocks as labeled counters.
	c.Registry().RegisterFuncVec("pullthrough_maturity_blocks_by_ecosystem_total",
		"Release-maturity gate cooldown blocks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BlocksByEco))
			for eco, n := range snap.BlocksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	// Per-ecosystem currently-cooling counts as labeled gauges.
	c.Registry().RegisterFuncVec("pullthrough_maturity_cooling_by_ecosystem",
		"Coordinates currently cooling, partitioned by ecosystem.",
		"gauge", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.CoolingByEco))
			for eco, n := range snap.CoolingByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
}

// bindContinuityMetrics registers the maintainer/publisher continuity gate's
// cumulative counters and gauges (Task 91): coordinates checked, trust-on-first-use
// establishments, detected maintainer drifts, blocks, and unknown publishers —
// overall and per ecosystem — plus gauges of the known-coordinate store size and
// the coordinates currently in maintainer-drift cooldown. This lets operators chart
// ownership-change activity per ecosystem and alert on a spike of drifts. Safe with
// a nil service (disabled).
func bindContinuityMetrics(c *metrics.Collector, svc *continuity.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_continuity_checks_total",
		"Total coordinates evaluated by the maintainer/publisher continuity gate.",
		func() float64 { return float64(svc.Metrics().Checks) })
	c.BindCounter("pullthrough_continuity_first_use_total",
		"Total coordinates whose maintainer set was established on first use (TOFU).",
		func() float64 { return float64(svc.Metrics().FirstUse) })
	c.BindCounter("pullthrough_continuity_drift_total",
		"Total detected maintainer/publisher ownership changes (drift) on previously-seen packages.",
		func() float64 { return float64(svc.Metrics().Drifts) })
	c.BindCounter("pullthrough_continuity_blocks_total",
		"Total pulls blocked by the continuity gate (maintainer drift under a block disposition).",
		func() float64 { return float64(svc.Metrics().Blocks) })
	c.BindCounter("pullthrough_continuity_unknown_total",
		"Total pulls whose publisher identity could not be determined by the continuity gate.",
		func() float64 { return float64(svc.Metrics().Unknown) })
	c.BindGauge("pullthrough_continuity_known_coordinates",
		"Coordinates with an established trust-on-first-use maintainer set.",
		func() float64 { return float64(svc.Metrics().KnownCoordinates) })
	c.BindGauge("pullthrough_continuity_pending_current",
		"Coordinates with a currently-untrusted (within-cooldown) new maintainer.",
		func() float64 { return float64(svc.Metrics().PendingNow) })
	c.Registry().RegisterFuncVec("pullthrough_continuity_checks_by_ecosystem_total",
		"Continuity gate checks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ChecksByEco))
			for eco, n := range snap.ChecksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_continuity_drift_by_ecosystem_total",
		"Continuity gate maintainer drifts, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.DriftsByEco))
			for eco, n := range snap.DriftsByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_continuity_blocks_by_ecosystem_total",
		"Continuity gate blocks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BlocksByEco))
			for eco, n := range snap.BlocksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
}

// bindDepFirewallMetrics registers the dependency-firewall gate's cumulative
// counters (Task 65): coordinates checked, blocks, and explicit allows — overall,
// per ecosystem, and per violation code (not-pinned / out-of-range / below-floor
// / denied / not-governed). This lets operators chart firewall enforcement and
// alert on a spike of policy violations from CI. Safe with a nil service.
func bindDepFirewallMetrics(c *metrics.Collector, svc *depfirewall.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_depfirewall_checks_total",
		"Total coordinates evaluated by the dependency-firewall (version-policy) gate.",
		func() float64 { return float64(svc.Metrics().Checks) })
	c.BindCounter("pullthrough_depfirewall_blocks_total",
		"Total pulls blocked by the dependency-firewall gate (version outside the approved set).",
		func() float64 { return float64(svc.Metrics().Blocks) })
	c.BindCounter("pullthrough_depfirewall_allowed_total",
		"Total pulls explicitly approved by a dependency-firewall rule.",
		func() float64 { return float64(svc.Metrics().Allowed) })
	// Per-ecosystem checks as labeled counters.
	c.Registry().RegisterFuncVec("pullthrough_depfirewall_checks_by_ecosystem_total",
		"Dependency-firewall gate checks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ChecksByEco))
			for eco, n := range snap.ChecksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	// Per-ecosystem blocks as labeled counters.
	c.Registry().RegisterFuncVec("pullthrough_depfirewall_blocks_by_ecosystem_total",
		"Dependency-firewall gate blocks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BlocksByEco))
			for eco, n := range snap.BlocksByEco {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	// Per-violation-code blocks as labeled counters (the "per-rule" view).
	c.Registry().RegisterFuncVec("pullthrough_depfirewall_blocks_by_code_total",
		"Dependency-firewall gate blocks, partitioned by violation code.",
		"counter", []string{"code"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BlocksByCode))
			for code, n := range snap.BlocksByCode {
				out = append(out, metrics.LabeledValue{Labels: []string{code}, Value: float64(n)})
			}
			return out
		})
}

// bindWebhookMetrics registers the Kubernetes admission-webhook counters (Task
// 111): reviews handled, Pods admitted/denied/warned/bypassed, images checked and
// blocked, lockdown-driven denials, verdict-source errors and their fail-open /
// fail-closed resolution, plus a per-verdict breakdown. Safe with a nil handler.
func bindWebhookMetrics(c *metrics.Collector, h *k8swebhook.Handler) {
	if h == nil {
		return
	}
	c.BindCounter("pullthrough_admission_reviews_total",
		"Total Kubernetes AdmissionReview requests handled by the webhook.",
		func() float64 { return float64(h.Metrics().Reviews) })
	c.BindCounter("pullthrough_admission_admitted_total",
		"Total Pods admitted by the admission webhook.",
		func() float64 { return float64(h.Metrics().Admitted) })
	c.BindCounter("pullthrough_admission_denied_total",
		"Total Pods denied by the admission webhook.",
		func() float64 { return float64(h.Metrics().Denied) })
	c.BindCounter("pullthrough_admission_warned_total",
		"Total Pods admitted with an advisory supply-chain warning.",
		func() float64 { return float64(h.Metrics().Warned) })
	c.BindCounter("pullthrough_admission_bypassed_total",
		"Total admission requests bypassed (exempt namespace or non-Pod resource).",
		func() float64 { return float64(h.Metrics().Bypassed) })
	c.BindCounter("pullthrough_admission_images_checked_total",
		"Total container images evaluated against the supply-chain verdict.",
		func() float64 { return float64(h.Metrics().ImagesChecked) })
	c.BindCounter("pullthrough_admission_images_blocked_total",
		"Total container images whose verdict denied the Pod.",
		func() float64 { return float64(h.Metrics().ImagesBlocked) })
	c.BindCounter("pullthrough_admission_lockdown_denies_total",
		"Total admission denials driven by the emergency-lockdown kill-switch.",
		func() float64 { return float64(h.Metrics().LockdownDenies) })
	c.BindCounter("pullthrough_admission_source_errors_total",
		"Total verdict-source errors or timeouts during admission.",
		func() float64 { return float64(h.Metrics().SourceErrors) })
	c.BindCounter("pullthrough_admission_fail_open_total",
		"Total images admitted despite a verdict-source error (fail-open).",
		func() float64 { return float64(h.Metrics().FailOpen) })
	c.BindCounter("pullthrough_admission_fail_closed_total",
		"Total images denied due to a verdict-source error (fail-closed).",
		func() float64 { return float64(h.Metrics().FailClosed) })
	c.BindCounterVec("pullthrough_admission_verdicts_total",
		"Dossier verdicts resolved during admission, labeled by verdict.",
		[]string{"verdict"},
		func() []metrics.LabeledValue {
			snap := h.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ByVerdict))
			for verdict, n := range snap.ByVerdict {
				out = append(out, metrics.LabeledValue{Labels: []string{verdict}, Value: float64(n)})
			}
			return out
		})
}

// bindSnapshotMetrics registers the organization snapshot / freeze / rollback
// subsystem's gauges and counters (Task 70): live-state size, retained snapshots,
// captures/freezes/rollbacks, whether a freeze is active and its set size, and the
// freeze-gate allow/block/quarantine tallies. Safe with a nil service.
func bindSnapshotMetrics(c *metrics.Collector, svc *snapshot.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_snapshot_live_entries",
		"Distinct coordinates in the snapshot live state (served-dependency state captured so far).",
		func() float64 { return float64(svc.Metrics().LiveEntries) })
	c.BindGauge("pullthrough_snapshot_count",
		"Number of retained point-in-time snapshot manifests.",
		func() float64 { return float64(svc.Metrics().Snapshots) })
	c.BindCounter("pullthrough_snapshot_captured_total",
		"Total snapshots captured (on-demand and scheduled).",
		func() float64 { return float64(svc.Metrics().Taken) })
	c.BindCounter("pullthrough_snapshot_recorded_total",
		"Total served coordinates folded into the snapshot live state.",
		func() float64 { return float64(svc.Metrics().Recorded) })
	c.BindCounter("pullthrough_snapshot_freezes_total",
		"Total times the organization was frozen to a snapshot.",
		func() float64 { return float64(svc.Metrics().Freezes) })
	c.BindCounter("pullthrough_snapshot_rollbacks_total",
		"Total instant rollbacks to the last-known-good snapshot.",
		func() float64 { return float64(svc.Metrics().Rollbacks) })
	c.BindGauge("pullthrough_snapshot_freeze_active",
		"Whether an organization freeze is currently active (1) or not (0).",
		func() float64 {
			if svc.Metrics().FreezeActive {
				return 1
			}
			return 0
		})
	c.BindGauge("pullthrough_snapshot_frozen_set_size",
		"Number of coordinates in the currently-active frozen set (0 when no freeze).",
		func() float64 { return float64(svc.Metrics().FrozenSetSize) })
	c.BindCounter("pullthrough_snapshot_freeze_gate_allowed_total",
		"Total pulls the freeze gate allowed (in the frozen set, or observe-only).",
		func() float64 { return float64(svc.Metrics().GateAllowed) })
	c.BindCounter("pullthrough_snapshot_freeze_gate_blocked_total",
		"Total pulls the freeze gate blocked (outside the frozen set or digest mismatch).",
		func() float64 { return float64(svc.Metrics().GateBlocked) })
	c.BindCounter("pullthrough_snapshot_freeze_gate_quarantined_total",
		"Total pulls the freeze gate quarantined (held for break-glass review).",
		func() float64 { return float64(svc.Metrics().GateQuarantine) })
}

// bindLockdownMetrics registers the emergency-lockdown / global kill-switch
// counters and the current posture (Task 74): whether a lockdown is active, a
// per-mode {mode="freeze|strict|block"} gauge, the seconds remaining until
// auto-expiry, the targeted-block coordinate count, and the cumulative
// check/block/freeze-fetch-block/engage/clear/expire tallies. Safe with a nil
// service (disabled).
func bindLockdownMetrics(c *metrics.Collector, svc *lockdown.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_lockdown_active",
		"Whether an emergency lockdown is currently engaged (1) or not (0).",
		func() float64 {
			if svc.Metrics().Active {
				return 1
			}
			return 0
		})
	c.BindGaugeVec("pullthrough_lockdown_mode_active",
		"Whether each lockdown mode is the currently-active posture (1) or not (0), by mode.",
		[]string{"mode"}, func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(lockdown.Modes()))
			for _, m := range lockdown.Modes() {
				out = append(out, metrics.LabeledValue{Labels: []string{m}, Value: snap.ModeActive(m)})
			}
			return out
		})
	c.BindGauge("pullthrough_lockdown_seconds_remaining",
		"Seconds until the active lockdown auto-expires (-1 when no lockdown is active).",
		func() float64 { return svc.Metrics().SecondsRemaining })
	c.BindGauge("pullthrough_lockdown_block_targets",
		"Number of coordinates a targeted-block lockdown currently denies (0 when not in block mode).",
		func() float64 { return float64(svc.Metrics().TargetCount) })
	c.BindCounter("pullthrough_lockdown_checks_total",
		"Total pull-path lockdown consults (the FIRST admission check).",
		func() float64 { return float64(svc.Metrics().Checks) })
	c.BindCounter("pullthrough_lockdown_blocks_total",
		"Total pulls denied by a targeted-block lockdown coordinate match.",
		func() float64 { return float64(svc.Metrics().Blocks) })
	c.BindCounter("pullthrough_lockdown_freeze_fetch_blocks_total",
		"Total upstream fetches refused because a freeze lockdown was active (cache miss under freeze).",
		func() float64 { return float64(svc.Metrics().FreezeFetchBlocks) })
	c.BindCounter("pullthrough_lockdown_engagements_total",
		"Total times an emergency lockdown was engaged.",
		func() float64 { return float64(svc.Metrics().Engagements) })
	c.BindCounter("pullthrough_lockdown_clears_total",
		"Total times an emergency lockdown was cleared by an operator.",
		func() float64 { return float64(svc.Metrics().Clears) })
	c.BindCounter("pullthrough_lockdown_expirations_total",
		"Total times an emergency lockdown auto-expired at its TTL.",
		func() float64 { return float64(svc.Metrics().Expirations) })
}

// bindGitopsMetrics registers the GitOps policy & config synchronization gauges and
// counters (Task 93): in-sync / drift / pending-change posture and the cumulative
// reconcile, apply, rollback, verify-failure, and error tallies. Safe with a nil
// service (disabled).
func bindGitopsMetrics(c *metrics.Collector, svc *gitops.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_gitops_in_sync",
		"Whether the live config matches the GitOps source of truth (1) or not (0).",
		func() float64 {
			if svc.Metrics().InSync {
				return 1
			}
			return 0
		})
	c.BindGauge("pullthrough_gitops_drift",
		"Whether the live config has drifted from the GitOps source of truth (1) or not (0).",
		func() float64 {
			if svc.Metrics().DriftDetected {
				return 1
			}
			return 0
		})
	c.BindGauge("pullthrough_gitops_pending_change",
		"Whether a GitOps change is pending dual-control approval (1) or not (0).",
		func() float64 {
			if svc.Metrics().PendingChange {
				return 1
			}
			return 0
		})
	c.BindCounter("pullthrough_gitops_reconciles_total",
		"Total GitOps reconcile passes performed.",
		func() float64 { return float64(svc.Metrics().Reconciles) })
	c.BindCounter("pullthrough_gitops_applies_total",
		"Total GitOps desired-state bundles applied to the on-disk config.",
		func() float64 { return float64(svc.Metrics().Applies) })
	c.BindCounter("pullthrough_gitops_rollbacks_total",
		"Total GitOps rollbacks to the last-known-good applied revision.",
		func() float64 { return float64(svc.Metrics().Rollbacks) })
	c.BindCounter("pullthrough_gitops_verify_failures_total",
		"Total GitOps bundles that failed signature/digest verification.",
		func() float64 { return float64(svc.Metrics().VerifyFailures) })
	c.BindCounter("pullthrough_gitops_errors_total",
		"Total GitOps reconcile passes that failed with an infrastructure error.",
		func() float64 { return float64(svc.Metrics().Errors) })
}

// bindInstallHooksMetrics registers the install-script / lifecycle-hook risk
// gate's cumulative counters (Task 62): artifacts scanned, install hooks found,
// artifacts flagged, total findings, and warn/block tallies — plus a per-rule
// labeled counter so operators can chart which high-risk patterns are firing.
// Safe with a nil service (disabled).
func bindInstallHooksMetrics(c *metrics.Collector, svc *installhooks.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_installhooks_scanned_total",
		"Total artifacts whose install/lifecycle hooks were statically extracted and scored.",
		func() float64 { return float64(svc.Metrics().Scanned) })
	c.BindCounter("pullthrough_installhooks_hooks_found_total",
		"Total install/lifecycle hooks discovered across scanned artifacts.",
		func() float64 { return float64(svc.Metrics().HooksFound) })
	c.BindCounter("pullthrough_installhooks_flagged_artifacts_total",
		"Total artifacts with at least one high-risk install-hook finding.",
		func() float64 { return float64(svc.Metrics().FlaggedArts) })
	c.BindCounter("pullthrough_installhooks_findings_total",
		"Total high-risk install-hook pattern findings emitted.",
		func() float64 { return float64(svc.Metrics().FindingsTotal) })
	c.BindCounter("pullthrough_installhooks_blocked_total",
		"Total artifacts blocked (and evicted) by the install-hook gate.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_installhooks_warned_total",
		"Total artifacts served with an install-hook warning.",
		func() float64 { return float64(svc.Metrics().Warned) })
	c.BindCounterVec("pullthrough_installhooks_findings_by_rule_total",
		"Install-hook findings emitted, labeled by the detection rule that fired.",
		[]string{"rule"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.FindingsByRule))
			for rule, n := range snap.FindingsByRule {
				out = append(out, metrics.LabeledValue{Labels: []string{rule}, Value: float64(n)})
			}
			return out
		})
}

// bindMLGuardMetrics registers the ML weight-scanning gate's cumulative counters
// (Task 110): pickle weight files disassembled, safetensors recognized, artifacts
// flagged, total findings, warn/block tallies — plus a per-rule labeled counter.
// Safe with a nil service (disabled).
func bindMLGuardMetrics(c *metrics.Collector, svc *mlguard.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_mlguard_scanned_total",
		"Total pickle-based model weight files whose opcode stream was statically disassembled.",
		func() float64 { return float64(svc.Metrics().Scanned) })
	c.BindCounter("pullthrough_mlguard_safetensors_total",
		"Total safetensors (safe, tensor-only) weight files recognized and preferred.",
		func() float64 { return float64(svc.Metrics().Safetensors) })
	c.BindCounter("pullthrough_mlguard_flagged_artifacts_total",
		"Total weight files with at least one unsafe-pickle finding.",
		func() float64 { return float64(svc.Metrics().FlaggedArts) })
	c.BindCounter("pullthrough_mlguard_findings_total",
		"Total unsafe-pickle findings emitted.",
		func() float64 { return float64(svc.Metrics().FindingsTotal) })
	c.BindCounter("pullthrough_mlguard_blocked_total",
		"Total weight files blocked (and quarantined) by the ML weight gate.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_mlguard_warned_total",
		"Total weight files served with an ML weight-gate warning.",
		func() float64 { return float64(svc.Metrics().Warned) })
	c.BindCounterVec("pullthrough_mlguard_findings_by_rule_total",
		"Unsafe-pickle findings emitted, labeled by the detection rule that fired.",
		[]string{"rule"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.FindingsByRule))
			for rule, n := range snap.FindingsByRule {
				out = append(out, metrics.LabeledValue{Labels: []string{rule}, Value: float64(n)})
			}
			return out
		})
}

// bindAVScanMetrics registers the antivirus content-scanning gate's cumulative
// counters (Task 136): artifacts scanned/clean/infected/truncated, engine
// unavailability (degradation), bytes scanned, the per-action tallies
// (quarantined/blocked/annotated), fail-open degraded admissions, and infected
// counts labeled by matched malware signature. Safe with a nil service.
func bindAVScanMetrics(c *metrics.Collector, svc *avscan.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_avscan_scanned_total",
		"Total artifact payloads streamed through the AV engine with a completed verdict.",
		func() float64 { return float64(svc.Metrics().Scanned) })
	c.BindCounter("pullthrough_avscan_clean_total",
		"Total artifact payloads scanned clean.",
		func() float64 { return float64(svc.Metrics().Clean) })
	c.BindCounter("pullthrough_avscan_infected_total",
		"Total artifact payloads with a positive malware detection.",
		func() float64 { return float64(svc.Metrics().Infected) })
	c.BindCounter("pullthrough_avscan_truncated_total",
		"Total artifact payloads scanned only up to the size bound (oversize).",
		func() float64 { return float64(svc.Metrics().Truncated) })
	c.BindCounter("pullthrough_avscan_unavailable_total",
		"Total scans where the AV engine could not be reached or errored.",
		func() float64 { return float64(svc.Metrics().Unavailable) })
	c.BindCounter("pullthrough_avscan_bytes_scanned_total",
		"Total artifact payload bytes streamed to the AV engine.",
		func() float64 { return float64(svc.Metrics().BytesScanned) })
	c.BindCounter("pullthrough_avscan_quarantined_total",
		"Total artifacts quarantined (refused and evicted) on a malware detection.",
		func() float64 { return float64(svc.Metrics().Quarantined) })
	c.BindCounter("pullthrough_avscan_blocked_total",
		"Total artifacts blocked (refused, retained for forensics) on a malware detection.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_avscan_annotated_total",
		"Total artifacts served with an advisory malware-detection annotation.",
		func() float64 { return float64(svc.Metrics().Annotated) })
	c.BindCounter("pullthrough_avscan_degraded_total",
		"Total artifacts admitted under the fail-open policy without an engine verdict.",
		func() float64 { return float64(svc.Metrics().Degraded) })
	c.BindCounterVec("pullthrough_avscan_infected_by_signature_total",
		"Malware detections, labeled by the matched engine signature.",
		[]string{"signature"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.InfectedBySignat))
			for sig, n := range snap.InfectedBySignat {
				out = append(out, metrics.LabeledValue{Labels: []string{sig}, Value: float64(n)})
			}
			return out
		})
}

// bindLLMPkgScanMetrics registers the LLM package-content scan gate's
// cumulative counters (Task 173) as pullthrough_llmpkgscan_*: what the gate was
// asked and how it answered (verdict cache hits vs. scans, coalesced requests),
// what the model said, what the gate did about it, why artifacts went unscanned,
// and what the scans cost (provider calls, tokens, dollars, time). Every label
// set is closed: verdict categories, reason codes, the three tool names,
// configured ecosystems and budget scopes. Safe with a nil service.
func bindLLMPkgScanMetrics(c *metrics.Collector, svc *llmpkgscan.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_llmpkgscan_assessed_total",
		"Total pulls of a package artifact the LLM content-scan gate produced a report for.",
		func() float64 { return float64(svc.Metrics().Assessed) })
	c.BindCounter("pullthrough_llmpkgscan_not_package_total",
		"Total pulls the gate left alone because the resource is not an archive (a metadata document under a package coordinate).",
		func() float64 { return float64(svc.Metrics().NotPackage) })
	c.BindCounter("pullthrough_llmpkgscan_cache_hits_total",
		"Total pulls answered from a stored verdict (no model call).",
		func() float64 { return float64(svc.Metrics().CacheHits) })
	c.BindCounter("pullthrough_llmpkgscan_cache_misses_total",
		"Total pulls of an artifact with no stored verdict (a scan was needed).",
		func() float64 { return float64(svc.Metrics().CacheMisses) })
	c.BindCounter("pullthrough_llmpkgscan_negative_cache_hits_total",
		"Total pulls answered from a remembered scan failure (no model call).",
		func() float64 { return float64(svc.Metrics().NegativeHits) })
	c.BindCounter("pullthrough_llmpkgscan_coalesced_total",
		"Total pulls that joined a scan of the same digest already in flight.",
		func() float64 { return float64(svc.Metrics().Coalesced) })
	c.BindCounter("pullthrough_llmpkgscan_scans_total",
		"Total scans that produced a verdict.",
		func() float64 { return float64(svc.Metrics().Scans) })
	c.BindCounter("pullthrough_llmpkgscan_scan_errors_total",
		"Total scans that ended without a verdict.",
		func() float64 { return float64(svc.Metrics().ScanErrors) })
	c.BindCounterVec("pullthrough_llmpkgscan_verdicts_total",
		"Fresh verdicts, labeled by what the model said (malicious|suspicious|benign).",
		[]string{"verdict"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			return []metrics.LabeledValue{
				{Labels: []string{llmpkgscan.VerdictMalicious}, Value: float64(snap.VerdictMalicious)},
				{Labels: []string{llmpkgscan.VerdictSuspicious}, Value: float64(snap.VerdictSuspicious)},
				{Labels: []string{llmpkgscan.VerdictBenign}, Value: float64(snap.VerdictBenign)},
			}
		})
	c.BindCounter("pullthrough_llmpkgscan_injection_detected_total",
		"Total scanned artifacts whose content addressed the scanner (deterministic prompt-injection indicators).",
		func() float64 { return float64(svc.Metrics().InjectionDetected) })
	c.BindCounter("pullthrough_llmpkgscan_truncated_total",
		"Total verdicts that rest on an incomplete view of the package (an unpack or prompt limit was hit).",
		func() float64 { return float64(svc.Metrics().Truncated) })
	c.BindCounter("pullthrough_llmpkgscan_blocked_total",
		"Total pulls refused (and the artifact evicted) under the block action.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_llmpkgscan_quarantined_total",
		"Total pulls refused (and the artifact evicted) under the quarantine action.",
		func() float64 { return float64(svc.Metrics().Quarantined) })
	c.BindCounter("pullthrough_llmpkgscan_annotated_total",
		"Total pulls of a flagged artifact that were served with the verdict on record.",
		func() float64 { return float64(svc.Metrics().Annotated) })
	c.BindCounter("pullthrough_llmpkgscan_failed_open_total",
		"Total pulls served without a verdict under the fail-open policy.",
		func() float64 { return float64(svc.Metrics().FailedOpen) })
	c.BindCounter("pullthrough_llmpkgscan_failed_closed_total",
		"Total pulls refused for want of a verdict under the fail-closed policy.",
		func() float64 { return float64(svc.Metrics().FailedClosed) })
	c.BindCounterVec("pullthrough_llmpkgscan_unscanned_total",
		"Scans that ended without a verdict, labeled by reason code.",
		[]string{"code"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.UnscannedByCode))
			for code, n := range snap.UnscannedByCode {
				out = append(out, metrics.LabeledValue{Labels: []string{code}, Value: float64(n)})
			}
			return out
		})
	c.BindCounter("pullthrough_llmpkgscan_provider_calls_total",
		"Total LLM provider completions requested by the gate.",
		func() float64 { return float64(svc.Metrics().ProviderCalls) })
	c.BindCounter("pullthrough_llmpkgscan_provider_errors_total",
		"Total LLM provider completions that failed.",
		func() float64 { return float64(svc.Metrics().ProviderErrors) })
	c.BindCounterVec("pullthrough_llmpkgscan_tokens_total",
		"Tokens consumed by package scans, labeled by kind (input|output|cache_read).",
		[]string{"kind"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			return []metrics.LabeledValue{
				{Labels: []string{"input"}, Value: float64(snap.InputTokens)},
				{Labels: []string{"output"}, Value: float64(snap.OutputTokens)},
				{Labels: []string{"cache_read"}, Value: float64(snap.CacheReadTokens)},
			}
		})
	c.BindCounter("pullthrough_llmpkgscan_turns_total",
		"Total model turns across all scans.",
		func() float64 { return float64(svc.Metrics().Turns) })
	c.BindCounterVec("pullthrough_llmpkgscan_tool_calls_total",
		"Read-only tool calls executed for the model, labeled by tool (list_files|read_file|grep).",
		[]string{"tool"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ToolCallsByTool))
			for tool, n := range snap.ToolCallsByTool {
				out = append(out, metrics.LabeledValue{Labels: []string{tool}, Value: float64(n)})
			}
			return out
		})
	c.BindCounter("pullthrough_llmpkgscan_cost_usd_total",
		"Estimated provider spend on package scans, in US dollars.",
		func() float64 { return svc.Metrics().CostUSD })
	c.BindCounter("pullthrough_llmpkgscan_scan_seconds_total",
		"Total wall-clock seconds spent in scans that produced a verdict.",
		func() float64 { return svc.Metrics().ScanSeconds })
	c.BindCounterVec("pullthrough_llmpkgscan_scans_by_ecosystem_total",
		"Scans that produced a verdict, labeled by ecosystem.",
		[]string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ScansByEcosystem))
			for eco, n := range snap.ScansByEcosystem {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	c.BindCounterVec("pullthrough_llmpkgscan_budget_exhausted_total",
		"Pulls not scanned because a cost ceiling was reached, labeled by scope (tenant|global).",
		[]string{"scope"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BudgetExhaustedByKind))
			for scope, n := range snap.BudgetExhaustedByKind {
				out = append(out, metrics.LabeledValue{Labels: []string{scope}, Value: float64(n)})
			}
			return out
		})
	c.BindGauge("pullthrough_llmpkgscan_in_flight",
		"Scans currently running.",
		func() float64 { return float64(svc.Metrics().InFlight) })
	c.BindGauge("pullthrough_llmpkgscan_queued",
		"Scans waiting for a free scan slot.",
		func() float64 { return float64(svc.Metrics().Queued) })
	c.BindGauge("pullthrough_llmpkgscan_breaker_open",
		"1 while the provider circuit breaker is open (scans are paused after repeated provider failures), else 0.",
		func() float64 {
			if svc.Metrics().BreakerOpen {
				return 1
			}
			return 0
		})
}

// bindFindingsDedupMetrics registers the finding de-duplication and suppression
// audit-trail counters (Task 165): the pullthrough_findings_dedup_* family
// (documents processed, findings seen vs retained, duplicates collapsed, and the
// per-category collapse breakdown) and the pullthrough_findings_suppressions_*
// family (distinct suppressions recorded, total observations, the live ledger
// size, per-mechanism breakdown, and audit-mirroring successes/failures). Safe
// with nil arguments (either surface disabled).
func bindFindingsDedupMetrics(c *metrics.Collector, m *findings.Metrics, ledger *findings.SuppressionLedger) {
	if m != nil {
		c.BindCounter("pullthrough_findings_dedup_documents_total",
			"Total findings documents normalized and de-duplicated before risk/SARIF/dossier.",
			func() float64 { return float64(m.Snapshot().Documents) })
		c.BindCounter("pullthrough_findings_dedup_input_total",
			"Total findings seen across all documents before de-duplication.",
			func() float64 { return float64(m.Snapshot().Input) })
		c.BindCounter("pullthrough_findings_dedup_output_total",
			"Total findings retained across all documents after de-duplication.",
			func() float64 { return float64(m.Snapshot().Output) })
		c.BindCounter("pullthrough_findings_dedup_collapsed_total",
			"Total duplicate findings collapsed into a canonical finding across all documents.",
			func() float64 { return float64(m.Snapshot().Collapsed) })
		c.BindCounterVec("pullthrough_findings_dedup_collapsed_by_category_total",
			"Duplicate findings collapsed, labeled by the finding category they were merged within.",
			[]string{"category"},
			func() []metrics.LabeledValue {
				snap := m.Snapshot()
				out := make([]metrics.LabeledValue, 0, len(snap.CollapsedByCategory))
				for cat, n := range snap.CollapsedByCategory {
					out = append(out, metrics.LabeledValue{Labels: []string{cat}, Value: float64(n)})
				}
				return out
			})
	}
	if ledger != nil {
		c.BindCounter("pullthrough_findings_suppressions_recorded_total",
			"Total distinct finding suppressions recorded in the immutable suppression audit trail.",
			func() float64 { return float64(ledger.Metrics().Recorded) })
		c.BindCounter("pullthrough_findings_suppressions_observed_total",
			"Total suppression observations, including repeat observations of an already-recorded suppression.",
			func() float64 { return float64(ledger.Metrics().Observed) })
		c.BindCounter("pullthrough_findings_suppressions_audit_mirrored_total",
			"Total suppressions mirrored into the tamper-evident audit log.",
			func() float64 { return float64(ledger.Metrics().AuditMirrored) })
		c.BindCounter("pullthrough_findings_suppressions_audit_errors_total",
			"Total suppression audit-log mirroring failures (best-effort; never fatal).",
			func() float64 { return float64(ledger.Metrics().AuditErrors) })
		c.BindGauge("pullthrough_findings_suppressions_current",
			"Number of distinct suppressions currently retained in the audit trail.",
			func() float64 { return float64(ledger.Metrics().Current) })
		c.BindCounterVec("pullthrough_findings_suppressions_by_mechanism_total",
			"Distinct finding suppressions recorded, labeled by mechanism (vex|reachability|policy|break-glass).",
			[]string{"mechanism"},
			func() []metrics.LabeledValue {
				snap := ledger.Metrics()
				out := make([]metrics.LabeledValue, 0, len(snap.ByMechanism))
				for mech, n := range snap.ByMechanism {
					out = append(out, metrics.LabeledValue{Labels: []string{mech}, Value: float64(n)})
				}
				return out
			})
	}
}

// bindContentScanMetrics registers the package-content analysis gate's cumulative
// counters (Task 138): artifacts inspected, files scanned, flagged artifacts and
// total findings, the per-action tallies (blocked/downgraded/annotated), budget
// hits (truncated/timed-out), and the per-category and per-ecosystem finding
// breakdowns — so operators can chart which content heuristic fires for which
// ecosystem. Safe with a nil service (disabled).
func bindContentScanMetrics(c *metrics.Collector, svc *contentscan.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_contentscan_scanned_total",
		"Total source artifacts unpacked and content-scanned.",
		func() float64 { return float64(svc.Metrics().Scanned) })
	c.BindCounter("pullthrough_contentscan_files_scanned_total",
		"Total package files examined across all content scans.",
		func() float64 { return float64(svc.Metrics().FilesScanned) })
	c.BindCounter("pullthrough_contentscan_flagged_artifacts_total",
		"Total artifacts with at least one content finding.",
		func() float64 { return float64(svc.Metrics().FlaggedArts) })
	c.BindCounter("pullthrough_contentscan_findings_total",
		"Total content findings emitted across all scans.",
		func() float64 { return float64(svc.Metrics().FindingsTotal) })
	c.BindCounter("pullthrough_contentscan_blocked_total",
		"Total artifacts blocked (refused and evicted) on a content finding.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_contentscan_downgraded_total",
		"Total artifacts served with downgraded content findings.",
		func() float64 { return float64(svc.Metrics().Downgraded) })
	c.BindCounter("pullthrough_contentscan_annotated_total",
		"Total artifacts served with advisory (annotate / below-threshold) content findings.",
		func() float64 { return float64(svc.Metrics().Annotated) })
	c.BindCounter("pullthrough_contentscan_truncated_total",
		"Total content scans that hit a size/entry/finding budget bound.",
		func() float64 { return float64(svc.Metrics().Truncated) })
	c.BindCounter("pullthrough_contentscan_timed_out_total",
		"Total content scans that hit the time budget before completing.",
		func() float64 { return float64(svc.Metrics().TimedOut) })
	c.BindCounterVec("pullthrough_contentscan_findings_by_category_total",
		"Content findings, labeled by heuristic category.",
		[]string{"category"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ByCategory))
			for cat, n := range snap.ByCategory {
				out = append(out, metrics.LabeledValue{Labels: []string{cat}, Value: float64(n)})
			}
			return out
		})
	c.BindCounterVec("pullthrough_contentscan_scanned_by_ecosystem_total",
		"Content scans, labeled by ecosystem.",
		[]string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ByEcosystem))
			for eco, n := range snap.ByEcosystem {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
}

// bindMalfeedMetrics registers the known-malicious-package gate's cumulative
// counters and freshness gauges (Task 48): entries loaded (overall and per
// ecosystem), blocks (overall and per ecosystem), stale blocks/serves, refresh
// attempts/failures, and the refresh age — so operators can chart known-bad
// blocks per ecosystem and alert on a stale malware feed. Safe with a nil
// service (disabled).
func bindMalfeedMetrics(c *metrics.Collector, svc *malfeed.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_malfeed_entries_loaded",
		"Known-malicious-package records currently loaded across all ecosystems.",
		func() float64 { return float64(svc.Metrics().EntriesLoaded) })
	c.BindCounter("pullthrough_malfeed_checks_total",
		"Total coordinates evaluated by the known-malicious-package gate.",
		func() float64 { return float64(svc.Metrics().Checks) })
	c.BindCounter("pullthrough_malfeed_blocks_total",
		"Total pulls blocked by the known-malicious-package gate (concrete match or fail-closed staleness).",
		func() float64 { return float64(svc.Metrics().Blocks) })
	c.BindCounter("pullthrough_malfeed_stale_blocks_total",
		"Total pulls blocked solely because the malware feed was stale and the gate is fail-closed.",
		func() float64 { return float64(svc.Metrics().StaleBlocks) })
	c.BindCounter("pullthrough_malfeed_stale_serves_total",
		"Total unmatched pulls served while the malware feed was stale (fail-open).",
		func() float64 { return float64(svc.Metrics().StaleServes) })
	c.BindCounter("pullthrough_malfeed_refreshes_total",
		"Total known-malicious feed refresh attempts (background and on-demand).",
		func() float64 { return float64(svc.Metrics().Refreshes) })
	c.BindCounter("pullthrough_malfeed_refresh_failures_total",
		"Total known-malicious feed refreshes that failed to load any source.",
		func() float64 { return float64(svc.Metrics().RefreshFailures) })
	c.BindGauge("pullthrough_malfeed_refresh_age_seconds",
		"Seconds since the last successful known-malicious feed refresh (-1 when never loaded).",
		func() float64 { return svc.Metrics().RefreshAgeSeconds })
	c.BindGauge("pullthrough_malfeed_stale",
		"Whether the known-malicious feed is currently stale (1) or fresh (0).",
		func() float64 {
			if svc.Metrics().Stale {
				return 1
			}
			return 0
		})
	// Per-ecosystem loaded-entry counts as labeled gauges.
	c.Registry().RegisterFuncVec("pullthrough_malfeed_entries_by_ecosystem",
		"Known-malicious-package records loaded, partitioned by ecosystem.",
		"gauge", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.EntriesByEcosystem))
			for eco, n := range snap.EntriesByEcosystem {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
	// Per-ecosystem block counts as labeled counters.
	c.Registry().RegisterFuncVec("pullthrough_malfeed_blocks_by_ecosystem_total",
		"Known-malicious-package blocks, partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			snap := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.BlocksByEcosystem))
			for eco, n := range snap.BlocksByEcosystem {
				out = append(out, metrics.LabeledValue{Labels: []string{eco}, Value: float64(n)})
			}
			return out
		})
}

// bindSigverifyMetrics registers the signature-verification gate's cumulative
// counters so operators can chart verified vs unsigned/blocked artifacts and
// alert on a spike of untrusted-signature or tampered-artifact attempts (Task 23).
func bindSigverifyMetrics(c *metrics.Collector, svc *sigverify.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_sigverify_verifications_total",
		"Total artifact signature/attestation verifications performed (cache misses).",
		func() float64 { return float64(svc.Metrics().Verifications) })
	c.BindCounter("pullthrough_sigverify_cache_hits_total",
		"Total verifications served from the result cache.",
		func() float64 { return float64(svc.Metrics().CacheHits) })
	c.BindCounter("pullthrough_sigverify_errors_total",
		"Total verifications that failed to fetch/parse signature material.",
		func() float64 { return float64(svc.Metrics().Errors) })
	c.BindCounter("pullthrough_sigverify_verified_total",
		"Total artifacts with a verified, trusted signature.",
		func() float64 { return float64(svc.Metrics().Verified) })
	c.BindCounter("pullthrough_sigverify_unsigned_total",
		"Total artifacts for which no signature material was found.",
		func() float64 { return float64(svc.Metrics().Unsigned) })
	c.BindCounter("pullthrough_sigverify_blocked_total",
		"Total artifacts blocked by the signature gate.",
		func() float64 { return float64(svc.Metrics().Blocked) })
	c.BindCounter("pullthrough_sigverify_warned_total",
		"Total artifacts served with a signature-gate warning.",
		func() float64 { return float64(svc.Metrics().Warned) })
	c.BindCounter("pullthrough_sigverify_quarantined_total",
		"Total artifacts quarantined (blocked and evicted) by the signature gate.",
		func() float64 { return float64(svc.Metrics().Quarantined) })
	c.BindCounter("pullthrough_sigverify_signatures_checked_total",
		"Total individual signatures verified across artifacts.",
		func() float64 { return float64(svc.Metrics().SignaturesChecked) })
	c.BindCounter("pullthrough_sigverify_attestations_parsed_total",
		"Total individual attestations verified across artifacts.",
		func() float64 { return float64(svc.Metrics().AttestationsParsed) })
	c.BindCounter("pullthrough_sigverify_rekor_verified_total",
		"Total signatures/attestations with a verified Rekor Signed Entry Timestamp (SET).",
		func() float64 { return float64(svc.Metrics().RekorVerified) })
	c.BindCounter("pullthrough_sigverify_rekor_inclusion_verified_total",
		"Total signatures/attestations with a verified Rekor Merkle inclusion proof.",
		func() float64 { return float64(svc.Metrics().RekorInclusion) })
	c.BindGauge("pullthrough_sigverify_cache_entries",
		"Number of artifacts with a cached verification result.",
		func() float64 { return float64(svc.Metrics().CacheEntries) })

	// Post-quantum / hybrid signature-verification metrics (Task 151). These let
	// operators chart adoption of PQC/hybrid signatures and alert on signatures
	// refused by the PQC policy.
	c.BindCounter("pullthrough_sigverify_pqc_signatures_total",
		"Total cryptographically-valid post-quantum/hybrid signatures verified.",
		func() float64 { return float64(svc.Metrics().PQCSignatures) })
	c.BindCounter("pullthrough_sigverify_pqc_verified_total",
		"Total artifacts whose trusted signature used a post-quantum or hybrid algorithm.",
		func() float64 { return float64(svc.Metrics().PQCVerified) })
	c.BindCounter("pullthrough_sigverify_pqc_rejected_total",
		"Total post-quantum/hybrid signatures refused by the PQC policy (classical-only or disabled).",
		func() float64 { return float64(svc.Metrics().PQCRejected) })
	// Per-algorithm signature tally, partitioned by algorithm and quantum-resistance class.
	c.Registry().RegisterFuncVec("pullthrough_sigverify_pqc_algorithm_signatures_total",
		"Cryptographically-valid signatures verified, partitioned by signature algorithm and class.",
		"counter", []string{"algorithm", "class"},
		func() []metrics.LabeledValue {
			usage := svc.Metrics().AlgorithmUsage
			out := make([]metrics.LabeledValue, 0, len(usage))
			for _, u := range usage {
				out = append(out, metrics.LabeledValue{Labels: []string{u.Algorithm, string(u.Class)}, Value: float64(u.Count)})
			}
			return out
		})
}

// bindNotifyMetrics registers the notification subsystem's per-sink delivery
// counters and the live queue-depth gauge so operators can chart alert volume
// and alert on a failing or backed-up sink (Task 21). The per-sink counters are
// exposed as labeled scrape-time callbacks reading the Notifier's atomics, so the
// notifier's counters remain the single source of truth.
func bindNotifyMetrics(c *metrics.Collector, n *notify.Notifier) {
	if n == nil {
		return
	}
	c.BindCounterVec("pullthrough_notifications_sent_total",
		"Total notifications delivered successfully, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return notifyValues(n, func(m notify.SinkMetrics) float64 { return float64(m.Sent) })
		})
	c.BindCounterVec("pullthrough_notifications_failed_total",
		"Total notifications that failed delivery after exhausting retries, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return notifyValues(n, func(m notify.SinkMetrics) float64 { return float64(m.Failed) })
		})
	c.BindCounterVec("pullthrough_notifications_dropped_total",
		"Total notifications dropped because the async delivery queue was full, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return notifyValues(n, func(m notify.SinkMetrics) float64 { return float64(m.Dropped) })
		})
	c.BindCounterVec("pullthrough_notifications_retries_total",
		"Total notification delivery retries, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return notifyValues(n, func(m notify.SinkMetrics) float64 { return float64(m.Retries) })
		})
	c.BindGauge("pullthrough_notifications_queue_depth",
		"Number of notifications currently waiting in the async delivery queue.",
		func() float64 { return float64(n.Metrics().QueueDepth) })
}

// bindSIEMMetrics registers the SIEM / log-forwarding subsystem's queue-depth
// and per-sink delivery telemetry (Task 119) as scrape-time callbacks reading
// the forwarder's atomics, so the forwarder remains the single source of truth.
// A nil forwarder (siem forwarding disabled) registers nothing.
func bindSIEMMetrics(c *metrics.Collector, f *siem.Forwarder) {
	if f == nil {
		return
	}
	c.BindGauge("pullthrough_siem_queue_depth",
		"Number of SIEM events currently waiting in the in-memory delivery queue.",
		func() float64 { return float64(f.Metrics().QueueDepth) })
	c.BindGauge("pullthrough_siem_spill_depth",
		"Number of SIEM events currently buffered in the on-disk spill queue.",
		func() float64 { return float64(f.Metrics().SpillDepth) })
	c.BindCounter("pullthrough_siem_events_enqueued_total",
		"Total SIEM events accepted onto the delivery queue.",
		func() float64 { return float64(f.Metrics().Enqueued) })
	c.BindCounter("pullthrough_siem_events_spilled_total",
		"Total SIEM events written to the on-disk spill queue on in-memory overflow.",
		func() float64 { return float64(f.Metrics().Spilled) })
	c.BindCounter("pullthrough_siem_events_dropped_total",
		"Total SIEM events dropped because both the in-memory and spill queues were full.",
		func() float64 { return float64(f.Metrics().Dropped) })
	c.BindCounterVec("pullthrough_siem_events_delivered_total",
		"Total SIEM events delivered successfully, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return siemValues(f, func(m siem.SinkMetrics) float64 { return float64(m.Delivered) })
		})
	c.BindCounterVec("pullthrough_siem_events_failed_total",
		"Total SIEM events that failed delivery after exhausting retries, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return siemValues(f, func(m siem.SinkMetrics) float64 { return float64(m.Failed) })
		})
	c.BindCounterVec("pullthrough_siem_retries_total",
		"Total SIEM batch-delivery retry attempts, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return siemValues(f, func(m siem.SinkMetrics) float64 { return float64(m.Retries) })
		})
	c.BindCounterVec("pullthrough_siem_batches_total",
		"Total SIEM batches attempted, by sink.",
		[]string{"sink"},
		func() []metrics.LabeledValue {
			return siemValues(f, func(m siem.SinkMetrics) float64 { return float64(m.Batches) })
		})
	c.BindCounterVec("pullthrough_siem_ocsf_events_encoded_total",
		"Total events encoded to OCSF across all ocsf sinks, by OCSF class.",
		[]string{"class"},
		func() []metrics.LabeledValue {
			snap := f.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.OCSF.ByClass))
			for class, n := range snap.OCSF.ByClass {
				out = append(out, metrics.LabeledValue{Labels: []string{class}, Value: float64(n)})
			}
			return out
		})
	c.BindCounter("pullthrough_siem_ocsf_encode_errors_total",
		"Total events that failed to encode to OCSF JSON across all ocsf sinks.",
		func() float64 { return float64(f.Metrics().OCSF.EncodeErrors) })
}

// bindPrewarmMetrics registers the predictive cache pre-warming counters (Task
// 134) as scrape-time callbacks reading the service's metrics snapshot. A nil
// (disabled) service registers nothing.
func bindPrewarmMetrics(c *metrics.Collector, svc *prewarm.Service) {
	if svc == nil {
		return
	}
	m := svc.Metrics()
	c.BindCounter("pullthrough_prewarm_predicted_total",
		"Total artifacts the predictor forecast as likely near-future pulls.",
		func() float64 { return float64(m.Snapshot().Predicted) })
	c.BindCounter("pullthrough_prewarm_fetched_total",
		"Total predicted artifacts fetched and admitted into the cache ahead of client demand.",
		func() float64 { return float64(m.Snapshot().Fetched) })
	c.BindCounter("pullthrough_prewarm_already_cached_total",
		"Total predicted artifacts found already present in the cache.",
		func() float64 { return float64(m.Snapshot().AlreadyCached) })
	c.BindCounter("pullthrough_prewarm_gate_blocked_total",
		"Total pre-warmed artifacts refused by an admission gate (quarantined, never served).",
		func() float64 { return float64(m.Snapshot().GateBlocked) })
	c.BindCounter("pullthrough_prewarm_errors_total",
		"Total pre-warm fetches that failed (e.g. a predicted version that does not exist upstream).",
		func() float64 { return float64(m.Snapshot().Errors) })
	c.BindCounter("pullthrough_prewarm_hit_attributed_total",
		"Total client cache hits served from an artifact a prior pre-warm had fetched.",
		func() float64 { return float64(m.Snapshot().HitAttributed) })
	c.BindCounter("pullthrough_prewarm_cycles_total",
		"Total prediction+pre-warm cycles executed.",
		func() float64 { return float64(m.Snapshot().CyclesRun) })
	c.BindCounterVec("pullthrough_prewarm_cycles_skipped_total",
		"Total pre-warm cycles skipped, by reason.",
		[]string{"reason"},
		func() []metrics.LabeledValue {
			snap := m.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.SkippedCycles))
			for reason, v := range snap.SkippedCycles {
				out = append(out, metrics.LabeledValue{Labels: []string{reason}, Value: float64(v)})
			}
			return out
		})
}

// siemValues projects the forwarder's per-sink snapshot into labeled metric
// values keyed by sink name.
func siemValues(f *siem.Forwarder, pick func(siem.SinkMetrics) float64) []metrics.LabeledValue {
	snap := f.Metrics()
	out := make([]metrics.LabeledValue, 0, len(snap.PerSink))
	for name, m := range snap.PerSink {
		out = append(out, metrics.LabeledValue{Labels: []string{name}, Value: pick(m)})
	}
	return out
}

// bindSecretsMetrics registers the secrets-provider resolution/refresh counters
// (Task 133) as scrape-time callbacks reading the resolver's snapshot. Labels
// carry only the reference scheme ("env", "file", "vault", "literal") — never a
// secret value or a full reference path.
func bindSecretsMetrics(c *metrics.Collector, r *secrets.Resolver) {
	if r == nil {
		return
	}
	c.BindCounterVec("pullthrough_secrets_resolve_success_total",
		"Total secretRef resolutions that succeeded, by reference scheme.",
		[]string{"scheme"},
		func() []metrics.LabeledValue { return secretsSchemeValues(r.Metrics().ResolveSuccess) })
	c.BindCounterVec("pullthrough_secrets_resolve_failure_total",
		"Total secretRef resolutions that failed, by reference scheme.",
		[]string{"scheme"},
		func() []metrics.LabeledValue { return secretsSchemeValues(r.Metrics().ResolveFailure) })
	c.BindCounter("pullthrough_secrets_refresh_success_total",
		"Total Vault lease renewals / cached-secret re-reads that succeeded.",
		func() float64 { return float64(r.Metrics().RefreshSuccess) })
	c.BindCounter("pullthrough_secrets_refresh_failure_total",
		"Total Vault lease renewals / cached-secret re-reads that failed.",
		func() float64 { return float64(r.Metrics().RefreshFailure) })
	c.BindCounter("pullthrough_secrets_rotations_total",
		"Total times a background refresh observed a rotated (changed) secret value.",
		func() float64 { return float64(r.Metrics().Rotations) })
}

// secretsSchemeValues projects a per-scheme counter map into labeled metric
// values keyed by scheme.
func secretsSchemeValues(byScheme map[string]uint64) []metrics.LabeledValue {
	out := make([]metrics.LabeledValue, 0, len(byScheme))
	for scheme, v := range byScheme {
		out = append(out, metrics.LabeledValue{Labels: []string{scheme}, Value: float64(v)})
	}
	return out
}

// bindRateLimitMetrics registers the rate limiter's cumulative throttle/allow
// counters and per-tenant live gauges (Task 24) as scrape-time callbacks reading
// the limiter's atomics, so the limiter remains the single source of truth.
func bindRateLimitMetrics(c *metrics.Collector, lim *ratelimit.Limiter) {
	if lim == nil {
		return
	}
	c.BindCounter("pullthrough_ratelimit_allowed_total",
		"Total backend requests admitted by the rate limiter.",
		func() float64 { return float64(lim.Metrics().Allowed) })
	c.BindCounter("pullthrough_ratelimit_throttled_total",
		"Total backend requests rejected by the rate limiter (any dimension).",
		func() float64 { return float64(lim.Metrics().Throttled) })
	c.BindCounterVec("pullthrough_ratelimit_throttled_by_reason_total",
		"Total rate-limit rejections, by violated dimension (rps|concurrency|bytes).",
		[]string{"reason"},
		func() []metrics.LabeledValue {
			snap := lim.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ThrottledByReason))
			for reason, v := range snap.ThrottledByReason {
				out = append(out, metrics.LabeledValue{Labels: []string{reason}, Value: float64(v)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_ratelimit_concurrent_inflight",
		"Current in-flight pulls held against the concurrency cap, by tenant.",
		"gauge", []string{"tenant"},
		func() []metrics.LabeledValue {
			snap := lim.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.Tenants)+1)
			if snap.Global.InFlight > 0 || snap.Global.Policy.MaxConcurrent > 0 {
				out = append(out, metrics.LabeledValue{Labels: []string{ratelimit.GlobalKey}, Value: float64(snap.Global.InFlight)})
			}
			for _, t := range snap.Tenants {
				out = append(out, metrics.LabeledValue{Labels: []string{t.Tenant}, Value: float64(t.InFlight)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_ratelimit_bytes_used",
		"Bytes consumed in the current byte-quota window, by tenant.",
		"gauge", []string{"tenant"},
		func() []metrics.LabeledValue {
			snap := lim.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.Tenants)+1)
			if snap.Global.Policy.ByteQuota > 0 {
				out = append(out, metrics.LabeledValue{Labels: []string{ratelimit.GlobalKey}, Value: float64(snap.Global.BytesUsed)})
			}
			for _, t := range snap.Tenants {
				if t.Policy.ByteQuota > 0 {
					out = append(out, metrics.LabeledValue{Labels: []string{t.Tenant}, Value: float64(t.BytesUsed)})
				}
			}
			return out
		})
}

// bindAuditMetrics registers the tamper-evident audit log's chain/transparency
// telemetry (Task 31) as scrape-time callbacks reading the logger's live state,
// so operators can chart growth, alert on a stalled checkpoint sealer, and page
// on any verification failure. Safe to call with a nil logger.
func bindAuditMetrics(c *metrics.Collector, l *audit.Logger) {
	if l == nil {
		return
	}
	c.BindCounter("pullthrough_audit_chain_length",
		"Number of records in the tamper-evident audit hash chain.",
		func() float64 { return float64(l.Stats().ChainLength) })
	c.BindGauge("pullthrough_audit_tree_size",
		"Number of records covered by the audit Merkle transparency tree.",
		func() float64 { return float64(l.Stats().TreeSize) })
	c.BindCounter("pullthrough_audit_checkpoints_total",
		"Total signed checkpoints (signed tree heads) sealed over the audit log.",
		func() float64 { return float64(l.Stats().Checkpoints) })
	c.BindGauge("pullthrough_audit_last_seal_timestamp",
		"Unix timestamp (seconds) of the most recently sealed audit checkpoint (0 if none).",
		func() float64 { return float64(l.Stats().LastSealUnix) })
	c.BindCounter("pullthrough_audit_verification_failures_total",
		"Total audit-log proof/integrity verification failures detected.",
		func() float64 { return float64(l.Stats().VerificationFailures) })
}

// bindProvgraphMetrics registers the supply-chain graph's size as scrape-time
// gauges (Task 33): total nodes/edges plus a per-kind labeled breakdown and the
// cumulative count of ingested events, so operators can chart the graph's growth
// and shape. Safe to call with a nil service.
func bindProvgraphMetrics(c *metrics.Collector, svc *provgraph.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_provgraph_nodes",
		"Total nodes in the supply-chain provenance graph.",
		func() float64 { return float64(svc.Snapshot().Nodes) })
	c.BindGauge("pullthrough_provgraph_edges",
		"Total edges in the supply-chain provenance graph.",
		func() float64 { return float64(svc.Snapshot().Edges) })
	c.BindCounter("pullthrough_provgraph_events_total",
		"Total events ingested into the supply-chain provenance graph.",
		func() float64 { return float64(svc.Snapshot().EventsIngested) })
	// Per-kind breakdowns as labeled gauges so each node/edge kind is its own
	// series.
	c.Registry().RegisterFuncVec("pullthrough_provgraph_nodes_by_kind_total",
		"Supply-chain graph node count, partitioned by node kind.", "gauge", []string{"kind"},
		func() []metrics.LabeledValue {
			snap := svc.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.NodesByKind))
			for kind, n := range snap.NodesByKind {
				out = append(out, metrics.LabeledValue{Labels: []string{kind}, Value: float64(n)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_provgraph_edges_by_kind_total",
		"Supply-chain graph edge count, partitioned by edge kind.", "gauge", []string{"kind"},
		func() []metrics.LabeledValue {
			snap := svc.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.EdgesByKind))
			for kind, n := range snap.EdgesByKind {
				out = append(out, metrics.LabeledValue{Labels: []string{kind}, Value: float64(n)})
			}
			return out
		})
}

// bindCoalesceMetrics registers the pull-path coalescer's cumulative counters,
// dedup ratio, and live gauges (Task 36) as scrape-time callbacks reading the
// coalescer's own atomics. Safe to call with a nil coalescer (disabled).
func bindCoalesceMetrics(c *metrics.Collector, cl *coalesce.Coalescer[*cache.Entry]) {
	if cl == nil {
		return
	}
	c.BindCounter("pullthrough_coalesce_lookups_total",
		"Total pull-path lookups handled by the request coalescer.",
		func() float64 { return float64(cl.Metrics().Lookups) })
	c.BindCounter("pullthrough_coalesce_hits_total",
		"Total cache-miss requests that joined an in-flight upstream fetch instead of issuing their own (coalesced).",
		func() float64 { return float64(cl.Metrics().Coalesced) })
	c.BindCounter("pullthrough_coalesce_leads_total",
		"Total requests that ran the upstream fetch themselves (single-flight leaders).",
		func() float64 { return float64(cl.Metrics().Leads) })
	c.BindGauge("pullthrough_coalesce_dedup_ratio",
		"Fraction of upstream-bound pull-path decisions served by joining an in-flight fetch (0..1).",
		func() float64 { return cl.Metrics().DedupRatio() })
	c.BindGauge("pullthrough_coalesce_inflight",
		"Number of distinct upstream fetches currently in flight.",
		func() float64 { return float64(cl.Metrics().InFlight) })
	c.BindCounter("pullthrough_coalesce_overloaded_total",
		"Total requests shed because the in-flight fetch ceiling was reached.",
		func() float64 { return float64(cl.Metrics().Overloaded) })
	c.BindCounter("pullthrough_negative_cache_hits_total",
		"Total requests served from the negative cache (a remembered upstream 404/410/auth/5xx) without contacting the upstream.",
		func() float64 { return float64(cl.Metrics().NegativeHits) })
	c.BindCounter("pullthrough_negative_cache_stored_total",
		"Total negative-cache entries written for terminal/transient upstream failures.",
		func() float64 { return float64(cl.Metrics().NegativeStored) })
	c.BindCounter("pullthrough_negative_cache_evictions_total",
		"Total negative-cache entries dropped by the LRU size bound.",
		func() float64 { return float64(cl.Metrics().NegativeEvictions) })
	c.BindCounter("pullthrough_negative_cache_expired_total",
		"Total negative-cache entries observed expired on lookup.",
		func() float64 { return float64(cl.Metrics().NegativeExpired) })
	c.BindGauge("pullthrough_negative_cache_entries",
		"Current number of entries in the negative cache.",
		func() float64 { return float64(cl.Metrics().NegativeEntries) })
	// Per-failure-class breakdown of negative-cache hits, so operators can see
	// whether they are absorbing missing-artifact, auth, or upstream-error storms.
	c.BindCounterVec("pullthrough_negative_cache_hits_by_kind_total",
		"Negative-cache hits, partitioned by upstream failure class (not_found|gone|auth|throttled|server|error).",
		[]string{"kind"},
		func() []metrics.LabeledValue {
			snap := cl.Metrics()
			out := make([]metrics.LabeledValue, 0, len(snap.ByKind))
			for kind, st := range snap.ByKind {
				out = append(out, metrics.LabeledValue{Labels: []string{kind}, Value: float64(st.Hits)})
			}
			return out
		})
}

// bindComplianceMetrics registers the continuous-compliance scorecard's gauges
// (Task 35) as scrape-time callbacks reading the latest computed scorecard, so
// the existing Grafana bundle can chart the compliance trend and Prometheus can
// alert on posture regressions. It exposes an overall score, the estimated SLSA
// build level, and per-control score/pass series. Safe to call with a nil service.
func bindComplianceMetrics(c *metrics.Collector, svc *compliance.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_compliance_score",
		"Overall continuous-compliance posture score (0..1) across applicable controls.",
		func() float64 { return svc.Latest().Score })
	c.BindGauge("pullthrough_compliance_slsa_build_level",
		"Estimated SLSA build level (0..3) inferred from the current posture.",
		func() float64 { return float64(svc.Latest().SLSA.BuildLevel) })
	c.BindGauge("pullthrough_compliance_controls_failing",
		"Number of compliance controls currently in a failing state.",
		func() float64 { return float64(svc.Latest().Summary.Fail) })
	c.BindGauge("pullthrough_compliance_controls_warning",
		"Number of compliance controls currently in a warning state.",
		func() float64 { return float64(svc.Latest().Summary.Warn) })
	c.BindGauge("pullthrough_compliance_last_computed_timestamp",
		"Unix timestamp (seconds) of the most recent scorecard computation.",
		func() float64 { return float64(svc.Latest().GeneratedAt.Unix()) })
	c.Registry().RegisterFuncVec("pullthrough_compliance_control_score",
		"Per-control compliance posture score (0..1), labeled by control id.",
		"gauge", []string{"control"},
		func() []metrics.LabeledValue {
			scores := svc.ControlScores()
			out := make([]metrics.LabeledValue, 0, len(scores))
			for id, v := range scores {
				out = append(out, metrics.LabeledValue{Labels: []string{id}, Value: v})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_compliance_control_pass",
		"Per-control compliance pass indicator (1 passing, 0 otherwise), labeled by control id.",
		"gauge", []string{"control"},
		func() []metrics.LabeledValue {
			pass := svc.ControlPass()
			out := make([]metrics.LabeledValue, 0, len(pass))
			for id, v := range pass {
				out = append(out, metrics.LabeledValue{Labels: []string{id}, Value: v})
			}
			return out
		})
}

// bindRiskScoreMetrics registers the unified risk-scoring engine's per-band
// scored-artifact gauges and the cumulative blocked/warned/threshold-crossing
// counters (Task 37) as scrape-time callbacks reading the engine's own state,
// so operators can chart the risk-band distribution and alert on threshold
// crossings. Safe to call with a nil engine (disabled).
func bindRiskScoreMetrics(c *metrics.Collector, e *riskscore.Engine) {
	if e == nil {
		return
	}
	c.BindGauge("pullthrough_riskscore_artifacts_scored_total",
		"Total artifacts scored by the unified risk-scoring engine.",
		func() float64 { return float64(e.Snapshot().TotalScored) })
	c.BindCounter("pullthrough_riskscore_blocked_total",
		"Total artifacts blocked by the risk-score admission threshold.",
		func() float64 { return float64(e.Snapshot().Blocked) })
	c.BindCounter("pullthrough_riskscore_warned_total",
		"Total artifacts warned on by the risk-score admission threshold.",
		func() float64 { return float64(e.Snapshot().Warned) })
	c.BindCounter("pullthrough_riskscore_threshold_crossings_total",
		"Total risk-score admission-threshold crossings (warn or block).",
		func() float64 { return float64(e.Snapshot().Crossings) })
	// Per-band scored-artifact counts as labeled gauges so each band is its own
	// series for the band-distribution panel.
	c.Registry().RegisterFuncVec("pullthrough_riskscore_artifacts_by_band_total",
		"Scored-artifact count partitioned by risk band (low|medium|high|critical).",
		"gauge", []string{"band"},
		func() []metrics.LabeledValue {
			counts := e.BandCounts()
			out := make([]metrics.LabeledValue, 0, len(counts))
			for band, n := range counts {
				out = append(out, metrics.LabeledValue{Labels: []string{band}, Value: n})
			}
			return out
		})
}

// bindRepoScoreMetrics registers the source-repository health provider's
// counters and gauges (Task 63) — evaluations, resolved/unresolved repositories,
// cache hits, online enrichments, errors, the average health score, and the
// per-grade resolved-repo distribution — as scrape-time callbacks reading the
// service's own state. Safe to call with a nil service (disabled).
func bindRepoScoreMetrics(c *metrics.Collector, s *reposcore.Service) {
	if s == nil {
		return
	}
	c.BindCounter("pullthrough_reposcore_evaluated_total",
		"Total repository-health evaluations performed.",
		func() float64 { return float64(s.Metrics().Evaluated) })
	c.BindCounter("pullthrough_reposcore_resolved_total",
		"Total repository-health evaluations that resolved a local clone.",
		func() float64 { return float64(s.Metrics().Resolved) })
	c.BindCounter("pullthrough_reposcore_unresolved_total",
		"Total repository-health evaluations with no local clone available.",
		func() float64 { return float64(s.Metrics().Unresolved) })
	c.BindCounter("pullthrough_reposcore_cache_hits_total",
		"Total repository-health evaluations served from the per-repo facts cache.",
		func() float64 { return float64(s.Metrics().CacheHits) })
	c.BindCounter("pullthrough_reposcore_online_total",
		"Total repository-health evaluations that used online enrichment.",
		func() float64 { return float64(s.Metrics().Online) })
	c.BindCounter("pullthrough_reposcore_errors_total",
		"Total repository-health evaluations that recorded an extraction error.",
		func() float64 { return float64(s.Metrics().Errors) })
	c.BindGauge("pullthrough_reposcore_cache_size",
		"Number of repositories with a cached facts extraction.",
		func() float64 { return float64(s.Metrics().CacheSize) })
	c.BindGauge("pullthrough_reposcore_avg_health",
		"Average repository-health score (0..100) across resolved repositories.",
		func() float64 { return s.Metrics().AvgHealth })
	// Per-grade resolved-repo counts as labeled gauges so each grade is its own
	// series for the health-distribution panel.
	c.Registry().RegisterFuncVec("pullthrough_reposcore_repos_by_grade_total",
		"Resolved-repository count partitioned by health grade (A|B|C|D|F).",
		"gauge", []string{"grade"},
		func() []metrics.LabeledValue {
			byGrade := s.Metrics().ByGrade
			out := make([]metrics.LabeledValue, 0, len(byGrade))
			for grade, n := range byGrade {
				out = append(out, metrics.LabeledValue{Labels: []string{grade}, Value: float64(n)})
			}
			return out
		})
}

// bindSbomDiffMetrics registers the SBOM diff & dependency-drift subsystem's
// cumulative gauges/counters (Task 64): snapshots observed, versions compared,
// significant drifts, and the resulting warn/block/quarantine tallies, plus a
// per-ecosystem significant-drift vector for the drift-distribution panel.
func bindSbomDiffMetrics(c *metrics.Collector, s *sbomdiff.Service) {
	if s == nil {
		return
	}
	c.BindCounter("pullthrough_sbomdiff_observed_total",
		"Total version snapshots observed (recorded into the per-coordinate history).",
		func() float64 { return float64(s.Metrics(0).Observed) })
	c.BindCounter("pullthrough_sbomdiff_compared_total",
		"Total version-to-version diffs computed (a prior version existed).",
		func() float64 { return float64(s.Metrics(0).Compared) })
	c.BindCounter("pullthrough_sbomdiff_significant_total",
		"Total diffs whose drift score met the significance threshold.",
		func() float64 { return float64(s.Metrics(0).Significant) })
	c.BindCounter("pullthrough_sbomdiff_warned_total",
		"Total pulls warned on for dependency drift.",
		func() float64 { return float64(s.Metrics(0).Warned) })
	c.BindCounter("pullthrough_sbomdiff_blocked_total",
		"Total pulls blocked for dependency drift.",
		func() float64 { return float64(s.Metrics(0).Blocked) })
	c.BindCounter("pullthrough_sbomdiff_quarantined_total",
		"Total pulls quarantined for dependency drift.",
		func() float64 { return float64(s.Metrics(0).Quarantined) })
	c.BindGauge("pullthrough_sbomdiff_coordinates",
		"Number of coordinates with a retained SBOM history.",
		func() float64 { return float64(s.Metrics(0).Coordinates) })
	// Per-ecosystem significant-drift counts as a labeled vector.
	c.Registry().RegisterFuncVec("pullthrough_sbomdiff_significant_by_ecosystem_total",
		"Significant dependency-drift events partitioned by ecosystem.",
		"counter", []string{"ecosystem"},
		func() []metrics.LabeledValue {
			eco := s.EcosystemDrift()
			out := make([]metrics.LabeledValue, 0, len(eco))
			for _, e := range eco {
				out = append(out, metrics.LabeledValue{Labels: []string{e.Ecosystem}, Value: float64(e.Count)})
			}
			return out
		})
}

// bindRebuildVerifyMetrics registers the reproducible-build verification gate's
// cumulative counters (Task 68): total verifications, the per-verdict tallies
// (reproducible / mismatch / unsupported / unattested), builds run, build errors,
// and cache hits — plus a per-ecosystem-and-verdict labeled vector so operators
// can chart, and alert on, reproducibility mismatches per ecosystem. Safe with a
// nil service (disabled).
func bindRebuildVerifyMetrics(c *metrics.Collector, s *rebuildverify.Service) {
	if s == nil {
		return
	}
	c.BindCounter("pullthrough_rebuildverify_verifications_total",
		"Total reproducible-build verifications that reached a terminal verdict.",
		func() float64 { return float64(s.Metrics().Verifications) })
	c.BindCounter("pullthrough_rebuildverify_reproducible_total",
		"Total artifacts whose rebuild matched the upstream-served artifact.",
		func() float64 { return float64(s.Metrics().Reproducible) })
	c.BindCounter("pullthrough_rebuildverify_mismatch_total",
		"Total artifacts whose rebuild did NOT match the upstream-served artifact (confirmed mismatch).",
		func() float64 { return float64(s.Metrics().Mismatch) })
	c.BindCounter("pullthrough_rebuildverify_unsupported_total",
		"Total verifications skipped as unsupported (no builder / toolchain or source unavailable).",
		func() float64 { return float64(s.Metrics().Unsupported) })
	c.BindCounter("pullthrough_rebuildverify_unattested_total",
		"Total verifications skipped as unattested (no source-commit provenance to rebuild from).",
		func() float64 { return float64(s.Metrics().Unattested) })
	c.BindCounter("pullthrough_rebuildverify_builds_run_total",
		"Total rebuild attempts dispatched to a builder.",
		func() float64 { return float64(s.Metrics().BuildsRun) })
	c.BindCounter("pullthrough_rebuildverify_build_errors_total",
		"Total rebuild attempts that errored (fail-open; counted as unsupported).",
		func() float64 { return float64(s.Metrics().BuildErrors) })
	c.BindCounter("pullthrough_rebuildverify_cache_hits_total",
		"Total verification requests served from the per-(coordinate,digest) result cache.",
		func() float64 { return float64(s.Metrics().CacheHits) })
	c.BindGauge("pullthrough_rebuildverify_cache_size",
		"Number of cached terminal verification results.",
		func() float64 { return float64(s.Metrics().CacheSize) })
	c.BindGauge("pullthrough_rebuildverify_inflight",
		"Number of reproducible-build rebuilds currently in flight.",
		func() float64 { return float64(s.Metrics().InFlight) })
	// Per-ecosystem, per-verdict counts as a labeled vector.
	c.Registry().RegisterFuncVec("pullthrough_rebuildverify_verdicts_total",
		"Reproducible-build verdicts partitioned by ecosystem and verdict.",
		"counter", []string{"ecosystem", "verdict"},
		func() []metrics.LabeledValue {
			byEco := s.Metrics().ByEcosystem
			out := make([]metrics.LabeledValue, 0, len(byEco)*4)
			for eco, vc := range byEco {
				out = append(out,
					metrics.LabeledValue{Labels: []string{eco, "reproducible"}, Value: float64(vc.Reproducible)},
					metrics.LabeledValue{Labels: []string{eco, "mismatch"}, Value: float64(vc.Mismatch)},
					metrics.LabeledValue{Labels: []string{eco, "unsupported"}, Value: float64(vc.Unsupported)},
					metrics.LabeledValue{Labels: []string{eco, "unattested"}, Value: float64(vc.Unattested)},
				)
			}
			return out
		})
}

// bindBuildProvMetrics registers the inbound build-provenance gate's cumulative
// counters (Task 72): total verifications, attestations checked, the per-outcome
// tallies (present / verified / source-verified / mismatch), gate decisions
// (blocked / quarantined / warned), errors and cache hits — plus a per-ecosystem
// labeled vector of the four headline outcomes so operators can chart, and alert
// on, build-provenance mismatches per ecosystem. Safe with a nil service.
func bindBuildProvMetrics(c *metrics.Collector, s *buildprov.Service) {
	if s == nil {
		return
	}
	c.BindCounter("pullthrough_buildprov_verifications_total",
		"Total inbound build-provenance verifications performed.",
		func() float64 { return float64(s.Metrics().Verifications) })
	c.BindCounter("pullthrough_buildprov_attestations_checked_total",
		"Total inbound build-provenance attestations cryptographically verified.",
		func() float64 { return float64(s.Metrics().AttestationsCheck) })
	c.BindCounter("pullthrough_buildprov_present_total",
		"Total artifacts for which an inbound build-provenance attestation was discovered.",
		func() float64 { return float64(s.Metrics().Present) })
	c.BindCounter("pullthrough_buildprov_verified_total",
		"Total artifacts with a cryptographically-valid, digest-bound build-provenance attestation.",
		func() float64 { return float64(s.Metrics().Verified) })
	c.BindCounter("pullthrough_buildprov_source_verified_total",
		"Total artifacts whose build-provenance attestation chained to a trusted, allowed signer.",
		func() float64 { return float64(s.Metrics().SourceVerified) })
	c.BindCounter("pullthrough_buildprov_mismatch_total",
		"Total artifacts whose PROVEN source disagreed with the source CLAIMED by package metadata.",
		func() float64 { return float64(s.Metrics().Mismatch) })
	c.BindCounter("pullthrough_buildprov_blocked_total",
		"Total artifacts blocked by the inbound build-provenance gate.",
		func() float64 { return float64(s.Metrics().Blocked) })
	c.BindCounter("pullthrough_buildprov_quarantined_total",
		"Total artifacts quarantined by the inbound build-provenance gate.",
		func() float64 { return float64(s.Metrics().Quarantined) })
	c.BindCounter("pullthrough_buildprov_warned_total",
		"Total artifacts warned on by the inbound build-provenance gate.",
		func() float64 { return float64(s.Metrics().Warned) })
	c.BindCounter("pullthrough_buildprov_errors_total",
		"Total inbound build-provenance verifications that hit an infrastructure error (fetch/parse).",
		func() float64 { return float64(s.Metrics().Errors) })
	c.BindCounter("pullthrough_buildprov_cache_hits_total",
		"Total verification requests served from the result cache.",
		func() float64 { return float64(s.Metrics().CacheHits) })
	c.BindGauge("pullthrough_buildprov_cache_size",
		"Number of cached build-provenance verification results.",
		func() float64 { return float64(s.Metrics().CacheEntries) })
	// Per-ecosystem outcome counts as a labeled vector.
	c.Registry().RegisterFuncVec("pullthrough_buildprov_outcomes_total",
		"Inbound build-provenance outcomes partitioned by ecosystem and outcome.",
		"counter", []string{"ecosystem", "outcome"},
		func() []metrics.LabeledValue {
			byEco := s.Metrics().ByEcosystem
			out := make([]metrics.LabeledValue, 0, len(byEco)*5)
			for eco, c := range byEco {
				out = append(out,
					metrics.LabeledValue{Labels: []string{eco, "checked"}, Value: float64(c.Checked)},
					metrics.LabeledValue{Labels: []string{eco, "present"}, Value: float64(c.Present)},
					metrics.LabeledValue{Labels: []string{eco, "verified"}, Value: float64(c.Verified)},
					metrics.LabeledValue{Labels: []string{eco, "source_verified"}, Value: float64(c.SourceVerified)},
					metrics.LabeledValue{Labels: []string{eco, "mismatch"}, Value: float64(c.Mismatch)},
				)
			}
			return out
		})
}

// bindPyPIAttestMetrics registers the inbound PyPI PEP 740 attestation gate's
// cumulative counters (Task 146): total verifications, attestations checked, the
// per-outcome tallies (present / verified / publisher-trusted / digest-mismatch /
// transparency-verified), gate decisions (blocked / downgraded), errors and cache
// hits — plus a per-ecosystem labeled vector of the headline outcomes. Safe with
// a nil service.
func bindPyPIAttestMetrics(c *metrics.Collector, s *pypiattest.Service) {
	if s == nil {
		return
	}
	c.BindCounter("pullthrough_pypi_attestation_verifications_total",
		"Total inbound PyPI PEP 740 attestation verifications performed.",
		func() float64 { return float64(s.Metrics().Verifications) })
	c.BindCounter("pullthrough_pypi_attestation_attestations_checked_total",
		"Total inbound PyPI attestations cryptographically verified.",
		func() float64 { return float64(s.Metrics().AttestationsCheck) })
	c.BindCounter("pullthrough_pypi_attestation_present_total",
		"Total distributions for which a PyPI PEP 740 attestation was discovered.",
		func() float64 { return float64(s.Metrics().Present) })
	c.BindCounter("pullthrough_pypi_attestation_verified_total",
		"Total distributions with a cryptographically-valid, digest-bound PyPI attestation.",
		func() float64 { return float64(s.Metrics().Verified) })
	c.BindCounter("pullthrough_pypi_attestation_publisher_trusted_total",
		"Total distributions whose PyPI attestation chained to a trusted, allowed Trusted Publisher.",
		func() float64 { return float64(s.Metrics().PublisherTrusted) })
	c.BindCounter("pullthrough_pypi_attestation_digest_mismatch_total",
		"Total distributions where a valid PyPI attestation attested a different digest than served.",
		func() float64 { return float64(s.Metrics().DigestMismatch) })
	c.BindCounter("pullthrough_pypi_attestation_transparency_verified_total",
		"Total distributions whose PyPI attestation carried a verifiable Rekor transparency-log entry.",
		func() float64 { return float64(s.Metrics().Transparency) })
	c.BindCounter("pullthrough_pypi_attestation_blocked_total",
		"Total distributions blocked by the inbound PyPI attestation gate.",
		func() float64 { return float64(s.Metrics().Blocked) })
	c.BindCounter("pullthrough_pypi_attestation_downgraded_total",
		"Total distributions downgraded (served with a warning) by the inbound PyPI attestation gate.",
		func() float64 { return float64(s.Metrics().Downgraded) })
	c.BindCounter("pullthrough_pypi_attestation_errors_total",
		"Total PyPI attestation verifications that hit an infrastructure error (fetch/parse).",
		func() float64 { return float64(s.Metrics().Errors) })
	c.BindCounter("pullthrough_pypi_attestation_cache_hits_total",
		"Total verification requests served from the result cache.",
		func() float64 { return float64(s.Metrics().CacheHits) })
	c.BindGauge("pullthrough_pypi_attestation_cache_size",
		"Number of cached PyPI attestation verification results.",
		func() float64 { return float64(s.Metrics().CacheEntries) })
	c.Registry().RegisterFuncVec("pullthrough_pypi_attestation_outcomes_total",
		"Inbound PyPI attestation outcomes partitioned by ecosystem and outcome.",
		"counter", []string{"ecosystem", "outcome"},
		func() []metrics.LabeledValue {
			byEco := s.Metrics().ByEcosystem
			out := make([]metrics.LabeledValue, 0, len(byEco)*5)
			for eco, c := range byEco {
				out = append(out,
					metrics.LabeledValue{Labels: []string{eco, "checked"}, Value: float64(c.Checked)},
					metrics.LabeledValue{Labels: []string{eco, "present"}, Value: float64(c.Present)},
					metrics.LabeledValue{Labels: []string{eco, "verified"}, Value: float64(c.Verified)},
					metrics.LabeledValue{Labels: []string{eco, "publisher_trusted"}, Value: float64(c.PublisherTrusted)},
					metrics.LabeledValue{Labels: []string{eco, "digest_mismatch"}, Value: float64(c.DigestMismatch)},
				)
			}
			return out
		})
}

// bindExtensionMetrics registers the per-module WASM extension-gate telemetry
// (Task 59) — invocations, verdicts by decision, timeouts, fuel exhaustion,
// errors, load state, and last-invocation duration — as scrape-time callbacks
// reading the manager's own state, each labeled by module so every gate is its
// own time series. Safe to call with a nil manager (disabled).
func bindExtensionMetrics(c *metrics.Collector, m *extension.Manager) {
	if m == nil {
		return
	}
	// Per-module counters/gauges labeled by module name.
	type modField struct {
		name, help, typ string
		get             func(extension.ModuleSnapshot) float64
	}
	fields := []modField{
		{"pullthrough_extension_invocations_total", "Extension module invocations.", "counter", func(s extension.ModuleSnapshot) float64 { return float64(s.Invocations) }},
		{"pullthrough_extension_timeouts_total", "Extension module CPU/time-budget timeouts.", "counter", func(s extension.ModuleSnapshot) float64 { return float64(s.Timeouts) }},
		{"pullthrough_extension_fuel_exhausted_total", "Extension module fuel-budget exhaustions.", "counter", func(s extension.ModuleSnapshot) float64 { return float64(s.FuelExhausted) }},
		{"pullthrough_extension_errors_total", "Extension module evaluation errors (traps, ABI violations, malformed verdicts).", "counter", func(s extension.ModuleSnapshot) float64 { return float64(s.Errors) }},
		{"pullthrough_extension_loaded", "Whether the extension module compiled and verified its ABI (1) or not (0).", "gauge", func(s extension.ModuleSnapshot) float64 {
			if s.Loaded {
				return 1
			}
			return 0
		}},
		{"pullthrough_extension_last_duration_microseconds", "Most recent extension invocation wall-clock time, in microseconds.", "gauge", func(s extension.ModuleSnapshot) float64 { return float64(s.LastDurationMicros) }},
	}
	for _, f := range fields {
		get := f.get
		c.Registry().RegisterFuncVec(f.name, f.help, f.typ, []string{"module"},
			func() []metrics.LabeledValue {
				mods := m.Snapshot().Modules
				out := make([]metrics.LabeledValue, 0, len(mods))
				for _, s := range mods {
					out = append(out, metrics.LabeledValue{Labels: []string{s.Name}, Value: get(s)})
				}
				return out
			})
	}
	// Verdicts partitioned by module and decision.
	c.Registry().RegisterFuncVec("pullthrough_extension_verdicts_total",
		"Extension module verdicts by decision (allow|warn|block).",
		"counter", []string{"module", "decision"},
		func() []metrics.LabeledValue {
			mods := m.Snapshot().Modules
			out := make([]metrics.LabeledValue, 0, len(mods)*3)
			for _, s := range mods {
				out = append(out,
					metrics.LabeledValue{Labels: []string{s.Name, "allow"}, Value: float64(s.Allow)},
					metrics.LabeledValue{Labels: []string{s.Name, "warn"}, Value: float64(s.Warn)},
					metrics.LabeledValue{Labels: []string{s.Name, "block"}, Value: float64(s.Block)},
				)
			}
			return out
		})
}

// bindAnomalyMetrics registers the behavioral-anomaly engine's cumulative
// counters (observations, alerts, soft-blocks), the per-level assessment
// distribution, the per-detector trigger counts, and the per-detector
// current-saturation gauge (Task 43) as scrape-time callbacks reading the
// engine's own state, so operators can chart anomaly pressure per detector and
// alert on soft-blocks. Safe to call with a nil engine (disabled).
func bindAnomalyMetrics(c *metrics.Collector, e *anomaly.Engine) {
	if e == nil {
		return
	}
	c.BindCounter("pullthrough_anomaly_observations_total",
		"Total pull observations folded into the behavioral anomaly detectors.",
		func() float64 { o, _, _ := e.Totals(); return float64(o) })
	c.BindCounter("pullthrough_anomaly_alerts_total",
		"Total behavioral-anomaly alerts raised (assessments that crossed the warn level and cleared the alert cooldown).",
		func() float64 { _, a, _ := e.Totals(); return float64(a) })
	c.BindCounter("pullthrough_anomaly_soft_blocks_total",
		"Total requests soft-blocked by the behavioral-anomaly gate.",
		func() float64 { _, _, b := e.Totals(); return float64(b) })
	// Per-level assessment counts so the level distribution is chartable.
	c.Registry().RegisterFuncVec("pullthrough_anomaly_assessments_by_level_total",
		"Anomaly assessments partitioned by overall level (none|low|medium|high).",
		"counter", []string{"level"},
		func() []metrics.LabeledValue { return labeledMap(e.LevelCounts()) })
	// Per-detector trigger counts so each detector is its own series.
	c.Registry().RegisterFuncVec("pullthrough_anomaly_detector_triggers_total",
		"Detector trigger count partitioned by detector (fanout|new_namespace|off_hours|enumeration|egress).",
		"counter", []string{"detector"},
		func() []metrics.LabeledValue { return labeledMap(e.TriggerCounts()) })
	// Per-detector maximum current score across all tracked scopes, a saturation
	// gauge that shows how close any scope is to a given detector's high cutoff.
	c.Registry().RegisterFuncVec("pullthrough_anomaly_detector_score_max",
		"Maximum current anomaly score (0..1) across tracked scopes, per detector.",
		"gauge", []string{"detector"},
		func() []metrics.LabeledValue { return labeledMap(e.DetectorScoreMax()) })
	// Number of tenant/identity scopes currently tracked, for capacity awareness.
	c.BindGauge("pullthrough_anomaly_tracked_scopes",
		"Number of tenant/identity scopes currently tracked by the anomaly engine.",
		func() float64 { return float64(e.Snapshot().TrackedScopes) })
}

// bindEgressMetrics registers the SSRF / outbound-egress guard's cumulative
// counters (Task 89): total egress checks, allowed, blocked, and the per-reason
// block breakdown as its own label series so operators can chart and alert on
// (e.g.) metadata-service or private-network egress attempts — a live SSRF
// indicator. Safe to call with a nil/disabled guard.
func bindEgressMetrics(c *metrics.Collector, g *egress.Guard) {
	if !g.Enabled() {
		return
	}
	c.BindCounter("pullthrough_egress_checks_total",
		"Total outbound-egress destination checks performed by the SSRF guard.",
		func() float64 { checked, _, _ := g.Totals(); return float64(checked) })
	c.BindCounter("pullthrough_egress_allowed_total",
		"Total outbound-egress checks the SSRF guard permitted.",
		func() float64 { _, allowed, _ := g.Totals(); return float64(allowed) })
	c.BindCounter("pullthrough_egress_blocked_total",
		"Total outbound fetches the SSRF guard blocked (fail-closed).",
		func() float64 { _, _, blocked := g.Totals(); return float64(blocked) })
	// Per-reason block counts so each denial cause is its own chartable series.
	c.Registry().RegisterFuncVec("pullthrough_egress_blocked_by_reason_total",
		"Blocked outbound fetches partitioned by reason (scheme_not_allowed|host_not_allowlisted|private_network|loopback|link_local|metadata|unique_local|cgnat|unspecified|multicast|resolve_error|too_many_redirects|invalid_url).",
		"counter", []string{"reason"},
		func() []metrics.LabeledValue { return labeledMap(g.BlockedByReason()) })
}

// bindTLSPinMetrics registers the per-upstream TLS certificate/CA pinning guard's
// counters (Task 128) as scrape-time callbacks reading the guard's own state:
// total handshakes checked against a pin, how many matched, and violations split
// by enforcement mode, plus a per-(host,mode) violation breakdown and a gauge of
// how many endpoints installed a pin verifier. Safe to call with a guard that
// has no pinned endpoints (the series simply stay at zero).
func bindTLSPinMetrics(c *metrics.Collector, g *tlspin.Guard) {
	c.BindGauge("pullthrough_upstream_tls_pin_endpoints",
		"Number of upstream endpoints (primary or mirror) with certificate/CA pinning configured.",
		func() float64 { return float64(g.PinnedEndpoints()) })
	c.BindCounter("pullthrough_upstream_tls_pin_checks_total",
		"Total upstream TLS handshakes checked against a configured certificate pin.",
		func() float64 { checks, _, _, _ := g.Totals(); return float64(checks) })
	c.BindCounter("pullthrough_upstream_tls_pin_matches_total",
		"Total upstream TLS handshakes whose certificate chain satisfied a configured pin.",
		func() float64 { _, matches, _, _ := g.Totals(); return float64(matches) })
	c.BindCounter("pullthrough_upstream_tls_pin_violations_total",
		"Total upstream TLS handshakes whose certificate chain satisfied no configured pin (enforced + report-only).",
		func() float64 {
			_, _, enforced, report := g.Totals()
			return float64(enforced + report)
		})
	// Per-(host,mode) violation breakdown so each pinned upstream's mismatches are
	// an individually chartable series, and enforced (fail-closed) violations are
	// distinguishable from report-only ones.
	c.Registry().RegisterFuncVec("pullthrough_upstream_tls_pin_violations_by_host_total",
		"Upstream TLS pin violations partitioned by host and enforcement mode (enforce|report_only).",
		"counter", []string{"host", "mode"},
		func() []metrics.LabeledValue {
			out := make([]metrics.LabeledValue, 0)
			for hm, v := range g.ViolationsByHost() {
				out = append(out, metrics.LabeledValue{Labels: []string{hm[0], hm[1]}, Value: v})
			}
			return out
		})
}

// bindUpstreamConnMetrics registers the shared outbound connection-pool
// telemetry (Task 130) as scrape-time callbacks reading the ConnMetrics the
// client pool records into. The metrics let operators see connection reuse,
// dial latency, and pool footprint for the whole pull/fetch path and catch
// connection churn under high-concurrency load:
//
//   - reuse rate: rate(pullthrough_upstream_conn_reused_total) /
//     rate(pullthrough_upstream_conn_acquired_total)
//   - average dial latency: rate(..._dial_duration_seconds_sum) /
//     rate(..._dial_duration_seconds_count)
//   - dials per request / churn: rate(..._conn_dials_total)
//
// Safe to call with a nil ConnMetrics (the series simply stay at zero).
func bindUpstreamConnMetrics(c *metrics.Collector, m *upstream.ConnMetrics) {
	c.BindCounter("pullthrough_upstream_conn_dials_total",
		"Total new outbound connections dialed to upstreams (including failed attempts); the raw connection-churn signal.",
		func() float64 { return float64(m.Snapshot().Dials) })
	c.BindCounter("pullthrough_upstream_conn_dial_errors_total",
		"Total outbound connection dials that failed (DNS, connect, or egress-policy refusal).",
		func() float64 { return float64(m.Snapshot().DialErrors) })
	c.BindCounter("pullthrough_upstream_conn_dial_duration_seconds_sum",
		"Cumulative latency in seconds of successful outbound dials (divide by _count for the average dial latency).",
		func() float64 { return m.Snapshot().DialSeconds })
	c.BindCounter("pullthrough_upstream_conn_dial_duration_seconds_count",
		"Number of successful outbound dials contributing to the dial-duration sum.",
		func() float64 { return float64(m.Snapshot().DialCount) })
	c.BindCounter("pullthrough_upstream_conn_acquired_total",
		"Total connection acquisitions handed to an upstream request (new dials plus reuses from the keep-alive pool).",
		func() float64 { return float64(m.Snapshot().Acquired) })
	c.BindCounter("pullthrough_upstream_conn_reused_total",
		"Total connection acquisitions satisfied from the keep-alive pool rather than a fresh dial (divide by acquired for the reuse rate).",
		func() float64 { return float64(m.Snapshot().Reused) })
	c.BindCounter("pullthrough_upstream_conn_closed_total",
		"Total outbound connections torn down (idle-timeout eviction, upstream close, or error).",
		func() float64 { return float64(m.Snapshot().Closed) })
	c.BindGauge("pullthrough_upstream_conn_open",
		"Outbound connections currently open across all upstream clients (active plus idle).",
		func() float64 { return float64(m.Snapshot().Open) })
	c.BindGauge("pullthrough_upstream_conn_idle",
		"Approximate number of outbound connections currently parked idle in the keep-alive pool.",
		func() float64 { return float64(m.Snapshot().Idle) })
}

// bindApprovalsMetrics registers the quarantine-review / break-glass workflow's
// live gauges (open reviews, active grants) and cumulative counters (requests,
// approvals, denials, expiries, break-glass serves) plus the time-to-approval
// sum/count (for an avg-latency panel via rate(sum)/rate(count)) (Task 50) as
// scrape-time callbacks reading the service's own state. Safe to call with a nil
// service (disabled).
func bindApprovalsMetrics(c *metrics.Collector, svc *approvals.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_approvals_open_requests",
		"Number of quarantine-review requests currently awaiting an operator decision.",
		func() float64 { return float64(svc.Snapshot().Open) })
	c.BindGauge("pullthrough_approvals_active_grants",
		"Number of break-glass grants currently active (approved and within their TTL).",
		func() float64 { return float64(svc.Snapshot().ActiveGrants) })
	c.BindCounter("pullthrough_approvals_requests_total",
		"Total quarantine-review requests opened.",
		func() float64 { return float64(svc.Snapshot().RequestsTotal) })
	c.BindCounter("pullthrough_approvals_approved_total",
		"Total quarantine-review requests granted a break-glass exception.",
		func() float64 { return float64(svc.Snapshot().ApprovedTotal) })
	c.BindCounter("pullthrough_approvals_denied_total",
		"Total quarantine-review requests denied (block confirmed).",
		func() float64 { return float64(svc.Snapshot().DeniedTotal) })
	c.BindCounter("pullthrough_approvals_expired_total",
		"Total break-glass grants and pending reviews that auto-expired.",
		func() float64 { return float64(svc.Snapshot().ExpiredTotal) })
	c.BindCounter("pullthrough_approvals_break_glass_serves_total",
		"Total artifact serves authorized by an active break-glass grant.",
		func() float64 { return float64(svc.Snapshot().BreakGlassServesTotal) })
	c.BindCounter("pullthrough_approvals_time_to_approval_seconds_sum",
		"Cumulative seconds from request creation to grant (divide by _count for the average time-to-approval).",
		func() float64 { return svc.Snapshot().TimeToApprovalSumSeconds })
	c.BindCounter("pullthrough_approvals_time_to_approval_seconds_count",
		"Number of grants contributing to the time-to-approval sum.",
		func() float64 { return float64(svc.Snapshot().TimeToApprovalCount) })
}

// labeledMap converts a {label: value} map into the LabeledValue slice the
// metrics func-vec callbacks expect.
func labeledMap(m map[string]float64) []metrics.LabeledValue {
	out := make([]metrics.LabeledValue, 0, len(m))
	for k, v := range m {
		out = append(out, metrics.LabeledValue{Labels: []string{k}, Value: v})
	}
	return out
}

// bindUpstreamPoolMetrics registers the health-aware upstream router's
// per-endpoint counters, circuit-state gauge, latency, and failover counts
// (Task 38) as scrape-time callbacks reading the manager's live snapshots, so the
// pool's own state remains the single source of truth. Safe to call with a nil
// manager (no mirrored upstreams).
func bindUpstreamPoolMetrics(c *metrics.Collector, mgr *upstreampool.Manager) {
	if mgr == nil || mgr.Len() == 0 {
		return
	}
	// Per-endpoint success/failure/probe counters, labeled by backend + endpoint.
	c.BindCounterVec("pullthrough_upstream_endpoint_requests_total",
		"Upstream requests served by a mirror endpoint that returned a healthy response, by backend and endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return float64(e.TotalSuccess) })
		})
	c.BindCounterVec("pullthrough_upstream_endpoint_failures_total",
		"Upstream requests to a mirror endpoint that failed (transport error or retryable status), by backend and endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return float64(e.TotalFailure) })
		})
	c.BindCounterVec("pullthrough_upstream_endpoint_probes_total",
		"Active health probes issued to a mirror endpoint, by backend and endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return float64(e.TotalProbes) })
		})
	c.BindCounterVec("pullthrough_upstream_endpoint_circuit_trips_total",
		"Times a mirror endpoint's circuit breaker tripped open, by backend and endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return float64(e.TripCount) })
		})
	// Cumulative observed latency (sum + count) per endpoint, so operators can chart
	// average upstream latency per mirror as rate(sum)/rate(count).
	c.BindCounterVec("pullthrough_upstream_endpoint_latency_seconds_sum",
		"Cumulative observed request latency in seconds, by backend and mirror endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return e.LatencySum })
		})
	c.BindCounterVec("pullthrough_upstream_endpoint_latency_seconds_count",
		"Number of latency observations, by backend and mirror endpoint.",
		[]string{"backend", "endpoint"},
		func() []metrics.LabeledValue {
			return endpointValues(mgr, func(e upstreampool.EndpointStatus) float64 { return float64(e.LatencyCount) })
		})
	// Circuit state as a gauge: 0 closed, 1 half-open, 2 open.
	c.Registry().RegisterFuncVec("pullthrough_upstream_circuit_state",
		"Mirror endpoint circuit-breaker state (0 closed, 1 half-open, 2 open), by backend and endpoint.",
		"gauge", []string{"backend", "endpoint"},
		func() []metrics.LabeledValue { return endpointValues(mgr, upstreampool.EndpointStatus.StateValue) })
	// Per-backend failover counter.
	c.BindCounterVec("pullthrough_upstream_failover_total",
		"Times a backend's pull was served by a non-primary mirror after failover, by backend.",
		[]string{"backend"},
		func() []metrics.LabeledValue {
			snaps := mgr.Snapshots()
			out := make([]metrics.LabeledValue, 0, len(snaps))
			for _, s := range snaps {
				out = append(out, metrics.LabeledValue{Labels: []string{s.Backend}, Value: float64(s.FailoverTotal)})
			}
			return out
		})
	// Per-backend count of currently-healthy (not open, not drained) endpoints.
	c.Registry().RegisterFuncVec("pullthrough_upstream_healthy_endpoints",
		"Number of mirror endpoints currently eligible for selection (not open, not drained), by backend.",
		"gauge", []string{"backend"},
		func() []metrics.LabeledValue {
			snaps := mgr.Snapshots()
			out := make([]metrics.LabeledValue, 0, len(snaps))
			for _, s := range snaps {
				out = append(out, metrics.LabeledValue{Labels: []string{s.Backend}, Value: float64(s.Healthy)})
			}
			return out
		})
}

// bindCacheGCMetrics registers the cache lifecycle/GC engine's cumulative
// counters and last-sweep gauges (Task 39) as scrape-time callbacks reading the
// engine's live snapshot, so the engine remains the single source of truth. Safe
// to call with a nil engine (GC disabled or unsupported backend).
func bindCacheGCMetrics(c *metrics.Collector, gc *cachegc.Engine) {
	if gc == nil {
		return
	}
	c.BindCounter("pullthrough_cachegc_runs_total",
		"Total cache garbage-collection sweeps that performed eviction (excludes dry-runs).",
		func() float64 { return float64(gc.Snapshot().Runs) })
	c.BindCounter("pullthrough_cachegc_dry_runs_total",
		"Total cache garbage-collection sweeps run in dry-run (report-only) mode.",
		func() float64 { return float64(gc.Snapshot().DryRuns) })
	c.BindCounter("pullthrough_cachegc_evicted_total",
		"Total cache entries evicted by garbage collection.",
		func() float64 { return float64(gc.Snapshot().EvictedTotal) })
	c.BindCounter("pullthrough_cachegc_expired_evicted_total",
		"Total cache entries evicted specifically because they exceeded their TTL.",
		func() float64 { return float64(gc.Snapshot().ExpiredEvictedTotal) })
	c.BindCounter("pullthrough_cachegc_bytes_reclaimed_total",
		"Total bytes reclaimed by cache garbage collection.",
		func() float64 { return float64(gc.Snapshot().BytesReclaimedTotal) })
	c.BindCounter("pullthrough_cachegc_delete_errors_total",
		"Total cache entry deletions that failed during garbage collection.",
		func() float64 { return float64(gc.Snapshot().DeleteErrorsTotal) })
	c.BindCounter("pullthrough_cachegc_above_high_watermark_total",
		"Total GC sweeps that finished with the cache still at or above the high watermark.",
		func() float64 { return float64(gc.Snapshot().AboveHighWatermark) })
	// Live cache-utilization gauges so operators can chart fill level vs watermark.
	c.BindGauge("pullthrough_cachegc_used_bytes",
		"Cache content size in bytes as of the most recent GC sweep.",
		func() float64 { return float64(gc.Snapshot().UsedBytes) })
	c.BindGauge("pullthrough_cachegc_capacity_bytes",
		"Configured cache capacity in bytes used for watermark math (0 = size eviction disabled).",
		func() float64 { return float64(gc.Snapshot().CapacityBytes) })
	c.BindGauge("pullthrough_cachegc_high_watermark_bytes",
		"High-watermark size in bytes; the cache is reduced toward the low watermark when above it.",
		func() float64 { return float64(gc.Snapshot().HighWatermarkBytes) })
	c.BindGauge("pullthrough_cachegc_low_watermark_bytes",
		"Low-watermark size in bytes; the eviction target.",
		func() float64 { return float64(gc.Snapshot().LowWatermarkBytes) })
	c.BindGauge("pullthrough_cachegc_utilization_ratio",
		"Cache utilization as a fraction of capacity (0..1+) as of the most recent sweep.",
		func() float64 {
			s := gc.Snapshot()
			if s.CapacityBytes <= 0 {
				return 0
			}
			return float64(s.UsedBytes) / float64(s.CapacityBytes)
		})
	c.BindGauge("pullthrough_cachegc_entries",
		"Number of cached entries observed by the most recent GC sweep.",
		func() float64 { return float64(gc.Snapshot().Entries) })
	c.BindGauge("pullthrough_cachegc_last_duration_seconds",
		"Duration in seconds of the most recent GC sweep.",
		func() float64 { return float64(gc.Snapshot().LastDurationMillis) / 1000 })
	c.BindGauge("pullthrough_cachegc_consecutive_above_high_watermark",
		"Number of consecutive GC sweeps that left the cache at or above the high watermark.",
		func() float64 { return float64(gc.Snapshot().ConsecutiveAbove) })
}

// bindBackupMetrics registers the disaster-recovery backup scheduler's
// age/last-success gauges (Task 44) so operators can alert when the last
// successful backup is older than their recovery-point objective (RPO). Safe to
// call with a nil scheduler.
func bindBackupMetrics(c *metrics.Collector, sched *backup.Scheduler) {
	if sched == nil {
		return
	}
	c.BindGauge("pullthrough_backup_last_success_timestamp",
		"Unix timestamp (seconds) of the last successful backup (0 if none).",
		func() float64 {
			t := sched.Status().LastSuccess
			if t.IsZero() {
				return 0
			}
			return float64(t.Unix())
		})
	c.BindGauge("pullthrough_backup_age_seconds",
		"Seconds since the last successful backup (-1 if none has ever succeeded); the primary RPO alerting signal.",
		func() float64 { return sched.Status().AgeSeconds })
	c.BindGauge("pullthrough_backup_last_duration_seconds",
		"Duration in seconds of the most recent backup.",
		func() float64 { return sched.Status().LastDuration.Seconds() })
	c.BindGauge("pullthrough_backup_last_bytes",
		"Total content bytes written by the most recent successful backup.",
		func() float64 { return float64(sched.Status().LastBytes) })
	c.BindCounter("pullthrough_backup_success_total",
		"Total successful backups performed (scheduled and on-demand).",
		func() float64 { return float64(sched.Status().SuccessCount) })
	c.BindCounter("pullthrough_backup_failure_total",
		"Total failed backup attempts.",
		func() float64 { return float64(sched.Status().FailureCount) })
}

// bindCoordinationMetrics registers the HA coordination subsystem's leadership
// gauges and lease counters (Task 56): a per-job leader gauge (1 when this
// replica holds the lease), the current fencing token, accumulated time-as-leader,
// and acquisition/renewal/loss/contention/error counters partitioned by job — so
// operators can confirm exactly one replica leads each scheduled job and alert on
// leadership flapping. Safe with a nil service (coordination disabled).
func bindCoordinationMetrics(c *metrics.Collector, svc *coord.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_coordination_enabled",
		"Whether distributed coordination (leader election) is enabled (1) or in single-node fallback (0).",
		func() float64 {
			if svc.Enabled() {
				return 1
			}
			return 0
		})
	// Per-job leadership and lease state/counters as labeled series.
	jobGauge := func(name, help string, val func(coord.JobStatus) float64) {
		c.Registry().RegisterFuncVec(name, help, "gauge", []string{"job"}, func() []metrics.LabeledValue {
			jobs := svc.Snapshot().Jobs
			out := make([]metrics.LabeledValue, 0, len(jobs))
			for _, j := range jobs {
				out = append(out, metrics.LabeledValue{Labels: []string{j.Job}, Value: val(j)})
			}
			return out
		})
	}
	jobCounter := func(name, help string, val func(coord.JobStatus) float64) {
		c.Registry().RegisterFuncVec(name, help, "counter", []string{"job"}, func() []metrics.LabeledValue {
			jobs := svc.Snapshot().Jobs
			out := make([]metrics.LabeledValue, 0, len(jobs))
			for _, j := range jobs {
				out = append(out, metrics.LabeledValue{Labels: []string{j.Job}, Value: val(j)})
			}
			return out
		})
	}
	jobGauge("pullthrough_coordination_leader",
		"Whether this replica currently holds the named job's lease (1) or not (0).",
		func(j coord.JobStatus) float64 {
			if j.IsLeader {
				return 1
			}
			return 0
		})
	jobGauge("pullthrough_coordination_fencing_token",
		"Fencing token of the lease this replica holds for the job (0 when not leader).",
		func(j coord.JobStatus) float64 { return float64(j.FencingToken) })
	jobCounter("pullthrough_coordination_time_as_leader_seconds_total",
		"Cumulative seconds this replica has held the job's lease.",
		func(j coord.JobStatus) float64 { return j.TimeAsLeaderSeconds })
	jobCounter("pullthrough_coordination_lease_acquisitions_total",
		"Total times this replica acquired (or stole) the job's lease.",
		func(j coord.JobStatus) float64 { return float64(j.Acquisitions) })
	jobCounter("pullthrough_coordination_lease_renewals_total",
		"Total successful lease heartbeat renewals for the job by this replica.",
		func(j coord.JobStatus) float64 { return float64(j.Renewals) })
	jobCounter("pullthrough_coordination_lease_losses_total",
		"Total times this replica lost the job's lease (taken over after a stall/crash).",
		func(j coord.JobStatus) float64 { return float64(j.Losses) })
	jobCounter("pullthrough_coordination_lease_acquire_contended_total",
		"Total acquisition attempts that found the job's lease held by another replica.",
		func(j coord.JobStatus) float64 { return float64(j.AcquireContended) })
	jobCounter("pullthrough_coordination_lease_errors_total",
		"Total coordination-backend errors encountered acquiring/renewing the job's lease.",
		func(j coord.JobStatus) float64 { return float64(j.Errors) })
}

// bindAttestMetrics registers the outbound attestation engine's counters (Task
// 46) as scrape-time callbacks reading the service's live atomics, so operators
// can chart how many served artifacts were attested, how many carried a source
// commit, and alert on signing errors. Safe to call with a nil service (no
// signing key / disabled).
// bindSimReplayMetrics exposes the what-if capture recorder's buffer fill and
// throughput so operators can see how representative the replay corpus is.
func bindSimReplayMetrics(c *metrics.Collector, rec *simreplay.Recorder) {
	if rec == nil {
		return
	}
	c.BindCounter("pullthrough_simreplay_observed_total",
		"Total admission events offered to the what-if capture recorder (pre-sampling).",
		func() float64 { return float64(rec.Status().Observed) })
	c.BindCounter("pullthrough_simreplay_captured_total",
		"Total admission events recorded into the what-if capture buffer (post-sampling).",
		func() float64 { return float64(rec.Status().Captured) })
	c.BindGauge("pullthrough_simreplay_buffered",
		"Number of captured admission events currently retained in the replay ring buffer.",
		func() float64 { return float64(rec.Status().Buffered) })
}

func bindAttestMetrics(c *metrics.Collector, svc *attestbundle.Service) {
	if svc == nil {
		return
	}
	c.BindCounter("pullthrough_attest_bundles_total",
		"Total outbound supply-chain attestation bundles signed for served artifacts.",
		func() float64 { return float64(svc.Snapshot().Produced) })
	c.BindCounter("pullthrough_attest_bundles_with_source_total",
		"Total attestations that bound the served artifact to a source repository/commit.",
		func() float64 { return float64(svc.Snapshot().WithSource) })
	c.BindCounter("pullthrough_attest_bundles_warned_total",
		"Total attestations issued for artifacts admitted with a non-blocking gate warning.",
		func() float64 { return float64(svc.Snapshot().Warned) })
	c.BindCounter("pullthrough_attest_sign_errors_total",
		"Total attestation signing failures (best-effort; never blocks serving).",
		func() float64 { return float64(svc.Snapshot().SignErrors) })
	c.BindGauge("pullthrough_attest_retained_bundles",
		"Number of attestation bundles currently retained for the referrers/export surfaces.",
		func() float64 { return float64(svc.Snapshot().Retained) })
}

// bindRekorMetrics registers the Sigstore Rekor transparency-log counters (Task
// 142), covering both the outbound submit path (attestation engine / self-
// release) and the inbound verify path (signature gate), as scrape-time
// callbacks over the shared rekor.Metrics atomics. Safe to call with a nil
// metrics instance (transparency disabled).
func bindRekorMetrics(c *metrics.Collector, m *rekor.Metrics) {
	if m == nil {
		return
	}
	c.BindCounter("pullthrough_rekor_submissions_total",
		"Total signed attestations successfully submitted to the transparency log.",
		func() float64 { return float64(m.Snapshot().Submissions) })
	c.BindCounter("pullthrough_rekor_submission_errors_total",
		"Total transparency-log submissions that failed (best-effort; never blocks serving).",
		func() float64 { return float64(m.Snapshot().SubmissionErrors) })
	c.BindCounter("pullthrough_rekor_submission_proofs_total",
		"Total submissions whose returned log entry carried a verified inclusion proof.",
		func() float64 { return float64(m.Snapshot().SubmissionProofs) })
	c.BindCounter("pullthrough_rekor_verifications_total",
		"Total inbound transparency-log entries checked (inclusion proof + SET).",
		func() float64 { return float64(m.Snapshot().Verifications) })
	c.BindCounter("pullthrough_rekor_inclusion_verified_total",
		"Total inbound entries with a valid Merkle inclusion proof to a trusted log root.",
		func() float64 { return float64(m.Snapshot().InclusionVerified) })
	c.BindCounter("pullthrough_rekor_set_verified_total",
		"Total inbound entries with a valid Signed Entry Timestamp.",
		func() float64 { return float64(m.Snapshot().SETVerified) })
	c.BindCounter("pullthrough_rekor_verify_failures_total",
		"Total inbound entries that failed a required transparency-log check.",
		func() float64 { return float64(m.Snapshot().VerifyFailures) })
}

// bindKeyRotationMetrics registers the credential & signing-key rotation/expiry
// metrics (Task 148): the per-material pullthrough_key_expiry_seconds gauge (read
// live from the service so it decreases smoothly between scans) plus the
// cumulative scan/rotation counters and current per-band material-count gauges.
// Safe to call with a nil/disabled service (binds nothing).
func bindKeyRotationMetrics(c *metrics.Collector, svc *keyrotation.Service) {
	if svc == nil || !svc.Enabled() {
		return
	}
	c.BindGaugeVec("pullthrough_key_expiry_seconds",
		"Seconds until each monitored signing key / credential / certificate expires (negative when expired).",
		[]string{"key"},
		func() []metrics.LabeledValue {
			secs := svc.ExpirySeconds()
			out := make([]metrics.LabeledValue, 0, len(secs))
			for key, v := range secs {
				out = append(out, metrics.LabeledValue{Labels: []string{key}, Value: v})
			}
			return out
		})
	m := svc.Metrics()
	c.BindCounter("pullthrough_key_rotation_scans_total",
		"Total leader-gated expiry scans completed.",
		func() float64 { return float64(m.Snapshot().Scans) })
	c.BindCounter("pullthrough_key_rotation_source_errors_total",
		"Total material-source scan errors (one unreadable source never fails the scan).",
		func() float64 { return float64(m.Snapshot().SourceErrors) })
	c.BindCounter("pullthrough_key_rotation_warnings_total",
		"Total transitions of a material into the warning expiry band.",
		func() float64 { return float64(m.Snapshot().Warnings) })
	c.BindCounter("pullthrough_key_rotation_criticals_total",
		"Total transitions of a material into the critical expiry band.",
		func() float64 { return float64(m.Snapshot().Criticals) })
	c.BindCounter("pullthrough_key_rotation_expiries_total",
		"Total transitions of a material into the expired band.",
		func() float64 { return float64(m.Snapshot().Expiries) })
	c.BindCounter("pullthrough_key_rotation_rotations_total",
		"Total successful in-place key/credential rotations driven by the subsystem.",
		func() float64 { return float64(m.Snapshot().Rotations) })
	c.BindCounter("pullthrough_key_rotation_rotation_failures_total",
		"Total failed in-place key/credential rotation attempts.",
		func() float64 { return float64(m.Snapshot().RotationFailures) })
	c.BindGauge("pullthrough_key_rotation_warning_materials",
		"Monitored material currently within the warning expiry band.",
		func() float64 { return float64(m.Snapshot().WarningMaterials) })
	c.BindGauge("pullthrough_key_rotation_critical_materials",
		"Monitored material currently within the critical expiry band.",
		func() float64 { return float64(m.Snapshot().CriticalMaterials) })
	c.BindGauge("pullthrough_key_rotation_expired_materials",
		"Monitored material currently past its expiry.",
		func() float64 { return float64(m.Snapshot().ExpiredMaterials) })
}

// bindCacheFedMetrics registers the cross-proxy cache-federation counters (Task
// 143) as scrape-time callbacks over the subsystem's shared atomics, plus
// per-peer latency and circuit-state series read from the live peer registry.
// Safe to call with a nil/disabled federation (binds nothing).
func bindCacheFedMetrics(c *metrics.Collector, f *cachefed.Federation) {
	if !f.Enabled() {
		return
	}
	m := f.Metrics()
	c.BindCounter("pullthrough_cachefed_hits_total",
		"Total local cache misses satisfied by a sibling peer (digest re-verified on receipt).",
		func() float64 { return float64(m.Snapshot().Hits) })
	c.BindCounter("pullthrough_cachefed_misses_total",
		"Total local cache misses no healthy peer could satisfy (fell through to the upstream).",
		func() float64 { return float64(m.Snapshot().Misses) })
	c.BindCounter("pullthrough_cachefed_peer_errors_total",
		"Total peer read-through requests that failed (network / non-200 / timeout).",
		func() float64 { return float64(m.Snapshot().PeerErrors) })
	c.BindCounter("pullthrough_cachefed_verify_failures_total",
		"Total peer responses rejected because the bytes failed content-digest re-verification.",
		func() float64 { return float64(m.Snapshot().VerifyFailures) })
	c.BindCounter("pullthrough_cachefed_skipped_no_digest_total",
		"Total misses not offered to peers because no expected digest was available to re-verify against.",
		func() float64 { return float64(m.Snapshot().SkippedNoDigest) })
	c.BindCounter("pullthrough_cachefed_served_total",
		"Total sibling peer requests answered from this instance's local cache.",
		func() float64 { return float64(m.Snapshot().Served) })
	c.BindCounter("pullthrough_cachefed_served_misses_total",
		"Total sibling peer requests for a key this instance did not hold.",
		func() float64 { return float64(m.Snapshot().ServedMisses) })
	c.BindCounter("pullthrough_cachefed_unauthorized_total",
		"Total sibling peer requests rejected for a missing or invalid auth token.",
		func() float64 { return float64(m.Snapshot().Unauthorized) })

	c.BindCounterVec("pullthrough_cachefed_peer_requests_total",
		"Total read-through requests to each peer, partitioned by outcome.",
		[]string{"peer", "outcome"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, p := range f.PeerStatuses() {
				out = append(out,
					metrics.LabeledValue{Labels: []string{p.Name, "success"}, Value: float64(p.TotalSuccess)},
					metrics.LabeledValue{Labels: []string{p.Name, "failure"}, Value: float64(p.TotalFailure)},
				)
			}
			return out
		})
	c.BindCounterVec("pullthrough_cachefed_peer_latency_seconds_sum",
		"Cumulative read-through latency per peer; divide by the _count series for a mean.",
		[]string{"peer"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, p := range f.PeerStatuses() {
				out = append(out, metrics.LabeledValue{Labels: []string{p.Name}, Value: p.LatencySum})
			}
			return out
		})
	c.BindCounterVec("pullthrough_cachefed_peer_latency_seconds_count",
		"Number of read-through latency samples recorded per peer.",
		[]string{"peer"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, p := range f.PeerStatuses() {
				out = append(out, metrics.LabeledValue{Labels: []string{p.Name}, Value: float64(p.LatencyCount)})
			}
			return out
		})
	c.BindGaugeVec("pullthrough_cachefed_peer_circuit_state",
		"Per-peer circuit-breaker state (0=closed, 1=half-open, 2=open).",
		[]string{"peer"},
		func() []metrics.LabeledValue {
			var out []metrics.LabeledValue
			for _, p := range f.PeerStatuses() {
				out = append(out, metrics.LabeledValue{Labels: []string{p.Name}, Value: cacheFedStateValue(p.State)})
			}
			return out
		})
}

// cacheFedStateValue maps a peer circuit-state label to its numeric gauge value,
// matching the upstream-pool convention (closed=0, half-open=1, open=2).
func cacheFedStateValue(state string) float64 {
	switch state {
	case "half_open":
		return 1
	case "open":
		return 2
	default:
		return 0
	}
}

// bindTracingMetrics registers the distributed-tracing exporter's counters
// (Task 41) as scrape-time callbacks reading the provider's live atomics, so
// operators can alert on dropped spans (queue saturation) or a failing OTLP
// collector. Safe to call with a nil provider (tracing disabled).
func bindTracingMetrics(c *metrics.Collector, p *tracing.Provider) {
	if p == nil {
		return
	}
	c.BindCounter("pullthrough_tracing_spans_started_total",
		"Total spans started by the tracer (sampled and unsampled).",
		func() float64 { return float64(p.Metrics().SpansStarted) })
	c.BindCounter("pullthrough_tracing_spans_sampled_total",
		"Total spans that passed sampling and are recorded for export.",
		func() float64 { return float64(p.Metrics().SpansSampled) })
	c.BindCounter("pullthrough_tracing_spans_exported_total",
		"Total spans successfully exported to the OTLP collector.",
		func() float64 { return float64(p.Metrics().SpansExported) })
	c.BindCounter("pullthrough_tracing_spans_dropped_total",
		"Total sampled spans dropped because the export queue was full (collector too slow/unreachable).",
		func() float64 { return float64(p.Metrics().SpansDropped) })
	c.BindCounter("pullthrough_tracing_export_batches_total",
		"Total OTLP export requests attempted.",
		func() float64 { return float64(p.Metrics().ExportBatches) })
	c.BindCounter("pullthrough_tracing_export_errors_total",
		"Total OTLP export requests that failed (transport error or non-2xx response).",
		func() float64 { return float64(p.Metrics().ExportErrors) })
	c.BindGauge("pullthrough_tracing_queue_depth",
		"Number of finished spans currently waiting in the export queue.",
		func() float64 { return float64(p.Metrics().QueueDepth) })
}

// bindOTLPLogsMetrics registers the OTLP structured-log export counters (Task
// 160) as scrape-time callbacks reading the pipeline's live metrics snapshot. A
// nil (disabled) pipeline registers nothing.
func bindOTLPLogsMetrics(c *metrics.Collector, p *otlplog.Pipeline) {
	if p == nil {
		return
	}
	c.BindGauge("pullthrough_otlp_logs_queue_depth",
		"Number of log records currently waiting in the in-memory OTLP export queue.",
		func() float64 { return float64(p.Metrics().QueueDepth) })
	c.BindGauge("pullthrough_otlp_logs_spill_depth",
		"Number of log records currently buffered in the on-disk OTLP spill queue.",
		func() float64 { return float64(p.Metrics().SpillDepth) })
	c.BindCounter("pullthrough_otlp_logs_enqueued_total",
		"Total log records accepted onto the OTLP export queue.",
		func() float64 { return float64(p.Metrics().Enqueued) })
	c.BindCounter("pullthrough_otlp_logs_delivered_total",
		"Total log records successfully exported to the OTLP collector.",
		func() float64 { return float64(p.Metrics().Delivered) })
	c.BindCounter("pullthrough_otlp_logs_spilled_total",
		"Total log records written to the on-disk spill queue on in-memory overflow.",
		func() float64 { return float64(p.Metrics().Spilled) })
	c.BindCounter("pullthrough_otlp_logs_dropped_total",
		"Total log records dropped because both the in-memory and spill queues were full.",
		func() float64 { return float64(p.Metrics().Dropped) })
	c.BindCounter("pullthrough_otlp_logs_failed_total",
		"Total log records that failed export after exhausting retries.",
		func() float64 { return float64(p.Metrics().Failed) })
	c.BindCounter("pullthrough_otlp_logs_retries_total",
		"Total OTLP log batch-export retry attempts.",
		func() float64 { return float64(p.Metrics().Retries) })
	c.BindCounter("pullthrough_otlp_logs_batches_total",
		"Total OTLP log batches attempted.",
		func() float64 { return float64(p.Metrics().Batches) })
}

// endpointValues projects one field of every endpoint across every pool into the
// labeled (backend, endpoint) samples the metrics bridge expects.
func endpointValues(mgr *upstreampool.Manager, pick func(upstreampool.EndpointStatus) float64) []metrics.LabeledValue {
	snaps := mgr.Snapshots()
	out := make([]metrics.LabeledValue, 0, len(snaps)*2)
	for _, s := range snaps {
		for _, e := range s.Endpoints {
			out = append(out, metrics.LabeledValue{Labels: []string{s.Backend, e.ID}, Value: pick(e)})
		}
	}
	return out
}

// notifyValues projects one field of every sink's metrics into the labeled
// samples the metrics bridge expects.
func notifyValues(n *notify.Notifier, pick func(notify.SinkMetrics) float64) []metrics.LabeledValue {
	snap := n.Metrics()
	out := make([]metrics.LabeledValue, 0, len(snap.PerSink))
	for sink, m := range snap.PerSink {
		out = append(out, metrics.LabeledValue{Labels: []string{sink}, Value: pick(m)})
	}
	return out
}

// newDossierBuilder assembles the per-coordinate security dossier builder (Task
// 87) over whichever subsystems are wired. Each provider is assigned only when
// its concrete service is non-nil so a disabled subsystem contributes an absent
// section (and a typed-nil never masquerades as a live provider). The admin "360
// view" and the admission webhook's in-process verdict source (Task 111) share
// this builder.
func newDossierBuilder(
	findingsStore *findings.Store,
	riskEngine *riskscore.Engine,
	vulnService *vulnscan.Service,
	sigVerify *sigverify.Service,
	buildProvSvc *buildprov.Service,
	pypiAttestSvc *pypiattest.Service,
	provGraph *provgraph.Service,
	rebuildVerifySvc *rebuildverify.Service,
	sbomDiffSvc *sbomdiff.Service,
	approvalsSvc *approvals.Service,
	attestor *attestbundle.Service,
	timelineEngine *timeline.Engine,
	remediationSvc *remediation.Service,
	suppressionLedger *findings.SuppressionLedger,
	llmPkgScanSvc *llmpkgscan.Service,
) *dossier.Builder {
	dp := dossier.Providers{}
	if findingsStore != nil {
		dp.Findings = findingsStore
	}
	if suppressionLedger != nil {
		dp.Suppressions = suppressionLedger
	}
	if riskEngine != nil {
		dp.Risk = riskEngine
	}
	if vulnService != nil {
		dp.Vuln = vulnService
	}
	if sigVerify != nil {
		dp.Sigverify = sigVerify
	}
	if buildProvSvc != nil {
		dp.BuildProv = buildProvSvc
	}
	if pypiAttestSvc != nil {
		dp.PyPIAttest = pypiAttestSvc
	}
	if provGraph != nil {
		dp.Provgraph = provGraph
	}
	if rebuildVerifySvc != nil {
		dp.Rebuild = rebuildVerifySvc
	}
	if sbomDiffSvc != nil {
		dp.SbomDrift = sbomDiffSvc
	}
	if approvalsSvc != nil {
		dp.Approvals = approvalsSvc
	}
	if attestor != nil {
		dp.Attest = attestor
	}
	if timelineEngine != nil {
		dp.Timeline = timelineEngine
	}
	if remediationSvc != nil {
		dp.Remediation = remediationSvc
	}
	if llmPkgScanSvc != nil {
		dp.LLMPackageScan = llmPkgScanSvc
	}
	return dossier.New(dossier.Config{}, dp)
}

// buildAdminServer wires the admin API/dashboard against whatever subsystems are
// present. The cache inspector is required; the scan, provenance, vulnerability,
// notification, and backend surfaces are attached when available and the
// dashboard degrades gracefully without them.
func buildAdminServer(
	cfg *config.Config,
	configSvc *config.Service,
	registry *backends.Registry,
	cacheImpl cache.Cache,
	commitScanner *commit.Scanner,
	provService *provenance.Service,
	provResolver provenance.Resolver,
	vulnService *vulnscan.Service,
	sigVerify *sigverify.Service,
	licenseService *license.Service,
	pacEngine *policyengine.Engine,
	rescanner *vulnscan.Rescanner,
	notifier *notify.Notifier,
	rateLimiter *ratelimit.Limiter,
	auditLog *audit.Logger,
	provGraph *provgraph.Service,
	coalescer *coalesce.Coalescer[*cache.Entry],
	complianceSvc *compliance.Service,
	riskEngine *riskscore.Engine,
	repoScoreSvc *reposcore.Service,
	sbomDiffSvc *sbomdiff.Service,
	rebuildVerifySvc *rebuildverify.Service,
	buildProvSvc *buildprov.Service,
	pypiAttestSvc *pypiattest.Service,
	extManager *extension.Manager,
	anomalyEngine *anomaly.Engine,
	approvalsSvc *approvals.Service,
	malfeedSvc *malfeed.Service,
	maturitySvc *maturity.Service,
	continuitySvc *continuity.Service,
	depFirewallSvc *depfirewall.Service,
	installHooksSvc *installhooks.Service,
	avScanSvc *avscan.Service,
	contentScanSvc *contentscan.Service,
	llmPkgScanSvc *llmpkgscan.Service,
	poolMgr *upstreampool.Manager,
	egressGuard *egress.Guard,
	cacheGC *cachegc.Engine,
	backupScheduler *backup.Scheduler,
	findingsStore *findings.Store,
	suppressionLedger *findings.SuppressionLedger,
	simReplayRecorder *simreplay.Recorder,
	attestor *attestbundle.Service,
	snapshotSvc *snapshot.Service,
	lockdownSvc *lockdown.Service,
	gitopsSvc *gitops.Service,
	prewarmSvc *prewarm.Service,
	sbomExporter *sbomexport.Service,
	tracerProvider *tracing.Provider,
	coordSvc *coord.Service,
	secopsHub *secops.Hub,
	keyRotationSvc *keyrotation.Service,
	webAuthnSvc *webauthn.Service,
	queryEngine *queryapi.Engine,
	timelineEngine *timeline.Engine,
	mcpSrv *mcpserver.Server,
	grpcSrv *grpcapi.Server,
	meter *metering.Meter,
	adminAuthSvc *adminauth.Service,
	vexExporter *vexexport.Service,
	logger *slog.Logger,
) (*admin.Server, error) {
	opts := admin.Options{
		Logger:     logger,
		PathPrefix: cfg.Observability.AdminPrefixOrDefault(),
		Token:      cfg.Observability.AdminToken,
		Backends:   registry,
		Info:       adminInfo(cfg),
	}
	if cfg.Observability.Profiling {
		opts.Profiling = admin.ProfilingOptions{
			Enabled:              true,
			BlockProfileRate:     cfg.Observability.ProfilingBlockRate,
			MutexProfileFraction: cfg.Observability.ProfilingMutexFraction,
		}
	}
	if configSvc != nil {
		opts.Config = configSvc
		// Curated compliance presets (Task 88) dry-run against the running config
		// and apply by patching the on-disk file the config service tracks.
		opts.Presets = presets.NewManager(configSvc.Path(), cfg)
	}
	if adminAuthSvc != nil {
		opts.AdminAuth = adminAuthSvc
		if auditLog != nil {
			opts.AuditLog = auditLog
		}
	}
	// WebAuthn/passkey step-up (Task 161). Enforcement binds each ceremony to a
	// real identity, so it presupposes the admin SSO/RBAC layer; when no AdminAuth
	// is configured the ceremonies are still served (and credentials stored) but
	// the middleware cannot attribute a step-up to a subject, so a warning is
	// logged. The subsystem is wired regardless so metrics/status are available.
	if webAuthnSvc != nil && webAuthnSvc.Enabled() {
		opts.WebAuthn = webAuthnSvc
		if adminAuthSvc == nil && webAuthnSvc.Enforcing() {
			logger.Warn("webauthn step-up enforcement requires admin SSO/RBAC (adminAuth); without it protected endpoints cannot bind a step-up to an identity")
		}
	}
	if rateLimiter != nil {
		opts.RateLimit = rateLimiter
	}
	if auditLog != nil {
		opts.Audit = auditLog
	}
	if ci, ok := cacheImpl.(admin.CacheInspector); ok {
		opts.Cache = ci
	}
	if cms, ok := cacheImpl.(admin.CacheMetricsSource); ok {
		opts.CacheMetrics = cms
	}
	if commitScanner != nil {
		opts.Scan = commitScanner
		opts.CommitScan = commitScanner
	}
	if vulnService != nil {
		opts.Vulnerabilities = vulnService
	}
	if sigVerify != nil {
		opts.Sigverify = sigVerify
	}
	if licenseService != nil {
		opts.License = licenseService
	}
	if pacEngine != nil {
		opts.PolicyEngine = pacEngine
	}
	if rescanner != nil {
		opts.Rescan = rescanner
	}
	// Surface the Notify admin tab only when external delivery is configured; a
	// headless notifier (built so the SecOps feed still sees events when
	// notifications are disabled) has no sinks and should read as disabled there.
	if notifier != nil && cfg.Notifications.Enabled {
		opts.Notify = notifier
	}
	if provResolver != nil {
		opts.Provenance = provResolver
	}
	if provService != nil {
		opts.ProvenanceLinks = provService
	}
	if provGraph != nil {
		opts.Provgraph = provGraph
	}
	if coalescer != nil {
		opts.Coalesce = coalescer
	}
	if complianceSvc != nil {
		opts.Compliance = complianceSvc
	}
	if riskEngine != nil {
		opts.RiskScore = riskEngine
	}
	if repoScoreSvc != nil {
		opts.RepoScore = repoScoreSvc
	}
	if sbomDiffSvc != nil {
		opts.SbomDiff = sbomDiffSvc
	}
	remediationSvc := buildRemediation(cfg, vulnService, licenseService, maturitySvc, depFirewallSvc)
	if remediationSvc.Enabled() {
		opts.Remediation = remediationSvc
	}
	if rebuildVerifySvc != nil {
		opts.RebuildVerify = rebuildVerifySvc
	}
	if buildProvSvc != nil {
		opts.BuildProv = buildProvSvc
	}
	if extManager != nil {
		opts.Extension = extManager
	}
	if anomalyEngine != nil {
		opts.Anomaly = anomalyEngine
	}
	if approvalsSvc != nil {
		opts.Approvals = approvalsSvc
	}
	if malfeedSvc != nil {
		opts.Malfeed = malfeedSvc
	}
	if maturitySvc != nil {
		opts.Maturity = maturitySvc
	}
	if continuitySvc != nil {
		opts.Continuity = continuitySvc
	}
	if depFirewallSvc != nil {
		opts.DepFirewall = depFirewallSvc
	}
	if snapshotSvc != nil {
		opts.Snapshot = snapshotSvc
	}
	if lockdownSvc != nil {
		opts.Lockdown = lockdownSvc
	}
	if gitopsSvc != nil {
		opts.Gitops = gitopsSvc
	}
	if prewarmSvc != nil {
		opts.Prewarm = prewarmSvc
	}
	if sbomExporter != nil {
		opts.SBOMExport = sbomExporter
	}
	if installHooksSvc != nil {
		opts.InstallHooks = installHooksSvc
	}
	if avScanSvc != nil {
		opts.AVScan = avScanSvc
	}
	if contentScanSvc != nil {
		opts.ContentScan = contentScanSvc
	}
	if llmPkgScanSvc != nil {
		opts.LLMPkgScan = llmPkgScanSvc
	}
	if poolMgr != nil && poolMgr.Len() > 0 {
		opts.UpstreamPool = poolMgr
	}
	if egressGuard.Enabled() {
		opts.Egress = egressGuard
	}
	if cacheGC != nil {
		opts.CacheGC = cacheGC
	}
	// Read-time cache integrity verification + admin-triggered scan (Task 107).
	// The cache.IntegrityCache wrapper (outermost) satisfies the inspector.
	if ic, ok := cacheImpl.(*cache.IntegrityCache); ok {
		opts.Integrity = ic
		opts.CacheIntegrityVerifyOnServe = cfg.Cache.Integrity.VerifyOnServe
	}
	// Transparent storage-efficiency layer stats (Task 125). Any cache that
	// forwards CompactionStats (the integrity/sealed wrappers over a compacting
	// store) satisfies the inspector.
	if cs, ok := cacheImpl.(admin.CompactionInspector); ok {
		opts.Compaction = cs
	}
	// At-rest encryption envelope status + KEK rotation (Task 141). Any cache that
	// forwards EncryptionStats/RotateKEK (the integrity/sealed wrappers over an
	// encrypting store) satisfies the inspector; it reports Enabled=false when no
	// encryption layer is present.
	if ei, ok := cacheImpl.(admin.EncryptionInspector); ok {
		opts.Encryption = ei
	}
	// Hot/cold tiered storage status + on-demand demotion sweep (Task 154). The
	// tiered store is reached through the decorator unwrap chain; absent when no
	// tiering layer is composed into the cache stack.
	if ts, ok := cache.TieredStoreOf(cacheImpl); ok {
		opts.Tiering = ts
	}
	if backupScheduler != nil {
		opts.Backup = backupScheduler
	}
	if tracerProvider != nil {
		opts.Tracing = tracingInspector{
			provider: tracerProvider,
			endpoint: cfg.Tracing.Endpoint,
			ratio:    cfg.Tracing.SamplerRatio,
		}
	}
	if findingsStore != nil {
		opts.Findings = findingsInspector{store: findingsStore, version: version}
	}
	if simReplayRecorder != nil {
		opts.SimReplay = simReplayRecorder
	}
	if attestor != nil {
		opts.Attest = attestInspector{svc: attestor}
	}
	if coordSvc != nil && coordSvc.Enabled() {
		opts.Coordination = coordSvc
	}
	if secopsHub != nil {
		opts.SecOps = secopsHub
	}
	if keyRotationSvc != nil {
		opts.KeyRotation = keyRotationSvc
	}
	if queryEngine != nil {
		opts.QueryAPI = queryEngine
	}
	if timelineEngine != nil {
		opts.Timeline = timelineEngine
	}
	// The per-coordinate security dossier (Task 87) is always constructed: it
	// fans out across whichever subsystems are wired and degrades to partial
	// results for the rest. The same builder backs the admission webhook's
	// in-process verdict source (Task 111).
	opts.Dossier = newDossierBuilder(findingsStore, riskEngine, vulnService, sigVerify, buildProvSvc, pypiAttestSvc, provGraph, rebuildVerifySvc, sbomDiffSvc, approvalsSvc, attestor, timelineEngine, remediationSvc, suppressionLedger, llmPkgScanSvc)
	if mcpSrv.Enabled() {
		opts.MCP = mcpSrv
	}
	if grpcSrv.Enabled() {
		opts.GRPC = grpcSrv
	}
	if meter.Enabled() {
		opts.Metering = meter
	}
	// Outbound VEX authoring (Task 137): the service is built once in
	// buildObservability so the metrics bridge and this endpoint share it.
	if vexExporter != nil {
		opts.VEXExport = vexExporter
	}
	return admin.New(opts)
}

// adminInfo assembles the static configuration/policy snapshot the admin surface
// presents to operators.
func adminInfo(cfg *config.Config) admin.Info {
	info := admin.Info{
		Version:                   version,
		CacheBackend:              cfg.Cache.Backend,
		CacheSealed:               cfg.Cache.Sealed,
		ScanningEnabled:           cfg.Scanning.Enabled,
		ScanProvider:              cfg.Scanning.Provider,
		ScanFailOn:                cfg.Scanning.FailOn,
		ProvenanceEnabled:         cfg.Provenance.Enabled,
		ProvenanceRequireAttested: cfg.Provenance.RequireAttested,
		VulnEnabled:               cfg.Vulnerabilities.Enabled,
		VulnScanner:               cfg.Vulnerabilities.Scanner,
		VulnAction:                cfg.Vulnerabilities.Action,
		VulnFailSeverity:          cfg.Vulnerabilities.FailSeverity,
		LicenseEnabled:            cfg.License.Enabled,
		LicenseAction:             cfg.License.Policy.Action,
	}
	fipsMode := fips.Detect(cfg.FIPS.Enabled, cfg.FIPS.RequireModuleOrDefault())
	module := ""
	if fipsMode.ModuleActive {
		module = strings.TrimSpace(fips.ModuleName + " " + fipsMode.ModuleVersion)
	}
	info.Crypto = admin.CryptoInfo{
		Mode:           fipsMode.CryptoModeLabel(),
		FIPSEnabled:    fipsMode.Enabled,
		ModuleActive:   fipsMode.ModuleActive,
		ModuleEnforced: fipsMode.ModuleEnforced,
		Module:         module,
		BuildVariant:   fipsMode.BuildVariant,
	}
	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() {
			continue
		}
		info.Upstreams = append(info.Upstreams, admin.UpstreamInfo{
			Name: name,
			Type: up.Type,
			URL:  up.URL,
		})
	}
	return info
}

// buildAdminAuth constructs the admin SSO/RBAC service (Task 51) from config. It
// returns (nil, nil) when adminAuth is disabled. When OIDC is enabled it may
// perform discovery against the IdP, so an unreachable IdP yields an error the
// caller logs (degrading to the legacy token) rather than crashing.
func buildAdminAuth(cfg *config.Config, logger *slog.Logger) (*adminauth.Service, error) {
	ac := cfg.AdminAuth
	if !ac.Enabled {
		return nil, nil
	}
	opts := adminauth.Options{
		Prefix:        cfg.Observability.AdminPrefixOrDefault(),
		SessionKey:    []byte(ac.SessionKey),
		SessionTTL:    ac.SessionTTL,
		CookieName:    ac.CookieName,
		SecureCookies: !ac.InsecureCookies,
		RoleBindings:  ac.RoleBindings,
		DefaultRole:   ac.DefaultRole,
		Logger:        logger,
	}
	// When the self-service portal is enabled it is mounted on a separate path
	// from the admin surface, so broaden the SSO session cookie to the site root
	// so one login works for both. The cookie remains HttpOnly + signed.
	if cfg.Observability.Portal {
		opts.CookiePath = "/"
	}
	if ac.AllowLegacyToken == nil || *ac.AllowLegacyToken {
		opts.LegacyAdminToken = cfg.Observability.AdminToken
	}
	for _, t := range ac.StaticTokens {
		opts.StaticTokens = append(opts.StaticTokens, adminauth.StaticToken{
			Name:   t.Name,
			Tenant: t.Tenant,
			Roles:  t.Roles,
			Secret: t.Token,
			Hash:   t.TokenHash,
		})
	}
	if ac.OIDC.Enabled {
		o := ac.OIDC
		opts.OIDC = &adminauth.OIDCConfig{
			Issuer:                o.Issuer,
			ClientID:              o.ClientID,
			ClientSecret:          o.ClientSecret,
			RedirectURL:           o.RedirectURL,
			Scopes:                o.Scopes,
			Audience:              o.Audience,
			DiscoveryURL:          o.DiscoveryURL,
			AuthorizationEndpoint: o.AuthorizationEndpoint,
			TokenEndpoint:         o.TokenEndpoint,
			EndSessionEndpoint:    o.EndSessionEndpoint,
			JWKSURL:               o.JWKSURL,
			JWKS:                  o.JWKS,
			SubjectClaim:          o.SubjectClaim,
			GroupsClaim:           o.GroupsClaim,
			TenantClaim:           o.TenantClaim,
			JWKSCacheTTL:          o.JWKSCacheTTL,
			Leeway:                o.Leeway,
		}
	}
	return adminauth.New(opts)
}

// bindAdminAuthMetrics surfaces the admin SSO/RBAC subsystem's authentication and
// authorization counters (Task 51) as scrape-time callbacks reading the service's
// own atomics, so operators can chart admin auth successes/failures by role and
// alert on a spike of denials. Safe to call with a nil service (disabled).
func bindAdminAuthMetrics(c *metrics.Collector, svc *adminauth.Service) {
	if svc == nil || svc.Metrics() == nil {
		return
	}
	m := svc.Metrics()
	labeled := func(metric, help, typ, label string, pick func(adminauth.Snapshot) map[string]uint64) {
		c.Registry().RegisterFuncVec(metric, help, typ, []string{label}, func() []metrics.LabeledValue {
			snap := pick(m.Snapshot())
			out := make([]metrics.LabeledValue, 0, len(snap))
			for k, v := range snap {
				out = append(out, metrics.LabeledValue{Labels: []string{k}, Value: float64(v)})
			}
			return out
		})
	}
	labeled("pullthrough_adminauth_auth_success_total",
		"Admin authentications that succeeded, by granted role.", "counter", "role",
		func(s adminauth.Snapshot) map[string]uint64 { return s.AuthSuccessByRole })
	labeled("pullthrough_adminauth_auth_success_by_method_total",
		"Admin authentications that succeeded, by authentication method.", "counter", "method",
		func(s adminauth.Snapshot) map[string]uint64 { return s.AuthSuccessByMethod })
	labeled("pullthrough_adminauth_auth_failure_total",
		"Admin authentication failures, by reason.", "counter", "reason",
		func(s adminauth.Snapshot) map[string]uint64 { return s.AuthFailureByReason })
	labeled("pullthrough_adminauth_authz_allowed_total",
		"Admin authorization decisions that allowed the request, by required capability.", "counter", "capability",
		func(s adminauth.Snapshot) map[string]uint64 { return s.AuthzAllowByCap })
	labeled("pullthrough_adminauth_authz_denied_total",
		"Admin authorization decisions that denied the request, by required capability.", "counter", "capability",
		func(s adminauth.Snapshot) map[string]uint64 { return s.AuthzDenyByCap })
	c.BindCounter("pullthrough_adminauth_logins_total",
		"Successful OIDC SSO logins completed.",
		func() float64 { return float64(m.Snapshot().Logins) })
	c.BindCounter("pullthrough_adminauth_login_failures_total",
		"OIDC SSO login attempts that failed (state/exchange/token/role errors).",
		func() float64 { return float64(m.Snapshot().LoginFailures) })
	c.BindCounter("pullthrough_adminauth_logouts_total",
		"Admin SSO logouts performed.",
		func() float64 { return float64(m.Snapshot().Logouts) })
}

// bindClientMTLSMetrics registers the SPIFFE/mTLS workload-identity auth metrics
// (Task 58) as scrape-time callbacks reading the authenticator's accumulator:
// auth success/failure by method/reason, the soonest client-certificate expiry,
// the count of certs expiring within the warning window, and the trust-bundle
// root expiry. Safe to call with a nil clientMTLS (disabled).
func bindClientMTLSMetrics(c *metrics.Collector, m *clientMTLS) {
	if m == nil || m.metricsOrNil() == nil {
		return
	}
	metricsAcc := m.metricsOrNil()
	warn := m.expiryWarning
	source := m.source

	c.Registry().RegisterFuncVec("pullthrough_clientauth_mtls_success_total",
		"SPIFFE/mTLS client authentications that succeeded, by method.", "counter", []string{"method"},
		func() []metrics.LabeledValue {
			return []metrics.LabeledValue{{Labels: []string{"mtls"}, Value: float64(metricsAcc.Snapshot(warn).Success)}}
		})
	c.Registry().RegisterFuncVec("pullthrough_clientauth_mtls_failure_total",
		"SPIFFE/mTLS client authentication failures, by reason.", "counter", []string{"reason"},
		func() []metrics.LabeledValue {
			snap := metricsAcc.Snapshot(warn)
			out := make([]metrics.LabeledValue, 0, len(snap.FailuresByReason))
			for reason, v := range snap.FailuresByReason {
				out = append(out, metrics.LabeledValue{Labels: []string{reason}, Value: float64(v)})
			}
			return out
		})
	c.BindGauge("pullthrough_clientauth_cert_expiry_seconds",
		"Seconds until the soonest-expiring recently-verified mTLS client certificate expires (0 if none observed).",
		func() float64 { return metricsAcc.Snapshot(warn).SoonestCertExpirySeconds })
	c.BindGauge("pullthrough_clientauth_certs_expiring_soon",
		"Distinct workload identities whose last-seen client certificate expires within the configured warning window.",
		func() float64 { return float64(metricsAcc.Snapshot(warn).CertsExpiringSoon) })
	c.BindGauge("pullthrough_clientauth_trust_bundle_reloads_total",
		"Number of times the SPIFFE trust bundle has been (re)loaded.",
		func() float64 { return float64(source.Stats().Reloads) })
	c.BindGauge("pullthrough_clientauth_trust_bundle_expiry_seconds",
		"Seconds until the soonest-expiring SPIFFE trust-bundle root certificate expires (0 if unknown).",
		func() float64 {
			soonest := source.Stats().SoonestRoot
			if soonest.IsZero() {
				return 0
			}
			secs := time.Until(soonest).Seconds()
			if secs < 0 {
				secs = 0
			}
			return secs
		})
}

// bindSecOpsMetrics surfaces the Security Operations dashboard's own telemetry
// (Task 60) as scrape-time callbacks reading the Hub's cumulative counters: the
// number of notable events folded into the read-model, dashboard-query volume
// (summary fetches and stream connections), dropped stream events (a slow-client
// signal), and the current number of live SSE subscribers. Safe to call with a
// nil Hub (the metrics are simply absent).
func bindSecOpsMetrics(c *metrics.Collector, h *secops.Hub) {
	if h == nil {
		return
	}
	c.BindCounter("pullthrough_secops_events_observed_total",
		"Total notable security events folded into the SecOps dashboard read-model.",
		func() float64 { return float64(h.MetricsSnapshot().EventsObserved) })
	c.BindCounter("pullthrough_secops_summary_queries_total",
		"Total SecOps dashboard posture-summary queries served.",
		func() float64 { return float64(h.MetricsSnapshot().SummaryQueries) })
	c.BindCounter("pullthrough_secops_stream_connections_total",
		"Total SecOps dashboard live-event (SSE) stream connections opened.",
		func() float64 { return float64(h.MetricsSnapshot().StreamOpened) })
	c.BindCounter("pullthrough_secops_stream_dropped_total",
		"Total SecOps live-stream events dropped because a subscriber fell behind (best-effort feed; no backpressure on the request path).",
		func() float64 { return float64(h.MetricsSnapshot().StreamDropped) })
	c.BindGauge("pullthrough_secops_active_streams",
		"Number of SecOps dashboard live-event streams currently connected.",
		func() float64 { return float64(h.MetricsSnapshot().ActiveStreams) })
}

// meteringBudgets converts the per-tenant budget config (Task 84) into the
// metering package's budget type.
func meteringBudgets(in map[string]config.MeteringBudget) map[string]metering.Budget {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]metering.Budget, len(in))
	for tenant, b := range in {
		out[tenant] = metering.Budget{MaxBytes: b.MaxBytes, MaxScanCostMicros: b.MaxScanCostMicros}
	}
	return out
}

// bindMeteringMetrics surfaces the per-tenant usage-metering counters (Task 84)
// as labeled scrape-time callbacks reading the meter's cumulative snapshot, plus
// the subsystem's own rollup/budget-alert telemetry. Safe to call with a nil or
// disabled meter (the metrics are simply absent).
func bindMeteringMetrics(c *metrics.Collector, m *metering.Meter) {
	if m == nil || !m.Enabled() {
		return
	}
	tenantSeries := func(pick func(metering.TenantMetric) float64) func() []metrics.LabeledValue {
		return func() []metrics.LabeledValue {
			snap := m.MetricsSnapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.Tenants))
			for _, t := range snap.Tenants {
				out = append(out, metrics.LabeledValue{Labels: []string{t.Tenant}, Value: pick(t)})
			}
			return out
		}
	}
	c.BindCounterVec("pullthrough_metering_requests_total",
		"Total backend requests metered per tenant.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.Requests) }))
	c.BindCounterVec("pullthrough_metering_served_bytes_cache_hit_total",
		"Total bytes served to a tenant from cache hits.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.BytesCacheHit) }))
	c.BindCounterVec("pullthrough_metering_served_bytes_upstream_total",
		"Total bytes served to a tenant that required an upstream fetch.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.BytesUpstream) }))
	c.BindCounterVec("pullthrough_metering_storage_bytes_total",
		"Total cache-fill storage footprint a tenant caused.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.StorageBytes) }))
	c.BindCounterVec("pullthrough_metering_scan_invocations_total",
		"Total admission-scan invocations attributed to a tenant.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.ScanInvocations) }))
	c.BindCounterVec("pullthrough_metering_scan_cost_micros_total",
		"Estimated cumulative admission-scan/LLM cost (micro-units) per tenant.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.ScanCostMicros) }))
	c.BindCounterVec("pullthrough_metering_blocked_total",
		"Total admission-gate refusals attributed to a tenant.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.Blocked) }))
	c.BindCounterVec("pullthrough_metering_quarantined_total",
		"Total quarantine events attributed to a tenant.", []string{"tenant"},
		tenantSeries(func(t metering.TenantMetric) float64 { return float64(t.Quarantined) }))
	c.BindCounter("pullthrough_metering_rollups_total",
		"Total usage rollups captured by the metering subsystem.",
		func() float64 { return float64(m.MetricsSnapshot().RollupsTotal) })
	c.BindCounter("pullthrough_metering_budget_alerts_total",
		"Total per-tenant budget-threshold alerts fired.",
		func() float64 { return float64(m.MetricsSnapshot().BudgetAlerts) })
}

// bindQueryAPIMetrics surfaces the federated query engine's cost telemetry
// (Task 67). Average query cost is derivable as cost_units_total/queries_total;
// the max/last-cost gauges flag individual expensive queries.
func bindQueryAPIMetrics(c *metrics.Collector, e *queryapi.Engine) {
	if e == nil {
		return
	}
	c.BindCounter("pullthrough_queryapi_queries_total",
		"Total federated queries executed successfully.",
		func() float64 { return float64(e.Snapshot().QueriesTotal) })
	c.BindCounter("pullthrough_queryapi_rejected_total",
		"Total federated queries rejected at validation (unknown field/operator, bad pagination, malformed filter).",
		func() float64 { return float64(e.Snapshot().RejectedTotal) })
	c.BindCounter("pullthrough_queryapi_cost_units_total",
		"Cumulative query-cost units charged across all federated queries (records scanned + predicate work + projected cells).",
		func() float64 { return float64(e.Snapshot().CostUnitsTotal) })
	c.BindCounter("pullthrough_queryapi_rows_scanned_total",
		"Cumulative model records scanned across all federated queries.",
		func() float64 { return float64(e.Snapshot().RowsScannedTotal) })
	c.BindCounter("pullthrough_queryapi_rows_returned_total",
		"Cumulative rows returned across all federated queries.",
		func() float64 { return float64(e.Snapshot().RowsReturnedTotal) })
	c.BindCounter("pullthrough_queryapi_truncated_total",
		"Total federated queries whose result was truncated by the page or scan bound.",
		func() float64 { return float64(e.Snapshot().TruncatedTotal) })
	c.BindGauge("pullthrough_queryapi_max_cost_units",
		"Highest single-query cost (units) observed since start.",
		func() float64 { return float64(e.Snapshot().MaxCost) })
	c.BindGauge("pullthrough_queryapi_last_cost_units",
		"Cost (units) of the most recently executed federated query.",
		func() float64 { return float64(e.Snapshot().LastCost) })
}

// bindMCPServerMetrics surfaces the read-only MCP server's telemetry (Task 79):
// total JSON-RPC requests and errors, plus per-tool call/error counters so
// operators can see which security questions AI agents ask most.
func bindMCPServerMetrics(c *metrics.Collector, m *mcpserver.Server) {
	if !m.Enabled() {
		return
	}
	c.BindCounter("pullthrough_mcp_requests_total",
		"Total MCP JSON-RPC requests dispatched (excluding notifications).",
		func() float64 { return float64(m.Snapshot().Requests) })
	c.BindCounter("pullthrough_mcp_errors_total",
		"Total MCP requests that produced a JSON-RPC error or a tool result flagged isError.",
		func() float64 { return float64(m.Snapshot().Errors) })
	c.Registry().RegisterFuncVec("pullthrough_mcp_tool_calls_total",
		"Total MCP tools/call invocations, partitioned by tool name.",
		"counter", []string{"tool"},
		func() []metrics.LabeledValue {
			snap := m.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.ToolCalls))
			for tool, n := range snap.ToolCalls {
				out = append(out, metrics.LabeledValue{Labels: []string{tool}, Value: float64(n)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_mcp_tool_errors_total",
		"Total MCP tools/call invocations that returned a tool error, partitioned by tool name.",
		"counter", []string{"tool"},
		func() []metrics.LabeledValue {
			snap := m.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.ToolErrors))
			for tool, n := range snap.ToolErrors {
				out = append(out, metrics.LabeledValue{Labels: []string{tool}, Value: float64(n)})
			}
			return out
		})
}

// bindGRPCServerMetrics surfaces the read-only gRPC/Connect security API's
// per-RPC telemetry (Task 159) to Prometheus under the pullthrough_grpc_*
// namespace. It is a no-op when the service is not enabled.
func bindGRPCServerMetrics(c *metrics.Collector, g *grpcapi.Server) {
	if !g.Enabled() {
		return
	}
	c.BindCounter("pullthrough_grpc_requests_total",
		"Total gRPC/Connect RPCs dispatched (unary and streaming).",
		func() float64 { return float64(g.Snapshot().Requests) })
	c.BindCounter("pullthrough_grpc_errors_total",
		"Total gRPC/Connect RPCs that returned a Connect error.",
		func() float64 { return float64(g.Snapshot().Errors) })
	c.BindCounter("pullthrough_grpc_streams_total",
		"Total gRPC/Connect server-streaming RPCs dispatched.",
		func() float64 { return float64(g.Snapshot().Streams) })
	c.BindCounter("pullthrough_grpc_stream_messages_total",
		"Total messages sent across all gRPC/Connect server-streaming RPCs.",
		func() float64 { return float64(g.Snapshot().StreamMessages) })
	c.Registry().RegisterFuncVec("pullthrough_grpc_rpc_calls_total",
		"Total gRPC/Connect RPC invocations, partitioned by method name.",
		"counter", []string{"method"},
		func() []metrics.LabeledValue {
			snap := g.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.RPCCalls))
			for method, n := range snap.RPCCalls {
				out = append(out, metrics.LabeledValue{Labels: []string{method}, Value: float64(n)})
			}
			return out
		})
	c.Registry().RegisterFuncVec("pullthrough_grpc_rpc_errors_total",
		"Total gRPC/Connect RPC invocations that returned an error, partitioned by method name.",
		"counter", []string{"method"},
		func() []metrics.LabeledValue {
			snap := g.Snapshot()
			out := make([]metrics.LabeledValue, 0, len(snap.RPCErrors))
			for method, n := range snap.RPCErrors {
				out = append(out, metrics.LabeledValue{Labels: []string{method}, Value: float64(n)})
			}
			return out
		})
}

// bindConfigDriftMetrics exposes the configuration drift signal (Task 85) as a
// gauge so operators can alert when the on-disk config diverges from the running
// process — the metric twin of the /api/config/drift endpoint. The detector
// re-reads and re-loads the config file at scrape time, which is cheap relative
// to the scrape interval.
func bindConfigDriftMetrics(c *metrics.Collector, svc *config.Service) {
	if svc == nil {
		return
	}
	c.BindGauge("pullthrough_config_drift",
		"Whether the on-disk configuration has drifted from the running process (1) or not (0). 1 also when the file no longer reads/parses/validates.",
		func() float64 {
			if svc.Drift().Drifted {
				return 1
			}
			return 0
		})
}
