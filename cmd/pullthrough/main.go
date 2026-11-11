// Command pullthrough is the entrypoint for the pull-through proxy. It loads
// configuration, constructs the caching subsystem and backend registry, wires
// the optional scanning and provenance pipelines, and serves the gateway until
// it receives a termination signal.
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/actionpin"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
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
	"github.com/blechschmidt/pullthrough-security/internal/backends/docker"
	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
	"github.com/blechschmidt/pullthrough-security/internal/backends/hackage"
	"github.com/blechschmidt/pullthrough-security/internal/backends/helm"
	"github.com/blechschmidt/pullthrough-security/internal/backends/hex"
	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/backends/jsr"
	"github.com/blechschmidt/pullthrough-security/internal/backends/julia"
	"github.com/blechschmidt/pullthrough-security/internal/backends/maven"
	"github.com/blechschmidt/pullthrough-security/internal/backends/nix"
	"github.com/blechschmidt/pullthrough-security/internal/backends/openvsx"
	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/backends/puppet"
	"github.com/blechschmidt/pullthrough-security/internal/backends/rubygems"
	"github.com/blechschmidt/pullthrough-security/internal/backends/swift"
	"github.com/blechschmidt/pullthrough-security/internal/backends/terraform"
	"github.com/blechschmidt/pullthrough-security/internal/backends/yum"
	"github.com/blechschmidt/pullthrough-security/internal/backup"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
	"github.com/blechschmidt/pullthrough-security/internal/continuity"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/egress"
	"github.com/blechschmidt/pullthrough-security/internal/fips"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/logging"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/scan"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
	"github.com/blechschmidt/pullthrough-security/internal/siem"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/spiffe"
	"github.com/blechschmidt/pullthrough-security/internal/tlspin"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pullthrough: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Air-gapped mirror subcommands are dispatched before the server flag set so
	// each can own its own flags. Anything else (including global flags like
	// -version) falls through to the server entrypoint below.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "export", "import", "prewarm":
			return runMirrorCommand(os.Args[1], os.Args[2:])
		case "backup", "restore":
			return runBackupSubcommand(os.Args[1], os.Args[2:])
		case "verify-audit":
			return runVerifyAuditCommand(os.Args[2:])
		case "verify-config":
			return runVerifyConfigCommand(os.Args[2:])
		case "findings":
			return runFindingsCommand(os.Args[2:])
		case "attest":
			return runAttestCommand(os.Args[2:])
		case "simulate":
			return runSimulateCommand(os.Args[2:])
		case "malfeed":
			return runMalfeedCommand(os.Args[2:])
		case "webhook":
			return runWebhookCommand(os.Args[2:])
		}
	}

	var (
		configPath  = flag.String("config", "", "path to YAML configuration file")
		showVersion = flag.Bool("version", false, "print version and exit")
		verifyAudit = flag.String("verify-audit", "", "verify the tamper-evidence of an audit log file and exit (see also the verify-audit subcommand)")
		auditKey    = flag.String("audit-key", "", "HMAC key for -verify-audit (defaults to $PTS_AUDIT_HMAC_KEY)")
		auditChecks = flag.String("audit-checkpoints", "", "checkpoint file for -verify-audit (defaults to <log>.checkpoints when present)")
		auditPubKey = flag.String("audit-pubkey", "", "PEM public key to verify checkpoint signatures for -verify-audit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	if *verifyAudit != "" {
		ckPath := *auditChecks
		if ckPath == "" {
			if def := *verifyAudit + ".checkpoints"; fileExists(def) {
				ckPath = def
			}
		}
		return runVerifyAudit(*verifyAudit, *auditKey, ckPath, *auditPubKey)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	// Configuration validation & drift-detection service (Task 85): captures the
	// effective config fingerprint at boot so the admin /api/config/drift endpoint
	// and the pullthrough_config_drift metric can detect when the on-disk file
	// diverges from what the process is running (pairs with hot-reload).
	configSvc := config.NewService(*configPath, cfg)

	logger, err := logging.New(logging.Options{
		Level:     cfg.Logging.Level,
		Format:    logging.Format(cfg.Logging.Format),
		AddSource: cfg.Logging.AddSource,
	})
	if err != nil {
		return err
	}
	logger.Info("starting pullthrough", "version", version)

	// Secrets provider resolution (Task 133): turn any "env://", "file://", or
	// "vault://path#key" secretRef in a credential field into its live value
	// before any subsystem reads that field. The resolver always provides the
	// env/file/literal providers and registers HashiCorp Vault when configured
	// (performing the initial auth and starting the lease refresher). It must be
	// closed on shutdown to stop the refresher. Resolution errors name the field
	// but never the secret value.
	secretsResolver, err := config.NewSecretsResolver(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := secretsResolver.Close(); cerr != nil {
			logger.Error("closing secrets resolver", "error", cerr)
		}
	}()
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), 30*time.Second)
	err = config.ResolveRefs(resolveCtx, cfg, secretsResolver)
	cancelResolve()
	if err != nil {
		return err
	}

	// OTLP structured-log export pipeline (Task 160): when a collector is
	// configured, tee every operational log record to an OTLP/HTTP sink,
	// correlated with the active trace/span. Built after secret resolution so
	// header ingest tokens are live, and after the plain logger so the pipeline's
	// own diagnostic logger (bootLogger below) is NOT the tapped logger — that
	// would recurse. The returned pipeline is nil (a no-op) when disabled.
	logPipeline, err := buildOTLPLogs(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		// Registered early so it runs late (LIFO): logs emitted while other
		// subsystems shut down are still flushed to the collector.
		if cerr := logPipeline.Close(); cerr != nil {
			logger.Error("closing OTLP log pipeline", "error", cerr)
		}
	}()
	if logPipeline != nil {
		// Replace the process logger with one that fans out to both stderr (the
		// original handler) and the OTLP forwarder. Every subsystem constructed
		// below receives this tapped logger.
		logger = slog.New(logPipeline.Handler(logger.Handler()))
	}

	// FIPS 140-3 cryptographic operating mode (Task 120). Detect the effective
	// mode (operator intent + live crypto/fips140 module state) and fail fast
	// before any subsystem is constructed if FIPS is required but the validated
	// module is not active — so an operator can never believe a deployment is
	// compliant when it is not. The active mode is logged and surfaced via the
	// admin API.
	fipsMode := fips.Detect(cfg.FIPS.Enabled, cfg.FIPS.RequireModuleOrDefault())
	if err := fipsMode.Validate(); err != nil {
		return fmt.Errorf("fips: %w", err)
	}
	logger.Info("crypto mode", fipsMode.LogAttrs()...)

	// Distributed tracing (Task 41): build the OpenTelemetry provider early so
	// every subsystem (gateway, commit scanner, CVE re-scan) can share it. A nil
	// provider is the disabled no-op. Shut it down last so spans produced during
	// graceful shutdown are flushed to the collector.
	tracerProvider, err := buildTracing(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if serr := tracerProvider.Shutdown(shutdownCtx); serr != nil {
			logger.Error("shutting down tracer", "error", serr)
		}
	}()

	cacheImpl, err := buildCache(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := cacheImpl.Close(); cerr != nil {
			logger.Error("closing cache", "error", cerr)
		}
	}()

	// The notification subsystem (Task 21) is built early so the scan pipeline,
	// vulnerability re-scan, the upstream mirror pool (Task 38), and the gateway
	// can all emit security alerts to it. A nil notifier is a valid no-op Emitter,
	// so disabling alerting needs no nil checks.
	notifier, err := buildNotifier(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if notifier != nil {
			_ = notifier.Close()
		}
	}()

	// SSRF / outbound-egress guard (Task 89): a transport-level defense-in-depth
	// control installed on every upstream client so all HTTP backends are covered
	// uniformly. Built before the backends so its hooks are wired into the client
	// pool at construction; its audit logger is attached once the audit log exists.
	egressGuard, err := buildEgress(cfg, notifyEmitter(notifier), logger)
	if err != nil {
		return err
	}

	// Per-upstream TLS certificate/CA pinning guard (Task 128): a transport-level
	// defense-in-depth control installed as a VerifyConnection hook on each pinned
	// upstream client, so an artifact can never be fetched over a connection whose
	// certificate chain does not satisfy the configured pin (MITM / compromised-CA
	// protection). Like the egress guard it is built before the backends so its
	// hooks are wired into the client pool at construction; its audit logger is
	// attached once the audit log exists.
	pinGuard := tlspin.New(tlspin.Options{Notifier: notifyEmitter(notifier), Logger: logger})

	// Shared outbound connection-pool telemetry (Task 130). One ConnMetrics is
	// built here and handed to both the client pool (so every per-TLS-policy
	// upstream client records into it) and the observability layer (so the
	// pullthrough_upstream_conn_* metrics read it), giving a single process-wide
	// view of connection reuse, dial latency, and pool footprint.
	connMetrics := &upstream.ConnMetrics{}

	registry, gitRT, poolMgr, err := buildBackends(cfg, cacheImpl, notifyEmitter(notifier), egressGuard, pinGuard, connMetrics, logger)
	if err != nil {
		return err
	}

	sshServer, err := buildGitSSHServer(cfg, gitRT, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start active health probing of upstream mirror pools (Task 38), if any pool
	// enabled it. The prober loops until ctx is cancelled at shutdown.
	poolMgr.StartProbing(ctx)

	scanner, secretDetector, closeScanner, err := buildScanner(ctx, cfg, notifier, tracerProvider.Tracer("pullthrough/scan"), logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeScanner(); cerr != nil {
			logger.Error("closing scanner", "error", cerr)
		}
	}()

	// Wire the deterministic secret detector into the Git LFS content gate (Task
	// 123) so large objects pulled through LFS are scanned for embedded
	// credentials, the same commit-scan content gate applied elsewhere. This is
	// done after the scanner is built (buildBackends runs earlier), by installing
	// the gate on every registered Git backend that enabled LFS.
	if cfg.Git.LFS.Enabled && secretDetector != nil {
		gate := newLFSSecretGate(secretDetector)
		for _, name := range registry.Names() {
			if bk, ok := registry.Get(name); ok {
				if gb, ok := backends.Unwrap(bk).(*git.Backend); ok {
					gb.SetLFSContentGate(gate)
				}
			}
		}
	}

	// Distributed coordination & leader election (Task 56): in an HA, multi-replica
	// deployment the lease-based coordinator ensures each shared-state scheduled job
	// (CVE-drift re-scan, backup, audit Merkle checkpoint signing) runs on only one
	// replica at a time. Constructed before the schedulers so their leader gates are
	// wired at build time; disabled by default (single-node ⇒ every guard is leader).
	coordSvc, err := buildCoordination(cfg, logger)
	if err != nil {
		return err
	}
	coordSvc.Start(ctx)
	defer func() {
		if cerr := coordSvc.Close(); cerr != nil {
			logger.Error("closing coordination", "error", cerr)
		}
	}()

	// Hot/cold tiered cache storage (Task 154): if a tiering layer is composed
	// into the cache stack, gate its background demotion sweep to the coordination
	// leader (only one replica demotes shared cold-tier artifacts) and start it.
	// The sweep goroutine is stopped when the cache is closed (via the Store.Close
	// chain) or ctx is cancelled.
	if tieredStore, ok := cache.TieredStoreOf(cacheImpl); ok {
		tieredStore.SetTierLeaderGate(coordSvc.Guard("cache-tiering").IsLeader)
		tieredStore.StartSweep(ctx)
	}

	// Cross-proxy peer cache federation (Task 143): built after coordination so it
	// can self-exclude by NodeID, and before the gateway so it can be injected and
	// its metrics bound. A nil/disabled federation is a harmless no-op.
	cacheFed, err := buildCacheFed(cfg, coordSvc, logger)
	if err != nil {
		return err
	}

	// SIEM / log-forwarding (Task 119): built before the audit log so its
	// decorating sink can tap each committed audit record, and before the gateway
	// so admission-gate findings can be forwarded. A nil forwarder is a valid
	// no-op. The forwarder is closed last (after the audit log) so records sealed
	// during audit shutdown are still forwarded.
	siemFwd, err := buildSIEMForwarder(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := siemFwd.Close(); cerr != nil {
			logger.Error("closing siem forwarder", "error", cerr)
		}
	}()

	auditLog, closeAudit, err := buildAuditLog(ctx, cfg, siemFwd, coordSvc.Guard("audit-checkpoint").IsLeader, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeAudit(); cerr != nil {
			logger.Error("closing audit log", "error", cerr)
		}
	}()

	// Attach the audit log to the egress guard now that it exists, so a blocked
	// outbound fetch is recorded in the tamper-evident log (it was built earlier so
	// its transport hooks could be wired into the client pool).
	egressGuard.SetAuditLogger(auditLog)

	// Likewise attach the audit log to the TLS-pinning guard so a pin violation is
	// recorded in the tamper-evident log (the guard was built earlier so its verify
	// hooks could be wired into the client pool).
	pinGuard.SetAuditLogger(auditLog)

	// Install the cache-integrity observer now that audit + notification exist, so
	// a detected content-integrity violation (Task 107) records a tamper-evident
	// audit event and raises an operator alert in addition to quarantining the
	// entry and self-healing on the next pull.
	if ic, ok := cacheImpl.(*cache.IntegrityCache); ok {
		ic.SetObserver(newCacheIntegrityObserver(auditLog, notifyEmitter(notifier),
			cfg.Cache.Integrity.NotifySeverity, logger))
	}

	// SPIFFE/SVID mutual-TLS workload identity (Task 58): when enabled, build the
	// mTLS authenticator (reloadable trust bundle + identity-mapping policy) and
	// prepend it to the auth chain so a verified client certificate maps to a
	// tenant + roles. Built before the enforcer so the chain is wired at
	// construction; its trust-bundle watcher runs for the lifetime of the server.
	clientMTLS, err := buildClientMTLS(cfg, logger)
	if err != nil {
		return err
	}
	if clientMTLS != nil {
		clientMTLS.start(ctx, logger)
	}

	enforcer, err := buildEnforcer(cfg, clientMTLS.authenticatorOrNil(), logger)
	if err != nil {
		return err
	}

	rateLimiter, closeRateLimiter, err := buildRateLimiter(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeRateLimiter(); cerr != nil {
			logger.Error("closing rate-limit store", "error", cerr)
		}
	}()

	provService, closeProvenance, err := buildProvenance(cfg, registry, scanner, egressGuard, pinGuard, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeProvenance(); cerr != nil {
			logger.Error("closing provenance store", "error", cerr)
		}
	}()

	// A nil *provenance.Service must reach the gateway as a true nil interface, not
	// a typed-nil, so the optional dependency is correctly detected as absent.
	var provResolver provenance.Resolver
	if provService != nil {
		provResolver = provService
	}

	policyEngine := buildPolicy(cfg, provService, logger)

	vulnService, err := buildVulnScanner(cfg, logger)
	if err != nil {
		return err
	}

	nameGuard := buildNameguard(cfg, logger)

	// Known-malicious-package gate (Task 48): matches concrete coordinates against
	// curated malware datasets and hard-blocks listed crypto-miners / credential
	// stealers / install-script backdoors. Started here so its background feed
	// refresh (ETag/conditional) runs for the lifetime of the server.
	malfeedSvc, err := buildMalfeed(cfg, logger)
	if err != nil {
		return err
	}
	if malfeedSvc != nil {
		malfeedSvc.Start(ctx)
		defer malfeedSvc.Close()
	}

	// Release-maturity / version-cooldown gate (Task 61): quarantines
	// newly-published versions until they age past a configurable cooldown window,
	// deriving publish timestamps from the upstream registry metadata.
	maturitySvc := buildMaturity(cfg, logger)

	// Maintainer/publisher continuity monitoring gate (Task 91): tracks each
	// coordinate's publisher identity over time with trust-on-first-use and flags an
	// ownership change (new maintainer / rotated key / new namespace owner) as a
	// supply-chain risk signal. A store-load failure is fatal so a corrupt durable
	// known-maintainer set is not silently discarded.
	continuitySvc, err := buildContinuity(cfg, logger)
	if err != nil {
		return fmt.Errorf("building continuity gate: %w", err)
	}

	// Dependency-firewall version-pinning & allowlist gate (Task 65): enforces
	// explicit per-tenant version policy (pinned versions, allowed ranges, floors,
	// denylists, or a deny-by-default lockfile allowlist) on the pull path. A
	// malformed range is fatal so a misconfigured firewall fails loudly.
	depFirewallSvc, err := buildDepFirewall(cfg, logger)
	if err != nil {
		return fmt.Errorf("dependency firewall: %w", err)
	}

	// Install-script / lifecycle-hook risk-analysis gate (Task 62): statically
	// scores a package's automatically-run install hooks against deterministic
	// high-risk patterns. Built before the gateway so it can be wired as a content
	// gate and surfaced in observability/admin.
	installHooksSvc, err := buildInstallHooks(cfg, logger)
	if err != nil {
		return fmt.Errorf("building install-hook analysis gate: %w", err)
	}

	// ML model weight-scanning gate (Task 110): statically disassembles a Hugging
	// Face pickle weight file's opcode stream and blocks/quarantines one carrying an
	// unsafe import invoked via __reduce__. Built before the gateway so it can be
	// wired as a content gate and surfaced in observability.
	mlGuardSvc, err := buildMLGuard(cfg, logger)
	if err != nil {
		return fmt.Errorf("building ML weight-scanning gate: %w", err)
	}

	// Antivirus content-scanning gate (Task 136): streams fetched artifact
	// payloads through a configurable AV engine (ClamAV via clamd INSTREAM) and
	// quarantines/blocks/annotates on a positive byte-level malware detection.
	avScanSvc, err := buildAVScan(cfg, logger)
	if err != nil {
		return fmt.Errorf("building antivirus content-scanning gate: %w", err)
	}

	// Package-payload static content-analysis gate (Task 138): unpacks a cached
	// source artifact and applies deterministic heuristics (embedded binaries,
	// high-entropy blobs, obfuscated JS, dynamic-exec sinks, in-source secrets) to
	// its files, reusing the deterministic secret detector. Built before the gateway
	// so it can be wired as a content gate and surfaced in observability/admin.
	contentScanSvc, err := buildContentScan(cfg, secretDetector, logger)
	if err != nil {
		return fmt.Errorf("building package-content analysis gate: %w", err)
	}

	// Sandboxed LLM package-content scan gate (Task 173): has a language model
	// read the unpacked contents of a fetched package — through a bounded,
	// read-only view; nothing is executed — and return a malicious / suspicious /
	// benign verdict before the artifact is served. It reuses the commit scanner's
	// provider abstraction, caches verdicts by artifact digest, and is bounded by
	// a per-tenant / global cost budget. Built before the gateway so it can be
	// wired as a content gate and surfaced in observability/admin.
	llmPkgScanSvc, closeLLMPkgScan, err := buildLLMPkgScan(cfg, auditLog, notifier, logger)
	if err != nil {
		return fmt.Errorf("building LLM package-content scan gate: %w", err)
	}
	defer func() {
		if cerr := closeLLMPkgScan(); cerr != nil {
			logger.Error("closing LLM package-content scan gate", "error", cerr)
		}
	}()

	licenseService, err := buildLicense(cfg, logger)
	if err != nil {
		return err
	}

	// Transparency log (Sigstore Rekor, Task 142): shared submit/verify wiring and
	// the pullthrough_rekor_* metrics, threaded into the signature gate (inbound
	// inclusion-proof verification) and the attestation engine (outbound submit).
	rekorDeps, err := buildRekor(cfg, logger)
	if err != nil {
		return err
	}

	sigVerify, err := buildSigverify(cfg, registry, rekorDeps, logger)
	if err != nil {
		return err
	}

	// Supply-chain provenance & dependency graph (Task 33): ingests every pull
	// (artifact, source commit, SBOM components, CVE findings, signature status)
	// into an in-memory graph that powers blast-radius / reverse-dependency /
	// path-to-commit queries and the admin visualization.
	provGraph := buildProvgraph(cfg, logger)

	// Declarative policy-as-code admission engine (Task 32): evaluates operator-
	// authored CEL rule bundles over the aggregated signals the gates above
	// produce. It is the final, extensible admission layer over the hard-coded
	// gates.
	pacEngine, err := buildPolicyEngine(cfg, logger)
	if err != nil {
		return err
	}
	if pacEngine != nil {
		defer pacEngine.Close()
	}

	// Continuous CVE-drift re-scan of cached artifacts (Task 18): re-runs the OSV
	// pipeline over stored SBOMs on a schedule (and on demand via the admin API),
	// quarantining artifacts that become vulnerable after they were cached.
	rescanner := buildRescanner(cfg, vulnService, cacheImpl, auditLog, notifier, tracerProvider.Tracer("pullthrough/vulnscan"), logger)
	if rescanner != nil {
		// In HA, only the coordination leader runs the sweep (it mutates shared
		// quarantine state); set the gate before Start.
		rescanner.SetLeaderGate(coordSvc.Guard("cve-drift-rescan").IsLeader)
		rescanner.Start(ctx)
		defer rescanner.Close()
	}

	// Continuous compliance scorecard (Task 35): periodically aggregates the
	// security gates' signals into a SLSA/SOC2-style posture report, exposed over
	// the admin API (JSON/Markdown/HTML), as a signed exportable artifact, and as
	// per-control Prometheus gauges.
	complianceSvc, err := buildCompliance(cfg, sigVerify, provGraph, vulnService, licenseService, secretDetector, auditLog, logger)
	if err != nil {
		return err
	}
	if complianceSvc != nil {
		complianceSvc.Start(ctx)
	}

	// Unified supply-chain risk-scoring engine (Task 37): aggregates every gate
	// signal into one composite, explainable risk score and band per artifact,
	// with an optional warn/block admission threshold that composes with the
	// policy-as-code engine.
	riskEngine, err := buildRiskScore(cfg, logger)
	if err != nil {
		return err
	}

	// Source-repository health signal provider (Task 63): OpenSSF Scorecard-style
	// health signals for the repository an artifact was built from, fed into the
	// policy and risk engines. Offline/air-gap friendly; opt-in.
	repoScoreSvc, err := buildRepoScore(cfg, logger)
	if err != nil {
		return err
	}

	// Sandboxed WASM extensibility gates (Task 59): operator-supplied wasm modules
	// invoked as a final admission stage over the aggregated signal set, under
	// strict CPU/memory/time/fuel limits with no host fs/network access.
	extManager, err := buildExtension(cfg, logger)
	if err != nil {
		return err
	}
	if extManager != nil {
		defer extManager.Close(context.Background())
	}

	// Behavioral anomaly detection (Task 43): online rolling-window/EWMA detectors
	// over the pull stream that flag per-tenant/identity fan-out spikes, new-
	// namespace bursts, off-hours bursts, rapid 404 enumeration, and anomalous
	// egress volume — feeding the notify subsystem and optionally soft-blocking.
	anomalyEngine, err := buildAnomaly(cfg, logger)
	if err != nil {
		return err
	}

	// Human-in-the-loop quarantine-review & break-glass approval workflow (Task 50):
	// lets an operator grant a time-boxed, tenant+coordinate+gate-scoped exception
	// to a gate block/quarantine (or confirm the block), with every state change
	// recorded in the tamper-evident audit log and surfaced as a notification.
	approvalsSvc, err := buildApprovals(cfg, auditLog, notifier, logger)
	if err != nil {
		return err
	}
	if approvalsSvc != nil {
		stopSweeper := startApprovalsSweeper(ctx, approvalsSvc, cfg.Approvals.SweepInterval, logger)
		defer stopSweeper()
	}

	// Pull-path request coalescing + negative caching (Task 36): collapse
	// concurrent cache-miss requests for the same tenant-scoped artifact onto a
	// single upstream fetch and remember terminal upstream failures briefly.
	coalescer := buildCoalescer(cfg, logger)

	// Cache lifecycle manager (Task 39): a background GC/eviction/retention engine
	// that keeps the content-addressable cache bounded via size watermarks
	// (LRU/LFU/FIFO), per-artifact/per-tenant TTLs, and pin/reference retention,
	// coordinating safely with the single-flight pull path and the shared store.
	cacheGC, err := buildCacheGC(cfg, cacheImpl, vulnService, notifier, logger)
	if err != nil {
		return err
	}
	if cacheGC != nil {
		cacheGC.Start(ctx)
		defer cacheGC.Close()
	}

	// Disaster-recovery backup scheduler (Task 44): a periodic, consistent
	// snapshot of the cache and all sidecar metadata stores, plus the on-demand
	// (admin/CLI) trigger and the backup-age/last-success stats used for RPO
	// alerting. Always constructed so the admin status surface and metrics are
	// present; the periodic loop runs only when backup.interval is configured.
	backupScheduler := backup.NewScheduler(cfg.Backup.Interval, buildScheduledBackupRun(cfg), backup.NewStats(nil), logger)
	// In HA, only the coordination leader runs the scheduled backup (it writes
	// snapshots to a shared destination); set the gate before Start.
	backupScheduler.SetLeaderGate(coordSvc.Guard("backup").IsLeader)
	backupScheduler.Start(ctx)
	defer backupScheduler.Stop()

	// Unified SARIF findings-aggregation layer (Task 42): a bounded, in-memory
	// store of the most recent normalized findings per artifact, fed by the gateway
	// after each admission run and exported as SARIF 2.1.0 over the admin API and
	// the `findings` CLI subcommand for CI pull-request decoration.
	findingsStore := buildFindingsStore(cfg, logger)

	// Finding de-duplication + suppression audit trail (Task 165): the gateway
	// collapses overlapping gate findings before recording and records every
	// suppressed finding (who/what/why) into an immutable, per-coordinate-queryable
	// ledger mirrored to the tamper-evident audit log.
	findingsMetrics, suppressionLedger := buildFindingsDedup(cfg, auditLog, logger)

	// SBOM diff & dependency-drift subsystem (Task 64): persists a bounded
	// per-coordinate history of resolved SBOMs and, on each new version, diffs the
	// dependency set / licenses / namespaces / vulnerabilities against the prior
	// version, deriving a drift-risk signal. Reuses the license service to classify
	// newly-introduced licenses.
	sbomDiffSvc := buildSbomDiff(cfg, licenseService, logger)

	// Reproducible-build verification gate (Task 68): for an artifact mapped to a
	// source commit, asynchronously rebuild it from source (via a pluggable,
	// sandboxed, air-gap-aware builder) and compare digests, emitting a
	// reproducible|mismatch|unsupported|unattested verdict that feeds the policy and
	// risk engines and the SARIF findings layer.
	rebuildVerifySvc, err := buildRebuildVerify(cfg, notifier, logger)
	if err != nil {
		return err
	}

	// Inbound build-provenance verification gate (Task 72): consumes
	// upstream-published build provenance (npm provenance / GitHub artifact
	// attestations) to cryptographically bind a package version to its source repo +
	// commit + CI workflow, then cross-checks that proven commit against the
	// package-to-commit association from the provenance subsystem (Task 8) and flags
	// mismatches. Observe-only by default.
	buildProvSvc, err := buildBuildProv(cfg, logger)
	if err != nil {
		return err
	}

	// Inbound PyPI PEP 740 digital-attestation gate (Task 146): verifies the
	// Trusted-Publisher attestations PyPI serves for a wheel/sdist and binds the
	// attested sha256 digest to the served artifact. Annotate-only by default.
	pypiAttestSvc, err := buildPyPIAttest(cfg, logger)
	if err != nil {
		return err
	}

	// Policy & risk what-if replay capture recorder (Task 47): a sampled, redacted
	// ring buffer of recent admission inputs and their live verdicts, fed by the
	// gateway after each admission run, that operators replay through a candidate
	// configuration via the `simulate` CLI or the admin endpoint.
	simReplayRecorder := buildSimReplayRecorder(cfg, logger)

	// Outbound SLSA/in-toto attestation engine (Task 46): signs a supply-chain
	// attestation for every served artifact, binding its digest to the source
	// commit and the verdicts it passed, and embeds the bundle digest in the audit
	// log. Reuses the audit signing key by default; inactive when no key exists.
	attestor, err := buildAttestor(cfg, rekorDeps, logger)
	if err != nil {
		return err
	}

	// Organization-wide dependency snapshot, freeze & instant-rollback subsystem
	// (Task 70): captures the resolved dependency state actually served into signed,
	// content-addressed point-in-time manifests; can freeze the org to a snapshot
	// (a pull-path gate refuses pulls outside the frozen set) and roll back to the
	// last-known-good snapshot in one action. Reuses the audit signing key to sign
	// manifests and records lifecycle actions to the Merkle audit log.
	snapshotSvc, err := buildSnapshot(cfg, auditLog, notifier, logger)
	if err != nil {
		return err
	}
	// Coord-guarded scheduled capture (Task 56): only the lease-holder captures on
	// each tick so HA replicas do not each write a snapshot.
	snapshotScheduler := snapshot.NewScheduler(snapshotSvc)
	snapshotScheduler.SetLeaderGate(coordSvc.Guard("snapshot").IsLeader)
	snapshotScheduler.Start(ctx)
	defer snapshotScheduler.Stop()

	// Emergency-lockdown / global kill-switch incident-response control (Task 74):
	// the org-wide freeze/strict/targeted-block posture consulted as the FIRST check
	// on the pull path. State is durable and coord-guarded (the "lockdown" guard's
	// fencing token orders transitions across the HA cluster, and the leader gate
	// drives the single auto-expiry sweep), with a mandatory reason + incident ID
	// recorded to the Merkle audit log and a TTL with auto-expiry.
	lockdownSvc, err := buildLockdown(cfg, auditLog, notifier, coordSvc.Guard("lockdown"), logger)
	if err != nil {
		return err
	}

	// GitOps policy & config synchronization (Task 93): continuously reconcile the
	// proxy's policy/config bundles from a version-controlled source of truth
	// (Git/OCI/local). Verifies the desired-state bundle, validates and previews it
	// (configcheck + simreplay blast radius), then applies it (auto) or surfaces it
	// for dual-control approval (suggest mode); supports rollback to last-known-good.
	gitopsSvc, err := buildGitops(cfg, *configPath, auditLog, notifier, approvalsSvc, simReplayRecorder, logger)
	if err != nil {
		return err
	}
	// Coord-guarded reconcile loop (Task 56): only the lease-holder reconciles and
	// mutates the shared config/state, so HA replicas do not each apply.
	if gitopsSvc != nil {
		gitopsSvc.SetLeaderGate(coordSvc.Guard("gitops").IsLeader)
		gitopsSvc.Start(ctx)
		defer gitopsSvc.Stop()
	}

	// Predictive cache pre-warming (Task 134): learns historical pull patterns and
	// proactively fetches + admission-gates forecast near-future pulls during
	// off-peak windows, so cache hits and gate verdicts are ready before the first
	// client request. Constructed here (before the gateway) so its pull-observer
	// tap can be wired into the gateway; its fetcher, leader gate, and kill-switch
	// are attached once the gateway exists (below). Disabled by default.
	prewarmSvc, err := buildPrewarm(cfg, provGraph, logger)
	if err != nil {
		return err
	}

	// Credential & signing-key rotation/expiry monitoring (Task 148): builds a
	// leader-gated expiry scanner over the audit keys, cache KEK, attestation
	// signing key, upstream credentials, and monitored certificates. Always
	// constructed (inert when disabled); started below behind the leader gate.
	keyRotationSvc := buildKeyRotation(cfg, cacheImpl, auditLog, attestor, logger)

	// Outbound SBOM/findings federation (Task 153): renders the generated
	// CycloneDX SBOMs (and admission-gate findings) and pushes them to external
	// supply-chain graph systems (Dependency-Track, GUAC). Its periodic sweep is
	// leader-gated so only one HA node exports; a manual `ptctl sbom-export run`
	// trigger bypasses the gate. Disabled by default; nil when disabled.
	sbomExporter := buildSBOMExporter(cfg, vulnService, logger)
	if sbomExporter != nil {
		sbomExporter.SetLeaderGate(coordSvc.Guard("sbom-export").IsLeader)
		sbomExporter.Start(ctx)
		defer func() { _ = sbomExporter.Close() }()
	}

	// WebAuthn/passkey step-up authentication (Task 161): gates the most sensitive
	// admin mutations behind a fresh FIDO2 assertion and serves the enrolment/
	// assertion ceremonies. Constructed after the audit log so every ceremony is
	// recorded in the tamper-evident chain; nil when disabled.
	webAuthnSvc, err := buildWebAuthn(cfg, auditLog, logger)
	if err != nil {
		return err
	}

	obs := buildObservability(cfg, configSvc, registry, cacheImpl, scanner, secretDetector, provService, provResolver, vulnService, nameGuard, malfeedSvc, maturitySvc, continuitySvc, depFirewallSvc, installHooksSvc, mlGuardSvc, avScanSvc, contentScanSvc, llmPkgScanSvc, sigVerify, licenseService, pacEngine, rescanner, notifier, siemFwd, rateLimiter, auditLog, provGraph, coalescer, complianceSvc, riskEngine, repoScoreSvc, sbomDiffSvc, rebuildVerifySvc, buildProvSvc, pypiAttestSvc, extManager, anomalyEngine, approvalsSvc, poolMgr, egressGuard, pinGuard, connMetrics, cacheGC, backupScheduler, findingsStore, findingsMetrics, suppressionLedger, simReplayRecorder, attestor, snapshotSvc, lockdownSvc, gitopsSvc, prewarmSvc, sbomExporter, tracerProvider, logPipeline, coordSvc, clientMTLS, secretsResolver, rekorDeps.metrics, cacheFed, keyRotationSvc, webAuthnSvc, logger)

	// Only the coordination leader emits expiry notifications (the scan still runs
	// on every replica so each node's gauge is populated); then start the loop.
	keyRotationSvc.SetLeaderGate(coordSvc.Guard("key-rotation").IsLeader)
	keyRotationSvc.Start(ctx)
	defer keyRotationSvc.Stop()

	// Continuous webhook/polling-driven incremental Git commit scanner (Task 108):
	// watches a configured set of repositories, detects new commits via a push
	// webhook and/or polling, and scans only commits not previously scanned,
	// persisting a per-repo cursor. Built after the findings store, audit log, and
	// observability so each scanned commit is recorded, audited, and metered.
	commitWatch, closeCommitWatch, err := buildCommitWatch(cfg, scanner, findingsStore, auditLog, notifier, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeCommitWatch(); cerr != nil {
			logger.Error("closing commit watcher", "error", cerr)
		}
	}()
	if commitWatch != nil {
		// In HA, only the coordination leader runs the polling sweep (it mutates the
		// shared per-repo cursor state); webhook-driven scans are idempotent via the
		// cursor and are not gated.
		commitWatch.SetLeaderGate(coordSvc.Guard("commit-watch").IsLeader)
		bindCommitWatchMetrics(obs.collector, commitWatch)
		commitWatch.Start(ctx)
	}
	var webhookHandler http.Handler
	if commitWatch != nil {
		webhookHandler = commitWatch.WebhookHandler(ctx)
	}

	interceptor, err := buildInterceptor(cfg, logger)
	if err != nil {
		return err
	}

	gateway, err := proxy.New(proxy.Dependencies{
		Logger:          logger,
		Cache:           cacheImpl,
		Backends:        registry,
		Scanner:         scanner,
		SSHServer:       sshServer,
		Interceptor:     interceptor,
		Enforcer:        enforcer,
		RateLimit:       rateLimiter,
		Coalescer:       coalescer,
		Audit:           auditLog,
		Ecosystems:      ecosystemMap(cfg),
		Provenance:      provResolver,
		Policy:          policyEngine,
		Vulnerabilities: vulnService,
		License:         licenseService,
		NameGuard:       nameGuard,
		Continuity:      continuitySvc,
		Malfeed:         malfeedSvc,
		Maturity:        maturitySvc,
		DepFirewall:     depFirewallSvc,
		InstallHooks:    installHooksSvc,
		MLGuard:         mlGuardSvc,
		AVScan:          avScanSvc,
		ContentScan:     contentScanSvc,
		LLMPkgScan:      llmPkgScanSvc,
		Sigverify:       sigVerify,
		PolicyEngine:    pacEngine,
		RiskScore:       riskEngine,
		RepoScore:       repoScoreSvc,
		SbomDiff:        sbomDiffSvc,
		RebuildVerify:   rebuildVerifySvc,
		BuildProv:       buildProvSvc,
		PyPIAttest:      pypiAttestSvc,
		Snapshot:        snapshotSvc,
		Lockdown:        lockdownSvc,
		Extension:       extManager,
		Anomaly:         anomalyEngine,
		Approvals:       approvalsSvc,
		Findings:        findingsStore,
		FindingsMetrics: findingsMetrics,
		Suppressions:    suppressionLedger,
		SIEM:            siemFindingsForwarder(siemFwd),
		SimReplay:       simReplayRecorder,
		Attestor:        attestor,
		ProvGraph:       provGraph,
		Notify:          notifyEmitter(notifier),
		Metrics:         obs.recorder,
		Metering:        meteringRecorder(obs.metering),
		Tracer:          tracerProvider.Tracer("pullthrough/proxy"),
		MetricsHandler:  obs.metricsHandler,
		AdminHandler:    obs.adminHandler,
		PortalHandler:   obs.portalHandler,
		WebhookHandler:  webhookHandler,
		PullObserver:    newPrewarmPullObserver(prewarmSvc),
		CacheFed:        cacheFed,
	}, proxy.Options{
		HTTPAddr:         cfg.Server.HTTPAddr,
		ReadTimeout:      cfg.Server.ReadTimeout,
		WriteTimeout:     cfg.Server.WriteTimeout,
		ShutdownTimeout:  cfg.Server.ShutdownTimeout,
		TLSCertFile:      cfg.Server.TLSCertFile,
		TLSKeyFile:       cfg.Server.TLSKeyFile,
		TLSClientAuth:    clientMTLS.clientAuthType(),
		CacheNamespacing: cfg.Auth.CacheNamespacing,
		MetricsPath:      obs.metricsPath,
		AdminPrefix:      obs.adminPrefix,
		PortalUIPrefix:   obs.portalUIPrefix,
		PortalAPIPrefix:  obs.portalAPIPath,
		InterceptAddr:    cfg.Server.Intercept.ListenAddr,
		WebhookPath:      watchWebhookPath(cfg),
		FIPSEnabled:      fipsMode.Enabled,
		RegistryRoot:     buildRegistryRoot(cfg, logger),
	})
	if err != nil {
		return err
	}

	// The gateway is built after the metrics collector, so its Range/streaming
	// serve counters (Task 75) are bound here, once both exist.
	bindServeMetrics(obs.collector, gateway)

	// Git LFS objects are served by the Git backend itself, not through the
	// gateway's cached-artifact path, so the LLM package-content scan (Task 174)
	// is handed to it as a serve gate: every object request — hit, miss, Range —
	// passes it before a byte is written.
	wireLFSServeGate(registry, gateway, llmPkgScanSvc)

	// Now that the gateway exists, give the pre-warmer its fetcher (which drives
	// the gateway's full gated pull pipeline), gate periodic pre-warm cycles on HA
	// leadership (Task 56) so only one node pre-warms, and refuse to pre-warm while
	// the emergency kill-switch / lockdown is engaged (Task 74). Then start it; it
	// persists its learned history on Close.
	if prewarmSvc != nil {
		prewarmSvc.SetFetcher(newGatewayPrewarmFetcher(gateway, logger))
		prewarmSvc.SetLeaderGate(coordSvc.Guard("prewarm").IsLeader)
		prewarmSvc.SetKillSwitch(func() bool { return lockdownSvc.Status().Active })
		prewarmSvc.Start(ctx)
		defer func() { _ = prewarmSvc.Close() }()
	}

	// The Kubernetes admission webhook (Task 111), when enabled, runs as an
	// additional HTTPS listener sharing the gateway's lifecycle: it starts here
	// and shuts down when ctx is canceled. A fatal webhook error cancels the
	// shared context so the gateway also stops (and the process exits non-zero),
	// mirroring how the SSH/interception listeners are supervised.
	if obs.webhook != nil {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		webhookErr := make(chan error, 1)
		go func() {
			if err := obs.webhook.Run(ctx); err != nil {
				logger.Error("admission webhook stopped with error", "error", err)
				webhookErr <- err
				cancel()
				return
			}
			webhookErr <- nil
		}()
		if err := gateway.Run(ctx); err != nil {
			return err
		}
		// The gateway returned (ctx canceled): wait for the webhook to drain and
		// surface a fatal webhook error, if any.
		if err := <-webhookErr; err != nil {
			return err
		}
		return nil
	}

	return gateway.Run(ctx)
}

// runVerifyAuditCommand is the `verify-audit` subcommand. It owns its own flag
// set so it can offer the full transparency-verification surface (checkpoints
// and signing-key material) without crowding the server's global flags.
func runVerifyAuditCommand(args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	var (
		logPath     = fs.String("log", "", "path to the append-only audit log file (required)")
		key         = fs.String("key", "", "HMAC key for the hash chain (defaults to $PTS_AUDIT_HMAC_KEY)")
		checkpoints = fs.String("checkpoints", "", "path to the sealed-checkpoints file (defaults to <log>.checkpoints when present)")
		pubKeyFile  = fs.String("pubkey", "", "PEM public key to verify checkpoint signatures (optional)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough verify-audit -log <path> [-key <hmac>] [-checkpoints <path>] [-pubkey <path>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Accept the log path as a bare positional argument too, for ergonomics.
	if *logPath == "" && fs.NArg() > 0 {
		*logPath = fs.Arg(0)
	}
	if *logPath == "" {
		fs.Usage()
		return fmt.Errorf("verify-audit: -log is required")
	}
	ckPath := *checkpoints
	if ckPath == "" {
		if def := *logPath + ".checkpoints"; fileExists(def) {
			ckPath = def
		}
	}
	return runVerifyAudit(*logPath, *key, ckPath, *pubKeyFile)
}

// runVerifyAudit verifies the tamper-evidence of an on-disk audit log: it reads
// every record, checks sequence linkage and the keyed hash chain, then — when
// sealed checkpoints are present — recomputes the Merkle root for each
// checkpoint's prefix, validates append-only consistency between checkpoints,
// and (with a public key) verifies checkpoint signatures. It reports the first
// break and exits non-zero on tampering so it can be wired into monitoring/CI.
func runVerifyAudit(path, key, checkpointPath, pubKeyFile string) error {
	if key == "" {
		key = os.Getenv("PTS_AUDIT_HMAC_KEY")
	}
	if key == "" {
		return fmt.Errorf("verify-audit: an HMAC key is required (-key or $PTS_AUDIT_HMAC_KEY)")
	}
	records, err := audit.ReadAllRecords(path)
	if err != nil {
		return err
	}
	if idx, verr := audit.VerifyChain([]byte(key), records); verr != nil {
		return fmt.Errorf("verify-audit: hash chain INVALID at record %d: %w", idx, verr)
	}
	fmt.Printf("verify-audit: hash chain OK — %d records form an intact tamper-evident chain\n", len(records))

	if checkpointPath == "" {
		fmt.Println("verify-audit: no checkpoint file provided; skipping Merkle transparency checks")
		return nil
	}
	cps, err := audit.ReadCheckpoints(checkpointPath)
	if err != nil {
		return err
	}
	if len(cps) == 0 {
		fmt.Printf("verify-audit: checkpoint file %q is empty; nothing to cross-check\n", checkpointPath)
		return nil
	}

	var pub crypto.PublicKey
	if pubKeyFile != "" {
		pemData, rerr := os.ReadFile(pubKeyFile)
		if rerr != nil {
			return fmt.Errorf("verify-audit: reading public key: %w", rerr)
		}
		// Reuse the signature-verification gate's trust-material parser so the
		// audit log can be anchored to the same keys.
		pub, err = sigverify.ParsePublicKeyPEM(pemData)
		if err != nil {
			return fmt.Errorf("verify-audit: parsing public key: %w", err)
		}
	}

	results, verr := audit.VerifyLog(records, cps, pub)
	for _, r := range results {
		status := "OK"
		if !r.OK() {
			status = "BROKEN: " + r.Problem
		}
		sig := "unsigned"
		if r.Signed {
			if pub == nil {
				sig = "signed (not checked)"
			} else if r.SignatureOK {
				sig = "signed+verified"
			} else {
				sig = "signed but INVALID"
			}
		}
		fmt.Printf("  checkpoint treeSize=%d root=%s… %s [%s]\n", r.TreeSize, truncateHex(r.RootHash), sig, status)
	}
	if verr != nil {
		return fmt.Errorf("verify-audit: transparency check FAILED: %w", verr)
	}
	fmt.Printf("verify-audit: transparency OK — %d checkpoints consistent with the log\n", len(cps))
	return nil
}

// truncateHex shortens a hex digest for compact CLI output.
func truncateHex(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ecosystemMap builds the backend-name → ecosystem-type mapping the gateway
// uses for RBAC and audit, covering all enabled upstreams.
func ecosystemMap(cfg *config.Config) map[string]string {
	m := make(map[string]string, len(cfg.Upstreams))
	for name, up := range cfg.Upstreams {
		if up.IsEnabled() {
			m[name] = up.Type
		}
	}
	return m
}

// buildAuditLog constructs the tamper-evident audit logger when auditing is
// enabled, resuming the hash chain from the configured file sink (or an
// in-memory sink when no file is set). It returns a nil logger (and a no-op
// closer) when auditing is disabled.
func buildAuditLog(ctx context.Context, cfg *config.Config, siemFwd *siem.Forwarder, sealLeaderFn func() bool, logger *slog.Logger) (*audit.Logger, func() error, error) {
	noop := func() error { return nil }
	if !cfg.Audit.Enabled {
		logger.Warn("audit logging disabled (set audit.enabled and audit.hmacKey to record a tamper-evident trail)")
		return nil, noop, nil
	}

	key := cfg.Audit.HMACKey
	if key == "" && cfg.Audit.HMACKeyEnv != "" {
		key = os.Getenv(cfg.Audit.HMACKeyEnv)
	}
	if key == "" {
		return nil, noop, fmt.Errorf("audit: hmac key is empty (set audit.hmacKey or audit.hmacKeyEnv)")
	}

	var sink audit.Sink
	if cfg.Audit.File != "" {
		fs, ferr := audit.NewFileSink(cfg.Audit.File)
		if ferr != nil {
			return nil, noop, ferr
		}
		sink = fs
		logger.Info("audit log: file", "path", cfg.Audit.File)
	} else {
		sink = audit.NewMemorySink()
		logger.Warn("audit log: in-memory (records are lost on restart; set audit.file for durability)")
	}

	// SIEM forwarding tap (Task 119): decorate the durable sink so every committed
	// record is also streamed to the external SIEM. The decorator forwards only
	// after the inner sink persists the record and never participates in the hash
	// chain (the Logger computes and chains the hash before calling Append), so the
	// local log's tamper-evidence is unaffected. When the forwarder is nil or audit
	// forwarding is disabled, WrapAuditSink returns the inner sink unchanged.
	sink = siem.WrapAuditSink(sink, siemFwd)

	opts := audit.Options{Key: []byte(key), Sink: sink}

	// Merkle transparency layer: signed checkpoints + inclusion/consistency
	// proofs on top of the hash chain. Enabled by default whenever auditing is on.
	var ckStore audit.CheckpointStore
	if !cfg.Audit.Transparency.Disabled {
		tOpts, store, cErr := buildAuditTransparency(cfg, logger)
		if cErr != nil {
			_ = sink.Close()
			return nil, noop, cErr
		}
		ckStore = store
		opts.Transparency = tOpts
	}

	l, err := audit.NewLogger(ctx, opts)
	if err != nil {
		_ = sink.Close()
		if ckStore != nil {
			_ = ckStore.Close()
		}
		return nil, noop, err
	}

	// Interval sealing: periodically seal a checkpoint so the latest signed tree
	// head never lags far behind the live log between batch-triggered seals.
	stopSealer := func() {}
	if l.TransparencyEnabled() && cfg.Audit.Transparency.SealInterval > 0 {
		stopSealer = startAuditSealer(ctx, l, cfg.Audit.Transparency.SealInterval, sealLeaderFn, logger)
	}

	closer := func() error {
		stopSealer()
		// Seal a final checkpoint so the on-disk log is fully covered at shutdown.
		if _, sealed, serr := l.Seal(context.Background()); serr != nil {
			logger.Error("audit: final checkpoint seal failed", "error", serr)
		} else if sealed {
			logger.Info("audit: sealed final checkpoint at shutdown")
		}
		err := sink.Close()
		if ckStore != nil {
			if cErr := ckStore.Close(); cErr != nil && err == nil {
				err = cErr
			}
		}
		return err
	}
	return l, closer, nil
}

// buildAuditTransparency assembles the Merkle transparency options: the
// checkpoint store (file-backed when a path can be derived, else in-memory) and
// the optional checkpoint signer loaded from operator-supplied key material.
func buildAuditTransparency(cfg *config.Config, logger *slog.Logger) (*audit.TransparencyOptions, audit.CheckpointStore, error) {
	tc := cfg.Audit.Transparency

	checkpointPath := tc.CheckpointFile
	if checkpointPath == "" && cfg.Audit.File != "" {
		checkpointPath = cfg.Audit.File + ".checkpoints"
	}

	var store audit.CheckpointStore
	if checkpointPath != "" {
		fs, err := audit.NewFileCheckpointStore(checkpointPath)
		if err != nil {
			return nil, nil, err
		}
		store = fs
		logger.Info("audit transparency: checkpoint file", "path", checkpointPath)
	} else {
		store = audit.NewMemoryCheckpointStore()
		logger.Warn("audit transparency: in-memory checkpoints (lost on restart; set audit.transparency.checkpointFile)")
	}

	opts := &audit.TransparencyOptions{
		Origin:    tc.Origin,
		SealEvery: tc.SealEvery,
		Store:     store,
	}

	switch {
	case tc.SigningKey != "":
		signer, err := audit.LoadSigner([]byte(tc.SigningKey))
		if err != nil {
			_ = store.Close()
			return nil, nil, err
		}
		opts.Signer = signer
		logger.Info("audit transparency: checkpoints signed", "keyId", signer.KeyID())
	case tc.SigningKeyFile != "":
		signer, err := audit.LoadSignerFile(tc.SigningKeyFile)
		if err != nil {
			_ = store.Close()
			return nil, nil, err
		}
		opts.Signer = signer
		logger.Info("audit transparency: checkpoints signed", "keyId", signer.KeyID(), "keyFile", tc.SigningKeyFile)
	default:
		logger.Warn("audit transparency: checkpoints unsigned (set audit.transparency.signingKey[File] to anchor them to a key)")
	}

	return opts, store, nil
}

// startAuditSealer seals a checkpoint on a fixed interval until ctx is cancelled,
// returning a stop function. It complements batch (SealEvery) sealing so the
// latest checkpoint stays fresh on a low-traffic log.
//
// leaderFn, when non-nil, gates the interval seal on HA coordination leadership
// (Task 56): in a multi-replica deployment only the lease-holder signs Merkle
// checkpoints, so the shared checkpoint store is written by one replica and
// signatures are not duplicated. The final shutdown seal (in the audit closer) is
// not gated, so every replica anchors its own on-disk log at exit.
func startAuditSealer(ctx context.Context, l *audit.Logger, interval time.Duration, leaderFn func() bool, logger *slog.Logger) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				if leaderFn != nil && !leaderFn() {
					logger.Debug("audit: skipping interval checkpoint seal; not coordination leader")
					continue
				}
				if _, _, err := l.Seal(ctx); err != nil && ctx.Err() == nil {
					logger.Error("audit: interval checkpoint seal failed", "error", err)
				}
			}
		}
	}()
	return func() { close(done) }
}

// buildEnforcer constructs the access-control enforcer (authentication, RBAC,
// quotas) from configuration. It returns a nil enforcer when auth is disabled,
// in which case the gateway serves every request anonymously.
func buildEnforcer(cfg *config.Config, mtlsAuth auth.Authenticator, logger *slog.Logger) (*auth.Enforcer, error) {
	if !cfg.Auth.Enabled {
		logger.Warn("client authentication disabled (set auth.enabled to require API tokens / OIDC)")
		return nil, nil
	}

	roles := make([]auth.Role, 0, len(cfg.Auth.Roles))
	for _, r := range cfg.Auth.Roles {
		roles = append(roles, auth.Role{Name: r.Name, Ecosystems: r.Ecosystems, Upstreams: r.Upstreams})
	}
	authorizer, err := auth.NewAuthorizer(roles)
	if err != nil {
		return nil, err
	}

	var chain auth.Chain
	// The mTLS workload-identity authenticator (Task 58) goes first so a verified
	// client certificate is preferred over a bearer token when both are presented;
	// it declines (falls through) cleanly when no client certificate is present.
	if mtlsAuth != nil {
		chain = append(chain, mtlsAuth)
		logger.Info("spiffe/mtls workload-identity authentication enabled")
	}
	if len(cfg.Auth.Tokens) > 0 {
		entries := make([]auth.TokenEntry, 0, len(cfg.Auth.Tokens))
		for _, t := range cfg.Auth.Tokens {
			entries = append(entries, auth.TokenEntry{
				Name:   t.Name,
				Team:   t.Team,
				Roles:  t.Roles,
				Secret: t.Token,
				Hash:   t.TokenHash,
			})
		}
		ta, terr := auth.NewTokenAuthenticator(entries)
		if terr != nil {
			return nil, terr
		}
		chain = append(chain, ta)
		logger.Info("token authentication enabled", "tokens", ta.Len())
	}
	if cfg.Auth.OIDC.Enabled {
		o := cfg.Auth.OIDC
		oa, oerr := auth.NewOIDCAuthenticator(auth.OIDCOptions{
			Issuer:       o.Issuer,
			Audience:     o.Audience,
			JWKSURL:      o.JWKSURL,
			StaticJWKS:   []byte(o.JWKS),
			JWKSCacheTTL: o.JWKSCacheTTL,
			Leeway:       o.Leeway,
			SubjectClaim: o.SubjectClaim,
			TeamClaim:    o.TeamClaim,
			RolesClaim:   o.RolesClaim,
			RoleMap:      o.RoleMap,
		})
		if oerr != nil {
			return nil, oerr
		}
		chain = append(chain, oa)
		logger.Info("oidc authentication enabled", "issuer", o.Issuer)
	}

	var authenticator auth.Authenticator
	if len(chain) > 0 {
		authenticator = chain
	}

	quota := auth.NewQuotaManager(auth.QuotaOptions{
		PerTeam: teamQuotas(cfg.Auth.Teams),
		Default: toQuota(cfg.Auth.DefaultQuota),
	})

	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{
		Authenticator:  authenticator,
		Authorizer:     authorizer,
		Quota:          quota,
		AllowAnonymous: cfg.Auth.AllowAnonymous,
		Anonymous: &auth.Principal{
			Subject: "anonymous",
			Team:    cfg.Auth.AnonymousTeam,
			Roles:   cfg.Auth.AnonymousRoles,
			Method:  "anonymous",
		},
	})
	if err != nil {
		return nil, err
	}
	logger.Info("access control enabled",
		"roles", len(roles),
		"cacheNamespacing", cfg.Auth.CacheNamespacing,
		"allowAnonymous", cfg.Auth.AllowAnonymous)
	return enforcer, nil
}

// clientMTLS bundles the artifacts produced when SPIFFE/mTLS client auth is
// enabled (Task 58): the authenticator wired into the auth chain, the reloadable
// trust-bundle source, the metrics accumulator exposed to Prometheus, and the
// TLS client-auth mode the listener must use. A nil *clientMTLS means mTLS is
// disabled; all methods are nil-safe so call sites need no branching.
type clientMTLS struct {
	authenticator  *spiffe.Authenticator
	source         *spiffe.BundleSource
	metrics        *spiffe.Metrics
	clientAuth     tls.ClientAuthType
	reloadInterval time.Duration
	expiryWarning  time.Duration
	stop           chan struct{}
}

// buildClientMTLS constructs the SPIFFE/mTLS authenticator from configuration.
// It returns (nil, nil) when mTLS is disabled.
func buildClientMTLS(cfg *config.Config, logger *slog.Logger) (*clientMTLS, error) {
	m := cfg.ClientAuth.MTLS
	if !m.Enabled {
		return nil, nil
	}

	source, err := spiffe.NewBundleSource(m.TrustBundle, spiffe.BundleFormat(strings.ToLower(strings.TrimSpace(m.TrustBundleFormat))), m.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("loading mTLS trust bundle: %w", err)
	}

	rules := make([]spiffe.Rule, 0, len(m.Rules))
	for _, r := range m.Rules {
		rules = append(rules, spiffe.Rule{Pattern: r.Pattern, Tenant: r.Tenant, Roles: r.Roles})
	}
	var overrides map[string][]spiffe.Rule
	if len(m.TenantOverrides) > 0 {
		overrides = make(map[string][]spiffe.Rule, len(m.TenantOverrides))
		for tenant, ors := range m.TenantOverrides {
			conv := make([]spiffe.Rule, 0, len(ors))
			for _, r := range ors {
				conv = append(conv, spiffe.Rule{Pattern: r.Pattern, Tenant: r.Tenant, Roles: r.Roles})
			}
			overrides[tenant] = conv
		}
	}
	policy, err := spiffe.NewPolicy(spiffe.RuleSet{
		Rules:           rules,
		DefaultTenant:   m.DefaultTenant,
		TenantOverrides: overrides,
	})
	if err != nil {
		return nil, fmt.Errorf("compiling mTLS identity-mapping policy: %w", err)
	}

	metrics := spiffe.NewMetrics(nil)
	authenticator, err := spiffe.NewAuthenticator(spiffe.Options{
		Source:              source,
		Policy:              policy,
		Metrics:             metrics,
		ExpiryWarning:       m.ExpiryWarning,
		AllowedTrustDomains: m.AllowedTrustDomains,
	})
	if err != nil {
		return nil, fmt.Errorf("building mTLS authenticator: %w", err)
	}

	logger.Info("spiffe/mtls client auth configured",
		"required", m.Required,
		"trustBundle", m.TrustBundle,
		"trustDomains", source.Current().Domains(),
		"rules", len(rules))

	return &clientMTLS{
		authenticator:  authenticator,
		source:         source,
		metrics:        metrics,
		clientAuth:     spiffe.ClientAuthType(m.Required),
		reloadInterval: m.ReloadInterval,
		expiryWarning:  authenticator.ExpiryWarning(),
		stop:           make(chan struct{}),
	}, nil
}

// start launches the trust-bundle reload watcher (if a reload interval is
// configured) and arranges for it to stop when ctx is canceled.
func (c *clientMTLS) start(ctx context.Context, logger *slog.Logger) {
	if c == nil || c.reloadInterval <= 0 {
		return
	}
	go func() {
		<-ctx.Done()
		close(c.stop)
	}()
	go c.source.Watch(c.stop, c.reloadInterval, func(err error) {
		if err != nil {
			logger.Error("mTLS trust bundle reload failed", "error", err)
			return
		}
		logger.Info("mTLS trust bundle reloaded", "trustDomains", c.source.Current().Domains())
	})
}

// authenticatorOrNil returns the authenticator as an auth.Authenticator
// interface value, preserving a true nil (not a typed-nil) when mTLS is
// disabled so the enforcer correctly detects its absence.
func (c *clientMTLS) authenticatorOrNil() auth.Authenticator {
	if c == nil || c.authenticator == nil {
		return nil
	}
	return c.authenticator
}

// clientAuthType returns the TLS client-auth mode for the listener
// (tls.NoClientCert when mTLS is disabled).
func (c *clientMTLS) clientAuthType() tls.ClientAuthType {
	if c == nil {
		return tls.NoClientCert
	}
	return c.clientAuth
}

// metricsOrNil returns the metrics accumulator, or nil when mTLS is disabled.
func (c *clientMTLS) metricsOrNil() *spiffe.Metrics {
	if c == nil {
		return nil
	}
	return c.metrics
}

// teamQuotas converts the per-team config quotas into the auth package form.
func teamQuotas(teams map[string]config.TeamConfig) map[string]auth.Quota {
	if len(teams) == 0 {
		return nil
	}
	out := make(map[string]auth.Quota, len(teams))
	for name, t := range teams {
		out[name] = toQuota(t.Quota)
	}
	return out
}

// toQuota converts a config QuotaConfig to an auth.Quota.
func toQuota(q config.QuotaConfig) auth.Quota {
	return auth.Quota{MaxRequests: q.MaxRequests, MaxBytes: q.MaxBytes, Window: q.Window}
}

// buildRateLimiter constructs the per-tenant/global rate-limit, concurrency, and
// byte-quota limiter (Task 24). It returns a nil limiter (and a no-op closer)
// when rate limiting is disabled, in which case the gateway serves every request
// unmetered. When shared coordination is requested and the cache is the S3
// backend, byte quotas are coordinated across replicas through a dedicated,
// separately-prefixed object-store namespace; the returned closer releases that
// store.
func buildRateLimiter(cfg *config.Config, logger *slog.Logger) (*ratelimit.Limiter, func() error, error) {
	noop := func() error { return nil }
	if !cfg.RateLimit.Enabled {
		return nil, noop, nil
	}

	var (
		store  ratelimit.Store
		closer = noop
	)
	if cfg.RateLimit.Shared {
		if cfg.Cache.Backend != "s3" {
			logger.Warn("rate-limit shared coordination requested but cache backend is not s3; falling back to per-replica in-memory counters")
		} else {
			s3 := cfg.Cache.S3
			prefix := "ratelimit"
			if p := strings.TrimRight(s3.Prefix, "/"); p != "" {
				prefix = p + "/ratelimit"
			}
			s3store, err := cache.NewS3Store(cache.S3Options{
				Endpoint:           s3.Endpoint,
				Region:             s3.Region,
				Bucket:             s3.Bucket,
				Prefix:             prefix,
				AccessKeyID:        s3.AccessKeyID,
				SecretAccessKey:    s3.SecretAccessKey,
				SessionToken:       s3.SessionToken,
				UsePathStyle:       s3.UsePathStyle,
				InsecureSkipVerify: s3.InsecureSkipVerify,
				MaxRetries:         s3.MaxRetries,
				SpoolDir:           s3.SpoolDir,
			})
			if err != nil {
				return nil, noop, fmt.Errorf("rate-limit shared store: %w", err)
			}
			store = ratelimit.NewCacheStore(s3store, nil)
			closer = s3store.Close
			logger.Info("rate-limit byte quotas coordinated via shared object store", "prefix", prefix)
		}
	}

	perTenant := tenantRatePolicies(cfg.Auth.Teams)
	lim := ratelimit.New(ratelimit.Options{
		Global:    toRatePolicy(cfg.RateLimit.Global),
		Default:   toRatePolicy(cfg.RateLimit.Default),
		PerTenant: perTenant,
		Store:     store,
	})
	logger.Info("rate limiting enabled",
		"perTenantPolicies", len(perTenant),
		"shared", store != nil)
	return lim, closer, nil
}

// tenantRatePolicies converts per-team rate-limit overrides into the ratelimit
// package form, skipping teams that declare no override.
func tenantRatePolicies(teams map[string]config.TeamConfig) map[string]ratelimit.Policy {
	if len(teams) == 0 {
		return nil
	}
	out := make(map[string]ratelimit.Policy, len(teams))
	for name, t := range teams {
		p := toRatePolicy(t.RateLimit)
		if p == (ratelimit.Policy{}) {
			continue // no override; the default policy applies
		}
		out[name] = p
	}
	return out
}

// toRatePolicy converts a config RateLimitPolicyConfig to a ratelimit.Policy.
func toRatePolicy(p config.RateLimitPolicyConfig) ratelimit.Policy {
	return ratelimit.Policy{
		RPS:           p.RPS,
		Burst:         p.Burst,
		MaxConcurrent: p.MaxConcurrent,
		ByteQuota:     p.ByteQuota,
		Window:        p.Window,
	}
}

// buildScanner constructs the LLM commit-scanning pipeline when scanning is
// enabled with an LLM provider. It returns a nil scanner (and a no-op closer)
// when scanning is disabled or the configured provider has no implementation
// yet, so the gateway runs without a scanner. The returned closer stops the
// async scan workers and the verdict store.
func buildScanner(ctx context.Context, cfg *config.Config, notifier *notify.Notifier, tracer *tracing.Tracer, logger *slog.Logger) (scan.Scanner, *secretscan.Detector, func() error, error) {
	noop := func() error { return nil }

	// The deterministic secret-detection pass (Task 29) is cheap and offline, so
	// it runs whenever scanning is enabled (default) or explicitly turned on,
	// even when no LLM provider is configured.
	detector, err := buildSecretDetector(cfg, logger)
	if err != nil {
		return nil, nil, noop, err
	}

	// The deterministic GitHub Actions pinning gate (Task 115) is likewise cheap
	// and offline; it runs whenever commit scanning is enabled (or explicitly
	// turned on), inspecting the `uses:` references in changed workflow files.
	actionSvc, err := buildActionScanner(cfg, logger)
	if err != nil {
		return nil, nil, noop, err
	}

	// Build the LLM provider when scanning is enabled and a usable provider is
	// configured. A missing/unimplemented provider is not fatal when the
	// deterministic detector can still run on its own.
	var provider commit.Provider
	if cfg.Scanning.Enabled {
		switch cfg.Scanning.Provider {
		case "claude":
			p, perr := commit.NewClaudeProvider(commit.ClaudeOptions{
				APIKey:     cfg.Scanning.APIKey,
				BaseURL:    cfg.Scanning.BaseURL,
				MaxRetries: cfg.Scanning.Commit.MaxRetries,
			})
			if perr != nil {
				return nil, nil, noop, fmt.Errorf("building claude provider: %w", perr)
			}
			provider = p
		case "openai", "codex":
			p, perr := commit.NewOpenAIProvider(commit.OpenAIOptions{
				APIKey:          cfg.Scanning.APIKey,
				BaseURL:         cfg.Scanning.BaseURL,
				APIVersion:      cfg.Scanning.APIVersion,
				ReasoningEffort: cfg.Scanning.ReasoningEffort,
				Timeout:         cfg.Scanning.Timeout,
				MaxRetries:      cfg.Scanning.Commit.MaxRetries,
			})
			if perr != nil {
				return nil, nil, noop, fmt.Errorf("building openai provider: %w", perr)
			}
			provider = p
		default:
			return nil, nil, noop, fmt.Errorf("unsupported scanning provider %q", cfg.Scanning.Provider)
		}
	}

	// Nothing to do: no LLM provider and no deterministic gate.
	if provider == nil && detector == nil && actionSvc == nil {
		logger.Info("scanning disabled")
		return nil, nil, noop, nil
	}

	var secretScanner commit.SecretScanner
	if detector != nil {
		secretScanner = &secretScanAdapter{d: detector}
	}
	var actionScanner commit.ActionScanner
	if actionSvc != nil {
		actionScanner = &actionScanAdapter{s: actionSvc}
	}

	store, closeStore, err := buildVerdictStore(cfg, logger)
	if err != nil {
		return nil, nil, noop, err
	}

	cc := cfg.Scanning.Commit

	// When the OpenAI/Codex provider is selected but no models are configured,
	// fall back to OpenAI defaults rather than the pipeline's Claude defaults
	// (which the OpenAI endpoint would reject). An explicit model is always
	// honored.
	if cfg.Scanning.Provider == "openai" || cfg.Scanning.Provider == "codex" {
		if strings.TrimSpace(cc.TriageModel) == "" {
			cc.TriageModel = commit.DefaultOpenAITriageModel
		}
		if strings.TrimSpace(cc.DeepModel) == "" {
			cc.DeepModel = commit.DefaultOpenAIDeepModel
		}
	}

	// Multi-provider consensus (Task 78): build any additional providers that
	// participate in the deep pass alongside the primary provider.
	consensus, err := buildConsensusMembers(cc.Consensus, logger)
	if err != nil {
		_ = closeStore()
		return nil, nil, noop, err
	}

	// Per-tenant cost budgeting (Task 78).
	var budgeter *commit.Budgeter
	pricing := commit.DefaultPricing()
	if len(cc.Budget.Pricing) > 0 {
		pricing = pricing.WithOverrides(modelPriceOverrides(cc.Budget.Pricing))
	}
	if cc.Budget.Enabled {
		budgeter = commit.NewBudgeter(commit.BudgetPolicy{
			DefaultCeilingUSD: cc.Budget.DefaultCeilingUSD,
			TenantCeilingsUSD: cc.Budget.TenantCeilingsUSD,
			Window:            cc.Budget.Window,
			FailOpen:          cc.Budget.FailOpen,
		})
	}

	// Ruleset hash: fold the deterministic secret rules into the verdict cache key
	// so changing the rule set forces a re-scan rather than serving stale verdicts.
	var rulesetToken string
	if detector != nil {
		rulesetToken = strings.Join(detector.Rules(), ",")
	}
	if actionSvc != nil {
		// Fold the action-pinning policy into the verdict cache key so a change to
		// the allowlist or thresholds forces a re-scan rather than a stale hit.
		rulesetToken += "|actionpin:" + actionSvc.CacheSignature()
	}

	pipeline, err := commit.New(provider, store, commit.Config{
		TriageModel:        cc.TriageModel,
		DeepModel:          cc.DeepModel,
		EscalateAtScore:    cc.EscalateAtScore,
		MaxDiffTokens:      cc.MaxDiffTokens,
		MaxChunks:          cc.MaxChunks,
		MaxRetries:         cc.MaxRetries,
		Workers:            cc.Workers,
		QueueSize:          cc.QueueSize,
		Secrets:            secretScanner,
		Actions:            actionScanner,
		Tracer:             tracer,
		OnVerdict:          commitVerdictNotifier(notifier),
		Consensus:          consensus,
		Quorum:             cc.Quorum,
		Budgeter:           budgeter,
		Pricing:            pricing,
		OnBudgetExhausted:  commitBudgetNotifier(notifier),
		RulesetHash:        rulesetToken,
		InjectionRiskFloor: cc.InjectionRiskFloor,
		RetentionTTL:       cc.RetentionTTL,
		RetentionInterval:  cc.RetentionInterval,
	}, logger)
	if err != nil {
		_ = closeStore()
		return nil, nil, noop, fmt.Errorf("building scan pipeline: %w", err)
	}
	pipeline.Start(ctx)

	closer := func() error {
		err := pipeline.Close()
		if serr := closeStore(); serr != nil && err == nil {
			err = serr
		}
		return err
	}
	switch {
	case provider != nil && detector != nil:
		logger.Info("commit scanning enabled", "provider", provider.Name(),
			"deterministicSecrets", true, "secretRules", len(detector.Rules()))
	case provider != nil:
		logger.Info("commit scanning enabled", "provider", provider.Name(), "deterministicSecrets", false)
	default:
		logger.Info("commit scanning enabled (deterministic-only, no LLM provider)",
			"secretRules", secretRuleCount(detector), "actionPinning", actionSvc != nil)
	}
	return commit.NewScanner(pipeline, scan.Severity(cfg.Scanning.FailOn)), detector, closer, nil
}

// buildConsensusMembers constructs the additional providers that participate in
// the multi-provider consensus deep pass (Task 78). An empty config yields nil
// (single-provider mode).
func buildConsensusMembers(cfgs []config.ConsensusProviderConfig, logger *slog.Logger) ([]commit.ConsensusMember, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	members := make([]commit.ConsensusMember, 0, len(cfgs))
	for _, c := range cfgs {
		if strings.TrimSpace(c.Model) == "" {
			return nil, fmt.Errorf("scanning consensus provider %q requires a model", c.Provider)
		}
		switch c.Provider {
		case "claude", "":
			p, err := commit.NewClaudeProvider(commit.ClaudeOptions{APIKey: c.APIKey, BaseURL: c.BaseURL})
			if err != nil {
				return nil, fmt.Errorf("building consensus claude provider: %w", err)
			}
			members = append(members, commit.ConsensusMember{Provider: p, Model: c.Model})
		case "openai", "codex":
			p, err := commit.NewOpenAIProvider(commit.OpenAIOptions{APIKey: c.APIKey, BaseURL: c.BaseURL})
			if err != nil {
				return nil, fmt.Errorf("building consensus openai provider: %w", err)
			}
			members = append(members, commit.ConsensusMember{Provider: p, Model: c.Model})
		default:
			return nil, fmt.Errorf("unsupported consensus provider %q", c.Provider)
		}
	}
	logger.Info("commit-scan multi-provider consensus enabled", "members", len(members))
	return members, nil
}

// modelPriceOverrides converts the config price table to the commit package type.
func modelPriceOverrides(in map[string]config.ModelPriceConfig) map[string]commit.ModelPrice {
	out := make(map[string]commit.ModelPrice, len(in))
	for model, p := range in {
		out[model] = commit.ModelPrice{InputPerMTok: p.InputPerMTok, OutputPerMTok: p.OutputPerMTok}
	}
	return out
}

// commitBudgetNotifier returns the pipeline OnBudgetExhausted hook that emits a
// notification when a tenant exhausts its commit-scan cost budget (Task 78). It
// returns nil when no notifier is configured.
func commitBudgetNotifier(n *notify.Notifier) func(context.Context, string, bool) {
	if n == nil {
		return nil
	}
	return func(ctx context.Context, tenant string, failOpen bool) {
		n.Emit(ctx, notify.CostBudgetEvent(tenant, failOpen))
	}
}

// secretScanAdapter adapts a *secretscan.Detector to the commit.SecretScanner
// interface, converting between the two packages' types so the commit pipeline
// stays decoupled from the detection implementation.
type secretScanAdapter struct {
	d *secretscan.Detector
}

func (a *secretScanAdapter) ScanCommit(c *commit.Commit) []commit.SecretFinding {
	if len(c.Files) == 0 {
		return nil
	}
	files := make([]secretscan.FileInput, 0, len(c.Files))
	for _, f := range c.Files {
		files = append(files, secretscan.FileInput{Path: f.Path, Patch: f.Patch, Binary: f.Binary})
	}
	findings := a.d.ScanFiles(files)
	if len(findings) == 0 {
		return nil
	}
	out := make([]commit.SecretFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, commit.SecretFinding{
			RuleID:      f.RuleID,
			Description: f.Description,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Match:       f.Match,
		})
	}
	return out
}

// buildSecretDetector constructs the deterministic secret detector from config,
// returning nil when secret detection is disabled. Detection defaults to enabled
// wherever scanning is enabled (it is cheap and offline); it can also be enabled
// explicitly to run without an LLM provider.
func buildSecretDetector(cfg *config.Config, logger *slog.Logger) (*secretscan.Detector, error) {
	sc := cfg.Scanning.Secrets
	enabled := cfg.Scanning.Enabled
	if sc.Enabled != nil {
		enabled = *sc.Enabled
	}
	if !enabled {
		return nil, nil
	}

	rules, err := secretscan.CompileRules(toRuleSpecs(sc.Rules))
	if err != nil {
		return nil, fmt.Errorf("compiling secret rules: %w", err)
	}
	allow, err := secretscan.AllowlistSpec{
		DisableBuiltins: sc.Allowlist.DisableBuiltins,
		Paths:           sc.Allowlist.Paths,
		Patterns:        sc.Allowlist.Patterns,
		StopWords:       sc.Allowlist.StopWords,
		Fingerprints:    sc.Allowlist.Fingerprints,
	}.Compile()
	if err != nil {
		return nil, fmt.Errorf("compiling secret allowlist: %w", err)
	}

	entropy := secretscan.EntropyConfig{
		MinLength:     sc.Entropy.MinLength,
		MaxLength:     sc.Entropy.MaxLength,
		Base64Entropy: sc.Entropy.Base64Entropy,
		HexEntropy:    sc.Entropy.HexEntropy,
		Severity:      sc.Entropy.Severity,
	}
	if sc.Entropy.Enabled != nil && !*sc.Entropy.Enabled {
		entropy = secretscan.EntropyConfigDisabled()
	} else {
		entropy.Enabled = true
	}

	detector := secretscan.New(secretscan.Config{
		Rules:              rules,
		DisableBuiltins:    sc.DisableBuiltinRules,
		Entropy:            entropy,
		Allowlist:          allow,
		RevealPrefix:       sc.RevealPrefix,
		MaxFindingsPerFile: sc.MaxFindingsPerFile,
	})
	logger.Info("deterministic secret detection enabled", "rules", len(detector.Rules()))
	return detector, nil
}

// toRuleSpecs converts config rule entries to secretscan rule specs.
func toRuleSpecs(rules []config.SecretRuleConfig) []secretscan.RuleSpec {
	if len(rules) == 0 {
		return nil
	}
	out := make([]secretscan.RuleSpec, 0, len(rules))
	for _, r := range rules {
		out = append(out, secretscan.RuleSpec{
			ID:          r.ID,
			Description: r.Description,
			Severity:    r.Severity,
			Pattern:     r.Pattern,
			Group:       r.Group,
			Keywords:    r.Keywords,
			MinEntropy:  r.MinEntropy,
		})
	}
	return out
}

// secretRuleCount returns the active secret-rule count, or 0 when no detector is
// configured (deterministic-only mode may run on the action scanner alone).
func secretRuleCount(d *secretscan.Detector) int {
	if d == nil {
		return 0
	}
	return len(d.Rules())
}

// actionScanAdapter adapts an *actionpin.Service to the commit.ActionScanner
// interface. It extracts the added lines of each changed workflow / composite-
// action file from the commit diff (so only newly-introduced references are
// flagged) and converts the resulting report back to commit action findings.
type actionScanAdapter struct {
	s *actionpin.Service
}

func (a *actionScanAdapter) ScanCommit(c *commit.Commit) []commit.ActionFinding {
	if len(c.Files) == 0 {
		return nil
	}
	var files []actionpin.FileInput
	for _, f := range c.Files {
		if f.Binary || !actionpin.IsActionsFile(f.Path) {
			continue
		}
		added := secretscan.AddedLines(f.Patch)
		if len(added) == 0 {
			continue
		}
		lines := make([]actionpin.Line, 0, len(added))
		for _, ln := range added {
			lines = append(lines, actionpin.Line{Number: ln.Line, Text: ln.Text})
		}
		files = append(files, actionpin.FileInput{Path: f.Path, Lines: lines})
	}
	if len(files) == 0 {
		return nil
	}
	report := a.s.Assess(actionpin.Artifact{Repository: c.RepositoryURL, CommitSHA: c.SHA}, files)
	if !report.HasFindings() {
		return nil
	}
	out := make([]commit.ActionFinding, 0, len(report.Findings))
	for _, f := range report.Findings {
		out = append(out, commit.ActionFinding{
			RuleID:      f.RuleID,
			Title:       f.Title,
			Description: f.Detail,
			Severity:    string(f.Severity),
			File:        f.File,
			Line:        f.Line,
			Reference:   f.Reference,
		})
	}
	return out
}

// buildActionScanner constructs the deterministic GitHub Actions pinning gate
// from config, returning nil when it is disabled. Like secret detection, it
// defaults to enabled wherever scanning is enabled (cheap and offline) and can
// be enabled explicitly to run without an LLM provider.
func buildActionScanner(cfg *config.Config, logger *slog.Logger) (*actionpin.Service, error) {
	ac := cfg.Scanning.Actions
	enabled := cfg.Scanning.Enabled
	if ac.Enabled != nil {
		enabled = *ac.Enabled
	}
	if !enabled {
		return nil, nil
	}

	build := actionpin.DefaultConfig()
	build.Enabled = true
	if ac.FailSeverity != "" {
		build.FailSeverity = actionpin.Severity(strings.ToLower(ac.FailSeverity))
	}
	// WarnSeverity is special: an explicit empty value disables warnings, so only
	// override the default when the operator set it.
	if ac.WarnSeverity != "" {
		build.WarnSeverity = actionpin.Severity(strings.ToLower(ac.WarnSeverity))
	}
	if ac.Action != "" {
		build.Action = actionpin.Action(strings.ToLower(ac.Action))
	}
	if ac.RequirePinning != nil {
		build.RequirePinning = *ac.RequirePinning
	}
	build.AllowedOwners = ac.AllowedOwners
	if ac.MaxFindings != 0 {
		build.MaxFindings = ac.MaxFindings
	}
	if len(ac.Tenants) > 0 {
		build.Tenants = make(map[string]actionpin.TenantConfig, len(ac.Tenants))
		for id, t := range ac.Tenants {
			build.Tenants[id] = actionpin.TenantConfig{
				FailSeverity: actionpin.Severity(strings.ToLower(t.FailSeverity)),
				WarnSeverity: actionpin.Severity(strings.ToLower(t.WarnSeverity)),
				Action:       actionpin.Action(strings.ToLower(t.Action)),
			}
		}
	}

	svc, err := actionpin.NewService(build)
	if err != nil {
		return nil, fmt.Errorf("building actionpin gate: %w", err)
	}
	logger.Info("GitHub Actions pinning gate enabled",
		"failSeverity", build.FailSeverity, "action", build.Action,
		"allowedOwners", len(build.AllowedOwners), "requirePinning", build.RequirePinning)
	return svc, nil
}

// buildVerdictStore constructs the persistent (filesystem) verdict store when a
// directory is configured, falling back to an in-memory store otherwise.
func buildVerdictStore(cfg *config.Config, logger *slog.Logger) (commit.VerdictStore, func() error, error) {
	if dir := cfg.Scanning.Commit.StoreDir; dir != "" {
		store, err := commit.NewFileStore(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("building verdict store: %w", err)
		}
		logger.Info("verdict store: filesystem", "dir", dir)
		return store, store.Close, nil
	}
	logger.Warn("verdict store: in-memory (verdicts are lost on restart; set scanning.commit.storeDir for durability)")
	store := commit.NewMemoryStore()
	return store, store.Close, nil
}

// buildProvenance constructs the package->commit provenance service when
// provenance association is enabled. It wires an attestation verifier (with the
// configured trust roots), an ecosystem-appropriate resolver per enabled
// upstream (npm/pip/go metadata + OCI cosign attestations), a GitHub
// build-provenance enricher, a durable link store, and a join to the commit scan
// verdicts so a consumed package's risk can be surfaced against its source
// commit. It returns a nil service (and no-op closer) when disabled.
func buildProvenance(cfg *config.Config, registry *backends.Registry, scanner scan.Scanner, egressGuard *egress.Guard, pinGuard *tlspin.Guard, logger *slog.Logger) (*provenance.Service, func() error, error) {
	noop := func() error { return nil }
	if !cfg.Provenance.Enabled {
		logger.Info("provenance association disabled (set provenance.enabled to link packages to source commits)")
		return nil, noop, nil
	}

	roots, err := buildTrustRoots(cfg.Provenance)
	if err != nil {
		return nil, noop, err
	}
	if roots == nil {
		logger.Warn("provenance: no attestation trust roots configured; signed attestations will be labeled 'claimed', not 'attested' (set provenance.trustRootsFile to the Fulcio/corporate root, or provenance.useSystemTrustRoots)")
	}
	verifier := provenance.NewVerifier(roots)

	metaVerifyConn, err := pinGuard.VerifierFor(tlspin.EndpointConfig{
		Pins:       cfg.Outbound.TLS.Pins,
		ReportOnly: cfg.Outbound.TLS.PinReportOnly,
	})
	if err != nil {
		return nil, noop, fmt.Errorf("provenance: outbound tls pinning: %w", err)
	}
	metaOpts := upstream.Options{
		TLS: upstream.TLSOptions{
			CACertFile:         cfg.Outbound.TLS.CACertFile,
			InsecureSkipVerify: cfg.Outbound.TLS.InsecureSkipVerify,
			MinVersion:         cfg.Outbound.TLS.MinVersion,
			VerifyConnection:   metaVerifyConn,
		},
		// Apply the same tuned transport settings as the main fetch path so the
		// provenance metadata client shares the connection-reuse profile.
		DialTimeout:           cfg.Outbound.DialTimeout,
		ResponseHeaderTimeout: cfg.Outbound.ResponseHeaderTimeout,
		IdleConnTimeout:       cfg.Outbound.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.Outbound.TLSHandshakeTimeout,
		MaxIdleConns:          cfg.Outbound.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.Outbound.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.Outbound.MaxConnsPerHost,
		KeepAlive:             cfg.Outbound.KeepAlive,
		ExpectContinueTimeout: cfg.Outbound.ExpectContinueTimeout,
		DisableKeepAlives:     cfg.Outbound.DisableKeepAlives,
		DisableHTTP2:          cfg.Outbound.DisableHTTP2,
		UserAgent:             cfg.Outbound.UserAgent,
	}
	applyEgressHooks(&metaOpts, egressGuard)
	metaClient, err := upstream.New(metaOpts)
	if err != nil {
		return nil, noop, fmt.Errorf("provenance: building metadata client: %w", err)
	}

	var (
		resolvers []provenance.Resolver
		goAdded   bool
	)
	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() {
			continue
		}
		creds := upstream.Credentials{
			Username: up.Credentials.Username,
			Password: up.Credentials.Password,
			Token:    up.Credentials.Token,
		}
		switch up.Type {
		case "npm":
			resolvers = append(resolvers, provenance.ForEcosystems(
				provenance.NewNPMResolver(metaClient, verifier, up.URL, creds), "npm"))
		case "pip":
			resolvers = append(resolvers, provenance.ForEcosystems(
				provenance.NewPyPIResolver(metaClient, hostBaseURL(up.URL), creds), "pip", "pypi"))
		case "go":
			if !goAdded {
				resolvers = append(resolvers, provenance.ForEcosystems(provenance.NewGoResolver(), "go"))
				goAdded = true
			}
		case "docker":
			if b, ok := registry.Get(name); ok {
				if fetcher, ok := b.(provenance.RegistryFetcher); ok {
					resolvers = append(resolvers, provenance.ForEcosystems(
						provenance.NewOCIResolver(fetcher, verifier), "docker", "oci"))
				}
			}
		}
	}
	// GitHub build-provenance enricher runs last (across ecosystems) so a claimed
	// repository discovered above can be upgraded to an attested commit.
	resolvers = append(resolvers, provenance.NewGitHubResolver(
		metaClient, verifier, cfg.Provenance.GitHubAPIBase, cfg.Provenance.GitHubToken))

	store, closeStore, err := buildLinkStore(cfg, logger)
	if err != nil {
		return nil, noop, err
	}

	pins, err := buildProvenancePins(cfg.Provenance.Pins)
	if err != nil {
		_ = closeStore()
		return nil, noop, err
	}

	svc := provenance.NewService(provenance.ServiceOptions{
		Resolvers: resolvers,
		Pins:      pins,
		Store:     store,
		Verdicts:  verdictLookup(scanner),
		Logger:    logger,
	})
	logger.Info("provenance association enabled",
		"resolvers", len(resolvers),
		"pins", pins.Len(),
		"requireAttested", cfg.Provenance.RequireAttested,
		"trustRoots", roots != nil)
	return svc, closeStore, nil
}

// buildProvenancePins converts the configured operator pins (package -> source
// commit assertions) into the provenance service's validated pin set.
func buildProvenancePins(cfgPins []config.ProvenancePin) (*provenance.PinSet, error) {
	pins := make([]provenance.Pin, 0, len(cfgPins))
	for _, p := range cfgPins {
		pins = append(pins, provenance.Pin{
			Ecosystem:  p.Ecosystem,
			Name:       p.Name,
			Version:    p.Version,
			Repository: p.Repository,
			Commit:     p.Commit,
		})
	}
	set, err := provenance.NewPinSet(pins)
	if err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	return set, nil
}

// buildPolicy constructs the admission-policy engine (Task 9) when policy
// enforcement is enabled. It wires an assessment source over the provenance
// Service so the engine can gate artifacts on provenance confidence,
// signature/attestation state, and the source commit's scan verdict. It returns
// nil when policy is disabled, in which case the gateway serves every artifact.
func buildPolicy(cfg *config.Config, provService *provenance.Service, logger *slog.Logger) *policy.Engine {
	if !cfg.Policy.Enabled {
		logger.Info("admission policy disabled (set policy.enabled to gate serving on scan/provenance)")
		return nil
	}

	var source policy.AssessmentSource
	if provService != nil {
		source = &provenanceAssessor{svc: provService}
	} else {
		logger.Warn("admission policy enabled without provenance; risk/signature checks cannot fire (only allow/deny lists and missing-provenance handling apply). Set provenance.enabled.")
	}

	engine := policy.New(toPolicyConfig(cfg.Policy), source, logger)
	logger.Info("admission policy enabled",
		"failClosed", cfg.Policy.FailClosed,
		"ecosystems", len(cfg.Policy.Ecosystems))
	return engine
}

// toPolicyConfig converts the config representation of the policy into the
// policy package's Config.
func toPolicyConfig(p config.PolicyConfig) policy.Config {
	cfg := policy.Config{
		FailClosed: p.FailClosed,
		Default:    toPolicyRule(p.Default),
	}
	if len(p.Ecosystems) > 0 {
		cfg.Ecosystems = make(map[string]policy.Rule, len(p.Ecosystems))
		for eco, r := range p.Ecosystems {
			cfg.Ecosystems[eco] = toPolicyRule(r)
		}
	}
	return cfg
}

// toPolicyRule converts a single config policy rule.
func toPolicyRule(r config.PolicyRule) policy.Rule {
	return policy.Rule{
		BlockAtRiskScore:    r.BlockAtRiskScore,
		WarnAtRiskScore:     r.WarnAtRiskScore,
		BlockMalicious:      r.BlockMalicious,
		OnMissingProvenance: policy.Action(r.OnMissingProvenance),
		OnMissingScan:       policy.Action(r.OnMissingScan),
		RequireSignature:    r.RequireSignature,
		RequireAttested:     r.RequireAttested,
		MinConfidence:       r.MinConfidence,
		OnLowConfidence:     policy.Action(r.OnLowConfidence),
		Allowlist:           r.Allowlist,
		Denylist:            r.Denylist,
	}
}

// buildPolicyEngine constructs the declarative policy-as-code admission engine
// (Task 32) when enabled. It loads operator-authored rule bundles from the
// configured directory (layered over the embedded default bundle), in either
// enforce or audit (dry-run) mode, with optional hot-reload polling. It returns
// nil when the engine is disabled, in which case only the hard-coded gates apply.
func buildPolicyEngine(cfg *config.Config, logger *slog.Logger) (*policyengine.Engine, error) {
	pe := cfg.PolicyEngine
	if !pe.Enabled {
		logger.Info("policy-as-code engine disabled (set policyEngine.enabled to evaluate declarative admission rules)")
		return nil, nil
	}

	mode := policyengine.ModeEnforce
	if strings.EqualFold(strings.TrimSpace(pe.Mode), string(policyengine.ModeAudit)) {
		mode = policyengine.ModeAudit
	}
	// Default to including the embedded bundle unless explicitly disabled.
	includeDefault := true
	if pe.IncludeDefaultBundle != nil {
		includeDefault = *pe.IncludeDefaultBundle
	}

	engine, err := policyengine.New(policyengine.Config{
		Dir:                  pe.Dir,
		Mode:                 mode,
		DefaultAction:        policyengine.Action(strings.ToLower(strings.TrimSpace(pe.DefaultAction))),
		IncludeDefaultBundle: includeDefault,
		ReloadInterval:       pe.ReloadInterval,
		Logger:               logger,
	})
	if err != nil {
		return nil, fmt.Errorf("policy-as-code engine: %w", err)
	}
	snap := engine.Snapshot()
	logger.Info("policy-as-code engine enabled",
		"mode", mode,
		"dir", pe.Dir,
		"bundles", snap.BundlesLoaded,
		"rules", snap.RulesLoaded,
		"reloadInterval", pe.ReloadInterval)
	return engine, nil
}

// buildVulnScanner constructs the vulnerability-scanning Service (Task 15) when
// enabled: it selects the database backend (OSV by default, behind the pluggable
// Scanner interface), wires the result cache TTL / offline fallback, and
// translates the configured severity/CVSS thresholds and action into the gate
// config. It returns nil when scanning is disabled, in which case the gateway
// serves artifacts without a vulnerability check.
func buildVulnScanner(cfg *config.Config, logger *slog.Logger) (*vulnscan.Service, error) {
	vc := cfg.Vulnerabilities
	if !vc.Enabled {
		logger.Info("vulnerability scanning disabled (set vulnerabilities.enabled to generate SBOMs and gate on CVEs)")
		return nil, nil
	}

	var scanner vulnscan.Scanner
	if !vc.Offline {
		timeout := vc.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		// OSV is the only built-in backend; config validation has already rejected
		// an unsupported/unbuilt scanner selection.
		scanner = vulnscan.NewOSVScanner(vc.OSVBaseURL,
			vulnscan.WithOSVHTTPClient(&http.Client{Timeout: timeout}))
	}

	ttl := vc.CacheTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	vexStore, err := buildVEXStore(vc, logger)
	if err != nil {
		return nil, fmt.Errorf("vulnscan: %w", err)
	}

	svc, err := vulnscan.NewService(vulnscan.Config{
		CacheTTL:        ttl,
		CacheMaxEntries: vc.CacheMaxEntries,
		Timeout:         vc.Timeout,
		Offline:         vc.Offline,
		FailSeverity:    vulnscan.NormalizeSeverityConfig(vc.FailSeverity),
		FailCVSS:        vc.FailCVSS,
		WarnSeverity:    vulnscan.NormalizeSeverityConfig(vc.WarnSeverity),
		Action:          policy.Action(vc.Action),
		FailOnError:     vc.FailOnError,
		IgnoreIDs:       vc.IgnoreIDs,
		VEX:             vexStore,
		Reachability: vulnscan.ReachabilityConfig{
			Enabled:           vc.Reachability.Enabled,
			UnreachableAction: vulnscan.NormalizeReachabilityAction(vc.Reachability.UnreachableAction),
		},
	}, scanner, logger)
	if err != nil {
		return nil, fmt.Errorf("vulnscan: %w", err)
	}
	logger.Info("vulnerability scanning enabled",
		"scanner", svc.ScannerName(),
		"failSeverity", vc.FailSeverity,
		"failCvss", vc.FailCVSS,
		"action", svc.GateAction(),
		"cacheTtl", ttl,
		"offline", vc.Offline,
		"reachability", vc.Reachability.Enabled)
	return svc, nil
}

// buildVEXStore constructs the VEX store (Task 27) when VEX processing is enabled:
// it loads statements from the configured directory (the air-gapped source) and,
// unless the subsystem is offline, wires an optional per-artifact HTTP fetcher. It
// returns nil when VEX is disabled, in which case scan findings are gated as-is.
func buildVEXStore(vc config.VulnConfig, logger *slog.Logger) (*vulnscan.VEXStore, error) {
	if !vc.VEX.Enabled {
		return nil, nil
	}

	var opts []vulnscan.VEXStoreOption
	opts = append(opts, vulnscan.WithVEXOffline(vc.Offline))
	if !vc.Offline && strings.TrimSpace(vc.VEX.FetchURL) != "" {
		fetcher, err := vulnscan.NewHTTPVEXFetcher(vc.VEX.FetchURL)
		if err != nil {
			return nil, fmt.Errorf("vex: %w", err)
		}
		opts = append(opts, vulnscan.WithVEXFetcher(fetcher))
	}

	store := vulnscan.NewVEXStore(logger, opts...)
	if dir := strings.TrimSpace(vc.VEX.Dir); dir != "" {
		if err := store.LoadDir(dir); err != nil {
			return nil, fmt.Errorf("vex: loading %s: %w", dir, err)
		}
	}
	stats := store.Stats()
	logger.Info("vex suppression enabled",
		"dir", vc.VEX.Dir,
		"documents", stats.Documents,
		"statements", stats.Statements,
		"malformed", stats.Malformed,
		"fetchUrl", vc.VEX.FetchURL,
		"offline", vc.Offline)
	return store, nil
}

// buildNameguard constructs the typosquatting & dependency-confusion guard
// (Task 19) from config. It returns nil when the subsystem is disabled, in which
// case the gateway serves package names unchecked. Homoglyph detection defaults
// on unless explicitly disabled.
func buildNameguard(cfg *config.Config, logger *slog.Logger) *nameguard.Service {
	nc := cfg.Nameguard
	if !nc.Enabled {
		logger.Info("nameguard disabled (set nameguard.enabled to detect typosquatting and dependency confusion)")
		return nil
	}
	detectHomoglyphs := true
	if nc.DetectHomoglyphs != nil {
		detectHomoglyphs = *nc.DetectHomoglyphs
	}
	svc := nameguard.NewService(nameguard.Config{
		PopularNames:       nc.PopularNames,
		InternalNamespaces: nc.InternalNamespaces,
		Allowlist:          nc.Allowlist,
		DisableBuiltins:    nc.DisableBuiltins,
		DistanceThreshold:  nc.DistanceThreshold,
		MinNameLength:      nc.MinNameLength,
		FailSeverity:       nameguard.NormalizeSeverity(nc.FailSeverity),
		WarnSeverity:       nameguard.NormalizeSeverity(nc.WarnSeverity),
		Action:             policy.Action(nc.Action),
		DetectHomoglyphs:   detectHomoglyphs,
	}, logger)
	internalCount := 0
	for _, names := range nc.InternalNamespaces {
		internalCount += len(names)
	}
	logger.Info("nameguard enabled",
		"action", svc.GateAction(),
		"failSeverity", nc.FailSeverity,
		"internalNamespaces", internalCount,
		"homoglyphs", detectHomoglyphs)
	return svc
}

// buildMalfeed constructs the known-malicious-package admission gate (Task 48)
// from config. It returns nil when the subsystem is disabled. When configured it
// imports an offline signed bundle at startup (for air-gapped operation) and
// wires the live HTTP feed sources; the background refresh loop is started by the
// caller via Start. The gate is inert (fails open with an empty matcher) until a
// feed or bundle supplies data.
func buildMalfeed(cfg *config.Config, logger *slog.Logger) (*malfeed.Service, error) {
	mc := cfg.Malfeed
	if !mc.Enabled {
		logger.Info("malfeed disabled (set malfeed.enabled to block known-malicious packages)")
		return nil, nil
	}

	sources := make([]malfeed.FeedSource, 0, len(mc.Sources))
	for _, s := range mc.Sources {
		sources = append(sources, malfeed.FeedSource{URL: s.URL, Name: s.Name})
	}

	var initial []malfeed.Entry
	loaded := false
	if mc.BundlePath != "" {
		var trusted ed25519.PublicKey
		if mc.BundlePublicKeyFile != "" {
			pem, err := os.ReadFile(mc.BundlePublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("malfeed: read bundle public key: %w", err)
			}
			trusted, err = malfeed.LoadVerifierPEM(pem)
			if err != nil {
				return nil, err
			}
		}
		data, err := os.ReadFile(mc.BundlePath)
		if err != nil {
			return nil, fmt.Errorf("malfeed: read offline bundle: %w", err)
		}
		entries, err := malfeed.ImportBundle(data, trusted)
		if err != nil {
			return nil, fmt.Errorf("malfeed: import offline bundle: %w", err)
		}
		initial = entries
		loaded = true
		logger.Info("malfeed offline bundle imported",
			"path", mc.BundlePath, "entries", len(entries), "pinnedKey", mc.BundlePublicKeyFile != "")
	}

	svc := malfeed.NewService(malfeed.Config{
		Sources:             sources,
		RefreshInterval:     mc.RefreshInterval,
		StaleAfter:          mc.StaleAfter,
		FailClosedWhenStale: mc.FailClosed,
		Timeout:             mc.Timeout,
		InitialEntries:      initial,
		InitialLoaded:       loaded,
		Logger:              logger,
	})
	logger.Info("malfeed enabled (known-malicious-package gate)",
		"sources", len(sources),
		"refreshInterval", mc.RefreshInterval,
		"staleAfter", mc.StaleAfter,
		"failClosed", mc.FailClosed,
		"seedEntries", len(initial))
	return svc, nil
}

// buildMaturity constructs the release-maturity / version-cooldown admission gate
// (Task 61) from config. It returns nil when the subsystem is disabled. When
// enabled it wires the live HTTP publish-timestamp resolver (which queries each
// ecosystem's public registry metadata, with optional per-ecosystem base-URL
// overrides for private mirrors). The gate is inert until a positive cooldown is
// configured.
func buildMaturity(cfg *config.Config, logger *slog.Logger) *maturity.Service {
	mc := cfg.Maturity
	if !mc.Enabled {
		logger.Info("maturity gate disabled (set maturity.enabled to quarantine newly-published versions)")
		return nil
	}

	tenants := make(map[string]maturity.TenantConfig, len(mc.Tenants))
	for id, t := range mc.Tenants {
		tc := maturity.TenantConfig{
			Ecosystems: cloneDurMap(t.Ecosystems),
			Allowlist:  append([]string(nil), t.Allowlist...),
		}
		if t.DefaultCooldown != 0 {
			d := t.DefaultCooldown
			tc.DefaultCooldown = &d
		}
		tenants[id] = tc
	}

	resolver := maturity.NewHTTPResolver(&http.Client{Timeout: mc.Timeout}, mc.UserAgent)
	if len(mc.BaseURLs) > 0 {
		resolver.BaseURLs = make(map[string]string, len(mc.BaseURLs))
		for eco, u := range mc.BaseURLs {
			resolver.BaseURLs[strings.ToLower(strings.TrimSpace(eco))] = u
		}
	}

	svc := maturity.NewService(maturity.Config{
		DefaultCooldown:     mc.DefaultCooldown,
		Ecosystems:          cloneDurMap(mc.Ecosystems),
		Tenants:             tenants,
		Allowlist:           append([]string(nil), mc.Allowlist...),
		FailClosedOnUnknown: mc.FailClosedOnUnknown,
		Resolver:            resolver,
		Timeout:             mc.Timeout,
		CacheTTL:            mc.CacheTTL,
		NegativeCacheTTL:    mc.NegativeCacheTTL,
		CacheSize:           mc.CacheSize,
		Logger:              logger,
	})
	logger.Info("maturity gate enabled (release-maturity / version-cooldown)",
		"defaultCooldown", mc.DefaultCooldown,
		"ecosystemOverrides", len(mc.Ecosystems),
		"tenantOverrides", len(mc.Tenants),
		"allowlist", len(mc.Allowlist),
		"failClosedOnUnknown", mc.FailClosedOnUnknown)
	return svc
}

// buildContinuity constructs the maintainer/publisher continuity monitoring gate
// (Task 91) from config. It returns nil when the subsystem is disabled. When
// enabled it wires the live HTTP publisher resolver (npm/PyPI/RubyGems/crates.io
// maintainer rosters plus coordinate-derived ownership namespaces) and loads the
// durable known-maintainer set. A store-load failure is returned as an error.
func buildContinuity(cfg *config.Config, logger *slog.Logger) (*continuity.Service, error) {
	cc := cfg.Continuity
	if !cc.Enabled {
		logger.Info("continuity gate disabled (set continuity.enabled to monitor maintainer/publisher ownership changes)")
		return nil, nil
	}

	tenants := make(map[string]continuity.TenantConfig, len(cc.Tenants))
	for id, t := range cc.Tenants {
		tc := continuity.TenantConfig{
			Ecosystems: cloneDispMap(t.Ecosystems),
			Allowlist:  append([]string(nil), t.Allowlist...),
		}
		if d := strings.TrimSpace(t.Disposition); d != "" {
			disp := continuity.NormalizeDisposition(d)
			tc.Disposition = &disp
		}
		if t.Cooldown != 0 {
			cd := t.Cooldown
			tc.Cooldown = &cd
		}
		tenants[id] = tc
	}

	resolver := continuity.NewHTTPResolver(&http.Client{Timeout: cc.Timeout}, cc.UserAgent)
	if len(cc.BaseURLs) > 0 {
		resolver.BaseURLs = make(map[string]string, len(cc.BaseURLs))
		for eco, u := range cc.BaseURLs {
			resolver.BaseURLs[strings.ToLower(strings.TrimSpace(eco))] = u
		}
	}

	svc, err := continuity.New(continuity.Config{
		DefaultDisposition: continuity.NormalizeDisposition(cc.DefaultDisposition),
		Ecosystems:         cloneDispMap(cc.Ecosystems),
		Tenants:            tenants,
		Cooldown:           cc.Cooldown,
		Allowlist:          append([]string(nil), cc.Allowlist...),
		Resolver:           resolver,
		StorePath:          cc.StorePath,
		Timeout:            cc.Timeout,
		CacheTTL:           cc.CacheTTL,
		NegativeCacheTTL:   cc.NegativeCacheTTL,
		CacheSize:          cc.CacheSize,
		MaxRecords:         cc.MaxRecords,
		Logger:             logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("continuity gate enabled (maintainer/publisher continuity monitoring)",
		"defaultDisposition", string(continuity.NormalizeDisposition(cc.DefaultDisposition)),
		"cooldown", cc.Cooldown,
		"ecosystemOverrides", len(cc.Ecosystems),
		"tenantOverrides", len(cc.Tenants),
		"allowlist", len(cc.Allowlist),
		"durable", cc.StorePath != "")
	return svc, nil
}

// cloneDispMap returns a normalized copy of a per-ecosystem disposition map.
func cloneDispMap(in map[string]string) map[string]continuity.Disposition {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]continuity.Disposition, len(in))
	for eco, d := range in {
		out[strings.ToLower(strings.TrimSpace(eco))] = continuity.NormalizeDisposition(d)
	}
	return out
}

// buildDepFirewall constructs the dependency-firewall version-pinning & allowlist
// enforcement gate (Task 65) from config. It returns nil when the subsystem is
// disabled. A malformed range expression in any rule is a fatal configuration
// error so a misconfigured firewall fails loudly rather than silently
// mis-enforcing.
func buildDepFirewall(cfg *config.Config, logger *slog.Logger) (*depfirewall.Service, error) {
	dc := cfg.DepFirewall
	if !dc.Enabled {
		logger.Info("dependency firewall disabled (set depfirewall.enabled to enforce version policy)")
		return nil, nil
	}

	tenants := make(map[string]depfirewall.TenantConfig, len(dc.Tenants))
	for id, t := range dc.Tenants {
		tenants[id] = depfirewall.TenantConfig{
			DefaultAction: depfirewall.Action(t.DefaultAction),
			Rules:         convertDepFirewallRules(t.Rules),
		}
	}

	svc, err := depfirewall.NewService(depfirewall.Config{
		DefaultAction: depfirewall.Action(dc.DefaultAction),
		Rules:         convertDepFirewallRules(dc.Rules),
		Tenants:       tenants,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("dependency firewall enabled (version-pinning & allowlist enforcement)",
		"defaultAction", dc.DefaultAction,
		"globalRules", len(dc.Rules),
		"tenantPolicies", len(dc.Tenants))
	return svc, nil
}

// buildSnapshot constructs the organization-wide dependency snapshot, freeze &
// instant-rollback subsystem (Task 70) from config. It returns nil when disabled.
// The persistence directory defaults to <cache.dir>/snapshots. Manifests are
// signed with the audit transparency / attestation key (when available) so a
// snapshot is a verifiable commitment; lifecycle actions are recorded to the
// Merkle audit log and raised as EventSnapshot notifications.
func buildSnapshot(cfg *config.Config, auditLog *audit.Logger, notifier *notify.Notifier, logger *slog.Logger) (*snapshot.Service, error) {
	sc := cfg.Snapshot
	if !sc.Enabled {
		logger.Info("dependency snapshot/freeze subsystem disabled (set snapshot.enabled to capture and freeze the served dependency state)")
		return nil, nil
	}

	dir := strings.TrimSpace(sc.Dir)
	if dir == "" && strings.TrimSpace(cfg.Cache.Dir) != "" {
		dir = filepath.Join(cfg.Cache.Dir, "snapshots")
	}

	signer, source := loadSnapshotSigner(cfg)

	opts := []snapshot.Option{}
	if auditLog != nil {
		opts = append(opts, snapshot.WithAudit(auditLog))
	}
	if notifier != nil {
		opts = append(opts, snapshot.WithNotifier(notifier))
	}

	svc, err := snapshot.New(snapshot.Config{
		Enabled:           true,
		Dir:               dir,
		MaxLiveEntries:    sc.MaxLiveEntries,
		MaxSnapshots:      sc.MaxSnapshots,
		ScheduleInterval:  sc.ScheduleInterval,
		FreezeEnforceGate: sc.FreezeEnforce,
	}, signer, logger, opts...)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	logger.Info("dependency snapshot/freeze subsystem enabled (supply-chain time machine)",
		"dir", dirOrMemory(dir),
		"keyId", signer.KeyID(),
		"keySource", source,
		"scheduleInterval", sc.ScheduleInterval,
		"freezeEnforce", sc.FreezeEnforce)
	return svc, nil
}

// loadSnapshotSigner resolves the manifest signing key, reusing the same key
// preference as the outbound attestation engine: an attestation-specific key, else
// the audit transparency checkpoint key. It returns a nil signer (manifests are
// then unsigned) when no key material is configured.
func loadSnapshotSigner(cfg *config.Config) (*snapshot.Signer, string) {
	tc := cfg.Audit.Transparency
	ac := cfg.Attest
	switch {
	case ac.SigningKey != "":
		if s, err := snapshot.LoadSigner([]byte(ac.SigningKey)); err == nil {
			return s, "attest.signingKey"
		}
	case ac.SigningKeyFile != "":
		if s, err := snapshot.LoadSignerFile(ac.SigningKeyFile); err == nil {
			return s, "attest.signingKeyFile"
		}
	case tc.SigningKey != "":
		if s, err := snapshot.LoadSigner([]byte(tc.SigningKey)); err == nil {
			return s, "audit.transparency.signingKey"
		}
	case tc.SigningKeyFile != "":
		if s, err := snapshot.LoadSignerFile(tc.SigningKeyFile); err == nil {
			return s, "audit.transparency.signingKeyFile"
		}
	}
	return nil, "none (unsigned)"
}

// dirOrMemory renders a store dir for logging, distinguishing the in-memory mode.
func dirOrMemory(dir string) string {
	if dir == "" {
		return "(in-memory)"
	}
	return dir
}

// convertDepFirewallRules adapts the config rule slice to the service rule type,
// tagging each with a "config" source for the admin view.
func convertDepFirewallRules(in []config.DepFirewallRule) []depfirewall.Rule {
	if len(in) == 0 {
		return nil
	}
	out := make([]depfirewall.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, depfirewall.Rule{
			Ecosystem:  r.Ecosystem,
			Name:       r.Name,
			Pinned:     append([]string(nil), r.Pinned...),
			Ranges:     append([]string(nil), r.Ranges...),
			MinVersion: r.MinVersion,
			Denied:     append([]string(nil), r.Denied...),
			Note:       r.Note,
			Source:     "config",
		})
	}
	return out
}

// buildInstallHooks constructs the install-script / lifecycle-hook risk-analysis
// gate (Task 62). It returns nil when the subsystem is disabled. A configuration
// error (a bad rule pattern or severity threshold) is fatal so a misconfigured
// security gate fails loudly rather than silently admitting everything.
func buildInstallHooks(cfg *config.Config, logger *slog.Logger) (*installhooks.Service, error) {
	hc := cfg.InstallHooks
	if !hc.Enabled {
		logger.Info("install-hook analysis gate disabled (set installHooks.enabled to score package install scripts)")
		return nil, nil
	}

	icfg := installhooks.Config{
		Enabled:            true,
		FailSeverity:       installhooks.Severity(strings.ToLower(strings.TrimSpace(hc.FailSeverity))),
		WarnSeverity:       installhooks.Severity(strings.ToLower(strings.TrimSpace(hc.WarnSeverity))),
		Action:             installhooks.Action(strings.ToLower(strings.TrimSpace(hc.Action))),
		DisabledRules:      append([]string(nil), hc.DisabledRules...),
		MaxFindingsPerHook: hc.MaxFindingsPerHook,
		Logger:             logger,
	}
	for _, r := range hc.Rules {
		icfg.Rules = append(icfg.Rules, installhooks.RuleSpec{
			ID:       r.ID,
			Title:    r.Title,
			Severity: installhooks.Severity(strings.ToLower(strings.TrimSpace(r.Severity))),
			Pattern:  r.Pattern,
		})
	}
	if len(hc.Tenants) > 0 {
		icfg.Tenants = make(map[string]installhooks.TenantConfig, len(hc.Tenants))
		for id, t := range hc.Tenants {
			icfg.Tenants[id] = installhooks.TenantConfig{
				FailSeverity: installhooks.Severity(strings.ToLower(strings.TrimSpace(t.FailSeverity))),
				WarnSeverity: installhooks.Severity(strings.ToLower(strings.TrimSpace(t.WarnSeverity))),
				Action:       installhooks.Action(strings.ToLower(strings.TrimSpace(t.Action))),
			}
		}
	}

	svc, err := installhooks.NewService(icfg)
	if err != nil {
		return nil, err
	}
	logger.Info("install-hook analysis gate enabled",
		"failSeverity", icfg.FailSeverity,
		"warnSeverity", icfg.WarnSeverity,
		"action", icfg.Action,
		"disabledRules", len(icfg.DisabledRules),
		"customRules", len(icfg.Rules),
		"tenantOverrides", len(icfg.Tenants))
	return svc, nil
}

// buildMLGuard constructs the ML model weight-scanning gate (Task 110). It
// returns nil when the subsystem is disabled. A configuration error is fatal so a
// misconfigured security gate fails loudly rather than silently admitting
// everything.
func buildMLGuard(cfg *config.Config, logger *slog.Logger) (*mlguard.Service, error) {
	mc := cfg.MLGuard
	if !mc.Enabled {
		logger.Info("ML weight-scanning gate disabled (set mlGuard.enabled to scan Hugging Face pickle weights)")
		return nil, nil
	}

	// PreferSafetensors defaults to true unless explicitly set false.
	prefer := true
	if mc.PreferSafetensors != nil {
		prefer = *mc.PreferSafetensors
	}

	gcfg := mlguard.Config{
		Enabled:           true,
		FailSeverity:      mlguard.Severity(strings.ToLower(strings.TrimSpace(mc.FailSeverity))),
		WarnSeverity:      mlguard.Severity(strings.ToLower(strings.TrimSpace(mc.WarnSeverity))),
		Action:            mlguard.Action(strings.ToLower(strings.TrimSpace(mc.Action))),
		PreferSafetensors: prefer,
		MaxScanBytes:      mc.MaxScanBytes,
		MaxZipEntries:     mc.MaxZipEntries,
		Logger:            logger,
	}
	if len(mc.Tenants) > 0 {
		gcfg.Tenants = make(map[string]mlguard.TenantConfig, len(mc.Tenants))
		for id, t := range mc.Tenants {
			gcfg.Tenants[id] = mlguard.TenantConfig{
				FailSeverity: mlguard.Severity(strings.ToLower(strings.TrimSpace(t.FailSeverity))),
				WarnSeverity: mlguard.Severity(strings.ToLower(strings.TrimSpace(t.WarnSeverity))),
				Action:       mlguard.Action(strings.ToLower(strings.TrimSpace(t.Action))),
			}
		}
	}

	svc, err := mlguard.NewService(gcfg)
	if err != nil {
		return nil, err
	}
	logger.Info("ML weight-scanning gate enabled",
		"failSeverity", gcfg.FailSeverity,
		"warnSeverity", gcfg.WarnSeverity,
		"action", gcfg.Action,
		"preferSafetensors", gcfg.PreferSafetensors,
		"tenantOverrides", len(gcfg.Tenants))
	return svc, nil
}

// buildAVScan constructs the antivirus content-scanning gate (Task 136) from
// configuration. Returns (nil, nil) when disabled. A clamd connection is not
// required at startup — the gate degrades gracefully per fail-open/fail-closed
// policy when the engine is unreachable — so construction only validates config
// and parses the engine address.
func buildAVScan(cfg *config.Config, logger *slog.Logger) (*avscan.Service, error) {
	ac := cfg.AVScan
	if !ac.Enabled {
		logger.Info("antivirus content-scanning gate disabled (set avScan.enabled with a clamd address to scan artifact payloads)")
		return nil, nil
	}
	// FailOpen defaults to true unless explicitly set false.
	failOpen := true
	if ac.FailOpen != nil {
		failOpen = *ac.FailOpen
	}
	gcfg := avscan.Config{
		Enabled:      true,
		Engine:       strings.ToLower(strings.TrimSpace(ac.Engine)),
		Address:      strings.TrimSpace(ac.Address),
		Action:       avscan.Action(strings.ToLower(strings.TrimSpace(ac.Action))),
		MaxScanBytes: ac.MaxScanBytes,
		Timeout:      ac.Timeout,
		FailOpen:     failOpen,
		Logger:       logger,
	}
	svc, err := avscan.NewService(gcfg)
	if err != nil {
		return nil, err
	}
	logger.Info("antivirus content-scanning gate enabled",
		"engine", svc.EngineName(),
		"address", gcfg.Address,
		"action", svc.Action(),
		"failOpen", failOpen)
	return svc, nil
}

// buildContentScan constructs the package-payload static content-analysis gate
// (Task 138) from configuration. Returns (nil, nil) when disabled. The shared
// deterministic secret detector (the Task 29 detectors) is reused for the
// in-source-secret heuristic when present; when secret scanning is enabled but no
// shared detector was built, the gate constructs its own default detector.
func buildContentScan(cfg *config.Config, secretDetector *secretscan.Detector, logger *slog.Logger) (*contentscan.Service, error) {
	cs := cfg.ContentScan
	if !cs.Enabled {
		logger.Info("package-content analysis gate disabled (set contentScan.enabled to statically scan served package contents)")
		return nil, nil
	}
	boolOr := func(p *bool, def bool) bool {
		if p != nil {
			return *p
		}
		return def
	}
	gcfg := contentscan.Config{
		Enabled:             true,
		Action:              contentscan.Action(strings.ToLower(strings.TrimSpace(cs.Action))),
		FailSeverity:        contentscan.Severity(strings.ToLower(strings.TrimSpace(cs.FailSeverity))),
		Ecosystems:          cs.Ecosystems,
		DetectEntropy:       boolOr(cs.DetectEntropy, true),
		DetectBinary:        boolOr(cs.DetectBinary, true),
		DetectJS:            boolOr(cs.DetectJS, true),
		DetectExec:          boolOr(cs.DetectExec, true),
		DetectSecrets:       boolOr(cs.DetectSecrets, true),
		EntropyThreshold:    cs.EntropyThreshold,
		MinEntropyBlobBytes: cs.MinEntropyBlobBytes,
		MaxArchiveBytes:     cs.MaxArchiveBytes,
		MaxFileBytes:        cs.MaxFileBytes,
		MaxFiles:            cs.MaxFiles,
		MaxScanBytesPerFile: cs.MaxScanBytesPerFile,
		MaxFindings:         cs.MaxFindings,
		MaxFindingsPerFile:  cs.MaxFindingsPerFile,
		Timeout:             cs.Timeout,
		SecretDetector:      secretDetector,
		Logger:              logger,
	}
	svc, err := contentscan.NewService(gcfg)
	if err != nil {
		return nil, err
	}
	logger.Info("package-content analysis gate enabled",
		"action", svc.Action(), "ecosystems", svc.Status().Ecosystems)
	return svc, nil
}

// cloneDurMap returns a normalized (lower-cased keys) copy of a per-ecosystem
// duration map, or nil for an empty input.
func cloneDurMap(in map[string]time.Duration) map[string]time.Duration {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]time.Duration, len(in))
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

// buildProvgraph constructs the supply-chain provenance & dependency graph store
// (Task 33). It returns nil when the subsystem is disabled, in which case no
// graph is ingested and the admin surface reports it as unavailable.
func buildProvgraph(cfg *config.Config, logger *slog.Logger) *provgraph.Service {
	if !cfg.Provgraph.Enabled {
		logger.Info("provenance graph disabled (set provgraph.enabled to build the queryable supply-chain graph)")
		return nil
	}
	logger.Info("provenance graph enabled (ingesting pulls into the supply-chain graph; query/visualize via the admin API)")
	return provgraph.New(provgraph.Options{Logger: logger})
}

// buildLicense constructs the license-compliance admission gate (Task 28) from
// config. It returns (nil, nil) when the subsystem is disabled, in which case the
// gateway serves artifacts without a license check. The service is fully offline
// (a local SPDX catalog and policy), so it requires no network access.
func buildLicense(cfg *config.Config, logger *slog.Logger) (*license.Service, error) {
	lc := cfg.License
	if !lc.Enabled {
		logger.Info("license compliance disabled (set license.enabled to evaluate SPDX licenses against an allow/deny policy)")
		return nil, nil
	}
	tenants := make(map[string]license.PolicyConfig, len(lc.Tenants))
	for name, ov := range lc.Tenants {
		tenants[name] = licensePolicyConfig(ov)
	}
	svc, err := license.NewService(license.Config{
		Base:           licensePolicyConfig(lc.Policy),
		Tenants:        tenants,
		DriftDetection: lc.DriftDetection,
		DriftMaxEvents: lc.DriftMaxEvents,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("license: %w", err)
	}
	sum := svc.Summary()
	logger.Info("license compliance enabled",
		"action", sum.Action,
		"allow", len(sum.Allow),
		"deny", len(sum.Deny),
		"review", len(sum.Review),
		"tenants", len(tenants),
		"driftDetection", lc.DriftDetection)
	return svc, nil
}

// licensePolicyConfig translates a config license policy block into the license
// package's primitive PolicyConfig.
func licensePolicyConfig(p config.LicensePolicyConfig) license.PolicyConfig {
	return license.PolicyConfig{
		Allow:           p.Allow,
		Deny:            p.Deny,
		Review:          p.Review,
		AllowExceptions: p.AllowExceptions,
		Unknown:         p.Unknown,
		Default:         p.Default,
		Action:          p.Action,
		ReviewAction:    p.ReviewAction,
		DriftAction:     p.DriftAction,
	}
}

// buildSigverify constructs the Sigstore/cosign signature & attestation
// verification gate (Task 23) when enabled. It assembles the trust material
// (Fulcio roots, Rekor keys, configured public keys, allowed identities) either
// from inline config files or, in air-gapped mode, from a portable trust bundle,
// then wires a signature Source per configured ecosystem (an OCI registry router
// over the docker backends; HTTP attestation sources for npm/pip). It returns nil
// when disabled, in which case artifacts are served without an authenticity check.
func buildSigverify(cfg *config.Config, registry *backends.Registry, rekorDeps *rekorDeps, logger *slog.Logger) (*sigverify.Service, error) {
	sc := cfg.Sigverify
	if !sc.Enabled {
		logger.Info("signature verification disabled (set sigverify.enabled to verify cosign signatures and attestations)")
		return nil, nil
	}

	roots, rekorKeys, keys, identities, err := buildSigverifyTrust(sc)
	if err != nil {
		return nil, err
	}

	source := buildSigverifySources(cfg, registry, logger)
	if source == nil {
		logger.Warn("sigverify enabled but no verifiable ecosystem source could be wired; gate will be inert")
	}

	var rekorMetrics *rekor.Metrics
	requireInclusionProof := false
	if rekorDeps != nil {
		rekorMetrics = rekorDeps.metrics
		requireInclusionProof = rekorDeps.requireInclusionProof
	}
	svc, err := sigverify.NewService(sigverify.Config{
		Action:                policy.Action(sc.Action),
		FailSeverity:          sigverify.NormalizeSeverity(sc.FailSeverity),
		WarnSeverity:          sigverify.NormalizeSeverity(sc.WarnSeverity),
		RequireSignature:      sc.RequireSignature,
		RequireAttestation:    sc.RequireAttestation,
		RequireRekorProof:     sc.RequireRekorProof,
		RequireInclusionProof: requireInclusionProof,
		RekorMetrics:          rekorMetrics,
		FailOnError:           sc.FailOnError,
		Roots:                 roots,
		Identities:            identities,
		Keys:                  keys,
		RekorKeys:             rekorKeys,
		CacheTTL:              sc.CacheTTL,
		CacheMaxEntries:       sc.CacheMaxEntries,
		Offline:               sc.Offline,
		PQCEnabled:            sc.PQC.Enabled,
		PQCPolicy:             sigverify.NormalizePQCPolicy(sc.PQC.Policy),
	}, source, logger)
	if err != nil {
		return nil, fmt.Errorf("sigverify: %w", err)
	}
	logger.Info("signature verification enabled",
		"action", svc.GateAction(),
		"failSeverity", sc.FailSeverity,
		"requireSignature", sc.RequireSignature,
		"requireAttestation", sc.RequireAttestation,
		"requireRekorProof", sc.RequireRekorProof,
		"requireInclusionProof", requireInclusionProof,
		"trustRoots", roots != nil,
		"identities", len(identities),
		"keys", len(keys),
		"offline", sc.Offline,
		"pqc.enabled", sc.PQC.Enabled,
		"pqc.policy", svc.PQCPolicy())
	if sc.PQC.Enabled {
		logger.Info("post-quantum signature verification enabled",
			"provider", sigverify.PQCProviderName,
			"fipsValidated", sigverify.PQCProviderFIPSValidated,
			"policy", svc.PQCPolicy(),
			"schemes", sigverify.SupportedPQCSchemes())
	}
	return svc, nil
}

// buildSigverifyTrust assembles the gate's trust material from configuration:
// from a portable trust bundle when offline/air-gapped, or from inline files
// (Fulcio roots, Rekor keys, public keys) and the identity policy otherwise.
func buildSigverifyTrust(sc config.SigverifyConfig) (roots *x509.CertPool, rekorKeys []crypto.PublicKey, keys []sigverify.TrustedKey, identities []sigverify.Identity, err error) {
	if sc.Offline || sc.TrustBundleFile != "" {
		f, oerr := os.Open(sc.TrustBundleFile)
		if oerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: opening trust bundle %q: %w", sc.TrustBundleFile, oerr)
		}
		defer f.Close()
		bundle, lerr := sigverify.LoadTrustBundle(f, sc.TrustBundleDigest)
		if lerr != nil {
			return nil, nil, nil, nil, lerr
		}
		return bundle.Material()
	}

	if sc.TrustRootsFile != "" {
		pemBytes, rerr := os.ReadFile(sc.TrustRootsFile)
		if rerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: reading trust roots %q: %w", sc.TrustRootsFile, rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: no certificates found in trust roots %q", sc.TrustRootsFile)
		}
		roots = pool
	} else if sc.UseSystemTrustRoots {
		pool, serr := x509.SystemCertPool()
		if serr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: loading system trust roots: %w", serr)
		}
		roots = pool
	}

	for _, file := range sc.RekorKeyFiles {
		pemBytes, rerr := os.ReadFile(file)
		if rerr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: reading rekor key %q: %w", file, rerr)
		}
		pub, perr := sigverify.ParsePublicKeyPEM(pemBytes)
		if perr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: rekor key %q: %w", file, perr)
		}
		rekorKeys = append(rekorKeys, pub)
	}

	for _, k := range sc.Keys {
		pemBytes := []byte(k.PEM)
		if k.File != "" {
			b, rerr := os.ReadFile(k.File)
			if rerr != nil {
				return nil, nil, nil, nil, fmt.Errorf("sigverify: reading key %q: %w", k.File, rerr)
			}
			pemBytes = b
		}
		pub, perr := sigverify.ParsePublicKeyPEM(pemBytes)
		if perr != nil {
			return nil, nil, nil, nil, fmt.Errorf("sigverify: key %q: %w", k.Name, perr)
		}
		keys = append(keys, sigverify.TrustedKey{Name: k.Name, Public: pub})
	}

	for _, id := range sc.Identities {
		identities = append(identities, sigverify.Identity{Issuer: id.Issuer, SubjectPattern: id.SubjectPattern})
	}
	return roots, rekorKeys, keys, identities, nil
}

// buildSigverifySources wires a signature Source per configured ecosystem: an OCI
// registry router over the docker backends, and HTTP attestation sources for
// npm/pip. It returns nil when no source could be wired.
func buildSigverifySources(cfg *config.Config, registry *backends.Registry, logger *slog.Logger) sigverify.Source {
	ecosystems := cfg.Sigverify.Ecosystems
	if len(ecosystems) == 0 {
		ecosystems = []string{"docker"}
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	sources := make(map[string]sigverify.Source)

	for _, eco := range ecosystems {
		switch strings.ToLower(strings.TrimSpace(eco)) {
		case "docker", "oci":
			clients := dockerRegistryClients(cfg, registry)
			if len(clients) == 0 {
				logger.Warn("sigverify: no docker upstreams registered; OCI verification inert")
				continue
			}
			sources["docker"] = sigverify.NewOCIRouter(clients)
		case "npm":
			base := cfg.Sigverify.NPMRegistryURL
			if base == "" {
				base = "https://registry.npmjs.org"
			}
			sources["npm"] = sigverify.NewNPMSource(httpClient, base)
		case "pip", "pypi":
			// PyPI PEP 740 provenance is addressed per uploaded file; the artifact
			// filename is required to construct the provenance URL. Until the gate
			// surfaces the filename, pip attestation lookup is best-effort and yields
			// "not applicable" rather than spurious blocks.
			logger.Warn("sigverify: pip provenance lookup requires the artifact filename and is not yet wired; pip artifacts will pass through")
		}
	}
	if len(sources) == 0 {
		return nil
	}
	return sigverify.NewMultiSource(sources)
}

// dockerRegistryClients collects the registered docker backends as OCI registry
// clients, keyed by backend name.
func dockerRegistryClients(cfg *config.Config, registry *backends.Registry) map[string]sigverify.RegistryClient {
	clients := make(map[string]sigverify.RegistryClient)
	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() || up.Type != "docker" {
			continue
		}
		if b, ok := registry.Get(name); ok {
			clients[name] = b
		}
	}
	return clients
}

// buildRescanner constructs the continuous CVE-drift re-scan subsystem (Task 18)
// over an enabled vulnerability Service. It re-resolves cached artifacts' stored
// SBOMs against the database on a schedule and on demand, quarantining any that
// cross the policy threshold and recording an audit event. It returns nil when
// vulnerability scanning is disabled or the service is offline (no backend to
// re-query against). It is constructed even when the periodic interval is zero so
// the admin API's on-demand trigger remains available.
// buildCoalescer constructs the pull-path request coalescer + negative cache
// (Task 36) from config, or returns nil when disabled (the gateway then degrades
// to a direct GetOrLoad on every miss).
func buildCoalescer(cfg *config.Config, logger *slog.Logger) *coalesce.Coalescer[*cache.Entry] {
	cc := cfg.Coalesce
	if !cc.Enabled {
		return nil
	}
	c := proxy.NewCoalescer(coalesce.Config{
		Enabled:            true,
		NegativeTTL:        cc.NegativeTTL,
		MaxNegativeEntries: cc.MaxNegativeEntries,
		MaxInflight:        cc.MaxInflight,
		Backoff5xxBase:     cc.Backoff5xxBase,
		Backoff5xxMax:      cc.Backoff5xxMax,
	})
	snap := c.Metrics()
	logger.Info("pull-path coalescing enabled",
		"negativeTtl", snap.NegativeTTL,
		"maxNegativeEntries", snap.MaxNegativeEntries,
		"maxInflight", snap.MaxInflight)
	return c
}

func buildRescanner(cfg *config.Config, svc *vulnscan.Service, cacheImpl cache.Cache, auditLog *audit.Logger, notifier *notify.Notifier, tracer *tracing.Tracer, logger *slog.Logger) *vulnscan.Rescanner {
	if svc == nil || cfg.Vulnerabilities.Offline {
		return nil
	}

	// Map a re-scan quarantine into the tamper-evident audit log and (when
	// configured) a security alert. A nil *Logger and a nil *Notifier are both
	// valid no-ops, so this is safe even when those subsystems are disabled.
	auditFn := func(ctx context.Context, ev vulnscan.RescanAudit) {
		_ = auditLog.Log(ctx, audit.Event{
			Type:      audit.EventPolicy,
			Decision:  audit.DecisionDeny,
			Ecosystem: ev.Artifact.Ecosystem,
			Resource:  ev.Artifact.Name + "@" + ev.Artifact.Version,
			Reason:    ev.Reason,
			Detail: map[string]any{
				"event":       "cve-drift-quarantine",
				"digest":      ev.Digest,
				"advisory":    ev.Advisory,
				"maxSeverity": string(ev.MaxSeverity),
				"maxCvss":     ev.MaxCVSS,
				"prevAction":  string(ev.PrevAction),
				"newAction":   string(ev.NewAction),
			},
		})
		notifier.Emit(ctx, notify.RescanRegressionEvent(
			notify.NormalizeSeverity(string(ev.MaxSeverity)),
			ev.Artifact.Ecosystem,
			ev.Artifact.Name+"@"+ev.Artifact.Version,
			ev.Advisory,
			ev.Reason,
		).WithField("digest", ev.Digest))
	}

	rescanner := vulnscan.NewRescanner(svc, vulnscan.RescanConfig{
		Interval: cfg.Vulnerabilities.RescanInterval,
		Workers:  cfg.Vulnerabilities.RescanWorkers,
		Tracer:   tracer,
	}, cacheImpl, auditFn, logger)
	logger.Info("cve-drift re-scan subsystem enabled",
		"interval", cfg.Vulnerabilities.RescanInterval,
		"workers", cfg.Vulnerabilities.RescanWorkers)
	return rescanner
}

// buildCacheGC constructs the cache lifecycle / garbage-collection engine
// (Task 39) over the content cache. It returns nil when GC is disabled or the
// configured cache backend does not support lifecycle management (e.g. the
// in-memory dev cache). Capacity and the default TTL fall back to the cache's own
// maxSizeBytes/ttl so an existing deployment needs no extra configuration. The
// quarantine set and metadata pins are wired as retention sources so artifacts
// held for evidence or marked signed-and-attested are never reclaimed.
func buildCacheGC(cfg *config.Config, cacheImpl cache.Cache, vulnService *vulnscan.Service, notifier *notify.Notifier, logger *slog.Logger) (*cachegc.Engine, error) {
	if !cfg.CacheGC.Enabled {
		return nil, nil
	}
	gcCache, ok := cacheImpl.(cachegc.Cache)
	if !ok {
		logger.Info("cache gc disabled: cache backend does not support lifecycle inspection",
			"backend", cfg.Cache.Backend)
		return nil, nil
	}

	capacity := cfg.CacheGC.CapacityBytes
	if capacity == 0 {
		capacity = cfg.Cache.MaxSizeBytes
	}
	defaultTTL := cfg.CacheGC.DefaultTTL
	if defaultTTL == 0 {
		defaultTTL = cfg.Cache.TTL
	}

	// Retention sources compose: an entry claimed by any source is never evicted.
	// Metadata pins cover signed-and-attested or otherwise-pinned entries; the
	// quarantine set covers artifacts held for investigation as evidence.
	sources := []cachegc.ReferenceSource{cachegc.NewMetadataPinSource()}
	if vulnService != nil {
		sources = append(sources, cachegc.NewKeySetSource("quarantine", func() map[string]struct{} {
			entries := vulnService.Quarantined()
			set := make(map[string]struct{}, len(entries))
			for _, q := range entries {
				if q.Digest != "" {
					set[q.Digest] = struct{}{}
				}
			}
			return set
		}))
	}

	onHigh := func(ctx context.Context, rep cachegc.Report) {
		used := rep.UsedBytes - rep.BytesReclaimed
		notifier.Emit(ctx, notify.CacheHighWatermarkEvent(
			used, rep.CapacityBytes, rep.BytesReclaimed, rep.UtilizationPct,
			fmt.Sprintf("Cache is %.0f%% full and a GC sweep could not bring it below the high watermark; reclaimable space is exhausted (everything else is pinned, referenced, or in-flight).", rep.UtilizationPct),
		))
	}

	engine, err := cachegc.New(cachegc.Config{
		Enabled:          cfg.CacheGC.Enabled,
		Interval:         cfg.CacheGC.Interval,
		CapacityBytes:    capacity,
		HighWatermarkPct: cfg.CacheGC.HighWatermarkPct,
		LowWatermarkPct:  cfg.CacheGC.LowWatermarkPct,
		Policy:           cachegc.EvictionPolicy(cfg.CacheGC.Policy),
		DefaultTTL:       defaultTTL,
		TenantTTLs:       cfg.CacheGC.TenantTTLs,
		MinIdle:          cfg.CacheGC.MinIdle,
		MaxDeletesPerRun: cfg.CacheGC.MaxDeletesPerRun,
		AllowEvictPinned: cfg.CacheGC.AllowEvictPinned,
		DryRun:           cfg.CacheGC.DryRun,
	}, gcCache, cachegc.Options{
		Sources:         sources,
		OnHighWatermark: onHigh,
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("cache gc subsystem enabled",
		"policy", cfg.CacheGC.Policy, "interval", cfg.CacheGC.Interval,
		"capacityBytes", capacity, "defaultTtl", defaultTTL, "dryRun", cfg.CacheGC.DryRun)
	return engine, nil
}

// buildNotifier constructs the event-notification subsystem (Task 21) from
// config, translating the YAML schema into the notify package's Config and
// starting the asynchronous delivery workers. It returns nil when notifications
// are disabled, in which case every emit is a no-op.
func buildNotifier(cfg *config.Config, logger *slog.Logger) (*notify.Notifier, error) {
	nc := cfg.Notifications
	if !nc.Enabled {
		// Even with external delivery (webhook/Slack) disabled, construct a
		// headless notifier with no sinks: it remains the in-process security-event
		// bus, so the SecOps dashboard's live feed and rolling-window read-model
		// (Task 60) still observe every gate verdict via the notifier tap. Nothing
		// is delivered off-box (no sinks/routes), so this is free when unused.
		logger.Info("external notifications disabled (no webhook/Slack sinks); security events still feed the SecOps dashboard")
		return notify.New(notify.Options{Logger: logger}), nil
	}

	sinks := make([]notify.SinkConfig, 0, len(nc.Sinks))
	for _, s := range nc.Sinks {
		sinks = append(sinks, notify.SinkConfig{
			Name:               s.Name,
			Kind:               s.Kind,
			URL:                s.URL,
			Headers:            s.Headers,
			Channel:            s.Channel,
			Username:           s.Username,
			IconEmoji:          s.IconEmoji,
			InsecureSkipVerify: s.InsecureSkipVerify,
		})
	}
	routes := make([]notify.RouteConfig, 0, len(nc.Routes))
	for _, r := range nc.Routes {
		routes = append(routes, notify.RouteConfig{
			Sinks:       r.Sinks,
			EventTypes:  r.EventTypes,
			MinSeverity: notify.NormalizeSeverity(r.MinSeverity),
		})
	}

	notifier, err := notify.Build(notify.Config{
		Workers:        nc.Workers,
		QueueSize:      nc.QueueSize,
		MaxRetries:     nc.MaxRetries,
		RetryBaseDelay: nc.RetryBaseDelay,
		RetryMaxDelay:  nc.RetryMaxDelay,
		Timeout:        nc.Timeout,
		MinSeverity:    notify.NormalizeSeverity(nc.MinSeverity),
		RedactFields:   nc.RedactFields,
		Sinks:          sinks,
		Routes:         routes,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("notify: %w", err)
	}
	logger.Info("notifications enabled",
		"sinks", len(sinks),
		"routes", len(routes),
		"minSeverity", nc.MinSeverity)
	return notifier, nil
}

// buildSIEMForwarder constructs the SIEM / log-forwarding subsystem (Task 119)
// from config, translating the YAML schema into the siem package's Config and
// starting the asynchronous dispatcher. It returns a nil forwarder (a valid
// no-op) when siem forwarding is disabled.
func buildSIEMForwarder(cfg *config.Config, logger *slog.Logger) (*siem.Forwarder, error) {
	sc := cfg.SIEM
	if !sc.Enabled {
		return nil, nil
	}
	sinks := make([]siem.SinkConfig, 0, len(sc.Sinks))
	for _, s := range sc.Sinks {
		sinks = append(sinks, siem.SinkConfig{
			Name:       s.Name,
			Kind:       s.Kind,
			URL:        s.URL,
			Token:      s.Token,
			AuthHeader: s.AuthHeader,
			AuthScheme: s.AuthScheme,
			Index:      s.Index,
			Source:     s.Source,
			SourceType: s.SourceType,
			Host:       s.Host,
			Headers:    s.Headers,
			Address:    s.Address,
			Network:    s.Network,
			Facility:   s.Facility,
			Hostname:   s.Hostname,
			AppName:    s.AppName,
			Vendor:     s.Vendor,
			Product:    s.Product,
			Version:    s.Version,
			TLS: siem.TLSConfig{
				InsecureSkipVerify: s.TLS.InsecureSkipVerify,
				CAFile:             s.TLS.CAFile,
				ServerName:         s.TLS.ServerName,
				MinVersion:         s.TLS.MinVersion,
			},
		})
	}
	fwd, err := siem.Build(siem.Config{
		QueueSize:       sc.QueueSize,
		BatchSize:       sc.BatchSize,
		BatchTimeout:    sc.BatchTimeout,
		MaxRetries:      sc.MaxRetries,
		RetryBaseDelay:  sc.RetryBaseDelay,
		RetryMaxDelay:   sc.RetryMaxDelay,
		Timeout:         sc.Timeout,
		MinSeverity:     siem.NormalizeSeverity(sc.MinSeverity),
		ForwardAudit:    sc.ForwardAuditOrDefault(),
		ForwardFindings: sc.ForwardFindingsOrDefault(),
		Spill: siem.SpillConfig{
			Enabled:  sc.Spill.Enabled,
			File:     sc.Spill.File,
			MaxBytes: sc.Spill.MaxBytes,
		},
		OCSF: siem.OCSFConfig{
			SchemaVersion: sc.OCSF.SchemaVersion,
			ClassMap:      sc.OCSF.ClassMap,
			ProductName:   sc.OCSF.ProductName,
			VendorName:    sc.OCSF.VendorName,
		},
		Sinks: sinks,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("siem: %w", err)
	}
	logger.Info("siem forwarding enabled",
		"sinks", len(sinks),
		"forwardAudit", sc.ForwardAuditOrDefault(),
		"forwardFindings", sc.ForwardFindingsOrDefault(),
		"spill", sc.Spill.Enabled)
	return fwd, nil
}

// siemFindingsForwarder adapts the concrete *siem.Forwarder to the gateway's
// SIEMForwarder dependency, returning a true-nil interface when forwarding is
// disabled or findings forwarding is off, so the gateway's nil check correctly
// detects the absent dependency (a typed-nil pointer would defeat it).
func siemFindingsForwarder(f *siem.Forwarder) proxy.SIEMForwarder {
	if f == nil {
		return nil
	}
	return f
}

// notifyEmitter adapts the concrete *notify.Notifier to the gateway's
// notify.Emitter dependency, returning a true-nil interface when notifications
// are disabled so the gateway's nil check correctly detects the absent
// dependency (a typed-nil pointer would defeat it).
func notifyEmitter(n *notify.Notifier) notify.Emitter {
	if n == nil {
		return nil
	}
	return n
}

// meteringRecorder adapts the concrete *metering.Meter to the gateway's
// MeteringRecorder dependency, returning a true-nil interface when metering is
// disabled so the gateway's nil check correctly detects the absent dependency
// (a typed-nil pointer would defeat it).
func meteringRecorder(m *metering.Meter) proxy.MeteringRecorder {
	if m == nil || !m.Enabled() {
		return nil
	}
	return m
}

// commitVerdictNotifier returns the pipeline OnVerdict hook that emits an alert
// for a freshly-produced commit-scan verdict, or nil when notifications are
// disabled (so no hook is installed). A malicious verdict is escalated to at
// least high severity so it is delivered even under a high severity floor; the
// notifier's routing applies the configured floor for everything else.
func commitVerdictNotifier(n *notify.Notifier) func(context.Context, *commit.Verdict) {
	if n == nil {
		return nil
	}
	return func(ctx context.Context, v *commit.Verdict) {
		if v == nil {
			return
		}
		sev := notify.NormalizeSeverity(v.HighestSeverity())
		if v.Malicious && !sev.AtLeast(notify.SeverityHigh) {
			sev = notify.SeverityHigh
		}
		summary := v.Rationale
		if summary == "" {
			summary = fmt.Sprintf("commit scan produced risk score %d", v.RiskScore)
		}
		// Repository is not carried on the verdict; the SHA identifies the commit.
		n.Emit(ctx, notify.CommitScanEvent(sev, "", v.SHA, v.RiskScore, v.Malicious, summary))
	}
}

// provenanceAssessor adapts the provenance Service to the policy engine's
// AssessmentSource: it resolves an artifact's provenance link joined with its
// source commit's scan verdict and flattens them into a policy.Assessment. A
// missing association is reported as Assessment{Found:false} with a nil error so
// the engine applies its missing-provenance policy rather than failing.
type provenanceAssessor struct{ svc *provenance.Service }

func (a *provenanceAssessor) Assess(ctx context.Context, art policy.Artifact) (policy.Assessment, error) {
	enriched, err := a.svc.ResolveEnriched(ctx, provenance.Artifact{
		Ecosystem: art.Ecosystem,
		Name:      art.Name,
		Version:   art.Version,
		Digest:    art.Digest,
	})
	if err != nil {
		if errors.Is(err, provenance.ErrNoProvenance) {
			return policy.Assessment{Found: false}, nil
		}
		return policy.Assessment{}, err
	}
	asmt := policy.Assessment{
		Found:             true,
		Confidence:        string(enriched.Link.Confidence),
		SignatureVerified: enriched.Link.SignatureVerified,
		ChainTrusted:      enriched.Link.ChainTrusted,
		CommitSHA:         enriched.Link.CommitSHA,
		RepositoryURL:     enriched.Link.RepositoryURL,
	}
	if v := enriched.Verdict; v != nil {
		asmt.HasVerdict = true
		asmt.RiskScore = v.RiskScore
		asmt.Malicious = v.Malicious
		asmt.HighestSeverity = v.HighestSeverity
	}
	return asmt, nil
}

// buildLinkStore constructs the durable (filesystem) provenance link store when a
// directory is configured, falling back to an in-memory store otherwise.
func buildLinkStore(cfg *config.Config, logger *slog.Logger) (provenance.LinkStore, func() error, error) {
	if dir := cfg.Provenance.StoreDir; dir != "" {
		store, err := provenance.NewFileLinkStore(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("provenance: building link store: %w", err)
		}
		logger.Info("provenance link store: filesystem", "dir", dir)
		return store, store.Close, nil
	}
	logger.Warn("provenance link store: in-memory (links are lost on restart; set provenance.storeDir for durability)")
	store := provenance.NewMemoryLinkStore()
	return store, store.Close, nil
}

// buildTrustRoots loads the attestation trust-anchor pool. A configured PEM
// bundle takes precedence; otherwise the system pool is used only when explicitly
// opted in. Returns nil when no trust anchor should be asserted.
func buildTrustRoots(p config.ProvenanceConfig) (*x509.CertPool, error) {
	if p.TrustRootsFile != "" {
		pem, err := os.ReadFile(p.TrustRootsFile)
		if err != nil {
			return nil, fmt.Errorf("provenance: reading trust roots %q: %w", p.TrustRootsFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("provenance: no certificates found in trust roots %q", p.TrustRootsFile)
		}
		return pool, nil
	}
	if p.UseSystemTrustRoots {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("provenance: loading system trust roots: %w", err)
		}
		return pool, nil
	}
	return nil, nil
}

// verdictLookup adapts a scan.Scanner that can read persisted commit verdicts
// into the provenance.VerdictLookup join interface. It returns nil when the
// scanner does not expose verdicts (commit scanning disabled), in which case
// provenance links are surfaced without verdicts.
func verdictLookup(scanner scan.Scanner) provenance.VerdictLookup {
	reader, ok := scanner.(verdictReader)
	if !ok {
		return nil
	}
	return &scanVerdictLookup{reader: reader}
}

// verdictReader is the subset of the commit scanner used to read verdicts.
type verdictReader interface {
	Verdict(ctx context.Context, sha string) (*commit.Verdict, error)
}

type scanVerdictLookup struct{ reader verdictReader }

func (a *scanVerdictLookup) VerdictFor(ctx context.Context, sha string) (*provenance.CommitVerdict, bool) {
	v, err := a.reader.Verdict(ctx, sha)
	if err != nil || v == nil {
		return nil, false
	}
	return &provenance.CommitVerdict{
		SHA:             v.SHA,
		RiskScore:       v.RiskScore,
		Malicious:       v.Malicious,
		HighestSeverity: v.HighestSeverity(),
		Findings:        len(v.Findings),
	}, true
}

// hostBaseURL reduces an upstream URL to its scheme://host origin, used to locate
// an ecosystem's JSON metadata API (e.g. PyPI's /pypi/<name>/json) which lives at
// the registry origin rather than under the index path.
func hostBaseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// buildCache constructs the configured cache implementation. The "filesystem"
// backend uses the durable content-addressable store with LRU + max-size + TTL
// eviction; "memory" uses the lightweight in-memory cache. When sealed
// (offline/air-gapped) mode is enabled the cache is wrapped so it serves only
// from local content and never triggers an upstream load.
func buildCache(cfg *config.Config, logger *slog.Logger) (cache.Cache, error) {
	impl, err := newCacheImpl(cfg, logger)
	if err != nil {
		return nil, err
	}
	if cfg.Cache.Sealed {
		impl = cache.NewSealedCache(impl)
	}
	// Read-time cache integrity verification and self-healing (Task 107). The
	// wrapper always sits outermost so the admin-triggered integrity scan and the
	// integrity metrics exist regardless of the serve-time verification toggle;
	// SetObserver is called once the audit/notification subsystems are built. The
	// memory backend is unaffected in practice (nothing serves it in production)
	// but is wrapped uniformly for consistency.
	integrity := cache.NewIntegrityCache(impl, cache.IntegrityOptions{
		VerifyOnServe: cfg.Cache.Integrity.VerifyOnServe,
		Logger:        logger,
	})
	return integrity, nil
}

// newCacheImpl constructs the raw (unsealed) cache implementation. The pre-warm
// workflow uses it directly: warming inherently fetches from upstream, so it
// must bypass the sealed wrapper even when the instance is otherwise sealed.
func newCacheImpl(cfg *config.Config, logger *slog.Logger) (cache.Cache, error) {
	switch cfg.Cache.Backend {
	case "memory":
		return cache.NewMemoryCache(), nil
	case "filesystem":
		fsStore, err := cache.NewFilesystemStore(cfg.Cache.Dir)
		if err != nil {
			return nil, err
		}
		// Hot/cold tiering (Task 154) sits innermost of all, composing the fast
		// (hot) durable store with a slower/cheaper cold store; encryption and
		// compaction wrap it, so a tier move only ever relocates already-transformed
		// bytes and the digest-over-plaintext invariant is preserved above it.
		tiered, err := wrapTiering(fsStore, cfg, logger)
		if err != nil {
			return nil, err
		}
		// At-rest encryption (Task 141) sits above tiering (wrapping the durable
		// store), so compaction/dedup still operate on plaintext above it.
		encrypted, err := wrapEncryption(tiered, cfg)
		if err != nil {
			return nil, err
		}
		store, err := wrapCompaction(encrypted, cfg.Cache.Compression, false)
		if err != nil {
			return nil, err
		}
		return cache.NewFilesystemCache(cache.FilesystemOptions{
			Store:        store,
			MaxSizeBytes: cfg.Cache.MaxSizeBytes,
			TTL:          cfg.Cache.TTL,
		})
	case "s3":
		s3 := cfg.Cache.S3
		store, err := cache.NewS3Store(cache.S3Options{
			Endpoint:           s3.Endpoint,
			Region:             s3.Region,
			Bucket:             s3.Bucket,
			Prefix:             s3.Prefix,
			AccessKeyID:        s3.AccessKeyID,
			SecretAccessKey:    s3.SecretAccessKey,
			SessionToken:       s3.SessionToken,
			UsePathStyle:       s3.UsePathStyle,
			InsecureSkipVerify: s3.InsecureSkipVerify,
			MaxRetries:         s3.MaxRetries,
			SpoolDir:           s3.SpoolDir,
		})
		if err != nil {
			return nil, err
		}
		tiered, err := wrapTiering(store, cfg, logger)
		if err != nil {
			return nil, err
		}
		encrypted, err := wrapEncryption(tiered, cfg)
		if err != nil {
			return nil, err
		}
		compacted, err := wrapCompaction(encrypted, cfg.Cache.Compression, s3.IsSharedMode())
		if err != nil {
			return nil, err
		}
		// The FilesystemCache type is the generic caching layer (in-memory index,
		// LRU/TTL eviction, single-flight loading, metrics) over any Store; the S3
		// store is the documented extension point. SharedStore makes reads fall
		// back to the shared bucket so HA replicas see each other's writes.
		return cache.NewFilesystemCache(cache.FilesystemOptions{
			Store:        compacted,
			MaxSizeBytes: cfg.Cache.MaxSizeBytes,
			TTL:          cfg.Cache.TTL,
			SharedStore:  s3.IsSharedMode(),
		})
	default:
		return nil, fmt.Errorf("unsupported cache backend %q", cfg.Cache.Backend)
	}
}

// wrapCompaction optionally wraps a durable store with the transparent
// compression + chunk-deduplication layer (Task 125). When the layer is
// disabled it returns the store unchanged, so the serve and storage paths are
// byte-for-byte identical to the pre-Task-125 behavior.
func wrapCompaction(store cache.Store, cc config.CompressionConfig, shared bool) (cache.Store, error) {
	if !cc.Enabled {
		return store, nil
	}
	return cache.NewCompactStore(store, cache.CompactOptions{
		Codec:        cc.Codec,
		Level:        cc.Level,
		MinSizeBytes: cc.MinSizeBytes,
		Dedup:        cc.Dedup,
		Shared:       shared,
		SpoolDir:     cc.SpoolDir,
	})
}

// wrapTiering optionally composes the hot (primary) durable store with a cold
// store into a tiered Store (Task 154). When the layer is disabled it returns
// the hot store unchanged. The returned store's background demotion sweep is
// started (and leader-gated) separately in main, once coordination is wired.
func wrapTiering(hot cache.Store, cfg *config.Config, logger *slog.Logger) (cache.Store, error) {
	tc := cfg.Cache.Tiering
	if !tc.Enabled {
		return hot, nil
	}
	cold, err := buildTierBackend(tc.Cold)
	if err != nil {
		return nil, err
	}
	return cache.NewTieredStore(cache.TieredOptions{
		Hot:                  hot,
		Cold:                 cold,
		PromoteOnRead:        tc.PromoteOnReadEnabled(),
		DemoteAfterIdle:      tc.DemoteAfterIdle,
		HotMaxBytes:          tc.HotMaxBytes,
		MinAccessesToStayHot: tc.MinAccessesToStayHot,
		SweepInterval:        tc.SweepInterval,
		Logger:               logger,
	})
}

// buildTierBackend constructs the cold-tier durable store from its config.
func buildTierBackend(b config.TierBackendConfig) (cache.Store, error) {
	switch b.Backend {
	case "filesystem":
		return cache.NewFilesystemStore(b.Dir)
	case "s3":
		return cache.NewS3Store(cache.S3Options{
			Endpoint:           b.S3.Endpoint,
			Region:             b.S3.Region,
			Bucket:             b.S3.Bucket,
			Prefix:             b.S3.Prefix,
			AccessKeyID:        b.S3.AccessKeyID,
			SecretAccessKey:    b.S3.SecretAccessKey,
			SessionToken:       b.S3.SessionToken,
			UsePathStyle:       b.S3.UsePathStyle,
			InsecureSkipVerify: b.S3.InsecureSkipVerify,
			MaxRetries:         b.S3.MaxRetries,
			SpoolDir:           b.S3.SpoolDir,
		})
	default:
		return nil, fmt.Errorf("unsupported cache.tiering.cold.backend %q", b.Backend)
	}
}

// wrapEncryption optionally wraps a durable store with the transparent at-rest
// encryption envelope (Task 141). When the layer is disabled it returns the
// store unchanged. The KEK material carried in the config has already been
// resolved from its secretRef (env/file/vault) by config.ResolveRefs at startup;
// here it is decoded into raw key bytes and the keyring is assembled. FIPS mode
// is read from config so the status report reflects the deployment's crypto mode.
func wrapEncryption(store cache.Store, cfg *config.Config) (cache.Store, error) {
	ec := cfg.Cache.Encryption
	if !ec.Enabled {
		return store, nil
	}
	primaryKey, err := cache.DeriveKEK(ec.KeyID, ec.KeyRef, ec.KeyEncoding)
	if err != nil {
		return nil, err
	}
	var previous []cache.KEK
	for _, pk := range ec.PreviousKeys {
		key, err := cache.DeriveKEK(pk.KeyID, pk.KeyRef, pk.KeyEncoding)
		if err != nil {
			return nil, err
		}
		previous = append(previous, cache.KEK{ID: pk.KeyID, Key: key})
	}
	return cache.NewEncryptStore(store, cache.EncryptOptions{
		Primary:   cache.KEK{ID: ec.KeyID, Key: primaryKey},
		Previous:  previous,
		FrameSize: ec.FrameSizeBytes,
		FIPS:      cfg.FIPS.Enabled,
	})
}

// gitRuntime carries the shared Git proxy infrastructure built alongside the
// backend registry: the (optional) mirror manager and the set of Git upstreams,
// which the SSH endpoint resolves repository paths against.
type gitRuntime struct {
	mirror    *git.Mirror
	upstreams map[string]*git.Upstream
}

// resolve maps an upstream name to its Git upstream, satisfying the SSH server's
// resolver.
func (g *gitRuntime) resolve(name string) (*git.Upstream, bool) {
	up, ok := g.upstreams[name]
	return up, ok
}

// buildInterceptor constructs the TLS-interception forward proxy (Task 100) from
// config, or returns a true nil when interception is disabled (so the gateway's
// nil check correctly detects the absent dependency). It loads or generates the
// signing CA and builds the host->backend routing table: the primary host of
// every enabled upstream URL is mapped automatically, then any explicit
// server.intercept.hosts entries are applied on top (overriding).
func buildInterceptor(cfg *config.Config, logger *slog.Logger) (proxy.Interceptor, error) {
	ic := cfg.Server.Intercept
	if !ic.Enabled {
		return nil, nil
	}

	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{
		CertFile:     ic.CACertFile,
		KeyFile:      ic.CAKeyFile,
		Generate:     ic.GenerateCA,
		Organization: ic.CAOrganization,
		CommonName:   ic.CACommonName,
		LeafTTL:      ic.LeafTTL,
		CacheSize:    ic.CertCacheSize,
	})
	if err != nil {
		return nil, fmt.Errorf("building intercept CA: %w", err)
	}

	hosts := make(map[string]string)
	// Auto-map the primary registry/index host of every enabled upstream. Only
	// the primary host is derived automatically: a backend serves its upstream's
	// native path layout, and its index-rewriting keeps dependent artifact fetches
	// on that same host. Operators map extra hosts (e.g. a separate artifact CDN)
	// explicitly via server.intercept.hosts.
	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() {
			continue
		}
		if host := intercept.HostOf(up.URL); host != "" {
			if _, taken := hosts[host]; !taken {
				hosts[host] = name
			}
		}
	}
	// Explicit host mappings override the auto-derived ones.
	for host, backend := range ic.Hosts {
		hosts[host] = backend
	}

	router := intercept.NewRouter(hosts)
	if router.Len() == 0 {
		logger.Warn("tls-interception enabled but no upstream hosts to route; configure upstreams or server.intercept.hosts")
	}

	p, err := intercept.New(intercept.Options{
		Router:               router,
		CA:                   ca,
		Logger:               logger,
		PassthroughUnmatched: ic.PassthroughUnmatched,
		AllowPlainHTTP:       ic.AllowPlainHTTP,
		ReadTimeout:          cfg.Server.ReadTimeout,
		WriteTimeout:         cfg.Server.WriteTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("building intercept proxy: %w", err)
	}
	logger.Info("tls-interception forward proxy configured",
		"listenAddr", ic.ListenAddr,
		"routedHosts", router.Hosts(),
		"passthroughUnmatched", ic.PassthroughUnmatched,
		"caSubject", ca.Subject())
	return p, nil
}

// buildBackends registers a backend per enabled upstream. Package ecosystems and
// Docker are served by their protocol-aware HTTP backends; Git upstreams get the
// dedicated smart-HTTP/SSH proxy backend (Task 6), which the proxy core
// delegates to via the HTTPHandler capability.
func buildBackends(cfg *config.Config, cacheImpl cache.Cache, notifier notify.Emitter, egressGuard *egress.Guard, pinGuard *tlspin.Guard, connMetrics *upstream.ConnMetrics, logger *slog.Logger) (*backends.Registry, *gitRuntime, *upstreampool.Manager, error) {
	registry := backends.NewRegistry()
	pool := newClientPool(cfg.Outbound, egressGuard, pinGuard, connMetrics)
	poolMgr := upstreampool.NewManager()

	mirror := buildGitMirror(cfg, logger)
	gitRT := &gitRuntime{mirror: mirror, upstreams: make(map[string]*git.Upstream)}

	for name, up := range cfg.Upstreams {
		if !up.IsEnabled() {
			logger.Info("skipping disabled upstream", "name", name)
			continue
		}

		creds := upstream.Credentials{
			Username: up.Credentials.Username,
			Password: up.Credentials.Password,
			Token:    up.Credentials.Token,
		}

		var (
			b   backends.Backend
			err error
		)
		if up.Type == "git" {
			b, err = buildGitBackend(cfg, name, up, pool, creds, mirror, cacheImpl, logger, gitRT)
		} else {
			doer, derr := upstreamDoer(cfg, name, up, pool, creds, poolMgr, notifier, logger)
			if derr != nil {
				return nil, nil, nil, fmt.Errorf("building upstream client for %q: %w", name, derr)
			}
			b, err = buildBackend(cfg, name, up, doer, creds)
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("building backend %q: %w", name, err)
		}
		// In sealed (offline) mode, refuse live upstream fetches at the backend
		// layer so the non-cacheable serving path also stays air-gapped. The Git
		// smart-HTTP backend (HTTPHandler) is left to its own mirror policy.
		if cfg.Cache.Sealed {
			b = backends.Seal(b)
		}
		if err := registry.Register(b); err != nil {
			return nil, nil, nil, fmt.Errorf("registering backend %q: %w", name, err)
		}
		logger.Info("registered upstream",
			"name", name, "type", up.Type, "url", up.URL,
			"authenticated", hasCredentials(up.Credentials),
			"tlsOverride", up.TLS != nil,
			"mirrors", len(up.Mirrors),
			"sealed", cfg.Cache.Sealed)
	}

	if registry.Len() == 0 {
		logger.Warn("no upstreams configured; gateway will serve no backend traffic")
	}
	return registry, gitRT, poolMgr, nil
}

// upstreamDoer returns the request executor a non-Git backend should use. When
// the upstream declares no mirrors it is the bare per-TLS-policy client. When it
// declares one or more mirrors it is a health-aware multi-mirror pool (Task 38)
// that fails over across the primary URL and the mirrors, which is registered in
// poolMgr so the admin API and metrics can observe it.
//
// Each endpoint gets a client built from its own TLS policy: the primary from
// the upstream's TLS override, each mirror from its own (falling back to the
// default outbound policy). Per-mirror credentials, when configured, override the
// request credentials for that mirror only; the primary inherits the backend's
// upstream credentials so existing auth-passthrough behavior is unchanged.
func upstreamDoer(cfg *config.Config, name string, up config.UpstreamConfig, clients *clientPool, creds upstream.Credentials, mgr *upstreampool.Manager, notifier notify.Emitter, logger *slog.Logger) (upstream.Doer, error) {
	primaryClient, err := clients.clientFor(up.TLS)
	if err != nil {
		return nil, err
	}
	if len(up.Mirrors) == 0 {
		return primaryClient, nil
	}

	// Shared client (default outbound TLS) for endpoints without a TLS override.
	sharedClient, err := clients.clientFor(nil)
	if err != nil {
		return nil, err
	}

	endpoints := make([]upstreampool.EndpointConfig, 0, len(up.Mirrors)+1)
	endpoints = append(endpoints, upstreampool.EndpointConfig{
		ID:     name + "-primary",
		URL:    up.URL,
		Client: primaryClient,
		// Primary inherits the backend's upstream credentials via the request; no
		// per-endpoint override so docker token-handshake behavior is preserved.
	})
	for i, m := range up.Mirrors {
		mirrorClient := sharedClient
		if m.TLS != nil {
			mc, cerr := clients.clientFor(m.TLS)
			if cerr != nil {
				return nil, cerr
			}
			mirrorClient = mc
		}
		id := strings.TrimSpace(m.ID)
		if id == "" {
			id = fmt.Sprintf("%s-mirror-%d", name, i+1)
		}
		endpoints = append(endpoints, upstreampool.EndpointConfig{
			ID:     id,
			URL:    m.URL,
			Client: mirrorClient,
			Credentials: upstream.Credentials{
				Username: m.Credentials.Username,
				Password: m.Credentials.Password,
				Token:    m.Credentials.Token,
			},
		})
	}

	p, err := upstreampool.New(upstreampool.Config{
		Backend:           name,
		Ecosystem:         up.Type,
		Endpoints:         endpoints,
		Client:            sharedClient,
		FailureThreshold:  up.Failover.FailureThreshold,
		SuccessThreshold:  up.Failover.SuccessThreshold,
		OpenTimeout:       up.Failover.OpenTimeout,
		HalfOpenMaxProbes: up.Failover.HalfOpenMaxProbes,
		Probe: upstreampool.ProbeConfig{
			Enabled:  up.Failover.Probe.Enabled,
			Interval: up.Failover.Probe.Interval,
			Timeout:  up.Failover.Probe.Timeout,
			Path:     up.Failover.Probe.Path,
		},
		Notifier: notifier,
		Logger:   logger,
	})
	if err != nil {
		return nil, err
	}
	if err := mgr.Add(p); err != nil {
		return nil, err
	}
	logger.Info("registered upstream mirror pool",
		"backend", name, "type", up.Type, "mirrors", len(up.Mirrors),
		"activeProbe", up.Failover.Probe.Enabled)
	return p, nil
}

// buildBackend constructs the backend for a single non-Git upstream.
// Package-manager ecosystems (pip, npm, cargo, go, nuget) get their
// protocol-aware backend from the pkgmgr package; maven, rubygems, composer, and
// helm get their dedicated self-contained backends; docker gets the Registry v2
// pull-through backend.
func buildBackend(cfg *config.Config, name string, up config.UpstreamConfig, client upstream.Doer, creds upstream.Credentials) (backends.Backend, error) {
	switch up.Type {
	case "pip", "npm", "cargo", "go", "nuget":
		return pkgmgr.Build(up.Type, pkgmgr.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
			Settings:      up.Settings,
		})
	case "maven":
		return maven.New(maven.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "rubygems":
		return rubygems.New(rubygems.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "composer":
		return composer.New(composer.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "helm":
		return helm.New(helm.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
			OCI:           strings.EqualFold(strings.TrimSpace(up.Settings["oci"]), "true"),
		})
	case "apt", "deb":
		gpgKey, err := loadBackendGPGKey(name, up.Settings)
		if err != nil {
			return nil, err
		}
		return apt.New(apt.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
			GPGKey:      gpgKey,
		})
	case "yum", "rpm":
		gpgKey, err := loadBackendGPGKey(name, up.Settings)
		if err != nil {
			return nil, err
		}
		return yum.New(yum.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
			GPGKey:      gpgKey,
		})
	case "terraform":
		return terraform.New(terraform.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "conan":
		return conan.New(conan.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "conda":
		return conda.New(conda.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "cpan":
		return cpan.New(cpan.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "cran":
		return cran.New(cran.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "hex":
		return hex.New(hex.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "bazel":
		return bazel.New(bazel.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "julia":
		return julia.New(julia.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "jsr":
		return jsr.New(jsr.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "hackage":
		return hackage.New(hackage.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "nix":
		return nix.New(nix.Options{
			Name:              name,
			UpstreamURL:       up.URL,
			PublicBaseURL:     pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			TrustedPublicKeys: splitSettingList(up.Settings["trustedPublicKeys"]),
			Client:            client,
			Credentials:       creds,
		})
	case "homebrew":
		return homebrew.New(homebrew.Options{
			Name:              name,
			UpstreamURL:       up.URL,
			PublicBaseURL:     pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			BottleRegistryURL: strings.TrimSpace(up.Settings["bottleRegistryUrl"]),
			Client:            client,
			Credentials:       creds,
			// A sealed (air-gapped) instance must not reach upstream from Resolve
			// either: skip the formula-API recovery of a bottle's version.
			Offline: cfg.Cache.Sealed,
		})
	case "ansible":
		return ansible.New(ansible.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "puppet":
		return puppet.New(puppet.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "huggingface":
		return huggingface.New(huggingface.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "openvsx":
		return openvsx.New(openvsx.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "swift":
		return swift.New(swift.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "dart", "pub":
		return dart.New(dart.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
		})
	case "docker":
		return docker.New(docker.Options{
			Name:        name,
			UpstreamURL: up.URL,
			Client:      client,
			Credentials: creds,
		})
	case "generic":
		// Config-driven declarative backend (Task 147). The generic block is
		// required and already validated by config.Validate at load; New
		// re-validates and compiles the route regexps.
		if up.Generic == nil {
			return nil, fmt.Errorf("generic upstream %q: a 'generic' configuration block is required", name)
		}
		return generic.New(generic.Options{
			Name:          name,
			UpstreamURL:   up.URL,
			PublicBaseURL: pkgmgr.PublicBase(cfg.Server.PublicURL, name),
			Client:        client,
			Credentials:   creds,
			Config:        *up.Generic,
		})
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", up.Type)
	}
}

// splitSettingList splits a backend setting value that carries a list of tokens
// (e.g. Nix trusted-public-keys) on commas and any whitespace, dropping empties.
// Nix public keys are "name:base64" with no internal whitespace or commas, so
// this cleanly recovers each key whether the operator wrote them space-separated
// (nix.conf style), comma-separated, or one per line.
func splitSettingList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// loadBackendGPGKey resolves the optional GPG keyring an OS-package backend
// (apt/yum) validates repository signatures against. It accepts an inline armored
// key ("gpgKey") or a path to one ("gpgKeyFile"); the inline form takes
// precedence. An empty result disables GPG enforcement for that upstream.
func loadBackendGPGKey(name string, settings map[string]string) ([]byte, error) {
	if inline := strings.TrimSpace(settings["gpgKey"]); inline != "" {
		return []byte(inline), nil
	}
	if path := strings.TrimSpace(settings["gpgKeyFile"]); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: reading gpgKeyFile: %w", name, err)
		}
		return data, nil
	}
	return nil, nil
}

// buildGitBackend constructs the dedicated Git proxy backend for one upstream
// and records its Upstream for the SSH resolver. HTTPS upstreams use a pooled
// outbound client (for pass-through serving when mirroring is off); SSH-transport
// upstreams require mirror mode.
func buildGitBackend(cfg *config.Config, name string, up config.UpstreamConfig, pool *clientPool, creds upstream.Credentials, mirror *git.Mirror, cacheImpl cache.Cache, logger *slog.Logger, gitRT *gitRuntime) (backends.Backend, error) {
	var client *upstream.Client
	if strings.HasPrefix(up.URL, "http://") || strings.HasPrefix(up.URL, "https://") {
		c, err := pool.clientFor(up.TLS)
		if err != nil {
			return nil, fmt.Errorf("building upstream client: %w", err)
		}
		client = c
	}

	s := up.Settings
	gitUp, err := git.NewUpstream(git.UpstreamOptions{
		Name:                     name,
		URL:                      up.URL,
		Credentials:              creds,
		Client:                   client,
		SSHKeyFile:               s["sshPrivateKeyFile"],
		SSHKnownHostsFile:        s["sshKnownHostsFile"],
		SSHInsecureIgnoreHostKey: s["sshInsecureIgnoreHostKey"] == "true",
	})
	if err != nil {
		return nil, err
	}
	gitRT.upstreams[name] = gitUp

	backend, err := git.NewBackend(git.BackendOptions{
		Upstream:    gitUp,
		Mirror:      mirror,
		Cache:       cacheImpl,
		InfoRefsTTL: cfg.Git.InfoRefsTTL,
		Logger:      logger,
		LFS: git.LFSOptions{
			Enabled:         cfg.Git.LFS.Enabled,
			MaxObjectBytes:  cfg.Git.LFS.MaxObjectBytes,
			ScanMaxBytes:    cfg.Git.LFS.ScanMaxBytes,
			BlockOnFindings: cfg.Git.LFS.BlockOnFindings,
		},
	})
	if err != nil {
		return nil, err
	}
	return backend, nil
}

// buildGitMirror constructs the Git mirror manager when mirroring is configured.
// A missing git binary is non-fatal: it logs a warning and returns nil so the
// proxy falls back to HTTPS pass-through (and the SSH endpoint stays disabled).
func buildGitMirror(cfg *config.Config, logger *slog.Logger) *git.Mirror {
	if cfg.Git.MirrorDir == "" {
		logger.Info("git mirroring disabled (set git.mirrorDir to cache packs/objects and enable SSH)")
		return nil
	}
	mirror, err := git.NewMirror(git.MirrorOptions{
		Root:            cfg.Git.MirrorDir,
		GitBinary:       cfg.Git.GitBinary,
		RefreshInterval: cfg.Git.RefreshInterval,
		FetchTimeout:    cfg.Git.FetchTimeout,
		Logger:          logger,
	})
	if err != nil {
		logger.Warn("git mirror unavailable; falling back to HTTPS pass-through", "error", err)
		return nil
	}
	logger.Info("git mirroring enabled", "dir", cfg.Git.MirrorDir)
	return mirror
}

// buildGitSSHServer constructs the inbound Git-over-SSH endpoint when configured.
// It requires both server.sshAddr and an active mirror; otherwise it returns a
// nil server (SSH disabled). The return type is the proxy.SSHServer interface so
// a disabled endpoint is a true nil interface, not a typed-nil pointer.
func buildGitSSHServer(cfg *config.Config, gitRT *gitRuntime, logger *slog.Logger) (proxy.SSHServer, error) {
	if cfg.Server.SSHAddr == "" {
		return nil, nil
	}
	if gitRT.mirror == nil {
		logger.Warn("git ssh endpoint requested but mirroring is unavailable; SSH disabled",
			"sshAddr", cfg.Server.SSHAddr)
		return nil, nil
	}
	srv, err := git.NewSSHServer(git.SSHServerOptions{
		Addr:               cfg.Server.SSHAddr,
		HostKeyFile:        cfg.Git.SSH.HostKeyFile,
		AuthorizedKeys:     cfg.Git.SSH.AuthorizedKeys,
		AuthorizedKeysFile: cfg.Git.SSH.AuthorizedKeysFile,
		NoClientAuth:       cfg.Git.SSH.NoClientAuth,
		Mirror:             gitRT.mirror,
		Resolve:            gitRT.resolve,
		Logger:             logger,
	})
	if err != nil {
		return nil, fmt.Errorf("building git ssh server: %w", err)
	}
	return srv, nil
}

// hasCredentials reports whether any upstream credential field is set.
func hasCredentials(c config.Credentials) bool {
	return c.Username != "" || c.Password != "" || c.Token != ""
}

// clientPool builds and memoizes outbound HTTP clients keyed by their effective
// TLS policy, so upstreams that share TLS settings also share a connection pool
// (and its keep-alive connections). Upstreams with a distinct TLS override —
// e.g. a private registry behind an internal CA — get a dedicated client.
type clientPool struct {
	base    config.OutboundConfig
	egress  *egress.Guard
	pins    *tlspin.Guard
	conn    *upstream.ConnMetrics
	clients map[string]*upstream.Client
}

func newClientPool(base config.OutboundConfig, egressGuard *egress.Guard, pinGuard *tlspin.Guard, conn *upstream.ConnMetrics) *clientPool {
	return &clientPool{base: base, egress: egressGuard, pins: pinGuard, conn: conn, clients: make(map[string]*upstream.Client)}
}

// buildEgress constructs the SSRF / outbound-egress guard (Task 89) from config.
// A disabled guard returns a nil *egress.Guard, which is a valid permissive no-op
// (and leaves the upstream transport unguarded). The tenant resolver reads the
// authenticated principal's team from the request context so per-tenant
// allowlists apply.
func buildEgress(cfg *config.Config, notifier notify.Emitter, logger *slog.Logger) (*egress.Guard, error) {
	e := cfg.Egress
	tenants := make(map[string]egress.TenantConfig, len(e.Tenants))
	for name, tc := range e.Tenants {
		tenants[name] = egress.TenantConfig{Allowlist: tc.Allowlist, HTTPSOnly: tc.HTTPSOnly}
	}
	guard, err := egress.New(egress.Config{
		Enabled:                 e.Enabled,
		HTTPSOnly:               e.HTTPSOnly,
		AllowedSchemes:          e.AllowedSchemes,
		Allowlist:               e.Allowlist,
		BlockPrivateNetworks:    e.BlockPrivateNetworks,
		AllowedDestinationCIDRs: e.AllowedDestinationCIDRs,
		FollowRedirects:         e.FollowRedirects,
		MaxRedirects:            e.MaxRedirects,
		TenantOverrides:         tenants,
	}, egress.Options{
		TenantFromContext: func(ctx context.Context) string {
			if p, ok := auth.FromContext(ctx); ok && p != nil {
				return p.Team
			}
			return ""
		},
		Notifier: notifier,
		Logger:   logger,
	})
	if err != nil {
		return nil, err
	}
	if guard.Enabled() {
		logger.Info("egress guard enabled",
			"httpsOnly", e.HTTPSOnly,
			"blockPrivateNetworks", e.BlockPrivateNetworks,
			"allowlistEntries", len(e.Allowlist),
			"maxRedirects", guard.Snapshot().MaxRedirects)
	}
	return guard, nil
}

// applyEgressHooks installs the egress guard's transport-level hooks onto an
// upstream.Options so every client built from it is uniformly guarded. A
// disabled (nil) guard is a no-op.
func applyEgressHooks(opts *upstream.Options, guard *egress.Guard) {
	if !guard.Enabled() {
		return
	}
	opts.WrapTransport = guard.WrapRoundTripper
	opts.DialControl = guard.DialControl
	opts.CheckRedirect = guard.CheckRedirect
}

// clientFor returns the client for the given per-upstream TLS override (nil to
// use the global default), constructing and caching it on first use.
func (p *clientPool) clientFor(override *config.TLSConfig) (*upstream.Client, error) {
	tlsCfg := p.base.TLS
	if override != nil {
		tlsCfg = *override
	}

	// The memoization key must distinguish every TLS policy that would build a
	// different client — including the pin set and report-only mode, so upstreams
	// with distinct pins never collide onto one shared (mis-pinned) connection
	// pool.
	key := fmt.Sprintf("%s\x00%t\x00%s\x00%s\x00%t",
		tlsCfg.CACertFile, tlsCfg.InsecureSkipVerify, tlsCfg.MinVersion,
		strings.Join(tlsCfg.Pins, "\x1f"), tlsCfg.PinReportOnly)
	if c, ok := p.clients[key]; ok {
		return c, nil
	}

	// Install the per-endpoint certificate/CA pinning hook (Task 128) when this
	// policy configures pins. A malformed pin is rejected at config-load time, so
	// an error here is defensive.
	verifyConn, err := p.pins.VerifierFor(tlspin.EndpointConfig{
		Pins:       tlsCfg.Pins,
		ReportOnly: tlsCfg.PinReportOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("upstream tls pinning: %w", err)
	}

	opts := upstream.Options{
		TLS: upstream.TLSOptions{
			CACertFile:         tlsCfg.CACertFile,
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
			MinVersion:         tlsCfg.MinVersion,
			VerifyConnection:   verifyConn,
		},
		DialTimeout:           p.base.DialTimeout,
		ResponseHeaderTimeout: p.base.ResponseHeaderTimeout,
		IdleConnTimeout:       p.base.IdleConnTimeout,
		TLSHandshakeTimeout:   p.base.TLSHandshakeTimeout,
		MaxIdleConns:          p.base.MaxIdleConns,
		MaxIdleConnsPerHost:   p.base.MaxIdleConnsPerHost,
		MaxConnsPerHost:       p.base.MaxConnsPerHost,
		KeepAlive:             p.base.KeepAlive,
		ExpectContinueTimeout: p.base.ExpectContinueTimeout,
		DisableKeepAlives:     p.base.DisableKeepAlives,
		DisableHTTP2:          p.base.DisableHTTP2,
		UserAgent:             p.base.UserAgent,
		// A single shared ConnMetrics aggregates connection-pool statistics across
		// every per-TLS-policy client the pool memoizes.
		ConnMetrics: p.conn,
	}
	applyEgressHooks(&opts, p.egress)
	c, err := upstream.New(opts)
	if err != nil {
		return nil, err
	}
	p.clients[key] = c
	return c, nil
}
