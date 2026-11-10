package vulnscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// Config configures the vulnerability-scanning Service.
type Config struct {
	// CacheTTL bounds how long a scan result is considered fresh. After it elapses
	// the artifact is re-scanned on next pull; a stale result is retained for the
	// offline fallback. 0 means results never expire.
	CacheTTL time.Duration
	// CacheMaxEntries bounds the result cache (0 = default).
	CacheMaxEntries int
	// Timeout bounds a single scan (SBOM resolution against the database). 0 uses
	// no additional deadline beyond the caller's context.
	Timeout time.Duration
	// Offline forces cache-only operation: the scanner backend is never contacted,
	// and an artifact with no cached result is treated as unscanned. Use in
	// air-gapped deployments fed by a pre-warmed result cache.
	Offline bool

	// FailSeverity is the minimum severity that triggers Action. Empty disables
	// severity-based gating.
	FailSeverity Severity
	// FailCVSS is the minimum CVSS base score that triggers Action (0 disables).
	// A finding trips the gate if it meets either FailSeverity or FailCVSS.
	FailCVSS float64
	// WarnSeverity is the minimum severity that triggers a warning (below the fail
	// threshold). Empty disables severity-based warnings.
	WarnSeverity Severity
	// Action is applied when the fail threshold is met: warn, block, or quarantine.
	// Empty defaults to block.
	Action policy.Action
	// FailOnError controls behavior when a scan cannot be performed and no cached
	// fallback exists: true blocks the artifact (fail-closed), false serves it with
	// a warning (fail-open, the default).
	FailOnError bool
	// IgnoreIDs is a set of advisory IDs (or aliases) to exclude from gating (an
	// operator-maintained allowlist of accepted/false-positive findings).
	IgnoreIDs []string

	// VEX is the optional VEX store (Task 27). When set, findings are correlated
	// against ingested VEX statements before gating: not_affected/fixed statements
	// suppress a finding, while affected statements raise its severity. Nil disables
	// VEX processing.
	VEX *VEXStore

	// Reachability configures static reachability analysis (Task 118). When enabled,
	// each finding is annotated reachable/unreachable/unknown via import analysis of
	// the artifact's source, and the configured action optionally downgrades or
	// suppresses findings proven unreachable from the artifact's own code.
	Reachability ReachabilityConfig
}

// ReachabilityConfig configures reachability-aware vulnerability prioritization
// (Task 118).
type ReachabilityConfig struct {
	// Enabled turns on reachability analysis and annotation. When false, findings
	// carry no reachability attribute and gate exactly as before.
	Enabled bool
	// UnreachableAction selects how a finding proven unreachable is treated:
	// annotate (default, record only), downgrade (lower severity one bucket), or
	// suppress (exclude from gating). Reachable and unknown findings are never
	// altered.
	UnreachableAction ReachabilityAction
}

// Snapshot is a point-in-time view of the subsystem's cumulative counters,
// surfaced through the metrics layer.
type Snapshot struct {
	ScansTotal       int64
	ScanErrors       int64
	CacheHits        int64
	OfflineFallbacks int64
	Blocked          int64
	Warned           int64
	Quarantined      int64
	VulnCritical     int64
	VulnHigh         int64
	VulnMedium       int64
	VulnLow          int64
	CacheEntries     int

	// Background re-scan (Task 18) telemetry.
	RescansTotal         int64
	NewlyVulnerableTotal int64
	// LastRescanUnix is the Unix timestamp (seconds) of the last completed
	// re-scan sweep, or 0 if none has run.
	LastRescanUnix int64
	// Quarantined artifacts currently held unservable by the re-scan subsystem.
	QuarantinedEntries int

	// VEX suppression/escalation (Task 27) telemetry.
	// VEXSuppressed and VEXEscalated are cumulative counts of findings dropped and
	// severity-raised by VEX statements across all scans.
	VEXSuppressed int64
	VEXEscalated  int64
	// VEXStatements / VEXDocuments are the currently-loaded VEX corpus size, and
	// VEXMalformed is how many documents failed to parse on the last load.
	VEXStatements int
	VEXDocuments  int
	VEXMalformed  int

	// Reachability (Task 118) telemetry: cumulative counts of findings classified
	// unreachable, and of those how many policy suppressed or downgraded.
	ReachUnreachable int64
	ReachSuppressed  int64
	ReachDowngraded  int64
}

// Service orchestrates SBOM generation, vulnerability resolution, result caching,
// and admission gating. It is safe for concurrent use.
type Service struct {
	cfg     Config
	scanner Scanner
	cache   *resultCache
	logger  *slog.Logger
	ignore  map[string]bool
	vex     *VEXStore
	reach   ReachabilityConfig

	// single-flights concurrent scans of the same digest so a thundering herd of
	// identical pulls performs the work once.
	inflight sync.Map // digest -> *scanOnce

	// quarantine records artifacts the background re-scan subsystem (Task 18) has
	// marked unservable because a CVE disclosed after they were cached pushed them
	// above the policy threshold. The serve-path gate consults it so a quarantined
	// digest is refused even if a stale (clean) cached scan result would otherwise
	// be served via the offline fallback.
	qmu        sync.Mutex
	quarantine map[string]QuarantineEntry

	counters struct {
		scans            atomic.Int64
		scanErrors       atomic.Int64
		cacheHits        atomic.Int64
		offlineFallbacks atomic.Int64
		blocked          atomic.Int64
		warned           atomic.Int64
		quarantined      atomic.Int64
		vulnCritical     atomic.Int64
		vulnHigh         atomic.Int64
		vulnMedium       atomic.Int64
		vulnLow          atomic.Int64

		// Background re-scan (Task 18) counters.
		rescans         atomic.Int64
		newlyVulnerable atomic.Int64
		lastRescanUnix  atomic.Int64

		// VEX suppression/escalation (Task 27) counters.
		vexSuppressed atomic.Int64
		vexEscalated  atomic.Int64

		// Reachability (Task 118) counters.
		reachUnreachable atomic.Int64
		reachSuppressed  atomic.Int64
		reachDowngraded  atomic.Int64
	}
}

// NewService constructs a Service with the given pluggable scanner. A nil scanner
// is an error unless Offline is set (cache-only operation needs no backend).
func NewService(cfg Config, scanner Scanner, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if scanner == nil && !cfg.Offline {
		return nil, errors.New("vulnscan: a scanner is required unless Offline is set")
	}
	if cfg.Action == "" {
		cfg.Action = policy.ActionBlock
	}
	ignore := make(map[string]bool, len(cfg.IgnoreIDs))
	for _, id := range cfg.IgnoreIDs {
		if id = strings.TrimSpace(id); id != "" {
			ignore[strings.ToLower(id)] = true
		}
	}
	reach := cfg.Reachability
	if reach.UnreachableAction == "" {
		reach.UnreachableAction = ReachActionAnnotate
	} else {
		reach.UnreachableAction = NormalizeReachabilityAction(string(reach.UnreachableAction))
	}
	return &Service{
		cfg:        cfg,
		scanner:    scanner,
		cache:      newResultCache(cfg.CacheTTL, cfg.CacheMaxEntries),
		logger:     logger,
		ignore:     ignore,
		vex:        cfg.VEX,
		reach:      reach,
		quarantine: make(map[string]QuarantineEntry),
	}, nil
}

// ContentOpener lazily opens the artifact content for SBOM extraction. It is
// invoked only on a cache miss so a cached result avoids re-reading the artifact.
// The returned stream is closed by the Service.
type ContentOpener func() (io.ReadCloser, error)

// scanOnce coordinates a single in-flight scan for a digest.
type scanOnce struct {
	done   chan struct{}
	report *Report
	err    error
}

// Assess returns the scan Report for an artifact, scanning on a cache miss.
// Concurrent assessments of the same digest are coalesced. When the scanner is
// unreachable, a stale cached result is returned (flagged Offline) if one exists;
// otherwise a Report carrying an Error is returned (and the gate applies the
// fail-open/closed posture). The returned error is non-nil only for an
// unrecoverable internal failure; an unreachable backend is reported via the
// Report, not the error.
func (s *Service) Assess(ctx context.Context, art Artifact, open ContentOpener) (*Report, error) {
	digest := art.Digest
	if digest == "" {
		// Without a content digest we cannot cache by content; scan inline.
		return s.scan(ctx, art, open), nil
	}

	if report, fresh, ok := s.cache.get(digest); ok && fresh {
		s.counters.cacheHits.Add(1)
		return report, nil
	}

	// Coalesce concurrent identical scans.
	once := &scanOnce{done: make(chan struct{})}
	actual, loaded := s.inflight.LoadOrStore(digest, once)
	if loaded {
		leader := actual.(*scanOnce)
		select {
		case <-leader.done:
			return leader.report, leader.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer func() {
		s.inflight.Delete(digest)
		close(once.done)
	}()

	// Re-check under leadership: a prior leader may have populated the cache in the
	// window between our cache miss above and acquiring the in-flight slot.
	if report, fresh, ok := s.cache.get(digest); ok && fresh {
		s.counters.cacheHits.Add(1)
		once.report = report
		return report, nil
	}

	report := s.scan(ctx, art, open)
	s.cache.put(digest, report)
	once.report = report
	return report, nil
}

// scan performs SBOM extraction and a single backend scan, applying offline
// handling. It always returns a non-nil Report.
func (s *Service) scan(ctx context.Context, art Artifact, open ContentOpener) *Report {
	if s.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	report := &Report{
		Digest:    art.Digest,
		Artifact:  art,
		ScannedAt: time.Now(),
	}

	// In offline mode we never contact the backend: a fresh entry was already
	// returned by Assess, so reaching here means no usable cached result exists.
	if s.cfg.Offline || s.scanner == nil {
		report.Error = "scanner offline and no cached result available"
		return report
	}

	var content io.ReadCloser
	if open != nil {
		c, err := open()
		if err != nil {
			s.logger.Warn("vulnscan: opening artifact content failed; scanning on coordinate only",
				"artifact", art.Name, "error", err)
		} else {
			content = c
			defer content.Close()
		}
	}

	// When reachability analysis is enabled, buffer the artifact content once so it
	// feeds both SBOM extraction and the import-reachability index; otherwise stream
	// it straight into the extractor (unchanged memory profile).
	var sbom *SBOM
	var reachIdx *reachabilityIndex
	if s.reach.Enabled && content != nil {
		data, err := readCapped(content, maxArtifactBytes)
		if err != nil && err != io.ErrShortBuffer {
			s.logger.Warn("vulnscan: reading artifact content for reachability failed; scanning on coordinate only",
				"artifact", art.Name, "error", err)
		}
		sbom, _ = Extract(art, bytes.NewReader(data))
		reachIdx = analyzeReachability(art, data)
	} else {
		sbom, _ = Extract(art, content)
	}
	report.SBOM = sbom
	report.Scanner = s.scanner.Name()

	vulns, err := s.scanner.Scan(ctx, sbom)
	s.counters.scans.Add(1)
	if err != nil {
		s.counters.scanErrors.Add(1)
		// Offline fallback: serve the last-known (stale) result if we have one.
		if stale, _, ok := s.cache.get(art.Digest); ok && stale != nil && stale.Error == "" {
			s.counters.offlineFallbacks.Add(1)
			s.logger.Warn("vulnscan: scanner unreachable; using stale cached result",
				"artifact", art.Name, "error", err)
			fallback := *stale
			fallback.Offline = true
			return &fallback
		}
		s.logger.Warn("vulnscan: scan failed and no cached fallback",
			"artifact", art.Name, "error", err)
		report.Error = err.Error()
		return report
	}

	report.Vulnerabilities = vulns
	s.applyReachability(report, reachIdx)
	s.applyVEX(ctx, report)
	report.summarize()
	s.recordFindings(report.Counts)
	return report
}

// applyVEX correlates each finding against the ingested VEX statements and
// annotates the report in place: a not_affected/fixed statement suppresses the
// finding (it is excluded from the counts, headline figures, and gating), while
// an affected statement raises the finding's severity. Every suppression and
// escalation is logged with its VEX source for audit, and the cumulative VEX
// counters are advanced. It is a no-op when no VEX store is configured.
//
// applyVEX must run before Report.summarize so the recomputed counts and headline
// severity reflect the suppressions and escalations.
func (s *Service) applyVEX(ctx context.Context, report *Report) {
	if s.vex == nil || report == nil || len(report.Vulnerabilities) == 0 {
		return
	}
	// Resolve the relevant statements once. An empty result still runs the reset
	// loop below so a revoked corpus re-activates a previously-suppressed finding.
	stmts := s.vex.statementsFor(ctx, report.Artifact)
	report.VEXSuppressed = 0
	report.VEXEscalated = 0
	for i := range report.Vulnerabilities {
		v := &report.Vulnerabilities[i]
		// Reset any prior VEX annotation so a re-scan reflects the current corpus
		// (this is how a revoked statement re-activates a previously-suppressed
		// finding).
		v.Suppressed = false
		v.VEXStatus = ""
		v.VEXJustification = ""
		v.VEXSource = ""
		if v.OriginalSeverity != "" {
			v.Severity = v.OriginalSeverity
			v.OriginalSeverity = ""
		}
		if v.Withdrawn || len(stmts) == 0 {
			continue
		}
		st, ok := matchStatement(stmts, report.Artifact, *v)
		if !ok {
			continue
		}
		v.VEXStatus = st.Status
		v.VEXJustification = st.Justification
		v.VEXSource = st.Source
		switch st.Status {
		case VEXNotAffected, VEXFixed:
			v.Suppressed = true
			report.VEXSuppressed++
			s.counters.vexSuppressed.Add(1)
			s.logger.Info("vulnscan: VEX suppressed finding",
				"artifact", report.Artifact.Name, "version", report.Artifact.Version,
				"advisory", v.ID, "component", v.Component,
				"status", string(st.Status), "justification", string(st.Justification),
				"vexSource", st.Source)
		case VEXAffected:
			orig := v.Severity
			raised := escalateSeverity(orig)
			if severityRank(raised) > severityRank(orig) {
				v.OriginalSeverity = orig
				v.Severity = raised
			}
			report.VEXEscalated++
			s.counters.vexEscalated.Add(1)
			s.logger.Warn("vulnscan: VEX escalated finding",
				"artifact", report.Artifact.Name, "version", report.Artifact.Version,
				"advisory", v.ID, "component", v.Component,
				"fromSeverity", string(orig), "toSeverity", string(v.Severity),
				"vexSource", st.Source)
		default:
			// under_investigation: annotated only.
		}
	}
}

// applyReachability annotates each finding with its reachability relative to the
// consuming artifact and, for findings proven unreachable, applies the configured
// action (downgrade severity or suppress from gating). It is a no-op when
// reachability analysis is disabled. idx may be nil (e.g. on a background re-scan
// that re-resolves from the stored SBOM without artifact content), in which case
// every non-primary finding is annotated Unknown and nothing is altered.
//
// applyReachability must run before applyVEX so a VEX operator statement — the
// authoritative adjudication — takes precedence over the heuristic reachability
// downgrade, and before Report.summarize so the recomputed counts and headline
// severity reflect any suppression or downgrade.
func (s *Service) applyReachability(report *Report, idx *reachabilityIndex) {
	if !s.reach.Enabled || report == nil || len(report.Vulnerabilities) == 0 {
		return
	}
	for i := range report.Vulnerabilities {
		v := &report.Vulnerabilities[i]
		// Reset any prior reachability annotation so a re-scan reflects the current
		// analysis (defensive: findings are normally produced fresh per scan).
		v.ReachSuppressed = false
		v.Reachability = ""
		v.ReachabilityReason = ""
		if v.ReachOriginalSeverity != "" {
			v.Severity = v.ReachOriginalSeverity
			v.ReachOriginalSeverity = ""
		}
		if v.Withdrawn {
			continue
		}
		isPrimary := s.vulnIsPrimary(report.Artifact, *v)
		r, reason := idx.classifyFinding(v.Package, v.AffectedModules, isPrimary)
		v.Reachability = r
		v.ReachabilityReason = reason
		if r != ReachabilityUnreachable {
			continue
		}
		s.counters.reachUnreachable.Add(1)
		switch s.reach.UnreachableAction {
		case ReachActionSuppress:
			v.ReachSuppressed = true
			s.counters.reachSuppressed.Add(1)
			s.logger.Info("vulnscan: reachability suppressed finding",
				"artifact", report.Artifact.Name, "version", report.Artifact.Version,
				"advisory", v.ID, "component", v.Component, "reason", reason)
		case ReachActionDowngrade:
			orig := v.Severity
			lowered := downgradeSeverity(orig)
			if severityRank(lowered) < severityRank(orig) {
				v.ReachOriginalSeverity = orig
				v.Severity = lowered
				s.counters.reachDowngraded.Add(1)
				s.logger.Info("vulnscan: reachability downgraded finding",
					"artifact", report.Artifact.Name, "version", report.Artifact.Version,
					"advisory", v.ID, "component", v.Component,
					"fromSeverity", string(orig), "toSeverity", string(lowered), "reason", reason)
			}
		}
	}
}

// vulnIsPrimary reports whether a finding is on the artifact itself (the primary
// SBOM component) rather than one of its dependencies. The artifact's coordinate
// name is the full package/module path, matching how osvToVulnerability populates
// Vulnerability.Package.
func (s *Service) vulnIsPrimary(art Artifact, v Vulnerability) bool {
	if !strings.EqualFold(strings.TrimSpace(v.Package), strings.TrimSpace(art.Name)) {
		return false
	}
	return art.Version == "" || v.Version == "" || v.Version == art.Version
}

// recordFindings accumulates per-severity finding counters.
func (s *Service) recordFindings(c SeverityCounts) {
	s.counters.vulnCritical.Add(int64(c.Critical))
	s.counters.vulnHigh.Add(int64(c.High))
	s.counters.vulnMedium.Add(int64(c.Medium))
	s.counters.vulnLow.Add(int64(c.Low))
}

// Decision is the gating outcome for an artifact's scan Report.
type Decision struct {
	Action policy.Action
	Code   string
	Reason string
	// Highest is the most severe gating finding, when the decision was driven by a
	// specific vulnerability.
	Highest *Vulnerability
}

// Gate evaluates a Report against the configured thresholds and returns the
// admission decision, recording the cumulative gate counters. A nil or empty
// report allows. Withdrawn and ignored findings are excluded.
func (s *Service) Gate(report *Report) Decision {
	d := s.evaluate(report)
	s.countDecision(d)
	return d
}

// EvaluateReport returns the admission decision for a report without touching the
// cumulative serve-path counters. The background re-scan subsystem (Task 18) uses
// it to compare an artifact's prior and current posture without inflating the
// blocked/warned/quarantined metrics that account for live client serves.
func (s *Service) EvaluateReport(report *Report) Decision { return s.evaluate(report) }

// evaluate is the pure gating logic shared by Gate (serve path) and
// EvaluateReport (re-scan path); it never mutates counters.
func (s *Service) evaluate(report *Report) Decision {
	if report == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok"}
	}

	// A failed scan with no usable result: apply the fail-open/closed posture.
	if report.Error != "" {
		if s.cfg.FailOnError {
			return Decision{Action: policy.ActionBlock, Code: "scan-error",
				Reason: "vulnerability scan could not be performed and the gate is fail-closed: " + report.Error}
		}
		return Decision{Action: policy.ActionWarn, Code: "scan-error",
			Reason: "vulnerability scan could not be performed; served with a warning: " + report.Error}
	}

	worst := s.worstGateable(report)
	if worst == nil {
		return Decision{Action: policy.ActionAllow, Code: "ok",
			Reason: fmt.Sprintf("no known vulnerabilities above policy threshold (%d scanned findings)", len(report.Vulnerabilities))}
	}

	// Does the worst finding meet the fail threshold (by severity OR CVSS)?
	if s.meetsFail(*worst) {
		return Decision{
			Action:  s.cfg.Action,
			Code:    "vulnerable",
			Reason:  gateReason(report, *worst, s.cfg.Action),
			Highest: worst,
		}
	}

	// Below fail but at/above the warn threshold?
	if s.cfg.WarnSeverity != "" && worst.Severity.AtLeast(s.cfg.WarnSeverity) {
		return Decision{
			Action:  policy.ActionWarn,
			Code:    "vulnerable",
			Reason:  gateReason(report, *worst, policy.ActionWarn),
			Highest: worst,
		}
	}

	return Decision{Action: policy.ActionAllow, Code: "ok",
		Reason: fmt.Sprintf("%d known vulnerabilities, none above policy threshold", report.Counts.Total())}
}

// countDecision records the cumulative gate counters for a decision, reproducing
// the exact accounting the inlined Gate logic performed before it was split out
// (a fail-open scan-error warning is intentionally not counted as a warning).
func (s *Service) countDecision(d Decision) {
	switch d.Code {
	case "scan-error":
		if d.Action == policy.ActionBlock {
			s.counters.blocked.Add(1)
		}
	case "vulnerable":
		switch d.Action {
		case policy.ActionQuarantine:
			s.counters.quarantined.Add(1)
		case policy.ActionWarn:
			s.counters.warned.Add(1)
		default:
			s.counters.blocked.Add(1)
		}
	}
}

// worstGateable returns the highest-severity finding eligible for gating
// (excluding withdrawn and ignored advisories).
func (s *Service) worstGateable(report *Report) *Vulnerability {
	var worst *Vulnerability
	for i := range report.Vulnerabilities {
		v := &report.Vulnerabilities[i]
		if v.Withdrawn || v.Suppressed || v.ReachSuppressed || s.isIgnored(v) {
			continue
		}
		if worst == nil || moreSevere(*v, *worst) {
			worst = v
		}
	}
	return worst
}

// meetsFail reports whether a finding trips the fail threshold by severity or by
// CVSS score.
func (s *Service) meetsFail(v Vulnerability) bool {
	if s.cfg.FailSeverity != "" && v.Severity.AtLeast(s.cfg.FailSeverity) {
		return true
	}
	if s.cfg.FailCVSS > 0 && v.CVSS >= s.cfg.FailCVSS {
		return true
	}
	return false
}

// isIgnored reports whether a finding's ID or any alias is on the ignore list.
func (s *Service) isIgnored(v *Vulnerability) bool {
	if len(s.ignore) == 0 {
		return false
	}
	if s.ignore[strings.ToLower(v.ID)] {
		return true
	}
	for _, a := range v.Aliases {
		if s.ignore[strings.ToLower(a)] {
			return true
		}
	}
	return false
}

// moreSevere reports whether a outranks b by severity then CVSS.
func moreSevere(a, b Vulnerability) bool {
	if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
		return ra > rb
	}
	return a.CVSS > b.CVSS
}

// gateReason renders an actionable explanation for a gating decision.
func gateReason(report *Report, v Vulnerability, action policy.Action) string {
	verb := "blocked"
	switch action {
	case policy.ActionWarn:
		verb = "flagged"
	case policy.ActionQuarantine:
		verb = "quarantined"
	}
	fix := ""
	if len(v.FixedVersions) > 0 {
		fix = fmt.Sprintf(" A fix is available in version(s): %s.", strings.Join(v.FixedVersions, ", "))
	}
	score := ""
	if v.CVSS > 0 {
		score = fmt.Sprintf(" CVSS %.1f.", v.CVSS)
	}
	return fmt.Sprintf("%s %s@%s %s by vulnerability policy: %s (%s severity)%s.%s "+
		"Total findings: %d critical, %d high, %d medium, %d low.",
		report.Artifact.Ecosystem, v.Package, v.Version, verb,
		v.ID, v.Severity, score, fix,
		report.Counts.Critical, report.Counts.High, report.Counts.Medium, report.Counts.Low)
}

// Report returns the cached scan Report for a content digest, if present.
func (s *Service) Report(digest string) (*Report, bool) {
	report, _, ok := s.cache.get(digest)
	return report, ok
}

// Reports lists the cached scan Reports (most-recent first), for the admin and
// observability surfaces.
func (s *Service) Reports() []*Report { return s.cache.snapshot() }

// Evict removes an artifact's cached scan result. The gateway calls it when an
// artifact is quarantined so a re-pull re-scans rather than serving the cached
// (poisoned) verdict.
func (s *Service) Evict(digest string) { s.cache.delete(digest) }

// rescanReport re-resolves a previously-cached artifact against the vulnerability
// backend using its stored SBOM, without re-reading (re-downloading) the artifact
// content. On success it replaces the cached Report and returns it; the caller
// compares the prior and refreshed reports to detect CVE drift. A backend error
// leaves the cached result untouched and returns it (flagged Offline) so a
// transient outage never erases a known-good assessment.
//
// It returns (nil, false) when the prior report has no usable SBOM to re-scan
// (e.g. it recorded a scan error) or the service is offline, since there is
// nothing to re-resolve without contacting the backend.
func (s *Service) rescanReport(ctx context.Context, prev *Report) (*Report, bool) {
	if prev == nil || prev.Error != "" || prev.SBOM == nil {
		return nil, false
	}
	if s.cfg.Offline || s.scanner == nil {
		return nil, false
	}

	if s.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	vulns, err := s.scanner.Scan(ctx, prev.SBOM)
	s.counters.scans.Add(1)
	if err != nil {
		s.counters.scanErrors.Add(1)
		s.logger.Warn("vulnscan: re-scan failed; retaining prior cached result",
			"artifact", prev.Artifact.Name, "digest", prev.Digest, "error", err)
		fallback := *prev
		fallback.Offline = true
		return &fallback, false
	}

	report := &Report{
		Digest:          prev.Digest,
		Artifact:        prev.Artifact,
		Scanner:         s.scanner.Name(),
		SBOM:            prev.SBOM,
		Vulnerabilities: vulns,
		ScannedAt:       time.Now(),
	}
	// A re-scan re-resolves from the stored SBOM without re-reading artifact content,
	// so no source is available for reachability analysis; findings are annotated
	// Unknown (never downgraded/suppressed) — conservative for CVE-drift detection.
	s.applyReachability(report, nil)
	s.applyVEX(ctx, report)
	report.summarize()
	s.recordFindings(report.Counts)
	s.cache.put(prev.Digest, report)
	return report, true
}

// QuarantineEntry records an artifact the re-scan subsystem has marked unservable
// because newly-disclosed vulnerabilities pushed it above the policy threshold.
type QuarantineEntry struct {
	Digest        string         `json:"digest"`
	Artifact      Artifact       `json:"artifact"`
	Action        policy.Action  `json:"action"`
	Reason        string         `json:"reason"`
	Advisory      string         `json:"advisory,omitempty"`
	MaxSeverity   Severity       `json:"maxSeverity"`
	MaxCVSS       float64        `json:"maxCvss,omitempty"`
	Counts        SeverityCounts `json:"counts"`
	QuarantinedAt time.Time      `json:"quarantinedAt"`
}

// quarantineDigest records a digest as quarantined so the serve-path gate refuses
// it on every subsequent pull, independent of the (possibly stale) cached scan
// result.
func (s *Service) quarantineDigest(entry QuarantineEntry) {
	if entry.Digest == "" {
		return
	}
	s.qmu.Lock()
	s.quarantine[entry.Digest] = entry
	s.qmu.Unlock()
}

// QuarantineInfo returns the quarantine record for a digest, if the artifact has
// been quarantined.
func (s *Service) QuarantineInfo(digest string) (QuarantineEntry, bool) {
	if digest == "" {
		return QuarantineEntry{}, false
	}
	s.qmu.Lock()
	defer s.qmu.Unlock()
	e, ok := s.quarantine[digest]
	return e, ok
}

// IsQuarantined reports whether a digest is currently quarantined.
func (s *Service) IsQuarantined(digest string) bool {
	_, ok := s.QuarantineInfo(digest)
	return ok
}

// Quarantined lists the current quarantine records (most-recent first), for the
// admin surface.
func (s *Service) Quarantined() []QuarantineEntry {
	s.qmu.Lock()
	defer s.qmu.Unlock()
	out := make([]QuarantineEntry, 0, len(s.quarantine))
	for _, e := range s.quarantine {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QuarantinedAt.After(out[j].QuarantinedAt) })
	return out
}

// ReleaseQuarantine lifts an artifact's quarantine (operator override after the
// finding is triaged) and drops its cached scan result so the next pull re-scans.
func (s *Service) ReleaseQuarantine(digest string) bool {
	s.qmu.Lock()
	_, ok := s.quarantine[digest]
	delete(s.quarantine, digest)
	s.qmu.Unlock()
	if ok {
		s.cache.delete(digest)
	}
	return ok
}

// GateAction returns the action applied when the fail threshold is met.
func (s *Service) GateAction() policy.Action { return s.cfg.Action }

// VEXEnabled reports whether a VEX store is configured.
func (s *Service) VEXEnabled() bool { return s.vex != nil }

// VEXStats returns the loaded VEX corpus statistics (zero value when no store is
// configured).
func (s *Service) VEXStats() VEXStats {
	if s.vex == nil {
		return VEXStats{}
	}
	return s.vex.Stats()
}

// VEXStatements returns the loaded static VEX statements (empty when no store is
// configured), for the admin surface.
func (s *Service) VEXStatements() []VEXStatement {
	if s.vex == nil {
		return nil
	}
	return s.vex.Statements()
}

// ScannerName returns the active backend's name (or "offline").
func (s *Service) ScannerName() string {
	if s.scanner == nil {
		return "offline"
	}
	return s.scanner.Name()
}

// Metrics returns a snapshot of the cumulative counters.
func (s *Service) Metrics() Snapshot {
	var vexStats VEXStats
	if s.vex != nil {
		vexStats = s.vex.Stats()
	}
	return Snapshot{
		ScansTotal:       s.counters.scans.Load(),
		ScanErrors:       s.counters.scanErrors.Load(),
		CacheHits:        s.counters.cacheHits.Load(),
		OfflineFallbacks: s.counters.offlineFallbacks.Load(),
		Blocked:          s.counters.blocked.Load(),
		Warned:           s.counters.warned.Load(),
		Quarantined:      s.counters.quarantined.Load(),
		VulnCritical:     s.counters.vulnCritical.Load(),
		VulnHigh:         s.counters.vulnHigh.Load(),
		VulnMedium:       s.counters.vulnMedium.Load(),
		VulnLow:          s.counters.vulnLow.Load(),
		CacheEntries:     s.cache.size(),

		RescansTotal:         s.counters.rescans.Load(),
		NewlyVulnerableTotal: s.counters.newlyVulnerable.Load(),
		LastRescanUnix:       s.counters.lastRescanUnix.Load(),
		QuarantinedEntries:   s.quarantineCount(),

		VEXSuppressed: s.counters.vexSuppressed.Load(),
		VEXEscalated:  s.counters.vexEscalated.Load(),
		VEXStatements: vexStats.Statements,
		VEXDocuments:  vexStats.Documents,
		VEXMalformed:  vexStats.Malformed,

		ReachUnreachable: s.counters.reachUnreachable.Load(),
		ReachSuppressed:  s.counters.reachSuppressed.Load(),
		ReachDowngraded:  s.counters.reachDowngraded.Load(),
	}
}

// ReachabilityEnabled reports whether static reachability analysis is enabled.
func (s *Service) ReachabilityEnabled() bool { return s.reach.Enabled }

// quarantineCount returns the number of currently-quarantined artifacts.
func (s *Service) quarantineCount() int {
	s.qmu.Lock()
	defer s.qmu.Unlock()
	return len(s.quarantine)
}
