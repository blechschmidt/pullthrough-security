package vulnscan

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// ContentEvicter is the narrow slice of the content cache the re-scan subsystem
// needs: removing a poisoned artifact so it is not served from disk. The proxy's
// cache implementations satisfy it. It is optional; when nil, a quarantined
// artifact is still refused by the serve-path gate via the quarantine set, it is
// just not physically evicted.
type ContentEvicter interface {
	Delete(ctx context.Context, key string) error
}

// RescanAudit is the event handed to the audit callback when a cached artifact
// transitions to a blocking posture during a re-scan (CVE drift). The caller maps
// it onto its audit log; keeping it a plain struct keeps the vulnscan package free
// of an audit-package import (avoiding a cycle).
type RescanAudit struct {
	Digest      string
	Artifact    Artifact
	PrevAction  policy.Action
	NewAction   policy.Action
	Advisory    string
	MaxSeverity Severity
	MaxCVSS     float64
	Reason      string
	Quarantined bool
}

// AuditFunc receives a RescanAudit for each artifact that became newly vulnerable.
type AuditFunc func(ctx context.Context, ev RescanAudit)

// RescanConfig configures the background re-scan subsystem.
type RescanConfig struct {
	// Interval is the period between automatic re-scan sweeps. Zero (or negative)
	// disables the periodic schedule; on-demand triggers via the admin API still
	// work.
	Interval time.Duration
	// Workers bounds how many artifacts are re-resolved concurrently within a
	// sweep. Non-positive defaults to 4.
	Workers int
	// Tracer, when set, emits an OpenTelemetry span per re-scan sweep (Task 41)
	// so background CVE-drift latency is visible in the trace backend. A nil
	// Tracer is a no-op.
	Tracer *tracing.Tracer
}

// RiskChange records an artifact whose vulnerability posture changed between two
// re-scan sweeps — the unit surfaced through the admin "what changed" view.
type RiskChange struct {
	Digest          string         `json:"digest"`
	Artifact        Artifact       `json:"artifact"`
	PrevAction      policy.Action  `json:"prevAction"`
	NewAction       policy.Action  `json:"newAction"`
	PrevMaxSeverity Severity       `json:"prevMaxSeverity"`
	NewMaxSeverity  Severity       `json:"newMaxSeverity"`
	PrevCounts      SeverityCounts `json:"prevCounts"`
	NewCounts       SeverityCounts `json:"newCounts"`
	// NewAdvisories lists advisory IDs present after the re-scan but not before
	// (the freshly-disclosed CVEs that drove the change).
	NewAdvisories []string `json:"newAdvisories,omitempty"`
	// NewlyVulnerable is true when the artifact crossed from a servable posture to
	// a blocking one (block or quarantine) — i.e. it was quarantined.
	NewlyVulnerable bool      `json:"newlyVulnerable"`
	DetectedAt      time.Time `json:"detectedAt"`
}

// RescanSummary is the outcome of one re-scan sweep.
type RescanSummary struct {
	StartedAt       time.Time    `json:"startedAt"`
	CompletedAt     time.Time    `json:"completedAt"`
	Candidates      int          `json:"candidates"`
	Rescanned       int          `json:"rescanned"`
	Errors          int          `json:"errors"`
	Changed         int          `json:"changed"`
	NewlyVulnerable int          `json:"newlyVulnerable"`
	Changes         []RiskChange `json:"changes,omitempty"`
}

// Rescanner periodically (and on demand) re-runs the OSV/vulnscan pipeline over
// already-cached artifacts using their stored SBOMs, detecting vulnerabilities
// disclosed after an artifact was first pulled (CVE drift). It never re-downloads
// upstream content. When a previously-servable artifact crosses the policy
// threshold it is quarantined (so the serve-path gate refuses it), an audit event
// is emitted, and the change is recorded for the admin surface.
type Rescanner struct {
	svc     *Service
	evicter ContentEvicter
	auditFn AuditFunc
	logger  *slog.Logger
	cfg     RescanConfig

	trigger  chan chan RescanSummary
	done     chan struct{}
	started  sync.Once
	closed   sync.Once
	leaderFn func() bool

	mu          sync.Mutex
	lastSummary RescanSummary
	changes     []RiskChange // cumulative since last non-empty sweep
}

// NewRescanner constructs a Rescanner over the given scanning Service. svc is
// required. evicter and auditFn are optional. A nil logger uses slog.Default.
func NewRescanner(svc *Service, cfg RescanConfig, evicter ContentEvicter, auditFn AuditFunc, logger *slog.Logger) *Rescanner {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	return &Rescanner{
		svc:     svc,
		evicter: evicter,
		auditFn: auditFn,
		logger:  logger,
		cfg:     cfg,
		trigger: make(chan chan RescanSummary),
		done:    make(chan struct{}),
	}
}

// Interval returns the configured periodic interval (0 when periodic re-scans are
// disabled).
func (r *Rescanner) Interval() time.Duration { return r.cfg.Interval }

// SetLeaderGate installs a predicate consulted before each *periodic* sweep: the
// scheduler runs a sweep only when it returns true. It wires HA leader election
// (Task 56) so that across N replicas only the lease-holder re-scans cached
// artifacts and mutates the shared quarantine state, preventing duplicated work,
// quarantine races, and N× notifications. On-demand sweeps via Trigger (admin
// API) are never gated. A nil gate (the default) sweeps unconditionally. Call
// before Start.
func (r *Rescanner) SetLeaderGate(fn func() bool) { r.leaderFn = fn }

// Start launches the background loop: it runs a sweep every Interval (when set)
// and serves on-demand triggers, until ctx is cancelled or Close is called. It is
// idempotent. Periodic-disabled (Interval<=0) Rescanners still serve triggers.
func (r *Rescanner) Start(ctx context.Context) {
	if r.svc == nil {
		return
	}
	r.started.Do(func() {
		go r.loop(ctx)
		if r.cfg.Interval > 0 {
			r.logger.Info("cve drift re-scan scheduler started",
				"interval", r.cfg.Interval, "workers", r.cfg.Workers)
		} else {
			r.logger.Info("cve drift re-scan scheduler started (on-demand only)",
				"workers", r.cfg.Workers)
		}
	})
}

// Close stops the background loop. It is safe to call multiple times.
func (r *Rescanner) Close() {
	r.closed.Do(func() { close(r.done) })
}

func (r *Rescanner) loop(ctx context.Context) {
	var tick <-chan time.Time
	if r.cfg.Interval > 0 {
		t := time.NewTicker(r.cfg.Interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.done:
			return
		case <-tick:
			// In an HA deployment only the coordination leader runs the periodic
			// sweep; followers skip it so the shared quarantine state is mutated once.
			if r.leaderFn != nil && !r.leaderFn() {
				r.logger.Debug("cve drift re-scan: skipping scheduled sweep; not coordination leader")
				continue
			}
			r.RunOnce(ctx)
		case resp := <-r.trigger:
			resp <- r.RunOnce(ctx)
		}
	}
}

// Trigger requests an immediate sweep and waits for its summary. It is the
// admin-API on-demand entry point. It returns ctx.Err() if the caller's context
// is cancelled while waiting, or false-ok semantics via error when the scheduler
// is shut down.
func (r *Rescanner) Trigger(ctx context.Context) (RescanSummary, error) {
	resp := make(chan RescanSummary, 1)
	select {
	case r.trigger <- resp:
	case <-ctx.Done():
		return RescanSummary{}, ctx.Err()
	case <-r.done:
		return RescanSummary{}, context.Canceled
	}
	select {
	case s := <-resp:
		return s, nil
	case <-ctx.Done():
		return RescanSummary{}, ctx.Err()
	case <-r.done:
		return RescanSummary{}, context.Canceled
	}
}

// RunOnce performs a single re-scan sweep synchronously and returns its summary.
// It is exported so it can be invoked directly (e.g. in tests) without the loop.
// Concurrent sweeps are serialized through the loop; a direct caller is
// responsible for not racing the scheduler.
func (r *Rescanner) RunOnce(ctx context.Context) RescanSummary {
	// A sweep span roots a background trace so CVE-drift re-scan latency and
	// outcomes are visible in the trace backend; audit events emitted during the
	// sweep correlate to it via the context.
	ctx, span := r.cfg.Tracer.Start(ctx, "vulnscan.rescan.sweep",
		tracing.WithSpanKind(tracing.SpanKindInternal))
	defer span.End()

	started := time.Now()
	reports := r.svc.Reports()

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []rescanResult
		sem = make(chan struct{}, r.cfg.Workers)
	)

	for _, prev := range reports {
		if ctx.Err() != nil {
			break
		}
		// Only artifacts with a usable SBOM and a clean prior scan are re-scannable;
		// skip error/offline entries (nothing to re-resolve without re-downloading).
		if prev == nil || prev.Error != "" || prev.SBOM == nil {
			continue
		}
		prev := prev
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := r.rescanOne(ctx, prev)
			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}()
	}
	wg.Wait()

	summary := RescanSummary{StartedAt: started, Candidates: len(reports)}
	for _, res := range out {
		if res.ok {
			summary.Rescanned++
		}
		if res.err {
			summary.Errors++
		}
		if res.change != nil {
			summary.Changes = append(summary.Changes, *res.change)
			summary.Changed++
			if res.change.NewlyVulnerable {
				summary.NewlyVulnerable++
			}
		}
		if res.audit != nil && r.auditFn != nil {
			r.auditFn(ctx, *res.audit)
		}
	}
	sort.Slice(summary.Changes, func(i, j int) bool {
		return summary.Changes[i].DetectedAt.After(summary.Changes[j].DetectedAt)
	})
	summary.CompletedAt = time.Now()

	r.svc.counters.lastRescanUnix.Store(summary.CompletedAt.Unix())

	r.mu.Lock()
	r.lastSummary = summary
	if len(summary.Changes) > 0 {
		r.changes = summary.Changes
	}
	r.mu.Unlock()

	span.SetAttributes(
		tracing.Int("pullthrough.rescan.candidates", summary.Candidates),
		tracing.Int("pullthrough.rescan.rescanned", summary.Rescanned),
		tracing.Int("pullthrough.rescan.changed", summary.Changed),
		tracing.Int("pullthrough.rescan.newly_vulnerable", summary.NewlyVulnerable),
		tracing.Int("pullthrough.rescan.errors", summary.Errors),
	)

	r.logger.Info("cve drift re-scan sweep complete",
		"candidates", summary.Candidates,
		"rescanned", summary.Rescanned,
		"changed", summary.Changed,
		"newlyVulnerable", summary.NewlyVulnerable,
		"errors", summary.Errors,
		"duration", summary.CompletedAt.Sub(summary.StartedAt))
	return summary
}

// rescanResult is one artifact's outcome within a sweep.
type rescanResult struct {
	change *RiskChange
	audit  *RescanAudit
	ok     bool // a backend re-resolution actually happened
	err    bool
}

// rescanOne re-resolves a single cached artifact and computes any risk change,
// quarantining it (and emitting an audit event) when it became newly vulnerable.
func (r *Rescanner) rescanOne(ctx context.Context, prev *Report) (res rescanResult) {
	prevDecision := r.svc.EvaluateReport(prev)

	fresh, ok := r.svc.rescanReport(ctx, prev)
	if !ok {
		// fresh is non-nil only when a backend error occurred (retained fallback).
		res.err = fresh != nil
		return res
	}
	res.ok = true
	r.svc.counters.rescans.Add(1)

	newDecision := r.svc.EvaluateReport(fresh)

	if !riskChanged(prev, fresh, prevDecision, newDecision) {
		return res
	}

	change := &RiskChange{
		Digest:          fresh.Digest,
		Artifact:        fresh.Artifact,
		PrevAction:      prevDecision.Action,
		NewAction:       newDecision.Action,
		PrevMaxSeverity: prev.MaxSeverity,
		NewMaxSeverity:  fresh.MaxSeverity,
		PrevCounts:      prev.Counts,
		NewCounts:       fresh.Counts,
		NewAdvisories:   newAdvisories(prev, fresh),
		DetectedAt:      fresh.ScannedAt,
	}

	// Newly vulnerable: a previously-servable artifact crossed into a blocking
	// posture. Quarantine it so the policy/serve gate refuses future serves.
	if !prevDecision.Action.Blocked() && newDecision.Action.Blocked() {
		change.NewlyVulnerable = true
		r.svc.counters.newlyVulnerable.Add(1)

		entry := QuarantineEntry{
			Digest:        fresh.Digest,
			Artifact:      fresh.Artifact,
			Action:        policy.ActionQuarantine,
			Reason:        newDecision.Reason,
			MaxSeverity:   fresh.MaxSeverity,
			MaxCVSS:       fresh.MaxCVSS,
			Counts:        fresh.Counts,
			QuarantinedAt: fresh.ScannedAt,
		}
		if newDecision.Highest != nil {
			entry.Advisory = newDecision.Highest.ID
		}
		r.svc.quarantineDigest(entry)

		// Best-effort physical eviction of the cached content so it is not served
		// from disk. The quarantine set is the authoritative refusal; eviction is
		// belt-and-suspenders. The content key is the artifact's content digest.
		if r.evicter != nil && fresh.Digest != "" {
			if err := r.evicter.Delete(ctx, fresh.Digest); err != nil {
				r.logger.Debug("re-scan: content eviction skipped",
					"digest", fresh.Digest, "error", err)
			}
		}

		res.audit = &RescanAudit{
			Digest:      fresh.Digest,
			Artifact:    fresh.Artifact,
			PrevAction:  prevDecision.Action,
			NewAction:   newDecision.Action,
			Advisory:    entry.Advisory,
			MaxSeverity: fresh.MaxSeverity,
			MaxCVSS:     fresh.MaxCVSS,
			Reason:      newDecision.Reason,
			Quarantined: true,
		}
		r.logger.Warn("cve drift: cached artifact newly vulnerable; quarantined",
			"artifact", fresh.Artifact.Name, "version", fresh.Artifact.Version,
			"digest", fresh.Digest, "advisory", entry.Advisory,
			"maxSeverity", string(fresh.MaxSeverity), "maxCvss", fresh.MaxCVSS)
	}

	res.change = change
	return res
}

// LastSummary returns the most recent sweep summary.
func (r *Rescanner) LastSummary() RescanSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSummary
}

// RiskChanges returns the artifacts whose risk changed in the most recent sweep
// that produced any change.
func (r *Rescanner) RiskChanges() []RiskChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RiskChange, len(r.changes))
	copy(out, r.changes)
	return out
}

// riskChanged reports whether an artifact's posture changed between two reports.
func riskChanged(prev, fresh *Report, prevD, newD Decision) bool {
	if prevD.Action != newD.Action {
		return true
	}
	if prev.MaxSeverity != fresh.MaxSeverity || prev.MaxCVSS != fresh.MaxCVSS {
		return true
	}
	return prev.Counts != fresh.Counts
}

// newAdvisories returns the advisory IDs present in fresh but not in prev.
func newAdvisories(prev, fresh *Report) []string {
	had := make(map[string]bool, len(prev.Vulnerabilities))
	for i := range prev.Vulnerabilities {
		had[prev.Vulnerabilities[i].ID] = true
	}
	var out []string
	seen := make(map[string]bool)
	for i := range fresh.Vulnerabilities {
		id := fresh.Vulnerabilities[i].ID
		if id == "" || had[id] || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
