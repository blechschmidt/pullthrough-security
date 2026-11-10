// Package sbomexport pushes the proxy's generated SBOMs (Task 15/64) and
// admission-gate findings into external supply-chain graph systems (Task 153).
//
// It renders each cached scan report into a CycloneDX 1.5 document — the stored
// SBOM, optionally enriched with the artifact's vulnerability findings as a
// CycloneDX vulnerabilities array — and delivers it to one or both pluggable
// sinks:
//
//   - an OWASP Dependency-Track client that uploads the CycloneDX BOM per
//     project/coordinate via PUT /api/v1/bom with API-key auth and project
//     auto-create, and
//   - a GUAC ingestion sink that emits the CycloneDX (or in-toto-wrapped)
//     document to a GUAC collector endpoint.
//
// A periodic, leader-gated sweep (Task 56) ensures only one HA node exports; an
// operator can also trigger an immediate export on a specific node, which
// bypasses the leader gate. Credentials are resolved through the secrets
// provider (Task 133) before the service is built, and delivery is instrumented
// with pullthrough_sbomexport_* metrics (uploads, failures, retries).
package sbomexport

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// ReportSource provides the scan reports (SBOM + findings) to export.
// *vulnscan.Service satisfies it via its Reports method.
type ReportSource interface {
	Reports() []*vulnscan.Report
}

// Config is the resolved, in-process configuration of the export service. The
// cmd layer translates config.SBOMExportConfig (including secretRef resolution)
// into this and the sink constructors.
type Config struct {
	// IncludeFindings embeds admission-gate vulnerability findings into exported
	// BOMs as CycloneDX vulnerabilities.
	IncludeFindings bool
	// MinSeverity drops embedded findings below this floor (empty = keep all).
	MinSeverity vulnscan.Severity
	// Interval drives the periodic leader-gated export sweep. A non-positive value
	// disables the automatic sweep (manual trigger only).
	Interval time.Duration
	// MaxRetries is the number of additional attempts after the first on a
	// retryable (5xx/429/network) failure.
	MaxRetries int
	// RetryBaseDelay is the base of the exponential backoff; RetryMaxDelay caps it.
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	// Timeout bounds a single upload attempt.
	Timeout time.Duration
}

// RunReport summarizes one export sweep.
type RunReport struct {
	Reports  int `json:"reports"`
	Uploaded int `json:"uploaded"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
}

// Status is the operator-facing view of the subsystem (admin + ptctl).
type Status struct {
	Enabled   bool      `json:"enabled"`
	Sinks     []string  `json:"sinks"`
	Interval  string    `json:"interval,omitempty"`
	Leader    bool      `json:"leader"`
	LastRunAt time.Time `json:"lastRunAt,omitempty"`
	LastRun   RunReport `json:"lastRun"`
	Snapshot  Snapshot  `json:"metrics"`
}

// Service orchestrates rendering and delivery of SBOM/finding documents to the
// configured sinks. A nil *Service is inert (every method is a safe no-op),
// which lets the cmd layer treat "disabled" uniformly.
type Service struct {
	cfg    Config
	source ReportSource
	sinks  []Sink
	log    *slog.Logger

	leaderGate func() bool

	metrics metricsState

	mu        sync.Mutex
	lastRunAt time.Time
	lastRun   RunReport

	stop     chan struct{}
	stopOnce sync.Once
	started  bool
}

// New constructs an export service. It returns nil when no sinks are configured
// (nothing to export), so callers can treat the result as "disabled".
func New(cfg Config, source ReportSource, sinks []Sink, log *slog.Logger) *Service {
	if len(sinks) == 0 || source == nil {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	return &Service{
		cfg:    cfg,
		source: source,
		sinks:  sinks,
		log:    log,
		stop:   make(chan struct{}),
	}
}

// SetLeaderGate installs the HA leadership predicate (Task 56). When it returns
// false the periodic sweep is skipped on this node; the manual Trigger path
// ignores the gate (an operator explicitly asked this node to export). A nil
// gate means always-leader.
func (s *Service) SetLeaderGate(fn func() bool) {
	if s == nil {
		return
	}
	s.leaderGate = fn
}

func (s *Service) isLeader() bool {
	if s == nil || s.leaderGate == nil {
		return true
	}
	return s.leaderGate()
}

// Start launches the periodic leader-gated export sweep when an Interval is
// configured. It is a no-op when the service is nil, already started, or has no
// interval (manual-trigger-only).
func (s *Service) Start(ctx context.Context) {
	if s == nil || s.started || s.cfg.Interval <= 0 {
		return
	}
	s.started = true
	go s.loop(ctx)
}

func (s *Service) loop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-ticker.C:
			if !s.isLeader() {
				s.log.Debug("sbomexport: skipping sweep (not leader)")
				continue
			}
			rep := s.export(ctx)
			s.log.Info("sbomexport: periodic sweep complete",
				"reports", rep.Reports, "uploaded", rep.Uploaded,
				"failed", rep.Failed, "skipped", rep.Skipped)
		}
	}
}

// Close stops the periodic sweep. It is idempotent and safe on a nil service.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

// Trigger runs an immediate export sweep on this node, bypassing the HA leader
// gate (an operator explicitly targeted this node). It is safe on a nil service.
func (s *Service) Trigger(ctx context.Context) (RunReport, error) {
	if s == nil {
		return RunReport{}, nil
	}
	return s.export(ctx), nil
}

// export renders every available report and delivers it to every sink,
// recording per-sink metrics and the last-run summary.
func (s *Service) export(ctx context.Context) RunReport {
	reports := s.source.Reports()
	var rep RunReport
	rep.Reports = len(reports)
	for _, r := range reports {
		if ctx.Err() != nil {
			break
		}
		item, ok, err := buildItem(r, s.cfg.IncludeFindings, s.cfg.MinSeverity)
		if err != nil {
			s.log.Warn("sbomexport: rendering BOM failed", "error", err)
			rep.Skipped++
			s.metrics.recordSkipped(1)
			continue
		}
		if !ok {
			rep.Skipped++
			s.metrics.recordSkipped(1)
			continue
		}
		for _, sink := range s.sinks {
			if err := s.deliver(ctx, sink, item); err != nil {
				s.metrics.recordFailure(sink.Target())
				rep.Failed++
				s.log.Warn("sbomexport: delivery failed",
					"sink", sink.Name(), "target", sink.Target(),
					"coordinate", coordinate(r.Artifact), "error", err)
				continue
			}
			s.metrics.recordUpload(sink.Target())
			rep.Uploaded++
		}
	}

	s.mu.Lock()
	s.lastRunAt = time.Now()
	s.lastRun = rep
	s.mu.Unlock()
	return rep
}

// deliver sends one item to one sink with bounded exponential-backoff retries.
// Each attempt is bounded by the configured per-attempt Timeout.
func (s *Service) deliver(ctx context.Context, sink Sink, item ExportItem) error {
	var lastErr error
	for attempt := 0; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, s.attemptTimeout())
		err := sink.Upload(attemptCtx, item)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt >= s.cfg.MaxRetries || !isRetryable(err) {
			return lastErr
		}
		s.metrics.recordRetry()
		if !s.backoff(ctx, attempt) {
			return lastErr
		}
	}
}

func (s *Service) attemptTimeout() time.Duration {
	if s.cfg.Timeout > 0 {
		return s.cfg.Timeout
	}
	return 30 * time.Second
}

// backoff sleeps for the exponential delay of the given (zero-based) attempt,
// returning false if the context is cancelled or the service is closing so the
// retry loop can abort promptly.
func (s *Service) backoff(ctx context.Context, attempt int) bool {
	base := s.cfg.RetryBaseDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	maxDelay := s.cfg.RetryMaxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	delay := base << attempt
	if delay <= 0 || delay > maxDelay {
		delay = maxDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-s.stop:
		return false
	case <-timer.C:
		return true
	}
}

// Metrics returns a snapshot of the cumulative counters. Safe on a nil service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return s.metrics.snapshot()
}

// Status returns the operator-facing view of the subsystem. Safe on a nil
// service (returns Enabled=false).
func (s *Service) Status() Status {
	if s == nil {
		return Status{Enabled: false}
	}
	s.mu.Lock()
	lastRunAt := s.lastRunAt
	lastRun := s.lastRun
	s.mu.Unlock()
	names := make([]string, 0, len(s.sinks))
	for _, sink := range s.sinks {
		names = append(names, sink.Name())
	}
	interval := ""
	if s.cfg.Interval > 0 {
		interval = s.cfg.Interval.String()
	}
	return Status{
		Enabled:   true,
		Sinks:     names,
		Interval:  interval,
		Leader:    s.isLeader(),
		LastRunAt: lastRunAt,
		LastRun:   lastRun,
		Snapshot:  s.metrics.snapshot(),
	}
}
