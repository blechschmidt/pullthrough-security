// Package prewarm implements an optional predictive cache pre-warming subsystem
// (Task 134). It analyses historical pull telemetry — a bounded, in-process
// record of the coordinates clients actually pull, fed by a tap on the gateway's
// serve path — and forecasts likely near-future pulls: new patch/minor releases
// of frequently-pulled coordinates and transitive dependencies of recently-
// pulled top-level packages. It then proactively fetches and admission-gates
// those artifacts during off-peak windows, through the proxy's full gated pull
// pipeline, so cache hits and gate verdicts are ready before the first client
// request.
//
// Safety properties, all enforced here or by construction:
//
//   - Disabled by default, behind its own config stanza.
//   - Leader-election aware: in an HA deployment only the coordination leader
//     (Task 56) runs the periodic cycle, so pre-warming happens once cluster-wide.
//   - Rate- and concurrency-bounded, so a prediction burst cannot hammer an
//     upstream.
//   - Respects the SSRF egress allowlist and the emergency kill-switch: every
//     fetch goes through the gated pull path (which enforces the egress allowlist
//     at the transport layer and refuses upstream fetches under a freeze
//     lockdown), and the scheduler additionally short-circuits an entire cycle
//     when the kill-switch is engaged.
//   - A pre-warmed artifact that fails an admission gate is recorded (and
//     quarantined by the pull pipeline) but never served implicitly — the gate
//     pipeline refuses and evicts it exactly as it would for a client pull.
//
// A nil *Service is a valid no-op so the subsystem can be left unconfigured
// without nil checks at the call sites.
package prewarm

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	defaultInterval       = time.Hour
	defaultMaxConcurrency = 2
	defaultMaxPerCycle    = 50
	defaultHistorySize    = 4096
	maxPrewarmedTracked   = 8192
)

// Skip reasons recorded when a scheduled cycle does not run.
const (
	skipNotLeader  = "not-leader"
	skipKillSwitch = "kill-switch"
	skipOffPeak    = "off-peak"
	skipNoFetcher  = "no-fetcher"
)

// Config configures the subsystem. The zero value is disabled.
type Config struct {
	Enabled bool
	// Interval is the periodic prediction+pre-warm cycle cadence (default 1h).
	Interval time.Duration
	// OffPeakStart / OffPeakEnd bound the daily window (local to OffPeakTimezone)
	// in which pre-warming may run, as "HH:MM". Both empty means any time. A window
	// may wrap midnight (e.g. start 22:00, end 05:00).
	OffPeakStart    string
	OffPeakEnd      string
	OffPeakTimezone string
	// MaxConcurrency bounds parallel pre-warm fetches (default 2).
	MaxConcurrency int
	// MaxPerCycle caps how many predicted targets are fetched per cycle (default
	// 50), bounding a single cycle's upstream load.
	MaxPerCycle int
	// RatePerMinute caps the pre-warm fetch rate across the cycle (0 = unlimited).
	RatePerMinute int

	// Predictor tuning.
	MinPulls       int
	RecencyWindow  time.Duration
	PatchLookahead int
	PredictMinor   bool
	TransitiveDeps bool

	// HistorySize bounds the distinct coordinates tracked (default 4096).
	HistorySize int
	// HistoryPath, when set, persists learned history to disk so it survives a
	// restart.
	HistoryPath string
}

// Deps carries the subsystem's collaborators. All are optional and may be wired
// after construction (Fetcher via SetFetcher, the leader gate via SetLeaderGate,
// the kill-switch via SetKillSwitch).
type Deps struct {
	Fetcher   Fetcher
	DepSource DepSource
	Predictor Predictor // overrides the built-in heuristic predictor when set
	Metrics   *Metrics
	Logger    *slog.Logger
	Clock     func() time.Time
}

// RunReport summarizes a single cycle.
type RunReport struct {
	StartedAt     time.Time `json:"startedAt"`
	FinishedAt    time.Time `json:"finishedAt"`
	Predicted     int       `json:"predicted"`
	Fetched       int       `json:"fetched"`
	AlreadyCached int       `json:"alreadyCached"`
	GateBlocked   int       `json:"gateBlocked"`
	Errors        int       `json:"errors"`
	// Skipped is the reason the cycle did not run (empty when it did).
	Skipped string `json:"skipped,omitempty"`
}

type prewarmedEntry struct {
	warmedAt   time.Time
	attributed bool
}

// Service is the pre-warming scheduler.
type Service struct {
	cfg       Config
	history   *History
	predictor Predictor
	metrics   *Metrics
	logger    *slog.Logger
	now       func() time.Time

	// Off-peak window, pre-compiled. startMin < 0 means "always open".
	startMin int
	endMin   int
	loc      *time.Location

	mu         sync.Mutex
	fetcher    Fetcher
	leaderFn   func() bool
	killSwitch func() bool
	prewarmed  map[string]prewarmedEntry // key backend\x00path
	lastRun    RunReport

	rateMu   sync.Mutex
	nextSlot time.Time

	trigger   chan chan RunReport
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	started   bool
}

// New constructs the subsystem. It returns (nil, nil) when disabled, so a caller
// can wire it unconditionally. A non-nil error indicates misconfiguration.
func New(cfg Config, deps Deps) (*Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := deps.Clock
	if now == nil {
		now = time.Now
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = defaultMaxConcurrency
	}
	if cfg.MaxPerCycle <= 0 {
		cfg.MaxPerCycle = defaultMaxPerCycle
	}
	if cfg.HistorySize <= 0 {
		cfg.HistorySize = defaultHistorySize
	}

	startMin, endMin, loc, err := compileWindow(cfg.OffPeakStart, cfg.OffPeakEnd, cfg.OffPeakTimezone)
	if err != nil {
		return nil, err
	}

	metrics := deps.Metrics
	if metrics == nil {
		metrics = NewMetrics()
	}

	history := NewHistory(cfg.HistorySize, now)
	if cfg.HistoryPath != "" {
		if lerr := history.Load(cfg.HistoryPath); lerr != nil {
			// A corrupt or unreadable history file must not prevent startup; log and
			// begin with an empty history.
			logger.Warn("prewarm: could not load persisted history; starting empty",
				"path", cfg.HistoryPath, "error", lerr)
		}
	}

	predictor := deps.Predictor
	if predictor == nil {
		predictor = NewHeuristicPredictor(HeuristicConfig{
			MinPulls:       cfg.MinPulls,
			RecencyWindow:  cfg.RecencyWindow,
			PatchLookahead: cfg.PatchLookahead,
			PredictMinor:   cfg.PredictMinor,
			TransitiveDeps: cfg.TransitiveDeps,
			MaxCandidates:  cfg.MaxPerCycle,
		}, deps.DepSource)
	}

	return &Service{
		cfg:       cfg,
		history:   history,
		predictor: predictor,
		metrics:   metrics,
		logger:    logger,
		now:       now,
		startMin:  startMin,
		endMin:    endMin,
		loc:       loc,
		fetcher:   deps.Fetcher,
		prewarmed: make(map[string]prewarmedEntry),
		trigger:   make(chan chan RunReport),
		done:      make(chan struct{}),
	}, nil
}

// Metrics returns the metrics accumulator (for the Prometheus bridge). Safe on
// nil.
func (s *Service) Metrics() *Metrics {
	if s == nil {
		return nil
	}
	return s.metrics
}

// SetFetcher installs the gated-pull fetcher. It is set after construction
// because the fetcher owns the gateway, which is built after this service (whose
// pull-observer tap the gateway in turn depends on). Call before Start.
func (s *Service) SetFetcher(f Fetcher) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.fetcher = f
	s.mu.Unlock()
}

// SetLeaderGate installs the HA leader predicate consulted before each periodic
// cycle; followers skip it so only the lease-holder pre-warms. On-demand Trigger
// runs are never leader-gated. A nil gate pre-warms unconditionally. Call before
// Start.
func (s *Service) SetLeaderGate(fn func() bool) {
	if s == nil {
		return
	}
	s.leaderFn = fn
}

// SetKillSwitch installs the emergency kill-switch predicate: when it returns
// true (a lockdown is engaged) the scheduler skips the entire cycle without
// attempting any fetch. Call before Start.
func (s *Service) SetKillSwitch(fn func() bool) {
	if s == nil {
		return
	}
	s.killSwitch = fn
}

// Observe folds one client pull into the learned history and attributes a cache
// hit to a prior pre-warm when applicable. It is the gateway pull-observer tap
// entry point. Synthetic pre-warm fetches must never be reported here (the
// gateway excludes them). Safe on nil / when disabled.
func (s *Service) Observe(ev PullEvent) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	s.history.Observe(ev)
	if ev.CacheHit {
		s.attributeHit(ev.Backend, ev.Path)
	}
}

// attributeHit credits a client cache hit to a prior pre-warm of the same
// artifact, at most once per pre-warmed artifact.
func (s *Service) attributeHit(backend, path string) {
	key := prewarmKeyFor(backend, path)
	s.mu.Lock()
	e, ok := s.prewarmed[key]
	if !ok || e.attributed {
		s.mu.Unlock()
		return
	}
	e.attributed = true
	s.prewarmed[key] = e
	s.mu.Unlock()
	s.metrics.recordHitAttributed()
}

// markPrewarmed records that a target's artifact was successfully pre-warmed, so
// a subsequent client hit can be attributed to it.
func (s *Service) markPrewarmed(t Target) {
	key := prewarmKeyFor(t.Backend, t.Path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.prewarmed[key]; !exists && len(s.prewarmed) >= maxPrewarmedTracked {
		s.evictPrewarmedLocked()
	}
	s.prewarmed[key] = prewarmedEntry{warmedAt: s.now()}
}

func (s *Service) evictPrewarmedLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range s.prewarmed {
		if first || e.warmedAt.Before(oldest) {
			oldestKey, oldest, first = k, e.warmedAt, false
		}
	}
	if oldestKey != "" {
		delete(s.prewarmed, oldestKey)
	}
}

func prewarmKeyFor(backend, path string) string { return backend + "\x00" + path }

// Start launches the background loop. It is idempotent and a no-op when
// disabled. The loop runs a cycle every Interval (subject to the leader,
// kill-switch, and off-peak gates) and serves on-demand triggers, until ctx is
// cancelled or Close is called.
func (s *Service) Start(ctx context.Context) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	s.startOnce.Do(func() {
		s.started = true
		go s.loop(ctx)
		s.logger.Info("predictive cache pre-warming started",
			"interval", s.cfg.Interval, "maxConcurrency", s.cfg.MaxConcurrency,
			"maxPerCycle", s.cfg.MaxPerCycle, "ratePerMinute", s.cfg.RatePerMinute,
			"offPeak", s.windowString(), "transitiveDeps", s.cfg.TransitiveDeps)
	})
}

// Close stops the background loop and persists the learned history (best-effort).
// It is safe to call multiple times. Safe on nil.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { close(s.done) })
	if s.cfg.HistoryPath != "" {
		if err := s.history.Save(s.cfg.HistoryPath); err != nil {
			s.logger.Warn("prewarm: could not persist history", "path", s.cfg.HistoryPath, "error", err)
		}
	}
	return nil
}

func (s *Service) loop(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			s.scheduledCycle(ctx)
		case resp := <-s.trigger:
			resp <- s.RunOnce(ctx)
		}
	}
}

// scheduledCycle runs one periodic cycle subject to the leader, kill-switch, and
// off-peak gates, recording a skip (and its reason) when a gate declines.
func (s *Service) scheduledCycle(ctx context.Context) RunReport {
	if s.leaderFn != nil && !s.leaderFn() {
		s.metrics.recordSkip(skipNotLeader)
		return s.recordSkip(skipNotLeader)
	}
	if s.killSwitch != nil && s.killSwitch() {
		s.metrics.recordSkip(skipKillSwitch)
		s.logger.Debug("prewarm: skipping cycle; kill-switch engaged")
		return s.recordSkip(skipKillSwitch)
	}
	if !s.inWindow(s.now()) {
		s.metrics.recordSkip(skipOffPeak)
		return s.recordSkip(skipOffPeak)
	}
	return s.runCycle(ctx)
}

// RunOnce executes a single cycle immediately, bypassing the leader and off-peak
// gates (an operator explicitly asked this node to run) but still honoring the
// kill-switch. It is the admin/on-demand entry point and the test seam.
func (s *Service) RunOnce(ctx context.Context) RunReport {
	if s == nil || !s.cfg.Enabled {
		return RunReport{Skipped: "disabled"}
	}
	if s.killSwitch != nil && s.killSwitch() {
		s.metrics.recordSkip(skipKillSwitch)
		return s.recordSkip(skipKillSwitch)
	}
	return s.runCycle(ctx)
}

func (s *Service) recordSkip(reason string) RunReport {
	now := s.now()
	r := RunReport{StartedAt: now, FinishedAt: now, Skipped: reason}
	s.mu.Lock()
	s.lastRun = r
	s.mu.Unlock()
	return r
}

// runCycle predicts targets and fetches them under the concurrency and rate
// bounds. It assumes the leader/kill-switch/window gates have already been
// checked by the caller.
func (s *Service) runCycle(ctx context.Context) RunReport {
	report := RunReport{StartedAt: s.now()}
	s.metrics.recordCycle()

	fetcher := s.currentFetcher()
	if fetcher == nil {
		s.metrics.recordSkip(skipNoFetcher)
		s.logger.Warn("prewarm: cycle skipped; no fetcher configured")
		return s.recordSkip(skipNoFetcher)
	}

	stats := s.history.Snapshot()
	targets := s.predictor.Predict(ctx, s.now(), stats)
	report.Predicted = len(targets)
	s.metrics.addPredicted(len(targets))

	if s.cfg.MaxPerCycle > 0 && len(targets) > s.cfg.MaxPerCycle {
		targets = targets[:s.cfg.MaxPerCycle]
	}

	// Reset the rate-limiter window at the start of the cycle.
	s.rateMu.Lock()
	s.nextSlot = time.Time{}
	s.rateMu.Unlock()

	var counts struct {
		sync.Mutex
		fetched, cached, blocked, errs int
	}

	grp, gctx := errgroup.WithContext(ctx)
	grp.SetLimit(s.cfg.MaxConcurrency)
	for _, t := range targets {
		t := t
		grp.Go(func() error {
			if err := s.rateWait(gctx); err != nil {
				return err // context cancelled
			}
			res, err := fetcher.Fetch(gctx, t)
			outcome := res.Outcome
			if err != nil {
				outcome = OutcomeError
			}
			s.metrics.recordOutcome(outcome)
			counts.Lock()
			switch outcome {
			case OutcomeAdmitted:
				counts.fetched++
			case OutcomeAlreadyCached:
				counts.cached++
			case OutcomeGateBlocked:
				counts.blocked++
			default:
				counts.errs++
			}
			counts.Unlock()

			switch outcome {
			case OutcomeAdmitted:
				s.markPrewarmed(t)
			case OutcomeGateBlocked:
				s.logger.Info("prewarm: predicted artifact blocked by an admission gate; quarantined, not served",
					"backend", t.Backend, "name", t.Name, "version", t.Version, "reason", string(t.Reason))
			case OutcomeError:
				if err != nil {
					s.logger.Debug("prewarm: fetch failed",
						"backend", t.Backend, "path", t.Path, "error", err)
				}
			}
			return nil
		})
	}
	_ = grp.Wait()

	counts.Lock()
	report.Fetched = counts.fetched
	report.AlreadyCached = counts.cached
	report.GateBlocked = counts.blocked
	report.Errors = counts.errs
	counts.Unlock()
	report.FinishedAt = s.now()

	s.mu.Lock()
	s.lastRun = report
	s.mu.Unlock()

	s.logger.Info("prewarm: cycle complete",
		"predicted", report.Predicted, "fetched", report.Fetched,
		"alreadyCached", report.AlreadyCached, "gateBlocked", report.GateBlocked,
		"errors", report.Errors)
	return report
}

// Trigger requests an immediate cycle and waits for its report. It is the admin
// on-demand entry point. It returns the loop-shutdown/ctx error if it cannot be
// scheduled.
func (s *Service) Trigger(ctx context.Context) (RunReport, error) {
	if s == nil || !s.cfg.Enabled {
		return RunReport{Skipped: "disabled"}, nil
	}
	resp := make(chan RunReport, 1)
	select {
	case s.trigger <- resp:
	case <-ctx.Done():
		return RunReport{}, ctx.Err()
	case <-s.done:
		return RunReport{}, context.Canceled
	}
	select {
	case r := <-resp:
		return r, nil
	case <-ctx.Done():
		return RunReport{}, ctx.Err()
	case <-s.done:
		return RunReport{}, context.Canceled
	}
}

func (s *Service) currentFetcher() Fetcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetcher
}

// rateWait blocks until the next rate-limit slot is available (no-op when
// RatePerMinute <= 0), honoring context cancellation.
func (s *Service) rateWait(ctx context.Context) error {
	if s.cfg.RatePerMinute <= 0 {
		return nil
	}
	interval := time.Minute / time.Duration(s.cfg.RatePerMinute)
	s.rateMu.Lock()
	now := s.now()
	if s.nextSlot.Before(now) {
		s.nextSlot = now
	}
	wait := s.nextSlot.Sub(now)
	s.nextSlot = s.nextSlot.Add(interval)
	s.rateMu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// inWindow reports whether t falls inside the configured off-peak window. An
// unconfigured window is always open.
func (s *Service) inWindow(t time.Time) bool {
	if s.startMin < 0 {
		return true
	}
	loc := s.loc
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	m := lt.Hour()*60 + lt.Minute()
	if s.startMin == s.endMin {
		return true // degenerate: treat equal bounds as always-open
	}
	if s.startMin < s.endMin {
		return m >= s.startMin && m < s.endMin
	}
	// Window wraps midnight.
	return m >= s.startMin || m < s.endMin
}

func (s *Service) windowString() string {
	if s.startMin < 0 {
		return "always"
	}
	tz := "UTC"
	if s.loc != nil {
		tz = s.loc.String()
	}
	return fmt.Sprintf("%s-%s %s", minToHHMM(s.startMin), minToHHMM(s.endMin), tz)
}

// Status is the operational snapshot served to the admin API and `ptctl prewarm
// status`.
type Status struct {
	Enabled            bool            `json:"enabled"`
	Running            bool            `json:"running"`
	Leader             bool            `json:"leader"`
	KillSwitchActive   bool            `json:"killSwitchActive"`
	InOffPeakWindow    bool            `json:"inOffPeakWindow"`
	Interval           string          `json:"interval"`
	OffPeakWindow      string          `json:"offPeakWindow"`
	MaxConcurrency     int             `json:"maxConcurrency"`
	MaxPerCycle        int             `json:"maxPerCycle"`
	RatePerMinute      int             `json:"ratePerMinute"`
	TransitiveDeps     bool            `json:"transitiveDeps"`
	HistoryCoordinates int             `json:"historyCoordinates"`
	PrewarmedTracked   int             `json:"prewarmedTracked"`
	LastRun            RunReport       `json:"lastRun"`
	Metrics            MetricsSnapshot `json:"metrics"`
}

// Status returns the current operational snapshot. Safe on nil / when disabled.
func (s *Service) Status() Status {
	if s == nil || !s.cfg.Enabled {
		return Status{Enabled: false, Metrics: MetricsSnapshot{SkippedCycles: map[string]uint64{}}}
	}
	s.mu.Lock()
	leader := s.leaderFn == nil || s.leaderFn()
	kill := s.killSwitch != nil && s.killSwitch()
	last := s.lastRun
	tracked := len(s.prewarmed)
	s.mu.Unlock()

	return Status{
		Enabled:            true,
		Running:            s.started,
		Leader:             leader,
		KillSwitchActive:   kill,
		InOffPeakWindow:    s.inWindow(s.now()),
		Interval:           s.cfg.Interval.String(),
		OffPeakWindow:      s.windowString(),
		MaxConcurrency:     s.cfg.MaxConcurrency,
		MaxPerCycle:        s.cfg.MaxPerCycle,
		RatePerMinute:      s.cfg.RatePerMinute,
		TransitiveDeps:     s.cfg.TransitiveDeps,
		HistoryCoordinates: s.history.Len(),
		PrewarmedTracked:   tracked,
		LastRun:            last,
		Metrics:            s.metrics.Snapshot(),
	}
}

// compileWindow parses the "HH:MM" off-peak bounds and timezone. An empty
// start/end disables the window (startMin < 0). An invalid value is an error.
func compileWindow(start, end, tz string) (startMin, endMin int, loc *time.Location, err error) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" && end == "" {
		return -1, -1, time.UTC, nil
	}
	if start == "" || end == "" {
		return 0, 0, nil, fmt.Errorf("prewarm: offPeakStart and offPeakEnd must both be set or both empty")
	}
	startMin, err = parseHHMM(start)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("prewarm: offPeakStart: %w", err)
	}
	endMin, err = parseHHMM(end)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("prewarm: offPeakEnd: %w", err)
	}
	loc = time.UTC
	if strings.TrimSpace(tz) != "" {
		loc, err = time.LoadLocation(strings.TrimSpace(tz))
		if err != nil {
			return 0, 0, nil, fmt.Errorf("prewarm: offPeakTimezone %q: %w", tz, err)
		}
	}
	return startMin, endMin, loc, nil
}

func parseHHMM(v string) (int, error) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time %q (want HH:MM)", v)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour in %q", v)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute in %q", v)
	}
	return h*60 + m, nil
}

func minToHHMM(m int) string {
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}
