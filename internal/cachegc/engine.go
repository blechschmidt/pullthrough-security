// Package cachegc implements the cache lifecycle manager (Task 39): a background
// garbage-collection / eviction / retention engine that keeps the
// content-addressable cache (the local filesystem store and the S3-backed shared
// store) from growing unbounded.
//
// The engine runs configurable policies over a GC-facing view of the cache:
//
//   - Size watermarks: when total size crosses a high watermark it evicts down to
//     a low watermark, choosing victims by LRU, LFU, or FIFO.
//   - TTLs: per-artifact (default) and per-tenant time-to-live, removing expired
//     entries regardless of utilization.
//   - Pin / protect rules and reference counting: entries that are pinned (e.g.
//     signed-and-attested, or quarantined-for-evidence) or still referenced by
//     provenance/audit evidence are never evicted unless explicitly allowed.
//   - Safe coordination with the pull path: an entry with a single-flight fetch
//     in progress is never evicted (no eviction mid-stream), and a short
//     "min-idle" guard protects entries being actively streamed. Deletion is
//     idempotent and tolerates a peer replica having already removed an entry, so
//     it is safe for the HA shared store.
//
// A dry-run mode reports exactly what a real run would evict. The engine exposes
// cumulative metrics and the most recent run report for the admin API and the
// Prometheus bridge, and invokes an optional callback when the cache remains
// above the high watermark after a sweep so operators can be alerted.
package cachegc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// Cache is the narrow cache surface the GC engine needs: a rich listing for
// planning and an idempotent delete for eviction. The FilesystemCache (over both
// the local and the S3 store) satisfies it.
type Cache interface {
	GCEntries(ctx context.Context) ([]cache.GCEntry, error)
	Delete(ctx context.Context, key string) error
}

// Config is the policy configuration for the GC engine. It is the structured,
// already-validated form of the YAML config block.
type Config struct {
	// Enabled turns the subsystem on. A disabled engine still serves on-demand
	// runs via the admin API but never sweeps on its own.
	Enabled bool
	// Interval is the period between automatic sweeps. Zero disables the schedule
	// (on-demand only).
	Interval time.Duration
	// CapacityBytes is the cache size used for watermark math. Zero disables
	// size-driven eviction, leaving TTL-only behavior.
	CapacityBytes int64
	// HighWatermarkPct and LowWatermarkPct are fractions (0..1] of CapacityBytes.
	// A sweep that finds utilization above the high watermark evicts down to the
	// low watermark. Defaults: 0.9 and 0.7.
	HighWatermarkPct float64
	LowWatermarkPct  float64
	// Policy selects eviction ordering under size pressure (lru|lfu|fifo).
	Policy EvictionPolicy
	// DefaultTTL is the maximum age (from creation) of an entry before it is
	// eligible for TTL eviction. Zero disables the default TTL.
	DefaultTTL time.Duration
	// TenantTTLs overrides DefaultTTL per tenant. An explicit zero disables TTL
	// for that tenant.
	TenantTTLs map[string]time.Duration
	// MinIdle protects entries accessed within this window from eviction, a safety
	// margin so an artifact being actively streamed to a client is not evicted out
	// from under the read. Zero disables the guard.
	MinIdle time.Duration
	// MaxDeletesPerRun bounds how many entries a single sweep evicts (0 =
	// unlimited), so a large reclaim is spread across sweeps rather than stalling.
	MaxDeletesPerRun int
	// AllowEvictPinned permits evicting metadata-pinned entries (it does not affect
	// other reference sources). Off by default.
	AllowEvictPinned bool
	// DryRun makes the periodic sweep report-only: it plans and reports evictions
	// but deletes nothing. On-demand runs override this per call.
	DryRun bool
}

// Options carries the engine's collaborators, separate from the policy Config.
type Options struct {
	// Sources are the reference/pin sources consulted for retention. They compose:
	// an entry claimed by any source is retained.
	Sources []ReferenceSource
	// OnHighWatermark is invoked (best-effort, synchronously) after a non-dry-run
	// sweep that leaves the cache at or above the high watermark, so the caller can
	// emit an alert. A nil callback is a no-op.
	OnHighWatermark func(ctx context.Context, rep Report)
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// Now overrides the clock; used in tests.
	Now func() time.Time
}

// Engine is the cache garbage collector. It is safe for concurrent use.
type Engine struct {
	cfg     Config
	cache   Cache
	sources []ReferenceSource
	onHigh  func(ctx context.Context, rep Report)
	logger  *slog.Logger
	now     func() time.Time
	metrics *Metrics

	highPct float64
	lowPct  float64

	trigger chan triggerReq
	done    chan struct{}
	started sync.Once
	closed  sync.Once

	mu               sync.Mutex
	last             Report
	hasLast          bool
	consecutiveAbove int
}

type triggerReq struct {
	dryRun bool
	resp   chan triggerResult
}

type triggerResult struct {
	report Report
	err    error
}

// New constructs a GC engine. The cache is required. Watermark percentages and
// the policy are defaulted and validated.
func New(cfg Config, c Cache, opts Options) (*Engine, error) {
	if c == nil {
		return nil, errors.New("cachegc: a Cache is required")
	}
	if cfg.CapacityBytes < 0 {
		return nil, fmt.Errorf("cachegc: capacityBytes must not be negative, got %d", cfg.CapacityBytes)
	}
	high := cfg.HighWatermarkPct
	if high <= 0 {
		high = 0.9
	}
	low := cfg.LowWatermarkPct
	if low <= 0 {
		low = 0.7
	}
	if high > 1 || low > 1 {
		return nil, fmt.Errorf("cachegc: watermark fractions must be in (0,1], got high=%.3f low=%.3f", high, low)
	}
	if low >= high {
		return nil, fmt.Errorf("cachegc: lowWatermarkPct (%.3f) must be below highWatermarkPct (%.3f)", low, high)
	}
	if !ValidPolicy(string(cfg.Policy)) {
		return nil, fmt.Errorf("cachegc: invalid policy %q (want lru|lfu|fifo)", cfg.Policy)
	}
	cfg.Policy = normalizePolicy(string(cfg.Policy))
	if cfg.Interval < 0 {
		return nil, fmt.Errorf("cachegc: interval must not be negative, got %s", cfg.Interval)
	}
	if cfg.MaxDeletesPerRun < 0 {
		return nil, fmt.Errorf("cachegc: maxDeletesPerRun must not be negative, got %d", cfg.MaxDeletesPerRun)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Engine{
		cfg:     cfg,
		cache:   c,
		sources: opts.Sources,
		onHigh:  opts.OnHighWatermark,
		logger:  logger,
		now:     now,
		metrics: &Metrics{},
		highPct: high,
		lowPct:  low,
		trigger: make(chan triggerReq),
		done:    make(chan struct{}),
	}, nil
}

// Start launches the background sweep loop until ctx is cancelled or Close is
// called. It is idempotent. An engine with Interval<=0 still serves on-demand
// triggers. A disabled engine does not start a loop.
func (e *Engine) Start(ctx context.Context) {
	if e == nil || !e.cfg.Enabled {
		return
	}
	e.started.Do(func() {
		go e.loop(ctx)
		if e.cfg.Interval > 0 {
			e.logger.Info("cache gc scheduler started",
				"interval", e.cfg.Interval, "policy", e.cfg.Policy,
				"capacityBytes", e.cfg.CapacityBytes, "dryRun", e.cfg.DryRun)
		} else {
			e.logger.Info("cache gc scheduler started (on-demand only)", "policy", e.cfg.Policy)
		}
	})
}

// Close stops the background loop and blocks until it has exited. It is safe to
// call on a nil engine or one that was never started.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.closed.Do(func() { close(e.done) })
	return nil
}

func (e *Engine) loop(ctx context.Context) {
	var tick <-chan time.Time
	if e.cfg.Interval > 0 {
		t := time.NewTicker(e.cfg.Interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case <-tick:
			if _, err := e.Run(ctx, e.cfg.DryRun); err != nil {
				e.logger.Error("cache gc sweep failed", "error", err)
			}
		case req := <-e.trigger:
			rep, err := e.Run(ctx, req.dryRun)
			req.resp <- triggerResult{report: rep, err: err}
		}
	}
}

// Trigger requests an on-demand sweep from the running loop and waits for its
// report. When the loop is not running (disabled or not started) it runs the
// sweep inline so the admin API always works. dryRun overrides the configured
// mode for this run only.
func (e *Engine) Trigger(ctx context.Context, dryRun bool) (Report, error) {
	if e == nil {
		return Report{}, errors.New("cachegc: engine not configured")
	}
	resp := make(chan triggerResult, 1)
	select {
	case e.trigger <- triggerReq{dryRun: dryRun, resp: resp}:
		res := <-resp
		return res.report, res.err
	case <-ctx.Done():
		return Report{}, ctx.Err()
	default:
		// No loop is receiving (engine disabled or not started): run inline.
		return e.Run(ctx, dryRun)
	}
}

// Run performs a single GC pass: it lists the cache, plans eviction under the
// configured policy, and (unless dryRun) deletes the selected entries. It records
// metrics, stores the report as the most recent one, and fires the high-watermark
// callback when a real run leaves the cache above the high watermark.
func (e *Engine) Run(ctx context.Context, dryRun bool) (Report, error) {
	start := e.now()
	// Sources whose evidence lives elsewhere refresh it first, so the pass
	// does not act on a stale view (release pins another replica wrote).
	for _, src := range e.sources {
		if p, ok := src.(Preparer); ok {
			if err := p.Prepare(ctx); err != nil {
				return Report{}, fmt.Errorf("cachegc: refreshing retention source %s: %w", src.Name(), err)
			}
		}
	}
	entries, err := e.cache.GCEntries(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("cachegc: listing cache: %w", err)
	}

	rep := e.plan(entries, start)
	rep.DryRun = dryRun

	var (
		ttlEvicted int64
		deleteErrs int
	)
	if dryRun {
		// Dry-run: count TTL evictions for the report but move no operational
		// counters and delete nothing.
		for i := range rep.Evicted {
			if rep.Evicted[i].Reason == ReasonTTL {
				ttlEvicted++
			}
		}
	} else {
		for i := range rep.Evicted {
			er := &rep.Evicted[i]
			derr := e.cache.Delete(ctx, er.Key)
			switch {
			case derr == nil || errors.Is(derr, cache.ErrNotFound):
				// Success, or a peer replica already removed it (idempotent,
				// distributed-safe): the space is reclaimed either way.
				if er.Reason == ReasonTTL {
					ttlEvicted++
				}
			default:
				er.Error = derr.Error()
				deleteErrs++
				// The delete failed, so this entry's bytes were not reclaimed.
				rep.EvictedCount--
				rep.BytesReclaimed -= er.Size
			}
		}
		// Recompute the post-sweep watermark state from what was actually freed.
		if rep.CapacityBytes > 0 {
			remaining := rep.UsedBytes - rep.BytesReclaimed
			rep.AboveHighWatermark = remaining >= rep.HighWatermarkBytes
			rep.UtilizationPct = float64(remaining) / float64(rep.CapacityBytes) * 100
		}
	}
	rep.Errors = deleteErrs
	rep.Duration = e.now().Sub(start)

	e.record(ctx, rep, ttlEvicted)
	return cappedReport(rep), nil
}

// record updates the cumulative metrics, stores the (capped) report as the latest
// one, tracks the consecutive-above-high-watermark streak, and fires the alert
// callback for a real run that stayed above the high watermark.
func (e *Engine) record(ctx context.Context, rep Report, ttlEvicted int64) {
	if rep.DryRun {
		e.metrics.incDryRuns()
	} else {
		e.metrics.incRuns()
		e.metrics.addEvicted(int64(rep.EvictedCount))
		e.metrics.addExpiredEvicted(ttlEvicted)
		e.metrics.addBytesReclaimed(rep.BytesReclaimed)
		e.metrics.addDeleteErrors(int64(rep.Errors))
	}

	e.mu.Lock()
	e.last = cappedReport(rep)
	e.hasLast = true
	if !rep.DryRun {
		if rep.AboveHighWatermark {
			e.consecutiveAbove++
		} else {
			e.consecutiveAbove = 0
		}
	}
	streak := e.consecutiveAbove
	e.mu.Unlock()

	if !rep.DryRun {
		if rep.EvictedCount > 0 || rep.Errors > 0 {
			e.logger.Info("cache gc sweep complete",
				"evicted", rep.EvictedCount, "bytesReclaimed", rep.BytesReclaimed,
				"retained", rep.RetainedCount, "errors", rep.Errors,
				"utilizationPct", rep.UtilizationPct, "aboveHigh", rep.AboveHighWatermark)
		}
		if rep.AboveHighWatermark {
			e.metrics.incHighWatermark()
			e.logger.Warn("cache remains above high watermark after gc",
				"usedBytes", rep.UsedBytes-rep.BytesReclaimed, "highWatermarkBytes", rep.HighWatermarkBytes,
				"consecutiveSweeps", streak)
			if e.onHigh != nil {
				e.onHigh(ctx, rep)
			}
		}
	}
}

// Snapshot returns the cumulative counters merged with the most-recent run state.
func (e *Engine) Snapshot() Snapshot {
	s := e.metrics.snapshot()
	s.Enabled = e.cfg.Enabled
	s.Policy = string(e.cfg.Policy)
	s.IntervalSeconds = e.cfg.Interval.Seconds()
	s.DryRun = e.cfg.DryRun
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hasLast {
		r := e.last
		s.CapacityBytes = r.CapacityBytes
		s.HighWatermarkBytes = r.HighWatermarkBytes
		s.LowWatermarkBytes = r.LowWatermarkBytes
		// A dry-run frees nothing, so report the observed size; a real run reports
		// what remains after the reclaim.
		if r.DryRun {
			s.UsedBytes = r.UsedBytes
		} else {
			s.UsedBytes = r.UsedBytes - r.BytesReclaimed
		}
		s.Entries = r.Entries
		s.UtilizationPct = r.UtilizationPct
		s.LastEvicted = r.EvictedCount
		s.LastBytesReclaimed = r.BytesReclaimed
		s.LastDurationMillis = r.Duration.Milliseconds()
		s.LastWasAboveHigh = r.AboveHighWatermark
		s.ConsecutiveAbove = e.consecutiveAbove
	}
	return s
}

// LastReport returns the most recent run's report and whether one has happened.
func (e *Engine) LastReport() (Report, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last, e.hasLast
}

// cappedReport returns a copy of rep with its detail lists bounded for transport.
// The summary *Count fields remain exact.
func cappedReport(rep Report) Report {
	if len(rep.Evicted) > maxReportItems {
		ev := make([]EvictionRecord, maxReportItems)
		copy(ev, rep.Evicted[:maxReportItems])
		rep.Evicted = ev
	}
	if len(rep.Retained) > maxReportItems {
		rt := make([]RetentionRecord, maxReportItems)
		copy(rt, rep.Retained[:maxReportItems])
		rep.Retained = rt
	}
	return rep
}
