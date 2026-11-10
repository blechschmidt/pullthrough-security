package backup

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Stats records the outcome of backup runs for operator visibility and alerting.
// All access is synchronized so the metrics layer can read a consistent snapshot
// while a backup runs.
type Stats struct {
	mu           sync.Mutex
	lastSuccess  time.Time
	lastAttempt  time.Time
	lastDuration time.Duration
	lastBytes    int64
	lastError    string
	successCount int64
	failureCount int64
	now          func() time.Time
}

// NewStats constructs a Stats with the given clock (nil uses time.Now).
func NewStats(now func() time.Time) *Stats {
	if now == nil {
		now = time.Now
	}
	return &Stats{now: now}
}

// recordSuccess updates the stats after a successful backup.
func (s *Stats) recordSuccess(at time.Time, dur time.Duration, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttempt = at
	s.lastSuccess = at
	s.lastDuration = dur
	s.lastBytes = bytes
	s.lastError = ""
	s.successCount++
}

// recordFailure updates the stats after a failed backup.
func (s *Stats) recordFailure(at time.Time, dur time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttempt = at
	s.lastDuration = dur
	if err != nil {
		s.lastError = err.Error()
	}
	s.failureCount++
}

// Snapshot is an immutable view of the stats for reporting.
type Snapshot struct {
	LastSuccess  time.Time
	LastAttempt  time.Time
	LastDuration time.Duration
	LastBytes    int64
	LastError    string
	SuccessCount int64
	FailureCount int64
	// AgeSeconds is the seconds since the last successful backup, or -1 if none has
	// ever succeeded. It is the primary alerting signal (RPO breach detection).
	AgeSeconds float64
}

// Snapshot returns a consistent view of the current stats.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	age := -1.0
	if !s.lastSuccess.IsZero() {
		age = s.now().Sub(s.lastSuccess).Seconds()
		if age < 0 {
			age = 0
		}
	}
	return Snapshot{
		LastSuccess:  s.lastSuccess,
		LastAttempt:  s.lastAttempt,
		LastDuration: s.lastDuration,
		LastBytes:    s.lastBytes,
		LastError:    s.lastError,
		SuccessCount: s.successCount,
		FailureCount: s.failureCount,
		AgeSeconds:   age,
	}
}

// RunFunc performs a single backup and returns the bytes written. The scheduler
// is agnostic to where the snapshot is written (a file, an object store, a pipe);
// the CLI/admin layer supplies a closure that captures the destination, source
// set, encryption key, and retention policy.
type RunFunc func(ctx context.Context) (bytes int64, err error)

// Scheduler drives periodic backups on a fixed interval and records their
// outcome into Stats so the metrics layer can expose backup-age/last-success for
// alerting. It mirrors the cache-GC scheduler's lifecycle: constructed always,
// runs only when an interval is configured.
type Scheduler struct {
	interval time.Duration
	run      RunFunc
	stats    *Stats
	logger   *slog.Logger
	now      func() time.Time
	leaderFn func() bool

	mu     sync.Mutex
	cancel context.CancelFunc
	doneCh chan struct{}
}

// NewScheduler constructs a backup scheduler. A non-positive interval disables
// the periodic loop (Start is then a no-op), leaving on-demand backups via the
// CLI/admin path. The stats argument is shared with the metrics layer.
func NewScheduler(interval time.Duration, run RunFunc, stats *Stats, logger *slog.Logger) *Scheduler {
	if stats == nil {
		stats = NewStats(nil)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		interval: interval,
		run:      run,
		stats:    stats,
		logger:   logger,
		now:      stats.now,
	}
}

// SetLeaderGate installs a predicate consulted before each *scheduled* backup:
// the periodic loop runs a backup only when it returns true. It wires HA leader
// election (Task 56) so that across N replicas only the lease-holder runs the
// scheduled backup, avoiding duplicate, double-written snapshots. A nil gate (the
// default) runs unconditionally. On-demand backups via RunOnce are never gated —
// an operator-triggered backup always runs. Call before Start.
func (s *Scheduler) SetLeaderGate(fn func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaderFn = fn
}

// Stats returns the scheduler's shared stats.
func (s *Scheduler) Stats() *Stats { return s.stats }

// Status returns a consistent snapshot of the scheduler's backup outcomes, for
// the admin API and metrics layer.
func (s *Scheduler) Status() Snapshot { return s.stats.Snapshot() }

// Enabled reports whether a periodic schedule is configured.
func (s *Scheduler) Enabled() bool { return s.interval > 0 && s.run != nil }

// RunOnce executes a single backup synchronously, recording the outcome. It is
// used by the admin "trigger now" path and shares the same stats accounting as
// the periodic loop.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	start := s.now()
	bytes, err := s.run(ctx)
	dur := s.now().Sub(start)
	if err != nil {
		s.stats.recordFailure(start, dur, err)
		s.logger.Error("scheduled backup failed", "error", err, "duration", dur)
		return err
	}
	s.stats.recordSuccess(start, dur, bytes)
	s.logger.Info("backup completed", "bytes", bytes, "duration", dur)
	return nil
}

// Start launches the periodic loop in a goroutine. It is safe to call when
// disabled (it does nothing). Stop blocks until the loop has exited.
func (s *Scheduler) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return // already running
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.doneCh = make(chan struct{})
	go s.loop(loopCtx, s.doneCh)
}

func (s *Scheduler) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.logger.Info("backup scheduler started", "interval", s.interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// In an HA deployment only the coordination leader runs the scheduled
			// backup; followers skip this tick so the snapshot is written once.
			if s.leaderFn != nil && !s.leaderFn() {
				s.logger.Debug("backup: skipping scheduled run; not coordination leader")
				continue
			}
			// A failed run is logged and counted; the loop continues so a transient
			// failure does not silently stop future backups.
			_ = s.RunOnce(ctx)
		}
	}
}

// Stop halts the periodic loop and waits for it to exit.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.doneCh
	s.cancel = nil
	s.doneCh = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}
