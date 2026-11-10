package snapshot

import (
	"context"
	"sync"
	"time"
)

// Scheduler periodically captures an automatic snapshot of the live state. In an
// HA deployment it is coord-guarded (Task 56) so only the lease-holder captures
// on each tick, avoiding duplicate snapshots across replicas. Captures are
// content-addressed, so even if two replicas raced an identical state would
// collapse to one manifest — the leader gate is an efficiency, not a correctness,
// guard.
type Scheduler struct {
	svc      *Service
	interval time.Duration

	mu       sync.Mutex
	leaderFn func() bool
	cancel   context.CancelFunc
	doneCh   chan struct{}
}

// NewScheduler builds a scheduler for the service. A non-positive interval (or a
// disabled service) yields a scheduler whose Start is a no-op.
func NewScheduler(svc *Service) *Scheduler {
	interval := time.Duration(0)
	if svc != nil {
		interval = svc.cfg.ScheduleInterval
	}
	return &Scheduler{svc: svc, interval: interval}
}

// Enabled reports whether a periodic schedule is configured and active.
func (s *Scheduler) Enabled() bool {
	return s != nil && s.svc.Enabled() && s.interval > 0
}

// SetLeaderGate installs the HA leadership predicate consulted before each
// scheduled capture. A nil gate (default) captures unconditionally. Call before
// Start.
func (s *Scheduler) SetLeaderGate(fn func() bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaderFn = fn
}

// Start launches the periodic loop in a goroutine. Safe to call when disabled.
func (s *Scheduler) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return
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
	s.svc.logger.Info("snapshot scheduler started", "interval", s.interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			gate := s.leaderFn
			s.mu.Unlock()
			if gate != nil && !gate() {
				s.svc.logger.Debug("snapshot: skipping scheduled capture; not coordination leader")
				continue
			}
			if _, err := s.svc.Take(TakeOptions{
				CreatedBy: "scheduler",
				Note:      "automatic scheduled snapshot",
				Scheduled: true,
			}); err != nil {
				s.svc.logger.Error("snapshot: scheduled capture failed", "error", err)
			}
		}
	}
}

// Stop halts the periodic loop and waits for it to exit.
func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
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
