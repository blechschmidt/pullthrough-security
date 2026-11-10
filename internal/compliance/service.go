package compliance

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// PostureSource samples the live security signals into a Posture. The wiring
// layer implements it (or supplies a closure via PostureFunc) over the concrete
// subsystem snapshots; tests supply a fixture.
type PostureSource interface {
	Posture() Posture
}

// PostureFunc adapts a function to a PostureSource.
type PostureFunc func() Posture

// Posture implements PostureSource.
func (f PostureFunc) Posture() Posture { return f() }

// Options configures a Service.
type Options struct {
	// Source samples the live posture. Required.
	Source PostureSource
	// Config tunes scorecard computation (thresholds, control overrides, version).
	Config Config
	// Interval is how often the scorecard is recomputed in the background. Zero
	// disables periodic recomputation (the scorecard is still computed on demand
	// and once at construction).
	Interval time.Duration
	// Signer optionally signs exported report artifacts for auditors.
	Signer *Signer
	// Logger is used for diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// Service computes and serves the continuous-compliance scorecard. It is safe
// for concurrent use: the latest scorecard is recomputed on a schedule and cached
// under a mutex so admin reads and metric scrapes never block on computation.
type Service struct {
	source   PostureSource
	cfg      Config
	interval time.Duration
	signer   *Signer
	log      *slog.Logger

	mu     sync.RWMutex
	latest Scorecard
}

// New constructs a Service and computes an initial scorecard so the admin surface
// and metrics have a value before the first tick.
func New(opts Options) *Service {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		source:   opts.Source,
		cfg:      opts.Config,
		interval: opts.Interval,
		signer:   opts.Signer,
		log:      log,
	}
	s.Recompute()
	return s
}

// Recompute samples the live posture, computes a fresh scorecard, caches it as
// the latest, and returns it.
func (s *Service) Recompute() Scorecard {
	var p Posture
	if s.source != nil {
		p = s.source.Posture()
	}
	card := Compute(p, s.cfg)
	s.mu.Lock()
	s.latest = card
	s.mu.Unlock()
	return card
}

// Latest returns the most recently computed scorecard.
func (s *Service) Latest() Scorecard {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

// Start launches the background recomputation loop until ctx is cancelled. It is
// a no-op when no interval is configured. The caller typically pairs it with a
// deferred Close, though cancelling ctx is sufficient to stop the loop.
func (s *Service) Start(ctx context.Context) {
	if s.interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				card := s.Recompute()
				s.log.Debug("compliance scorecard recomputed",
					"score", card.Score, "grade", card.Grade, "status", card.Status,
					"slsaLevel", card.SLSA.BuildLevel)
			}
		}
	}()
}

// SignerKeyID returns the configured signer's key id, or "" when reports are
// exported unsigned.
func (s *Service) SignerKeyID() string {
	if s.signer == nil {
		return ""
	}
	return s.signer.KeyID()
}

// Export returns the latest scorecard as a signed (or unsigned, when no signer is
// configured) report artifact suitable for handing to an auditor.
func (s *Service) Export() (SignedReport, error) {
	return BuildSignedReport(s.Latest(), s.signer)
}

// ControlScores projects the latest scorecard onto per-control 0..1 score samples
// for the metrics bridge.
func (s *Service) ControlScores() map[string]float64 {
	card := s.Latest()
	out := make(map[string]float64, len(card.Controls))
	for _, c := range card.Controls {
		out[c.ID] = c.Score
	}
	return out
}

// ControlPass projects the latest scorecard onto a per-control 1/0 pass indicator
// (1 only for a fully passing control) for alert-friendly metrics.
func (s *Service) ControlPass() map[string]float64 {
	card := s.Latest()
	out := make(map[string]float64, len(card.Controls))
	for _, c := range card.Controls {
		if c.Status == StatusPass {
			out[c.ID] = 1
		} else {
			out[c.ID] = 0
		}
	}
	return out
}
