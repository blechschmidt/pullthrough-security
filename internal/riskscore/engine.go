package riskscore

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// Engine computes and records explainable risk assessments. A zero Engine is not
// usable; construct one with New. All methods are safe for concurrent use.
type Engine struct {
	cfg Config

	mu          sync.RWMutex
	totalScored int64
	byBand      map[Band]int64
	blocked     int64
	warned      int64
	crossings   int64
	// history is a most-recent-last ring of recent assessments, bounded by
	// cfg.HistorySize, for trend visibility and the admin drill-down.
	history []Assessment
}

// New constructs an Engine, applying built-in defaults for any unset config
// field and validating the result. It returns an error only for an invalid
// configuration (negative weights, non-monotonic bands, bad enum values).
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("riskscore: %w", err)
	}
	return &Engine{
		cfg:     cfg,
		byBand:  make(map[Band]int64, 4),
		history: make([]Assessment, 0, cfg.HistorySize),
	}, nil
}

// Enabled reports whether the engine is enabled in configuration.
func (e *Engine) Enabled() bool { return e != nil && e.cfg.Enabled }

// Score computes an explainable assessment for a subject. It is a pure function
// of the subject and configuration: it never mutates engine state and never
// reads the clock, so it is fully deterministic and unit-testable. Call Record
// to fold the result into history and the band counters.
func (e *Engine) Score(s Subject) Assessment {
	r := e.cfg.resolve(s.Input.Tenant)

	// Evaluate every signal in canonical order, partitioning into applicable
	// contributions and skipped signals.
	type scored struct {
		kind   SignalKind
		result signalResult
	}
	evaluated := make([]scored, 0, len(allSignals))
	var sumW float64
	for _, k := range allSignals {
		res := evalSignal(k, s)
		if !res.present {
			continue
		}
		evaluated = append(evaluated, scored{kind: k, result: res})
		sumW += r.weights.forSignal(k)
	}

	contributions := make([]Contribution, 0, len(evaluated))
	var composite float64
	for _, ev := range evaluated {
		w := r.weights.forSignal(ev.kind)
		var norm, points float64
		if sumW > 0 {
			norm = w / sumW
			points = 100 * norm * ev.result.subscore
		}
		composite += points
		contributions = append(contributions, Contribution{
			Signal:           ev.kind,
			Subscore:         round4(ev.result.subscore),
			Weight:           w,
			NormalizedWeight: round4(norm),
			Points:           round2(points),
			Raw:              ev.result.raw,
			Detail:           ev.result.detail,
		})
	}

	skipped := skippedSignals(evaluated, func(s scored) SignalKind { return s.kind })

	score := int(math.Round(composite))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	band := r.bands.bandFor(score)

	exceeds := bandRank(band) >= bandRank(r.threshold.Band)
	action := ThresholdOff
	if exceeds {
		action = r.threshold.Action
	}

	a := Assessment{
		Tenant: s.Input.Tenant,
		Artifact: Artifact{
			Ecosystem:  s.Input.Artifact.Ecosystem,
			Backend:    s.Input.Artifact.Backend,
			Name:       s.Input.Artifact.Name,
			Version:    s.Input.Artifact.Version,
			Digest:     s.Input.Artifact.Digest,
			Coordinate: coordinate(s.Input.Artifact.Name, s.Input.Artifact.Version),
		},
		Score:           score,
		Band:            band,
		Action:          action,
		Block:           action == ThresholdBlock,
		Warn:            action == ThresholdWarn,
		Exceeds:         exceeds,
		ThresholdBand:   r.threshold.Band,
		ThresholdAction: r.threshold.Action,
		Contributions:   contributions,
		Skipped:         skipped,
	}
	a.Summary = summarize(a)
	return a
}

// Record folds an assessment into the engine's cumulative counters and recent
// history. The assessment's ScoredAt is stamped from the engine clock when zero.
func (e *Engine) Record(a Assessment) {
	if e == nil {
		return
	}
	if a.ScoredAt.IsZero() {
		a.ScoredAt = e.cfg.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.totalScored++
	e.byBand[a.Band]++
	if a.Block {
		e.blocked++
	}
	if a.Warn {
		e.warned++
	}
	if a.Exceeds && a.ThresholdAction != ThresholdOff {
		e.crossings++
	}
	e.history = append(e.history, a)
	if len(e.history) > e.cfg.HistorySize {
		// Drop the oldest entries, keeping the most recent HistorySize.
		e.history = append(e.history[:0], e.history[len(e.history)-e.cfg.HistorySize:]...)
	}
}

// ScoreAndRecord is the convenience the pull path uses: score then record.
func (e *Engine) ScoreAndRecord(s Subject) Assessment {
	a := e.Score(s)
	e.Record(a)
	return a
}

// Recent returns up to limit most-recently-scored assessments, most-recent
// first. A non-positive limit returns the full retained history.
func (e *Engine) Recent(limit int) []Assessment {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.recentLocked(limit)
}

func (e *Engine) recentLocked(limit int) []Assessment {
	n := len(e.history)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Assessment, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, e.history[len(e.history)-1-i])
	}
	return out
}

// Snapshot returns the cumulative engine state for the admin API and metrics.
func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	byBand := make(map[string]int64, len(e.byBand))
	for b, n := range e.byBand {
		byBand[string(b)] = n
	}
	// Ensure every band key is present (zero) so dashboards have stable series.
	for _, b := range []Band{BandLow, BandMedium, BandHigh, BandCritical} {
		if _, ok := byBand[string(b)]; !ok {
			byBand[string(b)] = 0
		}
	}
	return Snapshot{
		Enabled:     e.cfg.Enabled,
		TotalScored: e.totalScored,
		ByBand:      byBand,
		Blocked:     e.blocked,
		Warned:      e.warned,
		Crossings:   e.crossings,
		Threshold:   ThresholdInfo{Band: e.cfg.Threshold.Band, Action: e.cfg.Threshold.Action},
		Weights:     e.cfg.Weights,
		Bands:       e.cfg.Bands,
		HistorySize: e.cfg.HistorySize,
		Recent:      e.recentLocked(0),
	}
}

// BandCounts returns the cumulative count of scored artifacts per band as float
// samples, for the metrics bridge. Every band is always present.
func (e *Engine) BandCounts() map[string]float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := map[string]float64{
		string(BandLow): 0, string(BandMedium): 0, string(BandHigh): 0, string(BandCritical): 0,
	}
	for b, n := range e.byBand {
		out[string(b)] = float64(n)
	}
	return out
}

// Threshold returns the global (non-tenant) admission threshold in force.
func (e *Engine) Threshold() ThresholdInfo {
	return ThresholdInfo{Band: e.cfg.Threshold.Band, Action: e.cfg.Threshold.Action}
}

// --- helpers ----------------------------------------------------------------

func coordinate(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

// summarize produces a one-line, human-readable explanation naming the top
// risk drivers by their marginal points.
func summarize(a Assessment) string {
	if len(a.Contributions) == 0 {
		return fmt.Sprintf("risk %d/100 (%s) — no signals available", a.Score, a.Band)
	}
	ranked := make([]Contribution, len(a.Contributions))
	copy(ranked, a.Contributions)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Points > ranked[j].Points })
	parts := make([]string, 0, 3)
	for _, c := range ranked {
		if c.Points <= 0 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s +%.1f", c.Signal, c.Points))
		if len(parts) == 3 {
			break
		}
	}
	drivers := "all signals clean"
	if len(parts) > 0 {
		drivers = "top drivers: " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("risk %d/100 (%s) — %s", a.Score, a.Band, drivers)
}

// skippedSignals returns the canonical signals absent from the evaluated set.
func skippedSignals[T any](evaluated []T, kindOf func(T) SignalKind) []SignalKind {
	present := make(map[SignalKind]struct{}, len(evaluated))
	for _, e := range evaluated {
		present[kindOf(e)] = struct{}{}
	}
	var out []SignalKind
	for _, k := range allSignals {
		if _, ok := present[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
