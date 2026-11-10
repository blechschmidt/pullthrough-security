package anomaly

import (
	"math"
	"time"
)

// This file holds the lightweight, dependency-free online-statistics primitives
// the detectors are built from: a rolling time window (count of timestamped
// events in the recent past), a distinct-key rolling window (distinct keys seen
// recently), and an EWMA baseline with an EWMA mean-absolute-deviation estimate
// for z-scoring a value against a slowly-adapting per-scope baseline. None of
// these allocate unboundedly: the time windows prune on every mutation, so their
// memory is bounded by the configured window and the arrival rate.

// rollingWindow counts timestamped events within a trailing duration. It is the
// substrate for the off-hours-burst and rapid-enumeration detectors, which care
// about "how many of X happened in the last window".
type rollingWindow struct {
	// events holds the timestamps still inside the window, oldest first. Pruning
	// happens lazily on add/count, so the slice never grows beyond the number of
	// events that physically occurred within one window.
	events []time.Time
}

// add records an event at t and prunes anything older than now-window. now is
// passed explicitly (rather than read from the clock) so the windows are fully
// deterministic under test.
func (w *rollingWindow) add(t time.Time, now time.Time, window time.Duration) {
	w.events = append(w.events, t)
	w.prune(now, window)
}

// count returns the number of events still inside the trailing window ending at
// now. It prunes as a side effect so a long-idle window collapses to zero.
func (w *rollingWindow) count(now time.Time, window time.Duration) int {
	w.prune(now, window)
	return len(w.events)
}

func (w *rollingWindow) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	i := 0
	for i < len(w.events) && !w.events[i].After(cutoff) {
		i++
	}
	if i > 0 {
		// Shift the surviving suffix to the front and truncate so the backing
		// array does not retain expired entries indefinitely.
		w.events = append(w.events[:0], w.events[i:]...)
	}
}

// distinctWindow tracks the set of distinct keys observed within a trailing
// window, keyed by their most-recent sighting. It backs the distinct-package
// fan-out detector: a credential-compromised identity tends to enumerate many
// distinct packages in a short burst.
type distinctWindow struct {
	seen map[string]time.Time
}

// add records key at t and returns the number of distinct keys still inside the
// trailing window (including key). It prunes expired keys as a side effect.
func (d *distinctWindow) add(key string, t time.Time, now time.Time, window time.Duration) int {
	if d.seen == nil {
		d.seen = make(map[string]time.Time)
	}
	if prev, ok := d.seen[key]; !ok || t.After(prev) {
		d.seen[key] = t
	}
	return d.count(now, window)
}

// count returns the number of distinct keys inside the trailing window, pruning
// expired keys.
func (d *distinctWindow) count(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	for k, ts := range d.seen {
		if !ts.After(cutoff) {
			delete(d.seen, k)
		}
	}
	return len(d.seen)
}

// byteWindow is a rolling window of transferred byte counts. It backs the egress
// detector, which baselines the recent *volume* (sum of bytes over the window)
// rather than a single transfer, so steady traffic of small artifacts and a
// sudden bulk exfiltration are distinguished.
type byteWindow struct {
	events []timedBytes
	sum    int64
}

type timedBytes struct {
	at    time.Time
	bytes int64
}

// add records bytes transferred at t and returns the running sum still inside
// the trailing window.
func (b *byteWindow) add(bytes int64, t time.Time, now time.Time, window time.Duration) int64 {
	if bytes < 0 {
		bytes = 0
	}
	b.events = append(b.events, timedBytes{at: t, bytes: bytes})
	b.sum += bytes
	b.prune(now, window)
	return b.sum
}

func (b *byteWindow) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	i := 0
	for i < len(b.events) && !b.events[i].at.After(cutoff) {
		b.sum -= b.events[i].bytes
		i++
	}
	if i > 0 {
		b.events = append(b.events[:0], b.events[i:]...)
	}
	if b.sum < 0 {
		// Defensive: floating accumulation of int64 can never go negative here,
		// but guard so a logic error cannot poison the baseline.
		b.sum = 0
	}
}

// baseline is an exponentially-weighted moving average paired with an EWMA of
// the absolute deviation, giving a cheap, online estimate of both the central
// tendency and the spread of a stream. zscore reports how many mean-absolute
// deviations a sample sits above the running mean; update folds the sample into
// the estimate. The deviation (rather than a true standard deviation) keeps the
// math single-pass and robust to the occasional outlier.
type baseline struct {
	alpha float64
	mean  float64
	dev   float64
	n     int
}

func newBaseline(alpha float64) baseline {
	if alpha <= 0 || alpha > 1 {
		alpha = defaultEWMAAlpha
	}
	return baseline{alpha: alpha}
}

// ready reports whether enough samples have been folded in for the z-score to be
// meaningful. Before warmup the detector must stay silent so a cold scope cannot
// alert on its very first transfers.
func (b *baseline) ready(min int) bool { return b.n >= min }

// zscore returns (x-mean)/deviation, with the deviation floored so a perfectly
// flat baseline (dev≈0) does not divide by zero and report spurious infinities.
func (b *baseline) zscore(x float64, floor float64) float64 {
	if b.n == 0 {
		return 0
	}
	d := b.dev
	if d < floor {
		d = floor
	}
	if d <= 0 {
		return 0
	}
	return (x - b.mean) / d
}

// update folds x into the running mean and deviation estimates.
func (b *baseline) update(x float64) {
	if b.n == 0 {
		b.mean = x
		b.dev = 0
		b.n = 1
		return
	}
	b.mean = b.alpha*x + (1-b.alpha)*b.mean
	dev := math.Abs(x - b.mean)
	b.dev = b.alpha*dev + (1-b.alpha)*b.dev
	b.n++
}

// ramp maps a raw detector value onto a normalized [0,1] anomaly score and a
// coarse per-detector Level, using two cutoffs: warn (the value at which the
// signal becomes noteworthy) and high (the value at which it is fully
// anomalous). The mapping is piecewise-linear and pinned so that warn→0.5 and
// high→1.0; values below warn occupy [0,0.5). This makes a detector's score
// directly comparable across detectors with very different natural units (a
// distinct-package count vs. a byte-volume z-score).
type ramp struct {
	warn float64
	high float64
}

// eval returns the normalized score in [0,1] and the per-detector level for v.
func (r ramp) eval(v float64) (float64, Level) {
	warn, high := r.warn, r.high
	if high <= warn {
		high = warn + 1
	}
	switch {
	case v <= 0:
		return 0, LevelNone
	case v >= high:
		return 1, LevelHigh
	case v >= warn:
		score := 0.5 + 0.5*(v-warn)/(high-warn)
		return clamp01(score), LevelMedium
	default:
		// Below the warn cutoff: only the upper half [warn/2, warn) registers as a
		// low-grade signal (mapped to [0.25, 0.5)); quieter activity is nominal, so
		// ordinary traffic does not constantly read as a faint anomaly.
		if warn <= 0 || v < warn/2 {
			return 0, LevelNone
		}
		score := 0.25 + 0.25*(v-warn/2)/(warn/2)
		return clamp01(score), LevelLow
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
