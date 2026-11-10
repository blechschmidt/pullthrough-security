package simreplay

import (
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// DefaultCapacity is the ring-buffer size applied when Config.Capacity is unset.
const DefaultCapacity = 1024

// Config configures a Recorder.
type Config struct {
	// Enabled gates capture. A disabled recorder ignores every Observe call and is
	// safe to wire unconditionally.
	Enabled bool
	// Capacity bounds the ring buffer; the oldest record is evicted once full. A
	// non-positive value uses DefaultCapacity.
	Capacity int
	// SampleRate captures one in every N observed pulls (deterministic, counter-
	// based — not random — so capture is reproducible). A value <= 1 captures every
	// pull.
	SampleRate int
	// Redact strips sensitive leaf fields from each captured input (see Redact).
	// Defaults to on at the wiring layer; the zero value here is off so a test can
	// capture raw inputs.
	Redact bool
	// Now is an injectable clock for deterministic capture timestamps; defaults to
	// time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Capacity <= 0 {
		c.Capacity = DefaultCapacity
	}
	if c.SampleRate < 1 {
		c.SampleRate = 1
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Recorder is a bounded, sampled, redacted ring buffer of recent admission
// events. It is the capture half of the what-if harness. All methods are safe
// for concurrent use; Observe is cheap and never blocks the pull path.
type Recorder struct {
	cfg Config

	mu       sync.Mutex
	ring     []Record // ring buffer; len grows to Capacity then wraps
	next     int      // write index into ring
	seq      int64    // monotonic sequence assigned to captured records
	observed int64    // total Observe calls (pre-sampling)
	captured int64    // records actually stored (post-sampling, pre-eviction)
}

// NewRecorder constructs a Recorder from cfg, applying defaults.
func NewRecorder(cfg Config) *Recorder {
	cfg = cfg.withDefaults()
	return &Recorder{
		cfg:  cfg,
		ring: make([]Record, 0, cfg.Capacity),
	}
}

// Enabled reports whether capture is on. A nil recorder reports false, so the
// pull path can call this unconditionally.
func (r *Recorder) Enabled() bool { return r != nil && r.cfg.Enabled }

// Observe offers one admission event to the recorder. It applies sampling, then
// (when selected) redaction, then stores the record in the ring buffer. It is a
// no-op on a nil or disabled recorder. Observe is best-effort and never returns
// an error: capture must never affect serving.
func (r *Recorder) Observe(in policyengine.Input, baseline Verdict) {
	if !r.Enabled() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.observed++
	// Counter-based sampling: capture the first of every SampleRate observations.
	// This is deterministic given an observation order, unlike probabilistic
	// sampling, which keeps the whole harness reproducible.
	if (r.observed-1)%int64(r.cfg.SampleRate) != 0 {
		return
	}

	rec := Record{
		Seq:        r.seq,
		CapturedAt: r.cfg.Now(),
		Tenant:     in.Tenant,
		Coordinate: coordinate(in.Artifact.Name, in.Artifact.Version),
		Baseline:   baseline.finalize(),
	}
	if r.cfg.Redact {
		rec.Input = Redact(in)
	} else {
		rec.Input = in
	}
	r.seq++
	r.captured++

	if len(r.ring) < r.cfg.Capacity {
		r.ring = append(r.ring, rec)
	} else {
		r.ring[r.next] = rec
	}
	r.next = (r.next + 1) % r.cfg.Capacity
}

// Records returns the buffered records in capture order (oldest first). The
// returned slice is a copy; the caller may retain or mutate it freely.
func (r *Recorder) Records() []Record {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotLocked()
}

func (r *Recorder) snapshotLocked() []Record {
	n := len(r.ring)
	out := make([]Record, 0, n)
	if n < r.cfg.Capacity {
		// Not yet wrapped: the buffer is already in insertion order.
		out = append(out, r.ring...)
		return out
	}
	// Wrapped: the oldest record is at r.next.
	for i := 0; i < n; i++ {
		out = append(out, r.ring[(r.next+i)%n])
	}
	return out
}

// Capture exports the current buffer as a self-describing, persistable envelope.
func (r *Recorder) Capture() Capture {
	if r == nil {
		return Capture{Version: CaptureVersion}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return Capture{
		Version:    CaptureVersion,
		ExportedAt: r.cfg.Now(),
		Sampling: SamplingInfo{
			Capacity:   r.cfg.Capacity,
			SampleRate: r.cfg.SampleRate,
			Observed:   r.observed,
			Captured:   r.captured,
			Redacted:   r.cfg.Redact,
		},
		Records: r.snapshotLocked(),
	}
}

// Status is the recorder's operational snapshot for the admin surface and
// metrics. It excludes the records themselves (use Capture for those).
type Status struct {
	Enabled    bool  `json:"enabled"`
	Capacity   int   `json:"capacity"`
	SampleRate int   `json:"sampleRate"`
	Redacted   bool  `json:"redacted"`
	Buffered   int   `json:"buffered"`
	Observed   int64 `json:"observed"`
	Captured   int64 `json:"captured"`
}

// Status returns the recorder's operational snapshot. A nil recorder reports a
// disabled status.
func (r *Recorder) Status() Status {
	if r == nil {
		return Status{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{
		Enabled:    r.cfg.Enabled,
		Capacity:   r.cfg.Capacity,
		SampleRate: r.cfg.SampleRate,
		Redacted:   r.cfg.Redact,
		Buffered:   len(r.ring),
		Observed:   r.observed,
		Captured:   r.captured,
	}
}

// Reset clears the buffer and counters, keeping the configuration. It is exposed
// for the admin surface so an operator can start a fresh capture window.
func (r *Recorder) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ring = r.ring[:0]
	r.next = 0
	r.seq = 0
	r.observed = 0
	r.captured = 0
}
