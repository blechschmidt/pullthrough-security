package prewarm

import "sync"

// Metrics accumulates the subsystem's counters. The proxy bridges these into the
// Prometheus registry as scrape-time callbacks (pullthrough_prewarm_*), so this
// struct is the single source of truth. A nil *Metrics is a valid no-op.
type Metrics struct {
	mu sync.Mutex

	predicted     uint64            // candidates emitted by the predictor
	fetched       uint64            // artifacts fetched+admitted (cache now warm)
	alreadyCached uint64            // predicted artifacts already present
	gateBlocked   uint64            // fetched artifacts an admission gate refused
	errors        uint64            // fetch failures (404 for a predicted version, etc.)
	hitAttributed uint64            // later client hits served from a pre-warmed artifact
	skippedCycles map[string]uint64 // cycles skipped, by reason (not-leader|kill-switch|off-peak|disabled)
	cyclesRun     uint64
}

// NewMetrics returns an initialized Metrics.
func NewMetrics() *Metrics {
	return &Metrics{skippedCycles: make(map[string]uint64)}
}

func (m *Metrics) addPredicted(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.predicted += uint64(n)
	m.mu.Unlock()
}

func (m *Metrics) recordOutcome(o Outcome) {
	if m == nil {
		return
	}
	m.mu.Lock()
	switch o {
	case OutcomeAdmitted:
		m.fetched++
	case OutcomeAlreadyCached:
		m.alreadyCached++
	case OutcomeGateBlocked:
		m.gateBlocked++
	default:
		m.errors++
	}
	m.mu.Unlock()
}

func (m *Metrics) recordHitAttributed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.hitAttributed++
	m.mu.Unlock()
}

func (m *Metrics) recordCycle() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.cyclesRun++
	m.mu.Unlock()
}

func (m *Metrics) recordSkip(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.skippedCycles == nil {
		m.skippedCycles = make(map[string]uint64)
	}
	m.skippedCycles[reason]++
	m.mu.Unlock()
}

// MetricsSnapshot is an immutable copy of the counters for export.
type MetricsSnapshot struct {
	Predicted     uint64            `json:"predicted"`
	Fetched       uint64            `json:"fetched"`
	AlreadyCached uint64            `json:"alreadyCached"`
	GateBlocked   uint64            `json:"gateBlocked"`
	Errors        uint64            `json:"errors"`
	HitAttributed uint64            `json:"hitAttributed"`
	CyclesRun     uint64            `json:"cyclesRun"`
	SkippedCycles map[string]uint64 `json:"skippedCycles"`
}

// Snapshot returns a deep copy of the current counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{SkippedCycles: map[string]uint64{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	skipped := make(map[string]uint64, len(m.skippedCycles))
	for k, v := range m.skippedCycles {
		skipped[k] = v
	}
	return MetricsSnapshot{
		Predicted:     m.predicted,
		Fetched:       m.fetched,
		AlreadyCached: m.alreadyCached,
		GateBlocked:   m.gateBlocked,
		Errors:        m.errors,
		HitAttributed: m.hitAttributed,
		CyclesRun:     m.cyclesRun,
		SkippedCycles: skipped,
	}
}
