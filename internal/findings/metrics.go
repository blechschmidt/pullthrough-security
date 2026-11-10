package findings

import "sync"

// Metrics accumulates the cumulative counters for the finding de-duplication
// layer (Task 165), exported as the pullthrough_findings_dedup_* family via the
// Prometheus bridge. It is safe for concurrent use; a nil *Metrics is a no-op so
// callers need no nil checks.
type Metrics struct {
	mu         sync.Mutex
	documents  uint64
	input      uint64
	output     uint64
	collapsed  uint64
	byCategory map[Category]uint64
}

// NewMetrics constructs a Metrics accumulator.
func NewMetrics() *Metrics {
	return &Metrics{byCategory: make(map[Category]uint64)}
}

// RecordDedup folds one Deduplicate pass's statistics into the counters.
func (m *Metrics) RecordDedup(s DedupStats) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.documents++
	m.input += uint64(s.Input)
	m.output += uint64(s.Output)
	m.collapsed += uint64(s.Collapsed)
	if m.byCategory == nil {
		m.byCategory = make(map[Category]uint64)
	}
	for cat, n := range s.CollapsedByCategory {
		m.byCategory[cat] += uint64(n)
	}
}

// MetricsSnapshot is the scrape-time view of the de-duplication counters.
type MetricsSnapshot struct {
	Documents           uint64            // documents normalized + deduplicated
	Input               uint64            // findings seen before de-duplication
	Output              uint64            // findings retained after
	Collapsed           uint64            // duplicate findings removed
	CollapsedByCategory map[string]uint64 // removed duplicates, by category
}

// Snapshot returns a consistent copy of the counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{CollapsedByCategory: map[string]uint64{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	by := make(map[string]uint64, len(m.byCategory))
	for cat, n := range m.byCategory {
		by[string(cat)] = n
	}
	return MetricsSnapshot{
		Documents:           m.documents,
		Input:               m.input,
		Output:              m.output,
		Collapsed:           m.collapsed,
		CollapsedByCategory: by,
	}
}
