package sbomexport

import "sync"

// Snapshot is an immutable, point-in-time copy of the subsystem's cumulative
// counters, consumed by the metrics bridge (pullthrough_sbomexport_*). All
// counters are monotonic for the process lifetime.
type Snapshot struct {
	// Uploads is the total number of per-coordinate documents successfully
	// delivered to a sink (counted once per sink).
	Uploads uint64
	// Failures is the total number of deliveries that exhausted retries (or hit a
	// non-retryable error) without succeeding.
	Failures uint64
	// Retries is the total number of retry attempts across all deliveries (an
	// upload that succeeded on its third try contributes two retries).
	Retries uint64
	// Skipped is the total number of reports that carried no usable SBOM and were
	// therefore not exported.
	Skipped uint64
	// UploadsByTarget and FailuresByTarget partition Uploads/Failures by sink
	// target ("dependency-track", "guac").
	UploadsByTarget  map[string]uint64
	FailuresByTarget map[string]uint64
}

// metricsState accumulates the counters behind a mutex. A zero value is ready
// to use; the per-target maps are created lazily.
type metricsState struct {
	mu               sync.Mutex
	uploads          uint64
	failures         uint64
	retries          uint64
	skipped          uint64
	uploadsByTarget  map[string]uint64
	failuresByTarget map[string]uint64
}

func (m *metricsState) recordUpload(target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploads++
	if m.uploadsByTarget == nil {
		m.uploadsByTarget = make(map[string]uint64)
	}
	m.uploadsByTarget[target]++
}

func (m *metricsState) recordFailure(target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures++
	if m.failuresByTarget == nil {
		m.failuresByTarget = make(map[string]uint64)
	}
	m.failuresByTarget[target]++
}

func (m *metricsState) recordRetry() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retries++
}

func (m *metricsState) recordSkipped(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.skipped += uint64(n)
}

func (m *metricsState) snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := func(src map[string]uint64) map[string]uint64 {
		out := make(map[string]uint64, len(src))
		for k, v := range src {
			out[k] = v
		}
		return out
	}
	return Snapshot{
		Uploads:          m.uploads,
		Failures:         m.failures,
		Retries:          m.retries,
		Skipped:          m.skipped,
		UploadsByTarget:  cp(m.uploadsByTarget),
		FailuresByTarget: cp(m.failuresByTarget),
	}
}
