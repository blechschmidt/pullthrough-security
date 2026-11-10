package spiffe

import (
	"sort"
	"sync"
	"time"
)

// Failure reasons recorded by the mTLS authenticator. They are stable label
// values for the failure metric and the audit reason.
const (
	ReasonNoSPIFFEID      = "no_spiffe_id"
	ReasonUntrustedDomain = "untrusted_domain"
	ReasonChainInvalid    = "chain_invalid"
	ReasonExpired         = "expired"
	ReasonPolicyDenied    = "policy_denied"
	ReasonMalformedID     = "malformed_id"
)

// Metrics accumulates authentication outcomes and observed client-certificate
// expiries for the mTLS workload-identity path. It is the single source of
// truth read by the Prometheus bridge at scrape time. Safe for concurrent use.
type Metrics struct {
	now func() time.Time

	mu         sync.Mutex
	success    uint64
	failures   map[string]uint64    // reason -> count
	expiryByID map[string]time.Time // spiffe id -> last-seen leaf NotAfter
}

// maxTrackedCerts bounds the per-identity expiry map so a churn of distinct
// SPIFFE IDs cannot grow it without limit. When exceeded, the soonest-expiring
// entries are kept (they are the ones the operator most needs to see).
const maxTrackedCerts = 4096

// NewMetrics returns an empty Metrics. now defaults to time.Now.
func NewMetrics(now func() time.Time) *Metrics {
	if now == nil {
		now = time.Now
	}
	return &Metrics{
		now:        now,
		failures:   make(map[string]uint64),
		expiryByID: make(map[string]time.Time),
	}
}

func (m *Metrics) recordSuccess(id string, notAfter time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.success++
	if id != "" && !notAfter.IsZero() {
		m.expiryByID[id] = notAfter
		if len(m.expiryByID) > maxTrackedCerts {
			m.evictFurthestLocked()
		}
	}
}

func (m *Metrics) recordFailure(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures[reason]++
}

// evictFurthestLocked drops the entry expiring furthest in the future so the
// tracked set retains the most operationally relevant (soonest-expiring) certs.
func (m *Metrics) evictFurthestLocked() {
	var furthestID string
	var furthest time.Time
	for id, exp := range m.expiryByID {
		if furthestID == "" || exp.After(furthest) {
			furthestID, furthest = id, exp
		}
	}
	if furthestID != "" {
		delete(m.expiryByID, furthestID)
	}
}

// MetricsSnapshot is a point-in-time view of the mTLS auth metrics.
type MetricsSnapshot struct {
	Success          uint64
	FailuresByReason map[string]uint64
	FailureTotal     uint64
	// SoonestCertExpirySeconds is the time remaining (seconds) until the soonest-
	// expiring recently-verified client certificate expires, or 0 when none have
	// been observed. Negative values (already expired) are clamped to 0.
	SoonestCertExpirySeconds float64
	// CertsExpiringSoon counts distinct identities whose last-seen certificate
	// expires within the warning window passed to Snapshot.
	CertsExpiringSoon int
	TrackedCerts      int
}

// Snapshot returns the current metrics, computing the cert-expiry gauges
// against the supplied warning window.
func (m *Metrics) Snapshot(expiryWarning time.Duration) MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{FailuresByReason: map[string]uint64{}}
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := MetricsSnapshot{
		Success:          m.success,
		FailuresByReason: make(map[string]uint64, len(m.failures)),
		TrackedCerts:     len(m.expiryByID),
	}
	for reason, n := range m.failures {
		snap.FailuresByReason[reason] = n
		snap.FailureTotal += n
	}
	var soonest time.Time
	for _, exp := range m.expiryByID {
		if soonest.IsZero() || exp.Before(soonest) {
			soonest = exp
		}
		if expiryWarning > 0 && exp.Sub(now) <= expiryWarning {
			snap.CertsExpiringSoon++
		}
	}
	if !soonest.IsZero() {
		secs := soonest.Sub(now).Seconds()
		if secs < 0 {
			secs = 0
		}
		snap.SoonestCertExpirySeconds = secs
	}
	return snap
}

// SortedReasons returns the failure reasons in deterministic order, for tests
// and stable rendering.
func SortedReasons(byReason map[string]uint64) []string {
	out := make([]string, 0, len(byReason))
	for r := range byReason {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
