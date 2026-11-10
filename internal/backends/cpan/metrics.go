package cpan

import "sync/atomic"

// Metrics holds the CPAN backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered repository) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how the
// other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	distributionsServed   atomic.Uint64 // distribution tarballs served
	distributionsVerified atomic.Uint64 // tarballs whose SHA-256 verified against CHECKSUMS
	checksumMismatch      atomic.Uint64 // tarballs whose content failed verification and were refused
	checksumMissing       atomic.Uint64 // tarballs served without a usable CHECKSUMS digest
	checksumsFetched      atomic.Uint64 // CHECKSUMS files fetched and parsed for verification
	indexServed           atomic.Uint64 // module indices / CHECKSUMS / sidecar documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	DistributionsServed   float64
	DistributionsVerified float64
	ChecksumMismatch      float64
	ChecksumMissing       float64
	ChecksumsFetched      float64
	IndexServed           float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		DistributionsServed:   float64(m.distributionsServed.Load()),
		DistributionsVerified: float64(m.distributionsVerified.Load()),
		ChecksumMismatch:      float64(m.checksumMismatch.Load()),
		ChecksumMissing:       float64(m.checksumMissing.Load()),
		ChecksumsFetched:      float64(m.checksumsFetched.Load()),
		IndexServed:           float64(m.indexServed.Load()),
	}
}

func (m *Metrics) incDistributionsServed()   { m.distributionsServed.Add(1) }
func (m *Metrics) incDistributionsVerified() { m.distributionsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()      { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()       { m.checksumMissing.Add(1) }
func (m *Metrics) incChecksumsFetched()      { m.checksumsFetched.Add(1) }
func (m *Metrics) incIndexServed()           { m.indexServed.Add(1) }
