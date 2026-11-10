package hackage

import "sync/atomic"

// Metrics holds the Hackage backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered repository) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	sdistsServed     atomic.Uint64 // sdist tarballs served
	sdistsVerified   atomic.Uint64 // sdists whose SHA-256 verified against the TUF target metadata
	checksumMismatch atomic.Uint64 // sdists whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // sdists served without a usable declared digest
	targetsFetched   atomic.Uint64 // package.json TUF target documents fetched to resolve a digest
	indexServed      atomic.Uint64 // index/TUF/cabal documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	SdistsServed     float64
	SdistsVerified   float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	TargetsFetched   float64
	IndexServed      float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		SdistsServed:     float64(m.sdistsServed.Load()),
		SdistsVerified:   float64(m.sdistsVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		TargetsFetched:   float64(m.targetsFetched.Load()),
		IndexServed:      float64(m.indexServed.Load()),
	}
}

func (m *Metrics) incSdistsServed()     { m.sdistsServed.Add(1) }
func (m *Metrics) incSdistsVerified()   { m.sdistsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incTargetsFetched()   { m.targetsFetched.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
