package conda

import "sync/atomic"

// Metrics holds the Conda backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered channel) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	packagesServed   atomic.Uint64 // package archives served
	packagesVerified atomic.Uint64 // packages whose digest verified against repodata.json
	checksumMismatch atomic.Uint64 // packages whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // packages served without a usable repodata.json digest
	repodataFetched  atomic.Uint64 // repodata.json documents fetched to resolve a package digest
	indexServed      atomic.Uint64 // repodata/channeldata index documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	PackagesServed   float64
	PackagesVerified float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	RepodataFetched  float64
	IndexServed      float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		PackagesServed:   float64(m.packagesServed.Load()),
		PackagesVerified: float64(m.packagesVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		RepodataFetched:  float64(m.repodataFetched.Load()),
		IndexServed:      float64(m.indexServed.Load()),
	}
}

func (m *Metrics) incPackagesServed()   { m.packagesServed.Add(1) }
func (m *Metrics) incPackagesVerified() { m.packagesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incRepodataFetched()  { m.repodataFetched.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
