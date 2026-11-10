package julia

import "sync/atomic"

// Metrics holds the Julia backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered Pkg Server) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	tarballsServed   atomic.Uint64 // content-addressed tarballs served
	tarballsVerified atomic.Uint64 // tarballs whose git-tree-sha1 verified against the URL
	treeHashMismatch atomic.Uint64 // tarballs whose content failed verification and were refused
	listingServed    atomic.Uint64 // /registries listings served (mutable, unverified)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	TarballsServed   float64
	TarballsVerified float64
	TreeHashMismatch float64
	ListingServed    float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		TarballsServed:   float64(m.tarballsServed.Load()),
		TarballsVerified: float64(m.tarballsVerified.Load()),
		TreeHashMismatch: float64(m.treeHashMismatch.Load()),
		ListingServed:    float64(m.listingServed.Load()),
	}
}

func (m *Metrics) incTarballsServed()   { m.tarballsServed.Add(1) }
func (m *Metrics) incTarballsVerified() { m.tarballsVerified.Add(1) }
func (m *Metrics) incTreeHashMismatch() { m.treeHashMismatch.Add(1) }
func (m *Metrics) incListingServed()    { m.listingServed.Add(1) }
