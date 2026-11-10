package cran

import "sync/atomic"

// Metrics holds the CRAN backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered repository) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	packagesServed   atomic.Uint64 // package tarballs served
	packagesVerified atomic.Uint64 // tarballs whose MD5 verified against PACKAGES
	checksumMismatch atomic.Uint64 // tarballs whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // tarballs served without a usable PACKAGES digest
	packagesFetched  atomic.Uint64 // PACKAGES indices fetched and parsed for verification
	indexServed      atomic.Uint64 // PACKAGES index documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	PackagesServed   float64
	PackagesVerified float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	PackagesFetched  float64
	IndexServed      float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		PackagesServed:   float64(m.packagesServed.Load()),
		PackagesVerified: float64(m.packagesVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		PackagesFetched:  float64(m.packagesFetched.Load()),
		IndexServed:      float64(m.indexServed.Load()),
	}
}

func (m *Metrics) incPackagesServed()   { m.packagesServed.Add(1) }
func (m *Metrics) incPackagesVerified() { m.packagesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incPackagesFetched()  { m.packagesFetched.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
