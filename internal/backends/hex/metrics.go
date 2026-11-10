package hex

import "sync/atomic"

// Metrics holds the Hex backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered repository) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	tarballsServed   atomic.Uint64 // release tarballs served
	tarballsVerified atomic.Uint64 // tarballs whose SHA-256 verified against the package resource
	checksumMismatch atomic.Uint64 // tarballs whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // tarballs served without a usable outer_checksum
	resourceFetched  atomic.Uint64 // /packages/<name> resources fetched and parsed for verification
	registryServed   atomic.Uint64 // signed registry resources served (names/versions/packages)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	TarballsServed   float64
	TarballsVerified float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	ResourceFetched  float64
	RegistryServed   float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		TarballsServed:   float64(m.tarballsServed.Load()),
		TarballsVerified: float64(m.tarballsVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		ResourceFetched:  float64(m.resourceFetched.Load()),
		RegistryServed:   float64(m.registryServed.Load()),
	}
}

func (m *Metrics) incTarballsServed()   { m.tarballsServed.Add(1) }
func (m *Metrics) incTarballsVerified() { m.tarballsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incResourceFetched()  { m.resourceFetched.Add(1) }
func (m *Metrics) incRegistryServed()   { m.registryServed.Add(1) }
