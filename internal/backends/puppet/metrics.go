package puppet

import "sync/atomic"

// Metrics holds the Puppet Forge backend's supply-chain telemetry counters.
// They are owned by the backend (one set per registered registry) and bridged
// into the central Prometheus collector at scrape time by the cmd wiring,
// mirroring how the other ecosystem backends surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	releasesServed    atomic.Uint64 // release tarballs served
	releasesVerified  atomic.Uint64 // release tarballs whose digest verified against the release metadata
	checksumMismatch  atomic.Uint64 // release tarballs whose content failed verification and were refused
	checksumMissing   atomic.Uint64 // release tarballs served without a usable published digest
	md5Fallback       atomic.Uint64 // release tarballs verified against the legacy MD5 (no SHA-256 published)
	releaseMetaFetch  atomic.Uint64 // release-metadata documents fetched to resolve a tarball digest
	metadataServed    atomic.Uint64 // metadata documents served (module/release/listing)
	metadataRewritten atomic.Uint64 // metadata documents whose embedded upstream URLs were rewritten
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ReleasesServed    float64
	ReleasesVerified  float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	MD5Fallback       float64
	ReleaseMetaFetch  float64
	MetadataServed    float64
	MetadataRewritten float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ReleasesServed:    float64(m.releasesServed.Load()),
		ReleasesVerified:  float64(m.releasesVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		MD5Fallback:       float64(m.md5Fallback.Load()),
		ReleaseMetaFetch:  float64(m.releaseMetaFetch.Load()),
		MetadataServed:    float64(m.metadataServed.Load()),
		MetadataRewritten: float64(m.metadataRewritten.Load()),
	}
}

func (m *Metrics) incReleasesServed()    { m.releasesServed.Add(1) }
func (m *Metrics) incReleasesVerified()  { m.releasesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incMD5Fallback()       { m.md5Fallback.Add(1) }
func (m *Metrics) incReleaseMetaFetch()  { m.releaseMetaFetch.Add(1) }
func (m *Metrics) incMetadataServed()    { m.metadataServed.Add(1) }
func (m *Metrics) incMetadataRewritten() { m.metadataRewritten.Add(1) }
