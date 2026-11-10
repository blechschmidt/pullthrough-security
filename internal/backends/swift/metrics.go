package swift

import "sync/atomic"

// Metrics holds the Swift backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	archivesServed   atomic.Uint64 // source archives served
	archivesVerified atomic.Uint64 // archives whose SHA-256 verified against the release metadata
	checksumMismatch atomic.Uint64 // archives whose content failed SHA-256 verification
	checksumMissing  atomic.Uint64 // archives served without a usable metadata checksum
	metadataFetched  atomic.Uint64 // release metadata documents fetched to resolve a checksum
	manifestsServed  atomic.Uint64 // Package.swift manifests served
	metadataServed   atomic.Uint64 // discovery docs served (release list, release metadata, identifiers)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArchivesServed   float64
	ArchivesVerified float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	MetadataFetched  float64
	ManifestsServed  float64
	MetadataServed   float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArchivesServed:   float64(m.archivesServed.Load()),
		ArchivesVerified: float64(m.archivesVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		MetadataFetched:  float64(m.metadataFetched.Load()),
		ManifestsServed:  float64(m.manifestsServed.Load()),
		MetadataServed:   float64(m.metadataServed.Load()),
	}
}

func (m *Metrics) incArchivesServed()   { m.archivesServed.Add(1) }
func (m *Metrics) incArchivesVerified() { m.archivesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incMetadataFetched()  { m.metadataFetched.Add(1) }
func (m *Metrics) incManifestsServed()  { m.manifestsServed.Add(1) }
func (m *Metrics) incMetadataServed()   { m.metadataServed.Add(1) }
