package ansible

import "sync/atomic"

// Metrics holds the Ansible Galaxy backend's supply-chain telemetry counters.
// They are owned by the backend (one set per registered registry) and bridged
// into the central Prometheus collector at scrape time by the cmd wiring,
// mirroring how the other ecosystem backends surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	artifactsServed    atomic.Uint64 // collection artifacts served
	artifactsVerified  atomic.Uint64 // collection artifacts whose SHA-256 verified against the version detail
	checksumMismatch   atomic.Uint64 // collection artifacts whose content failed verification and were refused
	checksumMissing    atomic.Uint64 // collection artifacts served without a usable published digest
	versionMetaFetched atomic.Uint64 // version-detail documents fetched to resolve an artifact digest
	metadataServed     atomic.Uint64 // metadata documents served (index/versions/version-detail/role)
	metadataRewritten  atomic.Uint64 // metadata documents whose embedded upstream URLs were rewritten
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArtifactsServed    float64
	ArtifactsVerified  float64
	ChecksumMismatch   float64
	ChecksumMissing    float64
	VersionMetaFetched float64
	MetadataServed     float64
	MetadataRewritten  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArtifactsServed:    float64(m.artifactsServed.Load()),
		ArtifactsVerified:  float64(m.artifactsVerified.Load()),
		ChecksumMismatch:   float64(m.checksumMismatch.Load()),
		ChecksumMissing:    float64(m.checksumMissing.Load()),
		VersionMetaFetched: float64(m.versionMetaFetched.Load()),
		MetadataServed:     float64(m.metadataServed.Load()),
		MetadataRewritten:  float64(m.metadataRewritten.Load()),
	}
}

func (m *Metrics) incArtifactsServed()    { m.artifactsServed.Add(1) }
func (m *Metrics) incArtifactsVerified()  { m.artifactsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()   { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()    { m.checksumMissing.Add(1) }
func (m *Metrics) incVersionMetaFetched() { m.versionMetaFetched.Add(1) }
func (m *Metrics) incMetadataServed()     { m.metadataServed.Add(1) }
func (m *Metrics) incMetadataRewritten()  { m.metadataRewritten.Add(1) }
