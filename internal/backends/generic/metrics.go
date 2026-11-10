package generic

import "sync/atomic"

// Metrics holds the generic backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered generic upstream) and bridged
// into the central Prometheus collector at scrape time by the cmd wiring,
// mirroring how the other ecosystem backends surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	artifactsServed   atomic.Uint64 // cacheable artifacts served
	artifactsVerified atomic.Uint64 // artifacts whose content digest verified
	checksumMismatch  atomic.Uint64 // artifacts whose content failed verification and were refused
	checksumMissing   atomic.Uint64 // verified routes served without a usable expected digest (fail-open)
	sidecarsFetched   atomic.Uint64 // checksum sidecars fetched to resolve an artifact's digest
	metadataServed    atomic.Uint64 // metadata/listing documents served live
	metadataRewrite   atomic.Uint64 // metadata documents whose embedded URLs were rewritten
	unmatched         atomic.Uint64 // requests rejected because no route matched
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArtifactsServed   float64
	ArtifactsVerified float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	SidecarsFetched   float64
	MetadataServed    float64
	MetadataRewrite   float64
	Unmatched         float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArtifactsServed:   float64(m.artifactsServed.Load()),
		ArtifactsVerified: float64(m.artifactsVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		SidecarsFetched:   float64(m.sidecarsFetched.Load()),
		MetadataServed:    float64(m.metadataServed.Load()),
		MetadataRewrite:   float64(m.metadataRewrite.Load()),
		Unmatched:         float64(m.unmatched.Load()),
	}
}

func (m *Metrics) incArtifactsServed()   { m.artifactsServed.Add(1) }
func (m *Metrics) incArtifactsVerified() { m.artifactsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incSidecarsFetched()   { m.sidecarsFetched.Add(1) }
func (m *Metrics) incMetadataServed()    { m.metadataServed.Add(1) }
func (m *Metrics) incMetadataRewrite()   { m.metadataRewrite.Add(1) }
func (m *Metrics) incUnmatched()         { m.unmatched.Add(1) }
