package maven

import "sync/atomic"

// Metrics holds the Maven backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other subsystems surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	artifactsVerified  atomic.Uint64 // artifacts whose checksum sidecar was verified OK
	checksumMismatch   atomic.Uint64 // artifacts whose content failed checksum verification
	sidecarMissing     atomic.Uint64 // artifacts served without any usable checksum sidecar
	pomsParsed         atomic.Uint64 // POMs successfully parsed for coordinate enrichment
	pomParseErrors     atomic.Uint64 // POMs that failed to parse
	coordinateMismatch atomic.Uint64 // POMs whose declared GAV disagreed with their path
	snapshotMetadata   atomic.Uint64 // snapshot maven-metadata.xml documents served
	releaseMetadata    atomic.Uint64 // release maven-metadata.xml documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArtifactsVerified  float64
	ChecksumMismatch   float64
	SidecarMissing     float64
	POMsParsed         float64
	POMParseErrors     float64
	CoordinateMismatch float64
	SnapshotMetadata   float64
	ReleaseMetadata    float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArtifactsVerified:  float64(m.artifactsVerified.Load()),
		ChecksumMismatch:   float64(m.checksumMismatch.Load()),
		SidecarMissing:     float64(m.sidecarMissing.Load()),
		POMsParsed:         float64(m.pomsParsed.Load()),
		POMParseErrors:     float64(m.pomParseErrors.Load()),
		CoordinateMismatch: float64(m.coordinateMismatch.Load()),
		SnapshotMetadata:   float64(m.snapshotMetadata.Load()),
		ReleaseMetadata:    float64(m.releaseMetadata.Load()),
	}
}

func (m *Metrics) incArtifactsVerified()  { m.artifactsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()   { m.checksumMismatch.Add(1) }
func (m *Metrics) incSidecarMissing()     { m.sidecarMissing.Add(1) }
func (m *Metrics) incPOMsParsed()         { m.pomsParsed.Add(1) }
func (m *Metrics) incPOMParseErrors()     { m.pomParseErrors.Add(1) }
func (m *Metrics) incCoordinateMismatch() { m.coordinateMismatch.Add(1) }
func (m *Metrics) incSnapshotMetadata()   { m.snapshotMetadata.Add(1) }
func (m *Metrics) incReleaseMetadata()    { m.releaseMetadata.Add(1) }
