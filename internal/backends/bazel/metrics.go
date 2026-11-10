package bazel

import "sync/atomic"

// Metrics holds the Bazel registry backend's supply-chain telemetry counters.
// They are owned by the backend (one set per registered registry) and bridged
// into the central Prometheus collector at scrape time by the cmd wiring,
// mirroring how the other ecosystem backends surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	archivesServed   atomic.Uint64 // module source archives served
	archivesVerified atomic.Uint64 // archives whose digest verified against source.json integrity
	checksumMismatch atomic.Uint64 // archives whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // archives served without a usable source.json integrity
	sourceFetched    atomic.Uint64 // source.json documents fetched to resolve an archive URL/integrity
	sourceRewritten  atomic.Uint64 // source.json documents whose archive URL was rewritten to the proxy
	indexServed      atomic.Uint64 // registry/module metadata documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArchivesServed   float64
	ArchivesVerified float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	SourceFetched    float64
	SourceRewritten  float64
	IndexServed      float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArchivesServed:   float64(m.archivesServed.Load()),
		ArchivesVerified: float64(m.archivesVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		SourceFetched:    float64(m.sourceFetched.Load()),
		SourceRewritten:  float64(m.sourceRewritten.Load()),
		IndexServed:      float64(m.indexServed.Load()),
	}
}

func (m *Metrics) incArchivesServed()   { m.archivesServed.Add(1) }
func (m *Metrics) incArchivesVerified() { m.archivesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incSourceFetched()    { m.sourceFetched.Add(1) }
func (m *Metrics) incSourceRewritten()  { m.sourceRewritten.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
