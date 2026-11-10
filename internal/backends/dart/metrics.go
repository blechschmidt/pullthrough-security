package dart

import "sync/atomic"

// Metrics holds the Dart/pub backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	archivesServed    atomic.Uint64 // package archives served
	archivesVerified  atomic.Uint64 // archives whose SHA-256 verified against the list-versions document
	checksumMismatch  atomic.Uint64 // archives whose content failed SHA-256 verification
	checksumMissing   atomic.Uint64 // archives served without a usable content hash
	versionsRewritten atomic.Uint64 // list-versions documents whose archive_url fields were rewritten
	versionsServed    atomic.Uint64 // list-versions documents served
	advisoriesServed  atomic.Uint64 // advisories documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ArchivesServed    float64
	ArchivesVerified  float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	VersionsRewritten float64
	VersionsServed    float64
	AdvisoriesServed  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ArchivesServed:    float64(m.archivesServed.Load()),
		ArchivesVerified:  float64(m.archivesVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		VersionsRewritten: float64(m.versionsRewritten.Load()),
		VersionsServed:    float64(m.versionsServed.Load()),
		AdvisoriesServed:  float64(m.advisoriesServed.Load()),
	}
}

func (m *Metrics) incArchivesServed()    { m.archivesServed.Add(1) }
func (m *Metrics) incArchivesVerified()  { m.archivesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incVersionsRewritten() { m.versionsRewritten.Add(1) }
func (m *Metrics) incVersionsServed()    { m.versionsServed.Add(1) }
func (m *Metrics) incAdvisoriesServed()  { m.advisoriesServed.Add(1) }
