package composer

import "sync/atomic"

// Metrics holds the Composer backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the Maven and RubyGems backends surface their counters. All methods are safe
// for concurrent use; the zero value is ready to use.
type Metrics struct {
	distVerified     atomic.Uint64 // dist archives whose SHA-1 was verified OK
	checksumMismatch atomic.Uint64 // dist archives whose content failed verification
	checksumMissing  atomic.Uint64 // dist archives served without a recoverable shasum
	metadataParsed   atomic.Uint64 // v2 metadata documents successfully parsed
	metadataErrors   atomic.Uint64 // v2 metadata documents that failed to parse
	metadataServed   atomic.Uint64 // metadata/root/provider documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	DistVerified     float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	MetadataParsed   float64
	MetadataErrors   float64
	MetadataServed   float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		DistVerified:     float64(m.distVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		MetadataParsed:   float64(m.metadataParsed.Load()),
		MetadataErrors:   float64(m.metadataErrors.Load()),
		MetadataServed:   float64(m.metadataServed.Load()),
	}
}

func (m *Metrics) incDistVerified()     { m.distVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incMetadataParsed()   { m.metadataParsed.Add(1) }
func (m *Metrics) incMetadataErrors()   { m.metadataErrors.Add(1) }
func (m *Metrics) incMetadataServed()   { m.metadataServed.Add(1) }
