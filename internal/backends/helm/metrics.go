package helm

import "sync/atomic"

// Metrics holds the Helm backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the Maven, RubyGems, and Composer backends surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	chartsVerified   atomic.Uint64 // chart .tgz archives whose SHA-256 was verified OK
	checksumMismatch atomic.Uint64 // chart archives whose content failed verification
	checksumMissing  atomic.Uint64 // chart archives served without a recoverable index digest
	indexParsed      atomic.Uint64 // index.yaml documents successfully parsed
	indexErrors      atomic.Uint64 // index.yaml documents that failed to parse
	indexServed      atomic.Uint64 // index.yaml documents served to clients
	provenanceServed atomic.Uint64 // chart provenance (.prov) sidecars served
	ociChartsServed  atomic.Uint64 // OCI-hosted chart manifests/blobs served via the OCI path
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ChartsVerified   float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	IndexParsed      float64
	IndexErrors      float64
	IndexServed      float64
	ProvenanceServed float64
	OCIChartsServed  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ChartsVerified:   float64(m.chartsVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		IndexParsed:      float64(m.indexParsed.Load()),
		IndexErrors:      float64(m.indexErrors.Load()),
		IndexServed:      float64(m.indexServed.Load()),
		ProvenanceServed: float64(m.provenanceServed.Load()),
		OCIChartsServed:  float64(m.ociChartsServed.Load()),
	}
}

func (m *Metrics) incChartsVerified()   { m.chartsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incIndexParsed()      { m.indexParsed.Add(1) }
func (m *Metrics) incIndexErrors()      { m.indexErrors.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
func (m *Metrics) incProvenanceServed() { m.provenanceServed.Add(1) }
func (m *Metrics) incOCIChartsServed()  { m.ociChartsServed.Add(1) }
