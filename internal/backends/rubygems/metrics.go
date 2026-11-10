package rubygems

import "sync/atomic"

// Metrics holds the RubyGems backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the Maven backend and the other subsystems surface their counters. All methods
// are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	gemsVerified     atomic.Uint64 // .gem files whose SHA-256 was verified OK
	checksumMismatch atomic.Uint64 // .gem files whose content failed verification
	checksumMissing  atomic.Uint64 // .gem files served without a recoverable checksum
	infoParsed       atomic.Uint64 // /info/<gem> documents successfully parsed
	infoParseErrors  atomic.Uint64 // /info/<gem> documents that failed to parse
	indexServed      atomic.Uint64 // compact-index /versions, /names, /info documents served
	legacyServed     atomic.Uint64 // legacy Marshal index / dependency-API documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	GemsVerified     float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	InfoParsed       float64
	InfoParseErrors  float64
	IndexServed      float64
	LegacyServed     float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		GemsVerified:     float64(m.gemsVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		InfoParsed:       float64(m.infoParsed.Load()),
		InfoParseErrors:  float64(m.infoParseErrors.Load()),
		IndexServed:      float64(m.indexServed.Load()),
		LegacyServed:     float64(m.legacyServed.Load()),
	}
}

func (m *Metrics) incGemsVerified()     { m.gemsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incInfoParsed()       { m.infoParsed.Add(1) }
func (m *Metrics) incInfoParseErrors()  { m.infoParseErrors.Add(1) }
func (m *Metrics) incIndexServed()      { m.indexServed.Add(1) }
func (m *Metrics) incLegacyServed()     { m.legacyServed.Add(1) }
