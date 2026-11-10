package jsr

import "sync/atomic"

// Metrics holds the JSR backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered registry) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	modulesServed      atomic.Uint64 // module files served
	modulesVerified    atomic.Uint64 // module files whose SHA-256 verified against the version manifest
	checksumMismatch   atomic.Uint64 // module files whose content failed verification and were refused
	checksumMissing    atomic.Uint64 // module files served without a usable manifest digest
	versionMetaFetched atomic.Uint64 // <version>_meta.json documents fetched to resolve a file digest
	metadataServed     atomic.Uint64 // metadata documents served (package/version meta)
	metadataRewritten  atomic.Uint64 // metadata documents whose embedded upstream URLs were rewritten
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ModulesServed      float64
	ModulesVerified    float64
	ChecksumMismatch   float64
	ChecksumMissing    float64
	VersionMetaFetched float64
	MetadataServed     float64
	MetadataRewritten  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ModulesServed:      float64(m.modulesServed.Load()),
		ModulesVerified:    float64(m.modulesVerified.Load()),
		ChecksumMismatch:   float64(m.checksumMismatch.Load()),
		ChecksumMissing:    float64(m.checksumMissing.Load()),
		VersionMetaFetched: float64(m.versionMetaFetched.Load()),
		MetadataServed:     float64(m.metadataServed.Load()),
		MetadataRewritten:  float64(m.metadataRewritten.Load()),
	}
}

func (m *Metrics) incModulesServed()      { m.modulesServed.Add(1) }
func (m *Metrics) incModulesVerified()    { m.modulesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()   { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()    { m.checksumMissing.Add(1) }
func (m *Metrics) incVersionMetaFetched() { m.versionMetaFetched.Add(1) }
func (m *Metrics) incMetadataServed()     { m.metadataServed.Add(1) }
func (m *Metrics) incMetadataRewritten()  { m.metadataRewritten.Add(1) }
