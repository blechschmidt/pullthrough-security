package homebrew

import "sync/atomic"

// Metrics holds the Homebrew backend's supply-chain telemetry counters. They
// are owned by the backend (one set per registered upstream) and bridged into
// the central Prometheus collector at scrape time by the cmd wiring, mirroring
// how the other ecosystem backends surface their counters. All methods are safe
// for concurrent use; the zero value is ready to use.
type Metrics struct {
	formulaServed      atomic.Uint64 // formula index/per-formula documents served
	formulaRewritten   atomic.Uint64 // formula documents whose bottle URLs were rewritten
	metadataServed     atomic.Uint64 // other formulae.brew.sh documents proxied byte-exact
	bottlesServed      atomic.Uint64 // bottle OCI blobs served
	bottlesVerified    atomic.Uint64 // bottles whose SHA-256 matched the content address in their URL
	bottleHashMismatch atomic.Uint64 // bottles whose content failed verification and were refused
	tokensFetched      atomic.Uint64 // ghcr bearer tokens obtained via the registry handshake
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	FormulaServed      float64
	FormulaRewritten   float64
	MetadataServed     float64
	BottlesServed      float64
	BottlesVerified    float64
	BottleHashMismatch float64
	TokensFetched      float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		FormulaServed:      float64(m.formulaServed.Load()),
		FormulaRewritten:   float64(m.formulaRewritten.Load()),
		MetadataServed:     float64(m.metadataServed.Load()),
		BottlesServed:      float64(m.bottlesServed.Load()),
		BottlesVerified:    float64(m.bottlesVerified.Load()),
		BottleHashMismatch: float64(m.bottleHashMismatch.Load()),
		TokensFetched:      float64(m.tokensFetched.Load()),
	}
}

func (m *Metrics) incFormulaServed()      { m.formulaServed.Add(1) }
func (m *Metrics) incFormulaRewritten()   { m.formulaRewritten.Add(1) }
func (m *Metrics) incMetadataServed()     { m.metadataServed.Add(1) }
func (m *Metrics) incBottlesServed()      { m.bottlesServed.Add(1) }
func (m *Metrics) incBottlesVerified()    { m.bottlesVerified.Add(1) }
func (m *Metrics) incBottleHashMismatch() { m.bottleHashMismatch.Add(1) }
func (m *Metrics) incTokensFetched()      { m.tokensFetched.Add(1) }
