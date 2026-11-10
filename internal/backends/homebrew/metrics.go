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
	manifestsServed    atomic.Uint64 // OCI manifests / image indexes proxied from the bottle registry
	bottlesServed      atomic.Uint64 // bottle OCI blobs served
	bottlesVerified    atomic.Uint64 // bottles whose SHA-256 matched the content address in their URL
	bottleHashMismatch atomic.Uint64 // bottles whose content failed verification and were refused
	tokensFetched      atomic.Uint64 // ghcr bearer tokens obtained via the registry handshake

	// How the formula version of a bottle requested on the registry-native path
	// was established (one increment per such request).
	versionFromManifest   atomic.Uint64 // learned from the OCI image index
	versionFromFormulaAPI atomic.Uint64 // recovered from the formula JSON API
	versionFromDigest     atomic.Uint64 // unknown: the digest-derived stand-in was used
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	FormulaServed         float64
	FormulaRewritten      float64
	MetadataServed        float64
	ManifestsServed       float64
	BottlesServed         float64
	BottlesVerified       float64
	BottleHashMismatch    float64
	TokensFetched         float64
	VersionFromManifest   float64
	VersionFromFormulaAPI float64
	VersionFromDigest     float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		FormulaServed:         float64(m.formulaServed.Load()),
		FormulaRewritten:      float64(m.formulaRewritten.Load()),
		MetadataServed:        float64(m.metadataServed.Load()),
		ManifestsServed:       float64(m.manifestsServed.Load()),
		BottlesServed:         float64(m.bottlesServed.Load()),
		BottlesVerified:       float64(m.bottlesVerified.Load()),
		BottleHashMismatch:    float64(m.bottleHashMismatch.Load()),
		TokensFetched:         float64(m.tokensFetched.Load()),
		VersionFromManifest:   float64(m.versionFromManifest.Load()),
		VersionFromFormulaAPI: float64(m.versionFromFormulaAPI.Load()),
		VersionFromDigest:     float64(m.versionFromDigest.Load()),
	}
}

func (m *Metrics) incFormulaServed()      { m.formulaServed.Add(1) }
func (m *Metrics) incFormulaRewritten()   { m.formulaRewritten.Add(1) }
func (m *Metrics) incMetadataServed()     { m.metadataServed.Add(1) }
func (m *Metrics) incManifestsServed()    { m.manifestsServed.Add(1) }
func (m *Metrics) incBottlesServed()      { m.bottlesServed.Add(1) }
func (m *Metrics) incBottlesVerified()    { m.bottlesVerified.Add(1) }
func (m *Metrics) incBottleHashMismatch() { m.bottleHashMismatch.Add(1) }
func (m *Metrics) incTokensFetched()      { m.tokensFetched.Add(1) }

// incVersionSource counts one registry-native bottle request by the source its
// formula version was established from.
func (m *Metrics) incVersionSource(source string) {
	switch source {
	case versionSourceManifest:
		m.versionFromManifest.Add(1)
	case versionSourceFormulaAPI:
		m.versionFromFormulaAPI.Add(1)
	case versionSourceDigest:
		m.versionFromDigest.Add(1)
	}
}
