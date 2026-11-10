package apt

import "sync/atomic"

// Metrics holds the APT backend's supply-chain telemetry counters. They are owned
// by the backend (one set per registered upstream) and bridged into the central
// Prometheus collector at scrape time by the cmd wiring, mirroring how the Maven,
// Helm, and RubyGems backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	debsVerified      atomic.Uint64 // .deb artifacts whose SHA-256 was verified OK
	checksumMismatch  atomic.Uint64 // .deb artifacts whose content failed verification
	checksumMissing   atomic.Uint64 // .deb artifacts served without a recorded digest
	packagesParsed    atomic.Uint64 // Packages indices successfully parsed for digests
	packagesErrors    atomic.Uint64 // Packages indices that failed to parse/decompress
	indexVerified     atomic.Uint64 // Packages indices verified against Release
	indexMismatch     atomic.Uint64 // Packages indices whose content failed Release verification
	releaseServed     atomic.Uint64 // Release/InRelease documents served to clients
	signatureVerified atomic.Uint64 // Release/InRelease GPG signatures validated against a trusted key
	signatureFailures atomic.Uint64 // Release/InRelease GPG signatures that failed validation
	signatureSkipped  atomic.Uint64 // Release/InRelease served without GPG enforcement (no keyring)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	DebsVerified      float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	PackagesParsed    float64
	PackagesErrors    float64
	IndexVerified     float64
	IndexMismatch     float64
	ReleaseServed     float64
	SignatureVerified float64
	SignatureFailures float64
	SignatureSkipped  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		DebsVerified:      float64(m.debsVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		PackagesParsed:    float64(m.packagesParsed.Load()),
		PackagesErrors:    float64(m.packagesErrors.Load()),
		IndexVerified:     float64(m.indexVerified.Load()),
		IndexMismatch:     float64(m.indexMismatch.Load()),
		ReleaseServed:     float64(m.releaseServed.Load()),
		SignatureVerified: float64(m.signatureVerified.Load()),
		SignatureFailures: float64(m.signatureFailures.Load()),
		SignatureSkipped:  float64(m.signatureSkipped.Load()),
	}
}

func (m *Metrics) incDebsVerified()      { m.debsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incPackagesParsed()    { m.packagesParsed.Add(1) }
func (m *Metrics) incPackagesErrors()    { m.packagesErrors.Add(1) }
func (m *Metrics) incIndexVerified()     { m.indexVerified.Add(1) }
func (m *Metrics) incIndexMismatch()     { m.indexMismatch.Add(1) }
func (m *Metrics) incReleaseServed()     { m.releaseServed.Add(1) }
func (m *Metrics) incSignatureVerified() { m.signatureVerified.Add(1) }
func (m *Metrics) incSignatureFailures() { m.signatureFailures.Add(1) }
func (m *Metrics) incSignatureSkipped()  { m.signatureSkipped.Add(1) }
