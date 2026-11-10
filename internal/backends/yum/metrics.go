package yum

import "sync/atomic"

// Metrics holds the YUM/RPM backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how the
// Maven, Helm, and APT backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	rpmsVerified      atomic.Uint64 // .rpm artifacts whose checksum was verified OK
	checksumMismatch  atomic.Uint64 // .rpm artifacts whose content failed verification
	checksumMissing   atomic.Uint64 // .rpm artifacts served without a recorded digest
	primaryParsed     atomic.Uint64 // primary.xml documents successfully parsed for digests
	primaryErrors     atomic.Uint64 // primary.xml documents that failed to parse/decompress
	repomdParsed      atomic.Uint64 // repomd.xml documents successfully parsed
	repomdErrors      atomic.Uint64 // repomd.xml documents that failed to parse
	repodataVerified  atomic.Uint64 // repodata files verified against repomd.xml
	repodataMismatch  atomic.Uint64 // repodata files whose content failed repomd verification
	repomdServed      atomic.Uint64 // repomd.xml documents served to clients
	signatureVerified atomic.Uint64 // repomd.xml GPG signatures validated against a trusted key
	signatureFailures atomic.Uint64 // repomd.xml GPG signatures that failed validation
	signatureSkipped  atomic.Uint64 // repomd.xml served without GPG enforcement (no keyring)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	RPMsVerified      float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	PrimaryParsed     float64
	PrimaryErrors     float64
	RepomdParsed      float64
	RepomdErrors      float64
	RepodataVerified  float64
	RepodataMismatch  float64
	RepomdServed      float64
	SignatureVerified float64
	SignatureFailures float64
	SignatureSkipped  float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		RPMsVerified:      float64(m.rpmsVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		PrimaryParsed:     float64(m.primaryParsed.Load()),
		PrimaryErrors:     float64(m.primaryErrors.Load()),
		RepomdParsed:      float64(m.repomdParsed.Load()),
		RepomdErrors:      float64(m.repomdErrors.Load()),
		RepodataVerified:  float64(m.repodataVerified.Load()),
		RepodataMismatch:  float64(m.repodataMismatch.Load()),
		RepomdServed:      float64(m.repomdServed.Load()),
		SignatureVerified: float64(m.signatureVerified.Load()),
		SignatureFailures: float64(m.signatureFailures.Load()),
		SignatureSkipped:  float64(m.signatureSkipped.Load()),
	}
}

func (m *Metrics) incRPMsVerified()      { m.rpmsVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incPrimaryParsed()     { m.primaryParsed.Add(1) }
func (m *Metrics) incPrimaryErrors()     { m.primaryErrors.Add(1) }
func (m *Metrics) incRepomdParsed()      { m.repomdParsed.Add(1) }
func (m *Metrics) incRepomdErrors()      { m.repomdErrors.Add(1) }
func (m *Metrics) incRepodataVerified()  { m.repodataVerified.Add(1) }
func (m *Metrics) incRepodataMismatch()  { m.repodataMismatch.Add(1) }
func (m *Metrics) incRepomdServed()      { m.repomdServed.Add(1) }
func (m *Metrics) incSignatureVerified() { m.signatureVerified.Add(1) }
func (m *Metrics) incSignatureFailures() { m.signatureFailures.Add(1) }
func (m *Metrics) incSignatureSkipped()  { m.signatureSkipped.Add(1) }
