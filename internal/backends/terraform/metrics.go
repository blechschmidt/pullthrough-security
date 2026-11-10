package terraform

import "sync/atomic"

// Metrics holds the Terraform/OpenTofu backend's supply-chain telemetry
// counters. They are owned by the backend (one set per registered upstream) and
// bridged into the central Prometheus collector at scrape time by the cmd
// wiring, mirroring how the Maven and Helm backends surface their counters. All
// methods are safe for concurrent use; the zero value is ready to use.
type Metrics struct {
	providersVerified   atomic.Uint64 // provider zips whose SHA-256 matched the signed SHASUMS manifest
	checksumMismatch    atomic.Uint64 // provider zips whose content failed SHA-256 verification
	checksumMissing     atomic.Uint64 // provider zips served without a recoverable SHASUMS digest
	signatureVerified   atomic.Uint64 // SHASUMS manifests whose GPG signature verified against the registry keys
	signatureFailed     atomic.Uint64 // SHASUMS manifests whose GPG signature failed to verify (refused)
	signatureMissing    atomic.Uint64 // provider downloads with no signature/keys to verify against
	providerDownloads   atomic.Uint64 // provider download descriptors (download/{os}/{arch}) served
	providerVersions    atomic.Uint64 // provider version-list documents served
	moduleArchives      atomic.Uint64 // module source archives fetched and cached
	moduleDownloads     atomic.Uint64 // module download descriptors (X-Terraform-Get) served
	moduleVersions      atomic.Uint64 // module version-list documents served
	moduleArchivePassed atomic.Uint64 // module downloads passed through unrewritten (non-HTTP getter)
	jsonParseErrors     atomic.Uint64 // provider/module descriptors that failed to parse
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	ProvidersVerified   float64
	ChecksumMismatch    float64
	ChecksumMissing     float64
	SignatureVerified   float64
	SignatureFailed     float64
	SignatureMissing    float64
	ProviderDownloads   float64
	ProviderVersions    float64
	ModuleArchives      float64
	ModuleDownloads     float64
	ModuleVersions      float64
	ModuleArchivePassed float64
	JSONParseErrors     float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		ProvidersVerified:   float64(m.providersVerified.Load()),
		ChecksumMismatch:    float64(m.checksumMismatch.Load()),
		ChecksumMissing:     float64(m.checksumMissing.Load()),
		SignatureVerified:   float64(m.signatureVerified.Load()),
		SignatureFailed:     float64(m.signatureFailed.Load()),
		SignatureMissing:    float64(m.signatureMissing.Load()),
		ProviderDownloads:   float64(m.providerDownloads.Load()),
		ProviderVersions:    float64(m.providerVersions.Load()),
		ModuleArchives:      float64(m.moduleArchives.Load()),
		ModuleDownloads:     float64(m.moduleDownloads.Load()),
		ModuleVersions:      float64(m.moduleVersions.Load()),
		ModuleArchivePassed: float64(m.moduleArchivePassed.Load()),
		JSONParseErrors:     float64(m.jsonParseErrors.Load()),
	}
}

func (m *Metrics) incProvidersVerified()   { m.providersVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()    { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()     { m.checksumMissing.Add(1) }
func (m *Metrics) incSignatureVerified()   { m.signatureVerified.Add(1) }
func (m *Metrics) incSignatureFailed()     { m.signatureFailed.Add(1) }
func (m *Metrics) incSignatureMissing()    { m.signatureMissing.Add(1) }
func (m *Metrics) incProviderDownloads()   { m.providerDownloads.Add(1) }
func (m *Metrics) incProviderVersions()    { m.providerVersions.Add(1) }
func (m *Metrics) incModuleArchives()      { m.moduleArchives.Add(1) }
func (m *Metrics) incModuleDownloads()     { m.moduleDownloads.Add(1) }
func (m *Metrics) incModuleVersions()      { m.moduleVersions.Add(1) }
func (m *Metrics) incModuleArchivePassed() { m.moduleArchivePassed.Add(1) }
func (m *Metrics) incJSONParseErrors()     { m.jsonParseErrors.Add(1) }
