package openvsx

import "sync/atomic"

// Metrics holds the OpenVSX backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered registry) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	vsixServed       atomic.Uint64 // .vsix extension archives served
	vsixVerified     atomic.Uint64 // .vsix archives whose SHA-256 verified against the sidecar
	checksumMismatch atomic.Uint64 // .vsix archives whose content failed verification and were refused
	checksumMissing  atomic.Uint64 // .vsix archives served without a usable .sha256 sidecar
	sha256Fetched    atomic.Uint64 // .sha256 sidecars fetched to resolve an archive's digest
	metadataServed   atomic.Uint64 // metadata/query documents served
	metadataRewrite  atomic.Uint64 // metadata/gallery documents whose embedded URLs were rewritten
	galleryServed    atomic.Uint64 // VS Code gallery-protocol documents served
	fileServed       atomic.Uint64 // byte-exact /file/ sidecar resources served (sha256/signature/…)
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	VsixServed       float64
	VsixVerified     float64
	ChecksumMismatch float64
	ChecksumMissing  float64
	SHA256Fetched    float64
	MetadataServed   float64
	MetadataRewrite  float64
	GalleryServed    float64
	FileServed       float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		VsixServed:       float64(m.vsixServed.Load()),
		VsixVerified:     float64(m.vsixVerified.Load()),
		ChecksumMismatch: float64(m.checksumMismatch.Load()),
		ChecksumMissing:  float64(m.checksumMissing.Load()),
		SHA256Fetched:    float64(m.sha256Fetched.Load()),
		MetadataServed:   float64(m.metadataServed.Load()),
		MetadataRewrite:  float64(m.metadataRewrite.Load()),
		GalleryServed:    float64(m.galleryServed.Load()),
		FileServed:       float64(m.fileServed.Load()),
	}
}

func (m *Metrics) incVsixServed()       { m.vsixServed.Add(1) }
func (m *Metrics) incVsixVerified()     { m.vsixVerified.Add(1) }
func (m *Metrics) incChecksumMismatch() { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()  { m.checksumMissing.Add(1) }
func (m *Metrics) incSHA256Fetched()    { m.sha256Fetched.Add(1) }
func (m *Metrics) incMetadataServed()   { m.metadataServed.Add(1) }
func (m *Metrics) incMetadataRewrite()  { m.metadataRewrite.Add(1) }
func (m *Metrics) incGalleryServed()    { m.galleryServed.Add(1) }
func (m *Metrics) incFileServed()       { m.fileServed.Add(1) }
