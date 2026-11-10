package conan

import "sync/atomic"

// Metrics holds the Conan backend's supply-chain telemetry counters. They are
// owned by the backend (one set per registered upstream) and bridged into the
// central Prometheus collector at scrape time by the cmd wiring, mirroring how
// the other ecosystem backends surface their counters. All methods are safe for
// concurrent use; the zero value is ready to use.
type Metrics struct {
	filesServed       atomic.Uint64 // recipe/package content files served
	filesVerified     atomic.Uint64 // files whose MD5 verified against conanmanifest.txt
	checksumMismatch  atomic.Uint64 // files whose content failed MD5 verification
	manifestMissing   atomic.Uint64 // files served without a usable manifest entry
	manifestParsed    atomic.Uint64 // conanmanifest.txt documents fetched and parsed for verification
	conanInfoServed   atomic.Uint64 // conaninfo.txt package descriptors served
	metadataServed    atomic.Uint64 // discovery docs served (latest/revisions/search/ping/users)
	fileListingServed atomic.Uint64 // per-revision file listings served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	FilesServed       float64
	FilesVerified     float64
	ChecksumMismatch  float64
	ManifestMissing   float64
	ManifestParsed    float64
	ConanInfoServed   float64
	MetadataServed    float64
	FileListingServed float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		FilesServed:       float64(m.filesServed.Load()),
		FilesVerified:     float64(m.filesVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ManifestMissing:   float64(m.manifestMissing.Load()),
		ManifestParsed:    float64(m.manifestParsed.Load()),
		ConanInfoServed:   float64(m.conanInfoServed.Load()),
		MetadataServed:    float64(m.metadataServed.Load()),
		FileListingServed: float64(m.fileListingServed.Load()),
	}
}

func (m *Metrics) incFilesServed()       { m.filesServed.Add(1) }
func (m *Metrics) incFilesVerified()     { m.filesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incManifestMissing()   { m.manifestMissing.Add(1) }
func (m *Metrics) incManifestParsed()    { m.manifestParsed.Add(1) }
func (m *Metrics) incConanInfoServed()   { m.conanInfoServed.Add(1) }
func (m *Metrics) incMetadataServed()    { m.metadataServed.Add(1) }
func (m *Metrics) incFileListingServed() { m.fileListingServed.Add(1) }
