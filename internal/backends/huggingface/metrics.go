package huggingface

import "sync/atomic"

// Metrics holds the Hugging Face backend's supply-chain telemetry counters. They
// are owned by the backend (one set per registered upstream) and bridged into
// the central Prometheus collector at scrape time by the cmd wiring, mirroring
// how the other ecosystem backends surface their counters. All methods are safe
// for concurrent use; the zero value is ready to use.
type Metrics struct {
	filesServed       atomic.Uint64 // resolve blobs served
	filesVerified     atomic.Uint64 // blobs whose SHA-256 verified against X-Linked-Etag
	checksumMismatch  atomic.Uint64 // blobs whose content failed SHA-256 verification
	checksumMissing   atomic.Uint64 // blobs served without a usable upstream content hash
	lfsResolved       atomic.Uint64 // LFS blobs resolved through the CDN redirect
	pointersSeen      atomic.Uint64 // git-lfs pointer bodies observed on the resolve path
	safetensorsServed atomic.Uint64 // .safetensors (safe, tensor-only) weight files served
	pickleServed      atomic.Uint64 // pickle-based weight files (.bin/.pkl/.pt/.ckpt) served
	metadataServed    atomic.Uint64 // /api/{models,datasets} metadata documents served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	FilesServed       float64
	FilesVerified     float64
	ChecksumMismatch  float64
	ChecksumMissing   float64
	LFSResolved       float64
	PointersSeen      float64
	SafetensorsServed float64
	PickleServed      float64
	MetadataServed    float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		FilesServed:       float64(m.filesServed.Load()),
		FilesVerified:     float64(m.filesVerified.Load()),
		ChecksumMismatch:  float64(m.checksumMismatch.Load()),
		ChecksumMissing:   float64(m.checksumMissing.Load()),
		LFSResolved:       float64(m.lfsResolved.Load()),
		PointersSeen:      float64(m.pointersSeen.Load()),
		SafetensorsServed: float64(m.safetensorsServed.Load()),
		PickleServed:      float64(m.pickleServed.Load()),
		MetadataServed:    float64(m.metadataServed.Load()),
	}
}

func (m *Metrics) incFilesServed()       { m.filesServed.Add(1) }
func (m *Metrics) incFilesVerified()     { m.filesVerified.Add(1) }
func (m *Metrics) incChecksumMismatch()  { m.checksumMismatch.Add(1) }
func (m *Metrics) incChecksumMissing()   { m.checksumMissing.Add(1) }
func (m *Metrics) incLFSResolved()       { m.lfsResolved.Add(1) }
func (m *Metrics) incPointersSeen()      { m.pointersSeen.Add(1) }
func (m *Metrics) incSafetensorsServed() { m.safetensorsServed.Add(1) }
func (m *Metrics) incPickleServed()      { m.pickleServed.Add(1) }
func (m *Metrics) incMetadataServed()    { m.metadataServed.Add(1) }
