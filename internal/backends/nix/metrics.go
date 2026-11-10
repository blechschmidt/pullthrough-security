package nix

import "sync/atomic"

// Metrics holds the Nix binary-cache backend's supply-chain telemetry counters.
// They are owned by the backend (one set per registered cache) and bridged into
// the central Prometheus collector at scrape time by the cmd wiring, mirroring
// how the other ecosystem backends surface their counters. All methods are safe
// for concurrent use; the zero value is ready to use.
type Metrics struct {
	narsServed        atomic.Uint64 // NAR archives served
	narsVerified      atomic.Uint64 // NARs whose SHA-256 verified against the URL content address
	fileHashMismatch  atomic.Uint64 // NARs whose content failed verification and were refused
	fileHashMissing   atomic.Uint64 // NARs served without a verifiable SHA-256 content address
	narInfoServed     atomic.Uint64 // narinfo documents served
	narInfoSigValid   atomic.Uint64 // narinfos whose signature verified against a trusted key
	narInfoSigInvalid atomic.Uint64 // narinfos rejected for lacking a valid trusted signature
	narInfoUnverified atomic.Uint64 // narinfos served without signature verification (no keys configured)
	narInfoRewritten  atomic.Uint64 // narinfos whose URL field was rewritten through the proxy
	cacheInfoServed   atomic.Uint64 // /nix-cache-info descriptors served
}

// Snapshot is an immutable copy of the counters for a single scrape.
type Snapshot struct {
	NarsServed        float64
	NarsVerified      float64
	FileHashMismatch  float64
	FileHashMissing   float64
	NarInfoServed     float64
	NarInfoSigValid   float64
	NarInfoSigInvalid float64
	NarInfoUnverified float64
	NarInfoRewritten  float64
	CacheInfoServed   float64
}

// Stats returns the current counter values.
func (m *Metrics) Stats() Snapshot {
	return Snapshot{
		NarsServed:        float64(m.narsServed.Load()),
		NarsVerified:      float64(m.narsVerified.Load()),
		FileHashMismatch:  float64(m.fileHashMismatch.Load()),
		FileHashMissing:   float64(m.fileHashMissing.Load()),
		NarInfoServed:     float64(m.narInfoServed.Load()),
		NarInfoSigValid:   float64(m.narInfoSigValid.Load()),
		NarInfoSigInvalid: float64(m.narInfoSigInvalid.Load()),
		NarInfoUnverified: float64(m.narInfoUnverified.Load()),
		NarInfoRewritten:  float64(m.narInfoRewritten.Load()),
		CacheInfoServed:   float64(m.cacheInfoServed.Load()),
	}
}

func (m *Metrics) incNarsServed()        { m.narsServed.Add(1) }
func (m *Metrics) incNarsVerified()      { m.narsVerified.Add(1) }
func (m *Metrics) incFileHashMismatch()  { m.fileHashMismatch.Add(1) }
func (m *Metrics) incFileHashMissing()   { m.fileHashMissing.Add(1) }
func (m *Metrics) incNarInfoServed()     { m.narInfoServed.Add(1) }
func (m *Metrics) incNarInfoSigValid()   { m.narInfoSigValid.Add(1) }
func (m *Metrics) incNarInfoSigInvalid() { m.narInfoSigInvalid.Add(1) }
func (m *Metrics) incNarInfoUnverified() { m.narInfoUnverified.Add(1) }
func (m *Metrics) incNarInfoRewritten()  { m.narInfoRewritten.Add(1) }
func (m *Metrics) incCacheInfoServed()   { m.cacheInfoServed.Add(1) }
