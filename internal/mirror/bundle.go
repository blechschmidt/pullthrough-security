// Package mirror provides operational tooling for disconnected ("air-gapped")
// and enterprise deployments of the pull-through proxy. It implements three
// workflows on top of the existing content-addressable cache and provenance
// stores:
//
//   - Pre-warming: populate a cache from a declarative manifest of packages and
//     images before the instance is sealed (see Warmer).
//   - Export: serialize the cache (content blobs + metadata) and the provenance
//     links into a portable, integrity-verified bundle (see Exporter).
//   - Import: load such a bundle into an air-gapped instance, verifying every
//     blob against its recorded digest and (optionally) the whole bundle against
//     an out-of-band manifest digest (see Importer).
//
// The bundle is an ordinary tar archive so it can be inspected, transported, and
// resumed with standard tools. Its layout is deterministic: given the same store
// contents and creation timestamp the same bytes are produced, which makes
// transfers idempotent and re-runnable.
package mirror

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
)

const (
	// BundleFormatVersion is the on-disk schema version of a bundle manifest.
	// Importers refuse a bundle whose version they do not understand.
	BundleFormatVersion = 1

	// manifestMember is the tar member holding the bundle manifest. It is always
	// written first so an importer can stream-verify subsequent blob members
	// without buffering the whole archive.
	manifestMember = "pullthrough-bundle.json"

	// blobPrefix is the tar member directory holding content blobs. Each blob is
	// named "<blobPrefix><sha256-of-cache-key>" so the mapping from member to
	// cache entry is exact and free of path-significant characters.
	blobPrefix = "blobs/"

	// generator labels the producing tool in the manifest, for auditability.
	generator = "pullthrough-mirror"
)

// BundleManifest is the integrity root of a bundle. Its canonical JSON encoding
// is hashed to produce the bundle's manifest digest (see Digest); that digest is
// what an operator transfers out-of-band and an importer verifies against. Each
// cache entry additionally carries the content digest of its blob, so any blob
// tampering is detected even without the out-of-band digest.
type BundleManifest struct {
	// FormatVersion is the schema version (BundleFormatVersion).
	FormatVersion int `json:"formatVersion"`
	// Generator identifies the producing tool.
	Generator string `json:"generator"`
	// CreatedAt is when the bundle was produced.
	CreatedAt time.Time `json:"createdAt"`
	// CacheEntries describes every cached blob in the bundle, sorted by cache key
	// for deterministic ordering.
	CacheEntries []CacheEntry `json:"cacheEntries"`
	// ProvenanceLinks carries the exported package->commit associations, sorted by
	// artifact coordinate. Links are small structured records and are embedded in
	// the manifest rather than stored as separate blobs.
	ProvenanceLinks []*provenance.Link `json:"provenanceLinks,omitempty"`
	// TotalBlobBytes is the sum of all cache blob sizes, for operator reporting.
	TotalBlobBytes int64 `json:"totalBlobBytes"`
}

// CacheEntry indexes one cached blob within a bundle.
type CacheEntry struct {
	// Record is the authoritative cache metadata to restore on import (key, size,
	// origin, content-type, timestamps, and any extra metadata).
	Record cache.Record `json:"record"`
	// Digest is the "sha256:<hex>" content digest of the blob, verified on import.
	Digest string `json:"digest"`
	// Blob is the tar member path holding the content.
	Blob string `json:"blob"`
}

// blobMember returns the deterministic tar member name for a cache key.
func blobMember(key string) string {
	sum := sha256.Sum256([]byte(key))
	return blobPrefix + hex.EncodeToString(sum[:])
}

// sortManifest orders the manifest's entries deterministically: cache entries by
// key, provenance links by artifact coordinate. Both the on-tar member order and
// the canonical digest depend on this ordering.
func (m *BundleManifest) sortManifest() {
	sort.Slice(m.CacheEntries, func(i, j int) bool {
		return m.CacheEntries[i].Record.Key < m.CacheEntries[j].Record.Key
	})
	sort.Slice(m.ProvenanceLinks, func(i, j int) bool {
		a, b := m.ProvenanceLinks[i].Artifact, m.ProvenanceLinks[j].Artifact
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Digest < b.Digest
	})
}

// canonicalJSON encodes the manifest deterministically: Go's json.Marshal emits
// struct fields in declaration order and map keys sorted, and the manifest is
// sorted first, so the byte output is stable for a given logical content.
func (m *BundleManifest) canonicalJSON() ([]byte, error) {
	m.sortManifest()
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("mirror: encoding bundle manifest: %w", err)
	}
	return data, nil
}

// Digest returns the "sha256:<hex>" digest of the manifest's canonical encoding.
// This is the bundle's stable identity and integrity root.
func (m *BundleManifest) Digest() (string, error) {
	data, err := m.canonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
