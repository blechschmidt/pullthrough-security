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
	"context"
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
	// ScanVerdicts carries the content-gate verdicts on record for the bundle's
	// blobs (see ScanVerdict), sorted by gate and digest. Omitted when there are
	// none, so a bundle without verdicts is byte-identical to one written before
	// they existed and the format version is unchanged.
	ScanVerdicts []ScanVerdict `json:"scanVerdicts,omitempty"`
	// Releases carries the release manifests of the repository registry
	// (Task 180), sorted by repository and commit, and PinnedKeys the cache
	// keys they pin that the bundle holds. An instance importing the bundle
	// stores the manifests, which pins the same objects there. Omitted when
	// there are none, so older bundles are unchanged.
	Releases   []ReleaseRecord `json:"releases,omitempty"`
	PinnedKeys []string        `json:"pinnedKeys,omitempty"`
}

// ReleaseRecord is one release manifest travelling with a bundle.
type ReleaseRecord struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	// Manifest is the registry's own encoding of the manifest; opaque here.
	Manifest json.RawMessage `json:"manifest"`
}

// ReleaseSource yields the release manifests to carry in a bundle and the
// cache keys they pin.
type ReleaseSource interface {
	ExportReleases(ctx context.Context) ([]ReleaseRecord, []string, error)
}

// ReleaseSink stores the release manifests of an imported bundle.
type ReleaseSink interface {
	// ImportRelease validates one manifest and stores it; imported is false
	// when the instance already holds a manifest of that release.
	ImportRelease(ctx context.Context, r ReleaseRecord) (imported bool, err error)
}

// ScanVerdict is one content-gate verdict travelling with a bundle: which gate
// reached it, the content digest of the bytes it is about, and the gate's own
// record of it.
//
// A verdict is what lets an air-gapped instance enforce a decision it cannot
// reach for itself: the LLM package scan needs a provider, and behind an air
// gap there is none. Carried in the bundle, a "malicious" verdict reached on
// the connected side is refused on the disconnected one, and a clean one is
// served without the scan that could not run.
//
// That makes a verdict a statement the importer acts on, so it is only as good
// as the bundle's provenance: Import hands verdicts to the sink only when the
// bundle's manifest digest was verified against a value obtained out of band
// (ImportOptions.ExpectedManifestDigest). The per-blob digests alone prove that
// the blobs match the manifest — not that the manifest is the one the exporting
// instance wrote.
type ScanVerdict struct {
	// Gate names the gate whose verdict this is (e.g. "llmpkgscan").
	Gate string `json:"gate"`
	// Digest is the "sha256:<hex>" content digest the verdict is about.
	Digest string `json:"digest"`
	// Record is the gate's own encoding of the verdict; it is opaque here.
	Record json.RawMessage `json:"record"`
}

// VerdictSource yields the verdicts to carry in a bundle.
type VerdictSource interface {
	// ExportVerdicts returns the verdicts on record for the artifacts whose
	// content digest ("sha256:<hex>") is in digests.
	ExportVerdicts(ctx context.Context, digests map[string]bool) ([]ScanVerdict, error)
}

// VerdictSink receives the verdicts of an imported bundle.
type VerdictSink interface {
	// ImportVerdict validates one verdict and stores it. imported is false when
	// it was left out for a reason that is not an error (the sink already holds
	// a verdict for it, or it is for another gate).
	ImportVerdict(ctx context.Context, v ScanVerdict) (imported bool, err error)
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
	sort.Slice(m.Releases, func(i, j int) bool {
		a, b := m.Releases[i], m.Releases[j]
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		return a.Commit < b.Commit
	})
	sort.Strings(m.PinnedKeys)
	sort.Slice(m.ScanVerdicts, func(i, j int) bool {
		a, b := m.ScanVerdicts[i], m.ScanVerdicts[j]
		if a.Gate != b.Gate {
			return a.Gate < b.Gate
		}
		if a.Digest != b.Digest {
			return a.Digest < b.Digest
		}
		return string(a.Record) < string(b.Record)
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
