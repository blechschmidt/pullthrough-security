// Package backup implements consistent, integrity-verified backup and restore of
// the pull-through proxy's stateful data so an enterprise can meet its
// RPO/RTO objectives.
//
// A backup is a single, self-describing snapshot covering two classes of state:
//
//   - The content-addressable cache, read and rehydrated through the storage
//     -agnostic cache.Store interface, so a snapshot is taken (and restored)
//     identically whether the cache lives on the local filesystem or in an
//     S3-compatible object store.
//   - The sidecar metadata stores — the audit/Merkle transparency log, the
//     provenance link store, the commit-scan verdict store, VEX/policy bundles,
//     and any other durable on-disk state — modelled generically as a set of
//     named MetadataSource trees so new stores can be added without reworking
//     the snapshot format.
//
// The snapshot is an ordinary tar stream (optionally wrapped in a streaming
// AES-256-GCM envelope, see crypto.go) carrying a manifest first, then every
// cache blob, then every metadata file. The manifest is the integrity root: its
// canonical JSON encoding is hashed to a manifest digest that is transferred and
// verified out-of-band, and it additionally records the SHA-256 of every blob
// and file so corruption or tampering of any individual member is detected on
// restore. The layout is deterministic (members sorted, fixed tar mod-times) so
// an interrupted backup is safely re-runnable and a restore is idempotent.
//
// The tar framing makes the format air-gapped friendly: a backup can be streamed
// to a pipe, a tape, or removable media and restored by streaming back, never
// buffering a blob in memory.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

const (
	// SnapshotFormatVersion is the on-disk schema version of a backup manifest. A
	// restore refuses a snapshot whose version it does not understand, so an
	// operator can never silently rehydrate a format the binary cannot interpret.
	SnapshotFormatVersion = 1

	// manifestMember is the tar member holding the manifest. It is always written
	// first so a restore can read it, validate it, and then stream-verify every
	// subsequent member without buffering the whole archive.
	manifestMember = "pullthrough-backup.json"

	// cachePrefix and metaPrefix are the tar member directories for cache blobs
	// and metadata files respectively. Members are named by the hash of their
	// logical identity so the archive is free of path-significant characters and
	// immune to path-traversal via crafted names.
	cachePrefix = "cache/"
	metaPrefix  = "meta/"

	// generator labels the producing tool in the manifest, for auditability.
	generator = "pullthrough-backup"
)

// Manifest is the integrity root and schema/version header of a backup. Its
// canonical JSON encoding is hashed to produce the snapshot's manifest digest
// (see Digest); that digest is transferred out-of-band and verified on restore.
// Every cache entry and metadata file additionally carries the SHA-256 of its
// content, so member-level corruption is detected even without the out-of-band
// digest.
type Manifest struct {
	// FormatVersion is the schema version (SnapshotFormatVersion).
	FormatVersion int `json:"formatVersion"`
	// Generator identifies the producing tool.
	Generator string `json:"generator"`
	// AppVersion records the proxy build that produced the snapshot, for operator
	// traceability across upgrades. Informational; not enforced on restore.
	AppVersion string `json:"appVersion,omitempty"`
	// CreatedAt is when the snapshot was produced (UTC).
	CreatedAt time.Time `json:"createdAt"`
	// Encrypted records whether the snapshot payload was wrapped in an encryption
	// envelope. Informational: by the time this manifest is read the envelope has
	// already been removed. The envelope's own plaintext header is authoritative.
	Encrypted bool `json:"encrypted"`
	// CacheEntries describes every cached blob in the snapshot, sorted by key.
	CacheEntries []CacheEntry `json:"cacheEntries"`
	// MetadataSources describes each named sidecar store and its files, sorted by
	// source name then relative path.
	MetadataSources []MetadataSourceManifest `json:"metadataSources"`
	// TotalCacheBytes and TotalMetaBytes are the summed content sizes, for
	// operator reporting and capacity planning.
	TotalCacheBytes int64 `json:"totalCacheBytes"`
	TotalMetaBytes  int64 `json:"totalMetaBytes"`
}

// CacheEntry indexes one cached blob within a snapshot.
type CacheEntry struct {
	// Record is the authoritative cache metadata to restore (key, size, origin,
	// content-type, timestamps, pin/tenant metadata, etc.).
	Record cache.Record `json:"record"`
	// Digest is the "sha256:<hex>" content digest of the blob, verified on restore.
	Digest string `json:"digest"`
	// Member is the tar member path holding the content.
	Member string `json:"member"`
}

// MetadataSourceManifest describes one named sidecar metadata store and the files
// captured from it.
type MetadataSourceManifest struct {
	// Name is the logical, stable identifier of the source (e.g. "audit-log",
	// "provenance", "vex"). It maps a source in the snapshot back to a restore
	// target root supplied by the operator.
	Name string `json:"name"`
	// Kind classifies the source for documentation/diagnostics (e.g. "file" for a
	// single-file store, "tree" for a directory). Informational.
	Kind string `json:"kind"`
	// Files are the captured files, sorted by relative path.
	Files []MetadataFile `json:"files"`
}

// MetadataFile indexes one file captured from a metadata source.
type MetadataFile struct {
	// RelPath is the file's slash-separated path relative to the source root. It
	// is always a clean, non-rooted, traversal-free path.
	RelPath string `json:"relPath"`
	// Size is the file's byte length.
	Size int64 `json:"size"`
	// Mode is the file's permission bits, preserved across the round-trip.
	Mode uint32 `json:"mode"`
	// ModTime is the file's modification time, preserved for forensic continuity.
	ModTime time.Time `json:"modTime"`
	// Digest is the "sha256:<hex>" content digest, verified on restore.
	Digest string `json:"digest"`
	// Member is the tar member path holding the content.
	Member string `json:"member"`
}

// cacheBlobMember returns the deterministic tar member name for a cache key.
func cacheBlobMember(key string) string {
	sum := sha256.Sum256([]byte(key))
	return cachePrefix + hex.EncodeToString(sum[:])
}

// metaFileMember returns the deterministic tar member name for a metadata file,
// keyed by its source name and relative path so the mapping is exact and free of
// path-significant characters.
func metaFileMember(source, relPath string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + relPath))
	return metaPrefix + hex.EncodeToString(sum[:])
}

// sortManifest orders the manifest deterministically: cache entries by key,
// metadata sources by name and their files by relative path. Both the on-tar
// member order and the canonical digest depend on this ordering.
func (m *Manifest) sortManifest() {
	sort.Slice(m.CacheEntries, func(i, j int) bool {
		return m.CacheEntries[i].Record.Key < m.CacheEntries[j].Record.Key
	})
	sort.Slice(m.MetadataSources, func(i, j int) bool {
		return m.MetadataSources[i].Name < m.MetadataSources[j].Name
	})
	for si := range m.MetadataSources {
		files := m.MetadataSources[si].Files
		sort.Slice(files, func(i, j int) bool {
			return files[i].RelPath < files[j].RelPath
		})
	}
}

// canonicalJSON encodes the manifest deterministically. Go's json.Marshal emits
// struct fields in declaration order and map keys sorted, and the manifest is
// sorted first, so the byte output is stable for a given logical content.
func (m *Manifest) canonicalJSON() ([]byte, error) {
	m.sortManifest()
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("backup: encoding manifest: %w", err)
	}
	return data, nil
}

// Digest returns the "sha256:<hex>" digest of the manifest's canonical encoding.
// This is the snapshot's stable identity and integrity root.
func (m *Manifest) Digest() (string, error) {
	data, err := m.canonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
