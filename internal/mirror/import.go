package mirror

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
)

// ImportOptions configures a bundle import.
type ImportOptions struct {
	// Links is the optional provenance link store to populate from the bundle.
	// When nil, provenance links in the bundle are ignored.
	Links provenance.LinkStore
	// ExpectedManifestDigest, when non-empty, is the out-of-band "sha256:<hex>"
	// digest the bundle's manifest must match. Supplying it detects tampering of
	// the manifest itself; per-blob digests are always verified regardless.
	ExpectedManifestDigest string
	// Overwrite forces re-importing entries that already exist in the target
	// store. By default an entry whose key and size already match is skipped,
	// which makes a re-run of an interrupted import resume cheaply.
	Overwrite bool
	// Verdicts is the optional sink for the content-gate verdicts the bundle
	// carries (see ScanVerdict). Verdicts are handed to it only when
	// ExpectedManifestDigest was given and matched: a verdict is acted on by the
	// importing instance, so it is accepted only from a bundle whose manifest was
	// verified against a value obtained out of band. When nil, or when the
	// manifest was not verified, the bundle's verdicts are not imported, and the
	// importing instance decides about each artifact itself.
	Verdicts VerdictSink
}

// ImportResult summarizes a completed import.
type ImportResult struct {
	// ManifestDigest is the verified "sha256:<hex>" digest of the bundle manifest.
	ManifestDigest string
	// Imported is the number of cache blobs written to the target store.
	Imported int
	// Skipped is the number of cache blobs already present and left untouched.
	Skipped int
	// ProvenanceLinks is the number of provenance links written.
	ProvenanceLinks int
	// TotalBytes is the sum of imported blob sizes.
	TotalBytes int64
	// ScanVerdicts is the number of content-gate verdicts stored;
	// ScanVerdictsSkipped the number the sink left out (already present, or of a
	// gate it does not handle).
	ScanVerdicts        int
	ScanVerdictsSkipped int
	// ScanVerdictsUntrusted is the number of verdicts the bundle carries that
	// were NOT imported because its manifest digest was not verified
	// (ExpectedManifestDigest empty) or no sink was given.
	ScanVerdictsUntrusted int
}

// Importer loads a bundle into a content-addressable cache store (and optionally
// a provenance link store), verifying integrity as it goes.
type Importer struct {
	store cache.Store
}

// NewImporter constructs an importer that writes into the given cache store.
func NewImporter(store cache.Store) (*Importer, error) {
	if store == nil {
		return nil, errors.New("mirror: importer requires a cache store")
	}
	return &Importer{store: store}, nil
}

// Import reads a bundle from r and writes its contents into the target stores.
// The manifest member is read first; it is verified against
// ExpectedManifestDigest when provided. Each blob member is then streamed into
// the store while its content is hashed and checked against the digest recorded
// in the manifest — a mismatch aborts the import. Entries already present (same
// key and size) are skipped unless Overwrite is set, which makes the operation
// idempotent and safe to resume.
func (im *Importer) Import(ctx context.Context, r io.Reader, opts ImportOptions) (*ImportResult, error) {
	tr := tar.NewReader(r)

	manifest, err := readManifestMember(tr)
	if err != nil {
		return nil, err
	}
	if manifest.FormatVersion != BundleFormatVersion {
		return nil, fmt.Errorf("mirror: unsupported bundle format version %d (want %d)", manifest.FormatVersion, BundleFormatVersion)
	}

	actualDigest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}
	if want := opts.ExpectedManifestDigest; want != "" && want != actualDigest {
		return nil, fmt.Errorf("mirror: bundle manifest digest mismatch: got %s, want %s", actualDigest, want)
	}

	// Index the manifest by blob member so each archive member maps back to its
	// authoritative record and expected digest.
	byMember := make(map[string]CacheEntry, len(manifest.CacheEntries))
	for _, entry := range manifest.CacheEntries {
		byMember[entry.Blob] = entry
	}

	result := &ImportResult{ManifestDigest: actualDigest}
	seen := make(map[string]bool, len(byMember))

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("mirror: reading bundle: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		entry, ok := byMember[hdr.Name]
		if !ok {
			return nil, fmt.Errorf("mirror: bundle contains unexpected member %q not present in the manifest", hdr.Name)
		}
		seen[hdr.Name] = true

		imported, err := im.importEntry(ctx, tr, entry, opts.Overwrite)
		if err != nil {
			return nil, err
		}
		if imported {
			result.Imported++
			result.TotalBytes += entry.Record.Size
		} else {
			result.Skipped++
		}
	}

	// Every cache entry named in the manifest must have appeared in the archive;
	// a missing member means a truncated or malformed bundle.
	if len(seen) != len(byMember) {
		return nil, fmt.Errorf("mirror: bundle is incomplete: manifest declares %d cache blobs but %d were present", len(byMember), len(seen))
	}

	links, err := im.importLinks(ctx, manifest, opts.Links)
	if err != nil {
		return nil, err
	}
	result.ProvenanceLinks = links

	if err := im.importVerdicts(ctx, manifest, opts, result); err != nil {
		return nil, err
	}

	return result, nil
}

// importVerdicts hands the bundle's content-gate verdicts to the sink — but
// only from a bundle whose manifest was verified against an out-of-band digest,
// and only verdicts about a blob the bundle itself carries.
//
// It runs last, after every blob has been written and verified: a verdict is
// never stored for content that did not arrive.
func (im *Importer) importVerdicts(ctx context.Context, manifest *BundleManifest, opts ImportOptions, result *ImportResult) error {
	if len(manifest.ScanVerdicts) == 0 {
		return nil
	}
	if opts.Verdicts == nil || opts.ExpectedManifestDigest == "" {
		result.ScanVerdictsUntrusted = len(manifest.ScanVerdicts)
		return nil
	}
	carried := make(map[string]bool, len(manifest.CacheEntries))
	for _, entry := range manifest.CacheEntries {
		carried[entry.Digest] = true
	}
	for _, v := range manifest.ScanVerdicts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !carried[v.Digest] {
			return fmt.Errorf("mirror: bundle carries a %s verdict for %s, which is not the digest of any blob in it", v.Gate, v.Digest)
		}
		imported, err := opts.Verdicts.ImportVerdict(ctx, v)
		if err != nil {
			return fmt.Errorf("mirror: importing %s verdict for %s: %w", v.Gate, v.Digest, err)
		}
		if imported {
			result.ScanVerdicts++
		} else {
			result.ScanVerdictsSkipped++
		}
	}
	return nil
}

// importEntry streams one blob member into the store, verifying its digest. It
// returns whether the entry was written (false means it was skipped because an
// identical entry already exists).
func (im *Importer) importEntry(ctx context.Context, tr *tar.Reader, entry CacheEntry, overwrite bool) (bool, error) {
	if !overwrite {
		if existing, err := im.store.Stat(ctx, entry.Record.Key); err == nil && existing.Size == entry.Record.Size {
			// Already present at the expected size; drain the member and skip.
			if _, derr := io.Copy(io.Discard, tr); derr != nil {
				return false, fmt.Errorf("mirror: skipping existing blob %q: %w", entry.Record.Key, derr)
			}
			return false, nil
		} else if err != nil && !errors.Is(err, cache.ErrNotFound) {
			return false, fmt.Errorf("mirror: stating target for %q: %w", entry.Record.Key, err)
		}
	}

	// Tee the content through a hasher so the digest is verified as the bytes are
	// written, without a second pass over the (potentially large) blob.
	h := sha256.New()
	stored, err := im.store.Put(ctx, entry.Record, io.TeeReader(tr, h))
	if err != nil {
		return false, fmt.Errorf("mirror: writing blob %q: %w", entry.Record.Key, err)
	}

	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != entry.Digest {
		// The bytes did not match the manifest's digest: this is tampering or
		// corruption. Remove the just-written entry so a partial/poisoned blob is
		// never left behind, then fail loudly.
		_ = im.store.Delete(ctx, entry.Record.Key)
		return false, fmt.Errorf("mirror: blob %q failed integrity check: got %s, want %s", entry.Record.Key, got, entry.Digest)
	}
	if stored.Size != entry.Record.Size {
		_ = im.store.Delete(ctx, entry.Record.Key)
		return false, fmt.Errorf("mirror: blob %q size mismatch: got %d, want %d", entry.Record.Key, stored.Size, entry.Record.Size)
	}
	return true, nil
}

// importLinks writes the bundle's provenance links into the link store when one
// is provided.
func (im *Importer) importLinks(ctx context.Context, manifest *BundleManifest, store provenance.LinkStore) (int, error) {
	if store == nil || len(manifest.ProvenanceLinks) == 0 {
		return 0, nil
	}
	count := 0
	for _, link := range manifest.ProvenanceLinks {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if link == nil {
			continue
		}
		if err := store.Put(ctx, link); err != nil {
			return count, fmt.Errorf("mirror: writing provenance link for %s/%s@%s: %w",
				link.Artifact.Ecosystem, link.Artifact.Name, link.Artifact.Version, err)
		}
		count++
	}
	return count, nil
}

// readManifestMember reads and decodes the first archive member, which must be
// the bundle manifest.
func readManifestMember(tr *tar.Reader) (*BundleManifest, error) {
	hdr, err := tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("mirror: bundle is empty")
	}
	if err != nil {
		return nil, fmt.Errorf("mirror: reading bundle: %w", err)
	}
	if hdr.Name != manifestMember {
		return nil, fmt.Errorf("mirror: first bundle member is %q, expected %q (not a pullthrough bundle?)", hdr.Name, manifestMember)
	}

	var manifest BundleManifest
	if err := json.NewDecoder(tr).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("mirror: decoding bundle manifest: %w", err)
	}
	return &manifest, nil
}
