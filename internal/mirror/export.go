package mirror

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
)

// fixedModTime is the tar header modification time stamped on every member.
// Holding it constant keeps a bundle's bytes reproducible for identical content
// (the manifest's CreatedAt is the only intended source of variation), which is
// what makes a re-run of an interrupted export resumable by restart.
var fixedModTime = time.Unix(0, 0).UTC()

// ExportOptions configures a bundle export.
type ExportOptions struct {
	// Links is the optional provenance link store to include. When nil, the
	// bundle carries cache content only.
	Links provenance.LinkStore
	// CreatedAt stamps the manifest. When zero, the caller-supplied clock (or
	// time.Now) is used; tests pass a fixed value for byte-reproducible output.
	CreatedAt time.Time
	// Verdicts is the optional source of content-gate verdicts to carry for the
	// bundle's blobs (see ScanVerdict). When nil the bundle carries none.
	Verdicts VerdictSource
}

// ExportResult summarizes a completed export.
type ExportResult struct {
	// ManifestDigest is the "sha256:<hex>" digest of the bundle manifest, to be
	// transferred out-of-band and verified on import.
	ManifestDigest string
	// CacheEntries is the number of cache blobs written.
	CacheEntries int
	// ProvenanceLinks is the number of links written.
	ProvenanceLinks int
	// TotalBlobBytes is the sum of cache blob sizes written.
	TotalBlobBytes int64
	// ScanVerdicts is the number of content-gate verdicts carried.
	ScanVerdicts int
}

// Exporter serializes a content-addressable cache store (and optionally a
// provenance link store) into an integrity-verified bundle.
type Exporter struct {
	store cache.Store
	now   func() time.Time
}

// NewExporter constructs an exporter over the given cache store. The store is
// read but never modified.
func NewExporter(store cache.Store) (*Exporter, error) {
	if store == nil {
		return nil, errors.New("mirror: exporter requires a cache store")
	}
	return &Exporter{store: store, now: time.Now}, nil
}

// Export writes a bundle to w. It performs two passes over the cache store: the
// first computes each blob's content digest to build the manifest (written
// first, so the archive stream-verifies on import); the second streams the blob
// bytes into the archive in the same deterministic order. Blobs are never held
// in memory, so arbitrarily large caches export in bounded memory.
func (e *Exporter) Export(ctx context.Context, w io.Writer, opts ExportOptions) (*ExportResult, error) {
	manifest, err := e.buildManifest(ctx, opts)
	if err != nil {
		return nil, err
	}

	digest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(w)
	canonical, err := manifest.canonicalJSON()
	if err != nil {
		return nil, err
	}
	if err := writeTarMember(tw, manifestMember, canonical); err != nil {
		return nil, fmt.Errorf("mirror: writing manifest member: %w", err)
	}

	for _, entry := range manifest.CacheEntries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := e.writeBlobMember(ctx, tw, entry); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("mirror: finalizing bundle: %w", err)
	}

	return &ExportResult{
		ManifestDigest:  digest,
		CacheEntries:    len(manifest.CacheEntries),
		ProvenanceLinks: len(manifest.ProvenanceLinks),
		TotalBlobBytes:  manifest.TotalBlobBytes,
		ScanVerdicts:    len(manifest.ScanVerdicts),
	}, nil
}

// buildManifest performs the first pass: it lists every stored record, hashes
// each blob's content to obtain its digest, and assembles the (sorted) manifest.
func (e *Exporter) buildManifest(ctx context.Context, opts ExportOptions) (*BundleManifest, error) {
	records, err := e.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("mirror: listing cache store: %w", err)
	}

	createdAt := opts.CreatedAt
	if createdAt.IsZero() {
		createdAt = e.now().UTC()
	}

	manifest := &BundleManifest{
		FormatVersion: BundleFormatVersion,
		Generator:     generator,
		CreatedAt:     createdAt,
	}

	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		digest, size, err := e.hashBlob(ctx, rec.Key)
		if err != nil {
			return nil, err
		}
		// Trust the size observed while hashing; reconcile the record so the
		// manifest and the bytes that follow it cannot disagree.
		rec.Size = size
		manifest.CacheEntries = append(manifest.CacheEntries, CacheEntry{
			Record: rec,
			Digest: digest,
			Blob:   blobMember(rec.Key),
		})
		manifest.TotalBlobBytes += size
	}

	if opts.Links != nil {
		links, err := opts.Links.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("mirror: listing provenance links: %w", err)
		}
		manifest.ProvenanceLinks = links
	}

	if opts.Verdicts != nil && len(manifest.CacheEntries) > 0 {
		// Only verdicts about bytes that are in the bundle travel with it: a
		// verdict is carried with the content it is about, never on its own.
		digests := make(map[string]bool, len(manifest.CacheEntries))
		for _, entry := range manifest.CacheEntries {
			digests[entry.Digest] = true
		}
		verdicts, err := opts.Verdicts.ExportVerdicts(ctx, digests)
		if err != nil {
			return nil, fmt.Errorf("mirror: collecting scan verdicts: %w", err)
		}
		for _, v := range verdicts {
			if !digests[v.Digest] || v.Gate == "" || len(v.Record) == 0 {
				continue
			}
			manifest.ScanVerdicts = append(manifest.ScanVerdicts, v)
		}
	}

	manifest.sortManifest()
	return manifest, nil
}

// hashBlob streams a stored blob through a SHA-256 hasher, returning its digest
// and byte length without retaining the content.
func (e *Exporter) hashBlob(ctx context.Context, key string) (digest string, size int64, err error) {
	rc, _, err := e.store.Get(ctx, key)
	if err != nil {
		return "", 0, fmt.Errorf("mirror: reading blob %q: %w", key, err)
	}
	defer rc.Close()

	h := sha256.New()
	n, err := io.Copy(h, rc)
	if err != nil {
		return "", 0, fmt.Errorf("mirror: hashing blob %q: %w", key, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// writeBlobMember streams one blob into the archive, re-verifying its digest as
// it copies to guard against the (rare) case of the store mutating between the
// two passes.
func (e *Exporter) writeBlobMember(ctx context.Context, tw *tar.Writer, entry CacheEntry) error {
	rc, _, err := e.store.Get(ctx, entry.Record.Key)
	if err != nil {
		return fmt.Errorf("mirror: reading blob %q: %w", entry.Record.Key, err)
	}
	defer rc.Close()

	hdr := &tar.Header{
		Name:     entry.Blob,
		Mode:     0o600,
		Size:     entry.Record.Size,
		ModTime:  fixedModTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("mirror: writing blob header %q: %w", entry.Record.Key, err)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), rc)
	if err != nil {
		return fmt.Errorf("mirror: streaming blob %q: %w", entry.Record.Key, err)
	}
	if n != entry.Record.Size {
		return fmt.Errorf("mirror: blob %q changed size during export (%d != %d)", entry.Record.Key, n, entry.Record.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != entry.Digest {
		return fmt.Errorf("mirror: blob %q changed content during export (%s != %s)", entry.Record.Key, got, entry.Digest)
	}
	return nil
}

// writeTarMember writes a complete in-memory member (used for the manifest).
func writeTarMember(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(data)),
		ModTime:  fixedModTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
