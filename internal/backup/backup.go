package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// fixedModTime is the tar header modification time stamped on every member so a
// snapshot's bytes are reproducible for identical content (the manifest's
// CreatedAt is the only intended source of variation). File mod-times are
// preserved separately in the manifest, not in the tar header.
var fixedModTime = time.Unix(0, 0).UTC()

// Options configures a backup.
type Options struct {
	// Cache is the content-addressable cache store to snapshot. Required: a
	// backup without the cache is not a meaningful disaster-recovery artifact, but
	// an empty store is fine.
	Cache cache.Store
	// Sources are the named sidecar metadata stores to capture.
	Sources []MetadataSource
	// CreatedAt stamps the manifest. When zero, the backuper's clock (time.Now) is
	// used; tests pass a fixed value for byte-reproducible output.
	CreatedAt time.Time
	// AppVersion records the producing proxy build in the manifest (informational).
	AppVersion string
	// Encryption, when set, wraps the snapshot in a streaming AES-256-GCM envelope.
	Encryption EncryptionKey
}

// Result summarizes a completed backup.
type Result struct {
	// ManifestDigest is the "sha256:<hex>" digest of the manifest, to be
	// transferred out-of-band and verified on restore.
	ManifestDigest string
	// CacheEntries is the number of cache blobs written.
	CacheEntries int
	// MetadataFiles is the number of metadata files written.
	MetadataFiles int
	// TotalCacheBytes and TotalMetaBytes are the summed content sizes written.
	TotalCacheBytes int64
	TotalMetaBytes  int64
	// Encrypted reports whether the snapshot was encrypted.
	Encrypted bool
}

// Backuper produces consistent snapshots of the cache and metadata stores.
type Backuper struct {
	now func() time.Time
}

// NewBackuper constructs a Backuper.
func NewBackuper() *Backuper { return &Backuper{now: time.Now} }

// Backup writes a snapshot to w. It performs two passes so the manifest can be
// written first (enabling stream-verification on restore): the first hashes every
// cache blob and metadata file to build the manifest; the second streams the
// content in the same deterministic order. Content is never buffered in memory,
// so arbitrarily large caches and stores snapshot in bounded memory.
//
// When Options.Encryption is set, the entire tar stream is wrapped in a streaming
// AEAD envelope; the manifest digest returned is computed over the (plaintext)
// manifest and is what an operator verifies on restore.
func (b *Backuper) Backup(ctx context.Context, w io.Writer, opts Options) (*Result, error) {
	if opts.Cache == nil {
		return nil, errors.New("backup: a cache store is required")
	}
	if err := validateSources(opts.Sources); err != nil {
		return nil, err
	}

	manifest, scans, err := b.buildManifest(ctx, opts)
	if err != nil {
		return nil, err
	}
	digest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}

	// Optionally wrap the output in the encryption envelope. The envelope writer
	// must be Closed to flush its final authenticated frame.
	out := w
	var encCloser io.WriteCloser
	if opts.Encryption.IsSet() {
		ew, eerr := newEncryptingWriter(w, opts.Encryption)
		if eerr != nil {
			return nil, eerr
		}
		encCloser = ew
		out = ew
		manifest.Encrypted = true
		// Re-derive the digest: Encrypted is now set, so the manifest bytes differ.
		digest, err = manifest.Digest()
		if err != nil {
			return nil, err
		}
	}

	tw := tar.NewWriter(out)
	canonical, err := manifest.canonicalJSON()
	if err != nil {
		return nil, err
	}
	if err := writeTarMember(tw, manifestMember, canonical); err != nil {
		return nil, fmt.Errorf("backup: writing manifest member: %w", err)
	}

	if err := b.writeCacheBlobs(ctx, tw, opts.Cache, manifest.CacheEntries); err != nil {
		return nil, err
	}
	if err := writeMetadataFiles(ctx, tw, manifest.MetadataSources, scans); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("backup: finalizing snapshot: %w", err)
	}
	if encCloser != nil {
		if err := encCloser.Close(); err != nil {
			return nil, fmt.Errorf("backup: finalizing encryption envelope: %w", err)
		}
	}

	return &Result{
		ManifestDigest:  digest,
		CacheEntries:    len(manifest.CacheEntries),
		MetadataFiles:   countFiles(manifest.MetadataSources),
		TotalCacheBytes: manifest.TotalCacheBytes,
		TotalMetaBytes:  manifest.TotalMetaBytes,
		Encrypted:       manifest.Encrypted,
	}, nil
}

// scanIndex maps a metadata member name to the absolute file path to stream from,
// captured during the first (manifest-building) pass.
type scanIndex map[string]string

// buildManifest performs the first pass: it hashes every cache blob and metadata
// file, assembling the sorted manifest and the index used by the streaming pass.
func (b *Backuper) buildManifest(ctx context.Context, opts Options) (*Manifest, scanIndex, error) {
	createdAt := opts.CreatedAt
	if createdAt.IsZero() {
		createdAt = b.now().UTC()
	}
	manifest := &Manifest{
		FormatVersion: SnapshotFormatVersion,
		Generator:     generator,
		AppVersion:    opts.AppVersion,
		CreatedAt:     createdAt,
	}

	records, err := opts.Cache.List(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: listing cache store: %w", err)
	}
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		digest, size, herr := hashCacheBlob(ctx, opts.Cache, rec.Key)
		if herr != nil {
			return nil, nil, herr
		}
		rec.Size = size // trust the size observed while hashing
		manifest.CacheEntries = append(manifest.CacheEntries, CacheEntry{
			Record: rec,
			Digest: digest,
			Member: cacheBlobMember(rec.Key),
		})
		manifest.TotalCacheBytes += size
	}

	scans := make(scanIndex)
	for _, src := range opts.Sources {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		kind, files, serr := scanSource(src)
		if serr != nil {
			return nil, nil, serr
		}
		sm := MetadataSourceManifest{Name: src.Name, Kind: kind}
		for _, f := range files {
			digest, err := hashFile(f.absPath)
			if err != nil {
				return nil, nil, fmt.Errorf("backup: hashing %s/%s: %w", src.Name, f.relPath, err)
			}
			member := metaFileMember(src.Name, f.relPath)
			fi, ferr := os.Stat(f.absPath)
			if ferr != nil {
				return nil, nil, fmt.Errorf("backup: stating %s/%s: %w", src.Name, f.relPath, ferr)
			}
			sm.Files = append(sm.Files, MetadataFile{
				RelPath: f.relPath,
				Size:    fi.Size(),
				Mode:    uint32(f.mode),
				ModTime: fi.ModTime().UTC(),
				Digest:  digest,
				Member:  member,
			})
			scans[member] = f.absPath
			manifest.TotalMetaBytes += fi.Size()
		}
		manifest.MetadataSources = append(manifest.MetadataSources, sm)
	}

	manifest.sortManifest()
	return manifest, scans, nil
}

// writeCacheBlobs streams each cache blob into the archive, re-verifying its
// digest as it copies to guard against the store mutating between passes.
func (b *Backuper) writeCacheBlobs(ctx context.Context, tw *tar.Writer, store cache.Store, entries []CacheEntry) error {
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		rc, _, err := store.Get(ctx, entry.Record.Key)
		if err != nil {
			return fmt.Errorf("backup: reading blob %q: %w", entry.Record.Key, err)
		}
		err = streamMember(tw, entry.Member, entry.Record.Size, 0o600, rc, entry.Digest, entry.Record.Key)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// writeMetadataFiles streams each metadata file into the archive in manifest
// order, re-verifying digests.
func writeMetadataFiles(ctx context.Context, tw *tar.Writer, sources []MetadataSourceManifest, scans scanIndex) error {
	for _, src := range sources {
		for _, f := range src.Files {
			if err := ctx.Err(); err != nil {
				return err
			}
			absPath, ok := scans[f.Member]
			if !ok {
				return fmt.Errorf("backup: internal error: no source path for %s/%s", src.Name, f.RelPath)
			}
			file, err := os.Open(absPath)
			if err != nil {
				return fmt.Errorf("backup: opening %s/%s: %w", src.Name, f.RelPath, err)
			}
			err = streamMember(tw, f.Member, f.Size, 0o600, file, f.Digest, src.Name+"/"+f.RelPath)
			file.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// streamMember writes one tar member, copying content through a hasher and
// failing loudly if the byte count or digest disagrees with the manifest.
func streamMember(tw *tar.Writer, name string, size int64, mode int64, r io.Reader, wantDigest, label string) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     size,
		ModTime:  fixedModTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: writing header for %q: %w", label, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), r)
	if err != nil {
		return fmt.Errorf("backup: streaming %q: %w", label, err)
	}
	if n != size {
		return fmt.Errorf("backup: %q changed size during backup (%d != %d)", label, n, size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != wantDigest {
		return fmt.Errorf("backup: %q changed content during backup (%s != %s)", label, got, wantDigest)
	}
	return nil
}

// hashCacheBlob streams a stored blob through SHA-256, returning its digest and
// byte length without retaining the content.
func hashCacheBlob(ctx context.Context, store cache.Store, key string) (digest string, size int64, err error) {
	rc, _, err := store.Get(ctx, key)
	if err != nil {
		return "", 0, fmt.Errorf("backup: reading blob %q: %w", key, err)
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, rc)
	if err != nil {
		return "", 0, fmt.Errorf("backup: hashing blob %q: %w", key, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// hashFile streams a file through SHA-256.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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

// countFiles totals the files across all sources.
func countFiles(sources []MetadataSourceManifest) int {
	n := 0
	for _, s := range sources {
		n += len(s.Files)
	}
	return n
}
