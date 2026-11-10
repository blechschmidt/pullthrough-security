package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// RestoreOptions configures a restore.
type RestoreOptions struct {
	// Cache is the target cache store to rehydrate. Required.
	Cache cache.Store
	// Targets maps a metadata source name (as recorded in the manifest) to the
	// directory root the source's files are restored under. A source present in
	// the snapshot but absent from this map is skipped (and reported), so an
	// operator can selectively restore subsets of state.
	Targets map[string]string
	// ExpectedManifestDigest, when non-empty, is the out-of-band "sha256:<hex>"
	// digest the snapshot's manifest must match. Supplying it detects tampering of
	// the manifest itself; per-member digests are always verified regardless.
	ExpectedManifestDigest string
	// Encryption supplies the secret for an encrypted snapshot. It is required iff
	// the snapshot was encrypted; the magic preamble is detected automatically.
	Encryption EncryptionKey
	// Overwrite forces re-writing cache entries and metadata files that already
	// exist. By default an identical-size cache entry is skipped and an existing
	// metadata file is overwritten only when its content differs, which makes a
	// re-run of an interrupted restore resume cheaply.
	Overwrite bool
}

// RestoreResult summarizes a completed restore.
type RestoreResult struct {
	// ManifestDigest is the verified "sha256:<hex>" digest of the manifest.
	ManifestDigest string
	// CreatedAt is the snapshot's creation time, from the manifest.
	CreatedAt string
	// CacheImported and CacheSkipped count rehydrated and already-present blobs.
	CacheImported int
	CacheSkipped  int
	// MetadataWritten and MetadataSkipped count restored metadata files and those
	// whose source had no configured target (skipped).
	MetadataWritten int
	MetadataSkipped int
	// TotalBytes is the sum of restored content sizes.
	TotalBytes int64
	// Encrypted reports whether the snapshot was encrypted.
	Encrypted bool
}

// Restorer rehydrates a snapshot into a target deployment, verifying integrity.
type Restorer struct{}

// NewRestorer constructs a Restorer.
func NewRestorer() *Restorer { return &Restorer{} }

// Restore reads a snapshot from r and rehydrates its contents. The manifest is
// read first and validated (format version, optional out-of-band digest). Each
// member is then streamed into the cache store or onto disk while its content is
// hashed and checked against the manifest's digest — any mismatch aborts the
// restore and removes the partially-written member, so a corrupt or tampered
// snapshot never partially lands. The whole-archive completeness is checked at
// the end: every member the manifest declares must have appeared.
func (rs *Restorer) Restore(ctx context.Context, r io.Reader, opts RestoreOptions) (*RestoreResult, error) {
	if opts.Cache == nil {
		return nil, errors.New("backup: a target cache store is required")
	}

	// Peek the magic to decide whether to wrap r in a decrypting reader. We buffer
	// the first bytes and prepend them back so detection is transparent.
	src, encrypted, err := maybeDecrypt(r, opts.Encryption)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(src)
	manifest, err := readManifestMember(tr)
	if err != nil {
		return nil, err
	}
	if manifest.FormatVersion != SnapshotFormatVersion {
		return nil, fmt.Errorf("backup: unsupported snapshot format version %d (want %d)", manifest.FormatVersion, SnapshotFormatVersion)
	}

	actualDigest, err := manifest.Digest()
	if err != nil {
		return nil, err
	}
	if want := opts.ExpectedManifestDigest; want != "" && want != actualDigest {
		return nil, fmt.Errorf("backup: manifest digest mismatch: got %s, want %s", actualDigest, want)
	}

	// Index every declared member so each archive member maps back to its
	// authoritative record/file metadata, and unknown members are rejected.
	cacheByMember := make(map[string]CacheEntry, len(manifest.CacheEntries))
	for _, e := range manifest.CacheEntries {
		cacheByMember[e.Member] = e
	}
	type metaTarget struct {
		source string
		file   MetadataFile
	}
	metaByMember := make(map[string]metaTarget)
	for _, s := range manifest.MetadataSources {
		for _, f := range s.Files {
			metaByMember[f.Member] = metaTarget{source: s.Name, file: f}
		}
	}

	result := &RestoreResult{
		ManifestDigest: actualDigest,
		CreatedAt:      manifest.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Encrypted:      encrypted,
	}
	seen := make(map[string]bool, len(cacheByMember)+len(metaByMember))

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: reading snapshot: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if entry, ok := cacheByMember[hdr.Name]; ok {
			seen[hdr.Name] = true
			imported, ierr := restoreCacheEntry(ctx, opts.Cache, tr, entry, opts.Overwrite)
			if ierr != nil {
				return nil, ierr
			}
			if imported {
				result.CacheImported++
				result.TotalBytes += entry.Record.Size
			} else {
				result.CacheSkipped++
			}
			continue
		}
		if mt, ok := metaByMember[hdr.Name]; ok {
			seen[hdr.Name] = true
			written, n, merr := restoreMetadataFile(ctx, tr, mt.source, mt.file, opts)
			if merr != nil {
				return nil, merr
			}
			if written {
				result.MetadataWritten++
				result.TotalBytes += n
			} else {
				result.MetadataSkipped++
			}
			continue
		}
		return nil, fmt.Errorf("backup: snapshot contains unexpected member %q not present in the manifest", hdr.Name)
	}

	want := len(cacheByMember) + len(metaByMember)
	if len(seen) != want {
		return nil, fmt.Errorf("backup: snapshot is incomplete: manifest declares %d members but %d were present", want, len(seen))
	}
	return result, nil
}

// restoreCacheEntry streams one blob member into the cache store, verifying its
// digest. It returns whether the entry was written (false means skipped).
func restoreCacheEntry(ctx context.Context, store cache.Store, tr *tar.Reader, entry CacheEntry, overwrite bool) (bool, error) {
	if !overwrite {
		if existing, err := store.Stat(ctx, entry.Record.Key); err == nil && existing.Size == entry.Record.Size {
			if _, derr := io.Copy(io.Discard, tr); derr != nil {
				return false, fmt.Errorf("backup: skipping existing blob %q: %w", entry.Record.Key, derr)
			}
			return false, nil
		} else if err != nil && !errors.Is(err, cache.ErrNotFound) {
			return false, fmt.Errorf("backup: stating target for %q: %w", entry.Record.Key, err)
		}
	}

	h := sha256.New()
	stored, err := store.Put(ctx, entry.Record, io.TeeReader(tr, h))
	if err != nil {
		return false, fmt.Errorf("backup: writing blob %q: %w", entry.Record.Key, err)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != entry.Digest {
		_ = store.Delete(ctx, entry.Record.Key)
		return false, fmt.Errorf("backup: blob %q failed integrity check: got %s, want %s", entry.Record.Key, got, entry.Digest)
	}
	if stored.Size != entry.Record.Size {
		_ = store.Delete(ctx, entry.Record.Key)
		return false, fmt.Errorf("backup: blob %q size mismatch: got %d, want %d", entry.Record.Key, stored.Size, entry.Record.Size)
	}
	return true, nil
}

// restoreMetadataFile streams one metadata-file member onto disk under its
// source's configured target root, verifying its digest. A source with no
// configured target is skipped (its member is drained). The write is atomic
// (temp file + rename) so an interrupted restore never leaves a torn file, and a
// failed digest check removes the temp file.
func restoreMetadataFile(ctx context.Context, tr *tar.Reader, source string, file MetadataFile, opts RestoreOptions) (bool, int64, error) {
	root, ok := opts.Targets[source]
	if !ok || root == "" {
		// No restore target for this source: drain and skip.
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return false, 0, fmt.Errorf("backup: skipping source %q file: %w", source, err)
		}
		return false, 0, nil
	}

	dest, err := safeJoin(root, file.RelPath)
	if err != nil {
		return false, 0, err
	}

	if !opts.Overwrite {
		if existing, serr := os.Stat(dest); serr == nil && existing.Size() == file.Size {
			if d, derr := hashFile(dest); derr == nil && d == file.Digest {
				if _, cerr := io.Copy(io.Discard, tr); cerr != nil {
					return false, 0, fmt.Errorf("backup: skipping existing file %q: %w", dest, cerr)
				}
				return false, 0, nil
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return false, 0, fmt.Errorf("backup: creating directory for %q: %w", dest, err)
	}
	tmp := dest + ".restore.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(file.Mode)&0o777)
	if err != nil {
		return false, 0, fmt.Errorf("backup: creating %q: %w", tmp, err)
	}

	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), tr)
	syncErr := f.Sync()
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: writing %q: %w", dest, copyErr)
	case syncErr != nil:
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: syncing %q: %w", dest, syncErr)
	case closeErr != nil:
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: closing %q: %w", dest, closeErr)
	}

	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != file.Digest {
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: file %s/%s failed integrity check: got %s, want %s", source, file.RelPath, got, file.Digest)
	}
	if n != file.Size {
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: file %s/%s size mismatch: got %d, want %d", source, file.RelPath, n, file.Size)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return false, 0, fmt.Errorf("backup: finalizing %q: %w", dest, err)
	}
	// Best-effort restoration of the recorded mod-time for forensic continuity.
	_ = os.Chtimes(dest, file.ModTime, file.ModTime)
	return true, n, nil
}

// maybeDecrypt inspects the leading bytes of r for the encryption envelope magic.
// If present, it returns a decrypting reader; otherwise it returns r with the
// peeked bytes restored. The detection is transparent so an operator need not
// declare up front whether a snapshot is encrypted.
func maybeDecrypt(r io.Reader, key EncryptionKey) (io.Reader, bool, error) {
	prefix := make([]byte, len(envelopeMagic))
	n, err := io.ReadFull(r, prefix)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("backup: reading snapshot prefix: %w", err)
	}
	combined := io.MultiReader(newPrefixReader(prefix[:n]), r)
	if n == len(envelopeMagic) && string(prefix) == envelopeMagicStr {
		if !key.IsSet() {
			return nil, true, errors.New("backup: snapshot is encrypted but no decryption key was supplied")
		}
		dr, derr := newDecryptingReader(combined, key)
		if derr != nil {
			return nil, true, derr
		}
		return dr, true, nil
	}
	return combined, false, nil
}

// prefixReader replays a small captured prefix before the underlying stream.
type prefixReader struct {
	data []byte
	off  int
}

func newPrefixReader(data []byte) *prefixReader { return &prefixReader{data: data} }

func (p *prefixReader) Read(b []byte) (int, error) {
	if p.off >= len(p.data) {
		return 0, io.EOF
	}
	n := copy(b, p.data[p.off:])
	p.off += n
	return n, nil
}

// readManifestMember reads and decodes the first archive member, which must be
// the manifest.
func readManifestMember(tr *tar.Reader) (*Manifest, error) {
	hdr, err := tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("backup: snapshot is empty")
	}
	if err != nil {
		return nil, fmt.Errorf("backup: reading snapshot: %w", err)
	}
	if hdr.Name != manifestMember {
		return nil, fmt.Errorf("backup: first member is %q, expected %q (not a pullthrough backup?)", hdr.Name, manifestMember)
	}
	var manifest Manifest
	if err := json.NewDecoder(tr).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("backup: decoding manifest: %w", err)
	}
	return &manifest, nil
}
