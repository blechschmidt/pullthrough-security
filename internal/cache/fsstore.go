package cache

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// FilesystemStore is a content-addressable Store backed by the local filesystem.
//
// Layout under the root directory:
//
//	blobs/ab/cd/<name>        raw content
//	meta/ab/cd/<name>.json    Record (JSON-encoded metadata index entry)
//	tmp/                      staging area for atomic writes
//
// <name> is the lowercase hex SHA-256 of the cache key. Hashing the key (rather
// than using it directly) yields fixed-length, filesystem-safe names for
// arbitrary keys and spreads entries across a two-level fan-out (256x256) to
// avoid oversized directories. The real key is stored inside the Record.
//
// Writes are atomic: content and metadata are each staged in tmp/, fsync'd, then
// renamed into place. The blob is written before the metadata, and reads key off
// the metadata file, so a reader never sees metadata pointing at a missing or
// partial blob.
type FilesystemStore struct {
	root     string
	blobDir  string
	metaDir  string
	tmpDir   string
	fileMode os.FileMode
	dirMode  os.FileMode
}

var _ Store = (*FilesystemStore)(nil)

// NewFilesystemStore creates (if necessary) the directory layout under root and
// returns a ready-to-use store.
func NewFilesystemStore(root string) (*FilesystemStore, error) {
	if root == "" {
		return nil, errors.New("cache: filesystem store requires a non-empty root directory")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("cache: resolving store root %q: %w", root, err)
	}
	s := &FilesystemStore{
		root:     abs,
		blobDir:  filepath.Join(abs, "blobs"),
		metaDir:  filepath.Join(abs, "meta"),
		tmpDir:   filepath.Join(abs, "tmp"),
		fileMode: 0o640,
		dirMode:  0o750,
	}
	for _, dir := range []string{s.blobDir, s.metaDir, s.tmpDir} {
		if err := os.MkdirAll(dir, s.dirMode); err != nil {
			return nil, fmt.Errorf("cache: creating store directory %q: %w", dir, err)
		}
	}
	// Clear any leftover staging files from a previous unclean shutdown.
	s.cleanTmp()
	return s, nil
}

// storageName derives the fixed-length filesystem name for a key.
func storageName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *FilesystemStore) blobPath(name string) string {
	return filepath.Join(s.blobDir, name[0:2], name[2:4], name)
}

func (s *FilesystemStore) metaPath(name string) string {
	return filepath.Join(s.metaDir, name[0:2], name[2:4], name+".json")
}

func (s *FilesystemStore) cleanTmp() {
	entries, err := os.ReadDir(s.tmpDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(s.tmpDir, e.Name()))
	}
}

// Put implements Store.
func (s *FilesystemStore) Put(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if rec.Key == "" {
		return Record{}, errors.New("cache: Put requires a non-empty key")
	}
	name := storageName(rec.Key)

	// Compute the content digest over the exact bytes persisted, incrementally as
	// they stream to the blob file, so no extra pass over the content is needed and
	// memory stays bounded. It becomes the authoritative fixity baseline for
	// read-time integrity verification (Task 107).
	var size int64
	hasher := sha256.New()
	if err := s.writeAtomic(s.blobPath(name), func(w io.Writer) error {
		n, err := io.Copy(io.MultiWriter(w, hasher), r)
		size = n
		return err
	}); err != nil {
		return Record{}, fmt.Errorf("cache: writing blob for %q: %w", rec.Key, err)
	}
	rec.Size = size
	rec.Digest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))

	if err := s.writeMeta(name, rec); err != nil {
		// Roll back the orphaned blob on metadata failure (best effort).
		_ = os.Remove(s.blobPath(name))
		return Record{}, fmt.Errorf("cache: writing metadata for %q: %w", rec.Key, err)
	}
	return rec, nil
}

// Get implements Store.
func (s *FilesystemStore) Get(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, Record{}, err
	}
	name := storageName(key)
	rec, err := s.readMeta(name)
	if err != nil {
		return nil, Record{}, err
	}
	f, err := os.Open(s.blobPath(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Record{}, ErrNotFound
		}
		return nil, Record{}, fmt.Errorf("cache: opening blob for %q: %w", key, err)
	}
	return f, rec, nil
}

// Stat implements Store.
func (s *FilesystemStore) Stat(ctx context.Context, key string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	return s.readMeta(storageName(key))
}

// SetAccessed implements Store.
func (s *FilesystemStore) SetAccessed(ctx context.Context, key string, t time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := storageName(key)
	rec, err := s.readMeta(name)
	if err != nil {
		return err
	}
	rec.AccessedAt = t
	return s.writeMeta(name, rec)
}

// Delete implements Store.
func (s *FilesystemStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := storageName(key)
	metaPath := s.metaPath(name)
	if _, err := os.Stat(metaPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("cache: stating metadata for %q: %w", key, err)
	}
	// Remove metadata first so the entry instantly reads as absent, then the blob.
	if err := os.Remove(metaPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cache: removing metadata for %q: %w", key, err)
	}
	if err := os.Remove(s.blobPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cache: removing blob for %q: %w", key, err)
	}
	return nil
}

// UpdateMetadata persists an updated Record without touching the content blob.
// It is the in-place metadata-update capability the at-rest encryption layer's
// KEK rotation uses to re-wrap an object's data key without re-encrypting its
// payload (Task 141). It returns ErrNotFound if the entry is absent, so a
// concurrently deleted entry is reported rather than silently recreated with no
// blob. The write is atomic (staged in tmp/, fsynced, renamed), exactly like a
// normal metadata write.
func (s *FilesystemStore) UpdateMetadata(ctx context.Context, rec Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rec.Key == "" {
		return errors.New("cache: UpdateMetadata requires a non-empty key")
	}
	name := storageName(rec.Key)
	if _, err := os.Stat(s.metaPath(name)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("cache: stating metadata for %q: %w", rec.Key, err)
	}
	return s.writeMeta(name, rec)
}

// List implements Store by walking the metadata tree.
func (s *FilesystemStore) List(ctx context.Context) ([]Record, error) {
	var records []Record
	err := filepath.WalkDir(s.metaDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rec, derr := decodeRecordFile(path)
		if derr != nil {
			// Skip unreadable/corrupt index files rather than failing warm-up.
			return nil
		}
		records = append(records, rec)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cache: listing store metadata: %w", err)
	}
	return records, nil
}

// Close implements Store. The filesystem store holds no long-lived resources.
func (s *FilesystemStore) Close() error { return nil }

func (s *FilesystemStore) readMeta(name string) (Record, error) {
	rec, err := decodeRecordFile(s.metaPath(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	return rec, nil
}

func decodeRecordFile(path string) (Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	var rec Record
	if err := json.NewDecoder(f).Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("cache: decoding metadata %q: %w", path, err)
	}
	return rec, nil
}

func (s *FilesystemStore) writeMeta(name string, rec Record) error {
	return s.writeAtomic(s.metaPath(name), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rec)
	})
}

// writeAtomic stages the output of write in tmp/, flushes and fsyncs it, then
// renames it into place at path. The parent directory is created on demand.
func (s *FilesystemStore) writeAtomic(path string, write func(w io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), s.dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.tmpDir, "stage-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Ensure the staging file is cleaned up on any error path; after a
	// successful rename these become harmless no-ops.
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(s.fileMode); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}
