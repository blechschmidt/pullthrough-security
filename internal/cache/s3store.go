package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// S3Store is a content-addressable Store backed by S3-compatible object storage
// (AWS S3, MinIO, Ceph RGW, GCS via its S3-compatible endpoint). It is the
// horizontally-scalable counterpart to FilesystemStore: many proxy replicas can
// point at the same bucket and share one cache instead of each maintaining its
// own.
//
// Object layout under the configured prefix mirrors the filesystem store so the
// two are operationally interchangeable:
//
//	<prefix>blobs/ab/cd/<name>        raw content
//	<prefix>meta/ab/cd/<name>.json    Record (JSON-encoded metadata index entry)
//
// <name> is the lowercase hex SHA-256 of the cache key, giving fixed-length,
// object-key-safe names and a two-level fan-out. The real key is stored inside
// the Record.
//
// Each object PUT is atomic at the object-store level — a reader never observes a
// partially uploaded object. The blob is written before the metadata, and reads
// key off the metadata object, so a reader that finds metadata is guaranteed the
// blob exists. Deletes remove metadata first so the entry instantly reads as
// absent.
type S3Store struct {
	client    objectClient
	prefix    string // normalized: empty or ends with "/"
	spoolDir  string // staging directory for spooling streamed PUT bodies
	ownClient bool   // close the client on Close when we constructed it
}

var _ Store = (*S3Store)(nil)

// S3Options configures an S3Store.
type S3Options struct {
	// Endpoint, Region, Bucket, credentials, and addressing mode for the object
	// store. See S3ClientConfig for field semantics.
	Endpoint           string
	Region             string
	Bucket             string
	AccessKeyID        string
	SecretAccessKey    string
	SessionToken       string
	UsePathStyle       bool
	InsecureSkipVerify bool
	MaxRetries         int

	// Prefix is an optional key prefix isolating this cache within a shared
	// bucket (e.g. "proxy/cache/"). A trailing slash is added if missing.
	Prefix string

	// SpoolDir is the directory used to spool streamed upload bodies so their
	// length and digest can be computed for a signed PUT. Defaults to the OS temp
	// directory.
	SpoolDir string

	// Client overrides the object-store client. When nil, an HTTP S3 client is
	// constructed from the fields above. Supplying a client is the seam used by
	// unit tests (a fake object store).
	Client objectClient
}

// NewS3Store constructs an S3Store. When opts.Client is nil it builds an HTTP S3
// client from the connection fields.
func NewS3Store(opts S3Options) (*S3Store, error) {
	client := opts.Client
	ownClient := false
	if client == nil {
		c, err := newS3HTTPClient(S3ClientConfig{
			Endpoint:           opts.Endpoint,
			Region:             opts.Region,
			Bucket:             opts.Bucket,
			AccessKeyID:        opts.AccessKeyID,
			SecretAccessKey:    opts.SecretAccessKey,
			SessionToken:       opts.SessionToken,
			UsePathStyle:       opts.UsePathStyle,
			InsecureSkipVerify: opts.InsecureSkipVerify,
			MaxRetries:         opts.MaxRetries,
		})
		if err != nil {
			return nil, err
		}
		client = c
		ownClient = true
	}

	prefix := strings.TrimSpace(opts.Prefix)
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	spoolDir := opts.SpoolDir
	if spoolDir == "" {
		spoolDir = os.TempDir()
	}

	return &S3Store{
		client:    client,
		prefix:    prefix,
		spoolDir:  spoolDir,
		ownClient: ownClient,
	}, nil
}

// blobKey and metaKey derive the object keys for a storage name.
func (s *S3Store) blobKey(name string) string {
	return s.prefix + "blobs/" + name[0:2] + "/" + name[2:4] + "/" + name
}

func (s *S3Store) metaKey(name string) string {
	return s.prefix + "meta/" + name[0:2] + "/" + name[2:4] + "/" + name + ".json"
}

// metaPrefix is the listing prefix for all metadata objects.
func (s *S3Store) metaPrefix() string {
	return s.prefix + "meta/"
}

// Put implements Store. It spools the content to compute its length and digest,
// uploads the blob, then uploads the JSON metadata object.
func (s *S3Store) Put(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if rec.Key == "" {
		return Record{}, errors.New("cache: Put requires a non-empty key")
	}
	name := storageName(rec.Key)

	spool, size, sum, err := s.spool(r)
	if err != nil {
		return Record{}, fmt.Errorf("cache: spooling content for %q: %w", rec.Key, err)
	}
	defer spool.cleanup()
	rec.Size = size
	// The spool already computed the SHA-256 of the exact bytes being uploaded (it
	// is required for the signed PUT); record it as the fixity baseline so the
	// read-time integrity verification and background scan (Task 107) work
	// identically over the S3 backend.
	rec.Digest = "sha256:" + sum

	if err := s.client.putObject(ctx, s.blobKey(name), spool.reader, size, sum, rec.ContentType); err != nil {
		return Record{}, fmt.Errorf("cache: uploading blob for %q: %w", rec.Key, err)
	}

	if err := s.putMeta(ctx, name, rec); err != nil {
		// Roll back the orphaned blob on metadata failure (best effort).
		_ = s.client.deleteObject(ctx, s.blobKey(name))
		return Record{}, fmt.Errorf("cache: uploading metadata for %q: %w", rec.Key, err)
	}
	return rec, nil
}

// Get implements Store.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, Record{}, err
	}
	name := storageName(key)
	rec, err := s.readMeta(ctx, name)
	if err != nil {
		return nil, Record{}, err
	}
	body, _, err := s.client.getObject(ctx, s.blobKey(name))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, Record{}, ErrNotFound
		}
		return nil, Record{}, fmt.Errorf("cache: downloading blob for %q: %w", key, err)
	}
	return body, rec, nil
}

// Stat implements Store.
func (s *S3Store) Stat(ctx context.Context, key string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	return s.readMeta(ctx, storageName(key))
}

// SetAccessed implements Store. It reads the metadata, updates the access
// timestamp, and rewrites it.
func (s *S3Store) SetAccessed(ctx context.Context, key string, t time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := storageName(key)
	rec, err := s.readMeta(ctx, name)
	if err != nil {
		return err
	}
	rec.AccessedAt = t
	return s.putMeta(ctx, name, rec)
}

// Delete implements Store. It removes the metadata object first (so the entry
// reads as absent immediately), then the blob. A missing entry returns
// ErrNotFound.
func (s *S3Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name := storageName(key)
	if _, err := s.client.headObject(ctx, s.metaKey(name)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("cache: checking metadata for %q: %w", key, err)
	}
	if err := s.client.deleteObject(ctx, s.metaKey(name)); err != nil {
		return fmt.Errorf("cache: deleting metadata for %q: %w", key, err)
	}
	if err := s.client.deleteObject(ctx, s.blobKey(name)); err != nil {
		return fmt.Errorf("cache: deleting blob for %q: %w", key, err)
	}
	return nil
}

// List implements Store by enumerating and decoding every metadata object.
func (s *S3Store) List(ctx context.Context) ([]Record, error) {
	var records []Record
	err := s.client.listObjects(ctx, s.metaPrefix(), func(objKey string, _ objectAttrs) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !strings.HasSuffix(objKey, ".json") {
			return nil
		}
		rec, derr := s.fetchRecord(ctx, objKey)
		if derr != nil {
			// Skip unreadable/corrupt index objects rather than failing warm-up,
			// mirroring the filesystem store's tolerance. A concurrent delete by
			// another replica also lands here.
			if errors.Is(derr, ErrNotFound) {
				return nil
			}
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

// Close implements Store. It closes the underlying client when this store owns
// it (i.e. constructed it rather than receiving an injected one).
func (s *S3Store) Close() error {
	if s.ownClient {
		return s.client.close()
	}
	return nil
}

// readMeta fetches and decodes the Record for a storage name, mapping a missing
// object to ErrNotFound.
func (s *S3Store) readMeta(ctx context.Context, name string) (Record, error) {
	return s.fetchRecord(ctx, s.metaKey(name))
}

// fetchRecord downloads and JSON-decodes a metadata object by its full key.
func (s *S3Store) fetchRecord(ctx context.Context, objKey string) (Record, error) {
	body, _, err := s.client.getObject(ctx, objKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("cache: downloading metadata %q: %w", objKey, err)
	}
	defer body.Close()
	var rec Record
	if err := json.NewDecoder(body).Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("cache: decoding metadata %q: %w", objKey, err)
	}
	return rec, nil
}

// putMeta JSON-encodes and uploads the Record as the metadata object.
func (s *S3Store) putMeta(ctx context.Context, name string, rec Record) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rec); err != nil {
		return err
	}
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	return s.client.putObject(ctx, s.metaKey(name), bytes.NewReader(data), int64(len(data)), hex.EncodeToString(sum[:]), "application/json")
}

// spooled holds a staged upload body together with its cleanup hook.
type spooled struct {
	reader  io.ReadSeeker
	cleanup func()
}

// spool drains r to a seekable buffer (memory for small bodies, a temp file for
// large ones) while computing its length and SHA-256, which the signed PUT
// requires. Spilling large blobs to disk keeps memory bounded for big artifacts
// such as Docker layers.
const spoolMemoryLimit = 8 << 20 // 8 MiB

func (s *S3Store) spool(r io.Reader) (*spooled, int64, string, error) {
	h := sha256.New()

	// First, try to buffer in memory up to the limit.
	var mem bytes.Buffer
	tee := io.TeeReader(io.LimitReader(r, spoolMemoryLimit), h)
	n, err := mem.ReadFrom(tee)
	if err != nil {
		return nil, 0, "", err
	}
	if n < spoolMemoryLimit {
		// Entire body fit in memory.
		data := mem.Bytes()
		return &spooled{reader: bytes.NewReader(data), cleanup: func() {}}, n, hex.EncodeToString(h.Sum(nil)), nil
	}

	// Body exceeds the memory limit: spill to a temp file, starting with what we
	// already buffered, then continue streaming the remainder.
	f, err := os.CreateTemp(s.spoolDir, "pts-s3-spool-*")
	if err != nil {
		return nil, 0, "", err
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}
	if _, err := f.Write(mem.Bytes()); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	total := n
	written, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		cleanup()
		return nil, 0, "", err
	}
	total += written
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, 0, "", err
	}
	return &spooled{reader: f, cleanup: cleanup}, total, hex.EncodeToString(h.Sum(nil)), nil
}
