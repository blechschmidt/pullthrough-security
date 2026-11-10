package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeObjectClient is an in-memory objectClient for unit testing S3Store without
// a live S3 endpoint. It verifies the caller-supplied payload digest matches the
// body, mirroring S3's integrity guarantee.
type fakeObjectClient struct {
	mu      sync.Mutex
	objects map[string][]byte
	// failPutOn, when non-empty, makes putObject of a matching key suffix fail,
	// used to exercise rollback paths.
	failPutOn string
	puts      int
	gets      int
	deletes   int
}

func newFakeObjectClient() *fakeObjectClient {
	return &fakeObjectClient{objects: make(map[string][]byte)}
}

func (f *fakeObjectClient) getObject(ctx context.Context, key string) (io.ReadCloser, objectAttrs, error) {
	if err := ctx.Err(); err != nil {
		return nil, objectAttrs{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	data, ok := f.objects[key]
	if !ok {
		return nil, objectAttrs{}, ErrNotFound
	}
	sum := sha256.Sum256(data)
	cp := append([]byte(nil), data...)
	return io.NopCloser(bytes.NewReader(cp)), objectAttrs{Size: int64(len(cp)), ETag: hex.EncodeToString(sum[:])}, nil
}

func (f *fakeObjectClient) putObject(ctx context.Context, key string, body io.ReadSeeker, size int64, sha256hex, contentType string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.failPutOn != "" && strings.HasSuffix(key, f.failPutOn) {
		return fmt.Errorf("fake: induced put failure for %q", key)
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("fake: size mismatch for %q: header %d, body %d", key, size, len(data))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sha256hex {
		return fmt.Errorf("fake: payload digest mismatch for %q: header %s, body %s", key, sha256hex, got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	f.objects[key] = data
	return nil
}

func (f *fakeObjectClient) headObject(ctx context.Context, key string) (objectAttrs, error) {
	if err := ctx.Err(); err != nil {
		return objectAttrs{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[key]
	if !ok {
		return objectAttrs{}, ErrNotFound
	}
	sum := sha256.Sum256(data)
	return objectAttrs{Size: int64(len(data)), ETag: hex.EncodeToString(sum[:])}, nil
}

func (f *fakeObjectClient) deleteObject(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	delete(f.objects, key) // idempotent
	return nil
}

func (f *fakeObjectClient) listObjects(ctx context.Context, prefix string, fn func(key string, attrs objectAttrs) error) error {
	f.mu.Lock()
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	f.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		f.mu.Lock()
		data := f.objects[k]
		f.mu.Unlock()
		sum := sha256.Sum256(data)
		if err := fn(k, objectAttrs{Size: int64(len(data)), ETag: hex.EncodeToString(sum[:])}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeObjectClient) close() error { return nil }

func newTestS3Store(t *testing.T, prefix string) (*S3Store, *fakeObjectClient) {
	t.Helper()
	fake := newFakeObjectClient()
	store, err := NewS3Store(S3Options{Client: fake, Prefix: prefix, SpoolDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	return store, fake
}

func TestS3StorePutGetRoundTrip(t *testing.T) {
	store, fake := newTestS3Store(t, "proxy/cache/")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	rec := Record{
		Key:         "sha256:abc",
		Origin:      "https://registry.npmjs.org/left-pad",
		ContentType: "application/octet-stream",
		ETag:        "W/\"v1\"",
		CreatedAt:   now,
		ModTime:     now,
		AccessedAt:  now,
		Extra:       map[string]string{"x-custom": "value"},
	}
	content := []byte("hello content-addressable object storage")

	stored, err := store.Put(ctx, rec, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stored.Size != int64(len(content)) {
		t.Fatalf("stored size = %d, want %d", stored.Size, len(content))
	}

	// Verify content-addressed object layout under the prefix.
	name := storageName(rec.Key)
	wantBlob := "proxy/cache/blobs/" + name[0:2] + "/" + name[2:4] + "/" + name
	wantMeta := "proxy/cache/meta/" + name[0:2] + "/" + name[2:4] + "/" + name + ".json"
	fake.mu.Lock()
	_, blobOK := fake.objects[wantBlob]
	_, metaOK := fake.objects[wantMeta]
	fake.mu.Unlock()
	if !blobOK {
		t.Fatalf("blob object %q not present; have keys %v", wantBlob, keysOf(fake))
	}
	if !metaOK {
		t.Fatalf("meta object %q not present; have keys %v", wantMeta, keysOf(fake))
	}

	rc, got, err := store.Get(ctx, rec.Key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if !bytes.Equal(data, content) {
		t.Fatalf("content = %q, want %q", data, content)
	}
	if got.Origin != rec.Origin || got.ContentType != rec.ContentType || got.ETag != rec.ETag {
		t.Fatalf("metadata round-trip mismatch: %+v", got)
	}
	if got.Extra["x-custom"] != "value" {
		t.Fatalf("extra metadata lost: %+v", got.Extra)
	}
	if got.Size != int64(len(content)) {
		t.Fatalf("record size = %d, want %d", got.Size, len(content))
	}
}

func keysOf(f *fakeObjectClient) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks := make([]string, 0, len(f.objects))
	for k := range f.objects {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func TestS3StoreGetMissing(t *testing.T) {
	store, _ := newTestS3Store(t, "")
	_, _, err := store.Get(context.Background(), "sha256:absent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
	if _, err := store.Stat(context.Background(), "sha256:absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat missing = %v, want ErrNotFound", err)
	}
}

func TestS3StoreStatSetAccessedDelete(t *testing.T) {
	store, _ := newTestS3Store(t, "")
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	rec := Record{Key: "k1", CreatedAt: t0, ModTime: t0, AccessedAt: t0}
	if _, err := store.Put(ctx, rec, strings.NewReader("data")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Stat(ctx, "k1")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !got.AccessedAt.Equal(t0) {
		t.Fatalf("AccessedAt = %v, want %v", got.AccessedAt, t0)
	}

	t1 := t0.Add(time.Hour)
	if err := store.SetAccessed(ctx, "k1", t1); err != nil {
		t.Fatalf("SetAccessed: %v", err)
	}
	got, _ = store.Stat(ctx, "k1")
	if !got.AccessedAt.Equal(t1) {
		t.Fatalf("AccessedAt after update = %v, want %v", got.AccessedAt, t1)
	}

	if err := store.Delete(ctx, "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Stat(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat after delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing = %v, want ErrNotFound", err)
	}
	if err := store.SetAccessed(ctx, "k1", t1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetAccessed missing = %v, want ErrNotFound", err)
	}
}

func TestS3StoreList(t *testing.T) {
	store, _ := newTestS3Store(t, "p/")
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		rec := Record{Key: key, CreatedAt: now, ModTime: now, AccessedAt: now}
		if _, err := store.Put(ctx, rec, strings.NewReader(strings.Repeat("x", i+1))); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	recs, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("List returned %d records, want 5", len(recs))
	}
	seen := map[string]bool{}
	for _, r := range recs {
		seen[r.Key] = true
		if r.Size == 0 {
			t.Fatalf("record %q has zero size", r.Key)
		}
	}
	for i := 0; i < 5; i++ {
		if !seen[fmt.Sprintf("key-%d", i)] {
			t.Fatalf("List missing key-%d", i)
		}
	}
}

func TestS3StorePutRollbackOnMetaFailure(t *testing.T) {
	fake := newFakeObjectClient()
	fake.failPutOn = ".json" // fail the metadata write
	store, err := NewS3Store(S3Options{Client: fake, SpoolDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	now := time.Now()
	_, err = store.Put(context.Background(), Record{Key: "k", CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("data"))
	if err == nil {
		t.Fatalf("Put expected to fail on meta write")
	}
	// The orphaned blob must have been rolled back.
	if got := keysOf(fake); len(got) != 0 {
		t.Fatalf("orphaned objects after rollback: %v", got)
	}
}

// TestS3StoreLargeBlobSpoolsToDisk exercises the temp-file spool path for bodies
// exceeding the in-memory limit.
func TestS3StoreLargeBlobSpoolsToDisk(t *testing.T) {
	store, _ := newTestS3Store(t, "")
	ctx := context.Background()
	size := spoolMemoryLimit + (1 << 20) // 1 MiB over the limit
	content := bytes.Repeat([]byte("A"), size)
	now := time.Now()
	if _, err := store.Put(ctx, Record{Key: "big", CreatedAt: now, ModTime: now, AccessedAt: now}, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put large: %v", err)
	}
	rc, rec, err := store.Get(ctx, "big")
	if err != nil {
		t.Fatalf("Get large: %v", err)
	}
	defer rc.Close()
	if rec.Size != int64(size) {
		t.Fatalf("size = %d, want %d", rec.Size, size)
	}
	data, _ := io.ReadAll(rc)
	if !bytes.Equal(data, content) {
		t.Fatalf("large content mismatch (len %d vs %d)", len(data), len(content))
	}
}

// TestS3StoreSatisfiesStoreInterface is a compile-time and runtime check that the
// generic FilesystemCache works over an S3-backed store, preserving single-flight
// loading and metrics.
func TestFilesystemCacheOverS3Store(t *testing.T) {
	fake := newFakeObjectClient()
	store, err := NewS3Store(S3Options{Client: fake, SpoolDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	c, err := NewFilesystemCache(FilesystemOptions{Store: store})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer c.Close()
	ctx := context.Background()

	var loads int32
	var mu sync.Mutex
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		mu.Lock()
		loads++
		mu.Unlock()
		return strings.NewReader("payload"), map[string]string{MetaOrigin: "https://example/x"}, nil
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			e, err := c.GetOrLoad(ctx, "shared-key", loader)
			if err != nil {
				t.Errorf("GetOrLoad: %v", err)
				return
			}
			data, _ := io.ReadAll(e.Content)
			e.Content.Close()
			if string(data) != "payload" {
				t.Errorf("content = %q", data)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	gotLoads := loads
	mu.Unlock()
	if gotLoads != 1 {
		t.Fatalf("loader ran %d times, want 1 (single-flight)", gotLoads)
	}
	snap := c.Metrics()
	if snap.Loads != 1 {
		t.Fatalf("metrics Loads = %d, want 1", snap.Loads)
	}
	// A subsequent read of the now-populated key is a straightforward hit.
	e, err := c.Get(ctx, "shared-key")
	if err != nil {
		t.Fatalf("Get after load: %v", err)
	}
	e.Content.Close()
	if c.Metrics().Hits == 0 {
		t.Fatalf("expected a hit to be recorded after the key was cached")
	}
}

// TestSharedStoreFallback verifies that with SharedStore enabled, a cache whose
// in-memory index does not know a key still serves it from the durable store
// (simulating a write by another replica), and that without it the read misses.
func TestSharedStoreFallback(t *testing.T) {
	fake := newFakeObjectClient()

	// "Replica A" writes directly to the shared store.
	storeA, _ := NewS3Store(S3Options{Client: fake, SpoolDir: t.TempDir()})
	now := time.Now().UTC()
	if _, err := storeA.Put(context.Background(), Record{Key: "k", CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("data")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// "Replica B" starts later over the same bucket but the key already exists.
	// We simulate a B that warmed an empty index then A wrote, by constructing the
	// cache with the store empty at warm time is hard; instead test the read path
	// directly: a fresh cache over the populated store warms the index, so to test
	// the *fallback* we delete from the index by using a key written after warm.
	storeB, _ := NewS3Store(S3Options{Client: fake, SpoolDir: t.TempDir()})

	withFallback, err := NewFilesystemCache(FilesystemOptions{Store: storeB, SharedStore: true})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer withFallback.Close()

	// Write a brand-new key straight to the bucket, bypassing the cache index.
	if _, err := storeA.Put(context.Background(), Record{Key: "late", CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("late-data")); err != nil {
		t.Fatalf("Put late: %v", err)
	}

	e, err := withFallback.Get(context.Background(), "late")
	if err != nil {
		t.Fatalf("Get with fallback: %v", err)
	}
	data, _ := io.ReadAll(e.Content)
	e.Content.Close()
	if string(data) != "late-data" {
		t.Fatalf("content = %q, want late-data", data)
	}

	// Without fallback, the same out-of-band write is invisible.
	storeC, _ := NewS3Store(S3Options{Client: fake, SpoolDir: t.TempDir()})
	noFallback, err := NewFilesystemCache(FilesystemOptions{Store: storeC, SharedStore: false})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer noFallback.Close()
	if _, err := storeA.Put(context.Background(), Record{Key: "later", CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("x")); err != nil {
		t.Fatalf("Put later: %v", err)
	}
	if _, err := noFallback.Get(context.Background(), "later"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get without fallback = %v, want ErrNotFound", err)
	}
}
