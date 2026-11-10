package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestCache(t *testing.T, opts FilesystemOptions) *FilesystemCache {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = t.TempDir()
	}
	c, err := NewFilesystemCache(opts)
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func putString(t *testing.T, c *FilesystemCache, key, content string, meta map[string]string) *Stat {
	t.Helper()
	stat, err := c.Put(context.Background(), key, strings.NewReader(content), meta)
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	return stat
}

func getString(t *testing.T, c *FilesystemCache, key string) (string, *Stat) {
	t.Helper()
	entry, err := c.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	defer entry.Content.Close()
	data, err := io.ReadAll(entry.Content)
	if err != nil {
		t.Fatalf("reading %q: %v", key, err)
	}
	return string(data), &entry.Stat
}

func TestPutGetRoundTrip(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	meta := map[string]string{
		MetaOrigin:      "https://registry.npmjs.org/left-pad",
		MetaContentType: "application/octet-stream",
		MetaETag:        `"abc123"`,
		"custom":        "value",
	}
	stat := putString(t, c, "sha256:deadbeef", "hello world", meta)
	if stat.Size != int64(len("hello world")) {
		t.Errorf("Put size = %d, want %d", stat.Size, len("hello world"))
	}

	got, gotStat := getString(t, c, "sha256:deadbeef")
	if got != "hello world" {
		t.Errorf("content = %q, want %q", got, "hello world")
	}
	if gotStat.Metadata[MetaOrigin] != meta[MetaOrigin] {
		t.Errorf("origin = %q, want %q", gotStat.Metadata[MetaOrigin], meta[MetaOrigin])
	}
	if gotStat.Metadata[MetaContentType] != meta[MetaContentType] {
		t.Errorf("content-type = %q, want %q", gotStat.Metadata[MetaContentType], meta[MetaContentType])
	}
	if gotStat.Metadata[MetaETag] != meta[MetaETag] {
		t.Errorf("etag = %q, want %q", gotStat.Metadata[MetaETag], meta[MetaETag])
	}
	if gotStat.Metadata["custom"] != "value" {
		t.Errorf("custom metadata = %q, want %q", gotStat.Metadata["custom"], "value")
	}
}

func TestGetMissing(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	if _, err := c.Get(context.Background(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(absent) error = %v, want ErrNotFound", err)
	}
	if snap := c.Metrics(); snap.Misses != 1 {
		t.Errorf("misses = %d, want 1", snap.Misses)
	}
}

func TestStatDoesNotOpenContent(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "k", "abcdef", nil)
	stat, err := c.Stat(context.Background(), "k")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if stat.Size != 6 {
		t.Errorf("Stat size = %d, want 6", stat.Size)
	}
	if _, err := c.Stat(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Stat(nope) = %v, want ErrNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "k", "data", nil)
	if err := c.Delete(context.Background(), "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(context.Background(), "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := c.Delete(context.Background(), "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(missing) = %v, want ErrNotFound", err)
	}
}

func TestOverwritePreservesCreatedAt(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(t, FilesystemOptions{Now: clock.Now})

	putString(t, c, "k", "v1", nil)
	rec1, err := c.store.Stat(context.Background(), "k")
	if err != nil {
		t.Fatalf("store.Stat: %v", err)
	}

	clock.advance(time.Hour)
	putString(t, c, "k", "v2-longer", nil)
	rec2, err := c.store.Stat(context.Background(), "k")
	if err != nil {
		t.Fatalf("store.Stat: %v", err)
	}

	if !rec2.CreatedAt.Equal(rec1.CreatedAt) {
		t.Errorf("CreatedAt changed on overwrite: %v -> %v", rec1.CreatedAt, rec2.CreatedAt)
	}
	if !rec2.ModTime.After(rec1.ModTime) {
		t.Errorf("ModTime did not advance on overwrite")
	}
	got, _ := getString(t, c, "k")
	if got != "v2-longer" {
		t.Errorf("content = %q, want v2-longer", got)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	c1, err := NewFilesystemCache(FilesystemOptions{Dir: dir})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	putString(t, c1, "alpha", "first", map[string]string{MetaOrigin: "u1"})
	putString(t, c1, "beta", "second", nil)
	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c2, err := NewFilesystemCache(FilesystemOptions{Dir: dir})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer c2.Close()

	got, stat := getString(t, c2, "alpha")
	if got != "first" {
		t.Errorf("alpha = %q, want first", got)
	}
	if stat.Metadata[MetaOrigin] != "u1" {
		t.Errorf("alpha origin = %q, want u1", stat.Metadata[MetaOrigin])
	}
	if got, _ := getString(t, c2, "beta"); got != "second" {
		t.Errorf("beta = %q, want second", got)
	}
}

func TestLRUEvictionBySize(t *testing.T) {
	// Budget of 30 bytes; each entry is 10 bytes.
	c := newTestCache(t, FilesystemOptions{MaxSizeBytes: 30})
	for _, k := range []string{"a", "b", "c"} {
		putString(t, c, k, "0123456789", nil)
	}
	// Touch "a" so "b" becomes the least-recently-used.
	getString(t, c, "a")
	// Insert "d" -> total would be 40, evict one entry (the LRU, "b").
	putString(t, c, "d", "0123456789", nil)

	if _, err := c.Stat(context.Background(), "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected b to be evicted, got err=%v", err)
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, err := c.Stat(context.Background(), k); err != nil {
			t.Errorf("expected %q to remain, got err=%v", k, err)
		}
	}
	if snap := c.Metrics(); snap.Evictions != 1 {
		t.Errorf("evictions = %d, want 1", snap.Evictions)
	}
}

func TestOversizedEntryRetained(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{MaxSizeBytes: 5})
	putString(t, c, "big", "0123456789", nil) // 10 bytes > 5 budget
	if _, err := c.Stat(context.Background(), "big"); err != nil {
		t.Errorf("oversized lone entry should be retained, got %v", err)
	}
}

func TestTTLExpiryOnRead(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	c := newTestCache(t, FilesystemOptions{TTL: time.Minute, Now: clock.Now})
	putString(t, c, "k", "v", nil)

	clock.advance(30 * time.Second)
	if _, err := c.Stat(context.Background(), "k"); err != nil {
		t.Errorf("entry should be live at 30s, got %v", err)
	}

	clock.advance(2 * time.Minute)
	if _, err := c.Get(context.Background(), "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired entry Get = %v, want ErrNotFound", err)
	}
	if snap := c.Metrics(); snap.Expired != 1 {
		t.Errorf("expired = %d, want 1", snap.Expired)
	}
}

func TestGetOrLoadSingleFlight(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})

	const goroutines = 50
	var loadCount atomic.Int64
	release := make(chan struct{})

	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		loadCount.Add(1)
		<-release // hold all callers in the single flight together
		return strings.NewReader("payload"), map[string]string{MetaOrigin: "upstream"}, nil
	}

	var wg sync.WaitGroup
	results := make([]string, goroutines)
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry, err := c.GetOrLoad(context.Background(), "key", loader)
			if err != nil {
				errs[i] = err
				return
			}
			defer entry.Content.Close()
			data, rerr := io.ReadAll(entry.Content)
			if rerr != nil {
				errs[i] = rerr
				return
			}
			results[i] = string(data)
		}(i)
	}
	// Give goroutines a moment to converge on the single flight, then release.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d error: %v", i, errs[i])
		}
		if results[i] != "payload" {
			t.Errorf("goroutine %d result = %q, want payload", i, results[i])
		}
	}
	if n := loadCount.Load(); n != 1 {
		t.Errorf("loader called %d times, want exactly 1 (single-flight)", n)
	}

	snap := c.Metrics()
	if snap.Loads != 1 {
		t.Errorf("loads = %d, want 1", snap.Loads)
	}
	if snap.Coalesced == 0 {
		t.Errorf("coalesced = 0, want >0 (concurrent callers should merge)")
	}
}

func TestGetOrLoadHitDoesNotLoad(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "k", "cached", nil)

	called := false
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		called = true
		return strings.NewReader("upstream"), nil, nil
	}
	entry, err := c.GetOrLoad(context.Background(), "k", loader)
	if err != nil {
		t.Fatalf("GetOrLoad: %v", err)
	}
	defer entry.Content.Close()
	data, _ := io.ReadAll(entry.Content)
	if string(data) != "cached" {
		t.Errorf("content = %q, want cached", data)
	}
	if called {
		t.Error("loader should not run on a cache hit")
	}
}

func TestGetOrLoadPropagatesLoaderError(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	want := errors.New("upstream down")
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		return nil, nil, want
	}
	if _, err := c.GetOrLoad(context.Background(), "k", loader); !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{MaxSizeBytes: 1 << 20})
	const workers = 16
	const iterations = 100

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("k-%d-%d", w, i%10)
				content := fmt.Sprintf("content-%d-%d", w, i)
				if _, err := c.Put(context.Background(), key, strings.NewReader(content), nil); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				entry, err := c.Get(context.Background(), key)
				if err != nil {
					if errors.Is(err, ErrNotFound) {
						continue // may have been evicted; acceptable
					}
					t.Errorf("Get: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, entry.Content)
				entry.Content.Close()
			}
		}(w)
	}
	wg.Wait()
}

func TestMetricsHitRatio(t *testing.T) {
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "k", "v", nil)
	getString(t, c, "k")                       // hit
	getString(t, c, "k")                       // hit
	_, _ = c.Get(context.Background(), "miss") // miss

	snap := c.Metrics()
	if snap.Hits != 2 || snap.Misses != 1 {
		t.Fatalf("hits=%d misses=%d, want 2/1", snap.Hits, snap.Misses)
	}
	if got := snap.HitRatio(); got < 0.66 || got > 0.67 {
		t.Errorf("HitRatio = %f, want ~0.666", got)
	}
	if snap.BytesServed != 2 {
		t.Errorf("bytesServed = %d, want 2", snap.BytesServed)
	}
}

func TestContentAddressableIntegrity(t *testing.T) {
	// Two distinct keys must not collide on disk.
	c := newTestCache(t, FilesystemOptions{})
	putString(t, c, "key-one", "AAAA", nil)
	putString(t, c, "key-two", "BBBB", nil)
	if got, _ := getString(t, c, "key-one"); got != "AAAA" {
		t.Errorf("key-one = %q, want AAAA", got)
	}
	if got, _ := getString(t, c, "key-two"); got != "BBBB" {
		t.Errorf("key-two = %q, want BBBB", got)
	}
}

func TestStoreWriteIsAtomic(t *testing.T) {
	// A failed copy must not leave a half-written, retrievable entry.
	c := newTestCache(t, FilesystemOptions{})
	_, err := c.Put(context.Background(), "k", &failingReader{}, nil)
	if err == nil {
		t.Fatal("expected Put to fail on a failing reader")
	}
	if _, err := c.Get(context.Background(), "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after failed Put = %v, want ErrNotFound", err)
	}
}

// --- helpers ---

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		r.n++
		// Write a few bytes before failing to exercise the rollback path.
		copy(p, []byte("partial"))
		return 7, nil
	}
	return 0, errors.New("read failure")
}

var _ io.Reader = (*bytes.Reader)(nil)
