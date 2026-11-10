package docker

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// loadThroughCache mirrors how the proxy gateway fills the content-addressable
// cache on a miss: Resolve, then GetOrLoad with a loader backed by Fetch. It
// returns the served bytes, whether the upstream was hit, and any error.
func loadThroughCache(t *testing.T, c cache.Cache, b *Backend, path string, header http.Header) (string, bool, error) {
	t.Helper()
	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Header: header})
	if err != nil {
		return "", false, err
	}
	if !resolved.Cacheable {
		t.Fatalf("path %q resolved as non-cacheable; this helper exercises the cache path", path)
	}

	var loaded bool
	loader := func(ctx context.Context) (io.Reader, map[string]string, error) {
		loaded = true
		fr, ferr := b.Fetch(ctx, resolved)
		if ferr != nil {
			return nil, nil, ferr
		}
		meta := map[string]string{cache.MetaOrigin: resolved.UpstreamURL}
		if fr.MediaType != "" {
			meta[cache.MetaContentType] = fr.MediaType
		}
		return fr.Content, meta, nil
	}

	entry, err := c.GetOrLoad(context.Background(), resolved.CacheKey, loader)
	if err != nil {
		return "", loaded, err
	}
	defer entry.Content.Close()
	body, err := io.ReadAll(entry.Content)
	return string(body), loaded, err
}

func TestDigestVerifiedCachingReusesCASStore(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	c, err := cache.NewFilesystemCache(cache.FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer c.Close()

	blobPath := "/v2/library/nginx/blobs/" + reg.blobDigest

	// First request: cache miss -> fetched upstream, digest-verified, and stored.
	body, loaded, err := loadThroughCache(t, c, b, blobPath, nil)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if !loaded {
		t.Error("first request should have hit the upstream (miss)")
	}
	if body != string(reg.blob) {
		t.Errorf("body = %q, want %q", body, reg.blob)
	}

	// Second request: served from the content-addressable store, no upstream hit.
	body, loaded, err = loadThroughCache(t, c, b, blobPath, nil)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if loaded {
		t.Error("second request should have been served from cache (hit)")
	}
	if body != string(reg.blob) {
		t.Errorf("cached body = %q, want %q", body, reg.blob)
	}
}

func TestPoisonedBlobIsNeverCached(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	c, err := cache.NewFilesystemCache(cache.FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewFilesystemCache: %v", err)
	}
	defer c.Close()

	poisonedPath := "/v2/library/nginx/blobs/" + reg.poisonedDigest

	// The cold fill must fail closed: the digest mismatch aborts the store.
	if _, _, err := loadThroughCache(t, c, b, poisonedPath, nil); err == nil {
		t.Fatal("expected the poisoned fill to fail")
	}

	// And nothing must have been committed to the store under that key.
	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: poisonedPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat(context.Background(), resolved.CacheKey); err == nil {
		t.Error("poisoned content must not be present in the cache")
	}
}
