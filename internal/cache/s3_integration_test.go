//go:build integration
// +build integration

package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Integration tests for the S3 object-storage cache backend, exercised against a
// real S3-compatible endpoint (MinIO). They are gated behind the `integration`
// build tag, mirroring the convention used by internal/git and the docker
// backend, so the default `go test ./...` run stays hermetic.
//
// Bring up MinIO with the dev stack and run the suite:
//
//	docker compose --profile extras up -d minio
//	PTS_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
//	PTS_TEST_S3_BUCKET=pts-itest \
//	PTS_TEST_S3_ACCESS_KEY=pullthrough \
//	PTS_TEST_S3_SECRET_KEY=pullthrough123 \
//	  go test -tags integration -run TestS3 ./internal/cache/
//
// The bucket must already exist (create it once with `mc mb local/pts-itest` or
// the MinIO console). When PTS_TEST_S3_ENDPOINT is unset the suite is skipped.

func s3IntegrationOptions(t *testing.T) S3Options {
	t.Helper()
	endpoint := os.Getenv("PTS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PTS_TEST_S3_ENDPOINT (and bucket/credentials) to run S3 integration tests")
	}
	bucket := envOr("PTS_TEST_S3_BUCKET", "pts-itest")
	// A unique prefix per run keeps repeated runs and parallel tests isolated.
	prefix := fmt.Sprintf("itest/%d/", time.Now().UnixNano())
	return S3Options{
		Endpoint:        endpoint,
		Region:          envOr("PTS_TEST_S3_REGION", "us-east-1"),
		Bucket:          bucket,
		Prefix:          prefix,
		AccessKeyID:     envOr("PTS_TEST_S3_ACCESS_KEY", "pullthrough"),
		SecretAccessKey: envOr("PTS_TEST_S3_SECRET_KEY", "pullthrough123"),
		UsePathStyle:    true,
		SpoolDir:        t.TempDir(),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newIntegrationStore(t *testing.T) *S3Store {
	t.Helper()
	store, err := NewS3Store(s3IntegrationOptions(t))
	if err != nil {
		t.Fatalf("NewS3Store: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup of everything this run wrote.
		recs, _ := store.List(context.Background())
		for _, r := range recs {
			_ = store.Delete(context.Background(), r.Key)
		}
		_ = store.Close()
	})
	return store
}

func TestS3IntegrationRoundTrip(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	rec := Record{
		Key:         "sha256:integration-roundtrip",
		Origin:      "https://registry.example/pkg-1.0.0.tgz",
		ContentType: "application/octet-stream",
		ETag:        "abc123",
		CreatedAt:   now,
		ModTime:     now,
		AccessedAt:  now,
		Extra:       map[string]string{"team": "platform"},
	}
	content := []byte("integration content over a real object store")

	if _, err := store.Put(ctx, rec, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, got, err := store.Get(ctx, rec.Key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(data, content) {
		t.Fatalf("content mismatch: %q", data)
	}
	if got.Origin != rec.Origin || got.Extra["team"] != "platform" || got.Size != int64(len(content)) {
		t.Fatalf("metadata round-trip mismatch: %+v", got)
	}

	// SetAccessed then re-read.
	later := now.Add(time.Hour)
	if err := store.SetAccessed(ctx, rec.Key, later); err != nil {
		t.Fatalf("SetAccessed: %v", err)
	}
	if s, _ := store.Stat(ctx, rec.Key); !s.AccessedAt.Equal(later) {
		t.Fatalf("AccessedAt = %v, want %v", s.AccessedAt, later)
	}

	if err := store.Delete(ctx, rec.Key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Stat(ctx, rec.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat after delete = %v, want ErrNotFound", err)
	}
}

func TestS3IntegrationLargeBlob(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	size := spoolMemoryLimit + (2 << 20) // exceed the in-memory spool threshold
	content := bytes.Repeat([]byte("Z"), size)

	if _, err := store.Put(ctx, Record{Key: "sha256:big", CreatedAt: now, ModTime: now, AccessedAt: now}, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put large: %v", err)
	}
	rc, rec, err := store.Get(ctx, "sha256:big")
	if err != nil {
		t.Fatalf("Get large: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if rec.Size != int64(size) || !bytes.Equal(data, content) {
		t.Fatalf("large blob mismatch: size=%d want=%d equal=%v", rec.Size, size, bytes.Equal(data, content))
	}
}

func TestS3IntegrationList(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const n = 12
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("sha256:list-%02d", i)
		if _, err := store.Put(ctx, Record{Key: key, CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("x")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	recs, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("List returned %d, want %d", len(recs), n)
	}
}

// TestS3IntegrationCacheSharing exercises the full caching layer over S3 with HA
// store-fallback, verifying that a second "replica" serves content the first
// wrote out of band, and that single-flight coalesces concurrent loads.
func TestS3IntegrationCacheSharing(t *testing.T) {
	opts := s3IntegrationOptions(t)

	storeA, err := NewS3Store(opts)
	if err != nil {
		t.Fatalf("NewS3Store A: %v", err)
	}
	storeB, err := NewS3Store(opts) // same bucket+prefix => shared cache
	if err != nil {
		t.Fatalf("NewS3Store B: %v", err)
	}
	t.Cleanup(func() {
		recs, _ := storeA.List(context.Background())
		for _, r := range recs {
			_ = storeA.Delete(context.Background(), r.Key)
		}
		_ = storeA.Close()
		_ = storeB.Close()
	})

	replicaB, err := NewFilesystemCache(FilesystemOptions{Store: storeB, SharedStore: true})
	if err != nil {
		t.Fatalf("NewFilesystemCache B: %v", err)
	}
	defer replicaB.Close()
	ctx := context.Background()

	// Replica A writes directly to the shared bucket after B warmed its index.
	now := time.Now().UTC()
	if _, err := storeA.Put(ctx, Record{Key: "sha256:shared", CreatedAt: now, ModTime: now, AccessedAt: now}, strings.NewReader("from-A")); err != nil {
		t.Fatalf("A Put: %v", err)
	}

	// Replica B sees it via the store fallback.
	e, err := replicaB.Get(ctx, "sha256:shared")
	if err != nil {
		t.Fatalf("B Get shared: %v", err)
	}
	data, _ := io.ReadAll(e.Content)
	e.Content.Close()
	if string(data) != "from-A" {
		t.Fatalf("B read %q, want from-A", data)
	}

	// Single-flight: many concurrent GetOrLoad calls run the loader once.
	var loads int32
	var mu sync.Mutex
	loader := func(context.Context) (io.Reader, map[string]string, error) {
		mu.Lock()
		loads++
		mu.Unlock()
		return strings.NewReader("loaded"), nil, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := replicaB.GetOrLoad(ctx, "sha256:coalesce", loader)
			if err == nil {
				e.Content.Close()
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	got := loads
	mu.Unlock()
	if got != 1 {
		t.Fatalf("loader ran %d times, want 1", got)
	}
}
