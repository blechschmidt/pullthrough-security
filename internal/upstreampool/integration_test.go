package upstreampool_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/docker"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/upstreampool"
)

// blobServer is a minimal OCI blob endpoint that serves `body` (or, when down,
// a 503) for any /v2/.../blobs/<digest> request.
func blobServer(t *testing.T, body []byte, down bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "mirror down", http.StatusServiceUnavailable)
			return
		}
		if !strings.Contains(r.URL.Path, "/blobs/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCacheIntegrityIdenticalAcrossMirrors proves the Task 38 guarantee: the
// proxy's content-addressable verification holds regardless of which mirror
// served the bytes. The primary is down, so the Docker backend fails over to a
// mirror; the digest-verified content it returns is byte-identical to what the
// primary would have served, and a mirror that serves tampered bytes is rejected
// by the same digest check.
func TestCacheIntegrityIdenticalAcrossMirrors(t *testing.T) {
	content := []byte("layer-bytes: the same on every honest mirror\n")
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	blobPath := "/v2/library/demo/blobs/" + digest

	client, err := upstream.New(upstream.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Build a Docker backend whose request executor is a mirror pool: primary is
	// down (503), the good mirror serves the real bytes.
	primary := blobServer(t, content, true)
	goodMirror := blobServer(t, content, false)

	pool, err := upstreampool.New(upstreampool.Config{
		Backend: "dockerhub",
		Client:  client,
		Endpoints: []upstreampool.EndpointConfig{
			{ID: "primary", URL: primary.URL},
			{ID: "mirror", URL: goodMirror.URL},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := docker.New(docker.Options{
		Name:        "dockerhub",
		UpstreamURL: primary.URL,
		Client:      pool,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := fetchBlob(t, backend, blobPath)
	if string(got) != string(content) {
		t.Fatalf("mirror-served bytes differ from origin: got %q", got)
	}
	if snap := pool.Snapshot(); snap.FailoverTotal != 1 {
		t.Errorf("failoverTotal = %d, want 1 (primary down)", snap.FailoverTotal)
	}

	// A tampered mirror serving different bytes for the same digest must be
	// rejected by the content-addressable verifier — the security gate holds
	// independent of which mirror answered.
	tamperMirror := blobServer(t, []byte("evil substituted layer"), false)
	poolBad, err := upstreampool.New(upstreampool.Config{
		Backend: "dockerhub",
		Client:  client,
		Endpoints: []upstreampool.EndpointConfig{
			{ID: "primary", URL: primary.URL},
			{ID: "mirror", URL: tamperMirror.URL},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	backendBad, err := docker.New(docker.Options{
		Name:        "dockerhub",
		UpstreamURL: primary.URL,
		Client:      poolBad,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchBlobErr(t, backendBad, blobPath); err == nil {
		t.Fatal("expected digest-verification failure for tampered mirror bytes, got nil")
	}
}

func fetchBlob(t *testing.T, backend backends.Backend, path string) []byte {
	t.Helper()
	out, err := fetchBlobErr(t, backend, path)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return out
}

func fetchBlobErr(t *testing.T, backend backends.Backend, path string) ([]byte, error) {
	t.Helper()
	ctx := context.Background()
	resolved, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: path})
	if err != nil {
		return nil, err
	}
	res, err := backend.Fetch(ctx, resolved)
	if err != nil {
		return nil, err
	}
	defer res.Content.Close()
	return io.ReadAll(res.Content)
}
