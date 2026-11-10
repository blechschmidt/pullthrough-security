package docker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const testToken = "TEST-BEARER-TOKEN"

// fakeRegistry is an in-memory Docker Registry v2 stand-in that enforces the
// bearer-token handshake and records traffic for assertions.
type fakeRegistry struct {
	srv          *httptest.Server
	tokenFetches int64
	challenges   int64

	manifestListBody []byte
	imageManifest    []byte
	imageDigest      string
	blob             []byte
	blobDigest       string
	poisonedDigest   string // a blob digest whose served bytes deliberately mismatch
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	fr := &fakeRegistry{
		manifestListBody: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`),
		imageManifest:    []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`),
		blob:             []byte("layer-blob-contents"),
	}
	fr.imageDigest = sha256Digest(fr.imageManifest)
	fr.blobDigest = sha256Digest(fr.blob)
	fr.poisonedDigest = sha256Digest([]byte("the real bytes")) // server will serve different bytes

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fr.tokenFetches, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"`+testToken+`","expires_in":300}`)
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			atomic.AddInt64(&fr.challenges, 1)
			ref, _ := parseReference(r.URL.Path)
			scope := ref.scope()
			realm := fr.srv.URL + "/token"
			ch := `Bearer realm="` + realm + `",service="test-registry"`
			if scope != "" {
				ch += `,scope="` + scope + `"`
			}
			w.Header().Set("WWW-Authenticate", ch)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fr.serveAuthed(w, r)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRegistry) serveAuthed(w http.ResponseWriter, r *http.Request) {
	ref, ok := parseReference(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case ref.kind == refManifest && !ref.isDigest:
		// Tag: honor content negotiation by returning a multi-arch index.
		if !strings.Contains(r.Header.Get("Accept"), "index") {
			http.Error(w, "client did not accept an index", http.StatusNotAcceptable)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("Docker-Content-Digest", sha256Digest(fr.manifestListBody))
		_, _ = w.Write(fr.manifestListBody)
	case ref.kind == refManifest && ref.reference == fr.imageDigest:
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(fr.imageManifest)
	case ref.kind == refBlob && ref.reference == fr.blobDigest:
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fr.blob)
	case ref.kind == refBlob && ref.reference == fr.poisonedDigest:
		// Serve bytes that do NOT hash to the requested digest.
		_, _ = w.Write([]byte("POISONED PAYLOAD"))
	default:
		http.NotFound(w, r)
	}
}

func testBackend(t *testing.T, fr *fakeRegistry) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:        "dockerhub",
		UpstreamURL: fr.srv.URL,
		Client:      upstream.NewWithHTTPClient(fr.srv.Client(), "test/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// get resolves and fetches path, returning the resolved record, the fetch
// result, and the fully-read body.
func get(t *testing.T, b *Backend, method, path string, header http.Header) (*backends.Resolved, *backends.FetchResult, []byte, error) {
	t.Helper()
	req := &backends.Request{Method: method, Path: path, Header: header}
	resolved, err := b.Resolve(context.Background(), req)
	if err != nil {
		return nil, nil, nil, err
	}
	fr, err := b.Fetch(context.Background(), resolved)
	if err != nil {
		return resolved, nil, nil, err
	}
	if fr.Content == nil {
		return resolved, fr, nil, nil
	}
	defer fr.Content.Close()
	body, err := io.ReadAll(fr.Content)
	return resolved, fr, body, err
}

func acceptIndex() http.Header {
	return http.Header{"Accept": {"application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json"}}
}

func TestTokenHandshakeAndManifestList(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	resolved, fr, body, err := get(t, b, http.MethodGet, "/v2/library/nginx/manifests/latest", acceptIndex())
	if err != nil {
		t.Fatalf("fetch manifest list: %v", err)
	}
	if fr.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", fr.Status)
	}
	if string(body) != string(reg.manifestListBody) {
		t.Errorf("body = %q, want manifest list", body)
	}
	if !strings.Contains(fr.MediaType, "index") {
		t.Errorf("media type = %q, want an index type", fr.MediaType)
	}
	// A tag is mutable: it must not be cached.
	if resolved.Cacheable {
		t.Error("tag manifest should not be cacheable")
	}
	// The handshake should have occurred exactly once.
	if got := atomic.LoadInt64(&reg.tokenFetches); got != 1 {
		t.Errorf("tokenFetches = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&reg.challenges); got != 1 {
		t.Errorf("challenges = %d, want 1", got)
	}
}

func TestTokenCachingAvoidsRepeatHandshake(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	for i := 0; i < 3; i++ {
		if _, _, _, err := get(t, b, http.MethodGet, "/v2/library/nginx/manifests/latest", acceptIndex()); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	// Only the first request should be challenged; subsequent ones reuse the
	// cached token and are authorized proactively.
	if got := atomic.LoadInt64(&reg.tokenFetches); got != 1 {
		t.Errorf("tokenFetches = %d, want 1 (token should be cached)", got)
	}
	if got := atomic.LoadInt64(&reg.challenges); got != 1 {
		t.Errorf("challenges = %d, want 1 (only the first request lacks a token)", got)
	}
}

func TestManifestByDigestIsCacheableAndVerified(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	path := "/v2/library/nginx/manifests/" + reg.imageDigest
	resolved, fr, body, err := get(t, b, http.MethodGet, path, acceptIndex())
	if err != nil {
		t.Fatalf("fetch manifest by digest: %v", err)
	}
	if !resolved.Cacheable {
		t.Error("digest-addressed manifest should be cacheable")
	}
	if resolved.CacheKey != "dockerhub:manifests:"+reg.imageDigest {
		t.Errorf("cache key = %q", resolved.CacheKey)
	}
	if resolved.Digest != reg.imageDigest {
		t.Errorf("digest = %q, want %q", resolved.Digest, reg.imageDigest)
	}
	if string(body) != string(reg.imageManifest) {
		t.Errorf("body mismatch")
	}
	_ = fr
}

func TestBlobIsCacheableVerifiedAndKeyedByDigest(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	path := "/v2/library/nginx/blobs/" + reg.blobDigest
	resolved, _, body, err := get(t, b, http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("fetch blob: %v", err)
	}
	if !resolved.Cacheable {
		t.Error("blob should be cacheable")
	}
	if resolved.CacheKey != "dockerhub:blobs:"+reg.blobDigest {
		t.Errorf("cache key = %q, want digest-keyed", resolved.CacheKey)
	}
	if string(body) != string(reg.blob) {
		t.Errorf("blob body = %q, want %q", body, reg.blob)
	}
}

func TestDigestVerificationRejectsPoisonedBlob(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	path := "/v2/library/nginx/blobs/" + reg.poisonedDigest
	_, _, _, err := get(t, b, http.MethodGet, path, nil)
	if err == nil {
		t.Fatal("expected a digest mismatch error for poisoned content, got nil")
	}
	var mism *DigestMismatchError
	if !errors.As(err, &mism) {
		t.Fatalf("error = %v, want *DigestMismatchError", err)
	}
}

func TestUpstreamErrorRelayedAsStatusError(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	// A manifest digest the registry does not serve -> 404.
	missing := sha256Digest([]byte("does-not-exist"))
	path := "/v2/library/nginx/manifests/" + missing
	_, _, _, err := get(t, b, http.MethodGet, path, acceptIndex())
	if err == nil {
		t.Fatal("expected an error for a missing manifest")
	}
	se, ok := backends.AsStatusError(err)
	if !ok {
		t.Fatalf("error = %v, want *backends.StatusError", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", se.Status)
	}
}

func TestNonV2PathNotSupported(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/not-a-registry-path"})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
}

// TestAcceptHeaderLinesAreFolded covers how the Docker Engine negotiates: it
// sends one Accept header LINE per manifest media type rather than a single
// comma-separated value. Forwarding only the first line narrowed the negotiation
// to one type, so a registry holding the tag as an OCI index answered 404/406
// (found pulling ghcr.io images through the proxy with a real dockerd).
func TestAcceptHeaderLinesAreFolded(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	// The index media type is only on the third line; the first line alone would
	// make the fake registry refuse the request.
	multiLine := http.Header{"Accept": {
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}}
	if _, _, _, err := get(t, b, http.MethodGet, "/v2/library/nginx/manifests/latest", multiLine); err != nil {
		t.Fatalf("multi-line Accept was not forwarded in full: %v", err)
	}

	if got, want := acceptHeader(multiLine), "application/vnd.docker.distribution.manifest.v2+json, "+
		"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json"; got != want {
		t.Errorf("acceptHeader = %q, want %q", got, want)
	}
	if got := acceptHeader(nil); got != "" {
		t.Errorf("acceptHeader(nil) = %q, want empty", got)
	}
	if got := acceptHeader(http.Header{}); got != "" {
		t.Errorf("acceptHeader(no Accept) = %q, want empty", got)
	}
}

func TestAcceptHeaderForwardedForMultiArch(t *testing.T) {
	reg := newFakeRegistry(t)
	b := testBackend(t, reg)

	// Without an index in Accept, the fake registry refuses the tag request with
	// 406 — proving the Accept header is forwarded upstream.
	_, _, _, err := get(t, b, http.MethodGet, "/v2/library/nginx/manifests/latest",
		http.Header{"Accept": {"text/plain"}})
	if err == nil {
		t.Fatal("expected upstream to reject a non-index Accept")
	}
	se, ok := backends.AsStatusError(err)
	if !ok || se.Status != http.StatusNotAcceptable {
		t.Fatalf("error = %v, want 406 StatusError", err)
	}
}
