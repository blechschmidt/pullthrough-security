package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// headerBackend serves a cacheable artifact whose fetch result carries response
// headers, and whose Resolved metadata may declare headers that must survive
// caching (backends.SetResponseHeader).
type headerBackend struct {
	body     []byte
	fetched  http.Header       // headers on the FetchResult
	declared map[string]string // headers declared via SetResponseHeader during Fetch
	fetches  int32
}

func (b *headerBackend) Name() string { return "hdr" }

func (b *headerBackend) Resolve(_ context.Context, req *backends.Request) (*backends.Resolved, error) {
	return &backends.Resolved{
		Coordinate:  backends.Coordinate{Name: "pkg", Version: "1.0.0"},
		UpstreamURL: "https://example.test" + req.Path,
		CacheKey:    "hdr:" + req.Path,
		Cacheable:   true,
		Metadata:    map[string]string{"backend": "hdr"},
	}, nil
}

func (b *headerBackend) Fetch(_ context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	atomic.AddInt32(&b.fetches, 1)
	for name, value := range b.declared {
		backends.SetResponseHeader(resolved.Metadata, name, value)
	}
	return &backends.FetchResult{
		Resolved: resolved,
		Content:  io.NopCloser(bytes.NewReader(b.body)),
		Size:     int64(len(b.body)),
		Header:   b.fetched.Clone(),
		Status:   http.StatusOK,
	}, nil
}

// TestCachedArtifactKeepsItsProtocolHeaders covers the headers that belong to an
// artifact rather than to one upstream response. A cacheable artifact is always
// served from its cache entry, so anything the backend set on the fetch result
// used to be dropped — on the very first response as well as on later hits.
// Found with real clients: the Hugging Face client refuses a file without
// X-Repo-Commit, and no client ever saw the X-Checksum-Verified header the
// documentation promises.
func TestCachedArtifactKeepsItsProtocolHeaders(t *testing.T) {
	b := &headerBackend{
		body: []byte("ARTIFACT"),
		fetched: http.Header{
			// A verification header the proxy generated: persisted automatically.
			"X-Checksum-Verified": {"sha256"},
			// Per-response upstream headers: must NOT be persisted.
			"Date":       {"Tue, 10 Nov 2026 00:00:00 GMT"},
			"Set-Cookie": {"session=abc"},
			"Age":        {"42"},
		},
		declared: map[string]string{
			// A header the backend declares part of the artifact's contract.
			"X-Repo-Commit": "f171d7baecaf37b5da5a3616d8833b9969753535",
			// Attempts to smuggle proxy-owned or hop-by-hop headers through the
			// cache must be ignored.
			"Content-Length":    "999999",
			"Content-Type":      "text/evil",
			"Transfer-Encoding": "chunked",
			"Connection":        "close",
		},
	}
	g := newGatewayWith(t, cache.NewMemoryCache(), b)
	h := g.routes()

	get := func(method string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, "/v1/hdr/pkg-1.0.0.tgz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status = %d (body %q)", method, rr.Code, rr.Body.String())
		}
		return rr
	}

	for i, step := range []struct {
		method    string
		wantCache string
	}{
		{http.MethodGet, "MISS"}, // the fetch that fills the cache
		{http.MethodGet, "HIT"},  // served from the cache entry
		{http.MethodHead, "HIT"}, // clients probe metadata with HEAD first
	} {
		rr := get(step.method)
		hdr := rr.Header()
		if got := hdr.Get("X-Cache"); got != step.wantCache {
			t.Fatalf("request %d: X-Cache = %q, want %q", i, got, step.wantCache)
		}
		if got := hdr.Get("X-Repo-Commit"); got != "f171d7baecaf37b5da5a3616d8833b9969753535" {
			t.Errorf("request %d (%s %s): X-Repo-Commit = %q, want the declared commit", i, step.method, step.wantCache, got)
		}
		if got := hdr.Get("X-Checksum-Verified"); got != "sha256" {
			t.Errorf("request %d (%s %s): X-Checksum-Verified = %q, want sha256", i, step.method, step.wantCache, got)
		}
		// Per-response upstream headers are not part of the artifact.
		for _, name := range []string{"Set-Cookie", "Age"} {
			if got := hdr.Get(name); got != "" {
				t.Errorf("request %d: per-response upstream header %s = %q was replayed from the cache", i, name, got)
			}
		}
		if got := hdr.Get("Date"); got == "Tue, 10 Nov 2026 00:00:00 GMT" {
			t.Errorf("request %d: the upstream's Date header was replayed from the cache", i)
		}
		// Proxy-owned and hop-by-hop headers come from the proxy, never the cache.
		if got := hdr.Get("Content-Type"); got == "text/evil" {
			t.Errorf("request %d: Content-Type was overridden from cache metadata", i)
		}
		if got := hdr.Get("Content-Length"); got == "999999" {
			t.Errorf("request %d: Content-Length was overridden from cache metadata", i)
		}
		if got := hdr.Get("Transfer-Encoding"); got != "" {
			t.Errorf("request %d: Transfer-Encoding %q was taken from cache metadata", i, got)
		}
		if got := hdr.Get("Connection"); got != "" {
			t.Errorf("request %d: Connection %q was taken from cache metadata", i, got)
		}
		if step.method == http.MethodGet && rr.Body.String() != "ARTIFACT" {
			t.Errorf("request %d: body = %q", i, rr.Body.String())
		}
	}
	if n := atomic.LoadInt32(&b.fetches); n != 1 {
		t.Errorf("upstream fetched %d times, want 1 (the hits must come from the cache)", n)
	}
}

func TestResponseHeaderMetadataHelpers(t *testing.T) {
	meta := map[string]string{"backend": "x"}
	backends.SetResponseHeader(meta, "x-repo-commit", "abc")
	backends.SetResponseHeader(meta, "X-Empty", "")     // ignored
	backends.SetResponseHeader(meta, "", "value")       // ignored
	backends.SetResponseHeader(nil, "X-Nil-Map", "abc") // must not panic

	got := backends.ResponseHeaders(meta)
	if len(got) != 1 || got["X-Repo-Commit"] != "abc" {
		t.Errorf("ResponseHeaders = %v, want only X-Repo-Commit=abc (canonicalized)", got)
	}
	if backends.ResponseHeaders(map[string]string{"backend": "x"}) != nil {
		t.Error("ResponseHeaders must be nil when nothing is declared")
	}
	if backends.ResponseHeaders(nil) != nil {
		t.Error("ResponseHeaders(nil) must be nil")
	}
}
