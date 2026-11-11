package httpbackend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func testClient() *upstream.Client {
	return upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
}

func newBackend(t *testing.T, opts Options) *Backend {
	t.Helper()
	if opts.Client == nil {
		opts.Client = testClient()
	}
	b, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"missing name", Options{BaseURL: "https://x", Client: testClient()}},
		{"missing base", Options{Name: "n", Client: testClient()}},
		{"missing client", Options{Name: "n", BaseURL: "https://x"}},
		{"bad scheme", Options{Name: "n", BaseURL: "ftp://x", Client: testClient()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.opts); err == nil {
				t.Errorf("New(%s) = nil error, want error", c.name)
			}
		})
	}
}

func TestResolvePassthrough(t *testing.T) {
	b := newBackend(t, Options{Name: "npm", BaseURL: "https://registry.npmjs.org"})
	req := &backends.Request{Method: http.MethodGet, Path: "/lodash/-/lodash-4.17.21.tgz"}

	res, err := b.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"; res.UpstreamURL != want {
		t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, want)
	}
	if !res.Cacheable {
		t.Errorf("GET should be cacheable by default")
	}
	if res.CacheKey != "npm:lodash/-/lodash-4.17.21.tgz" {
		t.Errorf("CacheKey = %q", res.CacheKey)
	}
}

func TestResolvePreservesBasePathPrefix(t *testing.T) {
	b := newBackend(t, Options{Name: "maven", BaseURL: "https://repo.example.com/repository/maven"})
	res, err := b.Resolve(context.Background(), &backends.Request{Path: "/org/foo/1.0/foo-1.0.jar"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "https://repo.example.com/repository/maven/org/foo/1.0/foo-1.0.jar"; res.UpstreamURL != want {
		t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestResolveCustomRouter(t *testing.T) {
	router := func(req *backends.Request) (string, url.Values) {
		return "/simple" + req.Path + "/", nil
	}
	b := newBackend(t, Options{Name: "pip", BaseURL: "https://pypi.org", Router: router})
	res, err := b.Resolve(context.Background(), &backends.Request{Path: "/requests"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := "https://pypi.org/simple/requests/"; res.UpstreamURL != want {
		t.Errorf("UpstreamURL = %q, want %q", res.UpstreamURL, want)
	}
}

func TestResolveCacheableKeyIgnoresQueryButNonCacheableIncludesIt(t *testing.T) {
	// Cacheable: query excluded from the key so the same artifact dedupes.
	cacheable := newBackend(t, Options{Name: "go", BaseURL: "https://proxy.golang.org"})
	res, err := cacheable.Resolve(context.Background(), &backends.Request{
		Path:  "/mod/@v/v1.0.0.zip",
		Query: url.Values{"trace": {"1"}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strings.Contains(res.CacheKey, "trace") {
		t.Errorf("cacheable CacheKey should not include query, got %q", res.CacheKey)
	}

	// Non-cacheable: query included so short-lived entries do not collide.
	never := newBackend(t, Options{
		Name:      "search",
		BaseURL:   "https://example.com",
		Cacheable: func(*backends.Request) bool { return false },
	})
	res2, err := never.Resolve(context.Background(), &backends.Request{
		Path:  "/search",
		Query: url.Values{"q": {"abc"}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res2.Cacheable {
		t.Fatal("expected non-cacheable")
	}
	if !strings.Contains(res2.CacheKey, "q=abc") {
		t.Errorf("non-cacheable CacheKey should include query, got %q", res2.CacheKey)
	}
}

func TestResolveNilRequest(t *testing.T) {
	b := newBackend(t, Options{Name: "n", BaseURL: "https://x"})
	if _, err := b.Resolve(context.Background(), nil); err == nil {
		t.Error("expected error for nil request")
	}
}

func TestResolveHonorsCanceledContext(t *testing.T) {
	b := newBackend(t, Options{Name: "n", BaseURL: "https://x"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Resolve(ctx, &backends.Request{Path: "/x"}); err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestFetchSuccess(t *testing.T) {
	var (
		gotPath string
		gotAuth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"deadbeef"`)
		w.Header().Set("Cache-Control", "immutable")
		_, _ = io.WriteString(w, "PACKAGE-BYTES")
	}))
	defer srv.Close()

	b := newBackend(t, Options{
		Name:        "npm",
		BaseURL:     srv.URL,
		Credentials: upstream.Credentials{Token: "secret-token"},
	})
	res, err := b.Resolve(context.Background(), &backends.Request{Path: "/pkg/-/pkg-1.0.0.tgz"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer fr.Content.Close()

	if gotPath != "/pkg/-/pkg-1.0.0.tgz" {
		t.Errorf("upstream path = %q", gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("upstream Authorization = %q, want injected credentials", gotAuth)
	}
	if fr.MediaType != "application/octet-stream" {
		t.Errorf("MediaType = %q", fr.MediaType)
	}
	if fr.Header.Get("ETag") != `"deadbeef"` {
		t.Errorf("ETag header not preserved: %q", fr.Header.Get("ETag"))
	}
	if fr.Header.Get("Cache-Control") != "immutable" {
		t.Errorf("Cache-Control should be propagated, got %q", fr.Header.Get("Cache-Control"))
	}
	body, _ := io.ReadAll(fr.Content)
	if string(body) != "PACKAGE-BYTES" {
		t.Errorf("body = %q", body)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = io.WriteString(w, "fresh")
	}))
	defer srv.Close()

	b := newBackend(t, Options{Name: "n", BaseURL: srv.URL})
	res, _ := b.Resolve(context.Background(), &backends.Request{Path: "/index"})
	res.IfNoneMatch = `"v1"`

	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !fr.NotModified {
		t.Fatalf("NotModified = false, want true")
	}
	if fr.Status != http.StatusNotModified {
		t.Errorf("Status = %d, want 304", fr.Status)
	}
	if fr.Content != nil {
		t.Errorf("Content should be nil on 304")
	}
}

func TestFetchStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such package", http.StatusNotFound)
	}))
	defer srv.Close()

	b := newBackend(t, Options{Name: "n", BaseURL: srv.URL})
	res, _ := b.Resolve(context.Background(), &backends.Request{Path: "/missing"})

	_, err := b.Fetch(context.Background(), res)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	se, ok := backends.AsStatusError(err)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", err)
	}
	if se.Status != http.StatusNotFound {
		t.Errorf("StatusError.Status = %d, want 404", se.Status)
	}
	if !strings.Contains(se.Body, "no such package") {
		t.Errorf("StatusError.Body = %q, want upstream snippet", se.Body)
	}
}

func TestFetchNilResolved(t *testing.T) {
	b := newBackend(t, Options{Name: "n", BaseURL: "https://x"})
	if _, err := b.Fetch(context.Background(), nil); err == nil {
		t.Error("expected error for nil resolved")
	}
}

func TestName(t *testing.T) {
	b := newBackend(t, Options{Name: "cargo", BaseURL: "https://crates.io"})
	if b.Name() != "cargo" {
		t.Errorf("Name() = %q, want cargo", b.Name())
	}
}

func TestIndexRewrite(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tarball":"UPSTREAM/pkg.tgz"}`)
	}))
	defer srv.Close()

	b := newBackend(t, Options{
		Name:          "npm",
		BaseURL:       srv.URL,
		ForwardAccept: true,
		Index:         func(req *backends.Request) bool { return !strings.Contains(req.Path, "/-/") },
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			return []byte(strings.ReplaceAll(string(body), "UPSTREAM", "PROXY")), nil
		},
	})

	req := &backends.Request{Path: "/pkg", Header: http.Header{"Accept": {"application/json"}}}
	res, err := b.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer fr.Content.Close()
	body, _ := io.ReadAll(fr.Content)
	if string(body) != `{"tarball":"PROXY/pkg.tgz"}` {
		t.Errorf("body not rewritten: %s", body)
	}
	if fr.Size != int64(len(body)) {
		t.Errorf("Size = %d, want %d (rewritten length)", fr.Size, len(body))
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept not forwarded for index request: %q", gotAccept)
	}
}

func TestIndexPredicateNotRewritingArtifacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT-UPSTREAM")
	}))
	defer srv.Close()

	rewritten := false
	b := newBackend(t, Options{
		Name:    "npm",
		BaseURL: srv.URL,
		Index:   func(req *backends.Request) bool { return !strings.Contains(req.Path, "/-/") },
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			rewritten = true
			return body, nil
		},
	})

	// Artifact path: must stream unmodified without invoking Rewrite.
	res, _ := b.Resolve(context.Background(), &backends.Request{Path: "/pkg/-/pkg-1.0.0.tgz"})
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer fr.Content.Close()
	body, _ := io.ReadAll(fr.Content)
	if string(body) != "ARTIFACT-UPSTREAM" {
		t.Errorf("artifact body = %q", body)
	}
	if rewritten {
		t.Error("Rewrite must not be called for non-index (artifact) requests")
	}
}

func TestAbsoluteRouter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdn/artifact" {
			_, _ = io.WriteString(w, "CDN-BYTES")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	b := newBackend(t, Options{
		Name:    "pip",
		BaseURL: "https://index.example.com",
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			if strings.HasPrefix(req.Path, "/files/") {
				return srv.URL + "/cdn/artifact", true
			}
			return "", false
		},
	})

	res, err := b.Resolve(context.Background(), &backends.Request{Path: "/files/x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.UpstreamURL != srv.URL+"/cdn/artifact" {
		t.Errorf("AbsoluteRouter URL = %q", res.UpstreamURL)
	}
	// Cache key must be host-qualified so distinct CDN hosts never collide.
	if !strings.Contains(res.CacheKey, "/cdn/artifact") {
		t.Errorf("CacheKey = %q, want host-qualified path", res.CacheKey)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer fr.Content.Close()
	body, _ := io.ReadAll(fr.Content)
	if string(body) != "CDN-BYTES" {
		t.Errorf("body = %q", body)
	}
}

func TestAbsoluteRouterRejectsBadScheme(t *testing.T) {
	b := newBackend(t, Options{
		Name:    "pip",
		BaseURL: "https://index.example.com",
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			return "ftp://evil.example.com/x", true
		},
	})
	if _, err := b.Resolve(context.Background(), &backends.Request{Path: "/files/x"}); err == nil {
		t.Error("expected error for non-http(s) absolute URL")
	}
}

// Resolve reports what the Classify callback says the request addresses. The
// callback sees the inbound request — not the routed upstream path — and is
// consulted for absolutely routed requests too.
func TestResolveClassify(t *testing.T) {
	var seen []string
	b := newBackend(t, Options{
		Name:    "eco",
		BaseURL: "https://index.example.com",
		Router: func(req *backends.Request) (string, url.Values) {
			return "/routed" + req.Path, nil
		},
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			if strings.HasPrefix(req.Path, "/dl/") {
				return "https://cdn.example.com/blob", true
			}
			return "", false
		},
		Classify: func(req *backends.Request) backends.Artifact {
			seen = append(seen, req.Path)
			switch {
			case strings.HasSuffix(req.Path, ".tgz"):
				return backends.Payload()
			case strings.HasSuffix(req.Path, "/download"):
				return backends.PayloadNamed("pkg-1.0.0.crate")
			case strings.HasSuffix(req.Path, ".json"):
				return backends.Metadata()
			}
			return backends.Artifact{}
		},
	})

	cases := []struct {
		path     string
		want     backends.Artifact
		wantURL  string
		wantFile string // what the gates take as the artifact's file name
	}{
		{"/pkg/-/pkg-1.0.0.tgz", backends.Payload(), "https://index.example.com/routed/pkg/-/pkg-1.0.0.tgz", "pkg-1.0.0.tgz"},
		{"/dl/pkg/1.0.0/download", backends.PayloadNamed("pkg-1.0.0.crate"), "https://cdn.example.com/blob", "pkg-1.0.0.crate"},
		{"/pkg/index.json", backends.Metadata(), "https://index.example.com/routed/pkg/index.json", "index.json"},
		{"/-/v1/search", backends.Artifact{}, "https://index.example.com/routed/-/v1/search", "search"},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", c.path, err)
		}
		if res.Artifact != c.want {
			t.Errorf("Resolve(%s).Artifact = %+v, want %+v", c.path, res.Artifact, c.want)
		}
		if res.UpstreamURL != c.wantURL {
			t.Errorf("Resolve(%s).UpstreamURL = %q, want %q", c.path, res.UpstreamURL, c.wantURL)
		}
		if got := res.ArtifactFilename(); got != c.wantFile {
			t.Errorf("Resolve(%s).ArtifactFilename() = %q, want %q", c.path, got, c.wantFile)
		}
	}
	if want := []string{"/pkg/-/pkg-1.0.0.tgz", "/dl/pkg/1.0.0/download", "/pkg/index.json", "/-/v1/search"}; strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Errorf("Classify saw %q, want the inbound paths %q", seen, want)
	}
}

// Without a Classify callback the engine makes no statement about any resource:
// a metadata claim must come from an ecosystem's grammar, never from a default.
func TestResolveWithoutClassifyLeavesUnclassified(t *testing.T) {
	b := newBackend(t, Options{Name: "npm", BaseURL: "https://registry.npmjs.org"})
	for _, path := range []string{"/lodash/-/lodash-4.17.21.tgz", "/lodash", "/index.json", "/"} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", path, err)
		}
		if res.Artifact != (backends.Artifact{}) {
			t.Errorf("Resolve(%s).Artifact = %+v, want the zero value", path, res.Artifact)
		}
		if res.Artifact.Class != backends.ArtifactUnclassified {
			t.Errorf("Resolve(%s) class = %s, want unclassified", path, res.Artifact.Class)
		}
	}
}
