package homebrew

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func sha256Hex(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// --- path classification ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		path string
		want resourceKind
	}{
		{"/api/formula.json", kindIndex},
		{"/api/formula/wget.json", kindFormula},
		{"/api/formula/openssl@3.json", kindFormula},
		{"/api/cask.json", kindMetadata},
		{"/api/cask/firefox.json", kindMetadata},
		{"/api/formula.jws.json", kindMetadata},
		{"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + strings.Repeat("a", 64), kindBottle},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) returned ok=false", c.path)
			continue
		}
		if res.kind != c.want {
			t.Errorf("classify(%q).kind = %v, want %v", c.path, res.kind, c.want)
		}
	}

	for _, bad := range []string{
		"", "/", "////",
		"/other/thing",
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:short",                   // bad digest
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/manifests/latest",                     // not a blob
		"/bottle/wget/1.21.4/homebrew/core/wget/blobs/sha256:" + strings.Repeat("a", 64), // missing v2
		"/bottle/wget/1.21.4/v2/blobs/sha256:" + strings.Repeat("a", 64),                 // empty repo
		"/bottle/wget",       // too short
		"/api/../etc/passwd", // traversal
		"/bottle/wget/1.21.4/v2/x/../blobs/sha256:" + strings.Repeat("a", 64),
	} {
		if _, ok := classify(bad); ok {
			t.Errorf("classify(%q) unexpectedly ok", bad)
		}
	}
}

func TestClassifyBottleFields(t *testing.T) {
	digest := strings.Repeat("b", 64)
	res, ok := classify("/bottle/openssl@3/3.2.1/v2/homebrew/core/openssl/3/blobs/sha256:" + digest)
	if !ok {
		t.Fatal("classify failed")
	}
	if res.name != "openssl@3" || res.version != "3.2.1" {
		t.Errorf("name/version = %q/%q", res.name, res.version)
	}
	if res.repo != "homebrew/core/openssl/3" {
		t.Errorf("repo = %q", res.repo)
	}
	if res.digest != digest {
		t.Errorf("digest = %q", res.digest)
	}
	if res.blobPath != "v2/homebrew/core/openssl/3/blobs/sha256:"+digest {
		t.Errorf("blobPath = %q", res.blobPath)
	}
}

// --- bottle-URL rewriting ---------------------------------------------------

func TestRewriteBottleURLs(t *testing.T) {
	digest := strings.Repeat("c", 64)
	ghcr := "https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:" + digest
	doc := map[string]any{
		"name":     "wget",
		"versions": map[string]any{"stable": "1.21.4"},
		"bottle": map[string]any{
			"stable": map[string]any{
				"root_url": "https://ghcr.io/v2/homebrew/core",
				"files": map[string]any{
					"arm64_sonoma": map[string]any{"url": ghcr, "sha256": digest},
				},
			},
		},
		// An unmodeled field must be preserved verbatim.
		"desc": "Internet file retriever",
	}
	data, _ := json.Marshal(doc)

	out, n := rewriteBottleURLs(data, "https://proxy.example/v1/homebrew", "ghcr.io")
	if n != 1 {
		t.Fatalf("rewrote %d URLs, want 1", n)
	}
	want := "https://proxy.example/v1/homebrew/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest
	if !strings.Contains(string(out), want) {
		t.Errorf("rewritten doc missing %q:\n%s", want, out)
	}
	if strings.Contains(string(out), ghcr) {
		t.Errorf("rewritten doc still contains the original ghcr URL")
	}
	if !strings.Contains(string(out), "Internet file retriever") {
		t.Errorf("rewrite dropped an unmodeled field")
	}
}

func TestRewriteFullIndexArray(t *testing.T) {
	d1 := strings.Repeat("1", 64)
	d2 := strings.Repeat("2", 64)
	u1 := "https://ghcr.io/v2/homebrew/core/a/blobs/sha256:" + d1
	u2 := "https://ghcr.io/v2/homebrew/core/b/blobs/sha256:" + d2
	arr := fmt.Sprintf(`[`+
		`{"name":"a","versions":{"stable":"1.0"},"bottle":{"stable":{"files":{"x":{"url":%q,"sha256":%q}}}}},`+
		`{"name":"b","versions":{"stable":"2.0"},"bottle":{"stable":{"files":{"y":{"url":%q,"sha256":%q}}}}}`+
		`]`, u1, d1, u2, d2)
	out, n := rewriteBottleURLs([]byte(arr), "https://proxy.example/v1/homebrew", "ghcr.io")
	if n != 2 {
		t.Fatalf("rewrote %d URLs, want 2", n)
	}
	for _, want := range []string{
		"https://proxy.example/v1/homebrew/bottle/a/1.0/v2/homebrew/core/a/blobs/sha256:" + d1,
		"https://proxy.example/v1/homebrew/bottle/b/2.0/v2/homebrew/core/b/blobs/sha256:" + d2,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rewritten index missing %q", want)
		}
	}
}

func TestRewriteSkipsOffRegistryHost(t *testing.T) {
	digest := strings.Repeat("d", 64)
	other := "https://evil.example/v2/homebrew/core/wget/blobs/sha256:" + digest
	doc := fmt.Sprintf(`{"name":"wget","versions":{"stable":"1.0"},"bottle":{"stable":{"files":{"x":{"url":%q,"sha256":%q}}}}}`, other, digest)
	out, n := rewriteBottleURLs([]byte(doc), "https://proxy.example/v1/homebrew", "ghcr.io")
	if n != 0 {
		t.Errorf("rewrote %d URLs, want 0 (off-registry host)", n)
	}
	if !strings.Contains(string(out), other) {
		t.Error("off-registry URL must be left unchanged")
	}
}

func TestRewriteNonJSONFailOpen(t *testing.T) {
	raw := []byte("not json at all")
	out, n := rewriteBottleURLs(raw, "https://proxy.example/v1/homebrew", "ghcr.io")
	if n != 0 || string(out) != string(raw) {
		t.Errorf("non-JSON input must be returned unchanged")
	}
}

// --- integration: fake formulae API + fake ghcr registry --------------------

type fakeEnv struct {
	formulae *httptest.Server
	ghcr     *httptest.Server
	backend  *Backend
	metrics  *Metrics
}

func newFakeEnv(t *testing.T, bottle []byte, tamperedDigest bool) *fakeEnv {
	t.Helper()
	env := &fakeEnv{metrics: &Metrics{}}

	digest := sha256Hex(bottle)
	manifestDigest := digest
	if tamperedDigest {
		// The manifest records a digest for different bytes than ghcr serves.
		manifestDigest = sha256Hex([]byte("a different bottle"))
	}

	// Fake ghcr: a bearer-token handshake guards the blob endpoint.
	ghcrMux := http.NewServeMux()
	env.ghcr = httptest.NewServer(ghcrMux)
	t.Cleanup(env.ghcr.Close)
	ghcrMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "test-token", "expires_in": 300})
	})
	ghcrMux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="%s/token",service="ghcr.io",scope="repository:homebrew/core/wget:pull"`, env.ghcr.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(bottle)
	})

	// Fake formulae API: one formula whose bottle URL points at fake ghcr.
	formMux := http.NewServeMux()
	env.formulae = httptest.NewServer(formMux)
	t.Cleanup(env.formulae.Close)
	bottleURL := env.ghcr.URL + "/v2/homebrew/core/wget/blobs/sha256:" + manifestDigest
	formMux.HandleFunc("/api/formula/wget.json", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"name":     "wget",
			"versions": map[string]any{"stable": "1.21.4"},
			"bottle": map[string]any{
				"stable": map[string]any{
					"files": map[string]any{
						"arm64_sonoma": map[string]any{"url": bottleURL, "sha256": manifestDigest},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	b, err := New(Options{
		Name:              "homebrew",
		UpstreamURL:       env.formulae.URL,
		PublicBaseURL:     "https://proxy.example/v1/homebrew",
		BottleRegistryURL: env.ghcr.URL,
		Client:            upstream.NewWithHTTPClient(env.formulae.Client(), "test/1"),
		Metrics:           env.metrics,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.backend = b
	return env
}

func resolveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	var rerr error
	if fres.Content != nil {
		body, rerr = io.ReadAll(fres.Content)
		_ = fres.Content.Close()
	}
	fres.Resolved = res
	return fres, body, rerr
}

func TestServeFormulaRewritesBottleURL(t *testing.T) {
	env := newFakeEnv(t, []byte("\x1f\x8b fake bottle tarball"), false)
	fres, body, err := resolveFetch(t, env.backend, "/api/formula/wget.json")
	if err != nil {
		t.Fatalf("fetch formula: %v", err)
	}
	if fres.Resolved.Cacheable {
		t.Error("formula metadata must not be cacheable")
	}
	if !strings.Contains(string(body), "https://proxy.example/v1/homebrew/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:") {
		t.Errorf("formula not rewritten:\n%s", body)
	}
	if env.metrics.Stats().FormulaRewritten != 1 {
		t.Errorf("FormulaRewritten = %v, want 1", env.metrics.Stats().FormulaRewritten)
	}
}

func TestServeBottleVerified(t *testing.T) {
	bottle := []byte("\x1f\x8b a real homebrew bottle payload")
	env := newFakeEnv(t, bottle, false)
	digest := sha256Hex(bottle)
	path := "/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest

	fres, body, err := resolveFetch(t, env.backend, path)
	if err != nil {
		t.Fatalf("fetch bottle: %v", err)
	}
	if !fres.Resolved.Cacheable {
		t.Error("bottle must be cacheable")
	}
	if string(body) != string(bottle) {
		t.Errorf("served bottle bytes mismatch")
	}
	if fres.Resolved.Coordinate.Name != "wget" || fres.Resolved.Coordinate.Version != "1.21.4" {
		t.Errorf("coordinate = %+v", fres.Resolved.Coordinate)
	}
	if fres.Resolved.CacheKey != "homebrew:bottle:sha256:"+digest {
		t.Errorf("cache key = %q", fres.Resolved.CacheKey)
	}
	s := env.metrics.Stats()
	if s.BottlesServed != 1 || s.BottlesVerified != 1 || s.TokensFetched != 1 {
		t.Errorf("metrics = %+v", s)
	}
}

func TestServeBottleDigestMismatch(t *testing.T) {
	bottle := []byte("the bytes ghcr actually serves")
	env := newFakeEnv(t, bottle, true) // manifest records a different digest
	// The requested path carries the (tampered) manifest digest; the served bytes
	// hash to something else, so verification must fail.
	manifestDigest := sha256Hex([]byte("a different bottle"))
	path := "/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + manifestDigest

	_, _, err := resolveFetch(t, env.backend, path)
	if err == nil {
		t.Fatal("expected a digest-mismatch error")
	}
	var mm *DigestMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("error = %v, want *DigestMismatchError", err)
	}
	if env.metrics.Stats().BottleHashMismatch != 1 {
		t.Errorf("BottleHashMismatch = %v, want 1", env.metrics.Stats().BottleHashMismatch)
	}
}

func TestServeCaskPassthrough(t *testing.T) {
	env := newFakeEnv(t, []byte("x"), false)
	// Register a cask document on the formulae server.
	// (newFakeEnv's mux only has /api/formula/wget.json; add cask here.)
	env.formulae.Config.Handler.(*http.ServeMux).HandleFunc("/api/cask/firefox.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"firefox","url":"https://download.example/firefox.dmg"}`))
	})
	_, body, err := resolveFetch(t, env.backend, "/api/cask/firefox.json")
	if err != nil {
		t.Fatalf("fetch cask: %v", err)
	}
	if !strings.Contains(string(body), "firefox.dmg") {
		t.Errorf("cask passthrough body = %s", body)
	}
	if env.metrics.Stats().MetadataServed != 1 {
		t.Errorf("MetadataServed = %v, want 1", env.metrics.Stats().MetadataServed)
	}
}

func TestNewValidation(t *testing.T) {
	client := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	bad := []Options{
		{Name: "", UpstreamURL: "https://x", Client: client},
		{Name: "h", UpstreamURL: "", Client: client},
		{Name: "h", UpstreamURL: "ftp://x", Client: client},
		{Name: "h", UpstreamURL: "https://x", Client: nil},
		{Name: "h", UpstreamURL: "https://x", BottleRegistryURL: "ftp://y", Client: client},
	}
	for i, o := range bad {
		if _, err := New(o); err == nil {
			t.Errorf("New(bad #%d) = nil error", i)
		}
	}
	b, err := New(Options{Name: "h", UpstreamURL: "https://formulae.brew.sh", Client: client})
	if err != nil {
		t.Fatalf("New(valid): %v", err)
	}
	if b.registryHost != "ghcr.io" {
		t.Errorf("default registry host = %q, want ghcr.io", b.registryHost)
	}
}

func TestResolveUnsupported(t *testing.T) {
	b, _ := New(Options{Name: "h", UpstreamURL: "https://formulae.brew.sh",
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "t")})
	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/nope", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Errorf("err = %v, want ErrNotSupported", err)
	}
}
