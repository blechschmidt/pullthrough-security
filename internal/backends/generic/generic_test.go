package generic

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// mockUpstream is a deterministic in-process stand-in for a declaratively
// proxied upstream. It serves a metadata document (carrying an absolute
// self-URL so rewriting can be exercised), an artifact with a correct and an
// incorrect sidecar, and a content-addressed blob whose path embeds its own
// SHA-256. It counts hits per path so tests can prove caching semantics.
type mockUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int

	artifact []byte
	casBlob  []byte
	casHex   string // SHA-256 of casBlob, set in newMockUpstream
}

func newMockUpstream() *mockUpstream {
	m := &mockUpstream{
		hits:     map[string]int{},
		artifact: []byte("generic-artifact-payload-v1\n"),
		casBlob:  []byte("content-addressed-blob-body\n"),
	}
	mux := http.NewServeMux()
	m.srv = httptest.NewServer(mux)

	sum := sha256.Sum256(m.artifact)
	artifactSHA256 := toHex(sum[:])
	sum512 := sha512.Sum512(m.artifact)
	artifactSHA512 := toHex(sum512[:])
	casSum := sha256.Sum256(m.casBlob)
	m.casHex = toHex(casSum[:])

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits[r.URL.Path]++
		m.mu.Unlock()

		switch r.URL.Path {
		case "/meta.json":
			w.Header().Set("Content-Type", "application/json")
			// Embed an absolute self-origin URL so rewrite can be verified.
			fmt.Fprintf(w, `{"name":"foo","dist":{"tarball":"%s/pkg/foo-1.0.tar.gz"}}`, m.srv.URL)
		case "/pkg/foo-1.0.tar.gz":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(m.artifact)
		case "/pkg/foo-1.0.tar.gz.sha256":
			fmt.Fprintln(w, artifactSHA256)
		case "/pkg/foo-1.0.tar.sha256": // replaces-extension sidecar (.gz → .sha256)
			fmt.Fprintf(w, "%s  foo-1.0.tar.gz\n", artifactSHA256)
		case "/pkg/foo-1.0.tar.gz.sha512":
			fmt.Fprintln(w, artifactSHA512)
		case "/pkg/bad-1.0.tar.gz":
			_, _ = w.Write(m.artifact)
		case "/pkg/bad-1.0.tar.gz.sha256":
			// Wrong digest: the sha256 of different bytes.
			bad := sha256.Sum256([]byte("different"))
			fmt.Fprintln(w, toHex(bad[:]))
		case "/pkg/nosidecar-1.0.tar.gz":
			_, _ = w.Write(m.artifact)
		case "/cas/" + m.casHex + "/blob":
			_, _ = w.Write(m.casBlob)
		default:
			http.NotFound(w, r)
		}
	})
	return m
}

func (m *mockUpstream) count(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits[path]
}

func (m *mockUpstream) close() { m.srv.Close() }

func newTestBackend(t *testing.T, m *mockUpstream, cfg BackendConfig, metrics *Metrics) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "mysource",
		UpstreamURL:   m.srv.URL,
		PublicBaseURL: "https://proxy.example/v1/mysource",
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "generic-test/1"),
		Config:        cfg,
		Metrics:       metrics,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func fetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		return nil, nil, err
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	if fr.NotModified {
		return fr, nil, nil
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	fr.Resolved = res
	return fr, body, rerr
}

func TestValidateRejectsUnsafeConfigs(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BackendConfig
		want string
	}{
		{"nil", nil, "configuration block is required"},
		{"no routes", &BackendConfig{}, "at least one route"},
		{"negative maxRewrite", &BackendConfig{MaxRewriteBytes: -1, Routes: []RouteConfig{{Match: "^/x$"}}}, "maxRewriteBytes"},
		{"empty match", &BackendConfig{Routes: []RouteConfig{{}}}, "match is required"},
		{"bad regexp", &BackendConfig{Routes: []RouteConfig{{Match: "("}}}, "invalid match regexp"},
		{"rewrite+cacheable", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Rewrite: true, Cacheable: true}}}, "mutually exclusive"},
		{"rewrite+verify", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Rewrite: true, Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"}}}}, "mutually exclusive"},
		{"unknown gate", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Gates: []string{"bogus"}}}}, "unknown content gate"},
		{"verify no algo", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{}}}}, "verify.algorithm is required"},
		{"verify bad algo", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{Algorithm: "md5", SidecarSuffix: ".md5"}}}}, "unsupported verify.algorithm"},
		{"sidecar no suffix", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{Algorithm: "sha256", Source: "sidecar"}}}}, "sidecarSuffix is required"},
		{"path no group", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{Algorithm: "sha256", Source: "path"}}}}, "digestGroup must be >= 1"},
		{"path group OOR", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{Algorithm: "sha256", Source: "path", DigestGroup: 2}}}}, "exceeds the 0 capture group"},
		{"bad source", &BackendConfig{Routes: []RouteConfig{{Match: "^/x$", Cacheable: true, Verify: &VerifyConfig{Algorithm: "sha256", Source: "url"}}}}, "unknown verify.source"},
		{"dup names", &BackendConfig{Routes: []RouteConfig{{Name: "a", Match: "^/x$"}, {Name: "a", Match: "^/y$"}}}, "duplicate route name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate("mysource")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateAcceptsGoodConfig(t *testing.T) {
	cfg := &BackendConfig{
		PublicBaseURL: "https://proxy.example/v1/mysource",
		Routes: []RouteConfig{
			{Name: "meta", Match: `^/meta\.json$`, Rewrite: true},
			{Name: "artifact", Match: `^/pkg/.+\.tar\.gz$`, Cacheable: true, Gates: []string{"contentscan", "avscan"}, Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"}},
			{Name: "cas", Match: `^/cas/([0-9a-f]{64})/blob$`, Cacheable: true, Verify: &VerifyConfig{Algorithm: "sha256", Source: "path", DigestGroup: 1}},
		},
	}
	if err := cfg.Validate("mysource"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	good := BackendConfig{Routes: []RouteConfig{{Match: "^/x$"}}}
	client := upstream.NewWithHTTPClient(http.DefaultClient, "t/1")

	if _, err := New(Options{Name: "", UpstreamURL: "https://x", Client: client, Config: good}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := New(Options{Name: "x", UpstreamURL: "ftp://x", Client: client, Config: good}); err == nil {
		t.Error("expected error for non-http scheme")
	}
	if _, err := New(Options{Name: "x", UpstreamURL: "https://x", Config: good}); err == nil {
		t.Error("expected error for nil client")
	}
	if _, err := New(Options{Name: "x", UpstreamURL: "https://x", Client: client, Config: BackendConfig{}}); err == nil {
		t.Error("expected error for empty routes")
	}
}

func TestResolveUnmatchedPathNotSupported(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{Routes: []RouteConfig{{Match: `^/pkg/.+$`}}}, &Metrics{})

	_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/nope", Query: url.Values{}})
	if !errors.Is(err, backends.ErrNotSupported) {
		t.Fatalf("Resolve error = %v, want ErrNotSupported", err)
	}
	if b.metrics.unmatched.Load() != 1 {
		t.Errorf("unmatched metric = %d, want 1", b.metrics.unmatched.Load())
	}
}

func TestMetadataRewriteNotCacheable(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	metrics := &Metrics{}
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{Name: "meta", Match: `^/meta\.json$`, Rewrite: true}},
	}, metrics)

	fr, body, rerr := fetch(t, b, "/meta.json")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if fr.Resolved.Cacheable {
		t.Error("metadata route must not be cacheable")
	}
	if strings.Contains(string(body), m.srv.URL) {
		t.Errorf("upstream URL not rewritten: %s", body)
	}
	if !strings.Contains(string(body), "https://proxy.example/v1/mysource/pkg/foo-1.0.tar.gz") {
		t.Errorf("rewritten public URL missing: %s", body)
	}
	if metrics.metadataRewrite.Load() != 1 {
		t.Errorf("metadataRewrite = %d, want 1", metrics.metadataRewrite.Load())
	}
}

func TestSidecarVerifiedArtifactCaches(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	metrics := &Metrics{}
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Name: "artifact", Match: `^/pkg/foo-.+\.tar\.gz$`, Cacheable: true,
			Gates:  []string{"contentscan"},
			Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"},
		}},
	}, metrics)

	fr, body, rerr := fetch(t, b, "/pkg/foo-1.0.tar.gz")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(body) != string(m.artifact) {
		t.Fatalf("body = %q, want %q", body, m.artifact)
	}
	if !fr.Resolved.Cacheable {
		t.Error("artifact route must be cacheable")
	}
	if got := fr.Resolved.Metadata[MetaChecksumVerified]; got != "sha256" {
		t.Errorf("checksumVerified = %q, want sha256", got)
	}
	if got := fr.Resolved.Metadata[MetaContentGates]; got != "contentscan" {
		t.Errorf("contentGates = %q, want contentscan", got)
	}
	if st := metrics.Stats(); st.ArtifactsVerified != 1 || st.SidecarsFetched != 1 {
		t.Errorf("metrics = %+v, want 1 verified + 1 sidecar", st)
	}
}

func TestSidecarReplacesExtension(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/pkg/foo-.+\.tar\.gz$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256", SidecarReplacesExtension: true},
		}},
	}, &Metrics{})

	// path.Ext on "/pkg/foo-1.0.tar.gz" strips ".gz" → the sidecar URL becomes
	// "/pkg/foo-1.0.tar.sha256", which the mock serves. A served (fail-closed)
	// artifact therefore implies the replace-extension sidecar was found and the
	// digest verified.
	fr, _, rerr := fetch(t, b, "/pkg/foo-1.0.tar.gz")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if got := fr.Resolved.Metadata[MetaChecksumVerified]; got != "sha256" {
		t.Errorf("checksumVerified = %q, want sha256 (replace-extension sidecar)", got)
	}
}

func TestSidecarMismatchRefused(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	metrics := &Metrics{}
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/pkg/bad-.+\.tar\.gz$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"},
		}},
	}, metrics)

	_, _, rerr := fetch(t, b, "/pkg/bad-1.0.tar.gz")
	var mm *ChecksumMismatchError
	if !errors.As(rerr, &mm) {
		t.Fatalf("read error = %v, want ChecksumMismatchError", rerr)
	}
	if metrics.checksumMismatch.Load() != 1 {
		t.Errorf("checksumMismatch = %d, want 1", metrics.checksumMismatch.Load())
	}
}

func TestVerifiedRouteMissingSidecarFailsClosed(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/pkg/nosidecar-.+\.tar\.gz$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256"},
		}},
	}, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/pkg/nosidecar-1.0.tar.gz", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := b.Fetch(context.Background(), res); err == nil {
		t.Fatal("expected Fetch to fail closed when no digest is recoverable")
	}
}

func TestVerifiedRouteMissingSidecarFailOpen(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	metrics := &Metrics{}
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/pkg/nosidecar-.+\.tar\.gz$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha256", SidecarSuffix: ".sha256", FailOpen: true},
		}},
	}, metrics)

	fr, body, rerr := fetch(t, b, "/pkg/nosidecar-1.0.tar.gz")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(body) != string(m.artifact) {
		t.Fatalf("body mismatch")
	}
	if got := fr.Resolved.Metadata[MetaChecksumVerified]; got != "none" {
		t.Errorf("checksumVerified = %q, want none", got)
	}
	if metrics.checksumMissing.Load() != 1 {
		t.Errorf("checksumMissing = %d, want 1", metrics.checksumMissing.Load())
	}
}

func TestPathSourceContentAddressed(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	metrics := &Metrics{}
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/cas/([0-9a-f]{64})/blob$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha256", Source: "path", DigestGroup: 1},
		}},
	}, metrics)

	fr, body, rerr := fetch(t, b, "/cas/"+m.casHex+"/blob")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(body) != string(m.casBlob) {
		t.Fatalf("body mismatch")
	}
	if got := fr.Resolved.Metadata[MetaChecksumVerified]; got != "sha256" {
		t.Errorf("checksumVerified = %q, want sha256", got)
	}
	if metrics.artifactsVerified.Load() != 1 {
		t.Errorf("artifactsVerified = %d, want 1", metrics.artifactsVerified.Load())
	}
	// No sidecar fetch for a path-embedded digest.
	if metrics.sidecarsFetched.Load() != 0 {
		t.Errorf("sidecarsFetched = %d, want 0 (digest was embedded in path)", metrics.sidecarsFetched.Load())
	}
}

func TestSHA512Verification(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{
			Match: `^/pkg/foo-.+\.tar\.gz$`, Cacheable: true,
			Verify: &VerifyConfig{Algorithm: "sha512", SidecarSuffix: ".sha512"},
		}},
	}, &Metrics{})

	fr, _, rerr := fetch(t, b, "/pkg/foo-1.0.tar.gz")
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if got := fr.Resolved.Metadata[MetaChecksumVerified]; got != "sha512" {
		t.Errorf("checksumVerified = %q, want sha512", got)
	}
}

func TestNonReadMethodNotCacheable(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{{Match: `^/pkg/.+$`, Cacheable: true}},
	}, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodPost, Path: "/pkg/foo-1.0.tar.gz", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Cacheable {
		t.Error("a non-read method must not be cacheable")
	}
}

func TestFirstMatchingRouteWins(t *testing.T) {
	m := newMockUpstream()
	defer m.close()
	b := newTestBackend(t, m, BackendConfig{
		Routes: []RouteConfig{
			{Name: "first", Match: `^/pkg/`, Cacheable: false},
			{Name: "second", Match: `^/pkg/foo`, Cacheable: true},
		},
	}, &Metrics{})

	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: "/pkg/foo-1.0.tar.gz", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Metadata[MetaRoute] != "first" {
		t.Errorf("matched route = %q, want first (ordered match)", res.Metadata[MetaRoute])
	}
	if res.Cacheable {
		t.Error("first route (non-cacheable) should have won")
	}
}
