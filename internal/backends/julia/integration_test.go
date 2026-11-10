//go:build integration
// +build integration

// Integration tests for the Julia backend against the live public Pkg Server
// (https://pkg.julialang.org). Gated behind the `integration` build tag (and
// skipped when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/julia/
package julia

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const livePkgServer = "https://pkg.julialang.org"

// A stable, immutable coordinate: Example.jl v0.5.3's source tree hash, recorded
// in the General registry Versions.toml. Because it is content-addressed, it
// never changes, so the backend's recomputed git-tree-sha1 must match it.
const (
	liveExampleUUID    = "7876af07-990d-54b4-ab0e-23690620f79a"
	liveExampleTreeSHA = "46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc"
)

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 90 * time.Second}
	b, err := New(Options{
		Name:        "julia-live",
		UpstreamURL: livePkgServer,
		Client:      upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:     m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func skipIfOffline(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		t.Skipf("network unavailable: %v", err)
	}
}

func liveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("Fetch(%q): %v", path, err)
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	if rerr != nil {
		var mm *TreeHashMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live content failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	fr.Resolved = res
	return fr, body
}

// TestLivePackageVerification downloads a real package source tarball by its
// immutable git-tree-sha1 and confirms the backend recomputed and verified it.
func TestLivePackageVerification(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	path := "/package/" + liveExampleUUID + "/" + liveExampleTreeSHA
	fr, body := liveFetch(t, b, path)
	if len(body) == 0 {
		t.Fatalf("%s was empty", path)
	}
	if fr.Resolved.Metadata[MetaTreeHashVerified] != "git-sha1" {
		t.Errorf("%s not git-sha1 verified: %q", path, fr.Resolved.Metadata[MetaTreeHashVerified])
	}
	if fr.Resolved.Coordinate.Version != liveExampleTreeSHA {
		t.Errorf("coordinate version = %q, want %q", fr.Resolved.Coordinate.Version, liveExampleTreeSHA)
	}
	if st := m.Stats(); st.TarballsVerified < 1 || st.TreeHashMismatch != 0 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}

// TestLiveRegistriesListing confirms the mutable /registries listing proxies and
// is not cached, and names the General registry.
func TestLiveRegistriesListing(t *testing.T) {
	b := liveBackend(t, &Metrics{})
	fr, body := liveFetch(t, b, "/registries")
	if len(body) == 0 {
		t.Fatal("/registries was empty")
	}
	if fr.Resolved.Cacheable {
		t.Error("/registries must not be cacheable")
	}
	if !strings.Contains(string(body), "/registry/") {
		t.Errorf("/registries did not list any registry: %q", string(body))
	}
}
