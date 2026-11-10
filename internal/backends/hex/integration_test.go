//go:build integration
// +build integration

// Integration tests for the Hex backend against the live hex.pm repository
// (https://repo.hex.pm). Gated behind the `integration` build tag (and skipped
// when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/hex/
package hex

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const liveHex = "https://repo.hex.pm"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "hex-live",
		UpstreamURL: liveHex,
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
		var mm *ChecksumMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live content failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	fr.Resolved = res
	return fr, body
}

// TestLiveTarballFlow drives a real release end-to-end: fetch the
// /packages/jason resource, parse the latest release's version, then download
// its tarball through the backend and confirm the backend verified it against
// the outer_checksum the resource declared.
func TestLiveTarballFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	// jason is a tiny, ubiquitous JSON library — stable and small.
	const pkg = "jason"
	_, resource := liveFetch(t, b, "/packages/"+pkg)
	idx, err := ParsePackageResource(resource)
	if err != nil {
		t.Fatalf("parse live /packages/%s: %v", pkg, err)
	}
	var version string
	for v := range idx.outer {
		version = v // any release with a recorded outer_checksum works
		break
	}
	if version == "" {
		t.Skipf("no release with an outer_checksum in live /packages/%s", pkg)
	}

	path := "/tarballs/" + pkg + "-" + version + ".tar"
	fr, body := liveFetch(t, b, path)
	if len(body) == 0 {
		t.Fatalf("%s was empty", path)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("%s was not SHA-256 verified: %q", path, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Resolved.Coordinate.Name != pkg || fr.Resolved.Coordinate.Version != version {
		t.Errorf("coordinate = %+v, want %s/%s", fr.Resolved.Coordinate, pkg, version)
	}
	if st := m.Stats(); st.TarballsVerified < 1 || st.ResourceFetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}

// TestLiveRegistryResources confirms the signed /names and /versions resources
// proxy and decode (the /versions resource is a different message type, so this
// exercises byte-exact pass-through, not the Package parser).
func TestLiveRegistryResources(t *testing.T) {
	b := liveBackend(t, &Metrics{})
	for _, p := range []string{"/names", "/versions"} {
		fr, body := liveFetch(t, b, p)
		if len(body) == 0 {
			t.Errorf("%s was empty", p)
		}
		if fr.Resolved.Cacheable {
			t.Errorf("%s must not be cacheable", p)
		}
	}
}
