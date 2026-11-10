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
	"crypto/sha512"
	"errors"
	"fmt"
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

// TestLiveInstallsTree fetches what Hex's update check and `mix local.hex` read
// when HEX_MIRROR points at the proxy: the Hex builds list and its signature.
// repo.hex.pm redirects the /installs/ tree to builds.hex.pm, so this also
// covers following that redirect.
func TestLiveInstallsTree(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	fr, csv := liveFetch(t, b, "/installs/hex-1.x.csv")
	if fr.Resolved.Cacheable || fr.Resolved.Coordinate != (backends.Coordinate{}) {
		t.Errorf("the builds list must be live and coordinate-less: %+v", fr.Resolved)
	}
	// Every row is "<hex version>,<sha512 hex>,<elixir version>".
	rows := strings.Split(strings.TrimSpace(string(csv)), "\n")
	if len(rows) < 10 {
		t.Fatalf("builds list has only %d rows", len(rows))
	}
	last := strings.Split(rows[len(rows)-1], ",")
	if len(last) < 3 || len(last[1]) != 128 {
		t.Fatalf("unexpected builds-list row %q", rows[len(rows)-1])
	}

	_, sig := liveFetch(t, b, "/installs/hex-1.x.csv.signed")
	if len(sig) == 0 {
		t.Error("builds-list signature was empty")
	}

	// The build that row describes is served too (and, deliberately, not cached).
	fr, ez := liveFetch(t, b, "/installs/"+last[2]+"/hex-"+last[0]+".ez")
	if fr.Resolved.Cacheable {
		t.Error("a Hex build must be passed through live, not cached")
	}
	if got := fmt.Sprintf("%x", sha512.Sum512(ez)); got != last[1] {
		t.Errorf("Hex build does not match the SHA-512 its list records: %s vs %s", got, last[1])
	}
	if st := m.Stats(); st.InstallsServed != 3 {
		t.Errorf("installs-served metric = %v, want 3", st.InstallsServed)
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
