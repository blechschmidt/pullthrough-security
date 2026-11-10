//go:build integration
// +build integration

// Integration tests for the CPAN backend against the live CPAN CDN
// (https://cpan.metacpan.org). Gated behind the `integration` build tag (and
// skipped when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/cpan/
package cpan

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

const liveCPAN = "https://cpan.metacpan.org"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "cpan-live",
		UpstreamURL: liveCPAN,
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

// TestLiveDistributionFlow downloads a real, stable distribution end-to-end and
// confirms the backend verified it against the SHA-256 the sibling CHECKSUMS file
// declared. Try-Tiny-0.32 is a tiny, long-stable distribution under a stable
// author path.
func TestLiveDistributionFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	const path = "/authors/id/E/ET/ETHER/Try-Tiny-0.32.tar.gz"
	fr, body := liveFetch(t, b, path)
	if len(body) == 0 {
		t.Fatalf("%s was empty", path)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("%s was not SHA-256-verified: %q", path, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Resolved.Coordinate.Name != "Try-Tiny" || fr.Resolved.Coordinate.Version != "0.32" {
		t.Errorf("coordinate = %+v", fr.Resolved.Coordinate)
	}
	if st := m.Stats(); st.DistributionsVerified < 1 || st.ChecksumsFetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}

// TestLiveIndexServed confirms the master package index routes and serves live.
func TestLiveIndexServed(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	fr, body := liveFetch(t, b, "/modules/02packages.details.txt.gz")
	if len(body) == 0 {
		t.Fatal("empty 02packages index")
	}
	if fr.Resolved.Cacheable {
		t.Error("the master index must not be cacheable")
	}
	if m.Stats().IndexServed < 1 {
		t.Errorf("index-served metric not recorded: %+v", m.Stats())
	}
}
