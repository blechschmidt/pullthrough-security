//go:build integration
// +build integration

// Integration tests for the Helm backend against live chart repositories.
// Gated behind the `integration` build tag (and skipped when the network is
// unavailable) so the default `go test ./...` stays hermetic, mirroring the
// other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/helm/
package helm

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

const livePublicBase = "https://proxy.example.com/v1/live"

func liveBackend(t *testing.T, upstreamURL string, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 120 * time.Second}
	b, err := New(Options{
		Name:          "live",
		UpstreamURL:   upstreamURL,
		PublicBaseURL: livePublicBase,
		Client:        upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:       m,
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
	if se, ok := backends.AsStatusError(err); ok && (se.Status == http.StatusTooManyRequests || se.Status >= 500) {
		t.Skipf("upstream unavailable: %v", err)
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
			t.Fatalf("live archive failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	return fr, body
}

// liveIndexFlow serves a live repository's index through the backend, checks
// that every chart URL in it leads back through the proxy, then pulls the first
// version of the named chart through the link the index hands out and confirms
// it was fetched from where the upstream index said and verified against the
// digest published there.
func liveIndexFlow(t *testing.T, upstreamURL, chart, wantArchivePrefix string) {
	m := &Metrics{}
	b := liveBackend(t, upstreamURL, m)

	_, body := liveFetch(t, b, "/index.yaml")
	idx, err := ParseIndex(body)
	if err != nil {
		t.Fatalf("the served index does not parse: %v", err)
	}
	total := 0
	for name, versions := range idx.Entries {
		for _, cv := range versions {
			for _, u := range cv.URLs {
				total++
				if !strings.HasPrefix(u, livePublicBase+"/-/") {
					t.Fatalf("%s %s: chart URL %q does not lead back through the proxy", name, cv.Version, u)
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("the served index lists no chart URLs")
	}

	versions := idx.Entries[chart]
	if len(versions) == 0 || len(versions[0].URLs) == 0 {
		t.Fatalf("the served index does not list chart %q", chart)
	}
	link := versions[0].URLs[0]
	fr, archive := liveFetch(t, b, strings.TrimPrefix(link, livePublicBase))
	if len(archive) == 0 {
		t.Fatalf("%s: empty archive", link)
	}
	if got := sha256Hex(archive); got != versions[0].Digest {
		t.Errorf("%s: served archive hashes to %s, the index publishes %s", link, got, versions[0].Digest)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" || m.Stats().ChartsVerified != 1 {
		t.Errorf("%s: archive not verified (metadata %q, metrics %+v)", link, fr.Resolved.Metadata[MetaChecksumVerified], m.Stats())
	}
	if got := fr.Resolved.Metadata[MetaArchiveURL]; !strings.HasPrefix(got, wantArchivePrefix) {
		t.Errorf("%s: fetched from %q, want a location under %q", link, got, wantArchivePrefix)
	}
	if fr.Resolved.Coordinate != (backends.Coordinate{Name: chart, Version: versions[0].Version}) {
		t.Errorf("%s: coordinate = %+v", link, fr.Resolved.Coordinate)
	}
	if m.Stats().IndexParsed != 1 {
		t.Errorf("the upstream index was parsed %v times, want 1", m.Stats().IndexParsed)
	}
}

// A repository that hosts its archives next to its index (GitHub Pages).
func TestLiveSameHostArchives(t *testing.T) {
	liveIndexFlow(t, "https://stefanprodan.github.io/podinfo", "podinfo", "https://stefanprodan.github.io/podinfo/")
}

// A repository whose index lists archives on a different host (GitHub release
// assets): the case in which a client served the upstream's index as-is would
// download the chart around the proxy.
func TestLiveForeignHostArchives(t *testing.T) {
	liveIndexFlow(t, "https://kubernetes.github.io/ingress-nginx", "ingress-nginx", "https://github.com/kubernetes/ingress-nginx/releases/download/")
}
