//go:build integration
// +build integration

// Integration tests for the Composer backend against the live Packagist
// metadata repository. Gated behind the `integration` build tag (and skipped
// when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/composer/
package composer

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

const livePackagist = "https://repo.packagist.org"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second}
	b, err := New(Options{
		Name:        "packagist-live",
		UpstreamURL: livePackagist,
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

func liveResolve(t *testing.T, b *Backend, path string) *backends.Resolved {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	return res
}

// TestLiveMetadataParses fetches a real /p2 document and confirms it parses,
// expands the minified delta encoding, and yields dist references.
func TestLiveMetadataParses(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)
	res := liveResolve(t, b, "/p2/psr/log.json")
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("fetch metadata: %v", err)
	}
	body, _ := io.ReadAll(fr.Content)
	_ = fr.Content.Close()

	md, err := ParseMetadata(body)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	versions := md.Packages["psr/log"]
	if len(versions) == 0 {
		t.Fatal("expected at least one version for psr/log")
	}
	refs := 0
	for _, v := range versions {
		if v.Dist.Reference != "" && v.Dist.URL != "" {
			refs++
		}
	}
	if refs == 0 {
		t.Error("expected at least one version with a dist reference + URL")
	}
	if m.Stats().MetadataParsed != 1 {
		t.Errorf("MetadataParsed = %v, want 1", m.Stats().MetadataParsed)
	}
}

// TestLiveDistDownloads resolves a real dist reference end-to-end: it reads the
// live metadata, picks a version, and fetches the archive through the backend's
// /dist path, confirming the metadata-driven download + verification flow works
// against the real upstream.
func TestLiveDistDownloads(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	// Read metadata to discover a real dist reference.
	res := liveResolve(t, b, "/p2/psr/log.json")
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("fetch metadata: %v", err)
	}
	body, _ := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	md, err := ParseMetadata(body)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}

	var reference string
	for _, v := range md.Packages["psr/log"] {
		if v.Dist.Reference != "" && v.Dist.URL != "" {
			reference = v.Dist.Reference
			break
		}
	}
	if reference == "" {
		t.Skip("no usable dist reference in live metadata")
	}

	distRes := liveResolve(t, b, "/dist/psr/log/"+reference+".zip")
	distFR, err := b.Fetch(context.Background(), distRes)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("fetch dist: %v", err)
	}
	n, err := io.Copy(io.Discard, distFR.Content)
	_ = distFR.Content.Close()
	if err != nil {
		// A checksum mismatch is a real failure; anything else is treated as a
		// transport hiccup and skipped.
		var mm *ChecksumMismatchError
		if errors.As(err, &mm) {
			t.Fatalf("dist failed verification: %v", err)
		}
		skipIfOffline(t, err)
		t.Fatalf("stream dist: %v", err)
	}
	if n == 0 {
		t.Error("dist archive was empty")
	}
}
