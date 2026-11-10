//go:build integration
// +build integration

// Integration tests for the RubyGems backend against the live rubygems.org
// compact index. They are gated behind the `integration` build tag (and skipped
// when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/rubygems/
package rubygems

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

const liveRubygems = "https://rubygems.org"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second}
	b, err := New(Options{
		Name:        "rubygems-live",
		UpstreamURL: liveRubygems,
		Client:      upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:     m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// skipIfOffline turns a dial/network failure into a skip rather than a failure.
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

func TestLiveInfoParses(t *testing.T) {
	b := liveBackend(t, &Metrics{})
	res := liveResolve(t, b, "/info/rake")
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("fetch /info/rake: %v", err)
	}
	body, _ := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	info, err := ParseInfo(body)
	if err != nil {
		t.Fatalf("ParseInfo: %v", err)
	}
	if len(info.Versions) == 0 {
		t.Fatal("expected at least one version in /info/rake")
	}
	withChecksum := 0
	for _, v := range info.Versions {
		if v.Checksum != "" {
			withChecksum++
		}
	}
	if withChecksum == 0 {
		t.Error("expected at least one version to declare a checksum")
	}
}

// TestLiveGemVerifies fetches a real .gem and confirms it verifies against the
// SHA-256 the compact index declares — the end-to-end supply-chain guarantee.
func TestLiveGemVerifies(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)
	res := liveResolve(t, b, "/gems/rake-13.0.6.gem")
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("fetch gem: %v", err)
	}
	if _, err := io.Copy(io.Discard, fr.Content); err != nil {
		t.Fatalf("stream gem: %v", err)
	}
	_ = fr.Content.Close()
	if m.Stats().GemsVerified != 1 {
		t.Errorf("GemsVerified = %v, want 1 (checksum should match)", m.Stats().GemsVerified)
	}
	if m.Stats().ChecksumMismatch != 0 {
		t.Errorf("unexpected checksum mismatch on a genuine gem")
	}
}
