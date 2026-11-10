//go:build integration
// +build integration

// Integration tests for the OpenVSX backend against the live open-vsx.org
// registry. Gated behind the `integration` build tag (and skipped when the
// network is unavailable) so the default `go test ./...` stays hermetic,
// mirroring the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/openvsx/
package openvsx

import (
	"context"
	"encoding/json"
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

const liveOpenVSX = "https://open-vsx.org"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:          "openvsx-live",
		UpstreamURL:   liveOpenVSX,
		PublicBaseURL: "https://proxy.example/v1/openvsx",
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

// TestLiveVsixFlow drives a real extension end-to-end: fetch the extension
// metadata, read the latest version, then download its .vsix through the backend
// and confirm it was verified against the published .sha256 sidecar.
func TestLiveVsixFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	// dracula-theme is a tiny, ubiquitous color theme — stable and small.
	const ns, ext = "dracula-theme", "theme-dracula"
	_, meta := liveFetch(t, b, "/api/"+ns+"/"+ext)
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(meta, &doc); err != nil || doc.Version == "" {
		t.Skipf("could not read live version for %s.%s: %v", ns, ext, err)
	}

	file := ns + "." + ext + "-" + doc.Version + ".vsix"
	path := "/api/" + ns + "/" + ext + "/" + doc.Version + "/file/" + file
	fr, body := liveFetch(t, b, path)
	if len(body) == 0 {
		t.Fatalf("%s was empty", path)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("%s was not SHA-256 verified: %q", path, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Resolved.Coordinate.Name != ns+"."+ext || fr.Resolved.Coordinate.Version != doc.Version {
		t.Errorf("coordinate = %+v, want %s.%s/%s", fr.Resolved.Coordinate, ns, ext, doc.Version)
	}
	if st := m.Stats(); st.VsixVerified < 1 || st.SHA256Fetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}

// TestLiveMetadataRewrite confirms the extension metadata proxies and has its
// embedded upstream URLs rewritten through the proxy's public base.
func TestLiveMetadataRewrite(t *testing.T) {
	b := liveBackend(t, &Metrics{})
	fr, body := liveFetch(t, b, "/api/dracula-theme/theme-dracula")
	if len(body) == 0 {
		t.Fatal("metadata was empty")
	}
	if fr.Resolved.Cacheable {
		t.Error("metadata must not be cacheable")
	}
	if got := string(body); !contains(got, "https://proxy.example/v1/openvsx") {
		t.Errorf("download URLs were not rewritten through the proxy base")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOfStr(s, sub) >= 0) }

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
