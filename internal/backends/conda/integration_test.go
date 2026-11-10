//go:build integration
// +build integration

// Integration tests for the Conda backend against the live conda-forge channel
// (https://conda.anaconda.org/conda-forge). Gated behind the `integration`
// build tag (and skipped when the network is unavailable) so the default
// `go test ./...` stays hermetic, mirroring internal/git's and the other
// backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/conda/
package conda

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

const liveCondaForge = "https://conda.anaconda.org/conda-forge"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "conda-forge-live",
		UpstreamURL: liveCondaForge,
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

// TestLiveNoarchFlow drives a real package end-to-end: fetch the noarch
// repodata.json, pick a .conda entry, then download it through the backend and
// confirm the backend verified it against the SHA-256 the index declared.
func TestLiveNoarchFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	_, repodata := liveFetch(t, b, "/noarch/repodata.json")
	var doc struct {
		PackagesConda map[string]json.RawMessage `json:"packages.conda"`
	}
	if err := json.Unmarshal(repodata, &doc); err != nil {
		t.Fatalf("repodata not JSON: %v", err)
	}
	var pick string
	for name := range doc.PackagesConda {
		pick = name
		break
	}
	if pick == "" {
		t.Skip("no .conda packages in noarch repodata")
	}

	fr, body := liveFetch(t, b, "/noarch/"+pick)
	if len(body) == 0 {
		t.Fatalf("%s was empty", pick)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("%s was not SHA-256-verified: %q", pick, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.PackagesVerified < 1 || st.RepodataFetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}
