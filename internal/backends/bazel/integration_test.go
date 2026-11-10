//go:build integration
// +build integration

// Integration tests for the Bazel backend against the live Bazel Central
// Registry (https://bcr.bazel.build). Gated behind the `integration` build tag
// (and skipped when the network is unavailable) so the default `go test ./...`
// stays hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/bazel/
package bazel

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

const liveBCR = "https://bcr.bazel.build"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "bcr-live",
		UpstreamURL: liveBCR,
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
		var mm *IntegrityMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live archive failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	fr.Resolved = res
	return fr, body
}

// TestLiveModuleFlow drives a real module end-to-end: fetch the "platforms"
// MODULE.bazel and source.json, then download the synthetic archive endpoint and
// confirm the backend verified it against the SRI integrity source.json declared.
func TestLiveModuleFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	const mod = "platforms"
	const ver = "0.0.10"

	_, modBazel := liveFetch(t, b, "/modules/"+mod+"/"+ver+"/MODULE.bazel")
	if len(modBazel) == 0 {
		t.Fatal("MODULE.bazel was empty")
	}

	_, src := liveFetch(t, b, "/modules/"+mod+"/"+ver+"/source.json")
	if len(src) == 0 {
		t.Fatal("source.json was empty")
	}

	fr, body := liveFetch(t, b, "/modules/"+mod+"/"+ver+"/archive")
	if len(body) == 0 {
		t.Fatalf("%s@%s archive was empty", mod, ver)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha256" {
		t.Errorf("%s@%s archive was not SHA-256-verified: %q", mod, ver, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.ArchivesVerified < 1 || st.SourceFetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}
