//go:build integration
// +build integration

// Integration tests for the Homebrew backend against the live formulae.brew.sh
// JSON API and the live ghcr.io bottle registry. Gated behind the `integration`
// build tag (and skipped when the network is unavailable) so the default
// `go test ./...` stays hermetic, mirroring the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/homebrew/
package homebrew

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

const (
	liveFormulae = "https://formulae.brew.sh"
	publicBase   = "https://proxy.example/v1/homebrew-live"
)

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 90 * time.Second}
	b, err := New(Options{
		Name:          "homebrew-live",
		UpstreamURL:   liveFormulae,
		PublicBaseURL: publicBase,
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

func liveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		return nil, nil, err
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	fr.Resolved = res
	return fr, body, rerr
}

// TestLiveFormulaAndBottle fetches wget's live formula metadata, confirms its
// bottle URLs are rewritten through the proxy, then drives one rewritten bottle
// download back through the backend and confirms the ghcr-hosted OCI blob
// verifies against the SHA-256 recorded in the manifest.
func TestLiveFormulaAndBottle(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	fr, body, err := liveFetch(t, b, "/api/formula/wget.json")
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("formula fetch: %v", err)
	}
	if fr.Resolved.Cacheable {
		t.Error("formula metadata must not be cacheable")
	}
	bottlePath := extractProxyBottlePath(t, string(body))

	fr2, blob, rerr := liveFetch(t, b, bottlePath)
	if rerr != nil {
		var mm *DigestMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live bottle failed content-address verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read bottle %q: %v", bottlePath, rerr)
	}
	if len(blob) == 0 {
		t.Fatalf("bottle %q was empty", bottlePath)
	}
	if fr2.Resolved.Metadata[MetaDigestVerified] != "sha256" {
		t.Errorf("bottle not sha256-verified: %q", fr2.Resolved.Metadata[MetaDigestVerified])
	}
	if st := m.Stats(); st.BottlesVerified < 1 || st.BottleHashMismatch != 0 || st.TokensFetched < 1 {
		t.Errorf("bottle verification metrics not recorded: %+v", st)
	}
}

// extractProxyBottlePath pulls one rewritten "/bottle/..." path out of a served
// formula document, so a live bottle fetch can be driven through the backend.
func extractProxyBottlePath(t *testing.T, doc string) string {
	t.Helper()
	marker := publicBase + "/bottle/"
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatalf("no rewritten bottle URL in formula document")
	}
	rest := doc[i+len(publicBase):]
	// The URL ends at the closing JSON quote.
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
