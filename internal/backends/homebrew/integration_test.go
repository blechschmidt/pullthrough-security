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
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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

// TestLiveRegistryNativeFlow replays what the real brew client does once
// HOMEBREW_ARTIFACT_DOMAIN points at the proxy — fetch the formula's OCI image
// index, then its bottle blob, both on the registry-native "/v2/..." paths —
// against live ghcr.io, and confirms the bottle's coordinate is learned from the
// index, that a backend which never saw the index recovers the same coordinate
// from the formula JSON API, and that the blob verifies.
func TestLiveRegistryNativeFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	// The formula document tells us which tag and digest brew would request.
	_, doc, err := liveFetch(t, b, "/api/formula/hello.json")
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("formula fetch: %v", err)
	}
	var formula struct {
		Versions struct {
			Stable string `json:"stable"`
		} `json:"versions"`
		Revision int `json:"revision"`
		Bottle   struct {
			Stable struct {
				Rebuild int `json:"rebuild"`
				Files   map[string]struct {
					SHA256 string `json:"sha256"`
				} `json:"files"`
			} `json:"stable"`
		} `json:"bottle"`
	}
	if err := json.Unmarshal(doc, &formula); err != nil {
		t.Fatalf("decoding formula document: %v", err)
	}
	digest := formula.Bottle.Stable.Files["x86_64_linux"].SHA256
	if formula.Versions.Stable == "" || digest == "" {
		t.Fatalf("formula document lacks a stable version or an x86_64_linux bottle")
	}
	// brew's GitHubPackages.version_rebuild: "<version>[_<revision>][-<rebuild>]".
	tag := formula.Versions.Stable
	if formula.Revision > 0 {
		tag += "_" + strconv.Itoa(formula.Revision)
	}
	if formula.Bottle.Stable.Rebuild > 0 {
		tag += "-" + strconv.Itoa(formula.Bottle.Stable.Rebuild)
	}
	want := backends.Coordinate{Name: "hello", Version: formula.Versions.Stable}
	blob := "/v2/homebrew/core/hello/blobs/sha256:" + digest

	// 1. The image index, negotiated exactly as brew does.
	res, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet,
		Path:   "/v2/homebrew/core/hello/manifests/" + tag,
		Header: http.Header{"Accept": {"application/vnd.oci.image.index.v1+json"}},
	})
	if err != nil {
		t.Fatalf("Resolve manifest: %v", err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("manifest fetch: %v", err)
	}
	index, _ := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	if fr.MediaType != "application/vnd.oci.image.index.v1+json" {
		t.Errorf("manifest media type = %q", fr.MediaType)
	}
	if !strings.Contains(string(index), digest) {
		t.Fatalf("image index does not list the bottle digest %s", digest)
	}

	// 2. The bottle: coordinate learned from the index, content verified.
	fr2, body, rerr := liveFetch(t, b, blob)
	if rerr != nil {
		skipIfOffline(t, rerr)
		t.Fatalf("bottle fetch: %v", rerr)
	}
	if len(body) == 0 {
		t.Fatal("bottle was empty")
	}
	if fr2.Resolved.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", fr2.Resolved.Coordinate, want)
	}
	if got := fr2.Resolved.Metadata[MetaVersionSource]; got != versionSourceManifest {
		t.Errorf("version source = %q, want %q", got, versionSourceManifest)
	}
	if st := m.Stats(); st.BottlesVerified < 1 || st.BottleHashMismatch != 0 || st.ManifestsServed < 1 {
		t.Errorf("metrics = %+v", st)
	}

	// 3. A backend that never saw the index (a restart, another replica)
	// recovers the same coordinate from the formula JSON API.
	fresh := liveBackend(t, &Metrics{})
	res3, err := fresh.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: blob})
	if err != nil {
		t.Fatalf("Resolve bottle on a fresh backend: %v", err)
	}
	if res3.Metadata[MetaVersionSource] == versionSourceDigest {
		t.Skipf("formula API unavailable for recovery; got the digest fallback %+v", res3.Coordinate)
	}
	if res3.Coordinate != want || res3.Metadata[MetaVersionSource] != versionSourceFormulaAPI {
		t.Errorf("recovered coordinate = %+v (%s), want %+v (%s)",
			res3.Coordinate, res3.Metadata[MetaVersionSource], want, versionSourceFormulaAPI)
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
