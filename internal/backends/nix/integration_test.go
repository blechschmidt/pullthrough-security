//go:build integration
// +build integration

// Integration tests for the Nix backend against the live public binary cache
// (https://cache.nixos.org). Gated behind the `integration` build tag (and
// skipped when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/nix/
package nix

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

const liveCache = "https://cache.nixos.org"

// The current signing key for cache.nixos.org (stable, published in the NixOS
// manual and nix.conf defaults).
const liveCacheKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

func liveBackend(t *testing.T, keys []string, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 90 * time.Second}
	b, err := New(Options{
		Name:              "nix-live",
		UpstreamURL:       liveCache,
		PublicBaseURL:     "https://proxy.example/v1/nix-live",
		TrustedPublicKeys: keys,
		Client:            upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:           m,
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

// TestLiveCacheInfo fetches the cache descriptor and confirms it names the store
// directory.
func TestLiveCacheInfo(t *testing.T) {
	_, body, err := liveFetch(t, liveBackend(t, nil, &Metrics{}), "/nix-cache-info")
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("nix-cache-info: %v", err)
	}
	if !strings.Contains(string(body), "StoreDir: /nix/store") {
		t.Errorf("nix-cache-info missing StoreDir:\n%s", body)
	}
}

// TestLiveNarInfoSignature downloads a real, stable narinfo and confirms it
// verifies against cache.nixos.org's published key and that its URL is rewritten
// through the proxy. The store path is the content-addressed `hello` build, which
// is permanent on the cache; if the chosen path is ever absent the test skips.
func TestLiveNarInfoSignature(t *testing.T) {
	// hello-2.12.1 on x86_64-linux (nixpkgs 23.11); its store hash is immutable
	// and permanently retained on cache.nixos.org for a released channel.
	const storeHash = "3pz29jpsk65xjhvhnnbzsad0gwkr5frx"
	m := &Metrics{}
	b := liveBackend(t, []string{liveCacheKey}, m)

	fr, body, err := liveFetch(t, b, "/"+storeHash+".narinfo")
	if err != nil {
		var se *SignatureError
		if errors.As(err, &se) {
			t.Fatalf("live narinfo failed signature verification: %v", err)
		}
		var ste *backends.StatusError
		if errors.As(err, &ste) && ste.Status == http.StatusNotFound {
			t.Skipf("store path %s no longer on the cache", storeHash)
		}
		skipIfOffline(t, err)
		t.Fatalf("narinfo: %v", err)
	}
	if got := fr.Resolved.Metadata[MetaSignatureVerified]; !strings.HasPrefix(got, "trusted:") {
		t.Errorf("signatureVerified = %q, want trusted:*", got)
	}
	if !strings.Contains(string(body), "URL: https://proxy.example/v1/nix-live/nar/") {
		t.Errorf("narinfo URL not rewritten through proxy:\n%s", body)
	}
	if st := m.Stats(); st.NarInfoSigValid < 1 {
		t.Errorf("signature-valid metric not recorded: %+v", st)
	}

	// Chain to the NAR the (signed) narinfo points at and confirm the backend
	// recomputes and verifies its SHA-256 content address against the live bytes.
	narPath := extractProxyNarPath(t, string(body))
	fr2, narBody, rerr := liveFetch(t, b, narPath)
	if rerr != nil {
		var mm *FileHashMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live NAR failed content-address verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read NAR %q: %v", narPath, rerr)
	}
	if len(narBody) == 0 {
		t.Fatalf("NAR %q was empty", narPath)
	}
	if fr2.Resolved.Metadata[MetaFileHashVerified] != "sha256" {
		t.Errorf("NAR not sha256-verified: %q", fr2.Resolved.Metadata[MetaFileHashVerified])
	}
	if st := m.Stats(); st.NarsVerified < 1 || st.FileHashMismatch != 0 {
		t.Errorf("NAR verification metrics not recorded: %+v", st)
	}
}

// extractProxyNarPath pulls the rewritten "/nar/<file>" path out of a served
// narinfo's URL line, so a live NAR fetch can be driven through the same backend.
func extractProxyNarPath(t *testing.T, narinfo string) string {
	t.Helper()
	for _, ln := range strings.Split(narinfo, "\n") {
		if !strings.HasPrefix(ln, "URL: ") {
			continue
		}
		u := strings.TrimPrefix(ln, "URL: ")
		if i := strings.Index(u, "/nar/"); i >= 0 {
			return u[i:]
		}
	}
	t.Fatalf("no NAR URL in narinfo:\n%s", narinfo)
	return ""
}
