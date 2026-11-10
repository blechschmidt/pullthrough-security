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
	"bytes"
	"context"
	"encoding/json"
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

	// The named form of the endpoint — what a rewritten source.json points at —
	// serves the same verified archive.
	named, namedBody := liveFetch(t, b, "/modules/"+mod+"/"+ver+"/archive/platforms-0.0.10.tar.gz")
	if !bytes.Equal(namedBody, body) {
		t.Error("the named archive endpoint served different bytes than the bare one")
	}
	if named.Resolved.CacheKey != fr.Resolved.CacheKey {
		t.Errorf("cache keys differ: %q vs %q", named.Resolved.CacheKey, fr.Resolved.CacheKey)
	}
}

// TestLiveRewriteOfRealDescriptors rewrites live BCR descriptors of each shape
// the registry uses and checks what a Bazel client would be handed.
func TestLiveRewriteOfRealDescriptors(t *testing.T) {
	const publicBase = "https://proxy.example.com/v1/bazel"
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:          "bcr-live",
		UpstreamURL:   liveBCR,
		PublicBaseURL: publicBase,
		Client:        upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		module  string // "<name>/<version>"
		wantURL string // expected rewritten url suffix; "" = passed through untouched
	}{
		{"platforms/0.0.10", "/archive/platforms-0.0.10.tar.gz"},
		{"abc/0.0.0-20250408-yosyshq", "/archive/e55d316cc9a7f72a84a76eda555aa6ec083c9d0d.zip"}, // overlay
		{"bison/3.8.2.bcr.10", "/archive/bison-3.8.2.tar.xz"},                                   // mirror_urls
		{"eigen/3.4.1", "/archive/download.tar.gz"},                                             // archive_type
		{"pico-sdk/2.1.1-develop.bcr.20250113-4b6e6475", ""},                                    // git_repository
	}
	for _, c := range cases {
		_, body := liveFetch(t, b, "/modules/"+c.module+"/source.json")
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("%s: source.json is not JSON: %v", c.module, err)
			continue
		}
		if c.wantURL == "" {
			if _, ok := doc["url"]; ok || doc["type"] != "git_repository" {
				t.Errorf("%s: a git_repository descriptor must pass through untouched: %s", c.module, body)
			}
			continue
		}
		if want := publicBase + "/modules/" + c.module + c.wantURL; doc["url"] != want {
			t.Errorf("%s: url = %v, want %q", c.module, doc["url"], want)
		}
		if _, ok := doc["mirror_urls"]; ok {
			t.Errorf("%s: mirror_urls must not reach the client", c.module)
		}
		if s, _ := doc["integrity"].(string); !strings.HasPrefix(s, "sha") {
			t.Errorf("%s: integrity missing from the rewritten descriptor: %s", c.module, body)
		}
	}

	// An overlay file is served from the registry and is cacheable.
	fr, build := liveFetch(t, b, "/modules/abc/0.0.0-20250408-yosyshq/overlay/BUILD.bazel")
	if len(build) == 0 || !fr.Resolved.Cacheable {
		t.Errorf("overlay file: %d bytes, cacheable=%v", len(build), fr.Resolved.Cacheable)
	}
}
