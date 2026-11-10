//go:build integration
// +build integration

// Integration tests for the Conan backend against the live ConanCenter remote
// (https://center2.conan.io). Gated behind the `integration` build tag (and
// skipped when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/conan/
package conan

import (
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

const liveConanCenter = "https://center2.conan.io"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second}
	b, err := New(Options{
		Name:        "conancenter-live",
		UpstreamURL: liveConanCenter,
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

// TestLiveRecipeFlow drives a real recipe end-to-end: discover the latest recipe
// revision, list its files, then fetch conanfile.py through the backend and
// confirm the backend verified it against the live conanmanifest.txt (MD5) and
// passed the upstream's stronger X-Checksum-Sha256 header through.
func TestLiveRecipeFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	const ref = "/v2/conans/zlib/1.3.1/_/_"

	// 1. Latest recipe revision.
	_, latestBody := liveFetch(t, b, ref+"/latest")
	var latest struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(latestBody, &latest); err != nil {
		t.Fatalf("latest not JSON: %v (%s)", err, latestBody)
	}
	if latest.Revision == "" {
		t.Fatal("no recipe revision in latest response")
	}

	// 2. File listing for that revision.
	filesPath := ref + "/revisions/" + latest.Revision + "/files"
	_, filesBody := liveFetch(t, b, filesPath)
	var listing struct {
		Files map[string]json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(filesBody, &listing); err != nil {
		t.Fatalf("files not JSON: %v (%s)", err, filesBody)
	}
	if _, ok := listing.Files["conanfile.py"]; !ok {
		t.Fatalf("conanfile.py not in listing: %v", listing.Files)
	}

	// 3. Download and verify conanfile.py.
	fr, body := liveFetch(t, b, filesPath+"/conanfile.py")
	if len(body) == 0 {
		t.Fatal("conanfile.py was empty")
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "md5" {
		t.Errorf("conanfile.py was not MD5-verified: %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Header.Get("X-Checksum-Sha256") == "" {
		t.Error("upstream X-Checksum-Sha256 header was not passed through")
	}
	if st := m.Stats(); st.FilesVerified < 1 || st.ManifestParsed < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
	if got := fr.Resolved.Metadata[MetaChecksumSource]; got != checksumSourceManifest {
		t.Errorf("conanfile.py checksum source = %q, want %q", got, checksumSourceManifest)
	}

	// 4. The archives are not in the manifest (it lists their members); ConanCenter
	// declares their MD5 in X-Checksum-Md5, which is what they are verified against.
	for name := range listing.Files {
		if name != "conan_export.tgz" && name != "conan_sources.tgz" {
			continue
		}
		fr, body := liveFetch(t, b, filesPath+"/"+name)
		if len(body) == 0 {
			t.Errorf("%s was empty", name)
		}
		md := fr.Resolved.Metadata
		if md[MetaChecksumVerified] != "md5" || md[MetaChecksumSource] != checksumSourceHeader {
			t.Errorf("%s: verified=%q source=%q, want md5/%s", name, md[MetaChecksumVerified], md[MetaChecksumSource], checksumSourceHeader)
		}
	}
	if st := m.Stats(); st.ManifestMissing != 0 || st.ChecksumMismatch != 0 {
		t.Errorf("live recipe files left unverified or mismatched: %+v", st)
	}
}

// TestLiveCapabilityProbe hits the route a real Conan 2.x client probes first:
// GET /v1/ping, whose X-Conan-Server-Capabilities header must advertise
// "revisions" for the client to use the remote at all.
func TestLiveCapabilityProbe(t *testing.T) {
	b := liveBackend(t, &Metrics{})
	fr, _ := liveFetch(t, b, "/v1/ping")
	caps := fr.Header.Get("X-Conan-Server-Capabilities")
	if !strings.Contains(caps, "revisions") {
		t.Errorf("X-Conan-Server-Capabilities = %q, want it to include \"revisions\"", caps)
	}
	if fr.Resolved.Cacheable {
		t.Error("the capability probe must be served live")
	}
}
