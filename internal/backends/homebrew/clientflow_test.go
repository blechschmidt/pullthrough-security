package homebrew

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
)

// These tests replay the request sequence of the real brew client (4.6.20, with
// HOMEBREW_ARTIFACT_DOMAIN pointed at the proxy) against the gateway's own HTTP
// handler, so they cover what a backend-level test cannot: that the paths route
// (the original bug was a 501 from the gateway), that the bottle is served from
// the cache the second time, and that the admission policy gate — which only
// applies to a coordinate with both a name and a version — actually sees one.

// recordingAssessor is a policy.AssessmentSource that records every artifact
// the policy gate evaluates. It reports no provenance, which the default policy
// admits.
type recordingAssessor struct {
	mu   sync.Mutex
	seen []policy.Artifact
}

func (a *recordingAssessor) Assess(_ context.Context, art policy.Artifact) (policy.Assessment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, art)
	return policy.Assessment{}, nil
}

func (a *recordingAssessor) artifacts() []policy.Artifact {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]policy.Artifact(nil), a.seen...)
}

// newBrewGateway mounts env's backend as "homebrew" behind a gateway with an
// in-memory cache and the given admission policy.
func newBrewGateway(t *testing.T, env *regEnv, cfg policy.Config, assessor policy.AssessmentSource) http.Handler {
	t.Helper()
	registry := backends.NewRegistry()
	if err := registry.Register(env.backend); err != nil {
		t.Fatalf("Register: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g, err := proxy.New(proxy.Dependencies{
		Logger:     logger,
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Policy:     policy.New(cfg, assessor, logger),
		Ecosystems: map[string]string{"homebrew": "homebrew"},
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return g.Handler()
}

func serve(h http.Handler, method, path string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, vs := range header {
		req.Header[k] = vs
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// blobFetches counts the bottle-blob requests the fake registry served.
func (e *regEnv) blobFetches() int {
	n := 0
	for _, hit := range e.registryRequests() {
		if strings.Contains(hit.path, "/blobs/") {
			n++
		}
	}
	return n
}

func TestBrewClientFlowThroughGateway(t *testing.T) {
	env := newRegEnv(t)
	bottle := []byte("\x1f\x8b the hello 2.12.3 bottle for x86_64_linux")
	digest := sha256Hex(bottle)
	index := ociIndex("hello", "2.12.3", 1,
		platformBottle{"x86_64_linux", digest}, platformBottle{"arm64_sequoia", hexOf("a")})
	env.addManifest("homebrew/core/hello", "2.12.3-1", index, ociIndexType)
	env.addBlob("homebrew/core/hello", digest, bottle)

	assessor := &recordingAssessor{}
	gw := newBrewGateway(t, env, policy.Config{}, assessor)

	const (
		manifestPath = "/v1/homebrew/v2/homebrew/core/hello/manifests/2.12.3-1"
	)
	bottlePath := "/v1/homebrew/v2/homebrew/core/hello/blobs/sha256:" + digest
	brewAccept := http.Header{"Accept": {ociIndexType}}

	// 1. brew downloads the image index, asking for the OCI index media type.
	rec := serve(gw, http.MethodGet, manifestPath, brewAccept)
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest: status %d, body %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != ociIndexType {
		t.Errorf("manifest Content-Type = %q, want %q", ct, ociIndexType)
	}
	if !bytes.Equal(rec.Body.Bytes(), index) {
		t.Errorf("manifest body was altered in transit")
	}
	if got := rec.Header().Get("X-Cache"); got != "BYPASS" {
		t.Errorf("manifest X-Cache = %q, want BYPASS (served live)", got)
	}

	// 2. brew downloads the bottle: fetched from the registry, verified, cached.
	rec = serve(gw, http.MethodGet, bottlePath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bottle: status %d, body %q", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), bottle) {
		t.Errorf("bottle bytes mismatch")
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first bottle X-Cache = %q, want MISS", got)
	}

	// The policy gate ran, on the formula coordinate learned from the manifest.
	seen := assessor.artifacts()
	if len(seen) != 1 || seen[0].Ecosystem != "homebrew" || seen[0].Name != "hello" || seen[0].Version != "2.12.3" {
		t.Fatalf("policy gate evaluated %+v, want exactly homebrew hello@2.12.3", seen)
	}

	// 3. A second, fresh client repeats the sequence: the bottle comes from the
	// proxy cache, with no second registry blob fetch.
	if rec := serve(gw, http.MethodGet, manifestPath, brewAccept); rec.Code != http.StatusOK {
		t.Fatalf("second manifest: status %d", rec.Code)
	}
	rec = serve(gw, http.MethodGet, bottlePath, nil)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), bottle) {
		t.Fatalf("second bottle: status %d", rec.Code)
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second bottle X-Cache = %q, want HIT", got)
	}
	if n := env.blobFetches(); n != 1 {
		t.Errorf("registry served the bottle blob %d times, want once", n)
	}

	// A HEAD for the cached bottle answers from the cache too.
	rec = serve(gw, http.MethodHead, bottlePath, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD bottle: status %d, %d body bytes", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(bottle)) {
		t.Errorf("HEAD bottle Content-Length = %q, want %d", got, len(bottle))
	}
	if n := env.blobFetches(); n != 1 {
		t.Errorf("registry served the bottle blob %d times after HEAD, want once", n)
	}
}

// With HOMEBREW_DOWNLOAD_CONCURRENCY brew sends the manifest and bottle requests
// in parallel. The bottle request reaches the gateway while the manifest is
// still being fetched, and must nevertheless be gated under the version that
// manifest carries — here a version the formula API could not have supplied.
func TestBrewClientFlowParallelDownloads(t *testing.T) {
	env := newRegEnv(t)
	bottle := []byte("\x1f\x8b the hello 2.12.2 bottle")
	digest := sha256Hex(bottle)
	env.addManifest("homebrew/core/hello", "2.12.2",
		ociIndex("hello", "2.12.2", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	env.addBlob("homebrew/core/hello", digest, bottle)
	// The formula API has already moved on: it does not list this bottle.
	env.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", hexOf("f")}))
	held := env.gateManifests(t)

	assessor := &recordingAssessor{}
	gw := newBrewGateway(t, env, policy.Config{}, assessor)

	manifestDone := make(chan int, 1)
	go func() {
		rec := serve(gw, http.MethodGet, "/v1/homebrew/v2/homebrew/core/hello/manifests/2.12.2",
			http.Header{"Accept": {ociIndexType}})
		manifestDone <- rec.Code
	}()
	<-held.arrived // the manifest is in flight at the registry

	bottleDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		bottleDone <- serve(gw, http.MethodGet, "/v1/homebrew/v2/homebrew/core/hello/blobs/sha256:"+digest, nil)
	}()
	select {
	case rec := <-bottleDone:
		t.Fatalf("bottle answered (%d) before its in-flight manifest", rec.Code)
	case <-time.After(150 * time.Millisecond):
	}
	if n := env.blobFetches(); n != 0 {
		t.Fatalf("the bottle was fetched (%d) before its coordinate was established", n)
	}

	held.release()
	if code := <-manifestDone; code != http.StatusOK {
		t.Fatalf("manifest: status %d", code)
	}
	rec := <-bottleDone
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), bottle) {
		t.Fatalf("bottle: status %d", rec.Code)
	}
	seen := assessor.artifacts()
	if len(seen) != 1 || seen[0].Name != "hello" || seen[0].Version != "2.12.2" {
		t.Errorf("policy gate evaluated %+v, want exactly hello@2.12.2", seen)
	}
}

func TestBrewClientFlowTamperedBottleIsRefused(t *testing.T) {
	env := newRegEnv(t)
	promised := sha256Hex([]byte("the bottle the signed index promised"))
	env.addManifest("homebrew/core/hello", "2.12.3",
		ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", promised}), ociIndexType)
	env.addBlob("homebrew/core/hello", promised, []byte("something else entirely"))
	gw := newBrewGateway(t, env, policy.Config{}, nil)
	bottlePath := "/v1/homebrew/v2/homebrew/core/hello/blobs/sha256:" + promised

	serve(gw, http.MethodGet, "/v1/homebrew/v2/homebrew/core/hello/manifests/2.12.3", http.Header{"Accept": {ociIndexType}})
	rec := serve(gw, http.MethodGet, bottlePath, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("tampered bottle: status %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "something else") {
		t.Errorf("tampered bytes reached the client")
	}
	// Nothing was committed to the cache: the next request tries upstream again.
	if rec := serve(gw, http.MethodGet, bottlePath, nil); rec.Code != http.StatusBadGateway {
		t.Errorf("second request: status %d, want 502 (a mismatched bottle must not be cached)", rec.Code)
	}
	if n := env.blobFetches(); n != 2 {
		t.Errorf("registry blob fetches = %d, want 2", n)
	}
	if s := env.metrics.Stats(); s.BottleHashMismatch != 2 || s.BottlesVerified != 0 {
		t.Errorf("metrics = %+v", s)
	}
}

// A name-keyed policy rule must bite on the registry-native path whatever is
// known about the bottle's version — including nothing at all.
func TestBrewClientFlowPolicyDenylistAppliesInEveryVersionState(t *testing.T) {
	digest := hexOf("b")
	deny := policy.Config{Default: policy.Rule{Denylist: []string{"hello"}}}
	bottlePath := "/v1/homebrew/v2/homebrew/core/hello/blobs/sha256:" + digest

	cases := []struct {
		name    string
		options func(*Options)
		prepare func(t *testing.T, env *regEnv, gw http.Handler)
	}{
		{
			name: "version learned from the manifest",
			prepare: func(t *testing.T, env *regEnv, gw http.Handler) {
				env.addManifest("homebrew/core/hello", "2.12.3",
					ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
				// The manifest itself is metadata and is still served.
				if rec := serve(gw, http.MethodGet, "/v1/homebrew/v2/homebrew/core/hello/manifests/2.12.3", nil); rec.Code != http.StatusOK {
					t.Fatalf("manifest: status %d", rec.Code)
				}
			},
		},
		{
			name: "version recovered from the formula API",
			prepare: func(t *testing.T, env *regEnv, gw http.Handler) {
				env.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", digest}))
			},
		},
		{
			name:    "version unknown: digest-derived fallback",
			prepare: func(t *testing.T, env *regEnv, gw http.Handler) {},
		},
		{
			name:    "version unknown and offline",
			options: func(o *Options) { o.Offline = true },
			prepare: func(t *testing.T, env *regEnv, gw http.Handler) {},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mutate []func(*Options)
			if c.options != nil {
				mutate = append(mutate, c.options)
			}
			env := newRegEnv(t, mutate...)
			env.addBlob("homebrew/core/hello", digest, []byte("never served"))
			gw := newBrewGateway(t, env, deny, nil)
			c.prepare(t, env, gw)

			rec := serve(gw, http.MethodGet, bottlePath, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403; body %q", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("X-Policy-Code"); got != "denylist" {
				t.Errorf("X-Policy-Code = %q, want denylist", got)
			}
			// Blocked before retrieval: the registry was never asked for the blob.
			if n := env.blobFetches(); n != 0 {
				t.Errorf("registry served the blob %d times for a denylisted formula", n)
			}
		})
	}
}

// A third-party tap's formula is addressed tap-qualified, so an allowlist that
// names a core formula does not admit a same-named formula from another tap.
func TestBrewClientFlowTapFormulaDoesNotPassForCore(t *testing.T) {
	env := newRegEnv(t)
	bottle := []byte("wget bottle")
	digest := sha256Hex(bottle)
	env.addBlob("homebrew/core/wget", digest, bottle)
	env.addBlob("evil/tap/wget", digest, bottle)
	env.addFormula("wget", formulaJSON("wget", "1.25.0", platformBottle{"x86_64_linux", digest}))
	gw := newBrewGateway(t, env, policy.Config{Default: policy.Rule{Allowlist: []string{"wget"}}}, nil)

	if rec := serve(gw, http.MethodGet, "/v1/homebrew/v2/homebrew/core/wget/blobs/sha256:"+digest, nil); rec.Code != http.StatusOK {
		t.Fatalf("core wget: status %d, want 200", rec.Code)
	}
	rec := serve(gw, http.MethodGet, "/v1/homebrew/v2/evil/tap/wget/blobs/sha256:"+digest, nil)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Policy-Code") != "allowlist" {
		t.Errorf("evil/tap/wget: status %d code %q, want 403 allowlist", rec.Code, rec.Header().Get("X-Policy-Code"))
	}
}

func TestGatewayRejectsNonBottleRegistryPaths(t *testing.T) {
	env := newRegEnv(t)
	gw := newBrewGateway(t, env, policy.Config{}, nil)
	for _, path := range []string{
		"/v1/homebrew/v2/",
		"/v1/homebrew/v2/_catalog",
		"/v1/homebrew/v2/homebrew/core/hello/tags/list",
		"/v1/homebrew/v2/library/alpine/manifests/latest",
		"/v1/homebrew/v2/library/alpine/blobs/sha256:" + hexOf("c"),
		"/v1/homebrew/v2/homebrew/core/hello/blobs/sha256:nope",
		"/v1/homebrew/v2/homebrew/core/Hello/manifests/1.0",
	} {
		if rec := serve(gw, http.MethodGet, path, nil); rec.Code != http.StatusNotImplemented {
			t.Errorf("GET %s: status %d, want 501", path, rec.Code)
		}
	}
	// Nothing reached the registry — not even an anonymous, challenged attempt.
	if challenges, _ := env.handshake(); challenges != 0 || len(env.registryRequests()) != 0 {
		t.Errorf("rejected paths reached the registry: %d challenges, %v", challenges, env.registryRequests())
	}
	// The pull-through gateway serves reads only.
	if rec := serve(gw, http.MethodPost, "/v1/homebrew/v2/homebrew/core/hello/blobs/uploads/", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST upload: status %d, want 405", rec.Code)
	}
}
