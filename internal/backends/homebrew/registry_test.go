package homebrew

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Tests for the registry-native paths the real brew client requests once
// HOMEBREW_ARTIFACT_DOMAIN points at the proxy:
//
//	/v2/<repo>/manifests/<reference>
//	/v2/<repo>/blobs/sha256:<hex>
//
// They run against a fake formulae API and a fake bottle registry that guards
// /v2 with the Docker Registry v2 bearer-token handshake, like ghcr.io.

const (
	testRegistryToken = "registry-token"
	ociIndexType      = "application/vnd.oci.image.index.v1+json"
	ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
)

// registryHit is one authorized request the fake registry served.
type registryHit struct {
	path   string
	accept string
}

type fakeManifest struct {
	body        []byte
	contentType string
}

// regEnv is a Homebrew backend wired to a fake formulae API and a fake bottle
// registry, with an adjustable clock.
type regEnv struct {
	backend  *Backend
	metrics  *Metrics
	formulae *httptest.Server
	registry *httptest.Server

	mu          sync.Mutex
	now         time.Time
	manifests   map[string]fakeManifest // "<repo>|<reference>"
	blobs       map[string][]byte       // "<repo>|<hex>" -> the bytes actually served
	formulaDocs map[string]string       // formula name -> JSON document
	apiStatus   int                     // non-zero: the formula API answers every request with it
	apiHits     []string                // formula names requested from the API, in order
	hits        []registryHit           // authorized registry requests, in order
	challenges  int                     // 401 challenges issued
	tokenScopes []string                // scopes a token was requested for

	// Gates hold a class of upstream responses back until released, to stage the
	// interleavings of brew's parallel downloads deterministically.
	manifestGate *gate // registry manifest responses
	apiGate      *gate // formula API responses
}

// gate holds responses back until it is released. arrived receives one value
// per request that reached it.
type gate struct {
	arrived chan struct{}
	open    chan struct{}
	once    sync.Once
}

func newGate() *gate {
	return &gate{arrived: make(chan struct{}, 16), open: make(chan struct{})}
}

// release lets every held (and future) response through. Idempotent.
func (g *gate) release() { g.once.Do(func() { close(g.open) }) }

// hold blocks the calling handler until the gate is released or the request is
// abandoned, reporting whether the response should still be written.
func (g *gate) hold(r *http.Request) bool {
	if g == nil {
		return true
	}
	select {
	case g.arrived <- struct{}{}:
	default:
	}
	select {
	case <-g.open:
		return true
	case <-r.Context().Done():
		return false
	}
}

// gateManifests makes the registry hold manifest responses until the returned
// gate is released (which also happens when the test ends).
func (e *regEnv) gateManifests(t *testing.T) *gate {
	t.Helper()
	g := newGate()
	t.Cleanup(g.release)
	e.mu.Lock()
	e.manifestGate = g
	e.mu.Unlock()
	return g
}

// gateFormulaAPI makes the formula API hold its responses until the returned
// gate is released (which also happens when the test ends).
func (e *regEnv) gateFormulaAPI(t *testing.T) *gate {
	t.Helper()
	g := newGate()
	t.Cleanup(g.release)
	e.mu.Lock()
	e.apiGate = g
	e.mu.Unlock()
	return g
}

func newRegEnv(t *testing.T, mutate ...func(*Options)) *regEnv {
	t.Helper()
	env := &regEnv{
		metrics:     &Metrics{},
		now:         time.Unix(1_700_000_000, 0),
		manifests:   make(map[string]fakeManifest),
		blobs:       make(map[string][]byte),
		formulaDocs: make(map[string]string),
	}

	regMux := http.NewServeMux()
	regMux.HandleFunc("/token", env.serveToken)
	regMux.HandleFunc("/v2/", env.serveRegistry)
	env.registry = httptest.NewServer(regMux)
	t.Cleanup(env.registry.Close)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/formula/", env.serveFormula)
	env.formulae = httptest.NewServer(apiMux)
	t.Cleanup(env.formulae.Close)

	opts := Options{
		Name:              "homebrew",
		UpstreamURL:       env.formulae.URL,
		PublicBaseURL:     "https://proxy.example/v1/homebrew",
		BottleRegistryURL: env.registry.URL,
		Client:            upstream.NewWithHTTPClient(&http.Client{}, "test/1"),
		Metrics:           env.metrics,
	}
	for _, m := range mutate {
		m(&opts)
	}
	b, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.now = env.clock
	env.backend = b
	return env
}

func (e *regEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *regEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

func (e *regEnv) addManifest(repo, reference string, body []byte, contentType string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.manifests[repo+"|"+reference] = fakeManifest{body: body, contentType: contentType}
}

// addBlob makes the registry serve content for the blob named digest in repo
// (content need not hash to digest: that is how a tampered blob is simulated).
func (e *regEnv) addBlob(repo, digest string, content []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blobs[repo+"|"+digest] = content
}

func (e *regEnv) addFormula(name, doc string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.formulaDocs[name] = doc
}

func (e *regEnv) setAPIStatus(status int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apiStatus = status
}

func (e *regEnv) apiRequests() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.apiHits...)
}

func (e *regEnv) registryRequests() []registryHit {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]registryHit(nil), e.hits...)
}

// handshake reports how many 401 challenges the registry issued and the scopes
// tokens were requested for.
func (e *regEnv) handshake() (challenges int, scopes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.challenges, append([]string(nil), e.tokenScopes...)
}

func (e *regEnv) serveToken(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.tokenScopes = append(e.tokenScopes, r.URL.Query().Get("scope"))
	e.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"token": testRegistryToken, "expires_in": 300})
}

func (e *regEnv) serveRegistry(w http.ResponseWriter, r *http.Request) {
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/"), "/")
	if len(segs) < 3 {
		http.NotFound(w, r)
		return
	}
	repo := strings.Join(segs[:len(segs)-2], "/")
	marker, ref := segs[len(segs)-2], segs[len(segs)-1]

	if r.Header.Get("Authorization") != "Bearer "+testRegistryToken {
		e.mu.Lock()
		e.challenges++
		e.mu.Unlock()
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(
			`Bearer realm="%s/token",service="ghcr.io",scope="repository:%s:pull"`, e.registry.URL, repo))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	e.mu.Lock()
	e.hits = append(e.hits, registryHit{path: r.URL.Path, accept: strings.Join(r.Header.Values("Accept"), ", ")})
	manifest, haveManifest := e.manifests[repo+"|"+ref]
	blob, haveBlob := e.blobs[repo+"|"+strings.TrimPrefix(ref, "sha256:")]
	manifestGate := e.manifestGate
	e.mu.Unlock()

	if marker == "manifests" && !manifestGate.hold(r) {
		return
	}

	switch {
	case marker == "manifests" && haveManifest:
		etag := `"sha256:` + sha256Hex(manifest.body) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		// An empty content type suppresses the header altogether.
		w.Header()["Content-Type"] = nil
		if manifest.contentType != "" {
			w.Header().Set("Content-Type", manifest.contentType)
		}
		w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex(manifest.body))
		w.Header().Set("ETag", etag)
		_, _ = w.Write(manifest.body)
	case marker == "blobs" && haveBlob:
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`)
	}
}

func (e *regEnv) serveFormula(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/formula/"), ".json")
	e.mu.Lock()
	e.apiHits = append(e.apiHits, name)
	status, apiGate := e.apiStatus, e.apiGate
	e.mu.Unlock()

	if !apiGate.hold(r) {
		return
	}
	// Read the document only once released, so a test can publish it while a
	// lookup is being held.
	e.mu.Lock()
	doc, ok := e.formulaDocs[name]
	e.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, doc)
}

// platformBottle is one platform's bottle in a fixture index or formula.
type platformBottle struct {
	tag    string
	digest string
}

// ociIndex renders a bottle image index the way brew's
// GitHubPackages#upload_bottle does: per-platform entries annotated with the
// bottle digest and "<pkg_version>.<tag>[.<rebuild>]", document annotations
// carrying the formula's full name, pkg_version and "<pkg_version>[-<rebuild>]".
func ociIndex(title, pkgVersion string, rebuild int, bottles ...platformBottle) []byte {
	manifests := make([]map[string]any, 0, len(bottles))
	for _, b := range bottles {
		ref := pkgVersion + "." + b.tag
		if rebuild > 0 {
			ref += "." + strconv.Itoa(rebuild)
		}
		manifests = append(manifests, map[string]any{
			"mediaType": ociManifestType,
			"digest":    "sha256:" + sha256Hex([]byte("manifest for "+ref)),
			"size":      1234,
			"annotations": map[string]any{
				annRefName:      ref,
				annBottleDigest: b.digest,
				"sh.brew.tab":   `{"homebrew_version":"4.6.20"}`,
			},
		})
	}
	tag := pkgVersion
	if rebuild > 0 {
		tag += "-" + strconv.Itoa(rebuild)
	}
	doc := map[string]any{
		"schemaVersion": 2,
		"manifests":     manifests,
		"annotations": map[string]any{
			"com.github.package.type": "homebrew_bottle",
			annRefName:                tag,
			annTitle:                  title,
			annVersion:                pkgVersion,
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

// formulaJSON renders the subset of a formula API document the backend reads.
func formulaJSON(name, stable string, bottles ...platformBottle) string {
	files := make(map[string]any, len(bottles))
	for _, b := range bottles {
		files[b.tag] = map[string]any{
			"url":    "https://ghcr.io/v2/homebrew/core/" + imageFormulaName(name) + "/blobs/sha256:" + b.digest,
			"sha256": b.digest,
		}
	}
	out, err := json.Marshal(map[string]any{
		"name":      name,
		"full_name": name,
		"versions":  map[string]any{"stable": stable},
		"bottle":    map[string]any{"stable": map[string]any{"rebuild": 0, "files": files}},
	})
	if err != nil {
		panic(err)
	}
	return string(out)
}

func resolveWith(t *testing.T, b *Backend, method, path string, header http.Header) (*backends.Resolved, error) {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	return b.Resolve(context.Background(), &backends.Request{Method: method, Path: path, Query: url.Values{}, Header: header})
}

func mustResolve(t *testing.T, b *Backend, path string) *backends.Resolved {
	t.Helper()
	res, err := resolveWith(t, b, http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	return res
}

func resolveFetchWith(t *testing.T, b *Backend, path string, header http.Header) (*backends.FetchResult, []byte, error) {
	t.Helper()
	res, err := resolveWith(t, b, http.MethodGet, path, header)
	if err != nil {
		return nil, nil, err
	}
	fres, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	var rerr error
	if fres.Content != nil {
		body, rerr = io.ReadAll(fres.Content)
		_ = fres.Content.Close()
	}
	fres.Resolved = res
	return fres, body, rerr
}

// fetchManifest pulls a manifest through the backend the way brew does.
func (e *regEnv) fetchManifest(t *testing.T, repo, reference string) {
	t.Helper()
	_, _, err := resolveFetchWith(t, e.backend, "/v2/"+repo+"/manifests/"+reference, http.Header{"Accept": {ociIndexType}})
	if err != nil {
		t.Fatalf("fetch manifest %s:%s: %v", repo, reference, err)
	}
}

func blobPath(repo, digest string) string { return "/v2/" + repo + "/blobs/sha256:" + digest }

func hexOf(c string) string { return strings.Repeat(c, 64) }

// --- manifests --------------------------------------------------------------

func TestServeManifestPassthrough(t *testing.T) {
	env := newRegEnv(t)
	body := ociIndex("hello", "2.12.3", 1,
		platformBottle{"x86_64_linux", hexOf("a")}, platformBottle{"arm64_sequoia", hexOf("b")})
	env.addManifest("homebrew/core/hello", "2.12.3-1", body, ociIndexType)

	fres, got, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3-1",
		http.Header{"Accept": {ociIndexType}})
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("manifest body was altered in transit")
	}
	if fres.MediaType != ociIndexType {
		t.Errorf("media type = %q, want the registry's %q", fres.MediaType, ociIndexType)
	}
	if fres.Size != int64(len(body)) {
		t.Errorf("size = %d, want %d", fres.Size, len(body))
	}
	if want := "sha256:" + sha256Hex(body); fres.Header.Get("Docker-Content-Digest") != want {
		t.Errorf("Docker-Content-Digest = %q, want %q", fres.Header.Get("Docker-Content-Digest"), want)
	}
	if fres.Header.Get("ETag") == "" {
		t.Errorf("the registry's ETag was not propagated")
	}
	res := fres.Resolved
	if res.Cacheable {
		t.Error("a tag manifest is mutable and must be served live, not cached")
	}
	if want := env.registry.URL + "/v2/homebrew/core/hello/manifests/2.12.3-1"; res.UpstreamURL != want {
		t.Errorf("upstream URL = %q, want %q", res.UpstreamURL, want)
	}
	if res.Coordinate != (backends.Coordinate{Name: "hello"}) {
		t.Errorf("coordinate = %+v, want the formula name and no version", res.Coordinate)
	}

	// Token handshake: the anonymous attempt is challenged, a token is obtained
	// for the repository's pull scope, and the retry carries it — together with
	// the client's Accept header.
	challenges, scopes := env.handshake()
	if challenges != 1 {
		t.Errorf("challenges = %d, want 1", challenges)
	}
	if want := []string{"repository:homebrew/core/hello:pull"}; !reflect.DeepEqual(scopes, want) {
		t.Errorf("token scopes = %v, want %v", scopes, want)
	}
	hits := env.registryRequests()
	if len(hits) != 1 || hits[0].accept != ociIndexType {
		t.Errorf("authorized registry requests = %+v, want one carrying Accept %q", hits, ociIndexType)
	}
	if s := env.metrics.Stats(); s.ManifestsServed != 1 || s.TokensFetched != 1 {
		t.Errorf("metrics = %+v, want ManifestsServed=1 TokensFetched=1", s)
	}

	// The token is cached by scope: a second fetch is neither challenged nor
	// costs another token.
	env.fetchManifest(t, "homebrew/core/hello", "2.12.3-1")
	if challenges, scopes := env.handshake(); challenges != 1 || len(scopes) != 1 {
		t.Errorf("second fetch: challenges=%d tokens=%d, want the cached token reused", challenges, len(scopes))
	}
}

func TestServeManifestAcceptNegotiation(t *testing.T) {
	const custom = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
	cases := []struct {
		name   string
		header http.Header
		want   string
	}{
		{"client value forwarded verbatim", http.Header{"Accept": {custom}}, custom},
		{"repeated headers joined", http.Header{"Accept": {ociIndexType, ociManifestType}}, ociIndexType + ", " + ociManifestType},
		{"no header: default manifest types", http.Header{}, defaultManifestAccept},
		{"bare wildcard: default manifest types", http.Header{"Accept": {"*/*"}}, defaultManifestAccept},
		{"nil header: default manifest types", nil, defaultManifestAccept},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newRegEnv(t)
			env.addManifest("homebrew/core/hello", "2.12.3", ociIndex("hello", "2.12.3", 0), ociIndexType)
			res, err := env.backend.Resolve(context.Background(), &backends.Request{
				Method: http.MethodGet, Path: "/v2/homebrew/core/hello/manifests/2.12.3", Header: c.header,
			})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			fres, err := env.backend.Fetch(context.Background(), res)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			_ = fres.Content.Close()
			hits := env.registryRequests()
			if len(hits) != 1 || hits[0].accept != c.want {
				t.Errorf("registry saw Accept %+v, want %q", hits, c.want)
			}
		})
	}
}

func TestServeManifestByDigestCanonicalised(t *testing.T) {
	env := newRegEnv(t)
	body := []byte(`{"schemaVersion":2}`)
	digest := sha256Hex(body)
	env.addManifest("homebrew/core/hello", "sha256:"+digest, body, ociManifestType)

	// An uppercase digest reference reaches the registry in canonical lowercase.
	fres, got, err := resolveFetchWith(t, env.backend,
		"/v2/homebrew/core/hello/manifests/sha256:"+strings.ToUpper(digest), nil)
	if err != nil {
		t.Fatalf("fetch manifest by digest: %v", err)
	}
	if !bytes.Equal(got, body) || fres.MediaType != ociManifestType {
		t.Errorf("got %q (%s)", got, fres.MediaType)
	}
	if want := "/v2/homebrew/core/hello/manifests/sha256:" + digest; env.registryRequests()[0].path != want {
		t.Errorf("registry path = %q, want %q", env.registryRequests()[0].path, want)
	}
}

func TestServeManifestNotModified(t *testing.T) {
	env := newRegEnv(t)
	body := ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", hexOf("a")})
	env.addManifest("homebrew/core/hello", "2.12.3", body, ociIndexType)

	res := mustResolve(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3")
	res.IfNoneMatch = `"sha256:` + sha256Hex(body) + `"`
	fres, err := env.backend.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !fres.NotModified || fres.Content != nil {
		t.Errorf("a matching validator must be relayed as 304: %+v", fres)
	}
	if env.metrics.Stats().ManifestsServed != 0 {
		t.Errorf("a 304 serves no manifest")
	}
}

func TestServeManifestUpstreamStatus(t *testing.T) {
	env := newRegEnv(t)
	_, _, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/9.9.9", nil)
	se, ok := backends.AsStatusError(err)
	if !ok || se.Status != http.StatusNotFound {
		t.Fatalf("err = %v, want the registry's 404 as a StatusError", err)
	}
}

func TestServeManifestTooLarge(t *testing.T) {
	env := newRegEnv(t)
	huge := bytes.Repeat([]byte(" "), maxManifestBytes+1)
	env.addManifest("homebrew/core/hello", "2.12.3", huge, ociIndexType)
	_, _, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an oversize-manifest error", err)
	}
}

func TestServeManifestRegistryUnreachable(t *testing.T) {
	env := newRegEnv(t)
	env.registry.Close()
	_, _, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3", nil)
	if err == nil {
		t.Fatal("an unreachable registry must surface as an error")
	}
	if _, isStatus := backends.AsStatusError(err); isStatus {
		t.Errorf("err = %v, want a transport error, not an upstream status", err)
	}
	if env.metrics.Stats().ManifestsServed != 0 {
		t.Error("no manifest was served")
	}
}

func TestServeManifestWithoutContentType(t *testing.T) {
	env := newRegEnv(t)
	env.addManifest("homebrew/core/hello", "2.12.3", []byte(`{"schemaVersion":2}`), "")
	fres, _, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3", nil)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	if fres.MediaType != "application/json" {
		t.Errorf("media type = %q, want the JSON default when the registry names none", fres.MediaType)
	}
}

func TestServeManifestNotABottleIndexStillServed(t *testing.T) {
	env := newRegEnv(t)
	body := []byte("definitely not json")
	env.addManifest("homebrew/core/hello", "2.12.3", body, "text/plain")
	_, got, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/hello/manifests/2.12.3", nil)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("an unparseable manifest must pass through unchanged: %q, %v", got, err)
	}
	if n := env.backend.index.len(); n != 0 {
		t.Errorf("index learned %d entries from a non-bottle document", n)
	}
}

// --- bottles ----------------------------------------------------------------

func TestServeRegistryBottleVerified(t *testing.T) {
	env := newRegEnv(t)
	bottle := []byte("\x1f\x8b the hello bottle tarball")
	digest := sha256Hex(bottle)
	env.addManifest("homebrew/core/hello", "2.12.3-1",
		ociIndex("hello", "2.12.3", 1, platformBottle{"x86_64_linux", digest}), ociIndexType)
	env.addBlob("homebrew/core/hello", digest, bottle)

	// brew fetches the manifest, then the bottle.
	env.fetchManifest(t, "homebrew/core/hello", "2.12.3-1")
	fres, body, err := resolveFetchWith(t, env.backend, blobPath("homebrew/core/hello", digest), nil)
	if err != nil {
		t.Fatalf("fetch bottle: %v", err)
	}
	if !bytes.Equal(body, bottle) {
		t.Errorf("served bottle bytes mismatch")
	}
	res := fres.Resolved
	if !res.Cacheable {
		t.Error("a bottle blob is immutable and must be cacheable")
	}
	// The cache entry is digest-scoped and shared with the synthetic endpoint.
	if want := "homebrew:bottle:sha256:" + digest; res.CacheKey != want {
		t.Errorf("cache key = %q, want %q", res.CacheKey, want)
	}
	synthetic := mustResolve(t, env.backend, "/bottle/hello/2.12.3/v2/homebrew/core/hello/blobs/sha256:"+digest)
	if synthetic.CacheKey != res.CacheKey {
		t.Errorf("synthetic key %q != registry-native key %q", synthetic.CacheKey, res.CacheKey)
	}
	if want := env.registry.URL + "/v2/homebrew/core/hello/blobs/sha256:" + digest; res.UpstreamURL != want {
		t.Errorf("upstream URL = %q, want %q", res.UpstreamURL, want)
	}
	if res.Coordinate != (backends.Coordinate{Name: "hello", Version: "2.12.3"}) {
		t.Errorf("coordinate = %+v, want hello 2.12.3", res.Coordinate)
	}
	for key, want := range map[string]string{
		MetaFormula:        "hello",
		MetaVersion:        "2.12.3",
		MetaVersionSource:  versionSourceManifest,
		MetaDigestVerified: "sha256",
	} {
		if got := res.Metadata[key]; got != want {
			t.Errorf("metadata[%s] = %q, want %q", key, got, want)
		}
	}
	if fres.Digest != "sha256:"+digest {
		t.Errorf("fetch digest = %q", fres.Digest)
	}
	s := env.metrics.Stats()
	if s.BottlesServed != 1 || s.BottlesVerified != 1 || s.BottleHashMismatch != 0 || s.VersionFromManifest != 1 {
		t.Errorf("metrics = %+v", s)
	}
	// Manifest and bottle share a repository scope, so one token covers both.
	if s.TokensFetched != 1 {
		t.Errorf("TokensFetched = %v, want 1", s.TokensFetched)
	}
	if got := env.apiRequests(); len(got) != 0 {
		t.Errorf("formula API consulted (%v) although the manifest taught the version", got)
	}
}

func TestServeRegistryBottleDigestMismatch(t *testing.T) {
	env := newRegEnv(t)
	claimed := sha256Hex([]byte("the bottle the index promised"))
	env.addManifest("homebrew/core/hello", "2.12.3",
		ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", claimed}), ociIndexType)
	// The registry serves different bytes under the promised digest.
	env.addBlob("homebrew/core/hello", claimed, []byte("tampered bytes"))

	env.fetchManifest(t, "homebrew/core/hello", "2.12.3")
	_, _, err := resolveFetchWith(t, env.backend, blobPath("homebrew/core/hello", claimed), nil)
	var mm *DigestMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("err = %v, want *DigestMismatchError", err)
	}
	if mm.Formula != "hello" || mm.Version != "2.12.3" || mm.Expected != "sha256:"+claimed {
		t.Errorf("mismatch error = %+v", mm)
	}
	s := env.metrics.Stats()
	if s.BottleHashMismatch != 1 || s.BottlesVerified != 0 {
		t.Errorf("metrics = %+v, want one mismatch and no verified bottle", s)
	}
}

func TestServeRegistryBottleUpstreamStatus(t *testing.T) {
	env := newRegEnv(t, func(o *Options) { o.Offline = true })
	_, _, err := resolveFetchWith(t, env.backend, blobPath("homebrew/core/hello", hexOf("c")), nil)
	se, ok := backends.AsStatusError(err)
	if !ok || se.Status != http.StatusNotFound {
		t.Fatalf("err = %v, want the registry's 404 as a StatusError", err)
	}
}

func TestRegistryBottleNotCacheableForWrites(t *testing.T) {
	env := newRegEnv(t, func(o *Options) { o.Offline = true })
	res, err := resolveWith(t, env.backend, http.MethodPost, blobPath("homebrew/core/hello", hexOf("c")), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Cacheable {
		t.Error("only reads are cacheable")
	}
}

// --- coordinate: learned from the manifest ----------------------------------

func TestRegistryBottleCoordinateLearnedFromManifest(t *testing.T) {
	digest := hexOf("d")
	cases := []struct {
		name        string
		repo        string
		reference   string
		manifest    []byte
		wantName    string
		wantVersion string
	}{
		{
			name: "plain formula with a bottle rebuild",
			repo: "homebrew/core/hello", reference: "2.12.3-1",
			manifest: ociIndex("hello", "2.12.3", 1, platformBottle{"x86_64_linux", digest}),
			wantName: "hello", wantVersion: "2.12.3",
		},
		{
			name: "formula revision is not part of the version",
			repo: "homebrew/core/boost", reference: "1.92.0_1",
			manifest: ociIndex("boost", "1.92.0_1", 0, platformBottle{"arm64_sequoia", digest}),
			wantName: "boost", wantVersion: "1.92.0",
		},
		{
			name: "revision and rebuild together",
			repo: "homebrew/core/wget", reference: "1.25.0_2-3",
			manifest: ociIndex("wget", "1.25.0_2", 3, platformBottle{"all", digest}),
			wantName: "wget", wantVersion: "1.25.0",
		},
		{
			name: "version containing a dash",
			repo: "homebrew/core/imagemagick", reference: "7.1.2-35",
			manifest: ociIndex("imagemagick", "7.1.2-35", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "imagemagick", wantVersion: "7.1.2-35",
		},
		{
			name: "versioned formula: @ is encoded as / in the repository",
			repo: "homebrew/core/openssl/3", reference: "3.5.9",
			manifest: ociIndex("openssl@3", "3.5.9", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "openssl@3", wantVersion: "3.5.9",
		},
		{
			name: "dotted formula version suffix",
			repo: "homebrew/core/python/3.12", reference: "3.12.16",
			manifest: ociIndex("python@3.12", "3.12.16", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "python@3.12", wantVersion: "3.12.16",
		},
		{
			name: "+ is encoded as x; the title restores it",
			repo: "homebrew/core/gtkx3", reference: "3.24.52_1",
			manifest: ociIndex("gtk+3", "3.24.52_1", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "gtk+3", wantVersion: "3.24.52",
		},
		{
			name: "third-party tap formula is tap-qualified",
			repo: "acme/tap/widget", reference: "1.0.0",
			manifest: ociIndex("acme/tap/widget", "1.0.0", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "acme/tap/widget", wantVersion: "1.0.0",
		},
		{
			name: "a title naming another formula is ignored",
			repo: "homebrew/core/hello", reference: "2.12.3",
			manifest: ociIndex("curl", "2.12.3", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "hello", wantVersion: "2.12.3",
		},
		{
			name: "a title naming another tap is ignored",
			repo: "acme/tap/widget", reference: "1.0.0",
			manifest: ociIndex("homebrew/core/widget", "1.0.0", 0, platformBottle{"x86_64_linux", digest}),
			wantName: "acme/tap/widget", wantVersion: "1.0.0",
		},
		{
			name: "no document annotations: the per-platform reference name suffices",
			repo: "homebrew/core/hello", reference: "2.12.3-1",
			manifest: []byte(`{"schemaVersion":2,"manifests":[{"annotations":{` +
				`"org.opencontainers.image.ref.name":"2.12.3.x86_64_linux.1","sh.brew.bottle.digest":"` + digest + `"}}]}`),
			wantName: "hello", wantVersion: "2.12.3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newRegEnv(t)
			env.addManifest(c.repo, c.reference, c.manifest, ociIndexType)
			env.fetchManifest(t, c.repo, c.reference)

			res := mustResolve(t, env.backend, blobPath(c.repo, digest))
			if want := (backends.Coordinate{Name: c.wantName, Version: c.wantVersion}); res.Coordinate != want {
				t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
			}
			if got := res.Metadata[MetaVersionSource]; got != versionSourceManifest {
				t.Errorf("version source = %q, want %q", got, versionSourceManifest)
			}
			if got := env.apiRequests(); len(got) != 0 {
				t.Errorf("formula API consulted (%v) for a learned bottle", got)
			}
		})
	}
}

func TestRegistryBottleLearnedMappingIsRepositoryScoped(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("e")
	env.addManifest("homebrew/core/hello", "2.12.3",
		ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	env.fetchManifest(t, "homebrew/core/hello", "2.12.3")

	// The same digest requested under another repository learned nothing from
	// hello's manifest: it is named after its own repository and, with no
	// formula document either, gated under the digest-derived version.
	res := mustResolve(t, env.backend, blobPath("homebrew/core/wget", digest))
	if want := (backends.Coordinate{Name: "wget", Version: "sha256:" + digest}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if got := res.Metadata[MetaVersionSource]; got != versionSourceDigest {
		t.Errorf("version source = %q, want %q", got, versionSourceDigest)
	}
}

func TestRegistryBottleLearnsFromPlatformManifest(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("f")
	// The per-platform image manifest carries the bottle annotations at its top
	// level, and titles itself "<formula> <reference name>".
	manifest := []byte(`{"schemaVersion":2,"layers":[{"digest":"sha256:` + digest + `"}],"annotations":{` +
		`"org.opencontainers.image.title":"openssl@3 3.5.9.x86_64_linux",` +
		`"org.opencontainers.image.version":"3.5.9",` +
		`"org.opencontainers.image.ref.name":"3.5.9.x86_64_linux",` +
		`"sh.brew.bottle.digest":"` + digest + `"}}`)
	ref := "sha256:" + sha256Hex(manifest)
	env.addManifest("homebrew/core/openssl/3", ref, manifest, ociManifestType)
	if _, _, err := resolveFetchWith(t, env.backend, "/v2/homebrew/core/openssl/3/manifests/"+ref,
		http.Header{"Accept": {ociManifestType}}); err != nil {
		t.Fatalf("fetch platform manifest: %v", err)
	}
	res := mustResolve(t, env.backend, blobPath("homebrew/core/openssl/3", digest))
	if want := (backends.Coordinate{Name: "openssl@3", Version: "3.5.9"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
}

// --- coordinate: recovered from the formula JSON API ------------------------

func TestRegistryBottleCoordinateFromFormulaAPI(t *testing.T) {
	env := newRegEnv(t)
	linux, mac := hexOf("1"), hexOf("2")
	env.addFormula("hello", formulaJSON("hello", "2.12.3",
		platformBottle{"x86_64_linux", linux}, platformBottle{"arm64_sequoia", mac}))

	// No manifest was fetched (a restart, or another replica served it): the
	// version is recovered from the formula document.
	res := mustResolve(t, env.backend, blobPath("homebrew/core/hello", linux))
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if got := res.Metadata[MetaVersionSource]; got != versionSourceFormulaAPI {
		t.Errorf("version source = %q, want %q", got, versionSourceFormulaAPI)
	}
	if got, want := env.apiRequests(), []string{"hello"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("formula API requests = %v, want %v", got, want)
	}

	// The answer is memoized — for this bottle and for the document's other
	// platforms — so no further lookup is made.
	for _, digest := range []string{linux, mac} {
		res := mustResolve(t, env.backend, blobPath("homebrew/core/hello", digest))
		if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
			t.Errorf("memoized coordinate = %+v, want %+v", res.Coordinate, want)
		}
	}
	if got := env.apiRequests(); len(got) != 1 {
		t.Errorf("formula API requests = %v, want the single original lookup", got)
	}
	if s := env.metrics.Stats(); s.VersionFromFormulaAPI != 3 || s.VersionFromDigest != 0 {
		t.Errorf("metrics = %+v, want three formula-API resolutions", s)
	}
}

func TestRegistryBottleFormulaAPIResolvesImageNames(t *testing.T) {
	digest := hexOf("3")
	cases := []struct {
		repo     string
		formula  string
		wantHits []string
	}{
		// "@" is encoded as "/": the direct mapping finds the document.
		{"homebrew/core/openssl/3", "openssl@3", []string{"openssl@3"}},
		// A real "x" needs no guessing.
		{"homebrew/core/libx11", "libx11", []string{"libx11"}},
		// "+" is encoded as "x": the image spelling does not exist, the suffix
		// runs read as "+" are tried in order.
		{"homebrew/core/gtkx3", "gtk+3", []string{"gtkx3", "gtk+3"}},
		{"homebrew/core/libsigcxx/2", "libsigc++@2", []string{"libsigcxx@2", "libsigcx+@2", "libsigc++@2"}},
		{"homebrew/core/libxmlxx", "libxml++", []string{"libxmlxx", "libxmlx+", "libxml++"}},
	}
	for _, c := range cases {
		t.Run(c.formula, func(t *testing.T) {
			env := newRegEnv(t)
			env.addFormula(c.formula, formulaJSON(c.formula, "1.2.3", platformBottle{"x86_64_linux", digest}))
			res := mustResolve(t, env.backend, blobPath(c.repo, digest))
			if want := (backends.Coordinate{Name: c.formula, Version: "1.2.3"}); res.Coordinate != want {
				t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
			}
			if got := env.apiRequests(); !reflect.DeepEqual(got, c.wantHits) {
				t.Errorf("formula API requests = %v, want %v", got, c.wantHits)
			}
		})
	}
}

func TestFormulaAPIMalformedSiblingBottleIsSkipped(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("3")
	// One platform's sha256 is garbage: it is ignored, the rest still resolve.
	env.addFormula("hello", formulaJSON("hello", "2.12.3",
		platformBottle{"x86_64_linux", digest}, platformBottle{"arm64_sequoia", "not-a-digest"}))
	res := mustResolve(t, env.backend, blobPath("homebrew/core/hello", digest))
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if n := env.backend.index.len(); n != 1 {
		t.Errorf("index holds %d entries, want only the well-formed bottle", n)
	}
}

func TestManifestSupersedesAnEarlierFallback(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("4")
	path := blobPath("homebrew/core/hello", digest)

	// Unknown everywhere: gated under the digest, and remembered as unresolved.
	if res := mustResolve(t, env.backend, path); res.Coordinate.Version != "sha256:"+digest {
		t.Fatalf("coordinate = %+v, want the digest-derived version", res.Coordinate)
	}
	// The manifest then passes through: its answer applies immediately, without
	// waiting for the unresolved marker to expire.
	env.addManifest("homebrew/core/hello", "2.12.3",
		ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	env.fetchManifest(t, "homebrew/core/hello", "2.12.3")
	res := mustResolve(t, env.backend, path)
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
}

// --- coordinate: the digest-derived last resort -----------------------------

func TestRegistryBottleCoordinateDigestFallback(t *testing.T) {
	digest := hexOf("5")
	other := hexOf("6")
	cases := []struct {
		name     string
		repo     string
		setup    func(*regEnv)
		options  func(*Options)
		wantName string
		wantHits []string
		// wantSuspended: the outcome says the API itself failed, so further
		// lookups are suspended. An answer about one formula never does that.
		wantSuspended bool
	}{
		{
			name:     "no such formula upstream",
			repo:     "homebrew/core/hello",
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name: "formula has moved on: the digest is not among its current bottles",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", formulaJSON("hello", "2.13.0", platformBottle{"x86_64_linux", other}))
			},
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name: "formula found under its + spelling but the digest is unknown: the true name still applies",
			repo: "homebrew/core/gtkx3",
			setup: func(e *regEnv) {
				e.addFormula("gtk+3", formulaJSON("gtk+3", "3.24.52", platformBottle{"x86_64_linux", other}))
			},
			wantName: "gtk+3",
			wantHits: []string{"gtkx3", "gtk+3"},
		},
		{
			name:          "formula API failing",
			repo:          "homebrew/core/hello",
			setup:         func(e *regEnv) { e.setAPIStatus(http.StatusInternalServerError) },
			wantName:      "hello",
			wantHits:      []string{"hello"},
			wantSuspended: true,
		},
		{
			name:          "formula API rate limiting",
			repo:          "homebrew/core/hello",
			setup:         func(e *regEnv) { e.setAPIStatus(http.StatusTooManyRequests) },
			wantName:      "hello",
			wantHits:      []string{"hello"},
			wantSuspended: true,
		},
		{
			name: "formula document is not JSON",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", "<html>maintenance</html>")
			},
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name: "formula document names a different formula",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", formulaJSON("curl", "8.0.0", platformBottle{"x86_64_linux", digest}))
			},
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name: "formula document carries an unusable version",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", formulaJSON("hello", "2.12/3", platformBottle{"x86_64_linux", digest}))
			},
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name: "formula document is implausibly large",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", `{"name":"hello","pad":"`+strings.Repeat("x", maxFormulaLookupBytes)+`"}`)
			},
			wantName: "hello",
			wantHits: []string{"hello"},
		},
		{
			name:          "formula API unreachable",
			repo:          "homebrew/core/hello",
			setup:         func(e *regEnv) { e.formulae.Close() },
			wantName:      "hello",
			wantSuspended: true,
		},
		{
			name: "third-party tap: formulae.brew.sh has nothing to say, so it is not asked",
			repo: "acme/tap/widget/2",
			setup: func(e *regEnv) {
				e.addFormula("widget@2", formulaJSON("widget@2", "2.0.0", platformBottle{"x86_64_linux", digest}))
			},
			wantName: "acme/tap/widget@2",
		},
		{
			// brew's vendor-install downloads its portable Ruby from
			// "$HOMEBREW_ARTIFACT_DOMAIN/v2/homebrew/portable-ruby/portable-ruby/blobs/sha256:…"
			// with no manifest request before it.
			name:     "brew's portable ruby: a non-core repository fetched without a manifest",
			repo:     "homebrew/portable-ruby/portable-ruby",
			wantName: "homebrew/portable-ruby/portable-ruby",
		},
		{
			name: "offline (sealed): Resolve makes no network request",
			repo: "homebrew/core/hello",
			setup: func(e *regEnv) {
				e.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", digest}))
			},
			options:  func(o *Options) { o.Offline = true },
			wantName: "hello",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mutate []func(*Options)
			if c.options != nil {
				mutate = append(mutate, c.options)
			}
			env := newRegEnv(t, mutate...)
			if c.setup != nil {
				c.setup(env)
			}
			res := mustResolve(t, env.backend, blobPath(c.repo, digest))

			// The request is still gated under a complete coordinate: the formula
			// name, and a version derived from the digest.
			if want := (backends.Coordinate{Name: c.wantName, Version: "sha256:" + digest}); res.Coordinate != want {
				t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
			}
			if got := res.Metadata[MetaVersionSource]; got != versionSourceDigest {
				t.Errorf("version source = %q, want %q", got, versionSourceDigest)
			}
			if got := res.Metadata[MetaVersion]; got != "sha256:"+digest {
				t.Errorf("metadata version = %q", got)
			}
			if !res.Cacheable || res.CacheKey != "homebrew:bottle:sha256:"+digest {
				t.Errorf("the fallback must not change how the bottle is cached: %+v", res)
			}
			if got := env.apiRequests(); !reflect.DeepEqual(got, c.wantHits) {
				t.Errorf("formula API requests = %v, want %v", got, c.wantHits)
			}
			if s := env.metrics.Stats(); s.VersionFromDigest != 1 {
				t.Errorf("VersionFromDigest = %v, want 1", s.VersionFromDigest)
			}
			if got := env.backend.lookupsSuspended(); got != c.wantSuspended {
				t.Errorf("formula-API lookups suspended = %v, want %v", got, c.wantSuspended)
			}
		})
	}
}

func TestUnresolvedBottleIsRetriedAfterTTL(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("7")
	path := blobPath("homebrew/core/hello", digest)

	// The formula API does not know the formula: remembered, not re-asked.
	mustResolve(t, env.backend, path)
	mustResolve(t, env.backend, path)
	if got := env.apiRequests(); len(got) != 1 {
		t.Fatalf("formula API requests = %v, want one (the empty answer is remembered)", got)
	}

	// Once the marker expires the lookup is retried — and now succeeds.
	env.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", digest}))
	env.advance(unresolvedTTL + time.Second)
	res := mustResolve(t, env.backend, path)
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate after retry = %+v, want %+v", res.Coordinate, want)
	}
	if got := env.apiRequests(); len(got) != 2 {
		t.Errorf("formula API requests = %v, want a second lookup after the TTL", got)
	}
}

func TestFormulaAPIFailureSuspendsLookups(t *testing.T) {
	env := newRegEnv(t)
	env.setAPIStatus(http.StatusServiceUnavailable)
	first, second := hexOf("8"), hexOf("9")

	mustResolve(t, env.backend, blobPath("homebrew/core/hello", first))
	if !env.backend.lookupsSuspended() {
		t.Fatal("a failing formula API must suspend lookups")
	}
	// While suspended, other bottles do not wait on the API at all.
	res := mustResolve(t, env.backend, blobPath("homebrew/core/wget", second))
	if res.Coordinate.Version != "sha256:"+second {
		t.Errorf("coordinate = %+v, want the digest-derived version", res.Coordinate)
	}
	if got := env.apiRequests(); len(got) != 1 {
		t.Fatalf("formula API requests = %v, want none during the backoff", got)
	}

	// After the backoff the API is asked again.
	env.setAPIStatus(0)
	env.addFormula("wget", formulaJSON("wget", "1.25.0", platformBottle{"x86_64_linux", second}))
	env.advance(lookupBackoff + time.Second)
	res = mustResolve(t, env.backend, blobPath("homebrew/core/wget", second))
	if want := (backends.Coordinate{Name: "wget", Version: "1.25.0"}); res.Coordinate != want {
		t.Errorf("coordinate after backoff = %+v, want %+v", res.Coordinate, want)
	}
}

func TestFormulaAPITimeoutFallsBack(t *testing.T) {
	env := newRegEnv(t)
	env.backend.lookupTimeout = 50 * time.Millisecond
	env.gateFormulaAPI(t) // the API accepts the request and never answers
	digest := hexOf("a")

	start := time.Now()
	res := mustResolve(t, env.backend, blobPath("homebrew/core/hello", digest))
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Resolve took %v: a stalled formula API must not stall the pull", elapsed)
	}
	if want := (backends.Coordinate{Name: "hello", Version: "sha256:" + digest}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if !env.backend.lookupsSuspended() {
		t.Error("a timed-out formula API must suspend lookups")
	}
}

func TestClientCancellationDuringLookupRemembersNothing(t *testing.T) {
	env := newRegEnv(t)
	held := env.gateFormulaAPI(t) // the lookup stays in flight until abandoned
	digest := hexOf("b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Cancel as soon as the lookup has reached the formula API.
		select {
		case <-held.arrived:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, err := env.backend.Resolve(ctx, &backends.Request{
		Method: http.MethodGet, Path: blobPath("homebrew/core/hello", digest), Header: http.Header{},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (a pull is never gated under a fallback because its client left)", err)
	}
	// A client going away says nothing about the API or the bottle.
	if env.backend.lookupsSuspended() {
		t.Error("client cancellation must not suspend formula-API lookups")
	}
	if n := env.backend.index.len(); n != 0 {
		t.Errorf("index holds %d entries after a cancelled lookup, want none", n)
	}
}

// --- coordinate: brew's parallel downloads ----------------------------------

// resolveAsync resolves path on its own goroutine, as a second in-flight request.
func resolveAsync(b *Backend, path string) <-chan *backends.Resolved {
	out := make(chan *backends.Resolved, 1)
	go func() {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Header: http.Header{}})
		if err != nil {
			res = nil
		}
		out <- res
	}()
	return out
}

// fetchManifestAsync pulls a manifest on its own goroutine.
func (e *regEnv) fetchManifestAsync(repo, reference string) <-chan error {
	out := make(chan error, 1)
	go func() {
		res, err := e.backend.Resolve(context.Background(), &backends.Request{
			Method: http.MethodGet, Path: "/v2/" + repo + "/manifests/" + reference,
			Header: http.Header{"Accept": {ociIndexType}},
		})
		if err == nil {
			var fres *backends.FetchResult
			if fres, err = e.backend.Fetch(context.Background(), res); err == nil {
				_, _ = io.Copy(io.Discard, fres.Content)
				_ = fres.Content.Close()
			}
		}
		out <- err
	}()
	return out
}

// With HOMEBREW_DOWNLOAD_CONCURRENCY brew sends a bottle request while the
// manifest request for the same formula is still in flight. The bottle must
// wait for that manifest rather than be gated without the version it carries.
func TestBottleRequestWaitsForManifestInFlight(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("a")
	env.addManifest("homebrew/core/hello", "2.12.3-1",
		ociIndex("hello", "2.12.3", 1, platformBottle{"x86_64_linux", digest}), ociIndexType)
	held := env.gateManifests(t)

	manifestDone := env.fetchManifestAsync("homebrew/core/hello", "2.12.3-1")
	<-held.arrived // the manifest fetch is now in progress at the registry

	bottle := resolveAsync(env.backend, blobPath("homebrew/core/hello", digest))
	select {
	case res := <-bottle:
		t.Fatalf("bottle resolved (%+v) without waiting for its in-flight manifest", res)
	case <-time.After(150 * time.Millisecond):
	}

	held.release()
	if err := <-manifestDone; err != nil {
		t.Fatalf("manifest fetch: %v", err)
	}
	res := <-bottle
	if res == nil {
		t.Fatal("bottle Resolve failed")
	}
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if got := res.Metadata[MetaVersionSource]; got != versionSourceManifest {
		t.Errorf("version source = %q, want %q", got, versionSourceManifest)
	}
	if got := env.apiRequests(); len(got) != 0 {
		t.Errorf("formula API consulted (%v) although the manifest was on its way", got)
	}
}

// The wait is bounded: a manifest fetch that hangs does not hang the bottle,
// which falls back to the formula API.
func TestWaitForManifestInFlightIsBounded(t *testing.T) {
	env := newRegEnv(t)
	env.backend.manifestWait = 50 * time.Millisecond
	digest := hexOf("b")
	env.addManifest("homebrew/core/hello", "2.12.3",
		ociIndex("hello", "2.12.3", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	env.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", digest}))
	held := env.gateManifests(t) // never released before the bottle resolves

	manifestDone := env.fetchManifestAsync("homebrew/core/hello", "2.12.3")
	<-held.arrived

	start := time.Now()
	res := mustResolve(t, env.backend, blobPath("homebrew/core/hello", digest))
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("Resolve took %v, want roughly the 50ms wait bound", elapsed)
	}
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.3"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if got := res.Metadata[MetaVersionSource]; got != versionSourceFormulaAPI {
		t.Errorf("version source = %q, want %q", got, versionSourceFormulaAPI)
	}

	held.release()
	if err := <-manifestDone; err != nil {
		t.Fatalf("manifest fetch: %v", err)
	}
}

// The bottle request can also arrive first: it finds no manifest in flight and
// asks the formula API, which (for a bottle the formula no longer lists) has no
// answer. If the manifest request showed up meanwhile, the bottle waits for it
// instead of settling for the digest-derived version.
func TestManifestArrivingDuringAPILookupStillWins(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("c")
	env.addManifest("homebrew/core/hello", "2.12.2",
		ociIndex("hello", "2.12.2", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	// The formula has moved on to 2.12.3; this bottle is not among its files.
	env.addFormula("hello", formulaJSON("hello", "2.12.3", platformBottle{"x86_64_linux", hexOf("d")}))
	apiHeld := env.gateFormulaAPI(t)
	manifestHeld := env.gateManifests(t)

	// 1. The bottle request: nothing learned, nothing in flight -> formula API.
	bottle := resolveAsync(env.backend, blobPath("homebrew/core/hello", digest))
	<-apiHeld.arrived
	// 2. Its manifest request arrives while the API is being asked.
	manifestDone := env.fetchManifestAsync("homebrew/core/hello", "2.12.2")
	<-manifestHeld.arrived
	// 3. The API answers: no such bottle. The request must now wait for the manifest.
	apiHeld.release()
	select {
	case res := <-bottle:
		t.Fatalf("bottle resolved (%+v) without waiting for the manifest that arrived meanwhile", res)
	case <-time.After(150 * time.Millisecond):
	}
	// 4. The manifest lands and names the version.
	manifestHeld.release()
	if err := <-manifestDone; err != nil {
		t.Fatalf("manifest fetch: %v", err)
	}
	res := <-bottle
	if res == nil {
		t.Fatal("bottle Resolve failed")
	}
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.2"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if got := res.Metadata[MetaVersionSource]; got != versionSourceManifest {
		t.Errorf("version source = %q, want %q", got, versionSourceManifest)
	}
}

// A manifest that completes while the formula API is still being asked is not
// overwritten by the API's empty answer.
func TestEmptyAPIAnswerDoesNotClobberLearnedManifest(t *testing.T) {
	env := newRegEnv(t)
	digest := hexOf("e")
	env.addManifest("homebrew/core/hello", "2.12.2",
		ociIndex("hello", "2.12.2", 0, platformBottle{"x86_64_linux", digest}), ociIndexType)
	apiHeld := env.gateFormulaAPI(t)

	bottle := resolveAsync(env.backend, blobPath("homebrew/core/hello", digest))
	<-apiHeld.arrived
	env.fetchManifest(t, "homebrew/core/hello", "2.12.2") // completes during the lookup
	apiHeld.release()                                     // the API then answers 404

	res := <-bottle
	if res == nil {
		t.Fatal("bottle Resolve failed")
	}
	if want := (backends.Coordinate{Name: "hello", Version: "2.12.2"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	// And the index still holds the manifest's answer for the next request.
	again := mustResolve(t, env.backend, blobPath("homebrew/core/hello", digest))
	if again.Coordinate != res.Coordinate || again.Metadata[MetaVersionSource] != versionSourceManifest {
		t.Errorf("next request = %+v (%s)", again.Coordinate, again.Metadata[MetaVersionSource])
	}
}

// --- no open relay ----------------------------------------------------------

func TestRegistryRequestsStayOnTheConfiguredRegistry(t *testing.T) {
	env := newRegEnv(t, func(o *Options) { o.Offline = true })
	digest := hexOf("c")
	for _, path := range []string{
		"/v2/homebrew/core/hello/manifests/2.12.3-1",
		"/v2/homebrew/core/hello/manifests/sha256:" + digest,
		blobPath("homebrew/core/hello", digest),
		blobPath("homebrew/core/openssl/3", digest),
		blobPath("acme/tap/widget", digest),
	} {
		res := mustResolve(t, env.backend, path)
		if want := env.registry.URL + path; res.UpstreamURL != want {
			t.Errorf("Resolve(%q).UpstreamURL = %q, want %q", path, res.UpstreamURL, want)
		}
	}
}

func TestRegistryURLPreservesBasePath(t *testing.T) {
	b, err := New(Options{
		Name: "h", UpstreamURL: "https://formulae.brew.sh", BottleRegistryURL: "https://mirror.example/ghcr/",
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "t"), Offline: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := mustResolve(t, b, "/v2/homebrew/core/hello/manifests/2.12.3")
	if want := "https://mirror.example/ghcr/v2/homebrew/core/hello/manifests/2.12.3"; res.UpstreamURL != want {
		t.Errorf("upstream URL = %q, want %q", res.UpstreamURL, want)
	}
}

// --- signed API documents ---------------------------------------------------

// The brew client verifies the JWS signature over formula.jws.json, so the
// document must reach it byte-for-byte — including the ghcr URLs in its payload,
// which the backend rewrites in the unsigned documents.
func TestSignedIndexPassesThroughByteExact(t *testing.T) {
	env := newRegEnv(t)
	payload := `[{"name":"hello","versions":{"stable":"2.12.3"},"bottle":{"stable":{"files":{"x86_64_linux":{` +
		`"url":"` + env.registry.URL + `/v2/homebrew/core/hello/blobs/sha256:` + hexOf("d") + `","sha256":"` + hexOf("d") + `"}}}}}]`
	quoted, _ := json.Marshal(payload)
	jws := []byte(`{"payload":` + string(quoted) + `,"signatures":[{"protected":"eyJhbGciOiJQUzUxMiJ9","signature":"c2ln"}]}` + "\n")

	mux := env.formulae.Config.Handler.(*http.ServeMux)
	for _, doc := range []string{"formula.jws.json", "cask.jws.json", "formula_tap_migrations.jws.json"} {
		mux.HandleFunc("/api/"+doc, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jws)
		})
	}
	for _, path := range []string{"/api/formula.jws.json", "/api/cask.jws.json", "/api/formula_tap_migrations.jws.json"} {
		fres, body, err := resolveFetch(t, env.backend, path)
		if err != nil {
			t.Fatalf("fetch %s: %v", path, err)
		}
		if !bytes.Equal(body, jws) {
			t.Errorf("%s was altered in transit:\n got %q\nwant %q", path, body, jws)
		}
		if fres.Resolved.Cacheable {
			t.Errorf("%s is mutable metadata and must not be cached", path)
		}
		if fres.Resolved.Coordinate != (backends.Coordinate{}) {
			t.Errorf("%s coordinate = %+v, want none", path, fres.Resolved.Coordinate)
		}
	}
	if s := env.metrics.Stats(); s.MetadataServed != 3 || s.FormulaRewritten != 0 || s.FormulaServed != 0 {
		t.Errorf("metrics = %+v, want three verbatim documents and no rewrite", s)
	}
}
