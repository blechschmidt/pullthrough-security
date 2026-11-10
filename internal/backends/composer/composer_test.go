package composer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// fakeServer is an in-memory Composer repository serving packages.json, v2
// metadata, and the raw dist archives the metadata points at. It records every
// request it receives so a test can assert exactly what the backend fetched
// upstream — and, as importantly, what it did not.
type fakeServer struct {
	srv      *httptest.Server
	files    map[string][]byte
	handlers map[string]http.HandlerFunc

	mu       sync.Mutex
	requests []recordedRequest
}

type recordedRequest struct {
	path          string
	query         string
	authorization string
}

// newBareServer starts an empty fake upstream.
func newBareServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{files: map[string][]byte{}, handlers: map[string]http.HandlerFunc{}}
	// The handler reads fs.files at request time, so the server can be started
	// before the fixtures (which embed the server's own URL) are populated.
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.requests = append(fs.requests, recordedRequest{path: r.URL.Path, query: r.URL.RawQuery, authorization: r.Header.Get("Authorization")})
		fs.mu.Unlock()
		if h, ok := fs.handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		body, ok := fs.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"upstream-etag"`)
		_, _ = w.Write(body)
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

// requested returns the paths requested so far, in order.
func (fs *fakeServer) requested() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]string, len(fs.requests))
	for i, r := range fs.requests {
		out[i] = r.path
	}
	return out
}

// authorizationFor returns the Authorization header the last request for path
// carried, and whether path was requested at all.
func (fs *fakeServer) authorizationFor(path string) (string, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for i := len(fs.requests) - 1; i >= 0; i-- {
		if fs.requests[i].path == path {
			return fs.requests[i].authorization, true
		}
	}
	return "", false
}

func (fs *fakeServer) reset() {
	fs.mu.Lock()
	fs.requests = nil
	fs.mu.Unlock()
}

// Dist payloads of the standard fixture set.
var (
	goodZip     = []byte("PK\x03\x04 fake console dist zip")
	poisonZip   = []byte("POISONED DIST PAYLOAD")
	nosumZip    = []byte("dist without a shasum")
	devZip      = []byte("PK\x03\x04 dev branch dist")
	redirectZip = []byte("PK\x03\x04 dist behind a redirect")
)

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := newBareServer(t)
	base := fs.srv.URL

	// A good dist whose metadata shasum matches its bytes.
	fs.files["/raw/console-3.2.0.zip"] = goodZip
	// A poisoned dist: metadata names a shasum that the served bytes do not match.
	fs.files["/raw/evil-1.0.0.zip"] = poisonZip
	// A dist whose metadata carries no shasum — what every GitHub zipball looks like.
	fs.files["/raw/nosum-1.0.0.zip"] = nosumZip
	// A dev-branch dist, listed only in the "~dev" document.
	fs.files["/raw/console-dev.zip"] = devZip
	// A dist whose listed URL redirects (api.github.com -> codeload.github.com).
	fs.files["/codeload/redirected.zip"] = redirectZip
	fs.handlers["/api/zipball/abc123"] = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/codeload/redirected.zip", http.StatusFound)
	}

	// Minified, like the real thing: "3.2.0-RC1" shares 3.2.0's commit, so its
	// delta carries no dist and inherits it.
	fs.files["/p2/symfony/console.json"] = []byte(fmt.Sprintf(`{
      "minified": "composer/2.0",
      "packages": {
        "symfony/console": [
          {"name":"symfony/console","version":"3.2.0","license":["MIT"],"dist":{"type":"zip","url":"%s/raw/console-3.2.0.zip","reference":"c0ffee320","shasum":"%s"}},
          {"version":"3.2.0-RC1"},
          {"version":"3.1.0","license":["BSD-3-Clause"],"dist":{"type":"zip","url":"%s/raw/console-3.1.0.zip","reference":"c0ffee310","shasum":""}}
        ]
      },
      "security-advisories": []
    }`, base, sha1Hex(goodZip), base))

	fs.files["/p2/symfony/console~dev.json"] = []byte(fmt.Sprintf(`{
      "minified": "composer/2.0",
      "packages": {
        "symfony/console": [
          {"name":"symfony/console","version":"dev-feature/x","license":["MIT"],"dist":{"type":"zip","url":"%s/raw/console-dev.zip","reference":"d00dfeed","shasum":""}}
        ]
      }
    }`, base))

	fs.files["/p2/evil/pkg.json"] = []byte(fmt.Sprintf(`{
      "packages": {"evil/pkg": [
        {"name":"evil/pkg","version":"1.0.0","dist":{"type":"zip","url":"%s/raw/evil-1.0.0.zip","reference":"bad","shasum":"%s"}}
      ]}
    }`, base, sha1Hex([]byte("the real untampered dist"))))

	fs.files["/p2/no/sum.json"] = []byte(fmt.Sprintf(`{
      "packages": {"no/sum": [
        {"name":"no/sum","version":"1.0.0","dist":{"type":"zip","url":"%s/raw/nosum-1.0.0.zip","reference":"nochk","shasum":""}}
      ]}
    }`, base))

	fs.files["/p2/red/irect.json"] = []byte(fmt.Sprintf(`{
      "packages": {"red/irect": [
        {"name":"red/irect","version":"1.0.0","dist":{"type":"zip","url":"%s/api/zipball/abc123","reference":"abc123","shasum":""}}
      ]}
    }`, base))

	// The root, shaped like Packagist's: an absolute metadata-url on the
	// upstream, a host-root-relative providers-url, and the endpoints the proxy
	// must not let a client reach around it.
	fs.files["/packages.json"] = []byte(fmt.Sprintf(`{
      "packages": [],
      "metadata-url": "%s/p2/%%package%%.json",
      "providers-url": "/p/%%package%%$%%hash%%.json",
      "notify-batch": "%s/downloads/",
      "search": "%s/search.json?q=%%query%%&type=%%type%%",
      "list": "%s/packages/list.json",
      "providers-api": "%s/providers/%%package%%.json",
      "metadata-changes-url": "%s/metadata/changes.json",
      "security-advisories": {"metadata": true, "api-url": "%s/api/security-advisories/"},
      "filter": {"metadata": true, "lists": {"malware": {"enabled": true}}, "summary-url": "%s/lists/all/summary.json"}
    }`, base, base, base, base, base, base, base, base))

	fs.files["/lists/all/summary.json"] = []byte(`{"filter":{"malware":{"evil/pkg":"1.0.0"}}}`)
	fs.files["/p/symfony/console.json"] = []byte(`{"packages":{"symfony/console":{"3.2.0":{"name":"symfony/console","version":"3.2.0"}}}}`)

	return fs
}

func testBackend(t *testing.T, fs *fakeServer, m *Metrics) *Backend {
	t.Helper()
	return testBackendWith(t, fs, Options{Metrics: m, PublicBaseURL: testPublicBase})
}

// testBackendWith builds a backend against fs, filling in the fields a test does
// not care about.
func testBackendWith(t *testing.T, fs *fakeServer, opts Options) *Backend {
	t.Helper()
	if opts.Name == "" {
		opts.Name = "packagist"
	}
	if opts.UpstreamURL == "" {
		opts.UpstreamURL = fs.srv.URL
	}
	if opts.Client == nil {
		opts.Client = upstream.NewWithHTTPClient(fs.srv.Client(), "test/1")
	}
	b, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func resolve(t *testing.T, b *Backend, path string) *backends.Resolved {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	return res
}

func fetchAll(t *testing.T, b *Backend, res *backends.Resolved) (*backends.FetchResult, []byte, error) {
	t.Helper()
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		return nil, nil, err
	}
	if fr.Content == nil {
		return fr, nil, nil
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	return fr, body, rerr
}

// The dist path names the package AND the version, so the coordinate the
// admission gates need is complete at Resolve time — before any fetch.
func TestResolveDistCoordinate(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, nil)

	res := resolve(t, b, "/dist/symfony/console/3.2.0/c0ffee320.zip")
	if want := (backends.Coordinate{Name: "symfony/console", Version: "3.2.0"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	if !res.Cacheable {
		t.Error("dist should be cacheable")
	}
	if res.Metadata[metaVerify] != "1" {
		t.Error("dist should be flagged for verification")
	}
	if want := "packagist:dist/symfony/console/3.2.0/c0ffee320.zip"; res.CacheKey != want {
		t.Errorf("cache key = %q, want %q", res.CacheKey, want)
	}
	if want := fs.srv.URL + "/p2/symfony/console.json"; res.UpstreamURL != want {
		t.Errorf("upstream URL = %q, want %q", res.UpstreamURL, want)
	}

	// A dev branch with a "/" in its name: the whole name is the version, and
	// the metadata it will be looked up in is the "~dev" document.
	dev := resolve(t, b, "/dist/symfony/console/dev-feature/x/d00dfeed.zip")
	if want := (backends.Coordinate{Name: "symfony/console", Version: "dev-feature/x"}); dev.Coordinate != want {
		t.Errorf("dev coordinate = %+v, want %+v", dev.Coordinate, want)
	}
	if want := fs.srv.URL + "/p2/symfony/console~dev.json"; dev.UpstreamURL != want {
		t.Errorf("dev upstream URL = %q, want %q", dev.UpstreamURL, want)
	}

	// Resolve alone must not have touched the upstream.
	if got := fs.requested(); len(got) != 0 {
		t.Errorf("Resolve fetched upstream: %v", got)
	}
}

// Every spelling of one dist — the percent-decoded path the gateway hands over,
// the empty-reference alias, a trailing slash — shares a single cache entry.
func TestResolveDistCacheKeyIsCanonical(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	a := resolve(t, b, "/dist/no/sum/1.0.0/_.zip")
	for _, alias := range []string{"/dist/no/sum/1.0.0/.zip", "/dist/no/sum/1.0.0/_.zip/", "dist/no/sum/1.0.0/_.zip"} {
		if got := resolve(t, b, alias); got.CacheKey != a.CacheKey {
			t.Errorf("%q cache key = %q, want %q", alias, got.CacheKey, a.CacheKey)
		}
	}
}

func TestResolveCacheability(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{"/packages.json", "/p2/symfony/console.json", "/p2/symfony/console~dev.json", "/p/symfony/console.json", "/lists/all/summary.json"} {
		res := resolve(t, b, p)
		if res.Cacheable {
			t.Errorf("%q must not be cacheable", p)
		}
		if res.Coordinate.Version != "" {
			t.Errorf("%q is a document, not a versioned artifact: %+v", p, res.Coordinate)
		}
	}
	// A package document still names its package (for the name-based gates).
	if got := resolve(t, b, "/p2/symfony/console~dev.json").Coordinate.Name; got != "symfony/console" {
		t.Errorf("metadata coordinate name = %q", got)
	}

	// Only reads are cached.
	for method, want := range map[string]bool{http.MethodGet: true, http.MethodHead: true, "": true, http.MethodPost: false} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: method, Path: "/dist/symfony/console/3.2.0/c0ffee320.zip", Query: url.Values{}})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", method, err)
		}
		if res.Cacheable != want {
			t.Errorf("method %q cacheable = %v, want %v", method, res.Cacheable, want)
		}
	}

	// Every dist goes through the cache (and with it the content gates), even one
	// whose locator carries no reference.
	if res := resolve(t, b, "/dist/symfony/console/dev-master/_.zip"); !res.Cacheable {
		t.Error("a reference-less dist must still be cached")
	}
}

func TestResolveRejectsBadPath(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{
		"/nope",
		// The version-less dist form cannot be admission-gated and is not served.
		"/dist/symfony/console/c0ffee320.zip",
		"/search.json",
	} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q): expected ErrNotSupported, got %v", p, err)
		}
	}
	if _, err := b.Resolve(context.Background(), nil); err == nil {
		t.Error("a nil request should be rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Resolve(ctx, &backends.Request{Path: "/packages.json"}); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context should be honored, got %v", err)
	}
}

func TestFetchDistVerifiesShasum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/symfony/console/3.2.0/c0ffee320.zip")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch+read: %v", err)
	}
	if string(body) != string(goodZip) {
		t.Error("served dist bytes differ from upstream")
	}
	if m.Stats().DistVerified != 1 {
		t.Errorf("DistVerified = %v, want 1", m.Stats().DistVerified)
	}
	if fr.Header.Get("X-Checksum-Verified") != "sha1" {
		t.Errorf("X-Checksum-Verified = %q", fr.Header.Get("X-Checksum-Verified"))
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "sha1" {
		t.Errorf("checksum metadata = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Resolved.Coordinate.Version != "3.2.0" {
		t.Errorf("version = %q", fr.Resolved.Coordinate.Version)
	}
	if fr.Resolved.Metadata[MetaLicenses] != "MIT" {
		t.Errorf("licenses = %q", fr.Resolved.Metadata[MetaLicenses])
	}
	if got, want := fr.Resolved.Metadata[MetaDistURL], fs.srv.URL+"/raw/console-3.2.0.zip"; got != want {
		t.Errorf("dist URL metadata = %q, want %q", got, want)
	}
	if got := fr.Resolved.Metadata[MetaReference]; got != "c0ffee320" {
		t.Errorf("reference metadata = %q", got)
	}
	// Exactly the metadata document and the one URL it lists were fetched.
	if got, want := fs.requested(), []string{"/p2/symfony/console.json", "/raw/console-3.2.0.zip"}; !equalStrings(got, want) {
		t.Errorf("upstream requests = %v, want %v", got, want)
	}
}

// A version whose minified delta carries no dist inherits its predecessor's; the
// dist request names that version, and it is the coordinate the gates see.
func TestFetchDistInheritedByAnotherVersion(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})

	res := resolve(t, b, "/dist/symfony/console/3.2.0-RC1/c0ffee320.zip")
	if want := (backends.Coordinate{Name: "symfony/console", Version: "3.2.0-RC1"}); res.Coordinate != want {
		t.Errorf("coordinate = %+v, want %+v", res.Coordinate, want)
	}
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(goodZip) {
		t.Error("served dist bytes differ from upstream")
	}
}

func TestFetchPoisonedDistFailsClosed(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/evil/pkg/1.0.0/bad.zip")
	_, _, err := fetchAll(t, b, res)
	var mm *ChecksumMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("expected ChecksumMismatchError, got %v", err)
	}
	if m.Stats().ChecksumMismatch != 1 {
		t.Errorf("ChecksumMismatch = %v, want 1", m.Stats().ChecksumMismatch)
	}
	if m.Stats().DistVerified != 0 {
		t.Errorf("DistVerified = %v, want 0", m.Stats().DistVerified)
	}
}

// No shasum in the metadata (every GitHub zipball): the archive is served and
// cached exactly as fetched, and recorded as unverified.
func TestFetchDistWithoutShasum(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/dist/no/sum/1.0.0/nochk.zip")
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(nosumZip) {
		t.Error("served bytes differ")
	}
	if m.Stats().ChecksumMissing != 1 {
		t.Errorf("ChecksumMissing = %v, want 1", m.Stats().ChecksumMissing)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "none" {
		t.Errorf("checksum metadata = %q", fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if fr.Header.Get("X-Checksum-Verified") != "" {
		t.Errorf("X-Checksum-Verified = %q on an unverified dist", fr.Header.Get("X-Checksum-Verified"))
	}
}

// The dist endpoint is no relay: it fetches only what the upstream metadata
// lists for exactly that package, version, reference and type. Everything else
// is a 404, and no archive URL is ever requested on its behalf.
func TestFetchDistRefusesUnlisted(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})

	cases := []struct{ name, path string }{
		{"reference the upstream never published", "/dist/symfony/console/3.2.0/doesnotexist.zip"},
		{"another version's reference", "/dist/symfony/console/3.1.0/c0ffee320.zip"},
		{"a listed reference under an unlisted version", "/dist/symfony/console/9.9.9/c0ffee320.zip"},
		{"a listed reference under a version from the other document", "/dist/symfony/console/dev-feature/x/c0ffee320.zip"},
		{"the placeholder for a dist that has a reference", "/dist/symfony/console/3.2.0/_.zip"},
		{"a type the entry does not have", "/dist/symfony/console/3.2.0/c0ffee320.tar"},
		{"a package the upstream does not have", "/dist/ghost/pkg/1.0.0/c0ffee320.zip"},
		{"another package's dist", "/dist/no/sum/3.2.0/c0ffee320.zip"},
	}
	for _, c := range cases {
		fs.reset()
		res := resolve(t, b, c.path)
		_, _, err := fetchAll(t, b, res)
		var se *backends.StatusError
		if !errors.As(err, &se) || se.Status != http.StatusNotFound {
			t.Errorf("%s: expected a 404 StatusError, got %v", c.name, err)
		}
		for _, p := range fs.requested() {
			if !strings.HasPrefix(p, "/p2/") {
				t.Errorf("%s: fetched %q upstream for an unlisted dist", c.name, p)
			}
		}
	}
}

// Dev versions live in the "~dev" document; it is consulted first for them.
func TestFetchDevDistFromDevDocument(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})

	res := resolve(t, b, "/dist/symfony/console/dev-feature/x/d00dfeed.zip")
	_, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(devZip) {
		t.Error("served dist bytes differ from upstream")
	}
	if got, want := fs.requested(), []string{"/p2/symfony/console~dev.json", "/raw/console-dev.zip"}; !equalStrings(got, want) {
		t.Errorf("upstream requests = %v, want %v", got, want)
	}
}

// A mirror may file a version in the "other" document; the lookup falls back to
// it instead of refusing a dist the upstream does list.
func TestFetchDistFallsBackToOtherDocument(t *testing.T) {
	fs := newBareServer(t)
	fs.files["/raw/a.zip"] = goodZip
	fs.files["/raw/b.zip"] = devZip
	// A tagged version listed only in the "~dev" document...
	fs.files["/p2/odd/mirror~dev.json"] = []byte(fmt.Sprintf(
		`{"packages":{"odd/mirror":[{"version":"1.0.0","dist":{"type":"zip","url":"%s/raw/a.zip","reference":"aaa"}}]}}`, fs.srv.URL))
	// ...and a dev version listed only in the main one.
	fs.files["/p2/odd/mirror.json"] = []byte(fmt.Sprintf(
		`{"packages":{"odd/mirror":[{"version":"dev-main","dist":{"type":"zip","url":"%s/raw/b.zip","reference":"bbb"}}]}}`, fs.srv.URL))
	b := testBackend(t, fs, &Metrics{})

	for path, want := range map[string][]byte{
		"/dist/odd/mirror/1.0.0/aaa.zip":    goodZip,
		"/dist/odd/mirror/dev-main/bbb.zip": devZip,
	} {
		_, body, err := fetchAll(t, b, resolve(t, b, path))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if string(body) != string(want) {
			t.Errorf("%s: served bytes differ", path)
		}
	}
}

// The listed URL is fetched through the shared client, which follows redirects —
// GitHub's api.github.com zipball URL answers with a 302 to codeload.github.com.
func TestFetchDistFollowsRedirect(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})

	fr, body, err := fetchAll(t, b, resolve(t, b, "/dist/red/irect/1.0.0/abc123.zip"))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != string(redirectZip) {
		t.Error("served bytes are not the redirect target's")
	}
	if got, want := fs.requested(), []string{"/p2/red/irect.json", "/api/zipball/abc123", "/codeload/redirected.zip"}; !equalStrings(got, want) {
		t.Errorf("upstream requests = %v, want %v", got, want)
	}
	// The recorded origin is the URL the metadata lists, not where it led.
	if got, want := fr.Resolved.Metadata[MetaDistURL], fs.srv.URL+"/api/zipball/abc123"; got != want {
		t.Errorf("dist URL metadata = %q, want %q", got, want)
	}
}

// The upstream's credentials authenticate the proxy to the upstream. A dist the
// metadata places on another host must never receive them.
func TestFetchDistKeepsCredentialsOnUpstreamHost(t *testing.T) {
	upstreamRepo := newBareServer(t)
	elsewhere := newBareServer(t) // stands in for api.github.com / a CDN
	elsewhere.files["/zipball/abc"] = devZip
	upstreamRepo.files["/dists/own.zip"] = goodZip
	upstreamRepo.files["/p2/acme/pkg.json"] = []byte(fmt.Sprintf(`{"packages":{"acme/pkg":[
	  {"version":"2.0.0","dist":{"type":"zip","url":"%s/zipball/abc","reference":"abc"}},
	  {"version":"1.0.0","dist":{"type":"zip","url":"%s/dists/own.zip","reference":"own"}}
	]}}`, elsewhere.srv.URL, upstreamRepo.srv.URL))

	b := testBackendWith(t, upstreamRepo, Options{
		PublicBaseURL: testPublicBase,
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		Credentials:   upstream.Credentials{Username: "proxy", Password: "s3cret"},
	})

	if _, body, err := fetchAll(t, b, resolve(t, b, "/dist/acme/pkg/2.0.0/abc.zip")); err != nil || string(body) != string(devZip) {
		t.Fatalf("fetch foreign-host dist: %v", err)
	}
	if auth, ok := upstreamRepo.authorizationFor("/p2/acme/pkg.json"); !ok || !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("the metadata request must be authenticated, got %q (requested=%v)", auth, ok)
	}
	if auth, ok := elsewhere.authorizationFor("/zipball/abc"); !ok || auth != "" {
		t.Errorf("upstream credentials leaked to another host: %q (requested=%v)", auth, ok)
	}

	if _, body, err := fetchAll(t, b, resolve(t, b, "/dist/acme/pkg/1.0.0/own.zip")); err != nil || string(body) != string(goodZip) {
		t.Fatalf("fetch upstream-host dist: %v", err)
	}
	if auth, ok := upstreamRepo.authorizationFor("/dists/own.zip"); !ok || !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("a dist on the upstream host must be authenticated, got %q (requested=%v)", auth, ok)
	}
}

// Some registries hand out dist URLs that carry an access token. The archive is
// fetched from the URL exactly as listed, but what is kept in the cache metadata
// is stripped of credentials and query string.
func TestFetchDistRecordsURLWithoutSecrets(t *testing.T) {
	fs := newBareServer(t)
	fs.files["/raw/signed.zip"] = goodZip
	signed := strings.Replace(fs.srv.URL, "http://", "http://user:pw@", 1) + "/raw/signed.zip?token=SECRET&expires=1"
	fs.files["/p2/acme/pkg.json"] = []byte(fmt.Sprintf(
		`{"packages":{"acme/pkg":[{"version":"1.0.0","dist":{"type":"zip","url":%q,"reference":"abc"}}]}}`, signed))
	b := testBackend(t, fs, &Metrics{})

	fr, body, err := fetchAll(t, b, resolve(t, b, "/dist/acme/pkg/1.0.0/abc.zip"))
	if err != nil || string(body) != string(goodZip) {
		t.Fatalf("fetch: %v", err)
	}
	if got, want := fr.Resolved.Metadata[MetaDistURL], fs.srv.URL+"/raw/signed.zip"; got != want {
		t.Errorf("recorded dist URL = %q, want %q", got, want)
	}
	for k, v := range fr.Resolved.Metadata {
		if strings.Contains(v, "SECRET") || strings.Contains(v, "user:pw") {
			t.Errorf("metadata %s = %q keeps a credential", k, v)
		}
	}
	// The upstream still got the URL the metadata listed.
	fs.mu.Lock()
	last := fs.requests[len(fs.requests)-1]
	fs.mu.Unlock()
	if last.path != "/raw/signed.zip" || last.query != "token=SECRET&expires=1" {
		t.Errorf("upstream dist request = %+v", last)
	}
}

// An upstream failure while looking a dist up is reported as such, not disguised
// as "no such dist" (which the proxy might negatively cache).
func TestFetchDistUpstreamFailureIsNotNotFound(t *testing.T) {
	fs := newBareServer(t)
	fs.handlers["/p2/flaky/pkg.json"] = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}
	b := testBackend(t, fs, &Metrics{})

	_, _, err := fetchAll(t, b, resolve(t, b, "/dist/flaky/pkg/1.0.0/abc.zip"))
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusServiceUnavailable {
		t.Fatalf("expected the upstream's 503, got %v", err)
	}

	// A metadata document that is not valid metadata is an upstream fault too.
	m := &Metrics{}
	b = testBackend(t, fs, m)
	fs.files["/p2/broken/pkg.json"] = []byte(`<html>cdn error</html>`)
	_, _, err = fetchAll(t, b, resolve(t, b, "/dist/broken/pkg/1.0.0/abc.zip"))
	if err == nil || errors.As(err, &se) && se.Status == http.StatusNotFound {
		t.Fatalf("expected a hard failure for malformed metadata, got %v", err)
	}
	if m.Stats().MetadataErrors != 1 {
		t.Errorf("MetadataErrors = %v, want 1", m.Stats().MetadataErrors)
	}
}

// A listed dist whose URL is not http(s) was never advertised through the proxy
// and is not something the proxy fetches.
func TestFetchDistRefusesNonHTTPURL(t *testing.T) {
	fs := newBareServer(t)
	fs.files["/p2/local/pkg.json"] = []byte(`{"packages":{"local/pkg":[
	  {"version":"1.0.0","dist":{"type":"zip","url":"file:///etc/passwd","reference":"abc"}},
	  {"version":"2.0.0","dist":{"type":"zip","url":"/srv/dists/pkg.zip","reference":"def"}}
	]}}`)
	b := testBackend(t, fs, &Metrics{})
	for _, p := range []string{"/dist/local/pkg/1.0.0/abc.zip", "/dist/local/pkg/2.0.0/def.zip"} {
		_, _, err := fetchAll(t, b, resolve(t, b, p))
		var se *backends.StatusError
		if !errors.As(err, &se) || se.Status != http.StatusNotFound {
			t.Errorf("%s: expected a 404 StatusError, got %v", p, err)
		}
	}
}

func TestFetchRootIsRewritten(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	res := resolve(t, b, "/packages.json")
	// A client validator must not be relayed upstream for a rewritten document.
	res.IfNoneMatch = `"upstream-etag"`
	fr, body, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch root: %v", err)
	}
	if fr.NotModified {
		t.Fatal("a rewritten document must not be answered from the upstream's validator")
	}
	root := decodeObject(t, body)
	if got, want := root["metadata-url"], testPublicBase+"/p2/%package%.json"; got != want {
		t.Errorf("metadata-url = %v, want %q", got, want)
	}
	if got, want := root["providers-url"], testPublicBase+"/p/%package%$%hash%.json"; got != want {
		t.Errorf("providers-url = %v, want %q", got, want)
	}
	if _, present := root["notify-batch"]; present {
		t.Error("notify-batch must not reach the client")
	}
	if strings.Contains(string(body), fs.srv.URL) {
		t.Errorf("the served root still points at the upstream:\n%s", body)
	}
	if fr.Size != int64(len(body)) {
		t.Errorf("Size = %d, body is %d bytes", fr.Size, len(body))
	}
	if fr.Header.Get("ETag") != "" {
		t.Errorf("the upstream ETag %q describes a different representation", fr.Header.Get("ETag"))
	}
	if fr.MediaType == "" {
		t.Error("media type missing")
	}
	if m.Stats().MetadataServed != 1 {
		t.Errorf("MetadataServed = %v, want 1", m.Stats().MetadataServed)
	}
}

func TestFetchMetadataIsRewritten(t *testing.T) {
	fs := newFakeServer(t)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	for _, p := range []string{"/p2/symfony/console.json", "/p2/symfony/console~dev.json"} {
		res := resolve(t, b, p)
		fr, body, err := fetchAll(t, b, res)
		if err != nil {
			t.Fatalf("fetch %s: %v", p, err)
		}
		if strings.Contains(string(body), fs.srv.URL) {
			t.Errorf("%s still hands the client an upstream URL:\n%s", p, body)
		}
		original := fs.files[p]
		assertOnlyDistURLsChanged(t, original, body, "symfony/console")
		if n := assertDistURLsResolve(t, b, original, body, "symfony/console"); n == 0 {
			t.Errorf("%s: no dist URL was rewritten", p)
		}
		if fr.Size != int64(len(body)) {
			t.Errorf("%s: Size = %d, body is %d bytes", p, fr.Size, len(body))
		}
		if fr.Header.Get("ETag") != "" {
			t.Errorf("%s: upstream ETag passed on for a rewritten document", p)
		}
	}
	versions := clientVersions(t, mustFetch(t, b, "/p2/symfony/console.json"), "symfony/console")
	want := []string{
		testPublicBase + "/dist/symfony/console/3.2.0/c0ffee320.zip",
		testPublicBase + "/dist/symfony/console/3.2.0-RC1/c0ffee320.zip",
		testPublicBase + "/dist/symfony/console/3.1.0/c0ffee310.zip",
	}
	for i, v := range versions {
		if got := distOf(t, v)["url"]; got != want[i] {
			t.Errorf("version %v dist.url = %v, want %q", v["version"], got, want[i])
		}
	}
	if m.Stats().MetadataParsed != 3 {
		t.Errorf("MetadataParsed = %v, want 3", m.Stats().MetadataParsed)
	}
	if m.Stats().MetadataServed != 3 {
		t.Errorf("MetadataServed = %v, want 3", m.Stats().MetadataServed)
	}
}

// A root or metadata document the backend cannot rewrite is refused: passing it
// through unmodified would send the client around the proxy.
func TestFetchMalformedDocumentIsRefused(t *testing.T) {
	fs := newBareServer(t)
	fs.files["/packages.json"] = []byte(`<html>cdn error</html>`)
	fs.files["/p2/acme/pkg.json"] = []byte(`["not", "an", "object"]`)
	m := &Metrics{}
	b := testBackend(t, fs, m)

	for _, p := range []string{"/packages.json", "/p2/acme/pkg.json"} {
		fr, body, err := fetchAll(t, b, resolve(t, b, p))
		if err == nil {
			t.Errorf("%s: expected an error, served %q (%+v)", p, body, fr)
		}
	}
	if m.Stats().MetadataErrors != 1 {
		t.Errorf("MetadataErrors = %v, want 1", m.Stats().MetadataErrors)
	}
	if m.Stats().MetadataServed != 0 {
		t.Errorf("MetadataServed = %v, want 0", m.Stats().MetadataServed)
	}
}

// Legacy provider documents and filter-list documents stream through untouched,
// validators and all.
func TestFetchPassthroughDocuments(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, &Metrics{})
	for _, p := range []string{"/p/symfony/console.json", "/lists/all/summary.json"} {
		fr, body, err := fetchAll(t, b, resolve(t, b, p))
		if err != nil {
			t.Fatalf("fetch %s: %v", p, err)
		}
		if string(body) != string(fs.files[p]) {
			t.Errorf("%s: served bytes differ from upstream", p)
		}
		if fr.Header.Get("ETag") != `"upstream-etag"` {
			t.Errorf("%s: ETag = %q", p, fr.Header.Get("ETag"))
		}
	}

	// ...including a conditional request answered 304 by the upstream.
	fs.handlers["/lists/all/summary.json"] = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"upstream-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(fs.files["/lists/all/summary.json"])
	}
	res := resolve(t, b, "/lists/all/summary.json")
	res.IfNoneMatch = `"upstream-etag"`
	fr, err := b.Fetch(context.Background(), res)
	if err != nil || !fr.NotModified {
		t.Errorf("expected a relayed 304, got %+v, %v", fr, err)
	}
}

func TestFetchUpstreamStatusIsRelayed(t *testing.T) {
	b := testBackend(t, newFakeServer(t), &Metrics{})
	_, _, err := fetchAll(t, b, resolve(t, b, "/p2/ghost/pkg.json"))
	var se *backends.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Fatalf("expected a 404 StatusError, got %v", err)
	}
	if _, err := b.Fetch(context.Background(), nil); err == nil {
		t.Error("a nil resolved should be rejected")
	}
}

// composerClient is a minimal stand-in for a Composer client that has been told
// about nothing but the proxy repository. It follows the URLs the repository
// hands it exactly as Composer does and fails the test the moment one of them
// leaves the proxy, so a passing walk proves an install stays on the proxy.
type composerClient struct {
	t *testing.T
	b *Backend
	// origin is the scheme and host the client reaches the proxy on, and mount
	// the path the backend is served under.
	origin, mount string
}

// canonicalize resolves a root-relative URL from packages.json against the
// repository's scheme and host (ComposerRepository::canonicalizeUrl).
func (c *composerClient) canonicalize(u string) string {
	if strings.HasPrefix(u, "/") {
		return c.origin + u
	}
	return u
}

// get fetches an absolute URL, which must be on the proxy mount.
func (c *composerClient) get(rawURL string) []byte {
	c.t.Helper()
	prefix := c.origin + c.mount
	if !strings.HasPrefix(rawURL, prefix+"/") {
		c.t.Fatalf("the client was sent off the proxy: %q", rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		c.t.Fatalf("bad URL %q: %v", rawURL, err)
	}
	// The gateway hands the backend the decoded path below the mount.
	res, err := c.b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet,
		Path:   strings.TrimPrefix(u.Path, c.mount),
		Query:  u.Query(),
	})
	if err != nil {
		c.t.Fatalf("Resolve(%q): %v", rawURL, err)
	}
	_, body, err := fetchAll(c.t, c.b, res)
	if err != nil {
		c.t.Fatalf("Fetch(%q): %v", rawURL, err)
	}
	return body
}

// install resolves and downloads one package version the way `composer install`
// does: root -> metadata-url -> the version's dist URLs (mirrors first).
func (c *composerClient) install(name, version string) []byte {
	c.t.Helper()
	root := decodeObject(c.t, c.get(c.origin+c.mount+"/packages.json"))

	metadataURL, _ := root["metadata-url"].(string)
	if metadataURL == "" {
		c.t.Fatalf("no metadata-url in the root: %v", root)
	}
	for _, key := range []string{"notify-batch", "notify", "search", "list", "providers-api"} {
		if v, present := root[key]; present {
			c.t.Errorf("the root tells the client about %s = %v", key, v)
		}
	}

	file := name
	if isDevVersion(version) {
		file += "~dev"
	}
	doc := c.get(strings.ReplaceAll(c.canonicalize(metadataURL), "%package%", file))
	for _, v := range clientVersions(c.t, doc, name) {
		if v["version"] != version {
			continue
		}
		dist := distOf(c.t, v)
		reference, _ := dist["reference"].(string)
		distType, _ := dist["type"].(string)
		distURL, _ := dist["url"].(string)

		// Package::getDistUrls: the package's own URL, with every preferred mirror
		// (its template expanded by ComposerMirror::processUrl) put in front.
		urls := []string{distURL}
		mirrors, _ := root["mirrors"].([]any)
		for _, m := range mirrors {
			mirror, _ := m.(map[string]any)
			template, _ := mirror["dist-url"].(string)
			expanded := strings.NewReplacer(
				"%package%", name, "%prettyVersion%", version, "%reference%", reference, "%type%", distType,
			).Replace(c.canonicalize(template))
			if mirror["preferred"] == true {
				urls = append([]string{expanded}, urls...)
			} else {
				urls = append(urls, expanded)
			}
		}
		// Composer downloads from the first URL; one that is not http(s) would be
		// read as a local file, which is of no use to a remote client.
		if !isHTTPURL(urls[0]) {
			c.t.Fatalf("%s %s: the first dist URL is not downloadable: %v", name, version, urls)
		}
		// The request the client is about to make is what the admission gates see:
		// it must name the very package and version being installed.
		if u, err := url.Parse(urls[0]); err != nil {
			c.t.Fatalf("%s %s: bad dist URL %q: %v", name, version, urls[0], err)
		} else if res, ok := classify(strings.TrimPrefix(u.Path, c.mount)); !ok || res.coordinateName() != name || res.version != version {
			c.t.Errorf("%s %s: the dist URL %q names %s@%s", name, version, urls[0], res.coordinateName(), res.version)
		}
		return c.get(urls[0])
	}
	c.t.Fatalf("%s %s is not in the served metadata", name, version)
	return nil
}

// The end-to-end property: a client that knows only the proxy can install — a
// tagged release, a release that inherits its dist, and a slash-named dev branch
// — without ever being handed a URL off the proxy, with or without a public base.
func TestClientInstallStaysOnProxy(t *testing.T) {
	const origin, mount = "https://proxy.example.com", "/v1/packagist"
	for _, mode := range []struct{ name, publicBase string }{
		{"absolute public base", origin + mount},
		{"no public base", ""},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fs := newFakeServer(t)
			b := testBackendWith(t, fs, Options{PublicBaseURL: mode.publicBase})
			client := &composerClient{t: t, b: b, origin: origin, mount: mount}

			for _, c := range []struct {
				name, version string
				want          []byte
			}{
				{"symfony/console", "3.2.0", goodZip},
				{"symfony/console", "3.2.0-RC1", goodZip},
				{"symfony/console", "dev-feature/x", devZip},
				{"no/sum", "1.0.0", nosumZip},
				{"red/irect", "1.0.0", redirectZip},
			} {
				if got := client.install(c.name, c.version); string(got) != string(c.want) {
					t.Errorf("%s %s: installed bytes differ from the upstream archive", c.name, c.version)
				}
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	cli := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	cases := []Options{
		{Name: "", UpstreamURL: "https://x", Client: cli},
		{Name: "x", UpstreamURL: "", Client: cli},
		{Name: "x", UpstreamURL: "ftp://x", Client: cli},
		{Name: "x", UpstreamURL: "https://x", Client: nil},
		// The public base is what clients are sent to: it must be something they
		// can resolve.
		{Name: "x", UpstreamURL: "https://x", Client: cli, PublicBaseURL: "proxy.example.com/v1/x"},
		{Name: "x", UpstreamURL: "https://x", Client: cli, PublicBaseURL: "ftp://proxy.example.com/v1/x"},
		{Name: "x", UpstreamURL: "https://x", Client: cli, PublicBaseURL: "//proxy.example.com/v1/x"},
		{Name: "x", UpstreamURL: "https://x", Client: cli, PublicBaseURL: "https:///v1/x"},
	}
	for i, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestNewPublicBase(t *testing.T) {
	cli := upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
	cases := []struct {
		in           string
		wantBase     string
		wantAbsolute bool
	}{
		{"https://proxy.example.com/v1/packagist", "https://proxy.example.com/v1/packagist", true},
		{"http://127.0.0.1:8080/v1/packagist/", "http://127.0.0.1:8080/v1/packagist", true},
		{"  https://proxy.example.com/v1/packagist  ", "https://proxy.example.com/v1/packagist", true},
		// No public URL configured: main.go passes the root-relative mount, and a
		// direct caller may pass nothing at all.
		{"/v1/packagist", "/v1/packagist", false},
		{"/v1/packagist/", "/v1/packagist", false},
		{"", "/v1/packagist", false},
	}
	for _, c := range cases {
		b, err := New(Options{Name: "packagist", UpstreamURL: "https://repo.packagist.org", PublicBaseURL: c.in, Client: cli})
		if err != nil {
			t.Errorf("New(%q): %v", c.in, err)
			continue
		}
		if b.publicBase != c.wantBase || b.absolutePublicBase != c.wantAbsolute {
			t.Errorf("New(%q): base = %q absolute = %v, want %q %v", c.in, b.publicBase, b.absolutePublicBase, c.wantBase, c.wantAbsolute)
		}
	}
}

// A repository served under a path prefix keeps that prefix in every upstream
// URL the backend builds.
func TestUpstreamBasePathIsPreserved(t *testing.T) {
	fs := newBareServer(t)
	fs.files["/acme/raw/a.zip"] = goodZip
	fs.files["/acme/p2/acme/pkg.json"] = []byte(fmt.Sprintf(
		`{"packages":{"acme/pkg":[{"version":"1.0.0","dist":{"type":"zip","url":"%s/acme/raw/a.zip","reference":"aaa"}}]}}`, fs.srv.URL))
	fs.files["/acme/packages.json"] = []byte(`{"metadata-url":"/acme/p2/%package%.json","filter":{"metadata":true,"summary-url":"/acme/lists/all/summary.json"}}`)
	b := testBackendWith(t, fs, Options{UpstreamURL: fs.srv.URL + "/acme/", PublicBaseURL: testPublicBase})

	root := decodeObject(t, mustFetch(t, b, "/packages.json"))
	if got, want := root["metadata-url"], testPublicBase+"/p2/%package%.json"; got != want {
		t.Errorf("metadata-url = %v, want %q", got, want)
	}
	filter, _ := root["filter"].(map[string]any)
	if got, want := filter["summary-url"], testPublicBase+"/lists/all/summary.json"; got != want {
		t.Errorf("filter.summary-url = %v, want %q", got, want)
	}
	if _, body, err := fetchAll(t, b, resolve(t, b, "/dist/acme/pkg/1.0.0/aaa.zip")); err != nil || string(body) != string(goodZip) {
		t.Errorf("dist under a base path: %v", err)
	}
	if got, want := fs.requested(), []string{"/acme/packages.json", "/acme/p2/acme/pkg.json", "/acme/raw/a.zip"}; !equalStrings(got, want) {
		t.Errorf("upstream requests = %v, want %v", got, want)
	}
}

// Query parameters of a document request are forwarded; a dist's are not part of
// its identity.
func TestResolveQueryHandling(t *testing.T) {
	fs := newFakeServer(t)
	b := testBackend(t, fs, nil)
	res, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet, Path: "/lists/all/summary.json", Query: url.Values{"v": {"2"}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := fs.srv.URL + "/lists/all/summary.json?v=2"; res.UpstreamURL != want {
		t.Errorf("upstream URL = %q, want %q", res.UpstreamURL, want)
	}
	plain := resolve(t, b, "/dist/symfony/console/3.2.0/c0ffee320.zip")
	withQuery, err := b.Resolve(context.Background(), &backends.Request{
		Method: http.MethodGet, Path: "/dist/symfony/console/3.2.0/c0ffee320.zip", Query: url.Values{"x": {"1"}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if withQuery.CacheKey != plain.CacheKey || withQuery.UpstreamURL != plain.UpstreamURL {
		t.Errorf("a query string changed a dist's identity: %+v vs %+v", withQuery, plain)
	}
}

func mustFetch(t *testing.T, b *Backend, path string) []byte {
	t.Helper()
	_, body, err := fetchAll(t, b, resolve(t, b, path))
	if err != nil {
		t.Fatalf("fetch %s: %v", path, err)
	}
	return body
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Guard against the fixture drifting from the documents the tests reason about.
func TestFakeServerFixturesAreValidJSON(t *testing.T) {
	fs := newFakeServer(t)
	for path, body := range fs.files {
		if !strings.HasSuffix(path, ".json") {
			continue
		}
		if !json.Valid(body) {
			t.Errorf("fixture %s is not valid JSON:\n%s", path, body)
		}
	}
}
