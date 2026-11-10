package pkgmgr

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func testClient() *upstream.Client {
	return upstream.NewWithHTTPClient(http.DefaultClient, "test/1")
}

// fetch runs Resolve+Fetch for path and returns the resolved resource, the
// served body, and any error. A non-nil StatusError (or transport error) is
// returned via err.
func fetch(t *testing.T, b backends.Backend, path string) (*backends.Resolved, string) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: path})
	if err != nil {
		t.Fatalf("Resolve(%s): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatalf("Fetch(%s): %v", path, err)
	}
	defer fr.Content.Close()
	body, err := io.ReadAll(fr.Content)
	if err != nil {
		t.Fatalf("ReadAll(%s): %v", path, err)
	}
	return res, string(body)
}

func TestPublicBase(t *testing.T) {
	cases := []struct{ url, name, want string }{
		{"https://proxy.example.com", "npm", "https://proxy.example.com/v1/npm"},
		{"https://proxy.example.com/", "npm", "https://proxy.example.com/v1/npm"},
		{"", "pip", "/v1/pip"},
	}
	for _, c := range cases {
		if got := PublicBase(c.url, c.name); got != c.want {
			t.Errorf("PublicBase(%q,%q) = %q, want %q", c.url, c.name, got, c.want)
		}
	}
}

func TestBuildUnknownEcosystem(t *testing.T) {
	if _, err := Build("git", Options{Name: "g", UpstreamURL: "https://x", Client: testClient()}); err == nil {
		t.Error("expected error for non-package-manager ecosystem")
	}
}

func TestBuildValidation(t *testing.T) {
	if _, err := Build("npm", Options{Name: "", UpstreamURL: "https://x", Client: testClient()}); err == nil {
		t.Error("expected error for missing name")
	}
	if _, err := Build("npm", Options{Name: "n", UpstreamURL: "", Client: testClient()}); err == nil {
		t.Error("expected error for missing upstream URL")
	}
	if _, err := Build("npm", Options{Name: "n", UpstreamURL: "https://x", Client: nil}); err == nil {
		t.Error("expected error for missing client")
	}
}

func TestNPMPackumentRewriteAndTarballCaching(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/lodash":
			w.Header().Set("Content-Type", "application/json")
			// Packument with absolute tarball URL on the registry host.
			_, _ = io.WriteString(w, `{"name":"lodash","versions":{"4.17.21":{"dist":{"tarball":"`+upstreamURL(r)+`/lodash/-/lodash-4.17.21.tgz"}}}}`)
		case r.URL.Path == "/lodash/-/lodash-4.17.21.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "TARBALL")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	b, err := NewNPM(Options{
		Name: "npm", UpstreamURL: srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/npm",
		Client:        testClient(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Packument: non-cacheable, tarball URL rewritten to the proxy.
	res, body := fetch(t, b, "/lodash")
	if res.Cacheable {
		t.Error("packument should not be cacheable")
	}
	want := "https://proxy.example.com/v1/npm/lodash/-/lodash-4.17.21.tgz"
	if !strings.Contains(body, want) {
		t.Errorf("packument not rewritten; body = %s", body)
	}
	if strings.Contains(body, srv.URL) {
		t.Errorf("packument still contains upstream host: %s", body)
	}

	// Tarball: cacheable, served verbatim.
	res2, body2 := fetch(t, b, "/lodash/-/lodash-4.17.21.tgz")
	if !res2.Cacheable {
		t.Error("tarball should be cacheable")
	}
	if body2 != "TARBALL" {
		t.Errorf("tarball body = %q", body2)
	}
}

func TestPyPISimpleRewriteAndArtifactFetch(t *testing.T) {
	var index, files *httptest.Server
	files = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/packages/aa/bb/requests-2.0.tar.gz" {
			_, _ = io.WriteString(w, "WHEELBYTES")
			return
		}
		http.NotFound(w, r)
	}))
	defer files.Close()
	index = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/requests/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<a href="`+files.URL+`/packages/aa/bb/requests-2.0.tar.gz#sha256=abc">requests-2.0.tar.gz</a>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer index.Close()

	filesHost := strings.TrimPrefix(files.URL, "http://")

	b, err := NewPyPI(Options{
		Name: "pip", UpstreamURL: index.URL,
		PublicBaseURL: "https://proxy.example.com/v1/pip",
		Client:        testClient(),
		Settings:      map[string]string{"filesUrl": files.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simple page: file URL rewritten to the host-encoded /files/ route.
	res, body := fetch(t, b, "/simple/requests/")
	if res.Cacheable {
		t.Error("simple page should not be cacheable")
	}
	wantPrefix := "https://proxy.example.com/v1/pip/files/http/" + filesHost + "/packages/aa/bb/requests-2.0.tar.gz#sha256=abc"
	if !strings.Contains(body, wantPrefix) {
		t.Errorf("simple page not rewritten; body = %s", body)
	}

	// Reconstruct the artifact request the client would now make.
	res2, body2 := fetch(t, b, "/files/http/"+filesHost+"/packages/aa/bb/requests-2.0.tar.gz")
	if !res2.Cacheable {
		t.Error("artifact should be cacheable")
	}
	if body2 != "WHEELBYTES" {
		t.Errorf("artifact body = %q", body2)
	}
}

func TestPyPIRejectsUnlistedFileHost(t *testing.T) {
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The index host should receive the (unrewritten) files path because the
		// disallowed host is refused by the AbsoluteRouter and falls through.
		http.NotFound(w, r)
	}))
	defer index.Close()

	b, err := NewPyPI(Options{
		Name: "pip", UpstreamURL: index.URL,
		PublicBaseURL: "https://proxy.example.com/v1/pip",
		Client:        testClient(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A files path naming a host outside the allowlist must NOT be fetched as an
	// artifact: it falls through to the index host (which 404s here), proving the
	// proxy never contacted evil.example.com.
	res, err := b.Resolve(context.Background(), &backends.Request{Path: "/files/https/evil.example.com/x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	u, err := url.Parse(res.UpstreamURL)
	if err != nil {
		t.Fatalf("parse resolved URL: %v", err)
	}
	if u.Host != strings.TrimPrefix(index.URL, "http://") {
		t.Errorf("disallowed host was routed to %q, want fallthrough to index host", u.Host)
	}
}

func TestCargoConfigRewriteAndDownload(t *testing.T) {
	var dlHits int
	download := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/crates/serde/1.0.0/download" {
			dlHits++
			_, _ = io.WriteString(w, "CRATEBYTES")
			return
		}
		http.NotFound(w, r)
	}))
	defer download.Close()
	indexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"dl":"https://static.crates.io/crates","api":"https://crates.io"}`)
		case "/se/rd/serde":
			_, _ = io.WriteString(w, `{"name":"serde","vers":"1.0.0","cksum":"x"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer indexSrv.Close()

	b, err := NewCargo(Options{
		Name: "cargo", UpstreamURL: indexSrv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/cargo",
		Client:        testClient(),
		Settings:      map[string]string{"downloadUrl": download.URL},
	})
	if err != nil {
		t.Fatal(err)
	}

	// config.json: dl rewritten to the proxy download endpoint; api preserved.
	res, body := fetch(t, b, "/config.json")
	if res.Cacheable {
		t.Error("config.json should not be cacheable")
	}
	if !strings.Contains(body, `"dl":"https://proxy.example.com/v1/cargo/api/v1/crates"`) {
		t.Errorf("config.json dl not rewritten: %s", body)
	}
	if !strings.Contains(body, `"api":"https://crates.io"`) {
		t.Errorf("config.json api should be preserved: %s", body)
	}

	// Index file: non-cacheable, not rewritten.
	resIdx, _ := fetch(t, b, "/se/rd/serde")
	if resIdx.Cacheable {
		t.Error("index file should not be cacheable")
	}

	// Download: routed to the download host, cacheable.
	resDL, bodyDL := fetch(t, b, "/api/v1/crates/serde/1.0.0/download")
	if !resDL.Cacheable {
		t.Error("crate download should be cacheable")
	}
	if bodyDL != "CRATEBYTES" || dlHits != 1 {
		t.Errorf("download body=%q hits=%d", bodyDL, dlHits)
	}
}

func TestGoProxyCacheability(t *testing.T) {
	b, err := NewGoProxy(Options{Name: "go", UpstreamURL: "https://proxy.golang.org", Client: testClient()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path      string
		cacheable bool
	}{
		{"/golang.org/x/mod/@v/v0.1.0.info", true},
		{"/golang.org/x/mod/@v/v0.1.0.mod", true},
		{"/golang.org/x/mod/@v/v0.1.0.zip", true},
		{"/golang.org/x/mod/@v/list", false},
		{"/golang.org/x/mod/@latest", false},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: "GET", Path: c.path})
		if err != nil {
			t.Fatalf("Resolve(%s): %v", c.path, err)
		}
		if res.Cacheable != c.cacheable {
			t.Errorf("Cacheable(%s) = %v, want %v", c.path, res.Cacheable, c.cacheable)
		}
	}
}

func TestNuGetServiceIndexRewriteAndPackageCaching(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"resources":[{"@id":"`+upstreamURL(r)+`/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"},{"@id":"https://azuresearch.nuget.org/query","@type":"SearchQueryService"}]}`)
		case "/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "NUPKG")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	b, err := NewNuGet(Options{
		Name: "nuget", UpstreamURL: srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/nuget",
		Client:        testClient(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Service index: same-host resource rewritten, cross-host search left alone.
	res, body := fetch(t, b, "/v3/index.json")
	if res.Cacheable {
		t.Error("service index should not be cacheable")
	}
	if !strings.Contains(body, `"@id":"https://proxy.example.com/v1/nuget/v3-flatcontainer/"`) {
		t.Errorf("flat container @id not rewritten: %s", body)
	}
	if !strings.Contains(body, `https://azuresearch.nuget.org/query`) {
		t.Errorf("cross-host search should be preserved: %s", body)
	}

	// Package: immutable, cacheable, served verbatim.
	res2, body2 := fetch(t, b, "/v3-flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg")
	if !res2.Cacheable {
		t.Error("nupkg should be cacheable")
	}
	if body2 != "NUPKG" {
		t.Errorf("nupkg body = %q", body2)
	}
}

func TestNuGetGzippedRegistrationRewrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a baked-in gzip body (no Content-Encoding header) so the transport
		// does not transparently decompress it.
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = io.WriteString(zw, `{"packageContent":"`+upstreamURL(r)+`/v3-flatcontainer/p/1.0.0/p.1.0.0.nupkg"}`)
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	b, err := NewNuGet(Options{
		Name: "nuget", UpstreamURL: srv.URL,
		PublicBaseURL: "https://proxy.example.com/v1/nuget",
		Client:        testClient(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := fetch(t, b, "/v3/registration5-gz-semver2/p/index.json")
	if !strings.Contains(body, "https://proxy.example.com/v1/nuget/v3-flatcontainer/p/1.0.0/p.1.0.0.nupkg") {
		t.Errorf("gzipped registration not decoded+rewritten: %s", body)
	}
}

// upstreamURL returns the absolute base URL the test server is reachable at,
// derived from the inbound request, so handlers can emit self-referential URLs.
func upstreamURL(r *http.Request) string {
	return "http://" + r.Host
}
