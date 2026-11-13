//go:build fuzz

package locate

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// The documents the locators read come from registries through the proxy:
// untrusted input. These targets hold the parsers to never panic and never to
// produce a path outside the backend's routes.

func FuzzParseSimplePage(f *testing.F) {
	f.Add([]byte(`{"files":[{"filename":"a-1.0.tar.gz","url":"/v1/pypi/files/https/h/a-1.0.tar.gz","hashes":{"sha256":"ab"}}]}`), "application/vnd.pypi.simple.v1+json")
	f.Add([]byte(`<a href="/v1/pypi/files/https/h/a-1.0.tar.gz#sha256=ab">a-1.0.tar.gz</a>`), "text/html")
	f.Add([]byte(`<a href='x'>`), "text/html")
	f.Fuzz(func(t *testing.T, body []byte, contentType string) {
		files, err := parseSimplePage(Document{Status: 200, ContentType: contentType, Body: body})
		if err != nil {
			return
		}
		up := Upstream{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org"}}
		for _, f := range files {
			if p, ok := pipFilePath(up, "/simple/a/", f.URL); ok {
				checkPath(t, p)
			}
		}
	})
}

func FuzzLocateDocker(f *testing.F) {
	d := "sha256:" + strings.Repeat("a", 64)
	f.Add([]byte(`{"config":{"digest":"` + d + `"},"layers":[{"digest":"` + d + `"}]}`))
	f.Add([]byte(`{"manifests":[{"digest":"` + d + `","platform":{"os":"linux","architecture":"amd64"}}]}`))
	f.Fuzz(func(t *testing.T, manifest []byte) {
		top := "sha256:" + strings.Repeat("0", 64)
		docs := fuzzDocs{"hub/v2/library/x/manifests/" + top: manifest, "hub/v2/library/x/manifests/" + d: manifest}
		env := Env{Upstreams: []Upstream{{Name: "hub", Type: "docker", URLs: []string{"https://registry-1.docker.io"}}}, Fetch: docs}
		plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: "docker", Name: "library/x", Version: top})
		if err != nil {
			return
		}
		for _, a := range plan.Artifacts {
			checkPath(t, a.Path)
			if !strings.HasPrefix(a.Path, "/v2/library/x/manifests/sha256:") && !strings.HasPrefix(a.Path, "/v2/library/x/blobs/sha256:") {
				t.Fatalf("path outside the registry routes: %q", a.Path)
			}
		}
	})
}

func FuzzLocatePaths(f *testing.F) {
	f.Add("npm", "@scope/pkg", "1.0.0", "", "")
	f.Add("go", "github.com/A/b", "v1.0.0", "", "")
	f.Add("cpan", "Try-Tiny", "0.31", "", "E/ET/ETHER/Try-Tiny-0.31.tar.gz")
	f.Add("conda", "zlib", "1.3", "https://conda.anaconda.org/c/linux-64/zlib-1.3-0.conda", "")
	f.Fuzz(func(t *testing.T, typ, name, version, url, id string) {
		env := Env{Upstreams: []Upstream{
			{Name: "u", Type: typ, URLs: []string{"https://conda.anaconda.org/c", "https://registry.npmjs.org"}},
		}}
		plan, err := Locate(context.Background(), env, lockfiles.Dependency{Type: typ, Name: name, Version: version, URL: url, ID: id})
		if err != nil {
			return
		}
		for _, a := range plan.Artifacts {
			checkPath(t, a.Path)
		}
	})
}

func FuzzCheckerModuleZip(f *testing.F) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("m@v1.0.0/go.mod")
	_, _ = w.Write([]byte("module m\n"))
	_ = zw.Close()
	f.Add(buf.Bytes())
	f.Add([]byte("PK\x03\x04 not really"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := NewChecker(Artifact{Role: "package", Path: "/m/@v/v1.0.0.zip",
			Expect: []lockfiles.Digest{{Algorithm: "h1", Value: "x"}}}, t.TempDir())
		if err != nil {
			t.Skip(err)
		}
		defer c.Close()
		_, _ = c.Write(data)
		res := c.Result()
		if res.Status == CheckVerified {
			t.Fatal("a made-up module hash verified")
		}
	})
}

type fuzzDocs map[string][]byte

func (f fuzzDocs) FetchDocument(_ context.Context, upstream, path, _ string) (Document, error) {
	if b, ok := f[upstream+path]; ok {
		return Document{Status: 200, Body: b}, nil
	}
	return Document{Status: 404}, nil
}

// checkPath holds a located path to the shape every backend route has.
func checkPath(t *testing.T, p string) {
	t.Helper()
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\x00\r\n") {
		t.Fatalf("malformed path %q", p)
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == ".." || seg == "." {
			t.Fatalf("dot segment in %q", p)
		}
	}
}
