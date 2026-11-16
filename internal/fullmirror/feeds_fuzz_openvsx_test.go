//go:build fuzz
// +build fuzz

// Fuzz targets for the openvsx feed's parsers (Task 191): the sitemap, the
// search listing by time, a version listing, an extension's document (with
// the archives Releases takes from it), the "platforms" option and an
// extension's identifier. None may panic; what they accept must stay bounded
// and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzOpenVSXSitemap$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/openvsx"
)

func openvsxFuzzFixtures(f *testing.F, prefix string) {
	entries, _ := os.ReadDir(filepath.Join("testdata", "feeds", "openvsx"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && !e.IsDir() {
			if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "openvsx", e.Name())); err == nil {
				f.Add(data)
			}
		}
	}
}

func FuzzOpenVSXSitemap(f *testing.F) {
	openvsxFuzzFixtures(f, "sitemap")
	for _, s := range []string{"", "<urlset/>", "<sitemapindex/>", `<urlset><url><loc>https://x/extension/a/b</loc><lastmod>2026-11-16</lastmod></url></urlset>`,
		`<urlset><url><loc>https://x/extension/a/b</loc><lastmod>2026-11-16T01:02:03Z</lastmod></url><url><loc>a/extension/b.c/d</loc></url></urlset>`,
		`<?xml version="1.0"?><!DOCTYPE x><urlset><url><loc>&amp;</loc></url>`, "<urlset>" + strings.Repeat("<a>", 20)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		n := 0
		err := openvsxParseSitemap(bytes.NewReader(data), func(e openvsxEntry) error {
			n++
			if !openvsx.ValidName(e.namespace) || !openvsx.ValidName(e.name) {
				t.Fatalf("entry %+v", e)
			}
			id := e.namespace + "." + e.name
			for _, rec := range []snapRecord{
				openvsxRecord(id, e.lastmod, "", false, 0, false),
				openvsxRecord(id, e.lastmod, e.lastmod+"/7", true, 9, true),
				openvsxRecord(id, e.lastmod, "2001-01-01/5", true, 0, true),
			} {
				if !rec.valid() || rec.Version != "" || rec.Path != "" || len(rec.Digest) > 64 {
					t.Fatalf("record %+v of %+v", rec, e)
				}
				if _, _, ok := openvsxSplitName(rec.Name); !ok {
					t.Fatalf("record name %q does not split", rec.Name)
				}
			}
			return nil
		})
		if err != nil && !IsPermanent(err) {
			t.Fatalf("a malformed sitemap is not a permanent error: %v", err)
		}
		if n > len(data)/20+1 {
			t.Fatalf("%d entries from %d bytes", n, len(data))
		}
	})
}

func FuzzOpenVSXSearch(f *testing.F) {
	openvsxFuzzFixtures(f, "search")
	for _, s := range []string{"", "{}", "[]", `{"totalSize":1,"extensions":[{"namespace":"a","name":"b","timestamp":"2026-11-16T07:28:26.067524Z"}]}`,
		`{"extensions":[{"namespace":"a.b","name":"c","timestamp":"x"},{"namespace":"a","name":"b","timestamp":"1970-01-01T00:00:00Z"}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		listed := map[string]int64{}
		floor := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()
		newest, n, _, _, err := openvsxReadSearchPage(data, floor, listed)
		if err != nil {
			return
		}
		if len(listed) > n {
			t.Fatalf("%d extensions listed from %d entries", len(listed), n)
		}
		for id, ts := range listed {
			if _, _, ok := openvsxSplitName(id); !ok || ts <= floor || ts > newest {
				t.Fatalf("listed %q at %d (newest %d)", id, ts, newest)
			}
		}
	})
}

func FuzzOpenVSXVersions(f *testing.F) {
	openvsxFuzzFixtures(f, "versions-")
	for _, s := range []string{"", "{}", `{"versions":{"1.0.0":"u","latest":"u"}}`, `{"totalSize":-1,"versions":[]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		versions, n, _, err := openvsxReadVersionPage(data)
		if err != nil {
			return
		}
		if len(versions) > n {
			t.Fatalf("%d versions of %d entries", len(versions), n)
		}
		for _, v := range versions {
			if !openvsx.ValidVersion(v) {
				t.Fatalf("version %q", v)
			}
			if _, ok := openvsx.VsixPath("a", "b", openvsx.Universal, v); !ok {
				t.Fatalf("version %q has no archive path", v)
			}
		}
	})
}

func FuzzOpenVSXDocument(f *testing.F) {
	openvsxFuzzFixtures(f, "redhat")
	openvsxFuzzFixtures(f, "rust-lang")
	for _, s := range []string{`{}`, `{"namespace":"a","name":"b"}`, `{"namespace":"a","name":"b","version":"1.0.0","files":{"download":"https://open-vsx.org/api/a/b/1.0.0/file/a.b-1.0.0.vsix"}}`,
		`{"namespace":"a","name":"b","version":"1.0.0","downloads":{"linux-x64":"https://open-vsx.org/api/a/b/linux-x64/1.0.0/file/a.b-1.0.0@linux-x64.vsix","macos":"x"}}`,
		`{"namespace":"file","name":"b","version":"1.0.0","files":{"download":"/v1/openvsx-fuzz/api/file/b/1.0.0/file/file.b-1.0.0.vsix"}}`, `[]`, `{"downloads":[1]}`} {
		f.Add([]byte(s))
	}
	k, err := newKit(Env{Upstream: "openvsx-fuzz", Type: "openvsx", URL: "https://open-vsx.org"})
	if err != nil {
		f.Fatal(err)
	}
	feed := &openvsxFeed{k: k}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := openvsxParseDoc(data)
		if err != nil {
			return
		}
		archives, platforms := feed.newestArchives(d)
		if len(platforms) > len(openvsx.TargetPlatforms()) || len(archives) > len(platforms) {
			t.Fatalf("%d archives of %d platforms", len(archives), len(platforms))
		}
		for p, path := range archives {
			if !openvsx.IsTargetPlatform(p) || !validArtifactPath(path) {
				t.Fatalf("archive %q of %q", path, p)
			}
			dec, err := url.PathUnescape(path)
			if err != nil {
				t.Fatalf("path %q: %v", path, err)
			}
			ext, version, ok := openvsx.VsixCoordinate(dec)
			if !ok || ext != d.Namespace+"."+d.Name || version != d.Version || !openvsx.ValidVersion(version) {
				t.Fatalf("%s is read as %q %q %v, listed for %s.%s %s", path, ext, version, ok, d.Namespace, d.Name, d.Version)
			}
		}
	})
}

func FuzzOpenVSXPlatforms(f *testing.F) {
	for _, s := range []string{"", "linux-x64", "linux-x64, darwin-arm64", "universal", ",", "macos", "a,,b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := openvsxParsePlatforms(s)
		if err != nil {
			return
		}
		for tp := range p {
			if !openvsx.IsTargetPlatform(tp) {
				t.Fatalf("%q kept platform %q", s, tp)
			}
		}
	})
}

func FuzzOpenVSXName(f *testing.F) {
	for _, s := range []string{"redhat.vscode-yaml", "golang.Go", "a.b.c", ".x", "x.", "../x.y", "file.x", "a_b.c+d$e~f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		ns, name, ok := openvsxSplitName(id)
		if !ok {
			return
		}
		if ns+"."+name != id || !openvsx.ValidName(ns) || !openvsx.ValidName(name) || !cleanName(id) {
			t.Fatalf("%q split into %q %q", id, ns, name)
		}
	})
}
