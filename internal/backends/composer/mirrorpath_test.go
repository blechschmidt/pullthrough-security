package composer

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// mirrorTestBackend builds a backend that never touches the network.
func mirrorTestBackend(t *testing.T, publicBase string) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "packagist",
		UpstreamURL:   "https://repo.packagist.org",
		PublicBaseURL: publicBase,
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// DistPath builds the locator the backend resolves: every path it returns
// classifies as that package's dist, with the version the path was built for
// as the coordinate the admission gates see, and is cached.
func TestDistPathRoundTripsThroughResolve(t *testing.T) {
	b := mirrorTestBackend(t, testPublicBase)
	for _, tc := range []struct{ vendor, pkg, version, ref, typ string }{
		{"psr", "log", "3.0.2", "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3", "zip"},
		{"symfony", "console", "v8.0.0-RC3", "c0ffee", "zip"},
		{"acme", "lib", "1.0.0+build.7", "", "tar"},
		{"acme", "lib", "2.0.0", "tags/v2.0.0@x", "zip"},
		{"0.1.x-dev", "upload", "1.0.0", "abc", "zip"},
		{"acme", "lib", "dev-feature/x", "abc", "zip"},
		{"acme", "lib", "1.0#beta?", "abc", "zip"},
	} {
		p, ok := DistPath(tc.vendor, tc.pkg, tc.version, tc.ref, tc.typ)
		if !ok {
			t.Errorf("%+v: not addressable", tc)
			continue
		}
		dec, err := url.PathUnescape(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}})
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !res.Cacheable || res.Metadata[metaKind] != "dist" {
			t.Errorf("%s: kind %q cacheable %v", p, res.Metadata[metaKind], res.Cacheable)
		}
		if res.Coordinate.Name != tc.vendor+"/"+tc.pkg || res.Coordinate.Version != tc.version {
			t.Errorf("%s: coordinate %+v", p, res.Coordinate)
		}
		if got, want := res.Metadata[metaReference], referenceToken(tc.ref); got != want {
			t.Errorf("%s: reference token %q, want %q", p, got, want)
		}
	}
	for _, bad := range [][5]string{
		{"Acme", "lib", "1.0.0", "a", "zip"},
		{"acme", "lib", "1.0.0 beta", "a", "zip"},
		{"acme", "lib", "1.0.0", "a", "tar.gz"},
		{"acme", "lib", "../1.0.0", "a", "zip"},
	} {
		if p, ok := DistPath(bad[0], bad[1], bad[2], bad[3], bad[4]); ok {
			t.Errorf("%v: addressable as %s", bad, p)
		}
	}
}

// The dist URLs the backend writes into the metadata it serves — with an
// absolute public base and with the root-relative mount — are the public base
// followed by DistPath, minified documents' inherited dists included.
func TestDistPathIsWhatTheRewriteNames(t *testing.T) {
	for _, base := range []string{testPublicBase, ""} {
		b := mirrorTestBackend(t, base)
		out, err := b.rewriteMetadata([]byte(inheritedDistFixture))
		if err != nil {
			t.Fatal(err)
		}
		md, err := ParseMetadata(out)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, v := range md.Packages["ralouphie/getallheaders"] {
			if v.Dist.URL == "" {
				continue
			}
			p, ok := DistPath("ralouphie", "getallheaders", v.Version, v.Dist.Reference, v.Dist.Type)
			if !ok {
				t.Errorf("%s: not addressable", v.Version)
				continue
			}
			if want := b.publicBase + p; v.Dist.URL != want {
				t.Errorf("%s: rewritten to %s, DistPath gives %s", v.Version, v.Dist.URL, want)
			}
			n++
		}
		if n == 0 {
			t.Errorf("public base %q: no dist checked", base)
		}
	}
}

func TestSplitPackageNameAndDevVersions(t *testing.T) {
	for name, want := range map[string]bool{"psr/log": true, "0.1.x-dev/upload": true, "Psr/Log": false, "psr": false, "a/b/c": false, "psr/log~dev": false, "-a/b": false} {
		if _, _, ok := SplitPackageName(name); ok != want {
			t.Errorf("%q: %v, want %v", name, ok, want)
		}
	}
	for v, want := range map[string]bool{"dev-master": true, "2.x-dev": true, "1.0.0": false, "v1.0.0-RC1": false} {
		if IsDevVersion(v) != want {
			t.Errorf("%q: dev %v", v, !want)
		}
	}
}

// ReleaseTimes expands the minified encoding: a version that does not repeat
// "time" has its predecessor's, and "__unset" removes it.
func TestReleaseTimesExpandsTheMinifiedEncoding(t *testing.T) {
	doc := `{"minified":"composer/2.0","packages":{"acme/lib":[
		{"name":"acme/lib","version":"2.0.0","time":"2024-09-11T13:17:53+00:00"},
		{"version":"1.9.0"},
		{"version":"1.8.0","time":"2019-01-02 03:04:05"},
		{"version":"1.7.0","time":"__unset"},
		{"version":"1.6.0","time":"yesterday"},
		{"version":"2.0.0","time":"2001-01-01T00:00:00+00:00"}
	]}}`
	got, err := ReleaseTimes([]byte(doc), "acme/lib")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"2.0.0": "2024-09-11T13:17:53Z",
		"1.9.0": "2024-09-11T13:17:53Z",
		"1.8.0": "2019-01-02T03:04:05Z",
	}
	if len(got) != len(want) {
		t.Errorf("times %v, want %v", got, want)
	}
	for v, w := range want {
		if g := got[v].Format(time.RFC3339); g != w {
			t.Errorf("%s: %s, want %s", v, g, w)
		}
	}
	// Not minified: every object stands alone.
	plain := strings.Replace(doc, `"minified":"composer/2.0",`, "", 1)
	if got, err = ReleaseTimes([]byte(plain), "acme/lib"); err != nil || len(got) != 2 {
		t.Errorf("plain document: %v %v", got, err)
	}
	if got, err := ReleaseTimes([]byte(doc), "other/pkg"); err != nil || len(got) != 0 {
		t.Errorf("another package: %v %v", got, err)
	}
	if _, err := ReleaseTimes([]byte(`[1,2]`), "acme/lib"); err == nil {
		t.Errorf("an array was read as metadata")
	}
}
