package maven

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Every path ArtifactPath builds resolves, through the backend's own Resolve,
// to a cacheable artifact of the coordinate it was built for; a coordinate
// the backend would read as something else is refused.
func TestArtifactPathRoundTrips(t *testing.T) {
	b, err := New(Options{Name: "maven-test", UpstreamURL: "https://repo.example.com/maven2", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		g, a, v, c, e string
		want          string
	}{
		{"com.google.guava", "guava", "31.1-jre", "", "jar", "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar"},
		{"com.google.guava", "guava", "31.1-jre", "", "pom", "/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom"},
		{"org.jenkins-ci.plugins", "nodelabelparameter", "1.12.0", "sources", "jar", "/org/jenkins-ci/plugins/nodelabelparameter/1.12.0/nodelabelparameter-1.12.0-sources.jar"},
		{"org.jenkins-ci.plugins", "git", "5.2.1", "", "hpi", "/org/jenkins-ci/plugins/git/5.2.1/git-5.2.1.hpi"},
		{"io.netty", "netty-tcnative", "2.0.61.Final", "linux-x86_64", "jar", "/io/netty/netty-tcnative/2.0.61.Final/netty-tcnative-2.0.61.Final-linux-x86_64.jar"},
		{"org.example", "dist", "1.0", "", "tar.gz", "/org/example/dist/1.0/dist-1.0.tar.gz"},
		{"clj-time", "clj-time", "0.15.2", "", "jar", "/clj-time/clj-time/0.15.2/clj-time-0.15.2.jar"},
		{"org.example", "lib", "1.0+build.5", "", "jar", "/org/example/lib/1.0+build.5/lib-1.0+build.5.jar"},
	} {
		p, ok := ArtifactPath(tc.g, tc.a, tc.v, tc.c, tc.e)
		if !ok || p != tc.want {
			t.Errorf("ArtifactPath(%s:%s:%s:%s:%s) = %q, %v; want %q", tc.g, tc.a, tc.v, tc.c, tc.e, p, ok, tc.want)
			continue
		}
		dec, err := url.PathUnescape(p)
		if err != nil || dec != p {
			t.Errorf("%s is not its own escaped form", p)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !res.Cacheable || res.Coordinate.Name != tc.g+":"+tc.a || res.Coordinate.Version != tc.v {
			t.Errorf("%s resolves to %+v (cacheable %v)", p, res.Coordinate, res.Cacheable)
		}
	}
	for _, tc := range []struct{ g, a, v, c, e string }{
		{"", "a", "1", "", "jar"},
		{"g", "", "1", "", "jar"},
		{"g", "a", "", "", "jar"},
		{"g", "a", "1", "", ""},
		{"g..x", "a", "1", "", "jar"},
		{".g", "a", "1", "", "jar"},
		{"g", "a/b", "1", "", "jar"},
		{"g", "..", "1", "", "jar"},
		{"g", "a", "..", "", "jar"},
		{"g", "a", "1/2", "", "jar"},
		{"g", "a", "1", "x/y", "jar"},
		{"g", "a b", "1", "", "jar"},
		{"g", "a", "1", "", "jar%2F"},
		{"g", "a", "1", "", "jar;x"},
		{"g", "a", "1.0-SNAPSHOT", "", "jar"}, // revalidated on every request, never cached
		{"g", "a", "1", "", "jar.sha1"},       // a checksum sidecar
		{"g", "a", "1", "", "pom.asc"},        // a signature sidecar
		{"g", "maven", "metadata", "", "xml"}, // maven-metadata.xml
		{"g", "a", "1", "", "jar.md5"},
	} {
		if p, ok := ArtifactPath(tc.g, tc.a, tc.v, tc.c, tc.e); ok {
			t.Errorf("ArtifactPath(%q, %q, %q, %q, %q) = %q, want a refusal", tc.g, tc.a, tc.v, tc.c, tc.e, p)
		}
	}
}
