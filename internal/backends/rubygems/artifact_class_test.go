package rubygems

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// These tests pin what Resolve says a RubyGems path is, for the content gates
// (backends.ArtifactClass): the .gem is the payload, every other resource of the
// protocol a metadata document.
func TestResolveArtifactClass(t *testing.T) {
	const (
		payload  = backends.ArtifactPayload
		metadata = backends.ArtifactMetadata
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// The gem package, with or without a platform.
		{"/gems/rails-7.0.4.gem", payload},
		{"/gems/net-http-persistent-4.0.1.gem", payload},
		{"/gems/nokogiri-1.13.0-x86_64-linux.gem", payload},
		{"/gems/foo-1.0.0.pre.rc1.gem", payload},

		// The compact index.
		{"/versions", metadata},
		{"/names", metadata},
		{"/info/rails", metadata},
		{"/info/net-http", metadata},
		// The legacy Marshal indexes and the per-version gemspec.
		{"/specs.4.8.gz", metadata},
		{"/latest_specs.4.8.gz", metadata},
		{"/prerelease_specs.4.8.gz", metadata},
		{"/quick/Marshal.4.8/rails-7.0.4.gemspec.rz", metadata},
		{"/quick/Marshal.4.8/nokogiri-1.13.0-x86_64-linux.gemspec.rz", metadata},
		// The dependency API.
		{"/api/v1/dependencies", metadata},
	}

	b := testBackend(t, newFakeServer(t), nil)
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("%q: class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		// The upstream URL ends in the file name, and no RubyGems resource needs a
		// kind: the classification is the class alone.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("%q: artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}

	// A gem is a payload whether or not this request may be cached.
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodPost, Path: "/gems/rails-7.0.4.gem", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Cacheable || res.Artifact != backends.Payload() {
		t.Errorf("non-read gem request: cacheable = %v, artifact = %+v; want uncached payload", res.Cacheable, res.Artifact)
	}
}

// The RubyGems grammar is closed: a path it does not name is refused, not
// resolved, so nothing reaches a client unclassified. Should a resource kind
// ever be added without a classification, it is unclassified — never metadata.
func TestUnnamedPathsAreRefusedNotClassified(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{
		"/gems/rails-7.0.4.tar.gz", // not a .gem
		"/gems/noversion.gem",
		"/gems/sub/dir-1.0.gem",
		"/info/a/b",
		"/quick/Marshal.4.8/rails-7.0.4.gemspec",
		"/api/v1/gems/rails.json",
		"/downloads/rails-7.0.4.gem",
		"/random/path",
	} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q): expected ErrNotSupported, got %v", p, err)
		}
	}

	for _, r := range []resource{{kind: kindOther}, {kind: kindOther + 1}} {
		if got := r.artifact(); got != (backends.Artifact{}) {
			t.Errorf("kind %d: artifact = %+v, want unclassified", r.kind, got)
		}
	}
}
