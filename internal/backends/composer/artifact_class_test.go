package composer

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// These tests pin what Resolve says a Composer path is, for the content gates
// (backends.ArtifactClass): the dist archive is the payload, every other
// resource of the protocol a metadata document.
func TestResolveArtifactClass(t *testing.T) {
	const (
		payload  = backends.ArtifactPayload
		metadata = backends.ArtifactMetadata
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
		// filename is the expected Artifact.Filename: a dist is resolved to its
		// package's metadata document, so the archive's name is stated.
		filename string
	}{
		// Dist archives.
		{"/dist/symfony/console/3.2.0/c0ffee320.zip", payload, "c0ffee320.zip"},
		{"/dist/symfony/console/v8.0.0-RC3/307d3cf852f5abc123def.zip", payload, "307d3cf852f5abc123def.zip"},
		{"/dist/symfony/console/dev-master/abc123.tar", payload, "abc123.tar"},
		// A dev branch name with a "/": the file is still the last segment.
		{"/dist/symfony/console/dev-feature/x/d00dfeed.zip", payload, "d00dfeed.zip"},
		// A reference with dots; the type is what follows the last one.
		{"/dist/symfony/console/1.0.0/v1.0.0.zip", payload, "v1.0.0.zip"},
		// A hashed (non-URL-safe) reference.
		{"/dist/symfony/console/1.0.0/_0123456789abcdef0123456789abcdef.zip", payload, "_0123456789abcdef0123456789abcdef.zip"},
		// Every spelling of a reference-less dist shares one cache entry, and one
		// name.
		{"/dist/no/sum/1.0.0/_.zip", payload, "_.zip"},
		{"/dist/no/sum/1.0.0/.zip", payload, "_.zip"},
		{"/dist/no/sum/1.0.0/_.zip/", payload, "_.zip"},
		{"dist/no/sum/1.0.0/_.zip", payload, "_.zip"},

		// The repository root.
		{"/packages.json", metadata, ""},
		// v2 package metadata, release and dev.
		{"/p2/symfony/console.json", metadata, ""},
		{"/p2/symfony/console~dev.json", metadata, ""},
		// Legacy v1 provider documents.
		{"/p/symfony/console.json", metadata, ""},
		{"/p/monolog/monolog$abcdef.json", metadata, ""},
		// Filter lists.
		{"/lists/all/summary.json", metadata, ""},
		{"/lists/malware/2026/summary.json", metadata, ""},
	}

	b := testBackend(t, newFakeServer(t), nil)
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("%q: class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Artifact.Filename != c.filename {
			t.Errorf("%q: filename = %q, want %q", c.path, res.Artifact.Filename, c.filename)
		}
		if res.Artifact.Kind != "" {
			t.Errorf("%q: kind = %q, want none", c.path, res.Artifact.Kind)
		}
		// What a gate takes as the file name of a dist is the archive's, not the
		// name of the metadata document the dist is resolved to.
		if c.want == payload {
			if got := res.ArtifactFilename(); got != c.filename {
				t.Errorf("%q: ArtifactFilename() = %q, want %q (upstream URL %q)", c.path, got, c.filename, res.UpstreamURL)
			}
		}
	}

	// A dist is a payload whether or not this request may be cached.
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodPost, Path: "/dist/symfony/console/3.2.0/c0ffee320.zip", Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Cacheable || res.Artifact != backends.PayloadNamed("c0ffee320.zip") {
		t.Errorf("non-read dist request: cacheable = %v, artifact = %+v; want uncached payload", res.Cacheable, res.Artifact)
	}
}

// The Composer grammar is closed: a path it does not name is refused, not
// resolved, so nothing reaches a client unclassified. Should a resource kind
// ever be added without a classification, it is unclassified — never metadata.
func TestUnnamedPathsAreRefusedNotClassified(t *testing.T) {
	b := testBackend(t, newFakeServer(t), nil)
	for _, p := range []string{
		"/search.json",
		"/packages/list.json",
		"/dist/symfony/console/c0ffee320.zip", // the version-less dist form
		"/dist/symfony/console/1.0.0/noext",
		"/p2/symfony/console.xml",
		"/lists/all/summary",
		"/downloads/",
		"/nope",
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
