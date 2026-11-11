package puppet

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about the
// paths a Forge mount serves. This backend forwards every well-formed path it
// does not recognize, so its "metadata" kind is not evidence that a path serves
// a document: a release tarball is a payload, a path the API grammar positively
// names as a document is metadata, and everything else stays unclassified so a
// gate judges it from its bytes. Calling a forwarded tarball metadata would let
// it reach a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: release tarballs, with and without a base prefix.
		{"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz", backends.ArtifactPayload, true},
		{"/v3/files/owner1-mod_name-2.0.0-rc1.tar.gz", backends.ArtifactPayload, true},
		{"/forge/v3/files/puppetlabs-stdlib-9.4.1.tar.gz", backends.ArtifactPayload, true},
		// A release file stays a payload even below a document-shaped prefix.
		{"/v3/modules/v3/files/puppetlabs-stdlib-9.4.1.tar.gz", backends.ArtifactPayload, true},

		// Metadata: the module, release, user and search documents and listings.
		{"/v3/modules", backends.ArtifactMetadata, false},
		{"/v3/modules/", backends.ArtifactMetadata, false},
		{"/v3/modules/puppetlabs-stdlib", backends.ArtifactMetadata, false},
		{"/v3/releases", backends.ArtifactMetadata, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1", backends.ArtifactMetadata, false},
		{"/v3/releases/owner1-mod_name-2.0.0-rc1", backends.ArtifactMetadata, false},
		{"/v3/releases/owner1-mod_name-2.0.0+build.5", backends.ArtifactMetadata, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1/plans", backends.ArtifactMetadata, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1/plans/deploy", backends.ArtifactMetadata, false},
		{"/v3/users", backends.ArtifactMetadata, false},
		{"/v3/users/puppetlabs", backends.ArtifactMetadata, false},
		{"/v3/search", backends.ArtifactMetadata, false},
		// ... also beneath a base prefix.
		{"/forge/v3/modules/puppetlabs-stdlib", backends.ArtifactMetadata, false},
		{"/forge/v3/releases/puppetlabs-stdlib-9.4.1", backends.ArtifactMetadata, false},

		// Unclassified: a file under /v3/files/ whose name does not decompose into
		// a release. It is forwarded like any unknown path — and it is exactly what
		// must not be waved through as metadata.
		{"/v3/files/weird.tar.gz", backends.ArtifactUnclassified, false},
		{"/v3/files/UPPER-Case-1.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{"/v3/files/puppetlabs-stdlib.tar.gz", backends.ArtifactUnclassified, false},
		{"/v3/files/weird.tar.gz/", backends.ArtifactUnclassified, false},
		{"/forge/v3/files/weird.tar.gz", backends.ArtifactUnclassified, false},
		{"/v3/modules/v3/files/weird.tar.gz", backends.ArtifactUnclassified, false},
		// Unclassified: anything else in the files collection.
		{"/v3/files", backends.ArtifactUnclassified, false},
		{"/v3/files/puppetlabs-stdlib-9.4.1.zip", backends.ArtifactUnclassified, false},
		{"/v3/files/puppetlabs-stdlib-9.4.1", backends.ArtifactUnclassified, false},
		{"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz/extra", backends.ArtifactUnclassified, false},
		// Unclassified: a "files" segment or an archive suffix inside a document
		// collection.
		{"/v3/modules/files/weird", backends.ArtifactUnclassified, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1/files/weird", backends.ArtifactUnclassified, false},
		{"/v3/modules/files", backends.ArtifactUnclassified, false},
		{"/v3/modules/FILES/weird", backends.ArtifactUnclassified, false},
		{"/v3/modules/V3/Files/weird", backends.ArtifactUnclassified, false},
		{"/v3/modules/puppetlabs-stdlib.tar.gz", backends.ArtifactUnclassified, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1.tgz", backends.ArtifactUnclassified, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1.zip", backends.ArtifactUnclassified, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1.tar", backends.ArtifactUnclassified, false},
		{"/v3/releases/puppetlabs-stdlib-9.4.1.TAR.GZ", backends.ArtifactUnclassified, false},
		{"/v3/users/puppetlabs/export.Zip", backends.ArtifactUnclassified, false},
		// Unclassified: paths the grammar says nothing about.
		{"", backends.ArtifactUnclassified, false},
		{"/", backends.ArtifactUnclassified, false},
		{"/v3", backends.ArtifactUnclassified, false},
		{"/v3/", backends.ArtifactUnclassified, false},
		{"/v3/other/thing", backends.ArtifactUnclassified, false},
		{"/v3/v3/modules/puppetlabs-stdlib", backends.ArtifactUnclassified, false},
		{"/modules/puppetlabs-stdlib", backends.ArtifactUnclassified, false},
		{"/v2/modules/puppetlabs-stdlib", backends.ArtifactUnclassified, false},
		{"/private/users/search_filters", backends.ArtifactUnclassified, false},
		{"/downloads/puppetlabs-stdlib-9.4.1.tar.gz", backends.ArtifactUnclassified, false},

		// Unclassified: a document-shaped path that is not spelled in plain
		// segments. A server that drops ";name=value" path parameters reads the
		// first two as "/v3/files/puppetlabs-stdlib-9.4.1.tar.gz", although neither
		// has a "files" segment or an archive suffix as spelled; the shape proves
		// nothing.
		{"/v3/modules/..;/files;a/puppetlabs-stdlib-9.4.1.tar.gz;.json", backends.ArtifactUnclassified, false},
		{"/v3/releases/..;/files;/puppetlabs-stdlib-9.4.1.tar.gz;", backends.ArtifactUnclassified, false},
		{"/v3/modules/puppetlabs-stdlib;x", backends.ArtifactUnclassified, false},
		{"/v3/modules;x/puppetlabs-stdlib", backends.ArtifactUnclassified, false},
		{"/v3/modules/puppetlabs stdlib", backends.ArtifactUnclassified, false},
		{"/v3/modules/puppetlabs%2Fstdlib", backends.ArtifactUnclassified, false},
		{"/v3/modules\\puppetlabs-stdlib", backends.ArtifactUnclassified, false},
		{"/v3/releases?module=puppetlabs-stdlib", backends.ArtifactUnclassified, false},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Cacheable != c.cacheable {
			t.Errorf("Resolve(%q).Cacheable = %v, want %v", c.path, res.Cacheable, c.cacheable)
		}
		// Every Forge resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestArtifactClassIgnoresQuery checks that the class comes from the path
// alone: a listing stays metadata and a forwarded file stays unclassified
// whatever query the client sends with it.
func TestArtifactClassIgnoresQuery(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)
	cases := []struct {
		path  string
		query url.Values
		want  backends.ArtifactClass
	}{
		{"/v3/releases", url.Values{"module": {"puppetlabs-stdlib"}, "limit": {"20"}}, backends.ArtifactMetadata},
		{"/v3/modules", url.Values{"query": {"stdlib.tar.gz"}}, backends.ArtifactMetadata},
		{"/v3/files/weird.tar.gz", url.Values{"module": {"puppetlabs-stdlib"}}, backends.ArtifactUnclassified},
		{"/v3/files/puppetlabs-stdlib-9.4.1.tar.gz", url.Values{"x": {"/v3/modules"}}, backends.ArtifactPayload},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: c.query})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q?%s).Artifact.Class = %s, want %s", c.path, c.query.Encode(), res.Artifact.Class, c.want)
		}
	}
}
