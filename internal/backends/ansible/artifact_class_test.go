package ansible

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about the
// paths a Galaxy mount serves. This backend forwards every well-formed path it
// does not recognize, so its "metadata" kind is not evidence that a path serves
// a document: a collection artifact is a payload, a path the API grammar
// positively names as a document is metadata, and everything else stays
// unclassified so a gate judges it from its bytes. Calling a forwarded tarball
// metadata would let it reach a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	const (
		stagingArt = "/api/v3/plugin/ansible/content/staging/collections/artifacts"
		// The form Galaxy uses for "href" links, and the content tree its artifact
		// URLs redirect into.
		hrefIndex   = "/api/content/published/v3/plugin/ansible/content/published/collections/index"
		pulpContent = "/api/pulp/content/published"
	)

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: published collection artifacts, in any repository.
		{artPrefix + "/community-general-8.0.0.tar.gz", backends.ArtifactPayload, true},
		{artPrefix + "/my_ns-my_coll-1.0.0-rc1.tar.gz", backends.ArtifactPayload, true},
		{stagingArt + "/community-general-8.0.0.tar.gz", backends.ArtifactPayload, true},
		// An artifact stays a payload even when its path also runs through an
		// index-shaped prefix.
		{indexPrefix + "/collections/artifacts/community-general-8.0.0.tar.gz", backends.ArtifactPayload, true},
		// Any name of the form <ident>-<ident>-<version>.tar.gz decomposes, however
		// unlikely it looks: this one is namespace "not", name "a", version
		// "valid-name" — an artifact, hence a payload.
		{artPrefix + "/not-a-valid-name.tar.gz", backends.ArtifactPayload, true},

		// Metadata: the collection index tree.
		{indexPrefix + "/", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/versions/", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/versions/8.0.0/", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/versions/8.0.0", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/versions/8.0.0/docs-blob/", backends.ArtifactMetadata, false},
		{indexPrefix + "/community/general/versions/8.0.0-rc.1+build.5/", backends.ArtifactMetadata, false},
		{hrefIndex + "/community/general/versions/8.0.0/", backends.ArtifactMetadata, false},
		// Metadata: API roots and listings (trailing slash, no file extension).
		{"/api/", backends.ArtifactMetadata, false},
		{"/api/v3/", backends.ArtifactMetadata, false},
		{"/api/v1/roles/", backends.ArtifactMetadata, false},
		{"/api/v3/collections/community/general/", backends.ArtifactMetadata, false},
		{"/api/v3/collections/community/general/versions/", backends.ArtifactMetadata, false},
		{"/api/v3/plugin/ansible/search/collection-versions/", backends.ArtifactMetadata, false},
		// Metadata: a JSON document by name.
		{"/api/v3/openapi.json", backends.ArtifactMetadata, false},

		// Unclassified: a tarball under artifacts/ whose name does not decompose
		// into a collection. It is forwarded like any unknown path — and it is
		// exactly what must not be waved through as metadata.
		{artPrefix + "/not_a_valid_slug.tar.gz", backends.ArtifactUnclassified, false},
		{artPrefix + "/Community-General-8.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{artPrefix + "/community-general.tar.gz", backends.ArtifactUnclassified, false},
		{artPrefix + "/weird.tar.gz", backends.ArtifactUnclassified, false},
		// ... also when an index-shaped prefix precedes it, or a slash trails it.
		{indexPrefix + "/collections/artifacts/not_a_valid_slug.tar.gz", backends.ArtifactUnclassified, false},
		{artPrefix + "/not_a_valid_slug.tar.gz/", backends.ArtifactUnclassified, false},
		// Unclassified: downloads of other layouts the backend merely forwards.
		{"/download/community-general-8.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{pulpContent + "/community-general-8.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{"/api/v3/artifacts/collections/published/community-general-8.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{artPrefix + "/community-general-8.0.0.tar.gz.sha256", backends.ArtifactUnclassified, false},
		{"/api/v3/files/setup.sh", backends.ArtifactUnclassified, false},
		// Unclassified: a trailing slash does not make a file name a listing.
		{"/api/v3/files/community-general-8.0.0.tar.gz/", backends.ArtifactUnclassified, false},
		{"/api/v3/collections/community/general/versions/8.0.0/", backends.ArtifactUnclassified, false},
		// Unclassified: paths the grammar says nothing about — the registry's web
		// root, and endpoints spelled without the API's trailing slash.
		{"", backends.ArtifactUnclassified, false},
		{"/", backends.ArtifactUnclassified, false},
		{"/api", backends.ArtifactUnclassified, false},
		{"/api/v1/roles", backends.ArtifactUnclassified, false},
		{"/api/v3/openapi.yaml", backends.ArtifactUnclassified, false},
		{"/api/v3/openapi.json/", backends.ArtifactUnclassified, false},

		// Unclassified: a document-shaped path that is not spelled in plain
		// segments. A server that drops ";name=value" path parameters reads the
		// first as the artifact path and the next two as the tarball, so here the
		// shape proves nothing.
		{indexPrefix + "/..;/artifacts/community-general-8.0.0.tar.gz", backends.ArtifactUnclassified, false},
		{"/download/community-general-8.0.0.tar.gz;.json", backends.ArtifactUnclassified, false},
		{"/download/community-general-8.0.0.tar.gz/;/", backends.ArtifactUnclassified, false},
		{indexPrefix + "/community/general;x/", backends.ArtifactUnclassified, false},
		{"/api/v3;x/", backends.ArtifactUnclassified, false},
		{"/api/v 3/", backends.ArtifactUnclassified, false},
		{"/api/v3%2Fx/", backends.ArtifactUnclassified, false},
		{"/api\\v3/", backends.ArtifactUnclassified, false},
		{"/api/v1/roles/?namespace=geerlingguy", backends.ArtifactUnclassified, false},
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
		// Every Galaxy resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestArtifactClassIgnoresQuery checks that the class comes from the path
// alone: a listing stays metadata and a forwarded download stays unclassified
// whatever query the client sends with it.
func TestArtifactClassIgnoresQuery(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)
	cases := []struct {
		path  string
		query url.Values
		want  backends.ArtifactClass
	}{
		{indexPrefix + "/community/general/versions/", url.Values{"limit": {"100"}, "offset": {"100"}}, backends.ArtifactMetadata},
		{"/api/v1/roles/", url.Values{"owner__username": {"geerlingguy"}, "name": {"docker"}}, backends.ArtifactMetadata},
		{"/download/community-general-8.0.0.tar.gz", url.Values{"format": {"json"}, "file": {"x.json"}}, backends.ArtifactUnclassified},
		{artPrefix + "/community-general-8.0.0.tar.gz", url.Values{"format": {"json"}}, backends.ArtifactPayload},
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
