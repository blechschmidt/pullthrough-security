package docker

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// classTestDigest is a well-formed sha256 digest (64 hex characters).
const classTestDigest = "sha256:" + "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"

func resolveClass(t *testing.T, b *Backend, method, reqPath string) (*backends.Resolved, error) {
	t.Helper()
	return b.Resolve(context.Background(), &backends.Request{
		Method: method, Path: reqPath, Query: url.Values{}, Header: http.Header{},
	})
}

// TestResolveArtifactClass pins what Resolve tells the content gates about each
// endpoint of the distribution API: a manifest and a blob are the image a client
// is about to run, everything else the backend serves is a document.
func TestResolveArtifactClass(t *testing.T) {
	b := testBackend(t, newFakeRegistry(t))

	cases := []struct {
		name  string
		path  string
		class backends.ArtifactClass
		kind  backends.ArtifactKind
	}{
		{"manifest by tag", "/v2/library/nginx/manifests/latest", backends.ArtifactPayload, backends.KindOCIManifest},
		{"manifest by digest", "/v2/library/nginx/manifests/" + classTestDigest, backends.ArtifactPayload, backends.KindOCIManifest},
		{"manifest of a nested repository", "/v2/org/team/app/manifests/v1.2.3", backends.ArtifactPayload, backends.KindOCIManifest},
		{"blob", "/v2/library/nginx/blobs/" + classTestDigest, backends.ArtifactPayload, backends.KindOCIBlob},
		{"referrers of a subject digest", "/v2/library/nginx/referrers/" + classTestDigest, backends.ArtifactMetadata, ""},
		{"api version check", "/v2/", backends.ArtifactMetadata, ""},
		{"api version check without the slash", "/v2", backends.ArtifactMetadata, ""},
		{"catalog", "/v2/_catalog", backends.ArtifactMetadata, ""},
		{"tag list", "/v2/library/nginx/tags/list", backends.ArtifactMetadata, ""},

		// A repository may be named like an endpoint. What decides is the endpoint
		// the path ends in, which is also what the registry routes on.
		{"manifest of a repository called tags/list", "/v2/tags/list/manifests/latest", backends.ArtifactPayload, backends.KindOCIManifest},
		{"blob of a repository called referrers", "/v2/referrers/blobs/" + classTestDigest, backends.ArtifactPayload, backends.KindOCIBlob},
		{"manifest below a referrers segment", "/v2/app/referrers/x/manifests/latest", backends.ArtifactPayload, backends.KindOCIManifest},
		{"tag list of a repository called app/manifests/x", "/v2/app/manifests/x/tags/list", backends.ArtifactMetadata, ""},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				resolved, err := resolveClass(t, b, method, tc.path)
				if err != nil {
					t.Fatalf("Resolve(%q): %v", tc.path, err)
				}
				got := resolved.Artifact
				if got.Class != tc.class {
					t.Errorf("Resolve(%q) class = %s, want %s", tc.path, got.Class, tc.class)
				}
				if got.Kind != tc.kind {
					t.Errorf("Resolve(%q) kind = %q, want %q", tc.path, got.Kind, tc.kind)
				}
				// The upstream URL of every registry resource ends in its own name.
				if got.Filename != "" {
					t.Errorf("Resolve(%q) filename = %q, want none", tc.path, got.Filename)
				}
			})
		}
	}

	if got := (reference{}).artifact(); got != (backends.Artifact{}) {
		t.Errorf("an unparsed reference is classified %+v, want the zero value", got)
	}
}

// TestMetadataClassSurvivesPathNormalization checks the property that makes a
// "metadata" answer safe. A registry, or a reverse proxy in front of it,
// normalizes a request path before it routes it: dot segments are resolved and
// repeated slashes merged. Whatever path Resolve calls metadata must therefore
// not turn into a manifest or blob request under that normalization, or a gate
// would skip an image payload. The test walks every path of up to five segments
// drawn from the words the API routes on, dot segments and empty segments
// included.
func TestMetadataClassSurvivesPathNormalization(t *testing.T) {
	segments := []string{
		"library", "nginx", "manifests", "blobs", "referrers", "tags", "list", "_catalog",
		"latest", classTestDigest, "..", ".", "",
	}
	var metadata int
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if ref, ok := parseReference(p); ok && ref.artifact().Class == backends.ArtifactMetadata {
			metadata++
			if norm, ok := parseReference(path.Clean(p)); ok && norm.artifact().Class == backends.ArtifactPayload {
				t.Errorf("%q is classified metadata, but normalizes to %q, a payload (%s)",
					p, path.Clean(p), norm.artifact().Kind)
			}
		}
		if depth == 0 {
			return
		}
		for _, s := range segments {
			walk(p+"/"+s, depth-1)
		}
	}
	walk("/v2", 5)

	// The walk must have exercised the property, not skipped everything.
	if metadata == 0 {
		t.Fatal("no generated path was classified metadata")
	}
}

// TestReferrersShapedPathIsNotAlwaysMetadata guards the place where the path
// grammar used to be wider than the API it names. Any single segment after
// "/referrers/" was accepted, so a dot segment got through, and a registry
// resolves (or redirects) "/v2/<name>/blobs/<digest>/referrers/.." to the blob
// itself: the proxy then relays a layer under a path that parsed as a referrers
// request. Metadata is not examined as a payload, so such a path must not be
// called metadata. It is now refused outright — the Referrers API is defined
// for a subject digest — and the classification stays the second line of
// defense.
func TestReferrersShapedPathIsNotAlwaysMetadata(t *testing.T) {
	b := testBackend(t, newFakeRegistry(t))

	for _, p := range []string{
		"/v2/library/nginx/blobs/" + classTestDigest + "/referrers/..",
		"/v2/library/nginx/manifests/" + classTestDigest + "/referrers/..",
		"/v2/library/nginx/manifests/latest/referrers/..",
		"/v2/library/nginx/manifests/latest/referrers/.",
		"/v2/library/nginx/referrers/..",
		"/v2/library/nginx/referrers/" + classTestDigest + "x",
		"/v2/library/nginx/referrers/latest",
		"/v2/library/nginx/referrers/sha256:abc",
	} {
		resolved, err := resolveClass(t, b, http.MethodGet, p)
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q) = %v, want it refused: the subject is not a digest", p, err)
		}
		if err == nil && resolved.Artifact.Class == backends.ArtifactMetadata {
			t.Errorf("Resolve(%q) is classified metadata; its subject is not a digest, so the response is not known to be a referrers index", p)
		}
	}

	// The classification itself does not rely on the parser having refused.
	if got := (reference{kind: refReferrers, name: "library/nginx", reference: "..", isDigest: false}).artifact(); got != (backends.Artifact{}) {
		t.Errorf("a referrers request without a subject digest is classified %+v, want unclassified", got)
	}
}

// TestParseReferenceRefusesPathsThatAreNotWhatTheyReadAs is the regression test
// for a way around the rule that an upstream's token endpoint is never
// forwarded. Registries host that endpoint under /v2/ on the registry itself
// (Artifactory and Nexus "/v2/token", Quay "/v2/auth"), and the backend answers
// an authentication challenge with the proxy's own credentials. The parser
// refuses "/v2/token" — but "/v2/token/manifests/.." parsed as the manifest
// ".." of the repository "token", was forwarded as written, and is "/v2/token"
// to the registry that normalizes it.
//
// So the parser now holds a path to the grammar of what it claims to be: a
// reference is a tag or a digest (a blob and a referrers subject: a digest), and
// a repository name has no relative segment in any spelling.
func TestParseReferenceRefusesPathsThatAreNotWhatTheyReadAs(t *testing.T) {
	refused := []string{
		// The token endpoint, reached through a dot segment.
		"/v2/token/manifests/..",
		"/v2/token/manifests/.",
		"/v2/token/blobs/..",
		"/v2/token/referrers/..",
		"/v2/auth/manifests/..",
		"/v2/x/y/manifests/..",
		// The same behind a path parameter, a backslash, or more encoding.
		"/v2/token/manifests/..;x",
		`/v2/token/manifests/..\`,
		"/v2/token/manifests/%2e%2e",
		"/v2/token/manifests/.%2e",
		// A relative segment in the repository name.
		"/v2/../token/manifests/latest",
		"/v2/lib/../../token/manifests/latest",
		"/v2/lib/./app/manifests/latest",
		"/v2/lib/..;x/app/manifests/latest",
		"/v2/lib/%2e%2e/app/manifests/latest",
		`/v2/lib\..\app/manifests/latest`,
		"/v2/../tags/list",
		"/v2/lib/../tags/list",
		// An empty name component: "//" is merged by the registry's router.
		"/v2/lib//app/manifests/latest",
		"/v2//manifests/latest",
		// Characters that end the path, or do not belong in one.
		"/v2/lib/app?x/manifests/latest",
		"/v2/lib/app#x/manifests/latest",
		"/v2/lib/app/manifests/latest?x",
		"/v2/lib/app/manifests/la test",
		"/v2/lib/app/manifests/-latest",
		"/v2/lib/app/manifests/.hidden",
		"/v2/lib/app/manifests/" + strings.Repeat("a", 129),
		// A blob or a referrers subject that is not a digest.
		"/v2/lib/app/blobs/latest",
		"/v2/lib/app/blobs/uploads",
		"/v2/lib/app/blobs/sha256:abc",
		"/v2/lib/app/referrers/latest",
	}
	for _, p := range refused {
		if ref, ok := parseReference(p); ok {
			t.Errorf("parseReference(%q) accepted it as %+v", p, ref)
		}
	}

	accepted := []struct {
		path string
		kind refKind
		name string
		ref  string
	}{
		{"/v2/library/nginx/manifests/latest", refManifest, "library/nginx", "latest"},
		{"/v2/library/nginx/manifests/1.27.0-alpine3.20", refManifest, "library/nginx", "1.27.0-alpine3.20"},
		{"/v2/library/nginx/manifests/_internal", refManifest, "library/nginx", "_internal"},
		{"/v2/library/nginx/manifests/V1", refManifest, "library/nginx", "V1"},
		{"/v2/library/nginx/manifests/" + strings.Repeat("a", 128), refManifest, "library/nginx", strings.Repeat("a", 128)},
		{"/v2/library/nginx/manifests/" + classTestDigest, refManifest, "library/nginx", classTestDigest},
		{"/v2/library/nginx/blobs/" + classTestDigest, refBlob, "library/nginx", classTestDigest},
		{"/v2/library/nginx/referrers/" + classTestDigest, refReferrers, "library/nginx", classTestDigest},
		// Names registries accept beyond the specification's grammar stay usable.
		{"/v2/Org/My_App.v2/manifests/latest", refManifest, "Org/My_App.v2", "latest"},
		{"/v2/a/b/c/d/e/manifests/latest", refManifest, "a/b/c/d/e", "latest"},
		{"/v2/a...b/manifests/latest", refManifest, "a...b", "latest"},
		// A repository really called "token" is still a repository.
		{"/v2/token/manifests/latest", refManifest, "token", "latest"},
	}
	for _, tc := range accepted {
		ref, ok := parseReference(tc.path)
		if !ok {
			t.Errorf("parseReference(%q) refused a well-formed request", tc.path)
			continue
		}
		if ref.kind != tc.kind || ref.name != tc.name || ref.reference != tc.ref {
			t.Errorf("parseReference(%q) = %+v, want kind %d name %q reference %q", tc.path, ref, tc.kind, tc.name, tc.ref)
		}
	}
}

func TestValidTag(t *testing.T) {
	for _, tag := range []string{"latest", "1", "v1.2.3", "1.27-alpine", "a_b", "_x", "A", "sha-abc123", strings.Repeat("z", 128)} {
		if !validTag(tag) {
			t.Errorf("validTag(%q) = false, want true", tag)
		}
	}
	for _, tag := range []string{"", ".", "..", ".x", "-x", "a/b", "a b", "a:b", "a;b", "a%2e", "a\\b", "ä", strings.Repeat("z", 129)} {
		if validTag(tag) {
			t.Errorf("validTag(%q) = true, want false", tag)
		}
	}
}
