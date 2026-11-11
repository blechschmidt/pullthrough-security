package conan

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every route of the Conan v2 API: the recipe, its exported files, the sources
// and the binary package archive are payloads; the discovery endpoints, the
// file lists, the manifest and conaninfo.txt are metadata; and a file of a
// revision that the layout does not name is left unclassified for a gate to
// judge from the bytes. Calling a payload metadata would let it reach a client
// unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified

		recipe = "/v2/conans/zlib/1.2.13/_/_"
		rrev   = recipe + "/revisions/abc123"
		prev   = rrev + "/packages/pid9/revisions/pr7"
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// Payload: the files of a recipe revision a client executes and builds
		// from.
		{rrev + "/files/conanfile.py", payload},
		{rrev + "/files/conan_export.tgz", payload},
		{rrev + "/files/conan_sources.tgz", payload},
		{"/v2/conans/fmt/10.1.1/bincrafters/stable/revisions/r1/files/conanfile.py", payload},
		// Payload: the binary package archive.
		{prev + "/files/conan_package.tgz", payload},
		// A payload name is a payload under either kind of revision and below a
		// sub-folder: the decision is the file's base name.
		{prev + "/files/conanfile.py", payload},
		{rrev + "/files/conan_package.tgz", payload},
		{rrev + "/files/export/conanfile.py", payload},

		// Metadata: the capability probe, in both spellings.
		{"/v1/ping", metadata},
		{"/v2/ping", metadata},
		// Metadata: searches.
		{"/v2/conans/search", metadata},
		{recipe + "/search", metadata},
		{rrev + "/search", metadata},
		// Metadata: revision pointers and lists.
		{recipe + "/latest", metadata},
		{recipe + "/revisions", metadata},
		{rrev + "/packages/pid9/latest", metadata},
		{rrev + "/packages/pid9/revisions", metadata},
		// Metadata: the JSON file list of a revision.
		{rrev + "/files", metadata},
		{prev + "/files", metadata},
		// Metadata: the integrity manifest and the package's settings record.
		{rrev + "/files/conanmanifest.txt", metadata},
		{prev + "/files/conanmanifest.txt", metadata},
		{prev + "/files/conaninfo.txt", metadata},

		// Unclassified: any other file of a revision. The layout does not name
		// it, so nothing is claimed about it.
		{rrev + "/files/something_else.bin", unclassified},
		{rrev + "/files/conanfile.pyc", unclassified},
		{rrev + "/files/conanfile.py.bak", unclassified},
		{rrev + "/files/conandata.yml", unclassified},
		{rrev + "/files/conan_sources.tar.gz", unclassified},
		{rrev + "/files/metadata/logs/build.log", unclassified},
		{rrev + "/files/metadata/sign/pkgsign-manifest.json", unclassified},
		{prev + "/files/conan_package.tar.zst", unclassified},
		{prev + "/files/CONANINFO.TXT", unclassified},
		{prev + "/files/conaninfo.txt.sh", unclassified},
		{prev + "/files/payload.tgz", unclassified},
		// A ";…" path parameter is dropped by a server built on a servlet
		// container: under that reading these are the recipe and an archive, and
		// they are payloads. The reading never makes anything metadata.
		{rrev + "/files/conanfile.py;x", payload},
		{rrev + "/files/conan_sources.tgz;v=1", payload},
		{prev + "/files/conan_package.tgz;x", payload},
		{rrev + "/files/conanmanifest.txt;x", unclassified},
		{prev + "/files/conaninfo.txt;x", unclassified},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s (kind %s)", c.path, res.Artifact.Class, c.want, res.Metadata[metaKind])
		}
		// Every Conan resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		// The recipe is one Python file; the three archives are archives.
		wantKind := backends.ArtifactKind("")
		if res.Artifact.Class == backends.ArtifactPayload && (strings.HasSuffix(c.path, "/conanfile.py") || strings.Contains(c.path, "/conanfile.py;")) {
			wantKind = backends.KindFile
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestFileArtifactClassIsNotCacheability shows why a file download is
// classified by name: every file of a pinned revision is immutable and cached
// alike and carries the same coordinate, so neither says which of them a
// client executes and which it only reads.
func TestFileArtifactClassIsNotCacheability(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)
	const files = "/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/"

	classes := map[backends.ArtifactClass]bool{}
	for _, name := range []string{"conanfile.py", "conanmanifest.txt", "something_else.bin"} {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: files + name, Query: url.Values{}})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", files+name, err)
		}
		if !res.Cacheable || res.Coordinate != (backends.Coordinate{Name: "zlib", Version: "1.2.13"}) {
			t.Errorf("Resolve(%q): cacheable=%v coordinate=%+v, want a cached file of zlib 1.2.13", files+name, res.Cacheable, res.Coordinate)
		}
		classes[res.Artifact.Class] = true
	}
	if len(classes) != 3 {
		t.Errorf("the three files resolved to %d classes, want payload, metadata and unclassified", len(classes))
	}
}
