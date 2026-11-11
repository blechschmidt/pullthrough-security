package cpan

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about the
// paths of a CPAN mirror: a distribution archive is a payload; a CHECKSUMS
// file, a distribution's .meta and .readme sidecars and the master indices in
// modules/ are metadata; and every other file is left unclassified for a gate
// to judge from the bytes. Calling a payload metadata would let it reach a
// client unexamined, so the two places a distribution is served from besides
// its author directory's recognized names — an archive format the backend does
// not list, and the by-module/by-category/by-authors views under modules/ —
// are covered shape by shape.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified

		author = "/authors/id/E/ET/ETHER"
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// Payload: a distribution archive in the author tree, in every format
		// the backend recognizes.
		{author + "/Try-Tiny-0.32.tar.gz", payload},
		{author + "/Try-Tiny-0.32.tgz", payload},
		{author + "/Try-Tiny-0.32.tar.bz2", payload},
		{author + "/Try-Tiny-0.32.tar.xz", payload},
		{author + "/Try-Tiny-0.32.zip", payload},
		{"/authors/id/M/MO/MONGER/Foo-v1.2.3.tar.gz", payload},
		// ... with or without a version the coordinate can carry, and in a
		// sub-directory of the author's.
		{author + "/Foo-Bar.tar.gz", payload},
		{author + "/subdir/Try-Tiny-0.32.tar.gz", payload},
		// An archive whose name spells a sidecar or an index is still an archive.
		{author + "/CHECKSUMS.tar.gz", payload},
		{author + "/Try-Tiny-0.32.meta.tar.gz", payload},
		{author + "/Try-Tiny-0.32.readme.zip", payload},

		// Metadata: the per-directory integrity record and a distribution's
		// sidecars, by name.
		{author + "/CHECKSUMS", metadata},
		{author + "/Try-Tiny-0.32.meta", metadata},
		{author + "/Try-Tiny-0.32.readme", metadata},
		{"/authors/id/E/CHECKSUMS", metadata},
		// Metadata: the master indices, which sit directly in modules/.
		{"/modules/02packages.details.txt.gz", metadata},
		{"/modules/02packages.details.txt", metadata},
		{"/modules/03modlist.data.gz", metadata},
		{"/modules/06perms.txt.gz", metadata},
		{"/modules/01modules.index.html", metadata},
		// Metadata: the same sidecars seen through the views under modules/.
		{"/modules/by-module/DBI/DBI-1.643.readme", metadata},
		{"/modules/by-module/DBI/DBI-1.643.meta", metadata},
		{"/modules/by-authors/id/T/TI/TIMB/CHECKSUMS", metadata},

		// Unclassified: any other file in the author tree. It may be an archive
		// in a format the backend does not list.
		{"/authors/id/A/AB/ABC/Foo-1.0.tar", unclassified},
		{"/authors/id/A/AB/ABC/Foo-1.0.tar.Z", unclassified},
		{"/authors/id/A/AB/ABC/Foo-1.0.tar.zst", unclassified},
		{"/authors/id/A/AB/ABC/Foo.pm.gz", unclassified},
		{"/authors/id/A/AB/ABC/Foo-1.0.par", unclassified},
		{"/authors/id/A/AB/ABC/fix.patch", unclassified},
		{"/authors/id/A/AB/ABC/install.sh", unclassified},
		{"/authors/id/A/AB/ABC/checksums", unclassified},
		{"/authors/id/A/AB/ABC/Foo-1.0.META", unclassified},
		{"/authors/01mailrc.txt.gz", unclassified},
		{"/authors/00whois.xml", unclassified},
		{"/authors", unclassified},

		// Unclassified: anything deeper under modules/. The by-module,
		// by-category and by-authors trees are views of the author directories
		// and serve the very same distribution archives; classify recognizes a
		// distribution only under authors/, so these are kind "index" — and must
		// not be called metadata for it.
		{"/modules/by-module/DBI/DBI-1.643.tar.gz", unclassified},
		{"/modules/by-module/DBI/TIMB/DBI-1.643.tar.gz", unclassified},
		{"/modules/by-category/07_Database_Interfaces/DBI/DBI-1.643.tar.gz", unclassified},
		{"/modules/by-authors/id/T/TI/TIMB/DBI-1.643.tar.gz", unclassified},
		{"/modules/by-authors/id/T/TI/TIMB/DBI-1.643.zip", unclassified},
		{"/modules/by-module/DBI/DBI-1.643.tar", unclassified},
		{"/modules/by-module/DBI/DBI.pm.gz", unclassified},
		{"/modules/by-module/DBI", unclassified},
		// Not even directly in modules/ is a distribution archive an index.
		{"/modules/DBI-1.643.tar.gz", unclassified},
		{"/modules/Foo-Bar.zip", unclassified},
		{"/modules", unclassified},
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
		// Every CPAN resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestDistributionNameIsNeverMetadata states the rule the table above samples:
// a file name the backend itself would take for a distribution archive is
// never classified as metadata, in whatever directory of the mirror it is
// requested — a payload in the author tree, unclassified elsewhere.
func TestDistributionNameIsNeverMetadata(t *testing.T) {
	names := []string{
		"DBI-1.643.tar.gz", "DBI-1.643.tgz", "DBI-1.643.tar.bz2", "DBI-1.643.tar.xz", "DBI-1.643.zip",
		"Foo-v1.2.3.tar.gz", "Foo-Bar.tar.gz", "02packages.details.txt.tar.gz", "CHECKSUMS.zip",
		"x.meta.tgz", "x.readme.tar.xz",
	}
	dirs := []string{
		"/authors/id/T/TI/TIMB/", "/authors/id/T/TI/TIMB/sub/", "/authors/", "/authors/id/",
		"/modules/", "/modules/by-module/DBI/", "/modules/by-category/07_Database_Interfaces/DBI/",
		"/modules/by-authors/id/T/TI/TIMB/", "/modules/dbperl/",
	}
	for _, dir := range dirs {
		for _, name := range names {
			if _, _, ok := parseDistFilename(name); !ok {
				t.Fatalf("parseDistFilename(%q) does not accept the name", name)
			}
			res, ok := classify(dir + name)
			if !ok {
				t.Fatalf("classify(%q) rejected the path", dir+name)
			}
			if got := res.artifact().Class; got == backends.ArtifactMetadata {
				t.Errorf("classify(%q).artifact().Class = %s (kind %s)", dir+name, got, res.kindLabel())
			}
		}
	}
}
