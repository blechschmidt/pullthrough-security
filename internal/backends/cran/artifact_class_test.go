package cran

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the CRAN repository layout names: a package — source tarball
// or prebuilt binary — is a payload, and a PACKAGES index is metadata in every
// encoding. Calling a payload metadata would let it reach a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	const (
		payload  = backends.ArtifactPayload
		metadata = backends.ArtifactMetadata
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// Payload: source packages, current and archived.
		{"/src/contrib/ggplot2_3.4.4.tar.gz", payload},
		{"/src/contrib/Archive/ggplot2/ggplot2_3.4.3.tar.gz", payload},
		{"/src/contrib/4.3.0/Recommended/Matrix_1.5-4.tar.gz", payload},
		// Payload: prebuilt Windows and macOS binaries.
		{"/bin/windows/contrib/4.3/ggplot2_3.4.4.zip", payload},
		{"/bin/macosx/big-sur-arm64/contrib/4.3/ggplot2_3.4.4.tgz", payload},
		// A package whose name spells an index is still a package: only the
		// exact index names are indexes.
		{"/src/contrib/PACKAGES_1.0.tar.gz", payload},

		// Metadata: the PACKAGES index of an area, in every encoding.
		{"/src/contrib/PACKAGES", metadata},
		{"/src/contrib/PACKAGES.gz", metadata},
		{"/src/contrib/PACKAGES.rds", metadata},
		{"/src/contrib/PACKAGES.bz2", metadata},
		{"/src/contrib/PACKAGES.xz", metadata},
		{"/bin/windows/contrib/4.3/PACKAGES", metadata},
		{"/bin/macosx/big-sur-arm64/contrib/4.3/PACKAGES.gz", metadata},
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
		// Every CRAN resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestNothingUnnamedIsServed records why the CRAN backend never returns an
// unclassified resource: the layout is closed. A path that is neither a
// package file nor a PACKAGES index is refused by Resolve, so there is no
// pass-through whose content a gate would have to judge.
func TestNothingUnnamedIsServed(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)
	for _, path := range []string{
		// Not an archive format the layout serves packages in, and a name
		// without a version: neither is a package file name.
		"/src/contrib/ggplot2_3.4.4.tar.xz",
		"/src/contrib/ggplot2.tar.gz",
		// Names that only resemble the index.
		"/src/contrib/PACKAGES.sh",
		"/src/contrib/PACKAGES.tar.gz",
		// Other files a CRAN mirror holds.
		"/src/contrib/Meta/archive.rds",
		"/src/base/R-4/R-4.4.1.tar.gz",
		"/bin/windows/base/R-4.4.1-win.exe",
		"/web/packages/ggplot2/index.html",
	} {
		_, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
		if !errors.Is(err, backends.ErrNotSupported) {
			t.Errorf("Resolve(%q): %v, want ErrNotSupported", path, err)
		}
	}
	// A kind the table does not know makes no statement.
	if got := (resource{kind: kindPackage + 1}).artifact(); got != (backends.Artifact{}) {
		t.Errorf("unknown kind: artifact() = %+v, want no statement", got)
	}
}
