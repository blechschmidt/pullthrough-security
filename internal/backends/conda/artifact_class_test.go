package conda

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the Conda channel layout names: a package archive, in either
// format, is a payload; the per-subdir repodata documents and channeldata.json
// are metadata. Calling a payload metadata would let it reach a client
// unexamined.
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
		// Payload: package archives, in both formats, under any subdir.
		{"/linux-64/numpy-1.26.4-py312heda63a1_0.conda", payload},
		{"/linux-64/numpy-1.26.4-py312heda63a1_0.tar.bz2", payload},
		{"/noarch/requests-2.31.0-pyhd8ed1ab_0.conda", payload},
		{"/noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2", payload},
		{"/osx-arm64/python-dateutil-2.9.0-pyhd8ed1ab_0.conda", payload},
		{"/label/dev/win-64/zlib-1.3.1-h2466b09_1.conda", payload},
		// A package whose name spells an index is still a package: the archive
		// extension is looked at first.
		{"/linux-64/repodata.json-1.0-0.tar.bz2", payload},
		{"/noarch/channeldata.json-1.0-0.conda", payload},

		// Metadata: the per-subdir index, in every variant and encoding.
		{"/linux-64/repodata.json", metadata},
		{"/linux-64/repodata.json.bz2", metadata},
		{"/linux-64/repodata.json.zst", metadata},
		{"/noarch/current_repodata.json", metadata},
		{"/noarch/current_repodata.json.bz2", metadata},
		{"/noarch/current_repodata.json.zst", metadata},
		{"/win-64/repodata_from_packages.json", metadata},
		{"/win-64/repodata_from_packages.json.bz2", metadata},
		{"/label/dev/osx-64/repodata.json", metadata},
		// Metadata: the channel summary.
		{"/channeldata.json", metadata},
		{"/label/dev/channeldata.json", metadata},
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
		// Every Conda resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// TestNothingUnnamedIsServed records why the Conda backend never returns an
// unclassified resource: the layout is closed. A path that is neither a
// package under a subdir nor one of the index documents is refused by Resolve,
// so there is no pass-through whose content a gate would have to judge.
func TestNothingUnnamedIsServed(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)
	for _, path := range []string{
		// Not a Conda archive format, and not an encoding the index is
		// published in.
		"/linux-64/numpy-1.26.4-py312heda63a1_0.tar.gz",
		"/linux-64/repodata.json.gz",
		"/linux-64/repodata.json.sh",
		// Files the layout does not name.
		"/linux-64/install.sh",
		"/rss.xml",
		// A package or an index outside any subdir, or under a directory that
		// is not one.
		"/numpy-1.26.4-py312heda63a1_0.conda",
		"/somewhere/numpy-1.26.4-py312heda63a1_0.conda",
		"/repodata.json",
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
