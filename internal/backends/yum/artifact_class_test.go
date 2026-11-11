package yum

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about the
// paths of an RPM repository: a package is a payload, repomd.xml with its
// signature and key and the metadata files of the repository's repodata/
// directory are metadata, and every path outside that layout is left
// unclassified for a gate to judge from the bytes. Calling a payload metadata
// would let it reach a client unexamined.
func TestResolveArtifactClass(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), Options{})

	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified
	)
	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// Payload: packages, recognized by extension wherever they are served
		// from — binary, noarch and source alike.
		{"/Packages/hello-1.0-1.x86_64.rpm", payload},
		{"/Packages/h/hello-1.0-1.fc40.x86_64.rpm", payload},
		{"/hello-1.0-1.noarch.rpm", payload},
		{"/SRPMS/hello-1.0-1.src.rpm", payload},
		// A package is a payload even inside the metadata directory.
		{"/repodata/hello-1.0-1.x86_64.rpm", payload},
		{"/repodata/repomd.xml.rpm", payload},

		// Metadata: the manifest, its detached signature and the signing key.
		{"/repodata/repomd.xml", metadata},
		{"/repodata/repomd.xml.asc", metadata},
		{"/repodata/repomd.xml.key", metadata},

		// Metadata: the files repomd.xml lists, under whatever name and encoding
		// the repository publishes them.
		{"/repodata/abc-primary.xml.gz", metadata},
		{"/repodata/abc-primary.xml.zst", metadata},
		{"/repodata/abc-filelists.xml.gz", metadata},
		{"/repodata/abc-other.xml.xz", metadata},
		{"/repodata/abc-primary.sqlite.bz2", metadata},
		{"/repodata/abc-comps-Everything.x86_64.xml", metadata},
		{"/repodata/abc-updateinfo.xml.zck", metadata},
		{"/repodata/abc-modules.yaml.gz", metadata},
		{"/repodata/primary.xml.gz", metadata},
		// ... and the directory's own listing.
		{"/repodata/", metadata},

		// Unclassified: paths outside the layout. A repository tree serves delta
		// RPMs, boot and installer images and keys there; none of them is named
		// by the layout, so none is called metadata.
		{"/Packages/foo-1.0-1.x86_64.drpm", unclassified},
		{"/drpms/foo-1.0-1_1.0-2.x86_64.drpm", unclassified},
		{"/images/pxeboot/vmlinuz", unclassified},
		{"/images/install.img", unclassified},
		{"/EFI/BOOT/BOOTX64.EFI", unclassified},
		{"/.treeinfo", unclassified},
		{"/RPM-GPG-KEY-fedora-40-primary", unclassified},
		{"/some/other", unclassified},
		// Only the repository's own repodata/ directory is the metadata area: the
		// same names below another directory are outside the layout.
		{"/os/repodata/repomd.xml", unclassified},
		{"/os/repodata/abc-primary.xml.gz", unclassified},
		{"/repomd.xml", unclassified},
	}
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s (kind %s)", c.path, res.Artifact.Class, c.want, res.Metadata[metaKind])
		}
		// Every resource is fetched from a URL that ends in its own file name,
		// so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}
