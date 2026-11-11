package apt

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about the
// paths of an APT repository: a binary package is a payload, the Release
// documents and the indices the repository format names are metadata, and
// everything else is left unclassified for a gate to judge from the bytes.
// Calling a payload metadata would let it reach a client unexamined, so the
// "dists/" tree — where real archives keep installer images and upgrade
// tarballs next to the indices — is covered shape by shape.
func TestResolveArtifactClass(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), Options{})

	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified
	)
	sha256 := strings.Repeat("0123456789abcdef", 4)

	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// Payload: binary packages, recognized by extension wherever they are
		// served from.
		{"/pool/main/h/hello/hello_1.0_amd64.deb", payload},
		{"/pool/main/c/cdrom-detect/cdrom-detect_1.89_all.udeb", payload},
		{"/pool/main/h/hello/hello-dbgsym_1.0_amd64.ddeb", payload},
		{"/extras/hello_1.0_all.deb", payload},
		// A package is a payload even on a path that would otherwise name an
		// index document.
		{"/dists/bookworm/main/binary-amd64/hello_1.0_amd64.deb", payload},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA256/hello_1.0_amd64.deb", payload},
		{"/dists/bookworm/main/i18n/Translation-en.deb", payload},

		// Metadata: the Release documents and the detached signature.
		{"/dists/bookworm/InRelease", metadata},
		{"/dists/bookworm/Release", metadata},
		{"/dists/bookworm/Release.gpg", metadata},
		// ... of a suite whose name has two segments, and the per-component,
		// per-architecture copies.
		{"/dists/bookworm/updates/InRelease", metadata},
		{"/dists/bookworm/updates/Release.gpg", metadata},
		{"/dists/bookworm/main/binary-amd64/Release", metadata},
		{"/dists/bookworm/main/source/Release", metadata},

		// Metadata: binary package indices, in every encoding.
		{"/dists/bookworm/main/binary-amd64/Packages", metadata},
		{"/dists/bookworm/main/binary-amd64/Packages.gz", metadata},
		{"/dists/bookworm/main/binary-amd64/Packages.xz", metadata},
		{"/dists/bookworm/main/binary-all/Packages.bz2", metadata},
		{"/dists/bookworm/main/binary-amd64/Packages.lz4", metadata},
		{"/dists/bookworm/main/binary-amd64/Packages.lzma", metadata},
		{"/dists/bookworm/main/binary-amd64/Packages.zst", metadata},
		{"/dists/bookworm/main/debian-installer/binary-amd64/Packages.xz", metadata},

		// Metadata: the other indices the repository format names.
		{"/dists/bookworm/main/source/Sources", metadata},
		{"/dists/bookworm/main/source/Sources.xz", metadata},
		{"/dists/bookworm/main/Contents-amd64.gz", metadata},
		{"/dists/bookworm/main/Contents-udeb-amd64.gz", metadata},
		{"/dists/bookworm/main/Contents-source.gz", metadata},
		{"/dists/bookworm/Contents-amd64.gz", metadata},
		{"/dists/bookworm/main/i18n/Translation-en", metadata},
		{"/dists/bookworm/main/i18n/Translation-en.bz2", metadata},
		{"/dists/bookworm/main/i18n/Translation-pt_BR.xz", metadata},
		{"/dists/bookworm/main/i18n/Index", metadata},
		{"/dists/bookworm/main/dep11/Components-amd64.yml.gz", metadata},
		{"/dists/bookworm/main/dep11/Components-amd64.yml.xz", metadata},
		{"/dists/bookworm/main/dep11/CID-Index-amd64.json.gz", metadata},
		{"/dists/bookworm/main/dep11/icons-64x64.tar.gz", metadata},
		{"/dists/bookworm/main/dep11/icons-64x64@2.tar.gz", metadata},
		{"/dists/jammy/main/cnf/Commands-amd64.xz", metadata},

		// Metadata: index diffs, and any index addressed by its digest.
		{"/dists/sid/main/binary-amd64/Packages.diff/Index", metadata},
		{"/dists/sid/main/binary-amd64/Packages.diff/2024-06-01-0204.36.gz", metadata},
		{"/dists/sid/main/binary-amd64/Packages.diff/T-2024-06-01-0204.36-F-2024-05-30-2003.11.gz", metadata},
		{"/dists/sid/main/source/Sources.diff/Index", metadata},
		{"/dists/sid/main/i18n/Translation-en.diff/Index", metadata},
		{"/dists/sid/main/Contents-amd64.diff/Index", metadata},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + sha256, metadata},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA512/" + sha256 + sha256, metadata},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA1/" + sha256[:40], metadata},
		{"/dists/bookworm/main/binary-amd64/by-hash/MD5Sum/" + sha256[:32], metadata},
		{"/dists/bookworm/main/by-hash/SHA256/" + sha256, metadata},
		{"/dists/bookworm/main/dep11/by-hash/SHA256/" + sha256, metadata},
		{"/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/" + sha256, metadata},

		// Unclassified: paths outside the layout. A source package is served
		// from the pool as a .dsc and tarballs, which the layout does not name.
		{"/pool/main/h/hello/hello_2.10.orig.tar.gz", unclassified},
		{"/pool/main/h/hello/hello_2.10-2.debian.tar.xz", unclassified},
		{"/pool/main/h/hello/hello_2.10-2.dsc", unclassified},
		{"/some/other/path", unclassified},
		{"/dists", unclassified},
		// A flat repository keeps its indices outside dists/; the layout does not
		// name them there.
		{"/Packages.gz", unclassified},
		{"/InRelease", unclassified},

		// Unclassified: what archives keep under dists/ that is not an index.
		// Installer images, the release upgrader and signed boot loaders are
		// booted, unpacked and run; none of them may be called metadata.
		{"/dists/bookworm/main/installer-amd64/current/images/netboot/netboot.tar.gz", unclassified},
		{"/dists/bookworm/main/installer-amd64/current/images/netboot/mini.iso", unclassified},
		{"/dists/bookworm/main/installer-amd64/current/images/netboot/debian-installer/amd64/linux", unclassified},
		{"/dists/bookworm/main/installer-amd64/current/images/netboot/debian-installer/amd64/initrd.gz", unclassified},
		{"/dists/bookworm/main/installer-amd64/current/images/SHA256SUMS", unclassified},
		{"/dists/jammy-updates/main/dist-upgrader-all/current/jammy.tar.gz", unclassified},
		{"/dists/jammy-updates/main/dist-upgrader-all/current/jammy.tar.gz.gpg", unclassified},
		{"/dists/jammy/main/signed/linux-amd64/5.15.0-25.25/signed.tar.gz", unclassified},
		{"/dists/jammy/main/uefi/grub2-amd64/current/grubx64.efi.signed", unclassified},
		// A directory, and names that only resemble an index name.
		{"/dists/bookworm", unclassified},
		{"/dists/bookworm/main", unclassified},
		{"/dists/bookworm/ChangeLog", unclassified},
		{"/dists/bookworm/main/binary-amd64/Packages.tar.gz", unclassified},
		{"/dists/bookworm/main/binary-amd64/Packages.gz.gz", unclassified},
		{"/dists/bookworm/main/Contents-amd64.tar.gz", unclassified},
		{"/dists/bookworm/main/i18n/Translation-en.sh", unclassified},
		{"/dists/bookworm/main/i18n/Translation-", unclassified},
		{"/dists/bookworm/main/release", unclassified},
		// A name the format gives to one directory means nothing in another.
		{"/dists/bookworm/main/installer-amd64/icons-64x64.tar.gz", unclassified},
		{"/dists/bookworm/main/installer-amd64/Translation-en.gz", unclassified},
		{"/dists/bookworm/main/installer-amd64/Commands-amd64.xz", unclassified},
		{"/dists/bookworm/main/dep11/icons-64x64.tar.gz.sh", unclassified},
		{"/dists/bookworm/main/dep11/payload.tar.gz", unclassified},
		// by-hash names a digest of the hash's own length, and nothing else.
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA256/not-a-digest", unclassified},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + sha256[:40], unclassified},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA3/" + sha256, unclassified},
		{"/dists/bookworm/main/binary-amd64/by-hash/" + sha256, unclassified},
		{"/dists/bookworm/main/binary-amd64/by-hash/SHA256/" + sha256 + "/netboot.tar.gz", unclassified},
		// A diff directory belongs to an index; "<anything>.diff/" does not.
		{"/dists/bookworm/main/installer-amd64/netboot.diff/netboot.tar.gz", unclassified},
	}
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s (kind %s)", c.path, res.Artifact.Class, c.want, res.Metadata[metaKind])
		}
		// Every APT resource is fetched from a URL that ends in its own file
		// name, so no explicit name is stated. The one refinement is the index
		// that is itself a tar archive: an AppStream icon set.
		wantKind := backends.ArtifactKind("")
		if c.want == metadata && strings.Contains(c.path, "/dep11/icons-") {
			wantKind = backends.KindIndexArchive
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want kind %q and no file name", c.path, res.Artifact, wantKind)
		}
	}
}

// TestMetaKindIsNotOneClass shows why the classification does not follow the
// resource kind alone: classify gives kindMeta to every path under
// "dists/<suite>/" it has no other kind for, and that set holds both index
// documents and content a client boots or runs.
func TestMetaKindIsNotOneClass(t *testing.T) {
	for path, want := range map[string]backends.ArtifactClass{
		"/dists/bookworm/main/source/Sources.xz":                                     backends.ArtifactMetadata,
		"/dists/bookworm/main/i18n/Translation-en.bz2":                               backends.ArtifactMetadata,
		"/dists/bookworm/main/installer-amd64/current/images/netboot/netboot.tar.gz": backends.ArtifactUnclassified,
		"/dists/jammy-updates/main/dist-upgrader-all/current/jammy.tar.gz":           backends.ArtifactUnclassified,
	} {
		res, ok := classify(path)
		if !ok || res.kind != kindMeta {
			t.Fatalf("classify(%q) = %+v ok=%v, want kindMeta", path, res, ok)
		}
		if got := res.artifact().Class; got != want {
			t.Errorf("classify(%q).artifact().Class = %s, want %s", path, got, want)
		}
	}
}
