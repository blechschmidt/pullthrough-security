package maven

import (
	"path"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// These tests pin what Resolve says a Maven layout path is, for the content
// gates (backends.ArtifactClass). The asymmetry they guard: a payload must never
// be called metadata, because metadata is served unexamined.
func TestResolveArtifactClass(t *testing.T) {
	const (
		payload      = backends.ArtifactPayload
		metadata     = backends.ArtifactMetadata
		unclassified = backends.ArtifactUnclassified
	)
	const dir = "/com/example/lib/1.0/"
	const snap = "/com/example/lib/1.0-SNAPSHOT/"

	cases := []struct {
		path string
		want backends.ArtifactClass
	}{
		// What a build puts on a class path, unpacks, links or runs.
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar", payload},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre-sources.jar", payload},
		{dir + "lib-1.0.war", payload},
		{dir + "lib-1.0.ear", payload},
		{dir + "lib-1.0.aar", payload},
		{dir + "lib-1.0.rar", payload},
		{dir + "lib-1.0.zip", payload},
		{dir + "lib-1.0.tar.gz", payload},
		{dir + "lib-1.0-bin.tar.gz", payload},
		{dir + "lib-1.0.tgz", payload},
		{dir + "lib-1.0.tar", payload},
		{dir + "lib-1.0-src.tar.bz2", payload},
		{dir + "lib-1.0.tar.xz", payload},
		{dir + "lib-1.0.klib", payload},
		{dir + "lib-1.0.hpi", payload},
		{dir + "lib-1.0.jpi", payload},
		{dir + "lib-1.0.nar", payload},
		{dir + "lib-1.0.kar", payload},
		{dir + "lib-1.0-linux-x86_64.so", payload},
		{dir + "lib-1.0-windows-x86_64.dll", payload},
		{dir + "lib-1.0-osx-aarch_64.dylib", payload},
		{dir + "lib-1.0-windows-x86_64.exe", payload},
		{dir + "lib-1.0.JAR", payload},
		// A file that does not carry its directory's version is parsed more
		// loosely; a payload extension still makes it a payload.
		{dir + "lib-2.0.jar", payload},
		{dir + "lib-2.0.tar.gz", payload},
		// A POM is examined as a single file.
		{"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom", payload},
		{snap + "lib-1.0-SNAPSHOT.pom", payload},
		// Snapshots, resolved or not.
		{snap + "lib-1.0-SNAPSHOT.jar", payload},
		{snap + "lib-1.0-20231010.123456-7.jar", payload},
		{snap + "lib-1.0-20231010.123456-7-sources.jar", payload},
		// A character outside the layout's alphabet does not make a payload less
		// of one.
		{dir + "lib-1.0-a;b.jar", payload},

		// Repository metadata and its sidecars.
		{"/com/google/guava/guava/maven-metadata.xml", metadata},
		{"/com/google/guava/guava/maven-metadata.xml.sha1", metadata},
		{"/com/google/guava/guava/maven-metadata.xml.asc", metadata},
		{snap + "maven-metadata.xml", metadata},
		{snap + "maven-metadata.xml.sha256", metadata},
		// Checksum and signature sidecars.
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1", metadata},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha256", metadata},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha512", metadata},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.md5", metadata},
		{"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.asc", metadata},
		{dir + "lib-1.0.pom.sha1", metadata},
		{dir + "lib-1.0.pom.asc", metadata},
		{dir + "lib-1.0.jar.asc.sha1", metadata},
		{dir + "lib-1.0+build.5.jar.sha1", metadata},
		{snap + "lib-1.0-SNAPSHOT.jar.sha1", metadata},
		// Gradle Module Metadata, under the one name Gradle publishes it.
		{dir + "lib-1.0.module", metadata},
		{dir + "lib-1.0.module.sha256", metadata},
		{dir + "lib-1.0.module.asc", metadata},
		{snap + "lib-1.0-SNAPSHOT.module", metadata},
		{snap + "lib-1.0-20231010.123456-7.module", metadata},

		// Any other ".module" is whatever its publisher put there: module metadata
		// points Gradle at a variant's files by relative URL.
		{dir + "lib-1.0-all.module", unclassified},
		{dir + "lib-1.0.jar.module", unclassified},
		{dir + "lib-2.0.module", unclassified},
		{dir + "lib-1.0.MODULE", unclassified},
		{snap + "lib-1.0-20231010.123456-7-all.module", unclassified},
		{snap + "lib-1.0-20231010.123456.module", unclassified},
		// Artifact extensions the backend does not name.
		{dir + "lib-1.0.txt", unclassified},
		{dir + "lib-1.0-cyclonedx.json", unclassified},
		{dir + "lib-1.0-features.xml", unclassified},
		{dir + "lib-1.0.gz", unclassified},
		{dir + "lib-1.0-tar.gz", unclassified}, // classifier "tar", not a tarball
		{dir + "lib-1.0.bin", unclassified},
		{dir + "lib-1.0.sh", unclassified},
		// A sidecar name is only taken at its word on a plain path: a servlet
		// container drops the ";…" path parameter and serves the jar.
		{dir + "lib-1.0.jar;x=.sha1", unclassified},
		{dir + "lib-1.0.jar;.asc", unclassified},
		{dir + "lib-1.0.jar;.sha1", unclassified},
		// The other way round, a payload is recognized under the reading a servlet
		// container makes of the name as well as under the one it is written in:
		// what is a jar or a POM once the ";…" is dropped is a payload.
		{dir + "lib-1.0.jar;v=1.module", payload},
		{dir + "lib-1.0.pom;x", payload},
		{dir + "lib-1.0.jar;jsessionid=1", payload},
		{dir + "lib-1.0.txt;x.pom", payload},
		{dir + "lib-1.0.txt;x", unclassified},
		{dir + "lib-1.0.jar%00.sha1", unclassified},
		{dir + `lib-1.0.jar\.sha1`, unclassified},
		{dir + "lib-1.0.jar .sha1", unclassified},
		{"/com/example/..;/lib/1.0/lib-1.0.jar.sha1", unclassified},
		{"/com/example;x/lib/maven-metadata.xml", unclassified},
		{dir + "lib-1.0.module;x", unclassified},
	}

	b := testBackend(t, newFakeRepo(t), nil)
	for _, c := range cases {
		res := resolve(t, b, c.path)
		if res.Artifact.Class != c.want {
			t.Errorf("%q: class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		// The layout path ends in the file name, and no Maven resource needs a
		// kind: the classification is the class alone.
		// A POM is one XML file; every other payload is an archive.
		wantKind := backends.ArtifactKind("")
		lower := strings.ToLower(c.path)
		bare, _, _ := strings.Cut(lower[strings.LastIndex(lower, "/")+1:], ";")
		if res.Artifact.Class == backends.ArtifactPayload && (strings.HasSuffix(lower, ".pom") || strings.HasSuffix(bare, ".pom")) {
			wantKind = backends.KindFile
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("%q: artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}

// Whether a resource is a payload does not follow from whether it is cached: a
// non-timestamped snapshot is revalidated on every request, and is still what
// the build runs.
func TestResolveSnapshotIsPayloadWhetherCachedOrNot(t *testing.T) {
	b := testBackend(t, newFakeRepo(t), nil)

	mutable := resolve(t, b, "/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar")
	if mutable.Cacheable {
		t.Error("a non-timestamped snapshot jar must not be cacheable")
	}
	if mutable.Artifact != backends.Payload() {
		t.Errorf("non-timestamped snapshot jar: artifact = %+v, want payload", mutable.Artifact)
	}

	resolved := resolve(t, b, "/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7.jar")
	if !resolved.Cacheable {
		t.Error("a timestamped snapshot jar should be cacheable")
	}
	if resolved.Artifact != backends.Payload() {
		t.Errorf("timestamped snapshot jar: artifact = %+v, want payload", resolved.Artifact)
	}

	// And the reverse: a release's sidecar is cached, and is metadata.
	sidecar := resolve(t, b, "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1")
	if !sidecar.Cacheable {
		t.Error("a release checksum sidecar should be cacheable")
	}
	if sidecar.Artifact != backends.Metadata() {
		t.Errorf("checksum sidecar: artifact = %+v, want metadata", sidecar.Artifact)
	}
}

func TestIsModuleMetadata(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/com/example/lib/1.0/lib-1.0.module", true},
		{"/com/example/my-lib/1.0-rc-1/my-lib-1.0-rc-1.module", true},
		{"/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.module", true},
		{"/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7.module", true},
		{"/com/example/lib/1.0/lib-1.0-all.module", false},
		{"/com/example/lib/1.0/lib-1.0-.module", false},
		{"/com/example/lib/1.0/lib-1.0.0.module", false},
		{"/com/example/lib/1.0/lib-1.0.jar", false},
		{"/com/example/lib/1.0/lib-1.0.module.jar", false},
		{"/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7-all.module", false},
		{"/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7x.module", false},
		{"/com/example/lib/1.0-SNAPSHOT/lib-1.0-2023.module", false},
		// A release directory does not hold timestamped builds.
		{"/com/example/lib/1.0/lib-1.0-20231010.123456-7.module", false},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) not ok", c.path)
			continue
		}
		file := path.Base(c.path)
		if got := res.isModuleMetadata(file); got != c.want {
			t.Errorf("isModuleMetadata(%q) = %v, want %v", file, got, c.want)
		}
	}
}

func TestPlainPath(t *testing.T) {
	for _, p := range []string{
		"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha1",
		"/org/scala-lang/scala-library/2.13.12/scala-library-2.13.12.pom.asc",
		"/com/example/lib_2.13/1.0+build.5/lib_2.13-1.0+build.5.module",
		"/com/example/lib/maven-metadata.xml",
	} {
		if !plainPath(p) {
			t.Errorf("plainPath(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"/a/b/1.0/b-1.0.jar;x=.sha1", `/a/b/1.0/b-1.0.jar\.sha1`, "/a/b/1.0/b-1.0.jar%00.sha1",
		"/a/b/1.0/b-1.0.jar .sha1", "/a/b/1.0/b-1.0.jar\x00.sha1", "/a/b/1.0/b-1.0.jar?.sha1",
		"/a/b/1.0/b-1.0.jar#.sha1", "/a/b/1.0/b-1.0.jar:.sha1", "/a/${v}/1.0/b-1.0.jar.sha1",
		"/a/b~1/1.0/b~1-1.0.jar.sha1", "/a/b/1.0/b-1.0-é.jar.sha1",
	} {
		if plainPath(p) {
			t.Errorf("plainPath(%q) = true, want false", p)
		}
	}
}
