//go:build fuzz
// +build fuzz

// Fuzz targets for the Maven pull-through parsers (Task 30, Task 40).
//
// A malicious or compromised upstream repository controls the POM, the
// maven-metadata.xml, the checksum sidecar body, and (via the client) the
// request path. All of these are parsed on the pull path before any content is
// cached or served, so the parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParsePOM ./internal/backends/maven/
package maven

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar",
		"/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar.sha256",
		"/com/google/guava/guava/maven-metadata.xml",
		"/com/example/lib/1.0-SNAPSHOT/lib-1.0-20231010.123456-7.jar",
		"/com/example/lib/1.0/lib-1.0.module",
		"/com/example/lib/1.0/lib-1.0-all.module",
		"/com/example/lib/1.0/lib-1.0.jar;x=.sha1",
		"/a/b/c/../../../etc/passwd",
		"",
		"/",
		"////",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		// Invariants for an accepted path: the cacheability and verification
		// predicates must be callable without panicking, and an artifact must carry
		// a non-empty extension.
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.verifiableArtifact() && res.ext == "" {
			t.Fatalf("verifiable artifact with empty ext: %q", path)
		}
		// A resource classified as metadata is served unexamined: it must not be a
		// primary artifact other than the module's own Gradle metadata, and its
		// path must be written in plain layout characters only.
		a := res.artifact(path)
		if a.Filename != "" || a.Kind != "" {
			t.Fatalf("artifact of %q carries more than a class: %+v", path, a)
		}
		file := strings.ToLower(strings.Trim(path, "/"))
		if a.Class == backends.ArtifactMetadata {
			if !plainPath(path) {
				t.Fatalf("path %q is not plain but is classified as metadata", path)
			}
			if res.verifiableArtifact() && !strings.HasSuffix(file, ".module") {
				t.Fatalf("primary artifact %q is classified as metadata", path)
			}
		}
		if res.verifiableArtifact() && (strings.HasSuffix(file, ".jar") || strings.HasSuffix(file, ".pom")) &&
			a.Class != backends.ArtifactPayload {
			t.Fatalf("%q is classified as %s, want payload", path, a.Class)
		}
	})
}

func FuzzParsePOM(f *testing.F) {
	f.Add([]byte(fullPOM))
	f.Add([]byte(`<project><parent><groupId>g</groupId><version>1</version></parent><artifactId>a</artifactId></project>`))
	f.Add([]byte(`<project></project>`))
	f.Add([]byte(`<not-a-project/>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePOM(data)
		if err != nil {
			return
		}
		// A parsed POM must answer its query methods without panicking.
		_ = p.Coordinate()
		_ = p.matchesPath("g", "a", "1")
	})
}

func FuzzParseMetadata(f *testing.F) {
	f.Add([]byte(releaseMetadataXML))
	f.Add([]byte(snapshotMetadataXML))
	f.Add([]byte(`<metadata></metadata>`))
	f.Add([]byte(`<other/>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseMetadata(data)
		if err != nil {
			return
		}
		// Snapshot resolution must be safe on any parsed metadata.
		_, _ = m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "", "jar")
		_, _ = m.ResolveSnapshot("lib", "1.0-SNAPSHOT", "sources", "jar")
	})
}

func FuzzParseChecksumValue(f *testing.F) {
	seeds := []string{
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709  file.jar",
		"file.jar: DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
		"",
		"   \n\t  ",
		"zzzz",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, alg := range verifyAlgorithms {
			if hex, err := parseChecksumValue(body, alg); err == nil {
				if len(hex) != alg.hexLen {
					t.Fatalf("accepted %q for %s with wrong length %d", hex, alg.name, len(hex))
				}
			}
		}
	})
}
