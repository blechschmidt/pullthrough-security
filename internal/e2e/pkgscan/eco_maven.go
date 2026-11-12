//go:build integration
// +build integration

package pkgscan

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"strings"
)

// Maven: a repository is a static tree laid out by coordinate,
// "/<groupId, dots as slashes>/<artifactId>/<version>/<artifactId>-<version>.<ext>".
// Every file in it is published with checksum sidecars next to it (".md5" and
// ".sha1" everywhere, ".sha256" and ".sha512" for newer uploads); the backend
// fetches the strongest sidecar the repository serves and verifies the
// artifact against it before it caches or serves a byte. The version listing,
// "<groupId>/<artifactId>/maven-metadata.xml", is what a build reads to
// resolve a dynamic version (a Maven range, LATEST/RELEASE, Gradle's "1.+").
// Nothing is rewritten: a client builds every URL from the coordinate itself.
//
// The payload is the jar: a zip whose first member is its manifest, carrying
// the POM it was built from under META-INF/maven/. The POM is served next to it
// — a client reads it before the jar — but is not pulled here: the backend
// calls it a payload of its own (one XML file), not metadata.

func init() {
	register(eco{
		ID: "maven", Type: "maven", Title: "Maven",
		Format:   "jar (.jar, zip)",
		Registry: mavenRegistry,
	})
}

// mavenGroup is the groupId every fixture is published under: the reverse of
// the reserved domain the Go row's module paths use.
const mavenGroup = "test.example.pte2e"

func mavenRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	groupDir := strings.ReplaceAll(mavenGroup, ".", "/")
	for _, s := range env.Specs {
		artifactID := s.Name()
		dir := "/" + groupDir + "/" + artifactID + "/"
		file := dir + fixtureVersion + "/" + artifactID + "-" + fixtureVersion
		pom := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n" +
			"  <modelVersion>4.0.0</modelVersion>\n" +
			"  <groupId>" + mavenGroup + "</groupId>\n" +
			"  <artifactId>" + artifactID + "</artifactId>\n" +
			"  <version>" + fixtureVersion + "</version>\n" +
			"  <packaging>jar</packaging>\n" +
			"  <description>pullthrough llm-package-scan e2e fixture</description>\n" +
			"</project>\n"
		// The marker file is a resource of the jar, beside the package it belongs to.
		marker := groupDir + "/" + s.Slug() + "/" + markerFile
		embedded := "META-INF/maven/" + mavenGroup + "/" + artifactID + "/"
		jar := zipOf(
			// A manifest is written with CRLF line ends and closed by an empty line.
			member{Name: "META-INF/MANIFEST.MF", Data: "Manifest-Version: 1.0\r\nCreated-By: pkgscan-e2e\r\nBuild-Jdk-Spec: 17\r\n\r\n"},
			member{Name: embedded + "pom.xml", Data: pom},
			member{Name: embedded + "pom.properties", Data: "artifactId=" + artifactID + "\ngroupId=" + mavenGroup + "\nversion=" + fixtureVersion + "\n"},
			member{Name: marker, Data: s.Text("")},
		)
		metadata := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<metadata>\n" +
			"  <groupId>" + mavenGroup + "</groupId>\n" +
			"  <artifactId>" + artifactID + "</artifactId>\n" +
			"  <versioning>\n" +
			"    <latest>" + fixtureVersion + "</latest>\n" +
			"    <release>" + fixtureVersion + "</release>\n" +
			"    <versions>\n" +
			"      <version>" + fixtureVersion + "</version>\n" +
			"    </versions>\n" +
			"    <lastUpdated>20240102030405</lastUpdated>\n" +
			"  </versioning>\n" +
			"</metadata>\n"
		mavenPublish(reg.mux, dir+"maven-metadata.xml", []byte(metadata), "text/xml")
		mavenPublish(reg.mux, file+".pom", []byte(pom), "text/xml")
		mavenPublish(reg.mux, file+".jar", jar, "application/java-archive")

		reg.add(s.Variant, &pkgPull{
			// The backend's coordinate is the GAV: "<groupId>:<artifactId>" and the
			// version directory.
			Name: mavenGroup + ":" + artifactID, Version: fixtureVersion,
			// A build that resolves a dynamic version reads the version listing first.
			Preamble: []step{{Path: dir + "maven-metadata.xml", Contains: []string{"<release>" + fixtureVersion + "</release>"}}},
			Payload:  step{Path: file + ".jar"},
			Body:     jar,
			Marker:   marker,
		})
	}
	return reg, nil
}

// mavenPublish serves a repository file together with the checksum sidecars a
// repository publishes beside every file: the bare lower-case hex digest.
func mavenPublish(mux *stubMux, path string, body []byte, contentType string) {
	mux.File(path, body, contentType)
	md5sum, sha1sum, sha512sum := md5.Sum(body), sha1.Sum(body), sha512.Sum512(body)
	for ext, digest := range map[string]string{
		".md5":    hex.EncodeToString(md5sum[:]),
		".sha1":   hex.EncodeToString(sha1sum[:]),
		".sha256": hexOf(body),
		".sha512": hex.EncodeToString(sha512sum[:]),
	} {
		mux.File(path+ext, []byte(digest), "text/plain")
	}
}
