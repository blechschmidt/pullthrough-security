package locate

import "strings"

// This file exports the parts of the Maven locator the full-mirror feed
// adapter (Task 191) reuses: it reads coordinates from a repository's Maven
// Indexer index and must name the same main artifact for a packaging as the
// release pinner does, and it refuses to follow Maven Central.

// MavenExtension returns the extension of the main file of a Maven artifact
// for the packaging its POM declares, as locateMaven reads it ("jar" for jar,
// bundle, maven-plugin and the other jar-producing packagings; "war", "ear",
// "aar", …). ok is false for "pom", whose POM is the whole artifact, and for
// a packaging the locator does not know (locateMaven then assumes a jar).
func MavenExtension(packaging string) (string, bool) {
	ext, ok := mavenExtensions[strings.ToLower(strings.TrimSpace(packaging))]
	return ext, ok
}

// MavenCentralHosts returns the host names Maven Central is known by: the
// hosts a lock file's registry URL is matched against as Central.
func MavenCentralHosts() []string {
	var out []string
	for _, group := range equivalentHosts["maven"] {
		out = append(out, group...)
	}
	return out
}
