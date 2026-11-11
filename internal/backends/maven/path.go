package maven

import (
	"regexp"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The Maven repository layout addresses every artifact by its GAV coordinate
// laid out as a directory path:
//
//	/<groupId-with-dots-as-slashes>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<ext>
//
// e.g. groupId "com.google.guava", artifactId "guava", version "31.1-jre":
//
//	/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar
//
// Checksum and signature sidecars append a further extension to the artifact
// filename (".sha1", ".sha256", ".md5", ".sha512", ".asc"). Version-level and
// artifact-level metadata live at well-known "maven-metadata.xml" files:
//
//	/<groupId>/<artifactId>/maven-metadata.xml                 (release: lists versions)
//	/<groupId>/<artifactId>/<version>-SNAPSHOT/maven-metadata.xml (snapshot: timestamped builds)
//
// This file classifies an inbound path into one of these resource kinds and
// derives the GAV coordinate, which feeds the admission gates (nameguard,
// policy, provenance, vulnscan, license, policyengine) and the cacheability
// decision.

// resourceKind enumerates the classes of resource a Maven path can address.
type resourceKind int

const (
	// kindArtifact is a primary artifact whose content is checksum-verified:
	// .jar, .pom, .war, .module, .aar, and similar packaging outputs.
	kindArtifact resourceKind = iota
	// kindChecksum is a checksum sidecar (.sha1/.sha256/.md5/.sha512) of another
	// file. It is served as-is (it is the source of truth used to verify the
	// artifact, so verifying it against itself is meaningless).
	kindChecksum
	// kindSignature is a detached PGP signature sidecar (.asc).
	kindSignature
	// kindMetadata is a maven-metadata.xml document (release or snapshot). It is
	// mutable and revalidated rather than cached indefinitely.
	kindMetadata
	// kindMetadataChecksum is a checksum sidecar of a maven-metadata.xml document.
	// Like the metadata it guards, it is mutable.
	kindMetadataChecksum
	// kindOther is any path that does not match the Maven layout (served live,
	// uncached, with no coordinate).
	kindOther
)

// resource is the parsed classification of an inbound Maven request path.
type resource struct {
	kind       resourceKind
	groupID    string
	artifactID string
	// version is the version directory. Empty for release-level metadata
	// (/<group>/<artifact>/maven-metadata.xml).
	version string
	// classifier is the optional artifact classifier (e.g. "sources", "javadoc").
	classifier string
	// ext is the primary artifact extension without the leading dot (e.g. "jar",
	// "pom"). For sidecars it is the underlying artifact's extension.
	ext string
	// checksumAlg, for kindChecksum/kindMetadataChecksum, is the sidecar algorithm.
	checksumAlg checksumAlg
	// isSnapshot reports whether the version is a -SNAPSHOT version.
	isSnapshot bool
	// snapshotTimestamped reports whether the filename carries a resolved snapshot
	// timestamp (e.g. "...-20231010.123456-7.jar"), which is immutable and
	// cacheable even though its version directory is a -SNAPSHOT.
	snapshotTimestamped bool
}

const metadataFile = "maven-metadata.xml"

// snapshotTimestampPattern matches the resolved-snapshot suffix Maven appends to
// a deployed snapshot artifact filename: "<base>-<yyyyMMdd.HHmmss>-<build>".
var snapshotTimestampPattern = regexp.MustCompile(`-[0-9]{8}\.[0-9]{6}-[0-9]+`)

// classify parses an inbound path (with the "/v1/maven" route prefix already
// stripped, retaining its leading slash) into a resource. It returns ok=false
// for paths that cannot be expressed in the Maven layout.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from these segments, so they must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	last := segs[len(segs)-1]

	// Peel an optional checksum or signature extension off the filename to find
	// the underlying file and its sidecar role.
	base := last
	var (
		isChecksum bool
		isSig      bool
		alg        checksumAlg
	)
	if dot := strings.LastIndex(last, "."); dot >= 0 {
		sfx := strings.ToLower(last[dot:])
		if a, ok := checksumExtensions[sfx]; ok {
			isChecksum = true
			alg = a
			base = last[:dot]
		} else if sfx == ".asc" {
			isSig = true
			base = last[:dot]
		}
	}

	// maven-metadata.xml (and its sidecars) is special: the directory above it is
	// either the artifactId (release metadata) or a version directory (snapshot
	// metadata), not a version+filename pair.
	if base == metadataFile {
		return classifyMetadata(segs, isChecksum, alg)
	}

	// A primary artifact (or its sidecar) needs at least
	// group(>=1)/artifact/version/filename → 4 segments.
	if len(segs) < 4 {
		return resource{}, false
	}
	version := segs[len(segs)-2]
	artifactID := segs[len(segs)-3]
	groupID := strings.Join(segs[:len(segs)-3], ".")
	if groupID == "" || artifactID == "" || version == "" {
		return resource{}, false
	}

	// The filename must begin with "<artifactId>-<version>" (or, for resolved
	// snapshots, "<artifactId>-<timestamped-version>"); reject mismatches so a
	// crafted path cannot smuggle an unrelated coordinate past the gates.
	if !strings.HasPrefix(base, artifactID+"-") {
		return resource{}, false
	}

	r := resource{
		groupID:    groupID,
		artifactID: artifactID,
		version:    version,
		isSnapshot: strings.HasSuffix(version, "-SNAPSHOT"),
	}
	r.classifier, r.ext = classifierAndExt(base, artifactID, version)
	if r.ext == "" {
		return resource{}, false
	}
	if r.isSnapshot && snapshotTimestampPattern.MatchString(base) {
		r.snapshotTimestamped = true
	}

	switch {
	case isChecksum:
		r.kind = kindChecksum
		r.checksumAlg = alg
	case isSig:
		r.kind = kindSignature
	default:
		r.kind = kindArtifact
	}
	return r, true
}

// classifyMetadata handles the maven-metadata.xml family. The path is either
// /<group...>/<artifact>/maven-metadata.xml (release) or
// /<group...>/<artifact>/<version>/maven-metadata.xml (snapshot).
func classifyMetadata(segs []string, isChecksum bool, alg checksumAlg) (resource, bool) {
	// Drop the trailing "maven-metadata.xml" segment.
	dirs := segs[:len(segs)-1]
	if len(dirs) < 2 {
		return resource{}, false
	}
	r := resource{}
	if isChecksum {
		r.kind = kindMetadataChecksum
		r.checksumAlg = alg
	} else {
		r.kind = kindMetadata
	}

	last := dirs[len(dirs)-1]
	if strings.HasSuffix(last, "-SNAPSHOT") {
		// Snapshot metadata: dirs = group.../artifact/version.
		if len(dirs) < 3 {
			return resource{}, false
		}
		r.version = last
		r.isSnapshot = true
		r.artifactID = dirs[len(dirs)-2]
		r.groupID = strings.Join(dirs[:len(dirs)-2], ".")
	} else {
		// Release metadata: dirs = group.../artifact.
		r.artifactID = last
		r.groupID = strings.Join(dirs[:len(dirs)-1], ".")
	}
	if r.groupID == "" || r.artifactID == "" {
		return resource{}, false
	}
	return r, true
}

// classifierAndExt splits an artifact filename's classifier and extension given
// its artifactId and version. The filename is "<artifactId>-<version>[-<classifier>].<ext>".
// For resolved snapshots the version embedded in the filename is the timestamped
// form, so we strip the "<artifactId>-" prefix and then take everything after
// the version token. Returns an empty ext when the filename has no extension.
func classifierAndExt(base, artifactID, version string) (classifier, ext string) {
	rest := strings.TrimPrefix(base, artifactID+"-")

	// Determine the version token actually present in the filename: either the
	// literal version, or (for a deployed snapshot) the timestamped replacement of
	// the "-SNAPSHOT" suffix, i.e. "<base-version>-<yyyyMMdd.HHmmss>-<build>".
	verToken := version
	if strings.HasSuffix(version, "-SNAPSHOT") {
		if loc := snapshotTimestampPattern.FindString(base); loc != "" {
			verToken = strings.TrimSuffix(version, "-SNAPSHOT") + loc
		}
	}

	if !strings.HasPrefix(rest, verToken) {
		// Fall back: treat the last dot as the extension boundary.
		if dot := strings.LastIndex(rest, "."); dot >= 0 {
			return "", rest[dot+1:]
		}
		return "", ""
	}
	tail := strings.TrimPrefix(rest, verToken)
	// tail is "[-<classifier>].<ext>" or ".<ext>".
	dot := strings.LastIndex(tail, ".")
	if dot < 0 {
		return "", ""
	}
	ext = tail[dot+1:]
	classPart := tail[:dot]
	classifier = strings.TrimPrefix(classPart, "-")
	return classifier, ext
}

// coordinate returns the GAV coordinate name ("groupId:artifactId") for a parsed
// resource, the form used to address Java artifacts everywhere (build files,
// vulnerability databases, SBOM purls).
func (r resource) coordinateName() string {
	if r.groupID == "" || r.artifactID == "" {
		return ""
	}
	return r.groupID + ":" + r.artifactID
}

// verifiableArtifact reports whether the resource is a primary artifact whose
// content the backend should checksum-verify against its sidecar.
func (r resource) verifiableArtifact() bool {
	return r.kind == kindArtifact
}

// cacheable reports whether the resource may be cached. Immutable artifacts
// (release versions and resolved/timestamped snapshots, plus their sidecars) are
// cached; mutable documents (maven-metadata.xml, non-timestamped -SNAPSHOT
// artifacts, and their sidecars) are revalidated live.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindMetadata, kindMetadataChecksum, kindOther:
		return false
	case kindArtifact, kindChecksum, kindSignature:
		if r.isSnapshot && !r.snapshotTimestamped {
			return false
		}
		return true
	default:
		return false
	}
}

// payloadExtensions are the primary-artifact extensions — lower case, as Maven
// packaging and Gradle write them — whose content a build puts on a class path,
// unpacks, links or runs: the POM (examined as a single file), Java archives of
// every flavor, generic archives, plugin packagings, native libraries and
// executables.
var payloadExtensions = []string{
	"pom",
	"jar", "war", "ear", "aar", "rar", "zip", "tar.gz", "tgz", "tar", "tar.bz2", "tar.xz",
	"klib", "hpi", "jpi", "nar", "kar", "so", "dll", "dylib", "exe",
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). path is the request path the resource was parsed
// from.
//
//   - maven-metadata.xml and every checksum and signature sidecar are metadata,
//     as is the component's Gradle Module Metadata (see isModuleMetadata).
//   - A primary artifact with one of payloadExtensions is a payload, cached or
//     not: a non-timestamped snapshot is revalidated on every request and is a
//     payload all the same.
//   - A primary artifact of any other extension is left unclassified.
//
// Metadata is served unexamined, so it is only claimed for a plain path (see
// plainPath).
func (r resource) artifact(path string) backends.Artifact {
	switch r.kind {
	case kindMetadata, kindMetadataChecksum, kindChecksum, kindSignature:
		if plainPath(path) {
			return backends.Metadata()
		}
	case kindArtifact:
		clean := strings.Trim(path, "/")
		file := clean[strings.LastIndex(clean, "/")+1:]
		// The name is judged as written and as a repository manager may read it:
		// a servlet container drops a ";name=value" path parameter before the
		// application looks the file up, so "lib-1.0.pom;x" is "lib-1.0.pom" to
		// it. What is a payload under either reading is a payload. (The reverse
		// — calling something metadata — is only ever done for a plain path.)
		names := []string{strings.ToLower(file)}
		if bare, _, found := strings.Cut(names[0], ";"); found {
			names = append(names, bare)
		}
		for _, lower := range names {
			for _, ext := range payloadExtensions {
				if strings.HasSuffix(lower, "."+ext) {
					if ext == "pom" {
						// A POM is one XML file: a parent or BOM is the whole artifact.
						return backends.PayloadFile()
					}
					return backends.Payload()
				}
			}
		}
		if r.isModuleMetadata(file) && plainPath(path) {
			return backends.Metadata()
		}
	}
	return backends.Artifact{}
}

// isModuleMetadata reports whether file is the component's Gradle Module
// Metadata: "<artifactId>-<version>.module", the version being the timestamped
// one for a deployed snapshot. Gradle publishes the document under that name and
// no other.
//
// The extension alone is not enough. The module metadata is written by the
// publisher and tells Gradle where each of a variant's files is ("url", relative
// to the module), so a file "<artifactId>-<version>-all.module" beside it can be
// what Gradle downloads as the component's jar.
func (r resource) isModuleMetadata(file string) bool {
	stem, ok := strings.CutSuffix(file, ".module")
	if !ok {
		return false
	}
	stem, ok = strings.CutPrefix(stem, r.artifactID+"-")
	if !ok {
		return false
	}
	if stem == r.version {
		return true
	}
	base, ok := strings.CutSuffix(r.version, "-SNAPSHOT")
	if !ok {
		return false
	}
	stamp, ok := strings.CutPrefix(stem, base)
	return ok && stamp != "" && snapshotTimestampPattern.FindString(stamp) == stamp
}

// plainPath reports whether a layout path is written only in the characters
// Maven coordinates and file names are made of: letters, digits, ".", "_", "-"
// and "+". (classify has already refused empty and dot segments.)
//
// What an upstream makes of other characters is not knowable here. A servlet
// container strips a ";" path parameter from a segment before the application
// looks the path up, so a repository manager built on one can answer
// "lib-1.0.jar;x=.sha1" — a checksum sidecar by its ending — with the jar.
func plainPath(path string) bool {
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '.', c == '_', c == '-', c == '+':
		default:
			return false
		}
	}
	return true
}
