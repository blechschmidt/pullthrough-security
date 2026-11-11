package backends

import (
	"net/url"
	"path"
)

// ArtifactClass says what a resolved resource is to the gates that examine what
// a client is about to install (the LLM package-content scan, Task 174).
//
// A backend knows its protocol's grammar, so it is the one place that can tell
// an installable payload from the documents served next to it: an index, a
// version listing, a checksum or signature sidecar. It states that knowledge on
// every Resolved it returns. Coordinates and cacheability do not: a Go module's
// ".info" file shares the ".zip" file's coordinate and is cached exactly like
// it, while a Maven snapshot jar is a payload that is never cached.
//
// The classes are deliberately asymmetric. A wrong "metadata" lets a payload
// reach a client unexamined, so a backend claims it only for a resource its
// grammar positively identifies. Everything it cannot name stays unclassified,
// and a gate then decides from the bytes.
//
// Even "metadata" is a statement about the path, and a path is only as good as
// whoever told the client to fetch it. In several protocols that is the
// repository itself: an APT Packages index names each package's Filename, a
// yum primary.xml its location, a PyPI simple page its links. A hostile
// repository can therefore route a package through a path that reads as an
// index. So a gate does not take "metadata" as "skip without looking": it
// still checks that the bytes are not a package archive or an executable (see
// KindIndexArchive for the one kind of metadata that legitimately is an
// archive).
type ArtifactClass uint8

const (
	// ArtifactUnclassified is the zero value: the backend made no statement — a
	// pass-through path, a file kind its grammar does not name, a route an
	// operator declared without saying what it serves. A content gate decides
	// from the bytes: an archive, an executable or a script served on such a
	// path is examined like a payload; anything else is left alone.
	ArtifactUnclassified ArtifactClass = iota
	// ArtifactMetadata is a document the client reads but neither installs nor
	// executes: a registry index, a version listing, a packument, a checksum or
	// signature sidecar, an API response. Content gates skip it — once its bytes
	// have shown that it is not a package archive or an executable after all.
	ArtifactMetadata
	// ArtifactPayload is content the client installs, unpacks, builds, imports
	// or executes: a package archive, an OS package, an image manifest or layer,
	// a model weight file, a build script or recipe served as a single file.
	// Content gates examine it whatever its bytes look like — a payload that is
	// not an archive is examined as a single file rather than waved through.
	ArtifactPayload
)

// String returns the class's stable label, as used in documentation and tests.
func (c ArtifactClass) String() string {
	switch c {
	case ArtifactMetadata:
		return "metadata"
	case ArtifactPayload:
		return "payload"
	default:
		return "unclassified"
	}
}

// ArtifactKind refines a payload for gates that treat some payloads specially.
// The zero value is an ordinary artifact whose format is detected from its
// bytes.
type ArtifactKind string

const (
	// KindOCIManifest is an OCI / Docker image manifest or index: the JSON root
	// of an image, whose config and layers are separate, digest-addressed blobs
	// of the same repository. A gate examines the image it describes, not the
	// JSON document alone.
	KindOCIManifest ArtifactKind = "oci-manifest"
	// KindOCIBlob is a digest-addressed blob of an OCI repository: an image
	// config or a layer. Which of the two is not knowable from the request.
	KindOCIBlob ArtifactKind = "oci-blob"
	// KindFile marks a payload that may be a single file rather than an archive:
	// a build script or recipe a tool evaluates (Package.swift, conanfile.py, a
	// POM, MODULE.bazel), a patch, one module file of a registry that serves
	// files individually, a model weight file, an installer. Bytes of such a
	// payload that are no archive are examined as the one file they are.
	//
	// It is deliberately opt-in. Every other payload is expected to be an
	// archive, and one that does not unpack is reported as a package that went
	// unexamined — never read as a harmless single file: extractors differ in
	// how much damage they tolerate, so "not an archive to the scanner" does not
	// mean "not unpacked by the installer".
	KindFile ArtifactKind = "file"
	// KindIndexArchive marks metadata that is itself an archive of data files:
	// Hackage's 01-index.tar.gz, a Julia registry tarball, an AppStream icon
	// set. The client unpacks it as an index, at a path its protocol fixes — no
	// upstream document can redirect a package download there — so a tar at such
	// a path is what belongs there and is not examined as a package. It is used
	// only with ArtifactMetadata.
	KindIndexArchive ArtifactKind = "index-archive"
)

// Artifact is a backend's classification of a resolved resource.
type Artifact struct {
	// Class is what the resource is; see ArtifactClass.
	Class ArtifactClass
	// Kind refines a payload; empty for an ordinary artifact.
	Kind ArtifactKind
	// Filename is the artifact's file name where the upstream URL does not end
	// in it — a crate served from ".../download", an archive whose upstream URL
	// is the metadata document that locates it. Empty means the last segment of
	// Resolved.UpstreamURL is the name.
	Filename string
}

// Payload returns the classification of an ordinary installable artifact.
func Payload() Artifact { return Artifact{Class: ArtifactPayload} }

// PayloadNamed returns the classification of an installable artifact whose file
// name the upstream URL does not carry.
func PayloadNamed(filename string) Artifact {
	return Artifact{Class: ArtifactPayload, Filename: filename}
}

// PayloadFile returns the classification of an installable artifact that may be
// a single file rather than an archive (see KindFile).
func PayloadFile() Artifact { return Artifact{Class: ArtifactPayload, Kind: KindFile} }

// Metadata returns the classification of a document content gates skip.
func Metadata() Artifact { return Artifact{Class: ArtifactMetadata} }

// MetadataArchive returns the classification of an index that is itself an
// archive of data files (see KindIndexArchive).
func MetadataArchive() Artifact {
	return Artifact{Class: ArtifactMetadata, Kind: KindIndexArchive}
}

// ArtifactFilename returns the file name a resolved resource is served under:
// the backend's explicit Artifact.Filename when it set one, else the last path
// segment of the upstream URL (without query or fragment). It returns "" when
// there is none.
func (r *Resolved) ArtifactFilename() string {
	if r == nil {
		return ""
	}
	if r.Artifact.Filename != "" {
		return r.Artifact.Filename
	}
	p := r.UpstreamURL
	if u, err := url.Parse(r.UpstreamURL); err == nil {
		p = u.Path
	}
	base := path.Base(p)
	if base == "." || base == "/" {
		return ""
	}
	return base
}
