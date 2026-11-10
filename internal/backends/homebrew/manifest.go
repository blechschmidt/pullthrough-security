package homebrew

import (
	"encoding/json"
	"strings"
)

// The bottle blob URL the real brew client requests,
// "/v2/<repo>/blobs/sha256:<digest>", names a repository and a content address
// but no formula version — yet the admission gates need a (name, version)
// coordinate to apply at all. brew always downloads the formula's OCI image
// index ("/v2/<repo>/manifests/<version>[-<rebuild>]") along with the bottle —
// immediately before it, or in parallel with it (flights.go) — to read the
// bottle's install receipt out of it, and that index is exactly the missing
// link: every per-platform entry is annotated with the bottle tarball's SHA-256
// and a reference name that embeds the formula version.
//
//	{
//	  "schemaVersion": 2,
//	  "manifests": [{
//	    "platform": {"architecture": "amd64", "os": "linux"},
//	    "annotations": {
//	      "org.opencontainers.image.ref.name": "2.12.3.x86_64_linux.1",
//	      "sh.brew.bottle.digest": "ab40f400…",          <- the blob's digest
//	      "sh.brew.tab": "{…}"
//	    }
//	  }, …],
//	  "annotations": {
//	    "org.opencontainers.image.title": "hello",        <- the formula name
//	    "org.opencontainers.image.version": "2.12.3",     <- pkg_version
//	    "org.opencontainers.image.ref.name": "2.12.3-1"   <- the tag
//	  }
//	}
//
// So as a manifest passes through, the backend records (repository, bottle
// digest) -> formula version in a bounded in-memory index (bottleindex.go), and
// the blob request that follows resolves its coordinate from it. The index is
// keyed by repository as well as digest, so a manifest can only describe blobs
// of the repository it was itself fetched from.
//
// The version recorded is the formula's version — brew's pkg_version with the
// "_<revision>" packaging suffix removed, and without the bottle rebuild
// counter — i.e. the same string the formula JSON API publishes as
// "versions.stable" and the synthetic "/bottle/<name>/<version>/…" endpoint
// carries. All three sources therefore agree on a bottle's coordinate.

// OCI annotation keys brew writes on a bottle image index (see brew's
// GitHubPackages#upload_bottle).
const (
	annBottleDigest = "sh.brew.bottle.digest"
	annRefName      = "org.opencontainers.image.ref.name"
	annVersion      = "org.opencontainers.image.version"
	annTitle        = "org.opencontainers.image.title"
)

const (
	// maxManifestBytes bounds a manifest fetch. A real bottle index is tens of
	// KiB; registries cap manifests at a few MiB. The cap stops a hostile
	// upstream returning an unbounded body into the buffer the parser reads.
	maxManifestBytes = 4 << 20 // 4 MiB
	// maxBottlesPerManifest bounds how many bottles one manifest may teach the
	// index (a real index lists one per supported platform, under a dozen), so a
	// single hostile document cannot flush the index of everything else.
	maxBottlesPerManifest = 256
)

// defaultManifestAccept is offered to the registry when the client negotiated no
// media type of its own. brew always sends the OCI image-index type.
const defaultManifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// ociDocument is the subset of an OCI image index or image manifest the backend
// reads. Annotation values are decoded loosely so one non-string value cannot
// make the whole document unreadable.
type ociDocument struct {
	Annotations map[string]any `json:"annotations"`
	Manifests   []struct {
		Annotations map[string]any `json:"annotations"`
	} `json:"manifests"`
}

// manifestBottle is one bottle a manifest describes.
type manifestBottle struct {
	digest  string // lowercase hex SHA-256 of the bottle tarball
	version string // formula version (revision and rebuild stripped)
}

// manifestFacts is what a manifest teaches the backend about its repository.
type manifestFacts struct {
	// title is the document's title annotation: the formula's full name, still
	// to be validated against the repository (formulaNameFromTitle).
	title   string
	bottles []manifestBottle
}

// parseBottleManifest extracts the bottles an OCI document describes. It accepts
// both shapes a client can negotiate — the image index brew requests, whose
// per-platform entries carry the bottle annotations, and a per-platform image
// manifest, which carries the same annotations at its top level. It reports
// ok=false for anything that names no bottle (not JSON, not a Homebrew bottle
// image), in which case nothing is learned; the document is still served
// verbatim either way.
func parseBottleManifest(data []byte) (manifestFacts, bool) {
	var doc ociDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return manifestFacts{}, false
	}
	facts := manifestFacts{title: annotation(doc.Annotations, annTitle)}
	pkgVersion := annotation(doc.Annotations, annVersion)

	add := func(ann map[string]any) {
		if len(facts.bottles) >= maxBottlesPerManifest {
			return
		}
		digest := strings.ToLower(annotation(ann, annBottleDigest))
		if len(digest) != sha256HexLen || !isHex(digest) {
			return
		}
		version, ok := formulaVersion(annotation(ann, annRefName), pkgVersion)
		if !ok {
			return
		}
		facts.bottles = append(facts.bottles, manifestBottle{digest: digest, version: version})
	}
	for _, m := range doc.Manifests {
		add(m.Annotations)
	}
	add(doc.Annotations)
	return facts, len(facts.bottles) > 0
}

// annotation returns a string annotation's trimmed value, or "" when it is
// absent or not a string.
func annotation(ann map[string]any, key string) string {
	s, _ := ann[key].(string)
	return strings.TrimSpace(s)
}

// formulaVersion derives a bottle's formula version from its per-platform
// reference name "<pkg_version>.<bottle tag>[.<rebuild>]" — the annotation brew
// itself matches against the version it expects before trusting a manifest
// entry. pkgVersion is the document-level version annotation: when the
// reference name is exactly it plus a tag (and rebuild) it settles the split
// outright; otherwise the reference name is split on its own, and pkgVersion is
// only the fallback for an absent or unparseable reference name. The result has
// the "_<revision>" suffix removed and must be a well-formed version.
func formulaVersion(refName, pkgVersion string) (string, bool) {
	pkg := pkgVersion
	if !refNameExtends(refName, pkgVersion) {
		if v, ok := pkgVersionFromRefName(refName); ok {
			pkg = v
		}
	}
	version := stripRevision(pkg)
	if !validVersion(version) {
		return "", false
	}
	return version, true
}

// refNameExtends reports whether refName is pkgVersion followed by exactly a
// bottle tag and an optional rebuild counter.
func refNameExtends(refName, pkgVersion string) bool {
	if pkgVersion == "" {
		return false
	}
	rest, ok := strings.CutPrefix(refName, pkgVersion+".")
	if !ok {
		return false
	}
	tag, rebuild, hasRebuild := strings.Cut(rest, ".")
	return isBottleTag(tag) && (!hasRebuild || isDigits(rebuild))
}

// pkgVersionFromRefName splits a per-platform reference name
// "<pkg_version>.<bottle tag>[.<rebuild>]" (brew's
// GitHubPackages.version_rebuild) and returns the pkg_version. A version may
// itself contain dots and dashes ("7.1.2-35"), so the split works from the
// right: a rebuild counter is all digits and a bottle tag never is, which makes
// the trailing components unambiguous.
func pkgVersionFromRefName(refName string) (string, bool) {
	parts := strings.Split(refName, ".")
	n := len(parts)
	switch {
	case n >= 3 && isDigits(parts[n-1]) && isBottleTag(parts[n-2]):
		return strings.Join(parts[:n-2], "."), true
	case n >= 2 && isBottleTag(parts[n-1]):
		return strings.Join(parts[:n-1], "."), true
	default:
		return "", false
	}
}

// stripRevision removes the "_<revision>" suffix brew appends to a formula's
// version to form its pkg_version ("1.92.0_1" -> "1.92.0"), mirroring brew's
// PkgVersion.parse (/\A(.+?)(?:_(\d+))?\z/). brew's audit forbids a version
// that itself ends in an underscore and digits, so the split is exact.
func stripRevision(pkgVersion string) string {
	i := strings.LastIndexByte(pkgVersion, '_')
	if i <= 0 || !isDigits(pkgVersion[i+1:]) {
		return pkgVersion
	}
	return pkgVersion[:i]
}

// validVersion reports whether v is usable as a coordinate version. A bottled
// formula's version is always a valid OCI tag — brew refuses to upload a bottle
// otherwise — so anything else (empty, over-long, or carrying a path separator,
// whitespace, or the ":" reserved for the digest-derived fallback version) is
// treated as unknown rather than passed to the gates.
func validVersion(v string) bool { return validOCITag(v) }

// isBottleTag reports whether s looks like a Homebrew bottle tag: a platform
// identifier such as "arm64_sequoia", "x86_64_linux", "sonoma" or "all". New
// macOS releases add tags every year, so the shape is matched rather than a
// fixed vocabulary: a lowercase letter followed by lowercase alphanumerics and
// underscores.
func isBottleTag(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
