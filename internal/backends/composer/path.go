package composer

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"unicode/utf8"
)

// The Composer/Packagist pull-through backend understands five families of
// request, all addressed off the repository root (the route prefix "/v1/<name>"
// is stripped before classification):
//
//	Repository root (mutable, rewritten — see rewrite.go):
//	  GET /packages.json                         advertises the metadata-url template.
//
//	v2 package metadata (mutable, dist URLs rewritten through the proxy):
//	  GET /p2/<vendor>/<package>.json            release versions.
//	  GET /p2/<vendor>/<package>~dev.json        dev (branch) versions.
//
//	v1 provider metadata (mutable, legacy mirrors; served live, as-is):
//	  GET /p/<vendor>/<package>.json
//	  GET /p/<vendor>/<package>$<sha256>.json
//
//	Filter-list documents (mutable, served live, as-is):
//	  GET /lists/<...>.json                      e.g. Packagist's /lists/all/summary.json.
//
//	Dist archives (immutable, cached, shasum-verified, admission-gated):
//	  GET /dist/<vendor>/<package>/<version>/<reference>.<type>
//
// The dist path is the proxy's own stable locator for a version's distributable
// archive; it is what every "dist.url" in served v2 metadata is rewritten to. It
// names the package AND the version, so Resolve yields a complete coordinate and
// the admission gates (policy, dependency firewall, malware feed, maturity, …)
// evaluate the artifact before anything is fetched. It also names the dist
// reference (for a VCS-backed package, the commit id), which makes the locator
// content-addressed: a moved branch or a re-pointed tag is a different URL and a
// different cache entry, never stale bytes under an old key.
//
// The shape deliberately equals what Composer itself produces when it expands a
// dist-mirror template "…/dist/%package%/%prettyVersion%/%reference%.%type%"
// (Composer\Util\ComposerMirror::processUrl), so one endpoint serves both the
// rewritten dist URLs and — when the proxy does not know its own absolute public
// URL — the dist mirror the root document advertises instead (see rewrite.go):
//
//   - <version> is the version exactly as the metadata's "version" field spells
//     it ("3.0.0", "v8.0.0-RC3", "dev-master"). A dev branch name may contain
//     "/" ("dev-feature/x"), so the version spans every path segment between the
//     package and the final file segment.
//   - <reference> is the dist reference verbatim when it is a plain token (a git
//     commit id always is). A dist that declares no reference uses the "_"
//     placeholder, and a reference that is not URL-safe is represented by "_"
//     followed by a truncated SHA-256 of it (see referenceToken).
//   - <type> is the dist type ("zip", "tar", …).
//
// There is intentionally no version-less dist form: a locator that cannot tell
// Resolve the version cannot be admission-gated, and would let a client pull any
// listed archive around the coordinate gates through the proxy's own egress.
//
// Because the real upstream download URL and the verification shasum both live in
// the package's v2 metadata, the backend resolves a dist request by fetching that
// metadata, locating the entry with exactly that version, reference and type, and
// verifying the streamed archive against the declared SHA-1 — analogous to the
// Maven backend fetching a checksum sidecar.

// resourceKind enumerates the classes of resource a Composer path can address.
type resourceKind int

const (
	// kindDist is a distributable archive: immutable, cached, SHA-1-verified
	// against the shasum in the package's v2 metadata.
	kindDist resourceKind = iota
	// kindRoot is the packages.json repository root: mutable, revalidated, and
	// rewritten so every lookup it advertises comes back through the proxy.
	kindRoot
	// kindMetadata is a /p2/<vendor>/<package>.json v2 metadata document: mutable,
	// revalidated, and rewritten so every dist URL points at kindDist.
	kindMetadata
	// kindProviderV1 is a legacy /p/<vendor>/<package>.json provider document:
	// mutable, served live (not parsed for verification, not rewritten).
	kindProviderV1
	// kindFilterList is a /lists/<...>.json filter-list document (the summary a
	// Composer 2.11+ client consults for its malware/policy lists): mutable,
	// served live, never rewritten.
	kindFilterList
	// kindOther is any path that does not match a known Composer resource (served
	// live, uncached, with no coordinate).
	kindOther
)

// noReferenceToken stands in for the <reference> path element of a dist that
// declares no reference. It starts with a character no verbatim reference token
// may start with, so it can never be mistaken for a real reference.
const noReferenceToken = "_"

// Bounds on the variable-length dist path elements, so a crafted request cannot
// make the backend carry (or cache-key) arbitrarily long strings.
const (
	maxVersionLen   = 255
	maxReferenceLen = 255
	maxDistTypeLen  = 16
)

// resource is the parsed classification of an inbound Composer request path.
type resource struct {
	kind resourceKind
	// vendor and pkg are the package coordinate halves, for
	// kindMetadata/kindProviderV1/kindDist.
	vendor string
	pkg    string
	// version is the package version a dist request names (for kindDist), exactly
	// as the metadata's "version" field spells it.
	version string
	// reference is the dist reference token (for kindDist; see referenceToken),
	// used together with version to locate the matching entry — and therefore the
	// download URL and shasum — in the v2 metadata.
	reference string
	// ext is the dist type, i.e. the archive extension without a leading dot (for
	// kindDist).
	ext string
}

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that cannot be
// expressed in the Composer layout.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from these segments, so each must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	if clean == "packages.json" {
		return resource{kind: kindRoot}, true
	}

	// v2 metadata: /p2/<vendor>/<package>.json (optionally "<package>~dev.json").
	if len(segs) == 3 && segs[0] == "p2" && strings.HasSuffix(segs[2], ".json") {
		vendor := segs[1]
		pkg := strings.TrimSuffix(segs[2], ".json")
		pkg = strings.TrimSuffix(pkg, "~dev")
		if validNamePart(vendor) && validNamePart(pkg) {
			return resource{kind: kindMetadata, vendor: vendor, pkg: pkg}, true
		}
		return resource{}, false
	}

	// v1 provider: /p/<vendor>/<package>.json (optionally "<package>$<hash>.json").
	if len(segs) == 3 && segs[0] == "p" && strings.HasSuffix(segs[2], ".json") {
		vendor := segs[1]
		pkg := strings.TrimSuffix(segs[2], ".json")
		if i := strings.IndexByte(pkg, '$'); i >= 0 {
			pkg = pkg[:i]
		}
		if validNamePart(vendor) && validNamePart(pkg) {
			return resource{kind: kindProviderV1, vendor: vendor, pkg: pkg}, true
		}
		return resource{}, false
	}

	// Filter-list documents: /lists/<...>.json. The root document's
	// "filter.summary-url" is only pointed at the proxy when it lands here.
	if len(segs) >= 2 && segs[0] == "lists" && strings.HasSuffix(segs[len(segs)-1], ".json") {
		return resource{kind: kindFilterList}, true
	}

	// Dist archive: /dist/<vendor>/<package>/<version>/<reference>.<type>. The
	// version may contain "/", so it is every segment between the package and the
	// final "<reference>.<type>" file segment.
	if len(segs) >= 5 && segs[0] == "dist" {
		vendor, pkg := segs[1], segs[2]
		version := strings.Join(segs[3:len(segs)-1], "/")
		file := segs[len(segs)-1]
		dot := strings.LastIndexByte(file, '.')
		if dot < 0 {
			return resource{}, false
		}
		token, ext := file[:dot], file[dot+1:]
		if token == "" {
			// "<version>/.zip" is what Composer's own mirror-template expansion
			// yields for a dist without a reference; treat it as the placeholder so
			// both spellings share one cache entry.
			token = noReferenceToken
		}
		if !validNamePart(vendor) || !validNamePart(pkg) || !validVersion(version) ||
			!validReferenceToken(token) || !validDistType(ext) {
			return resource{}, false
		}
		return resource{kind: kindDist, vendor: vendor, pkg: pkg, version: version, reference: token, ext: ext}, true
	}

	return resource{}, false
}

// validNamePart reports whether s is a syntactically valid Composer vendor or
// package name component: lowercase alphanumerics with single internal
// separators (".", "-", "_"), matching Packagist's naming rules closely enough to
// reject crafted segments while accepting every real package name.
func validNamePart(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
			// Separators may not lead, trail, or repeat.
			if i == 0 || i == len(s)-1 {
				return false
			}
			if prev := s[i-1]; prev == '.' || prev == '-' || prev == '_' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// splitPackageName splits a "vendor/package" name into its two valid halves. It
// returns ok=false for anything that is not exactly two valid name components,
// which is every name a dist URL could not carry.
func splitPackageName(name string) (vendor, pkg string, ok bool) {
	vendor, pkg, found := strings.Cut(name, "/")
	if !found || !validNamePart(vendor) || !validNamePart(pkg) {
		return "", "", false
	}
	return vendor, pkg, true
}

// validVersion reports whether a package version can be carried in a dist path.
// Composer versions are free-form ("3.0.0", "v8.0.0-RC3", "dev-feature/x"), so
// the rule only excludes what a URL path cannot represent unambiguously: empty,
// "." and ".." path segments, whitespace, control characters and backslashes.
// None of those can occur in a version derived from a VCS tag or branch.
func validVersion(v string) bool {
	if v == "" || len(v) > maxVersionLen || !utf8.ValidString(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	for _, seg := range strings.Split(v, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// isDevVersion reports whether a version is a development (branch) version,
// using Composer's own rule (VersionParser::parseStability): a "dev-" prefix or
// a "-dev" suffix. Dev versions live in the package's "~dev" metadata document
// and, unlike tags, are expected to move to a new reference over time.
func isDevVersion(v string) bool {
	return strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev")
}

// validDistType reports whether s is a usable dist type / archive extension: a
// short alphanumeric token ("zip", "tar", "gzip", "xz", …). It carries no dot,
// which keeps the "<reference>.<type>" file segment unambiguous.
func validDistType(s string) bool {
	if s == "" || len(s) > maxDistTypeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// validReferenceToken reports whether s is a well-formed <reference> path
// element: either the placeholder family (leading "_") or a verbatim plain
// reference.
func validReferenceToken(s string) bool {
	if s == "" || len(s) > maxReferenceLen {
		return false
	}
	if s[0] != '_' && !isAlnum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// isPlainReference reports whether a dist reference can appear verbatim as the
// <reference> path element: it starts with an alphanumeric and continues with
// alphanumerics, ".", "_" or "-". Every git/hg commit id qualifies.
func isPlainReference(ref string) bool {
	return ref != "" && ref[0] != '_' && validReferenceToken(ref)
}

// referenceToken maps a dist reference onto the <reference> element of a dist
// path. It is total, so every dist the metadata lists has exactly one locator:
//
//   - a plain reference (any commit id) is used verbatim;
//   - no reference at all becomes the "_" placeholder;
//   - anything else (a reference containing "/", "@", whitespace, …) becomes "_"
//     plus the first 128 bits of its SHA-256, hex-encoded.
//
// The mapping need not be reversible: a dist request is resolved by recomputing
// the token for the entry the metadata lists under that package and version and
// comparing, never by decoding the token back into a reference.
func referenceToken(ref string) string {
	if ref == "" {
		return noReferenceToken
	}
	if isPlainReference(ref) {
		return ref
	}
	sum := sha256.Sum256([]byte(ref))
	return noReferenceToken + hex.EncodeToString(sum[:16])
}

// distPath builds the dist locator (relative to the backend mount, leading slash
// included) for a package version, percent-encoding the version's segments as a
// URL path requires. It returns ok=false when any element cannot be carried in a
// path, in which case the dist is not addressable through the proxy.
func distPath(vendor, pkg, version, reference, distType string) (string, bool) {
	if !validNamePart(vendor) || !validNamePart(pkg) || !validVersion(version) || !validDistType(distType) {
		return "", false
	}
	segs := strings.Split(version, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/dist/" + vendor + "/" + pkg + "/" + strings.Join(segs, "/") + "/" + referenceToken(reference) + "." + distType, true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// coordinateName returns the "vendor/package" coordinate for the admission gates,
// or "" when the resource addresses no single package.
func (r resource) coordinateName() string {
	if r.vendor == "" || r.pkg == "" {
		return ""
	}
	return r.vendor + "/" + r.pkg
}

// distKey returns the canonical, decoded form of a dist resource's locator
// (without a leading slash). It is the cache key suffix, so every spelling of the
// same dist (percent-encoding variants, the empty-reference alias) shares one
// cache entry.
func (r resource) distKey() string {
	return "dist/" + r.vendor + "/" + r.pkg + "/" + r.version + "/" + r.reference + "." + r.ext
}

// verifiableArtifact reports whether the resource is a dist archive whose content
// the backend should checksum-verify.
func (r resource) verifiableArtifact() bool { return r.kind == kindDist }

// cacheable reports whether the resource may be cached. Only dist archives are
// cached; every metadata document is revalidated live.
//
// Every dist is cached, because the cache is where the content gates inspect an
// archive: nothing the dist endpoint serves bypasses them. A locator normally
// pins the content through its reference. A dist that declares no reference is
// pinned by its version alone and stays what it was when first fetched — which is
// also how a Composer client treats it (without a reference it can neither detect
// a change nor distinguish archives in its own download cache).
func (r resource) cacheable() bool { return r.kind == kindDist }

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindDist:
		return "dist"
	case kindRoot:
		return "root"
	case kindMetadata:
		return "metadata"
	case kindProviderV1:
		return "provider-v1"
	case kindFilterList:
		return "filter-list"
	default:
		return "other"
	}
}
