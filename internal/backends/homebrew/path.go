package homebrew

import "strings"

// Homebrew distributes two things the proxy fronts, from two different
// upstreams:
//
//   - Formula metadata, from the formulae.brew.sh JSON API:
//
//     GET /api/formula.jws.json        SIGNED full index — what the real brew
//     client downloads (with its cask and tap-migration siblings). A JWS
//     document cannot be rewritten without breaking brew's signature
//     check, so it is proxied byte-exact.
//     GET /api/formula.json            unsigned full index (mutable; URLs rewritten)
//     GET /api/formula/{name}.json     one formula's metadata (mutable; URLs rewritten)
//     GET /api/cask.json, /api/...     other metadata (mutable, proxied as-is)
//
//   - Bottle tarballs, which Homebrew stores as OCI blobs in GitHub Packages
//     (ghcr.io), next to an OCI image index per formula version:
//
//     https://ghcr.io/v2/{repo}/manifests/{version}[-{rebuild}]
//     https://ghcr.io/v2/{repo}/blobs/sha256:{digest}
//
// A client reaches the bottle registry through the proxy in one of two ways:
//
//   - The real brew client takes bottle URLs from the signed index and applies
//     HOMEBREW_ARTIFACT_DOMAIN itself: it swaps "https://ghcr.io" for the
//     artifact domain and requests the registry-native paths
//
//     GET /v2/{repo}/manifests/{reference}     image index (mutable; served live)
//     GET /v2/{repo}/blobs/sha256:{digest}     bottle (immutable; cached, verified)
//
//     These carry no formula version, so the backend learns it from the image
//     index the client fetches along with the bottle (see manifest.go).
//
//   - A consumer of the unsigned formula JSON follows the bottle URLs the
//     backend rewrote in that document to its own synthetic bottle endpoint,
//     which carries the formula name and version ahead of the verbatim OCI blob
//     path:
//
//     GET /bottle/{name}/{version}/v2/{repo}/blobs/sha256:{digest}
//
// Either way the blob is immutable and content-addressed, hence cacheable (both
// forms share one digest-scoped cache entry); metadata and manifests are mutable
// and revalidated live.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the coordinate that feeds the admission gates and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Homebrew path can address.
type resourceKind int

const (
	// kindIndex is the full formula index "/api/formula.json" (mutable; bottle
	// URLs are rewritten through the proxy).
	kindIndex resourceKind = iota
	// kindFormula is one formula's metadata "/api/formula/{name}.json" (mutable;
	// bottle URLs are rewritten through the proxy).
	kindFormula
	// kindMetadata is any other formulae.brew.sh document (cask indexes, the
	// JWS-signed variants, analytics) proxied byte-exact (mutable, revalidated).
	kindMetadata
	// kindBottle is a bottle OCI blob download (immutable, cached, verified
	// against the sha256 content address named in its URL).
	kindBottle
	// kindManifest is an OCI manifest or image index on the bottle registry,
	// requested on the registry-native path (mutable for a tag; served live).
	kindManifest
)

// bottlePrefix is the proxy's synthetic bottle endpoint, relative to a backend
// mount.
const bottlePrefix = "bottle/"

// OCI distribution path markers: the first segment of every registry path, and
// the segments that precede a blob's digest and a manifest's reference.
const (
	ociAPIPrefix      = "v2"
	ociBlobMarker     = "blobs"
	ociManifestMarker = "manifests"
)

// Bounds on a registry-native repository path. A Homebrew bottle repository is
// "{org}/{tap}/{image}", where the image is the formula name with "@" encoded
// as "/" (so at most two segments): "homebrew/core/hello",
// "homebrew/core/openssl/3". Anything shallower or deeper is not a bottle
// repository, which keeps the endpoint from relaying the registry's unrelated
// two-segment container images.
const (
	minRepoSegments = 3
	maxRepoSegments = 4
	// maxRepoSegmentLen bounds one repository path component.
	maxRepoSegmentLen = 128
	// maxReferenceLen is the OCI limit on a tag's length.
	maxReferenceLen = 128
)

// resource is the parsed classification of an inbound Homebrew request path.
type resource struct {
	kind resourceKind
	// name is the formula name (kindFormula, kindBottle, kindManifest). On a
	// registry-native path it is derived from the repository (see name.go) and
	// may be refined from upstream metadata during resolution.
	name string
	// version is the bottle's formula version (kindBottle). It is empty on a
	// registry-native path, whose URL names no version; Resolve fills it in.
	version string
	// blobPath is the OCI blob path for a bottle, e.g.
	// "v2/homebrew/core/wget/blobs/sha256:<hex>". Fetch joins it to the bottle
	// registry base to recover the exact upstream blob URL.
	blobPath string
	// repo is the OCI repository a bottle blob or manifest lives in, e.g.
	// "homebrew/core/wget" — the scope for the ghcr bearer-token handshake.
	repo string
	// digest is the lowercase hex SHA-256 the bottle is verified against.
	digest string
	// reference is a manifest's tag or canonical "sha256:<hex>" digest
	// (kindManifest).
	reference string
	// registryNative reports that the request used the registry-native "/v2/..."
	// layout rather than the synthetic "/bottle/..." endpoint.
	registryNative bool
}

// classify parses an inbound path into a resource. It returns ok=false for
// paths that cannot be expressed in the Homebrew layout, so an unrecognized
// request is reported as unsupported rather than blindly proxied.
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

	switch segs[0] {
	case "bottle":
		return classifyBottle(segs[1:])
	case ociAPIPrefix:
		return classifyRegistry(segs[1:])
	case "api":
		return classifyAPI(segs)
	default:
		return resource{}, false
	}
}

// classifyAPI parses a formulae.brew.sh "/api/..." path (segs[0] == "api").
// Only the two unsigned formula documents are rewritten; everything else —
// notably the JWS-signed indexes the real brew client consumes, whose payload
// must reach the client byte-exact for its signature to verify — is passed
// through untouched.
func classifyAPI(segs []string) (resource, bool) {
	switch {
	case len(segs) == 2 && segs[1] == "formula.json":
		return resource{kind: kindIndex}, true
	case len(segs) == 3 && segs[1] == "formula" && strings.HasSuffix(segs[2], ".json") &&
		!strings.HasSuffix(segs[2], ".jws.json"):
		name := strings.TrimSuffix(segs[2], ".json")
		if name == "" {
			return resource{}, false
		}
		return resource{kind: kindFormula, name: name}, true
	default:
		// Casks, JWS-signed variants, and any other /api/... document are proxied
		// verbatim (no bottle-URL rewriting, so no need to parse them).
		return resource{kind: kindMetadata}, true
	}
}

// classifyBottle parses the segments that follow the "bottle/" prefix:
//
//	{name}/{version}/v2/{repo...}/blobs/sha256:{hex}
//
// It extracts the formula coordinate, the verbatim OCI blob path, the OCI
// repository (the bearer-token scope), and the content-address digest.
func classifyBottle(segs []string) (resource, bool) {
	// Need at least: name, version, "v2", one repo segment, "blobs", digest.
	if len(segs) < 6 {
		return resource{}, false
	}
	name, version := segs[0], segs[1]
	if name == "" || version == "" {
		return resource{}, false
	}
	blob := segs[2:]
	if blob[0] != ociAPIPrefix {
		return resource{}, false
	}
	if blob[len(blob)-2] != ociBlobMarker {
		return resource{}, false
	}
	digest, ok := parseSHA256Ref(blob[len(blob)-1])
	if !ok {
		return resource{}, false
	}
	repo := strings.Join(blob[1:len(blob)-2], "/")
	if repo == "" {
		return resource{}, false
	}
	return resource{
		kind:     kindBottle,
		name:     name,
		version:  version,
		blobPath: strings.Join(blob, "/"),
		repo:     repo,
		digest:   digest,
	}, true
}

// classifyRegistry parses the segments that follow the "v2/" prefix of a
// registry-native path — the form the real brew client builds by replacing
// "https://ghcr.io" with HOMEBREW_ARTIFACT_DOMAIN:
//
//	{org}/{tap}/{image...}/manifests/{reference}
//	{org}/{tap}/{image...}/blobs/sha256:{hex}
//
// Validation is deliberately strict, because every accepted component is joined
// into the upstream registry URL and the bearer-token scope: the repository must
// be a well-formed bottle repository (see validRepo), a manifest reference an
// OCI tag or sha256 digest, and a blob reference a sha256 digest. Nothing else
// under "/v2/" (the API-version probe, tag listings, uploads, referrers) is
// served.
func classifyRegistry(segs []string) (resource, bool) {
	// Need at least: the repository, a marker, and a reference.
	if len(segs) < minRepoSegments+2 {
		return resource{}, false
	}
	repoSegs := segs[:len(segs)-2]
	marker, ref := segs[len(segs)-2], segs[len(segs)-1]
	if !validRepo(repoSegs) {
		return resource{}, false
	}
	repo := strings.Join(repoSegs, "/")
	tap, image := splitRepo(repo)
	name := pathFormulaName(tap, image)

	switch marker {
	case ociManifestMarker:
		reference, ok := parseManifestReference(ref)
		if !ok {
			return resource{}, false
		}
		return resource{
			kind:           kindManifest,
			name:           name,
			repo:           repo,
			reference:      reference,
			registryNative: true,
		}, true
	case ociBlobMarker:
		digest, ok := parseSHA256Ref(ref)
		if !ok {
			return resource{}, false
		}
		return resource{
			kind: kindBottle,
			name: name,
			// The canonical (lowercase-digest) blob path, rebuilt from validated
			// components rather than echoed from the request.
			blobPath:       ociAPIPrefix + "/" + repo + "/" + ociBlobMarker + "/sha256:" + digest,
			repo:           repo,
			digest:         digest,
			registryNative: true,
		}, true
	default:
		return resource{}, false
	}
}

// validRepo reports whether segs form a bottle repository path:
// "{org}/{tap}/{image}" with a one- or two-segment image, every component a
// lowercase OCI repository path component.
func validRepo(segs []string) bool {
	if len(segs) < minRepoSegments || len(segs) > maxRepoSegments {
		return false
	}
	for _, s := range segs {
		if !validRepoSegment(s) {
			return false
		}
	}
	return true
}

// validRepoSegment reports whether s is an acceptable repository path
// component: lowercase alphanumerics, optionally separated by ".", "_" or "-",
// starting and ending with an alphanumeric. This is the OCI distribution
// grammar's alphabet (which Homebrew's image names — a formula name with "@"
// mapped to "/" and "+" to "x" — stay within), and it excludes every character
// with a meaning in a URL ("%", "?", "#", ":", "@", "\"), uppercase, and the
// "." / ".." traversal segments.
func validRepoSegment(s string) bool {
	if s == "" || len(s) > maxRepoSegmentLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// parseManifestReference validates a manifest reference and returns its
// canonical form: a "sha256:<hex>" digest (lowercased) or an OCI tag, verbatim.
// The tag grammar is the one brew itself enforces on a bottle's version tag
// (GitHubPackages::VALID_OCI_TAG_REGEX).
func parseManifestReference(ref string) (string, bool) {
	if digest, ok := parseSHA256Ref(ref); ok {
		return "sha256:" + digest, true
	}
	if !validOCITag(ref) {
		return "", false
	}
	return ref, true
}

// validOCITag reports whether s matches the OCI tag grammar
// [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}.
func validOCITag(s string) bool {
	if s == "" || len(s) > maxReferenceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case c == '.' || c == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// parseSHA256Ref parses an OCI "sha256:<hex>" blob reference into its lowercase
// hex digest, rejecting any other algorithm or a malformed value.
func parseSHA256Ref(ref string) (hexDigest string, ok bool) {
	const prefix = "sha256:"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	h := strings.ToLower(ref[len(prefix):])
	if len(h) != sha256HexLen || !isHex(h) {
		return "", false
	}
	return h, true
}

// cacheable reports whether the resource may be cached. Only a bottle blob is
// immutable and content-addressed; the metadata documents and manifests are
// mutable and revalidated live.
func (r resource) cacheable() bool { return r.kind == kindBottle }

// isBottle reports whether the resource is a bottle blob download.
func (r resource) isBottle() bool { return r.kind == kindBottle }

// rewrites reports whether the resource is a formula document whose bottle URLs
// the backend rewrites through the proxy.
func (r resource) rewrites() bool { return r.kind == kindIndex || r.kind == kindFormula }

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindIndex:
		return "index"
	case kindFormula:
		return "formula"
	case kindMetadata:
		return "metadata"
	case kindBottle:
		return "bottle"
	case kindManifest:
		return "manifest"
	default:
		return "other"
	}
}
