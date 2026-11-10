package homebrew

import "strings"

// Homebrew distributes two things the proxy fronts, from two different
// upstreams:
//
//   - Formula metadata, from the formulae.brew.sh JSON API. The full index and
//     the per-formula documents enumerate, for each formula, a "bottle" — a
//     precompiled binary tarball — with its download URL and SHA-256:
//
//     GET /api/formula.json            full formula index (mutable; URLs rewritten)
//     GET /api/formula/{name}.json     one formula's metadata (mutable; URLs rewritten)
//     GET /api/cask.json, /api/...     other metadata (mutable, proxied as-is)
//
//   - Bottle tarballs, which Homebrew now stores as OCI blobs in GitHub Packages
//     (ghcr.io). A bottle's download URL in the formula metadata is a content-
//     addressed OCI blob reference:
//
//     https://ghcr.io/v2/{repo}/blobs/sha256:{digest}
//
//     The backend rewrites each such URL in the served metadata to its own
//     synthetic bottle endpoint so the client's download flows back through the
//     proxy (where it is cached, verified against the sha256 content address,
//     and gated):
//
//     GET /bottle/{name}/{version}/v2/{repo}/blobs/sha256:{digest}
//
// The synthetic bottle path carries the formula name and version (so the
// admission gates see a concrete coordinate) ahead of the verbatim OCI blob
// path (so Fetch can reconstruct the exact upstream blob URL). The blob is
// immutable and content-addressed, hence cacheable; metadata is mutable and
// revalidated live.
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
)

// bottlePrefix is the proxy's synthetic bottle endpoint, relative to a backend
// mount.
const bottlePrefix = "bottle/"

// ociBlobMarker is the path segment that precedes a blob's digest in an OCI
// distribution blob reference.
const ociBlobMarker = "blobs"

// resource is the parsed classification of an inbound Homebrew request path.
type resource struct {
	kind resourceKind
	// name is the formula name (kindFormula, kindBottle).
	name string
	// version is the bottle's formula version (kindBottle).
	version string
	// blobPath is the verbatim OCI blob path for a bottle, e.g.
	// "v2/homebrew/core/wget/blobs/sha256:<hex>". Fetch joins it to the bottle
	// registry base to recover the exact upstream blob URL.
	blobPath string
	// repo is the OCI repository a bottle blob lives in, e.g.
	// "homebrew/core/wget" — the scope for the ghcr bearer-token handshake.
	repo string
	// digest is the lowercase hex SHA-256 the bottle is verified against.
	digest string
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

	if segs[0] == "bottle" {
		return classifyBottle(segs[1:])
	}
	if segs[0] != "api" {
		return resource{}, false
	}
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
	if blob[0] != "v2" {
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
// immutable and content-addressed; the metadata documents are mutable and
// revalidated live.
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
	default:
		return "other"
	}
}
