package docker

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// refKind classifies a Registry v2 request path.
type refKind int

const (
	refUnknown   refKind = iota
	refPing              // /v2/ — API version / auth probe
	refManifest          // /v2/<name>/manifests/<reference>
	refBlob              // /v2/<name>/blobs/<digest>
	refReferrers         // /v2/<name>/referrers/<digest> (OCI Distribution v1.1 Referrers API)
	refOther             // the read-only listings: /v2/_catalog and /v2/<name>/tags/list
)

// reference is a parsed Registry v2 request.
type reference struct {
	kind      refKind
	name      string // repository name, e.g. "library/nginx" (may contain slashes)
	reference string // tag or digest for manifests; digest for blobs
	isDigest  bool   // whether reference is a content digest (vs. a tag)
}

// scope returns the bearer-token scope for the request, e.g.
// "repository:library/nginx:pull", or "" when no repository scope applies.
func (r reference) scope() string {
	if r.name == "" {
		return ""
	}
	return "repository:" + r.name + ":pull"
}

// artifact classifies the request for the content gates (see
// backends.ArtifactClass).
//
// A manifest, by tag or by digest, is the root of the image a client is about to
// run, and a blob is that image's config or one of its layers. Both are
// payloads, and each carries the kind that tells a gate how to read it. The API
// version check, the catalog and a tag list are documents a client only reads.
//
// So is a Referrers API response, but only where the path really is one. The
// API is defined for a subject digest, while parseReference accepts any single
// segment after "/referrers/". A segment that is not a digest may be a dot
// segment ("/v2/<name>/blobs/<digest>/referrers/.."), and a registry resolves
// that path, or redirects it, to the blob or manifest in front of it: the bytes
// served under such a path are not known to be an index. It is left
// unclassified, and a gate judges it from its content.
func (r reference) artifact() backends.Artifact {
	switch r.kind {
	case refManifest:
		return backends.Artifact{Class: backends.ArtifactPayload, Kind: backends.KindOCIManifest}
	case refBlob:
		return backends.Artifact{Class: backends.ArtifactPayload, Kind: backends.KindOCIBlob}
	case refReferrers:
		if !r.isDigest {
			return backends.Artifact{}
		}
		return backends.Metadata()
	case refPing, refOther:
		return backends.Metadata()
	default:
		return backends.Artifact{}
	}
}

// parseReference parses a path of the Registry v2 API (with the backend route
// prefix already stripped). It returns ok=false when the path is not one of the
// read endpoints this backend serves. The repository name may contain slashes,
// so manifest/blob and referrers paths are split on the last "/manifests/",
// "/blobs/", or "/referrers/" separator; the trailing reference must be a single
// path segment (which rules out push-only paths such as "/blobs/uploads/<uuid>").
func parseReference(path string) (reference, bool) {
	p := strings.TrimPrefix(path, "/")
	if p == "v2" || p == "v2/" {
		return reference{kind: refPing}, true
	}
	if !strings.HasPrefix(p, "v2/") {
		return reference{}, false
	}
	rest := strings.TrimPrefix(p, "v2/")

	for _, sep := range []struct {
		token string
		kind  refKind
	}{
		{"/manifests/", refManifest},
		{"/blobs/", refBlob},
		{"/referrers/", refReferrers},
	} {
		i := strings.LastIndex(rest, sep.token)
		if i < 0 {
			continue
		}
		name := rest[:i]
		ref := rest[i+len(sep.token):]
		if name == "" || ref == "" || strings.Contains(ref, "/") {
			continue
		}
		// The path is forwarded to the registry, with the proxy's credentials. It
		// must therefore be the path it reads as: a reference that is a tag or a
		// digest, under a repository name without relative segments. Anything
		// else is refused here. "/v2/token/manifests/.." parses as the manifest
		// ".." of the repository "token" — and is "/v2/token" to the registry that
		// receives it, which is the token endpoint this parser exists to keep
		// clients away from.
		isDigest := IsDigest(ref)
		switch {
		case !validRepositoryName(name):
			return reference{}, false
		case sep.kind == refManifest && !isDigest && !validTag(ref):
			return reference{}, false
		case sep.kind != refManifest && !isDigest:
			// Blobs and referrers are addressed by digest and nothing else.
			return reference{}, false
		}
		return reference{
			kind:      sep.kind,
			name:      name,
			reference: ref,
			isDigest:  isDigest,
		}, true
	}

	// The remaining read endpoints of the distribution API: the registry catalog
	// and a repository's tag list (whose repository name is recovered so the token
	// handshake requests the right scope).
	if rest == "_catalog" {
		return reference{kind: refOther}, true
	}
	if name := strings.TrimSuffix(rest, "/tags/list"); name != rest && validRepositoryName(name) {
		return reference{kind: refOther, name: name}, true
	}

	// Everything else under /v2/ is refused rather than forwarded. The backend
	// answers an upstream's authentication challenge with the proxy's own
	// credentials, and several registries host their token endpoint under /v2/ on
	// the registry itself (Artifactory and Nexus "/v2/token", Quay "/v2/auth").
	// Forwarding an arbitrary /v2/ path therefore let a client ask that endpoint —
	// through the proxy, authenticated as the proxy — for a token of any scope it
	// liked, push and delete included, and read it from the relayed response.
	// Push-only paths ("/blobs/uploads/<uuid>") end up here as well.
	return reference{}, false
}

// maxTagLength is the longest tag the distribution specification allows.
const maxTagLength = 128

// validTag reports whether s is a tag by the distribution specification's
// grammar: [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}. A tag cannot begin with a dot, so
// neither "." nor ".." is one.
func validTag(s string) bool {
	if s == "" || len(s) > maxTagLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case (c == '.' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// validRepositoryName reports whether a repository name is safe to place in an
// upstream URL: non-empty path components, none of them a relative segment in
// any spelling (see backends.HasDotSegment), and no character that ends the
// path or does not belong in one.
//
// It is deliberately looser than the specification's grammar for a name
// (lowercase alphanumerics with single separators): registries differ in what
// they accept, and a name the upstream does not know is simply not found. What
// must not get through is a name that makes the upstream path a different path.
func validRepositoryName(name string) bool {
	if name == "" || backends.HasDotSegment(name) {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" {
			return false
		}
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c <= ' ', c == 0x7f, c == '\\', c == '?', c == '#', c == ';', c == '%':
			return false
		}
	}
	return true
}
