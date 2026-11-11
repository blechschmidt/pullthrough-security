package docker

import "strings"

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
		return reference{
			kind:      sep.kind,
			name:      name,
			reference: ref,
			isDigest:  IsDigest(ref),
		}, true
	}

	// The remaining read endpoints of the distribution API: the registry catalog
	// and a repository's tag list (whose repository name is recovered so the token
	// handshake requests the right scope).
	if rest == "_catalog" {
		return reference{kind: refOther}, true
	}
	if name := strings.TrimSuffix(rest, "/tags/list"); name != rest && name != "" {
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
