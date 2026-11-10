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
	refOther             // other v2 endpoints (e.g. /v2/<name>/tags/list)
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
// prefix already stripped). It returns ok=false when the path is not a v2 API
// path at all. The repository name may contain slashes, so manifest/blob and
// referrers paths are split on the last "/manifests/", "/blobs/", or
// "/referrers/" separator; the trailing reference must be a single path segment
// (which rules out push-only paths such as "/blobs/uploads/<uuid>").
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

	// Other v2 endpoints. Recover the repository name for tag listings so the
	// token handshake can request the right scope.
	r := reference{kind: refOther}
	if name := strings.TrimSuffix(rest, "/tags/list"); name != rest && name != "" {
		r.name = name
	}
	return r, true
}
