package composer

import "strings"

// The Composer/Packagist pull-through backend understands four families of
// request, all addressed off the repository root (the route prefix "/v1/<name>"
// is stripped before classification):
//
//	Repository root (mutable):
//	  GET /packages.json                         advertises the metadata-url template.
//
//	v2 package metadata (mutable, parsed for dist shasums + licenses):
//	  GET /p2/<vendor>/<package>.json            release versions.
//	  GET /p2/<vendor>/<package>~dev.json        dev (branch) versions.
//
//	v1 provider metadata (mutable, legacy mirrors; served live):
//	  GET /p/<vendor>/<package>.json
//	  GET /p/<vendor>/<package>$<sha256>.json
//
//	Dist archives (immutable, reference-addressed, SHA-1-verified):
//	  GET /dist/<vendor>/<package>/<reference>.<ext>
//
// The dist path is the proxy's own stable, content-addressed locator for a
// version's distributable archive. Because the real upstream download URL and the
// verification shasum both live in the package's v2 metadata, the backend resolves
// a dist request by fetching that metadata, locating the version whose dist
// reference matches, and verifying the streamed archive against the declared
// SHA-1 — analogous to the Maven backend fetching a checksum sidecar.

// resourceKind enumerates the classes of resource a Composer path can address.
type resourceKind int

const (
	// kindDist is a distributable archive: immutable, cached, SHA-1-verified
	// against the shasum in the package's v2 metadata.
	kindDist resourceKind = iota
	// kindRoot is the packages.json repository root: mutable, revalidated.
	kindRoot
	// kindMetadata is a /p2/<vendor>/<package>.json v2 metadata document: mutable,
	// revalidated, and parsed to recover dist shasums and licenses.
	kindMetadata
	// kindProviderV1 is a legacy /p/<vendor>/<package>.json provider document:
	// mutable, served live (not parsed for verification).
	kindProviderV1
	// kindOther is any path that does not match a known Composer resource (served
	// live, uncached, with no coordinate).
	kindOther
)

// resource is the parsed classification of an inbound Composer request path.
type resource struct {
	kind resourceKind
	// vendor and pkg are the package coordinate halves, for
	// kindMetadata/kindProviderV1/kindDist.
	vendor string
	pkg    string
	// reference is the dist source reference (for kindDist), used to look up the
	// matching version's download URL and shasum in the v2 metadata.
	reference string
	// ext is the dist archive extension without a leading dot (for kindDist).
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

	// Dist archive: /dist/<vendor>/<package>/<reference>.<ext>.
	if len(segs) == 4 && segs[0] == "dist" {
		vendor, pkg, file := segs[1], segs[2], segs[3]
		dot := strings.LastIndexByte(file, '.')
		if dot <= 0 {
			return resource{}, false
		}
		reference := file[:dot]
		ext := file[dot+1:]
		if !validNamePart(vendor) || !validNamePart(pkg) || reference == "" || ext == "" {
			return resource{}, false
		}
		return resource{kind: kindDist, vendor: vendor, pkg: pkg, reference: reference, ext: ext}, true
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

// coordinateName returns the "vendor/package" coordinate for the admission gates,
// or "" when the resource addresses no single package.
func (r resource) coordinateName() string {
	if r.vendor == "" || r.pkg == "" {
		return ""
	}
	return r.vendor + "/" + r.pkg
}

// verifiableArtifact reports whether the resource is a dist archive whose content
// the backend should checksum-verify.
func (r resource) verifiableArtifact() bool { return r.kind == kindDist }

// cacheable reports whether the resource may be cached. Only the immutable,
// reference-addressed dist archives are cached; every metadata document is
// revalidated live.
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
	default:
		return "other"
	}
}
