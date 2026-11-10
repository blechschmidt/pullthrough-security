package rubygems

import "strings"

// The RubyGems pull-through backend understands three families of request, all
// addressed off the gem-server root (the route prefix "/v1/<name>" is stripped
// before classification):
//
//	Compact index (the modern Bundler protocol):
//	  GET /versions                     full gem→versions index (mutable)
//	  GET /names                        list of all gem names (mutable)
//	  GET /info/<gem>                   per-gem versions + checksums (mutable)
//
//	Gem fetches (immutable, content-addressed, checksum-verified):
//	  GET /gems/<name>-<version>.gem    the gem package itself
//	  GET /quick/Marshal.4.8/<name>-<version>.gemspec.rz
//	                                    legacy per-version Marshal gemspec
//
//	Legacy Marshal / dependency API (mutable index documents):
//	  GET /specs.4.8.gz                 full spec index (Marshal, gzipped)
//	  GET /latest_specs.4.8.gz          latest-only spec index
//	  GET /prerelease_specs.4.8.gz      prerelease spec index
//	  GET /api/v1/dependencies          runtime dependency resolver (Marshal)
//
// Classification derives the gem coordinate (name + version) where one is present
// so it can feed nameguard, the vulnerability/license gates, and provenance, and
// decides cacheability: only the immutable per-version artifacts (.gem and the
// Marshal gemspec) are cached; every index/listing document is revalidated live.

// resourceKind enumerates the classes of resource a RubyGems path can address.
type resourceKind int

const (
	// kindGem is a .gem package: immutable, cached, and SHA-256-verified against
	// the checksum in the gem's /info document.
	kindGem resourceKind = iota
	// kindQuickSpec is a legacy /quick/Marshal.4.8/<name>-<version>.gemspec.rz
	// document: per-version and immutable, so cached, but served as-is (the
	// compact index, not this Marshal blob, is the checksum source).
	kindQuickSpec
	// kindInfo is a compact-index /info/<gem> document: mutable, revalidated, and
	// parsed to recover per-version checksums.
	kindInfo
	// kindIndex is a compact-index /versions or /names document: mutable.
	kindIndex
	// kindLegacyIndex is a Marshal spec index (/specs.4.8.gz and friends): mutable.
	kindLegacyIndex
	// kindDependencyAPI is the legacy /api/v1/dependencies resolver: mutable.
	kindDependencyAPI
	// kindOther is any path that does not match a known RubyGems resource (served
	// live, uncached, with no coordinate).
	kindOther
)

// resource is the parsed classification of an inbound RubyGems request path.
type resource struct {
	kind resourceKind
	// name is the gem name, for kindGem/kindQuickSpec/kindInfo. Empty otherwise.
	name string
	// version is the version token (with optional platform suffix), for
	// kindGem/kindQuickSpec.
	version string
}

const (
	gemExt       = ".gem"
	gemspecRzExt = ".gemspec.rz"
	quickPrefix  = "quick/Marshal.4.8/"
)

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that cannot be
// expressed in the RubyGems layout.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from the cleaned path, so every segment must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	switch {
	case clean == "versions" || clean == "names":
		return resource{kind: kindIndex}, true
	case clean == "specs.4.8.gz" || clean == "latest_specs.4.8.gz" || clean == "prerelease_specs.4.8.gz":
		return resource{kind: kindLegacyIndex}, true
	case clean == "api/v1/dependencies":
		return resource{kind: kindDependencyAPI}, true
	}

	// Compact-index per-gem document: /info/<gem>.
	if len(segs) == 2 && segs[0] == "info" {
		return resource{kind: kindInfo, name: segs[1]}, true
	}

	// Gem package: /gems/<name>-<version>.gem.
	if len(segs) == 2 && segs[0] == "gems" && strings.HasSuffix(segs[1], gemExt) {
		base := strings.TrimSuffix(segs[1], gemExt)
		if name, version, ok := splitNameVersion(base); ok {
			return resource{kind: kindGem, name: name, version: version}, true
		}
		return resource{}, false
	}

	// Legacy Marshal gemspec: /quick/Marshal.4.8/<name>-<version>.gemspec.rz.
	if strings.HasPrefix(clean, quickPrefix) && strings.HasSuffix(clean, gemspecRzExt) {
		file := strings.TrimPrefix(clean, quickPrefix)
		// The filename must be a single path segment under the quick directory.
		if strings.Contains(file, "/") {
			return resource{}, false
		}
		base := strings.TrimSuffix(file, gemspecRzExt)
		if name, version, ok := splitNameVersion(base); ok {
			return resource{kind: kindQuickSpec, name: name, version: version}, true
		}
		return resource{}, false
	}

	return resource{}, false
}

// splitNameVersion splits a gem artifact basename ("<name>-<version>[-<platform>]")
// into its gem name and version token. A RubyGems version must begin with a
// digit, so the split is the first hyphen that is immediately followed by a
// digit: everything before it is the name, everything after (including any
// platform suffix such as "-x86_64-linux") is the version token. This matches the
// version key used in the compact-index /info document, so the recovered token can
// be looked up there to find the verification checksum.
//
// It returns ok=false when no version token is present (no hyphen-then-digit), so
// a bare or malformed filename is rejected rather than mis-split.
func splitNameVersion(base string) (name, version string, ok bool) {
	for i := 0; i+1 < len(base); i++ {
		if base[i] != '-' {
			continue
		}
		if c := base[i+1]; c >= '0' && c <= '9' {
			name = base[:i]
			version = base[i+1:]
			if name == "" || version == "" {
				return "", "", false
			}
			return name, version, true
		}
	}
	return "", "", false
}

// coordinateName returns the gem name as the coordinate for the admission gates.
func (r resource) coordinateName() string { return r.name }

// verifiableArtifact reports whether the resource is a .gem whose content the
// backend should checksum-verify against the compact-index checksum.
func (r resource) verifiableArtifact() bool { return r.kind == kindGem }

// cacheable reports whether the resource may be cached. Only the immutable
// per-version artifacts are cached; every index/listing document is revalidated.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindGem, kindQuickSpec:
		return true
	default:
		return false
	}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindGem:
		return "gem"
	case kindQuickSpec:
		return "gemspec"
	case kindInfo:
		return "info"
	case kindIndex:
		return "index"
	case kindLegacyIndex:
		return "legacy-index"
	case kindDependencyAPI:
		return "dependency-api"
	default:
		return "other"
	}
}
