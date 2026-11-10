package bazel

import "strings"

// The Bazel Central Registry (https://bcr.bazel.build) and every Bzlmod-format
// registry (self-hosted or a private BCR mirror) share one static HTTP layout,
// which the proxy mounts at its registry root ("<publicBase>/v1/<name>"):
//
//	/bazel_registry.json                             registry config      (mutable, live)
//	/modules/<name>/metadata.json                    module metadata      (mutable, live)
//	/modules/<name>/<version>/MODULE.bazel           module file          (immutable, cacheable)
//	/modules/<name>/<version>/source.json            source descriptor    (immutable; rewritten, live)
//	/modules/<name>/<version>/patches/<file>         module patch         (immutable, cacheable)
//	/modules/<name>/<version>/archive                source archive        (proxy-synthetic, verified, cacheable)
//
// source.json names the external source archive the module is built from,
// together with its Subresource-Integrity ("integrity") digest:
//
//	{"url": "https://github.com/.../archive/refs/tags/v1.0.0.tar.gz",
//	 "integrity": "sha256-...", "strip_prefix": "...", "patches": {...}, "patch_strip": 1}
//
// The archive lives at an arbitrary external URL, not under the registry. To
// bring archive fetches through the proxy (so they are cached and integrity-
// verified) the backend rewrites source.json's "url"/"urls" to a proxy-synthetic
// "/modules/<name>/<version>/archive" endpoint (see source.go). A request to
// that endpoint re-reads the module's source.json, resolves the real external
// URL and the expected integrity, fetches the archive, and verifies the fetched
// bytes against the SRI digest before they are cached or served (see bazel.go /
// integrity.go). This mirrors the proxy-synthetic artifact endpoints the
// Terraform and Dart backends use for externally-hosted archives.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the module coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Bazel registry path can
// address.
type resourceKind int

const (
	// kindRegistry is the registry-root bazel_registry.json config. Mutable, live.
	kindRegistry resourceKind = iota
	// kindMetadata is a module's metadata.json (its version list and maintainer
	// info). Mutable (versions are appended), served live.
	kindMetadata
	// kindModuleBazel is a module version's MODULE.bazel. Immutable, cacheable.
	kindModuleBazel
	// kindSource is a module version's source.json. Immutable upstream, but
	// rewritten on the fly to route archive fetches through the proxy, so it is
	// served live rather than cached.
	kindSource
	// kindPatch is a module version's patch file. Immutable, cacheable.
	kindPatch
	// kindArchive is the proxy-synthetic source-archive endpoint for a module
	// version: on fetch the backend reads source.json, fetches the external
	// archive, and verifies it against the declared SRI integrity. Immutable,
	// cacheable.
	kindArchive
)

// sourceFile is the per-version descriptor the backend consults to resolve an
// archive's external URL and integrity.
const sourceFile = "source.json"

// archiveEndpoint is the final path segment of the proxy-synthetic archive
// endpoint. It is not a real BCR file; source.json's "url" is rewritten to point
// at it so archive fetches flow through (and are verified by) the proxy.
const archiveEndpoint = "archive"

// resource is the parsed classification of an inbound Bazel registry request.
type resource struct {
	kind resourceKind
	// name/version form the module coordinate. name is empty for the registry
	// config; version is empty for metadata.json.
	name    string
	version string
	// filename is the final path component (the metadata/source/patch file).
	filename string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Bazel registry layout, so an unrecognized request is
// reported as unsupported rather than blindly proxied.
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

	// Registry-root config.
	if len(segs) == 1 && segs[0] == "bazel_registry.json" {
		return resource{kind: kindRegistry, filename: segs[0]}, true
	}

	// Everything else lives under /modules/<name>/...
	if segs[0] != "modules" || len(segs) < 3 {
		return resource{}, false
	}
	name := segs[1]
	if !isModuleName(name) {
		return resource{}, false
	}

	// /modules/<name>/metadata.json
	if len(segs) == 3 {
		if segs[2] != "metadata.json" {
			return resource{}, false
		}
		return resource{kind: kindMetadata, name: name, filename: segs[2]}, true
	}

	// /modules/<name>/<version>/...
	version := segs[2]
	if !isModuleVersion(version) {
		return resource{}, false
	}
	rest := segs[3:]
	switch {
	case len(rest) == 1 && rest[0] == "MODULE.bazel":
		return resource{kind: kindModuleBazel, name: name, version: version, filename: rest[0]}, true
	case len(rest) == 1 && rest[0] == sourceFile:
		return resource{kind: kindSource, name: name, version: version, filename: rest[0]}, true
	case len(rest) == 1 && rest[0] == archiveEndpoint:
		return resource{kind: kindArchive, name: name, version: version, filename: rest[0]}, true
	case len(rest) == 2 && rest[0] == "patches":
		if !isPatchFile(rest[1]) {
			return resource{}, false
		}
		return resource{kind: kindPatch, name: name, version: version, filename: rest[1]}, true
	default:
		return resource{}, false
	}
}

// isModuleName reports whether s is a valid Bzlmod module name. Bazel module
// names are lowercase and start with a letter, followed by letters, digits, and
// the separators '.', '_', '-'. Restricting to this charset keeps an arbitrary
// directory name from being mistaken for a module and keeps the segment inert in
// the synthesized upstream URL.
func isModuleName(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// isModuleVersion reports whether s is a plausible Bazel module version. Bazel
// versions are fairly permissive (e.g. "1.0.0", "0.0.10", "1.2.3.bcr.1",
// "20230802.0"); the charset is restricted to the characters those versions use
// so the segment stays inert in the upstream URL.
func isModuleVersion(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '+':
		default:
			return false
		}
	}
	return true
}

// isPatchFile reports whether name is an acceptable patch filename: a plain file
// name (no nested path) ending in .patch or .diff.
func isPatchFile(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return false
	}
	return strings.HasSuffix(name, ".patch") || strings.HasSuffix(name, ".diff")
}

// cacheable reports whether the resource may be cached. The immutable per-version
// files (MODULE.bazel, patches) and the proxy-synthetic archive are content-
// addressable; the registry config, module metadata, and the (rewritten)
// source.json are mutable/live and revalidated rather than cached.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindModuleBazel, kindPatch, kindArchive:
		return true
	default:
		return false
	}
}

// verifiableArchive reports whether the resource is the synthetic archive
// endpoint the backend verifies against source.json's integrity.
func (r resource) verifiableArchive() bool {
	return r.kind == kindArchive
}

// coordinateName returns the module name used to address the artifact in the
// admission gates. Empty for the registry config.
func (r resource) coordinateName() string {
	return r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindRegistry:
		return "registry"
	case kindMetadata:
		return "metadata"
	case kindModuleBazel:
		return "module-bazel"
	case kindSource:
		return "source"
	case kindPatch:
		return "patch"
	case kindArchive:
		return "archive"
	default:
		return "other"
	}
}
