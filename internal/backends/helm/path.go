package helm

import (
	"path"
	"strings"
)

// The classic Helm chart-repository protocol addresses three families of
// resource off the repository root (the route prefix "/v1/<name>" is stripped
// before classification):
//
//	Repository index (mutable, revalidated, parsed for chart digests):
//	  GET /index.yaml
//
//	Chart archives (immutable, content-addressed, SHA-256-verified):
//	  GET /<name>-<version>.tgz            the packaged chart itself
//	  GET /<sub>/.../<name>-<version>.tgz  charts may be served under a subpath
//	                                       (the index's urls are honored verbatim)
//
//	Provenance (immutable, cached, served as-is; presence feeds the gates):
//	  GET /<name>-<version>.tgz.prov       detached PGP provenance signature
//
// Classification derives the chart coordinate (name + version) from the archive
// basename so it can feed nameguard, the vulnerability/license/signature gates,
// provenance, and the risk engine, and decides cacheability: only the immutable
// per-version artifacts (.tgz and .tgz.prov) are cached; the index is revalidated
// live.

// resourceKind enumerates the classes of resource a classic Helm path can
// address.
type resourceKind int

const (
	// kindChart is a packaged chart .tgz: immutable, cached, and SHA-256-verified
	// against the digest in the repository index.
	kindChart resourceKind = iota
	// kindProvenance is a chart's detached provenance signature (.tgz.prov):
	// immutable and cached, served as-is, its presence recorded for the gates.
	kindProvenance
	// kindIndex is the repository index.yaml: mutable, revalidated, and parsed to
	// recover per-chart digests.
	kindIndex
	// kindOther is any path that does not match a known Helm resource (served
	// live, uncached, with no coordinate).
	kindOther
)

// resource is the parsed classification of an inbound classic Helm request path.
type resource struct {
	kind resourceKind
	// name is the chart name, for kindChart/kindProvenance. Empty otherwise.
	name string
	// version is the chart version, for kindChart/kindProvenance.
	version string
	// filename is the .tgz basename (without any ".prov" suffix), used to recover
	// the digest from the index authoritatively.
	filename string
}

const (
	indexFile = "index.yaml"
	chartExt  = ".tgz"
	provExt   = ".prov"
)

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that cannot be
// expressed in the classic Helm chart-repository layout.
func classify(p string) (resource, bool) {
	clean := strings.Trim(p, "/")
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

	last := segs[len(segs)-1]

	if last == indexFile {
		return resource{kind: kindIndex}, true
	}

	// Provenance sidecar: "<name>-<version>.tgz.prov".
	if strings.HasSuffix(last, chartExt+provExt) {
		base := strings.TrimSuffix(last, provExt)
		name, version, ok := splitChartFilename(base)
		if !ok {
			return resource{}, false
		}
		return resource{kind: kindProvenance, name: name, version: version, filename: base}, true
	}

	// Chart archive: "<name>-<version>.tgz".
	if strings.HasSuffix(last, chartExt) {
		name, version, ok := splitChartFilename(last)
		if !ok {
			return resource{}, false
		}
		return resource{kind: kindChart, name: name, version: version, filename: last}, true
	}

	return resource{}, false
}

// splitChartFilename splits a chart archive basename ("<name>-<version>.tgz")
// into its chart name and version. A Helm chart version is SemVer and so begins
// with a digit; the split is the first hyphen that is immediately followed by a
// digit. Everything before it is the chart name, everything after (up to the
// ".tgz") is the version. This is a heuristic — a chart name may itself contain
// "<word>-<digit>" — so the backend treats the index's per-URL match as
// authoritative and uses this split only as a coordinate hint and fallback.
//
// It returns ok=false when the basename does not end in ".tgz" or carries no
// version token (no hyphen-then-digit), so a malformed filename is rejected.
func splitChartFilename(filename string) (name, version string, ok bool) {
	base := strings.TrimSuffix(path.Base(filename), chartExt)
	if base == filename || base == "" {
		// No ".tgz" suffix was trimmed, or nothing remained.
		return "", "", false
	}
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

// coordinateName returns the chart name as the coordinate for the admission
// gates.
func (r resource) coordinateName() string { return r.name }

// verifiableArtifact reports whether the resource is a chart .tgz whose content
// the backend should checksum-verify against the index digest.
func (r resource) verifiableArtifact() bool { return r.kind == kindChart }

// cacheable reports whether the resource may be cached. Only the immutable
// per-version artifacts are cached; the index is revalidated.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindChart, kindProvenance:
		return true
	default:
		return false
	}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindChart:
		return "chart"
	case kindProvenance:
		return "provenance"
	case kindIndex:
		return "index"
	default:
		return "other"
	}
}
