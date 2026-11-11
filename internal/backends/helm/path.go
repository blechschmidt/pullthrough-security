package helm

import (
	"path"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The classic Helm chart-repository protocol addresses three families of
// resource off the repository root (the route prefix "/v1/<name>" is stripped
// before classification):
//
//	Repository index (mutable, revalidated, parsed for chart digests):
//	  GET /index.yaml                      rewritten so every chart URL points
//	                                       back at this mount (see rewrite.go)
//
//	Chart archives (immutable, content-addressed, SHA-256-verified):
//	  GET /-/<chart>/<version>/<file>      index-resolved: the archive the
//	                                       repository index lists for that chart
//	                                       version, wherever it is hosted
//	  GET /<name>-<version>.tgz            repository-relative: the packaged chart
//	  GET /<sub>/.../<name>-<version>.tgz  fetched from the same path under the
//	                                       upstream base
//
//	Provenance (immutable, cached, served as-is; presence feeds the gates):
//	  GET /-/<chart>/<version>/<file>.prov
//	  GET /<name>-<version>.tgz.prov       detached PGP provenance signature
//
// The index-resolved form is what a rewritten index.yaml hands to clients. It
// names an index entry rather than a location: the chart name and version are
// explicit path segments (so the coordinate the admission gates see is the
// index's own, never a guess from a filename), and the upstream URL is looked up
// in the repository index when the archive is fetched. A request can therefore
// only ever reach a URL the upstream index lists for that chart version — the
// proxy is not an open relay — yet the archive may live on any host.
//
// The repository-relative form is the path a client derives from an index whose
// urls are relative; it predates the index rewrite and keeps working. There the
// coordinate is derived from the archive basename.
//
// Either way classification feeds the chart coordinate (name + version) to
// nameguard, the vulnerability/license/signature gates, provenance, and the risk
// engine, and decides cacheability: only the immutable per-version artifacts
// (archives and their .prov sidecars) are cached; the index is revalidated live.

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
	// filename is the archive basename (without any ".prov" suffix). For a
	// repository-relative path it recovers the digest from the index; for an
	// index-resolved path it selects which of the entry's listed URLs is meant.
	filename string
	// indexed marks the index-resolved form ("/-/<chart>/<version>/<file>"): the
	// upstream URL is not derived from the path but looked up in the repository
	// index at fetch time.
	indexed bool
	// root marks the repository's own index ("/index.yaml" directly under the
	// mount), the one document the backend rewrites. An index.yaml found deeper
	// in the tree is some other repository's and is proxied as-is.
	root bool
}

const (
	indexFile = "index.yaml"
	chartExt  = ".tgz"
	provExt   = ".prov"

	// indexedPrefix is the reserved first path segment of an index-resolved
	// archive URL. No chart repository serves a directory named "-", so it cannot
	// shadow a repository-relative path that works today (npm reserves the same
	// segment for its tarballs for the same reason).
	indexedPrefix = "-"

	// maxSegmentLen bounds a chart name, version, or archive filename carried in
	// an index-resolved URL. Real ones are a few dozen bytes; the cap keeps a
	// hostile index from minting absurd URLs and cache keys.
	maxSegmentLen = 255
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

	if segs[0] == indexedPrefix {
		return classifyIndexed(segs[1:])
	}

	last := segs[len(segs)-1]

	if last == indexFile {
		return resource{kind: kindIndex, root: len(segs) == 1}, true
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

// classifyIndexed parses the segments after the reserved "-" prefix of an
// index-resolved URL: exactly <chart>/<version>/<file>, where a trailing ".prov"
// on the file selects that archive's provenance sidecar. The chart name and
// version are taken verbatim — they are the repository index's own key and
// version, which the rewritten index put there — so no filename heuristic is
// involved. Every segment must be one the index rewrite could have emitted
// (addressable); anything else was not handed out by this backend.
func classifyIndexed(segs []string) (resource, bool) {
	if len(segs) != 3 {
		return resource{}, false
	}
	name, version, file := segs[0], segs[1], segs[2]
	kind := kindChart
	if strings.HasSuffix(file, provExt) {
		file = strings.TrimSuffix(file, provExt)
		kind = kindProvenance
	}
	if !addressable(name) || !addressable(version) || !addressable(file) {
		return resource{}, false
	}
	return resource{kind: kind, name: name, version: version, filename: file, indexed: true}, true
}

// addressable reports whether s can be carried as one path segment of an
// index-resolved URL and come back unchanged: non-empty, bounded, not a dot
// segment, free of path separators (a backslash is normalized to a slash by
// some clients and intermediaries) and of control characters, and valid UTF-8.
// The index rewrite only mints URLs from addressable values and classification
// only accepts them, so the two always agree on what a URL names.
func addressable(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > maxSegmentLen || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return false
		}
	}
	return true
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

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A chart archive is what Helm unpacks and renders
// into the manifests it applies to a cluster: the payload, by either path form.
// A provenance file is a PGP-signed record of the archive's digest, and the
// repository index lists what the repository offers; a client reads both and
// installs neither.
//
// An index-resolved resource states its file name. Its upstream URL is the
// repository index with the entry it names as the fragment (the real location
// is only looked up at fetch time), so the URL's path ends in "index.yaml", not
// in the name of the archive or of its provenance file. The name stated is the
// final segment of the request — the one the rewritten index handed out, which
// never ends in ".prov" for an archive (see archiveFile).
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindChart:
		if r.indexed {
			return backends.PayloadNamed(r.filename)
		}
		return backends.Payload()
	case kindProvenance:
		if r.indexed {
			return backends.Artifact{Class: backends.ArtifactMetadata, Filename: r.filename + provExt}
		}
		return backends.Metadata()
	case kindIndex:
		return backends.Metadata()
	default:
		return backends.Artifact{}
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
