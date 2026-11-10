package helm

import (
	"fmt"
	"path"
	"strings"
)

// index.yaml is the mutable index document of the classic Helm chart-repository
// protocol (Helm v2/v3 HTTP repositories such as charts.bitnami.com). It is the
// authoritative record of every published chart version, the URL the chart .tgz
// is served at, and — critically for supply-chain integrity — the SHA-256
// `digest` of each .tgz. A client runs `helm repo add` to fetch it, then `helm
// pull`/`helm install` fetches the resolved .tgz.
//
// The backend serves index.yaml live (it is mutable) with every chart URL
// rewritten to lead back through the proxy (see rewrite.go), and consults it on
// a chart cache miss: to find the upstream location of the requested archive,
// and to recover the published digest the fetched archive is verified against
// before the bytes are cached or served. This is the cornerstone of the
// supply-chain guarantee for the Helm ecosystem, mirroring the way the RubyGems
// backend recovers a .gem's checksum from its compact-index /info document.

// Schematic of the document the parser accepts:
//
//	apiVersion: v1
//	entries:
//	  mychart:
//	    - name: mychart
//	      version: 1.2.3
//	      digest: <sha256-hex>
//	      urls: [ "https://charts.example.com/mychart-1.2.3.tgz" ]
//	      appVersion: "2.0"
//	      created: "2024-01-02T03:04:05Z"
//	generated: "2024-01-02T03:04:05Z"

// Index is the parsed, validated form of an index.yaml document.
type Index struct {
	APIVersion string
	// Entries maps a chart name to its published versions, newest-first as the
	// upstream ordered them.
	Entries map[string][]ChartVersion
}

// ChartVersion is one published version of a chart in the repository index.
type ChartVersion struct {
	Name string
	// Version is the chart's SemVer version (the version segment of the .tgz
	// filename), e.g. "1.2.3".
	Version string
	// Digest is the SHA-256 digest the index publishes for the chart .tgz. It is
	// normalized to bare lowercase hex; empty when the index omitted it or it was
	// not a well-formed SHA-256 value.
	Digest string
	// URLs are the locations the .tgz is served at, as the index declared them
	// (may be repository-relative filenames or absolute URLs).
	URLs []string
	// AppVersion is the application version the chart packages (advisory metadata
	// surfaced to the admission gates).
	AppVersion string
	// Deprecated reports whether the index marks this chart version deprecated.
	Deprecated bool
}

// maxIndexBytes bounds how much of an index.yaml document the backend parses, so
// a hostile or compromised upstream cannot exhaust memory. Large public
// repositories (e.g. Bitnami's) publish indexes in the tens of MiB; the cap is
// generous enough for those while still bounded.
const maxIndexBytes = 128 << 20 // 128 MiB

// ParseIndex decodes and validates an index.yaml document. It tolerates a
// missing apiVersion (older repositories), normalizes each entry's digest to
// bare lowercase SHA-256 hex, and drops entries that carry no version (which
// could not be addressed as an artifact anyway). A document that is not
// well-formed YAML, or whose top level is not a mapping with an `entries` map,
// is an error so the backend fails closed rather than treating garbage as an
// empty index.
//
// It reads the document exactly as the index rewrite does (see scanIndex): keys
// are matched the way a Helm client matches them, and a document using a YAML
// construct that could hide a chart URL from the rewrite is an error here too.
func ParseIndex(data []byte) (*Index, error) {
	doc, _, err := scanIndexSource(data)
	if err != nil {
		return nil, err
	}
	if !doc.hasEntries {
		return nil, fmt.Errorf("helm: index.yaml has no entries map")
	}
	return doc.index(), nil
}

// chartLocation is one place the index says a chart archive can be downloaded
// from, together with the digest the same entry declares for it.
type chartLocation struct {
	// URL is the location as the index lists it: absolute, or relative to the
	// repository URL.
	URL string
	// Digest is the entry's SHA-256 (bare lowercase hex), empty when the index
	// publishes none.
	Digest string
}

// checksum returns the digest the archive at this location must hash to.
func (l chartLocation) checksum() (expectedChecksum, bool) {
	return ChartVersion{Digest: l.Digest}.Checksum()
}

// locate resolves an index-resolved request back to the index: the locations
// listed for that chart version whose index-resolved URL ends in file, in the
// order the index lists them. Nothing the index does not list for that exact
// chart name and version is ever returned, which is what keeps the backend
// from fetching arbitrary URLs on a client's behalf.
func (idx *Index) locate(chart, version, file string) []chartLocation {
	var out []chartLocation
	for _, cv := range idx.Entries[chart] {
		if cv.Version != version {
			continue
		}
		for _, u := range cv.URLs {
			if archiveFile(u, chart, version) == file {
				out = append(out, chartLocation{URL: u, Digest: cv.Digest})
			}
		}
	}
	return out
}

// FindVersion returns the indexed chart version for an exact (name, version)
// pair. It is the authoritative path: the chart name and version come from the
// requested .tgz filename, and the matching entry carries the digest to verify
// against.
func (idx *Index) FindVersion(name, version string) (ChartVersion, bool) {
	for _, cv := range idx.Entries[name] {
		if cv.Version == version {
			return cv, true
		}
	}
	return ChartVersion{}, false
}

// FindByFilename recovers the indexed chart version whose artifact matches the
// requested .tgz basename. It first matches on the basename of any of an entry's
// declared URLs (the authoritative locator the index publishes), then falls back
// to reconstructing "<name>-<version>.tgz" from the entry fields. This tolerates
// repositories whose chart name or version contains hyphens, where splitting the
// filename heuristically would be ambiguous.
func (idx *Index) FindByFilename(filename string) (ChartVersion, bool) {
	filename = path.Base(strings.TrimSpace(filename))
	if filename == "" || filename == "." || filename == "/" {
		return ChartVersion{}, false
	}
	for _, versions := range idx.Entries {
		for _, cv := range versions {
			for _, u := range cv.URLs {
				if path.Base(u) == filename {
					return cv, true
				}
			}
			if cv.Name+"-"+cv.Version+chartExt == filename {
				return cv, true
			}
		}
	}
	return ChartVersion{}, false
}

// Checksum returns the entry's expected SHA-256 checksum, when the index
// published a well-formed one.
func (cv ChartVersion) Checksum() (expectedChecksum, bool) {
	if len(cv.Digest) != sha256HexLen {
		return expectedChecksum{}, false
	}
	return expectedChecksum{hex: cv.Digest}, true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
