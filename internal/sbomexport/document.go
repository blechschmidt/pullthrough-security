package sbomexport

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// ExportItem is one artifact's export payload: the identifying coordinate and a
// rendered CycloneDX 1.5 document (the scan SBOM, optionally enriched with the
// admission-gate vulnerability findings as a CycloneDX `vulnerabilities` array).
// A Sink consumes it; the raw BOM bytes are deterministic for a given report so
// they can be asserted in golden-fixture tests.
type ExportItem struct {
	// Ecosystem, Name, Version, and Digest identify the pulled artifact.
	Ecosystem string
	Name      string
	Version   string
	Digest    string
	// ProjectName and ProjectVersion are the Dependency-Track project coordinates
	// derived from the artifact (ProjectName includes the ecosystem so distinct
	// ecosystems never collide on a shared package name).
	ProjectName    string
	ProjectVersion string
	// BOM is the rendered CycloneDX 1.5 JSON document (indented, trailing newline).
	BOM []byte
}

// exportDocument is a CycloneDX 1.5 document: the scan SBOM's fields promoted in
// place (via the embedded pointer) plus a VEX/VDR-style vulnerabilities array.
// Embedding *vulnscan.SBOM anonymously flattens its JSON fields to the top level,
// so the emitted document is a superset of the stored SBOM.
type exportDocument struct {
	*vulnscan.SBOM
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

// cdxVulnerability models the subset of a CycloneDX 1.5 vulnerability object the
// exporter emits from an admission-gate finding.
type cdxVulnerability struct {
	BOMRef      string         `json:"bom-ref,omitempty"`
	ID          string         `json:"id"`
	Source      *cdxVulnSource `json:"source,omitempty"`
	Ratings     []cdxRating    `json:"ratings,omitempty"`
	Description string         `json:"description,omitempty"`
	Detail      string         `json:"detail,omitempty"`
	Advisories  []cdxAdvisory  `json:"advisories,omitempty"`
	Affects     []cdxAffect    `json:"affects,omitempty"`
	Analysis    *cdxAnalysis   `json:"analysis,omitempty"`
}

type cdxVulnSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Source   *cdxVulnSource `json:"source,omitempty"`
	Score    float64        `json:"score,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Method   string         `json:"method,omitempty"`
	Vector   string         `json:"vector,omitempty"`
}

type cdxAdvisory struct {
	URL string `json:"url"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxAnalysis struct {
	State         string `json:"state,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// buildItem renders one scan report into an ExportItem. It returns ok=false when
// the report carries no SBOM (nothing to export). includeFindings embeds the
// report's findings as CycloneDX vulnerabilities; minSeverity drops findings
// below the floor (empty = keep all). The caller has already verified r != nil.
func buildItem(r *vulnscan.Report, includeFindings bool, minSeverity vulnscan.Severity) (ExportItem, bool, error) {
	if r == nil || r.SBOM == nil {
		return ExportItem{}, false, nil
	}

	doc := exportDocument{SBOM: r.SBOM}
	if includeFindings {
		doc.Vulnerabilities = buildVulnerabilities(r, minSeverity)
	}

	bom, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ExportItem{}, false, fmt.Errorf("sbomexport: marshaling BOM for %s: %w", coordinate(r.Artifact), err)
	}
	bom = append(bom, '\n')

	art := r.Artifact
	return ExportItem{
		Ecosystem:      art.Ecosystem,
		Name:           art.Name,
		Version:        art.Version,
		Digest:         art.Digest,
		ProjectName:    projectName(art),
		ProjectVersion: projectVersion(art),
		BOM:            bom,
	}, true, nil
}

// buildVulnerabilities maps the report's findings to CycloneDX vulnerability
// objects. Withdrawn advisories and findings below minSeverity are excluded. The
// affected component reference is resolved to the SBOM component's bom-ref when
// the finding's purl matches a component, else the purl is used verbatim.
func buildVulnerabilities(r *vulnscan.Report, minSeverity vulnscan.Severity) []cdxVulnerability {
	floor := severityRank(minSeverity)
	// Map component purl -> bom-ref for affects resolution.
	refByPurl := make(map[string]string)
	if r.SBOM != nil {
		for _, c := range r.SBOM.Components {
			if c.PURL != "" && c.BOMRef != "" {
				refByPurl[c.PURL] = c.BOMRef
			}
		}
	}

	out := make([]cdxVulnerability, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		if v.Withdrawn {
			continue
		}
		if floor > 0 && severityRank(v.Severity) < floor {
			continue
		}
		cv := cdxVulnerability{
			ID:          v.ID,
			Source:      vulnSource(v.ID),
			Description: v.Summary,
			Detail:      v.Details,
		}
		if sev := cdxSeverity(v.Severity); sev != "" || v.CVSS > 0 {
			rating := cdxRating{Severity: sev}
			if v.CVSS > 0 {
				rating.Score = v.CVSS
				rating.Method = cvssMethod(v.CVSSVector)
				rating.Vector = v.CVSSVector
			}
			if src := vulnSource(v.ID); src != nil {
				rating.Source = src
			}
			cv.Ratings = []cdxRating{rating}
		}
		for _, ref := range v.References {
			if ref = strings.TrimSpace(ref); ref != "" {
				cv.Advisories = append(cv.Advisories, cdxAdvisory{URL: ref})
			}
		}
		ref := v.Component
		if mapped, ok := refByPurl[v.Component]; ok {
			ref = mapped
		}
		if ref != "" {
			cv.Affects = []cdxAffect{{Ref: ref}}
		}
		if a := vexAnalysis(v); a != nil {
			cv.Analysis = a
		}
		out = append(out, cv)
	}
	// Stable order (most-severe first already, but break ties by ID) so the
	// rendered document is deterministic for golden fixtures.
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := out[i], out[j]
		si, sj := ratingRank(ri), ratingRank(rj)
		if si != sj {
			return si > sj
		}
		return ri.ID < rj.ID
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func ratingRank(v cdxVulnerability) int {
	if len(v.Ratings) == 0 {
		return 0
	}
	switch v.Ratings[0].Severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "none":
		return 1
	default:
		return 0
	}
}

// vexAnalysis maps a finding's VEX annotation to a CycloneDX analysis block.
// Returns nil when the finding carries no VEX status.
func vexAnalysis(v vulnscan.Vulnerability) *cdxAnalysis {
	if v.VEXStatus == "" {
		return nil
	}
	state := ""
	switch string(v.VEXStatus) {
	case "not_affected":
		state = "not_affected"
	case "affected":
		state = "exploitable"
	case "fixed":
		state = "resolved"
	case "under_investigation":
		state = "in_triage"
	default:
		state = string(v.VEXStatus)
	}
	return &cdxAnalysis{State: state, Justification: string(v.VEXJustification)}
}

// vulnSource infers the advisory source from the vulnerability identifier.
func vulnSource(id string) *cdxVulnSource {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return &cdxVulnSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + id}
	case strings.HasPrefix(id, "GHSA-"):
		return &cdxVulnSource{Name: "GitHub Advisory Database", URL: "https://github.com/advisories/" + id}
	case strings.HasPrefix(id, "PYSEC-") || strings.HasPrefix(id, "GO-") || strings.HasPrefix(id, "RUSTSEC-"):
		return &cdxVulnSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}
	case id == "":
		return nil
	default:
		return &cdxVulnSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}
	}
}

func cvssMethod(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "CVSSv31"
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return "CVSSv3"
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return "CVSSv4"
	case strings.HasPrefix(vector, "AV:"):
		return "CVSSv2"
	default:
		return ""
	}
}

// cdxSeverity maps the proxy's normalized severity to a CycloneDX rating
// severity. CycloneDX uses "info" where the proxy uses "none".
func cdxSeverity(s vulnscan.Severity) string {
	switch s {
	case vulnscan.SeverityCritical:
		return "critical"
	case vulnscan.SeverityHigh:
		return "high"
	case vulnscan.SeverityMedium:
		return "medium"
	case vulnscan.SeverityLow:
		return "low"
	case vulnscan.SeverityNone:
		return "info"
	default:
		return "unknown"
	}
}

// severityRank orders severities for the minSeverity floor. Unknown/empty rank 0
// (never excluded by a floor).
func severityRank(s vulnscan.Severity) int {
	switch s {
	case vulnscan.SeverityCritical:
		return 5
	case vulnscan.SeverityHigh:
		return 4
	case vulnscan.SeverityMedium:
		return 3
	case vulnscan.SeverityLow:
		return 2
	case vulnscan.SeverityNone:
		return 1
	default:
		return 0
	}
}

// projectName derives a Dependency-Track project name from the artifact,
// namespacing by ecosystem so the same package name in two ecosystems maps to
// two distinct projects.
func projectName(a vulnscan.Artifact) string {
	eco := strings.TrimSpace(a.Ecosystem)
	name := strings.TrimSpace(a.Name)
	if name == "" {
		name = strings.TrimSpace(a.Digest)
	}
	if eco == "" {
		return name
	}
	return eco + ":" + name
}

// projectVersion derives the project version, falling back to the digest when no
// version is known (e.g. a raw blob) so Dependency-Track never sees an empty
// version.
func projectVersion(a vulnscan.Artifact) string {
	if v := strings.TrimSpace(a.Version); v != "" {
		return v
	}
	if d := strings.TrimSpace(a.Digest); d != "" {
		return d
	}
	return "unknown"
}

func coordinate(a vulnscan.Artifact) string {
	return fmt.Sprintf("%s %s@%s", a.Ecosystem, a.Name, a.Version)
}
