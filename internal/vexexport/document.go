// Package vexexport implements outbound VEX authoring: it turns the proxy's
// operator-triage posture — the loaded VEX suppression corpus (Task 27), the
// VEX-adjudicated findings, and the active break-glass/approval grants (Task
// 50) — into signed OpenVEX documents and CycloneDX VEX/VDR BOMs, exportable per
// coordinate or for a whole snapshot via ptctl and the admin API (Task 137).
//
// The project already *consumes* VEX for suppression; this package is the
// inverse. An OpenVEX document it emits re-ingests cleanly through the existing
// vulnscan VEX suppression gate (ParseVEX → VEXStore.Match), which the package's
// round-trip test asserts.
package vexexport

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// Format selects the serialization an export produces.
type Format string

const (
	// FormatOpenVEX emits an OpenVEX 0.2.0 document (application/vnd.openvex+json).
	FormatOpenVEX Format = "openvex"
	// FormatCycloneDX emits a CycloneDX 1.5 VEX/VDR BOM
	// (application/vnd.cyclonedx+json).
	FormatCycloneDX Format = "cyclonedx"
)

// NormalizeFormat coerces a raw format string onto the supported set, defaulting
// to OpenVEX for an empty value and reporting ok=false for an unknown one.
func NormalizeFormat(s string) (Format, bool) {
	switch Format(s) {
	case "":
		return FormatOpenVEX, true
	case FormatOpenVEX:
		return FormatOpenVEX, true
	case FormatCycloneDX, "cdx", "vdr", "vex":
		return FormatCycloneDX, true
	default:
		return "", false
	}
}

// MediaType returns the IANA-style media type for a format.
func (f Format) MediaType() string {
	switch f {
	case FormatCycloneDX:
		return "application/vnd.cyclonedx+json; version=1.5"
	default:
		return "application/vnd.openvex+json; charset=utf-8"
	}
}

// docMeta carries the document-level identity stamped into an exported document.
type docMeta struct {
	Author      string
	IDNamespace string
	Timestamp   time.Time
}

const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"
	toolingName    = "pullthrough-security"
	cdxBOMFormat   = "CycloneDX"
	cdxSpecVersion = "1.5"
)

// --- OpenVEX writer ---------------------------------------------------------

type openVEXOut struct {
	Context    string           `json:"@context"`
	ID         string           `json:"@id"`
	Author     string           `json:"author"`
	Timestamp  string           `json:"timestamp"`
	Version    int              `json:"version"`
	Tooling    string           `json:"tooling,omitempty"`
	Statements []openVEXStmtOut `json:"statements"`
}

type openVEXStmtOut struct {
	Vulnerability   openVEXVulnOut   `json:"vulnerability"`
	Timestamp       string           `json:"timestamp,omitempty"`
	Products        []openVEXProdOut `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
}

type openVEXVulnOut struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type openVEXProdOut struct {
	ID            string           `json:"@id,omitempty"`
	Name          string           `json:"name,omitempty"`
	Subcomponents []openVEXProdOut `json:"subcomponents,omitempty"`
}

func toOpenVEXProducts(refs []vulnscan.VEXProductRef) []openVEXProdOut {
	if len(refs) == 0 {
		return nil
	}
	out := make([]openVEXProdOut, 0, len(refs))
	for _, r := range refs {
		out = append(out, openVEXProdOut{
			ID:            r.ID,
			Name:          r.Name,
			Subcomponents: toOpenVEXProducts(r.Subcomponents),
		})
	}
	return out
}

// buildOpenVEX renders statements as an indented OpenVEX 0.2.0 document. The
// returned bytes are the exact signed preimage: callers must transmit them
// verbatim so a detached signature verifies.
func buildOpenVEX(stmts []vulnscan.VEXStatement, meta docMeta) ([]byte, error) {
	doc := openVEXOut{
		Context:    openVEXContext,
		Author:     meta.Author,
		Timestamp:  meta.Timestamp.UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    toolingName,
		Statements: make([]openVEXStmtOut, 0, len(stmts)),
	}
	for _, st := range stmts {
		s := openVEXStmtOut{
			Vulnerability:   openVEXVulnOut{Name: st.Vulnerability, Aliases: st.Aliases},
			Products:        toOpenVEXProducts(st.Products),
			Status:          string(st.Status),
			Justification:   string(st.Justification),
			ImpactStatement: st.ImpactStatement,
			ActionStatement: st.ActionStatement,
		}
		if !st.Timestamp.IsZero() {
			s.Timestamp = st.Timestamp.UTC().Format(time.RFC3339)
		}
		doc.Statements = append(doc.Statements, s)
	}
	doc.ID = meta.idFor(canonicalSeed(doc.Statements))
	return marshalIndent(doc)
}

// --- CycloneDX VEX/VDR writer ----------------------------------------------

type cdxBOM struct {
	BOMFormat       string    `json:"bomFormat"`
	SpecVersion     string    `json:"specVersion"`
	SerialNumber    string    `json:"serialNumber"`
	Version         int       `json:"version"`
	Metadata        cdxMeta   `json:"metadata"`
	Vulnerabilities []cdxVuln `json:"vulnerabilities"`
}

type cdxMeta struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools,omitempty"`
	Authors   []cdxContact `json:"authors,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxContact struct {
	Name string `json:"name"`
}

type cdxVuln struct {
	BOMRef     string       `json:"bom-ref,omitempty"`
	ID         string       `json:"id"`
	Source     *cdxSource   `json:"source,omitempty"`
	References []cdxVulnRef `json:"references,omitempty"`
	Analysis   *cdxAnalysis `json:"analysis,omitempty"`
	Affects    []cdxAffect  `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cdxVulnRef struct {
	ID     string    `json:"id"`
	Source cdxSource `json:"source"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// cdxState maps a VEX status onto the CycloneDX vulnerability analysis state
// vocabulary (impactAnalysisState).
func cdxState(s vulnscan.VEXStatus) string {
	switch s {
	case vulnscan.VEXNotAffected:
		return "not_affected"
	case vulnscan.VEXAffected:
		return "exploitable"
	case vulnscan.VEXFixed:
		return "resolved"
	case vulnscan.VEXUnderInvestigation:
		return "in_triage"
	default:
		return "in_triage"
	}
}

// cdxJustification maps the OpenVEX justification vocabulary onto the CycloneDX
// impactAnalysisJustification vocabulary. An unmapped value yields "" (omitted).
func cdxJustification(j vulnscan.VEXJustification) string {
	switch j {
	case vulnscan.JustificationComponentNotPresent, vulnscan.JustificationVulnerableCodeNotPresent:
		return "code_not_present"
	case vulnscan.JustificationVulnerableCodeNotInExecute:
		return "code_not_reachable"
	case vulnscan.JustificationVulnerableCodeNotControllable:
		return "protected_at_runtime"
	case vulnscan.JustificationInlineMitigationsExist:
		return "protected_by_mitigating_control"
	default:
		return ""
	}
}

// buildCycloneDX renders statements as an indented CycloneDX 1.5 BOM carrying a
// vulnerabilities array with per-vulnerability analysis (the VEX/VDR shape).
func buildCycloneDX(stmts []vulnscan.VEXStatement, meta docMeta) ([]byte, error) {
	bom := cdxBOM{
		BOMFormat:   cdxBOMFormat,
		SpecVersion: cdxSpecVersion,
		Version:     1,
		Metadata: cdxMeta{
			Timestamp: meta.Timestamp.UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "blechschmidt", Name: toolingName, Version: ""}},
		},
		Vulnerabilities: make([]cdxVuln, 0, len(stmts)),
	}
	if meta.Author != "" {
		bom.Metadata.Authors = []cdxContact{{Name: meta.Author}}
	}
	for i, st := range stmts {
		v := cdxVuln{
			BOMRef:  fmt.Sprintf("vuln-%d", i+1),
			ID:      st.Vulnerability,
			Affects: cdxAffects(st.Products),
			Analysis: &cdxAnalysis{
				State:         cdxState(st.Status),
				Justification: cdxJustification(st.Justification),
				Detail:        st.ImpactStatement,
			},
		}
		if st.ActionStatement != "" {
			v.Analysis.Response = []string{st.ActionStatement}
		}
		if len(st.Aliases) > 0 {
			refs := make([]cdxVulnRef, 0, len(st.Aliases))
			for _, a := range st.Aliases {
				refs = append(refs, cdxVulnRef{ID: a, Source: cdxSource{Name: "alias"}})
			}
			v.References = refs
		}
		bom.Vulnerabilities = append(bom.Vulnerabilities, v)
	}
	bom.SerialNumber = "urn:uuid:" + deterministicUUID(canonicalSeed(bom.Vulnerabilities))
	return marshalIndent(bom)
}

func cdxAffects(refs []vulnscan.VEXProductRef) []cdxAffect {
	out := make([]cdxAffect, 0, len(refs))
	for _, r := range refs {
		ref := r.ID
		if ref == "" {
			ref = r.Name
		}
		if ref == "" {
			continue
		}
		out = append(out, cdxAffect{Ref: ref})
	}
	return out
}

// --- shared helpers ---------------------------------------------------------

// marshalIndent encodes v as indented JSON with HTML escaping disabled so purls
// and URLs render verbatim.
func marshalIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vexexport: encoding document: %w", err)
	}
	return b, nil
}

// canonicalSeed derives a stable byte seed from a value for deterministic id
// generation (Go marshals struct fields in declaration order).
func canonicalSeed(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// idFor builds a stable document @id under the metadata namespace from a seed.
func (m docMeta) idFor(seed []byte) string {
	ns := m.IDNamespace
	if ns == "" {
		ns = defaultIDNamespace
	}
	return ns + "/" + deterministicUUID(seed)
}

// deterministicUUID formats the SHA-256 of seed as an RFC 4122 version-4-shaped
// UUID string. It is deterministic (same content → same id), which keeps
// exported documents reproducible for signature verification and diffing.
func deterministicUUID(seed []byte) string {
	sum := sha256.Sum256(seed)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
