package vulnscan

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
)

// CycloneDX schema constants. We emit version 1.5 of the JSON format, which is
// widely supported by downstream SBOM tooling (Dependency-Track, Trivy, Grype,
// the CycloneDX CLI).
const (
	cycloneDXBOMFormat  = "CycloneDX"
	cycloneDXSpecVer    = "1.5"
	cycloneDXJSONSchema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

// SBOM is a minimal but spec-valid CycloneDX 1.5 bill of materials. It is
// produced by the extractor and embedded in a scan Report; it is also the input
// to a Scanner. Only the fields the subsystem needs are modeled; unmodeled
// fields are simply absent, which CycloneDX permits.
type SBOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	JSONSchema   string       `json:"$schema,omitempty"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     *BOMMetadata `json:"metadata,omitempty"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
	Properties   []NameValue  `json:"properties,omitempty"`
}

// BOMMetadata carries SBOM-level metadata: the tool that produced it and the
// primary component the SBOM describes (the pulled artifact itself).
type BOMMetadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     []Tool     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

// Tool identifies the SBOM-producing tool.
type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Component is a single CycloneDX component (a package).
type Component struct {
	Type       string          `json:"type"` // "library", "application", "container"
	BOMRef     string          `json:"bom-ref,omitempty"`
	Group      string          `json:"group,omitempty"`
	Name       string          `json:"name"`
	Version    string          `json:"version,omitempty"`
	PURL       string          `json:"purl,omitempty"`
	Scope      string          `json:"scope,omitempty"` // "required", "optional"
	Licenses   []LicenseChoice `json:"licenses,omitempty"`
	Properties []NameValue     `json:"properties,omitempty"`

	// ecosystem is the proxy ecosystem the component belongs to, retained for OSV
	// query construction. It is not serialized (CycloneDX carries the purl type
	// instead) but is needed by the scanner.
	ecosystem string `json:"-"`
}

// Dependency expresses the SBOM's dependency graph by bom-ref.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// NameValue is a CycloneDX property (key/value annotation).
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// LicenseChoice is a CycloneDX license entry: either a single license reference
// (by SPDX id or free-text name) or an SPDX license expression. The two forms are
// mutually exclusive per the CycloneDX schema.
type LicenseChoice struct {
	License    *LicenseRef `json:"license,omitempty"`
	Expression string      `json:"expression,omitempty"`
}

// LicenseRef names a single license, preferring an SPDX id when one is known.
type LicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Ecosystem returns the proxy ecosystem associated with the component.
func (c Component) Ecosystem() string { return c.ecosystem }

// LicenseExpression returns a single SPDX-style license expression for the
// component's declared licenses, or "" when none are declared (NOASSERTION). A
// CycloneDX expression entry is returned verbatim; multiple discrete license
// references are combined with OR, reflecting the historical "the consumer may
// choose" semantics of a multi-license declaration.
func (c Component) LicenseExpression() string {
	operands := make([]string, 0, len(c.Licenses))
	for _, lc := range c.Licenses {
		switch {
		case strings.TrimSpace(lc.Expression) != "":
			operands = append(operands, "("+strings.TrimSpace(lc.Expression)+")")
		case lc.License != nil && strings.TrimSpace(lc.License.ID) != "":
			operands = append(operands, strings.TrimSpace(lc.License.ID))
		case lc.License != nil && strings.TrimSpace(lc.License.Name) != "":
			operands = append(operands, strings.TrimSpace(lc.License.Name))
		}
	}
	switch len(operands) {
	case 0:
		return ""
	case 1:
		return strings.TrimPrefix(strings.TrimSuffix(operands[0], ")"), "(")
	default:
		return strings.Join(operands, " OR ")
	}
}

// setLicenseExpression records an SPDX license expression on a component,
// replacing any prior license entries. A blank expression clears them.
func setLicenseExpression(c *Component, expr string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		c.Licenses = nil
		return
	}
	c.Licenses = []LicenseChoice{{Expression: expr}}
}

// newSBOM constructs an empty CycloneDX document with the format/version headers
// and tool metadata populated.
func newSBOM() *SBOM {
	return &SBOM{
		BOMFormat:   cycloneDXBOMFormat,
		SpecVersion: cycloneDXSpecVer,
		JSONSchema:  cycloneDXJSONSchema,
		Version:     1,
		Metadata: &BOMMetadata{
			Tools: []Tool{{Vendor: "pullthrough", Name: "pullthrough-vulnscan"}},
		},
		Components: []Component{},
	}
}

// addComponent appends a component, deduplicating by purl (or name@version when no
// purl) so the same dependency declared twice yields one component. It assigns a
// stable bom-ref. The first occurrence's scope/group wins.
func (s *SBOM) addComponent(c Component) {
	if c.BOMRef == "" {
		c.BOMRef = bomRef(c)
	}
	for i := range s.Components {
		if s.Components[i].BOMRef == c.BOMRef {
			return
		}
	}
	if c.Type == "" {
		c.Type = "library"
	}
	s.Components = append(s.Components, c)
}

// finalize sorts components for deterministic output (the primary component, when
// present, is held in metadata, not the list) and assigns a content-derived
// serial number so identical inputs yield identical SBOMs.
func (s *SBOM) finalize() {
	sort.SliceStable(s.Components, func(i, j int) bool {
		if s.Components[i].Name != s.Components[j].Name {
			return s.Components[i].Name < s.Components[j].Name
		}
		return s.Components[i].Version < s.Components[j].Version
	})
	s.SerialNumber = "urn:uuid:" + serialUUID(s)
}

// bomRef derives a stable component reference from the purl or coordinate.
func bomRef(c Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + name
	}
	if c.Version != "" {
		return name + "@" + c.Version
	}
	return name
}

// serialUUID derives a deterministic, RFC-4122-shaped UUID (version 5-style) from
// the SBOM's component set so the same inputs produce a stable serial number.
func serialUUID(s *SBOM) string {
	var b strings.Builder
	if s.Metadata != nil && s.Metadata.Component != nil {
		b.WriteString(s.Metadata.Component.PURL)
		b.WriteByte('\n')
	}
	refs := make([]string, 0, len(s.Components))
	for _, c := range s.Components {
		refs = append(refs, c.BOMRef)
	}
	sort.Strings(refs)
	b.WriteString(strings.Join(refs, "\n"))

	sum := sha1.Sum([]byte(b.String()))
	h := hex.EncodeToString(sum[:])
	// Shape as 8-4-4-4-12 with version (5) and variant nibbles set.
	return h[0:8] + "-" + h[8:12] + "-5" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// scannableComponents returns every component (primary + dependencies) that
// carries a concrete ecosystem and version, suitable for a vulnerability query.
func (s *SBOM) scannableComponents() []Component {
	var out []Component
	if s.Metadata != nil && s.Metadata.Component != nil {
		if c := *s.Metadata.Component; c.Version != "" && c.ecosystem != "" {
			out = append(out, c)
		}
	}
	for _, c := range s.Components {
		if c.Version != "" && c.ecosystem != "" {
			out = append(out, c)
		}
	}
	return out
}
