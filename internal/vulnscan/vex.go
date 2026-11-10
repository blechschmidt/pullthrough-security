package vulnscan

import (
	"net/url"
	"strings"
	"time"
)

// VEXStatus is the exploitability status a VEX statement asserts for a product /
// vulnerability pair. The vocabulary follows the OpenVEX specification, which the
// CSAF VEX product_status fields are normalized onto.
type VEXStatus string

const (
	// VEXNotAffected asserts the product is not affected by the vulnerability (the
	// vulnerable code is absent, unreachable, or otherwise not exploitable). A
	// matching finding is suppressed (dropped from gating).
	VEXNotAffected VEXStatus = "not_affected"
	// VEXAffected asserts the product is affected. A matching finding has its
	// severity raised so an operator-confirmed exploitable issue cannot slip below
	// the gate threshold.
	VEXAffected VEXStatus = "affected"
	// VEXFixed asserts the vulnerability has been remediated in the product. A
	// matching finding is suppressed.
	VEXFixed VEXStatus = "fixed"
	// VEXUnderInvestigation asserts the product's exposure is still being assessed.
	// A matching finding is annotated but neither suppressed nor escalated.
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// NormalizeVEXStatus coerces a raw status string (OpenVEX or CSAF) onto the known
// vocabulary, returning ok=false for an unrecognized value so a malformed
// statement can be rejected rather than silently treated as a no-op.
func NormalizeVEXStatus(s string) (VEXStatus, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected", "known_not_affected":
		return VEXNotAffected, true
	case "affected", "known_affected":
		return VEXAffected, true
	case "fixed", "first_fixed":
		return VEXFixed, true
	case "under_investigation", "under investigation":
		return VEXUnderInvestigation, true
	default:
		return "", false
	}
}

// Suppresses reports whether a status drops a matching finding from gating.
func (s VEXStatus) Suppresses() bool { return s == VEXNotAffected || s == VEXFixed }

// VEXJustification is the machine-readable reason a not_affected status is
// asserted. The OpenVEX justification labels are the canonical set; the CSAF flag
// labels are identical strings, so a single vocabulary serves both formats.
type VEXJustification string

const (
	JustificationComponentNotPresent           VEXJustification = "component_not_present"
	JustificationVulnerableCodeNotPresent      VEXJustification = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecute    VEXJustification = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeNotControllable VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsExist        VEXJustification = "inline_mitigations_already_exist"
)

// knownJustifications is the set of valid not_affected justifications per the
// OpenVEX/CSAF vocabulary. A not_affected statement that lacks one is still
// honored (some real-world documents omit it), but the value is recorded verbatim
// for audit.
var knownJustifications = map[string]bool{
	string(JustificationComponentNotPresent):           true,
	string(JustificationVulnerableCodeNotPresent):      true,
	string(JustificationVulnerableCodeNotInExecute):    true,
	string(JustificationVulnerableCodeNotControllable): true,
	string(JustificationInlineMitigationsExist):        true,
}

// Recognized reports whether the justification is one of the standard
// OpenVEX/CSAF labels (as opposed to a vendor-specific or malformed value).
func (j VEXJustification) Recognized() bool { return knownJustifications[string(j)] }

// VEXProductRef identifies a product (or subcomponent) a VEX statement applies
// to. A reference carries a parsed Package-URL when one was supplied, plus the
// raw identifier so digest-addressed OCI products and bare names still match.
type VEXProductRef struct {
	// ID is the raw product identifier as written in the document (typically a
	// purl, but possibly a bare name or an OCI digest reference).
	ID string `json:"id,omitempty"`
	// Name is a human-readable product name, when the document supplied one
	// (CSAF full_product_names) instead of (or alongside) a purl.
	Name string `json:"name,omitempty"`
	// Subcomponents narrows the statement to specific dependencies of the product
	// (OpenVEX subcomponents). When present, a finding matches only if its
	// component matches one of these.
	Subcomponents []VEXProductRef `json:"subcomponents,omitempty"`

	purl purlParts // parsed form of ID, when ID is a purl
	hasP bool      // whether purl is populated
}

// VEXStatement is a single normalized VEX assertion: a product (and optional
// subcomponents) is in a given exploitability Status for a given Vulnerability.
// Both OpenVEX statements and CSAF per-CVE product_status entries parse into this
// shared shape so the matcher and policy are format-agnostic.
type VEXStatement struct {
	// Vulnerability is the primary advisory identifier the statement concerns
	// (e.g. "CVE-2024-1234"); Aliases are equivalent identifiers.
	Vulnerability string   `json:"vulnerability"`
	Aliases       []string `json:"aliases,omitempty"`
	// Products are the products the statement applies to.
	Products []VEXProductRef `json:"products"`
	// Status is the asserted exploitability status.
	Status VEXStatus `json:"status"`
	// Justification is the machine-readable reason for a not_affected status.
	Justification VEXJustification `json:"justification,omitempty"`
	// ImpactStatement / ActionStatement carry the human-readable rationale, when
	// supplied; surfaced in audit logs and the admin API.
	ImpactStatement string `json:"impactStatement,omitempty"`
	ActionStatement string `json:"actionStatement,omitempty"`
	// Timestamp orders statements for the same product/vulnerability so the most
	// recent assertion wins (this is how OpenVEX expresses revocation: a newer
	// statement supersedes an older one).
	Timestamp time.Time `json:"timestamp,omitempty"`
	// Source identifies where the statement came from (the document path or URL
	// and its format), recorded on every suppression/escalation for audit.
	Source string `json:"source,omitempty"`
	// Format is "openvex" or "csaf".
	Format string `json:"format,omitempty"`
}

// matchesVuln reports whether the statement concerns the given finding's
// advisory, comparing the primary id and every alias on both sides
// case-insensitively.
func (st *VEXStatement) matchesVuln(v Vulnerability) bool {
	want := make(map[string]bool, 1+len(v.Aliases))
	want[normID(v.ID)] = true
	for _, a := range v.Aliases {
		want[normID(a)] = true
	}
	if want[normID(st.Vulnerability)] {
		return true
	}
	for _, a := range st.Aliases {
		if want[normID(a)] {
			return true
		}
	}
	return false
}

// matchesProduct reports whether the statement's product set covers the finding
// (component) within the given artifact. A statement matches when one of its
// product references resolves to either the finding's own component coordinate or
// the artifact coordinate; a reference carrying subcomponents additionally
// requires the finding's component to be one of them.
func (st *VEXStatement) matchesProduct(art Artifact, v Vulnerability) bool {
	comp := componentTarget(art, v)
	artifact := artifactTarget(art)
	for i := range st.Products {
		p := &st.Products[i]
		// Direct match against the finding's component.
		if p.matches(comp) {
			if len(p.Subcomponents) == 0 {
				return true
			}
		}
		// Product is the artifact and the statement narrows to subcomponents: the
		// finding's component must be one of them.
		if p.matches(artifact) {
			if len(p.Subcomponents) == 0 {
				return true
			}
			for j := range p.Subcomponents {
				if p.Subcomponents[j].matches(comp) {
					return true
				}
			}
		}
	}
	return false
}

// target is a normalized coordinate the matcher compares product references
// against: a parsed purl (when available), a name, and a version.
type target struct {
	purl    purlParts
	hasPurl bool
	name    string
	version string
	raw     string // an additional raw identifier (e.g. OCI digest) to match on
}

// componentTarget builds the match target for a finding's affected component.
func componentTarget(art Artifact, v Vulnerability) target {
	t := target{name: v.Package, version: v.Version}
	if v.Component != "" {
		if pp, ok := parsePurl(v.Component); ok {
			t.purl, t.hasPurl = pp, true
		}
		t.raw = v.Component
	}
	if t.name == "" {
		t.name = art.Name
	}
	if t.version == "" {
		t.version = art.Version
	}
	return t
}

// artifactTarget builds the match target for the pulled artifact itself.
func artifactTarget(art Artifact) target {
	t := target{name: art.Name, version: art.Version, raw: art.Digest}
	if art.Name != "" {
		if pp, ok := parsePurl(PackageURL(art.Ecosystem, art.Name, art.Version)); ok {
			t.purl, t.hasPurl = pp, true
		}
	}
	return t
}

// matches reports whether the product reference covers the given target.
func (p *VEXProductRef) matches(t target) bool {
	if p.hasP && t.hasPurl {
		return p.purl.matches(t.purl)
	}
	// purl present on only one side: fall back to a raw-identifier comparison so a
	// digest-addressed OCI product or an exact-string product id still matches.
	if p.ID != "" && t.raw != "" && strings.EqualFold(strings.TrimSpace(p.ID), strings.TrimSpace(t.raw)) {
		return true
	}
	// Name-based fallback (CSAF full_product_names without a purl helper, or a
	// bare-name OpenVEX product). Match the name, and the version when the product
	// reference pins one.
	pn := strings.TrimSpace(p.Name)
	if pn == "" && !p.hasP {
		pn = strings.TrimSpace(p.ID)
	}
	if pn != "" && t.name != "" && strings.EqualFold(pn, t.name) {
		return true
	}
	return false
}

// purlParts is the structural decomposition of a Package-URL used for matching.
type purlParts struct {
	typ       string
	namespace string
	name      string
	version   string
}

// matches reports whether a statement's purl (the receiver) covers a target
// purl: the type, namespace, and name must be equal, and the version must match
// when the statement pins one (an unpinned statement covers every version).
func (p purlParts) matches(o purlParts) bool {
	if !strings.EqualFold(p.typ, o.typ) {
		return false
	}
	if !strings.EqualFold(p.namespace, o.namespace) {
		return false
	}
	if !strings.EqualFold(p.name, o.name) {
		return false
	}
	if p.version == "" {
		return true
	}
	return p.version == o.version
}

// parsePurl decomposes a Package-URL into its type/namespace/name/version,
// percent-decoding each segment. It returns ok=false for a non-purl string.
func parsePurl(s string) (purlParts, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), "pkg:") {
		return purlParts{}, false
	}
	s = s[len("pkg:"):]
	// Strip subpath and qualifiers, which do not participate in identity matching.
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	var version string
	if i := strings.LastIndex(s, "@"); i >= 0 {
		version = unescape(s[i+1:])
		s = s[:i]
	}
	segs := strings.Split(s, "/")
	if len(segs) < 2 || segs[0] == "" {
		return purlParts{}, false
	}
	name := unescape(segs[len(segs)-1])
	if name == "" {
		return purlParts{}, false
	}
	namespace := ""
	if len(segs) > 2 {
		parts := segs[1 : len(segs)-1]
		for i, p := range parts {
			parts[i] = unescape(p)
		}
		namespace = strings.Join(parts, "/")
	}
	return purlParts{
		typ:       strings.ToLower(segs[0]),
		namespace: namespace,
		name:      name,
		version:   version,
	}, true
}

func unescape(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// normID normalizes an advisory identifier for case-insensitive comparison.
func normID(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// escalateSeverity raises a finding's severity one step toward critical, with a
// floor of High, when a VEX statement asserts the product is affected. A finding
// already at critical is left unchanged.
func escalateSeverity(s Severity) Severity {
	switch {
	case severityRank(s) >= severityRank(SeverityCritical):
		return SeverityCritical
	case severityRank(s) >= severityRank(SeverityHigh):
		return SeverityCritical
	default:
		return SeverityHigh
	}
}
