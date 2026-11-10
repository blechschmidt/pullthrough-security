package vulnscan

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VEXDocument is a parsed VEX file: its detected format and the normalized
// statements it yielded. It is the unit a VEXStore ingests.
type VEXDocument struct {
	Format     string         `json:"format"`
	Source     string         `json:"source"`
	Statements []VEXStatement `json:"statements"`
}

// ParseVEX auto-detects the document format (OpenVEX or CSAF VEX) and parses it
// into normalized statements. source labels the origin (file path or URL) and is
// stamped onto every statement for audit. A document that is valid JSON but
// carries no recognizable VEX content yields zero statements and a nil error; a
// syntactically invalid document, or one in neither recognized format, returns an
// error so the loader can report and skip it.
func ParseVEX(data []byte, source string) (*VEXDocument, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("vex: empty document")
	}

	// Probe the top-level keys to choose a parser without fully unmarshaling twice.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("vex: %s: not valid JSON: %w", source, err)
	}

	switch detectVEXFormat(probe) {
	case "openvex":
		return parseOpenVEX(data, source)
	case "csaf":
		return parseCSAF(data, source)
	default:
		return nil, fmt.Errorf("vex: %s: unrecognized document format (expected OpenVEX or CSAF VEX)", source)
	}
}

// detectVEXFormat classifies a document by its distinguishing top-level keys.
func detectVEXFormat(probe map[string]json.RawMessage) string {
	if _, ok := probe["statements"]; ok {
		return "openvex"
	}
	if ctx, ok := probe["@context"]; ok {
		if strings.Contains(strings.ToLower(string(ctx)), "openvex") {
			return "openvex"
		}
	}
	_, hasDoc := probe["document"]
	_, hasVulns := probe["vulnerabilities"]
	if hasDoc && hasVulns {
		return "csaf"
	}
	return ""
}

// --- OpenVEX ----------------------------------------------------------------

// openVEXDoc models the subset of the OpenVEX schema we consume. It tolerates
// both the 0.2.0 shape (vulnerability object, products array) and the legacy
// shape (vulnerability string, single product string).
type openVEXDoc struct {
	Context    string             `json:"@context"`
	Timestamp  string             `json:"timestamp"`
	Author     string             `json:"author"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   json.RawMessage `json:"vulnerability"`
	Status          string          `json:"status"`
	Justification   string          `json:"justification"`
	ImpactStatement string          `json:"impact_statement"`
	ActionStatement string          `json:"action_statement"`
	Timestamp       string          `json:"timestamp"`
	// Products is the 0.2.0 field; Product is the legacy single-product field.
	Products json.RawMessage `json:"products"`
	Product  json.RawMessage `json:"product"`
}

func parseOpenVEX(data []byte, source string) (*VEXDocument, error) {
	var doc openVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("vex: %s: decoding OpenVEX: %w", source, err)
	}
	docTime := parseVEXTime(doc.Timestamp)
	out := &VEXDocument{Format: "openvex", Source: source}
	for idx, st := range doc.Statements {
		vulnID, aliases := parseOpenVEXVuln(st.Vulnerability)
		status, ok := NormalizeVEXStatus(st.Status)
		if !ok {
			// A statement with an unknown/empty status carries no actionable
			// assertion; skip it rather than failing the whole document.
			continue
		}
		if vulnID == "" {
			continue
		}
		products := parseOpenVEXProducts(st.Products, st.Product)
		if len(products) == 0 {
			continue
		}
		ts := parseVEXTime(st.Timestamp)
		if ts.IsZero() {
			ts = docTime
		}
		out.Statements = append(out.Statements, VEXStatement{
			Vulnerability:   vulnID,
			Aliases:         aliases,
			Products:        products,
			Status:          status,
			Justification:   normalizeJustification(st.Justification),
			ImpactStatement: strings.TrimSpace(st.ImpactStatement),
			ActionStatement: strings.TrimSpace(st.ActionStatement),
			Timestamp:       ts,
			Source:          fmt.Sprintf("%s#statements[%d]", source, idx),
			Format:          "openvex",
		})
	}
	return out, nil
}

// parseOpenVEXVuln extracts the advisory id and aliases from the vulnerability
// field, which may be a plain string (legacy) or an object with name/@id/aliases.
func parseOpenVEXVuln(raw json.RawMessage) (id string, aliases []string) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s), nil
	}
	var obj struct {
		Name    string   `json:"name"`
		ID      string   `json:"@id"`
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		id = strings.TrimSpace(obj.Name)
		if id == "" {
			id = strings.TrimSpace(obj.ID)
		}
		for _, a := range obj.Aliases {
			if a = strings.TrimSpace(a); a != "" {
				aliases = append(aliases, a)
			}
		}
	}
	return id, aliases
}

// parseOpenVEXProducts parses the products array (0.2.0) and/or the legacy
// single product field into normalized references.
func parseOpenVEXProducts(products, legacy json.RawMessage) []VEXProductRef {
	var out []VEXProductRef
	out = append(out, parseProductList(products)...)
	if legacy != nil {
		out = append(out, parseProductList(legacy)...)
	}
	return out
}

// parseProductList accepts a JSON value that is an array of products, a single
// product object, or a bare product-id string, and returns normalized references.
func parseProductList(raw json.RawMessage) []VEXProductRef {
	if len(raw) == 0 {
		return nil
	}
	// Array of products.
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		var out []VEXProductRef
		for _, el := range arr {
			if ref, ok := parseProductRef(el); ok {
				out = append(out, ref)
			}
		}
		return out
	}
	if ref, ok := parseProductRef(raw); ok {
		return []VEXProductRef{ref}
	}
	return nil
}

// parseProductRef parses a single product reference, which may be a bare string
// id or an object carrying @id / identifiers / subcomponents.
func parseProductRef(raw json.RawMessage) (VEXProductRef, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return VEXProductRef{}, false
		}
		return newProductRef(s, ""), true
	}
	var obj struct {
		ID            string            `json:"@id"`
		Identifiers   map[string]string `json:"identifiers"`
		Name          string            `json:"name"`
		Subcomponents []json.RawMessage `json:"subcomponents"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return VEXProductRef{}, false
	}
	id := strings.TrimSpace(obj.ID)
	if id == "" && obj.Identifiers != nil {
		// Prefer a purl identifier when @id is not itself one.
		if p := strings.TrimSpace(obj.Identifiers["purl"]); p != "" {
			id = p
		}
	}
	if id == "" && strings.TrimSpace(obj.Name) == "" {
		return VEXProductRef{}, false
	}
	ref := newProductRef(id, strings.TrimSpace(obj.Name))
	for _, sc := range obj.Subcomponents {
		if scRef, ok := parseProductRef(sc); ok {
			ref.Subcomponents = append(ref.Subcomponents, scRef)
		}
	}
	return ref, true
}

// newProductRef builds a product reference, parsing the id as a purl when it is
// one (so structural matching is available).
func newProductRef(id, name string) VEXProductRef {
	ref := VEXProductRef{ID: id, Name: name}
	if pp, ok := parsePurl(id); ok {
		ref.purl, ref.hasP = pp, true
	}
	return ref
}

// --- CSAF VEX ---------------------------------------------------------------

// csafDoc models the subset of a CSAF 2.0 VEX document we consume: the product
// tree (to resolve product ids to purls/names) and the per-vulnerability product
// status / flags.
type csafDoc struct {
	Document struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Tracking struct {
			CurrentReleaseDate string `json:"current_release_date"`
			InitialReleaseDate string `json:"initial_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafProductTree struct {
	FullProductNames []csafFullProductName `json:"full_product_names"`
	Branches         []csafBranch          `json:"branches"`
	RelationShips    []csafRelationship    `json:"relationships"`
}

type csafFullProductName struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    struct {
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Category string               `json:"category"`
	Name     string               `json:"name"`
	Product  *csafFullProductName `json:"product"`
	Branches []csafBranch         `json:"branches"`
}

type csafRelationship struct {
	FullProductName csafFullProductName `json:"full_product_name"`
	ProductRef      string              `json:"product_reference"`
	RelatesTo       string              `json:"relates_to_product_reference"`
	Category        string              `json:"category"`
}

type csafVulnerability struct {
	CVE string `json:"cve"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	ProductStatus struct {
		KnownNotAffected   []string `json:"known_not_affected"`
		KnownAffected      []string `json:"known_affected"`
		Fixed              []string `json:"fixed"`
		FirstFixed         []string `json:"first_fixed"`
		UnderInvestigation []string `json:"under_investigation"`
	} `json:"product_status"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags"`
}

func parseCSAF(data []byte, source string) (*VEXDocument, error) {
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("vex: %s: decoding CSAF: %w", source, err)
	}

	// Resolve every product id to a reference (purl/name).
	products := make(map[string]VEXProductRef)
	for i := range doc.ProductTree.FullProductNames {
		addCSAFProduct(products, doc.ProductTree.FullProductNames[i])
	}
	collectCSAFBranches(products, doc.ProductTree.Branches)
	for i := range doc.ProductTree.RelationShips {
		addCSAFProduct(products, doc.ProductTree.RelationShips[i].FullProductName)
	}

	docTime := parseVEXTime(doc.Document.Tracking.CurrentReleaseDate)
	if docTime.IsZero() {
		docTime = parseVEXTime(doc.Document.Tracking.InitialReleaseDate)
	}

	out := &VEXDocument{Format: "csaf", Source: source}
	for vi := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[vi]
		vulnID := strings.TrimSpace(v.CVE)
		var aliases []string
		for _, id := range v.IDs {
			if t := strings.TrimSpace(id.Text); t != "" {
				if vulnID == "" {
					vulnID = t
				} else {
					aliases = append(aliases, t)
				}
			}
		}
		if vulnID == "" {
			continue
		}

		// Per-product justification from flags.
		just := make(map[string]VEXJustification)
		for _, f := range v.Flags {
			j := normalizeJustification(f.Label)
			for _, pid := range f.ProductIDs {
				just[pid] = j
			}
		}

		groups := []struct {
			ids    []string
			status VEXStatus
		}{
			{v.ProductStatus.KnownNotAffected, VEXNotAffected},
			{v.ProductStatus.KnownAffected, VEXAffected},
			{v.ProductStatus.Fixed, VEXFixed},
			{v.ProductStatus.FirstFixed, VEXFixed},
			{v.ProductStatus.UnderInvestigation, VEXUnderInvestigation},
		}
		for _, g := range groups {
			for _, pid := range g.ids {
				ref, ok := products[pid]
				if !ok {
					// Unknown product id: still honor the assertion using the bare id
					// so a name/digest match remains possible.
					ref = newProductRef(pid, "")
				}
				out.Statements = append(out.Statements, VEXStatement{
					Vulnerability: vulnID,
					Aliases:       aliases,
					Products:      []VEXProductRef{ref},
					Status:        g.status,
					Justification: just[pid],
					Timestamp:     docTime,
					Source:        fmt.Sprintf("%s#%s/%s", source, vulnID, pid),
					Format:        "csaf",
				})
			}
		}
	}
	return out, nil
}

// addCSAFProduct records a resolved product reference under its product id.
func addCSAFProduct(into map[string]VEXProductRef, fpn csafFullProductName) {
	pid := strings.TrimSpace(fpn.ProductID)
	if pid == "" {
		return
	}
	id := strings.TrimSpace(fpn.Helper.PURL)
	into[pid] = newProductRef(id, strings.TrimSpace(fpn.Name))
}

// collectCSAFBranches walks the product_tree branches, recording any product
// nodes it finds.
func collectCSAFBranches(into map[string]VEXProductRef, branches []csafBranch) {
	for i := range branches {
		b := &branches[i]
		if b.Product != nil {
			addCSAFProduct(into, *b.Product)
		}
		if len(b.Branches) > 0 {
			collectCSAFBranches(into, b.Branches)
		}
	}
}

// --- shared helpers ---------------------------------------------------------

// normalizeJustification trims and lowercases a justification label, leaving an
// unrecognized value verbatim (it is still recorded for audit).
func normalizeJustification(s string) VEXJustification {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	return VEXJustification(s)
}

// parseVEXTime parses an RFC3339 timestamp, tolerating the date-only form CSAF
// sometimes carries. A zero time is returned for an empty/unparseable value.
func parseVEXTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
