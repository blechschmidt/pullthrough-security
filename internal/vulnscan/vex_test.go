package vulnscan

import (
	"testing"
	"time"
)

func TestParseOpenVEX_v0_2_0(t *testing.T) {
	doc := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/1",
		"author": "Acme Security",
		"timestamp": "2026-01-01T00:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-1111", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
				"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
				"status": "not_affected",
				"justification": "vulnerable_code_not_present"
			},
			{
				"vulnerability": {"name": "CVE-2026-2222"},
				"products": [{"@id": "pkg:npm/lodash@4.17.20"}],
				"status": "affected"
			}
		]
	}`)
	parsed, err := ParseVEX(doc, "test.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if parsed.Format != "openvex" {
		t.Fatalf("format = %q, want openvex", parsed.Format)
	}
	if len(parsed.Statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(parsed.Statements))
	}
	s0 := parsed.Statements[0]
	if s0.Vulnerability != "CVE-2026-1111" {
		t.Errorf("vuln = %q", s0.Vulnerability)
	}
	if len(s0.Aliases) != 1 || s0.Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("aliases = %v", s0.Aliases)
	}
	if s0.Status != VEXNotAffected {
		t.Errorf("status = %q", s0.Status)
	}
	if !s0.Justification.Recognized() {
		t.Errorf("justification %q not recognized", s0.Justification)
	}
	if s0.Timestamp.IsZero() {
		t.Error("statement timestamp should fall back to document timestamp")
	}
}

func TestParseOpenVEX_LegacyShape(t *testing.T) {
	// Legacy: vulnerability is a string, product is a single string field.
	doc := []byte(`{
		"@context": "https://openvex.dev/ns/v0.0.1",
		"statements": [
			{
				"vulnerability": "CVE-2026-3333",
				"product": "pkg:pypi/requests@2.30.0",
				"status": "fixed"
			}
		]
	}`)
	parsed, err := ParseVEX(doc, "legacy.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(parsed.Statements) != 1 {
		t.Fatalf("got %d statements", len(parsed.Statements))
	}
	st := parsed.Statements[0]
	if st.Vulnerability != "CVE-2026-3333" || st.Status != VEXFixed {
		t.Errorf("unexpected statement: %+v", st)
	}
	if len(st.Products) != 1 || st.Products[0].ID != "pkg:pypi/requests@2.30.0" {
		t.Errorf("unexpected products: %+v", st.Products)
	}
}

func TestParseOpenVEX_Subcomponents(t *testing.T) {
	doc := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": [
			{
				"vulnerability": {"name": "CVE-2026-4444"},
				"products": [{
					"@id": "pkg:oci/myapp@sha256:abc",
					"subcomponents": [{"@id": "pkg:npm/leftpad@1.0.0"}]
				}],
				"status": "not_affected",
				"justification": "vulnerable_code_not_in_execute_path"
			}
		]
	}`)
	parsed, err := ParseVEX(doc, "sub.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	st := parsed.Statements[0]
	if len(st.Products) != 1 || len(st.Products[0].Subcomponents) != 1 {
		t.Fatalf("subcomponents not parsed: %+v", st.Products)
	}
}

func TestParseCSAF(t *testing.T) {
	doc := []byte(`{
		"document": {
			"category": "csaf_vex",
			"title": "Acme VEX",
			"tracking": {"current_release_date": "2026-02-02T00:00:00Z"}
		},
		"product_tree": {
			"full_product_names": [
				{"product_id": "PID-1", "name": "lodash 4.17.20",
				 "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.20"}},
				{"product_id": "PID-2", "name": "requests 2.30.0",
				 "product_identification_helper": {"purl": "pkg:pypi/requests@2.30.0"}}
			]
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2026-5555",
				"product_status": {
					"known_not_affected": ["PID-1"],
					"known_affected": ["PID-2"]
				},
				"flags": [
					{"label": "component_not_present", "product_ids": ["PID-1"]}
				]
			}
		]
	}`)
	parsed, err := ParseVEX(doc, "csaf.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if parsed.Format != "csaf" {
		t.Fatalf("format = %q, want csaf", parsed.Format)
	}
	if len(parsed.Statements) != 2 {
		t.Fatalf("got %d statements, want 2", len(parsed.Statements))
	}
	var na, aff *VEXStatement
	for i := range parsed.Statements {
		switch parsed.Statements[i].Status {
		case VEXNotAffected:
			na = &parsed.Statements[i]
		case VEXAffected:
			aff = &parsed.Statements[i]
		}
	}
	if na == nil || aff == nil {
		t.Fatalf("expected one not_affected and one affected statement")
	}
	if na.Products[0].purl.name != "lodash" {
		t.Errorf("not_affected product purl = %+v", na.Products[0].purl)
	}
	if na.Justification != JustificationComponentNotPresent {
		t.Errorf("justification = %q", na.Justification)
	}
	if na.Timestamp.IsZero() {
		t.Error("csaf statement should inherit the document release date")
	}
}

func TestParseVEX_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"invalid json":      []byte(`{not json`),
		"empty":             []byte(``),
		"unknown format":    []byte(`{"foo": "bar"}`),
		"truncated openvex": []byte(`{"statements": [`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseVEX(data, name); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestParseOpenVEX_SkipsBadStatements(t *testing.T) {
	// A document whose individual statements are unusable (unknown status, missing
	// product) parses without error but yields no usable statements.
	doc := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": [
			{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:npm/x@1"}], "status": "bogus_status"},
			{"vulnerability": {"name": "CVE-2"}, "status": "not_affected"},
			{"products": [{"@id": "pkg:npm/x@1"}], "status": "fixed"}
		]
	}`)
	parsed, err := ParseVEX(doc, "partial.json")
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if len(parsed.Statements) != 0 {
		t.Fatalf("expected 0 usable statements, got %d: %+v", len(parsed.Statements), parsed.Statements)
	}
}

func TestParsePurl(t *testing.T) {
	tests := []struct {
		in   string
		typ  string
		ns   string
		name string
		ver  string
		ok   bool
	}{
		{"pkg:npm/lodash@4.17.20", "npm", "", "lodash", "4.17.20", true},
		{"pkg:npm/%40scope/pkg@1.2.3", "npm", "@scope", "pkg", "1.2.3", true},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3", true},
		{"pkg:pypi/requests", "pypi", "", "requests", "", true},
		{"pkg:npm/lodash@4.17.20?arch=x64#sub", "npm", "", "lodash", "4.17.20", true},
		{"not-a-purl", "", "", "", "", false},
	}
	for _, tc := range tests {
		got, ok := parsePurl(tc.in)
		if ok != tc.ok {
			t.Errorf("parsePurl(%q) ok=%v want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.typ != tc.typ || got.namespace != tc.ns || got.name != tc.name || got.version != tc.ver {
			t.Errorf("parsePurl(%q) = %+v, want {%s %s %s %s}", tc.in, got, tc.typ, tc.ns, tc.name, tc.ver)
		}
	}
}

func TestMatchStatement_ProductAndVersion(t *testing.T) {
	art := Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Digest: "sha256:d"}
	finding := Vulnerability{ID: "CVE-2026-1111", Component: "pkg:npm/lodash@4.17.20", Package: "lodash", Version: "4.17.20"}

	// Version-pinned statement matches the same version.
	st := VEXStatement{Vulnerability: "CVE-2026-1111", Status: VEXNotAffected,
		Products: []VEXProductRef{newProductRef("pkg:npm/lodash@4.17.20", "")}}
	if _, ok := matchStatement([]VEXStatement{st}, art, finding); !ok {
		t.Error("expected match for same version")
	}

	// Version-pinned statement does NOT match a different version.
	other := Artifact{Ecosystem: "npm", Name: "lodash", Version: "5.0.0"}
	otherFinding := Vulnerability{ID: "CVE-2026-1111", Component: "pkg:npm/lodash@5.0.0", Package: "lodash", Version: "5.0.0"}
	if _, ok := matchStatement([]VEXStatement{st}, other, otherFinding); ok {
		t.Error("did not expect match across versions")
	}

	// Version-agnostic statement (no @version) matches any version.
	anyVer := VEXStatement{Vulnerability: "CVE-2026-1111", Status: VEXNotAffected,
		Products: []VEXProductRef{newProductRef("pkg:npm/lodash", "")}}
	if _, ok := matchStatement([]VEXStatement{anyVer}, other, otherFinding); !ok {
		t.Error("expected version-agnostic statement to match")
	}
}

func TestMatchStatement_AliasCorrelation(t *testing.T) {
	art := Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	// Statement is keyed by GHSA; finding is keyed by CVE with the GHSA as alias.
	st := VEXStatement{Vulnerability: "GHSA-aaaa-bbbb-cccc", Status: VEXNotAffected,
		Products: []VEXProductRef{newProductRef("pkg:npm/lodash@4.17.20", "")}}
	finding := Vulnerability{ID: "CVE-2026-1111", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
		Component: "pkg:npm/lodash@4.17.20", Package: "lodash", Version: "4.17.20"}
	if _, ok := matchStatement([]VEXStatement{st}, art, finding); !ok {
		t.Error("expected alias-based correlation to match")
	}
}

func TestMatchStatement_NewestWins(t *testing.T) {
	art := Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	finding := Vulnerability{ID: "CVE-2026-1111", Component: "pkg:npm/lodash@4.17.20", Package: "lodash", Version: "4.17.20"}
	older := VEXStatement{Vulnerability: "CVE-2026-1111", Status: VEXNotAffected,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Products:  []VEXProductRef{newProductRef("pkg:npm/lodash@4.17.20", "")}}
	newer := VEXStatement{Vulnerability: "CVE-2026-1111", Status: VEXAffected,
		Timestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Products:  []VEXProductRef{newProductRef("pkg:npm/lodash@4.17.20", "")}}
	got, ok := matchStatement([]VEXStatement{older, newer}, art, finding)
	if !ok {
		t.Fatal("expected a match")
	}
	if got.Status != VEXAffected {
		t.Errorf("newest statement should win; got status %q", got.Status)
	}
}

func TestMatchStatement_Subcomponent(t *testing.T) {
	// Product is the OCI image; the statement narrows to a vulnerable subcomponent.
	art := Artifact{Ecosystem: "oci", Name: "myapp", Version: "1.0", Digest: "sha256:img"}
	st := VEXStatement{Vulnerability: "CVE-2026-4444", Status: VEXNotAffected,
		Products: []VEXProductRef{{
			ID:            "sha256:img",
			Subcomponents: []VEXProductRef{newProductRef("pkg:npm/leftpad@1.0.0", "")},
		}},
	}
	// A finding on the named subcomponent matches.
	hit := Vulnerability{ID: "CVE-2026-4444", Component: "pkg:npm/leftpad@1.0.0", Package: "leftpad", Version: "1.0.0"}
	if _, ok := matchStatement([]VEXStatement{st}, art, hit); !ok {
		t.Error("expected subcomponent match")
	}
	// A finding on a different subcomponent does not match.
	miss := Vulnerability{ID: "CVE-2026-4444", Component: "pkg:npm/other@2.0.0", Package: "other", Version: "2.0.0"}
	if _, ok := matchStatement([]VEXStatement{st}, art, miss); ok {
		t.Error("did not expect match for unlisted subcomponent")
	}
}

func TestEscalateSeverity(t *testing.T) {
	tests := []struct {
		in   Severity
		want Severity
	}{
		{SeverityLow, SeverityHigh},
		{SeverityMedium, SeverityHigh},
		{SeverityHigh, SeverityCritical},
		{SeverityCritical, SeverityCritical},
		{SeverityUnknown, SeverityHigh},
	}
	for _, tc := range tests {
		if got := escalateSeverity(tc.in); got != tc.want {
			t.Errorf("escalateSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
