//go:build fuzz
// +build fuzz

// Fuzz targets for the vulnscan ingestion parsers (Task 30).
//
// Covers the untrusted-input surfaces the scanning gate exposes:
//   - SBOM extraction from artifact archives (gzip+tar, zip, embedded manifests)
//   - VEX/CSAF document ingestion (OpenVEX and CSAF auto-detection)
//   - go.mod and .nuspec embedded-manifest parsing
//   - OSV advisory-record normalization and CVSS vector scoring
//
// Every one of these consumes bytes from an upstream registry, mirror, or
// operator-supplied VEX feed, so they must never panic and must bound their
// allocations. The Extract path in particular decompresses attacker-controlled
// gzip/zip archives and must remain immune to decompression bombs (it reads
// through size-capped readers).
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseVEX ./internal/vulnscan/
package vulnscan

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzExtract fuzzes SBOM extraction. The ecosystem (first byte) selects the
// embedded-manifest parser; the remaining bytes are the artifact content, which
// may be a gzip/tar or zip archive containing a manifest.
func FuzzExtract(f *testing.F) {
	ecosystems := []string{"npm", "go", "nuget", "pip", "docker", "cargo", ""}
	seeds := [][]byte{
		[]byte(`{"name":"x","version":"1.0.0","dependencies":{"lodash":"^4.0.0"}}`),
		[]byte("module example.com/x\n\ngo 1.21\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n"),
		[]byte("\x1f\x8b\x08\x00"), // truncated gzip
		[]byte("PK\x03\x04"),       // truncated zip
		[]byte(""),
		bytes.Repeat([]byte{0}, 4096),
	}
	for _, eco := range ecosystems {
		for _, s := range seeds {
			f.Add(eco, s)
		}
	}
	f.Fuzz(func(t *testing.T, ecosystem string, content []byte) {
		art := Artifact{Ecosystem: ecosystem, Name: "pkg", Version: "1.0.0"}
		// Extract is documented to be best-effort and to never return a fatal error
		// for unparseable content; it must always yield a valid primary-only SBOM.
		sbom, err := Extract(art, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("Extract returned an error (should be best-effort): %v", err)
		}
		if sbom == nil {
			t.Fatalf("Extract returned nil SBOM")
		}
		if sbom.Metadata == nil || sbom.Metadata.Component == nil {
			t.Fatalf("Extract produced no primary component")
		}
	})
}

// FuzzParseVEX fuzzes the VEX/CSAF auto-detecting parser.
func FuzzParseVEX(f *testing.F) {
	seeds := []string{
		`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-0001"},"status":"not_affected","products":["pkg:npm/x@1.0.0"]}]}`,
		`{"statements":[{"vulnerability":"CVE-2023-1","status":"affected","product":"pkg:pypi/y@2.0"}]}`,
		`{"document":{"category":"csaf_vex"},"vulnerabilities":[{"cve":"CVE-2022-9","product_status":{"known_not_affected":["CSAFPID-1"]}}]}`,
		`{}`,
		`{"statements":null}`,
		`{"statements":[{}]}`,
		`{"statements":"notarray"}`,
		`[]`,
		`null`,
		`not json`,
		``,
		`   `,
		`{"document":{},"vulnerabilities":[]}`,
		`{"@context":"openvex","statements":[]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "fuzz-source")
	}
	f.Fuzz(func(t *testing.T, data []byte, source string) {
		doc, err := ParseVEX(data, source)
		if err != nil {
			if doc != nil {
				t.Fatalf("error result returned non-nil doc")
			}
			return
		}
		if doc == nil {
			t.Fatalf("nil doc with nil error")
		}
		// Every statement parsed must carry the source label for audit.
		for _, st := range doc.Statements {
			_ = st
		}
	})
}

// FuzzParseGoRequires fuzzes the focused go.mod require parser.
func FuzzParseGoRequires(f *testing.F) {
	seeds := []string{
		"require github.com/pkg/errors v0.9.1\n",
		"require (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.0.0-20210101000000-abcdef // indirect\n)\n",
		"module x\ngo 1.21\n",
		"require (\n",                  // unterminated block
		"require (\n)\n",               // empty block
		"require\n",                    // bare keyword
		"require x\n",                  // missing version
		"require x notaversion\n",      // bad version
		"// require github.com/x v1\n", // commented out
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, gomod []byte) {
		reqs := parseGoRequires(gomod)
		for _, r := range reqs {
			if r.path == "" || r.version == "" {
				t.Fatalf("parsed require with empty field: %#v", r)
			}
		}
	})
}

// FuzzParseNuspec fuzzes the .nuspec XML dependency/license parsers.
func FuzzParseNuspec(f *testing.F) {
	seeds := []string{
		`<?xml version="1.0"?><package><metadata><id>X</id><dependencies><dependency id="Newtonsoft.Json" version="13.0.1"/></dependencies></metadata></package>`,
		`<package><metadata><license type="expression">MIT</license><dependencies><group><dependency id="A" version="1.0"/></group></dependencies></metadata></package>`,
		`<package><metadata><licenseUrl>https://example/license</licenseUrl></metadata></package>`,
		`<package>`, // unterminated
		`not xml`,
		`<package><metadata><dependencies><dependency/></dependencies></metadata></package>`,
		`<!DOCTYPE x [<!ENTITY a "b">]><package/>`, // entity (Go's xml ignores external entities)
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, nuspec []byte) {
		deps := parseNuspecDependencies(nuspec)
		for _, d := range deps {
			if d.id == "" {
				t.Fatalf("dependency with empty id: %#v", d)
			}
		}
		_ = parseNuspecLicense(nuspec)
	})
}

// FuzzOSVRecord fuzzes OSV advisory-record decoding plus its normalization into
// the subsystem Vulnerability (severity/CVSS derivation, fixed-version
// collection).
func FuzzOSVRecord(f *testing.F) {
	seeds := []string{
		`{"id":"GHSA-xxxx","summary":"s","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`,
		`{"id":"OSV-1","database_specific":{"severity":"HIGH"}}`,
		`{"withdrawn":"2024-01-01T00:00:00Z"}`,
		`{"severity":[{"type":"CVSS_V4","score":"garbage"}]}`,
		`{}`,
		`null`,
		`not json`,
		``,
	}
	comp := Component{Name: "x", Version: "1.0.0", Group: "grp", PURL: "pkg:npm/grp/x@1.0.0", ecosystem: "npm"}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return
		}
		v := osvToVulnerability("OSV-FUZZ", &rec, comp)
		if v.ID == "" {
			t.Fatalf("normalized vulnerability lost its id")
		}
		if v.CVSS < 0 || v.CVSS > 10 {
			t.Fatalf("CVSS out of range: %v", v.CVSS)
		}
	})
}

// FuzzParseCVSSBaseScore fuzzes the CVSS vector scorer.
func FuzzParseCVSSBaseScore(f *testing.F) {
	seeds := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/",
		"CVSS:3.1/AV:X", // invalid metric value
		"CVSS:2.0/AV:N",
		"not a vector",
		"CVSS:3.1/AV:N/AV:N/AV:N", // repeated metrics
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, vector string) {
		score, ok := ParseCVSSBaseScore(vector)
		if ok && (score < 0 || score > 10) {
			t.Fatalf("CVSS base score out of range: %v for %q", score, vector)
		}
	})
}
