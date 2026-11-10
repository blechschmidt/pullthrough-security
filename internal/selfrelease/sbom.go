package selfrelease

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// findSBOM locates the SBOM(s) for the binary. Both CycloneDX and SPDX JSON are
// accepted under the common suffix conventions syft/cyclonedx/trivy use.
func findSBOM(dir, binaryBase string) []string {
	return glob(dir,
		binaryBase+".sbom.json", binaryBase+".sbom.cdx.json", binaryBase+".sbom.spdx.json",
		binaryBase+".cdx.json", binaryBase+".spdx.json",
		binaryBase+".bom.json",
		"sbom.json", "sbom.cdx.json", "sbom.spdx.json",
	)
}

// sbomProbe is the union of fields that identify an SBOM's format and let us
// confirm it describes this binary.
type sbomProbe struct {
	// CycloneDX
	BOMFormat  string `json:"bomFormat"`
	SpecVer    string `json:"specVersion"`
	Components []struct {
		Name   string `json:"name"`
		Hashes []struct {
			Alg     string `json:"alg"`
			Content string `json:"content"`
		} `json:"hashes"`
	} `json:"components"`
	Metadata struct {
		Component struct {
			Name   string `json:"name"`
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"component"`
	} `json:"metadata"`
	// SPDX
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name      string `json:"name"`
		Checksums []struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"checksumValue"`
		} `json:"checksums"`
	} `json:"packages"`
}

func (p *sbomProbe) format() string {
	if strings.EqualFold(p.BOMFormat, "CycloneDX") {
		return "CycloneDX " + p.SpecVer
	}
	if p.SPDXVersion != "" {
		return p.SPDXVersion
	}
	return ""
}

// referencesDigest reports whether the SBOM records the wanted sha256 hex on any
// component/package (including the top-level metadata component).
func (p *sbomProbe) referencesDigest(wantHex string) bool {
	match := func(alg, val string) bool {
		a := strings.ToLower(strings.ReplaceAll(alg, "-", ""))
		return a == "sha256" && strings.EqualFold(strings.TrimSpace(val), wantHex)
	}
	for _, h := range p.Metadata.Component.Hashes {
		if match(h.Alg, h.Content) {
			return true
		}
	}
	for _, c := range p.Components {
		for _, h := range c.Hashes {
			if match(h.Alg, h.Content) {
				return true
			}
		}
	}
	for _, pk := range p.Packages {
		for _, c := range pk.Checksums {
			if match(c.Algorithm, c.Value) {
				return true
			}
		}
	}
	return false
}

// verifySBOM confirms an SBOM is present, parses as a known format, and is bound
// to this release: either it records the binary's digest, or (the common case,
// since an SBOM typically hashes the source tree / module graph rather than the
// final binary) the SBOM file is itself listed in the signed checksums manifest,
// so the signature transitively covers it.
func verifySBOM(dir, binaryBase, binaryDigest string, checksums map[string]checksumEntry) Check {
	const name = "sbom"

	files := findSBOM(dir, binaryBase)
	if len(files) == 0 {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("no SBOM found in %s (expected %s.sbom.json / .cdx.json / .spdx.json)", dir, binaryBase)}
	}

	wantHex := bareHex(binaryDigest)
	var lastErr string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		var probe sbomProbe
		if err := json.Unmarshal(data, &probe); err != nil {
			lastErr = "parsing SBOM: " + err.Error()
			continue
		}
		format := probe.format()
		if format == "" {
			lastErr = fmt.Sprintf("%s is not a recognized CycloneDX or SPDX SBOM", baseOf(f))
			continue
		}

		base := baseOf(f)
		// Binding (a): the SBOM directly records the binary digest.
		if probe.referencesDigest(wantHex) {
			return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("%s (%s) records this binary's digest", base, format)}
		}
		// Binding (b): the SBOM file is covered by the signed checksums manifest.
		if ent, ok := checksums[base]; ok {
			if gotHex, herr := hashFile(f); herr == nil && bareHex(gotHex) == ent.Hex {
				return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("%s (%s) present and covered by the signed checksums manifest", base, format)}
			}
			return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%s is listed in the checksums manifest but its content does not match the listed digest", base)}
		}
		lastErr = fmt.Sprintf("%s (%s) is present but neither records the binary digest nor is listed in the signed checksums manifest", base, format)
	}

	return Check{Name: name, Status: StatusFail, Detail: "SBOM could not be bound to this release: " + lastErr}
}
