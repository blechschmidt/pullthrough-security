package vulnscan

import (
	"bytes"
	"testing"
)

// primaryLicense extracts the primary component's license expression from an
// artifact's SBOM.
func primaryLicense(t *testing.T, art Artifact, content []byte) string {
	t.Helper()
	sbom, err := Extract(art, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if sbom.Metadata == nil || sbom.Metadata.Component == nil {
		t.Fatal("no primary component")
	}
	return sbom.Metadata.Component.LicenseExpression()
}

func TestExtractLicense_NPM(t *testing.T) {
	cases := []struct {
		name    string
		pkgJSON string
		want    string
	}{
		{"spdx-string", `{"name":"x","version":"1.0.0","license":"MIT"}`, "MIT"},
		{"spdx-expression", `{"name":"x","version":"1.0.0","license":"(MIT OR Apache-2.0)"}`, "(MIT OR Apache-2.0)"},
		{"deprecated-object", `{"name":"x","version":"1.0.0","license":{"type":"ISC","url":"http://x"}}`, "ISC"},
		{"legacy-array", `{"name":"x","version":"1.0.0","licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`, "MIT OR Apache-2.0"},
		{"none", `{"name":"x","version":"1.0.0"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgz := makeTarGz(t, map[string]string{"package/package.json": tc.pkgJSON})
			got := primaryLicense(t, Artifact{Ecosystem: "npm", Name: "x", Version: "1.0.0"}, tgz)
			if got != tc.want {
				t.Errorf("license = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractLicense_NuGet(t *testing.T) {
	withExpr := `<?xml version="1.0"?>
<package><metadata>
  <id>Pkg</id><version>1.0.0</version>
  <license type="expression">Apache-2.0</license>
</metadata></package>`
	zip := makeZip(t, map[string]string{"Pkg.nuspec": withExpr})
	if got := primaryLicense(t, Artifact{Ecosystem: "nuget", Name: "Pkg", Version: "1.0.0"}, zip); got != "Apache-2.0" {
		t.Errorf("nuget expression license = %q, want Apache-2.0", got)
	}

	// A license *file* reference is not a usable SPDX id -> undeclared.
	withFile := `<?xml version="1.0"?>
<package><metadata>
  <id>Pkg</id><version>1.0.0</version>
  <license type="file">LICENSE.txt</license>
</metadata></package>`
	zip = makeZip(t, map[string]string{"Pkg.nuspec": withFile})
	if got := primaryLicense(t, Artifact{Ecosystem: "nuget", Name: "Pkg", Version: "1.0.0"}, zip); got != "" {
		t.Errorf("nuget file license = %q, want empty (NOASSERTION)", got)
	}
}

func TestExtractLicense_PyPIWheel(t *testing.T) {
	// PEP 639 License-Expression header takes precedence.
	meta := "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0.0\nLicense-Expression: BSD-3-Clause\n\nThe long description.\n"
	zip := makeZip(t, map[string]string{"pkg-1.0.0.dist-info/METADATA": meta})
	if got := primaryLicense(t, Artifact{Ecosystem: "pip", Name: "pkg", Version: "1.0.0"}, zip); got != "BSD-3-Clause" {
		t.Errorf("wheel License-Expression = %q, want BSD-3-Clause", got)
	}

	// Fall back to trove classifiers when no expression is present.
	meta = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n" +
		"Classifier: License :: OSI Approved :: Apache Software License\n" +
		"Classifier: Programming Language :: Python\n\nbody"
	zip = makeZip(t, map[string]string{"pkg-1.0.0.dist-info/METADATA": meta})
	if got := primaryLicense(t, Artifact{Ecosystem: "pip", Name: "pkg", Version: "1.0.0"}, zip); got != "Apache-2.0" {
		t.Errorf("wheel classifier = %q, want Apache-2.0", got)
	}
}

func TestExtractLicense_PyPISdist(t *testing.T) {
	meta := "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\nLicense: MIT\n\nbody"
	tgz := makeTarGz(t, map[string]string{"pkg-1.0.0/PKG-INFO": meta})
	if got := primaryLicense(t, Artifact{Ecosystem: "pip", Name: "pkg", Version: "1.0.0"}, tgz); got != "MIT" {
		t.Errorf("sdist License field = %q, want MIT", got)
	}
}

func TestLicenseExpression_MultipleRefs(t *testing.T) {
	c := Component{Licenses: []LicenseChoice{
		{License: &LicenseRef{ID: "MIT"}},
		{License: &LicenseRef{ID: "Apache-2.0"}},
	}}
	if got := c.LicenseExpression(); got != "MIT OR Apache-2.0" {
		t.Errorf("multi-ref expression = %q, want MIT OR Apache-2.0", got)
	}
}
