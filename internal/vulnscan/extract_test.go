package vulnscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractPrimaryComponent(t *testing.T) {
	art := Artifact{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.2.3", Digest: "sha256:abc"}
	sbom, err := Extract(art, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sbom.BOMFormat != "CycloneDX" || sbom.SpecVersion != "1.5" {
		t.Errorf("unexpected bom header: %s %s", sbom.BOMFormat, sbom.SpecVersion)
	}
	if sbom.Metadata == nil || sbom.Metadata.Component == nil {
		t.Fatal("missing primary component")
	}
	pc := sbom.Metadata.Component
	if pc.Group != "@scope" || pc.Name != "pkg" || pc.Version != "1.2.3" {
		t.Errorf("primary component = %+v", pc)
	}
	if pc.PURL != "pkg:npm/%40scope/pkg@1.2.3" {
		t.Errorf("purl = %q", pc.PURL)
	}
	// Must be valid JSON and round-trip.
	b, err := json.Marshal(sbom)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"bomFormat":"CycloneDX"`)) {
		t.Error("serialized SBOM missing bomFormat")
	}
}

func TestExtractNPMDependencies(t *testing.T) {
	pkgJSON := `{"name":"demo","version":"1.0.0","dependencies":{"lodash":"^4.17.0","@scope/x":"1.2.3"},"optionalDependencies":{"fsevents":"~2.0.0"}}`
	tgz := makeTarGz(t, map[string]string{"package/package.json": pkgJSON})

	art := Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"}
	sbom, err := Extract(art, bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	names := componentNames(sbom)
	for _, want := range []string{"lodash", "x", "fsevents"} {
		if !names[want] {
			t.Errorf("missing dependency component %q; got %v", want, names)
		}
	}
	// Only the primary component (demo@1.0.0) carries a concrete version; the npm
	// dependency constraints are ranges and must not be queried for vulnerabilities.
	scannable := sbom.scannableComponents()
	if len(scannable) != 1 || scannable[0].Name != "demo" {
		t.Errorf("expected only the primary component scannable, got %+v", scannable)
	}
}

func TestExtractGoModRequires(t *testing.T) {
	gomod := `module example.com/demo

go 1.21

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/crypto v0.17.0 // indirect
)

require github.com/spf13/cobra v1.8.0
`
	zipData := makeZip(t, map[string]string{"example.com/demo@v1.0.0/go.mod": gomod})
	art := Artifact{Ecosystem: "go", Name: "example.com/demo", Version: "v1.0.0"}
	sbom, err := Extract(art, bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	// Go requires carry concrete versions, so they are scannable (plus the primary).
	scannable := sbom.scannableComponents()
	if len(scannable) != 4 {
		t.Fatalf("expected primary + 3 requires scannable, got %d: %+v", len(scannable), scannable)
	}
	names := componentNames(sbom)
	for _, want := range []string{"errors", "crypto", "cobra"} {
		if !names[want] {
			t.Errorf("missing require %q; got %v", want, names)
		}
	}
}

func TestExtractNuspec(t *testing.T) {
	nuspec := `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Demo</id>
    <version>1.0.0</version>
    <dependencies>
      <group targetFramework="net6.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" />
      </group>
    </dependencies>
  </metadata>
</package>`
	zipData := makeZip(t, map[string]string{"Demo.nuspec": nuspec})
	art := Artifact{Ecosystem: "nuget", Name: "demo", Version: "1.0.0"}
	sbom, err := Extract(art, bytes.NewReader(zipData))
	if err != nil {
		t.Fatal(err)
	}
	if !componentNames(sbom)["Newtonsoft.Json"] {
		t.Errorf("missing nuget dependency; got %v", componentNames(sbom))
	}
}

func TestExtractMalformedArchiveYieldsPrimaryOnly(t *testing.T) {
	art := Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"}
	sbom, err := Extract(art, strings.NewReader("not a tarball"))
	if err != nil {
		t.Fatal(err)
	}
	if sbom.Metadata.Component == nil {
		t.Fatal("expected primary component despite malformed archive")
	}
	if len(sbom.Components) != 0 {
		t.Errorf("expected no dependency components, got %d", len(sbom.Components))
	}
}

func TestSBOMDeterministicSerial(t *testing.T) {
	art := Artifact{Ecosystem: "pip", Name: "requests", Version: "2.31.0"}
	a, _ := Extract(art, nil)
	b, _ := Extract(art, nil)
	if a.SerialNumber != b.SerialNumber {
		t.Errorf("serial not deterministic: %s vs %s", a.SerialNumber, b.SerialNumber)
	}
	if a.SerialNumber == "" {
		t.Error("empty serial number")
	}
}

// --- helpers ----------------------------------------------------------------

func componentNames(sbom *SBOM) map[string]bool {
	m := make(map[string]bool)
	for _, c := range sbom.Components {
		m[c.Name] = true
	}
	return m
}

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
