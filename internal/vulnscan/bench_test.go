package vulnscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// Benchmarks for the vulnscan hot paths invoked on the cache-fill/admission
// path: Package-URL rendering (run for the primary component and every embedded
// dependency of every scanned artifact) and SBOM extraction (gzip+tar decode and
// manifest parse). See docs/performance.md for baselines.

func BenchmarkPackageURL(b *testing.B) {
	cases := []struct{ eco, name, version string }{
		{"npm", "@angular/core", "17.3.0"},
		{"go", "github.com/prometheus/client_golang", "v1.19.0"},
		{"pip", "requests", "2.31.0"},
		{"nuget", "Newtonsoft.Json", "13.0.3"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := cases[i%len(cases)]
		_ = PackageURL(c.eco, c.name, c.version)
	}
}

// npmTarball builds a minimal, valid npm package tarball (gzip+tar) carrying a
// package.json with the given number of declared dependencies, so the Extract
// benchmark exercises the real archive-decode + manifest-parse path.
func npmTarball(b *testing.B, deps int) []byte {
	b.Helper()
	var pj bytes.Buffer
	pj.WriteString(`{"name":"@acme/widget","version":"1.2.3","dependencies":{`)
	for i := 0; i < deps; i++ {
		if i > 0 {
			pj.WriteByte(',')
		}
		pj.WriteString(`"dep-`)
		pj.WriteString(itoa(i))
		pj.WriteString(`":"^1.0.0"`)
	}
	pj.WriteString("}}")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := pj.Bytes()
	if err := tw.WriteHeader(&tar.Header{
		Name:     "package/package.json",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		b.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		b.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func BenchmarkExtractNPM(b *testing.B) {
	for _, deps := range []int{1, 25, 200} {
		tarball := npmTarball(b, deps)
		art := Artifact{Ecosystem: "npm", Name: "@acme/widget", Version: "1.2.3", Filename: "widget-1.2.3.tgz"}
		b.Run(itoa(deps)+"deps", func(b *testing.B) {
			b.SetBytes(int64(len(tarball)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sbom, err := Extract(art, bytes.NewReader(tarball))
				if err != nil {
					b.Fatal(err)
				}
				if sbom == nil {
					b.Fatal("nil sbom")
				}
			}
		})
	}
}

// BenchmarkExtractMetadataOnly isolates the coordinate-only path (no content):
// the floor cost of producing a primary-component SBOM for every scanned pull.
func BenchmarkExtractMetadataOnly(b *testing.B) {
	art := Artifact{Ecosystem: "pip", Name: "requests", Version: "2.31.0"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Extract(art, nil); err != nil {
			b.Fatal(err)
		}
	}
}
