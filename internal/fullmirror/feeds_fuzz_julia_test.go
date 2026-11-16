//go:build fuzz
// +build fuzz

// Fuzz targets for the julia feed's parsers (Task 190): a Pkg server's
// registry list, and the registry tarball with the Registry.toml and
// Versions.toml files in it — all of which the server (or the registry's
// maintainers) control. Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzJuliaVersionsTOML$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func juliaFuzzSeed(f *testing.F, name string) []byte {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "julia", filepath.FromSlash(name)))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func FuzzJuliaRegistries(f *testing.F) {
	f.Add(juliaFuzzSeed(f, "registries.txt"))
	f.Add([]byte("/registry/23338594-aafe-5451-b93e-139f81909106/" + strings.Repeat("a", 64) + "\n/registry/x/y\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := juliaParseRegistries(data)
		if err == nil && !juliaValidSnapshot(list) {
			t.Fatalf("list %v is not a valid snapshot", list)
		}
	})
}

func FuzzJuliaRegistryTOML(f *testing.F) {
	f.Add(juliaFuzzSeed(f, "registry/Registry.toml"))
	f.Add([]byte("uuid = 'AAAAAAAA-0000-0000-0000-000000000000'\nx = '''\n'''\n[packages]\n\"aaaaaaaa-0000-0000-0000-000000000001\" = {path=\"A/A\",name=\"A\"}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		reg, err := juliaParseRegistryTOML(data)
		if err != nil {
			return
		}
		if !juliaUUID(reg.uuid) {
			t.Fatalf("registry uuid %q", reg.uuid)
		}
		seen := map[string]bool{}
		for _, p := range reg.packages {
			if !juliaUUID(p.uuid) || !juliaIsName(p.name) || !juliaRelPath(p.path) || seen[p.uuid] {
				t.Fatalf("entry %+v", p)
			}
			seen[p.uuid] = true
		}
	})
}

func FuzzJuliaVersionsTOML(f *testing.F) {
	for _, p := range []string{"registry/A/ADTypes/Versions.toml", "registry/A/AbstractMCMC/Versions.toml", "registry/jll/P/PTI_jll/Versions.toml"} {
		f.Add(juliaFuzzSeed(f, p))
	}
	f.Add([]byte("[\"1.0\"] # x\ngit-tree-sha1 = \"\\u0041\"\nyanked = true\n['2']\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := juliaParseVersionsTOML(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, v := range vs {
			if !juliaIsVersion(v.Version) || len(v.Tree) != 40 || !juliaTreeHash(v.Tree) || seen[v.Version] {
				t.Fatalf("version %+v", v)
			}
			seen[v.Version] = true
		}
	})
}

func FuzzJuliaRegistryTarball(f *testing.F) {
	pack := func(files map[string][]byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		for name, data := range files {
			_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))})
			_, _ = tw.Write(data)
		}
		_ = tw.Close()
		_ = zw.Close()
		return buf.Bytes()
	}
	f.Add(pack(map[string][]byte{
		"Registry.toml":           juliaFuzzSeed(f, "registry/Registry.toml"),
		"E/Example/Versions.toml": juliaFuzzSeed(f, "registry/E/Example/Versions.toml"),
	}))
	f.Add(pack(map[string][]byte{"./Registry.toml": []byte("uuid = \"23338594-aafe-5451-b93e-139f81909106\"\n")}))
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, err := juliaParseRegistryTarball(bytes.NewReader(data), "23338594-aafe-5451-b93e-139f81909106")
		if err != nil {
			return
		}
		for i, p := range pkgs {
			if !juliaIsName(p.Name) || !juliaUUID(p.UUID) || len(p.Versions) == 0 || (i > 0 && pkgs[i-1].Name > p.Name) {
				t.Fatalf("package %+v", p)
			}
		}
	})
}
