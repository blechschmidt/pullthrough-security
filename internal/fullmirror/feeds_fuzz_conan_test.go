//go:build fuzz
// +build fuzz

// Fuzz targets for the conan feed's parsers (Task 190): the remote's recipe
// search, revision pointers, file lists and package search, the "binaries"
// option, the version order, and the paths of the recipe repository. None of
// them may panic; what they accept must stay bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzConanSearch$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/conan"
)

func conanFuzzSeeds(f *testing.F, prefix string) {
	entries, _ := os.ReadDir(filepath.Join("testdata", "feeds", "conan"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "conan", e.Name())); err == nil {
				f.Add(data)
			}
		}
	}
}

func FuzzConanSearch(f *testing.F) {
	conanFuzzSeeds(f, "search-")
	for _, s := range []string{``, `{}`, `{"results":null}`, `{"results":"zlib/1.0"}`, `{"results":["zlib/1.0","zlib/1.0@_/_","zlib/1.0@u/c","zlib/../x",1]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := conanParseSearch("zlib", data)
		if err != nil {
			return
		}
		if len(vs) > conanMaxVersions {
			t.Fatalf("%d versions", len(vs))
		}
		seen := map[string]bool{}
		for i, v := range vs {
			if !conanValidPart(v) || seen[v] {
				t.Fatalf("version %q", v)
			}
			seen[v] = true
			if i > 0 && conanVersionCompare(vs[i-1], v) > 0 {
				t.Fatalf("%q before %q", vs[i-1], v)
			}
			if _, ok := conan.RecipeLatestPath("zlib", v); !ok {
				t.Fatalf("version %q has no path", v)
			}
		}
	})
}

func FuzzConanRevision(f *testing.F) {
	conanFuzzSeeds(f, "latest-")
	conanFuzzSeeds(f, "pkglatest-")
	for _, s := range []string{``, `{"revision":""}`, `{"revision":"../x"}`, `{"revision":"ABC"}`, `{"revision":"abc","time":5}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := conanParseRevision(data)
		if err != nil {
			return
		}
		if !conanValidHex(r.id) {
			t.Fatalf("revision %q", r.id)
		}
	})
}

func FuzzConanFiles(f *testing.F) {
	conanFuzzSeeds(f, "files-")
	conanFuzzSeeds(f, "pkgfiles-")
	for _, s := range []string{``, `{"files":null}`, `{"files":[]}`, `{"files":{"a/b":{},"..":{},"conanfile.py":1}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		files, err := conanParseFiles(data)
		if err != nil {
			return
		}
		if len(files) > conanMaxFiles || !sort.StringsAreSorted(files) {
			t.Fatalf("%d files", len(files))
		}
		for _, name := range files {
			p, ok := conan.RecipeFilePath("zlib", "1.0", "abc", name)
			if !conanValidFile(name) || !ok || !validArtifactPath(p) {
				t.Fatalf("file %q (%q %v)", name, p, ok)
			}
		}
	})
}

func FuzzConanPackages(f *testing.F) {
	conanFuzzSeeds(f, "pkgsearch-")
	for _, s := range []string{``, `[]`, `{"x":{}}`, `{"abc":{"settings":{"os":1,"arch":"x"},"options":null}}`} {
		f.Add([]byte(s))
	}
	filter, _ := conanParseBinaries("os=Linux,arch=x86_64;options.shared=True")
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, err := conanParsePackages(data)
		if err != nil {
			return
		}
		if len(pkgs) > conanMaxPackages {
			t.Fatalf("%d packages", len(pkgs))
		}
		for i, p := range pkgs {
			if !conanValidHex(p.id) || (i > 0 && pkgs[i-1].id >= p.id) {
				t.Fatalf("package %q", p.id)
			}
			_ = filter.selects(p)
		}
	})
}

func FuzzConanBinaries(f *testing.F) {
	for _, s := range []string{"", "none", "all", "ALL", "os=Linux", "os=Linux,arch=x86_64;os=Macos,arch=armv8", "options.shared=True",
		"os", "=x", "os=a=b", ";;", "os=Linux;", "options.=x", "a..b=c"} {
		f.Add(s)
	}
	pkg := conanPackage{id: "ab", settings: map[string]string{"os": "Linux", "arch": "x86_64"}, options: map[string]string{"shared": "True"}}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := conanParseBinaries(s)
		if err != nil {
			return
		}
		if b.mode == conanBinariesFilter && (len(b.any) == 0 || len(b.any) > conanMaxAlternatives) {
			t.Fatalf("%q: %d alternatives", s, len(b.any))
		}
		_ = b.selects(pkg)
	})
}

func FuzzConanVersionCompare(f *testing.F) {
	for _, p := range [][2]string{{"1.0", "1.0.0"}, {"1.0-alpha", "1.0"}, {"1.10", "1.9"}, {"1+b", "1"}, {"cci.2023", "1.0"},
		{"1-a-b+c+d", "1-a"}, {"", "."}, {"0001", "1"}} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := conanVersionCompare(a, b), conanVersionCompare(b, a)
		if (ab < 0) != (ba > 0) || (ab == 0) != (ba == 0) || (ab == 0) != (a == b) {
			t.Fatalf("%q vs %q: %d, reversed %d", a, b, ab, ba)
		}
	})
}

func FuzzConanCoordinate(f *testing.F) {
	for _, s := range []string{"recipes/zlib/config.yml", "recipes/zlib/all/conanfile.py", "recipes/zlib/all/test_package/x",
		"recipes/../config.yml", "recipes//config.yml", "recipes/z", "", "docs/x"} {
		f.Add(s, uint8(gitModified))
		f.Add(s, uint8(gitDeleted))
	}
	f.Fuzz(func(t *testing.T, p string, change uint8) {
		_ = conanArea(p)
		c, ok := conanCoordinate(p, gitChange(change%4))
		if !ok {
			return
		}
		if !conanValidPart(c.Name) || !cleanName(c.Name) || c.Version != "" {
			t.Fatalf("%q gave %+v", p, c)
		}
	})
}
