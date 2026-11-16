//go:build fuzz
// +build fuzz

// Fuzz targets for the jsr feed's parsers (Task 191): a page of the package
// list, a package's meta.json, a version's manifest, and the file lists the
// adapter keeps on disk. None of them may panic; what they accept must stay
// bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzJSRList$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/jsr"
	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

func FuzzJSRList(f *testing.F) {
	for _, name := range []string{"packages-limit3-page1.json", "packages-limit3-page2.json", "packages-limit3-past-end.json", "packages-page-trimmed.json"} {
		f.Add(fixture(f, "jsr", name))
	}
	f.Add([]byte(`{"items":[{"scope":"a","name":"b","latestVersion":"1.0.0/x","versionCount":-3,"updatedAt":"\u0000"}]}`))
	f.Add([]byte(`{"items":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		items, err := jsrParseList(data)
		if err != nil {
			return
		}
		for _, it := range items {
			r, ok := it.record()
			if !ok {
				continue
			}
			if !r.valid() || r.Version != "" || r.Path != "" || !strings.HasPrefix(r.Name, "@") {
				t.Fatalf("record %+v", r)
			}
			scope, pkg, ok := jsrSplitName(r.Name)
			if !ok || scope != it.Scope || pkg != it.Name {
				t.Fatalf("%s does not split back", r.Name)
			}
		}
	})
}

func FuzzJSRMeta(f *testing.F) {
	for _, name := range []string{"meta-std-fmt.json", "meta-luca-flag.json", "meta-std-path.json"} {
		f.Add(fixture(f, "jsr", name))
	}
	f.Add([]byte(`{"versions":{"1.0.0":{"yanked":"yes","createdAt":5},"..":{},"":{}}}`))
	scheme, _ := versions.For("npm")
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := jsrParseMeta(data, "std", "fmt")
		if err != nil {
			return
		}
		if len(vs) > jsrMaxVersions {
			t.Fatalf("%d versions", len(vs))
		}
		seen := map[string]bool{}
		var parsed []versions.Version
		for _, v := range vs {
			if !jsrValidVersion(v.version) || seen[v.version] {
				t.Fatalf("version %q", v.version)
			}
			seen[v.version] = true
			if p, err := scheme.Parse(v.version); err == nil {
				parsed = append(parsed, p)
			}
		}
		if !sort.SliceIsSorted(parsed, func(i, j int) bool { return scheme.Compare(parsed[i], parsed[j]) < 0 }) {
			t.Fatalf("versions out of order: %+v", vs)
		}
	})
}

func FuzzJSRManifest(f *testing.F) {
	for _, name := range []string{"std-fmt-1.0.10_meta.json", "luca-flag-1.0.1_meta.json", "std-path-1.1.6_meta.json"} {
		f.Add(fixture(f, "jsr", name))
	}
	f.Add([]byte(`{"manifest":{"/../x":{"size":1},"//a":{"size":-1},"/a\u0000b":{"size":2},"/ok":{"size":"x"}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		fl, err := jsrParseManifest(data, "std", "fmt", "1.0.0")
		if err != nil {
			return
		}
		if len(fl) > jsrMaxFiles || !sort.SliceIsSorted(fl, func(i, j int) bool { return fl[i].Path < fl[j].Path }) {
			t.Fatalf("%d files", len(fl))
		}
		for _, file := range fl {
			p, ok := jsr.ModuleFilePath("std", "fmt", "1.0.0", file.Path)
			if !ok || !validArtifactPath(p) || file.Size < 0 {
				t.Fatalf("file %+v", file)
			}
		}
	})
}

// FuzzJSRFileCache feeds arbitrary bytes to the reader of a stored file list
// (a damaged or planted state file): it is an empty list or one of valid
// versions, never a panic.
func FuzzJSRFileCache(f *testing.F) {
	f.Add([]byte(`{"format":"jsr-files/1","name":"@big/pkg","versions":{"1.0.0":[["/mod.ts",3]],"bad/1":[["/x",1]]}}`))
	f.Add([]byte(`{"format":"jsr-files/1","name":"@big/pkg","versions":{"1.0.0":[["/mod.ts"]]}}`))
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		feed := &jsrFeed{cache: files{dir: dir}}
		if err := os.WriteFile(filepath.Join(dir, jsrCacheName("@big/pkg")), data, 0o644); err != nil {
			t.Fatal(err)
		}
		c := feed.loadCache("@big/pkg")
		if c == nil || c.Name != "@big/pkg" || c.Versions == nil {
			t.Fatalf("%+v", c)
		}
		for v, fl := range c.Versions {
			if !jsrValidVersion(v) || len(fl) > jsrMaxFiles {
				t.Fatalf("version %q with %d files", v, len(fl))
			}
		}
	})
}
