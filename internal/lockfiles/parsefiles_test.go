package lockfiles

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestParseFilesMatchesGolden: the files of every fixture, handed over in
// memory, come out of ParseFiles exactly as the golden file (which the tree
// walk is held to as well) says. Fixtures with submodules are left out: their
// gitlinks are in the tree, which ParseFiles does not have.
func TestParseFilesMatchesGolden(t *testing.T) {
	for _, name := range fixtureNames(t) {
		dir := filepath.Join("testdata/fixtures", name)
		if _, err := os.Stat(filepath.Join(dir, gitmodulesPath)); err == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			files := map[string][]byte{}
			err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(dir, p)
				data, err := os.ReadFile(p)
				files[filepath.ToSlash(rel)] = data
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata/golden", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if got := marshalFiles(t, ParseFiles(nil, goldenProxy, files)); !bytes.Equal(got, want) {
				t.Errorf("ParseFiles differs from the golden file\n%s", firstDiff(string(want), string(got)))
			}
		})
	}
}

// TestParseFilesMergesPairsPerDirectory: go.mod and go.sum are merged within
// their directory only, undetected paths are passed over, and the files come
// back by path.
func TestParseFilesMergesPairsPerDirectory(t *testing.T) {
	sum := "rsc.io/quote v1.5.2 h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=\n" +
		"rsc.io/quote v1.5.2/go.mod h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=\n"
	files := map[string][]byte{
		"svc/go.sum":   []byte(sum),
		"svc/go.mod":   []byte("module example.com/svc\n\ngo 1.22\n\nrequire rsc.io/quote v1.5.2\n"),
		"other/go.mod": []byte("module example.com/other\n\ngo 1.22\n\nrequire rsc.io/quote v1.5.2\n"),
		"README.md":    []byte("# not a lock file\n"),
	}
	got := ParseFiles(nil, nil, files)
	var paths []string
	for _, f := range got {
		paths = append(paths, f.Path)
	}
	if want := []string{"other/go.mod", "svc/go.mod", "svc/go.sum"}; !slices.Equal(paths, want) {
		t.Fatalf("paths %v, want %v", paths, want)
	}
	other, mod, gosum := got[0], got[1], got[2]
	if len(other.Dependencies) != 1 || len(other.Dependencies[0].Digests) != 0 || !other.Dependencies[0].Unverified {
		t.Errorf("a go.mod without a go.sum next to it: %+v", other.Dependencies)
	}
	if len(mod.Dependencies) != 1 || len(mod.Dependencies[0].Digests) != 2 || mod.Dependencies[0].Unverified {
		t.Errorf("go.mod did not get the hashes of the go.sum next to it: %+v", mod.Dependencies)
	}
	if len(gosum.Dependencies) != 0 {
		t.Errorf("go.sum keeps the module go.mod requires: %+v", gosum.Dependencies)
	}
	if ParseFiles(nil, nil, nil) != nil {
		t.Error("no files should give no result")
	}
}
