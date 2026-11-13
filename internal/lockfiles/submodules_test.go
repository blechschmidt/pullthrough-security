package lockfiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanPinsSubmodulesAsTheGoldenSays: a fixture with a .gitmodules is
// committed at the root of a repository of its own, with real gitlinks for
// its GITLINKS, and the scan must read it exactly as the golden file says.
func TestScanPinsSubmodulesAsTheGoldenSays(t *testing.T) {
	found := 0
	for _, name := range fixtureNames(t) {
		dir := filepath.Join("testdata/fixtures", name)
		if _, err := os.Stat(filepath.Join(dir, gitmodulesPath)); err != nil {
			continue
		}
		found++
		t.Run(name, func(t *testing.T) {
			repo := newTestRepo(t)
			repo.copyFixture(name, ".")
			repo.commit()
			for _, l := range readGitlinks(t, dir) {
				repo.git("update-index", "--add", "--cacheinfo", "160000,"+l.Commit+","+l.Path)
			}
			repo.git("commit", "--quiet", "-m", "gitlinks")
			rep := repo.scan("HEAD", Options{Proxy: goldenProxy})
			want, err := os.ReadFile(filepath.Join("testdata/golden", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if got := marshalFiles(t, rep.Files); !bytes.Equal(got, want) {
				t.Errorf("the scan differs from the golden file\n%s", firstDiff(string(want), string(got)))
			}
			if len(rep.Submodules) != len(readGitlinks(t, dir)) {
				t.Errorf("submodules %v", rep.Submodules)
			}
		})
	}
	if found == 0 {
		t.Fatal("no fixture with a .gitmodules")
	}
}

// TestSubmodulesUnderSkippedDirectoriesAndRoots: a submodule is pinned even
// inside a directory the walk skips, only submodules inside the scanned
// directory are reported, and a gitlink no .gitmodules declares is reported
// as skipped.
func TestSubmodulesUnderSkippedDirectoriesAndRoots(t *testing.T) {
	repo := newTestRepo(t)
	repo.write(".gitmodules", []byte(`[submodule "gt"]
	path = third_party/googletest
	url = https://github.com/google/googletest.git
[submodule "lib"]
	path = src/lib
	url = git@github.com:o/lib.git
[submodule "gone"]
	path = src/gone
	url = https://github.com/o/gone.git
`))
	repo.write("src/Cargo.lock", []byte("version = 3\n"))
	repo.commit()
	a, b, c := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	repo.git("update-index", "--add", "--cacheinfo", "160000,"+a+",third_party/googletest")
	repo.git("update-index", "--add", "--cacheinfo", "160000,"+b+",src/lib")
	repo.git("update-index", "--add", "--cacheinfo", "160000,"+c+",src/undeclared")
	repo.git("commit", "--quiet", "-m", "gitlinks")

	rep := repo.scan("HEAD", Options{})
	var gm *File
	for _, f := range rep.Files {
		if f.Path == gitmodulesPath {
			gm = f
		}
	}
	if gm == nil {
		t.Fatalf("no .gitmodules in %v", filePaths(rep))
	}
	got := map[string]string{}
	for _, d := range gm.Dependencies {
		got[d.Name] = d.Revision + " " + d.Registry
		if d.Type != "git" || d.Source != SourceGit || d.Version != d.Revision || d.Unverified {
			t.Errorf("submodule dependency %+v", d)
		}
	}
	if got["third_party/googletest"] != a+" https://github.com/google/googletest.git" || got["src/lib"] != b+" git@github.com:o/lib.git" || len(got) != 2 {
		t.Errorf("dependencies %v", got)
	}
	if !strings.Contains(strings.Join(gm.Warnings, "\n"), `submodule "gone": the tree has no gitlink`) {
		t.Errorf("warnings %q", gm.Warnings)
	}
	if r := skippedReasons(rep)["src/undeclared"]; !strings.Contains(r, "does not declare") {
		t.Errorf("undeclared gitlink: %q", r)
	}

	// Only the directory scanned: the root .gitmodules is read for it.
	rep = repo.scan("HEAD", Options{Root: "src"})
	paths := strings.Join(filePaths(rep), ",")
	if paths != ".gitmodules,src/Cargo.lock" {
		t.Fatalf("files %s", paths)
	}
	deps := rep.Files[0].Dependencies
	if len(deps) != 1 || deps[0].Name != "src/lib" {
		t.Errorf("dependencies under src: %+v", deps)
	}
	// A directory without submodules does not report the root .gitmodules.
	repo.write("docs/x.txt", []byte("x"))
	repo.commit()
	if rep := repo.scan("HEAD", Options{Root: "docs"}); len(rep.Files) != 0 {
		t.Errorf("files %v", filePaths(rep))
	}
}

func TestGitConfigReadsAsGitReads(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string // section/sub/key=value lines, or "error"
	}{
		{"[submodule \"a\"]\n\tpath = x\n\turl = https://h/a.git\n", `submodule/a/path=x;submodule/a/url=https://h/a.git`},
		{"[Submodule \"A b\"] Path = \"x y\" ; c\n", `submodule/A b/path=x y`},
		{"[submodule.Lower]\npath=p\n", `submodule/lower/path=p`},
		{"[s \"q\\\"\\\\\"]\nk = a\\tb\\\\c\\\"d\n", `s/q"\/k=a	b\c"d`},
		{"[s]\nk = one \\\n  two # comment\n", `s//k=one   two`},
		{"[s]\nk =   spaced   value   \n", `s//k=spaced   value`},
		{"[s]\nflag\n", `s//flag=`},
		{"[s]\r\nk = v\r\n", `s//k=v`},
		{"k = v\n", "error"},
		{"[s]\nk = \"open\n", "error"},
		{"[s]\nk = a\\x\n", "error"},
		{"[s \"x\" ]\n", "error"},
		{"[s]\nflag # comment\n", "error"},
		{"[s]\n1k = v\n", "error"},
	} {
		entries, err := parseGitConfig(c.in)
		got := ""
		if err != nil {
			got = "error"
		} else {
			var parts []string
			for _, e := range entries {
				parts = append(parts, e.section+"/"+e.sub+"/"+e.key+"="+e.value)
			}
			got = strings.Join(parts, ";")
		}
		if got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestGitmodulesRefusesWhatGitIgnores(t *testing.T) {
	in := `[submodule "ok"]
	path = ok
	url = https://h/ok.git
[submodule "../escape"]
	path = esc
	url = https://h/esc.git
[submodule "twice"]
	path = t1
	path = t2
	url = https://h/t.git
[submodule "opt"]
	path = -x
	url = https://h/o.git
[submodule "helper"]
	path = h
	url = ext::sh -c id
[submodule "local"]
	path = l
	url = /srv/git/l.git
[submodule "dup1"]
	path = same
	url = https://h/d1.git
[submodule "dup2"]
	path = same
	url = https://h/d2.git
[submodule "dots"]
	path = a/../b
	url = https://h/b.git
[submodule "scp"]
	path = scp
	url = git@github.com:o/scp.git
`
	res, err := gitmodules{}.Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, d := range res.submodules {
		paths = append(paths, d.path)
	}
	if got := strings.Join(paths, ","); got != "ok,scp" {
		t.Errorf("declarations %s", got)
	}
	if len(res.Warnings) != 7 { // dup1 and dup2 share one
		t.Errorf("warnings %d: %q", len(res.Warnings), res.Warnings)
	}
}

// TestGitDependenciesOfEveryKind: the git upstream type is covered by
// .gitmodules and by the Git dependencies of the other formats, which the
// report collects in one place.
func TestGitDependenciesOfEveryKind(t *testing.T) {
	c, _ := CoverageFor("git")
	if len(c.Formats) != 1 || c.Formats[0] != ".gitmodules" || !strings.Contains(c.Note, "Cargo.lock") {
		t.Errorf("git coverage %+v", c)
	}
	rep := &Report{Files: []*File{
		{Dependencies: []Dependency{{Type: "cargo", Name: "a", Source: SourceGit}, {Type: "cargo", Name: "b"}}},
		{Dependencies: []Dependency{{Type: "git", Name: "sub", Source: SourceGit}}},
	}}
	var names []string
	for _, d := range rep.GitDependencies() {
		names = append(names, d.Name)
	}
	if strings.Join(names, ",") != "a,sub" {
		t.Errorf("git dependencies %v", names)
	}
	raw, _ := json.Marshal(c)
	if !bytes.Contains(raw, []byte(`"note"`)) {
		t.Error("the note is not in the JSON form")
	}
}

// TestSubmodulePathsThroughOneTreeCostOneRead: many declared paths leading
// through copies of one big tree object read it once, not once per path —
// a small repository must not make the scan read gigabytes of tree entries.
func TestSubmodulePathsThroughOneTreeCostOneRead(t *testing.T) {
	repo := newTestRepo(t)
	mktree := func(lines []string) string {
		cmd := exec.Command("git", "mktree")
		cmd.Dir = repo.dir
		cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	blob := repo.git("hash-object", "-w", "--stdin")
	var wide []string
	for i := 0; i < 3000; i++ {
		wide = append(wide, fmt.Sprintf("100644 blob %s\tf%05d", blob, i))
	}
	commit := strings.Repeat("c", 40)
	wide = append(wide, "160000 commit "+commit+"\tzz")
	wideTree := mktree(wide)
	var vendor, gitmodules []string
	for i := 0; i < 500; i++ {
		vendor = append(vendor, fmt.Sprintf("040000 tree %s\td%05d", wideTree, i))
		gitmodules = append(gitmodules, fmt.Sprintf("[submodule \"s%d\"]\n\tpath = vendor/d%05d/zz\n\turl = https://h.example/s%d.git", i, i, i))
	}
	vendorTree := mktree(vendor)
	cmd := exec.Command("git", "hash-object", "-w", "--stdin")
	cmd.Dir = repo.dir
	cmd.Stdin = strings.NewReader(strings.Join(gitmodules, "\n") + "\n")
	gmBlob, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	rootTree := mktree([]string{"100644 blob " + strings.TrimSpace(string(gmBlob)) + "\t.gitmodules", "040000 tree " + vendorTree + "\tvendor"})
	head := repo.git("commit-tree", rootTree, "-m", "c")

	rep := repo.scan(head, Options{})
	if len(rep.Files) != 1 || len(rep.Files[0].Dependencies) != 500 {
		t.Fatalf("files %v", filePaths(rep))
	}
	if rep.Stats.Trees > 10 {
		t.Errorf("%d tree objects read to pin 500 submodules through one tree", rep.Stats.Trees)
	}
	// The entries read count against the scan's limit.
	rep = repo.scan(head, Options{MaxTreeEntries: 1000})
	if len(rep.Files) != 1 || len(rep.Files[0].Dependencies) != 0 || !strings.Contains(strings.Join(rep.Files[0].Warnings, "\n"), "more than 1000 tree entries") {
		t.Errorf("with a small budget: %d dependencies, warnings %q", len(rep.Files[0].Dependencies), rep.Files[0].Warnings)
	}
}
