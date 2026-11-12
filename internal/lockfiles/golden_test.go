package lockfiles

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// The golden fixtures are real lock files: written by the package managers
// themselves wherever one could be run (see each fixture's GENERATED.md), by
// hand only for formats or shapes no current tool writes. Every fixture
// directory is read the way Scan reads a tree — every file detected, parsed,
// merged with its siblings, mapped through a proxy configuration — and the
// result must match testdata/golden/<fixture>.json. Regenerate after an
// intended change with
//
//	go test ./internal/lockfiles/ -run TestGolden -update
//
// and read the diff: it is the review of the change.

var update = flag.Bool("update", false, "rewrite the golden files")

// testToken is the personal link token in the proxied fixtures. It is spelled
// like a token but fails the checksum, so no secret scanner takes it for one.
const testToken = "ptl1abcdefghijklmnopqrstuvwxyz234567qwertyz"

// goldenProxy is the deployment the fixtures are mapped through.
var goldenProxy = &Proxy{
	PublicURLs: []string{"https://proxy.example.com"},
	LinkPrefix: "/u",
	Upstreams: map[string]ProxyUpstream{
		"npm":       {Type: "npm", URL: "https://registry.npmjs.org"},
		"pypi":      {Type: "pip", URL: "https://pypi.org/simple"},
		"crates":    {Type: "cargo", URL: "https://index.crates.io/"},
		"dockerhub": {Type: "docker", URL: "https://registry-1.docker.io"},
		"packagist": {Type: "composer", URL: "https://repo.packagist.org"},
		"rubygems":  {Type: "rubygems", URL: "https://rubygems.org"},
		"central":   {Type: "maven", URL: "https://repo.maven.apache.org/maven2"},
	},
}

// parseFixture reads every lock file under dir the way Scan does.
func parseFixture(t *testing.T, dir string) []*File {
	t.Helper()
	reg := DefaultRegistry()
	var files []*File
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		parser := reg.Detect(rel)
		if parser == nil {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files = append(files, parseOne(parser, rel, data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	finish(files, goldenProxy)
	return files
}

func fixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("testdata/fixtures")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) < 25 {
		t.Fatalf("only %d fixtures found", len(names))
	}
	return names
}

func marshalFiles(t *testing.T, files []*File) []byte {
	t.Helper()
	out, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestGolden(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			files := parseFixture(t, filepath.Join("testdata/fixtures", name))
			if len(files) == 0 {
				t.Fatal("no lock file detected in the fixture")
			}
			deps := 0
			for _, f := range files {
				if f.Error != "" {
					t.Errorf("%s: %s", f.Path, f.Error)
				}
				deps += len(f.Dependencies)
				for _, d := range f.Dependencies {
					if d.Name == "" || d.Version == "" || d.Line <= 0 || d.File != f.Path || d.Type == "" {
						t.Errorf("%s: incomplete dependency %+v", f.Path, d)
					}
				}
			}
			if deps == 0 {
				t.Error("the fixture yields no dependency")
			}
			got := marshalFiles(t, files)
			for _, secret := range []string{testToken, "ptl1abc", "s3cret", "ci-user"} {
				if bytes.Contains(got, []byte(secret)) {
					t.Errorf("the output contains %q", secret)
				}
			}
			golden := filepath.Join("testdata/golden", name+".json")
			if *update {
				if err := os.MkdirAll("testdata/golden", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s (run with -update and review the diff)\n%s", golden, firstDiff(string(want), string(got)))
			}
		})
	}
}

// TestGoldenFilesHaveFixtures fails on a golden file whose fixture is gone.
func TestGoldenFilesHaveFixtures(t *testing.T) {
	names := map[string]bool{}
	for _, n := range fixtureNames(t) {
		names[n] = true
	}
	entries, err := os.ReadDir("testdata/golden")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !names[strings.TrimSuffix(e.Name(), ".json")] {
			t.Errorf("testdata/golden/%s has no fixture", e.Name())
		}
	}
}

func TestTestTokenIsNotARealToken(t *testing.T) {
	if len(testToken) != userlinks.TokenLen || !strings.HasPrefix(testToken, userlinks.TokenPrefix) {
		t.Fatal("the test token is not spelled like a token")
	}
	if userlinks.WellFormed(testToken) {
		t.Fatal("the test token passes the checksum; pick one that does not")
	}
}

// firstDiff shows the first differing line of two texts.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "line " + itoa(i+1) + ":\n  want: " + w + "\n  got:  " + g
		}
	}
	return ""
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestFixturesSayHowTheyWereMade: every fixture records its origin — the
// tool, version and command, or that it was written by hand and why.
func TestFixturesSayHowTheyWereMade(t *testing.T) {
	for _, name := range fixtureNames(t) {
		data, err := os.ReadFile(filepath.Join("testdata/fixtures", name, "GENERATED.md"))
		if err != nil {
			t.Errorf("%s has no GENERATED.md", name)
			continue
		}
		if len(bytes.TrimSpace(data)) < 80 {
			t.Errorf("%s/GENERATED.md says too little", name)
		}
	}
}
