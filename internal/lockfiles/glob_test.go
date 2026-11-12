package lockfiles

import (
	"strings"
	"testing"
)

func TestGlobs(t *testing.T) {
	globs, err := compileGlobs([]string{"node_modules", "**/test/data", "docs/examples/*", "a/**/z", "*.bak"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"node_modules":            true,
		"web/node_modules":        true,
		"web/node_modules_extra":  false,
		"test/data":               true,
		"x/y/test/data":           true,
		"x/test/data/more":        false,
		"docs/examples/one":       true,
		"docs/examples/one/two":   false,
		"other/docs/examples/one": false,
		"a/z":                     true,
		"a/b/c/z":                 true,
		"a/b/c/zz":                false,
		"file.bak":                true,
		"deep/dir/file.bak":       true,
		"deep/dir/file.bak.not":   false,
	}
	for p, want := range cases {
		if got := matchAny(globs, p, baseName(p)); got != want {
			t.Errorf("matchAny(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestGlobsRejectMalformedPatterns(t *testing.T) {
	for _, bad := range [][]string{{""}, {"a//b"}, {"a/**b/c"}, {"[unclosed"}, {"a/[unclosed/b"}} {
		if _, err := compileGlobs(bad); err == nil {
			t.Errorf("compileGlobs(%q) accepted", bad)
		}
	}
	many := make([]string, maxGlobs+1)
	for i := range many {
		many[i] = "x"
	}
	if _, err := compileGlobs(many); err == nil {
		t.Error("too many globs accepted")
	}
}

// TestGlobMatchingIsLinear: a pattern of many "**" against a deep path
// finishes quickly (a backtracking matcher would not).
func TestGlobMatchingIsLinear(t *testing.T) {
	pat := strings.TrimSuffix(strings.Repeat("**/a/", 30), "/") + "/b"
	globs, err := compileGlobs([]string{pat})
	if err != nil {
		t.Fatal(err)
	}
	p := strings.TrimSuffix(strings.Repeat("a/", 60), "/")
	if matchAny(globs, p, "a") {
		t.Error("matched")
	}
}

func TestDefaultSkipCompiles(t *testing.T) {
	if _, err := compileGlobs(DefaultSkip); err != nil {
		t.Fatal(err)
	}
}

func TestGlobsIgnoreCase(t *testing.T) {
	globs, err := compileGlobs([]string{"fixtures", "Docs/Examples/*", "**/TEST/data"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"tests/Composer/Test/Fixtures", "docs/examples/one", "a/Test/Data"} {
		if !matchAny(globs, p, baseName(p)) {
			t.Errorf("%q not matched", p)
		}
	}
}
