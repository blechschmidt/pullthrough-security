package fullmirror

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEveryFuzzTargetIsListed holds the feed adapters' fuzz targets to the
// Makefile's FUZZ_TARGETS, which the nightly fuzzing runs: a parser of
// registry documents added with a fuzz target that nothing runs fails here,
// and so does a listed target that no longer exists.
func TestEveryFuzzTargetIsListed(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`internal/fullmirror:(Fuzz\w+)`).FindAllStringSubmatch(string(makefile), -1) {
		listed[m[1]] = true
	}
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	def := regexp.MustCompile(`(?m)^func (Fuzz\w+)\(f \*testing\.F\)`)
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range def.FindAllStringSubmatch(string(src), -1) {
			defined[m[1]] = true
		}
	}
	if len(defined) == 0 {
		t.Fatal("no fuzz targets found")
	}
	for name := range defined {
		if !listed[name] {
			t.Errorf("%s is not in the Makefile's FUZZ_TARGETS, so nothing fuzzes it", name)
		}
	}
	for name := range listed {
		if !defined[name] {
			t.Errorf("the Makefile lists internal/fullmirror:%s, which does not exist", name)
		}
	}
}
