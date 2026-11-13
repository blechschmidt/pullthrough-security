package versions

import (
	"os"
	"regexp"
	"testing"
)

// schemeFuzzTargets names the fuzz target of every scheme.
var schemeFuzzTargets = map[string]string{
	"npm":      "FuzzNpm",
	"cargo":    "FuzzCargo",
	"pip":      "FuzzPip",
	"go":       "FuzzGo",
	"nuget":    "FuzzNuGet",
	"maven":    "FuzzMaven",
	"rubygems": "FuzzRubyGems",
}

// TestEverySchemeIsFuzzed holds the schemes to the fuzz harness: each has a
// fuzz target in fuzz_test.go, and every target is in the Makefile's
// FUZZ_TARGETS, which the nightly fuzzing runs. A scheme added without one
// fails here.
func TestEverySchemeIsFuzzed(t *testing.T) {
	src, err := os.ReadFile("fuzz_test.go")
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`internal/versions:(Fuzz\w+)`).FindAllStringSubmatch(string(makefile), -1) {
		listed[m[1]] = true
	}
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^func (Fuzz\w+)\(f \*testing\.F\)`).FindAllStringSubmatch(string(src), -1) {
		defined[m[1]] = true
	}
	for _, name := range Supported() {
		target, ok := schemeFuzzTargets[name]
		if !ok {
			t.Errorf("scheme %s has no fuzz target (add one to fuzz_test.go and schemeFuzzTargets)", name)
			continue
		}
		if !defined[target] {
			t.Errorf("%s: %s is not defined in fuzz_test.go", name, target)
		}
	}
	for name := range defined {
		if !listed[name] {
			t.Errorf("%s is not in the Makefile's FUZZ_TARGETS, so nothing fuzzes it", name)
		}
	}
	for name := range listed {
		if !defined[name] {
			t.Errorf("the Makefile lists internal/versions:%s, which does not exist", name)
		}
	}
}
