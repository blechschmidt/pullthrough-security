package lockfiles

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// parserFuzzTargets names the fuzz target of every parser format.
var parserFuzzTargets = map[string]string{
	"package-lock.json":    "FuzzPackageLock",
	"npm-shrinkwrap.json":  "FuzzNpmShrinkwrap",
	"yarn.lock":            "FuzzYarnLock",
	"pnpm-lock.yaml":       "FuzzPnpmLock",
	"requirements.txt":     "FuzzRequirementsTxt",
	"Pipfile.lock":         "FuzzPipfileLock",
	"poetry.lock":          "FuzzPoetryLock",
	"uv.lock":              "FuzzUVLock",
	"pdm.lock":             "FuzzPDMLock",
	"Cargo.lock":           "FuzzCargoLock",
	"go.mod":               "FuzzGoMod",
	"go.sum":               "FuzzGoSum",
	"packages.lock.json":   "FuzzNuGetLock",
	"gradle.lockfile":      "FuzzGradleLock",
	"pom.xml":              "FuzzPOM",
	"Gemfile.lock":         "FuzzGemfileLock",
	"composer.lock":        "FuzzComposerLock",
	"Dockerfile":           "FuzzDockerfile",
	"compose":              "FuzzCompose",
	".gitmodules":          "FuzzGitmodules",
	"conda-lock.yml":       "FuzzCondaLock",
	"@EXPLICIT spec":       "FuzzCondaExplicit",
	"pixi.lock":            "FuzzPixiLock",
	"renv.lock":            "FuzzRenvLock",
	"mix.lock":             "FuzzMixLock",
	"Package.resolved":     "FuzzPackageResolved",
	"pubspec.lock":         "FuzzPubspecLock",
	"Manifest.toml":        "FuzzJuliaManifest",
	"MODULE.bazel.lock":    "FuzzModuleBazelLock",
	"flake.lock":           "FuzzFlakeLock",
	".terraform.lock.hcl":  "FuzzTerraformLock",
	"*.tf overrides":       "FuzzTerraformOverrides",
	"*.tf modules":         "FuzzTerraformModules",
	"conan.lock":           "FuzzConanLock",
	"cpanfile.snapshot":    "FuzzCpanfileSnapshot",
	"cabal.project.freeze": "FuzzCabalFreeze",
	"stack.yaml.lock":      "FuzzStackLock",
	"deno.lock":            "FuzzDenoLock",
	"Chart.lock":           "FuzzChartLock",
	"requirements.lock":    "FuzzRequirementsLock",
	"Brewfile.lock.json":   "FuzzBrewfileLock",
	"requirements.yml":     "FuzzAnsibleRequirements",
	"Puppetfile":           "FuzzPuppetfile",
}

// TestEveryParserIsFuzzed holds the parsers to the fuzz harness: each has a
// fuzz target in fuzz_test.go, and the target is in the Makefile's
// FUZZ_TARGETS, which the nightly fuzzing runs. A parser added without one
// fails here.
func TestEveryParserIsFuzzed(t *testing.T) {
	src, err := os.ReadFile("fuzz_test.go")
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile(`internal/lockfiles:(Fuzz\w+)`).FindAllStringSubmatch(string(makefile), -1) {
		listed[m[1]] = true
	}
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^func (Fuzz\w+)\(f \*testing\.F\)`).FindAllStringSubmatch(string(src), -1) {
		defined[m[1]] = true
	}
	for _, p := range DefaultRegistry().All() {
		name, ok := parserFuzzTargets[p.Format()]
		if !ok {
			t.Errorf("parser %s has no fuzz target (add one to fuzz_test.go and parserFuzzTargets)", p.Format())
			continue
		}
		if !defined[name] {
			t.Errorf("%s: %s is not defined in fuzz_test.go", p.Format(), name)
		}
	}
	for name := range defined {
		if !listed[name] {
			t.Errorf("%s is not in the Makefile's FUZZ_TARGETS, so nothing fuzzes it", name)
		}
	}
	for name := range listed {
		if !defined[name] {
			t.Errorf("the Makefile lists internal/lockfiles:%s, which does not exist", name)
		}
	}
	if !strings.Contains(string(makefile), "internal/git:FuzzParseTree") {
		t.Error("the tree-object parser the walk reads through is not fuzzed")
	}
}
