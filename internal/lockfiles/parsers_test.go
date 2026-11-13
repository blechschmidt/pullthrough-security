package lockfiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// detectCases maps paths to the format that must detect them ("" for none).
var detectCases = map[string]string{
	"package-lock.json":                  "package-lock.json",
	"web/npm-shrinkwrap.json":            "npm-shrinkwrap.json",
	"a/b/yarn.lock":                      "yarn.lock",
	"pnpm-lock.yaml":                     "pnpm-lock.yaml",
	"requirements.txt":                   "requirements.txt",
	"requirements-dev.txt":               "requirements.txt",
	"requirements_test.txt":              "requirements.txt",
	"test-requirements.txt":              "requirements.txt",
	"constraints.txt":                    "requirements.txt",
	"requirements/prod.txt":              "requirements.txt",
	"Pipfile.lock":                       "Pipfile.lock",
	"poetry.lock":                        "poetry.lock",
	"uv.lock":                            "uv.lock",
	"pdm.lock":                           "pdm.lock",
	"crates/x/Cargo.lock":                "Cargo.lock",
	"go.mod":                             "go.mod",
	"tools/go.sum":                       "go.sum",
	"src/App/packages.lock.json":         "packages.lock.json",
	"packages.App.lock.json":             "packages.lock.json",
	"gradle.lockfile":                    "gradle.lockfile",
	"buildscript-gradle.lockfile":        "gradle.lockfile",
	"gradle/dependency-locks/x.lockfile": "gradle.lockfile",
	"pom.xml":                            "pom.xml",
	"Gemfile.lock":                       "Gemfile.lock",
	"gems.locked":                        "Gemfile.lock",
	"composer.lock":                      "composer.lock",
	"Dockerfile":                         "Dockerfile",
	"Dockerfile.prod":                    "Dockerfile",
	"build/app.dockerfile":               "Dockerfile",
	"Containerfile":                      "Dockerfile",
	"compose.yaml":                       "compose",
	"docker-compose.yml":                 "compose",
	"docker-compose.override.yml":        "compose",
	"deploy/compose.prod.yaml":           "compose",
	"conda-lock.yml":                     "conda-lock.yml",
	"envs/ml.conda-lock.yml":             "conda-lock.yml",
	"conda-linux-64.lock":                "@EXPLICIT spec",
	"predict-osx-arm64.conda.lock":       "@EXPLICIT spec",
	"spec-file.txt":                      "@EXPLICIT spec",
	"pixi.lock":                          "pixi.lock",
	"renv.lock":                          "renv.lock",
	"mix.lock":                           "mix.lock",
	"apps/web/mix.lock":                  "mix.lock",
	"Package.resolved":                   "Package.resolved",
	"App.xcworkspace/xcshareddata/swiftpm/Package.resolved": "Package.resolved",
	"pubspec.lock":                      "pubspec.lock",
	"Manifest.toml":                     "Manifest.toml",
	"JuliaManifest.toml":                "Manifest.toml",
	"Manifest-v1.11.toml":               "Manifest.toml",
	"MODULE.bazel.lock":                 "MODULE.bazel.lock",
	"flake.lock":                        "flake.lock",
	".terraform.lock.hcl":               ".terraform.lock.hcl",
	"infra/main.tf":                     "*.tf modules",
	"infra/main.tofu":                   "*.tf modules",
	"conan.lock":                        "conan.lock",
	"cpanfile.snapshot":                 "cpanfile.snapshot",
	"cabal.project.freeze":              "cabal.project.freeze",
	"stack.yaml.lock":                   "stack.yaml.lock",
	"deno.lock":                         "deno.lock",
	"Chart.lock":                        "Chart.lock",
	"charts/old/requirements.lock":      "requirements.lock",
	"requirements-dev.lock":             "requirements.txt",
	"Brewfile.lock.json":                "Brewfile.lock.json",
	"requirements.yml":                  "requirements.yml",
	"roles/requirements.yaml":           "requirements.yml",
	"Puppetfile":                        "Puppetfile",
	".gitmodules":                       ".gitmodules",
	"package.json":                      "",
	"environment.yml":                   "",
	"conda-lock.toml":                   "",
	"pixi.toml":                         "",
	"DESCRIPTION":                       "",
	"mix.exs":                           "",
	"Package.swift":                     "",
	"pubspec.yaml":                      "",
	"Project.toml":                      "",
	"Manifest-vX.toml":                  "",
	"MODULE.bazel":                      "",
	"flake.nix":                         "",
	"main.tf.json":                      "",
	"terraform.tfvars":                  "",
	".tf":                               "",
	"conanfile.txt":                     "",
	"cpanfile":                          "",
	"foo.cabal":                         "",
	"stack.yaml":                        "",
	"deno.json":                         "",
	"Chart.yaml":                        "",
	"Brewfile":                          "",
	"galaxy.yml":                        "",
	"vendor/sub/.gitmodules":            "",
	".vscode/extensions.json":           "",
	"requirements.in":                   "",
	"Pipfile":                           "",
	"pyproject.toml":                    "",
	"Cargo.toml":                        "",
	"go.work":                           "",
	"Gemfile":                           "",
	"composer.json":                     "",
	"build.gradle":                      "",
	"notes.txt":                         "",
	"docs/requirements.md":              "",
	"composer.yaml.bak":                 "",
	"my-requirements-notes.txt.orig":    "",
	"something.lockfile":                "",
	"node_modules/x/package-lock.jsonx": "",
	"yarn.lock/":                        "",
}

func TestDetect(t *testing.T) {
	reg := DefaultRegistry()
	for path, want := range detectCases {
		p := reg.Detect(path)
		got := ""
		if p != nil {
			got = p.Format()
		}
		if got != want {
			t.Errorf("Detect(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestDetectIsUnambiguous: no path is claimed by two parsers, so detection
// order never decides a format.
func TestDetectIsUnambiguous(t *testing.T) {
	for path := range detectCases {
		var claimed []string
		for _, p := range DefaultRegistry().All() {
			if p.Detect(path) {
				claimed = append(claimed, p.Format())
			}
		}
		if len(claimed) > 1 {
			t.Errorf("%q is detected by %v", path, claimed)
		}
	}
}

// TestParsersRefuseOtherFormats: each parser handed another format's file (or
// junk) fails or finds nothing — it never invents a dependency, never panics.
func TestParsersRefuseOtherFormats(t *testing.T) {
	inputs := map[string]string{
		"empty":     "",
		"junk":      "\x00\xff\xfe binary \x01",
		"json":      `{"a": [1, 2, {"b": null}]}`,
		"yaml":      "a:\n  - b\n  - c: d\n",
		"toml":      "[x]\ny = 1\n",
		"xml":       "<?xml version=\"1.0\"?><root><a>1</a></root>",
		"html":      "<html><body>hello</body></html>",
		"deep json": strings.Repeat("[", 100000),
		"deep yaml": strings.Repeat("- ", 5000) + "x",
		"long line": strings.Repeat("a", 1<<20),
	}
	for _, p := range DefaultRegistry().All() {
		for name, in := range inputs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on %s: %v", p.Format(), name, r)
					}
				}()
				res, err := p.Parse([]byte(in))
				if err != nil {
					return
				}
				if res == nil {
					t.Errorf("%s: nil result and nil error on %s", p.Format(), name)
					return
				}
				if len(res.Dependencies) > 0 {
					t.Errorf("%s found %d dependencies in %s input: %+v", p.Format(), len(res.Dependencies), name, res.Dependencies[0])
				}
			}()
		}
	}
}

func parseWith(t *testing.T, p Parser, src string) *Result {
	t.Helper()
	res, err := p.Parse([]byte(src))
	if err != nil {
		t.Fatalf("%s: %v", p.Format(), err)
	}
	return res
}

func TestYarnSpecName(t *testing.T) {
	cases := map[string][2]string{
		"lodash@^4.17.21":                                {"lodash", "^4.17.21"},
		"@babel/core@7.0.0":                              {"@babel/core", "7.0.0"},
		"string-width-cjs@npm:string-width@^4.2.0":       {"string-width", "^4.2.0"},
		"alias@npm:@scope/real@1.0.0":                    {"@scope/real", "1.0.0"},
		"is-number@github:jonschlinkert/is-number#7.0.0": {"is-number", "github:jonschlinkert/is-number#7.0.0"},
		"x": {"x", ""},
	}
	for spec, want := range cases {
		n, r := yarnSpecName(spec)
		if n != want[0] || r != want[1] {
			t.Errorf("yarnSpecName(%q) = %q, %q; want %q, %q", spec, n, r, want[0], want[1])
		}
	}
}

func TestYarnClassicQuotedKeysAndLocalPackages(t *testing.T) {
	src := `# yarn lockfile v1


"@scope/a@^1.0.0", "@scope/a@^1.1.0":
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/@scope/a/-/a-1.2.0.tgz#0123456789abcdef0123456789abcdef01234567"

"local@file:../local":
  version "0.0.1"

b@1.0.0:
  version "1.0.0"
  resolved "git+https://github.com/o/b.git#0123456789abcdef0123456789abcdef01234567"
`
	res := parseWith(t, yarnLock{}, src)
	if len(res.Dependencies) != 2 {
		t.Fatalf("dependencies %+v", res.Dependencies)
	}
	a, b := res.Dependencies[0], res.Dependencies[1]
	if a.Name != "@scope/a" || a.Version != "1.2.0" || a.Registry != "https://registry.yarnpkg.com" || len(a.Digests) != 1 || a.Digests[0].Algorithm != "sha1" || a.Line != 4 {
		t.Errorf("scoped entry %+v", a)
	}
	if b.Source != SourceGit || b.Revision != "0123456789abcdef0123456789abcdef01234567" || b.Registry != "https://github.com/o/b.git" {
		t.Errorf("git entry %+v", b)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "local") {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func TestPnpmKey(t *testing.T) {
	cases := []struct {
		key           string
		major         int
		name, version string
	}{
		{"/lodash/4.17.21", 5, "lodash", "4.17.21"},
		{"/@types/node/20.14.10", 5, "@types/node", "20.14.10"},
		{"/react-dom/17.0.2_react@17.0.2", 5, "react-dom", "17.0.2"},
		{"/lodash@4.17.21", 6, "lodash", "4.17.21"},
		{"/@types/node@20.14.10", 6, "@types/node", "20.14.10"},
		{"/react-dom@17.0.2(react@17.0.2)", 6, "react-dom", "17.0.2"},
		{"lodash@4.17.21", 9, "lodash", "4.17.21"},
		{"@types/node@20.14.10", 9, "@types/node", "20.14.10"},
		{"is-number@https://codeload.github.com/o/r/tar.gz/abc", 9, "is-number", "https://codeload.github.com/o/r/tar.gz/abc"},
	}
	for _, c := range cases {
		n, v := pnpmKey(c.key, c.major)
		if n != c.name || v != c.version {
			t.Errorf("pnpmKey(%q, %d) = %q, %q; want %q, %q", c.key, c.major, n, v, c.name, c.version)
		}
	}
}

func TestGoModSyntax(t *testing.T) {
	src := "// a comment\nmodule `example.com/m` // the module\n\ngo 1.22\n\n" +
		"require \"example.com/quoted\" v1.0.0\n" +
		"require (\n\texample.com/a v1.2.3 // indirect\n\n\t// a comment in a block\n\texample.com/b v0.0.0-20240101000000-abcdefabcdef\n)\n" +
		"replace (\n\texample.com/a v1.2.3 => example.com/a-fork v1.2.4\n\texample.com/b => ../b\n)\n" +
		"exclude example.com/c v1.0.0\nretract v0.1.0\n"
	res := parseWith(t, goMod{}, src)
	got := map[string]string{}
	for _, d := range res.Dependencies {
		got[d.Name] = d.Version
	}
	if len(got) != 2 || got["example.com/quoted"] != "v1.0.0" || got["example.com/a-fork"] != "v1.2.4" {
		t.Errorf("dependencies %+v", res.Dependencies)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "example.com/b") {
		t.Errorf("warnings %v", res.Warnings)
	}
	for _, bad := range []string{"require (\nexample.com/a v1\n", "module \"unterminated\n", "require \"x\\q\" v1\n"} {
		if _, err := (goMod{}).Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestGoSumMergesIntoGoMod(t *testing.T) {
	mod := parseOne(goMod{}, "svc/go.mod", []byte("module m\n\nrequire example.com/a v1.0.0\n"))
	h := func(c string) string { return "h1:" + strings.Repeat(c, 43) + "=" }
	sum := parseOne(goSum{}, "svc/go.sum", []byte(
		"example.com/a v1.0.0 "+h("A")+"\nexample.com/a v1.0.0/go.mod "+h("B")+"\n"+
			"example.com/b v2.0.0 "+h("C")+"\nexample.com/old v0.1.0/go.mod "+h("D")+"\n"))
	other := parseOne(goSum{}, "other/go.sum", []byte("example.com/a v1.0.0 "+h("A")+"\n"))
	finish([]*File{mod, sum, other}, nil)
	if len(mod.Dependencies) != 1 || len(mod.Dependencies[0].Digests) != 2 {
		t.Fatalf("go.mod dependencies %+v", mod.Dependencies)
	}
	if len(sum.Dependencies) != 1 || sum.Dependencies[0].Name != "example.com/b" {
		t.Fatalf("go.sum keeps %+v, want only the module go.mod does not name", sum.Dependencies)
	}
	if len(other.Dependencies) != 1 {
		t.Fatalf("a go.sum in another directory is not merged: %+v", other.Dependencies)
	}
}

func TestRequirementsLogicalLines(t *testing.T) {
	src := "a==1.0 \\\n  --hash=sha256:" + strings.Repeat("ab", 32) + " \\\n  --hash sha256:" + strings.Repeat("cd", 32) +
		"\n# comment\nb == 2.0;python_version<'3.9' # trailing\nc==3.*\nd>=1,<2\n--index-url=https://u:p@idx.example/simple\ne==5\n"
	res := parseWith(t, requirementsTxt{}, src)
	if len(res.Dependencies) != 3 {
		t.Fatalf("dependencies %+v", res.Dependencies)
	}
	a, b, e := res.Dependencies[0], res.Dependencies[1], res.Dependencies[2]
	if a.Name != "a" || len(a.Digests) != 2 || a.Line != 1 {
		t.Errorf("a = %+v", a)
	}
	if b.Name != "b" || b.Version != "2.0" || b.Line != 5 {
		t.Errorf("b = %+v", b)
	}
	if e.Registry != "https://idx.example/simple" || e.Line != 9 {
		t.Errorf("e = %+v (the index URL applies from where it is set, without credentials)", e)
	}
	if len(res.Warnings) != 2 {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func TestDockerfileEscapeDirectiveAndHeredocs(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	src := "# escape=`\nFROM alpine@" + digest + " `\n  AS base\n" +
		"RUN <<-EOF cat\n\tFROM evil@" + digest + "\n\tEOF\n" +
		"COPY --from=0 /a /b\nCOPY --from=base /a /b\nCOPY --from=ghcr.io/o/tool@" + digest + " /t /t\n"
	res := parseWith(t, dockerfile{}, src)
	var names []string
	for _, d := range res.Dependencies {
		names = append(names, d.Name)
	}
	if strings.Join(names, ",") != "library/alpine,o/tool" {
		t.Errorf("images %v, warnings %v", names, res.Warnings)
	}
}

func TestParseImageRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("0", 64)
	cases := map[string]imageRef{
		"alpine":                         {domain: "docker.io", path: "library/alpine"},
		"alpine:3.20@" + digest:          {domain: "docker.io", path: "library/alpine", tag: "3.20", digest: digest},
		"bitnami/redis":                  {domain: "docker.io", path: "bitnami/redis"},
		"ghcr.io/o/r:v1":                 {domain: "ghcr.io", path: "o/r", tag: "v1"},
		"localhost:5000/x":               {domain: "localhost:5000", path: "x"},
		"index.docker.io/library/alpine": {domain: "docker.io", path: "library/alpine"},
	}
	for in, want := range cases {
		got, err := parseImageRef(in)
		if err != nil || got != want {
			t.Errorf("parseImageRef(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "a/UPPER", "a@sha256:short", "a:b:c:d/e", "a//b", "-a", "a@md5:" + strings.Repeat("0", 32)} {
		if _, err := parseImageRef(bad); err == nil {
			t.Errorf("parseImageRef(%q) accepted", bad)
		}
	}
}

func TestExpandVars(t *testing.T) {
	vars := map[string]string{"A": "x", "EMPTY": ""}
	cases := map[string]struct {
		out string
		ok  bool
	}{
		"$A/${A}":        {"x/x", true},
		"${B:-d}":        {"d", true},
		"${EMPTY:-d}":    {"d", true},
		"${EMPTY-d}":     {"", true},
		"${A:+alt}":      {"alt", true},
		"${B:+alt}x":     {"x", true},
		"$$A":            {"$A", true},
		"${B}":           {"", false},
		"${unterminated": {"${unterminated", false},
	}
	for in, want := range cases {
		out, ok := expandVars(in, vars)
		if out != want.out || ok != want.ok {
			t.Errorf("expandVars(%q) = %q, %v; want %q, %v", in, out, ok, want.out, want.ok)
		}
	}
}

func TestPOMRefusesExternalEntities(t *testing.T) {
	src := `<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY ext SYSTEM "file:///etc/passwd">]>
<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>&ext;</version></dependency></dependencies></project>`
	res, err := (pomXML{}).Parse([]byte(src))
	if err == nil && len(res.Dependencies) > 0 {
		t.Fatalf("an external entity was expanded: %+v", res.Dependencies)
	}
}

func TestDigestParsing(t *testing.T) {
	if d := sriDigests("sha512-" + strings.Repeat("A", 86) + "== sha1-bad sha256-?opt md5-" + strings.Repeat("A", 22) + "=="); len(d) != 2 {
		t.Errorf("sriDigests kept %+v", d)
	}
	if _, ok := hexDigest("sha256", strings.Repeat("g", 64), ""); ok {
		t.Error("non-hex accepted")
	}
	if _, ok := hexDigest("sha256", strings.Repeat("a", 63), ""); ok {
		t.Error("short hex accepted")
	}
	if d, ok := prefixedDigest("SHA256:"+strings.Repeat("A", 64), "f"); !ok || d.Value != strings.Repeat("a", 64) || d.Algorithm != "sha256" {
		t.Errorf("prefixedDigest = %+v, %v", d, ok)
	}
	if d, ok := base64Digest("sha512", strings.Repeat("A", 86), ""); !ok || len(d.Value) != 128 {
		t.Errorf("unpadded base64: %+v %v", d, ok)
	}
}

func TestParseGitURL(t *testing.T) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	cases := map[string]gitSource{
		"git+ssh://git@github.com/o/r.git#" + commit:     {repo: "ssh://git@github.com/o/r.git", revision: commit},
		"git+https://tok:x@github.com/o/r.git#" + commit: {repo: "https://github.com/o/r.git", revision: commit},
		"https://github.com/o/r.git#commit=" + commit:    {repo: "https://github.com/o/r.git", revision: commit},
		"github:o/r#v1.0.0":                              {repo: "https://github.com/o/r", ref: "v1.0.0"},
		"git+https://github.com/o/r?tag=v1#" + commit:    {repo: "https://github.com/o/r", revision: commit},
		"git+ssh://ptl1abc@github.com/o/r.git#" + commit: {repo: "ssh://github.com/o/r.git", revision: commit},
	}
	for in, want := range cases {
		if got := parseGitURL(in); got != want {
			t.Errorf("parseGitURL(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestNpmRegistryBase(t *testing.T) {
	cases := []struct {
		url, name, base string
		registry        bool
	}{
		{"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "lodash", "https://registry.npmjs.org", true},
		{"https://registry.npmjs.org/@types/node/-/node-1.0.0.tgz", "@types/node", "https://registry.npmjs.org", true},
		{"https://npm.example.com/repo/@types%2fnode/-/node-1.0.0.tgz", "@types/node", "https://npm.example.com/repo", true},
		{"https://npm.example.com/repo/%40types%2fnode/-/node-1.0.0.tgz", "@types/node", "https://npm.example.com/repo", true},
		{"https://u:p@npm.example.com/r/lodash/-/lodash-1.0.0.tgz?x=1", "lodash", "https://npm.example.com/r", true},
		// Not a registry's download: a tarball somewhere.
		{"https://pkgs.example.com/download/lodash/1.0.0/abc", "lodash", "https://pkgs.example.com", false},
		{"https://example.com/other/-/lodash-1.0.0.tgz", "lodash", "https://example.com", false},
	}
	for _, c := range cases {
		base, ok := npmRegistryBase(c.url, c.name)
		if base != c.base || ok != c.registry {
			t.Errorf("npmRegistryBase(%q, %q) = %q, %v; want %q, %v", c.url, c.name, base, ok, c.base, c.registry)
		}
	}
}

func TestResultWarningsAreBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("x>=1\n")
	}
	res := parseWith(t, requirementsTxt{}, b.String())
	if len(res.Warnings) != maxWarnings+1 {
		t.Fatalf("%d warnings kept", len(res.Warnings))
	}
}

// timeBound fails when fn takes longer than a generous bound: these inputs
// take milliseconds to read in linear time, and minutes or more with the
// quadratic or exponential algorithms the tests guard against. The bound
// leaves room for the race detector on a loaded CI runner.
func timeBound(t *testing.T, what string, fn func()) {
	t.Helper()
	start := time.Now()
	fn()
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("%s took %s", what, d)
	}
}

// TestAliasesCannotMultiplyWork: lock files written by tools never contain
// YAML aliases; one that does is refused — quickly: a hundred thousand entries
// aliasing one huge mapping would be quadratic work to follow.
func TestAliasesCannotMultiplyWork(t *testing.T) {
	var b strings.Builder
	b.WriteString("__metadata:\n  version: 8\n\"real@npm:1\": &big\n  version: 1.0.0\n  resolution: \"real@npm:1.0.0\"\n")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "  k%d: v\n", i)
	}
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "\"alias%d@npm:1\": *big\n", i)
	}
	timeBound(t, "yarn.lock with aliases", func() {
		if _, err := (yarnLock{}).Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "anchor or alias") {
			t.Errorf("a yarn.lock with aliases: %v; want it refused", err)
		}
	})
	pnpm := strings.Replace(strings.Replace(b.String(), "__metadata:\n  version: 8\n", "lockfileVersion: '9.0'\npackages:\n", 1), "\"real@npm:1\": &big", "  real@1.0.0: &big", 1)
	timeBound(t, "pnpm-lock.yaml with aliases", func() { _, _ = (pnpmLock{}).Parse([]byte(pnpm)) })
}

// TestComposeMergesAreBounded: merge keys that fan out at every level would be
// exponential to follow naively; each mapping is visited once, within a budget.
func TestComposeMergesAreBounded(t *testing.T) {
	var b strings.Builder
	const width, levels = 60, 8
	for l := 0; l < levels; l++ {
		for i := 0; i < width; i++ {
			fmt.Fprintf(&b, "x-l%d-%d: &l%d_%d\n", l, i, l, i)
			if l == 0 {
				b.WriteString("  other: 1\n")
				continue
			}
			b.WriteString("  <<: [")
			for j := 0; j < width; j++ {
				if j > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "*l%d_%d", l-1, j)
			}
			b.WriteString("]\n")
		}
	}
	b.WriteString("services:\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "  s%d:\n    <<: *l%d_0\n", i, levels-1)
	}
	timeBound(t, "compose merges", func() {
		res, err := (composeFile{}).Parse([]byte(b.String()))
		if err == nil && len(res.Dependencies) != 0 {
			t.Errorf("dependencies %+v", res.Dependencies)
		}
	})
}

func TestManyDigestsMergeInLinearTime(t *testing.T) {
	// One requirement can carry hundreds of thousands of hashes; merging two
	// copies of it pairwise would be 10^10 comparisons.
	digests := make([]Digest, 100000)
	for i := range digests {
		digests[i] = Digest{Algorithm: "sha256", Value: fmt.Sprintf("%064x", i)}
	}
	timeBound(t, "merging 100 000 digests into 100 000", func() {
		if got := mergeDigests(append([]Digest(nil), digests...), digests); len(got) != len(digests) {
			t.Errorf("%d digests after the merge", len(got))
		}
	})
	f := ParseFile(nil, nil, "requirements.txt", []byte("a==1.0 --hash=sha256:"+strings.Repeat("a", 64)+"\na==1.0 --hash=sha256:"+strings.Repeat("a", 64)+"\n"))
	if len(f.Dependencies) != 1 || len(f.Dependencies[0].Digests) != 1 {
		t.Errorf("a repeated requirement: %+v", f.Dependencies)
	}
}

func TestDedupeMergesEntriesWithoutRegistry(t *testing.T) {
	sha := func(c string) []Digest { return []Digest{{Algorithm: "sha1", Value: strings.Repeat(c, 40)}} }
	deps := dedupe([]Dependency{
		{Type: "npm", Name: "semver", Version: "6.3.1", Line: 9, Registry: "https://registry.npmjs.org", Digests: sha("a"), Dev: true},
		{Type: "npm", Name: "semver", Version: "6.3.1", Line: 4, Digests: sha("a"), Dev: true},
		// Two registries for one version: an entry without one cannot be placed.
		{Type: "npm", Name: "x", Version: "1.0.0", Line: 20, Registry: "https://a.example"},
		{Type: "npm", Name: "x", Version: "1.0.0", Line: 21, Registry: "https://b.example"},
		{Type: "npm", Name: "x", Version: "1.0.0", Line: 22},
		// A Git dependency is not merged with a registry one.
		{Type: "npm", Name: "y", Version: "1.0.0", Line: 30, Registry: "https://registry.npmjs.org"},
		{Type: "npm", Name: "y", Version: "1.0.0", Line: 31, Source: SourceGit, Revision: strings.Repeat("c", 40)},
	})
	var got []string
	for _, d := range deps {
		got = append(got, fmt.Sprintf("%s@%s:%d:%s:%d", d.Name, d.Version, d.Line, d.Registry, len(d.Digests)))
	}
	want := "semver@6.3.1:4:https://registry.npmjs.org:1,x@1.0.0:20:https://a.example:0,x@1.0.0:21:https://b.example:0,x@1.0.0:22::0,y@1.0.0:30:https://registry.npmjs.org:0,y@1.0.0:31::0"
	if strings.Join(got, ",") != want {
		t.Errorf("dedupe:\n got %s\nwant %s", strings.Join(got, ","), want)
	}
}

// panicMerger is a parser whose Merge panics.
type panicMerger struct{ goSum }

func (panicMerger) Format() string { return "go.sum" }
func (panicMerger) Merge([]*File) {
	var m map[string]int
	m["boom"]++
}

func TestAPanickingMergerFailsItsFileOnly(t *testing.T) {
	sum := parseOne(panicMerger{}, "a/go.sum", []byte("example.com/a v1.0.0 h1:"+strings.Repeat("A", 43)+"=\n"))
	mod := parseOne(goMod{}, "a/go.mod", []byte("module m\nrequire example.com/a v1.0.0\n"))
	finish([]*File{mod, sum}, nil)
	if !strings.Contains(sum.Error, "failed") || mod.Error != "" || len(mod.Dependencies) != 1 {
		t.Fatalf("go.sum error %q, go.mod %+v", sum.Error, mod)
	}
}

// TestByteOrderMarksAndCRLF: lock files edited on Windows read the same.
func TestByteOrderMarksAndCRLF(t *testing.T) {
	for _, name := range []string{
		"cargo-v4/Cargo.lock", "npm-lock-v3/package-lock.json", "npm-lock-v1-nested/package-lock.json",
		"yarn-classic/yarn.lock", "yarn-berry-v4/yarn.lock", "pnpm-v9/pnpm-lock.yaml", "pnpm-package-manager/pnpm-lock.yaml",
		"pip-requirements-hashes/requirements.txt", "pipenv/Pipfile.lock", "poetry-2/poetry.lock", "poetry-1.1/poetry.lock",
		"uv/uv.lock", "pdm/pdm.lock", "pdm-old/pdm.lock", "go-modules/go.mod", "go-modules/go.sum",
		"nuget/Fixture.Lib/packages.lock.json", "gradle/gradle.lockfile", "maven-pom/pom.xml", "bundler/Gemfile.lock",
		"composer/composer.lock", "docker/Dockerfile", "docker/compose.yaml",
	} {
		data, err := os.ReadFile("testdata/fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		plain := ParseFile(nil, nil, baseName(name), data)
		crlf := append([]byte("\xef\xbb\xbf"), bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))...)
		windows := ParseFile(nil, nil, baseName(name), crlf)
		if windows.Error != "" || len(windows.Dependencies) != len(plain.Dependencies) {
			t.Errorf("%s with a BOM and CRLF: %d dependencies (want %d), error %q", name, len(windows.Dependencies), len(plain.Dependencies), windows.Error)
			continue
		}
		for i := range plain.Dependencies {
			a, b := plain.Dependencies[i], windows.Dependencies[i]
			if a.Name != b.Name || a.Version != b.Version || a.Line != b.Line || len(a.Digests) != len(b.Digests) || a.Registry != b.Registry {
				t.Errorf("%s: %+v differs from %+v", name, b, a)
				break
			}
		}
	}
}

// TestJSONKeysAreReadAsTheToolsReadThem: keys match exactly (encoding/json's
// struct decoding would match "Resolved" and "reſolved" for "resolved"), and a
// repeated key or entry keeps its last value, as JSON.parse, json.load and
// json_decode do. Otherwise a lock file could show the scanner one artifact
// while the package manager installs another.
func TestJSONKeysAreReadAsTheToolsReadThem(t *testing.T) {
	good := "sha512-" + strings.Repeat("A", 86) + "=="
	evil := "sha512-" + strings.Repeat("B", 86) + "=="
	lock := `{"lockfileVersion": 3, "packages": {
  "node_modules/lodash": {"version": "4.17.21",
    "resolved": "https://evil.example/l.tgz", "integrity": "` + evil + `",
    "Resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "Integrity": "` + good + `",
    "reſolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
  "node_modules/ms": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz",
    "resolved": "https://evil.example/ms.tgz"},
  "node_modules/dup": {"version": "1.0.0"},
  "node_modules/dup": {"version": "2.0.0"}
}}`
	f := ParseFile(nil, nil, "package-lock.json", []byte(lock))
	got := map[string]Dependency{}
	for _, d := range f.Dependencies {
		got[d.Name] = d
	}
	if d := got["lodash"]; d.URL != "https://evil.example/l.tgz" || d.Source != SourceURL || len(d.Digests) != 1 || !strings.HasPrefix(d.Digests[0].Value, "0410") {
		t.Errorf("lodash = %+v; want what npm installs: the evil tarball", d)
	}
	if d := got["ms"]; d.URL != "https://evil.example/ms.tgz" {
		t.Errorf("ms = %+v; want the last \"resolved\"", d)
	}
	if d := got["dup"]; d.Version != "2.0.0" || len(f.Dependencies) != 3 {
		t.Errorf("dup = %+v (%d dependencies); want the last entry only", d, len(f.Dependencies))
	}

	pipfile := `{"_meta": {"sources": [{"name": "good", "url": "https://pypi.org/simple"}, {"name": "evil", "url": "https://evil.example/simple"}]},
"default": {"requests": {"version": "==2.32.3", "index": "evil", "Index": "good", "hashes": ["sha256:` + strings.Repeat("e", 64) + `"], "Hashes": ["sha256:` + strings.Repeat("a", 64) + `"]}}}`
	f = ParseFile(nil, nil, "Pipfile.lock", []byte(pipfile))
	if d := f.Dependencies[0]; d.Registry != "https://evil.example/simple" || d.Digests[0].Value != strings.Repeat("e", 64) {
		t.Errorf("Pipfile.lock: %+v", d)
	}

	composer := `{"packages": [{"name": "v/p", "version": "1.0.0",
  "dist": {"type": "zip", "url": "https://evil.example/p.zip", "Url": "https://repo.packagist.org/p.zip", "shasum": "` + strings.Repeat("e", 40) + `", "Shasum": "` + strings.Repeat("a", 40) + `"}}]}`
	f = ParseFile(nil, nil, "composer.lock", []byte(composer))
	if d := f.Dependencies[0]; d.URL != "https://evil.example/p.zip" || d.Digests[0].Value != strings.Repeat("e", 40) {
		t.Errorf("composer.lock: %+v", d)
	}

	nuget := `{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct", "resolved": "1.0.0", "Resolved": "9.9.9"}}}}`
	f = ParseFile(nil, nil, "packages.lock.json", []byte(nuget))
	if d := f.Dependencies[0]; d.Version != "1.0.0" {
		t.Errorf("packages.lock.json: %+v", d)
	}
}

func TestTarballURLDependencies(t *testing.T) {
	v1 := `{"lockfileVersion": 1, "dependencies": {"foo": {"version": "https://u:secret@files.example.com/foo-1.2.3.tgz?access_token=SECRET", "integrity": "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}`
	f := ParseFile(nil, nil, "package-lock.json", []byte(v1))
	if len(f.Dependencies) != 1 {
		t.Fatalf("%+v", f)
	}
	d := f.Dependencies[0]
	if d.Source != SourceURL || d.Version != "1.2.3" || d.URL != "https://files.example.com/foo-1.2.3.tgz" || d.Registry != "" {
		t.Errorf("npm 6 tarball dependency: %+v", d)
	}
	yarn := "# yarn lockfile v1\n\nfoo@https://files.example.com/foo-1.2.3.tgz:\n  version \"1.2.3\"\n  resolved \"https://files.example.com/foo-1.2.3.tgz#" + strings.Repeat("a", 40) + "\"\n"
	f = ParseFile(nil, nil, "yarn.lock", []byte(yarn))
	if d := f.Dependencies[0]; d.Source != SourceURL || d.Registry != "" {
		t.Errorf("yarn tarball dependency: %+v", d)
	}
	out, _ := json.Marshal(f)
	if bytes.Contains(out, []byte("SECRET")) || bytes.Contains(out, []byte("secret")) {
		t.Errorf("credentials survived: %s", out)
	}
}

// TestYAMLLockFilesReadOnlyWhatTheToolsRead: anchors, aliases, merge keys and
// repeated keys would be read differently by pnpm's and Yarn's own readers;
// such a lock file is refused, never read in a way the tool would not.
func TestYAMLLockFilesReadOnlyWhatTheToolsRead(t *testing.T) {
	integrity := "{integrity: sha512-" + strings.Repeat("A", 86) + "==}"
	pnpm := map[string]string{
		"alias":          "lockfileVersion: '9.0'\npackages:\n  a@1.0.0: &e\n    resolution: " + integrity + "\n  b@1.0.0: *e\n",
		"merge":          "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    <<: {resolution: {tarball: https://evil.example/a.tgz}}\n    resolution: " + integrity + "\n",
		"repeated key":   "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: " + integrity + "\n    resolution: {tarball: https://evil.example/a.tgz}\n",
		"repeated entry": "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: " + integrity + "\n  a@1.0.0:\n    resolution: " + integrity + "\n",
	}
	for name, src := range pnpm {
		if _, err := (pnpmLock{}).Parse([]byte(src)); err == nil {
			t.Errorf("pnpm-lock.yaml with a %s was read", name)
		}
	}
	berry := "__metadata:\n  version: 8\n\"a@npm:1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n  checksum: 10c0/" + strings.Repeat("a", 128) + "\n  checksum: 10c0/" + strings.Repeat("b", 128) + "\n"
	if _, err := (yarnLock{}).Parse([]byte(berry)); err == nil {
		t.Error("a yarn.lock with a repeated checksum was read")
	}
	compose := "services:\n  web:\n    image: alpine@sha256:" + strings.Repeat("a", 64) + "\n    image: evil@sha256:" + strings.Repeat("b", 64) + "\n"
	if _, err := (composeFile{}).Parse([]byte(compose)); err == nil {
		t.Error("a compose file with a repeated key was read")
	}
}

func TestGoSumAcceptsOnlyRealHashes(t *testing.T) {
	src := "a v1.0.0 h1:" + testToken + "\nb v1.0.0 h1:https://user:secret@host/x\nc v1.0.0 h1:" + strings.Repeat("A", 43) + "=\n"
	res := parseWith(t, goSum{}, src)
	if len(res.Dependencies) != 1 || res.Dependencies[0].Name != "c" || len(res.Warnings) != 2 {
		t.Fatalf("dependencies %+v, warnings %v", res.Dependencies, res.Warnings)
	}
	out, _ := json.Marshal(res)
	if bytes.Contains(out, []byte("ptl1")) || bytes.Contains(out, []byte("secret")) {
		t.Errorf("hash text survived: %s", out)
	}
}

// TestDockerfileHeredocsAsBuildKitReadsThem: only an unquoted shell word
// "[n]<<[-]WORD" of RUN, COPY or ADD opens a heredoc; anything else that
// contains "<<" must not swallow the FROM lines after it.
func TestDockerfileHeredocsAsBuildKitReadsThem(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, line := range []string{
		"RUN cat <<<hello",
		"RUN echo $((1<<n))",
		`RUN echo "x<<EOF"`,
		"RUN echo 'a <<EOF b'",
		"LABEL note=<<EOF",
		"ENV A=<<EOF",
	} {
		src := "FROM base" + digest + "\n" + line + "\nFROM later" + digest + "\n"
		res := parseWith(t, dockerfile{}, src)
		if len(res.Dependencies) != 2 {
			t.Errorf("%q hid the FROM after it: %+v %v", line, res.Dependencies, res.Warnings)
		}
	}
	for _, opener := range []string{"RUN <<EOF", "RUN 3<<-'EOF' cat", `COPY <<"EOF" /x`} {
		src := "FROM base" + digest + "\n" + opener + "\nFROM inside-the-heredoc" + digest + "\n\tEOF\nEOF\nFROM later" + digest + "\n"
		res := parseWith(t, dockerfile{}, src)
		var names []string
		for _, d := range res.Dependencies {
			names = append(names, d.Name)
		}
		if strings.Join(names, ",") != "library/base,library/later" {
			t.Errorf("%q: images %v", opener, names)
		}
	}
	res := parseWith(t, dockerfile{}, "FROM base"+digest+"\nRUN <<EOF\nFROM never-closed"+digest+"\n")
	if len(res.Dependencies) != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "never closed") {
		t.Errorf("an unclosed heredoc: %+v %v", res.Dependencies, res.Warnings)
	}
}

// allocated returns the bytes fn allocates.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestMemoryStaysProportional: inputs crafted to make a parser hold many
// times their size in memory are read in bounded memory or refused.
func TestMemoryStaysProportional(t *testing.T) {
	newlines := bytes.Repeat([]byte("\n"), 2<<20)
	for _, p := range []Parser{requirementsTxt{}, yarnLock{}, gemfileLock{}, gradleLock{}, goMod{}, goSum{}, dockerfile{}} {
		if n := allocated(func() { _, _ = p.Parse(newlines) }); n > 24<<20 {
			t.Errorf("%s allocated %d MiB for 2 MiB of empty lines", p.Format(), n>>20)
		}
	}
	var dotted strings.Builder
	for i := 0; dotted.Len() < 1<<20; i++ {
		fmt.Fprintf(&dotted, "%s.k%d = 1\n", strings.TrimSuffix(strings.Repeat("a.", 60), "."), i)
	}
	if n := allocated(func() { _, _ = parseTOML([]byte(dotted.String())) }); n > 64<<20 {
		t.Errorf("1 MiB of dotted keys allocated %d MiB", n>>20)
	}
	dense := []byte("lockfileVersion: '9.0'\npackages: [" + strings.Repeat("1,", 1<<19) + "1]\n")
	if _, err := (pnpmLock{}).Parse(dense); err == nil || !strings.Contains(err.Error(), "dense") {
		t.Errorf("dense YAML: %v", err)
	}
	if _, err := (pnpmLock{}).Parse(append([]byte("lockfileVersion: '9.0'\n#"), bytes.Repeat([]byte("x"), maxTreeInput)...)); err == nil {
		t.Error("a YAML lock file over the tree limit was read")
	}
}

// TestPOMWithDeepLongNamesIsLinear: element paths are built only where they
// can match, so long names nested deep cost nothing per element.
func TestPOMWithDeepLongNamesIsLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString("<project>")
	name := strings.Repeat("n", 800)
	for i := 0; i < 200; i++ {
		b.WriteString("<" + name + ">")
	}
	for i := 0; i < 20000; i++ {
		b.WriteString("<v>1</v>")
	}
	for i := 0; i < 200; i++ {
		b.WriteString("</" + name + ">")
	}
	b.WriteString("</project>")
	timeBound(t, "a POM of deep long names", func() { _, _ = (pomXML{}).Parse([]byte(b.String())) })
}
