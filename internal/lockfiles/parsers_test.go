package lockfiles

import (
	"fmt"
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
	"package.json":                       "",
	"requirements.in":                    "",
	"Pipfile":                            "",
	"pyproject.toml":                     "",
	"Cargo.toml":                         "",
	"go.work":                            "",
	"Gemfile":                            "",
	"composer.json":                      "",
	"build.gradle":                       "",
	"notes.txt":                          "",
	"docs/requirements.md":               "",
	"composer.yaml.bak":                  "",
	"my-requirements-notes.txt.orig":     "",
	"something.lockfile":                 "",
	"node_modules/x/package-lock.jsonx":  "",
	"yarn.lock/":                         "",
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
	sum := parseOne(goSum{}, "svc/go.sum", []byte(
		"example.com/a v1.0.0 h1:AAAA=\nexample.com/a v1.0.0/go.mod h1:BBBB=\n"+
			"example.com/b v2.0.0 h1:CCCC=\nexample.com/old v0.1.0/go.mod h1:DDDD=\n"))
	other := parseOne(goSum{}, "other/go.sum", []byte("example.com/a v1.0.0 h1:AAAA=\n"))
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
	cases := map[[2]string]string{
		{"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "lodash"}:             "https://registry.npmjs.org",
		{"https://registry.npmjs.org/@types/node/-/node-1.0.0.tgz", "@types/node"}:       "https://registry.npmjs.org",
		{"https://npm.example.com/repo/@types%2fnode/-/node-1.0.0.tgz", "@types/node"}:   "https://npm.example.com/repo",
		{"https://npm.example.com/repo/%40types%2fnode/-/node-1.0.0.tgz", "@types/node"}: "https://npm.example.com/repo",
		{"https://u:p@npm.example.com/r/lodash/-/lodash-1.0.0.tgz?x=1", "lodash"}:        "https://npm.example.com/r",
		{"https://pkgs.example.com/download/lodash/1.0.0/abc", "lodash"}:                 "https://pkgs.example.com",
	}
	for in, want := range cases {
		if got := npmRegistryBase(in[0], in[1]); got != want {
			t.Errorf("npmRegistryBase(%q, %q) = %q, want %q", in[0], in[1], got, want)
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
// are small, and only a super-linear algorithm makes them slow.
func timeBound(t *testing.T, what string, fn func()) {
	t.Helper()
	start := time.Now()
	fn()
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("%s took %s", what, d)
	}
}

// TestAliasesCannotMultiplyWork: lock files written by tools never contain
// YAML aliases; one that does gets nothing from them. A hundred thousand
// entries aliasing one huge mapping would otherwise be quadratic work.
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
		res := parseWith(t, yarnLock{}, b.String())
		if len(res.Dependencies) != 1 {
			t.Errorf("%d dependencies; aliases must give nothing", len(res.Dependencies))
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
	var b strings.Builder
	b.WriteString("a==1.0")
	for i := 0; i < 200000; i++ {
		fmt.Fprintf(&b, " --hash=sha256:%064x", i)
	}
	b.WriteString("\n")
	line := b.String()
	timeBound(t, "200 000 hashes, twice", func() {
		f := ParseFile(nil, nil, "requirements.txt", []byte(line+line))
		if len(f.Dependencies) != 1 || len(f.Dependencies[0].Digests) != 200000 {
			t.Errorf("%d dependencies", len(f.Dependencies))
		}
	})
}
