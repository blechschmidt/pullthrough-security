package lockfiles

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestNPMRequirementsResolvePositions(t *testing.T) {
	lock := `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"foo": "^1.0.0", "bar": "^1.0.0", "alias": "npm:real@^3.1.0"}, "devDependencies": {"dev": "~2.0.0"}},
    "node_modules/foo": {"version": "1.2.0"},
    "node_modules/bar": {"version": "1.0.0", "dependencies": {"foo": "^2.0.0"}},
    "node_modules/bar/node_modules/foo": {"version": "2.1.0"},
    "node_modules/alias": {"name": "real", "version": "3.1.4"},
    "node_modules/dev": {"version": "2.0.5", "dev": true, "dependencies": {"foo": ">=1.1.0"}},
    "packages/ws": {"name": "ws", "dependencies": {"foo": "1.x"}, "devDependencies": {"bar": "*"}},
    "node_modules/ws": {"resolved": "packages/ws", "link": true}
  }
}`
	reqs, err := NPMRequirements([]byte(lock), nil)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string][]string{}
	for _, r := range reqs {
		if r.Position == "" {
			t.Errorf("%s from %q did not resolve", r.Name, r.Dependent)
			continue
		}
		k := r.Package + "@" + r.Version
		byKey[k] = append(byKey[k], r.Range)
	}
	want := map[string]string{
		"foo@1.2.0":  "^1.0.0,>=1.1.0,1.x",
		"foo@2.1.0":  "^2.0.0",
		"bar@1.0.0":  "^1.0.0,*",
		"real@3.1.4": "^3.1.0",
		"dev@2.0.5":  "~2.0.0",
	}
	for k, w := range want {
		got := strings.Join(byKey[k], ",")
		if !sameSet(got, w) {
			t.Errorf("%s: ranges %q, want %q", k, got, w)
		}
	}
}

func sameSet(a, b string) bool {
	as, bs := strings.Split(a, ","), strings.Split(b, ",")
	if len(as) != len(bs) {
		return false
	}
	m := map[string]int{}
	for _, x := range as {
		m[x]++
	}
	for _, x := range bs {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestNPMRequirementsV1(t *testing.T) {
	lock := `{"name":"app","lockfileVersion":1,"requires":true,"dependencies":{
  "foo":{"version":"1.2.0","requires":{"baz":"^1.0.0"}},
  "bar":{"version":"1.0.0","requires":{"foo":"^2.0.0"},"dependencies":{"foo":{"version":"2.0.0"}}},
  "baz":{"version":"1.5.0"},
  "al":{"version":"npm:real@3.0.0"}
}}`
	pkg := `{"name":"app","dependencies":{"foo":"^1.2.0","bar":"1.0.0","al":"npm:real@^3.0.0"}}`
	reqs, err := NPMRequirements([]byte(lock), []byte(pkg))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, r := range reqs {
		got[r.Package+"@"+r.Version] = append(got[r.Package+"@"+r.Version], r.Range)
	}
	if !sameSet(strings.Join(got["foo@1.2.0"], ","), "^1.2.0") || !sameSet(strings.Join(got["foo@2.0.0"], ","), "^2.0.0") ||
		!sameSet(strings.Join(got["baz@1.5.0"], ","), "^1.0.0") || !sameSet(strings.Join(got["real@3.0.0"], ","), "^3.0.0") {
		t.Fatalf("ranges: %v", got)
	}
	if _, err := NPMRequirements([]byte(`{"name":"x"}`), nil); err == nil {
		t.Error("a lock without packages or dependencies must fail")
	}
}

func TestCargoManifestRequirements(t *testing.T) {
	toml := `
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0.100"
tokio = { version = "~1.38", features = ["full"] }
local = { path = "../local" }
renamed = { package = "real-crate", version = "=0.4.2" }
shared = { workspace = true }

[dev-dependencies]
criterion = "0.5"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[workspace.dependencies]
shared = "2.1"
`
	reqs, err := CargoManifestRequirements([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range reqs {
		got[r.Name] = r.Requirement + " (" + r.Table + ")"
	}
	want := map[string]string{
		"serde":      "1.0.100 (dependencies)",
		"tokio":      "~1.38 (dependencies)",
		"real-crate": "=0.4.2 (dependencies)",
		"criterion":  "0.5 (dev-dependencies)",
		"libc":       "0.2 (target.cfg(unix).dependencies)",
		"shared":     "2.1 (workspace.dependencies)",
	}
	if len(got) != len(want) {
		t.Fatalf("requirements: %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
	pkgs, err := CargoLockPackages([]byte("version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b 1.0.0\",\n \"c\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"))
	if err != nil || len(pkgs) != 2 || len(pkgs[0].Dependencies) != 2 {
		t.Fatalf("lock packages: %+v %v", pkgs, err)
	}
	if n, v := CargoDependencyRef(pkgs[0].Dependencies[0]); n != "b" || v != "1.0.0" {
		t.Errorf("ref: %s %s", n, v)
	}
	if n, v := CargoDependencyRef("c 2.0.0 (registry+https://x)"); n != "c" || v != "2.0.0" {
		t.Errorf("ref with source: %s %s", n, v)
	}
}

func TestPythonRequirements(t *testing.T) {
	cases := map[string]PythonRequirement{
		"requests>=2.0,<3": {Name: "requests", Specifier: ">=2.0,<3"},
		"Django[argon2] ~= 4.2 ; python_version >= '3.8'": {Name: "django", Specifier: "~=4.2", Marker: "python_version >= '3.8'"},
		"zope.interface":                    {Name: "zope-interface"},
		"attrs (>=21.3)":                    {Name: "attrs", Specifier: ">=21.3"},
		"tinyutil==1.0.0 --hash=sha256:abc": {Name: "tinyutil", Specifier: "==1.0.0"},
		"foo == 1.0  # pinned for now":      {Name: "foo", Specifier: "==1.0"},
	}
	for line, want := range cases {
		got, ok := PythonRequirementLine(line)
		if !ok || got != want {
			t.Errorf("%q: %+v %v, want %+v", line, got, ok, want)
		}
	}
	for _, line := range []string{"-r other.in", "pkg @ https://x/pkg.whl", "# comment", "", "./local"} {
		if r, ok := PythonRequirementLine(line); ok {
			t.Errorf("%q is not a requirement by name: %+v", line, r)
		}
	}
	in := PythonRequirementsIn([]byte("# top\nrequests>=2 \\\n    ,<3\n-c constraints.txt\nidna\n"))
	if len(in) != 2 || in[0].Specifier != ">=2,<3" {
		t.Errorf("requirements.in: %+v", in)
	}
	pp, err := PyProjectRequirements([]byte("[project]\nname = \"x\"\ndependencies = [\"httpx>=0.27\", \"anyio\"]\n\n[project.optional-dependencies]\ncli = [\"click<9\"]\n\n[dependency-groups]\ndev = [\"pytest>=8\"]\n"))
	if err != nil || len(pp) != 4 {
		t.Fatalf("pyproject: %+v %v", pp, err)
	}
}

// TestNPMRequirementsAreBounded: a lock file of a few megabytes can declare
// millions of ranges; reading them stops at the bound instead of holding one
// record each.
func TestNPMRequirementsAreBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"dependencies":{`)
	for i := 0; i < maxNPMRanges+10; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"p` + strconv.Itoa(i) + `":"1"`)
	}
	b.WriteString(`}}}}`)
	if _, err := NPMRequirements([]byte(b.String()), nil); !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("over the bound: %v", err)
	}
}

// TestRequirementsAreReadAsPipReadsThem holds the requirements reader to pip's
// own preprocessing (req_file.py): what pip installs must be what a scan sees.
// The expected set is what pip 24's parse_requirements returned for this file.
func TestRequirementsAreReadAsPipReadsThem(t *testing.T) {
	data := "safe==1.0.0\revil==2.0.0\na==1.0\fb==2.0\nc==1.0 d==2.0\n# a comment \\\nhidden==3.0\n" +
		"x==1.0 # trailing comment \\\nswallowed==9.9\ny==1.0\vz==2.0\n"
	res, err := requirementsTxt{}.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range res.Dependencies {
		got = append(got, d.Name+"=="+d.Version)
	}
	sort.Strings(got)
	want := "a==1.0,b==2.0,c==1.0,d==2.0,evil==2.0.0,hidden==3.0,safe==1.0.0,x==1.0,y==1.0,z==2.0"
	if strings.Join(got, ",") != want {
		t.Fatalf("read %v, pip reads %s", got, want)
	}
}
