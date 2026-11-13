package lockfiles

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// depsOf parses src with p and returns "name version" of every dependency.
func depsOf(t *testing.T, p Parser, src string) ([]Dependency, *Result) {
	t.Helper()
	res, err := p.Parse([]byte(src))
	if err != nil {
		t.Fatalf("%s: %v", p.Format(), err)
	}
	return res.Dependencies, res
}

func names(deps []Dependency) string {
	var out []string
	for _, d := range deps {
		out = append(out, d.Name+" "+d.Version)
	}
	return strings.Join(out, ", ")
}

func warned(res *Result, sub string) bool {
	return strings.Contains(strings.Join(res.Warnings, "\n"), sub)
}

func TestMixLockReadsLiteralsOnly(t *testing.T) {
	for name, src := range map[string]string{
		"interpolation": `%{"a": {:hex, :a, "#{System.cmd("id", [])}"}}`,
		"call":          `%{"a": {:hex, :a, File.read!("x")}}`,
		"variable":      `%{"a": x}`,
		"sigil":         `%{"a": ~s(x)}`,
		"struct":        `%{"a": %URI{}}`,
		"conflict":      "%{\n<<<<<<< HEAD\n}",
	} {
		if _, err := (mixLock{}).Parse([]byte(src)); err == nil || name != "conflict" && !strings.Contains(err.Error(), "Elixir code") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (mixLock{}).Parse([]byte(`%{"a": {:hex, :a, "1"}, "a": {:hex, :a, "2"}}`)); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Errorf("a repeated key: %v", err)
	}
	deps, res := depsOf(t, mixLock{}, `%{
  "old": {:hex, :old, "0.1.0"},
  "org": {:hex, :org, "1.0.0", "`+strings.Repeat("a", 64)+`", [:mix], [], "hexpm:acme", "`+strings.Repeat("b", 64)+`"},
  "own": {:hex, :own, "1.0.0", "`+strings.Repeat("a", 64)+`", [:mix], [], "myrepo", "`+strings.Repeat("c", 64)+`"},
  "renamed": {:hex, :real_name, "2.0.0", "`+strings.Repeat("d", 64)+`", [:mix], [{:x, "~> 1.0", [hex: :x, optional: true]}], "hexpm", "`+strings.Repeat("e", 64)+`"},
  "branch": {:git, "https://github.com/o/b.git", "main", [branch: "main"]},
}`)
	if got := names(deps); got != "old 0.1.0, org 1.0.0, own 1.0.0, real_name 2.0.0, branch main" {
		t.Fatalf("dependencies %s", got)
	}
	if deps[0].Registry != "https://repo.hex.pm" || len(deps[0].Digests) != 0 {
		t.Errorf("old tuple %+v", deps[0])
	}
	if deps[1].Registry != "https://repo.hex.pm/repos/acme" || deps[2].Registry != "" || !warned(res, `"myrepo"`) {
		t.Errorf("repositories %q %q, warnings %q", deps[1].Registry, deps[2].Registry, res.Warnings)
	}
	// A Git dependency at a ref that is no commit is reported, unverified.
	if d := deps[4]; d.Source != SourceGit || d.Revision != "" || !strings.Contains(d.UnverifiedReason, "not a full commit") {
		t.Errorf("git entry at a branch %+v", d)
	}
	// Only atom keys pin anything; a string name is the package's name; Mix
	// cannot read "1e5", so it reads the file as empty — and so must we.
	deps, res = depsOf(t, mixLock{}, `%{"a" => {:hex, :a, "1.0.0"}, "b": {:hex, "evil", "6.6.6"}}`)
	if names(deps) != "evil 6.6.6" || !warned(res, "not keyed by an atom") {
		t.Errorf("dependencies %s, warnings %q", names(deps), res.Warnings)
	}
	for _, n := range []string{"1e5", "1.", ".5", "1.0e", "0x", "1_", "1__0", "00x1"} {
		if _, err := (mixLock{}).Parse([]byte(`%{"a": {:hex, :a, "1.0.0", ` + n + `}}`)); err == nil {
			t.Errorf("%s was read as an Elixir number", n)
		}
	}
	for _, n := range []string{"1", "-1", "1_000", "1.5", "1.0e10", "1.0E-3", "0x1F", "0o17", "0b101"} {
		if _, err := (mixLock{}).Parse([]byte(`%{"a": {:hex, :a, "1.0.0", ` + n + `}}`)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

func TestHCLReadsAsTerraformReads(t *testing.T) {
	for name, src := range map[string]string{
		"repeated attribute": "module \"a\" {\n  source = \"x/y/z\"\n  source = \"x/y/w\"\n}\n",
		"unclosed block":     "module \"a\" {\n  source = \"x/y/z\"\n",
		"label on next line": "module\n\"a\" {}\n",
		"bad escape":         "a = \"\\q\"\n",
		"open heredoc":       "a = <<EOT\nx\n",
		"unbalanced":         "a = [1, 2))\n",
	} {
		if _, err := parseHCL([]byte(src), "module"); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	body, err := parseHCL([]byte(`# comment
/* block
   comment */
locals {
  x = { a = [1, 2], b = "%{ if c }d%{ endif }" }
  y = <<-EOT
    module "fake" { source = "evil/evil/evil" }
    ${var.z}
  EOT
}
module "m" { source = "a/b/c" }
module "n" {
  source  = "lit\u00e9ral $${not.a.template}"
  version = "${var.v}"
  list    = ["a",
    "b", ]
  nested {
    source = "ignored/ignored/ignored"
  }
}
`), "module")
	if err != nil {
		t.Fatal(err)
	}
	if len(body.blocks) != 2 || body.blockCount != 3 {
		t.Fatalf("blocks %d of %d", len(body.blocks), body.blockCount)
	}
	m, n := body.blocks[0].body, body.blocks[1].body
	if a := m.attrs["source"]; a == nil || !a.isStr || a.str != "a/b/c" {
		t.Errorf("one-line block source %+v", a)
	}
	if a := n.attrs["source"]; !a.isStr || a.str != "lit\u00e9ral ${not.a.template}" {
		t.Errorf("escaped source %+v", a)
	}
	if a := n.attrs["version"]; a.isStr {
		t.Errorf("a template was read as a literal: %+v", a)
	}
	if a := n.attrs["list"]; !a.isList || strings.Join(a.list, ",") != "a,b" {
		t.Errorf("list %+v", a)
	}
	if _, ok := n.attrs["nested"]; ok || len(n.blocks) != 0 {
		t.Error("a nested block was kept")
	}
}

func TestTerraformModuleSources(t *testing.T) {
	commit := strings.Repeat("a", 40)
	src := `
module "registry" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "= 5.1.2"
}
module "private" {
  source  = "app.terraform.io/acme/vpc/aws"
  version = "1.0.0"
}
module "range" {
  source  = "terraform-aws-modules/vpc/aws"
  version = ">= 5.0"
}
module "unversioned" {
  source = "terraform-aws-modules/iam/aws"
}
module "git-commit" {
  source = "git::https://u:p@example.com/net.git//modules/vpc?ref=` + commit + `"
}
module "git-tag" {
  source = "git::ssh://git@example.com/net.git?ref=v1.2.0&depth=1"
}
module "scp" {
  source = "git@github.com:o/r.git?ref=` + commit + `"
}
module "github" {
  source = "github.com/o/r?ref=v3"
}
module "archive" {
  source = "https://example.com/vpc.zip?checksum=sha256:` + strings.Repeat("b", 64) + `"
}
module "s3" {
  source = "s3::https://s3.amazonaws.com/bucket/vpc.zip"
}
module "local" {
  source = "../modules/x"
}
module "computed" {
  source = local.src
}
`
	deps, res := depsOf(t, terraformModules{}, src)
	got := map[string]Dependency{}
	for _, d := range deps {
		got[d.Name] = d
	}
	if d := got["terraform-aws-modules/vpc/aws"]; d.Version != "5.1.2" || d.Registry != "https://registry.terraform.io" || d.UnverifiedReason == "" {
		t.Errorf("registry module %+v", d)
	}
	if d := got["acme/vpc/aws"]; d.Registry != "https://app.terraform.io" {
		t.Errorf("private registry module %+v", d)
	}
	if d := got["git-commit"]; d.Revision != commit || d.Registry != "https://example.com/net.git" || d.Source != SourceGit {
		t.Errorf("git commit module %+v", d)
	}
	if d := got["git-tag"]; d.Version != "v1.2.0" || d.Revision != "" || d.Registry != "ssh://git@example.com/net.git" {
		t.Errorf("git tag module %+v", d)
	}
	if d := got["scp"]; d.Revision != commit || d.Registry != "git@github.com:o/r.git" {
		t.Errorf("scp-like module %+v", d)
	}
	if d := got["github"]; d.Version != "v3" || d.Registry != "https://github.com/o/r" {
		t.Errorf("github shorthand %+v", d)
	}
	if d := got["archive"]; d.Source != SourceURL || len(d.Digests) != 1 || d.Version != "sha256:"+strings.Repeat("b", 64) {
		t.Errorf("archive module %+v", d)
	}
	if len(deps) != 7 {
		t.Errorf("dependencies %s", names(deps))
	}
	for _, w := range []string{`"range"`, `"unversioned"`, `"s3": a source of a kind this parser does not read (s3)`, `"computed": its source is not a literal string`} {
		if !warned(res, w) {
			t.Errorf("no warning %s in %q", w, res.Warnings)
		}
	}
	if warned(res, "local") {
		t.Error("a local module was warned about")
	}
	if _, err := (terraformModules{}).Parse([]byte("module \"a\" {}\nmodule \"a\" {}\n")); err == nil {
		t.Error("a module declared twice was read")
	}
	if _, err := (terraformLock{}).Parse([]byte("provider \"a/b\" { version = \"1\" }\nprovider \"a/b\" { version = \"2\" }\n")); err == nil {
		t.Error("a provider locked twice was read")
	}
}

func TestPuppetfileReadsDeclarationsOnly(t *testing.T) {
	deps, res := depsOf(t, puppetfile{}, `
forge 'https://forge.example.com'
mod('puppetlabs/stdlib', '9.4.1')
mod "x-#{y}", '1.0'
mod 'a-b', :git => 'https://h/a.git', :git => 'https://h/b.git', :commit => '`+strings.Repeat("c", 40)+`'
if ENV['X'] then mod 'evil-mod', '6.6.6' end
version = '1.2.3'
mod 'puppetlabs-ntp', ">= 1.0"
mod 'puppetlabs-lvm', version: '2.0.0'
`)
	if got := names(deps); got != "puppetlabs-stdlib 9.4.1, puppetlabs-lvm 2.0.0" {
		t.Errorf("dependencies %s", got)
	}
	if deps[0].Registry != "https://forge.example.com" {
		t.Errorf("forge %q", deps[0].Registry)
	}
	for _, line := range []string{"line 4", "line 5", "line 6", "line 7", "line 8"} {
		if !warned(res, line+":") {
			t.Errorf("no warning for %s: %q", line, res.Warnings)
		}
	}
}

func TestRenvLock(t *testing.T) {
	if _, err := (renvLock{}).Parse([]byte(`{"Packages": {"a": {"Package": "a", "Version": "1", "Version": "2"}}}`)); err == nil {
		t.Error("a repeated field was read")
	}
	if _, err := (renvLock{}).Parse([]byte(`{"Packages": {"a": {}, "a": {}}}`)); err == nil {
		t.Error("a repeated package was read")
	}
	deps, res := depsOf(t, renvLock{}, `{
  "R": {"Version": "4.4.1", "Repositories": [{"Name": "CRAN", "URL": "https://cran.example.org"}]},
  "Packages": {
    "a": {"Package": "a", "Version": "1.0", "Source": "Repository", "Repository": "CRAN", "Hash": "`+strings.Repeat("a", 32)+`"},
    "b": {"Package": "b", "Version": "2.0", "Source": "Repository", "Repository": "CRAN"},
    "c": {"Package": "c", "Version": "3.0", "Source": "GitHub", "RemoteHost": "ghe.example.com/api/v3", "RemoteUsername": "o", "RemoteRepo": "c", "RemoteSha": "`+strings.Repeat("b", 40)+`"},
    "d": {"Package": "d", "Version": "4.0", "Source": "Local", "RemoteUrl": "/tmp/d"},
    "e": {"package": "e", "version": "5.0", "Source": "Repository"}
  }
}`)
	if got := names(deps); got != "a 1.0, b 2.0, c 3.0" {
		t.Fatalf("dependencies %s (warnings %q)", got, res.Warnings)
	}
	if deps[0].Registry != "https://cran.example.org" || !strings.Contains(deps[0].UnverifiedReason, "DESCRIPTION") || strings.Contains(deps[1].UnverifiedReason, "DESCRIPTION") {
		t.Errorf("repository packages %+v / %+v", deps[0], deps[1])
	}
	if deps[2].Registry != "https://ghe.example.com/o/c" || deps[2].Source != SourceGit {
		t.Errorf("GitHub Enterprise package %+v", deps[2])
	}
	// Keys match exactly: "package" and "version" are not "Package" and "Version".
	if !warned(res, "e: no usable name or version") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestDenoLock(t *testing.T) {
	if _, err := (denoLock{}).Parse([]byte(`{"version": "4", "jsr": {}, "jsr": {}}`)); err == nil {
		t.Error("a repeated top-level key was read")
	}
	deps, _ := depsOf(t, denoLock{}, `{
  "version": "4",
  "jsr": {"@std/path@1.0.8": {"integrity": "`+strings.Repeat("a", 64)+`"}, "@std/path@1.0.8": {"integrity": "`+strings.Repeat("b", 64)+`"}},
  "npm": {"@scope/pkg@1.0.0_peer@2.0.0": {"integrity": "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
  "remote": {"https://deno.land/x/oak@v12.6.0/mod.ts": "`+strings.Repeat("c", 64)+`"}
}`)
	if got := names(deps); got != "@std/path 1.0.8, @scope/pkg 1.0.0, deno.land/x/oak@v12.6.0/mod.ts sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("dependencies %s", got)
	}
	if deps[0].Digests[0].Value != strings.Repeat("b", 64) || deps[0].Digests[0].Of != "jsr-manifest" {
		t.Errorf("a repeated package keeps its last entry: %+v", deps[0].Digests)
	}
	if deps[1].Type != "npm" || deps[2].Type != "generic" || deps[2].Source != SourceURL {
		t.Errorf("types %s %s", deps[1].Type, deps[2].Type)
	}
}

func TestFlakeLockInputs(t *testing.T) {
	rev := strings.Repeat("a", 40)
	deps, res := depsOf(t, flakeLock{}, `{"nodes": {
  "a": {"locked": {"type": "gitlab", "owner": "o", "repo": "r", "host": "gitlab.example.com", "rev": "`+rev+`", "narHash": "sha256:0`+strings.Repeat("0", 51)+`"}},
  "b": {"locked": {"type": "github", "owner": "o", "repo": "r", "narHash": "sha256-`+strings.Repeat("A", 43)+`="}},
  "c": {"locked": {"type": "path", "path": "/x", "narHash": "sha256-`+strings.Repeat("A", 43)+`="}},
  "d": {"locked": {"type": "git", "url": "file:///x", "rev": "`+rev+`"}},
  "root": {"inputs": {"a": "a"}}
}, "root": "root", "version": 7}`)
	if len(deps) != 2 || deps[0].Name != "gitlab:o/r" || deps[0].Registry != "https://gitlab.example.com/o/r" || deps[0].Digests[0].Of != "nar" {
		t.Fatalf("dependencies %+v", deps)
	}
	if deps[0].Digests[0].Value != strings.Repeat("0", 64) {
		t.Errorf("base-32 NAR hash %+v", deps[0].Digests[0])
	}
	// An input locked without a commit is still pinned by its NAR hash.
	if d := deps[1]; d.Name != "github:o/r" || d.Revision != "" || d.Version != "sha256:"+strings.Repeat("0", 64) {
		t.Errorf("input without a commit %+v", d)
	}
	for _, w := range []string{`"c": a local path`, `"d": a git repository that is not fetched over the network`} {
		if !warned(res, w) {
			t.Errorf("no warning %s: %q", w, res.Warnings)
		}
	}
	if _, ok := nixBase32Decode(strings.Repeat("z", 52), 32); ok {
		t.Error("base-32 text with non-zero padding bits decoded")
	}
}

func TestConanReferences(t *testing.T) {
	rrev := strings.Repeat("a", 32)
	for ref, want := range map[string]string{
		"zlib/1.3.1#" + rrev + "%1708593606.497": "zlib 1.3.1  conan-recipe",
		"x/2.0@acme/stable#" + rrev:              "x 2.0 x/2.0@acme/stable conan-recipe",
		"y/3.0@_/_":                              "y 3.0  ",
		"z/1.0#" + strings.Repeat("b", 40):       "z 1.0  ",
		"no-version":                             "error",
		"r/[>=1 <2]":                             "error",
		"t/1.0#" + rrev + "%notatime":            "error",
	} {
		d, ok := conanDependency(ref, 1)
		got := "error"
		if ok {
			of := ""
			if len(d.Digests) > 0 {
				of = d.Digests[0].Of
			}
			got = d.Name + " " + d.Version + " " + d.ID + " " + of
		}
		if got != want {
			t.Errorf("%s: %q, want %q", ref, got, want)
		}
	}
	// Conan 2 pins the recipe, not the binary: unverified.
	d := Dependency{Digests: []Digest{{Algorithm: "md5", Value: rrev, Of: "conan-recipe"}}}
	markVerification(&d, formatInfo["conan/conan.lock"])
	if !d.Unverified || !strings.Contains(d.UnverifiedReason, "binary") {
		t.Errorf("a recipe revision alone: %+v", d)
	}
}

func TestSwiftPins(t *testing.T) {
	deps, res := depsOf(t, packageResolved{}, `{"pins": [
  {"identity": "a", "kind": "remoteSourceControl", "location": "https://h/a.git", "state": {"branch": "main"}},
  {"identity": "b", "kind": "localSourceControl", "location": "/src/b", "state": {"revision": "`+strings.Repeat("b", 40)+`"}},
  {"identity": "scope.c", "kind": "registry", "location": "", "state": {"version": "1.0.0"}},
  {"identity": "d", "kind": "remoteSourceControl", "location": "git@github.com:o/D.git", "state": {"revision": "`+strings.Repeat("d", 40)+`", "version": "2.0.0"}}
], "version": 2}`)
	if got := names(deps); got != "scope.c 1.0.0, d 2.0.0" {
		t.Fatalf("dependencies %s", got)
	}
	if deps[0].UnverifiedReason == "" || deps[1].Registry != "git@github.com:o/D.git" {
		t.Errorf("pins %+v", deps)
	}
	if !warned(res, `pinned to branch "main" without a commit`) || !warned(res, "b: a local package") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if got := swiftIdentity("https://github.com/Apple/Swift-Log.git/"); got != "swift-log" {
		t.Errorf("identity %q", got)
	}
}

func TestCabalAndStack(t *testing.T) {
	deps, res := depsOf(t, cabalFreeze{}, `-- comment
constraints: any.aeson ==2.2.3.0,
             setup.aeson ==2.2.3.0,
             aeson -ordered-keymap,
             any.base installed,
             any.rts ==1.0.2,
             any.text >=2.0 && <2.2,
             any.vector == 0.13.1.0
package aeson
  flags: +x
index-state: hackage.haskell.org 2024-11-11T00:00:00Z
`)
	if got := names(deps); got != "aeson 2.2.3.0, vector 0.13.1.0" {
		t.Errorf("dependencies %s", got)
	}
	if !warned(res, "text is constrained to a range") {
		t.Errorf("warnings %q", res.Warnings)
	}
	// A Hackage package whose lock entry has only its .cabal file's hash is
	// unverified: the description is pinned, the source is not.
	deps, _ = depsOf(t, stackLock{}, "packages:\n- completed:\n    hackage: a-1.0@sha256:"+strings.Repeat("a", 64)+",10\n  original:\n    hackage: a-1.0\n")
	if len(deps) != 1 || deps[0].Name != "a" || deps[0].Version != "1.0" {
		t.Fatalf("stack dependencies %+v", deps)
	}
	markVerification(&deps[0], formatInfo["hackage/stack.yaml.lock"])
	if !deps[0].Unverified || !strings.Contains(deps[0].UnverifiedReason, ".cabal") {
		t.Errorf("cabal-file hash alone: %+v", deps[0])
	}
}

func TestChartLockRepositories(t *testing.T) {
	deps, res := depsOf(t, chartLock{}, `dependencies:
- name: a
  repository: oci://registry.example.com/charts
  version: 1.0.0
- name: b
  repository: "@stable"
  version: 2.0.0
- name: c
  repository: alias:stable
  version: 3.0.0
- name: d
  repository: file://../d
  version: 4.0.0
- name: e
  repository: ""
  version: 5.0.0
digest: sha256:`+strings.Repeat("a", 64)+`
`)
	if got := names(deps); got != "a 1.0.0, b 2.0.0, c 3.0.0" {
		t.Errorf("dependencies %s", got)
	}
	if deps[0].Registry != "oci://registry.example.com/charts" || deps[1].Registry != "" {
		t.Errorf("registries %q %q", deps[0].Registry, deps[1].Registry)
	}
	if !warned(res, "d 4.0.0: a chart in a local directory") || !warned(res, "e 5.0.0: no repository") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestBrewfileEntries(t *testing.T) {
	deps, res := depsOf(t, brewfileLock{}, `{"entries": {
  "brew": {"src": {"version": "1.0", "bottle": false}, "src": {"version": "1.1", "bottle": false}},
  "cask": {"firefox": {"version": "120.0", "options": {"full_name": "firefox"}}},
  "mas": {"Xcode": {"id": 497799835, "version": "15.0"}},
  "tap": {"user/repo": {"revision": "`+strings.Repeat("a", 40)+`"}}
}, "system": {}}`)
	if got := names(deps); got != "src 1.1, firefox 120.0, user/repo "+strings.Repeat("a", 40) {
		t.Fatalf("dependencies %s", got)
	}
	if !strings.Contains(deps[0].UnverifiedReason, "built from source") || deps[2].Registry != "https://github.com/user/homebrew-repo" {
		t.Errorf("entries %+v", deps)
	}
	if !warned(res, "a mas entry, which is not a Homebrew package") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestAnsibleVersions(t *testing.T) {
	for v, want := range map[string]string{"1.2.3": "1.2.3", "==1.2.3": "1.2.3", "== 1.2.3": "1.2.3", ">=1.0": "", "*": "", "": "", "1.0,<2": "", "!=1.0": ""} {
		got, ok := ansibleExactVersion(v)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("%q: %q, want %q", v, got, want)
		}
	}
	// Helm 2's requirements.yaml shares the name: nothing, no error.
	res, err := (ansibleRequirements{}).Parse([]byte("dependencies:\n- name: a\n  version: 1.0.0\n  repository: https://h\n"))
	if err != nil || len(res.Dependencies) != 0 || len(res.Warnings) != 0 {
		t.Errorf("Helm requirements.yaml: %v %+v", err, res)
	}
	if _, err := (ansibleRequirements{}).Parse([]byte("galaxy_info:\n  author: x\n")); err == nil {
		t.Error("a YAML file with neither collections nor roles was read")
	}
}

func TestCondaExplicitHashes(t *testing.T) {
	deps, res := depsOf(t, condaExplicit{}, `# platform: linux-64
@EXPLICIT
https://c.example/ch/linux-64/a-1.0-h_0.conda#`+strings.Repeat("a", 32)+`
https://c.example/ch/linux-64/b-2.0-h_0.tar.bz2#`+strings.Repeat("b", 64)+`
https://c.example/ch/noarch/c-3.0-py_0.conda#sha256:`+strings.Repeat("c", 64)+`
https://c.example/ch/noarch/d-4.0-py_0.conda
./local/e-5.0-h_0.conda
# pip f @ https://files.example/f-6.0-py3-none-any.whl#sha256=`+strings.Repeat("f", 64)+`
`)
	if got := names(deps); got != "a 1.0, b 2.0, c 3.0, d 4.0, f 6.0" {
		t.Fatalf("dependencies %s", got)
	}
	algs := []string{}
	for _, d := range deps[:3] {
		algs = append(algs, d.Digests[0].Algorithm+" "+d.Digests[0].Of)
	}
	if strings.Join(algs, ",") != "md5 linux-64/a-1.0-h_0.conda,sha256 linux-64/b-2.0-h_0.tar.bz2,sha256 noarch/c-3.0-py_0.conda" {
		t.Errorf("digests %v", algs)
	}
	if deps[0].Registry != "https://c.example/ch" || deps[4].Type != "pip" || len(deps[3].Digests) != 0 {
		t.Errorf("dependencies %+v", deps)
	}
	if !warned(res, "line 7: not a package URL") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if _, err := (condaExplicit{}).Parse([]byte("numpy==1.0\n")); err == nil {
		t.Error("a file without @EXPLICIT was read")
	}
	if name, version, build, ok := condaFileParts("ld_impl_linux-64-2.46.1-default_hbd61a6d_103.conda"); !ok || name != "ld_impl_linux-64" || version != "2.46.1" || build != "default_hbd61a6d_103" {
		t.Errorf("file parts %q %q %q", name, version, build)
	}
}

func TestJuliaManifest(t *testing.T) {
	deps, res := depsOf(t, juliaManifest{}, `manifest_format = "2.0"
[[deps.A]]
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "1.0.0"
git-tree-sha1 = "`+strings.Repeat("a", 40)+`"
[[deps.A]]
uuid = "11111111-990d-54b4-ab0e-23690620f79a"
version = "2.0.0"
git-tree-sha1 = "`+strings.Repeat("b", 40)+`"
[[deps.Dates]]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
[[deps.Dev]]
uuid = "22222222-990d-54b4-ab0e-23690620f79a"
path = "../Dev"
[[deps.Bad]]
uuid = "not-a-uuid"
version = "1.0.0"
git-tree-sha1 = "`+strings.Repeat("c", 40)+`"
`)
	// Two packages of one name from two registries are two dependencies.
	if got := names(deps); got != "A 1.0.0, A 2.0.0" || deps[0].ID == deps[1].ID {
		t.Errorf("dependencies %s", got)
	}
	if !warned(res, "Dev: developed from a local path") || !warned(res, "Bad: no usable uuid") || warned(res, "Dates") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if _, err := (juliaManifest{}).Parse([]byte("name = \"x\"\n")); err == nil {
		t.Error("a TOML file that is not a manifest was read")
	}
}

func TestBazelRegistryFiles(t *testing.T) {
	h := func(c string) string { return strings.Repeat(c, 64) }
	deps, res := depsOf(t, moduleBazelLock{}, `{"lockFileVersion": 18, "registryFileHashes": {
  "https://bcr.bazel.build/bazel_registry.json": "`+h("0")+`",
  "https://bcr.bazel.build/modules/a/1.0/MODULE.bazel": "`+h("1")+`",
  "https://bcr.bazel.build/modules/a/2.0/MODULE.bazel": "`+h("2")+`",
  "https://bcr.bazel.build/modules/a/2.0/source.json": "`+h("3")+`",
  "https://mirror.example/modules/b/1.0/source.json": "not found",
  "https://mirror.example/modules/c/1.0/patches/x.patch": "`+h("4")+`"
}, "selectedYankedVersions": {"a@2.0": "broken"}}`)
	if got := names(deps); got != "a 2.0" || deps[0].Registry != "https://bcr.bazel.build" || len(deps[0].Digests) != 2 {
		t.Errorf("dependencies %s %+v", got, deps)
	}
	if !warned(res, `"a@2.0" is a yanked version`) {
		t.Errorf("warnings %q", res.Warnings)
	}
	// A module of which only MODULE.bazel is hashed is unverified.
	d := Dependency{Digests: []Digest{{Algorithm: "sha256", Value: h("1"), Of: "MODULE.bazel"}}}
	markVerification(&d, formatInfo["bazel/MODULE.bazel.lock"])
	if !d.Unverified {
		t.Error("a MODULE.bazel hash alone pinned a module")
	}
}

func TestCpanDistNameVersion(t *testing.T) {
	for in, want := range map[string]string{
		"Try-Tiny-0.31.tar.gz":       "Try-Tiny 0.31",
		"libwww-perl-6.77.tar.gz":    "libwww-perl 6.77",
		"Foo-v1.2.3.tgz":             "Foo v1.2.3",
		"Bar-Baz-1.0-TRIAL.tar.gz":   "Bar-Baz 1.0-TRIAL",
		"Module-Build-0.4234.tar.gz": "Module-Build 0.4234",
		"NoVersion.tar.gz":           "",
	} {
		name, version, ok := cpanDistNameVersion(in)
		got := ""
		if ok {
			got = name + " " + version
		}
		if got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

// TestUnverifiedIsExplicitAndNeverInvented: a dependency nothing pins says
// so, with a reason; a digest is never made up for it.
func TestUnverifiedIsExplicitAndNeverInvented(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, c := range []struct {
		d          Dependency
		unverified bool
		reason     string
	}{
		{Dependency{Source: SourceGit, Revision: commit}, false, ""},
		{Dependency{Source: SourceGit, Version: "v1"}, true, "branch or tag"},
		{Dependency{Revision: commit}, true, "no hash"}, // a commit does not pin a dist archive
		{Dependency{Digests: []Digest{{Algorithm: "sha256", Value: commit + commit[:24]}}}, false, ""},
		{Dependency{Digests: []Digest{{Algorithm: "h1", Value: "x", Of: "go.mod"}}}, true, "go.mod"},
		{Dependency{UnverifiedReason: "the parser's own reason"}, true, "the parser's own reason"},
		{Dependency{}, true, "no hash"},
	} {
		d := c.d
		markVerification(&d, FormatInfo{NoDigest: "the format records no hash"})
		if d.Unverified != c.unverified || !strings.Contains(d.UnverifiedReason, c.reason) {
			t.Errorf("%+v: unverified %v %q", c.d, d.Unverified, d.UnverifiedReason)
		}
		if len(d.Digests) != len(c.d.Digests) {
			t.Errorf("digests changed: %+v", d.Digests)
		}
	}
	// Formats that record no digest: every fixture dependency of them is
	// unverified or pinned by a commit, never given a digest.
	for _, name := range []string{"puppet", "ansible", "helm", "carton", "cabal-freeze"} {
		for _, f := range parseFixture(t, "testdata/fixtures/"+name) {
			for _, d := range f.Dependencies {
				if len(d.Digests) == 0 && !d.Unverified && !(d.Source == SourceGit && isCommitID(d.Revision)) {
					t.Errorf("%s: %s %s is neither pinned nor unverified", name, d.Name, d.Version)
				}
				if d.Unverified && d.UnverifiedReason == "" {
					t.Errorf("%s: %s %s is unverified without a reason", name, d.Name, d.Version)
				}
			}
		}
	}
}

// TestNewReadersStayProportional: the readers of the formats of other
// languages hold memory in proportion to what they keep, not to the input.
func TestNewReadersStayProportional(t *testing.T) {
	mb := 1 << 20
	for name, c := range map[string]struct {
		p    Parser
		data []byte
	}{
		"HCL list":         {terraformModules{}, []byte("x = [" + strings.Repeat("1,", mb/2) + "]\n")},
		"HCL blocks":       {terraformModules{}, bytes.Repeat([]byte("locals {}\n"), mb/10)},
		"Puppetfile list":  {puppetfile{}, []byte("mod 'a', " + strings.Repeat("1,", mb/2) + "\n")},
		"Elixir list":      {mixLock{}, []byte(`%{"a": {:hex, :a, "1", [` + strings.Repeat("1,", mb/2) + "]}}")},
		"cabal commas":     {cabalFreeze{}, []byte("constraints: " + strings.Repeat("a ==1,", mb/6) + "\n")},
		"git config lines": {gitmodules{}, bytes.Repeat([]byte("[s]\nk = v\n"), mb/12)},
	} {
		if n := allocated(func() { _, _ = c.p.Parse(c.data) }); n > 64<<20 {
			t.Errorf("%s: %d MiB allocated for 1 MiB", name, n>>20)
		}
	}
}

func TestBazelRefusesARepeatedRegistryFile(t *testing.T) {
	h := strings.Repeat("a", 64)
	src := `{"lockFileVersion": 18, "registryFileHashes": {"https://b/modules/a/1/source.json": "` + h + `", "https://b/modules/a/1/source.json": "` + h + `"}}`
	if _, err := (moduleBazelLock{}).Parse([]byte(src)); err == nil {
		t.Error("a registry file hashed twice was read")
	}
}

// TestManyDuplicatesMergeInLinearTime: thousands of entries of one package
// version, each with its own digest, merge in linear time — measured as the
// growth from n to 4n entries (linear: about 4 times as long; the quadratic
// merge this replaced: 16 times), which holds on a slow, race-instrumented
// machine where an absolute bound would not.
func TestManyDuplicatesMergeInLinearTime(t *testing.T) {
	spec := func(n int) []byte {
		var b strings.Builder
		b.WriteString("@EXPLICIT\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "https://conda.anaconda.org/c/linux-64/a-1-b%d.conda#%032x\n", i, i)
		}
		return []byte(b.String())
	}
	measure := func(n int) time.Duration {
		data := spec(n)
		best := time.Duration(0)
		for run := 0; run < 2; run++ {
			start := time.Now()
			f := ParseFile(nil, nil, "conda-linux-64.lock", data)
			if d := time.Since(start); best == 0 || d < best {
				best = d
			}
			if len(f.Dependencies) != 1 || len(f.Dependencies[0].Digests) != n {
				t.Fatalf("%d entries: %d dependencies", n, len(f.Dependencies))
			}
		}
		return best
	}
	small, large := measure(2000), measure(8000)
	if large > time.Second && large > 10*small {
		t.Errorf("2000 duplicate entries took %v, 8000 took %v: more than linear", small, large)
	}
}
