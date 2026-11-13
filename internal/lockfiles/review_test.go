package lockfiles

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression tests for what an independent review of the Task 179 parsers
// found: files the scanner read differently from the tool that reads them,
// and gaps in redaction. Each input is crafted the way an attacker would.

const (
	rvCommit  = "0123456789abcdef0123456789abcdef01234567"
	rvCommit2 = "89abcdef0123456789abcdef0123456789abcdef"
)

// TestSectionsAreChosenByVersion: a tool reads the layout of the version the
// file declares; a section of another layout is refused, never read instead.
func TestSectionsAreChosenByVersion(t *testing.T) {
	sha512 := "sha512-" + strings.Repeat("A", 86) + "=="
	for name, c := range map[string]struct {
		p   Parser
		src string
	}{
		"swift 2 with a version 1 object": {packageResolved{}, `{"pins": [], "object": {"pins": [{"package": "A", "repositoryURL": "https://h/a.git", "state": {"revision": "` + rvCommit + `", "version": "1.0.0"}}]}, "version": 7}`},
		"deno 4 with packages":            {denoLock{}, `{"version": "4", "npm": {"evil@6.6.6": {"integrity": "` + sha512 + `"}}, "packages": {"npm": {"good@1.0.0": {"integrity": "` + sha512 + `"}}}}`},
		"deno 3 with a top-level npm":     {denoLock{}, `{"version": "3", "packages": {"npm": {"evil@6.6.6": {"integrity": "` + sha512 + `"}}}, "npm": {"good@1.0.0": {"integrity": "` + sha512 + `"}}}`},
		"deno 9":                          {denoLock{}, `{"version": "9"}`},
		"conan 2 with a graph_lock":       {conanLock{}, `{"version": "0.5", "requires": [], "graph_lock": {"nodes": {"1": {"ref": "zlib/1.0#` + strings.Repeat("a", 32) + `", "prev": "` + strings.Repeat("b", 32) + `"}}}}`},
		"conan 1 with reference lists":    {conanLock{}, `{"version": "0.4", "requires": ["zlib/1.0"]}`},
		"bazel 13 with a moduleDepGraph":  {moduleBazelLock{}, `{"lockFileVersion": 13, "moduleDepGraph": {"rules_go@1.0": {"name": "rules_go", "version": "1.0", "repoSpec": {"ruleClassName": "http_archive", "attributes": {"urls": ["https://h/a.tgz"], "integrity": "sha256-` + strings.Repeat("A", 43) + `="}}}}}`},
		"bazel 6 with registry hashes":    {moduleBazelLock{}, `{"lockFileVersion": 6, "registryFileHashes": {"https://b/modules/a/1/source.json": "` + strings.Repeat("a", 64) + `"}}`},
	} {
		if _, err := c.p.Parse([]byte(c.src)); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	// Version 1 pins are read from "object" only.
	deps, _ := depsOf(t, packageResolved{}, `{"pins": [{"identity": "evil", "kind": "remoteSourceControl", "location": "https://h/evil.git", "state": {"revision": "`+rvCommit2+`", "version": "6.6.6"}}], "object": {"pins": [{"package": "A", "repositoryURL": "https://h/a.git", "state": {"revision": "`+rvCommit+`", "version": "1.0.0"}}]}, "version": 1}`)
	if names(deps) != "a 1.0.0" {
		t.Errorf("version 1: %s", names(deps))
	}
	// Deno before 1.28 wrote a flat map of module URLs.
	deps, _ = depsOf(t, denoLock{}, `{"https://deno.land/std@0.100.0/fmt/colors.ts": "`+strings.Repeat("c", 64)+`"}`)
	if len(deps) != 1 || deps[0].Type != "generic" || deps[0].Version != "sha256:"+strings.Repeat("c", 64) {
		t.Errorf("deno version 1: %+v", deps)
	}
	// A module named "modules" in a registry.
	deps, _ = depsOf(t, moduleBazelLock{}, `{"lockFileVersion": 18, "registryFileHashes": {"https://bcr.example/modules/modules/1.0/source.json": "`+strings.Repeat("a", 64)+`"}}`)
	if names(deps) != "modules 1.0" || deps[0].Registry != "https://bcr.example" {
		t.Errorf("a module named modules: %+v", deps)
	}
}

// TestChartLockIsReadAsHelmReadsIt: keys match ignoring case, as
// encoding/json matches them, and YAML 1.1 scalars that Helm turns into
// other strings are refused.
func TestChartLockIsReadAsHelmReadsIt(t *testing.T) {
	deps, res := depsOf(t, chartLock{}, `Dependencies:
- Name: redis
  VERSION: 17.0.0
  Repository: https://evil.example.com/charts
- name: nginx
  version: ">=1.0.0"
  repository: https://charts.example.com
digest: sha256:`+strings.Repeat("a", 64)+`
`)
	if len(deps) != 1 || deps[0].Name != "redis" || deps[0].Version != "17.0.0" || deps[0].Registry != "https://evil.example.com/charts" {
		t.Errorf("dependencies %+v", deps)
	}
	if !warned(res, "nginx: the version is a range") {
		t.Errorf("warnings %q", res.Warnings)
	}
	for name, src := range map[string]string{
		"a float version":       "dependencies:\n- name: a\n  version: 1.10\n  repository: https://h\n",
		"an octal version":      "dependencies:\n- name: a\n  version: 010\n  repository: https://h\n",
		"a boolean name":        "dependencies:\n- name: yes\n  version: 1.0.0\n  repository: https://h\n",
		"a date version":        "dependencies:\n- name: a\n  version: 2024-01-01\n  repository: https://h\n",
		"keys in two cases":     "dependencies:\n- name: a\n  version: 1.0.0\n  repository: https://good\n  Repository: https://evil\n",
		"a base-60 version":     "dependencies:\n- name: a\n  version: 1:20\n  repository: https://h\n",
		"an underscore integer": "dependencies:\n- name: a\n  version: 1_000\n  repository: https://h\n",
	} {
		if _, err := (chartLock{}).Parse([]byte(src)); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	// Quoted, the same scalars are strings to every YAML reader.
	if deps, _ := depsOf(t, chartLock{}, "dependencies:\n- name: \"yes\"\n  version: \"1.10\"\n  repository: https://h\n"); names(deps) != "yes 1.10" {
		t.Errorf("quoted scalars: %s", names(deps))
	}
	// Rye's requirements.lock is pip's, under Helm's name.
	f := ParseFile(nil, nil, "requirements.lock", []byte("# generated by rye\n-e file:.\nanyio==4.4.0\n    # via httpx\n"))
	if f.Format != "requirements.txt" || f.Type != "pip" || len(f.Dependencies) != 1 || f.Dependencies[0].Type != "pip" {
		t.Errorf("Rye's lock file: %+v", f)
	}
}

// TestRefsResolveAsTheToolsResolveThem: when a file gives several refs, the
// one the tool checks out is the one reported.
func TestRefsResolveAsTheToolsResolveThem(t *testing.T) {
	// r10k: the last of :branch, :tag, :commit, :ref and :version wins.
	deps, res := depsOf(t, puppetfile{}, "mod 'apache', :git => 'https://h/apache.git', :commit => '"+rvCommit+"', :branch => 'main'\n"+
		"mod 'ntp', git: 'https://h/ntp.git', branch: 'main', commit: '"+rvCommit2+"'\n")
	if names(deps) != "ntp "+rvCommit2 || deps[0].Revision != rvCommit2 {
		t.Errorf("dependencies %s", names(deps))
	}
	if !warned(res, `"apache" names several refs (commit, branch); r10k checks out the last, :branch`) {
		t.Errorf("warnings %q", res.Warnings)
	}
	// ansible-galaxy: a ",ref" after a collection's URL wins over version.
	deps, _ = depsOf(t, ansibleRequirements{}, "collections:\n  - name: https://github.com/o/c.git,main\n    type: git\n    version: "+rvCommit+"\n")
	if len(deps) != 1 || deps[0].Revision != "" || deps[0].Version != "main" {
		t.Errorf("git collection %+v", deps)
	}
	// The oldest role form, "role: owner.name".
	deps, _ = depsOf(t, ansibleRequirements{}, "- role: geerlingguy.java\n  version: 2.5.0\n")
	if names(deps) != "geerlingguy.java 2.5.0" {
		t.Errorf("old role form %s", names(deps))
	}
	// Pantry tries a repository before a Hackage package.
	deps, _ = depsOf(t, stackLock{}, "packages:\n- completed:\n    hackage: aeson-2.2.3.0@sha256:"+strings.Repeat("a", 64)+",10\n    git: https://github.com/evil/aeson.git\n    commit: "+rvCommit+"\n    name: aeson\n    version: 6.6.6\n  original: {}\n")
	if len(deps) != 1 || deps[0].Source != SourceGit || deps[0].Version != "6.6.6" {
		t.Errorf("stack entry %+v", deps)
	}
	// pixi never writes a record with both kinds; such a record is left out.
	_, res = depsOf(t, pixiLock{}, "version: 6\npackages:\n- conda: https://c.example/ch/linux-64/evil-6.6.6-h0_0.conda\n  pypi: https://files.example/requests-2.32.3-py3-none-any.whl\n  name: requests\n  version: 2.32.3\n")
	if !warned(res, "both a conda and a PyPI location") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

// TestCondaReadsWhatIsInstalled: names come from the file a URL names, and
// a lone carriage return ends a line, as in Python's text mode.
func TestCondaReadsWhatIsInstalled(t *testing.T) {
	deps, res := depsOf(t, condaLock{}, `version: 1
package:
- name: numpy
  version: 1.26.4
  manager: conda
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/evilpkg-6.6.6-h0_0.conda
  hash: {md5: `+strings.Repeat("a", 32)+`}
`)
	if names(deps) != "evilpkg 6.6.6" || !warned(res, `the entry says "numpy" "1.26.4"`) {
		t.Errorf("dependencies %s, warnings %q", names(deps), res.Warnings)
	}
	deps, _ = depsOf(t, condaExplicit{}, "@EXPLICIT\nhttps://c.example/ch/linux-64/good-1.0-h0_0.conda#"+strings.Repeat("a", 32)+"\rhttps://c.example/ch/linux-64/evil-6.6.6-h0_0.conda#"+strings.Repeat("b", 32)+"\n")
	if names(deps) != "good 1.0, evil 6.6.6" || len(deps[0].Digests) != 1 {
		t.Errorf("dependencies %+v", deps)
	}
}

// TestRenvIsReadAsRReadsIt.
func TestRenvIsReadAsRReadsIt(t *testing.T) {
	for name, src := range map[string]string{
		"a repository key twice":   `{"R": {"Repositories": [{"Name": "CRAN", "URL": "https://evil", "URL": "https://good"}]}, "Packages": {}}`,
		"a repository named twice": `{"R": {"Repositories": [{"Name": "CRAN", "URL": "https://evil"}, {"Name": "CRAN", "URL": "https://good"}]}, "Packages": {}}`,
	} {
		if _, err := (renvLock{}).Parse([]byte(src)); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	deps, res := depsOf(t, renvLock{}, `{"R": {"Repositories": [{"Name": "CRAN", "URL": "https://cran.example"}]}, "Packages": {
  "a": {"Package": "a", "Version": "1.0", "Source": "CRAN"},
  "b": {"Package": "b", "Version": "2.0", "Source": "github", "RemoteHost": "evil.example.com/x", "RemoteUsername": "o", "RemoteRepo": "b", "RemoteSha": "`+rvCommit+`"}
}}`)
	if names(deps) != "a 1.0" || deps[0].Registry != "https://cran.example" {
		t.Errorf("dependencies %+v", deps)
	}
	if !warned(res, "b: from github through a host this parser cannot map") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

// TestGitmodulesReadAsGitReadsThem.
func TestGitmodulesReadAsGitReadsThem(t *testing.T) {
	res, err := gitmodules{}.Parse([]byte("[submodule.lib \"x\"]\n\tpath = libx\n\turl = https://h/x.git\n" +
		"[submodule \"v\"]\n\tpath = \vlib\n\turl = https://h/v.git\n" +
		"[submodule \"s\"]\n\tpath = lib/\n\turl = https://h/s.git\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range res.submodules {
		got = append(got, d.name+"="+d.path)
	}
	// "[submodule.lib \"x\"]" names the submodule "lib.x". "\v" is no blank
	// to git: the path is "\vlib", not "lib" (and one with a control
	// character is left out). A trailing slash maps to no gitlink.
	if strings.Join(got, ",") != "lib.x=libx" {
		t.Errorf("declarations %q", got)
	}
	if !warned(res, `submodule "s": its path is not a path inside the repository`) || !warned(res, `submodule "v": its path is not a path`) {
		t.Errorf("warnings %q", res.Warnings)
	}
}

// TestCabalFieldNamesMayBeFollowedByBlanks.
func TestCabalFieldNamesMayBeFollowedByBlanks(t *testing.T) {
	deps, _ := depsOf(t, cabalFreeze{}, "index-state: hackage.haskell.org 2024-01-01T00:00:00Z\nconstraints : any.evil ==6.6.6\n")
	if names(deps) != "evil 6.6.6" {
		t.Errorf("dependencies %s", names(deps))
	}
}

// TestTerraformOverridesAndSubdirectories.
func TestTerraformOverridesAndSubdirectories(t *testing.T) {
	files := []*File{
		parseOne(terraformModules{}, "infra/main.tf", []byte(`module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
module "role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.48.0"
}
module "gone" {
  source  = "a/b/c"
  version = "1.0.0"
}
`)),
		parseOne(terraformOverrides{}, "infra/override.tf", []byte(`module "vpc" {
  version = "6.6.6"
}
module "gone" {
  version = "~> 1.0"
}
module "nowhere" {
  version = "1.0.0"
}
`)),
		parseOne(terraformOverrides{}, "infra/z_override.tf", []byte("module \"vpc\" {\n  version = \"7.0.0\"\n}\n")),
	}
	finish(files, nil)
	if got := names(files[0].Dependencies); got != "terraform-aws-modules/vpc/aws 7.0.0, terraform-aws-modules/iam/aws 5.48.0" {
		t.Errorf("dependencies %s", got)
	}
	if !strings.Contains(strings.Join(files[1].Warnings, "\n"), `module "nowhere" overrides a module no other file`) {
		t.Errorf("override warnings %q", files[1].Warnings)
	}
	if !strings.Contains(strings.Join(files[0].Warnings, "\n"), `module "gone": a/b/c is constrained to a range`) {
		t.Errorf("warnings %q", files[0].Warnings)
	}
}

// TestUserinfoNeverSurvives: scp-style user:password@ and passwords holding
// an "@" are cut out of every URL.
func TestUserinfoNeverSurvives(t *testing.T) {
	for in, want := range map[string]string{
		"user:s3cretpass@github.com:o/b.git": "github.com:o/b.git",
		"git@github.com:o/b.git":             "git@github.com:o/b.git",
		"https://u:pa@ss@host.example/r.git": "https://host.example/r.git",
		"ssh://git@host.example/r.git":       "ssh://git@host.example/r.git",
	} {
		if got := cleanGitRepoURL(in); got != want {
			t.Errorf("cleanGitRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
	deps, _ := depsOf(t, denoLock{}, `{"version": "4", "remote": {"https://user:pa@ss@host.example/mod.ts": "`+strings.Repeat("a", 64)+`"}}`)
	if len(deps) != 1 || deps[0].Name != "host.example/mod.ts" {
		t.Errorf("remote module %+v", deps)
	}
	f := ParseFile(nil, nil, ".gitmodules", []byte("[submodule \"a\"]\n\tpath = a\n\turl = user:s3cretpass@github.com:o/b.git\n"))
	if _, err := joinSubmodules(f, func(string) (string, error) { return rvCommit, nil }, "", nil); err != nil {
		t.Fatal(err)
	}
	finish([]*File{f}, nil)
	if out, _ := json.Marshal(f); strings.Contains(string(out), "s3cret") {
		t.Errorf("a password survived: %s", out)
	}
}
