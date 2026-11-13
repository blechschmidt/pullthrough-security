//go:build fuzz
// +build fuzz

// Fuzz targets for the lock-file parsers (Task 178). A lock file comes out of
// a repository, which is whatever its last committer made it: every parser is
// a parser of untrusted input, and runs inside the proxy. The properties:
//
//   - no input panics a parser or the TOML reader;
//   - parsing is deterministic;
//   - a dependency that comes out has a name, a version, a line inside the
//     file and well-formed digests;
//   - after the result is finished as a scan finishes it, nothing spelled like
//     a personal link token survives in any field, warning or error — the
//     fixtures seed every format with URLs that carry one.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzPackageLock ./internal/lockfiles/
package lockfiles

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fuzzMaxInput bounds an input: larger ones only make each run slower.
const fuzzMaxInput = 1 << 20

// fuzzSeedMax bounds the size of a fixture used as a seed.
const fuzzSeedMax = 256 << 10

// tokenLeft matches a token that survived redaction.
var tokenLeft = regexp.MustCompile(`ptl1[a-z0-9]`)

// fixtureSeeds returns every fixture file the parser detects.
func fixtureSeeds(f *testing.F, p Parser) [][]byte {
	f.Helper()
	var seeds [][]byte
	_ = filepath.WalkDir("testdata/fixtures", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !p.Detect(filepath.ToSlash(path)) {
			return nil
		}
		if data, err := os.ReadFile(path); err == nil && len(data) <= fuzzSeedMax {
			seeds = append(seeds, data)
		}
		return nil
	})
	return seeds
}

// fuzzParser runs one parser's fuzz target. path is a file name the parser
// detects.
func fuzzParser(f *testing.F, p Parser, path string, seeds ...string) {
	if !p.Detect(path) {
		f.Fatalf("%s does not detect %q", p.Format(), path)
	}
	for _, s := range fixtureSeeds(f, p) {
		f.Add(s)
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Add([]byte{})
	f.Add([]byte("\x00\xff"))
	reg, err := NewRegistry(p)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		res1, err1 := p.Parse(data)
		res2, err2 := p.Parse(data)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v / %v", err1, err2)
		}
		if err1 == nil {
			if res1 == nil {
				t.Fatal("nil result without an error")
			}
			a, _ := json.Marshal(res1)
			b, _ := json.Marshal(res2)
			if !bytes.Equal(a, b) {
				t.Fatal("non-deterministic result")
			}
			lines := bytes.Count(data, []byte("\n")) + 1
			for _, d := range res1.Dependencies {
				if d.Name == "" || d.Version == "" {
					t.Fatalf("dependency without a name or version: %+v", d)
				}
				if d.Line < 1 || d.Line > lines {
					t.Fatalf("line %d outside the file's %d lines: %+v", d.Line, lines, d)
				}
				for _, dg := range d.Digests {
					if dg.Algorithm == "" || dg.Value == "" {
						t.Fatalf("empty digest in %+v", d)
					}
					if n, ok := digestSizes[dg.Algorithm]; ok && len(dg.Value) != 2*n {
						t.Fatalf("digest of the wrong length: %+v", dg)
					}
				}
			}
		}
		file := ParseFile(reg, fuzzProxy, path, data)
		if file == nil {
			t.Fatal("the registry does not detect the path")
		}
		// Digest values are validated hashes (hex, or base64 of the hash's
		// length): random bytes, which may spell anything, never a URL.
		for i := range file.Dependencies {
			for j := range file.Dependencies[i].Digests {
				dg := &file.Dependencies[i].Digests[j]
				if dg.Algorithm == "h1" {
					if raw, err := base64.StdEncoding.DecodeString(dg.Value); err != nil || len(raw) != 32 {
						t.Fatalf("an h1 digest that is not a SHA-256: %q", dg.Value)
					}
				} else if !isHex(dg.Value) {
					t.Fatalf("a %s digest that is not hex: %q", dg.Algorithm, dg.Value)
				}
				dg.Value = ""
			}
		}
		out, _ := json.Marshal(file)
		// The path is the caller's, not the input's.
		out = bytes.ReplaceAll(out, []byte(path), nil)
		if loc := tokenLeft.FindIndex(out); loc != nil {
			t.Fatalf("a link token survived: …%s…", out[max(0, loc[0]-40):min(len(out), loc[1]+40)])
		}
	})
}

// fuzzProxy is the deployment results are finished with.
var fuzzProxy = &Proxy{
	PublicURLs: []string{"https://proxy.example.com", "http://10.0.0.1:8080/pt"},
	LinkPrefix: "/u",
	Upstreams: map[string]ProxyUpstream{
		"npm":       {Type: "npm", URL: "https://registry.npmjs.org"},
		"pypi":      {Type: "pip", URL: "https://pypi.org/simple"},
		"dockerhub": {Type: "docker", URL: "https://registry-1.docker.io"},
	},
	RegistryDefault: "dockerhub",
}

// seedURL is a personal link URL for hand-made seeds.
const seedURL = "https://proxy.example.com/u/" + testToken + "/v1/npm"

func FuzzPackageLock(f *testing.F) {
	fuzzParser(f, npmLock{file: "package-lock.json"}, "package-lock.json",
		`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"`+seedURL+`/a/-/a-1.0.0.tgz","integrity":"sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}`,
		`{"lockfileVersion":1,"dependencies":{"a":{"version":"npm:b@1.0.0","dependencies":{"c":{"version":"github:o/r#`+strings.Repeat("a", 40)+`"}}}}}`)
}

func FuzzNpmShrinkwrap(f *testing.F) {
	fuzzParser(f, npmLock{file: "npm-shrinkwrap.json"}, "npm-shrinkwrap.json",
		`{"lockfileVersion":2,"packages":{"":{},"node_modules/x":{"name":"y","version":"2","link":true}}}`)
}

func FuzzYarnLock(f *testing.F) {
	fuzzParser(f, yarnLock{}, "yarn.lock",
		"# yarn lockfile v1\n\n\"a@^1\", a@^1.1:\n  version \"1.2.0\"\n  resolved \""+seedURL+"/a/-/a-1.2.0.tgz#"+strings.Repeat("0", 40)+"\"\n",
		"__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n  checksum: 10c0/"+strings.Repeat("a", 128)+"\n")
}

func FuzzPnpmLock(f *testing.F) {
	fuzzParser(f, pnpmLock{}, "pnpm-lock.yaml",
		"lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {tarball: "+seedURL+"/a/-/a-1.0.0.tgz}\n",
		"lockfileVersion: 5.4\npackages:\n  /a/1.0.0_b@2:\n    resolution: {integrity: sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=}\n    dev: true\n")
}

func FuzzRequirementsTxt(f *testing.F) {
	fuzzParser(f, requirementsTxt{}, "requirements.txt",
		"--index-url https://proxy.example.com/u/"+testToken+"/v1/pypi/simple\na==1.0 \\\n  --hash=sha256:"+strings.Repeat("ab", 32)+"\n",
		"-e git+https://github.com/o/r@"+strings.Repeat("a", 40)+"#egg=r\nb @ https://proxy.example.com/u/"+testToken+"/v1/pypi/b-1.0-py3-none-any.whl#sha256="+strings.Repeat("0", 64)+"\n")
}

func FuzzPipfileLock(f *testing.F) {
	fuzzParser(f, pipfileLock{}, "Pipfile.lock",
		`{"_meta":{"sources":[{"name":"p","url":"https://proxy.example.com/u/`+testToken+`/v1/pypi/simple"}]},"default":{"a":{"version":"==1","index":"p","hashes":["sha256:`+strings.Repeat("0", 64)+`"]}}}`)
}

func FuzzPoetryLock(f *testing.F) {
	fuzzParser(f, poetryLock{}, "poetry.lock",
		"[[package]]\nname = \"a\"\nversion = \"1\"\nfiles = [{file = \"a-1.tar.gz\", hash = \"sha256:"+strings.Repeat("0", 64)+"\"}]\n[package.source]\ntype = \"legacy\"\nurl = \"https://proxy.example.com/u/"+testToken+"/v1/pypi/simple\"\n")
}

func FuzzUVLock(f *testing.F) {
	fuzzParser(f, uvLock{}, "uv.lock",
		"version = 1\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"https://proxy.example.com/u/"+testToken+"/v1/pypi/simple\" }\nsdist = { url = \"https://proxy.example.com/u/"+testToken+"\", hash = \"sha256:"+strings.Repeat("0", 64)+"\" }\n")
}

func FuzzPDMLock(f *testing.F) {
	fuzzParser(f, pdmLock{}, "pdm.lock",
		"[metadata]\nlock_version = \"4.2\"\n[[package]]\nname = \"a\"\nversion = \"1\"\n[metadata.files]\n\"a 1\" = [{url = \"https://proxy.example.com/u/"+testToken+"/a-1.tar.gz\", hash = \"sha256:"+strings.Repeat("0", 64)+"\"}]\n")
}

func FuzzCargoLock(f *testing.F) {
	fuzzParser(f, cargoLock{}, "Cargo.lock",
		"version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://proxy.example.com/u/"+testToken+"/v1/crates/\"\nchecksum = \""+strings.Repeat("0", 64)+"\"\n")
}

func FuzzGoMod(f *testing.F) {
	fuzzParser(f, goMod{}, "go.mod",
		"module m\nrequire (\n\ta v1.0.0 // indirect\n\t\"b\" v2.0.0\n)\nreplace a => c v1.1.0\nreplace b v2.0.0 => ./b\n")
}

func FuzzGoSum(f *testing.F) {
	h1 := func(c string) string { return " h1:" + strings.Repeat(c, 43) + "=\n" }
	fuzzParser(f, goSum{}, "go.sum", "a v1.0.0"+h1("A")+"a v1.0.0/go.mod"+h1("B")+"b v2.0.0/go.mod"+h1("C")+"c v1.0.0 h1:"+testToken+"\n")
}

func FuzzNuGetLock(f *testing.F) {
	fuzzParser(f, nugetLock{}, "packages.lock.json",
		`{"version":1,"dependencies":{"net8.0":{"A":{"type":"Direct","resolved":"1.0.0","contentHash":"`+strings.Repeat("A", 86)+`=="},"P":{"type":"Project"}}}}`)
}

func FuzzGradleLock(f *testing.F) {
	fuzzParser(f, gradleLock{}, "gradle.lockfile", "# comment\ng:a:1.0=compileClasspath,testRuntimeClasspath\nempty=\n")
}

func FuzzPOM(f *testing.F) {
	fuzzParser(f, pomXML{}, "pom.xml",
		`<project><properties><v>1.0</v></properties><repositories><repository><url>https://proxy.example.com/u/`+testToken+`/v1/central/</url></repository></repositories><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency></dependencies></project>`)
}

func FuzzGemfileLock(f *testing.F) {
	fuzzParser(f, gemfileLock{}, "Gemfile.lock",
		"GEM\n  remote: https://proxy.example.com/u/"+testToken+"/v1/rubygems/\n  specs:\n    a (1.0-x86_64-linux)\n\nCHECKSUMS\n  a (1.0-x86_64-linux) sha256="+strings.Repeat("0", 64)+"\n")
}

func FuzzComposerLock(f *testing.F) {
	fuzzParser(f, composerLock{}, "composer.lock",
		`{"packages":[{"name":"v/p","version":"1.0","dist":{"type":"zip","url":"https://proxy.example.com/u/`+testToken+`/v1/packagist/x.zip","shasum":"`+strings.Repeat("0", 40)+`"}}]}`)
}

func FuzzDockerfile(f *testing.F) {
	fuzzParser(f, dockerfile{}, "Dockerfile",
		"ARG B=proxy.example.com/u/"+testToken+"/dockerhub/library/alpine@sha256:"+strings.Repeat("a", 64)+"\nFROM ${B} AS x\nCOPY --from=x /a /b\nRUN <<EOF\nFROM y\nEOF\n")
}

func FuzzCompose(f *testing.F) {
	fuzzParser(f, composeFile{}, "compose.yaml",
		"x: &a\n  image: proxy.example.com/u/"+testToken+"/dockerhub/r@sha256:"+strings.Repeat("a", 64)+"\nservices:\n  s:\n    <<: *a\n  t:\n    image: ${T:-alpine}\n")
}

func FuzzCondaLock(f *testing.F) {
	fuzzParser(f, condaLock{}, "conda-lock.yml",
		"version: 1\npackage:\n- name: zlib\n  version: 1.3.1\n  manager: conda\n  platform: linux-64\n  url: https://proxy.example.com/u/"+testToken+"/v1/conda/linux-64/zlib-1.3.1-h_2.conda\n  hash: {md5: "+strings.Repeat("a", 32)+", sha256: "+strings.Repeat("b", 64)+"}\n  category: dev\n"+
			"- name: six\n  version: '1.16.0'\n  manager: pip\n  url: git+https://u:"+testToken+"@github.com/o/r.git@"+strings.Repeat("c", 40)+"\n")
}

func FuzzCondaExplicit(f *testing.F) {
	fuzzParser(f, condaExplicit{}, "conda-linux-64.lock",
		"# platform: linux-64\n@EXPLICIT\nhttps://proxy.example.com/u/"+testToken+"/v1/conda/linux-64/zlib-1.3.1-h_2.conda#"+strings.Repeat("a", 32)+"\nhttps://c.example/x/noarch/a-1-0.tar.bz2#sha256:"+strings.Repeat("b", 64)+"\n")
}

func FuzzPixiLock(f *testing.F) {
	fuzzParser(f, pixiLock{}, "pixi.lock",
		"version: 6\npackages:\n- conda: https://proxy.example.com/u/"+testToken+"/v1/conda/linux-64/zlib-1.3.1-h_2.conda\n  sha256: "+strings.Repeat("b", 64)+"\n- pypi: git+https://github.com/o/r.git?tag=1#"+strings.Repeat("c", 40)+"\n  name: r\n  version: 1.0.0\n"+
			"- kind: pypi\n  name: six\n  version: 1.16.0\n  url: https://proxy.example.com/u/"+testToken+"/v1/pypi/six-1.16.0-py2.py3-none-any.whl\n  sha256: "+strings.Repeat("d", 64)+"\n")
}

func FuzzRenvLock(f *testing.F) {
	fuzzParser(f, renvLock{}, "renv.lock",
		`{"R":{"Version":"4.4.1","Repositories":[{"Name":"CRAN","URL":"https://proxy.example.com/u/`+testToken+`/v1/cran"}]},"Packages":{"R6":{"Package":"R6","Version":"2.5.1","Source":"Repository","Repository":"CRAN","Hash":"`+strings.Repeat("a", 32)+`"},"x":{"Package":"x","Version":"1","Source":"GitHub","RemoteHost":"api.github.com","RemoteUsername":"o","RemoteRepo":"x","RemoteSha":"`+strings.Repeat("b", 40)+`"},"y":{"Package":"y","Version":"2","Source":"URL","RemoteUrl":"https://u:`+testToken+`@h.example/y.tar.gz"}}}`)
}

func FuzzMixLock(f *testing.F) {
	fuzzParser(f, mixLock{}, "mix.lock",
		"%{\n  \"jason\": {:hex, :jason, \"1.4.4\", \""+strings.Repeat("a", 64)+"\", [:mix], [{:decimal, \"~> 2.0\", [hex: :decimal, repo: \"hexpm\", optional: true]}], \"hexpm:acme\", \""+strings.Repeat("b", 64)+"\"},\n  \"d\": {:git, \"https://u:"+testToken+"@github.com/o/d.git\", \""+strings.Repeat("c", 40)+"\", [tag: \"v1\"]},\n  \"old\" => {:hex, :old, \"0.1.0\"},\n}\n",
		"%{\"x\": {:hex, :x, \"#{System.cmd(\"id\", [])}\"}}")
}

func FuzzPackageResolved(f *testing.F) {
	fuzzParser(f, packageResolved{}, "Package.resolved",
		`{"object":{"pins":[{"package":"P","repositoryURL":"https://u:`+testToken+`@github.com/o/p.git","state":{"branch":null,"revision":"`+strings.Repeat("a", 40)+`","version":"1.0.0"}}]},"version":1}`,
		`{"pins":[{"identity":"mona.linkedlist","kind":"registry","location":"","state":{"version":"1.0.0"}},{"identity":"x","kind":"remoteSourceControl","location":"https://proxy.example.com/u/`+testToken+`/v1/git/x.git","state":{"branch":"main","revision":"`+strings.Repeat("b", 40)+`"}}],"version":3,"originHash":"x"}`)
}

func FuzzPubspecLock(f *testing.F) {
	fuzzParser(f, pubspecLock{}, "pubspec.lock",
		"packages:\n  a:\n    dependency: \"direct dev\"\n    description:\n      name: a\n      sha256: \""+strings.Repeat("a", 64)+"\"\n      url: \"https://proxy.example.com/u/"+testToken+"/v1/pub\"\n    source: hosted\n    version: \"1.0.0\"\n  g:\n    dependency: transitive\n    description:\n      path: \".\"\n      ref: main\n      resolved-ref: \""+strings.Repeat("b", 40)+"\"\n      url: \"https://u:"+testToken+"@github.com/o/g.git\"\n    source: git\n    version: \"2.0.0\"\nsdks:\n  dart: \">=3.0.0 <4.0.0\"\n")
}

func FuzzJuliaManifest(f *testing.F) {
	fuzzParser(f, juliaManifest{}, "Manifest.toml",
		"julia_version = \"1.11.1\"\nmanifest_format = \"2.0\"\n[[deps.Example]]\ngit-tree-sha1 = \""+strings.Repeat("a", 40)+"\"\nrepo-rev = \""+strings.Repeat("b", 40)+"\"\nrepo-url = \"https://u:"+testToken+"@github.com/o/Example.jl\"\nuuid = \"7876af07-990d-54b4-ab0e-23690620f79a\"\nversion = \"0.5.4\"\n[[deps.Dates]]\nuuid = \"ade2ca70-3891-5945-98fb-dc099432e06a\"\n",
		"[[JSON]]\ngit-tree-sha1 = \""+strings.Repeat("c", 40)+"\"\nuuid = \"682c06a0-de6a-54ab-a142-c8b1cf79cde6\"\nversion = \"0.21.1\"\n")
}

func FuzzModuleBazelLock(f *testing.F) {
	fuzzParser(f, moduleBazelLock{}, "MODULE.bazel.lock",
		`{"lockFileVersion":13,"registryFileHashes":{"https://proxy.example.com/u/`+testToken+`/v1/bcr/modules/platforms/0.0.10/MODULE.bazel":"`+strings.Repeat("a", 64)+`","https://proxy.example.com/u/`+testToken+`/v1/bcr/modules/platforms/0.0.10/source.json":"`+strings.Repeat("b", 64)+`"},"selectedYankedVersions":{"x@1":"r"}}`,
		`{"lockFileVersion":3,"moduleDepGraph":{"<root>":{"name":"demo"},"a@1.0":{"name":"a","version":"1.0","repoSpec":{"ruleClassName":"http_archive","attributes":{"urls":["https://u:`+testToken+`@h.example/a.tar.gz"],"integrity":"sha256-`+strings.Repeat("A", 43)+`="}}},"g@_":{"name":"g","version":"","repoSpec":{"ruleClassName":"git_repository","attributes":{"remote":"https://github.com/o/g.git","commit":"`+strings.Repeat("c", 40)+`"}}}}}`)
}

func FuzzFlakeLock(f *testing.F) {
	fuzzParser(f, flakeLock{}, "flake.lock",
		`{"nodes":{"nixpkgs":{"locked":{"lastModified":1,"narHash":"sha256-`+strings.Repeat("A", 43)+`=","owner":"NixOS","repo":"nixpkgs","rev":"`+strings.Repeat("a", 40)+`","type":"github"}},"t":{"locked":{"narHash":"sha256:`+strings.Repeat("0", 52)+`","type":"tarball","url":"https://proxy.example.com/u/`+testToken+`/v1/x/t.tar.gz"}},"g":{"locked":{"narHash":"sha256-`+strings.Repeat("B", 43)+`=","rev":"`+strings.Repeat("b", 40)+`","type":"git","url":"https://u:`+testToken+`@h.example/g"}},"root":{"inputs":{"nixpkgs":"nixpkgs"}}},"root":"root","version":7}`)
}

func FuzzTerraformLock(f *testing.F) {
	fuzzParser(f, terraformLock{}, ".terraform.lock.hcl",
		"provider \"registry.terraform.io/hashicorp/null\" {\n  version     = \"3.2.3\"\n  constraints = \"~> 3.2\"\n  hashes = [\n    \"h1:"+strings.Repeat("A", 43)+"=\",\n    \"zh:"+strings.Repeat("a", 64)+"\",\n  ]\n}\n",
		"provider \"h.example/a/b\" { version = \"1.0.0\" }\n/* c */ # d\n// e\n")
}

func FuzzTerraformModules(f *testing.F) {
	fuzzParser(f, terraformModules{}, "main.tf",
		"module \"a\" {\n  source  = \"cloudposse/label/null\"\n  version = \"0.25.0\"\n}\nmodule \"g\" {\n  source = \"git::https://u:"+testToken+"@github.com/o/r.git//sub?ref="+strings.Repeat("a", 40)+"\"\n}\n"+
			"module \"h\" {\n  source = \"https://proxy.example.com/u/"+testToken+"/v1/x/m.zip?checksum=sha256:"+strings.Repeat("b", 64)+"\"\n  count = length([for x in var.y : x if x != \"${z}\"])\n  tags = <<-EOT\n    a ${b}\n  EOT\n}\n",
		"locals {\n  x = { a = [1, 2], b = \"%{ if c }d%{ endif }\" }\n}\n")
}

func FuzzTerraformOverrides(f *testing.F) {
	fuzzParser(f, terraformOverrides{}, "override.tf",
		"module \"label\" {\n  version = \"0.25.0\"\n  source = \"git::https://u:"+testToken+"@github.com/o/r.git?ref="+strings.Repeat("a", 40)+"\"\n}\n")
}

// FuzzTerraformMerge: a directory of a configuration file and an override
// file merges into well-formed dependencies without a token.
func FuzzTerraformMerge(f *testing.F) {
	f.Add([]byte("module \"a\" {\n  source = \"x/y/z\"\n  version = \"1.0.0\"\n}\n"), []byte("module \"a\" {\n  version = \"2.0.0\"\n}\n"))
	f.Add([]byte("module \"a\" {\n  source = \"x/y/z\"\n}\n"), []byte("module \"a\" {\n  source = \"git::https://proxy.example.com/u/"+testToken+"/r.git?ref="+strings.Repeat("b", 40)+"\"\n}\nmodule \"b\" {}\n"))
	f.Fuzz(func(t *testing.T, main, override []byte) {
		if len(main)+len(override) > fuzzMaxInput {
			return
		}
		files := []*File{parseOne(terraformModules{}, "main.tf", main), parseOne(terraformOverrides{}, "override.tf", override)}
		finish(files, fuzzProxy)
		for _, file := range files {
			for _, d := range file.Dependencies {
				if d.Name == "" || d.Version == "" || d.File != "main.tf" {
					t.Fatalf("malformed dependency %+v", d)
				}
			}
			out, _ := json.Marshal(file)
			if loc := tokenLeft.FindIndex(out); loc != nil {
				t.Fatalf("a link token survived: …%s…", out[max(0, loc[0]-40):min(len(out), loc[1]+40)])
			}
		}
	})
}

func FuzzConanLock(f *testing.F) {
	fuzzParser(f, conanLock{}, "conan.lock",
		`{"version":"0.5","requires":["zlib/1.3.1#`+strings.Repeat("a", 32)+`%1708593606.497","x/1.0@acme/stable#`+strings.Repeat("b", 32)+`"],"build_requires":["cmake/3.28.1"],"python_requires":[],"config_requires":[]}`,
		`{"graph_lock":{"nodes":{"0":{"path":"conanfile.txt","requires":["1"]},"1":{"ref":"zlib/1.2.13#`+strings.Repeat("c", 32)+`","package_id":"x","prev":"`+strings.Repeat("d", 32)+`"}},"revisions_enabled":true},"version":"0.4"}`)
}

func FuzzCpanfileSnapshot(f *testing.F) {
	fuzzParser(f, cpanfileSnapshot{}, "cpanfile.snapshot",
		"# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Try-Tiny-0.31\n    pathname: E/ET/ETHER/Try-Tiny-0.31.tar.gz\n    provides:\n      Try::Tiny 0.31\n    requirements:\n      Carp 0\n  "+testToken+"-1.0\n    pathname: X/"+testToken+"-1.0.tar.gz\n")
}

func FuzzCabalFreeze(f *testing.F) {
	fuzzParser(f, cabalFreeze{}, "cabal.project.freeze",
		"active-repositories: hackage.haskell.org:merge\nconstraints: any.aeson ==2.2.3.0,\n             aeson -ordered-keymap,\n             setup.Cabal ==3.10.3.0,\n             any.base installed,\n             any.text >=2\nindex-state: hackage.haskell.org 2024-11-11T15:28:27Z\n")
}

func FuzzStackLock(f *testing.F) {
	fuzzParser(f, stackLock{}, "stack.yaml.lock",
		"packages:\n- completed:\n    hackage: acme-missiles-0.3@sha256:"+strings.Repeat("a", 64)+",613\n    pantry-tree:\n      sha256: "+strings.Repeat("b", 64)+"\n      size: 226\n  original:\n    hackage: acme-missiles-0.3\n- completed:\n    commit: "+strings.Repeat("c", 40)+"\n    git: https://u:"+testToken+"@github.com/o/r.git\n    name: r\n    version: 0.1.0\n  original:\n    git: x\nsnapshots:\n- completed:\n    sha256: "+strings.Repeat("d", 64)+"\n    url: https://proxy.example.com/u/"+testToken+"/lts.yaml\n  original: lts-22.7\n")
}

func FuzzDenoLock(f *testing.F) {
	fuzzParser(f, denoLock{}, "deno.lock",
		`{"version":"4","specifiers":{"jsr:@std/path@^1":"1.0.8"},"jsr":{"@std/path@1.0.8":{"integrity":"`+strings.Repeat("a", 64)+`"}},"npm":{"chalk@5.3.0_x@1.0.0":{"integrity":"sha512-`+strings.Repeat("A", 86)+`==","tarball":"https://proxy.example.com/u/`+testToken+`/v1/npm/chalk/-/chalk-5.3.0.tgz"}},"remote":{"https://u:`+testToken+`@deno.land/std@0.200.0/fmt/colors.ts":"`+strings.Repeat("b", 64)+`"}}`,
		`{"version":"2","remote":{},"npm":{"specifiers":{},"packages":{"a@1.0.0":{"integrity":"sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}}`)
}

func FuzzChartLock(f *testing.F) {
	fuzzParser(f, chartLock{}, "Chart.lock",
		"dependencies:\n- name: redis\n  repository: oci://proxy.example.com/u/"+testToken+"/v1/helm\n  version: 20.1.0\n- name: a\n  repository: https://u:"+testToken+"@charts.example\n  version: 1.0.0\n- name: l\n  repository: file://../l\n  version: 0.1.0\n- name: s\n  repository: '@stable'\n  version: 2.0.0\ndigest: sha256:"+strings.Repeat("a", 64)+"\ngenerated: \"2024-10-10T10:10:10Z\"\n")
}

func FuzzRequirementsLock(f *testing.F) {
	fuzzParser(f, requirementsLock{}, "requirements.lock",
		"dependencies:\n- name: a\n  Repository: https://proxy.example.com/u/"+testToken+"/v1/helm\n  version: \"1.10\"\ndigest: sha256:"+strings.Repeat("a", 64)+"\n",
		"# generated by rye\n-e file:.\nanyio==4.4.0 \\\n  --hash=sha256:"+strings.Repeat("b", 64)+"\n    # via httpx\n--index-url https://u:"+testToken+"@proxy.example.com/v1/pypi/simple\n")
}

func FuzzBrewfileLock(f *testing.F) {
	fuzzParser(f, brewfileLock{}, "Brewfile.lock.json",
		`{"entries":{"tap":{"homebrew/core":{"revision":"`+strings.Repeat("a", 40)+`"}},"brew":{"hello":{"version":"2.12.1","bottle":{"rebuild":1,"root_url":"https://proxy.example.com/u/`+testToken+`/v1/homebrew","files":{"arm64_sonoma":{"cellar":":any","url":"https://u:`+testToken+`@ghcr.io/x","sha256":"`+strings.Repeat("b", 64)+`"}}}},"src":{"version":"1","bottle":false}},"cask":{"firefox":{"version":"120.0","options":{"full_name":"firefox"}}},"mas":{"Xcode":{"id":1,"version":"15"}}},"system":{}}`)
}

func FuzzAnsibleRequirements(f *testing.F) {
	fuzzParser(f, ansibleRequirements{}, "requirements.yml",
		"collections:\n  - name: community.general\n    version: 8.6.0\n    source: https://proxy.example.com/u/"+testToken+"/v1/galaxy\n  - name: https://u:"+testToken+"@github.com/o/c.git\n    type: git\n    version: "+strings.Repeat("a", 40)+"\n  - ns.c:1.0.0\nroles:\n  - name: geerlingguy.docker\n    version: 7.4.1\n  - src: git+https://github.com/o/r.git\n    version: v1\n",
		"- src: geerlingguy.java\n  version: 2.5.0\n- geerlingguy.repo-epel,3.1.1\n- src: https://h.example/r/archive/1.0.tar.gz\n  name: r\n")
}

func FuzzPuppetfile(f *testing.F) {
	fuzzParser(f, puppetfile{}, "Puppetfile",
		"forge 'https://proxy.example.com/u/"+testToken+"/v1/forge'\nmod 'puppetlabs/stdlib', '9.4.1'\nmod 'apache',\n  :git => 'https://u:"+testToken+"@github.com/o/apache.git',\n  :commit => '"+strings.Repeat("a", 40)+"' # c\nmod('x', git: 'https://h/x', ref: 'v1')\n"+
			"mod 'fw', type: 'tarball', source: 'https://proxy.example.com/u/"+testToken+"/fw.tar.gz', version: '"+strings.Repeat("b", 64)+"'\nif true then mod \"y#{z}\" end\n")
}

// FuzzGitmodules: .gitmodules is read as git reads it, and once every
// submodule is pinned to a gitlink the dependencies are well-formed and carry
// no token.
func FuzzGitmodules(f *testing.F) {
	p := gitmodules{}
	for _, s := range fixtureSeeds(f, p) {
		f.Add(s)
	}
	for _, s := range []string{
		"[submodule \"a\"]\n\tpath = vendor/a\n\turl = https://u:" + testToken + "@proxy.example.com/u/" + testToken + "/v1/git/a.git\n",
		"[submodule \"b\"] path = \"x y\" ; c\n url = git@github.com:o/r.git\n[Submodule.C]\npath=c\nurl=../c.git\\\n.d\n",
		"[submodule \"..\"]\npath=-p\nurl=ext::sh\n[submodule \"e\"]\npath=e\npath=f\nurl=https://h/e\n",
		"[submodule \"q\\\"\\\\\"]\npath = \"a\\tb\"\nurl = file:///x\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		res1, err1 := p.Parse(data)
		res2, err2 := p.Parse(data)
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("non-deterministic error")
		}
		if err1 != nil {
			return
		}
		if len(res1.submodules) != len(res2.submodules) {
			t.Fatal("non-deterministic result")
		}
		file := parseOne(p, gitmodulesPath, data)
		commit := strings.Repeat("c", 40)
		if _, err := joinSubmodules(file, func(string) (string, error) { return commit, nil }, "", nil); err != nil {
			t.Fatal(err)
		}
		finish([]*File{file}, fuzzProxy)
		if len(file.Dependencies) > len(res1.submodules) {
			t.Fatal("more dependencies than declarations")
		}
		for _, d := range file.Dependencies {
			if d.Name == "" || d.Version != commit || d.Revision != commit || d.Source != SourceGit || d.Unverified {
				t.Fatalf("malformed submodule dependency %+v", d)
			}
			if strings.HasPrefix(d.Name, "/") || strings.Contains("/"+d.Name+"/", "/../") || strings.HasPrefix(d.Registry, "-") {
				t.Fatalf("a path or URL git would not use: %+v", d)
			}
		}
		out, _ := json.Marshal(file)
		if loc := tokenLeft.FindIndex(out); loc != nil {
			t.Fatalf("a link token survived: …%s…", out[max(0, loc[0]-40):min(len(out), loc[1]+40)])
		}
	})
}

// FuzzTOML: the TOML reader never panics, and what it accepts it reads the
// same way twice.
func FuzzTOML(f *testing.F) {
	for _, p := range []Parser{cargoLock{}, poetryLock{}, uvLock{}, pdmLock{}} {
		for _, s := range fixtureSeeds(f, p) {
			f.Add(s)
		}
	}
	for _, s := range []string{"a = 1", "[[a]]\n[a.b]\nc = \"\"\"x\"\"\"", "a = {b = [1, {c = 'd'}]}", "a = " + strings.Repeat("[", 70)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, err1 := parseTOML(data)
		_, err2 := parseTOML(data)
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("non-deterministic")
		}
	})
}

// FuzzHCL: the HCL reader never panics, and what it accepts it reads the
// same way twice.
func FuzzHCL(f *testing.F) {
	for _, p := range []Parser{terraformLock{}, terraformModules{}} {
		for _, s := range fixtureSeeds(f, p) {
			f.Add(s)
		}
	}
	for _, s := range []string{"a = \"${b}\"", "b {\n c = <<EOT\nx\nEOT\n}", "c = [\"a\", \"b\",]", "d \"x\" { e = 1 }", "f = \"%{ if x }${\"}\"}%{ endif }\"", "g = " + strings.Repeat("[", 70)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		b1, err1 := parseHCL(data, "module", "provider")
		b2, err2 := parseHCL(data, "module", "provider")
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("non-deterministic")
		}
		if err1 == nil && (len(b1.blocks) != len(b2.blocks) || b1.attrCount != b2.attrCount || b1.blockCount != b2.blockCount) {
			t.Fatal("non-deterministic body")
		}
	})
}

// FuzzGitConfig: the git configuration reader never panics and is
// deterministic.
func FuzzGitConfig(f *testing.F) {
	for _, s := range fixtureSeeds(f, gitmodules{}) {
		f.Add(s)
	}
	for _, s := range []string{"[a]\nb", "[a \"b\\\"c\"] d = \"e\\\\\" ; f", "[a.B]c=d\\\ne", "[a]\r\nb = c\\x"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		e1, err1 := parseGitConfig(string(data))
		e2, err2 := parseGitConfig(string(data))
		if (err1 == nil) != (err2 == nil) || len(e1) != len(e2) {
			t.Fatal("non-deterministic")
		}
	})
}

// FuzzElixirTerms: the Elixir literal reader never panics and reads what it
// accepts the same way twice.
func FuzzElixirTerms(f *testing.F) {
	for _, s := range fixtureSeeds(f, mixLock{}) {
		f.Add(s)
	}
	for _, s := range []string{"%{}", "[a: 1, b: :c]", "{:x, \"y\\n\", -1.5e3}", "%{\"k\" => [{}]}", strings.Repeat("[", 70)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		p1 := &exParser{s: string(data), line: 1}
		err1 := p1.skip()
		p2 := &exParser{s: string(data), line: 1}
		err2 := p2.skip()
		if (err1 == nil) != (err2 == nil) || (err1 == nil && (p1.pos != p2.pos || p1.line != p2.line)) {
			t.Fatal("non-deterministic")
		}
		if err1 == nil && p1.pos > len(data) {
			t.Fatal("read past the end")
		}
	})
}

// FuzzProxyMapping: whatever a URL looks like, mapping and redaction never
// let a token through and never panic.
func FuzzProxyMapping(f *testing.F) {
	for _, s := range []string{
		seedURL + "/a/-/a.tgz",
		"https://registry.npmjs.org/_pullthrough/v1/npm/x",
		"https://cache.example/b/u/" + testToken + "/v1/npm/x?q#f",
		"https://u:" + testToken + "@proxy.example.com/v1/npm",
		"http://10.0.0.1:8080/pt/u/x/v1/pypi/simple",
		"git+ssh://git@github.com/o/r.git#" + strings.Repeat("a", 40),
		"proxy.example.com/u/" + testToken + "/dockerhub/library/alpine@sha256:" + strings.Repeat("a", 64),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		m, _ := fuzzProxy.mapURL(s)
		for _, field := range []string{m.url, m.upstream, m.upstreamURL, redactText(s, "/u"), cleanURL(s), sanitizeURL(redactText(s, "/u"))} {
			if tokenLeft.MatchString(field) {
				t.Fatalf("a token survived in %q", field)
			}
		}
		d := Dependency{Type: "docker", Name: s, Registry: "https://proxy.example.com"}
		fuzzProxy.finishImage(&d)
		if tokenLeft.MatchString(d.Name + d.Registry + d.Upstream) {
			t.Fatalf("token survived in an image: %+v", d)
		}
	})
}
