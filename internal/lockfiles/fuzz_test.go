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
	fuzzParser(f, goSum{}, "go.sum", "a v1.0.0 h1:AAAA=\na v1.0.0/go.mod h1:BBBB=\nb v2.0.0/go.mod h1:CCCC=\n")
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
