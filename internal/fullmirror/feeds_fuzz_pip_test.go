//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
)

// The pip feed reads PyPI's answers — untrusted input. These targets hold its
// parsers to never panic, to stay bounded, and to hand the engine only
// changes and paths it can carry.

// pypiFuzzSeedMax bounds a seed. The engine minimizes every input that finds
// new coverage, in time quadratic in its length: a seed of a few kilobytes
// would spend the whole fuzzing time being minimized.
const pypiFuzzSeedMax = 1 << 10

// pypiFuzzSeeds adds the recorded fixtures matching pattern as seeds, each cut
// to pypiFuzzSeedMax bytes at a line end.
func pypiFuzzSeeds(f *testing.F, pattern string) {
	f.Helper()
	paths, _ := filepath.Glob(filepath.Join("testdata", "feeds", "pip", pattern))
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			if len(data) > pypiFuzzSeedMax {
				data = data[:pypiFuzzSeedMax]
				if i := bytes.LastIndexByte(data, '\n'); i > 0 {
					data = data[:i+1]
				}
			}
			f.Add(data)
		}
	}
}

func FuzzPipXMLRPC(f *testing.F) {
	pypiFuzzSeeds(f, "*.xml")
	f.Add([]byte(`<methodResponse><params><param><value><array><data><value><array><data><value>a</value><value><nil/></value><value><i4>1</i4></value><value>remove project</value><value><i8>9</i8></value></data></array></value></data></array></value></param></params></methodResponse>`))
	f.Add([]byte(`<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>-32500</int></value></member><member><name>faultString</name><value>HTTPTooManyRequests: Limit may reset in 9 seconds.</value></member></struct></value></fault></methodResponse>`))
	f.Fuzz(func(t *testing.T, body []byte) {
		params, fault, err := pypiParseXMLRPC(body)
		if err != nil {
			return
		}
		if fault != nil {
			_ = fault.classify("fuzz")
			return
		}
		rows, total, err := pypiChangelogRows(params)
		if err != nil {
			return
		}
		if len(rows) > total {
			t.Fatalf("%d rows of %d", len(rows), total)
		}
		items := pypiChangelogItems(rows)
		if err := validateBatch(Batch{Items: items, Next: "x"}); err != nil {
			t.Fatalf("the engine would refuse the batch: %v", err)
		}
		seen := map[Coordinate]bool{}
		for _, c := range items {
			if !pypiValidName(c.Name) || (c.Version != "" && !pypiValidVersion(c.Version)) || seen[c] {
				t.Fatalf("change %+v", c)
			}
			seen[c] = true
		}
	})
}

func FuzzPipProjectList(f *testing.F) {
	pypiFuzzSeeds(f, "simple-index*.json")
	f.Add([]byte(`{"projects":[{"name":"A_b","_last-serial":3},{"name":"a.B","_last-serial":5},{"name":"-x"}],"meta":{"_last-serial":2}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		idx, err := pypiParseIndex(bytes.NewReader(body))
		if err != nil {
			return
		}
		for i, p := range idx.projects {
			if !pypiValidName(p.name) || p.serial < -1 || (i > 0 && idx.projects[i-1].name >= p.name) {
				t.Fatalf("project %d %+v", i, p)
			}
		}
		// What is stored reads back line by line as it was.
		var buf bytes.Buffer
		if err := pypiEncodeStore(&buf, idx); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		if len(lines) != len(idx.projects)+1 {
			t.Fatalf("%d lines for %d projects", len(lines), len(idx.projects))
		}
		for i, line := range lines[1:] {
			if p, ok := pypiStoreLine([]byte(line)); !ok || p != idx.projects[i] {
				t.Fatalf("line %q reads as %+v %v", line, p, ok)
			}
		}
	})
}

func FuzzPipStoreLine(f *testing.F) {
	f.Add([]byte(`["six",26356948]`))
	f.Add([]byte(`["a-b",-1]`))
	f.Add([]byte(`["\"",1]`))
	f.Fuzz(func(t *testing.T, line []byte) {
		p, ok := pypiStoreLine(line)
		if ok && (!pypiValidName(p.name) || p.serial < -1) {
			t.Fatalf("%q reads as %+v", line, p)
		}
	})
}

func FuzzPipSimplePageReleases(f *testing.F) {
	pypiFuzzSeeds(f, "page-*.json")
	f.Add([]byte(`{"files":[{"filename":"six-1.17.0.tar.gz","hashes":{"sha256":"ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81"},"size":34031,"upload-time":"2024-12-04T17:35:28.174320Z","url":"http://proxy.example/v1/pip-test/files/https/files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz","yanked":false}],"meta":{"_last-serial":26356948,"api-version":"1.4"},"name":"six","versions":["1.17.0"]}`))
	f.Add([]byte(`<a href="/v1/pip-test/files/https/files.pythonhosted.org/p/six-1.0.tar.gz" data-yanked>six-1.0.tar.gz</a><a href="/v1/pip-test/files/https/files.pythonhosted.org/p/six-1.0.0-py3-none-any.whl">six-1.0.0-py3-none-any.whl</a>`))
	up := locate.Upstream{Name: "pip-test", Type: "pip", URLs: []string{"https://pypi.org"}}
	f.Fuzz(func(t *testing.T, body []byte) {
		files, listed, err := locate.PipFiles(up, "six", "/simple/six/", locate.Document{Status: 200, Body: body})
		if err != nil {
			return
		}
		rels := pypiReleases(files, listed)
		seen := map[string]bool{}
		for _, r := range rels {
			if !pypiValidVersion(r.Version) || seen[r.Version] || len(r.Artifacts) == 0 {
				t.Fatalf("release %+v", r)
			}
			seen[r.Version] = true
			for _, a := range r.Artifacts {
				if !validArtifactPath(a.Path) || a.Size < 0 {
					t.Fatalf("artifact %+v", a)
				}
			}
		}
	})
}

func FuzzPipCursor(f *testing.F) {
	f.Add(`{"format":"pip/1","mode":"xmlrpc","serial":43707253}`)
	f.Add(`{"format":"pip/1","mode":"simple","serial":1,"listing":true,"skip":5,"store":"9418c9336f16440b06dbc99e3334827be5e83e0a329b6d2c62adc5fd5dd602b3"}`)
	feed := &pypiFeed{}
	f.Fuzz(func(t *testing.T, cursor string) {
		c, err := feed.decode(cursor)
		if err != nil {
			return
		}
		if c.Serial < 0 || c.Skip < 0 || (c.Store != "" && !pypiIsDigest(c.Store)) || (c.Listing && c.Store == "") {
			t.Fatalf("cursor %+v accepted", c)
		}
	})
}
