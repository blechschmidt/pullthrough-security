package locate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

func TestParseNPMPackument(t *testing.T) {
	doc := `{"name":"left-pad","versions":{
		"1.0.0":{"name":"left-pad","version":"1.0.0","license":"MIT","dependencies":{"a":"^1.0.0"},"dist":{"integrity":"sha512-AAAA","shasum":"0123456789012345678901234567890123456789"}},
		"1.0.1":{"version":"1.0.1","dependencies":{"a":"^1.0.0"},"license":"MIT","name":"left-pad","dist":{"integrity":"sha512-BBBB"}},
		"1.1.0":{"version":"1.1.0","dependencies":{"a":"^2.0.0"},"license":"MIT"},
		"1.2.0":{"version":"1.2.0","dependencies":{"a":"^1.0.0"},"license":"MIT","scripts":{"postinstall":"node x.js"}},
		"1.3.0":{"version":"1.3.0","dependencies":{"a":"^1.0.0"},"license":"MIT","deprecated":"use right-pad"},
		"9.9.9":"not an object"},
		"time":{"1.0.0":"2025-01-01T00:00:00Z","1.0.1":"2025-02-01T00:00:00.000Z"}}`
	l, err := ParseNPMPackument([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Releases) != 5 {
		t.Fatalf("releases: %+v", l.Releases)
	}
	r100, _ := l.Release("1.0.0")
	r101, _ := l.Release("1.0.1")
	r110, _ := l.Release("1.1.0")
	r120, _ := l.Release("1.2.0")
	r130, _ := l.Release("1.3.0")
	if r100.Fingerprint == "" || r100.Fingerprint != r101.Fingerprint {
		t.Errorf("equal metadata in another key order must fingerprint alike: %q %q", r100.Fingerprint, r101.Fingerprint)
	}
	for name, r := range map[string]Release{"other deps": r110, "install script": r120, "deprecated": r130} {
		if r.Fingerprint == r100.Fingerprint {
			t.Errorf("%s: the fingerprint must differ", name)
		}
	}
	if r130.Deprecated != "use right-pad" || r100.Published.IsZero() || r101.Published.IsZero() {
		t.Errorf("deprecated %q published %v %v", r130.Deprecated, r100.Published, r101.Published)
	}
	if len(r100.Integrity) != 2 || r100.Integrity[0].Algorithm != "sha512" || r100.Integrity[1].Algorithm != "sha1" {
		t.Errorf("integrity: %+v", r100.Integrity)
	}
	if len(r100.Requires) != 1 || r100.Requires[0] != (Requirement{Name: "a", Constraint: "^1.0.0"}) {
		t.Errorf("requires: %+v", r100.Requires)
	}
	if _, err := ParseNPMPackument([]byte(`{"versions": 3}`)); err == nil {
		t.Error("a packument whose versions are not an object must fail")
	}
}

func TestParseCargoIndex(t *testing.T) {
	line := func(v string, deps string, yanked bool) string {
		y := "false"
		if yanked {
			y = "true"
		}
		return `{"name":"tiny_crate","vers":"` + v + `","deps":[` + deps + `],"cksum":"` + strings.Repeat("a", 64) + `","features":{},"yanked":` + y + `}`
	}
	d1 := `{"name":"serde","req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"}`
	d2 := `{"name":"cc","req":"^1.0","features":[],"optional":false,"default_features":true,"target":null,"kind":"build"}`
	body := strings.Join([]string{
		line("1.0.0", d1+","+d2, false),
		line("1.0.1", d2+","+d1, false), // the same deps in another order
		line("1.0.2", d1, false),
		line("1.0.3", d1+","+d2, true),
		`{"name":"other","vers":"9.0.0","deps":[],"cksum":"","features":{}}`,
	}, "\n")
	l, err := ParseCargoIndex([]byte(body), "tiny-crate")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Releases) != 4 {
		t.Fatalf("releases: %+v", l.Releases)
	}
	if l.Releases[0].Fingerprint != l.Releases[1].Fingerprint {
		t.Error("the same dependencies in another order must fingerprint alike")
	}
	if l.Releases[0].Fingerprint == l.Releases[2].Fingerprint {
		t.Error("other dependencies must fingerprint differently")
	}
	if !l.Releases[3].Yanked || l.Releases[0].Yanked {
		t.Error("yanked flag")
	}
	if got := l.Releases[0].Requires; len(got) != 2 || got[1].Kind != "build" {
		t.Errorf("requires: %+v", got)
	}
	if _, err := ParseCargoIndex([]byte("{not json"), "x"); err == nil {
		t.Error("a malformed line must fail")
	}
}

func TestCargoIndexPath(t *testing.T) {
	for name, want := range map[string]string{"a": "/1/a", "ab": "/2/ab", "abc": "/3/a/abc", "Serde": "/se/rd/serde", "tinycrate": "/ti/ny/tinycrate"} {
		if got, err := cargoIndexPath(name); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", name, got, err, want)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "a b"} {
		if _, err := cargoIndexPath(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestGoModRequires(t *testing.T) {
	a := []byte("module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.0 // indirect\n\texample.com/a v1.2.3\n)\n\nrequire example.com/b v0.1.0\n")
	b := []byte("module x\n\n// a comment\nrequire example.com/b v0.1.0\nrequire (\nexample.com/a v1.2.3\ngolang.org/x/text v0.3.0\n)\n")
	ra, fa, err := GoModRequires(a)
	if err != nil {
		t.Fatal(err)
	}
	_, fb, err := GoModRequires(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(ra) != 3 || ra["example.com/a"] != "v1.2.3" || fa != fb {
		t.Errorf("requires %v, fingerprints %q %q", ra, fa, fb)
	}
	if _, fc, _ := GoModRequires([]byte("module x\nrequire example.com/b v0.2.0\n")); fc == fa {
		t.Error("other requirements must fingerprint differently")
	}
	if _, _, err := GoModRequires([]byte("require example.com/b\n")); err == nil {
		t.Error("a require without a version must fail")
	}
}

func TestSimplePageYanked(t *testing.T) {
	html := `<a href="https://files/x-1.0.0.tar.gz#sha256=aa">x-1.0.0.tar.gz</a>
<a data-yanked="" href="https://files/x-1.0.1.tar.gz#sha256=bb">x-1.0.1.tar.gz</a>
<a href="https://files/x-1.0.2-py3-none-any.whl#sha256=cc" data-yanked="broken">x-1.0.2-py3-none-any.whl</a>
<a href="https://files/x-1.0.2.tar.gz#sha256=dd">x-1.0.2.tar.gz</a>`
	files := parseSimpleHTML(html)
	if len(files) != 4 || files[0].Yanked || !files[1].Yanked || !files[2].Yanked || files[3].Yanked {
		t.Fatalf("yanked: %+v", files)
	}
	j, _ := json.Marshal(map[string]any{"files": []map[string]any{
		{"filename": "x-1.0.0.tar.gz", "url": "u", "hashes": map[string]string{"sha256": "AA"}, "yanked": false},
		{"filename": "x-1.0.1.tar.gz", "url": "u", "hashes": map[string]string{"sha256": "bb"}, "yanked": "reason"},
		{"filename": "x-1.0.2.tar.gz", "url": "u", "hashes": map[string]string{"sha256": "cc"}, "yanked": true},
	}})
	jf, err := parseSimplePage(Document{ContentType: "application/vnd.pypi.simple.v1+json", Body: j})
	if err != nil || len(jf) != 3 || jf[0].Yanked || !jf[1].Yanked || !jf[2].Yanked || jf[0].SHA256 != "aa" {
		t.Fatalf("json yanked: %+v %v", jf, err)
	}
}

// pathDocs serves documents by path (any upstream) for the listers.
type pathDocs map[string]Document

func (f pathDocs) FetchDocument(_ context.Context, _, path, _ string) (Document, error) {
	if d, ok := f[path]; ok {
		if d.Status == 0 {
			d.Status = 200
		}
		return d, nil
	}
	return Document{Status: 404}, nil
}

func TestListVersions(t *testing.T) {
	env := Env{
		Upstreams: []Upstream{
			{Name: "npm", Type: "npm", URLs: []string{"https://registry.npmjs.org"}},
			{Name: "pypi", Type: "pip", URLs: []string{"https://pypi.org"}},
			{Name: "gp", Type: "go", URLs: []string{"https://proxy.golang.org"}},
		},
		Fetch: pathDocs{
			"/@scope/pkg":                                 {Body: []byte(`{"versions":{"1.0.0":{},"1.1.0":{}}}`)},
			"/simple/my-pkg/":                             {ContentType: "text/html", Body: []byte(`<a href="https://f/My_Pkg-1.0.0.tar.gz">My_Pkg-1.0.0.tar.gz</a><a href="https://f/my_pkg-1.2.0-py3-none-any.whl" data-yanked>my_pkg-1.2.0-py3-none-any.whl</a><a href="https://f/other-9.tar.gz">other-9.tar.gz</a>`)},
			"/github.com/!burnt!sushi/toml/@v/list":       {Body: []byte("v1.0.0\nv1.2.0\n\nv1.3.0-rc.1\n")},
			"/github.com/!burnt!sushi/toml/@v/v1.2.0.mod": {Body: []byte("module github.com/BurntSushi/toml\n\nretract v1.0.0 // broken\n")},
			"/pypi/my-pkg/1.0.0/json":                     {Body: []byte(`{"info":{"version":"1.0.0","requires_dist":["b>=1", "a (<2)"]}}`)},
			"/pypi/my-pkg/1.2.0/json":                     {Body: []byte(`{"info":{"version":"1.2.0","requires_dist":["a (<2)","b>=1"]}}`)},
		},
	}
	ctx := context.Background()
	l, err := ListVersions(ctx, env, lockfiles.Dependency{Type: "npm", Name: "@scope/pkg", Version: "1.0.0"})
	if err != nil || len(l.Releases) != 2 || l.Upstream != "npm" {
		t.Fatalf("npm: %+v %v", l, err)
	}
	l, err = ListVersions(ctx, env, lockfiles.Dependency{Type: "pip", Name: "my-pkg", Version: "1.0.0"})
	if err != nil || len(l.Releases) != 2 || l.Releases[0].Yanked || !l.Releases[1].Yanked {
		t.Fatalf("pip: %+v %v", l, err)
	}
	l, err = ListVersions(ctx, env, lockfiles.Dependency{Type: "go", Name: "github.com/BurntSushi/toml", Version: "v1.0.0"})
	if err != nil || len(l.Releases) != 3 || !l.Releases[0].Yanked || l.Releases[1].Yanked {
		t.Fatalf("go: %+v %v", l, err)
	}
	if _, err := ListVersions(ctx, env, lockfiles.Dependency{Type: "npm", Name: "x", Source: lockfiles.SourceGit}); !IsUnsupported(err) {
		t.Errorf("a Git dependency must be unsupported: %v", err)
	}
	if _, err := ListVersions(ctx, env, lockfiles.Dependency{Type: "maven", Name: "g:a", Version: "1"}); !IsUnsupported(err) {
		t.Errorf("maven must be unsupported: %v", err)
	}
	_, fa, known, err := PythonRequirements(ctx, env, lockfiles.Dependency{Type: "pip", Name: "my-pkg"}, "1.0.0")
	_, fb, _, _ := PythonRequirements(ctx, env, lockfiles.Dependency{Type: "pip", Name: "my-pkg"}, "1.2.0")
	if err != nil || !known || fa == "" || fa != fb {
		t.Fatalf("requirements: %q %q %v %v", fa, fb, known, err)
	}
	if _, _, known, err := PythonRequirements(ctx, env, lockfiles.Dependency{Type: "pip", Name: "my-pkg"}, "3.0"); known || err != nil {
		t.Errorf("an unknown release must be unknown, not an error: %v %v", known, err)
	}
}

func TestCheckerComputes(t *testing.T) {
	body := []byte("hello")
	c, err := NewChecker(Artifact{Path: "/x/-/x-1.tgz", Role: "package", Compute: []string{"sha512", "sha1"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write(body)
	res := c.Result()
	if res.Status != CheckUnverified || res.Computed["sha1"] != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" || len(res.Computed["sha512"]) != 128 {
		t.Fatalf("result: %+v", res)
	}
	if _, err := NewChecker(Artifact{Path: "/x", Role: "package", Compute: []string{"h1"}}, ""); err == nil {
		t.Error("h1 of something other than a module zip or go.mod must be refused")
	}
	mod := []byte("module example.com/x\n")
	c, _ = NewChecker(Artifact{Path: "/example.com/x/@v/v1.0.0.mod", Role: "go.mod", Compute: []string{"h1"}}, "")
	_, _ = c.Write(mod)
	if got := c.Result().Computed["h1"]; got != goHash1([]goFile{{name: "go.mod", data: mod}}) {
		t.Fatalf("go.mod h1: %q", got)
	}
}

func TestGoModRetractions(t *testing.T) {
	retracted := GoModRetractions([]byte("module x\n\nretract v1.0.1 // a bug\nretract [v1.2.0, v1.2.5]\nretract (\n\tv2.0.0+incompatible\n\t[v1.4.0, v1.4.1] // more\n)\n"))
	for v, want := range map[string]bool{"v1.0.1": true, "v1.0.2": false, "v1.2.0": true, "v1.2.3": true, "v1.2.6": false,
		"v1.4.1": true, "v1.3.0": false, "v2.0.0+incompatible": true, "nonsense": false} {
		if got := retracted(v); got != want {
			t.Errorf("%s: retracted %v, want %v", v, got, want)
		}
	}
}
