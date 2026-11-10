package pkgmgr

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

func req(path string) *backends.Request { return &backends.Request{Method: "GET", Path: path} }

func TestNPMCoordinate(t *testing.T) {
	cases := []struct {
		path          string
		ok            bool
		name, version string
	}{
		{"/lodash/-/lodash-4.17.21.tgz", true, "lodash", "4.17.21"},
		{"/@babel/core/-/core-7.24.0.tgz", true, "@babel/core", "7.24.0"},
		{"/lodash", false, "", ""},
		{"/lodash/", false, "", ""},
	}
	for _, c := range cases {
		coord, ok := npmCoordinate(req(c.path))
		if ok != c.ok || coord.Name != c.name || coord.Version != c.version {
			t.Errorf("npmCoordinate(%q)=(%q,%q,%v) want (%q,%q,%v)",
				c.path, coord.Name, coord.Version, ok, c.name, c.version, c.ok)
		}
	}
}

func TestGoCoordinate(t *testing.T) {
	cases := []struct {
		path          string
		ok            bool
		name, version string
	}{
		{"/golang.org/x/text/@v/v0.3.8.zip", true, "golang.org/x/text", "v0.3.8"},
		{"/github.com/!cli/!cli/@v/v2.0.0.info", true, "github.com/!cli/!cli", "v2.0.0"},
		{"/example.com/m/@v/list", false, "", ""},
		{"/example.com/m/@latest", false, "", ""},
	}
	for _, c := range cases {
		coord, ok := goCoordinate(req(c.path))
		if ok != c.ok || coord.Name != c.name || coord.Version != c.version {
			t.Errorf("goCoordinate(%q)=(%q,%q,%v) want (%q,%q,%v)",
				c.path, coord.Name, coord.Version, ok, c.name, c.version, c.ok)
		}
	}
}

func TestCargoCoordinate(t *testing.T) {
	coord, ok := cargoCoordinate(req("/api/v1/crates/serde/1.0.193/download"))
	if !ok || coord.Name != "serde" || coord.Version != "1.0.193" {
		t.Errorf("cargoCoordinate = (%q,%q,%v)", coord.Name, coord.Version, ok)
	}
	if _, ok := cargoCoordinate(req("/config.json")); ok {
		t.Error("config.json should not yield a coordinate")
	}
}

func TestNuGetCoordinate(t *testing.T) {
	coord, ok := nugetCoordinate(req("/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"))
	if !ok || coord.Name != "newtonsoft.json" || coord.Version != "13.0.3" {
		t.Errorf("nugetCoordinate = (%q,%q,%v)", coord.Name, coord.Version, ok)
	}
	if _, ok := nugetCoordinate(req("/v3-flatcontainer/newtonsoft.json/index.json")); ok {
		t.Error("index.json should not yield a coordinate")
	}
}

func TestPipCoordinate(t *testing.T) {
	cases := []struct {
		path          string
		ok            bool
		name, version string
	}{
		{"/files/https/files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl", true, "requests", "2.31.0"},
		{"/files/https/files.pythonhosted.org/packages/aa/bb/Flask-3.0.0.tar.gz", true, "flask", "3.0.0"},
		{"/files/https/files.pythonhosted.org/packages/xx/yy/typing_extensions-4.9.0-py3-none-any.whl", true, "typing-extensions", "4.9.0"},
		{"/simple/requests/", false, "", ""},
	}
	for _, c := range cases {
		coord, ok := pipCoordinate(req(c.path))
		if ok != c.ok || coord.Name != c.name || coord.Version != c.version {
			t.Errorf("pipCoordinate(%q)=(%q,%q,%v) want (%q,%q,%v)",
				c.path, coord.Name, coord.Version, ok, c.name, c.version, c.ok)
		}
	}
}

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"Flask":             "flask",
		"typing_extensions": "typing-extensions",
		"Foo.Bar_baz":       "foo-bar-baz",
		"a--b":              "a-b",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q)=%q want %q", in, got, want)
		}
	}
}
