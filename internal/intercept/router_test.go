package intercept

import (
	"reflect"
	"testing"
)

func TestRouterLookup(t *testing.T) {
	r := NewRouter(map[string]string{
		"registry.npmjs.org": "npm",
		"pypi.org":           "pip",
		"*.docker.io":        "docker",
		"registry.docker.io": "docker-exact",
		"":                   "ignored-empty-host",
		"nohost.example":     "", // ignored: empty backend
	})

	cases := []struct {
		host        string
		wantBackend string
		wantOK      bool
	}{
		{"registry.npmjs.org", "npm", true},
		{"registry.npmjs.org:443", "npm", true}, // port ignored
		{"REGISTRY.NPMJS.ORG", "npm", true},     // case-insensitive
		{"pypi.org", "pip", true},
		{"index.docker.io", "docker", true},          // wildcard
		{"registry.docker.io", "docker-exact", true}, // exact beats wildcard
		{"files.pythonhosted.org", "", false},        // unconfigured
		{"nohost.example", "", false},                // backend was empty -> not added
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := r.Lookup(c.host)
		if got != c.wantBackend || ok != c.wantOK {
			t.Errorf("Lookup(%q) = (%q,%t), want (%q,%t)", c.host, got, ok, c.wantBackend, c.wantOK)
		}
	}
}

func TestRouterLongestWildcardWins(t *testing.T) {
	r := NewRouter(map[string]string{
		"*.io":            "broad",
		"*.pkg.github.io": "narrow",
	})
	if got, _ := r.Lookup("a.pkg.github.io"); got != "narrow" {
		t.Errorf("expected narrow wildcard to win, got %q", got)
	}
	if got, _ := r.Lookup("a.io"); got != "broad" {
		t.Errorf("expected broad wildcard, got %q", got)
	}
}

func TestNilRouter(t *testing.T) {
	var r *Router
	if _, ok := r.Lookup("x"); ok {
		t.Fatal("nil router should match nothing")
	}
	if r.Len() != 0 {
		t.Fatal("nil router Len should be 0")
	}
	if r.Hosts() != nil {
		t.Fatal("nil router Hosts should be nil")
	}
}

func TestRouterHosts(t *testing.T) {
	r := NewRouter(map[string]string{
		"b.example":   "x",
		"a.example":   "y",
		"*.c.example": "z",
	})
	want := []string{"*.c.example", "a.example", "b.example"}
	if got := r.Hosts(); !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://registry.npmjs.org":   "registry.npmjs.org",
		"https://pypi.org/simple/":     "pypi.org",
		"http://mirror.local:8080/foo": "mirror.local",
		"registry.example.com":         "registry.example.com", // scheme-less
		"HTTPS://UPPER.EXAMPLE.COM":    "upper.example.com",
		"":                             "",
		"://bad":                       "",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
