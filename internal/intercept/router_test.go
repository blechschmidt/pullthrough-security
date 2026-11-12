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
		route, ok := r.Route(c.host, "/x")
		if route.Backend != c.wantBackend || ok != c.wantOK {
			t.Errorf("Route(%q) = (%q,%t), want (%q,%t)", c.host, route.Backend, ok, c.wantBackend, c.wantOK)
		}
		if r.Intercepts(c.host) != c.wantOK {
			t.Errorf("Intercepts(%q) = %t, want %t", c.host, !c.wantOK, c.wantOK)
		}
	}
}

func TestRouterLongestWildcardWins(t *testing.T) {
	r := NewRouter(map[string]string{
		"*.io":            "broad",
		"*.pkg.github.io": "narrow",
	})
	if got, _ := r.Route("a.pkg.github.io", "/"); got.Backend != "narrow" {
		t.Errorf("expected narrow wildcard to win, got %q", got.Backend)
	}
	if got, _ := r.Route("a.io", "/"); got.Backend != "broad" {
		t.Errorf("expected broad wildcard, got %q", got.Backend)
	}
}

func TestNilRouter(t *testing.T) {
	var r *Router
	if _, ok := r.Route("x", "/"); ok || r.Intercepts("x") {
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

func TestRouterPathPrefixes(t *testing.T) {
	r := NewRouter(map[string]string{
		"deb.debian.org/debian":                "apt",
		"deb.debian.org/debian-security/":      "apt-security",
		"https://repo1.maven.org/maven2":       "maven",
		"repo.maven.apache.org/maven2":         "maven",
		"dl.rockylinux.org/pub/rocky/9/BaseOS": "yum",
		"registry.npmjs.org":                   "npm",
		"*.example.com/packages":               "wild",
	})
	cases := []struct {
		host, path string
		want       Route
		ok         bool
	}{
		{"deb.debian.org", "/debian/dists/bookworm/InRelease", Route{"apt", "/debian", "/dists/bookworm/InRelease"}, true},
		{"deb.debian.org", "/debian", Route{"apt", "/debian", "/"}, true},
		{"deb.debian.org", "/debian/", Route{"apt", "/debian", "/"}, true},
		// A sibling archive is not below /debian: it has a rule of its own.
		{"deb.debian.org", "/debian-security/dists/x", Route{"apt-security", "/debian-security", "/dists/x"}, true},
		// No rule covers the host's other paths.
		{"deb.debian.org", "/debian-ports/x", Route{}, false},
		{"deb.debian.org", "/", Route{}, false},
		{"repo1.maven.org", "/maven2/org/x/1/x-1.jar", Route{"maven", "/maven2", "/org/x/1/x-1.jar"}, true},
		{"repo.maven.apache.org:443", "/maven2/org/x/1/x-1.pom", Route{"maven", "/maven2", "/org/x/1/x-1.pom"}, true},
		{"dl.rockylinux.org", "/pub/rocky/9/BaseOS/x86_64/os/repodata/repomd.xml", Route{"yum", "/pub/rocky/9/BaseOS", "/x86_64/os/repodata/repomd.xml"}, true},
		// Paths are case-sensitive.
		{"dl.rockylinux.org", "/pub/rocky/9/baseos/x", Route{}, false},
		{"registry.npmjs.org", "/is-number", Route{"npm", "", "/is-number"}, true},
		{"registry.npmjs.org.", "/is-number", Route{"npm", "", "/is-number"}, true}, // fully qualified
		{"a.example.com", "/packages/x", Route{"wild", "/packages", "/x"}, true},
		{"a.example.com", "/other", Route{}, false},
	}
	for _, c := range cases {
		got, ok := r.Route(c.host, c.path)
		if ok != c.ok || got != c.want {
			t.Errorf("Route(%q, %q) = %+v, %t; want %+v, %t", c.host, c.path, got, ok, c.want, c.ok)
		}
	}
	// A host is intercepted as soon as any rule names it — whether a given path
	// on it is served is decided per request.
	for _, h := range []string{"deb.debian.org", "repo.maven.apache.org", "x.example.com"} {
		if !r.Intercepts(h) {
			t.Errorf("Intercepts(%q) = false", h)
		}
	}
	if r.Intercepts("example.com") {
		t.Error("a wildcard below a domain must not intercept the domain itself")
	}
	wantHosts := []string{
		"*.example.com/packages", "deb.debian.org/debian", "deb.debian.org/debian-security",
		"dl.rockylinux.org/pub/rocky/9/BaseOS", "registry.npmjs.org", "repo.maven.apache.org/maven2", "repo1.maven.org/maven2",
	}
	if got := r.Hosts(); !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("Hosts() = %v, want %v", got, wantHosts)
	}
	wantNames := []string{"deb.debian.org", "dl.rockylinux.org", "registry.npmjs.org", "repo.maven.apache.org", "repo1.maven.org"}
	if got := r.HostNames(); !reflect.DeepEqual(got, wantNames) {
		t.Errorf("HostNames() = %v, want %v", got, wantNames)
	}
}

func TestRouterConflictingRulesResolveDeterministically(t *testing.T) {
	// Two spellings of one rule naming different backends: the result must not
	// depend on map iteration order.
	for i := 0; i < 20; i++ {
		r := NewRouter(map[string]string{
			"https://deb.debian.org/debian": "b-apt",
			"deb.debian.org/debian/":        "a-apt",
		})
		if got, _ := r.Route("deb.debian.org", "/debian/x"); got.Backend != "a-apt" {
			t.Fatalf("conflicting rules resolved to %q", got.Backend)
		}
		if r.Len() != 1 {
			t.Fatalf("Len() = %d, want the duplicate dropped", r.Len())
		}
	}
}

func TestParseRuleAndRuleOf(t *testing.T) {
	cases := []struct {
		key, host, prefix string
		ok                bool
	}{
		{"pypi.org", "pypi.org", "", true},
		{"PyPI.org:443", "pypi.org", "", true},
		{"https://deb.debian.org/debian/", "deb.debian.org", "/debian", true},
		{"*.Docker.io/v2", "*.docker.io", "/v2", true},
		{"https://example.com/repo?x=1", "example.com", "/repo", true},
		{"[::1]:8080/x", "::1", "/x", true},
		{"", "", "", false},
		{"/only/a/path", "", "", false},
		{"*.", "", "", false},
	}
	for _, c := range cases {
		host, prefix, ok := ParseRule(c.key)
		if host != c.host || prefix != c.prefix || ok != c.ok {
			t.Errorf("ParseRule(%q) = %q, %q, %t; want %q, %q, %t", c.key, host, prefix, ok, c.host, c.prefix, c.ok)
		}
	}
	for in, want := range map[string]string{
		"https://deb.debian.org/debian/":         "deb.debian.org/debian",
		"https://registry.npmjs.org":             "registry.npmjs.org",
		"https://repo1.maven.org/maven2":         "repo1.maven.org/maven2",
		"http://mirror.local:8080/a/b":           "mirror.local/a/b",
		"":                                       "",
		"https://conda.anaconda.org/conda-forge": "conda.anaconda.org/conda-forge",
	} {
		if got := RuleOf(in); got != want {
			t.Errorf("RuleOf(%q) = %q, want %q", in, got, want)
		}
	}
}
