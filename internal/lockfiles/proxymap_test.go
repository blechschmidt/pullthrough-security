package lockfiles

import (
	"strings"
	"testing"
)

func TestMapURL(t *testing.T) {
	p := &Proxy{
		PublicURLs: []string{"https://proxy.example.com", "https://gw.example.com/pt/"},
		LinkPrefix: "/u",
		Upstreams: map[string]ProxyUpstream{
			"npm": {Type: "npm", URL: "https://user:pw@registry.npmjs.org/"},
		},
	}
	tok := testToken
	cases := []struct {
		in, url, upstream, upstreamURL string
	}{
		// Personal links under the public URL: the segment after the prefix
		// is a token whatever it looks like.
		{"https://proxy.example.com/u/" + tok + "/v1/npm/lodash/-/lodash-4.17.21.tgz", "https://proxy.example.com/v1/npm/lodash/-/lodash-4.17.21.tgz", "npm", "https://registry.npmjs.org/"},
		{"https://proxy.example.com/u/mistyped-token/v1/npm/x", "https://proxy.example.com/v1/npm/x", "npm", "https://registry.npmjs.org/"},
		// A public URL with a base path.
		{"https://gw.example.com/pt/u/" + tok + "/v1/npm/x", "https://gw.example.com/pt/v1/npm/x", "npm", "https://registry.npmjs.org/"},
		{"https://gw.example.com/pt/v1/npm", "https://gw.example.com/pt/v1/npm", "npm", "https://registry.npmjs.org/"},
		// The plain mount.
		{"https://proxy.example.com/v1/other/a?b=c#d", "https://proxy.example.com/v1/other/a", "other", ""},
		// A personal link on a host the configuration does not name: only a
		// token-shaped segment counts; the part before the prefix is the base.
		// Such a host may be another deployment: its upstreams are not this
		// configuration's.
		{"https://cache.example/base/u/" + tok + "/v1/npm/x", "https://cache.example/base/v1/npm/x", "npm", ""},
		// Not token-shaped: not taken for a link, but redacted all the same
		// (a mistyped token is still most of a token).
		{"https://cache.example/u/not-a-token/v1/npm/x", "https://cache.example/u/<link>/v1/npm/x", "", ""},
		// Interception: the links sit on the upstream host, and stay there; the
		// configured upstream is credited only on its own host.
		{"https://registry.npmjs.org/_pullthrough/v1/npm/x", "https://registry.npmjs.org/_pullthrough/v1/npm/x", "npm", "https://registry.npmjs.org/"},
		{"https://evil.example/_pullthrough/v1/npm/lodash/-/lodash.tgz", "https://evil.example/_pullthrough/v1/npm/lodash/-/lodash.tgz", "npm", ""},
		// Not the proxy: kept, minus credentials, query and fragment.
		{"https://user:secret@registry.npmjs.org/lodash/-/lodash.tgz?token=abc#frag", "https://registry.npmjs.org/lodash/-/lodash.tgz", "", ""},
		{"https://registry.npmjs.org/v1/npm/x", "https://registry.npmjs.org/v1/npm/x", "", ""},
		// Escaping is kept on a URL the mapping does not change.
		{"https://npm.example.com/@types%2fnode/-/node-1.tgz", "https://npm.example.com/@types%2fnode/-/node-1.tgz", "", ""},
	}
	for _, c := range cases {
		m, ok := p.mapURL(c.in)
		if !ok || m.url != c.url || m.upstream != c.upstream || m.upstreamURL != c.upstreamURL {
			t.Errorf("mapURL(%q) = %+v, %v; want url %q upstream %q upstreamURL %q", c.in, m, ok, c.url, c.upstream, c.upstreamURL)
		}
	}
	if m, ok := p.mapURL("git+ssh://git@github.com/o/r.git"); ok || strings.Contains(m.url, "ptl1") {
		t.Errorf("non-http URL: %+v %v", m, ok)
	}
}

func TestMapURLWithoutConfiguration(t *testing.T) {
	var p *Proxy
	m, ok := p.mapURL("https://proxy.example.com/u/" + testToken + "/v1/pypi/simple")
	if !ok || m.upstream != "pypi" || m.url != "https://proxy.example.com/v1/pypi/simple" || strings.Contains(m.url, "ptl1") {
		t.Errorf("personal link without configuration: %+v", m)
	}
	if m, _ := p.mapURL("https://proxy.example.com/v1/pypi/simple"); m.upstream != "" {
		t.Errorf("the plain mount on an unconfigured host was taken for the proxy: %+v", m)
	}
}

func TestRedactText(t *testing.T) {
	in := "fetch https://bob:hunter2@proxy.example.com/u/" + testToken + "/v1/npm/x and /u/strange-token/v1/pypi and ssh://git@github.com/o/r and ssh://u:pw@h/x"
	out := redactText(in, "/u")
	for _, secret := range []string{"hunter2", "bob", testToken, "ptl1", "strange-token", "pw@"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q survived: %s", secret, out)
		}
	}
	for _, kept := range []string{"https://proxy.example.com/u/<link>/v1/npm/x", "/u/<link>/v1/pypi", "ssh://git@github.com/o/r", "ssh://h/x"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q missing from %s", kept, out)
		}
	}
	if got := redactText("/custom/abc/v1/x", "/custom"); got != "/custom/<link>/v1/x" {
		t.Errorf("custom prefix: %s", got)
	}
	if got := RedactText("plain text"); got != "plain text" {
		t.Errorf("plain text changed: %s", got)
	}
}

func TestCleanURL(t *testing.T) {
	cases := map[string]string{
		"https://u:p@h.example/a/" + testToken + "/b?x=1#y": "https://h.example/a/ptl1/b",
		"https://h.example/simple":                          "https://h.example/simple",
		"  https://h.example/x  ":                           "https://h.example/x",
	}
	for in, want := range cases {
		if got := cleanURL(in); got != want {
			t.Errorf("cleanURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFinishImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	p := &Proxy{
		PublicURLs:      []string{"https://proxy.example.com"},
		Upstreams:       map[string]ProxyUpstream{"hub": {Type: "docker", URL: "https://registry-1.docker.io"}},
		RegistryDefault: "hub",
	}
	cases := []struct {
		ref, name, upstream, registry string
	}{
		{"proxy.example.com/u/" + testToken + "/hub/library/alpine@" + digest, "library/alpine", "hub", "https://registry-1.docker.io"},
		{"proxy.example.com/hub/library/alpine@" + digest, "library/alpine", "hub", "https://registry-1.docker.io"},
		// Registry-mirror mode: no upstream prefix, the default upstream.
		{"proxy.example.com/library/alpine@" + digest, "library/alpine", "hub", "https://registry-1.docker.io"},
		{"elsewhere.example/u/" + testToken + "/x/y@" + digest, "y", "x", "https://elsewhere.example"},
		{"ghcr.io/o/r@" + digest, "o/r", "", "https://ghcr.io"},
		{"ghcr.io/u/notatoken/r@" + digest, "u/notatoken/r", "", "https://ghcr.io"},
	}
	for _, c := range cases {
		res := &Result{}
		d, ok := imageDependency(res, c.ref, 1)
		if !ok {
			t.Fatalf("%s: %v", c.ref, res.Warnings)
		}
		p.finishImage(&d)
		if d.Name != c.name || d.Upstream != c.upstream || d.Registry != c.registry {
			t.Errorf("%s: name %q upstream %q registry %q; want %q %q %q", c.ref, d.Name, d.Upstream, d.Registry, c.name, c.upstream, c.registry)
		}
		if strings.Contains(d.Name+d.Registry, "ptl1") {
			t.Errorf("%s: the token survived: %+v", c.ref, d)
		}
	}
}

func TestRedactTextUserinfoWithQuotes(t *testing.T) {
	out := redactText("https://user:pa'ss@host.example/x", "/u")
	if strings.Contains(out, "pa'ss") || strings.Contains(out, "user") {
		t.Errorf("credentials survived: %s", out)
	}
	if got := cleanIfURL("https://u:p@h.example/foo-1.0.0.tgz?access_token=SECRET#x"); got != "https://h.example/foo-1.0.0.tgz" {
		t.Errorf("cleanIfURL = %q", got)
	}
	if got := cleanIfURL("1.2.3-beta"); got != "1.2.3-beta" {
		t.Errorf("a plain version changed: %q", got)
	}
}
