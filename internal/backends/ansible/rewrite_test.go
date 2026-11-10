package ansible

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"
)

const (
	testUpstream   = "https://galaxy.ansible.com"
	testPublicBase = "https://proxy.example.com/v1/ansible"
	testMountPath  = "/v1/ansible"
)

// testRewriter builds a linkRewriter the way New does: a configured public base
// is used as given, an empty one falls back to the root-relative mount path.
func testRewriter(t *testing.T, upstreamURL, publicBase string) *linkRewriter {
	t.Helper()
	base, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream %q: %v", upstreamURL, err)
	}
	if publicBase == "" {
		publicBase = testMountPath
	}
	return newLinkRewriter(base, publicBase)
}

// --- single values ----------------------------------------------------------

// A root-relative link keeps its shape and gains the mount's path, whether or
// not the proxy knows its public URL: the client resolves it against the proxy
// host it is already talking to.
func TestRewriteValueRootRelativeLink(t *testing.T) {
	links := []struct{ in, want string }{
		{
			"/api/v3/plugin/ansible/content/published/collections/index/community/general/",
			"/v1/ansible/api/v3/plugin/ansible/content/published/collections/index/community/general/",
		},
		{ // the pulp distribution-scoped form Galaxy uses for href / versions_url
			"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/14.0.1/",
			"/v1/ansible/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/14.0.1/",
		},
		{"/api/pulp/api/v3/repositories/ansible/ansible/4927dbd1/versions/52708/", "/v1/ansible/api/pulp/api/v3/repositories/ansible/ansible/4927dbd1/versions/52708/"},
		{"/api/v1/roles/", "/v1/ansible/api/v1/roles/"},
		{"/api/", "/v1/ansible/api/"},
	}
	for _, publicBase := range []string{testPublicBase, ""} {
		lr := testRewriter(t, testUpstream, publicBase)
		for _, c := range links {
			got, ok := lr.rewriteValue(c.in)
			if !ok || got != c.want {
				t.Errorf("publicBase=%q rewriteValue(%q) = %q, %v; want %q", publicBase, c.in, got, ok, c.want)
			}
		}
	}
}

// Pagination links carry a query string, which must survive byte-for-byte.
func TestRewriteValuePaginationLinkKeepsQuery(t *testing.T) {
	const versions = "/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/"
	cases := []struct{ in, want string }{
		{versions + "?limit=10&offset=10", testMountPath + versions + "?limit=10&offset=10"},
		{versions + "?limit=100&offset=200", testMountPath + versions + "?limit=100&offset=200"},
		{
			"/api/v3/plugin/ansible/search/collection-versions/?limit=1&name=general&namespace=community&offset=247",
			"/v1/ansible/api/v3/plugin/ansible/search/collection-versions/?limit=1&name=general&namespace=community&offset=247",
		},
		{"/api/v1/roles/?page=2&page_size=50", "/v1/ansible/api/v1/roles/?page=2&page_size=50"},
		{"/api/v1/search/roles/?tags=a%2Bb&q=x%20y#frag", "/v1/ansible/api/v1/search/roles/?tags=a%2Bb&q=x%20y#frag"},
	}
	for _, publicBase := range []string{testPublicBase, ""} {
		lr := testRewriter(t, testUpstream, publicBase)
		for _, c := range cases {
			got, ok := lr.rewriteValue(c.in)
			if !ok || got != c.want {
				t.Errorf("publicBase=%q rewriteValue(%q) = %q, %v; want %q", publicBase, c.in, got, ok, c.want)
			}
		}
	}
}

// An absolute upstream URL becomes absolute at the public base, exactly as
// before; without a public base it falls back to the root-relative mount path.
func TestRewriteValueAbsoluteUpstreamURL(t *testing.T) {
	const artifact = "/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz"
	cases := []struct{ in, rest string }{
		{testUpstream + artifact, artifact},
		{testUpstream + "/api/pulp/api/v3/content/ansible/namespaces/018d1a01/avatar/", "/api/pulp/api/v3/content/ansible/namespaces/018d1a01/avatar/"},
		{testUpstream + "/api/v1/roles/?page=2&page_size=2", "/api/v1/roles/?page=2&page_size=2"},
		// Not under /api/: an absolute URL is unambiguously a link, so the whole
		// upstream origin is mapped, as it always was.
		{testUpstream + "/ui/repo/published/community/general/", "/ui/repo/published/community/general/"},
		{testUpstream, ""},
		{testUpstream + "/", "/"},
		// Galaxy really emits http:// self-links (a v1 "next") from behind its TLS
		// terminator; they address the same registry.
		{"http://galaxy.ansible.com/api/v1/roles/?page=2&page_size=2", "/api/v1/roles/?page=2&page_size=2"},
		{"HTTPS://Galaxy.Ansible.COM/api/v3/", "/api/v3/"},
		{"https://galaxy.ansible.com:443/api/v3/", "/api/v3/"},
	}
	for _, publicBase := range []string{testPublicBase, ""} {
		lr := testRewriter(t, testUpstream, publicBase)
		wantBase := publicBase
		if wantBase == "" {
			wantBase = testMountPath
		}
		for _, c := range cases {
			got, ok := lr.rewriteValue(c.in)
			if want := wantBase + c.rest; !ok || got != want {
				t.Errorf("publicBase=%q rewriteValue(%q) = %q, %v; want %q", publicBase, c.in, got, ok, want)
			}
		}
	}
}

// Only links into the upstream tree are rewritten — never a string that merely
// starts with "/" or with the upstream's URL.
func TestRewriteValueLeavesNonLinksAlone(t *testing.T) {
	lr := testRewriter(t, testUpstream, testPublicBase)
	for _, s := range []string{
		"",
		"/",
		"/usr/local/bin/ansible",
		"/etc/ansible/ansible.cfg",
		"/ is the filesystem root",
		"/api",                            // no trailing slash: not inside the tree
		"/apiary/v3/",                     // a different first segment
		"/api/v3/ is where the API lives", // prose that starts like a link
		"/api/v3/collections/\tcommunity", // control character
		"/api/v3/collections/\ncommunity", // newline
		"/api/v3\\collections\\",          // backslashes
		"/api/../admin/api/cache",         // dot segments would leave the mount
		"/api/v3/./collections/",
		"/api/%2e%2e/admin/",           // encoded dot segment
		"/api/%2E%2E%2Fadmin/",         // encoded dot segment and separator
		"/api/v3/100%/",                // malformed escape
		"//galaxy.ansible.com/api/v3/", // protocol-relative, not a path
		"api/v3/collections/",          // path-relative
		"v3/",                          // the API root's "available_versions"
		"./x",
		"community.general",
		"8.0.0",
		">=2.13.0",
		"prn:ansible.ansiblerepository:4927dbd1",
		"see https://galaxy.ansible.com/api/v3/", // a URL inside prose
		"https://galaxy.ansible.com/ui/ is the web UI",
		"https://galaxy.ansible.com.evil.example/api/v3/", // look-alike host
		"https://evil.example/https://galaxy.ansible.com/api/v3/",
		"https://user@galaxy.ansible.com/api/v3/", // userinfo
		"https://galaxy.ansible.com:8443/api/v3/", // another port
		"https://galaxy.ansible.com/api/../admin/",
		"ftp://galaxy.ansible.com/api/v3/",
		"https://github.com/ansible-collections/community.general",
		"https://docs.ansible.com/ansible/latest/collections/community/general/",
		"https://ansible-galaxy-ng.s3.dualstack.us-east-1.amazonaws.com/artifact/74/db5d0b11",
	} {
		if got, ok := lr.rewriteValue(s); ok || got != s {
			t.Errorf("rewriteValue(%q) = %q, %v; want it untouched", s, got, ok)
		}
	}
}

// With an upstream served beneath a path, that path is the proxied tree: it is
// stripped when a link is mapped, and a root-relative link outside it is not a
// link into the mount at all (it resolves against the proxy host and fails
// there). An absolute upstream URL outside it has no faithful mapping either,
// but it is never left pointing straight at the upstream: it moves to the
// public base with its path intact, where it fails at the proxy instead of
// taking the client around it.
func TestRewriteValueUpstreamBasePath(t *testing.T) {
	lr := testRewriter(t, "https://hub.example.com/galaxy/", testPublicBase)
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/galaxy/api/v3/collections/?limit=10&offset=10", "/v1/ansible/api/v3/collections/?limit=10&offset=10", true},
		{"https://hub.example.com/galaxy/api/v3/artifacts/a-b-1.0.0.tar.gz", testPublicBase + "/api/v3/artifacts/a-b-1.0.0.tar.gz", true},
		{"https://hub.example.com/galaxy", testPublicBase, true},
		{"/api/v3/collections/", "", false}, // outside the upstream base path
		{"/galaxyish/api/v3/", "", false},   // shares only a string prefix
		// Same host, another tree: pulled onto the proxy, not left direct.
		{"https://hub.example.com/pulp/content/published/a-b-1.0.0.tar.gz", testPublicBase + "/pulp/content/published/a-b-1.0.0.tar.gz", true},
		{"https://hub.example.com/galaxyish/x?y=1", testPublicBase + "/galaxyish/x?y=1", true},
		{"https://hub.example.com", testPublicBase, true},
		{"https://hub.example.com/galaxy/../other/", "", false}, // dot segments: not a well-formed link
		{"https://hub.example.com/other/%2e%2e/x", "", false},
	}
	for _, c := range cases {
		got, ok := lr.rewriteValue(c.in)
		if ok != c.ok || (c.ok && got != c.want) || (!c.ok && got != c.in) {
			t.Errorf("rewriteValue(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}

	// An upstream URL that already ends at the API root exposes the tree below it.
	api := testRewriter(t, "https://galaxy.ansible.com/api", "")
	if got, ok := api.rewriteValue("/api/v3/plugin/x/?limit=10&offset=10"); !ok || got != "/v1/ansible/v3/plugin/x/?limit=10&offset=10" {
		t.Errorf("api-rooted upstream: got %q, %v", got, ok)
	}
}

// A public URL served beneath a path prefix contributes that prefix to
// root-relative links too.
func TestRewriteValuePublicBaseWithPathPrefix(t *testing.T) {
	lr := testRewriter(t, testUpstream, "https://proxy.example.com/pullthrough/v1/ansible")
	if got, _ := lr.rewriteValue("/api/v3/x/?offset=10"); got != "/pullthrough/v1/ansible/api/v3/x/?offset=10" {
		t.Errorf("root-relative = %q", got)
	}
	if got, _ := lr.rewriteValue(testUpstream + "/api/v3/x.tar.gz"); got != "https://proxy.example.com/pullthrough/v1/ansible/api/v3/x.tar.gz" {
		t.Errorf("absolute = %q", got)
	}
}

// --- whole documents --------------------------------------------------------

// Documents shaped after what galaxy.ansible.com really serves.
const (
	docCollection = `{"href":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/","namespace":"community","name":"general","deprecated":false,"versions_url":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/","highest_version":{"href":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/14.0.1/","version":"14.0.1"},"created_at":"2023-05-08T20:24:32.057064Z","updated_at":"2026-11-09T19:50:45.456021Z","download_count":284459819}`

	docVersions = `{"meta":{"count":248},"links":{"first":"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=10&offset=0","previous":null,"next":"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=10&offset=10","last":"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=10&offset=238"},"data":[{"version":"14.0.1","href":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/14.0.1/","created_at":"2026-11-09T19:50:45.269132Z","requires_ansible":">=2.19.0","marks":[]}]}`

	docVersionDetail = `{"version":"8.0.0","href":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/versions/8.0.0/","requires_ansible":">=2.13.0","artifact":{"filename":"community-general-8.0.0.tar.gz","sha256":"74db5d0b11a3ef62df32a3dfccea544972cd2e3d4891a01ec11987362ce1ebb4","size":2507962},"collection":{"id":"f90d6d7f-32c9-4b04-a9a2-c5e97853ce3f","name":"general","href":"/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/"},"download_url":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz","name":"general","namespace":{"name":"community","metadata_sha256":"7fb0389c"},"signatures":[],"metadata":{"authors":["Ansible (https://github.com/ansible)"],"dependencies":{"community.library_inventory_filtering_v1":">=1.0.0"},"description":"/api/v3 is not what this is about: the collection ships modules & plugins <for everyone>.","documentation":"https://docs.ansible.com/ansible/latest/collections/community/general/","homepage":"https://github.com/ansible-collections/community.general","tags":["community"]},"git_url":null,"files":{"files":[{"name":".","ftype":"dir"},{"name":"plugins/modules/api.py","ftype":"file"}],"format":1}}`

	docV1Root = `{"sync":"/api/v1/sync/","imports":"/api/v1/imports/","roles":"/api/v1/roles/","users":"/api/v1/users/","namespaces":"/api/v1/namespaces/"}`

	docV1Roles = `{"count":37895,"next":"http://galaxy.ansible.com/api/v1/roles/?page=2&page_size=2","next_link":"/api/v1/roles/?page=2&page_size=2","previous":null,"previous_link":null,"results":[{"id":10923,"github_user":"geerlingguy","description":"Docker for Linux.","summary_fields":{"namespace":{"id":2492,"avatar_url":"https://galaxy.ansible.com/api/pulp/api/v3/content/ansible/namespaces/018d1a01/avatar/"},"provider_namespace":{"id":103,"pulp_href":"/api/pulp/api/v3/pulp_ansible/namespaces/103/"}},"download_url":"https://github.com/geerlingguy/ansible-role-docker/archive/1.0.0.tar.gz"}]}`
)

func decodeDoc(t *testing.T, body []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("served document is not JSON: %v\n%s", err, body)
	}
	return m
}

// at walks a decoded document along object keys (strings) and array indexes
// (ints).
func at(t *testing.T, node any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("at %v: not an object at %q", path, k)
			}
			node = m[k]
		case int:
			a, ok := node.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("at %v: no element %d", path, k)
			}
			node = a[k]
		}
	}
	return node
}

func TestRewriteDocumentGalaxyShapes(t *testing.T) {
	const index = "/api/content/published/v3/plugin/ansible/content/published/collections/index/community/general/"
	const page = "/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/"
	const artifact = "/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz"

	for _, tc := range []struct {
		name       string
		publicBase string
		absolute   string // what an absolute upstream URL is re-anchored at
	}{
		{"public base configured", testPublicBase, testPublicBase},
		{"no public base", "", testMountPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lr := testRewriter(t, testUpstream, tc.publicBase)
			rewrite := func(doc string) map[string]any {
				t.Helper()
				out, changed := lr.rewriteDocument([]byte(doc))
				if !changed {
					t.Fatalf("document was not rewritten: %s", doc)
				}
				return decodeDoc(t, out)
			}
			check := func(doc map[string]any, want any, path ...any) {
				t.Helper()
				if got := at(t, doc, path...); got != want {
					t.Errorf("%v = %v, want %v", path, got, want)
				}
			}

			coll := rewrite(docCollection)
			check(coll, testMountPath+index, "href")
			check(coll, testMountPath+index+"versions/", "versions_url")
			check(coll, testMountPath+index+"versions/14.0.1/", "highest_version", "href")
			check(coll, "community", "namespace")
			check(coll, "14.0.1", "highest_version", "version")
			check(coll, json.Number("284459819"), "download_count")

			vers := rewrite(docVersions)
			check(vers, testMountPath+page+"?limit=10&offset=0", "links", "first")
			check(vers, testMountPath+page+"?limit=10&offset=10", "links", "next")
			check(vers, testMountPath+page+"?limit=10&offset=238", "links", "last")
			check(vers, nil, "links", "previous")
			check(vers, testMountPath+index+"versions/14.0.1/", "data", 0, "href")
			check(vers, ">=2.19.0", "data", 0, "requires_ansible")

			detail := rewrite(docVersionDetail)
			check(detail, testMountPath+index+"versions/8.0.0/", "href")
			check(detail, testMountPath+index, "collection", "href")
			check(detail, tc.absolute+artifact, "download_url")
			check(detail, "74db5d0b11a3ef62df32a3dfccea544972cd2e3d4891a01ec11987362ce1ebb4", "artifact", "sha256")
			check(detail, json.Number("2507962"), "artifact", "size")
			check(detail, "/api/v3 is not what this is about: the collection ships modules & plugins <for everyone>.", "metadata", "description")
			check(detail, "https://docs.ansible.com/ansible/latest/collections/community/general/", "metadata", "documentation")
			check(detail, "https://github.com/ansible-collections/community.general", "metadata", "homepage")
			check(detail, "Ansible (https://github.com/ansible)", "metadata", "authors", 0)
			check(detail, ">=1.0.0", "metadata", "dependencies", "community.library_inventory_filtering_v1")
			check(detail, "plugins/modules/api.py", "files", "files", 1, "name")

			root := rewrite(docV1Root)
			for _, k := range []string{"sync", "imports", "roles", "users", "namespaces"} {
				check(root, testMountPath+"/api/v1/"+k+"/", k)
			}

			roles := rewrite(docV1Roles)
			check(roles, tc.absolute+"/api/v1/roles/?page=2&page_size=2", "next")
			check(roles, testMountPath+"/api/v1/roles/?page=2&page_size=2", "next_link")
			check(roles, tc.absolute+"/api/pulp/api/v3/content/ansible/namespaces/018d1a01/avatar/", "results", 0, "summary_fields", "namespace", "avatar_url")
			check(roles, testMountPath+"/api/pulp/api/v3/pulp_ansible/namespaces/103/", "results", 0, "summary_fields", "provider_namespace", "pulp_href")
			check(roles, "https://github.com/geerlingguy/ansible-role-docker/archive/1.0.0.tar.gz", "results", 0, "download_url")
			check(roles, "Docker for Linux.", "results", 0, "description")
		})
	}
}

// The absolute-URL rewrite the backend has always done is unchanged: an
// upstream URL moves to the public base with its path and query intact, and a
// relative reference that is not a link into the API tree is left alone.
func TestRewriteDocumentAbsoluteURLsAsBefore(t *testing.T) {
	lr := testRewriter(t, testUpstream, testPublicBase)
	body := []byte(`{"download_url":"https://galaxy.ansible.com/api/v3/.../community-general-8.0.0.tar.gz","rel":"./x","n":{"href":"https://galaxy.ansible.com/api/v3/next?page=2"}}`)
	out, changed := lr.rewriteDocument(body)
	if !changed {
		t.Fatal("expected rewrite")
	}
	doc := decodeDoc(t, out)
	if got, want := at(t, doc, "download_url"), testPublicBase+"/api/v3/.../community-general-8.0.0.tar.gz"; got != want {
		t.Errorf("download_url = %v, want %v", got, want)
	}
	if got, want := at(t, doc, "n", "href"), testPublicBase+"/api/v3/next?page=2"; got != want {
		t.Errorf("n.href = %v, want %v", got, want)
	}
	if got := at(t, doc, "rel"); got != "./x" {
		t.Errorf("relative link must be untouched, got %v", got)
	}
}

// Rewriting must not disturb anything but the links: numbers keep their exact
// spelling, markup is not escaped, object keys are never treated as values.
func TestRewriteDocumentPreservesEverythingElse(t *testing.T) {
	lr := testRewriter(t, testUpstream, testPublicBase)
	in := `{"href":"/api/v3/x/","big":12345678901234567890,"float":1.0,"exp":1e21,"neg":-0.5,` +
		`"html":"<a href=\"/api/v3/\">R&D</a>","/api/v3/key/":"value","nested":[["/api/v3/y/"],{"k":"/tmp/x"}],` +
		`"t":true,"n":null,"empty":"","unicode":"café ☃"}`
	out, changed := lr.rewriteDocument([]byte(in))
	if !changed {
		t.Fatal("expected a rewrite")
	}
	for _, want := range []string{
		`"href":"/v1/ansible/api/v3/x/"`,
		`"big":12345678901234567890`,
		`"float":1.0`,
		`"exp":1e21`,
		`"neg":-0.5`,
		`"html":"<a href=\"/api/v3/\">R&D</a>"`, // prose containing a link is not a link
		`"/api/v3/key/":"value"`,                // an object key is never rewritten
		`"nested":[["/v1/ansible/api/v3/y/"],{"k":"/tmp/x"}]`,
		`"t":true`, `"n":null`, `"empty":""`, `"unicode":"café ☃"`,
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("rewritten document lacks %s\n%s", want, out)
		}
	}
	if bytes.HasSuffix(out, []byte("\n")) {
		t.Error("rewritten document gained a trailing newline")
	}

	// Rewriting is idempotent: a served document holds no upstream link.
	if again, changed := lr.rewriteDocument(out); changed || !bytes.Equal(again, out) {
		t.Errorf("second rewrite changed the document:\n%s", again)
	}
}

func TestRewriteDocumentUnchanged(t *testing.T) {
	lr := testRewriter(t, testUpstream, testPublicBase)
	for _, body := range []string{
		`{"available_versions":{"v3":"v3/","v1":"v1/"}}`, // the API root: relative, client-joined
		`{"a":"./b","description":"/usr/bin/env python","homepage":"https://github.com/x/y"}`,
		`{ "spaced" : [ 1, 2 ] }`,
		`"just a string"`,
		`[]`,
		`not json`,
		`<!doctype html><a href="/api/v3/">x</a>`,
		`{"href":"/api/v3/x/"} trailing`,             // not a single JSON value
		`{"href":"/api/v3/x/"}{"href":"/api/v3/y/"}`, // a JSON stream
		`{"href":"/api/v3/x/"`,                       // truncated
		``,
	} {
		out, changed := lr.rewriteDocument([]byte(body))
		if changed || string(out) != body {
			t.Errorf("rewriteDocument(%q) = %q, changed=%v; want it byte-for-byte", body, out, changed)
		}
	}

	// A bare top-level link is still a link.
	if out, changed := lr.rewriteDocument([]byte(`"/api/v3/x/"`)); !changed || string(out) != `"/v1/ansible/api/v3/x/"` {
		t.Errorf("top-level link = %q, changed=%v", out, changed)
	}
}

// --- redirects --------------------------------------------------------------

func TestLocation(t *testing.T) {
	const req = "https://galaxy.ansible.com/api/v3/collections/community/general/versions/?limit=100"
	const canonical = "/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/"

	cases := []struct {
		name     string
		location string
		want     string // with a public base configured
		wantBare string // without one
		ok       bool
	}{
		{"root-relative, as Galaxy answers", canonical + "?limit=100", testMountPath + canonical + "?limit=100", testMountPath + canonical + "?limit=100", true},
		{"trailing-slash redirect", "/api/", "/v1/ansible/api/", "/v1/ansible/api/", true},
		{"absolute at the upstream", testUpstream + "/api/pulp/content/published/x.tar.gz?expires=1&validate_token=a:b", testPublicBase + "/api/pulp/content/published/x.tar.gz?expires=1&validate_token=a:b", testMountPath + "/api/pulp/content/published/x.tar.gz?expires=1&validate_token=a:b", true},
		{"absolute, http self-link", "http://galaxy.ansible.com/api/v3/", testPublicBase + "/api/v3/", testMountPath + "/api/v3/", true},
		{"absolute, explicit default port", "https://galaxy.ansible.com:443/api/v3/", testPublicBase + "/api/v3/", testMountPath + "/api/v3/", true},
		{"protocol-relative at the upstream", "//galaxy.ansible.com/api/v3/", testPublicBase + "/api/v3/", testMountPath + "/api/v3/", true},
		{"upstream root", testUpstream, testPublicBase, testMountPath, true},
		{"outside /api but inside the registry", "/pulp/content/published/x.tar.gz", "/v1/ansible/pulp/content/published/x.tar.gz", "/v1/ansible/pulp/content/published/x.tar.gz", true},
		{"path-relative", "8.0.0/", "/v1/ansible/api/v3/collections/community/general/versions/8.0.0/", "/v1/ansible/api/v3/collections/community/general/versions/8.0.0/", true},
		{"path-relative, parent", "../", "/v1/ansible/api/v3/collections/community/general/", "/v1/ansible/api/v3/collections/community/general/", true},
		{"query only", "?limit=100&offset=100", "/v1/ansible/api/v3/collections/community/general/versions/?limit=100&offset=100", "/v1/ansible/api/v3/collections/community/general/versions/?limit=100&offset=100", true},
		{"fragment kept", "/api/v3/#top", "/v1/ansible/api/v3/#top", "/v1/ansible/api/v3/#top", true},
		{"dot segments resolved inside the tree", "/api/v3/../v1/roles/", "/v1/ansible/api/v1/roles/", "/v1/ansible/api/v1/roles/", true},
		{"surrounding space trimmed", "  /api/  ", "/v1/ansible/api/", "/v1/ansible/api/", true},

		{"another host (object storage)", "https://ansible-galaxy-ng.s3.dualstack.us-east-1.amazonaws.com/artifact/74/db5d?X-Amz-Signature=x", "", "", false},
		{"look-alike host", "https://galaxy.ansible.com.evil.example/api/", "", "", false},
		{"protocol-relative elsewhere", "//evil.example/api/v3/", "", "", false},
		{"another port", "https://galaxy.ansible.com:8443/api/", "", "", false},
		{"userinfo", "https://user:pw@galaxy.ansible.com/api/", "", "", false},
		{"other scheme", "ftp://galaxy.ansible.com/api/", "", "", false},
		{"javascript", "javascript:alert(1)", "", "", false},
		{"opaque", "mailto:root@galaxy.ansible.com", "", "", false},
		{"encoded dot segments", "/api/%2e%2e/%2e%2e/admin/api/cache", "", "", false},
		{"encoded separator", "/api/..%2f..%2fadmin/", "", "", false},
		{"backslash", "/api/..\\..\\admin/", "", "", false},
		{"header injection", "/api/\r\nSet-Cookie: x=1", "", "", false},
		{"embedded space", "/api/v3/ x", "", "", false},
		{"malformed escape", "/api/%zz/", "", "", false},
		{"empty", "", "", "", false},
		{"blank", "   ", "", "", false},
	}

	configured := testRewriter(t, testUpstream, testPublicBase)
	bare := testRewriter(t, testUpstream, "")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, ok := configured.location(req, c.location); ok != c.ok || got != c.want {
				t.Errorf("public base: location(%q) = %q, %v; want %q, %v", c.location, got, ok, c.want, c.ok)
			}
			if got, ok := bare.location(req, c.location); ok != c.ok || got != c.wantBare {
				t.Errorf("no public base: location(%q) = %q, %v; want %q, %v", c.location, got, ok, c.wantBare, c.ok)
			}
		})
	}
}

// A redirect that climbs above the upstream root is clamped there by reference
// resolution, so it still lands inside the mount.
func TestLocationCannotClimbOutOfTheMount(t *testing.T) {
	lr := testRewriter(t, testUpstream, testPublicBase)
	got, ok := lr.location("https://galaxy.ansible.com/api/v3/", "../../../../admin/api/cache")
	if !ok || got != "/v1/ansible/admin/api/cache" {
		t.Errorf("location = %q, %v; want it clamped inside the mount", got, ok)
	}
}

func TestLocationUpstreamBasePath(t *testing.T) {
	lr := testRewriter(t, "https://hub.example.com/galaxy", testPublicBase)
	const req = "https://hub.example.com/galaxy/api/v3/collections/a/b/"
	cases := []struct {
		location, want string
		ok             bool
	}{
		{"/galaxy/api/v3/plugin/x/", "/v1/ansible/api/v3/plugin/x/", true},
		{"https://hub.example.com/galaxy/api/v3/plugin/x/", testPublicBase + "/api/v3/plugin/x/", true},
		{"/galaxy", "/v1/ansible", true},
		{"../../../../../", "/v1/ansible/", true},        // resolves to the base path itself
		{"/api/v3/plugin/x/", "", false},                 // outside the upstream base path
		{"/galaxy-admin/", "", false},                    // shares only a string prefix
		{"../../../../../../login", "", false},           // climbs above the base path
		{"https://hub.example.com/sso/login", "", false}, // same host, another tree
	}
	for _, c := range cases {
		if got, ok := lr.location(req, c.location); ok != c.ok || got != c.want {
			t.Errorf("location(%q) = %q, %v; want %q, %v", c.location, got, ok, c.want, c.ok)
		}
	}

	if _, ok := lr.location("://not a url", "/galaxy/api/"); ok {
		t.Error("an unparseable request URL must not yield a location")
	}
}

func TestMountPathOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://proxy.example.com/v1/ansible":             "/v1/ansible",
		"https://proxy.example.com/pullthrough/v1/ansible": "/pullthrough/v1/ansible",
		"http://127.0.0.1:18514/v1/ansible":                "/v1/ansible",
		"/v1/ansible":                                      "/v1/ansible",
		"https://ansible.proxy.example.com":                "",
	} {
		if got := mountPathOf(in); got != want {
			t.Errorf("mountPathOf(%q) = %q, want %q", in, got, want)
		}
	}
}
