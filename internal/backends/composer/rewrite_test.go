package composer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const testPublicBase = "https://proxy.example.com/v1/packagist"

// offlineBackend builds a backend for the rewrite tests, which never touch the
// network. An empty publicBase exercises the no-public-base fallback.
func offlineBackend(t *testing.T, upstreamURL, publicBase string) *Backend {
	t.Helper()
	b, err := New(Options{
		Name:          "packagist",
		UpstreamURL:   upstreamURL,
		PublicBaseURL: publicBase,
		Client:        upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
	return obj
}

// clientVersions returns a package's versions the way a Composer client sees
// them: decoded and, for a minified document, expanded. It deliberately
// re-implements Composer's MetadataMinifier::expand (first object verbatim, then
// each delta applied on top, "__unset" removing a key) instead of calling the
// production parser, so the rewrite is checked against the client's algorithm
// rather than against itself.
func clientVersions(t *testing.T, doc []byte, name string) []map[string]any {
	t.Helper()
	var top struct {
		Minified any                        `json:"minified"`
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(doc, &top); err != nil {
		t.Fatalf("decoding document: %v", err)
	}
	var versions []map[string]any
	if err := json.Unmarshal(top.Packages[name], &versions); err != nil {
		t.Fatalf("decoding versions of %s: %v", name, err)
	}
	if top.Minified != "composer/2.0" {
		return versions
	}
	clone := func(m map[string]any) map[string]any {
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	var (
		out      []map[string]any
		expanded map[string]any
	)
	for _, delta := range versions {
		if len(expanded) == 0 {
			expanded = clone(delta)
			out = append(out, clone(expanded))
			continue
		}
		for k, v := range delta {
			if v == "__unset" {
				delete(expanded, k)
			} else {
				expanded[k] = v
			}
		}
		out = append(out, clone(expanded))
	}
	return out
}

func distOf(t *testing.T, version map[string]any) map[string]any {
	t.Helper()
	d, ok := version["dist"].(map[string]any)
	if !ok {
		t.Fatalf("version %v has no dist object: %v", version["version"], version["dist"])
	}
	return d
}

// assertOnlyDistURLsChanged checks that, as a client sees them, the rewritten
// versions equal the original ones in every field except dist.url.
func assertOnlyDistURLsChanged(t *testing.T, original, rewritten []byte, name string) {
	t.Helper()
	before := clientVersions(t, original, name)
	after := clientVersions(t, rewritten, name)
	if len(before) != len(after) {
		t.Fatalf("%s: %d versions before, %d after", name, len(before), len(after))
	}
	strip := func(v map[string]any) map[string]any {
		out := make(map[string]any, len(v))
		for k, val := range v {
			if d, ok := val.(map[string]any); ok && k == "dist" {
				dc := make(map[string]any, len(d))
				for dk, dv := range d {
					if dk != "url" {
						dc[dk] = dv
					}
				}
				val = dc
			}
			out[k] = val
		}
		return out
	}
	for i := range before {
		if !reflect.DeepEqual(strip(before[i]), strip(after[i])) {
			t.Errorf("%s version %d (%v) changed beyond dist.url:\n before %v\n after  %v",
				name, i, before[i]["version"], before[i], after[i])
		}
	}
}

// assertDistURLsResolve checks the property the whole design rests on: every
// dist URL the rewrite hands a client (a) lies under the public base, (b) parses
// back into a dist request naming that client-visible version, and (c) resolves,
// against the ORIGINAL upstream document, to exactly the upstream URL that
// version listed. It returns how many dist URLs it checked.
func assertDistURLsResolve(t *testing.T, b *Backend, original, rewritten []byte, name string) int {
	t.Helper()
	md, err := ParseMetadata(original)
	if err != nil {
		t.Fatalf("ParseMetadata(original): %v", err)
	}
	before := clientVersions(t, original, name)
	after := clientVersions(t, rewritten, name)
	checked := 0
	for i, v := range after {
		d, ok := v["dist"].(map[string]any)
		if !ok {
			continue
		}
		got, _ := d["url"].(string)
		if !strings.HasPrefix(got, b.publicBase+"/dist/") {
			continue // left as listed (not routable); asserted by the caller
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Errorf("rewritten dist URL %q does not parse: %v", got, err)
			continue
		}
		basePath := ""
		if pb, perr := url.Parse(b.publicBase); perr == nil {
			basePath = pb.Path
		}
		res, ok := classify(strings.TrimPrefix(u.Path, basePath))
		if !ok || res.kind != kindDist {
			t.Errorf("rewritten dist URL %q is not a dist request the backend routes", got)
			continue
		}
		if res.coordinateName() != name || res.version != v["version"] {
			t.Errorf("dist URL %q names %s@%s, but the client attributes it to %s@%v",
				got, res.coordinateName(), res.version, name, v["version"])
		}
		entry, found := md.FindDist(name, res.version, res.reference, res.ext)
		if !found {
			t.Errorf("dist URL %q does not resolve against the upstream document", got)
			continue
		}
		wantUpstream, _ := distOf(t, before[i])["url"].(string)
		if entry.Dist.URL != wantUpstream {
			t.Errorf("dist URL %q resolves to upstream %q, want %q", got, entry.Dist.URL, wantUpstream)
		}
		checked++
	}
	return checked
}

func TestRewriteRootPackagist(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	out, err := b.rewriteRoot([]byte(packagistRootFixture))
	if err != nil {
		t.Fatalf("rewriteRoot: %v", err)
	}
	root := decodeObject(t, out)

	// Package lookups come back through this backend's mount, as absolute URLs.
	wantStrings := map[string]string{
		"metadata-url":  testPublicBase + "/p2/%package%.json",
		"providers-url": testPublicBase + "/p/%package%$%hash%.json",
	}
	for key, want := range wantStrings {
		if got := root[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}

	// Nothing the backend does not front is advertised any more — above all not
	// the install-statistics endpoint.
	for _, key := range []string{"notify-batch", "notify", "search", "list", "providers-api", "metadata-changes-url", "mirrors"} {
		if v, present := root[key]; present {
			t.Errorf("%s must be removed, got %v", key, v)
		}
	}

	// Advisories: the POST API is gone, the in-metadata advisories stay, and the
	// repository is declared to (possibly) hold any package so Composer accepts an
	// advisory configuration without an API.
	if got, want := root["security-advisories"], map[string]any{"metadata": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("security-advisories = %v, want %v", got, want)
	}
	if got, want := root["available-package-patterns"], []any{"*"}; !reflect.DeepEqual(got, want) {
		t.Errorf("available-package-patterns = %v, want %v", got, want)
	}

	// Filter lists: the summary is served by the repository itself, so it is
	// routed through the mount; the rest of the object is untouched.
	wantFilter := map[string]any{
		"metadata":    true,
		"lists":       map[string]any{"malware": map[string]any{"enabled": true}},
		"summary-url": testPublicBase + "/lists/all/summary.json",
	}
	if got := root["filter"]; !reflect.DeepEqual(got, wantFilter) {
		t.Errorf("filter = %v, want %v", got, wantFilter)
	}

	// Plain data passes through unchanged.
	original := decodeObject(t, []byte(packagistRootFixture))
	for _, key := range []string{"packages", "providers", "warning", "warning-versions"} {
		if !reflect.DeepEqual(root[key], original[key]) {
			t.Errorf("%s changed: %v -> %v", key, original[key], root[key])
		}
	}

	// No Packagist host survives anywhere a client would act on. (The free-text
	// Composer 1 shutdown notice links to a blog post; it is not a lookup.)
	withoutWarning := decodeObject(t, out)
	delete(withoutWarning, "warning")
	rest, _ := json.Marshal(withoutWarning)
	if bytes.Contains(rest, []byte("packagist.org")) || bytes.Contains(rest, []byte("packagist.com")) {
		t.Errorf("rewritten root still points at a Packagist host:\n%s", rest)
	}

	// The summary URL the root now advertises must be one the backend serves.
	summary := wantFilter["summary-url"].(string)
	if res, ok := classify(strings.TrimPrefix(summary, testPublicBase)); !ok || res.kind != kindFilterList {
		t.Errorf("advertised summary URL %q is not routable", summary)
	}
}

// Without a public base the templates are root-relative under the mount, which
// Composer resolves against the repository's scheme and host. A root-relative
// dist.url is not something Composer downloads, so the root also advertises the
// dist endpoint as the preferred dist mirror.
func TestRewriteRootNoPublicBase(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", "")
	out, err := b.rewriteRoot([]byte(packagistRootFixture))
	if err != nil {
		t.Fatalf("rewriteRoot: %v", err)
	}
	root := decodeObject(t, out)

	if got, want := root["metadata-url"], "/v1/packagist/p2/%package%.json"; got != want {
		t.Errorf("metadata-url = %v, want %q", got, want)
	}
	if got, want := root["providers-url"], "/v1/packagist/p/%package%$%hash%.json"; got != want {
		t.Errorf("providers-url = %v, want %q", got, want)
	}
	filter, _ := root["filter"].(map[string]any)
	if got, want := filter["summary-url"], "/v1/packagist/lists/all/summary.json"; got != want {
		t.Errorf("filter.summary-url = %v, want %q", got, want)
	}
	wantMirrors := []any{map[string]any{
		"dist-url":  "/v1/packagist/dist/%package%/%prettyVersion%/%reference%.%type%",
		"preferred": true,
	}}
	if got := root["mirrors"]; !reflect.DeepEqual(got, wantMirrors) {
		t.Errorf("mirrors = %v, want %v", got, wantMirrors)
	}
	if _, present := root["notify-batch"]; present {
		t.Error("notify-batch must be removed in the fallback too")
	}
	if bytes.Contains(out, []byte("https://repo.packagist.org")) || bytes.Contains(out, []byte("https://packagist.org")) {
		t.Errorf("fallback root still points at the upstream:\n%s", out)
	}

	// With an absolute public base the dist URLs are directly downloadable and no
	// mirror is advertised.
	abs := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	absOut, err := abs.rewriteRoot([]byte(packagistRootFixture))
	if err != nil {
		t.Fatalf("rewriteRoot: %v", err)
	}
	if _, present := decodeObject(t, absOut)["mirrors"]; present {
		t.Error("an absolute public base needs no dist mirror")
	}
}

// The mirror template, expanded the way Composer expands it, is exactly the
// locator the metadata rewrite emits — so both name the same cache entry and the
// same coordinate.
func TestDistMirrorTemplateMatchesDistPath(t *testing.T) {
	cases := []struct{ version, reference string }{
		{"3.0.0", "fe5ea303b0887d5caefd3d431c3e61ad47037001"},
		{"v8.0.0-RC3", "307d3cf852f5"},
		{"dev-hotfix/composer-install", "aad26b2e26ba2e877e3f65cf3aa739c581b57967"},
		{"1.0.0", ""}, // Composer substitutes an empty %reference%
	}
	for _, c := range cases {
		expanded := strings.NewReplacer(
			"%package%", "vendor/pkg",
			"%prettyVersion%", c.version,
			"%reference%", c.reference,
			"%type%", "zip",
		).Replace(distMirrorTemplate)
		fromMirror, ok := classify(expanded)
		if !ok {
			t.Errorf("mirror expansion %q is not routable", expanded)
			continue
		}
		path, ok := distPath("vendor", "pkg", c.version, c.reference, "zip")
		if !ok {
			t.Fatalf("distPath(%q) not ok", c.version)
		}
		fromRewrite, ok := classify(path)
		if !ok {
			t.Fatalf("classify(%q) not ok", path)
		}
		if fromMirror != fromRewrite {
			t.Errorf("mirror expansion %q -> %+v, rewrite %q -> %+v", expanded, fromMirror, path, fromRewrite)
		}
	}
}

func TestRewriteRootVariants(t *testing.T) {
	b := offlineBackend(t, "https://repo.example.test/acme", testPublicBase)

	t.Run("upstream package list is respected", func(t *testing.T) {
		out, err := b.rewriteRoot([]byte(`{"metadata-url":"/acme/p2/%package%.json","available-packages":["acme/a","acme/b"],"security-advisories":{"metadata":true,"api-url":"https://repo.example.test/acme/api/security-advisories/"}}`))
		if err != nil {
			t.Fatalf("rewriteRoot: %v", err)
		}
		root := decodeObject(t, out)
		if _, present := root["available-package-patterns"]; present {
			t.Error("no match-everything pattern may be added when the upstream bounds its packages")
		}
		if got, want := root["available-packages"], []any{"acme/a", "acme/b"}; !reflect.DeepEqual(got, want) {
			t.Errorf("available-packages = %v", got)
		}
		if got, want := root["security-advisories"], map[string]any{"metadata": true}; !reflect.DeepEqual(got, want) {
			t.Errorf("security-advisories = %v", got)
		}
	})

	t.Run("advisories only reachable through the API are dropped", func(t *testing.T) {
		for _, doc := range []string{
			`{"metadata-url":"/acme/p2/%package%.json","security-advisories":{"metadata":false,"api-url":"https://repo.example.test/api/"}}`,
			`{"metadata-url":"/acme/p2/%package%.json","security-advisories":{"api-url":"https://repo.example.test/api/"}}`,
			`{"metadata-url":"/acme/p2/%package%.json","security-advisories":[]}`,
			`{"metadata-url":"/acme/p2/%package%.json","security-advisories":"yes"}`,
		} {
			out, err := b.rewriteRoot([]byte(doc))
			if err != nil {
				t.Fatalf("rewriteRoot(%s): %v", doc, err)
			}
			root := decodeObject(t, out)
			if v, present := root["security-advisories"]; present {
				t.Errorf("%s: security-advisories must be removed, got %v", doc, v)
			}
			if _, present := root["available-package-patterns"]; present {
				t.Errorf("%s: no pattern may be added when the advisories are dropped", doc)
			}
		}
	})

	t.Run("filter summary", func(t *testing.T) {
		cases := []struct {
			name, summary string
			want          any // nil: removed
		}{
			{"under the upstream base", "https://repo.example.test/acme/lists/all/summary.json", testPublicBase + "/lists/all/summary.json"},
			{"root-relative under the base", "/acme/lists/all/summary.json", testPublicBase + "/lists/all/summary.json"},
			{"query is kept", "https://repo.example.test/acme/lists/all/summary.json?v=2", testPublicBase + "/lists/all/summary.json?v=2"},
			{"another host", "https://lists.example.test/acme/lists/all/summary.json", nil},
			{"another scheme", "http://repo.example.test/acme/lists/all/summary.json", nil},
			{"outside the base path", "https://repo.example.test/other/lists/all/summary.json", nil},
			{"base path is only a string prefix", "https://repo.example.test/acmeX/lists/all/summary.json", nil},
			{"a path the backend does not route", "https://repo.example.test/acme/filter/summary.json", nil},
			{"traversal", "https://repo.example.test/acme/lists/../../secret.json", nil},
			{"protocol-relative", "//evil.example.test/acme/lists/all/summary.json", nil},
			{"empty", "", nil},
		}
		for _, c := range cases {
			doc, _ := json.Marshal(map[string]any{
				"metadata-url": "/acme/p2/%package%.json",
				"filter":       map[string]any{"metadata": true, "summary-url": c.summary, "api-url": "https://repo.example.test/acme/api/filter"},
			})
			out, err := b.rewriteRoot(doc)
			if err != nil {
				t.Fatalf("%s: rewriteRoot: %v", c.name, err)
			}
			filter, _ := decodeObject(t, out)["filter"].(map[string]any)
			if filter == nil {
				t.Fatalf("%s: filter object missing", c.name)
			}
			if _, present := filter["api-url"]; present {
				t.Errorf("%s: filter.api-url must be removed", c.name)
			}
			got, present := filter["summary-url"]
			if c.want == nil && present {
				t.Errorf("%s: summary-url must be removed, got %v", c.name, got)
			}
			if c.want != nil && got != c.want {
				t.Errorf("%s: summary-url = %v, want %v", c.name, got, c.want)
			}
			if filter["metadata"] != true {
				t.Errorf("%s: filter.metadata lost", c.name)
			}
		}
	})

	t.Run("lookup templates", func(t *testing.T) {
		out, err := b.rewriteRoot([]byte(`{"metadata-url":42,"providers-url":"","providers-lazy-url":"/acme/p/%package%.json","mirrors":[{"dist-url":"https://mirror.example.test/%package%/%reference%.%type%","preferred":true}],"notify":"/downloads/%package%"}`))
		if err != nil {
			t.Fatalf("rewriteRoot: %v", err)
		}
		root := decodeObject(t, out)
		for _, key := range []string{"metadata-url", "providers-url", "mirrors", "notify"} {
			if v, present := root[key]; present {
				t.Errorf("%s must be removed, got %v", key, v)
			}
		}
		if got, want := root["providers-lazy-url"], testPublicBase+"/p/%package%.json"; got != want {
			t.Errorf("providers-lazy-url = %v, want %q", got, want)
		}
	})

	t.Run("absent keys are not invented", func(t *testing.T) {
		out, err := b.rewriteRoot([]byte(`{"packages":{"acme/a":{"1.0.0":{"name":"acme/a","version":"1.0.0"}}},"includes":{"include/all$abc.json":{"sha1":"abc"}}}`))
		if err != nil {
			t.Fatalf("rewriteRoot: %v", err)
		}
		root := decodeObject(t, out)
		if len(root) != 2 {
			t.Errorf("root gained or lost keys: %v", root)
		}
	})

	t.Run("not an object", func(t *testing.T) {
		for _, doc := range []string{``, `null`, `[]`, `"x"`, `not json`, `{"metadata-url":`} {
			if out, err := b.rewriteRoot([]byte(doc)); err == nil {
				t.Errorf("rewriteRoot(%q) should fail, got %s", doc, out)
			}
		}
	})
}

// The minified encoding as real Packagist documents use it: a version that
// shares its predecessor's commit carries no "dist" and inherits it. Each such
// version must end up with a dist URL of its own, naming its own version.
func TestRewriteMetadataMinifiedInheritedDist(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	original := []byte(inheritedDistFixture)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}

	const name = "ralouphie/getallheaders"
	versions := clientVersions(t, out, name)
	if len(versions) != 4 {
		t.Fatalf("client sees %d versions, want 4", len(versions))
	}
	wantURLs := map[string]string{
		"dev-develop":                 testPublicBase + "/dist/ralouphie/getallheaders/dev-develop/120b605dfeb996808c31b6477290a714d356e822.zip",
		"dev-master":                  testPublicBase + "/dist/ralouphie/getallheaders/dev-master/120b605dfeb996808c31b6477290a714d356e822.zip",
		"dev-hotfix/composer-install": testPublicBase + "/dist/ralouphie/getallheaders/dev-hotfix/composer-install/aad26b2e26ba2e877e3f65cf3aa739c581b57967.zip",
	}
	for _, v := range versions {
		version, _ := v["version"].(string)
		want, hasDist := wantURLs[version]
		if !hasDist {
			if version != "dev-no-dist" {
				t.Errorf("unexpected version %q", version)
			}
			if d, present := v["dist"]; present {
				t.Errorf("%s: dist was unset upstream and must stay unset, got %v", version, d)
			}
			continue
		}
		if got := distOf(t, v)["url"]; got != want {
			t.Errorf("%s: dist.url = %v, want %q", version, got, want)
		}
	}

	assertOnlyDistURLsChanged(t, original, out, name)
	if n := assertDistURLsResolve(t, b, original, out, name); n != 3 {
		t.Errorf("checked %d dist URLs, want 3", n)
	}

	// The document stays minified, and keys the proxy does not model survive.
	top := decodeObject(t, out)
	if top["minified"] != "composer/2.0" {
		t.Errorf("minified marker = %v", top["minified"])
	}
	if !reflect.DeepEqual(top["security-advisories"], decodeObject(t, original)["security-advisories"]) {
		t.Errorf("security-advisories changed: %v", top["security-advisories"])
	}
	// Values are carried through verbatim, not HTML-escaped.
	if !bytes.Contains(out, []byte(`A polyfill for getallheaders <with> & 'specials'.`)) {
		t.Errorf("description was altered:\n%s", out)
	}
	if bytes.Contains(out, []byte("api.github.com")) {
		t.Errorf("an upstream dist URL survived the rewrite:\n%s", out)
	}
	// "source" describes the VCS origin, which this backend does not front.
	if !bytes.Contains(out, []byte("https://github.com/ralouphie/getallheaders.git")) {
		t.Errorf("source was altered:\n%s", out)
	}
}

func TestRewriteMetadataPlain(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	// Not minified: every object stands alone, so a version without a dist has
	// none — it must not be given its neighbour's.
	original := []byte(`{"packages":{"monolog/monolog":[
	  {"name":"monolog/monolog","version":"3.2.0","dist":{"type":"zip","url":"https://example.test/raw/monolog-3.2.0.zip","reference":"ref320","shasum":"0000000000000000000000000000000000000000"}},
	  {"name":"monolog/monolog","version":"3.1.5"},
	  {"name":"monolog/monolog","version":"3.1.0","dist":{"type":"zip","url":"https://example.test/raw/monolog-3.1.0.zip","reference":"ref310","shasum":""}}
	]}}`)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	versions := clientVersions(t, out, "monolog/monolog")
	if got, want := distOf(t, versions[0])["url"], testPublicBase+"/dist/monolog/monolog/3.2.0/ref320.zip"; got != want {
		t.Errorf("3.2.0 dist.url = %v, want %q", got, want)
	}
	if got := distOf(t, versions[0])["shasum"]; got != "0000000000000000000000000000000000000000" {
		t.Errorf("3.2.0 shasum = %v (the client verifies it; it must be kept)", got)
	}
	if d, present := versions[1]["dist"]; present {
		t.Errorf("3.1.5 has no dist upstream and must not gain one, got %v", d)
	}
	if got, want := distOf(t, versions[2])["url"], testPublicBase+"/dist/monolog/monolog/3.1.0/ref310.zip"; got != want {
		t.Errorf("3.1.0 dist.url = %v, want %q", got, want)
	}
	assertOnlyDistURLsChanged(t, original, out, "monolog/monolog")
	if n := assertDistURLsResolve(t, b, original, out, "monolog/monolog"); n != 2 {
		t.Errorf("checked %d dist URLs, want 2", n)
	}
}

// Without a public base the dist URLs are root-relative under the mount (the
// root document's dist mirror is what makes them downloadable).
func TestRewriteMetadataNoPublicBase(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", "")
	original := []byte(inheritedDistFixture)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	const name = "ralouphie/getallheaders"
	versions := clientVersions(t, out, name)
	if got, want := distOf(t, versions[1])["url"], "/v1/packagist/dist/ralouphie/getallheaders/dev-master/120b605dfeb996808c31b6477290a714d356e822.zip"; got != want {
		t.Errorf("dev-master dist.url = %v, want %q", got, want)
	}
	if bytes.Contains(out, []byte("api.github.com")) {
		t.Errorf("an upstream dist URL survived the fallback rewrite:\n%s", out)
	}
	if n := assertDistURLsResolve(t, b, original, out, name); n != 3 {
		t.Errorf("checked %d dist URLs, want 3", n)
	}
}

// A dist the proxy cannot fetch and route is left exactly as the upstream listed
// it; everything routable around it is still rewritten.
func TestRewriteMetadataLeavesUnroutableDists(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	original := []byte(`{"minified":"composer/2.0","packages":{"acme/pkg":[
	  {"name":"acme/pkg","version":"9.0.0","dist":{"type":"zip","url":"https://example.test/9.zip","reference":"r9"}},
	  {"version":"8.0.0","dist":{"type":"path","url":"../local/acme-pkg","reference":"r8"}},
	  {"version":"7.0.0","dist":{"type":"zip","url":"ftp://example.test/7.zip","reference":"r7"}},
	  {"version":"6.0.0","dist":{"type":"tar.gz","url":"https://example.test/6.tar.gz","reference":"r6"}},
	  {"version":"5.0 0","dist":{"type":"zip","url":"https://example.test/5.zip","reference":"r5"}},
	  {"version":"4.0.0","dist":"not-an-object"},
	  {"version":"3.0.0","dist":{"type":"zip","url":"https://example.test/3.zip","reference":3}},
	  {"version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"r2"}},
	  {"version":"dev-a/../b"},
	  {"version":"1.0.0"}
	]}}`)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	before := clientVersions(t, original, "acme/pkg")
	after := clientVersions(t, out, "acme/pkg")
	if len(after) != len(before) {
		t.Fatalf("version count changed: %d -> %d", len(before), len(after))
	}

	rewritten := map[string]string{
		"9.0.0": testPublicBase + "/dist/acme/pkg/9.0.0/r9.zip",
		"2.0.0": testPublicBase + "/dist/acme/pkg/2.0.0/r2.zip",
		// Inherits 2.0.0's dist, under its own version.
		"1.0.0": testPublicBase + "/dist/acme/pkg/1.0.0/r2.zip",
	}
	for i, v := range after {
		version, _ := v["version"].(string)
		if want, ok := rewritten[version]; ok {
			if got := distOf(t, v)["url"]; got != want {
				t.Errorf("%s: dist.url = %v, want %q", version, got, want)
			}
			continue
		}
		// Everything else — including the unroutable version that merely inherits
		// 2.0.0's dist — is left as the upstream listed it. In particular it must
		// not inherit a neighbour's rewritten URL.
		if !reflect.DeepEqual(v["dist"], before[i]["dist"]) {
			t.Errorf("%s: unroutable dist changed: %v -> %v", version, before[i]["dist"], v["dist"])
		}
	}
	if n := assertDistURLsResolve(t, b, original, out, "acme/pkg"); n != 3 {
		t.Errorf("checked %d dist URLs, want 3", n)
	}
}

// A version collection shaped as an object (as the legacy layout uses, and as a
// PHP client would iterate just the same) is rewritten in place and keeps its
// shape and order.
func TestRewriteMetadataObjectCollection(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	original := []byte(`{"packages":{"acme/pkg":{
	  "2.0.0":{"name":"acme/pkg","version":"2.0.0","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"r2"}},
	  "1.0.0":{"name":"acme/pkg","version":"1.0.0","dist":{"type":"zip","url":"https://example.test/1.zip","reference":"r1"}}
	}}}`)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	var doc struct {
		Packages map[string]map[string]struct {
			Version string
			Dist    struct{ URL string }
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the collection must stay an object: %v\n%s", err, out)
	}
	for version, entry := range doc.Packages["acme/pkg"] {
		want := testPublicBase + "/dist/acme/pkg/" + version + "/r" + version[:1] + ".zip"
		if entry.Dist.URL != want {
			t.Errorf("%s: dist.url = %q, want %q", version, entry.Dist.URL, want)
		}
	}
	if i2, i1 := bytes.Index(out, []byte(`"2.0.0":`)), bytes.Index(out, []byte(`"1.0.0":`)); i2 < 0 || i1 < 0 || i2 > i1 {
		t.Errorf("object order was not preserved:\n%s", out)
	}
	if bytes.Contains(out, []byte("https://example.test/")) {
		t.Errorf("an upstream dist URL survived:\n%s", out)
	}
}

// Anything else that would send a client around the proxy is dropped from a
// version: mirrors listed inside the dist, and a per-version notification URL.
func TestRewriteMetadataStripsSideChannels(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	original := []byte(`{"minified":"composer/2.0","packages":{"acme/pkg":[
	  {"name":"acme/pkg","version":"2.0.0","notification-url":"https://packagist.org/downloads/","dist":{"type":"zip","url":"https://example.test/2.zip","reference":"r2","mirrors":[{"url":"https://mirror.example.test/%package%/%reference%.%type%","preferred":true}]}},
	  {"version":"1.0.0","notification-url":"https://stats.example.test/","dist":{"type":"zip","url":"https://example.test/1.zip","reference":"r1"}},
	  {"version":"0.9.0","notification-url":"__unset"}
	]}}`)
	out, err := b.rewriteMetadata(original)
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	for _, v := range clientVersions(t, out, "acme/pkg") {
		if n, present := v["notification-url"]; present {
			t.Errorf("%v: notification-url must be removed, got %v", v["version"], n)
		}
		if m, present := distOf(t, v)["mirrors"]; present {
			t.Errorf("%v: dist.mirrors must be removed, got %v", v["version"], m)
		}
	}
	for _, leak := range []string{"packagist.org", "stats.example.test", "mirror.example.test", "https://example.test/"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("rewritten metadata still mentions %s:\n%s", leak, out)
		}
	}
}

// Only names a client can ask this repository for are rewritten; a document with
// nothing to rewrite is returned byte-for-byte.
func TestRewriteMetadataUntouchedDocuments(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	for _, doc := range []string{
		`{"packages":[]}`,
		`{"packages":{}}`,
		`{}`,
		`{ "packages" : { "acme/pkg" : [ ] } , "minified" : "composer/2.0" }`,
		`{"packages":{"acme/pkg":[{"name":"acme/pkg","version":"1.0.0"}]}}`,
		`{"packages":{"acme/pkg":"nonsense"}}`,
		`{"packages":{"acme/pkg":["nonsense",42,null]}}`,
		// Not a "vendor/package" name: the dist endpoint could not carry it.
		`{"packages":{"Acme/Pkg":[{"version":"1.0.0","dist":{"type":"zip","url":"https://example.test/1.zip","reference":"r1"}}]}}`,
	} {
		out, err := b.rewriteMetadata([]byte(doc))
		if err != nil {
			t.Errorf("rewriteMetadata(%s): %v", doc, err)
			continue
		}
		if string(out) != doc {
			t.Errorf("document with nothing to rewrite changed:\n in  %s\n out %s", doc, out)
		}
	}
}

func TestRewriteMetadataMalformed(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	for _, doc := range []string{``, `null`, `[]`, `"x"`, `not json`, `{"packages":`} {
		if out, err := b.rewriteMetadata([]byte(doc)); err == nil {
			t.Errorf("rewriteMetadata(%q) should fail, got %s", doc, out)
		}
	}
	if _, err := b.rewriteMetadata(make([]byte, maxMetadataBytes+1)); err == nil {
		t.Error("an oversized document should be rejected")
	}
}

// Rewriting is idempotent in the sense that matters: applied to its own output
// (a proxy chained behind a proxy) it still yields URLs under the public base.
func TestRewriteMetadataOutputIsStable(t *testing.T) {
	b := offlineBackend(t, "https://repo.packagist.org", testPublicBase)
	once, err := b.rewriteMetadata([]byte(inheritedDistFixture))
	if err != nil {
		t.Fatalf("rewriteMetadata: %v", err)
	}
	twice, err := b.rewriteMetadata(once)
	if err != nil {
		t.Fatalf("rewriteMetadata (second pass): %v", err)
	}
	if !bytes.Equal(once, twice) {
		t.Errorf("second pass changed the document:\n once  %s\n twice %s", once, twice)
	}
}
