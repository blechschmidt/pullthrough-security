package composer

import (
	"net/url"
	"strings"
	"testing"
)

func TestClassifyMetadataAndRoot(t *testing.T) {
	cases := []struct {
		path       string
		wantKind   resourceKind
		wantVendor string
		wantPkg    string
	}{
		{"/packages.json", kindRoot, "", ""},
		{"/p2/symfony/console.json", kindMetadata, "symfony", "console"},
		{"/p2/symfony/console~dev.json", kindMetadata, "symfony", "console"},
		{"/p/monolog/monolog.json", kindProviderV1, "monolog", "monolog"},
		{"/p/monolog/monolog$abcdef.json", kindProviderV1, "monolog", "monolog"},
		{"/lists/all/summary.json", kindFilterList, "", ""},
		{"/lists/malware/2026/summary.json", kindFilterList, "", ""},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) not ok", c.path)
			continue
		}
		if res.kind != c.wantKind || res.vendor != c.wantVendor || res.pkg != c.wantPkg {
			t.Errorf("classify(%q) = %+v, want kind %v vendor %q pkg %q", c.path, res, c.wantKind, c.wantVendor, c.wantPkg)
		}
		if res.cacheable() {
			t.Errorf("%q (metadata) must not be cacheable", c.path)
		}
		if res.verifiableArtifact() {
			t.Errorf("%q (metadata) must not be a verifiable artifact", c.path)
		}
	}
	if cn, _ := classify("/p2/symfony/console.json"); cn.coordinateName() != "symfony/console" {
		t.Errorf("coordinate = %q", cn.coordinateName())
	}
	if res, _ := classify("/lists/all/summary.json"); res.coordinateName() != "" || res.kindLabel() != "filter-list" {
		t.Errorf("filter list = %+v (label %q)", res, res.kindLabel())
	}
}

func TestClassifyDist(t *testing.T) {
	cases := []struct {
		path        string
		wantVersion string
		wantRef     string
		wantExt     string
	}{
		// The shape every rewritten dist.url has: package, version, commit id, type.
		{"/dist/symfony/console/v8.0.0-RC3/307d3cf852f5abc123def.zip", "v8.0.0-RC3", "307d3cf852f5abc123def", "zip"},
		{"/dist/symfony/console/3.0.0/fe5ea303b0887d5caefd3d431c3e61ad47037001.zip", "3.0.0", "fe5ea303b0887d5caefd3d431c3e61ad47037001", "zip"},
		{"/dist/symfony/console/dev-master/abc123.tar", "dev-master", "abc123", "tar"},
		// A dev branch name may contain "/": the version spans several segments.
		{"/dist/symfony/console/dev-feature/property-based-testing/abc123.zip", "dev-feature/property-based-testing", "abc123", "zip"},
		{"/dist/symfony/console/dev-dependabot/npm_and_yarn/lodash-4.17.21/abc123.zip", "dev-dependabot/npm_and_yarn/lodash-4.17.21", "abc123", "zip"},
		// The gateway hands the backend the percent-decoded path.
		{"/dist/symfony/console/dev-issue#42/abc123.zip", "dev-issue#42", "abc123", "zip"},
		{"/dist/symfony/console/1.0.0+build.5/abc123.zip", "1.0.0+build.5", "abc123", "zip"},
		// A reference may itself contain dots; the type never does.
		{"/dist/symfony/console/1.0.0/v1.0.0.zip", "1.0.0", "v1.0.0", "zip"},
		// No reference: the placeholder, or the empty stem Composer's mirror
		// expansion produces. Both name the same dist.
		{"/dist/symfony/console/1.0.0/_.zip", "1.0.0", noReferenceToken, "zip"},
		{"/dist/symfony/console/1.0.0/.zip", "1.0.0", noReferenceToken, "zip"},
		// A hashed (non-URL-safe) reference token.
		{"/dist/symfony/console/1.0.0/_0123456789abcdef0123456789abcdef.zip", "1.0.0", "_0123456789abcdef0123456789abcdef", "zip"},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) not ok", c.path)
			continue
		}
		if res.kind != kindDist || res.vendor != "symfony" || res.pkg != "console" {
			t.Errorf("classify(%q) = %+v", c.path, res)
		}
		if res.version != c.wantVersion || res.reference != c.wantRef || res.ext != c.wantExt {
			t.Errorf("classify(%q) version/reference/ext = %q/%q/%q, want %q/%q/%q",
				c.path, res.version, res.reference, res.ext, c.wantVersion, c.wantRef, c.wantExt)
		}
		if !res.verifiableArtifact() {
			t.Errorf("%q: dist should be verifiable", c.path)
		}
		if res.coordinateName() != "symfony/console" {
			t.Errorf("%q: coordinate = %q", c.path, res.coordinateName())
		}
	}
}

// The two spellings of a reference-less dist must share one cache entry.
func TestClassifyDistEmptyReferenceAliasSharesKey(t *testing.T) {
	a, okA := classify("/dist/vendor/pkg/1.0.0/_.zip")
	b, okB := classify("/dist/vendor/pkg/1.0.0/.zip")
	if !okA || !okB {
		t.Fatalf("classify not ok: %v %v", okA, okB)
	}
	if a.distKey() != b.distKey() {
		t.Errorf("dist keys differ: %q vs %q", a.distKey(), b.distKey())
	}
}

// Every dist is cached — the cache is where the content gates inspect an archive,
// so nothing the dist endpoint serves may bypass it — whether or not its locator
// carries a reference.
func TestDistIsAlwaysCacheable(t *testing.T) {
	for _, path := range []string{
		"/dist/vendor/pkg/1.0.0/abc123.zip",
		"/dist/vendor/pkg/dev-master/abc123.zip",
		"/dist/vendor/pkg/2.x-dev/abc123.zip",
		"/dist/vendor/pkg/1.0.0/_.zip",
		"/dist/vendor/pkg/dev-master/_.zip",
		"/dist/vendor/pkg/2.x-dev/.zip",
	} {
		res, ok := classify(path)
		if !ok {
			t.Errorf("classify(%q) not ok", path)
			continue
		}
		if !res.cacheable() {
			t.Errorf("%q must be cacheable", path)
		}
	}
}

func TestClassifyRejects(t *testing.T) {
	bad := []string{
		"",
		"/",
		"////",
		"/p2/symfony/console.xml",  // not .json
		"/p2/symfony",              // too few segments
		"/p2/Symfony/Console.json", // uppercase rejected by name rule
		"/p2/-bad/console.json",    // leading separator
		"/random/path",
		"/lists",              // no document
		"/lists/all/summary",  // not .json
		"/search.json",        // not a route this backend fronts
		"/packages/list.json", // ditto

		// The version-less dist form is gone: it cannot be admission-gated.
		"/dist/symfony/console/abc123def.zip",
		"/dist/symfony/console",
		"/dist/symfony",

		"/dist/symfony/console/1.0.0/noext",          // no type
		"/dist/symfony/console/1.0.0/abc123.",        // empty type
		"/dist/symfony/console/1.0.0/abc123.tar.gz!", // type is not a plain token
		"/dist/symfony/console/1.0.0/-abc.zip",       // reference token may not start with "-"
		"/dist/symfony/console/1.0.0/a@b.zip",        // reference token is not plain
		"/dist/../../etc/passwd.zip",                 // traversal
		"/dist/symfony/console/../1.0.0/abc.zip",     // traversal inside the version
		"/dist/symfony/console/1.0.0//abc.zip",       // empty segment
		"/dist/Symfony/console/1.0.0/abc.zip",        // uppercase vendor
		"/dist/symfony/con sole/1.0.0/abc.zip",       // invalid package
		"/dist/symfony/console/1.0 .0/abc.zip",       // whitespace in the version
		"/dist/symfony/console/1.0\x00.0/abc.zip",    // control character in the version
		"/dist/symfony/console/dev-a\\b/abc.zip",     // backslash in the version
		"/dist/symfony/console/" + strings.Repeat("9", maxVersionLen+1) + "/abc.zip",
		"/dist/symfony/console/1.0.0/" + strings.Repeat("a", maxReferenceLen+1) + ".zip",
		"/dist/symfony/console/1.0.0/abc." + strings.Repeat("z", maxDistTypeLen+1),
	}
	for _, p := range bad {
		if res, ok := classify(p); ok {
			t.Errorf("classify(%q) unexpectedly ok: %+v", p, res)
		}
	}
}

func TestValidNamePart(t *testing.T) {
	good := []string{"symfony", "php-http", "league", "phpunit", "a", "guzzle.http", "x_y"}
	for _, s := range good {
		if !validNamePart(s) {
			t.Errorf("validNamePart(%q) = false, want true", s)
		}
	}
	bad := []string{"", "-x", "x-", "x--y", ".x", "x.", "Foo", "a/b", "a b", "café"}
	for _, s := range bad {
		if validNamePart(s) {
			t.Errorf("validNamePart(%q) = true, want false", s)
		}
	}
}

func TestIsDevVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"dev-master":    true,
		"dev-feature/x": true,
		"3.x-dev":       true,
		"1.0.x-dev":     true,
		"3.0.0":         false,
		"v8.0.0-RC3":    false,
		"1.0.0-beta1":   false,
		"developer-1.0": false,
		"":              false,
	} {
		if got := isDevVersion(v); got != want {
			t.Errorf("isDevVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestReferenceToken(t *testing.T) {
	// Plain references (every commit id) are carried verbatim.
	for _, ref := range []string{
		"fe5ea303b0887d5caefd3d431c3e61ad47037001",
		"ABCDEF0123",
		"v1.2.3",
		"release_1-2.3",
	} {
		if got := referenceToken(ref); got != ref {
			t.Errorf("referenceToken(%q) = %q, want verbatim", ref, got)
		}
	}
	if got := referenceToken(""); got != noReferenceToken {
		t.Errorf("referenceToken(\"\") = %q, want %q", got, noReferenceToken)
	}

	// Anything a path segment cannot carry is hashed into the "_" namespace, so
	// it can collide neither with a verbatim reference nor with the placeholder.
	seen := map[string]string{}
	for _, ref := range []string{"refs/heads/main", "/trunk/@1234", "a b", "_leading", "-leading", ".hidden", "ref?x=1", "é"} {
		got := referenceToken(ref)
		if !strings.HasPrefix(got, "_") || len(got) != 33 || got == noReferenceToken {
			t.Errorf("referenceToken(%q) = %q, want \"_\" + 32 hex digits", ref, got)
		}
		if !validReferenceToken(got) {
			t.Errorf("referenceToken(%q) = %q is not a valid token", ref, got)
		}
		if got != referenceToken(ref) {
			t.Errorf("referenceToken(%q) is not deterministic", ref)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("referenceToken collision: %q and %q -> %q", prev, ref, got)
		}
		seen[got] = ref
	}
}

// distPath and classify must agree: whatever locator the rewrite emits, the
// backend must parse back into the very same version, reference token and type
// once the HTTP layer has percent-decoded the path.
func TestDistPathRoundTrip(t *testing.T) {
	cases := []struct {
		version, reference, distType string
	}{
		{"3.0.0", "fe5ea303b0887d5caefd3d431c3e61ad47037001", "zip"},
		{"v8.0.0-RC3", "307d3cf852f5", "zip"},
		{"dev-master", "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3", "zip"},
		{"dev-hotfix/composer-install", "aad26b2e26ba2e877e3f65cf3aa739c581b57967", "zip"},
		{"dev-dependabot/npm_and_yarn/lodash-4.17.21", "abc", "tar"},
		{"1.0.0+build.5", "abc", "zip"},
		{"dev-issue#42", "abc", "zip"},
		{"dev-what?", "abc", "zip"},
		{"dev-100%", "abc", "zip"},
		{"dev-ünïcode", "abc", "zip"},
		{"dev-a;b,c", "abc", "zip"},
		{"1.0.0", "", "zip"},
		{"1.0.0", "refs/tags/v1", "zip"},
		{"1.0.0", "v1.0.0", "zip"},
	}
	for _, c := range cases {
		path, ok := distPath("vendor", "pkg", c.version, c.reference, c.distType)
		if !ok {
			t.Errorf("distPath(%q, %q, %q) not ok", c.version, c.reference, c.distType)
			continue
		}
		// The emitted path must be a clean URL path: no query, fragment or
		// characters a client would re-encode.
		u, err := url.Parse("http://proxy.example" + path)
		if err != nil {
			t.Errorf("distPath(%q) = %q does not parse: %v", c.version, path, err)
			continue
		}
		if u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("distPath(%q) = %q leaks into query/fragment", c.version, path)
		}
		if u.EscapedPath() != path {
			t.Errorf("distPath(%q) = %q is not in canonical escaped form (%q)", c.version, path, u.EscapedPath())
		}
		res, ok := classify(u.Path)
		if !ok {
			t.Errorf("classify(%q) (from version %q) not ok", u.Path, c.version)
			continue
		}
		if res.kind != kindDist || res.vendor != "vendor" || res.pkg != "pkg" {
			t.Errorf("classify(%q) = %+v", u.Path, res)
		}
		if res.version != c.version || res.reference != referenceToken(c.reference) || res.ext != c.distType {
			t.Errorf("round trip of (%q, %q, %q) = (%q, %q, %q)",
				c.version, c.reference, c.distType, res.version, res.reference, res.ext)
		}
	}
}

func TestDistPathRefusesUnroutable(t *testing.T) {
	cases := []struct {
		name                                   string
		vendor, pkg, version, reference, dtype string
	}{
		{"empty version", "vendor", "pkg", "", "abc", "zip"},
		{"dot-segment version", "vendor", "pkg", "dev-a/../b", "abc", "zip"},
		{"empty version segment", "vendor", "pkg", "dev-a//b", "abc", "zip"},
		{"whitespace version", "vendor", "pkg", "1.0 0", "abc", "zip"},
		{"control character version", "vendor", "pkg", "1.0\n0", "abc", "zip"},
		{"invalid utf-8 version", "vendor", "pkg", "1.0\xff", "abc", "zip"},
		{"empty type", "vendor", "pkg", "1.0.0", "abc", ""},
		{"dotted type", "vendor", "pkg", "1.0.0", "abc", "tar.gz"},
		{"path type", "vendor", "pkg", "1.0.0", "abc", "zip/../x"},
		{"uppercase vendor", "Vendor", "pkg", "1.0.0", "abc", "zip"},
		{"empty package", "vendor", "", "1.0.0", "abc", "zip"},
	}
	for _, c := range cases {
		if path, ok := distPath(c.vendor, c.pkg, c.version, c.reference, c.dtype); ok {
			t.Errorf("%s: distPath unexpectedly ok: %q", c.name, path)
		}
	}
}

func TestSplitPackageName(t *testing.T) {
	if v, p, ok := splitPackageName("psr/log"); !ok || v != "psr" || p != "log" {
		t.Errorf("splitPackageName(psr/log) = %q, %q, %v", v, p, ok)
	}
	for _, bad := range []string{"", "psr", "psr/", "/log", "psr/log/extra", "Psr/Log", "psr/lo g"} {
		if _, _, ok := splitPackageName(bad); ok {
			t.Errorf("splitPackageName(%q) unexpectedly ok", bad)
		}
	}
}
