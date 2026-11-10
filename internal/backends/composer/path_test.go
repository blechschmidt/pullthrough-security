package composer

import "testing"

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
	}
	if cn, _ := classify("/p2/symfony/console.json"); cn.coordinateName() != "symfony/console" {
		t.Errorf("coordinate = %q", cn.coordinateName())
	}
}

func TestClassifyDist(t *testing.T) {
	res, ok := classify("/dist/symfony/console/abc123def.zip")
	if !ok {
		t.Fatal("classify dist not ok")
	}
	if res.kind != kindDist || res.vendor != "symfony" || res.pkg != "console" {
		t.Errorf("dist = %+v", res)
	}
	if res.reference != "abc123def" || res.ext != "zip" {
		t.Errorf("reference/ext = %q/%q", res.reference, res.ext)
	}
	if !res.verifiableArtifact() {
		t.Error("dist should be verifiable")
	}
	if !res.cacheable() {
		t.Error("dist should be cacheable")
	}
	if res.coordinateName() != "symfony/console" {
		t.Errorf("coordinate = %q", res.coordinateName())
	}
}

func TestClassifyRejects(t *testing.T) {
	bad := []string{
		"",
		"/",
		"////",
		"/p2/symfony/console.xml",       // not .json
		"/p2/symfony",                   // too few segments
		"/p2/Symfony/Console.json",      // uppercase rejected by name rule
		"/p2/-bad/console.json",         // leading separator
		"/dist/symfony/console/noext",   // no extension
		"/dist/../../etc/passwd.zip",    // traversal
		"/dist/symfony/console/a/b.zip", // too many segments
		"/random/path",
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
