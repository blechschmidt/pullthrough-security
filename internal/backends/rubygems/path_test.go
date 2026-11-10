package rubygems

import "testing"

func TestClassifyGem(t *testing.T) {
	cases := []struct {
		path        string
		wantName    string
		wantVersion string
	}{
		{"/gems/rails-7.0.4.gem", "rails", "7.0.4"},
		{"/gems/i18n-1.12.0.gem", "i18n", "1.12.0"},
		{"/gems/net-http-persistent-4.0.1.gem", "net-http-persistent", "4.0.1"},
		{"/gems/nokogiri-1.13.0-x86_64-linux.gem", "nokogiri", "1.13.0-x86_64-linux"},
		{"/gems/activesupport-7.0.4.1.gem", "activesupport", "7.0.4.1"},
		{"/gems/foo-1.0.0.pre.rc1.gem", "foo", "1.0.0.pre.rc1"},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) not ok", c.path)
			continue
		}
		if res.kind != kindGem {
			t.Errorf("classify(%q) kind = %v, want gem", c.path, res.kind)
		}
		if res.name != c.wantName || res.version != c.wantVersion {
			t.Errorf("classify(%q) = name %q version %q, want %q / %q", c.path, res.name, res.version, c.wantName, c.wantVersion)
		}
		if !res.verifiableArtifact() {
			t.Errorf("classify(%q) gem should be verifiable", c.path)
		}
		if !res.cacheable() {
			t.Errorf("classify(%q) gem should be cacheable", c.path)
		}
		if res.coordinateName() != c.wantName {
			t.Errorf("classify(%q) coordinate = %q", c.path, res.coordinateName())
		}
	}
}

func TestClassifyIndexAndInfo(t *testing.T) {
	cases := []struct {
		path     string
		wantKind resourceKind
		wantName string
	}{
		{"/versions", kindIndex, ""},
		{"/names", kindIndex, ""},
		{"/info/rails", kindInfo, "rails"},
		{"/info/net-http", kindInfo, "net-http"},
		{"/specs.4.8.gz", kindLegacyIndex, ""},
		{"/latest_specs.4.8.gz", kindLegacyIndex, ""},
		{"/prerelease_specs.4.8.gz", kindLegacyIndex, ""},
		{"/api/v1/dependencies", kindDependencyAPI, ""},
		{"/quick/Marshal.4.8/rails-7.0.4.gemspec.rz", kindQuickSpec, "rails"},
	}
	for _, c := range cases {
		res, ok := classify(c.path)
		if !ok {
			t.Errorf("classify(%q) not ok", c.path)
			continue
		}
		if res.kind != c.wantKind {
			t.Errorf("classify(%q) kind = %v, want %v", c.path, res.kind, c.wantKind)
		}
		if res.name != c.wantName {
			t.Errorf("classify(%q) name = %q, want %q", c.path, res.name, c.wantName)
		}
	}
	// Index and info documents are mutable: never cached.
	for _, p := range []string{"/versions", "/names", "/info/rails", "/specs.4.8.gz", "/api/v1/dependencies"} {
		res, _ := classify(p)
		if res.cacheable() {
			t.Errorf("%q must not be cacheable", p)
		}
	}
	// The Marshal gemspec is per-version and immutable: cached.
	res, _ := classify("/quick/Marshal.4.8/rails-7.0.4.gemspec.rz")
	if !res.cacheable() {
		t.Error("Marshal gemspec should be cacheable")
	}
	if res.verifiableArtifact() {
		t.Error("Marshal gemspec is not checksum-verified")
	}
}

func TestClassifyRejects(t *testing.T) {
	bad := []string{
		"",
		"/",
		"////",
		"/gems/",
		"/gems/noversion.gem",      // no hyphen-then-digit
		"/gems/rails-7.0.4.tar.gz", // not a .gem
		"/gems/sub/dir-1.0.gem",    // gem must be a single segment
		"/info/",                   // missing gem name
		"/info/a/b",                // info takes one segment
		"/quick/Marshal.4.8/../../etc/passwd.gemspec.rz",
		"/gems/../../etc/passwd.gem",
		"/random/path",
	}
	for _, p := range bad {
		if res, ok := classify(p); ok {
			t.Errorf("classify(%q) unexpectedly ok: %+v", p, res)
		}
	}
}

func TestSplitNameVersion(t *testing.T) {
	cases := []struct {
		base, name, version string
		ok                  bool
	}{
		{"rails-7.0.4", "rails", "7.0.4", true},
		{"net-http-persistent-4.0.1", "net-http-persistent", "4.0.1", true},
		{"nokogiri-1.13.0-x86_64-linux", "nokogiri", "1.13.0-x86_64-linux", true},
		{"noversion", "", "", false},
		{"-1.0.0", "", "", false}, // empty name
		{"trailingdash-", "", "", false},
	}
	for _, c := range cases {
		name, version, ok := splitNameVersion(c.base)
		if ok != c.ok || name != c.name || version != c.version {
			t.Errorf("splitNameVersion(%q) = %q,%q,%v; want %q,%q,%v", c.base, name, version, ok, c.name, c.version, c.ok)
		}
	}
}
