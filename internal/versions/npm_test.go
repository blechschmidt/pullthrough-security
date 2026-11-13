package versions

import "testing"

// Cases from node-semver's test fixtures (range-include, range-exclude,
// range-parse) and npm's documentation of ranges, plus the edge cases an
// updater must get right.

func TestNpmRanges(t *testing.T) {
	checkAllows(t, "npm", []allowCase{
		// Caret: the left-most non-zero component may not change.
		{"^1.2.3", []string{"1.2.3", "1.2.4", "1.9.0"}, []string{"1.2.2", "2.0.0", "2.0.0-0", "1.3.0-beta"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0", "0.2.2", "1.0.0"}},
		{"^0.0.3", []string{"0.0.3"}, []string{"0.0.4", "0.0.2", "0.1.0", "0.0.3-beta"}},
		{"^1.2.x", []string{"1.2.0", "1.9.9"}, []string{"1.1.9", "2.0.0"}},
		{"^0.0.x", []string{"0.0.0", "0.0.9"}, []string{"0.1.0"}},
		{"^0.0", []string{"0.0.0", "0.0.9"}, []string{"0.1.0"}},
		{"^0.x", []string{"0.0.0", "0.9.9"}, []string{"1.0.0"}},
		{"^1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0", "0.9.9"}},
		{"^1.2.3-beta.2", []string{"1.2.3-beta.2", "1.2.3-beta.4", "1.2.3", "1.9.0"}, []string{"1.2.3-beta.1", "1.2.4-beta.2", "2.0.0"}},
		// Tilde: patch-level changes if a minor version is given.
		{"~1.2.3", []string{"1.2.3", "1.2.9"}, []string{"1.3.0", "1.2.2"}},
		{"~1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0", "1.1.9"}},
		{"~1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0"}},
		{"~0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0"}},
		{"~> 1.2", []string{"1.2.5"}, []string{"1.3.0"}},
		{"~ >1.2", []string{"1.2.5"}, []string{"1.3.0"}},
		// X-ranges and partial versions.
		{"1.x", []string{"1.0.0", "1.9.9"}, []string{"2.0.0", "0.9.9"}},
		{"1.2.*", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0"}},
		{"1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"*", []string{"0.0.0", "99.0.0"}, []string{"1.0.0-beta"}},
		{"", []string{"0.0.0", "99.0.0"}, []string{"1.0.0-beta"}},
		{"x", []string{"1.2.3"}, nil},
		{">1.x", []string{"2.0.0"}, []string{"1.9.9"}},
		{"<=1.2.x", []string{"1.2.9"}, []string{"1.3.0"}},
		{">*", nil, []string{"0.0.0", "1.0.0"}},
		// Hyphen ranges: a partial upper bound includes all of it.
		{"1.2.3 - 2.3.4", []string{"1.2.3", "2.3.4"}, []string{"1.2.2", "2.3.5"}},
		{"1.2.3 - 2.3", []string{"1.2.3", "2.3.9"}, []string{"2.4.0", "2.4.0-0"}},
		{"1.2 - 2.3.4", []string{"1.2.0", "2.3.4"}, []string{"1.1.9", "2.3.5"}},
		// Comparators, AND and OR.
		{">=1.2.3-alpha <2", []string{"1.2.3-alpha", "1.2.3-beta", "1.2.3", "1.9.9"}, []string{"1.2.3-0", "1.2.4-alpha", "2.0.0-alpha", "2.0.0"}},
		{">= 1.0.0", []string{"1.0.0", "2.0.0"}, []string{"0.9.9"}},
		{"<2.0.0", []string{"1.9999.9999"}, []string{"2.0.0", "2.0.0-0"}},
		{"=1.2.3", []string{"1.2.3", "1.2.3+build"}, []string{"1.2.4"}},
		{"v1.2.3", []string{"1.2.3"}, []string{"1.2.4"}},
		{"0.1.20 || 1.2.4", []string{"0.1.20", "1.2.4"}, []string{"1.2.3"}},
		{">=0.2.3 || <0.0.1", []string{"0.0.0", "0.2.3"}, []string{"0.0.1", "0.2.2"}},
		{"1.2.x || 2.x", []string{"1.2.5", "2.1.3"}, []string{"1.3.0", "3.0.0"}},
		{"^1.2.3+build", []string{"1.2.3", "1.3.0"}, []string{"2.0.0"}},
	})
}

func TestNpmDesugaring(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"^0.0.3", ">=0.0.3 <0.0.4-0"},
		{"^1.2.3", ">=1.2.3 <2.0.0-0"},
		{"~1.2", ">=1.2.0 <1.3.0-0"},
		{"1.2.3 - 2.3", ">=1.2.3 <2.4.0-0"},
		{"1.x || >=2.5.0 || 5.0.0 - 7.2.3", ">=1.0.0 <2.0.0-0||>=2.5.0||>=5.0.0 <=7.2.3"},
		{"*", ""},
		{">=0.0.0 <1.0.0", "<1.0.0"},
		{"<*", "<0.0.0-0"},
	} {
		c, err := mustScheme(t, "npm").ParseConstraint(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got := c.(*npmRange).desugared(); got != tc.want {
			t.Errorf("%q desugars to %q, want %q", tc.in, got, tc.want)
		}
	}
}

// package.json specs that name no registry range declare no constraint; an
// alias names its target's range.
func TestNpmSpecs(t *testing.T) {
	checkNoConstraint(t, "npm",
		"latest", "next", "beta", "canary",
		"file:../foo", "link:../foo", "./foo", "../foo", "~/foo", "/abs/foo",
		"foo.tgz", "foo.tar.gz",
		"git+https://github.com/a/b.git", "git://github.com/a/b.git", "git+ssh://git@github.com:a/b.git",
		"git@github.com:a/b.git", "github:a/b", "gitlab:a/b", "a/b", "a/b#v1.2.3",
		"http://example.com/a.tgz", "https://example.com/a.tgz",
		"workspace:*", "workspace:^1.2.3", "catalog:", "jsr:@std/path@^1",
		"npm:other@latest",
	)
	checkAllows(t, "npm", []allowCase{
		{"npm:lodash@^4.17.0", []string{"4.17.21"}, []string{"5.0.0", "4.16.0"}},
		{"npm:@scope/pkg@~1.2.0", []string{"1.2.5"}, []string{"1.3.0"}},
		{"npm:other", []string{"1.0.0", "9.9.9"}, []string{"1.0.0-beta"}},
	})
	// Neither a range nor a tag: refused, never mistaken for a tag (a loose
	// "1.2.3beta" is an exact version to npm).
	checkInvalidConstraints(t, "npm",
		"1.2.3beta", ">=1.0.0 foo", "^", "=>1.0", "1.2.3 - ", "v", "1.x.3", "x.1",
		">= 1 +build < 2", "+1.2.3", "1.2.3*", "npm:", "npm:a b@1",
		"1.0.0 - 2.0.0 - 3.0.0", "^9007199254740991.0.0", "9007199254740992.0.0",
	)
}

func TestNpmVersions(t *testing.T) {
	s := mustScheme(t, "npm")
	// semver.clean: surrounding space, "=" and "v" are dropped.
	for _, in := range []string{"1.2.3", "v1.2.3", "=1.2.3", " =v1.2.3 ", "= v1.2.3"} {
		if v := mustParse(t, s, in); v.String() != in || s.Compare(v, mustParse(t, s, "1.2.3")) != 0 {
			t.Errorf("Parse(%q) = %v", in, v)
		}
	}
	checkInvalidVersions(t, "npm", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-01", "1.2.3-", "1.2.3+",
		"1.2.3beta", "vv1.2.3x", "9007199254740992.0.0", "", "latest")
	checkAscending(t, "npm", "1.0.0-0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0")
	checkEquivalent(t, "npm", "1.2.3", "1.2.3+build", "1.2.3+other", "v1.2.3")
	checkPrerelease(t, "npm", true, "1.2.3-0", "1.2.3-beta.1")
	checkPrerelease(t, "npm", false, "1.2.3", "1.2.3+beta")
}
