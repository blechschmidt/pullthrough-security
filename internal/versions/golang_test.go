package versions

import "testing"

// Cases from golang.org/x/mod's semver_test.go and module/pseudo_test.go.

func TestGoVersions(t *testing.T) {
	checkInvalidVersions(t, "go", "1.2.3", "V1.2.3", "v1.2.3.4", "v01.2.3", "v1.02.3", "v1.2-pre",
		"v1.2+meta", "v1.2.3-", "v1.2.3-01", "v", "", " v1.2.3")
	checkEquivalent(t, "go", "v1", "v1.0", "v1.0.0", "v1.0.0+meta", "v1.0.0+incompatible")
	checkAscending(t, "go", "v0.0.0-20210101000000-abcdef123456", "v0.1.0", "v1.0.0-alpha", "v1.0.0-alpha.1",
		"v1.0.0-beta", "v1.0.0-rc.1", "v1.0.0", "v1.2.3-pre.0.20210101000000-abcdef123456", "v1.2.3",
		"v1.2.4-0.20210101000000-abcdef123456", "v1.2.4", "v1.10.0", "v2.0.0")
	checkPrerelease(t, "go", true, "v0.0.0-20210101000000-abcdef123456", "v1.2.4-0.20210101000000-abcdef123456",
		"v1.2.3-pre.0.20210101000000-abcdef123456", "v1.2.3-rc.1")
	checkPrerelease(t, "go", false, "v1.2.3", "v2.0.0+incompatible")

	s := mustScheme(t, "go")
	for text, want := range map[string]bool{
		"v0.0.0-20210101000000-abcdef123456":       true,
		"v1.2.4-0.20210101000000-abcdef123456":     true,
		"v1.2.3-pre.0.20210101000000-abcdef123456": true,
		"v2.0.0-20210101000000-abcdef123456+meta":  true,
		"v1.2.3-20210101000000-abcdef123456":       false, // no base and not vX.0.0
		"v1.2.4-0.2021010100000-abcdef123456":      false, // 13-digit time
		"v1.2.3-pre":                               false,
		"v1.2.3":                                   false,
	} {
		if got := IsPseudoVersion(mustParse(t, s, text)); got != want {
			t.Errorf("IsPseudoVersion(%q) = %v, want %v", text, got, want)
		}
	}
}

// Go declares no ranges: a go.mod version is a minimum, and SameMajor is what
// minimal version selection may move to.
func TestGoConstraints(t *testing.T) {
	checkNoConstraint(t, "go", "v1.2.3", "", "latest", "upgrade", "patch", "master", "^v1.2.3", "<v2")
	checkAllows(t, "go", []allowCase{
		{">=v1.2.3", []string{"v1.2.3", "v1.9.0", "v2.0.0"}, []string{"v1.2.2", "v1.2.3-pre"}},
		{">= v1.2", []string{"v1.2.0"}, []string{"v1.1.9"}},
	})
	checkInvalidConstraints(t, "go", ">=1.2.3", ">=")

	s := mustScheme(t, "go")
	for _, tc := range []allowCase{
		{"v1.2.3", []string{"v1.2.3", "v1.2.4", "v1.9.0", "v1.3.0-pre"}, []string{"v1.2.2", "v2.0.0", "v0.9.0", "v2.0.0+incompatible"}},
		{"v0.4.1", []string{"v0.4.1", "v0.9.9"}, []string{"v0.4.0", "v1.0.0"}},
		{"v2.0.0+incompatible", []string{"v2.0.0+incompatible", "v2.1.0+incompatible"}, []string{"v2.1.0", "v3.0.0+incompatible", "v1.9.0"}},
		{"v2.1.0", []string{"v2.1.0", "v2.5.0"}, []string{"v2.5.0+incompatible", "v3.0.0"}},
	} {
		c := SameMajor(s, mustParse(t, s, tc.constraint))
		for _, v := range tc.allowed {
			if !c.Allows(mustParse(t, s, v)) {
				t.Errorf("SameMajor(%s) = %s does not allow %s", tc.constraint, c, v)
			}
		}
		for _, v := range tc.denied {
			if c.Allows(mustParse(t, s, v)) {
				t.Errorf("SameMajor(%s) = %s allows %s", tc.constraint, c, v)
			}
		}
	}
	if got := SameMajor(s, mustParse(t, s, "v1.2.3")).String(); got != ">=v1.2.3 <v2.0.0" {
		t.Errorf("SameMajor(v1.2.3) = %q", got)
	}
}
