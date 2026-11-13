package versions

import "testing"

// Cases from NuGet.Versioning's tests (VersionRangeTests, FloatingRangeTests,
// NuGetVersionTest) and the "Package versioning" documentation.

func TestNuGetVersions(t *testing.T) {
	checkEquivalent(t, "nuget", "1.0", "1.0.0", "1.0.0.0", "1", "01.0", " 1.0 ", "1. 0", "1.0.0+metadata", "1.0.0+other")
	checkEquivalent(t, "nuget", "1.0.0-Beta", "1.0.0-beta", "1.0.0-BETA+meta")
	checkAscending(t, "nuget", "0.9", "1.0.0-0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0.1-beta", "1.0.0.1", "1.0.1", "1.1", "2.0")
	checkInvalidVersions(t, "nuget", "1.0.0.0.0", "1.", ".1", "1..0", "1.0-", "1.0+", "v1.0", "2147483648.0",
		"1.0.0-01", "1.0.0-a_b", "1.0.0-*", "", "1 0")
	checkPrerelease(t, "nuget", true, "1.0.0-0", "1.0.0.1-beta")
	checkPrerelease(t, "nuget", false, "1.0", "1.0.0+beta")
	if r := mustParse(t, mustScheme(t, "nuget"), "1.2.3.4").Release(); len(r) != 4 || r[3] != 4 {
		t.Errorf("Release(1.2.3.4) = %v", r)
	}
}

func TestNuGetRanges(t *testing.T) {
	checkAllows(t, "nuget", []allowCase{
		// A bare version is a minimum, inclusive.
		{"1.0", []string{"1.0", "1.0.1", "2.0", "99.0"}, []string{"0.9", "1.1.0-beta"}},
		{"[1.0]", []string{"1.0", "1.0.0.0"}, []string{"1.0.1"}},
		{"[1.0,2.0)", []string{"1.0", "1.9.9"}, []string{"0.9", "2.0", "2.0.0-beta", "1.5.0-beta"}},
		{"[1.0,2.0]", []string{"2.0"}, []string{"2.0.1"}},
		{"(1.0,)", []string{"1.0.1"}, []string{"1.0"}},
		{"(,1.0]", []string{"0.1", "1.0"}, []string{"1.0.1"}},
		{"[1.0,]", []string{"1.0", "9.0"}, []string{"0.9"}},
		{"[ 1.0 , 2.0 )", []string{"1.5"}, []string{"2.0"}},
		// A pre-release bound admits pre-releases.
		{"[1.0.0-beta,2.0.0)", []string{"1.0.0-beta", "1.5.0-alpha"}, []string{"1.0.0-alpha"}},
		{"(,2.0.0-beta]", []string{"1.0.0-rc.1", "1.9"}, []string{"2.0.0"}},
		// Floating versions: within what the float covers.
		{"1.*", []string{"1.0", "1.9.9"}, []string{"2.0", "0.9", "1.5.0-beta"}},
		{"1.2.*", []string{"1.2.0", "1.2.9"}, []string{"1.3.0", "1.1.9"}},
		{"*", []string{"0.0.1", "99.0"}, []string{"1.0.0-beta"}},
		{"1.0.0-*", []string{"1.0.0-alpha", "1.0.0-beta.2", "1.0.0"}, []string{"1.0.1", "1.0.1-beta", "0.9"}},
		{"1.0.0-beta*", []string{"1.0.0-beta", "1.0.0-beta.2", "1.0.0-Beta2", "1.0.0"}, []string{"1.0.0-alpha", "1.0.0-rc"}},
		{"1.0.*-*", []string{"1.0.0-alpha", "1.0.5-beta", "1.0.9"}, []string{"1.1.0-beta", "1.1.0"}},
		{"1.*-*", []string{"1.0.0-alpha", "1.9.0"}, []string{"2.0.0-beta"}},
		{"*-*", []string{"0.0.0-0", "1.0.0-beta", "99.0"}, nil},
		{"[1.*, 2.0)", []string{"1.0", "1.9"}, []string{"2.0", "0.9"}},
	})
	checkInvalidConstraints(t, "nuget", "(1.0)", "[1.0)", "(1.0]", "[2.0,1.0]", "[1.0,1.0)", "[1.0,2.0,3.0]",
		"[,]", "(,)", "[]", "[1.0", "1.0]", "1.**", "[1.*]", "1.*.0", "*.1", "[1.0,2.0)a", "v1.0", "1.0.0.0.*")
	checkNoConstraint(t, "nuget", "", "  ")
}
