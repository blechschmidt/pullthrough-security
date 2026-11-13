package versions

import "testing"

// Cases from the semver crate's tests (tests/test_version_req.rs,
// tests/test_version.rs) and the Cargo book's "Specifying Dependencies".

func TestCargoRequirements(t *testing.T) {
	checkAllows(t, "cargo", []allowCase{
		// A bare version is a caret requirement.
		{"1.2.3", []string{"1.2.3", "1.2.4", "1.9.0"}, []string{"1.2.2", "2.0.0", "1.2.4-pre"}},
		{"^1.2.3", []string{"1.2.3", "1.9.0"}, []string{"2.0.0"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0", "0.2.2"}},
		{"^0.0.3", []string{"0.0.3"}, []string{"0.0.4", "0.1.0"}},
		{"^1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0", "0.9.9"}},
		{"^1.2", []string{"1.2.0", "1.9.9"}, []string{"1.1.9", "2.0.0"}},
		{"^0", []string{"0.0.0", "0.9.9"}, []string{"1.0.0"}},
		{"^0.0", []string{"0.0.0", "0.0.9"}, []string{"0.1.0"}},
		{"0.0.3", []string{"0.0.3"}, []string{"0.0.4"}},
		{"~1.2.3", []string{"1.2.3", "1.2.9"}, []string{"1.3.0", "1.2.2"}},
		{"~1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"~1", []string{"1.0.0", "1.9.9"}, []string{"2.0.0"}},
		{"~1.2.3-beta.2", []string{"1.2.3-beta.2", "1.2.3-beta.4", "1.2.3", "1.2.4"}, []string{"1.2.3-beta.1", "1.2.4-beta.2", "1.3.3"}},
		// Wildcards.
		{"*", []string{"0.0.0", "99.0.0"}, []string{"1.0.0-pre"}},
		{"1.*", []string{"1.0.0", "1.9.9"}, []string{"2.0.0", "1.2.0-pre"}},
		{"1.2.*", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"1.x", []string{"1.5.0"}, []string{"2.0.0"}},
		// Comparison requirements, partial versions.
		{"=1.2.3", []string{"1.2.3", "1.2.3+build"}, []string{"1.2.4", "1.2.3-pre"}},
		{">1.2.3", []string{"1.2.4"}, []string{"1.2.3"}},
		{">1", []string{"2.0.0"}, []string{"1.9.9"}},
		{">=1.2", []string{"1.2.0"}, []string{"1.1.9"}},
		{"<1.2", []string{"1.1.9"}, []string{"1.2.0"}},
		{"<=1.2", []string{"1.2.9"}, []string{"1.3.0"}},
		{">= 1.2.0, < 1.5", []string{"1.2.0", "1.4.9"}, []string{"1.5.0", "1.1.0"}},
		// A pre-release matches only a comparator with a pre-release of the
		// same MAJOR.MINOR.PATCH.
		{">=1.2.3-alpha, <2", []string{"1.2.3-alpha", "1.2.3-beta", "1.2.3", "1.9.9"}, []string{"1.3.0-alpha", "2.0.0-alpha", "1.2.3-0"}},
		{">= 2.1.0-alpha2", []string{"2.1.0-alpha2", "2.1.0-alpha3", "2.1.0", "3.0.0"}, []string{"2.0.0", "2.1.0-alpha1", "3.0.0-alpha2"}},
		{">1.0.0-alpha, <1.0.0", []string{"1.0.0-beta"}, nil},
		{">1.0.0-alpha, <1", nil, []string{"1.0.0-beta"}},
		{"^0.5.1-alpha3", []string{"0.5.1-alpha3", "0.5.1-beta", "0.5.1", "0.5.5"}, []string{"0.5.1-alpha1", "0.5.2-alpha3", "0.6.0"}},
	})
	// Cargo has no ranges with "||", no hyphen ranges, no "v".
	checkInvalidConstraints(t, "cargo", "1.2.3 - 2.3.4", "^1.2 || ^2", "v1.2.3", "> 0.0.9 <= 2.5.3",
		"*, 1", "1, *", "1.*.3", "1.2.3-01", "=>1.2", "~>1.2", ">= >= 1", "1.2.3,", "1.2-pre",
		">1, >2, >3, >4, >5, >6, >7, >8, >9, >10, >11, >12, >13, >14, >15, >16, >17, >18, >19, >20, >21, >22, >23, >24, >25, >26, >27, >28, >29, >30, >31, >32, >33")
	// A dependency without a version key declares none.
	checkNoConstraint(t, "cargo", "", "   ")
}

func TestCargoVersions(t *testing.T) {
	checkInvalidVersions(t, "cargo", "1.2", "v1.2.3", " 1.2.3", "1.2.3 ", "01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+", "")
	checkAscending(t, "cargo", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		// Build metadata breaks ties, as the crate's Ord does.
		"1.0.0+0", "1.0.0+00", "1.0.0+1", "1.0.0+01", "1.0.0+a", "1.0.0+a.1", "1.0.1")
	checkPrerelease(t, "cargo", true, "1.0.0-0")
	checkPrerelease(t, "cargo", false, "1.0.0+pre")
}
