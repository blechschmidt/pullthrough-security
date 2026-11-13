package versions

import "testing"

// Cases from maven-artifact's tests (ComparableVersionTest, VersionRangeTest)
// and Maven's "Version Order Specification".

func TestMavenOrder(t *testing.T) {
	checkAscending(t, "maven", "1-alpha", "1-beta", "1-milestone", "1-rc", "1-SNAPSHOT", "1", "1-sp", "1-abc", "1-1")
	// ComparableVersionTest's VERSIONS_QUALIFIER and VERSIONS_NUMBER.
	checkAscending(t, "maven", "1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2",
		"1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def",
		"1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123")
	checkAscending(t, "maven", "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c",
		"2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11",
		"11.a", "11b", "11c", "11m")
	checkEquivalent(t, "maven", "1", "1.0", "1.0.0", "1-0", "1.0-0", "1-ga", "1-GA", "1-final", "1.0.Final", "1-release", "1.0.0.RELEASE")
	checkEquivalent(t, "maven", "1-cr", "1-rc", "1-RC")
	checkEquivalent(t, "maven", "1a1", "1-a1", "1-alpha-1", "1-alpha1", "1.0-ALPHA-1")
	checkEquivalent(t, "maven", "1x", "1-x", "1.0x", "1.0-x", "1.0.0-x")
	checkAscending(t, "maven", "1.0-alpha-1", "1.0-SNAPSHOT", "1.0", "1.0.1", "1.1", "2.0-alpha-1", "2.0-SNAPSHOT", "2.0")
	checkAscending(t, "maven", "31.1-android", "31.1-jre", "32.0.0-android")
	// ComparableVersion widens a number's type by its length and compares
	// the type first.
	checkAscending(t, "maven", "1.0.1", "1.0000000000.1")
}

func TestMavenVersions(t *testing.T) {
	checkPrerelease(t, "maven", true, "1.0-SNAPSHOT", "2.0.0-M1", "1.0-RC1", "1.0-cr1", "1.0-alpha-1", "1.0-beta", "1.0.0-a1")
	checkPrerelease(t, "maven", false, "1.0", "31.1-jre", "1.0-sp1", "1.0-final", "1.0.0.RELEASE", "1.0-a", "1.0-pre")
	// Shapes on which ComparableVersion is no total order (1-alpha < 1 <
	// 1.final.1 < 1-alpha in Maven), other characters, numbers beyond int64.
	checkInvalidVersions(t, "maven", "1.final.1", "1-0.alpha", "1.0.0-alpha.beta.1", "1.0.0-x.7.z.92", "v1.0",
		"alpha", "1.0 beta", "${project.version}", "1.0~1", "[1.0]", "", "9223372036854775808")
	for _, ok := range []string{"7.1.0.Final-redhat-1", "2.0.0.v20100429", "1.0.0-alpha.1", "1.0.Alpha1-SNAPSHOT", "4.3.0.RELEASE", "RELEASE", "1.0_01", "1.0+build"} {
		mustParse(t, mustScheme(t, "maven"), ok)
	}
	if r := mustParse(t, mustScheme(t, "maven"), "1.10-SNAPSHOT").Release(); r[0] != 1 || r[1] != 10 || r[2] != 0 {
		t.Errorf("Release(1.10-SNAPSHOT) = %v", r)
	}
}

func TestMavenRanges(t *testing.T) {
	checkAllows(t, "maven", []allowCase{
		// Maven ranges have no pre-release rule: 2.0-SNAPSHOT orders below 2.0.
		{"[1.0,2.0)", []string{"1.0", "1.5", "1.99", "2.0-alpha-1", "2.0-SNAPSHOT"}, []string{"0.9", "2.0", "2.0.0"}},
		{"(,1.0]", []string{"0.5", "1.0", "1.0.0"}, []string{"1.0.1", "1.0-sp1"}},
		{"[1.2]", []string{"1.2", "1.2.0"}, []string{"1.2.1", "1.1"}},
		{"[1.0,)", []string{"1.0", "99"}, []string{"0.9"}},
		{"(1.0,2.0)", []string{"1.0.1"}, []string{"1.0", "2.0"}},
		{"(,1.0],[1.2,)", []string{"1.0", "1.2", "5.0"}, []string{"1.1", "1.1.9"}},
		{"(,1.0),[1.0,)", []string{"0.1", "1.0", "9"}, nil},
		{" [1.0 , 2.0) ", []string{"1.5"}, []string{"2.0"}},
	})
	// A bare version is a soft requirement.
	checkNoConstraint(t, "maven", "1.0", "1.0-SNAPSHOT", "LATEST", "RELEASE", "", " ", "1.0]")
	checkInvalidConstraints(t, "maven", "(1.0)", "[1.0)", "[1.0", "[2.0,1.0]", "[1.0,1.0)",
		"[1.0,3.0),[2.0,4.0)", "[1.0,2.0)x", "[1.0,2.0),1.5", "[1.0,2.0,3.0]", "[]", "[${a},${b})",
		"${project.version}", "[1.final.1,2)")
}
