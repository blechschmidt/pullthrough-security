package versions

import "testing"

// Cases from RubyGems' tests (test/rubygems/test_gem_version.rb,
// test_gem_requirement.rb) and the "Patterns" guide on pessimistic
// requirements.

func TestRubyGemsVersions(t *testing.T) {
	checkAscending(t, "rubygems", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1",
		"1.0.0-1", "1")
	checkEquivalent(t, "rubygems", "1.0.0-rc.1", "1.0.0-rc1", "1.0.0.pre.rc.1")
	checkAscending(t, "rubygems", "0.a", "0.0.1", "0.1", "1.0.a", "1.0.b1", "1.0", "1.0.0.1", "1.0.1",
		"1.9.3.alpha.5", "1.9.3", "1.10.0", "2.0.pre", "2", "5.2.4.rc1", "5.2.4", "5.2.4.1")
	checkEquivalent(t, "rubygems", "1.0", "1.0.0", "1", "1.00", " 1.0 ", "1.0.0.0.0")
	checkEquivalent(t, "rubygems", "1.2.b1", "1.2.b.1")
	checkEquivalent(t, "rubygems", "1.0.a", "1.a", "1.0.0.a")
	checkEquivalent(t, "rubygems", "", "0", "0.0")
	checkInvalidVersions(t, "rubygems", "junk", "1.0\n2.0", "1..2", "1.2\\ 3.4", "2.3422222.222.222222222.22222.ads0as.dasd0.ddd2222.2.qd3e.",
		"1.0.", ".1", "1.0-", "-1", "1.0+1", "1.0_1", "9223372036854775808")
	checkPrerelease(t, "rubygems", true, "1.0.0.pre", "1.0.0.rc1", "1.0.0-1", "1.A")
	checkPrerelease(t, "rubygems", false, "1.0.0", "1.2.3.4")
}

func TestRubyGemsRequirements(t *testing.T) {
	checkAllows(t, "rubygems", []allowCase{
		// Pessimistic: ~> 2.2 is >= 2.2, < 3; ~> 2.2.0 is >= 2.2.0, < 2.3.
		{"~> 2.2", []string{"2.2", "2.2.1", "2.9"}, []string{"2.1", "3.0", "3"}},
		{"~> 2.2.0", []string{"2.2.0", "2.2.9"}, []string{"2.3", "2.1.9"}},
		{"~> 2", []string{"2.0", "2.9"}, []string{"3.0", "1.9"}},
		{"~> 0", []string{"0.0.1", "0.9"}, []string{"1.0"}},
		{"~> 1.0.0.pre", []string{"1.0.0.pre", "1.0.0", "1.0.9", "1.0.1.pre"}, []string{"1.1.0", "0.9"}},
		{"~> 5.2.4, >= 5.2.4.1", []string{"5.2.4.1", "5.2.9"}, []string{"5.2.4", "5.3"}},
		// A bare version is "=".
		{"1.0", []string{"1.0", "1.0.0"}, []string{"1.0.1"}},
		{"= 1.0", []string{"1.0.0"}, []string{"1.1"}},
		{"!= 1.0", []string{"1.1", "0.9"}, []string{"1.0", "1.0.0"}},
		{"> 1.0", []string{"1.0.1"}, []string{"1.0"}},
		{"< 1.0", []string{"0.9"}, []string{"1.0"}},
		{">= 1.0", []string{"1.0", "2.0"}, []string{"0.9"}},
		{"<= 1.0", []string{"1.0", "0.9"}, []string{"1.0.1"}},
		{"> 0.0.0.1", []string{"0.0.1.0"}, nil},
		{"> 1.111", []string{"1.112"}, nil},
		{">= 1.0, < 2.0", []string{"1.0", "1.9"}, []string{"2.0", "0.9"}},
		{" >= 1.0 , < 2.0 ", []string{"1.5"}, []string{"2.0"}},
		// A pre-release only when a condition names one.
		{">= 1.0", nil, []string{"2.0.pre", "1.1.a"}},
		{">= 1.0.a", []string{"1.0.a", "1.0.b", "2.0.pre", "1.0"}, []string{"0.9"}},
		{"", []string{"0", "99"}, []string{"1.0.pre"}},
	})
	checkInvalidConstraints(t, "rubygems", "== 1.0", "=> 1.0", "=< 1.0", "> = 1.0", "~ 1.0", "^1.0",
		"1.0 2.0", ">= 1.0 < 2.0", ",", ">= 1.0,", ">", "~>", "junk", ">= 1.0;")
}
