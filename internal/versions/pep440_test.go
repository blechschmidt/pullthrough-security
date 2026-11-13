package versions

import "testing"

// Cases from packaging's tests (tests/test_version.py,
// tests/test_specifiers.py) and PEP 440's examples.

func TestPEP440Versions(t *testing.T) {
	// packaging's VERSIONS list, ascending.
	checkAscending(t, "pip",
		"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
		"1.0b2.post345.dev456", "1.0b2.post345", "1.0c1.dev456", "1.0c1", "1.0rc2", "1.0c3", "1.0",
		"1.0.post456.dev34", "1.0.post456", "1.1.dev1", "1.2+123abc", "1.2+123abc456", "1.2+abc",
		"1.2+abc123", "1.2+abc123def", "1.2+1234.abc", "1.2+123456", "1.2.r32+123456", "1.2.rev33+123456",
		"1!1.0.dev456", "1!1.0a1", "1!1.0", "1!1.0.post456", "1!1.2.rev33+123456")
	// Normalization: alternative spellings, implicit numbers, case,
	// insignificant trailing zeros.
	checkEquivalent(t, "pip", "1.0", "1.0.0", "1", "v1.0", "V1.0.0.0", " 1.0 ", "0!1.0")
	checkEquivalent(t, "pip", "1.0a1", "1.0alpha1", "1.0-a1", "1.0.A1", "1.0_alpha-1", "1.0a.1")
	checkEquivalent(t, "pip", "1.0rc0", "1.0c", "1.0pre", "1.0preview", "1.0-RC")
	checkEquivalent(t, "pip", "1.0.post1", "1.0post1", "1.0-1", "1.0.r1", "1.0-rev1", "1.0_post_1")
	checkEquivalent(t, "pip", "1.0.dev0", "1.0dev", "1.0-DEV", "1.0.dev")
	checkEquivalent(t, "pip", "1.0+abc.7", "1.0+ABC-007", "1.0+abc_7")
	for in, want := range map[string]string{
		"1.0ALPHA1": "1.0a1", "v1.0-2": "1.0.post2", "01.002.0-RC.3": "1.2.0rc3", "1!2.0.dev": "1!2.0.dev0",
		"1.0+Local.007": "1.0+local.7", "1.0a.post.dev": "1.0a0.post0.dev0",
	} {
		v := mustParse(t, mustScheme(t, "pip"), in)
		if got := v.(*pep440Version).normalized(); got != want {
			t.Errorf("%q normalizes to %q, want %q", in, got, want)
		}
	}
	checkInvalidVersions(t, "pip", "1.0.", "1.0-", "1.0+", "1.0+a..b", "french toast", "1.0.dev.1.dev",
		"1.0re", "1!", "!1.0", "1.0.*", "1.0 a1", "")
	checkPrerelease(t, "pip", true, "1.0a1", "1.0.dev0", "1.0rc1.post1", "1.0.post1.dev1")
	checkPrerelease(t, "pip", false, "1.0", "1.0.post1", "1.0+dev")
}

func TestPEP440Specifiers(t *testing.T) {
	checkAllows(t, "pip", []allowCase{
		// Compatible release: ~=1.4.5 is >=1.4.5, ==1.4.*.
		{"~=1.4.5", []string{"1.4.5", "1.4.9", "1.4.5.post1"}, []string{"1.4.4", "1.5.0", "1.4.6a1"}},
		{"~=1.4", []string{"1.4", "1.9"}, []string{"2.0", "1.3"}},
		{"~=2.2.post3", []string{"2.2.post3", "2.9"}, []string{"2.2", "3.0"}},
		{"~=1.4.5a4", []string{"1.4.5a4", "1.4.5", "1.4.6a1"}, []string{"1.5", "1.4.5a3"}},
		// Prefix matching.
		{"==1.1.*", []string{"1.1", "1.1.0", "1.1.5", "1.1.post1"}, []string{"1.10", "1.2", "1.1a1"}},
		{"!=1.1.*", []string{"1.0", "1.2", "1.10"}, []string{"1.1", "1.1.3"}},
		{"==1.0.*", []string{"1"}, nil},
		// Exclusive ordered comparisons.
		{"<1.0", []string{"0.9"}, []string{"1.0", "1.0rc1", "1.0.dev0"}},
		{">1.0", []string{"1.0.1", "1.1"}, []string{"1.0", "1.0.post1", "1.0+local"}},
		{">1.0.post1", []string{"1.0.post2"}, []string{"1.0.post1"}},
		{">=1.0a1,<1.0", nil, []string{"1.0a1", "1.0rc1", "1.0"}},
		{"<1.0rc2,>=1.0a1", []string{"1.0a1", "1.0rc1"}, []string{"1.0rc2"}},
		// Pre-releases only when a specifier names one.
		{">=1.0rc1", []string{"1.0rc1", "1.0rc2", "1.0", "2.0a1"}, []string{"1.0b1"}},
		{">=1.0", []string{"1.0", "2.0"}, []string{"2.0a1", "1.1.dev0"}},
		{">1.0a1", []string{"1.0"}, []string{"1.0b1"}},
		{"", []string{"1.0", "0.0.1"}, []string{"1.0a1"}},
		// Local versions and epochs.
		{"==1.0", []string{"1.0", "1.0+local"}, []string{"1.0.1"}},
		{"==1.0+local", []string{"1.0+local"}, []string{"1.0", "1.0+other"}},
		{"<=1.0", []string{"1.0+local"}, []string{"1.0.1"}},
		{">=1!1.0", []string{"1!1.0", "1!2.0"}, []string{"2.0", "99.0"}},
		{"===1.0", []string{"1.0"}, []string{"1.0.0", "1.0+local"}},
		{">= 1.0, < 2.0", []string{"1.5"}, []string{"2.0"}},
		{">=1.0,,<2.0", []string{"1.5"}, []string{"2.0"}},
		{">=1.0.0,!=1.0.1,<1.1", []string{"1.0.0", "1.0.2"}, []string{"1.0.1", "1.1"}},
	})
	checkInvalidConstraints(t, "pip", "1.0", "~=1", "~=1.0.*", ">=1.0.*", "==1.0a1.*", "<1.0+local",
		"~=1.0+local", "requests>=1.0", ">=1.0 <2.0", "=1.0", "===foobar", "===", ">= 1.0;python_version>'3'")
}
