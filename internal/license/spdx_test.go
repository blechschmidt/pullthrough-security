package license

import (
	"reflect"
	"testing"
)

func TestParseExpression_Valid(t *testing.T) {
	cases := []struct {
		in        string
		canonical string
		licenses  []string
	}{
		{"MIT", "MIT", []string{"MIT"}},
		{"  apache-2.0  ", "apache-2.0", []string{"apache-2.0"}},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"MIT AND Apache-2.0", "MIT AND Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"Apache-2.0+", "Apache-2.0+", []string{"Apache-2.0"}},
		{"GPL-2.0-or-later WITH Classpath-exception-2.0", "GPL-2.0-or-later WITH Classpath-exception-2.0", []string{"GPL-2.0-or-later"}},
		// Precedence: AND binds tighter than OR.
		{"MIT OR BSD-3-Clause AND Apache-2.0", "MIT OR BSD-3-Clause AND Apache-2.0", []string{"Apache-2.0", "BSD-3-Clause", "MIT"}},
		// Parentheses override and canonical rendering parenthesizes OR under AND.
		{"(MIT OR Apache-2.0) AND ISC", "(MIT OR Apache-2.0) AND ISC", []string{"Apache-2.0", "ISC", "MIT"}},
		// Lowercase operators are accepted.
		{"MIT or Apache-2.0", "MIT OR Apache-2.0", []string{"Apache-2.0", "MIT"}},
		{"LicenseRef-Custom-1", "LicenseRef-Custom-1", []string{"LicenseRef-Custom-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			e, err := ParseExpression(tc.in)
			if err != nil {
				t.Fatalf("ParseExpression(%q) error: %v", tc.in, err)
			}
			if e.String() != tc.canonical {
				t.Errorf("canonical = %q, want %q", e.String(), tc.canonical)
			}
			if got := e.Licenses(); !reflect.DeepEqual(got, tc.licenses) {
				t.Errorf("Licenses() = %v, want %v", got, tc.licenses)
			}
		})
	}
}

func TestParseExpression_Invalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"MIT AND",
		"OR MIT",
		"(MIT",
		"MIT)",
		"MIT WITH",
		"(MIT OR Apache-2.0) WITH Classpath-exception-2.0", // WITH on a group
		"MIT Apache-2.0", // missing operator
		"@@@",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseExpression(in); err == nil {
				t.Errorf("ParseExpression(%q) expected error, got nil", in)
			}
		})
	}
}

func TestParseExpression_WITHExceptionPreserved(t *testing.T) {
	e, err := ParseExpression("GPL-3.0-only WITH GCC-exception-3.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, ok := e.root.(licenseNode)
	if !ok {
		t.Fatalf("root is %T, want licenseNode", e.root)
	}
	if ln.id != "GPL-3.0-only" || ln.exception != "GCC-exception-3.1" {
		t.Errorf("got id=%q exception=%q", ln.id, ln.exception)
	}
}

func TestParseExpression_OrLater(t *testing.T) {
	e, err := ParseExpression("LGPL-2.1+")
	if err != nil {
		t.Fatal(err)
	}
	ln := e.root.(licenseNode)
	if ln.id != "LGPL-2.1" || !ln.orLater {
		t.Errorf("got id=%q orLater=%v, want LGPL-2.1 orLater=true", ln.id, ln.orLater)
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"gpl-*", "gpl-3.0-only", true},
		{"gpl-*", "lgpl-3.0-only", false},
		{"*gpl*", "lgpl-3.0-only", true},
		{"*gpl*", "agpl-3.0-only", true},
		{"mit", "mit", true},
		{"mit", "mit-0", false},
		{"*", "anything", true},
		{"bsd-*-clause", "bsd-3-clause", true},
		{"bsd-*-clause", "bsd-3-clause-clear", false},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.s); got != tc.want {
			t.Errorf("matchGlob(%q,%q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
