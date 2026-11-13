package versions

import (
	"errors"
	"testing"
)

// allowCase is one constraint with versions it must allow and versions it
// must not.
type allowCase struct {
	constraint string
	allowed    []string
	denied     []string
}

func mustScheme(t *testing.T, name string) Scheme {
	t.Helper()
	s, ok := For(name)
	if !ok {
		t.Fatalf("no scheme %q", name)
	}
	return s
}

func mustParse(t *testing.T, s Scheme, text string) Version {
	t.Helper()
	v, err := s.Parse(text)
	if err != nil {
		t.Fatalf("%s: Parse(%q): %v", s.Name(), text, err)
	}
	return v
}

// checkAllows holds each case's constraint to its allowed and denied
// versions.
func checkAllows(t *testing.T, scheme string, cases []allowCase) {
	t.Helper()
	s := mustScheme(t, scheme)
	for _, tc := range cases {
		c, err := s.ParseConstraint(tc.constraint)
		if err != nil {
			t.Errorf("%s: ParseConstraint(%q): %v", scheme, tc.constraint, err)
			continue
		}
		for _, v := range tc.allowed {
			if !c.Allows(mustParse(t, s, v)) {
				t.Errorf("%s: %q does not allow %q", scheme, tc.constraint, v)
			}
		}
		for _, v := range tc.denied {
			if c.Allows(mustParse(t, s, v)) {
				t.Errorf("%s: %q allows %q", scheme, tc.constraint, v)
			}
		}
	}
}

// checkAscending holds versions to strictly ascending order, every pair
// checked both ways.
func checkAscending(t *testing.T, scheme string, versions ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	parsed := make([]Version, len(versions))
	for i, v := range versions {
		parsed[i] = mustParse(t, s, v)
	}
	for i := range parsed {
		for j := range parsed {
			want := cmpInt64(int64(i), int64(j))
			if got := s.Compare(parsed[i], parsed[j]); got != want {
				t.Errorf("%s: Compare(%q, %q) = %d, want %d", scheme, versions[i], versions[j], got, want)
			}
		}
	}
}

// checkEquivalent holds versions to comparing equal.
func checkEquivalent(t *testing.T, scheme string, versions ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	first := mustParse(t, s, versions[0])
	for _, v := range versions[1:] {
		if c := s.Compare(first, mustParse(t, s, v)); c != 0 {
			t.Errorf("%s: Compare(%q, %q) = %d, want 0", scheme, versions[0], v, c)
		}
	}
}

// checkNoConstraint holds exprs to ErrNoConstraint.
func checkNoConstraint(t *testing.T, scheme string, exprs ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	for _, e := range exprs {
		c, err := s.ParseConstraint(e)
		if !errors.Is(err, ErrNoConstraint) {
			t.Errorf("%s: ParseConstraint(%q) = %v, %v; want ErrNoConstraint", scheme, e, c, err)
		}
	}
}

// checkInvalidConstraints holds exprs to an error that is not
// ErrNoConstraint.
func checkInvalidConstraints(t *testing.T, scheme string, exprs ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	for _, e := range exprs {
		c, err := s.ParseConstraint(e)
		if err == nil || errors.Is(err, ErrNoConstraint) {
			t.Errorf("%s: ParseConstraint(%q) = %v, %v; want an error", scheme, e, c, err)
		}
	}
}

// checkInvalidVersions holds texts to a Parse error.
func checkInvalidVersions(t *testing.T, scheme string, texts ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	for _, text := range texts {
		if v, err := s.Parse(text); err == nil {
			t.Errorf("%s: Parse(%q) = %v, want an error", scheme, text, v)
		}
	}
}

// checkPrerelease holds each version's Prerelease to want.
func checkPrerelease(t *testing.T, scheme string, want bool, texts ...string) {
	t.Helper()
	s := mustScheme(t, scheme)
	for _, text := range texts {
		if got := mustParse(t, s, text).Prerelease(); got != want {
			t.Errorf("%s: %q Prerelease() = %v, want %v", scheme, text, got, want)
		}
	}
}
