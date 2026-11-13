package versions

import (
	"strings"
)

// golang follows golang.org/x/mod/semver, the version semantics of Go
// modules (without depending on it):
//
//   - A version starts with "v": vMAJOR[.MINOR[.PATCH[-PRE][+BUILD]]], the
//     shorthands v1 and v1.2 standing for v1.0.0 and v1.2.0. Build metadata
//     does not order; "+incompatible" marks a v2+ module without a go.mod.
//   - Pseudo-versions (v0.0.0-20210101000000-abcdef123456,
//     v1.2.4-0.20210101000000-abcdef123456, v1.2.3-pre.0.2021...) are
//     pre-releases, as the go command treats them.
//
// Go has no version ranges: a go.mod requirement is a minimum, and minimal
// version selection may move to any newer version with the same module path —
// SameMajor. ParseConstraint accepts only ">=vX.Y.Z" for convenience; anything
// else, a bare module version included, is ErrNoConstraint.
//
// Deviation: version numbers are int64 where x/mod compares digit strings of
// any length (larger ones are an error).
type goScheme struct{}

func (goScheme) Name() string { return "go" }

type goVersion struct {
	raw string
	v   semver
}

func (v *goVersion) String() string   { return v.raw }
func (v *goVersion) Prerelease() bool { return len(v.v.pre) > 0 }
func (v *goVersion) Release() []int64 { return []int64{v.v.major, v.v.minor, v.v.patch} }
func (v *goVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "go"
}

// incompatible reports the "+incompatible" build suffix.
func (v *goVersion) incompatible() bool {
	return len(v.v.build) == 1 && v.v.build[0] == "incompatible"
}

func (goScheme) own(v Version) (*goVersion, bool) {
	if x, ok := v.(*goVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseGoVersion(v.String())
	return x, err == nil
}

// Parse is semver.IsValid with the parse that backs it.
func (goScheme) Parse(s string) (Version, error) {
	v, err := parseGoVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func parseGoVersion(s string) (*goVersion, error) {
	if err := checkLength("go", "version", s); err != nil {
		return nil, err
	}
	if s == "" || s[0] != 'v' {
		return nil, errorf("go", s, "a module version starts with \"v\"")
	}
	var v semver
	var err string
	i := 1
	if v.major, i, err = readNumber(s, i, maxInt64); err != "" {
		return nil, errorf("go", s, "major version: %s", err)
	}
	if i < len(s) && s[i] == '.' {
		if v.minor, i, err = readNumber(s, i+1, maxInt64); err != "" {
			return nil, errorf("go", s, "minor version: %s", err)
		}
		if i < len(s) && s[i] == '.' {
			if v.patch, i, err = readNumber(s, i+1, maxInt64); err != "" {
				return nil, errorf("go", s, "patch version: %s", err)
			}
			if i < len(s) && s[i] == '-' {
				if v.pre, i, err = readIdentifiers(s, i+1, true); err != "" {
					return nil, errorf("go", s, "pre-release: %s", err)
				}
			}
			if i < len(s) && s[i] == '+' {
				if v.build, i, err = readIdentifiers(s, i+1, false); err != "" {
					return nil, errorf("go", s, "build metadata: %s", err)
				}
			}
		}
	}
	if i != len(s) {
		return nil, errorf("go", s, "not a semantic version")
	}
	return &goVersion{raw: s, v: v}, nil
}

// Compare is semver.Compare: build metadata does not count.
func (s goScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return x.v.compare(&y.v)
}

// ParseConstraint accepts ">=vX.Y.Z" only; every other expression is
// ErrNoConstraint, since Go declares no ranges (see SameMajor).
func (goScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("go", "constraint", expr); err != nil {
		return nil, err
	}
	t := strings.TrimSpace(expr)
	if !strings.HasPrefix(t, ">=") {
		return nil, noConstraint("go", expr, "no range (Go modules declare minimum versions; see SameMajor)")
	}
	v, err := parseGoVersion(strings.TrimSpace(t[2:]))
	if err != nil {
		return nil, err
	}
	return &goAtLeast{raw: t, min: v}, nil
}

// goAtLeast is ">=v".
type goAtLeast struct {
	raw string
	min *goVersion
}

func (c *goAtLeast) String() string { return c.raw }

func (c *goAtLeast) Allows(v Version) bool {
	x, ok := goScheme{}.own(v)
	return ok && x.v.compare(&c.min.v) >= 0
}

// IsPseudoVersion reports whether v is a Go pseudo-version
// (module.IsPseudoVersion): vX.0.0-yyyymmddhhmmss-abcdef123456,
// vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdef123456 or
// vX.Y.Z-pre.0.yyyymmddhhmmss-abcdef123456, with optional build metadata. A
// registry lists tagged versions; a pseudo-version names a commit.
func IsPseudoVersion(v Version) bool {
	g, ok := goScheme{}.own(v)
	if !ok || len(g.v.pre) == 0 {
		return false
	}
	// The pre-release, as text, ends in "<14-digit timestamp>-<revision>";
	// with a base it starts "0." (release base) or "<pre>.0." (pre-release
	// base), and without one it is the timestamp alone on a vX.0.0.
	pre := strings.Join(g.v.pre, ".")
	dash := strings.LastIndexByte(pre, '-')
	if dash < 0 || dash+1 >= len(pre) {
		return false
	}
	for i := dash + 1; i < len(pre); i++ {
		if !isAlnum(pre[i]) {
			return false
		}
	}
	head := pre[:dash]
	if len(head) < 14 || !allDigits(head[len(head)-14:]) {
		return false
	}
	base := head[:len(head)-14]
	switch {
	case base == "":
		return g.v.minor == 0 && g.v.patch == 0
	case base == "0.":
		return true
	case strings.HasSuffix(base, ".0."):
		return len(base) > len(".0.")
	}
	return false
}
