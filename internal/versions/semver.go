package versions

import (
	"strconv"
	"strings"
)

// semver is the SemVer 2.0 core that npm, Cargo and Go versions share:
// MAJOR.MINOR.PATCH, dot-separated pre-release identifiers and build
// metadata. The three ecosystems differ in what they accept around it and in
// whether build metadata orders; the precedence of everything else is
// SemVer 2.0 §11, which all three implement.
type semver struct {
	major, minor, patch int64
	pre                 []string
	build               []string
}

// compareMain orders major, minor and patch.
func (a *semver) compareMain(b *semver) int {
	if c := cmpInt64(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt64(a.minor, b.minor); c != 0 {
		return c
	}
	return cmpInt64(a.patch, b.patch)
}

// compare orders two versions by SemVer 2.0 precedence: build metadata does
// not count.
func (a *semver) compare(b *semver) int {
	if c := a.compareMain(b); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

// samePatch reports equal major, minor and patch.
func (a *semver) samePatch(b *semver) bool {
	return a.major == b.major && a.minor == b.minor && a.patch == b.patch
}

// comparePre orders pre-releases (SemVer 2.0 §11): a version without one
// ranks above one with; identifiers compare one by one, numeric ones
// numerically and below alphanumeric ones, which compare in ASCII order; a
// longer list ranks above its own prefix.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt64(int64(len(a)), int64(len(b)))
}

// compareIdent orders two pre-release identifiers. Numeric identifiers have
// no leading zeros in any scheme that uses this, so comparing digit strings by
// value is exact; they may exceed every integer type, so they are not
// converted. (node-semver converts them to floats beyond 2^53 and can call two
// different ones equal; the SemVer order is used here.)
func compareIdent(a, b string) int {
	an, bn := allDigits(a), allDigits(b)
	switch {
	case an && bn:
		return cmpDigits(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// readNumber reads a version number at s[i:] the strict way all three
// ecosystems require: "0" or a digit run without a leading zero, no larger
// than max. It returns the value and the index after it.
func readNumber(s string, i int, max int64) (int64, int, string) {
	j := i
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	switch {
	case j == i:
		return 0, i, "a number is missing"
	case s[i] == '0' && j-i > 1:
		return 0, i, "a number has a leading zero"
	}
	n, ok := parseDigits(s[i:j], max)
	if !ok {
		return 0, i, "a number is larger than " + strconv.FormatInt(max, 10)
	}
	return n, j, ""
}

// readIdentifiers reads dot-separated identifiers of [0-9A-Za-z-] at s[i:],
// up to the first byte that is neither. Empty identifiers are refused;
// numeric ones with a leading zero too when noLeadingZero (the rule for
// pre-release identifiers). It returns the identifiers and the index after
// them.
func readIdentifiers(s string, i int, noLeadingZero bool) ([]string, int, string) {
	var out []string
	start := i
	for {
		j := i
		for j < len(s) && (isAlnum(s[j]) || s[j] == '-') {
			j++
		}
		id := s[i:j]
		if id == "" {
			if j == start {
				return nil, start, "an identifier is missing"
			}
			return nil, start, "an identifier is empty"
		}
		if noLeadingZero && len(id) > 1 && id[0] == '0' && allDigits(id) {
			return nil, start, "a numeric identifier has a leading zero"
		}
		out = append(out, id)
		if j < len(s) && s[j] == '.' {
			i = j + 1
			continue
		}
		return out, j, ""
	}
}

// formatSemver writes major.minor.patch[-pre] the way node-semver formats a
// version.
func formatSemver(v *semver) string {
	var b strings.Builder
	b.WriteString(strconv.FormatInt(v.major, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatInt(v.minor, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatInt(v.patch, 10))
	if len(v.pre) > 0 {
		b.WriteByte('-')
		b.WriteString(strings.Join(v.pre, "."))
	}
	return b.String()
}
