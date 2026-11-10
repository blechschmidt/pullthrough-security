package remediation

import (
	"sort"
	"strconv"
	"strings"
)

// This file provides the version ordering the advisor uses to pick the *nearest*
// safe upgrade. It is a pragmatic SemVer-grade comparator (numeric release
// segments plus a precedence-correct prerelease tail) sufficient for ordering a
// registry's published version list; it deliberately does not implement range
// matching (that lives in the dependency-firewall gate, which the advisor reuses
// rather than reimplements). Versions it cannot parse are excluded from upgrade
// candidacy rather than mis-ordered, so the advisor never recommends a target it
// cannot prove is newer than the flagged version.

// parsedVersion is a decomposed version: the dotted numeric release segments and
// the optional dot-separated prerelease identifiers. ok is false when the string
// is not a recognizable dotted-numeric version.
type parsedVersion struct {
	nums []int
	pre  []string
	ok   bool
}

// parseVersion decomposes a version string. It tolerates a leading "v", strips
// build metadata ("+..."), and splits a prerelease tail ("-..."). A trailing
// non-numeric release segment (e.g. the Java "1.2.RELEASE") is treated as 0 so
// the leading numeric portion still orders; a non-numeric *first* segment makes
// the whole version unparseable (ok=false).
func parseVersion(s string) parsedVersion {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return parsedVersion{}
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	nums := make([]int, 0, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			if i == 0 {
				return parsedVersion{}
			}
			n = 0
		}
		nums = append(nums, n)
	}
	var preIDs []string
	if pre != "" {
		preIDs = strings.Split(pre, ".")
	}
	return parsedVersion{nums: nums, pre: preIDs, ok: true}
}

// isPrerelease reports whether a parseable version carries a prerelease tail.
func isPrerelease(s string) bool {
	p := parseVersion(s)
	return p.ok && len(p.pre) > 0
}

// compareVersions orders two version strings, returning -1 when a<b, 0 when
// equal, +1 when a>b, and ok=false when either side is unparseable (the caller
// then declines to treat them as ordered). Numeric release segments compare
// left-to-right (a missing segment is 0); when the release portions are equal a
// version WITH a prerelease tail sorts BEFORE one without (SemVer §11), and two
// prerelease tails compare identifier-by-identifier (numeric identifiers
// numerically, mixed/alpha lexically, a longer tail winning when otherwise
// equal).
func compareVersions(a, b string) (int, bool) {
	pa, pb := parseVersion(a), parseVersion(b)
	if !pa.ok || !pb.ok {
		return 0, false
	}
	if c := compareNums(pa.nums, pb.nums); c != 0 {
		return c, true
	}
	return comparePre(pa.pre, pb.pre), true
}

func compareNums(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

// comparePre implements SemVer prerelease precedence. An empty tail (a normal
// release) has higher precedence than any non-empty tail.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0: // a is a release, b is a prerelease → a is greater
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ai, aNum := atoiOK(a[i])
		bi, bNum := atoiOK(b[i])
		switch {
		case aNum && bNum:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		case aNum && !bNum: // numeric identifiers have lower precedence than alphanumeric
			return -1
		case !aNum && bNum:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func atoiOK(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// newerVersions returns the parseable versions strictly greater than base,
// ordered nearest-first (ascending), de-duplicated. Prerelease versions are
// excluded unless includePrerelease is set. Versions that do not parse, or that
// are not comparable to base, are dropped — the advisor only ever offers a
// target it can prove is a newer release.
func newerVersions(all []string, base string, includePrerelease bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range all {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		if !includePrerelease && isPrerelease(v) {
			continue
		}
		cmp, ok := compareVersions(v, base)
		if !ok || cmp <= 0 {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		c, ok := compareVersions(out[i], out[j])
		if !ok {
			return out[i] < out[j]
		}
		return c < 0
	})
	return out
}
