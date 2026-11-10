package sbomdiff

import (
	"strconv"
	"strings"
)

// compareVersions compares two dotted version strings numerically segment by
// segment, returning -1 when a < b, 0 when equal, +1 when a > b, and ok=false
// when either side is not a clean dotted-numeric version (so the caller can fall
// back to a direction-agnostic "changed"). A leading "v" and a build/pre-release
// suffix after the first non-numeric segment are tolerated by treating that
// segment as 0; this is a best-effort ordering for reporting, not a full semver
// implementation (the gate never makes an admission decision on direction alone).
func compareVersions(a, b string) (int, bool) {
	as, aok := numericSegments(a)
	bs, bok := numericSegments(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		switch {
		case av < bv:
			return -1, true
		case av > bv:
			return 1, true
		}
	}
	return 0, true
}

// numericSegments parses the leading dotted-numeric portion of a version. It
// returns ok=false when the first segment is non-numeric (e.g. a date tag or a
// git hash) so the caller does not invent a misleading ordering.
func numericSegments(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return nil, false
	}
	// Cut any pre-release/build metadata: "1.2.3-rc1+build" -> "1.2.3".
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			if i == 0 {
				return nil, false
			}
			// A trailing non-numeric segment (e.g. "1.2.RELEASE") is treated as 0.
			n = 0
		}
		out = append(out, n)
	}
	return out, true
}
