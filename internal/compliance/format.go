package compliance

import "strconv"

// itoa formats an int.
func itoa(n int) string { return strconv.Itoa(n) }

// itoa64 formats an int64.
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// pctDetail renders a "N/M (P%) <suffix>" fragment used in control details.
func pctDetail(num, den int64, suffix string) string {
	pct := 0.0
	if den > 0 {
		pct = float64(num) / float64(den) * 100
	}
	return itoa64(num) + "/" + itoa64(den) + " (" + strconv.FormatFloat(pct, 'f', 1, 64) + "%) " + suffix
}

// humanizeAge renders an age in seconds as a compact human string.
func humanizeAge(seconds int64) string {
	switch {
	case seconds < 60:
		return itoa64(seconds) + "s"
	case seconds < 3600:
		return itoa64(seconds/60) + "m"
	case seconds < 86400:
		return itoa64(seconds/3600) + "h"
	default:
		return itoa64(seconds/86400) + "d"
	}
}
