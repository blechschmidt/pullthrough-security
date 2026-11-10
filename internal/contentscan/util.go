package contentscan

import (
	"strconv"
	"strings"
)

// maxExcerpt bounds the rendered excerpt so a finding stays legible and never
// leaks a large blob into logs/SARIF.
const maxExcerpt = 200

// excerpt collapses runs of whitespace and bounds the length of a match
// rendering.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxExcerpt {
		return s[:maxExcerpt] + "…"
	}
	return s
}

// splitLines splits text into lines without a trailing-newline empty element.
func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// humanBytes renders a byte count compactly (e.g. "4.0 KiB").
func humanBytes(n int) string {
	const unit = 1024
	if n < unit {
		return strconv.Itoa(n) + " B"
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	return strconv.FormatFloat(val, 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "iB"
}

// formatEntropy renders a bits/byte entropy value to 2 decimals.
func formatEntropy(e float64) string {
	return strconv.FormatFloat(e, 'f', 2, 64)
}

func itoa(n int) string { return strconv.Itoa(n) }
