package secretscan

import (
	"regexp"
	"strconv"
	"strings"
)

// AddedLine is a single line added by a diff, with its line number in the
// post-change file when derivable.
type AddedLine struct {
	// Text is the added content without the leading '+' marker.
	Text string
	// Line is the 1-based line number in the new file, or 0 when it cannot be
	// determined (a patch without hunk headers).
	Line int
}

// hunkHeaderRe matches a unified-diff hunk header, capturing the new-file start
// line: "@@ -a,b +c,d @@" (the count is optional: "+c").
var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// AddedLines extracts the added lines from a unified-diff patch, assigning each
// its line number in the new file. Only lines beginning with a single '+' are
// returned; file headers ("+++"), removals, and context lines are skipped (the
// latter only advance the line counter).
//
// When the patch carries no hunk headers (some backends emit a header-less body
// for new files), every '+'-prefixed line is still returned with Line 0 so the
// content is scanned even though it cannot be localized.
func AddedLines(patch string) []AddedLine {
	if patch == "" {
		return nil
	}
	var out []AddedLine
	curLine := 0
	inHunk := false

	lines := strings.Split(patch, "\n")
	for _, raw := range lines {
		switch {
		case strings.HasPrefix(raw, "@@"):
			if m := hunkHeaderRe.FindStringSubmatch(raw); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					curLine = n
					inHunk = true
				}
			}
			continue
		case strings.HasPrefix(raw, "+++") || strings.HasPrefix(raw, "---"):
			// File header lines, never content.
			continue
		case strings.HasPrefix(raw, "+"):
			out = append(out, AddedLine{Text: raw[1:], Line: lineNumber(inHunk, curLine)})
			if inHunk {
				curLine++
			}
		case strings.HasPrefix(raw, "-"):
			// Removed line: does not exist in the new file; do not advance.
		case strings.HasPrefix(raw, "\\"):
			// "\ No newline at end of file" — metadata, ignore.
		default:
			// Context line (leading space) or stray text: advances the new-file
			// cursor when inside a hunk.
			if inHunk {
				curLine++
			}
		}
	}
	return out
}

// lineNumber returns the current new-file line number, or 0 when not inside a
// recognized hunk.
func lineNumber(inHunk bool, cur int) int {
	if inHunk {
		return cur
	}
	return 0
}
