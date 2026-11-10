package watch

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// parsePatch splits the unified-diff text produced by `git show --format=` into
// one commit.FileDiff per changed file. It is a pure function so it can be unit
// tested against representative diff fixtures. maxFiles bounds the number of
// files returned; maxPatchBytes truncates an individual file's retained patch
// text (the pipeline's token chunker bounds the overall request size).
func parsePatch(diff string, maxFiles, maxPatchBytes int) []commit.FileDiff {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	segments := splitDiffSegments(diff)
	out := make([]commit.FileDiff, 0, len(segments))
	for _, seg := range segments {
		if maxFiles > 0 && len(out) >= maxFiles {
			break
		}
		fd := parseFileSegment(seg, maxPatchBytes)
		if fd.Path == "" {
			continue
		}
		out = append(out, fd)
	}
	return out
}

// splitDiffSegments breaks the combined diff into per-file segments, each
// starting at a "diff --git " line.
func splitDiffSegments(diff string) []string {
	lines := strings.Split(diff, "\n")
	var segments []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			segments = append(segments, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, ln := range lines {
		if strings.HasPrefix(ln, "diff --git ") {
			flush()
		}
		cur = append(cur, ln)
	}
	flush()
	// Drop a leading segment that is not a real file diff (e.g. a stray blank
	// line before the first "diff --git").
	if len(segments) > 0 && !strings.HasPrefix(segments[0], "diff --git ") {
		segments = segments[1:]
	}
	return segments
}

// parseFileSegment derives a FileDiff from one "diff --git ..." segment.
func parseFileSegment(seg string, maxPatchBytes int) commit.FileDiff {
	var fd commit.FileDiff
	lines := strings.Split(seg, "\n")
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "diff --git "):
			a, b := parseDiffGitPaths(ln)
			if b != "" {
				fd.Path = b
			} else if a != "" {
				fd.Path = a
			}
			if a != "" && b != "" && a != b {
				fd.OldPath = a
			}
		case strings.HasPrefix(ln, "new file mode"):
			fd.Status = "A"
		case strings.HasPrefix(ln, "deleted file mode"):
			fd.Status = "D"
		case strings.HasPrefix(ln, "rename from "):
			fd.OldPath = strings.TrimSpace(strings.TrimPrefix(ln, "rename from "))
			fd.Status = "R"
		case strings.HasPrefix(ln, "rename to "):
			fd.Path = strings.TrimSpace(strings.TrimPrefix(ln, "rename to "))
			if fd.Status == "" {
				fd.Status = "R"
			}
		case strings.HasPrefix(ln, "copy from "):
			fd.OldPath = strings.TrimSpace(strings.TrimPrefix(ln, "copy from "))
			fd.Status = "C"
		case strings.HasPrefix(ln, "Binary files "), strings.HasPrefix(ln, "GIT binary patch"):
			fd.Binary = true
		case strings.HasPrefix(ln, "+++ b/"):
			if p := strings.TrimPrefix(ln, "+++ b/"); p != "" && p != "dev/null" {
				fd.Path = p
			}
		case strings.HasPrefix(ln, "--- a/"):
			if fd.OldPath == "" {
				if p := strings.TrimPrefix(ln, "--- a/"); p != "" && p != "dev/null" && p != fd.Path {
					fd.OldPath = p
				}
			}
		}
	}

	fd.Additions, fd.Deletions = countChanges(lines)
	if fd.Status == "" {
		fd.Status = "M"
	}
	if !fd.Binary {
		fd.Patch = truncatePatch(seg, maxPatchBytes)
	}
	return fd
}

// parseDiffGitPaths extracts the a/ and b/ paths from a "diff --git a/x b/y"
// line. It handles unquoted paths without spaces (the common case); paths with
// spaces fall back to the +++/--- lines parsed by the caller.
func parseDiffGitPaths(ln string) (a, b string) {
	rest := strings.TrimPrefix(ln, "diff --git ")
	fields := strings.Fields(rest)
	if len(fields) >= 2 {
		a = strings.TrimPrefix(fields[0], "a/")
		b = strings.TrimPrefix(fields[len(fields)-1], "b/")
	}
	return a, b
}

// countChanges tallies added/removed lines in the hunk body, excluding the
// file-header lines (+++/---).
func countChanges(lines []string) (add, del int) {
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "+++"), strings.HasPrefix(ln, "---"):
			continue
		case strings.HasPrefix(ln, "+"):
			add++
		case strings.HasPrefix(ln, "-"):
			del++
		}
	}
	return add, del
}

func truncatePatch(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n… (patch truncated)"
}
