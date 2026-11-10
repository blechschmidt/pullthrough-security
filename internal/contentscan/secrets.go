package contentscan

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
)

// scanSecrets runs the reused Task 29 deterministic secret detector over a single
// package file's text. The detector's public entry point scans the *added* lines
// of a unified diff, so the file content is wrapped as an all-added synthetic
// patch (with a hunk header, so line numbers are the file's real line numbers).
// Findings are returned already redacted and fingerprinted by the detector.
func (s *Service) scanSecrets(name, text string) []secretscan.Finding {
	if s.secrets == nil || strings.TrimSpace(text) == "" {
		return nil
	}
	patch := synthesizeAddedPatch(text)
	return s.secrets.ScanFiles([]secretscan.FileInput{{Path: name, Patch: patch}})
}

// synthesizeAddedPatch renders content as a unified-diff hunk in which every line
// is an addition, so secretscan.AddedLines yields each line with its correct
// 1-based file line number. A trailing '+' prefix is applied per line; the hunk
// header advertises the line count.
func synthesizeAddedPatch(content string) string {
	lines := strings.Split(content, "\n")
	// A trailing newline produces a final empty element; drop it so the advertised
	// count matches the real added lines.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "@@ -0,0 +1,%d @@\n", len(lines))
	for _, ln := range lines {
		b.WriteByte('+')
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

// looksTextual reports whether a file's bytes are plausibly text (so the line-
// oriented heuristics and the secret detector apply). It rejects data containing
// NUL bytes or a high proportion of non-printable control bytes — the hallmark of
// a binary payload. The check inspects only a bounded prefix.
func looksTextual(data []byte) bool {
	const probe = 8192
	n := len(data)
	if n > probe {
		n = probe
	}
	if n == 0 {
		return false
	}
	nonPrintable := 0
	for i := 0; i < n; i++ {
		c := data[i]
		if c == 0 {
			return false // a NUL byte is a definitive binary marker
		}
		// Printable ASCII, common whitespace, or a UTF-8 continuation/lead byte.
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			continue
		}
		nonPrintable++
	}
	return float64(nonPrintable)/float64(n) < 0.30
}
