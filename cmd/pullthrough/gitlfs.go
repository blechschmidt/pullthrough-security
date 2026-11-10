package main

import (
	"context"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
)

// lfsSecretGate adapts the deterministic secret detector to the Git LFS content
// gate (Task 123). Git LFS blobs are opaque large objects, so they are scanned
// as a single synthetic "file": each content line is presented as an added line
// (the shape the detector's diff-oriented scanner expects) and the detector's
// rules and entropy heuristic run over it. This reuses the same secret-scanning
// control the commit-scan pipeline applies to diffs, rather than inventing a
// second detector.
type lfsSecretGate struct {
	det *secretscan.Detector
}

func newLFSSecretGate(det *secretscan.Detector) *lfsSecretGate {
	return &lfsSecretGate{det: det}
}

var _ git.LFSContentGate = (*lfsSecretGate)(nil)

// InspectLFSObject scans the blob content for secrets and returns the number of
// findings. Binary (non-UTF-8) content is skipped — secret detection is only
// meaningful on text, and feeding arbitrary bytes to the line scanner would be
// noise. It never returns an error (the detector is in-process and total).
func (g *lfsSecretGate) InspectLFSObject(_ context.Context, info git.LFSObjectInfo, content []byte) (int, error) {
	if g.det == nil || len(content) == 0 || !looksTextual(content) {
		return 0, nil
	}
	// Present the blob as a unified-diff hunk whose every line is an addition, so
	// secretscan.AddedLines yields the full content. Prefixing each line with '+'
	// is the minimal adaptation of raw content to the detector's input shape.
	patch := synthesizeAddedPatch(string(content))
	findings := g.det.ScanFiles([]secretscan.FileInput{{
		Path:  "lfs:" + info.OID,
		Patch: patch,
	}})
	return len(findings), nil
}

// synthesizeAddedPatch turns raw text into a header-less unified-diff body where
// every line is an added line (prefixed with '+'). secretscan.AddedLines returns
// such '+'-prefixed lines with line number 0 when no hunk header is present.
func synthesizeAddedPatch(content string) string {
	lines := strings.Split(content, "\n")
	var sb strings.Builder
	sb.Grow(len(content) + len(lines))
	for _, ln := range lines {
		sb.WriteByte('+')
		sb.WriteString(ln)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// looksTextual reports whether content is plausibly UTF-8 text (no NUL bytes in
// the inspected prefix). LFS stores mostly binary assets; scanning those for
// secrets is noise, so the gate restricts itself to textual blobs.
func looksTextual(content []byte) bool {
	limit := len(content)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if content[i] == 0x00 {
			return false
		}
	}
	return true
}
