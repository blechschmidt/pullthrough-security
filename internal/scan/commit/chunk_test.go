package commit

import (
	"strings"
	"testing"
)

func TestEstimateTokens(t *testing.T) {
	if got := estimateTokens(""); got != 0 {
		t.Errorf("estimateTokens(\"\") = %d, want 0", got)
	}
	if got := estimateTokens("abcd"); got != 1 {
		t.Errorf("estimateTokens(4 chars) = %d, want 1", got)
	}
	if got := estimateTokens("abcde"); got != 2 {
		t.Errorf("estimateTokens(5 chars) = %d, want 2", got)
	}
}

func TestChunkCommitEmptyYieldsOneChunk(t *testing.T) {
	c := &Commit{SHA: "abc123", Message: "fix: typo"}
	chunks := chunkCommit(c, 10000, 0)
	if len(chunks) != 1 {
		t.Fatalf("empty commit: got %d chunks, want 1", len(chunks))
	}
	if chunks[0].Total != 1 || chunks[0].Index != 0 {
		t.Errorf("chunk index/total = %d/%d, want 0/1", chunks[0].Index, chunks[0].Total)
	}
}

func TestChunkCommitSmallSingleChunk(t *testing.T) {
	c := &Commit{
		SHA: "deadbeef",
		Files: []FileDiff{
			{Path: "a.go", Patch: "@@ -1 +1 @@\n-old\n+new\n"},
			{Path: "b.go", Patch: "@@ -1 +1 @@\n-x\n+y\n"},
		},
	}
	chunks := chunkCommit(c, 10000, 0)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if len(chunks[0].Files) != 2 {
		t.Errorf("chunk file count = %d, want 2", len(chunks[0].Files))
	}
}

func TestChunkCommitSplitsLargeDiff(t *testing.T) {
	// Build several files whose combined size exceeds a tight budget.
	var files []FileDiff
	body := strings.Repeat("+some added line of source code here\n", 50) // ~1850 chars ≈ 460 tokens
	for i := 0; i < 6; i++ {
		files = append(files, FileDiff{Path: string(rune('a'+i)) + ".go", Patch: body})
	}
	c := &Commit{SHA: "abcd1234", Files: files}

	chunks := chunkCommit(c, 1200, 0)
	if len(chunks) < 2 {
		t.Fatalf("expected the diff to be split into multiple chunks, got %d", len(chunks))
	}
	// Every chunk must declare the same Total and a unique, ordered Index.
	for i, ch := range chunks {
		if ch.Index != i {
			t.Errorf("chunk %d has Index %d", i, ch.Index)
		}
		if ch.Total != len(chunks) {
			t.Errorf("chunk %d Total = %d, want %d", i, ch.Total, len(chunks))
		}
	}
}

func TestChunkCommitMaxChunksTruncates(t *testing.T) {
	var files []FileDiff
	body := strings.Repeat("+line\n", 200)
	for i := 0; i < 8; i++ {
		files = append(files, FileDiff{Path: string(rune('a'+i)) + ".go", Patch: body})
	}
	c := &Commit{SHA: "feedface", Files: files}

	chunks := chunkCommit(c, 800, 2)
	if len(chunks) != 2 {
		t.Fatalf("maxChunks=2: got %d chunks", len(chunks))
	}
	if !chunks[len(chunks)-1].Truncated {
		t.Error("final chunk should be marked Truncated when capped")
	}
}

func TestSplitFileOversizedSingleFile(t *testing.T) {
	// One file far larger than the budget must be split across units.
	patch := strings.Repeat("+a line of content\n", 500)
	f := FileDiff{Path: "big.go", Patch: patch}
	units := splitFile(f, 300)
	if len(units) < 2 {
		t.Fatalf("oversized file: got %d units, want >= 2", len(units))
	}
	for _, u := range units {
		if u.Path != "big.go" {
			t.Errorf("split unit lost path: %q", u.Path)
		}
	}
}

func TestSplitPatchHardCutsOverlongLine(t *testing.T) {
	// A single line bigger than the budget must still make progress.
	long := "+" + strings.Repeat("x", 5000) + "\n"
	parts := splitPatch(long, 100)
	if len(parts) < 2 {
		t.Fatalf("overlong line: got %d parts, want >= 2", len(parts))
	}
	sawTruncated := false
	var reassembled strings.Builder
	for _, p := range parts {
		if p.truncated {
			sawTruncated = true
		}
		reassembled.WriteString(p.text)
	}
	if !sawTruncated {
		t.Error("expected at least one part flagged truncated")
	}
	if reassembled.String() != long {
		t.Error("hard-cut parts should reassemble to the original line")
	}
}
