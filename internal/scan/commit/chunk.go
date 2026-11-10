package commit

import (
	"strings"
)

// DiffChunk is a slice of a commit's file diffs sized to fit a token budget.
// Large commits are split into multiple chunks, each analyzed independently and
// then aggregated.
type DiffChunk struct {
	// Index is the 0-based position of this chunk; Total is the chunk count.
	Index int
	Total int
	// Files are the (possibly partial) file diffs in this chunk.
	Files []FileDiff
	// Truncated reports that content was dropped from this chunk to fit the
	// budget (e.g. an over-long single line).
	Truncated bool
}

// avgCharsPerToken approximates the bytes-per-token ratio for English/code text.
// It is intentionally conservative (smaller -> higher token estimate -> smaller
// chunks) so we under-fill rather than overflow the context budget. Exact
// counting would require a per-request count_tokens API call; this heuristic
// keeps chunking deterministic and offline.
const avgCharsPerToken = 4

// estimateTokens approximates the token count of s.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + avgCharsPerToken - 1) / avgCharsPerToken
}

// minChunkBodyTokens is a floor for the per-chunk diff budget so a large header
// or a tiny configured budget cannot drive the usable space to zero.
const minChunkBodyTokens = 256

// chunkCommit splits a commit's diff into chunks whose rendered size stays
// within maxTokens (estimated), reserving room for the system prompt and commit
// header. A commit with no files yields a single empty chunk so it is still
// analyzed (the metadata/message alone can be suspicious). maxChunks > 0 caps
// the number of chunks; excess files are dropped and the final chunk is marked
// Truncated.
func chunkCommit(c *Commit, maxTokens, maxChunks int) []DiffChunk {
	headerTokens := estimateTokens(commitHeader(c)) + estimateTokens(systemPrompt)
	budget := maxTokens - headerTokens
	if budget < minChunkBodyTokens {
		budget = minChunkBodyTokens
	}

	// Expand each file into one or more units that individually fit the budget.
	var units []FileDiff
	for _, f := range c.Files {
		units = append(units, splitFile(f, budget)...)
	}

	if len(units) == 0 {
		return []DiffChunk{{Index: 0, Total: 1, Files: nil}}
	}

	// Greedily pack units into chunks under the budget.
	var chunks []DiffChunk
	var cur []FileDiff
	curTokens := 0
	flush := func() {
		if len(cur) > 0 {
			chunks = append(chunks, DiffChunk{Files: cur})
			cur = nil
			curTokens = 0
		}
	}
	for _, u := range units {
		ut := estimateTokens(renderDiff([]FileDiff{u}))
		if curTokens > 0 && curTokens+ut > budget {
			flush()
		}
		cur = append(cur, u)
		curTokens += ut
	}
	flush()

	truncated := false
	if maxChunks > 0 && len(chunks) > maxChunks {
		chunks = chunks[:maxChunks]
		truncated = true
	}

	total := len(chunks)
	for i := range chunks {
		chunks[i].Index = i
		chunks[i].Total = total
	}
	if truncated && total > 0 {
		chunks[total-1].Truncated = true
	}
	return chunks
}

// splitFile returns one FileDiff when f fits the budget, or several partial
// FileDiffs (each carrying a slice of the patch) when it does not. Binary files
// and empty patches always pass through as a single unit.
func splitFile(f FileDiff, budget int) []FileDiff {
	if f.Binary || strings.TrimSpace(f.Patch) == "" {
		return []FileDiff{f}
	}
	if estimateTokens(renderDiff([]FileDiff{f})) <= budget {
		return []FileDiff{f}
	}

	// Reserve a little room for the per-file header line in each part.
	bodyBudget := budget - 32
	if bodyBudget < minChunkBodyTokens {
		bodyBudget = minChunkBodyTokens
	}
	parts := splitPatch(f.Patch, bodyBudget)

	out := make([]FileDiff, 0, len(parts))
	for i, p := range parts {
		pf := f
		pf.Patch = p.text
		// Only the first part carries the line-count summary, to avoid implying
		// each part is a whole file.
		if i > 0 {
			pf.Additions, pf.Deletions = 0, 0
		}
		// Mark the part in the path so the model knows it is a slice.
		if len(parts) > 1 {
			pf.Path = f.Path
		}
		out = append(out, pf)
		_ = p.truncated
	}
	return out
}

type patchPart struct {
	text      string
	truncated bool
}

// splitPatch breaks patch text into parts each estimated under budget tokens,
// splitting on line boundaries. A single line longer than the budget is hard-cut
// (and its part marked truncated) so progress is always made.
func splitPatch(patch string, budget int) []patchPart {
	lines := strings.SplitAfter(patch, "\n")
	var parts []patchPart
	var b strings.Builder
	bTokens := 0
	flush := func(trunc bool) {
		if b.Len() > 0 {
			parts = append(parts, patchPart{text: b.String(), truncated: trunc})
			b.Reset()
			bTokens = 0
		}
	}
	for _, line := range lines {
		lt := estimateTokens(line)
		if lt > budget {
			// Oversized single line: flush what we have, then hard-cut the line.
			flush(false)
			maxChars := budget * avgCharsPerToken
			if maxChars < 1 {
				maxChars = 1
			}
			for len(line) > 0 {
				n := maxChars
				if n > len(line) {
					n = len(line)
				}
				parts = append(parts, patchPart{text: line[:n], truncated: true})
				line = line[n:]
			}
			continue
		}
		if bTokens > 0 && bTokens+lt > budget {
			flush(false)
		}
		b.WriteString(line)
		bTokens += lt
	}
	flush(false)
	if len(parts) == 0 {
		parts = append(parts, patchPart{})
	}
	return parts
}
