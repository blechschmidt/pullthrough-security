// Package commit implements the LLM-backed Git commit scanning pipeline. When a
// commit flows through the Git backend (Task 6), the pipeline extracts its
// metadata and diff, submits them to an LLM provider (Claude by default, with a
// pluggable interface so other providers such as Codex can be swapped in) for
// supply-chain risk analysis, and persists a structured verdict keyed by commit
// SHA so the same commit is never re-scanned.
//
// The pipeline is built around a few small, testable pieces:
//
//   - Provider:   a thin, provider-agnostic LLM completion interface (claude.go).
//   - chunking:   bounds the token size of each request and splits large diffs
//     (chunk.go).
//   - VerdictStore: durable, SHA-keyed persistence of results (store.go).
//   - Pipeline:   orchestrates triage -> deep analysis, retries/backoff,
//     aggregation, caching, and asynchronous scanning (pipeline.go).
package commit

import (
	"strings"
	"time"
)

// FileDiff is the change to a single file within a commit. Patch holds the
// unified-diff text for the file; it may be empty for binary files or pure
// renames.
type FileDiff struct {
	// Path is the file path after the change. For renames OldPath holds the
	// pre-rename path.
	Path    string `json:"path"`
	OldPath string `json:"oldPath,omitempty"`
	// Status is a single-letter change kind following git's convention:
	// A(dded), M(odified), D(eleted), R(enamed), C(opied), T(ype change).
	Status string `json:"status,omitempty"`
	// Additions and Deletions are line counts, when known.
	Additions int `json:"additions,omitempty"`
	Deletions int `json:"deletions,omitempty"`
	// Binary reports whether the file is binary (Patch is then typically empty).
	Binary bool `json:"binary,omitempty"`
	// Patch is the unified diff hunk text for this file.
	Patch string `json:"patch,omitempty"`
}

// Commit is the unit of work handed to the pipeline: the metadata and diff
// extracted from a single Git commit.
type Commit struct {
	// SHA is the full commit hash; it is the storage and cache key.
	SHA string `json:"sha"`
	// RepositoryURL identifies the source repository the commit belongs to.
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// Parents lists parent commit SHAs (more than one indicates a merge).
	Parents []string `json:"parents,omitempty"`

	AuthorName     string    `json:"authorName,omitempty"`
	AuthorEmail    string    `json:"authorEmail,omitempty"`
	AuthorDate     time.Time `json:"authorDate,omitempty"`
	CommitterName  string    `json:"committerName,omitempty"`
	CommitterEmail string    `json:"committerEmail,omitempty"`
	CommitDate     time.Time `json:"commitDate,omitempty"`

	// Message is the full commit message (subject + body).
	Message string `json:"message,omitempty"`
	// Files is the per-file diff. It may be empty for an empty/merge commit.
	Files []FileDiff `json:"files,omitempty"`

	// Tenant is the owning tenant for the pull that triggered the scan, when
	// known. It is used for per-tenant token/cost budgeting (Task 78) and is not
	// part of the verdict cache key (the same commit yields the same verdict
	// regardless of which tenant pulled it). It is never sent to the model.
	Tenant string `json:"tenant,omitempty"`
}

// Subject returns the first line of the commit message.
func (c *Commit) Subject() string {
	if i := strings.IndexByte(c.Message, '\n'); i >= 0 {
		return strings.TrimSpace(c.Message[:i])
	}
	return strings.TrimSpace(c.Message)
}

// Category classifies the kind of supply-chain risk a finding represents. The
// set mirrors the threat classes the pipeline is asked to look for; UNKNOWN is
// used when a provider returns a category we do not recognize.
type Category string

const (
	CategoryMaliciousCode  Category = "malicious_code"
	CategorySecret         Category = "secret"
	CategoryObfuscation    Category = "obfuscation"
	CategoryDependency     Category = "suspicious_dependency"
	CategoryExfiltration   Category = "data_exfiltration"
	CategoryBackdoor       Category = "backdoor"
	CategoryBuildTampering Category = "build_tampering"
	CategoryActionPinning  Category = "action_pinning"
	CategoryOther          Category = "other"
	CategoryUnknown        Category = "unknown"
)

// knownCategories is the allow-list used to validate provider-supplied
// categories; anything else is coerced to CategoryUnknown so untrusted model
// output cannot smuggle arbitrary values downstream.
var knownCategories = map[Category]bool{
	CategoryMaliciousCode:  true,
	CategorySecret:         true,
	CategoryObfuscation:    true,
	CategoryDependency:     true,
	CategoryExfiltration:   true,
	CategoryBackdoor:       true,
	CategoryBuildTampering: true,
	CategoryActionPinning:  true,
	CategoryOther:          true,
}

// normalize returns c if it is a recognized category, else CategoryUnknown.
func (c Category) normalize() Category {
	n := Category(strings.ToLower(strings.TrimSpace(string(c))))
	if knownCategories[n] {
		return n
	}
	return CategoryUnknown
}

// Finding is a single issue the LLM identified in a commit.
type Finding struct {
	Category Category `json:"category"`
	// Severity is one of info|low|medium|high|critical (scan.Severity values).
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	// File and Line point at where the issue was found, when the model can
	// localize it.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Confidence is the model's self-reported confidence, 0..1.
	Confidence float64 `json:"confidence,omitempty"`
}

// Verdict is the structured result of analyzing a commit. It is the JSON shape
// the LLM is instructed to emit, and the value persisted per commit SHA.
type Verdict struct {
	// SHA echoes the analyzed commit.
	SHA string `json:"sha"`
	// RiskScore is an overall supply-chain risk rating, 0 (benign) .. 100
	// (almost certainly malicious).
	RiskScore int `json:"riskScore"`
	// Malicious is the model's boolean call on whether the commit is malicious.
	Malicious bool `json:"malicious"`
	// Findings enumerates the concrete issues behind the score.
	Findings []Finding `json:"findings,omitempty"`
	// Rationale is a short natural-language explanation of the verdict.
	Rationale string `json:"rationale,omitempty"`

	// The fields below are stamped by the pipeline, not the model.

	// Provider and Models record what produced the verdict, for auditability.
	Provider string   `json:"provider,omitempty"`
	Models   []string `json:"models,omitempty"`
	// Escalated reports whether deep analysis was run in addition to triage.
	Escalated bool `json:"escalated,omitempty"`
	// Chunked reports whether the diff was split across multiple requests.
	Chunked bool `json:"chunked,omitempty"`
	// Truncated reports that some diff content was dropped to fit the token
	// budget; the verdict may therefore be incomplete.
	Truncated bool `json:"truncated,omitempty"`
	// Error, when non-empty, records that the scan could not be completed and the
	// verdict is a placeholder (RiskScore/Findings unreliable).
	Error string `json:"error,omitempty"`
	// ScannedAt is when the verdict was produced.
	ScannedAt time.Time `json:"scannedAt"`
	// InputTokens and OutputTokens aggregate provider token usage across all
	// requests made for this commit, for cost accounting.
	InputTokens  int `json:"inputTokens,omitempty"`
	OutputTokens int `json:"outputTokens,omitempty"`
	// CostUSD is the aggregate estimated provider cost for this commit's scan,
	// computed from the per-model pricing table (Task 78).
	CostUSD float64 `json:"costUsd,omitempty"`

	// CacheKey is the deterministic key under which this verdict is persisted:
	// it folds the commit SHA, the model IDs, the prompt-template version, and the
	// ruleset hash, so a change to any of them produces a fresh scan rather than a
	// stale cache hit (Task 78).
	CacheKey string `json:"cacheKey,omitempty"`

	// Consensus, when set, records the per-provider votes from a multi-provider
	// consensus deep pass: a 'malicious' verdict only blocks when a quorum of
	// providers agree, and provider disagreement is itself recorded as a finding
	// (Task 78).
	Consensus *ConsensusInfo `json:"consensus,omitempty"`

	// Injection records prompt-injection / data-exfiltration indicators found in
	// the (untrusted) commit message and diff by the deterministic defense pass
	// (Task 78). A non-empty list means the commit attempted to manipulate the
	// scanner, which is itself a supply-chain risk signal.
	Injection []InjectionHit `json:"injection,omitempty"`
}

// HighestSeverity returns the most severe finding severity, or "info" when
// there are no findings.
func (v *Verdict) HighestSeverity() string {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	best := "info"
	for _, f := range v.Findings {
		if order[normalizeSeverity(f.Severity)] > order[best] {
			best = normalizeSeverity(f.Severity)
		}
	}
	return best
}

// normalizeSeverity coerces arbitrary model output to a known severity, so a
// malformed value cannot inflate or evade policy. Unknown values map to "info".
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return "low"
	case "medium", "med":
		return "medium"
	case "high":
		return "high"
	case "critical", "crit":
		return "critical"
	case "info", "informational", "none", "":
		return "info"
	default:
		return "info"
	}
}

// sanitize clamps and normalizes untrusted model output to safe ranges. It is
// applied to every verdict the pipeline accepts from a provider.
func (v *Verdict) sanitize() {
	if v.RiskScore < 0 {
		v.RiskScore = 0
	}
	if v.RiskScore > 100 {
		v.RiskScore = 100
	}
	for i := range v.Findings {
		f := &v.Findings[i]
		f.Category = f.Category.normalize()
		f.Severity = normalizeSeverity(f.Severity)
		if f.Confidence < 0 {
			f.Confidence = 0
		}
		if f.Confidence > 1 {
			f.Confidence = 1
		}
		if f.Line < 0 {
			f.Line = 0
		}
	}
}
