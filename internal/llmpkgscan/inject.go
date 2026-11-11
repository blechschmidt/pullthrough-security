package llmpkgscan

import (
	"bytes"
	"context"
	"regexp"
)

// Deterministic prompt-injection detection.
//
// The prompt tells the model that package content is data. That is a request,
// not a guarantee: a model can still be talked round. This pass is the part of
// the defense that cannot be talked to. It looks for text that addresses the
// scanner itself, and its result is applied AFTER the model has answered — so a
// package that carries such text cannot earn a clean verdict by persuading the
// model to give it one (see Service.classify).
//
// The rules are deliberately narrow. Whole packages are scanned, and packages
// are full of ordinary prose about instructions, prompts, systems and
// assistants — an LLM SDK's documentation alone would trip any loose pattern.
// Each "strong" rule therefore requires phrasing that has no business in a
// package unless it is aimed at an automated reviewer. Chat-template role
// tokens are common in legitimate LLM tooling, so they are only recorded
// ("weak"), never held against the package on their own.

// InjectionHit is one indicator found in package content.
type InjectionHit struct {
	// Rule is the pattern that fired.
	Rule string `json:"rule"`
	// Strong reports a rule precise enough to affect the disposition.
	Strong bool `json:"strong"`
	// Path and Line locate the hit.
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	// Sample is a short, single-line excerpt of the match.
	Sample string `json:"sample,omitempty"`
}

// injectionRule is one pattern. It is matched against an ASCII-lower-cased copy
// of the file, so the expression is written in lower case.
//
// anchors is a cheap necessary condition: the expression can only match if, for
// every group in anchors, at least one of its substrings occurs in the file.
// Substring search is far faster than the regexp engine, so the expression is
// only run on the few files that could match it. The anchors are a strict
// superset filter — single words the expression itself requires — so they can
// never hide a match the expression would have found.
type injectionRule struct {
	name    string
	strong  bool
	anchors [][]string
	re      *regexp.Regexp
}

// injectionRules is the ruleset. PromptVersion covers it: changing a rule
// changes which packages can be cleared, so cached verdicts must not outlive it.
var injectionRules = []injectionRule{
	// "Ignore all previous instructions" and its variants.
	{
		name: "ignore-instructions", strong: true,
		anchors: [][]string{{"ignore", "disregard", "forget", "override"}, {"instruction", "prompt", "guideline", "direction"}},
		re:      regexp.MustCompile(`\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}\b(?:all|any|previous|prior|above|earlier|preceding)\b[^.\n]{0,30}\b(?:instructions?|prompts?|guidelines|directions)\b`),
	},
	// Text addressing its reader as an AI.
	{
		name: "ai-addressing", strong: true,
		anchors: [][]string{{"you"}, {"are"}, {"ai", "llm", "language", "automated"}},
		re:      regexp.MustCompile(`\b(?:if|since|as|because|when)\s+you\s+are\s+an?\s+(?:ai|llm|(?:large\s+)?language\s+model|ai\s+assistant|automated\s+(?:scanner|reviewer|analy[sz]er|tool))\b`),
	},
	// A directive aimed at a security scanner / reviewer.
	{
		name: "scanner-directive", strong: true,
		anchors: [][]string{{"scanner", "reviewer", "analyzer", "analyser", "analyst", "auditor"}},
		re:      regexp.MustCompile(`\b(?:security|malware|package|supply[- ]chain|code|ai|llm|automated)\s+(?:scanners?|reviewers?|analy[sz]ers?|analysts?|auditors?)\b[^.\n]{0,60}\b(?:must|should|shall|please|needs?\s+to|(?:is|are)\s+required\s+to)\b[^.\n]{0,60}\b(?:classify|report|mark|label|rate|respond|answer|conclude|treat|consider|return|output|skip|ignore)\b`),
	},
	// Asking for a clean verdict.
	{
		name: "verdict-coercion", strong: true,
		anchors: [][]string{{"benign", "safe", "malicious", "harmless", "clean"}, {"respond", "reply", "answer", "output", "report", "classify", "mark", "label", "rate"}},
		re:      regexp.MustCompile(`\b(?:respond|reply|answer|output|report|classify|mark|label|rate)\b[^.\n]{0,40}\b(?:this|the)\s+(?:package|file|code|module|library|script|archive)\b[^.\n]{0,30}\b(?:as|is)\s+(?:benign|safe|not\s+malicious|harmless|clean)\b`),
	},
	// A ready-made answer in the scanner's own output schema.
	{
		name: "verdict-snippet", strong: true,
		anchors: [][]string{{`"verdict"`}},
		re:      regexp.MustCompile(`"verdict"\s*:\s*"(?:benign|suspicious|malicious)"`),
	},
	// Claiming the package was already cleared.
	{
		name: "pre-approval-claim", strong: true,
		anchors: [][]string{{"approved", "verified", "audited", "listed", "scanned"}, {"safe", "benign", "review", "analysis", "scan"}},
		re:      regexp.MustCompile(`\bthis\s+(?:package|file|code|module|library|script)\b[^.\n]{0,40}\b(?:has\s+been|was|is)\b[^.\n]{0,30}\b(?:pre-?approved|verified|audited|white-?listed|allow-?listed|already\s+scanned)\b[^.\n]{0,60}\b(?:safe|benign|no\s+(?:further\s+)?(?:review|analysis|scan(?:ning)?))\b`),
	},
	// Asking not to be flagged.
	{
		name: "do-not-flag", strong: true,
		anchors: [][]string{{"malicious", "suspicious", "malware", "unsafe", "threat"}, {"flag", "report", "classify", "mark", "label"}},
		re:      regexp.MustCompile(`\b(?:do\s+not|don'?t|never|must\s+not)\b[^.\n]{0,20}\b(?:flag|report|classify|mark|label)\b[^.\n]{0,40}\bas\s+(?:malicious|suspicious|malware|unsafe|a\s+threat)\b`),
	},
	// Imitating the proxy's own framing.
	{
		name: "boundary-forgery", strong: true,
		anchors: [][]string{{"untrusted_package_data", "pt-pkg-canary"}},
		re:      regexp.MustCompile(`untrusted_package_data|pt-pkg-canary`),
	},
	// Chat-template role tokens: legitimate in LLM tooling, so recorded only.
	{
		name: "role-marker", strong: false,
		anchors: [][]string{{"<|im_start|>", "<|im_end|>", "<|endoftext|>", "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>", "[inst]", "[/inst]", "<<sys>>", "<</sys>>"}},
		re:      regexp.MustCompile(`<\|(?:im_start|im_end|endoftext|start_header_id|end_header_id|eot_id)\|>|\[/?inst\]|<</?sys>>`),
	},
}

// anchored reports whether a rule's necessary substrings are all present.
func (r injectionRule) anchored(lower []byte) bool {
	for _, group := range r.anchors {
		found := false
		for _, a := range group {
			if bytes.Contains(lower, []byte(a)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Bounds on the pass.
const (
	injectScanTotal   = 8 << 20   // bytes examined across the package
	injectScanPerFile = 256 << 10 // bytes examined per file
	injectMaxHits     = 32        // hits recorded per package
	injectSampleChars = 120       // characters of a match kept as the sample
)

// asciiLower returns a copy of data with A-Z lower-cased. Only ASCII is folded,
// so the copy has the same length and the same byte offsets as the original.
func asciiLower(data []byte) []byte {
	out := make([]byte, len(data))
	for i, c := range data {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// detectInjection scans the tree's readable files, most relevant first, for
// text aimed at the scanner. It is bounded in bytes and in hits, and stops when
// ctx is done. Each rule reports at most one hit per file.
func detectInjection(ctx context.Context, t *Tree) []InjectionHit {
	var hits []InjectionHit
	budget := injectScanTotal
	for _, f := range t.byPriority() {
		if len(hits) >= injectMaxHits || budget <= 0 || ctx.Err() != nil {
			break
		}
		if !f.Readable() || f.Lines == 0 {
			continue
		}
		data := f.Data
		if len(data) > injectScanPerFile {
			data = data[:injectScanPerFile]
		}
		if len(data) > budget {
			data = data[:budget]
		}
		budget -= len(data)
		lower := asciiLower(data)
		for _, rule := range injectionRules {
			if len(hits) >= injectMaxHits {
				break
			}
			if !rule.anchored(lower) {
				continue
			}
			loc := rule.re.FindIndex(lower)
			if loc == nil {
				continue
			}
			hits = append(hits, InjectionHit{
				Rule:   rule.name,
				Strong: rule.strong,
				Path:   f.Path,
				Line:   f.lineAt(loc[0]),
				// The sample is cut from the original text, not the folded copy.
				Sample: cleanText(string(data[loc[0]:loc[1]]), injectSampleChars),
			})
		}
	}
	return hits
}

// hasStrongInjection reports whether any hit comes from a strong rule.
func hasStrongInjection(hits []InjectionHit) bool {
	for _, h := range hits {
		if h.Strong {
			return true
		}
	}
	return false
}
