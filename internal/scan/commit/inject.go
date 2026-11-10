package commit

import (
	"fmt"
	"regexp"
	"strings"
)

// Prompt-injection / data-exfiltration defense (Task 78).
//
// Commit messages and diffs are untrusted input authored by whoever wrote the
// commit, including an attacker trying to coerce the scanning model into
// emitting a benign verdict, leaking the system prompt, or following embedded
// instructions. This file implements three layers of defense:
//
//  1. Delimiting: the untrusted commit text is wrapped between unguessable
//     boundary markers and the model is told (in the frozen system prompt) that
//     everything between them is data, never instructions.
//  2. Defanging: invisible/zero-width and control characters that hide payloads
//     or break up keywords are stripped, and known jailbreak directives embedded
//     in the data are wrapped in an explicit NEUTRALIZED tag so the model sees
//     them flagged rather than as live instructions.
//  3. Output validation + ground-truth findings: a deterministic scan records
//     every injection attempt as an InjectionHit. Those hits are applied to the
//     verdict after the model answers (raising the risk floor and adding a
//     finding), so a malicious commit cannot whitewash itself by instructing the
//     model to return malicious=false. The model's raw output is validated for
//     system-prompt leakage via an embedded canary token.

const (
	// untrustedBegin and untrustedEnd delimit the untrusted commit data in the
	// user message. The random-looking suffix makes the boundary unguessable from
	// inside the data so an attacker cannot forge an "end of data" marker and
	// smuggle trailing instructions. Any occurrence of these markers inside the
	// data itself is neutralized by defang before wrapping.
	untrustedBegin = "<<<UNTRUSTED_COMMIT_DATA::a7f3c19e>>>"
	untrustedEnd   = "<<<END_UNTRUSTED_COMMIT_DATA::a7f3c19e>>>"

	// promptCanary is embedded in the system prompt with an instruction never to
	// reveal it. If it appears in the model's output, the model leaked its
	// instructions (a successful injection) and the response is rejected.
	promptCanary = "PT-CANARY-9f1c2a44"

	// InjectionRulesetVersion is bumped whenever the injection patterns change, so
	// it participates in the verdict cache key and forces a re-scan.
	InjectionRulesetVersion = "inj-v1"
)

// InjectionHit is a single prompt-injection / exfiltration indicator found in
// untrusted commit text. Sample is a short, redacted excerpt of the match.
type InjectionHit struct {
	// Rule identifies the pattern that fired (e.g. "ignore-instructions").
	Rule string `json:"rule"`
	// Where locates the hit: "message" or a file path.
	Where string `json:"where,omitempty"`
	// Sample is a short, bounded excerpt of the offending text.
	Sample string `json:"sample,omitempty"`
}

// injectionRule is a named detection pattern.
type injectionRule struct {
	name string
	re   *regexp.Regexp
}

// injectionRules are deliberately conservative: they target imperative
// instruction-injection and exfiltration phrasing that has no legitimate reason
// to appear verbatim in a commit message or diff, plus role/turn markers used to
// hijack the conversation. They are case-insensitive.
var injectionRules = []injectionRule{
	{"ignore-instructions", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|the)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction|context)s?\b`)},
	{"new-instructions", regexp.MustCompile(`(?i)\b(new|updated|revised|real|actual)\b[^.\n]{0,20}\b(instruction|prompt|system|task|directive)s?\b`)},
	{"reveal-system-prompt", regexp.MustCompile(`(?i)\b(reveal|print|repeat|show|output|display|leak|reproduce)\b[^.\n]{0,30}\b(system|developer|initial|original|your)\b[^.\n]{0,20}\b(prompt|instruction|message|rule)s?\b`)},
	{"role-override", regexp.MustCompile(`(?i)\byou\s+are\s+now\b|\bact\s+as\b[^.\n]{0,30}\b(dan|jailbreak|unfiltered|developer\s+mode|no\s+restrictions)\b|\bdeveloper\s+mode\b|\bjailbreak\b`)},
	{"verdict-coercion", regexp.MustCompile(`(?i)\b(always|must|please)\b[^.\n]{0,40}\b(return|respond|reply|answer|output|set)\b[^.\n]{0,40}\b(benign|safe|malicious\s*[:=]\s*false|riskscore\s*[:=]\s*0|not\s+malicious|low\s+risk)\b`)},
	{"turn-marker", regexp.MustCompile(`(?im)^\s*(system|assistant|user|ai)\s*:`)},
	{"chatml-marker", regexp.MustCompile(`(?i)<\|?(im_start|im_end|system|assistant|endoftext)\|?>|\[/?INST\]|\[/?SYS\]`)},
	{"exfiltration", regexp.MustCompile(`(?i)\b(send|post|exfiltrate|upload|transmit|leak)\b[^.\n]{0,40}\b(env|environment|secret|token|api[_\- ]?key|credential|\.ssh|/etc/passwd)\b`)},
}

// zeroWidth matches invisible / formatting characters used to hide payloads or
// break up keywords so they evade naive matching: zero-width space/joiner,
// bidi controls, BOM, soft hyphen, word joiner. Written with explicit escapes so
// no invisible characters appear in the source.
var zeroWidth = regexp.MustCompile(`[\x{00AD}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]`)

// defang neutralizes untrusted text before it is embedded in a prompt. It strips
// invisible/zero-width characters and any forged boundary markers, and wraps
// recognized injection directives in an explicit NEUTRALIZED tag. It returns the
// cleaned text. Detection (for findings) is done separately by detectInjection
// over the original text so stripping does not hide the evidence.
func defang(s string) string {
	if s == "" {
		return s
	}
	// Strip invisible characters that hide or fragment payloads.
	s = zeroWidth.ReplaceAllString(s, "")
	// A commit must never be able to forge our data boundary.
	s = strings.ReplaceAll(s, untrustedBegin, "[neutralized-marker]")
	s = strings.ReplaceAll(s, untrustedEnd, "[neutralized-marker]")
	// Defang the canary so an echoed canary in the *input* cannot be confused with
	// a leaked canary in the output.
	s = strings.ReplaceAll(s, promptCanary, "[redacted-token]")
	// Wrap recognized injection directives so the model sees them flagged.
	for _, rule := range injectionRules {
		s = rule.re.ReplaceAllString(s, "[NEUTRALIZED-INJECTION:$0]")
	}
	return s
}

// detectInjection scans the commit's untrusted fields (message and diff patches)
// for prompt-injection / exfiltration indicators and returns the hits found. It
// runs over the original (un-defanged) text so the evidence is faithful. The
// returned hits are bounded in number and each sample is truncated.
func detectInjection(c *Commit) []InjectionHit {
	var hits []InjectionHit
	const maxHits = 32

	scan := func(where, text string) {
		if text == "" || len(hits) >= maxHits {
			return
		}
		// Normalize invisible characters first so a fragmented keyword still matches.
		norm := zeroWidth.ReplaceAllString(text, "")
		for _, rule := range injectionRules {
			if len(hits) >= maxHits {
				return
			}
			if loc := rule.re.FindString(norm); loc != "" {
				hits = append(hits, InjectionHit{
					Rule:   rule.name,
					Where:  where,
					Sample: injectionSample(loc),
				})
			}
		}
	}

	scan("message", c.Message)
	for _, f := range c.Files {
		if f.Binary {
			continue
		}
		scan(f.Path, addedLines(f.Patch))
	}
	return hits
}

// addedLines returns only the added ('+') lines of a unified diff, which is
// where an attacker introduces injected text. Context and removed lines are
// excluded to cut noise.
func addedLines(patch string) string {
	if patch == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			b.WriteString(line[1:])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// injectionSample returns a short, single-line, redacted excerpt of a match.
func injectionSample(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 80
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// applyInjectionFindings folds deterministic injection indicators into a verdict
// produced by the LLM pass: it records the hits, raises the risk floor, and adds
// a single finding. This runs after the model answers so an injected
// "respond benign" instruction cannot suppress the signal — the deterministic
// finding is authoritative and always retained. floor is the minimum risk score
// implied by a detected injection attempt.
func applyInjectionFindings(v *Verdict, hits []InjectionHit, floor int) {
	if len(hits) == 0 {
		return
	}
	v.Injection = hits
	rules := make([]string, 0, len(hits))
	seen := make(map[string]bool, len(hits))
	for _, h := range hits {
		if !seen[h.Rule] {
			seen[h.Rule] = true
			rules = append(rules, h.Rule)
		}
	}
	v.Findings = append(v.Findings, Finding{
		Category:   CategoryObfuscation,
		Severity:   "high",
		Title:      "Possible prompt-injection in commit",
		Detail:     fmt.Sprintf("the commit message or diff contains text that attempts to manipulate the commit scanner (%s); treated as untrusted data and flagged", strings.Join(rules, ", ")),
		Confidence: 0.9,
	})
	if floor <= 0 {
		floor = defaultInjectionRiskFloor
	}
	if floor > v.RiskScore {
		v.RiskScore = floor
	}
}

// defaultInjectionRiskFloor is the risk score a detected injection attempt
// raises a verdict to when the configured floor is unset. It is high enough to
// warn but below the default block threshold, so an injection attempt surfaces
// for review without, on its own, hard-blocking a legitimate-but-clumsy commit.
const defaultInjectionRiskFloor = 50

// errPromptLeak indicates the model echoed the system-prompt canary, i.e. an
// injection coerced it into revealing its instructions. The pipeline treats this
// as a failed, untrustworthy response.
var errPromptLeak = fmt.Errorf("commit: model response leaked the system prompt (injection suspected)")

// validateModelOutput rejects a raw model response that leaked the system prompt
// (detected via the canary token). It is applied before parsing so a coerced
// response is never trusted as a verdict.
func validateModelOutput(raw string) error {
	if strings.Contains(raw, promptCanary) {
		return errPromptLeak
	}
	return nil
}
