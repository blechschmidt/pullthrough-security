// Package secretscan implements a fast, deterministic secret- and
// credential-detection pass for Git commit scanning (Task 29). It complements
// the LLM-based commit scanner (Task 7) with cheap, offline, reproducible
// coverage that does not depend on provider availability or cost.
//
// The detector inspects only the *added* lines of each file's unified diff
// (so unchanged context and removed lines never produce findings) and applies
// two families of checks:
//
//   - High-confidence regular-expression rules for well-known credential
//     formats (AWS keys, GCP service-account JSON, GitHub/GitLab tokens, Slack
//     tokens, PEM private-key blocks, JWTs, and more). The ruleset is pluggable
//     and may be extended or replaced from configuration.
//   - A Shannon-entropy heuristic that flags generic high-entropy strings that
//     look like assigned secrets, with conservative thresholds and context
//     gating to keep the false-positive rate low.
//
// Findings are redacted (the raw secret never appears verbatim in a Finding),
// carry a stable fingerprint for baseline/allowlist suppression, and are
// counted per rule for metrics. The package has no dependencies on the rest of
// the proxy so the commit pipeline can adapt its output without an import cycle.
package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Severity strings mirror scan.Severity so findings map cleanly onto the rest
// of the pipeline without importing it here.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// EntropyRuleID is the synthetic rule identifier attributed to findings raised
// by the Shannon-entropy heuristic rather than a named regex rule.
const EntropyRuleID = "high-entropy-string"

// FileInput is one file's change handed to the detector. Only added lines of
// Patch are inspected; binary files are skipped.
type FileInput struct {
	// Path is the file path after the change (used for allowlisting and
	// reported in findings).
	Path string
	// Patch is the unified-diff hunk text for the file.
	Patch string
	// Binary marks the file as binary; its patch is not scanned.
	Binary bool
}

// Finding is a single deterministic secret/credential detection. The matched
// secret is always stored redacted in Match; Fingerprint is a stable identifier
// suitable for baseline suppression.
type Finding struct {
	// RuleID identifies the rule that fired (a named rule's ID or EntropyRuleID).
	RuleID string `json:"ruleId"`
	// Description is a human-readable explanation of what was detected.
	Description string `json:"description"`
	// Severity is one of info|low|medium|high|critical.
	Severity string `json:"severity"`
	// File and Line locate the finding in the post-change file. Line is the
	// 1-based line number within the new file when derivable, else 0.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Match is the redacted secret (never the raw value).
	Match string `json:"match"`
	// Entropy is the Shannon entropy (bits/char) of the matched value for
	// entropy-derived findings; 0 for pure regex matches.
	Entropy float64 `json:"entropy,omitempty"`
	// Fingerprint is a stable hash of (rule, file, secret) for baseline
	// suppression and de-duplication.
	Fingerprint string `json:"fingerprint"`
}

// Config configures a Detector. The zero value is usable and yields the
// built-in ruleset with the default entropy heuristic and no allowlist.
type Config struct {
	// Rules is an additional/override ruleset compiled from configuration. It is
	// combined with the built-in ruleset unless DisableBuiltins is set.
	Rules []Rule
	// DisableBuiltins drops the built-in ruleset so only Rules apply.
	DisableBuiltins bool
	// Entropy configures the generic high-entropy heuristic.
	Entropy EntropyConfig
	// Allowlist suppresses known false positives and test fixtures.
	Allowlist Allowlist
	// RevealPrefix is how many leading characters of a secret are kept when
	// redacting (the remainder is masked). Defaults to 4; clamped to [0,8].
	RevealPrefix int
	// MaxFindingsPerFile caps findings emitted per file to bound the cost of a
	// pathological diff (0 = the package default of 100).
	MaxFindingsPerFile int
}

// Detector performs deterministic secret detection. It is safe for concurrent
// use; all mutable state is in atomic counters.
type Detector struct {
	rules        []Rule
	entropy      EntropyConfig
	allow        Allowlist
	revealPrefix int
	maxPerFile   int

	metrics struct {
		diffsScanned atomic.Int64
		filesScanned atomic.Int64
		linesScanned atomic.Int64
		findings     atomic.Int64
		suppressed   atomic.Int64
	}
	// byRule counts findings per rule ID. It is pre-populated for every known
	// rule (plus the entropy rule) at construction so Snapshot keys are stable;
	// a lazily-created entry covers any rule added at runtime.
	byRule   map[string]*atomic.Int64
	byRuleMu sync.RWMutex
}

// New constructs a Detector from cfg, applying defaults. It returns an error
// only if a supplied rule is invalid (callers compiling rules from config
// should surface that to the operator).
func New(cfg Config) *Detector {
	rules := make([]Rule, 0, len(cfg.Rules)+len(builtinRules))
	if !cfg.DisableBuiltins {
		rules = append(rules, builtinRules...)
	}
	// Custom rules override built-ins with the same ID (custom wins), so apply
	// them after and de-duplicate by ID keeping the last occurrence.
	rules = append(rules, cfg.Rules...)
	rules = dedupeRulesByID(rules)

	reveal := cfg.RevealPrefix
	if reveal == 0 {
		reveal = 4
	}
	if reveal < 0 {
		reveal = 0
	}
	if reveal > 8 {
		reveal = 8
	}
	maxPerFile := cfg.MaxFindingsPerFile
	if maxPerFile <= 0 {
		maxPerFile = 100
	}

	d := &Detector{
		rules:        rules,
		entropy:      cfg.Entropy.withDefaults(),
		allow:        cfg.Allowlist,
		revealPrefix: reveal,
		maxPerFile:   maxPerFile,
		byRule:       make(map[string]*atomic.Int64, len(rules)+1),
	}
	for _, r := range rules {
		d.byRule[r.ID] = &atomic.Int64{}
	}
	d.byRule[EntropyRuleID] = &atomic.Int64{}
	return d
}

// Rules returns the active rule IDs (built-ins plus configured), sorted, for
// diagnostics and admin inspection.
func (d *Detector) Rules() []string {
	ids := make([]string, 0, len(d.rules))
	for _, r := range d.rules {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// ScanFiles scans the added lines of every file and returns the merged,
// de-duplicated findings. It updates detector metrics for the scanned commit.
func (d *Detector) ScanFiles(files []FileInput) []Finding {
	d.metrics.diffsScanned.Add(1)
	var out []Finding
	seen := make(map[string]struct{})
	for _, f := range files {
		for _, fnd := range d.scanFile(f) {
			if _, dup := seen[fnd.Fingerprint]; dup {
				continue
			}
			seen[fnd.Fingerprint] = struct{}{}
			out = append(out, fnd)
		}
	}
	return out
}

// scanFile scans a single file's added lines.
func (d *Detector) scanFile(f FileInput) []Finding {
	if f.Binary || strings.TrimSpace(f.Patch) == "" {
		return nil
	}
	d.metrics.filesScanned.Add(1)
	if d.allow.pathAllowed(f.Path) {
		return nil
	}

	var out []Finding
	for _, ln := range AddedLines(f.Patch) {
		d.metrics.linesScanned.Add(1)
		if len(out) >= d.maxPerFile {
			break
		}
		out = append(out, d.scanLine(f.Path, ln)...)
	}
	if len(out) > d.maxPerFile {
		out = out[:d.maxPerFile]
	}
	return out
}

// scanLine applies every rule and the entropy heuristic to a single added line.
//
// A given secret value is reported at most once per line: named rules run first
// (most specific first, by ruleset order) and the entropy heuristic is suppressed
// for any value a named rule already matched, so a recognized token is not also
// double-counted as a generic high-entropy string.
func (d *Detector) scanLine(path string, ln AddedLine) []Finding {
	var out []Finding
	text := ln.Text
	// seen holds raw secret values already accounted for on this line (whether
	// emitted or allowlist-suppressed), so neither a later rule nor the entropy
	// heuristic re-reports the same value.
	seen := make(map[string]struct{})

	for i := range d.rules {
		r := &d.rules[i]
		for _, secret := range r.match(text) {
			if _, dup := seen[secret]; dup {
				continue
			}
			seen[secret] = struct{}{}
			if fnd, ok := d.makeFinding(path, ln, r.ID, r.Description, r.Severity, secret, 0); ok {
				out = append(out, fnd)
			}
		}
	}

	if d.entropy.Enabled {
		for _, hit := range d.entropy.detect(text) {
			if overlapsSeen(hit.value, seen) {
				continue
			}
			seen[hit.value] = struct{}{}
			if fnd, ok := d.makeFinding(path, ln, EntropyRuleID,
				"High-entropy string resembling a secret or credential",
				d.entropy.Severity, hit.value, hit.entropy); ok {
				out = append(out, fnd)
			}
		}
	}
	return out
}

// overlapsSeen reports whether value equals, contains, or is contained by any
// already-seen secret on the line, so the entropy heuristic does not re-flag a
// value a named rule already captured (possibly with a prefix like "ghp_").
func overlapsSeen(value string, seen map[string]struct{}) bool {
	for s := range seen {
		if s == value || strings.Contains(s, value) || strings.Contains(value, s) {
			return true
		}
	}
	return false
}

// makeFinding redacts the secret, builds a fingerprint, applies allowlist
// suppression, and updates metrics. ok is false when the finding was suppressed.
func (d *Detector) makeFinding(path string, ln AddedLine, ruleID, desc, severity, secret string, entropy float64) (Finding, bool) {
	if d.allow.matchAllowed(secret) || d.allow.lineAllowed(ln.Text) {
		d.metrics.suppressed.Add(1)
		return Finding{}, false
	}
	fp := fingerprint(ruleID, path, secret)
	if d.allow.fingerprintAllowed(fp) {
		d.metrics.suppressed.Add(1)
		return Finding{}, false
	}
	f := Finding{
		RuleID:      ruleID,
		Description: desc,
		Severity:    normalizeSeverity(severity),
		File:        path,
		Line:        ln.Line,
		Match:       redact(secret, d.revealPrefix),
		Entropy:     roundEntropy(entropy),
		Fingerprint: fp,
	}
	d.metrics.findings.Add(1)
	d.counterFor(ruleID).Add(1)
	return f, true
}

// counterFor returns the per-rule counter, lazily creating one for an unknown
// rule ID (e.g. a rule added after construction).
func (d *Detector) counterFor(ruleID string) *atomic.Int64 {
	d.byRuleMu.RLock()
	c, ok := d.byRule[ruleID]
	d.byRuleMu.RUnlock()
	if ok {
		return c
	}
	d.byRuleMu.Lock()
	defer d.byRuleMu.Unlock()
	if c, ok := d.byRule[ruleID]; ok {
		return c
	}
	c = &atomic.Int64{}
	d.byRule[ruleID] = c
	return c
}

// Snapshot is a point-in-time view of detector counters, for metrics binding.
type Snapshot struct {
	// DiffsScanned counts commits (file sets) submitted to ScanFiles.
	DiffsScanned int64
	// FilesScanned counts individual non-binary files inspected.
	FilesScanned int64
	// LinesScanned counts added diff lines inspected.
	LinesScanned int64
	// FindingsTotal counts emitted (non-suppressed) findings.
	FindingsTotal int64
	// Suppressed counts matches dropped by the allowlist/baseline.
	Suppressed int64
	// ByRule maps each rule ID to its cumulative finding count.
	ByRule map[string]int64
}

// Metrics returns a snapshot of the detector's cumulative counters.
func (d *Detector) Metrics() Snapshot {
	d.byRuleMu.RLock()
	byRule := make(map[string]int64, len(d.byRule))
	for id, c := range d.byRule {
		byRule[id] = c.Load()
	}
	d.byRuleMu.RUnlock()
	return Snapshot{
		DiffsScanned:  d.metrics.diffsScanned.Load(),
		FilesScanned:  d.metrics.filesScanned.Load(),
		LinesScanned:  d.metrics.linesScanned.Load(),
		FindingsTotal: d.metrics.findings.Load(),
		Suppressed:    d.metrics.suppressed.Load(),
		ByRule:        byRule,
	}
}

// fingerprint is a stable identifier for a finding, derived from the rule, file
// path, and the raw secret. It is the value an operator records in a baseline to
// suppress a specific known finding. The raw secret is hashed, never stored.
func fingerprint(ruleID, path, secret string) string {
	h := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + secret))
	return hex.EncodeToString(h[:8])
}

// redact masks a secret, preserving at most reveal leading characters so a
// finding is identifiable without leaking the credential. Short secrets are
// fully masked.
func redact(secret string, reveal int) string {
	n := len(secret)
	if n == 0 {
		return ""
	}
	if reveal > 0 && n > reveal+2 {
		return secret[:reveal] + strings.Repeat("*", min(n-reveal, 8))
	}
	return strings.Repeat("*", min(n, 8))
}

// dedupeRulesByID keeps the last occurrence of each rule ID so a configured
// rule overrides a built-in with the same ID. Order otherwise preserved.
func dedupeRulesByID(rules []Rule) []Rule {
	lastIdx := make(map[string]int, len(rules))
	for i, r := range rules {
		lastIdx[r.ID] = i
	}
	out := make([]Rule, 0, len(rules))
	for i, r := range rules {
		if lastIdx[r.ID] == i {
			out = append(out, r)
		}
	}
	return out
}

// normalizeSeverity coerces an arbitrary severity string to a known value,
// defaulting unknown/empty inputs to medium (a deterministic regex match is a
// concrete signal, so the floor is not "info").
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SeverityInfo:
		return SeverityInfo
	case SeverityLow:
		return SeverityLow
	case SeverityMedium, "med":
		return SeverityMedium
	case SeverityHigh:
		return SeverityHigh
	case SeverityCritical, "crit":
		return SeverityCritical
	default:
		return SeverityMedium
	}
}
