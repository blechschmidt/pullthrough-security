package installhooks

import (
	"regexp"
	"strings"
)

// Stable rule identifiers for the high-risk install-hook patterns. They are the
// per-finding identifiers surfaced in metrics, the admin view, and the SARIF
// property bag; the SARIF catalog folds them all under one bounded rule
// (installhooks/risky-install-script).
const (
	RuleDownloadExecute  = "download-execute"
	RuleEvalBase64       = "eval-base64"
	RuleEnvExfil         = "env-exfiltration"
	RuleNetworkEgress    = "network-egress"
	RuleShellSpawn       = "shell-spawn"
	RuleFSWriteOutside   = "fs-write-outside"
	RuleObfuscation      = "obfuscation"
	RuleNativeExtension  = "native-extension"
	RuleWildcardActivate = "wildcard-activation"
)

// Severity is the gate's risk vocabulary, ordered info < low < medium < high <
// critical. It maps onto the canonical findings/SARIF severity scale by name.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank returns a comparable ordinal (info=1 .. critical=5), or 0 for an
// empty/unknown severity so it never accidentally meets a threshold.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ParseSeverity normalizes a string into a Severity, returning ok=false for an
// unrecognized value (empty maps to ok=false so callers can substitute a
// default).
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityInfo:
		return SeverityInfo, true
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityCritical:
		return SeverityCritical, true
	default:
		return "", false
	}
}

// Rule is one compiled detection rule: a stable id, a display title, the
// severity it raises, and the regular expression that matches the risky pattern
// on a single (whitespace-normalized) line of hook text.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	re       *regexp.Regexp
}

// match returns one entry per line of script that the rule's pattern matches,
// each carrying the 1-based line number and a redacted excerpt. A rule matches
// at most once per line (the pattern's first hit drives the excerpt).
func (r *Rule) match(script string) []match {
	if r.re == nil || script == "" {
		return nil
	}
	var out []match
	line := 0
	for _, raw := range strings.Split(script, "\n") {
		line++
		norm := normalizeLine(raw)
		if norm == "" {
			continue
		}
		if r.re.MatchString(norm) {
			out = append(out, match{line: line, excerpt: excerpt(norm)})
		}
	}
	return out
}

type match struct {
	line    int
	excerpt string
}

// RuleSpec is the externally-configurable form of a rule (a row in the rule
// catalog the operator can enable/disable or override). Pattern is a Go regular
// expression compiled case-insensitively unless it already carries flags.
type RuleSpec struct {
	ID       string
	Title    string
	Severity Severity
	Pattern  string
}

// builtinRuleSpecs is the fixed catalog of high-risk install-hook patterns, in
// canonical (and severity-descending) order. The patterns are intentionally
// conservative — they target the behaviors that are abnormal for a legitimate
// build/install step — and run only over the install-time hook text, never the
// package's ordinary source, to keep false positives low.
var builtinRuleSpecs = []RuleSpec{
	{
		ID:       RuleDownloadExecute,
		Title:    "Remote script piped directly into a shell/interpreter",
		Severity: SeverityCritical,
		// curl|wget ... | sh|bash|node|python ; the classic "curl | sh" dropper.
		Pattern: `(?i)\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python[0-9.]*|ruby|perl|pwsh|powershell)\b`,
	},
	{
		ID:       RuleEvalBase64,
		Title:    "base64/hex-decoded payload passed to eval/exec",
		Severity: SeverityCritical,
		// eval( atob( ... )) / Buffer.from(...,'base64')...eval / base64 -d | sh /
		// exec(base64.b64decode(...)).
		Pattern: `(?i)(?:eval|exec|new\s+function|child_process)[^\n]{0,80}(?:atob|b64decode|base64\.b64decode|from\s*\(\s*['"][^'"]+['"]\s*,\s*['"]?base64|base64\s+(?:-d|--decode)|frombase64string)`,
	},
	{
		ID:       RuleEnvExfil,
		Title:    "Environment variables read and sent off-host",
		Severity: SeverityHigh,
		// process.env / os.environ / printenv / $ENV serialized toward a network
		// sink (a URL, an http client, or a curl/wget data flag).
		Pattern: `(?i)(?:process\.env|os\.environ|printenv|env\b)[^\n]{0,120}(?:https?://|fetch\(|axios|requests\.(?:post|get)|urllib|net\.connect|\bcurl\b|\bwget\b|-d\s|--data|nc\s)`,
	},
	{
		ID:       RuleNetworkEgress,
		Title:    "Network egress during install",
		Severity: SeverityHigh,
		// A download/exfil primitive anywhere in an install hook.
		Pattern: `(?i)\b(?:curl|wget|nc|ncat|netcat|telnet)\b|\b(?:https?|ftp)://|(?:require\(['"](?:https?|net|dgram|tls)['"]\))|fetch\(|axios|urllib\.request|requests\.(?:get|post)|net\.connect|new\s+xmlhttprequest`,
	},
	{
		ID:       RuleShellSpawn,
		Title:    "Spawns a shell or child process",
		Severity: SeverityHigh,
		// child_process.exec/spawn/execSync, os.system, subprocess, Kernel#system,
		// backticks, sh -c.
		Pattern: `(?i)child_process|\b(?:exec|execsync|spawn|spawnsync|execfile)\s*\(|os\.system\s*\(|subprocess\.(?:popen|call|run|check_output)|\bsystem\s*\(|\bpopen\s*\(|\bsh\s+-c\b|\bbash\s+-c\b|backtick`,
	},
	{
		ID:       RuleFSWriteOutside,
		Title:    "Writes outside the package directory",
		Severity: SeverityHigh,
		// Writes/appends to a home dotfile, ssh dir, shell rc, cron, or an absolute
		// system path — persistence/escape from the install sandbox.
		Pattern: `(?i)(?:~|\$home|%userprofile%|/root|/etc|/usr/|/var/|/tmp/)[^\n]*(?:\.ssh|\.bashrc|\.bash_profile|\.profile|\.zshrc|authorized_keys|crontab|cron\.d|rc\.local|/bin/)|>>\s*(?:~|\$home|/etc|/root)`,
	},
	{
		ID:       RuleObfuscation,
		Title:    "Obfuscated one-liner",
		Severity: SeverityMedium,
		// fromCharCode / long \x.. escape runs / unescape / dense base64 blobs that
		// hide intent.
		Pattern: `(?i)string\.fromcharcode|fromcharcode\(|(?:\\x[0-9a-f]{2}){6,}|\\u00[0-9a-f]{2}(?:\\u00[0-9a-f]{2}){5,}|unescape\(|\\[0-7]{3}(?:\\[0-7]{3}){6,}`,
	},
	{
		ID:       RuleNativeExtension,
		Title:    "Compiles a native extension / build script",
		Severity: SeverityLow,
		// extconf.rb / Rakefile native builds / Cargo build.rs / node-gyp /
		// setup.py Extension — informational: native build steps run arbitrary
		// compiler-driven code and warrant a closer look.
		Pattern: `(?i)\bmkmf\b|create_makefile|node-gyp|node-pre-gyp|prebuild-install|cc::build|cargo:rerun-if|\bExtension\s*\(|build_ext`,
	},
	{
		ID:       RuleWildcardActivate,
		Title:    "VS Code extension activates on every startup (wildcard activationEvent)",
		Severity: SeverityLow,
		// The openvsx extractor renders each activationEvent as an
		// "activationEvent: <evt>" line; a bare "*" means the extension's code runs
		// on every editor startup regardless of context — abnormal for a focused
		// extension and a common marketplace-malware trait. Matches only the
		// synthetic activation-hook text, so it never fires for other ecosystems.
		Pattern: `(?i)^activationevent:\s*\*\s*$`,
	},
}

// maxSeverity returns the highest severity across the findings (or "" for none).
func maxSeverity(findings []Finding) Severity {
	var worst Severity
	for i := range findings {
		if severityRank(findings[i].Severity) > severityRank(worst) {
			worst = findings[i].Severity
		}
	}
	return worst
}

// riskScore maps the worst severity (and finding volume) onto a 0..100 ordinal
// risk contribution. The base is severity-driven so a single critical pattern
// already dominates; additional findings add a bounded surcharge against the
// remaining headroom so they can only raise the score.
func riskScore(worst Severity, count int) int {
	base := 0
	switch worst {
	case SeverityCritical:
		base = 95
	case SeverityHigh:
		base = 80
	case SeverityMedium:
		base = 55
	case SeverityLow:
		base = 30
	case SeverityInfo:
		base = 12
	default:
		return 0
	}
	if count > 1 {
		extra := (count - 1) * 3
		headroom := 100 - base
		if extra > headroom {
			extra = headroom
		}
		base += extra
	}
	if base > 100 {
		base = 100
	}
	return base
}

// normalizeLine collapses runs of whitespace to a single space and trims the
// line so a rule pattern need not account for arbitrary indentation/spacing
// (and a multi-space-padded payload cannot evade a single-space pattern).
func normalizeLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// excerpt renders a redacted, length-bounded rendering of a matched line for a
// finding. It keeps the line legible in logs/SARIF without dumping a large blob.
func excerpt(norm string) string {
	const max = 160
	if len(norm) <= max {
		return norm
	}
	return norm[:max] + "…"
}
