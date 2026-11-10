package secretscan

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule is a compiled deterministic detection rule. A Rule fires when its
// pattern matches an added diff line; when Keywords are set the line must first
// contain one of them (a cheap pre-filter), and when MinEntropy is set the
// captured secret must have at least that Shannon entropy (bits/char).
type Rule struct {
	// ID is a stable, unique identifier (used for metrics and baselines).
	ID string
	// Description explains what the rule detects.
	Description string
	// Severity is the default severity for findings from this rule.
	Severity string
	// Pattern is the compiled detection regex.
	Pattern *regexp.Regexp
	// Group selects which submatch is the secret (0 = whole match). Used for
	// redaction, entropy gating, and fingerprinting.
	Group int
	// Keywords, when non-empty, gate the rule: the line must contain one of
	// these (case-insensitive) before Pattern is evaluated.
	Keywords []string
	// MinEntropy, when > 0, requires the captured secret's Shannon entropy to be
	// at least this value, suppressing obvious placeholders.
	MinEntropy float64
}

// match returns every secret captured by the rule on a single line, after
// keyword and entropy gating.
func (r *Rule) match(line string) []string {
	if len(r.Keywords) > 0 && !containsAnyFold(line, r.Keywords) {
		return nil
	}
	matches := r.Pattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		secret := m[0]
		if r.Group > 0 && r.Group < len(m) {
			secret = m[r.Group]
		}
		if secret == "" {
			continue
		}
		if r.MinEntropy > 0 && shannonEntropy(secret) < r.MinEntropy {
			continue
		}
		out = append(out, secret)
	}
	return out
}

// RuleSpec is the serializable form of a Rule, loadable from configuration so
// operators can extend or replace the ruleset without recompiling.
type RuleSpec struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Group       int      `yaml:"group" json:"group"`
	Keywords    []string `yaml:"keywords" json:"keywords"`
	MinEntropy  float64  `yaml:"minEntropy" json:"minEntropy"`
}

// Compile validates and compiles a RuleSpec into a Rule.
func (s RuleSpec) Compile() (Rule, error) {
	id := strings.TrimSpace(s.ID)
	if id == "" {
		return Rule{}, fmt.Errorf("secretscan: rule is missing an id")
	}
	if strings.TrimSpace(s.Pattern) == "" {
		return Rule{}, fmt.Errorf("secretscan: rule %q is missing a pattern", id)
	}
	re, err := regexp.Compile(s.Pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("secretscan: rule %q has an invalid pattern: %w", id, err)
	}
	if s.Group < 0 {
		return Rule{}, fmt.Errorf("secretscan: rule %q has a negative group", id)
	}
	kw := make([]string, 0, len(s.Keywords))
	for _, k := range s.Keywords {
		if k = strings.TrimSpace(k); k != "" {
			kw = append(kw, k)
		}
	}
	return Rule{
		ID:          id,
		Description: strings.TrimSpace(s.Description),
		Severity:    normalizeSeverity(s.Severity),
		Pattern:     re,
		Group:       s.Group,
		Keywords:    kw,
		MinEntropy:  s.MinEntropy,
	}, nil
}

// CompileRules compiles a list of specs, failing on the first invalid rule and
// rejecting duplicate IDs so a misconfiguration is caught at startup.
func CompileRules(specs []RuleSpec) ([]Rule, error) {
	seen := make(map[string]bool, len(specs))
	out := make([]Rule, 0, len(specs))
	for i, s := range specs {
		r, err := s.Compile()
		if err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("secretscan: duplicate rule id %q (index %d)", r.ID, i)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}

// mustRule compiles a built-in rule, panicking on error. Built-in patterns are
// constant and covered by tests, so a panic here is a programmer error.
func mustRule(id, desc, severity, pattern string, group int, minEntropy float64, keywords ...string) Rule {
	r, err := RuleSpec{
		ID:          id,
		Description: desc,
		Severity:    severity,
		Pattern:     pattern,
		Group:       group,
		Keywords:    keywords,
		MinEntropy:  minEntropy,
	}.Compile()
	if err != nil {
		panic(err)
	}
	return r
}

// builtinRules is the default high-confidence ruleset. The patterns target
// credential formats whose structure makes a true positive overwhelmingly
// likely; lower-confidence/generic cases are left to the entropy heuristic.
//
// Word boundaries (\b) and anchored prefixes keep these from matching substrings
// of larger tokens, which is the main source of false positives for fixed-format
// keys.
var builtinRules = []Rule{
	// --- AWS -------------------------------------------------------------
	mustRule("aws-access-key-id",
		"AWS access key ID",
		SeverityHigh,
		`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b`,
		1, 0),
	mustRule("aws-secret-access-key",
		"AWS secret access key (assigned near an aws* identifier)",
		SeverityCritical,
		`(?i)aws[a-z0-9_.\- ]{0,28}?(?:secret|access)[a-z0-9_.\- ]{0,20}?key["'\s]{0,4}[:=]\s*["']([A-Za-z0-9/+]{40})["']`,
		1, 4.0, "aws"),

	// --- GCP -------------------------------------------------------------
	mustRule("gcp-service-account",
		"GCP service-account credential JSON (type=service_account)",
		SeverityCritical,
		`"type"\s*:\s*"service_account"`,
		0, 0, "service_account"),
	mustRule("gcp-api-key",
		"Google API key",
		SeverityHigh,
		`\b(AIza[0-9A-Za-z\-_]{35})\b`,
		1, 0),

	// --- GitHub / GitLab -------------------------------------------------
	mustRule("github-token",
		"GitHub personal-access / OAuth / app token",
		SeverityHigh,
		`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`,
		1, 0),
	mustRule("github-fine-grained-pat",
		"GitHub fine-grained personal-access token",
		SeverityHigh,
		`\b(github_pat_[0-9a-zA-Z_]{82})\b`,
		1, 0),
	mustRule("gitlab-pat",
		"GitLab personal-access token",
		SeverityHigh,
		`\b(glpat-[0-9A-Za-z\-_]{20})\b`,
		1, 0),

	// --- Slack -----------------------------------------------------------
	mustRule("slack-token",
		"Slack API token",
		SeverityHigh,
		`\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b`,
		1, 0),
	mustRule("slack-webhook",
		"Slack incoming-webhook URL",
		SeverityMedium,
		`(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{16,})`,
		1, 0),

	// --- Private keys ----------------------------------------------------
	mustRule("private-key-block",
		"PEM private-key block",
		SeverityCritical,
		`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`,
		0, 0),

	// --- JWT -------------------------------------------------------------
	mustRule("jwt",
		"JSON Web Token",
		SeverityMedium,
		`\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`,
		1, 0),

	// --- Other common providers -----------------------------------------
	mustRule("stripe-secret-key",
		"Stripe secret/restricted key",
		SeverityCritical,
		`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`,
		1, 0),
	mustRule("npm-token",
		"npm access token",
		SeverityHigh,
		`\b(npm_[0-9A-Za-z]{36})\b`,
		1, 0),
	mustRule("generic-secret-assignment",
		"Generic bearer secret assigned to a secret-named variable",
		SeverityMedium,
		`(?i)(?:secret|token|password|passwd|api[_.\- ]?key|access[_.\- ]?key)["' ]*[:=]\s*['"]([^\s'"]{12,80})['"]`,
		1, 3.2, "secret", "token", "password", "passwd", "apikey", "api_key", "api-key", "accesskey", "access_key", "access-key"),
}

// BuiltinRuleSpecs returns the built-in ruleset in serializable form, useful for
// documentation, admin display, and as a starting point for a custom ruleset.
func BuiltinRuleSpecs() []RuleSpec {
	out := make([]RuleSpec, 0, len(builtinRules))
	for _, r := range builtinRules {
		out = append(out, RuleSpec{
			ID:          r.ID,
			Description: r.Description,
			Severity:    r.Severity,
			Pattern:     r.Pattern.String(),
			Group:       r.Group,
			Keywords:    r.Keywords,
			MinEntropy:  r.MinEntropy,
		})
	}
	return out
}

// containsAnyFold reports whether s contains any of subs, case-insensitively.
func containsAnyFold(s string, subs []string) bool {
	ls := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(ls, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
