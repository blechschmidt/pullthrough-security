package secretscan

import (
	"fmt"
	"regexp"
	"strings"
)

// Allowlist suppresses known false positives and accepted test fixtures. A
// match is suppressed when any of the following holds:
//
//   - the file path matches a Paths pattern (e.g. testdata/, fixtures/);
//   - the matched secret matches a Patterns pattern (e.g. AWS docs example
//     keys, obvious placeholders like "EXAMPLE"/"changeme");
//   - the added line contains a StopWord (case-insensitive), e.g. "example";
//   - the finding's fingerprint is present in the Fingerprints baseline.
//
// The zero value suppresses nothing.
type Allowlist struct {
	// Paths are regexes matched against the file path.
	Paths []*regexp.Regexp
	// Patterns are regexes matched against the raw matched secret.
	Patterns []*regexp.Regexp
	// StopWords are substrings; a line containing one (case-insensitive) is
	// exempt.
	StopWords []string
	// Fingerprints is a baseline of accepted finding fingerprints to suppress.
	Fingerprints map[string]bool
}

func (a *Allowlist) pathAllowed(path string) bool {
	if path == "" {
		return false
	}
	for _, re := range a.Paths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (a *Allowlist) matchAllowed(secret string) bool {
	for _, re := range a.Patterns {
		if re.MatchString(secret) {
			return true
		}
	}
	return false
}

func (a *Allowlist) lineAllowed(line string) bool {
	if len(a.StopWords) == 0 {
		return false
	}
	return containsAnyFold(line, a.StopWords)
}

func (a *Allowlist) fingerprintAllowed(fp string) bool {
	return a.Fingerprints[fp]
}

// AllowlistSpec is the serializable form of an Allowlist, loadable from config.
type AllowlistSpec struct {
	// Paths are regexes for file paths to exempt.
	Paths []string `yaml:"paths" json:"paths"`
	// Patterns are regexes for secret values to exempt.
	Patterns []string `yaml:"patterns" json:"patterns"`
	// StopWords are case-insensitive substrings that exempt a whole line.
	StopWords []string `yaml:"stopWords" json:"stopWords"`
	// Fingerprints is a baseline of accepted finding fingerprints.
	Fingerprints []string `yaml:"fingerprints" json:"fingerprints"`
	// DisableBuiltins drops the built-in placeholder/example allowlist.
	DisableBuiltins bool `yaml:"disableBuiltins" json:"disableBuiltins"`
}

// Compile validates and compiles an AllowlistSpec. Built-in placeholder
// patterns and common fixture-path patterns are included unless DisableBuiltins
// is set.
func (s AllowlistSpec) Compile() (Allowlist, error) {
	var a Allowlist
	if !s.DisableBuiltins {
		a.Paths = append(a.Paths, builtinFixturePaths()...)
		a.Patterns = append(a.Patterns, builtinPlaceholderPatterns()...)
	}
	for i, p := range s.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return Allowlist{}, fmt.Errorf("secretscan: allowlist path pattern %d (%q): %w", i, p, err)
		}
		a.Paths = append(a.Paths, re)
	}
	for i, p := range s.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return Allowlist{}, fmt.Errorf("secretscan: allowlist secret pattern %d (%q): %w", i, p, err)
		}
		a.Patterns = append(a.Patterns, re)
	}
	for _, w := range s.StopWords {
		if w = strings.TrimSpace(w); w != "" {
			a.StopWords = append(a.StopWords, w)
		}
	}
	if len(s.Fingerprints) > 0 {
		a.Fingerprints = make(map[string]bool, len(s.Fingerprints))
		for _, fp := range s.Fingerprints {
			if fp = strings.TrimSpace(fp); fp != "" {
				a.Fingerprints[fp] = true
			}
		}
	}
	return a, nil
}

// builtinFixturePaths exempts conventional test-fixture locations so the proxy's
// own and downstream projects' test corpora do not generate noise.
func builtinFixturePaths() []*regexp.Regexp {
	pats := []string{
		`(^|/)testdata/`,
		`(^|/)fixtures?/`,
		`(^|/)__fixtures__/`,
		`(^|/)test/fixtures/`,
		`_test\.(go|py|js|ts|rb|java|rs)$`,
		`\.(spec|test)\.(js|ts|jsx|tsx)$`,
	}
	return compileAll(pats)
}

// builtinPlaceholderPatterns exempts secrets that are obviously documentation
// examples or placeholders, including the canonical AWS docs example keys.
func builtinPlaceholderPatterns() []*regexp.Regexp {
	pats := []string{
		`(?i)example`,
		`(?i)placeholder`,
		`(?i)changeme`,
		`(?i)your[_-]?(?:secret|token|key|password)`,
		`(?i)dummy`,
		`(?i)redacted`,
		`(?i)^x{8,}$`,          // XXXXXXXX...
		`(?i)^[a0]{16,}$`,      // aaaa.... / 0000....
		`AKIAIOSFODNN7EXAMPLE`, // AWS docs access key
		`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, // AWS docs secret key
	}
	return compileAll(pats)
}

func compileAll(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
