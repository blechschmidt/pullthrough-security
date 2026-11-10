package secretscan

import (
	"math"
	"regexp"
	"strings"
)

// EntropyConfig configures the generic high-entropy heuristic. It is deliberately
// conservative: it inspects candidate values that appear on the right-hand side
// of an assignment (key = value / key: value) or inside a quoted string, and
// flags them only when their Shannon entropy and length exceed thresholds. Hex
// candidates additionally require a secret-suggesting key to avoid flagging the
// many legitimate hex digests (commit SHAs, checksums) that pervade lockfiles.
type EntropyConfig struct {
	// Enabled turns the heuristic on. It defaults to true via withDefaults.
	Enabled bool
	// MinLength and MaxLength bound the candidate token length considered.
	MinLength int
	MaxLength int
	// Base64Entropy is the bits/char threshold for base64-charset candidates.
	Base64Entropy float64
	// HexEntropy is the bits/char threshold for hex-charset candidates (only
	// evaluated when the surrounding key looks secret-related).
	HexEntropy float64
	// Severity is the severity assigned to entropy findings.
	Severity string
	// disabledExplicitly records that the caller set Enabled=false on a non-zero
	// config so withDefaults does not flip it back on.
	disabledExplicitly bool
}

// EntropyConfigDisabled returns an EntropyConfig that stays disabled through
// withDefaults (the zero value enables the heuristic by default).
func EntropyConfigDisabled() EntropyConfig {
	return EntropyConfig{disabledExplicitly: true}
}

// withDefaults fills zero fields with sensible defaults. A wholly zero config
// enables the heuristic; use EntropyConfigDisabled to opt out.
func (c EntropyConfig) withDefaults() EntropyConfig {
	if (c == EntropyConfig{}) {
		c.Enabled = true
	}
	if c.disabledExplicitly {
		c.Enabled = false
	}
	if c.MinLength <= 0 {
		c.MinLength = 20
	}
	if c.MaxLength <= 0 {
		c.MaxLength = 100
	}
	if c.Base64Entropy <= 0 {
		c.Base64Entropy = 4.5
	}
	if c.HexEntropy <= 0 {
		c.HexEntropy = 3.5
	}
	if c.Severity == "" {
		c.Severity = SeverityMedium
	}
	return c
}

// entropyHit is one high-entropy candidate found on a line.
type entropyHit struct {
	value   string
	entropy float64
}

// assignmentRe captures an optional key and the assigned value, covering both
// quoted ("key": "VALUE", key = "VALUE") and unquoted (key=VALUE, key: VALUE)
// right-hand sides. The token charset is the union of base64, hex, and the
// url-safe/token punctuation commonly found in credentials.
var assignmentRe = regexp.MustCompile(
	`(?i)([A-Za-z0-9_.\-]{1,40})?\s*[:=]\s*['"]?([A-Za-z0-9+/=_\-]{12,200})['"]?`)

// quotedRe captures standalone quoted string literals, so a bare
// "BASE64SECRET" in an array or argument is still considered.
var quotedRe = regexp.MustCompile(`['"]([A-Za-z0-9+/=_\-]{12,200})['"]`)

var (
	hexRe       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	secretKeyRe = regexp.MustCompile(`(?i)(secret|token|key|pass|pwd|cred|auth|api|access|private|cert|signature|sig|nonce|seed)`)
	// stopContextRe marks lines that carry high-entropy strings which are not
	// secrets: dependency-lock integrity hashes, content-addressable digests,
	// and inline data URIs. The heuristic skips these lines entirely (named
	// rules still run).
	stopContextRe = regexp.MustCompile(`(?i)(integrity|sha512-|sha384-|sha256-|sha1-|;base64,|data:[a-z]+/|"?resolved"?\s*[:=]|\bgit\+https?://|#[0-9a-f]{7,40}\b|/blob/[0-9a-f]{40}|content-?hash)`)
)

// detect returns every high-entropy candidate on a line that passes the
// heuristic's gating.
func (c EntropyConfig) detect(line string) []entropyHit {
	if stopContextRe.MatchString(line) {
		return nil
	}
	seen := make(map[string]struct{})
	var hits []entropyHit

	consider := func(key, value string) {
		if value == "" {
			return
		}
		if _, dup := seen[value]; dup {
			return
		}
		if h, ok := c.evaluate(key, value); ok {
			seen[value] = struct{}{}
			hits = append(hits, h)
		}
	}

	for _, m := range assignmentRe.FindAllStringSubmatch(line, -1) {
		consider(m[1], m[2])
	}
	for _, m := range quotedRe.FindAllStringSubmatch(line, -1) {
		consider("", m[1])
	}
	return hits
}

// evaluate decides whether a single candidate value is a high-entropy hit given
// its (optional) key context.
func (c EntropyConfig) evaluate(key, value string) (entropyHit, bool) {
	v := strings.Trim(value, `"'`)
	n := len(v)
	if n < c.MinLength || n > c.MaxLength {
		return entropyHit{}, false
	}
	// A value with too few distinct characters is structurally not a secret
	// (e.g. "aaaaaaaaaaaaaaaaaaaa" or "----------------------").
	if distinctChars(v) < 6 {
		return entropyHit{}, false
	}
	ent := shannonEntropy(v)
	keySecretish := key != "" && secretKeyRe.MatchString(key)

	if hexRe.MatchString(v) {
		// Hex digests are abundant and benign (commit SHAs, checksums); only flag
		// when the key clearly names a secret.
		if keySecretish && ent >= c.HexEntropy {
			return entropyHit{value: v, entropy: ent}, true
		}
		return entropyHit{}, false
	}

	// Non-hex (base64/url-safe) candidate.
	threshold := c.Base64Entropy
	if keySecretish {
		// A secret-named key lowers the bar slightly since the context is strong.
		threshold -= 0.3
	} else if n < 24 {
		// Without a secret-named key, require a longer token to avoid flagging
		// ordinary identifiers and slugs.
		return entropyHit{}, false
	}
	if ent >= threshold {
		return entropyHit{value: v, entropy: ent}, true
	}
	return entropyHit{}, false
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

// distinctChars counts the distinct byte values in s.
func distinctChars(s string) int {
	var seen [256]bool
	count := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			count++
		}
	}
	return count
}

// roundEntropy rounds to 3 decimals for stable, readable findings.
func roundEntropy(e float64) float64 {
	return math.Round(e*1000) / 1000
}
