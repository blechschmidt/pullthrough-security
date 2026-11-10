package commit

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Deterministic result-cache keying (Task 78).
//
// A commit's verdict is cached so a re-scan — whether triggered by another pull
// of the same dependency, a CVE-drift revalidation, or an operator inspection —
// never re-bills the provider for an identical analysis. The cache key must,
// however, change when anything that would change the verdict changes: the model
// performing the analysis, the prompt template, or the deterministic ruleset.
// Otherwise an upgrade (a smarter model, a fixed prompt, a new secret rule) would
// silently serve stale verdicts.
//
// The key folds four inputs:
//
//   - the commit SHA (the subject of the analysis),
//   - the set of model IDs that may produce the verdict (triage, deep, and any
//     consensus providers),
//   - the prompt-template version (PromptVersion, bumped on prompt changes),
//   - a ruleset hash (the deterministic secret/injection rules in effect).

// PromptVersion is the version of the prompt template + output contract. It is
// part of the verdict cache key: bump it whenever the system/user prompt or the
// expected output schema changes so prior verdicts are recomputed rather than
// served stale. v2 introduces the prompt-injection delimiting/defanging and the
// canary-based output validation (Task 78).
const PromptVersion = 2

// signature derives the stable cache-key suffix from the model set, the prompt
// version, and the ruleset hash. The result is a short hex digest; combined with
// the commit SHA it forms the per-commit cache key. Model order is normalized so
// the same set of models always yields the same signature.
func signature(promptVersion int, models []string, rulesetHash string) string {
	norm := make([]string, 0, len(models))
	for _, m := range models {
		if m = strings.TrimSpace(m); m != "" {
			norm = append(norm, m)
		}
	}
	sort.Strings(norm)

	h := sha256.New()
	h.Write([]byte("pv=" + strconv.Itoa(promptVersion)))
	h.Write([]byte{0})
	h.Write([]byte("models=" + strings.Join(norm, ",")))
	h.Write([]byte{0})
	h.Write([]byte("rules=" + rulesetHash))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// cacheKey returns the storage key for a commit's verdict under this pipeline's
// signature: "<sha>-<signature>". The SHA is validated/normalized by the store;
// this only appends the signature suffix.
func cacheKey(sha, sig string) string {
	sha = strings.TrimSpace(sha)
	if sig == "" {
		return sha
	}
	return sha + "-" + sig
}

// rulesetHash derives a stable hash from the identifying tokens of the
// deterministic rulesets in effect (secret-scan rule IDs, injection ruleset
// version). main.go passes the secret-rule identity; an empty input still yields
// a hash that includes the injection ruleset version so a change there forces a
// re-scan.
func rulesetHash(tokens ...string) string {
	norm := make([]string, 0, len(tokens)+1)
	norm = append(norm, InjectionRulesetVersion)
	for _, t := range tokens {
		if t = strings.TrimSpace(t); t != "" {
			norm = append(norm, t)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\x00")))
	return hex.EncodeToString(sum[:8])
}
