// Package malfeed implements a known-malicious-package admission gate (Task 48).
//
// Unlike nameguard (Task 19), which applies typosquatting/dependency-confusion
// heuristics, and vulnscan (Task 15), which matches CVE advisories against an
// artifact's SBOM, this gate matches a pull's *concrete coordinate* — the tuple
// (ecosystem, name, version) — against curated datasets of packages that have
// been confirmed actively malicious: crypto-miners, credential stealers, and
// install-script backdoors. The canonical sources are the OpenSSF/OSV
// "malicious-packages" dataset (github.com/ossf/malicious-packages) and the
// malware entries in the GitHub Advisory Database. A match is a hard block: the
// pull is refused with the advisory ID and reason before any upstream fetch or
// cache fill.
//
// The package is deliberately self-contained (standard library only) so it can
// be reused by the gateway gate, the admin surface, the metrics bridge, and the
// offline-bundle CLI without pulling in proxy internals. It is organized as:
//
//   - malfeed.go  — the normalized domain model: Coordinate, Entry, and the
//     ecosystem/name/version normalization that makes matching robust across the
//     spelling differences each registry tolerates.
//   - version.go  — ecosystem-aware version comparison and range membership.
//   - matcher.go  — the immutable, indexed Matcher built from a set of Entries.
//   - osv.go       — parsing the OSV/GHSA JSON schema into Entries.
//   - feed.go      — the live Service: the current matcher, freshness tracking,
//     fail-open/closed staleness policy, and the background refresh loop with
//     ETag/conditional fetch.
//   - bundle.go    — the air-gapped signed import/export bundle (Ed25519).
//
// All exported types are safe for concurrent use unless noted otherwise.
package malfeed

import (
	"sort"
	"strings"
)

// Coordinate identifies the artifact a pull is for: a package in a given
// ecosystem, optionally at a specific version. The version is empty for index /
// metadata lookups that precede a concrete download; the matcher only blocks
// such version-less lookups when the *entire* package is known malicious.
type Coordinate struct {
	// Ecosystem is the package ecosystem as the gateway reports it (pip, npm,
	// cargo, go, nuget, maven, rubygems, composer, and common aliases). It is
	// canonicalized via CanonicalEcosystem before matching.
	Ecosystem string
	// Name is the package name as requested. It is normalized per-ecosystem before
	// matching so equivalent spellings (case, separator, scope) collide.
	Name string
	// Version is the requested version, or empty for a name-only lookup.
	Version string
}

// Entry is a single normalized known-malicious record: a package (or a set of
// its versions) flagged by a feed source, with the advisory metadata needed to
// explain a block. An Entry is immutable once built.
type Entry struct {
	// ID is the primary advisory identifier — an OSV "MAL-..." id, a GHSA id, or a
	// bundle-supplied id. It is surfaced in the block response and the audit log.
	ID string `json:"id"`
	// Ecosystem is the canonical ecosystem key (see CanonicalEcosystem).
	Ecosystem string `json:"ecosystem"`
	// Name is the package name exactly as published by the feed (the normalized
	// form is computed internally; the original is retained for display/search).
	Name string `json:"name"`
	// Aliases are cross-referenced advisory ids (CVE/GHSA/OSV) for this entry.
	Aliases []string `json:"aliases,omitempty"`
	// Summary is a short human-readable reason ("npm credential stealer", ...).
	Summary string `json:"summary,omitempty"`
	// Categories tags the malware class (crypto-miner, credential-stealer,
	// backdoor, ...) when the source provides it.
	Categories []string `json:"categories,omitempty"`
	// AllVersions is true when every version of the package is malicious (the
	// common case for the OSV malicious-packages dataset). Such an entry blocks
	// even a version-less index lookup.
	AllVersions bool `json:"allVersions,omitempty"`
	// Versions are the explicit affected versions (exact match) when the source
	// enumerates them. Ignored when AllVersions is set.
	Versions []string `json:"versions,omitempty"`
	// Ranges are affected version ranges (introduced/fixed/last_affected) when the
	// source expresses the affected set as an interval. Ignored when AllVersions.
	Ranges []VersionRange `json:"ranges,omitempty"`
	// Source names the feed the entry came from (e.g. "osv-malicious-packages",
	// "ghsa", or "bundle").
	Source string `json:"source,omitempty"`
	// Published is the advisory publication timestamp as the source reported it
	// (RFC 3339), retained verbatim for display; empty when unknown.
	Published string `json:"published,omitempty"`

	// norm is the normalized package name used as the index key. Computed once at
	// construction; never serialized.
	norm string
	// normVersions is the set of normalized explicit versions for O(1) lookup.
	normVersions map[string]struct{}
}

// VersionRange is a half-open affected interval following the OSV range model.
// Introduced is the inclusive lower bound ("0" or empty means from the first
// version). Exactly one upper bound applies: Fixed is exclusive (the version the
// fix landed in), LastAffected is inclusive. With no upper bound the range
// extends to the latest version.
type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"lastAffected,omitempty"`
}

// finalize computes the cached normalized fields. It is called once when an
// Entry is admitted to a Matcher.
func (e *Entry) finalize() {
	e.Ecosystem = CanonicalEcosystem(e.Ecosystem)
	e.norm = normalizeName(e.Ecosystem, e.Name)
	if len(e.Versions) > 0 {
		e.normVersions = make(map[string]struct{}, len(e.Versions))
		for _, v := range e.Versions {
			e.normVersions[normalizeVersion(v)] = struct{}{}
		}
	}
}

// matchesVersion reports whether the entry covers normalized version nv. An
// empty nv (name-only lookup) is covered only when the whole package is
// malicious.
func (e *Entry) matchesVersion(nv string) bool {
	if e.AllVersions {
		return true
	}
	if nv == "" {
		// A version-less lookup cannot be matched against version-specific
		// records; only a whole-package block (handled above) applies.
		return false
	}
	if e.normVersions != nil {
		if _, ok := e.normVersions[nv]; ok {
			return true
		}
	}
	for _, rng := range e.Ranges {
		if rng.contains(e.Ecosystem, nv) {
			return true
		}
	}
	return false
}

// CanonicalEcosystem maps the many spellings a feed or the gateway may use to a
// single canonical key. Unknown ecosystems are lowercased and returned as-is so
// the matcher still functions (it simply won't collide with a differently-named
// feed ecosystem).
func CanonicalEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pip", "pypi", "python":
		return "pip"
	case "npm", "node", "nodejs":
		return "npm"
	case "cargo", "crates", "crates.io", "rust":
		return "cargo"
	case "go", "golang", "gomod":
		return "go"
	case "nuget", ".net", "dotnet":
		return "nuget"
	case "maven", "mvn", "gradle", "java":
		return "maven"
	case "rubygems", "gem", "gems", "ruby":
		return "rubygems"
	case "composer", "packagist", "php":
		return "composer"
	default:
		return strings.ToLower(strings.TrimSpace(eco))
	}
}

// normalizeName canonicalizes a package name for an ecosystem so that the
// spelling variants each registry treats as equivalent collide on lookup. The
// rules mirror each registry's own identity comparison:
//
//   - pip (PyPI): PEP 503 — lowercase and collapse runs of "-_." to a single "-".
//   - npm: lowercase; the "@scope/name" shape is preserved.
//   - cargo (crates.io): lowercase and treat "_" and "-" as equivalent.
//   - nuget: case-insensitive — lowercase.
//   - composer (Packagist): "vendor/package", case-insensitive — lowercase.
//   - go, maven, rubygems: identity-sensitive — only surrounding space is trimmed.
func normalizeName(eco, name string) string {
	n := strings.TrimSpace(name)
	switch CanonicalEcosystem(eco) {
	case "pip":
		return collapseSeparators(strings.ToLower(n), '-')
	case "npm", "nuget", "composer":
		return strings.ToLower(n)
	case "cargo":
		return strings.ReplaceAll(strings.ToLower(n), "_", "-")
	default:
		// go (case-encoded, case-sensitive), maven (groupId:artifactId), rubygems
		// (case-sensitive gem names): compare verbatim apart from trimming.
		return n
	}
}

// collapseSeparators lowercase-normalizes a PEP 503 name: any run of '-', '_',
// or '.' becomes a single sep rune.
func collapseSeparators(s string, sep rune) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSep := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteRune(sep)
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), string(sep))
}

// dedupeStrings returns the input with empties dropped and duplicates removed,
// in sorted order, so serialized entries and bundles are deterministic.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
