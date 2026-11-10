// Package actionpin implements a deterministic, no-execution admission gate that
// inspects pulled Git content for GitHub Actions workflow / composite-action
// references and enforces supply-chain pinning hygiene on them (Task 115).
//
// GitHub Actions and reusable workflows are a first-class supply-chain surface:
// a workflow step like
//
//	uses: actions/checkout@v4
//
// resolves a *mutable* tag at run time. Whoever controls the `v4` tag (or the
// upstream repository) can move it to point at arbitrary code, which then runs
// with the workflow's credentials — the tj-actions/changed-files compromise
// (CVE-2025-30066) is the canonical example. The hardening practice, recommended
// by GitHub and SLSA, is to pin every third-party action to a full 40-character
// commit SHA:
//
//	uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
//
// A commit SHA is immutable, so the pinned code cannot change underneath you.
//
// This gate never executes anything. It parses the `uses:` references out of a
// repository's `.github/workflows/*.yml` and composite `action.yml` files and
// classifies each reference's pinning: a full-SHA pin passes, a mutable ref (a
// branch name or a floating tag such as `@v4`) is flagged, and — when an owner
// allowlist is configured — a reference to a disallowed owner/org is blocked.
// Findings are folded into the commit-scanning verdict (Task 29's deterministic
// pass is the template), and from there surface through the unified risk score
// (Task 37), the SARIF findings export (Task 42), and the per-coordinate dossier
// (Task 87).
//
// The parser is intentionally line-oriented rather than a full YAML decoder: a
// `uses:` reference is always a single scalar on one line, so a tolerant line
// scanner handles partial diffs, truncated files, and hostile input (it is the
// fuzz target, consistent with Task 30) without the cost or the
// deeply-nested-input risk of a structural parse. All exported functions are
// pure and safe for concurrent use.
package actionpin

import (
	"path"
	"strings"
)

// maxReferences bounds the number of references parsed from a single content
// blob so a pathological (or hostile) file cannot produce an unbounded result.
const maxReferences = 4096

// maxRawLen bounds the retained length of a single `uses:` value so an enormous
// line cannot blow up memory or finding messages.
const maxRawLen = 512

// Kind classifies the target of a `uses:` reference.
type Kind string

const (
	// KindRemote is a third-party action or reusable workflow pulled from a
	// repository: "owner/repo[/subpath]@ref".
	KindRemote Kind = "remote"
	// KindLocal is an action defined in the same repository: a path beginning
	// with "./" or "../". It carries no network-supply-chain risk and is never
	// flagged.
	KindLocal Kind = "local"
	// KindDocker is a container-image action: "docker://[registry/]image[:tag][@digest]".
	KindDocker Kind = "docker"
)

// Reference is one parsed `uses:` reference. All string fields are trimmed; the
// zero value is not a valid reference (see the ok result of ParseUsesValue).
type Reference struct {
	// Raw is the full (length-bounded) `uses:` value as written.
	Raw string
	// Owner is the repository owner/org for a remote reference (e.g. "actions"),
	// or the leading image path segment for a docker reference. Empty for local.
	Owner string
	// Repo is the repository name for a remote reference (e.g. "checkout").
	Repo string
	// Subpath is any path within the repository (reusable workflows use
	// ".github/workflows/foo.yml"), without the leading slash.
	Subpath string
	// Ref is the git ref following '@' (a tag, branch, or commit SHA), or the
	// digest for a docker reference. Empty when the reference carries no '@'.
	Ref string
	// Kind classifies the reference target.
	Kind Kind
	// Line is the 1-based line number the reference was parsed from.
	Line int
}

// ParseContent extracts every `uses:` reference from a block of workflow or
// composite-action YAML text, line by line. Line numbers are 1-based relative to
// content. It never panics and bounds its output at maxReferences.
func ParseContent(content string) []Reference {
	if content == "" {
		return nil
	}
	var out []Reference
	line := 0
	// strings.Split on "\n" also handles "\r\n" because the trailing '\r' is
	// trimmed by trimScalar below.
	for _, raw := range strings.Split(content, "\n") {
		line++
		if len(out) >= maxReferences {
			break
		}
		val, ok := ParseUsesValue(raw)
		if !ok {
			continue
		}
		ref := Classify(val)
		ref.Line = line
		out = append(out, ref)
	}
	return out
}

// ParseLines extracts references from pre-split, individually-numbered lines —
// the form produced from a unified diff's added lines so findings carry their
// real new-file line numbers. A zero or negative Number is preserved as-is.
func ParseLines(lines []Line) []Reference {
	var out []Reference
	for _, ln := range lines {
		if len(out) >= maxReferences {
			break
		}
		val, ok := ParseUsesValue(ln.Text)
		if !ok {
			continue
		}
		ref := Classify(val)
		ref.Line = ln.Number
		out = append(out, ref)
	}
	return out
}

// Line is one numbered line of content to inspect.
type Line struct {
	Number int
	Text   string
}

// Lines splits content into numbered Lines (1-based), the convenience inverse of
// ParseContent used by callers that already hold full file text.
func Lines(content string) []Line {
	if content == "" {
		return nil
	}
	parts := strings.Split(content, "\n")
	out := make([]Line, 0, len(parts))
	for i, p := range parts {
		out = append(out, Line{Number: i + 1, Text: p})
	}
	return out
}

// ParseUsesValue reports whether raw is a YAML line declaring a `uses:` key and,
// if so, returns the trimmed, unquoted, comment-stripped scalar value. It
// tolerates arbitrary leading indentation, an optional list-item marker ("- "),
// single/double quoting, and a trailing "# comment". A `uses:` key with an empty
// value yields ok=false.
func ParseUsesValue(raw string) (value string, ok bool) {
	s := strings.TrimRight(raw, "\r")
	s = strings.TrimLeft(s, " \t")
	// An optional block-sequence marker may precede the key: "- uses: x".
	if strings.HasPrefix(s, "-") {
		s = strings.TrimLeft(s[1:], " \t")
	}
	// The key must be exactly "uses" (GitHub Actions requires lowercase) followed
	// by a colon. Guard the length before slicing.
	const key = "uses:"
	if len(s) < len(key) || s[:len(key)] != key {
		return "", false
	}
	rest := s[len(key):]
	// Require the colon to be followed by whitespace or end-of-line, so a key like
	// "uses-something:" (already excluded above) or "uses::" edge cases behave.
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	v := trimScalar(rest)
	if v == "" {
		return "", false
	}
	if len(v) > maxRawLen {
		v = v[:maxRawLen]
	}
	return v, true
}

// trimScalar normalizes a YAML scalar value: trims surrounding whitespace, strips
// a single matching pair of surrounding quotes, and removes a trailing
// "# comment" from an unquoted value.
func trimScalar(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Quoted value: strip the first matching quote pair and return the inner text
	// verbatim (an inner '#' is part of the value, not a comment).
	if c := s[0]; c == '"' || c == '\'' {
		if i := strings.IndexByte(s[1:], c); i >= 0 {
			return s[1 : 1+i]
		}
		// Unterminated quote: drop the opening quote and fall through.
		s = s[1:]
	}
	// Unquoted value: a '#' preceded by whitespace begins a comment.
	if i := commentStart(s); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// commentStart returns the index of an inline-comment '#' (one preceded by a
// space or tab, per YAML), or -1 when the scalar carries no comment.
func commentStart(s string) int {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return i - 1
		}
	}
	return -1
}

// Classify parses a `uses:` value into a structured Reference (Kind, owner/repo/
// subpath, ref). It never errors: an unparseable value yields a best-effort
// KindRemote reference with whatever fields could be recovered.
func Classify(raw string) Reference {
	v := strings.TrimSpace(raw)
	if len(v) > maxRawLen {
		v = v[:maxRawLen]
	}
	ref := Reference{Raw: v}

	switch {
	case v == "." || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../"):
		ref.Kind = KindLocal
		return ref
	case strings.HasPrefix(v, "docker://"):
		ref.Kind = KindDocker
		body := strings.TrimPrefix(v, "docker://")
		// A digest ("@sha256:...") takes precedence; otherwise an image tag after
		// the final ':' is NOT a ref we pin on (tags are mutable).
		if at := strings.LastIndexByte(body, '@'); at >= 0 {
			ref.Ref = body[at+1:]
			body = body[:at]
		}
		ref.Owner = firstSegment(body)
		return ref
	default:
		ref.Kind = KindRemote
		repoPath := v
		if at := strings.LastIndexByte(v, '@'); at >= 0 {
			ref.Ref = v[at+1:]
			repoPath = v[:at]
		}
		owner, repo, sub := splitRepoPath(repoPath)
		ref.Owner, ref.Repo, ref.Subpath = owner, repo, sub
		return ref
	}
}

// splitRepoPath splits "owner/repo[/subpath]" into its parts. A value with fewer
// than two segments yields whatever is present (owner only, or empty).
func splitRepoPath(p string) (owner, repo, subpath string) {
	p = strings.TrimPrefix(p, "/")
	parts := strings.SplitN(p, "/", 3)
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return parts[0], "", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], parts[2]
	}
}

// firstSegment returns the leading path segment of a (possibly slashed) image
// reference, dropping any ":tag" suffix on that segment.
func firstSegment(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

// IsActionsFile reports whether a repository path is a GitHub Actions workflow or
// a composite-action definition — the files whose `uses:` references this gate
// inspects. Matching is case-insensitive on the extension.
//
//   - Workflows:        .github/workflows/*.yml  and  *.yaml
//   - Composite actions: any  action.yml / action.yaml
func IsActionsFile(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	// Normalize separators (a Windows-style path should still match).
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	lower := strings.ToLower(p)
	base := path.Base(lower)
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	// Workflow files live directly under .github/workflows/ (GitHub does not
	// recurse into subdirectories for workflow discovery).
	dir := path.Dir(lower)
	return strings.HasSuffix(dir, ".github/workflows") || dir == ".github/workflows"
}
