package lockfiles

import (
	"fmt"
	"sort"
	"strings"
)

// Markers of the generated part of docs/lockfiles.md. Everything between
// them is GenerateReference's; everything around them is written by hand.
const (
	ReferenceBegin = "<!-- BEGIN GENERATED: lock-file formats. Regenerate with `make lockfile-reference-gen`; source: internal/lockfiles (formats.go, coverage.go). -->"
	ReferenceEnd   = "<!-- END GENERATED: lock-file formats -->"
)

// GenerateReference renders the generated part of docs/lockfiles.md: every
// format with what is read from it, its digests and its limits; what each
// kind of digest is a hash of; and the upstream types without a lock-file
// format, each with the reason. It is made from the same tables the scanner
// and its tests use, so the document says what the code does.
func GenerateReference() string {
	r := DefaultRegistry()
	var b strings.Builder
	b.WriteString(ReferenceBegin + "\n\n")
	b.WriteString("## Formats\n\n")
	b.WriteString("Every format the scanner reads, by upstream type. **Digests** says how far the format's entries\n")
	b.WriteString("carry a digest — `all`, `some` (an entry or an older file may lack one) or `none` — and what\n")
	b.WriteString("it is a hash of. A dependency nothing in its lock file pins — no digest of the artifact (or\n")
	b.WriteString("of a manifest that hashes it) and, for a Git dependency, no commit — is marked\n")
	b.WriteString("`\"unverified\": true` with the reason quoted below; later stages treat it as unverified.\n")
	b.WriteString("No digest is ever made up.\n\n")
	b.WriteString("| Type | Format | Read | Digests | Limits |\n|---|---|---|---|---|\n")
	formats := r.Formats()
	sort.SliceStable(formats, func(i, j int) bool { return formats[i].Type < formats[j].Type })
	for _, f := range formats {
		digests := "**" + string(f.Digests) + "**"
		if f.Hashed != "" {
			digests += " — " + f.Hashed
		}
		if f.Digests != DigestsAll && f.NoDigest != "" {
			digests += " An entry without one is unverified: *" + f.NoDigest + "*."
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", f.Type, cell(f.Files), cell(f.Read), cell(digests), cell(f.Limits))
	}

	b.WriteString("\n### What a digest is of\n\n")
	b.WriteString("`of` on a digest says what was hashed when it is not simply the artifact the registry serves\n")
	b.WriteString("for the coordinate. A digest of a document next to the artifact pins only that document: a\n")
	b.WriteString("dependency with nothing else is unverified. Any other value of `of` is the name of the\n")
	b.WriteString("distribution file hashed (a wheel, a platform's bottle, a conda package file).\n\n")
	b.WriteString("| `of` | Meaning | Pins the content |\n|---|---|---|\n")
	for _, k := range DigestKinds() {
		of := "`" + k.Of + "`"
		if k.Of == "" {
			of = "(none)"
		}
		pins := "yes"
		if !k.PinsContent {
			pins = "no — unverified: *" + k.Unverified + "*"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", of, cell(k.Meaning), cell(pins))
	}

	b.WriteString("\n### Git dependencies\n\n")
	if c, ok := coverageFor(r, "git"); ok && len(c.Formats) > 0 {
		b.WriteString("The `git` upstream type is covered twice: a repository's own submodules (`.gitmodules`, each\n")
		b.WriteString("pinned by the gitlink at its path), and the Git dependencies other lock files record — every\n")
		b.WriteString("dependency with `\"source\": \"git\"`, pinned when its `revision` is a commit.\n")
		b.WriteString("`Report.GitDependencies()` collects both. Formats that record Git dependencies: ")
		b.WriteString(joinFormats(gitSourceFormats(r)) + ".\n")
	}

	b.WriteString("\n### Types without a lock-file format\n\n")
	b.WriteString("Every upstream type the proxy fronts has a parser or an entry saying why it has none\n")
	b.WriteString("(`internal/lockfiles/coverage.go`); a test fails when a type is added without either.\n\n")
	b.WriteString("| Type | Why |\n|---|---|\n")
	for _, c := range CoverageTable() {
		if len(c.Formats) == 0 {
			fmt.Fprintf(&b, "| `%s` | %s |\n", c.Type, cell(c.Reason))
		}
	}
	var unparsed []string
	for _, c := range CoverageTable() {
		if len(c.Formats) > 0 && len(c.Unparsed) > 0 {
			unparsed = append(unparsed, fmt.Sprintf("| `%s` | %s |", c.Type, cell(joinFormats(c.Unparsed))))
		}
	}
	if len(unparsed) > 0 {
		b.WriteString("\nLock-file formats of the ecosystems above that are not read yet:\n\n")
		b.WriteString("| Type | Not read |\n|---|---|\n")
		b.WriteString(strings.Join(unparsed, "\n") + "\n")
	}
	b.WriteString("\n" + ReferenceEnd + "\n")
	return b.String()
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "—"
	}
	return s
}

// SpliceReference replaces the generated part of a document (between
// ReferenceBegin and ReferenceEnd, both kept) with generated. It fails when
// the markers are missing or out of order.
func SpliceReference(doc, generated string) (string, error) {
	i := strings.Index(doc, ReferenceBegin)
	j := strings.Index(doc, ReferenceEnd)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("the document has no generated part (%q … %q)", ReferenceBegin, ReferenceEnd)
	}
	end := j + len(ReferenceEnd)
	if end < len(doc) && doc[end] == '\n' {
		end++
	}
	return doc[:i] + generated + doc[end:], nil
}
