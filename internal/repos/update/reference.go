package update

import (
	"fmt"
	"strings"
)

// Markers of the generated part of docs/repositories.md's maintenance section.
const (
	ReferenceBegin = "<!-- BEGIN GENERATED: maintenance update formats. Regenerate with `go test ./internal/repos/update -run TestRepositoriesDocIsCurrent -update`; source: internal/repos/update/catalog.go. -->"
	ReferenceEnd   = "<!-- END GENERATED: maintenance update formats -->"
)

// GenerateReference renders the table of how each lock-file format is updated:
// natively, through a sandboxed package manager, or not at all — with the
// reason. It is made from the catalog the updater consults, so the document
// says what the code does.
func GenerateReference() string {
	var b strings.Builder
	b.WriteString(ReferenceBegin + "\n\n")
	var native, sandboxed, none []FormatSupport
	for _, f := range Formats() {
		switch {
		case f.Method == Native:
			native = append(native, f)
		case f.Method == Sandbox || f.Fallback == Sandbox:
			sandboxed = append(sandboxed, f)
		default:
			none = append(none, f)
		}
	}
	b.WriteString("**Updated natively** — the proxy rewrites the lock file itself; when the new version declares other\n")
	b.WriteString("dependencies, the fallback applies:\n\n")
	b.WriteString("| Type | Format | Fallback | Manifests read | When |\n|---|---|---|---|---|\n")
	for _, f := range native {
		fallback := string(f.Fallback)
		if f.Fallback == Sandbox {
			fallback = "sandboxed `" + f.Tool + "`"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s |\n", f.Type, f.Format, fallback, codeList(f.Manifests), cell(f.Reason))
	}
	if len(sandboxed) > 0 {
		b.WriteString("\n**Updated through a sandboxed client only:**\n\n| Type | Format | Tool | Why |\n|---|---|---|---|\n")
		for _, f := range sandboxed {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", f.Type, f.Format, f.Tool, cell(f.Reason))
		}
	}
	b.WriteString("\n**Not updated:**\n\n| Type | Format | Why |\n|---|---|---|\n")
	for _, f := range none {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", f.Type, f.Format, cell(f.Reason))
	}
	b.WriteString("\n" + ReferenceEnd + "\n")
	return b.String()
}

func codeList(list []string) string {
	if len(list) == 0 {
		return "—"
	}
	return "`" + strings.Join(list, "`, `") + "`"
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// SpliceReference replaces the generated part of a document (between the
// markers, both kept) with generated.
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
