package livescan

import (
	"fmt"
	"sort"
	"strings"
)

// Markers of the generated section of docs/llm-live-scan.md.
const (
	docBegin = "<!-- BEGIN GENERATED: corpus (go test ./internal/e2e/livescan -run TestDocsCorpusSectionIsCurrent -update) -->"
	docEnd   = "<!-- END GENERATED: corpus -->"
)

// ReferenceMarkdown renders the corpus as the documentation's research notes:
// an overview table, then one section per sample. docs/llm-live-scan.md embeds
// it between docBegin and docEnd, and a test fails when the page and the corpus
// disagree, so the notes cannot drift from the fixtures they describe.
func ReferenceMarkdown(samples []*Sample) string {
	sorted := append([]*Sample(nil), samples...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Date != sorted[j].Date {
			return sorted[i].Date < sorted[j].Date
		}
		return sorted[i].ID < sorted[j].ID
	})

	var b strings.Builder
	b.WriteString("| Sample | Published | Served as | Campaign |\n|---|---|---|---|\n")
	for _, s := range sorted {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | `%s` |\n", s.ID, anchor(s.ID), s.Date, servedAs(s), s.Campaign)
	}
	b.WriteString("\n")

	for _, s := range sorted {
		fmt.Fprintf(&b, "### `%s`\n\n", s.ID)
		fmt.Fprintf(&b, "**%s**\n\n", mdText(s.Title))
		b.WriteString("| | |\n|---|---|\n")
		fmt.Fprintf(&b, "| Published | %s (campaign `%s`) |\n", s.Date, s.Campaign)
		fmt.Fprintf(&b, "| Served as | %s |\n", servedAs(s))
		fmt.Fprintf(&b, "| Malicious release | %s |\n", release(s, s.Version))
		fmt.Fprintf(&b, "| Control | %s |\n", control(s))
		if len(s.ModelsMayRefuse) > 0 {
			fmt.Fprintf(&b, "| Declined by | %s: the provider's safeguards decline to judge the malicious release; with them it is blocked without a verdict (`failMode: closed`) |\n", codeList(s.ModelsMayRefuse))
		}
		fmt.Fprintf(&b, "| Techniques | %s |\n", codeList(s.Techniques))
		fmt.Fprintf(&b, "| Indicators | %s |\n\n", codeList(s.Indicators))
		fmt.Fprintf(&b, "What the real attack did: %s\n\n", oneLine(s.Summary))
		fmt.Fprintf(&b, "What the fixture keeps and changes: %s\n\n", oneLine(s.Reconstruction))
		b.WriteString("Public analyses it is built from:\n\n")
		for _, r := range s.References {
			fmt.Fprintf(&b, "- <%s>\n", r)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// servedAs describes how a sample reaches the proxy.
func servedAs(s *Sample) string {
	switch s.Kind {
	case KindGitCommit:
		return "Git commits of `" + s.Name + "`, read by the commit scan"
	case KindVSIX:
		return "VS Code extension (`.vsix`) on the `" + s.Ecosystem + "` upstream"
	case KindOCIImage:
		return "container image on the `" + s.Ecosystem + "` upstream"
	case KindNPM:
		return "npm tarball on the `" + s.Ecosystem + "` upstream"
	case KindWheel:
		return "Python wheel on the `" + s.Ecosystem + "` upstream"
	case KindSdist:
		return "Python source distribution on the `" + s.Ecosystem + "` upstream"
	default:
		return s.Kind + " on the `" + s.Ecosystem + "` upstream"
	}
}

func release(s *Sample, version string) string {
	if s.Kind == KindGitCommit {
		return "the commit `" + oneLine(s.Commit.MaliciousMessage) + "` (" + oneLine(s.Commit.MaliciousAuthor) + ")"
	}
	if s.Kind == KindVSIX {
		return "`" + s.Extension.Publisher + "." + s.Extension.Name + "` " + version
	}
	return "`" + s.Name + "` " + version
}

func control(s *Sample) string {
	if s.Kind == KindGitCommit {
		return "the commit `" + oneLine(s.Commit.BenignMessage) + "` (an ordinary change that must not be flagged)"
	}
	return release(s, s.BenignVersion) + " (the last clean release; it must be served)"
}

func codeList(items []string) string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = "`" + strings.ReplaceAll(strings.ReplaceAll(it, "`", "'"), "|", "\\|") + "`"
	}
	return strings.Join(out, ", ")
}

// oneLine folds whitespace (the YAML block scalars are single paragraphs).
func oneLine(s string) string { return mdText(strings.Join(strings.Fields(s), " ")) }

// mdText escapes what would break a table cell.
func mdText(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// anchor is GitHub's heading anchor for "`id`": lower case, punctuation but
// "-" and "_" dropped, spaces to "-".
func anchor(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}
