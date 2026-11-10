package timeline

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Markdown renders a Result as a human-readable, copy-pasteable incident report:
// a scope/summary header followed by a chronological table of every correlated
// event, with the Merkle proof reference inlined where one exists. It is the
// format an analyst attaches to an incident ticket.
func (r Result) Markdown() string {
	var b strings.Builder

	b.WriteString("# Incident timeline\n\n")
	writeScope(&b, r.Query)
	fmt.Fprintf(&b, "- **Generated:** %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Events:** %d returned of %d matched%s\n", r.Returned, r.Total, truncNote(r.Truncated))
	fmt.Fprintf(&b, "- **Sources wired:** %s\n\n", joinEnabled(r.Sources))

	if len(r.Events) == 0 {
		b.WriteString("_No correlated events for this scope._\n")
		return b.String()
	}

	b.WriteString("| # | Time (UTC) | Source | Category | Decision | Actor | Coordinate | Summary | Proof |\n")
	b.WriteString("|---|------------|--------|----------|----------|-------|------------|---------|-------|\n")
	for i, ev := range r.Events {
		proof := "—"
		if ev.Proof != nil && ev.Proof.AuditSeq != 0 {
			if ev.Proof.Path != "" {
				proof = fmt.Sprintf("[seq %d](%s)", ev.Proof.AuditSeq, ev.Proof.Path)
			} else {
				proof = fmt.Sprintf("seq %d", ev.Proof.AuditSeq)
			}
		}
		src := string(ev.Source)
		if len(ev.Corroborated) > 1 {
			src = strings.Join(ev.Corroborated, "+")
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			i+1,
			ev.Time.UTC().Format("2006-01-02 15:04:05"),
			src,
			cellStr(string(ev.Category)),
			cellStr(ev.Decision),
			cellStr(ev.Actor),
			cellStr(ev.Coordinate),
			cellStr(firstNonEmpty(ev.Summary, ev.Kind)),
			proof,
		)
	}
	return b.String()
}

func writeScope(b *strings.Builder, q Query) {
	scope := make([]string, 0, 4)
	if q.Coordinate != "" {
		scope = append(scope, "coordinate `"+q.Coordinate+"`")
	}
	if q.Tenant != "" {
		scope = append(scope, "tenant `"+q.Tenant+"`")
	}
	if q.Identity != "" {
		scope = append(scope, "identity `"+q.Identity+"`")
	}
	if q.IncidentID != "" {
		scope = append(scope, "incident `"+q.IncidentID+"`")
	}
	if len(scope) == 0 {
		scope = append(scope, "all events")
	}
	fmt.Fprintf(b, "- **Scope:** %s\n", strings.Join(scope, ", "))
}

func truncNote(t bool) string {
	if t {
		return " (truncated — increase limit for the full history)"
	}
	return ""
}

func joinEnabled(sources map[string]bool) string {
	on := make([]string, 0, len(sources))
	for k, v := range sources {
		if v {
			on = append(on, k)
		}
	}
	sort.Strings(on)
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ", ")
}

// cellStr escapes a value for a Markdown table cell (pipes and newlines would
// break the row) and substitutes an em dash for emptiness.
func cellStr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 120 {
		s = s[:117] + "…"
	}
	return s
}
