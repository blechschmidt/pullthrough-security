package fullmirror

import (
	"fmt"
	"strings"
)

// Markers of the generated part of docs/full-mirroring.md. Everything between
// them is GenerateReference's; everything around them is written by hand.
const (
	ReferenceBegin = "<!-- BEGIN GENERATED: full-mirroring catalog. Regenerate with `make full-mirroring-reference-gen`; source: internal/fullmirror (catalog.go, catalog_data.go). -->"
	ReferenceEnd   = "<!-- END GENERATED: full-mirroring catalog -->"
)

// Description says what a tier means for a follower.
func (t Tier) Description() string {
	switch t {
	case TierFeed:
		return "The registry publishes its changes in order; the follower stores a cursor and asks for what came after it. Cheap per poll, nothing is missed while the cursor stays valid."
	case TierIndex:
		return "The registry publishes its complete current state; the follower re-reads it (conditionally, or through a delta where one exists) and diffs it against its previous copy."
	case TierListing:
		return "The registry only answers paginated listings; the follower pages until it reaches what it has seen, or reads the whole listing when it is not sorted by time."
	case TierNone:
		return "The registry cannot be enumerated; only what clients request, or a partial feed (one channel, the repositories one names), can be mirrored ahead of time."
	}
	return ""
}

// Description says what a follower stores for a cursor of this kind.
func (k CursorKind) Description() string {
	switch k {
	case CursorSequence:
		return "an integer the registry assigns to every change, in order"
	case CursorTimestamp:
		return "the registry's time stamp of the last change processed (never the follower's clock)"
	case CursorCommit:
		return "a commit of the Git repository the registry is built from"
	case CursorOffset:
		return "the length of an append-only file already read; the rest comes with an HTTP Range request"
	case CursorValidator:
		return "the ETag, Last-Modified or digest of the index copy held, plus that copy to diff against"
	case CursorPage:
		return "a position in a listing (page, offset or opaque cursor) and the newest item already seen"
	}
	return ""
}

// GenerateReference renders the generated part of docs/full-mirroring.md from
// the catalog: a summary table, the types by tier, the tier and cursor
// legends, and a section per upstream type with its feeds, limits, terms,
// size, private-upstream behaviour, notes and sources.
func GenerateReference() string {
	cat := Catalog()
	var b strings.Builder
	b.WriteString(ReferenceBegin + "\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("One row per upstream type. **How to follow it** names the type's best feed; every feed, with its endpoint and the\n")
	b.WriteString("live check that confirmed it, is in the type's section below. **Implementation status** is filled in as the\n")
	b.WriteString("full-mirror engine and its feed adapters land.\n\n")
	b.WriteString("| Type | Registry | Tier | How to follow it | Cursor | Full-mirror size | Implementation status |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, e := range cat {
		follow, cursor := "—", "—"
		if len(e.Feeds) > 0 {
			follow, cursor = e.Feeds[0].Name, string(e.Feeds[0].Cursor)
			if e.Feeds[0].Partial {
				follow += " (partial)"
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			typeLink(e), cell(registryLink(e.Registry)), "**("+string(e.Tier)+")** "+e.Tier.Title(),
			cell(follow), cursor, cell(e.Size.Figure), cell(statusText(e.Status)))
	}

	b.WriteString("\n## Types by tier\n\n")
	for _, t := range Tiers() {
		entries := ByTier(t)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, typeLink(e))
		}
		fmt.Fprintf(&b, "- **(%s) %s** (%d): %s\n", t, t.Title(), len(entries), strings.Join(names, ", "))
	}

	b.WriteString("\n### Tiers\n\n| Tier | Meaning |\n|---|---|\n")
	for _, t := range Tiers() {
		fmt.Fprintf(&b, "| **(%s)** %s | %s |\n", t, t.Title(), cell(t.Description()))
	}
	b.WriteString("\n### Cursor kinds\n\n| Cursor | What the follower stores |\n|---|---|\n")
	for _, k := range []CursorKind{CursorSequence, CursorTimestamp, CursorCommit, CursorOffset, CursorValidator, CursorPage} {
		fmt.Fprintf(&b, "| %s | %s |\n", k, cell(k.Description()))
	}

	b.WriteString("\n## Registries\n")
	for _, e := range cat {
		writeEntry(&b, e)
	}
	b.WriteString("\n" + ReferenceEnd + "\n")
	return b.String()
}

func writeEntry(b *strings.Builder, e Entry) {
	fmt.Fprintf(b, "\n### %s\n\n", e.Type)
	fmt.Fprintf(b, "**%s** — upstream type `%s`", e.Title, e.Type)
	if len(e.Aliases) > 0 {
		fmt.Fprintf(b, " (also `%s`)", strings.Join(e.Aliases, "`, `"))
	}
	if e.Registry != "" {
		fmt.Fprintf(b, ", registry <%s>", e.Registry)
	} else {
		b.WriteString(", no public registry")
	}
	fmt.Fprintf(b, ". Tier **(%s) %s**. Implementation: %s.\n\n", e.Tier, e.Tier.Title(), statusText(e.Status))

	if len(e.Feeds) == 0 {
		b.WriteString("**Feeds.** None.\n\n")
	} else {
		b.WriteString("**Feeds**\n\n")
		for _, f := range e.Feeds {
			name := "**" + f.Name + "**"
			if f.Partial {
				name += " (partial)"
			}
			fmt.Fprintf(b, "- %s — cursor: %s\n\n", name, f.Cursor)
			fmt.Fprintf(b, "  `%s`\n\n", f.URL)
			fmt.Fprintf(b, "  %s\n\n", f.Semantics)
			fmt.Fprintf(b, "  *Checked live:* %s\n\n", f.Verified)
		}
	}
	fmt.Fprintf(b, "**Rate limits.** %s\n\n", e.RateLimits)
	fmt.Fprintf(b, "**Terms of use.** %s\n\n", e.Terms)
	fmt.Fprintf(b, "**Full-mirror size.** %s. %s\n\n", upperFirst(e.Size.Figure), e.Size.Basis)
	fmt.Fprintf(b, "**Private and self-hosted upstreams.** %s\n\n", e.Private)
	if len(e.Notes) > 0 {
		b.WriteString("**Notes**\n\n")
		for _, n := range e.Notes {
			fmt.Fprintf(b, "- %s\n", n)
		}
		b.WriteString("\n")
	}
	links := make([]string, 0, len(e.Sources))
	for _, s := range e.Sources {
		links = append(links, fmt.Sprintf("[%s](%s)", s.Title, s.URL))
	}
	fmt.Fprintf(b, "**Sources.** %s\n", strings.Join(links, " · "))
}

// typeLink is a type's name linking to its section (anchored by the type).
func typeLink(e Entry) string {
	s := "[`" + e.Type + "`](#" + e.Type + ")"
	for _, a := range e.Aliases {
		s += " / `" + a + "`"
	}
	return s
}

func registryLink(registry string) string {
	if registry == "" {
		return "operator-defined"
	}
	host := strings.TrimPrefix(registry, "https://")
	return "[" + host + "](" + registry + ")"
}

func statusText(s Status) string {
	if s.Note == "" {
		return string(s.State)
	}
	return string(s.State) + " (" + s.Note + ")"
}

// upperFirst capitalises a phrase that starts a sentence.
func upperFirst(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
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
// the markers are missing, repeated or out of order.
func SpliceReference(doc, generated string) (string, error) {
	i := strings.Index(doc, ReferenceBegin)
	j := strings.Index(doc, ReferenceEnd)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("the document has no generated part (%q … %q)", ReferenceBegin, ReferenceEnd)
	}
	if strings.Count(doc, ReferenceBegin) != 1 || strings.Count(doc, ReferenceEnd) != 1 {
		return "", fmt.Errorf("the document has more than one generated part")
	}
	end := j + len(ReferenceEnd)
	if end < len(doc) && doc[end] == '\n' {
		end++
	}
	return doc[:i] + generated + doc[end:], nil
}
