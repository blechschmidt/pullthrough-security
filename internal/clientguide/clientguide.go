// Package clientguide keeps the client configuration guide honest.
//
// The guide — docs/clients.md and one page per ecosystem under docs/clients/ —
// tells people what to put into .npmrc, settings.xml, daemon.json and thirty
// other files. A configuration snippet in documentation is a claim that a real
// client, given exactly these lines, works; and such claims rot silently. This
// package turns every one of them into something a test can check:
//
//   - Every fenced block in the guide carries a marker (an HTML comment on the
//     line above it) saying what stands behind it.
//   - A block marked "verified" names the scripts that execute it: an ecosystem
//     test script (internal/ecotest/clients, run by CI with the real client on
//     every push) or a client-lab script (scripts/client-lab/clients, the real
//     client against a proxy with a private CA and with access control). Every
//     line of the block must occur in one of those scripts. A snippet nothing
//     executes cannot be marked verified, and a script that changes fails the
//     test until the guide follows.
//   - Anything else has to say so: "untested" (with the reason, which the page
//     must also tell its reader), "proxy-config" (a fragment of the proxy's own
//     configuration, checked against the configuration schema), "output" (what a
//     lab run printed) or "illustration" (not something to type).
//
// The tests in this package additionally hold the guide to the set of upstream
// types the proxy accepts (a new backend needs a page), to one page template, and
// to links that resolve.
package clientguide

import (
	"fmt"
	"regexp"
	"strings"
)

// Marker kinds. A marker is an HTML comment directly above a fenced block:
//
//	<!-- verified: lab:npm ci:npm -->
//	<!-- untested: needs a Windows host -->
const (
	// KindVerified: the block is executed by the scripts it names.
	KindVerified = "verified"
	// KindOutput: the block is what a client printed in a lab run.
	KindOutput = "output"
	// KindProxyConfig: the block is a fragment of the proxy's configuration.
	KindProxyConfig = "proxy-config"
	// KindUntested: the block was not executed; the marker says why.
	KindUntested = "untested"
	// KindIllustration: the block is not something to type or to configure.
	KindIllustration = "illustration"
)

// Source kinds of a verified block.
const (
	// SourceCI is an ecosystem test script, internal/ecotest/clients/<name>.sh.
	SourceCI = "ci"
	// SourceLab is a client-lab script, scripts/client-lab/clients/<name>.sh.
	SourceLab = "lab"
)

// Source names one script that executes a block.
type Source struct {
	Kind string // SourceCI or SourceLab
	Name string // script name without ".sh"
}

func (s Source) String() string { return s.Kind + ":" + s.Name }

// Marker is the parsed marker of a block.
type Marker struct {
	Kind string
	// Sources are the scripts of a verified or output block.
	Sources []Source
	// Text is the free text of an untested marker (the reason).
	Text string
}

// Block is one fenced code block of a page.
type Block struct {
	// Line is the 1-based line of the opening fence.
	Line int
	// Lang is the fence's info string.
	Lang string
	// Section is the nearest level-2 heading above the block ("" before the first).
	Section string
	// Marker is the block's marker; nil when the block has none.
	Marker *Marker
	// Lines are the block's content lines.
	Lines []string
}

// Heading is a heading of a page.
type Heading struct {
	Line  int
	Level int
	Text  string
}

// Link is a Markdown link of a page.
type Link struct {
	Line   int
	Target string
}

// Page is a parsed guide page.
type Page struct {
	Headings []Heading
	Blocks   []Block
	Links    []Link
}

var (
	fenceRE   = regexp.MustCompile("^\\s*(```+|~~~+)\\s*([A-Za-z0-9_+-]*)\\s*$")
	headingRE = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*#*\s*$`)
	markerRE  = regexp.MustCompile(`^\s*<!--\s*([a-z-]+)\s*(?::\s*(.*?))?\s*-->\s*$`)
	// linkRE matches inline links and images: [text](target) — the target up to
	// the first closing parenthesis or space (titles are not used in the guide).
	linkRE = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

// Parse parses a guide page. It reports malformed markers and unterminated
// fences as errors, with their line numbers.
func Parse(content []byte) (*Page, error) {
	var (
		page     Page
		problems []string
		section  string
		inFence  bool
		fence    string
		current  *Block
		// pending is the marker comment seen on the previous non-blank line.
		pending     *Marker
		pendingLine int
	)
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i, line := range lines {
		n := i + 1
		if inFence {
			if m := fenceRE.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[1], fence) && m[2] == "" {
				page.Blocks = append(page.Blocks, *current)
				inFence, current = false, nil
				continue
			}
			current.Lines = append(current.Lines, line)
			continue
		}
		if m := fenceRE.FindStringSubmatch(line); m != nil {
			inFence, fence = true, m[1]
			current = &Block{Line: n, Lang: m[2], Section: section}
			if pending != nil {
				current.Marker = pending
			}
			pending = nil
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue // a blank line may separate a marker from its block
		}
		if m := markerRE.FindStringSubmatch(line); m != nil && isMarkerKind(m[1]) {
			marker, err := parseMarker(m[1], m[2])
			if err != nil {
				problems = append(problems, fmt.Sprintf("line %d: %v", n, err))
			}
			pending, pendingLine = marker, n
			continue
		}
		if pending != nil {
			problems = append(problems, fmt.Sprintf("line %d: the marker is not followed by a fenced block", pendingLine))
			pending = nil
		}
		if m := headingRE.FindStringSubmatch(line); m != nil {
			h := Heading{Line: n, Level: len(m[1]), Text: m[2]}
			page.Headings = append(page.Headings, h)
			if h.Level == 2 {
				section = h.Text
			}
		}
		for _, m := range linkRE.FindAllStringSubmatch(line, -1) {
			page.Links = append(page.Links, Link{Line: n, Target: m[1]})
		}
	}
	if inFence {
		problems = append(problems, fmt.Sprintf("line %d: the fenced block is not closed", current.Line))
	}
	if pending != nil {
		problems = append(problems, fmt.Sprintf("line %d: the marker is not followed by a fenced block", pendingLine))
	}
	if len(problems) > 0 {
		return &page, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return &page, nil
}

func isMarkerKind(kind string) bool {
	switch kind {
	case KindVerified, KindOutput, KindProxyConfig, KindUntested, KindIllustration:
		return true
	}
	return false
}

func parseMarker(kind, rest string) (*Marker, error) {
	m := &Marker{Kind: kind}
	rest = strings.TrimSpace(rest)
	switch kind {
	case KindVerified, KindOutput:
		for _, field := range strings.Fields(rest) {
			k, name, ok := strings.Cut(field, ":")
			if !ok || name == "" || (k != SourceCI && k != SourceLab) {
				return m, fmt.Errorf("%s marker: %q is not a source (want ci:<script> or lab:<script>)", kind, field)
			}
			m.Sources = append(m.Sources, Source{Kind: k, Name: name})
		}
		if len(m.Sources) == 0 {
			return m, fmt.Errorf("%s marker names no script", kind)
		}
	case KindUntested:
		m.Text = rest
		if len(rest) < 12 {
			return m, fmt.Errorf("untested marker needs a reason")
		}
	case KindProxyConfig, KindIllustration:
		if rest != "" {
			return m, fmt.Errorf("%s marker takes no argument", kind)
		}
	}
	return m, nil
}

// Placeholders the guide uses, and what a script has in their place.
const (
	// TokenPlaceholder is how the guide writes a proxy token.
	TokenPlaceholder = "<token>"
	// labToken is how a client-lab script writes it.
	labToken = "${PROXY_TOKEN}"
)

var (
	spaceRE = regexp.MustCompile(`\s+`)
	// mountRE matches a package source address as the guide writes it.
	mountRE = regexp.MustCompile(`https://proxy\.example\.com/v1/[A-Za-z0-9._-]+`)
)

// squash collapses whitespace so indentation and alignment do not matter.
func squash(s string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
}

// isComment reports whether a snippet line is only a comment. Such lines are
// the guide's own words and are not looked for in a script. A line that begins
// with "//" directly followed by text is not a comment: that is how .npmrc
// spells a registry-scoped key.
func isComment(line string) bool {
	switch {
	case line == "#" || strings.HasPrefix(line, "# "):
		return true
	case line == "//" || strings.HasPrefix(line, "// "):
		return true
	case strings.HasPrefix(line, "<!--"):
		return true
	}
	return false
}

// forLab rewrites a guide line into the spelling of a client-lab script. Lab
// scripts use the guide's own addresses and paths, so only the token differs.
func forLab(line string) string {
	return strings.ReplaceAll(line, TokenPlaceholder, labToken)
}

// forCI returns the spellings a guide line may have in an ecosystem test script.
// Such a script takes the proxy's address from its environment: its own package
// source is $MOUNT, any other one is "$PROXY_URL/v1/<name>", the host is
// $PROXY_HOST. A script may also quote an address literally (in a comment that
// shows a configuration file).
func forCI(line string) []string {
	host := func(s string) string {
		s = strings.ReplaceAll(s, "https://proxy.example.com", "$PROXY_URL")
		return strings.ReplaceAll(s, "proxy.example.com", "$PROXY_HOST")
	}
	return []string{
		host(mountRE.ReplaceAllString(line, "$$MOUNT")),
		host(line),
		line,
	}
}

// unquote drops double quotes. A script writes `export JSR_URL="$MOUNT"` where
// the guide writes `export JSR_URL=https://…`: the quotes belong to the shell,
// not to the configuration, so a line is also looked for with the quotes of both
// sides removed — in ecosystem test scripts only, whose addresses are variables.
func unquote(s string) string {
	return strings.ReplaceAll(s, `"`, "")
}

// Unverified returns the lines of a verified block that occur in none of the
// scripts the block names, and the sources none of whose lines the block
// contains. scripts maps a source to the text of its script.
//
// A line "occurs" when, after collapsing whitespace, it is a substring of a
// script line: a script sets a configuration line with echo, printf or a here
// document, so the line is there verbatim, possibly inside a longer command.
func (b Block) Unverified(scripts map[Source]string) (missing []string, unused []Source) {
	if b.Marker == nil || b.Marker.Kind != KindVerified {
		return nil, nil
	}
	used := map[Source]bool{}
	checked := 0
	for _, raw := range b.Lines {
		line := squash(raw)
		if line == "" || isComment(line) {
			continue
		}
		checked++
		found := false
		for _, src := range b.Marker.Sources {
			candidates := []string{forLab(line)}
			if src.Kind == SourceCI {
				candidates = forCI(line)
			}
			for _, want := range candidates {
				if scriptHas(scripts[src], want) ||
					(src.Kind == SourceCI && scriptHas(unquote(scripts[src]), unquote(want))) {
					found = true
					used[src] = true
					break
				}
			}
		}
		if !found {
			missing = append(missing, raw)
		}
	}
	if checked == 0 {
		missing = append(missing, "(the block has no line to verify)")
	}
	for _, src := range b.Marker.Sources {
		if !used[src] {
			unused = append(unused, src)
		}
	}
	return missing, unused
}

// scriptHas reports whether some line of the script contains want.
func scriptHas(script, want string) bool {
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(squash(line), want) {
			return true
		}
	}
	return false
}

var slugDropRE = regexp.MustCompile(`[^\p{L}\p{N} _-]`)

// Slug returns the anchor GitHub and the documentation site derive from a
// heading: lower case, punctuation dropped, spaces turned into hyphens.
func Slug(heading string) string {
	s := strings.ToLower(strings.TrimSpace(heading))
	s = slugDropRE.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, " ", "-")
}

// Anchors returns the anchors a page defines, with the suffixes GitHub adds to
// repeated headings ("-1", "-2", …).
func (p *Page) Anchors() map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	for _, h := range p.Headings {
		slug := Slug(h.Text)
		if n := seen[slug]; n > 0 {
			out[fmt.Sprintf("%s-%d", slug, n)] = true
		} else {
			out[slug] = true
		}
		seen[slug]++
	}
	return out
}

// Sections returns the level-2 headings of a page, in order.
func (p *Page) Sections() []string {
	var out []string
	for _, h := range p.Headings {
		if h.Level == 2 {
			out = append(out, h.Text)
		}
	}
	return out
}

// Title returns the page's first level-1 heading.
func (p *Page) Title() string {
	for _, h := range p.Headings {
		if h.Level == 1 {
			return h.Text
		}
	}
	return ""
}

// Template is the section sequence every ecosystem page follows, so that a
// reader finds the same thing in the same place on each of them.
var Template = []string{
	"Configure",
	"Authenticate",
	"Trust a private CA",
	"Check that it works",
	"Good to know",
	"On the proxy",
}

// PageFor maps an upstream type to the slug of its page (docs/clients/<slug>.md).
// Aliases share the page of the type they are an alias of.
func PageFor(upstreamType string) string {
	switch upstreamType {
	case "deb":
		return "apt"
	case "rpm":
		return "yum"
	case "pub":
		return "dart"
	}
	return upstreamType
}
