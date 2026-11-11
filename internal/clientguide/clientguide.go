// Package clientguide keeps the client configuration guide honest.
//
// The guide — docs/clients.md and one page per ecosystem under docs/clients/ —
// tells people what to put into .npmrc, settings.xml, daemon.json and thirty
// other files. A configuration snippet in documentation is a claim that a real
// client, given exactly these lines, works; and such claims rot silently. This
// package turns every one of them into something a test can check:
//
//   - Every fenced block in the guide carries a marker (an HTML comment on the
//     line above it) saying what stands behind it. Code that would be shown
//     without being such a block — an indented code block, a fence inside a
//     blockquote, a <pre> element — is an error (Parse).
//   - A block marked "verified" names the scripts that execute it: an ecosystem
//     test script (internal/ecotest/clients, run by CI with the real client on
//     every push) or a client-lab script (scripts/client-lab/clients, the real
//     client against a proxy with a private CA and with access control). Every
//     line of the block must be a whole line one of those scripts executes, in
//     the script's order and — for the lines of a file — with the script's
//     nesting (Checker.Check). A snippet nothing executes cannot be marked
//     verified, and a script that changes fails the test until the guide
//     follows.
//   - Anything else has to say so: "untested" (with the reason, which the page
//     must also tell its reader), "proxy-config" (a fragment of the proxy's own
//     configuration, decoded as such), "output" (what a lab run printed) or
//     "illustration" (not something to type).
//
// What the check does not show is that a block is complete. A block may be part
// of a file — the registry line of an .npmrc in one section, its token line in
// the next — so a block that leaves out a line the client needs still passes.
// The tests narrow that gap for the lines that matter most (keepsOnTheProxy) and
// for files cut short (unclosed); the rest is for a reader of the page to catch.
//
// The tests in this package additionally hold the guide to the set of upstream
// types the proxy accepts (a new backend needs a page), to one page template and
// to links that resolve; the client lab's result table to the scripts as they
// are (Fingerprint); and the configurations `ptctl config` prints to the same
// scripts.
package clientguide

import (
	"crypto/sha256"
	"encoding/hex"
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
	// fenceRE matches a code fence: indentation, the fence, the info string.
	fenceRE   = regexp.MustCompile("^(\\s*)(```+|~~~+)(.*)$")
	langRE    = regexp.MustCompile(`^[A-Za-z0-9_+.#-]*$`)
	headingRE = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*#*\s*$`)
	markerRE  = regexp.MustCompile(`^\s*<!--\s*([a-z-]+)\s*(?::\s*(.*?))?\s*-->\s*$`)
	// linkRE matches inline links and images: [text](target) — the target up to
	// the first closing parenthesis or space (titles are not used in the guide).
	linkRE = regexp.MustCompile(`\]\(([^)\s]+)\)`)

	// Code a renderer shows that Parse does not turn into a Block, and that
	// would therefore escape the rule that every block has a marker.
	quotedFenceRE = regexp.MustCompile("^\\s*(>\\s*)+(```|~~~)")
	preRE         = regexp.MustCompile(`(?i)<pre[\s>]`)
	listItemRE    = regexp.MustCompile(`^(\s*)([-*+]|\d{1,9}[.)])\s+\S`)
)

// openingFence reports whether line opens a fenced block, and with which fence
// and info string. A backtick fence whose info string holds a backtick is a
// code span in running text, not a fence.
func openingFence(line string) (fence, info string, ok bool) {
	m := fenceRE.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	info = strings.TrimSpace(m[3])
	if m[2][0] == '`' && strings.Contains(info, "`") {
		return "", "", false
	}
	return m[2], info, true
}

// closesFence reports whether line closes a block opened with fence: the same
// character, at least as many of them, and nothing after.
func closesFence(line, fence string) bool {
	m := fenceRE.FindStringSubmatch(line)
	return m != nil && strings.HasPrefix(m[2], fence) && strings.TrimSpace(m[3]) == ""
}

// indentOf returns the width of a line's indentation, a tab counting as four.
func indentOf(line string) int {
	n := 0
	for _, r := range line {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// Parse parses a guide page. It reports as errors, with their line numbers:
// malformed markers, markers without a block, unterminated fences — and code
// that a renderer shows but that is not a fenced block of the page itself
// (a fence inside a blockquote, an indented code block, a <pre> element), since
// such code would carry no marker.
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
		// prevBlank: the previous line was blank (or there was none).
		// listIndent is where the text of the current list item starts, -1
		// outside a list: an indented code block needs four columns more.
		prevBlank  = true
		listIndent = -1
	)
	problem := func(n int, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("line %d: %s", n, fmt.Sprintf(format, args...)))
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i, line := range lines {
		n := i + 1
		if inFence {
			if closesFence(line, fence) {
				page.Blocks = append(page.Blocks, *current)
				inFence, current, prevBlank = false, nil, false
				continue
			}
			current.Lines = append(current.Lines, line)
			continue
		}
		if f, info, ok := openingFence(line); ok {
			lang := info
			if !langRE.MatchString(info) {
				// "```sh title=x" renders as a block as well; keeping the info
				// string to a language keeps this parser and the renderers in
				// agreement about where a block ends.
				problem(n, "the fence's info string %q is not just a language", info)
				lang = strings.Fields(info)[0]
			}
			inFence, fence = true, f
			current = &Block{Line: n, Lang: lang, Section: section, Marker: pending}
			pending = nil
			continue
		}
		if strings.TrimSpace(line) == "" {
			prevBlank = true
			continue // a blank line may separate a marker from its block
		}

		indent := indentOf(line)
		switch {
		case quotedFenceRE.MatchString(line):
			problem(n, "a fenced block inside a blockquote would carry no marker: move it out of the quote")
		case preRE.MatchString(line):
			problem(n, "a <pre> element would carry no marker: use a fenced block")
		case prevBlank && indent >= max(listIndent, 0)+4:
			problem(n, "an indented code block would carry no marker: use a fenced block")
		}
		if m := listItemRE.FindStringSubmatch(line); m != nil {
			listIndent = indentOf(m[1]) + len(m[2]) + 1
		} else if indent < listIndent {
			listIndent = indent
			if indent == 0 {
				listIndent = -1
			}
		}
		prevBlank = false

		if m := markerRE.FindStringSubmatch(line); m != nil && isMarkerKind(m[1]) {
			if pending != nil {
				problem(pendingLine, "the marker is not followed by a fenced block")
			}
			marker, err := parseMarker(m[1], m[2])
			if err != nil {
				problem(n, "%v", err)
			}
			pending, pendingLine = marker, n
			continue
		}
		if pending != nil {
			problem(pendingLine, "the marker is not followed by a fenced block")
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
		problem(current.Line, "the fenced block is not closed")
	}
	if pending != nil {
		problem(pendingLine, "the marker is not followed by a fenced block")
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
	// mountRE matches a package source address as the guide writes it; its
	// group is the upstream's name.
	mountRE = regexp.MustCompile(`https://proxy\.example\.com/v1/([A-Za-z0-9._-]+)`)
	// redirectRE matches output redirections at the end of a command.
	redirectRE = regexp.MustCompile(`(\s+(\d?>>?\s*\S+|2>&1))+$`)
	// echoRE matches a command that writes one line into a file.
	echoRE = regexp.MustCompile(`^echo (?:"(.*)"|'(.*)') >>? \S.*$`)
	// quotedVarRE matches a double-quoted word that holds the proxy's address as
	// an ecosystem test script spells it.
	quotedVarRE = regexp.MustCompile(`"([^"\s]*\$\{?(?:MOUNT|PROXY_URL|PROXY_HOST)\}?[^"\s]*)"`)
)

// squash collapses whitespace so indentation and alignment do not matter.
func squash(s string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
}

// substantial reports whether a line says enough to show that a script is the
// one a block was taken from: "}" and "EOF" are in every script.
func substantial(line string) bool {
	n := 0
	for _, r := range line {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			n++
		}
	}
	return n >= 4
}

// scriptLine is one line a script executes.
type scriptLine struct {
	// forms are the spellings a line of the guide may match the line as.
	forms []string
	// heredoc numbers the here document the line is content of (from 1); 0 for a
	// command.
	heredoc int
	// indent is the indentation of a here-document line — part of what the script
	// writes into the file.
	indent int
}

// heredocRE matches the start of a here document: <<EOF, <<'EOF', <<-EOF.
var heredocRE = regexp.MustCompile(`<<(-?)\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// executed returns the lines a script executes, in order.
//
// A command is matched as itself, without its output redirections
// ("mix local.hex --force >log 2>&1" runs the command the guide prints) and, for
// `echo "…" > file`, as the line it writes into the file. Comments are left out:
// a configuration that a script only shows in a comment has not been run.
//
// The lines of a here document are what the script writes into a file. They are
// matched as they are — a "#" line in one is a line of that file, not a comment
// of the script — and keep their indentation, which is part of the file.
func executed(script, kind string) []scriptLine {
	var (
		out       []scriptLine
		heredoc   int    // number of here documents seen
		end       string // the delimiter of the here document being read; "" outside
		stripTabs bool   // the here document was opened with <<-
	)
	for _, raw := range strings.Split(script, "\n") {
		if end != "" {
			content := raw
			if stripTabs {
				content = strings.TrimLeft(raw, "\t")
			}
			if content == end {
				end = ""
				continue
			}
			line := squash(content)
			if line == "" {
				continue
			}
			if kind == SourceCI {
				line = unquoteVars(line)
			}
			out = append(out, scriptLine{forms: []string{line}, heredoc: heredoc, indent: indentOf(content)})
			continue
		}
		line := squash(raw)
		if line == "" || line == "#" || strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "#!") {
			continue
		}
		forms := []string{line}
		if cmd := strings.TrimSpace(redirectRE.ReplaceAllString(line, "")); cmd != "" && cmd != line {
			forms = append(forms, cmd)
		}
		if m := echoRE.FindStringSubmatch(line); m != nil {
			forms = append(forms, m[1]+m[2])
		}
		if kind == SourceCI {
			for i := range forms {
				forms[i] = unquoteVars(forms[i])
			}
		}
		out = append(out, scriptLine{forms: forms})
		if m := heredocRE.FindStringSubmatch(line); m != nil {
			heredoc++
			end, stripTabs = m[2], m[1] == "-"
		}
	}
	return out
}

// unquoteVars drops the double quotes around a word that holds the proxy's
// address as a variable. An ecosystem test script writes
// `export JSR_URL="$MOUNT"` where the guide writes `export JSR_URL=https://…`:
// those quotes belong to the shell, not to the configuration. Both sides of a
// comparison with such a script are spelled this way.
func unquoteVars(s string) string {
	return quotedVarRE.ReplaceAllString(s, "$1")
}

// Checker holds what a verified block is checked against.
type Checker struct {
	// Scripts maps a source to the text of its script.
	Scripts map[Source]string
	// MountTypes maps an upstream name the guide uses in an address
	// (https://proxy.example.com/v1/<name>) to its upstream type, and CITypes an
	// ecosystem test script to the upstream type it tests. An ecosystem test
	// script spells its own package source "$MOUNT", whatever its name is — so a
	// line of the guide may be found there under that spelling only when the
	// address it names is of the type the script tests. Without these maps the
	// names are not compared.
	MountTypes map[string]string
	CITypes    map[string]string
}

// Result is the outcome of checking one verified block.
type Result struct {
	// Missing are the lines of the block that no script it names executes.
	Missing []string
	// Misordered are the lines a script executes, but before the line above
	// them: the block has the script's lines in another order.
	Misordered []string
	// Misindented are the lines of a file a script writes whose indentation,
	// relative to the line above them, is not the script's.
	Misindented []string
	// Scattered: the block's lines of a file are written by several scripts and
	// by no one of them all — a file no client has been given.
	Scattered bool
	// Unused are the sources that execute no substantial line of the block.
	Unused []Source
}

// OK reports whether the block is what its scripts execute.
func (r Result) OK() bool {
	return len(r.Missing) == 0 && len(r.Misordered) == 0 && len(r.Misindented) == 0 && !r.Scattered && len(r.Unused) == 0
}

// Check holds a verified block to the scripts its marker names. A block of
// another kind passes.
//
//   - Every line of the block — there are no comments: what the guide has to
//     say, it says in the text around a block — must be, after collapsing
//     whitespace, a whole line one of the scripts executes (see executed).
//   - Within one script the block's lines must come in the script's order.
//   - Lines of a file the script writes (a here document) must be indented, one
//     relative to the other, as the script indents them: a block may show part
//     of a file, moved to the left margin, but not another nesting.
//   - A block may take its lines from several scripts — a list of environment
//     variables, one per tool — but its lines of a file must all be written by
//     one of them: half an .npmrc and half a .condarc is a file no client was
//     given.
//   - Every script the marker names must execute at least one substantial line
//     of the block.
func (c Checker) Check(b Block) Result {
	var res Result
	if b.Marker == nil || b.Marker.Kind != KindVerified {
		return res
	}
	type progress struct {
		lines []scriptLine
		at    int // the script line the previous line of the block matched; -1 at the start
		// The indentation of that match in the block and in the script, to hold
		// the next line of the same here document to.
		blockIndent, scriptIndent int
	}
	scripts := map[Source]*progress{}
	for _, src := range b.Marker.Sources {
		scripts[src] = &progress{lines: executed(c.Scripts[src], src.Kind), at: -1}
	}
	credited := map[Source]bool{}
	checked := 0
	// fileLines counts the block's lines that are lines of a file some script
	// writes, and fileLinesIn those a given script writes.
	fileLines, fileLinesIn := 0, map[Source]int{}
	for _, raw := range b.Lines {
		line := squash(raw)
		if line == "" {
			continue
		}
		checked++
		indent := indentOf(raw)
		found, outOfOrder, otherIndent, ofFile := false, false, false, false
		for _, src := range b.Marker.Sources {
			script := scripts[src]
			wants := c.spellings(line, src)
			for i, sl := range script.lines {
				if !anyEqual(sl.forms, wants) {
					continue
				}
				if i <= script.at {
					outOfOrder = true
					continue
				}
				if sl.heredoc != 0 && script.at >= 0 && script.lines[script.at].heredoc == sl.heredoc &&
					indent-script.blockIndent != sl.indent-script.scriptIndent {
					otherIndent = true
					continue
				}
				script.at, script.blockIndent, script.scriptIndent = i, indent, sl.indent
				found = true
				if substantial(line) {
					credited[src] = true
				}
				if sl.heredoc != 0 {
					ofFile = true
					fileLinesIn[src]++
				}
				break
			}
		}
		if ofFile {
			fileLines++
		}
		switch {
		case found:
		case otherIndent:
			res.Misindented = append(res.Misindented, raw)
		case outOfOrder:
			res.Misordered = append(res.Misordered, raw)
		default:
			res.Missing = append(res.Missing, raw)
		}
	}
	if checked == 0 {
		res.Missing = append(res.Missing, "(the block has no line to verify)")
	}
	if fileLines > 0 {
		res.Scattered = true
		for _, n := range fileLinesIn {
			if n == fileLines {
				res.Scattered = false
			}
		}
	}
	for _, src := range b.Marker.Sources {
		if !credited[src] {
			res.Unused = append(res.Unused, src)
		}
	}
	return res
}

func anyEqual(have, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

// spellings returns how a line of the guide may be spelled in a script.
//
// A client-lab script uses the guide's own addresses and paths, so only the
// token differs. An ecosystem test script takes the proxy's address from its
// environment: its own package source is $MOUNT, any other one is
// "$PROXY_URL/v1/<name>", the host is $PROXY_HOST.
func (c Checker) spellings(line string, src Source) []string {
	if src.Kind != SourceCI {
		return []string{strings.ReplaceAll(line, TokenPlaceholder, labToken)}
	}
	host := func(s string) string {
		s = strings.ReplaceAll(s, "https://proxy.example.com", "$PROXY_URL")
		return strings.ReplaceAll(s, "proxy.example.com", "$PROXY_HOST")
	}
	out := []string{host(line), line}
	if c.ownMount(line, src) {
		out = append(out, host(mountRE.ReplaceAllString(line, "$$MOUNT")))
	}
	for i := range out {
		out[i] = unquoteVars(out[i])
	}
	return out
}

// ownMount reports whether every package source the line names is of the type
// the ecosystem test script tests — whether "$MOUNT" in that script can stand
// for it.
func (c Checker) ownMount(line string, src Source) bool {
	if c.MountTypes == nil || c.CITypes == nil {
		return true
	}
	want, ok := c.CITypes[src.Name]
	if !ok {
		return false
	}
	for _, m := range mountRE.FindAllStringSubmatch(line, -1) {
		typ, ok := c.MountTypes[m[1]]
		if !ok || PageFor(typ) != PageFor(want) {
			return false
		}
	}
	return true
}

// Fingerprint identifies what a client-lab script executes: a hash over its
// "# lab:" header lines (the image, the modes, the hosts it may look up) and its
// lines that are neither blank nor comments. scripts/client-lab/lab.sh computes
// the same value when it runs a script and records it with the result, so that
// a result can be told from the result of an earlier version of the script —
// while rewording a comment leaves it valid.
func Fingerprint(script string) string {
	lines := strings.Split(script, "\n")
	h := sha256.New()
	for _, line := range lines {
		if strings.HasPrefix(line, "# lab: ") {
			h.Write([]byte(line + "\n"))
		}
	}
	for _, line := range lines {
		text := strings.TrimLeft(line, " \t\r\v\f")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		h.Write([]byte(line + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
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
