package llmpkgscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// The sandbox. These three functions are everything the model can do, and each
// one is a pure read of the in-memory Tree: there is no filesystem path to
// traverse out of, no process to spawn, no socket to open. A request for
// anything else — an unknown tool name, a path that is not a key of the tree —
// yields an error result and nothing more.
//
// The model's arguments are untrusted output and are validated as such; the
// results are untrusted package content and are framed as such (delimited with
// the scan's nonce, never mixed with the proxy's own words).

// Tool names.
const (
	toolListFiles = "list_files"
	toolReadFile  = "read_file"
	toolGrep      = "grep"
)

// grepTimeBudget bounds one grep call's search time.
const grepTimeBudget = 3 * time.Second

// Bounds on a single tool call, independent of the configured budgets.
const (
	maxToolArgBytes   = 4 << 10  // a tool call's JSON arguments
	maxPatternBytes   = 512      // a grep pattern
	maxReadLines      = 2000     // lines one read_file call may return
	defaultReadLines  = 400      //
	maxGrepMatches    = 200      // matches one grep call may return
	defaultGrepMatch  = 60       //
	grepScanCap       = 16 << 20 // bytes one grep call may search
	maxGrepProgram    = 500      // compiled size of a grep pattern (instructions)
	grepContextChars  = 120      // characters shown either side of a match
	listPageMax       = 1000     // entries one list_files call may return
	defaultListPage   = 300      //
	maxSuggestions    = 5        // "did you mean" candidates for a bad path
	toolResultReserve = 400      // bytes kept back for the frame and trailer
)

// toolSpecs is the tool contract shown to the model. It is part of the prompt
// (PromptVersion covers it).
func toolSpecs() []commit.ToolSpec {
	return []commit.ToolSpec{
		{
			Name: toolListFiles,
			Description: "List the files of the unpacked artifact, sorted by path: path, size, kind (text or binary), and any role/signal labels. " +
				"Use it to see files the first message did not list, or to page through a directory.",
			Parameters: commit.ToolParameters{Properties: map[string]any{
				"prefix": map[string]any{"type": "string", "description": "Only list paths that start with this prefix, e.g. \"package/lib/\". Omit to list everything."},
				"offset": map[string]any{"type": "integer", "description": "Number of entries to skip, for paging. Default 0."},
			}},
		},
		{
			Name: toolReadFile,
			Description: "Read a range of lines from one file of the unpacked artifact, with line numbers. " +
				"A binary file cannot be shown: for one whose listing entry says \"extracted strings\" this returns those strings, otherwise only its kind. Long lines are cut — use grep to find text inside them.",
			Parameters: commit.ToolParameters{
				Properties: map[string]any{
					"path":       map[string]any{"type": "string", "description": "File path exactly as it appears in the listing."},
					"start_line": map[string]any{"type": "integer", "description": "First line to return (1-based). Default 1."},
					"max_lines":  map[string]any{"type": "integer", "description": "Maximum number of lines to return. Default 400."},
				},
				Required: []string{"path"},
			},
		},
		{
			Name: toolGrep,
			Description: "Search the text files of the unpacked artifact, and the strings extracted from its binaries, with a regular expression (RE2 syntax) and return matching lines as path:line: text. " +
				"Use it to find where something is defined or used, or to look for network calls, process execution, decoding, or credential access across the whole artifact.",
			Parameters: commit.ToolParameters{
				Properties: map[string]any{
					"pattern":     map[string]any{"type": "string", "description": "RE2 regular expression. A pattern that does not compile is searched as literal text."},
					"path_prefix": map[string]any{"type": "string", "description": "Only search paths that start with this prefix. Omit to search everything."},
					"ignore_case": map[string]any{"type": "boolean", "description": "Match case-insensitively. Default false."},
				},
				Required: []string{"pattern"},
			},
		},
	}
}

// toolbox executes tool calls for one scan and enforces that scan's budgets. It
// is used by a single goroutine.
type toolbox struct {
	tree  *Tree
	lim   Limits
	nonce string

	callsLeft int
	bytesLeft int

	calls  map[string]int // executed calls by tool name
	errors int            // calls answered with an error
}

func newToolbox(t *Tree, lim Limits, nonce string) *toolbox {
	return &toolbox{
		tree:      t,
		lim:       lim,
		nonce:     nonce,
		callsLeft: lim.MaxToolCalls,
		bytesLeft: lim.MaxToolBytes,
		calls:     make(map[string]int),
	}
}

// exhausted reports that no further tool call can be served.
func (tb *toolbox) exhausted() bool {
	return tb.callsLeft <= 0 || tb.bytesLeft < minToolResultBytes
}

// run executes one tool call and returns its result. It never returns a Go
// error: every failure is an error result the model can read and react to.
func (tb *toolbox) run(ctx context.Context, call commit.ToolCall) commit.ToolResult {
	fail := func(format string, args ...any) commit.ToolResult {
		tb.errors++
		return commit.ToolResult{CallID: call.ID, IsError: true, Content: fmt.Sprintf(format, args...) + tb.trailer()}
	}
	if tb.exhausted() {
		return fail("Tool budget exhausted. No further tool calls will be answered.")
	}
	tb.callsLeft--

	if len(call.Input) > maxToolArgBytes {
		return fail("Tool arguments are too large.")
	}
	// The per-result budget: the configured cap, shrunk to what is left overall.
	budget := tb.lim.MaxToolResultBytes
	if budget > tb.bytesLeft {
		budget = tb.bytesLeft
	}
	budget -= toolResultReserve
	if budget < 256 {
		return fail("Tool output budget exhausted. No further tool output is available.")
	}

	var (
		body string
		err  error
	)
	switch call.Name {
	case toolListFiles:
		var args struct {
			Prefix string `json:"prefix"`
			Offset int    `json:"offset"`
		}
		if err = decodeArgs(call.Input, &args); err == nil {
			body = tb.listFiles(args.Prefix, args.Offset, budget)
		}
	case toolReadFile:
		var args struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			MaxLines  int    `json:"max_lines"`
		}
		if err = decodeArgs(call.Input, &args); err == nil {
			body, err = tb.readFile(args.Path, args.StartLine, args.MaxLines, budget)
		}
	case toolGrep:
		var args struct {
			Pattern    string `json:"pattern"`
			PathPrefix string `json:"path_prefix"`
			IgnoreCase bool   `json:"ignore_case"`
		}
		if err = decodeArgs(call.Input, &args); err == nil {
			body, err = tb.grep(ctx, args.Pattern, args.PathPrefix, args.IgnoreCase, budget)
		}
	default:
		// The tool name is model output. It is neither interpreted nor echoed:
		// an error result is the proxy speaking, outside the data markers, so it
		// must not carry a string the package could have steered.
		return fail("Unknown tool. The only tools are list_files, read_file and grep.")
	}
	if err != nil {
		return fail("%s", err.Error())
	}
	tb.calls[call.Name]++

	// Frame the result as package data. The trailer is the proxy speaking and
	// therefore sits outside the markers.
	content := openMarker(tb.nonce) + "\n" + body + closeMarker(tb.nonce) + tb.trailer()
	tb.bytesLeft -= len(content)
	return commit.ToolResult{CallID: call.ID, Content: content}
}

// trailer states the remaining allowance, in the proxy's own words.
func (tb *toolbox) trailer() string {
	calls := tb.callsLeft
	if calls < 0 {
		calls = 0
	}
	if tb.exhausted() {
		return "\n[proxy] No tool calls remain. Reply now with only the JSON verdict."
	}
	return fmt.Sprintf("\n[proxy] %d tool call(s) remain.", calls)
}

// decodeArgs parses a tool call's arguments. Unknown keys are ignored (a model
// adding a harmless extra field should not lose the call); wrong types are an
// error the model can correct.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("Invalid tool arguments: they must be a JSON object matching the tool's schema.")
	}
	return nil
}

// matchPrefix normalizes a path prefix argument the way member names were
// normalized, keeping a trailing slash meaningful.
func matchPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "." || prefix == "/" || prefix == "./" {
		return ""
	}
	dir := strings.HasSuffix(prefix, "/") || strings.HasSuffix(prefix, `\`)
	clean, _ := safePath(prefix)
	if clean == "_unnamed" {
		return ""
	}
	if dir {
		clean += "/"
	}
	return clean
}

// listFiles renders a page of the path-sorted listing.
func (tb *toolbox) listFiles(prefix string, offset, budget int) string {
	prefix = matchPrefix(prefix)
	if offset < 0 {
		offset = 0
	}
	var matched []*File
	for _, f := range tb.tree.Files {
		if prefix == "" || strings.HasPrefix(f.Path, prefix) {
			matched = append(matched, f)
		}
	}
	var b strings.Builder
	total := len(matched)
	if total == 0 {
		fmt.Fprintf(&b, "(no files match prefix %s)\n", neutralize(quoteUntrusted(prefix, 200), tb.nonce))
		return b.String()
	}
	if offset >= total {
		fmt.Fprintf(&b, "(offset %d is past the end: %d file(s) match)\n", offset, total)
		return b.String()
	}
	fmt.Fprintf(&b, "(%d file(s) match; showing from entry %d)\n", total, offset+1)
	shown := 0
	for _, f := range matched[offset:] {
		line := listingLine(f, tb.nonce)
		if b.Len()+len(line)+80 > budget || shown == listPageMax {
			break
		}
		b.WriteString(line)
		shown++
	}
	if next := offset + shown; next < total {
		fmt.Fprintf(&b, "(%d more; call list_files again with offset %d)\n", total-next, next)
	}
	return b.String()
}

// readFile renders a line range of one file.
func (tb *toolbox) readFile(p string, start, maxLines, budget int) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("read_file needs a \"path\".")
	}
	var b strings.Builder
	f, ok := tb.tree.Lookup(p)
	if !ok {
		// Answered inside the data markers, not as an error: the reply repeats a
		// model-supplied path and names files from the package.
		fmt.Fprintf(&b, "(no such file in the package: %s.%s)\n", neutralize(quoteUntrusted(p, 200), tb.nonce), neutralize(tb.suggest(p), tb.nonce))
		return b.String(), nil
	}
	name := neutralize(f.Path, tb.nonce)
	switch {
	case f.Binary && !f.Strings:
		fmt.Fprintf(&b, "(%s is a binary file: %s, %d bytes. Binary content is not shown, and no printable strings were extracted from it.)\n", name, f.Kind, f.Size)
		return b.String(), nil
	case f.Unretained:
		fmt.Fprintf(&b, "(%s is a text file of %d bytes whose content was not retained: the scan's memory budget was spent.)\n", name, f.Size)
		return b.String(), nil
	case f.Lines == 0:
		fmt.Fprintf(&b, "(%s is empty.)\n", name)
		return b.String(), nil
	}
	if start < 1 {
		start = 1
	}
	if start > f.Lines {
		fmt.Fprintf(&b, "(%s has %d line(s); start_line %d is past the end.)\n", name, f.Lines, start)
		return b.String(), nil
	}
	if maxLines <= 0 {
		maxLines = defaultReadLines
	}
	if maxLines > maxReadLines {
		maxLines = maxReadLines
	}
	end := start + maxLines - 1
	if end > f.Lines {
		end = f.Lines
	}
	if f.Strings {
		fmt.Fprintf(&b, "(%s — binary: %s, %d bytes; what follows are the %d lines of printable strings the proxy extracted from it, not the file itself)\n", name, f.Kind, f.Size, f.Lines)
	} else {
		fmt.Fprintf(&b, "(%s — %d bytes, %d lines)\n", name, len(f.Data), f.Lines)
	}
	last := renderLines(&b, f, start, end, budget-b.Len()-160, tb.nonce)
	switch {
	case last < start:
		fmt.Fprintf(&b, "(line %d does not fit in the remaining tool output budget)\n", start)
	case last < f.Lines:
		fmt.Fprintf(&b, "(lines %d-%d of %d shown; continue with start_line %d)\n", start, last, f.Lines, last+1)
	case f.Truncated:
		fmt.Fprintf(&b, "(lines %d-%d shown; that is the end of what is available — the file is cut at the per-file limit of %d bytes)\n", start, last, tb.lim.MaxFileBytes)
	default:
		fmt.Fprintf(&b, "(lines %d-%d shown; end of file)\n", start, last)
	}
	return b.String(), nil
}

// suggest offers files with the same base name when a path does not resolve.
// It only ever names files that exist in the tree.
func (tb *toolbox) suggest(p string) string {
	clean, _ := safePath(p)
	base := path.Base(clean)
	var hits []string
	for _, f := range tb.tree.Files {
		if path.Base(f.Path) == base {
			hits = append(hits, f.Path)
			if len(hits) == maxSuggestions {
				break
			}
		}
	}
	if len(hits) == 0 {
		return " Use list_files to see the paths that exist."
	}
	quoted := make([]string, len(hits))
	for i, h := range hits {
		quoted[i] = quoteUntrusted(h, 200)
	}
	return " Files with that name: " + strings.Join(quoted, ", ") + "."
}

// grep searches the readable files and renders matching lines. The pattern is
// compiled by Go's regexp package, which guarantees linear-time matching, so a
// pathological pattern cannot stall the scan; the bytes searched per call are
// capped as well.
func (tb *toolbox) grep(ctx context.Context, pattern, prefix string, ignoreCase bool, budget int) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("grep needs a non-empty \"pattern\".")
	}
	if len(pattern) > maxPatternBytes {
		return "", fmt.Errorf("The pattern is too long (limit %d bytes).", maxPatternBytes)
	}
	re, literal, err := compileGrep(pattern, ignoreCase)
	if err != nil {
		return "", err
	}
	prefix = matchPrefix(prefix)
	deadline := time.Now().Add(grepTimeBudget)

	// Search the most relevant files first, so a capped result holds the hits
	// that matter most.
	files := tb.tree.byPriority()
	var b strings.Builder
	if literal {
		b.WriteString("(the pattern is not a valid regular expression; searched as literal text)\n")
	}
	matches, searched, skipped := 0, 0, 0
	truncated := ""
scan:
	for _, f := range files {
		if !f.Readable() || f.Lines == 0 {
			continue
		}
		if prefix != "" && !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			truncated = "the search ran out of time"
			break
		}
		if searched+len(f.Data) > grepScanCap {
			skipped++
			continue
		}
		searched += len(f.Data)
		lastLine := 0
		for _, loc := range re.FindAllIndex(f.Data, maxGrepMatches) {
			n := f.lineAt(loc[0])
			if n == lastLine {
				continue // one result per line
			}
			lastLine = n
			line := fmt.Sprintf("%s:%d: %s\n", neutralize(f.Path, tb.nonce), n, neutralize(matchContext(f, n, loc), tb.nonce))
			if b.Len()+len(line)+160 > budget {
				truncated = "the tool output budget for one call was reached"
				break scan
			}
			b.WriteString(line)
			matches++
			if matches >= defaultGrepMatch {
				truncated = fmt.Sprintf("the limit of %d matches per call was reached", defaultGrepMatch)
				break scan
			}
		}
	}
	switch {
	case matches == 0 && truncated == "":
		b.WriteString("(no matches)\n")
	case truncated != "":
		fmt.Fprintf(&b, "(%d match(es) shown; stopped because %s — narrow the pattern or use path_prefix)\n", matches, truncated)
	default:
		fmt.Fprintf(&b, "(%d match(es); search complete)\n", matches)
	}
	if skipped > 0 {
		fmt.Fprintf(&b, "(%d file(s) were not searched: the per-call search limit of %d bytes was reached — use path_prefix)\n", skipped, grepScanCap)
	}
	return b.String(), nil
}

// compileGrep compiles a model-supplied pattern. Go's regexp engine matches in
// time linear in the input, but the constant is the size of the compiled
// program, and a short pattern with counted repetitions can compile to a very
// large one. The program size is therefore capped: together with the per-call
// byte and time budgets this keeps a hostile pattern from turning a search into
// a CPU sink. A pattern that is not a valid expression is searched literally.
func compileGrep(pattern string, ignoreCase bool) (re *regexp.Regexp, literal bool, err error) {
	flags := syntax.Perl
	if ignoreCase {
		flags |= syntax.FoldCase
	}
	parsed, perr := syntax.Parse(pattern, flags)
	if perr != nil {
		literal = true
		parsed, perr = syntax.Parse(regexp.QuoteMeta(pattern), flags)
		if perr != nil {
			return nil, false, fmt.Errorf("The pattern cannot be searched.")
		}
	}
	prog, cerr := syntax.Compile(parsed.Simplify())
	if cerr != nil || len(prog.Inst) > maxGrepProgram {
		return nil, false, fmt.Errorf("The pattern is too complex. Use a simpler expression.")
	}
	expr := pattern
	if literal {
		expr = regexp.QuoteMeta(pattern)
	}
	if ignoreCase {
		expr = "(?i)" + expr
	}
	re, err = regexp.Compile(expr)
	if err != nil {
		return nil, false, fmt.Errorf("The pattern cannot be searched.")
	}
	return re, literal, nil
}

// matchContext renders the matched line, or — for a line too long to show whole
// — a window around the match, so a hit inside a minified one-line bundle is
// still legible.
func matchContext(f *File, n int, loc []int) string {
	line := f.line(n)
	if len(line) <= 2*grepContextChars+80 {
		return visible(line, maxLineChars)
	}
	lineStart := f.lineStarts[n-1]
	from := loc[0] - lineStart - grepContextChars
	to := loc[1] - lineStart + grepContextChars
	prefix, suffix := "…", "…"
	if from <= 0 {
		from, prefix = 0, ""
	}
	if to >= len(line) {
		to, suffix = len(line), ""
	}
	// Do not start or end inside a multi-byte character.
	for from > 0 && from < len(line) && !isRuneStart(line[from]) {
		from--
	}
	for to < len(line) && !isRuneStart(line[to]) {
		to++
	}
	if to-from > 4*grepContextChars+400 {
		to = from + 4*grepContextChars + 400
		suffix = "…"
	}
	return prefix + visible(line[from:to], maxLineChars) + suffix
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// stats returns the executed-call counts, sorted by tool name.
func (tb *toolbox) stats() (total int, byTool map[string]int) {
	byTool = make(map[string]int, len(tb.calls))
	names := make([]string, 0, len(tb.calls))
	for n := range tb.calls {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		byTool[n] = tb.calls[n]
		total += tb.calls[n]
	}
	return total, byTool
}
