package llmpkgscan

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/mlguard"
)

// What the model is given for a file it cannot read.
//
// Most of what a bottle, a NAR, an OS package, a jar or a model weight file
// holds is not text. A model cannot review machine code, but a binary is not
// opaque either: its printable strings carry the URLs it talks to, the shell
// commands it runs, the paths it touches and the names of the functions it
// imports, and its header says what kind of thing it is. This file turns a
// binary member into that: a one-line description (describeBinary) and a text
// view of its strings (binaryView), which the tools then read and search like
// any other file. Nothing is disassembled, loaded or executed, and none of the
// parsers below trusts a length it reads.

// Bounds on the strings view of one binary.
const (
	// minStringRun is the shortest run of printable characters kept, the default
	// of strings(1). A run shorter than minPlainRun is kept only if it is one of
	// the tokens that matter on their own.
	minStringRun = 4
	minPlainRun  = 6
	// maxStringRun cuts a single run; a longer one is a blob, not a string.
	maxStringRun = 400
	// maxStringCandidates bounds the runs considered per binary.
	maxStringCandidates = 20000
	// maxStringsBytes and maxStringsLines bound the view kept per binary.
	maxStringsBytes = 32 << 10
	maxStringsLines = 1500
	// maxPickleImports bounds the imports listed in a pickle's summary.
	maxPickleImports = 200
	// entropySample is how much of a binary the entropy estimate reads.
	entropySample = 256 << 10
)

// shortTokens are runs shorter than minPlainRun that are worth a line of their
// own: the names a pickle or a script imports to run something.
var shortTokens = setOf("os", "nt", "sh", "pty", "eval", "exec", "bash", "curl", "wget", "posix", "popen", "Popen",
	"runpy", "fork", "nc", "ncat", "dll", "exe", "ps1", "cmd", "su", "sudo", "ssh", "scp", "cron")

// stringRun is one printable run found in a binary.
type stringRun struct {
	off         int // offset of the run in the file (ASCII runs only)
	text        string
	interesting bool
}

// binaryView renders the printable strings of a binary as text, one per line,
// with the strings most likely to matter first: a structured summary where the
// format has one (a pickle's imports, a safetensors header), then the strings
// that trip a signal rule, then the rest in file order. It returns nil when the
// binary holds nothing printable worth showing.
func binaryView(data []byte, kind string) []byte {
	var b bytes.Buffer
	lines := 0
	for _, line := range structuredSummary(data, kind) {
		b.WriteString(line)
		b.WriteByte('\n')
		lines++
	}
	runs := extractStringRuns(data)
	// Interesting strings first; each group stays in file order.
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].interesting && !runs[j].interesting })
	for _, r := range runs {
		if b.Len()+len(r.text)+1 > maxStringsBytes || lines >= maxStringsLines {
			break
		}
		// A string in the file cannot pass for one of the proxy's summary lines.
		b.WriteString(defuseProxyTag(r.text))
		b.WriteByte('\n')
		lines++
	}
	if b.Len() == 0 {
		return nil
	}
	return b.Bytes()
}

// proxyTag opens the lines of a strings view that the proxy wrote itself.
const proxyTag = "[proxy]"

// defuseProxyTag rewrites a string found in a binary that begins like one of
// the proxy's own summary lines, so the summary cannot be forged from inside
// the file.
func defuseProxyTag(s string) string {
	if strings.HasPrefix(strings.TrimLeft(s, " \t"), proxyTag) {
		return strings.Replace(s, proxyTag, "[string from the file, not the proxy]", 1)
	}
	return s
}

// stringNeedles are the substrings that make a string worth showing first: the
// needles of the signal rules the ranking applies to text files (process
// execution, decoding, network access, credential paths, exfiltration hosts,
// persistence). The obfuscation rule is left out — a long unbroken run is what
// most strings in a binary are.
var stringNeedles = func() [][]byte {
	var out [][]byte
	for _, r := range signalRules {
		if r.name == "obfuscation" {
			continue
		}
		for _, n := range r.needles {
			out = append(out, []byte(n))
		}
		for _, w := range r.words {
			out = append(out, []byte(w))
		}
	}
	return out
}()

// maxNeedleHits bounds the occurrences of one needle that are followed up.
const maxNeedleHits = 32

// extractStringRuns finds the printable runs of a binary: ASCII, and UTF-16LE
// (the encoding of string literals in .NET assemblies and Windows resources).
// Duplicates are dropped; the result is in file order, ASCII runs first.
func extractStringRuns(data []byte) []stringRun {
	// ASCII runs. A run shorter than minStringRun counts only when it is one of
	// the short tokens and stands alone between non-printable bytes, which is how
	// a pickle or a symbol table stores a name.
	var runs []stringRun
	start := -1
	for i := 0; i <= len(data) && len(runs) < maxStringCandidates; i++ {
		if i < len(data) && printableASCII(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if n := i - start; n >= minStringRun || (n >= 2 && shortTokens[string(data[start:i])]) {
				runs = append(runs, stringRun{off: start, text: string(data[start:i])})
			}
			start = -1
		}
	}

	// Mark the runs a needle occurs in. Searching the file once per needle is far
	// cheaper than testing every run against every needle.
	mark := func(pos int) {
		i := sort.Search(len(runs), func(i int) bool { return runs[i].off > pos }) - 1
		if i >= 0 && pos < runs[i].off+len(runs[i].text) {
			runs[i].interesting = true
		}
	}
	for _, needle := range stringNeedles {
		for off, hits := 0, 0; off < len(data) && hits < maxNeedleHits; hits++ {
			i := bytes.Index(data[off:], needle)
			if i < 0 {
				break
			}
			mark(off + i)
			off += i + 1
		}
	}
	for off, hits := 0, 0; off < len(data) && hits < maxNeedleHits; hits++ {
		i := indexIPPort(data[off:])
		if i < 0 {
			break
		}
		mark(off + i)
		off += i + 1
	}

	// UTF-16LE runs: printable ASCII characters each followed by a zero byte.
	asciiRuns := len(runs)
	var wide []byte
	flush := func() {
		if len(wide) >= minPlainRun && len(runs) < maxStringCandidates {
			text := string(wide)
			runs = append(runs, stringRun{text: text, interesting: len(runs)-asciiRuns < maxWideChecked && interestingString(text)})
		}
		wide = wide[:0]
	}
	for i := 0; i+1 < len(data); {
		if printableASCII(data[i]) && data[i+1] == 0 {
			wide = append(wide, data[i])
			i += 2
			continue
		}
		flush()
		i++
	}
	flush()

	// Keep what is worth a line, cut over-long runs, and drop duplicates.
	out := runs[:0]
	seen := make(map[string]int, len(runs))
	for _, r := range runs {
		text := strings.TrimSpace(r.text)
		token := shortTokens[text]
		if len(text) < minPlainRun && !token && !r.interesting {
			continue
		}
		if len(text) > maxStringRun {
			text = truncateUTF8(text, maxStringRun) + "…"
		}
		if at, dup := seen[text]; dup {
			out[at].interesting = out[at].interesting || r.interesting
			continue
		}
		seen[text] = len(out)
		out = append(out, stringRun{off: r.off, text: text, interesting: r.interesting || token})
	}
	return out
}

// maxWideChecked bounds the UTF-16 runs tested against the needles one by one.
const maxWideChecked = 2000

func printableASCII(c byte) bool { return (c >= 0x20 && c <= 0x7e) || c == '\t' }

// interestingString reports whether a string contains one of stringNeedles.
func interestingString(s string) bool {
	data := []byte(s)
	for _, needle := range stringNeedles {
		if bytes.Contains(data, needle) {
			return true
		}
	}
	return indexIPPort(data) >= 0
}

// structuredSummary returns proxy-written lines describing a binary whose
// format has a header worth reading: what a pickle imports and calls, what a
// safetensors or GGUF file declares. Every line starts with "[proxy]" so it is
// never mistaken for a string found in the file.
func structuredSummary(data []byte, kind string) []string {
	switch {
	case looksLikePickle(data):
		sum := mlguard.SummarizePickle(data)
		var lines []string
		if len(sum.Imports) == 0 {
			lines = append(lines, proxyTag+" pickle opcode stream: imports no callables (GLOBAL / STACK_GLOBAL)")
		} else {
			// The stream's author chooses the order of its imports, and only the
			// first maxPickleImports are listed: the ones the model-file rules flag
			// go first, so a dangerous import cannot be pushed off the end of the
			// list by harmless ones placed in front of it.
			flagged := make(map[string]bool, len(sum.Flagged))
			imports := make([]string, 0, len(sum.Imports))
			for _, imp := range sum.Flagged {
				flagged[imp] = true
				imports = append(imports, imp)
			}
			for _, imp := range sum.Imports {
				if !flagged[imp] {
					imports = append(imports, imp)
				}
			}
			more := ""
			if len(imports) > maxPickleImports {
				more = fmt.Sprintf(" … and %d more", len(imports)-maxPickleImports)
				imports = imports[:maxPickleImports]
			}
			names, odd := pickleNames(imports)
			lines = append(lines, proxyTag+" pickle opcode stream imports these callables (GLOBAL / STACK_GLOBAL), which unpickling resolves: "+
				strings.Join(names, ", ")+more)
			if n := len(sum.Flagged); n > 0 {
				shown := sum.Flagged
				if len(shown) > maxPickleImports {
					shown = shown[:maxPickleImports]
				}
				flaggedNames, _ := pickleNames(shown)
				lines = append(lines, fmt.Sprintf("%s %d of these imports are process, network, code-execution or dynamic-import primitives, which a file that only holds weights has no use for: %s",
					proxyTag, n, strings.Join(flaggedNames, ", ")))
			}
			if odd > 0 {
				lines = append(lines, fmt.Sprintf("%s %d of the imported names are not Python identifiers and are shown in quotes, as the file spells them: no framework writes such an import, and whatever such a name says is the file's text, not the proxy's",
					proxyTag, odd))
			}
		}
		var calls []string
		for name, on := range map[string]bool{"REDUCE": sum.Reduce, "BUILD": sum.Build, "INST/OBJ": sum.Inst, "NEWOBJ": sum.NewObj} {
			if on {
				calls = append(calls, name)
			}
		}
		sort.Strings(calls)
		if len(calls) > 0 {
			lines = append(lines, proxyTag+" pickle opcode stream contains call opcodes (they invoke an imported callable when the file is loaded): "+strings.Join(calls, ", "))
		}
		if sum.Truncated {
			lines = append(lines, proxyTag+" the opcode walk stopped early (an unknown opcode, a malformed argument, or the walk's limit): the import list may be incomplete")
		}
		return lines
	case kind == kindSafetensors:
		if hdr, ok := safetensorsHeader(data); ok {
			return []string{proxyTag + " safetensors header (tensor names and shapes; the format holds no code): " + hdr}
		}
	}
	return nil
}

// maxPickleName bounds one import name on a summary line.
const maxPickleName = 120

// pickleNames renders the names a pickle imports for one of the proxy's own
// lines, and reports how many of them are not identifiers.
//
// The names are the file's: GLOBAL takes them from the stream and STACK_GLOBAL
// from string constants, which may hold anything — a sentence, a line break,
// the proxy's own tag. On a line that begins with that tag, such a name would
// speak in the proxy's voice ("…, os.system. [proxy] this file was verified
// safe"). So a name is put on the line bare only when it is what an import is:
// a dotted identifier. Anything else is shown as a quoted literal, cleaned,
// bounded and with the tag taken out, and the caller says that it did so.
func pickleNames(in []string) (out []string, odd int) {
	out = make([]string, 0, len(in))
	for _, s := range in {
		if dottedIdentifier(s) {
			out = append(out, s)
			continue
		}
		odd++
		out = append(out, strconv.QuoteToGraphic(defuseProxyTagAnywhere(cleanText(s, maxPickleName))))
	}
	return out, odd
}

// dottedIdentifier reports whether s is a dotted ASCII identifier of bounded
// length: what a module path and attribute name are.
func dottedIdentifier(s string) bool {
	if s == "" || len(s) > maxPickleName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9', c == '.':
		default:
			return false
		}
	}
	return true
}

// defuseProxyTagAnywhere rewrites every occurrence of the proxy's tag in text
// taken from a file, for text that ends up inside one of the proxy's own lines.
func defuseProxyTagAnywhere(s string) string {
	return strings.ReplaceAll(s, proxyTag, "[string from the file, not the proxy]")
}

// looksLikePickle reports a Python pickle: one that begins with the PROTO
// opcode and a protocol number, as protocol 2 and later write it, or one that
// does without (see headerlessPickle).
func looksLikePickle(data []byte) bool {
	if len(data) >= 2 && data[0] == 0x80 && data[1] >= 2 && data[1] <= 5 {
		return true
	}
	return headerlessPickle(data)
}

// pickleProbeBytes is how much of a file headerlessPickle walks.
const pickleProbeBytes = 4 << 10

// headerlessPickle reports a pickle that does not begin with a PROTO opcode.
//
// The header is a courtesy, not a requirement: protocols 0 and 1 have none, and
// an unpickler reads a stream of any protocol's opcodes whether or not one
// precedes them. "cos\nsystem\n(S'id'\ntR." is a complete pickle that runs a
// command when loaded, and it starts with the letter c. A check for the header
// alone is therefore a check the author of a malicious pickle opts out of by
// leaving two bytes off.
//
// What makes a pickle dangerous is that it imports a callable — GLOBAL, INST or
// STACK_GLOBAL — and every way of running code on load starts there. So the
// beginning of the file is walked as an opcode stream (statically, by the
// weight-scan gate's walker; nothing is unpickled), and the file is taken for a
// pickle when that walk reaches an import of something named like a module
// attribute before it reaches a byte that is not an opcode. Text does not get
// that far: a space or a line break is not an opcode, and "import os" read as an
// INST names a module with a space in it.
//
// This is a recognizer for the beginning of a file, and a pickle can be written
// to keep its first import out of any fixed-size beginning. Where it matters
// that a pickle is examined, the backend says so by classifying it as a payload;
// this is the net under the resources nobody classified.
func headerlessPickle(data []byte) bool {
	if len(data) < 4 || !pickleLeadOpcode[data[0]] {
		return false
	}
	head := data
	if len(head) > pickleProbeBytes {
		head = head[:pickleProbeBytes]
	}
	for _, imp := range mlguard.SummarizePickle(head).Imports {
		module, name, ok := strings.Cut(imp, ".")
		if ok && module != "" && name != "" && dottedIdentifier(imp) && !strings.HasPrefix(name, ".") && !strings.HasSuffix(imp, ".") {
			return true
		}
	}
	return false
}

// textPickleNote describes, for a member that reads as text, the pickle it
// turns out to be: which process, network, code-execution or dynamic-import
// primitives it imports. It returns "" for anything else — text that is no
// pickle, and a pickle that imports nothing the model-file rules flag.
func textPickleNote(data []byte) string {
	if !headerlessPickle(data) {
		return ""
	}
	sum := mlguard.SummarizePickle(data)
	if len(sum.Flagged) == 0 {
		return ""
	}
	shown := sum.Flagged
	more := ""
	if len(shown) > 20 {
		more = fmt.Sprintf(" … and %d more", len(shown)-20)
		shown = shown[:20]
	}
	names, _ := pickleNames(shown)
	return "imports callables that run code, reach the network or load modules when the file is unpickled: " + strings.Join(names, ", ") + more
}

// pickleLeadOpcode are the opcodes a pickle can sensibly begin with: the ones
// that push something, open a container, or import. It is a cheap filter in
// front of the walk, so that most files are dismissed on their first byte.
var pickleLeadOpcode = func() (t [256]bool) {
	// PROTO (with a protocol number the header check above does not accept),
	// MARK and the empty containers, GLOBAL, NONE, every string, bytes and number
	// push, the booleans, EMPTY_SET, BYTEARRAY8 and FRAME. An opcode that needs
	// something on the stack or in the memo (INST, PUT, GET, POP, MEMOIZE, …)
	// cannot come first.
	for _, op := range []byte("\x80(]})cNSVUTXBCFIJKLMG\x8c\x8d\x8e\x8a\x8b\x88\x89\x8f\x96\x95") {
		t[op] = true
	}
	return t
}()

// Kinds describeBinary returns that other code keys on.
const (
	kindSafetensors = "safetensors model weights"
	kindPickle      = "Python pickle"
)

// safetensorsHeader returns the start of a safetensors file's JSON header: an
// 8-byte little-endian length followed by a JSON object.
func safetensorsHeader(data []byte) (string, bool) {
	if len(data) < 10 {
		return "", false
	}
	n := binary.LittleEndian.Uint64(data[:8])
	if n < 2 || n > 100<<20 || data[8] != '{' {
		return "", false
	}
	end := uint64(len(data))
	if 8+n < end {
		end = 8 + n
	}
	hdr := data[8:end]
	if end == 8+n && !json.Valid(hdr) {
		return "", false
	}
	if !utf8.Valid(hdr) && end == 8+n {
		return "", false
	}
	// The header is the file's text — tensor names, and a free-form __metadata__
	// map — quoted on a line of the proxy's: the tag is taken out of it.
	return defuseProxyTagAnywhere(cleanText(string(hdr), 2000)), true
}

// describeBinary names what a binary member is, from its leading bytes, and
// adds what its header says: for an executable its bitness, architecture and
// whether it is a program or a library; for any binary whether it looks packed.
// It is a description for the model, not a security classification, and every
// field is read with its bounds checked.
func describeBinary(data []byte) string {
	kind := sniffBinary(data)
	switch {
	case bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}):
		kind = describeELF(data)
	case bytes.HasPrefix(data, []byte{'M', 'Z'}):
		kind = describePE(data)
	case isMachO(data):
		kind = describeMachO(data)
	case bytes.HasPrefix(data, []byte{0xCA, 0xFE, 0xBA, 0xBE}) && len(data) >= 8:
		// The same magic opens a Java class file and a Mach-O universal binary.
		// The next field tells them apart: a class file's version is 45 or more,
		// a universal binary's architecture count a handful.
		if n := binary.BigEndian.Uint32(data[4:8]); n < 43 {
			kind = fmt.Sprintf("Mach-O universal binary (%d architectures)", n)
		} else {
			kind = fmt.Sprintf("Java class file (class version %d)", binary.BigEndian.Uint16(data[6:8]))
		}
	case looksLikePickle(data):
		if data[0] == 0x80 {
			kind = fmt.Sprintf("%s (protocol %d)", kindPickle, data[1])
		} else {
			// Protocol 0 or 1, or a later one written without its header.
			kind = kindPickle + " (no protocol header)"
		}
	case isSafetensors(data):
		kind = kindSafetensors
	case bytes.HasPrefix(data, []byte("GGUF")):
		kind = "GGUF model weights"
	case bytes.HasPrefix(data, []byte("\x89HDF\r\n\x1a\n")):
		kind = "HDF5 data (Keras .h5 weights can embed code)"
	case bytes.HasPrefix(data, []byte("\x93NUMPY")):
		kind = "NumPy array file (an object array is a pickle)"
	case bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfe, 0xed}):
		kind = "Java keystore"
	}
	if bytes.Contains(data[:min(len(data), 4096)], []byte("UPX!")) {
		kind += "; UPX-packed"
	} else if len(data) >= 8<<10 && byteEntropy(data[:min(len(data), entropySample)]) > 7.6 && executableKind(kind) {
		kind += "; high entropy (packed or encrypted)"
	}
	return kind
}

// executableKind reports whether a description names machine code — the kinds
// for which high entropy is notable (a compressed archive is high-entropy by
// design).
func executableKind(kind string) bool {
	return strings.HasPrefix(kind, "ELF") || strings.HasPrefix(kind, "Windows PE") || strings.HasPrefix(kind, "Mach-O")
}

func isSafetensors(data []byte) bool {
	_, ok := safetensorsHeader(data)
	return ok
}

// byteEntropy is the Shannon entropy of data in bits per byte (0..8).
func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range data {
		counts[c]++
	}
	var h float64
	n := float64(len(data))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// describeELF reads the fixed part of an ELF header.
func describeELF(data []byte) string {
	if len(data) < 20 {
		return "ELF binary (truncated header)"
	}
	bits := "32-bit"
	if data[4] == 2 {
		bits = "64-bit"
	}
	var order binary.ByteOrder = binary.LittleEndian
	if data[5] == 2 {
		order = binary.BigEndian
	}
	typ := "object"
	switch order.Uint16(data[16:18]) {
	case 1:
		typ = "relocatable object"
	case 2:
		typ = "executable"
	case 3:
		typ = "shared object or position-independent executable"
	case 4:
		typ = "core dump"
	}
	arch := ""
	switch order.Uint16(data[18:20]) {
	case 3:
		arch = "x86"
	case 62:
		arch = "x86-64"
	case 40:
		arch = "ARM"
	case 183:
		arch = "AArch64"
	case 243:
		arch = "RISC-V"
	case 8:
		arch = "MIPS"
	case 20, 21:
		arch = "PowerPC"
	case 22:
		arch = "s390"
	case 247:
		arch = "eBPF"
	}
	if arch != "" {
		arch = " " + arch
	}
	return "ELF " + bits + arch + " " + typ
}

// describePE reads a PE file's COFF header and, when present, whether it is a
// .NET assembly.
func describePE(data []byte) string {
	const generic = "Windows PE executable or DLL"
	if len(data) < 0x40 {
		return generic
	}
	off := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if off < 0 || off > len(data)-24 || string(data[off:off+4]) != "PE\x00\x00" {
		return generic
	}
	coff := data[off+4:]
	arch := ""
	switch binary.LittleEndian.Uint16(coff[0:2]) {
	case 0x14c:
		arch = " x86"
	case 0x8664:
		arch = " x86-64"
	case 0xaa64:
		arch = " ARM64"
	case 0x1c0, 0x1c4:
		arch = " ARM"
	}
	kind := "executable"
	if binary.LittleEndian.Uint16(coff[18:20])&0x2000 != 0 {
		kind = "DLL"
	}
	out := "Windows PE" + arch + " " + kind
	// The optional header's 15th data directory is the CLR runtime header: its
	// presence marks a .NET assembly.
	opt := coff[20:]
	if len(opt) >= 2 {
		dirs := 0
		switch binary.LittleEndian.Uint16(opt[0:2]) {
		case 0x10b:
			dirs = 96
		case 0x20b:
			dirs = 112
		}
		if clr := dirs + 14*8; dirs > 0 && len(opt) >= clr+8 && binary.LittleEndian.Uint32(opt[clr:clr+4]) != 0 {
			out += " (.NET assembly)"
		}
	}
	return out
}

var machOMagics = [][]byte{
	{0xCF, 0xFA, 0xED, 0xFE}, {0xCE, 0xFA, 0xED, 0xFE}, {0xFE, 0xED, 0xFA, 0xCF}, {0xFE, 0xED, 0xFA, 0xCE},
}

func isMachO(data []byte) bool {
	for _, m := range machOMagics {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// describeMachO reads a thin Mach-O header.
func describeMachO(data []byte) string {
	if len(data) < 16 {
		return "Mach-O binary"
	}
	var order binary.ByteOrder = binary.LittleEndian
	if data[0] == 0xFE {
		order = binary.BigEndian
	}
	arch := ""
	switch order.Uint32(data[4:8]) {
	case 7:
		arch = " x86"
	case 0x01000007:
		arch = " x86-64"
	case 12:
		arch = " ARM"
	case 0x0100000c:
		arch = " ARM64"
	}
	kind := "binary"
	switch order.Uint32(data[12:16]) {
	case 1:
		kind = "object"
	case 2:
		kind = "executable"
	case 6:
		kind = "dynamic library"
	case 8:
		kind = "bundle"
	}
	return "Mach-O" + arch + " " + kind
}
