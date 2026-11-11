package contentscan

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The RPM package: a 96-byte lead, a signature header, the main header and the
// payload — a compressed cpio archive of the files the package installs.
//
// What an RPM runs is not in the payload. The scriptlets (%pre, %post, %preun,
// %postun, %pretrans, %posttrans, %verifyscript) and the triggers are strings
// in the main header, executed as root by rpm when the package is installed,
// upgraded or removed. The walker therefore reports them as files of their own,
// under RPM/scriptlets/ and RPM/triggers/, next to a summary of the header
// (RPM/header.txt) — entries it composes itself, marked synthetic — and then
// walks the payload.

const (
	rpmLeadSize = 96
	// maxRPMIndex and maxRPMStore bound the main header that is read into
	// memory. rpm itself accepts headers up to 256 MiB; a real one is kilobytes
	// to a few megabytes (it grows with the file list).
	maxRPMIndex = 1 << 18
	maxRPMStore = 32 << 20
	// maxRPMSkip bounds the signature header, which is skipped, not kept.
	maxRPMSkip = 64 << 20
	// maxRPMList bounds the entries rendered from one header array (requires,
	// provides, the file list shown when the payload could not be walked).
	maxRPMList = 20000
	// maxRPMFiles bounds the file table kept to resolve a stripped-cpio payload.
	// It is far above any real package and, like every header array, is bounded
	// by the header store as well.
	maxRPMFiles = 1 << 20
	// rpmFileGhost marks a file the package owns but does not ship.
	rpmFileGhost = 1 << 6
	// maxRPMSynthetic bounds one composed entry.
	maxRPMSynthetic = 1 << 20
	// maxRPMTriggers bounds the trigger scripts reported per trigger family.
	maxRPMTriggers = 64
)

// RPM header tag data types.
const (
	rpmTypeInt16       = 3
	rpmTypeInt32       = 4
	rpmTypeInt64       = 5
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

// RPM header tags the walker reads.
const (
	rpmTagName              = 1000
	rpmTagVersion           = 1001
	rpmTagRelease           = 1002
	rpmTagEpoch             = 1003
	rpmTagSummary           = 1004
	rpmTagBuildHost         = 1007
	rpmTagVendor            = 1011
	rpmTagLicense           = 1014
	rpmTagPackager          = 1015
	rpmTagURL               = 1020
	rpmTagArch              = 1022
	rpmTagPreIn             = 1023
	rpmTagPostIn            = 1024
	rpmTagPreUn             = 1025
	rpmTagPostUn            = 1026
	rpmTagOldFilenames      = 1027
	rpmTagFileSizes         = 1028
	rpmTagFileModes         = 1030
	rpmTagFileLinkTos       = 1036
	rpmTagFileFlags         = 1037
	rpmTagFileInodes        = 1096
	rpmTagSourceRPM         = 1044
	rpmTagProvideName       = 1047
	rpmTagRequireName       = 1049
	rpmTagTriggerScripts    = 1065
	rpmTagTriggerName       = 1066
	rpmTagTriggerIndex      = 1069
	rpmTagVerifyScript      = 1079
	rpmTagPreInProg         = 1085
	rpmTagPostInProg        = 1086
	rpmTagPreUnProg         = 1087
	rpmTagPostUnProg        = 1088
	rpmTagVerifyScriptProg  = 1091
	rpmTagTriggerScriptProg = 1092
	rpmTagDirIndexes        = 1116
	rpmTagBasenames         = 1117
	rpmTagDirNames          = 1118
	rpmTagPayloadFormat     = 1124
	rpmTagPayloadCompressor = 1125
	rpmTagPreTrans          = 1151
	rpmTagPostTrans         = 1152
	rpmTagPreTransProg      = 1153
	rpmTagPostTransProg     = 1154
	rpmTagPreUnTrans        = 1171
	rpmTagPostUnTrans       = 1172
	rpmTagPreUnTransProg    = 1173
	rpmTagPostUnTransProg   = 1174
	rpmTagLongFileSizes     = 5008
	rpmTagFileTrigScripts   = 5066
	rpmTagFileTrigProg      = 5067
	rpmTagFileTrigName      = 5069
	rpmTagFileTrigIndex     = 5070
	rpmTagTransTrigScripts  = 5076
	rpmTagTransTrigProg     = 5077
	rpmTagTransTrigName     = 5079
	rpmTagTransTrigIndex    = 5080
)

// rpmScriptlets lists the scriptlets in the order rpm runs them, with the tag
// of the interpreter each one is run by.
var rpmScriptlets = []struct {
	name string // the file name under RPM/scriptlets/, rpm's own name for the scriptlet
	body uint32
	prog uint32
}{
	{"pretrans", rpmTagPreTrans, rpmTagPreTransProg},       // %pretrans
	{"prein", rpmTagPreIn, rpmTagPreInProg},                // %pre
	{"postin", rpmTagPostIn, rpmTagPostInProg},             // %post
	{"preun", rpmTagPreUn, rpmTagPreUnProg},                // %preun
	{"postun", rpmTagPostUn, rpmTagPostUnProg},             // %postun
	{"posttrans", rpmTagPostTrans, rpmTagPostTransProg},    // %posttrans
	{"preuntrans", rpmTagPreUnTrans, rpmTagPreUnTransProg}, // %preuntrans
	{"postuntrans", rpmTagPostUnTrans, rpmTagPostUnTransProg},
	{"verifyscript", rpmTagVerifyScript, rpmTagVerifyScriptProg},
}

// rpmTriggerSets lists the three trigger families: scripts, interpreters, the
// names that fire them, and the index tying each name to its script.
var rpmTriggerSets = []struct {
	dir                         string
	scripts, prog, names, index uint32
}{
	{"triggers", rpmTagTriggerScripts, rpmTagTriggerScriptProg, rpmTagTriggerName, rpmTagTriggerIndex},
	{"filetriggers", rpmTagFileTrigScripts, rpmTagFileTrigProg, rpmTagFileTrigName, rpmTagFileTrigIndex},
	{"transfiletriggers", rpmTagTransTrigScripts, rpmTagTransTrigProg, rpmTagTransTrigName, rpmTagTransTrigIndex},
}

// rpmIndexEntry is one tag of a header.
type rpmIndexEntry struct {
	tag, typ, offset, count uint32
}

// rpmHeader is a parsed header: its tag index and its data store.
type rpmHeader struct {
	index []rpmIndexEntry
	store []byte
}

// readRPMHeaderIntro reads a header's 16-byte intro and returns the number of
// index entries and the size of the data store.
func readRPMHeaderIntro(r io.Reader) (il, dl uint32, err error) {
	var intro [16]byte
	if _, err := io.ReadFull(r, intro[:]); err != nil {
		return 0, 0, err
	}
	if intro[0] != 0x8e || intro[1] != 0xad || intro[2] != 0xe8 {
		return 0, 0, fmt.Errorf("contentscan: bad rpm header magic")
	}
	return binary.BigEndian.Uint32(intro[8:12]), binary.BigEndian.Uint32(intro[12:16]), nil
}

// find returns the index entry of a tag.
func (h *rpmHeader) find(tag uint32) (rpmIndexEntry, bool) {
	for _, e := range h.index {
		if e.tag == tag {
			return e, true
		}
	}
	return rpmIndexEntry{}, false
}

// cstring returns the NUL-terminated string at off, and the offset after it.
func (h *rpmHeader) cstring(off int) (string, int, bool) {
	if off < 0 || off >= len(h.store) {
		return "", off, false
	}
	end := bytes.IndexByte(h.store[off:], 0)
	if end < 0 {
		return string(h.store[off:]), len(h.store), true
	}
	return string(h.store[off : off+end]), off + end + 1, true
}

// strs returns a tag's strings: every element of a string array, or the single
// value of a string tag.
func (h *rpmHeader) strs(tag uint32) []string { return h.strsN(tag, maxRPMList) }

// strsN is strs with an explicit bound on the number of elements.
func (h *rpmHeader) strsN(tag uint32, max int) []string {
	e, ok := h.find(tag)
	if !ok {
		return nil
	}
	switch e.typ {
	case rpmTypeString, rpmTypeI18NString:
		if s, _, ok := h.cstring(int(e.offset)); ok {
			return []string{s}
		}
	case rpmTypeStringArray:
		var out []string
		off := int(e.offset)
		for i := uint32(0); i < e.count && len(out) < max; i++ {
			s, next, ok := h.cstring(off)
			if !ok {
				break
			}
			out = append(out, s)
			off = next
		}
		return out
	}
	return nil
}

// str returns a tag's first string.
func (h *rpmHeader) str(tag uint32) string {
	if v := h.strs(tag); len(v) > 0 {
		return v[0]
	}
	return ""
}

// ints returns a tag's integers (16-, 32- or 64-bit), widened.
func (h *rpmHeader) ints(tag uint32) []uint64 { return h.intsN(tag, maxRPMList) }

// intsN is ints with an explicit bound on the number of elements.
func (h *rpmHeader) intsN(tag uint32, max int) []uint64 {
	e, ok := h.find(tag)
	if !ok {
		return nil
	}
	width := 0
	switch e.typ {
	case rpmTypeInt16:
		width = 2
	case rpmTypeInt32:
		width = 4
	case rpmTypeInt64:
		width = 8
	default:
		return nil
	}
	var out []uint64
	off := int(e.offset)
	for i := uint32(0); i < e.count && len(out) < max; i++ {
		if off < 0 || off+width > len(h.store) {
			break
		}
		switch width {
		case 2:
			out = append(out, uint64(binary.BigEndian.Uint16(h.store[off:])))
		case 4:
			out = append(out, uint64(binary.BigEndian.Uint32(h.store[off:])))
		default:
			out = append(out, binary.BigEndian.Uint64(h.store[off:]))
		}
		off += width
	}
	return out
}

// walkRPM walks an RPM package whose members are reported under prefix.
func (w *walker) walkRPM(br *bufio.Reader, prefix string, depth int) error {
	fail := func() error {
		if depth == 0 && !w.done() {
			return errUnrecognizedArchive
		}
		return nil
	}
	if w.done() {
		return nil
	}
	var lead [rpmLeadSize]byte
	if _, err := io.ReadFull(br, lead[:]); err != nil || !bytes.HasPrefix(lead[:], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return fail()
	}
	// The signature header is skipped: it authenticates the package, which is
	// not this walker's concern. It is padded to an eight-byte boundary.
	il, dl, err := readRPMHeaderIntro(br)
	if err != nil {
		return fail()
	}
	skip := int64(il)*16 + int64(dl)
	skip += (8 - skip%8) % 8
	if skip > maxRPMSkip {
		return fail()
	}
	if _, err := io.CopyN(io.Discard, br, skip); err != nil {
		return fail()
	}

	il, dl, err = readRPMHeaderIntro(br)
	if err != nil || il > maxRPMIndex || dl > maxRPMStore {
		return fail()
	}
	raw := make([]byte, int(il)*16)
	if _, err := io.ReadFull(br, raw); err != nil {
		return fail()
	}
	h := &rpmHeader{index: make([]rpmIndexEntry, il), store: make([]byte, dl)}
	for i := range h.index {
		b := raw[i*16:]
		h.index[i] = rpmIndexEntry{
			tag:    binary.BigEndian.Uint32(b[0:4]),
			typ:    binary.BigEndian.Uint32(b[4:8]),
			offset: binary.BigEndian.Uint32(b[8:12]),
			count:  binary.BigEndian.Uint32(b[12:16]),
		}
	}
	if _, err := io.ReadFull(br, h.store); err != nil {
		return fail()
	}

	// Composed entries are not charged against the member count: there is a
	// bounded handful of them, and they are what remains of the inventory when
	// the payload could not be walked.
	synth := func(name, content string, mode uint32) {
		if w.stopped || w.ctx.Err() != nil {
			return
		}
		data := []byte(content)
		truncated := false
		if int64(len(data)) > maxRPMSynthetic {
			data, truncated = data[:maxRPMSynthetic], true
		}
		if w.b.maxFileBytes > 0 && int64(len(data)) > w.b.maxFileBytes {
			data, truncated = data[:w.b.maxFileBytes], true
		}
		w.emit(walkedFile{name: prefix + name, data: data, size: int64(len(content)), truncated: truncated, mode: mode, synthetic: true})
	}

	synth("RPM/header.txt", h.summary(), 0o444)
	for _, sc := range rpmScriptlets {
		body, prog := h.str(sc.body), h.strs(sc.prog)
		if body == "" && len(prog) == 0 {
			continue
		}
		synth("RPM/scriptlets/"+sc.name, rpmScript(prog, body, ""), 0o755)
	}
	for _, ts := range rpmTriggerSets {
		scripts := h.strs(ts.scripts)
		if len(scripts) == 0 {
			continue
		}
		progs, names, index := h.strs(ts.prog), h.strs(ts.names), h.ints(ts.index)
		for i, body := range scripts {
			if i == maxRPMTriggers {
				w.stats.addReason(stopFiles)
				break
			}
			var on []string
			for j, idx := range index {
				if int(idx) == i && j < len(names) {
					on = append(on, names[j])
				}
			}
			var prog []string
			if i < len(progs) {
				prog = []string{progs[i]}
			}
			note := ""
			if len(on) > 0 {
				note = "fired by: " + oneLine(strings.Join(on, ", "))
			}
			synth(fmt.Sprintf("RPM/%s/%d", ts.dir, i), rpmScript(prog, body, note), 0o755)
		}
	}

	// The payload: a cpio archive, compressed as the header says (the stream's
	// own signature decides which decoder is used, not the header's claim).
	before := w.stats.files
	head, _ := br.Peek(peekBytes)
	walked := false
	switch kind := sniffContainer(head); {
	case kind.compression():
		if dr, closer, derr := w.decompressor(kind, br); derr == nil {
			inner := bufio.NewReaderSize(w.guard(dr), 4*peekBytes)
			if ih, _ := inner.Peek(peekBytes); sniffContainer(ih) == containerCpio {
				_ = w.walkCpio(inner, prefix, depth+1, h.payloadTable(ih))
				walked = true
			}
			closer()
		}
	case kind == containerCpio:
		_ = w.walkCpio(w.guard(br), prefix, depth+1, h.payloadTable(head))
		walked = true
	}
	if !walked && len(head) > 0 && !w.done() {
		w.stats.addReason(stopNestedFormat)
	}
	if !walked || w.inventoryIncomplete() || w.stats.files == before {
		// The payload was not seen whole. The header still names every file the
		// package installs, so that list stands in for the missing inventory.
		if list := h.fileList(); list != "" {
			synth("RPM/files.txt", list, 0o444)
		}
	}
	return nil
}

// summary renders the header's identifying fields.
func (h *rpmHeader) summary() string {
	var b strings.Builder
	field := func(label string, tag uint32) {
		if v := h.str(tag); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", label, oneLine(v))
		}
	}
	field("Name", rpmTagName)
	if e := h.ints(rpmTagEpoch); len(e) > 0 {
		fmt.Fprintf(&b, "Epoch: %d\n", e[0])
	}
	field("Version", rpmTagVersion)
	field("Release", rpmTagRelease)
	field("Arch", rpmTagArch)
	field("Summary", rpmTagSummary)
	field("License", rpmTagLicense)
	field("Vendor", rpmTagVendor)
	field("Packager", rpmTagPackager)
	field("URL", rpmTagURL)
	field("BuildHost", rpmTagBuildHost)
	field("SourceRPM", rpmTagSourceRPM)
	field("PayloadFormat", rpmTagPayloadFormat)
	field("PayloadCompressor", rpmTagPayloadCompressor)
	list := func(label string, tag uint32) {
		vals := h.strs(tag)
		if len(vals) == 0 {
			return
		}
		seen := make(map[string]bool, len(vals))
		uniq := vals[:0:0]
		for _, v := range vals {
			if v = oneLine(v); v != "" && !seen[v] {
				seen[v] = true
				uniq = append(uniq, v)
			}
		}
		sort.Strings(uniq)
		fmt.Fprintf(&b, "%s (%d):\n", label, len(uniq))
		for _, v := range uniq {
			fmt.Fprintf(&b, "  %s\n", v)
		}
	}
	list("Requires", rpmTagRequireName)
	list("Provides", rpmTagProvideName)
	return b.String()
}

// rpmFile is one entry of the header's file table.
type rpmFile struct {
	path  string // absolute install path
	mode  uint64 // st_mode
	size  uint64
	flags uint64
	inode uint64
	known struct{ mode, size bool }
}

// files returns the header's file table, at most max entries: the install
// path of every file from the directory/basename tables (or the legacy
// full-path table), with its mode, size, flags and inode number.
func (h *rpmHeader) files(max int) []rpmFile {
	var paths []string
	if base := h.strsN(rpmTagBasenames, max); len(base) > 0 {
		dirs, idx := h.strsN(rpmTagDirNames, max), h.intsN(rpmTagDirIndexes, max)
		paths = make([]string, len(base))
		for i, name := range base {
			dir := ""
			if i < len(idx) && idx[i] < uint64(len(dirs)) {
				dir = dirs[idx[i]]
			}
			paths[i] = dir + name
		}
	} else {
		paths = h.strsN(rpmTagOldFilenames, max)
	}
	if len(paths) == 0 {
		return nil
	}
	sizes := h.intsN(rpmTagLongFileSizes, max)
	if len(sizes) == 0 {
		sizes = h.intsN(rpmTagFileSizes, max)
	}
	modes := h.intsN(rpmTagFileModes, max)
	flags := h.intsN(rpmTagFileFlags, max)
	inodes := h.intsN(rpmTagFileInodes, max)
	out := make([]rpmFile, len(paths))
	for i, p := range paths {
		f := rpmFile{path: p}
		if i < len(modes) {
			f.mode, f.known.mode = modes[i], true
		}
		if i < len(sizes) {
			f.size, f.known.size = sizes[i], true
		}
		if i < len(flags) {
			f.flags = flags[i]
		}
		if i < len(inodes) {
			f.inode = inodes[i]
		}
		out[i] = f
	}
	return out
}

// fileList renders the files the header says the package installs, one per
// line with mode and size.
func (h *rpmHeader) fileList() string {
	files := h.files(maxRPMList)
	if len(files) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %d file(s) listed in the package header: mode size path\n", len(files))
	for _, f := range files {
		mode, size := "------", "-"
		if f.known.mode {
			mode = fmt.Sprintf("%06o", f.mode)
		}
		if f.known.size {
			size = fmt.Sprintf("%d", f.size)
		}
		fmt.Fprintf(&b, "%s %s %s\n", mode, size, oneLine(f.path))
	}
	return b.String()
}

// payloadTable returns the table a stripped-cpio payload indexes, or nil when
// the payload (whose first bytes are head) is a self-describing cpio.
//
// A stripped member carries data only if it is a regular file or a symbolic
// link, and — for a set of hard links, which rpm records as regular files
// sharing an inode number — only if it is the last of its set. That is exactly
// rpm's own reading of the format (rpmfiArchiveReadHeader), and it has to be:
// the member headers do not say how long the data is.
func (h *rpmHeader) payloadTable(head []byte) []cpioIndexed {
	if !bytes.HasPrefix(head, []byte("07070X")) {
		return nil
	}
	files := h.files(maxRPMFiles)
	lastOfInode := make(map[uint64]int)
	linked := func(f rpmFile) bool {
		return f.mode&cpioTypeMask == cpioTypeReg && f.flags&rpmFileGhost == 0 && f.inode > 0
	}
	for i, f := range files {
		if linked(f) {
			lastOfInode[f.inode] = i
		}
	}
	table := make([]cpioIndexed, len(files))
	for i, f := range files {
		ent := cpioIndexed{path: "." + f.path, mode: int64(f.mode)}
		if !strings.HasPrefix(f.path, "/") {
			ent.path = f.path
		}
		switch f.mode & cpioTypeMask {
		case cpioTypeReg:
			if !linked(f) || lastOfInode[f.inode] == i {
				ent.size = int64(f.size)
			}
		case cpioTypeLink:
			ent.size = int64(f.size)
		}
		if ent.size < 0 {
			ent.size = 0
		}
		table[i] = ent
	}
	return table
}

// rpmScript renders one scriptlet as a script file: an interpreter line (the
// program rpm runs it with, /bin/sh unless the package says otherwise), an
// optional note (what fires a trigger), then the body.
func rpmScript(prog []string, body, note string) string {
	interp := "/bin/sh"
	if len(prog) > 0 && strings.TrimSpace(prog[0]) != "" {
		interp = oneLine(strings.Join(prog, " "))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#!%s\n", interp)
	if note != "" {
		fmt.Fprintf(&b, "# %s\n", note)
	}
	b.WriteString(body)
	if body != "" && !strings.HasSuffix(body, "\n") {
		b.WriteByte('\n')
	}
	return b.String()
}

// oneLine folds a header string onto one line.
func oneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}
