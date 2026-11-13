package update

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// cargoUpdater rewrites Cargo.lock, formats 1 to 4. The [[package]] of a
// changed crate from a registry moves to the new version with the new
// .crate's SHA-256 as its checksum — inline from format 2 on, in [metadata]
// under "checksum <name> <version> (<source>)" in format 1 — and the
// dependency lists that name the old version ("name version", or "name
// version (source)") name the new one. A crate that is the only one of its
// name is listed by name alone and stays so.
//
// The file is rewritten line by line, so it is read as Cargo writes it: one
// key per line, strings without escapes, dependency lists one entry per
// line. A line in any other shape inside the tables that matter is an error,
// as is an outcome Cargo would write differently from the edit — two crates
// of the name at the new version, a new version that sorts elsewhere among
// the crates of its name.
type cargoUpdater struct{}

func (cargoUpdater) Key() string { return "cargo/Cargo.lock" }

// cargoPkg is a [[package]] table (or the [root] table of the oldest files,
// which only lists dependencies).
type cargoPkg struct {
	keys                            map[string]bool
	name, version, source, checksum string
	replace                         string
	versionAt, checksumAt           span // the strings' contents, quotation marks left out
	change                          *Change
}

// cargoRef is an entry of a dependency list: where its text is.
type cargoRef struct{ at span }

func (r cargoRef) text(data []byte) string { return string(data[r.at.start:r.at.end]) }

// cargoMeta is a key of [metadata].
type cargoMeta struct {
	key, value   string
	keyAt, valAt span
}

// cargoDoc is what the rewrite reads of a Cargo.lock.
type cargoDoc struct {
	pkgs  []*cargoPkg
	lists [][]cargoRef // every dependency list
	meta  []cargoMeta
	// version is the top-level format version ("3", "4"), when the file
	// has one; patchUnused the crates [[patch.unused]] names.
	version     string
	patchUnused map[string]bool
}

// cargoChanged indexes the [[package]] each change moves by the crate's name
// and old version: a lookup costs the same whatever the number of crates of a
// name.
type cargoChanged map[[2]string]*cargoPkg

func (cargoUpdater) Apply(lockPath string, files map[string][]byte, changes []Change) (map[string][]byte, error) {
	data, ok := files[lockPath]
	if !ok {
		return nil, fmt.Errorf("%s is not among the files", lockPath)
	}
	if err := checkChanges("cargo", changes, func(s string) bool { return tokenOf(s, "_-") }, semverToken); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, c := range changes {
		names[c.Name] = true
	}
	doc, err := parseCargoLock(data, names)
	if err != nil {
		return nil, err
	}
	// Cargo reads a file of format 2 or later (inline checksums, or a
	// version key) that still has [metadata] checksums as a bad merge and
	// discards every checksum: none would pin the new version's bytes.
	inline := doc.version != ""
	for _, p := range doc.pkgs {
		inline = inline || p.keys["checksum"]
	}
	for _, m := range doc.meta {
		if strings.HasPrefix(m.key, "checksum ") && inline {
			return nil, errors.New("Cargo.lock has [metadata] checksums besides inline ones: Cargo discards every checksum of such a file")
		}
	}
	byName := map[string][]*cargoPkg{}
	for _, p := range doc.pkgs {
		byName[p.name] = append(byName[p.name], p)
	}
	changed := cargoChanged{}
	var edits []edit
	for i := range changes {
		c := &changes[i]
		if doc.patchUnused[c.Name] {
			// A patch Cargo has not used yet, which the new version may
			// match: then Cargo builds the patch, not the vetted crate.
			return nil, fmt.Errorf("%s: the workspace patches it ([[patch.unused]] in Cargo.lock)", c.Name)
		}
		var target *cargoPkg
		for _, p := range byName[c.Name] {
			switch {
			case p.version == c.From && (strings.HasPrefix(p.source, "registry+") || strings.HasPrefix(p.source, "sparse+")):
				if target != nil {
					return nil, fmt.Errorf("%s %s comes from two registries", c.Name, c.From)
				}
				target = p
			case p.version == c.From:
				return nil, fmt.Errorf("%s %s is also in the lock file from another source", c.Name, c.From)
			case p.version == c.To:
				return nil, fmt.Errorf("%s %s is already in the lock file", c.Name, c.To)
			}
		}
		if target == nil {
			return nil, fmt.Errorf("%s %s from a registry is not in the lock file", c.Name, c.From)
		}
		target.change = c
		changed[[2]string{c.Name, c.From}] = target
		edits = append(edits, edit{target.versionAt.start, target.versionAt.end, c.To})
		if target.keys["checksum"] {
			sum, err := cargoChecksum(c, target.checksum)
			if err != nil {
				return nil, err
			}
			edits = append(edits, edit{target.checksumAt.start, target.checksumAt.end, sum})
		}
	}
	if err := cargoCheckOrder(doc, changed); err != nil {
		return nil, err
	}
	metaEdits, err := cargoMetadata(doc, changed)
	if err != nil {
		return nil, err
	}
	refEdits, err := cargoRefs(data, doc, changed)
	if err != nil {
		return nil, err
	}
	out, err := splice(data, append(append(edits, metaEdits...), refEdits...))
	if err != nil {
		return nil, err
	}
	return map[string][]byte{lockPath: out}, nil
}

// cargoChecksum returns the new checksum of a crate whose old one is old,
// which must be one: "<none>" or anything else is a shape not rewritten.
func cargoChecksum(c *Change, old string) (string, error) {
	if _, ok := hexDigest(old, 32); !ok {
		return "", fmt.Errorf("%s %s: the lock file's checksum is not a SHA-256", c.Name, c.From)
	}
	a, err := onlyArtifact(*c, "package")
	if err != nil {
		return "", err
	}
	return sha256Of(*c, a)
}

// changeOf returns the changed crate a name and version name, if any.
func changeOf(changed cargoChanged, name, version string) *cargoPkg {
	return changed[[2]string{name, version}]
}

// cargoCheckOrder holds the crates of a changed name to the order Cargo
// writes them in (by version), so that the rewritten file is the one Cargo
// would write.
func cargoCheckOrder(doc *cargoDoc, changed cargoChanged) error {
	newVersion := func(p *cargoPkg) string {
		if p.change != nil {
			return p.change.To
		}
		return p.version
	}
	for i := 1; i < len(doc.pkgs); i++ {
		a, b := doc.pkgs[i-1], doc.pkgs[i]
		if a.name != b.name || (a.change == nil && b.change == nil) {
			continue
		}
		before, ok1 := semverCompare(a.version, b.version)
		after, ok2 := semverCompare(newVersion(a), newVersion(b))
		if !ok1 || !ok2 {
			return fmt.Errorf("%s: versions the updater cannot order", a.name)
		}
		if before != after {
			moved := a
			if b.change != nil {
				moved = b
			}
			return fmt.Errorf("%s %s sorts elsewhere among the crates of its name", moved.name, moved.change.To)
		}
	}
	for _, p := range doc.pkgs {
		if p.replace == "" {
			continue
		}
		f := strings.SplitN(p.replace, " ", 3)
		if len(f) >= 2 && changeOf(changed, f[0], f[1]) != nil {
			return fmt.Errorf("%s %s is the replacement of another crate", f[0], f[1])
		}
	}
	return nil
}

// cargoMetadata moves the [metadata] checksums of format 1 to the new
// versions, keeping the table's order.
func cargoMetadata(doc *cargoDoc, changed cargoChanged) ([]edit, error) {
	var edits []edit
	for i, m := range doc.meta {
		rest, ok := strings.CutPrefix(m.key, "checksum ")
		if !ok {
			continue
		}
		f := strings.SplitN(rest, " ", 3)
		if len(f) != 3 {
			continue
		}
		p := changeOf(changed, f[0], f[1])
		if p == nil || f[2] != "("+p.source+")" {
			continue
		}
		key := "checksum " + f[0] + " " + p.change.To + " " + f[2]
		if (i > 0 && doc.meta[i-1].key < m.key && doc.meta[i-1].key >= key) ||
			(i+1 < len(doc.meta) && m.key < doc.meta[i+1].key && key >= doc.meta[i+1].key) {
			return nil, fmt.Errorf("%s %s: its checksum would sort elsewhere in [metadata]", f[0], p.change.To)
		}
		sum, err := cargoChecksum(p.change, m.value)
		if err != nil {
			return nil, err
		}
		edits = append(edits, edit{m.keyAt.start, m.keyAt.end, key}, edit{m.valAt.start, m.valAt.end, sum})
	}
	return edits, nil
}

// cargoRefs moves the dependency-list entries that name a changed crate's old
// version. Cargo lists a crate by name alone when it is the only one of its
// name, by "name version" when there are several, and adds "(source)" when
// even that is ambiguous, and in format 1 always; the source must be the
// changed crate's.
func cargoRefs(data []byte, doc *cargoDoc, changed cargoChanged) ([]edit, error) {
	var edits []edit
	for _, list := range doc.lists {
		texts := make([]string, len(list))
		moved := make([]string, len(list))
		touched := false
		for i, r := range list {
			texts[i] = r.text(data)
			moved[i] = texts[i]
			f := strings.SplitN(texts[i], " ", 3)
			if len(f) < 2 {
				continue
			}
			p := changeOf(changed, f[0], f[1])
			if p == nil {
				continue
			}
			text := f[0] + " " + p.change.To
			if len(f) == 3 {
				if f[2] != "("+p.source+")" {
					return nil, fmt.Errorf("%s %s: a dependency names it from another source", f[0], f[1])
				}
				text += " " + f[2]
			}
			moved[i] = text
			touched = true
			edits = append(edits, edit{r.at.start, r.at.end, text})
		}
		if !touched {
			continue
		}
		// Cargo sorts a list by name, then by the version as text.
		for i := 1; i < len(list); i++ {
			if (texts[i-1] < texts[i]) != (moved[i-1] < moved[i]) {
				return nil, fmt.Errorf("%s: a dependency list would need another order", moved[i])
			}
		}
	}
	return edits, nil
}

// --- reading ------------------------------------------------------------------

// tomlCursor reads one line of a Cargo.lock.
type tomlCursor struct {
	data     []byte
	pos, end int
	line     int
}

func (t *tomlCursor) errorf(format string, args ...any) error {
	return fmt.Errorf("Cargo.lock line %d: %s", t.line, fmt.Sprintf(format, args...))
}

func (t *tomlCursor) blank() {
	for t.pos < t.end && (t.data[t.pos] == ' ' || t.data[t.pos] == '\t') {
		t.pos++
	}
}

func (t *tomlCursor) peek() byte {
	if t.pos < t.end {
		return t.data[t.pos]
	}
	return 0
}

// done reports whether nothing but blanks and a comment is left.
func (t *tomlCursor) done() bool {
	t.blank()
	return t.pos == t.end || t.data[t.pos] == '#'
}

// str reads a basic string without escapes — all Cargo writes.
func (t *tomlCursor) str() (string, span, error) {
	if t.peek() != '"' {
		return "", span{}, t.errorf("a string was expected")
	}
	start := t.pos + 1
	for i := start; i < t.end; i++ {
		switch c := t.data[i]; {
		case c == '"':
			t.pos = i + 1
			return string(t.data[start:i]), span{start, i}, nil
		case c == '\\':
			return "", span{}, t.errorf("an escape in a string, which the updater does not rewrite")
		case c < 0x20 && c != '\t', c == 0x7f:
			return "", span{}, t.errorf("a control character in a string")
		}
	}
	return "", span{}, t.errorf("an unterminated string")
}

// word reads a bare key, an integer or a boolean.
func (t *tomlCursor) word() string {
	start := t.pos
	for t.pos < t.end {
		c := t.data[t.pos]
		if !isAlnum(c) && c != '_' && c != '-' && c != '+' {
			break
		}
		t.pos++
	}
	return string(t.data[start:t.pos])
}

// list reads the entries of a dependency list from the cursor on, up to its
// closing bracket or the end of the line, appending them to refs unless it is
// nil; closed says whether the list closed.
func (t *tomlCursor) list(refs *[]cargoRef) (closed bool, err error) {
	for {
		if t.done() {
			return false, nil
		}
		if t.peek() == ']' {
			t.pos++
			return true, nil
		}
		_, at, err := t.str()
		if err != nil {
			return false, err
		}
		if refs != nil {
			*refs = append(*refs, cargoRef{at: at})
		}
		t.blank()
		switch t.peek() {
		case ',':
			t.pos++
		case ']':
			t.pos++
			return true, nil
		default:
			if !t.done() {
				return false, t.errorf("a comma was expected")
			}
			return false, nil
		}
	}
}

// maxCargoLock is the largest Cargo.lock read: internal/lockfiles reads no
// larger TOML file either.
const maxCargoLock = 16 << 20

// parseCargoLock reads a Cargo.lock as Cargo writes it. Of the dependency
// lists it keeps those that name one of names, the changed crates: the
// others are not rewritten, and a hostile file of millions of entries costs
// no memory for them.
func parseCargoLock(data []byte, names map[string]bool) (*cargoDoc, error) {
	if len(data) > maxCargoLock {
		return nil, fmt.Errorf("Cargo.lock: larger than %d bytes", maxCargoLock)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("Cargo.lock: not valid UTF-8")
	}
	if bytes.Contains(data, []byte(`"""`)) || bytes.Contains(data, []byte("'''")) {
		return nil, errors.New("Cargo.lock: a multi-line string, which Cargo does not write")
	}
	const (
		inTop = iota
		inPackage
		inMetadata
		inPatchUnused
		inOther
	)
	doc := &cargoDoc{patchUnused: map[string]bool{}}
	table := inTop
	var pkg *cargoPkg
	// The list being read; into is where its entries go — the scratch list
	// for a package's dependency list, nowhere for any other list.
	var list []cargoRef
	var into *[]cargoRef
	listOpen := false
	closeList := func() {
		for _, r := range list {
			name, _, _ := strings.Cut(r.text(data), " ")
			if names[name] {
				doc.lists = append(doc.lists, list)
				list = nil
				break
			}
		}
		list = list[:0]
		listOpen = false
	}
	lineNo := 0
	for off := 0; ; {
		l, ok := nextLine(data, off)
		if !ok {
			break
		}
		off = l.next
		lineNo++
		t := &tomlCursor{data: data, pos: l.start, end: l.end, line: lineNo}
		if listOpen {
			closed, err := t.list(into)
			if err != nil {
				return nil, err
			}
			if closed {
				if !t.done() {
					return nil, t.errorf("text after a list")
				}
				closeList()
			}
			continue
		}
		if t.done() {
			continue
		}
		if t.peek() == '[' {
			name, array, err := cargoHeader(t)
			if err != nil {
				return nil, err
			}
			pkg = nil
			switch {
			case array && name == "package", !array && name == "root":
				pkg = &cargoPkg{keys: map[string]bool{}}
				if name == "package" {
					doc.pkgs = append(doc.pkgs, pkg)
				}
				table = inPackage
			case !array && name == "metadata":
				table = inMetadata
			case array && name == "patch.unused":
				table = inPatchUnused
			default:
				table = inOther
			}
			continue
		}
		var key string
		var keyAt span
		if t.peek() == '"' {
			var err error
			if key, keyAt, err = t.str(); err != nil {
				return nil, err
			}
		} else if key = t.word(); key == "" {
			return nil, t.errorf("a key was expected")
		}
		t.blank()
		if t.peek() != '=' {
			return nil, t.errorf("a key in a form the updater does not read")
		}
		t.pos++
		t.blank()
		const (
			isString = iota
			isList
			isWord
		)
		var kind int
		var value string
		var valueAt span
		switch c := t.peek(); {
		case c == '"':
			var err error
			if value, valueAt, err = t.str(); err != nil {
				return nil, err
			}
			kind = isString
		case c == '[':
			t.pos++
			kind = isList
			into = nil
			if table == inPackage && key == "dependencies" {
				into = &list
			}
			closed, err := t.list(into)
			if err != nil {
				return nil, err
			}
			if closed {
				closeList()
			} else {
				listOpen = true
			}
		case isAlnum(c) || c == '-' || c == '+':
			value = t.word()
			kind = isWord
		default:
			return nil, t.errorf("a value in a form the updater does not read")
		}
		if !listOpen && !t.done() {
			return nil, t.errorf("text after a value")
		}
		switch table {
		case inPackage:
			if pkg.keys[key] {
				return nil, t.errorf("a repeated key")
			}
			pkg.keys[key] = true
			switch key {
			case "name", "version", "source", "checksum", "replace":
				if kind != isString {
					return nil, t.errorf("%s is not a string", key)
				}
				switch key {
				case "name":
					pkg.name = value
				case "version":
					pkg.version, pkg.versionAt = value, valueAt
				case "source":
					pkg.source = value
				case "checksum":
					pkg.checksum, pkg.checksumAt = value, valueAt
				case "replace":
					pkg.replace = value
				}
			case "dependencies":
				if kind != isList {
					return nil, t.errorf("dependencies is not a list")
				}
			default:
				return nil, t.errorf("a key the updater does not know in a [[package]]")
			}
		case inMetadata:
			if kind != isString {
				return nil, t.errorf("a [metadata] value that is not a string")
			}
			doc.meta = append(doc.meta, cargoMeta{key: key, value: value, keyAt: keyAt, valAt: valueAt})
		case inPatchUnused:
			if key == "name" && kind == isString {
				doc.patchUnused[value] = true
			}
		case inTop:
			if key == "version" {
				if kind != isWord {
					return nil, t.errorf("the format version is not a number")
				}
				doc.version = value
			}
		}
	}
	if listOpen {
		return nil, errors.New("Cargo.lock: a list is not closed")
	}
	for _, p := range doc.pkgs {
		if !p.keys["name"] || !p.keys["version"] {
			return nil, errors.New("Cargo.lock: a [[package]] without a name or a version")
		}
	}
	return doc, nil
}

// cargoHeader reads a table header: "[name]" or "[[name]]".
func cargoHeader(t *tomlCursor) (name string, array bool, err error) {
	t.pos++
	if t.peek() == '[' {
		array = true
		t.pos++
	}
	t.blank()
	start := t.pos
	for t.pos < t.end && t.data[t.pos] != ']' {
		if c := t.data[t.pos]; c == '"' || c == '\'' {
			return "", false, t.errorf("a quoted table name, which the updater does not read")
		}
		t.pos++
	}
	name = strings.TrimRight(string(t.data[start:t.pos]), " \t")
	closing := "]"
	if array {
		closing = "]]"
	}
	if !bytes.HasPrefix(t.data[t.pos:t.end], []byte(closing)) {
		return "", false, t.errorf("a malformed table header")
	}
	t.pos += len(closing)
	if !t.done() {
		return "", false, t.errorf("text after a table header")
	}
	return name, array, nil
}
