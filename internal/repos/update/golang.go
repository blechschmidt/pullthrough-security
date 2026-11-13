package update

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// goUpdater rewrites a module's go.mod and go.sum together; the lock path may
// name either. In go.mod the requirement of a changed module moves to the new
// version, wherever it is (a single require directive or a require block)
// and with its comments ("// indirect"). In go.sum the module hash of the old
// version's zip goes and those of the new version's zip and go.mod come in,
// where the go command sorts them; the old version's go.mod hash stays, for
// other modules' go.mod files may still name that version in the module
// graph the go command loads. A zip hash is only written where go.sum had one
// for the old version: a module whose packages the build never loaded has
// none.
//
// A module that a replace directive names, on either side, is not rewritten:
// what is fetched for it is decided there.
type goUpdater struct{}

func (goUpdater) Key() string { return "go/go.mod" }

func (goUpdater) Apply(lockPath string, files map[string][]byte, changes []Change) (map[string][]byte, error) {
	base := path.Base(lockPath)
	if base != "go.mod" && base != "go.sum" {
		return nil, fmt.Errorf("%s is not a go.mod or go.sum", lockPath)
	}
	dir := lockPath[:len(lockPath)-len(base)]
	modPath, sumPath := dir+"go.mod", dir+"go.sum"
	mod, ok := files[modPath]
	if !ok {
		return nil, fmt.Errorf("%s is not among the files", modPath)
	}
	sum, ok := files[sumPath]
	if !ok {
		return nil, fmt.Errorf("%s is not among the files", sumPath)
	}
	if err := checkChanges("go", changes, goModulePath, goModuleVersion); err != nil {
		return nil, err
	}
	for _, c := range changes {
		if !goMajorFits(c.Name, c.From) || !goMajorFits(c.Name, c.To) {
			return nil, fmt.Errorf("%s: %s or %s is not a version of that module path", c.Name, c.From, c.To)
		}
	}
	modOut, err := rewriteGoMod(mod, changes)
	if err != nil {
		return nil, err
	}
	sumOut, err := rewriteGoSum(sum, changes)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{modPath: modOut, sumPath: sumOut}, nil
}

// goModulePath accepts what can be a module path.
func goModulePath(s string) bool {
	return tokenOf(s, "._~/+-") && s[0] != '.' && s[0] != '/' && !strings.Contains(s, "//")
}

// goModuleVersion accepts a canonical module version: "v" and a semantic
// version with all three numbers, a pseudo-version, or a major version from
// before modules ("+incompatible").
func goModuleVersion(s string) bool {
	v, ok := parseSemver(strings.TrimPrefix(s, "v"))
	return ok && s[0] == 'v' && !v.short && (v.build == "" || v.build == "incompatible")
}

// goMajorFits reports whether a version can be one of the module path's: the
// major version a path ends in ("/v2", gopkg.in's ".v2") is the version's,
// and a path without one has versions v0 and v1, and those of a v2 or later
// from before modules ("+incompatible").
func goMajorFits(modPath, version string) bool {
	v, ok := parseSemver(strings.TrimPrefix(version, "v"))
	if !ok {
		return false
	}
	major := "v" + v.major
	if rest, ok := strings.CutPrefix(modPath, "gopkg.in/"); ok {
		i := strings.LastIndex(rest, ".v")
		if i < 0 {
			return false
		}
		suffix := rest[i+1:]
		if strings.HasSuffix(suffix, "-unstable") {
			return true
		}
		return major == suffix || (suffix == "v1" && strings.HasPrefix(version, "v0.0.0-"))
	}
	if i := strings.LastIndex(modPath, "/v"); i > 0 {
		if n := modPath[i+2:]; n != "" && n[0] != '0' && n != "1" && digitsOnly(n) {
			return major == "v"+n && v.build == ""
		}
	}
	return v.major == "0" || v.major == "1" || v.build == "incompatible"
}

func digitsOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// rewriteGoMod moves the require directives of the changed modules.
func rewriteGoMod(data []byte, changes []Change) ([]byte, error) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("go.mod contains a NUL byte")
	}
	byName := map[string]*Change{}
	for i := range changes {
		if byName[changes[i].Name] != nil {
			return nil, fmt.Errorf("two changes of %s", changes[i].Name)
		}
		byName[changes[i].Name] = &changes[i]
	}
	required := map[string]int{}
	var edits []edit
	block := ""
	lineNo := 0
	for off := 0; ; {
		l, ok := nextLine(data, off)
		if !ok {
			break
		}
		off = l.next
		lineNo++
		toks, err := goModTokens(string(data[l.start:l.end]))
		if err != nil {
			return nil, fmt.Errorf("go.mod line %d: %w", lineNo, err)
		}
		if len(toks) == 0 {
			continue
		}
		verb, args := block, toks
		if block == "" {
			verb, args = toks[0].text, toks[1:]
			if len(args) == 1 && args[0].text == "(" {
				block = verb
				continue
			}
		} else if toks[0].text == ")" {
			block = ""
			continue
		}
		switch verb {
		case "require":
			if len(args) == 0 || byName[args[0].text] == nil {
				continue
			}
			c := byName[args[0].text]
			required[c.Name]++
			if len(args) != 2 || args[1].quoted || args[0].quoted {
				return nil, fmt.Errorf("go.mod line %d: a requirement of %s in a form the updater does not rewrite", lineNo, c.Name)
			}
			if args[1].text != c.From {
				return nil, fmt.Errorf("go.mod requires %s %s, not %s", c.Name, args[1].text, c.From)
			}
			edits = append(edits, edit{l.start + args[1].start, l.start + args[1].end, c.To})
		case "replace":
			for _, a := range args {
				if byName[a.text] != nil {
					return nil, fmt.Errorf("go.mod line %d: a replace directive names %s", lineNo, a.text)
				}
			}
		case "exclude":
			if len(args) == 2 && byName[args[0].text] != nil && args[1].text == byName[args[0].text].To {
				return nil, fmt.Errorf("go.mod excludes %s %s", args[0].text, args[1].text)
			}
		}
	}
	if block != "" {
		return nil, fmt.Errorf("go.mod: a %s block is not closed", block)
	}
	for _, c := range changes {
		switch required[c.Name] {
		case 1:
		case 0:
			return nil, fmt.Errorf("go.mod does not require %s", c.Name)
		default:
			return nil, fmt.Errorf("go.mod requires %s more than once", c.Name)
		}
	}
	return splice(data, edits)
}

// goToken is a token of a go.mod line, where it is in the line.
type goToken struct {
	text       string
	start, end int
	quoted     bool
}

// goModTokens splits a go.mod line as internal/lockfiles does: words, Go
// string literals, "(", ")" and "=>", with "//" comments dropped.
func goModTokens(line string) ([]goToken, error) {
	var out []goToken
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return out, nil
		case c == '(' || c == ')':
			out = append(out, goToken{text: string(c), start: i, end: i + 1})
			i++
		case c == '"' || c == '`':
			end := i + 1
			for end < len(line) && line[end] != c {
				if c == '"' && line[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(line) {
				return nil, errors.New("unterminated string")
			}
			s, err := strconv.Unquote(line[i : end+1])
			if err != nil {
				return nil, errors.New("malformed string")
			}
			out = append(out, goToken{text: s, start: i, end: end + 1, quoted: true})
			i = end + 1
		default:
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '(' && line[i] != ')' &&
				!(line[i] == '/' && i+1 < len(line) && line[i+1] == '/') {
				i++
			}
			out = append(out, goToken{text: line[start:i], start: start, end: i})
		}
	}
	return out, nil
}

// sumLine is a line of go.sum: "<module> <version>[/go.mod] <hash>".
type sumLine struct {
	module, version, hash string
}

func (s sumLine) String() string { return s.module + " " + s.version + " " + s.hash }

// rewriteGoSum swaps the changed modules' hashes. Lines are sorted as the go
// command writes go.sum: by module path, then by version as semantic
// versions, a version's go.mod after its zip; a new line is merged in before
// the first line that sorts after it. The file is read twice, as a stream —
// once for what it holds of the changed modules, once to write it out — and
// nothing is kept per line: a go.sum can run to hundreds of thousands.
func rewriteGoSum(data []byte, changes []Change) ([]byte, error) {
	byName := map[string]*Change{}
	for i := range changes {
		byName[changes[i].Name] = &changes[i]
	}
	// What go.sum holds of the changed modules, by module and version.
	held := map[[2]string][]string{}
	eol := ""
	lineNo := 0
	for off := 0; off < len(data); {
		l, _ := nextLine(data, off)
		off = l.next
		lineNo++
		if eol == "" && strings.HasSuffix(l.eol(data), "\n") {
			eol = l.eol(data)
		}
		f, n := sumFields(data[l.start:l.end])
		switch {
		case n == 0:
			continue
		case n != 3:
			return nil, fmt.Errorf("go.sum line %d: expected three fields", lineNo)
		}
		if byName[string(f[0])] != nil {
			k := [2]string{string(f[0]), string(f[1])}
			held[k] = append(held[k], string(f[2]))
		}
	}
	if eol == "" {
		eol = "\n"
	}
	var added []sumLine
	for _, c := range changes {
		// The old version's zip hash goes; its go.mod hash stays.
		old := held[[2]string{c.Name, c.From}]
		for _, h := range old {
			if v, ok := strings.CutPrefix(h, "h1:"); !ok || !validH1(v) {
				return nil, fmt.Errorf("go.sum holds a hash of %s %s that is not an h1 hash", c.Name, c.From)
			}
		}
		hadZip := len(old) > 0
		modHash, err := goSumHash(c, "go.mod")
		if err != nil {
			return nil, err
		}
		want := []sumLine{{c.Name, c.To + "/go.mod", modHash}}
		if hadZip {
			zipHash, err := goSumHash(c, "package")
			if err != nil {
				return nil, err
			}
			want = append([]sumLine{{c.Name, c.To, zipHash}}, want...)
		}
		for _, w := range want {
			hashes := held[[2]string{w.module, w.version}]
			for _, h := range hashes {
				if h != w.hash {
					return nil, fmt.Errorf("go.sum already holds another hash for %s %s", c.Name, w.version)
				}
			}
			if len(hashes) == 0 {
				added = append(added, w)
			}
		}
	}
	sort.SliceStable(added, func(i, j int) bool { return goSumLess(added[i], added[j]) })

	var b bytes.Buffer
	b.Grow(len(data) + 128*len(added))
	// The line ending written after the last line so far, and whether that
	// line is the file's own last one; dangling is what follows that one when
	// no newline does (carriage returns, or nothing).
	lastEOL, lastIsLast, dangling := "", false, ""
	write := func(line []byte, e string, isLast bool) {
		b.Write(line)
		b.WriteString(e)
		lastEOL, lastIsLast = e, isLast
	}
	// before reports whether added line j sorts before a line of the file,
	// converting the line's version only when the modules are the same.
	before := func(j int, module, version []byte) bool {
		if c := bytes.Compare([]byte(added[j].module), module); c != 0 {
			return c < 0
		}
		return goSumLess(added[j], sumLine{module: added[j].module, version: string(version)})
	}
	j := 0
	for off := 0; off < len(data); {
		l, _ := nextLine(data, off)
		off = l.next
		line := data[l.start:l.end]
		if f, n := sumFields(line); n == 3 {
			if c := byName[string(f[0])]; c != nil && string(f[1]) == c.From {
				continue
			}
			for j < len(added) && before(j, f[0], f[1]) {
				write([]byte(added[j].String()), eol, false)
				j++
			}
		}
		e := l.eol(data)
		if !strings.HasSuffix(e, "\n") {
			dangling, e = e, eol
		}
		write(line, e, l.next > len(data))
	}
	for ; j < len(added); j++ {
		write([]byte(added[j].String()), eol, false)
	}
	out := b.Bytes()
	// The file keeps ending as it did: without a newline (and with whatever
	// carriage return its last line had) if it did.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		out = out[:len(out)-len(lastEOL)]
		if lastIsLast {
			out = append(out, dangling...)
		}
	}
	return out, nil
}

// sumFields splits a go.sum line as strings.Fields does — as the go command
// and internal/lockfiles read it — without allocating; n is the number of
// fields, of which the first three are returned.
func sumFields(line []byte) (f [3][]byte, n int) {
	start := -1
	for i := 0; i < len(line); {
		r, w := rune(line[i]), 1
		if r >= utf8.RuneSelf {
			r, w = utf8.DecodeRune(line[i:])
		}
		if unicode.IsSpace(r) {
			if start >= 0 {
				if n < 3 {
					f[n] = line[start:i]
				}
				n++
				start = -1
			}
		} else if start < 0 {
			start = i
		}
		i += w
	}
	if start >= 0 {
		if n < 3 {
			f[n] = line[start:]
		}
		n++
	}
	return f, n
}

// validH1 reports whether internal/lockfiles reads v (after "h1:") as a
// module hash: the standard base64 of a SHA-256.
func validH1(v string) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	return err == nil && len(raw) == 32
}

// goSumHash returns "h1:<hash>" of a change's artifact of a role.
func goSumHash(c Change, role string) (string, error) {
	a, err := onlyArtifact(c, role)
	if err != nil {
		return "", err
	}
	h, ok := goH1(a.H1)
	if !ok {
		return "", fmt.Errorf("%s %s: the %s artifact has no module hash", c.Name, c.To, role)
	}
	return "h1:" + h, nil
}

// goSumLess orders go.sum lines as the go command does (module.Sort).
func goSumLess(a, b sumLine) bool {
	if a.module != b.module {
		return a.module < b.module
	}
	va, fa, _ := strings.Cut(a.version, "/")
	vb, fb, _ := strings.Cut(b.version, "/")
	if va != vb {
		return goSemverCompare(va, vb) < 0
	}
	return fa < fb
}

// --- semantic versions ----------------------------------------------------------

// semver is a parsed semantic version, without the "v" Go puts in front.
type semver struct {
	major, minor, patch string
	pre                 []string
	build               string
	// short marks Go's shorthand "v1" or "v1.2" (golang.org/x/mod/semver
	// reads them as v1.0.0 and v1.2.0).
	short bool
}

// parseSemver reads MAJOR[.MINOR[.PATCH]][-PRERELEASE][+BUILD] with the rules
// of semver.org: numbers without leading zeros, prerelease identifiers of
// [0-9A-Za-z-], numeric ones without leading zeros.
func parseSemver(s string) (semver, bool) {
	var v semver
	num := func() (string, bool) {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		n := s[:i]
		if n == "" || (len(n) > 1 && n[0] == '0') {
			return "", false
		}
		s = s[i:]
		return n, true
	}
	var ok bool
	if v.major, ok = num(); !ok {
		return v, false
	}
	v.minor, v.patch = "0", "0"
	if strings.HasPrefix(s, ".") {
		s = s[1:]
		if v.minor, ok = num(); !ok {
			return v, false
		}
		if strings.HasPrefix(s, ".") {
			s = s[1:]
			if v.patch, ok = num(); !ok {
				return v, false
			}
		} else {
			v.short = true
		}
	} else {
		v.short = true
	}
	if rest, found := strings.CutPrefix(s, "-"); found {
		pre, _, _ := strings.Cut(rest, "+")
		for _, id := range strings.Split(pre, ".") {
			if id == "" || !tokenOf(id, "-") || (digitsOnly(id) && len(id) > 1 && id[0] == '0') {
				return v, false
			}
			v.pre = append(v.pre, id)
		}
		s = rest[len(pre):]
	}
	if rest, found := strings.CutPrefix(s, "+"); found {
		for _, id := range strings.Split(rest, ".") {
			if id == "" || !tokenOf(id, "-") {
				return v, false
			}
		}
		v.build, s = rest, ""
	}
	if s != "" || (v.short && (v.pre != nil || v.build != "")) {
		return v, false
	}
	return v, true
}

// compareNum compares numbers written without leading zeros.
func compareNum(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// comparePrecedence compares two versions by semantic-version precedence:
// the numbers, then the prerelease (none ranks above any); build metadata
// does not count.
func comparePrecedence(a, b semver) int {
	if c := compareNum(a.major, b.major); c != 0 {
		return c
	}
	if c := compareNum(a.minor, b.minor); c != 0 {
		return c
	}
	if c := compareNum(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case a.pre == nil && b.pre == nil:
		return 0
	case a.pre == nil:
		return 1
	case b.pre == nil:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xn, yn := digitsOnly(x), digitsOnly(y)
		switch {
		case xn && yn:
			return compareNum(x, y)
		case xn:
			return -1
		case yn:
			return 1
		}
		return strings.Compare(x, y)
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// goSemverCompare compares Go module versions as golang.org/x/mod/semver
// does: an invalid version sorts before every valid one and equal to other
// invalid ones; build metadata is ignored.
func goSemverCompare(a, b string) int {
	va, okA := parseSemver(strings.TrimPrefix(a, "v"))
	vb, okB := parseSemver(strings.TrimPrefix(b, "v"))
	okA = okA && strings.HasPrefix(a, "v")
	okB = okB && strings.HasPrefix(b, "v")
	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return -1
	case !okB:
		return 1
	}
	return comparePrecedence(va, vb)
}

// semverCompare compares two Cargo versions as Cargo orders the crates of a
// lock file. ok is false when one is not a full semantic version, or when
// they differ only in build metadata, whose order the updater does not
// reproduce.
func semverCompare(a, b string) (int, bool) {
	va, okA := parseSemver(a)
	vb, okB := parseSemver(b)
	if !okA || !okB || va.short || vb.short {
		return 0, false
	}
	c := comparePrecedence(va, vb)
	if c == 0 && va.build != vb.build {
		return 0, false
	}
	return c, true
}
