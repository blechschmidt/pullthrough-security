package lockfiles

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Go modules: go.mod names the version of every module the build selects
// (since Go 1.17, indirect ones included), go.sum holds their hashes — "h1:",
// the checksum database's hash of the module's files — and the hashes of the
// go.mod files of the wider module graph. The two are read separately and
// merged per directory (goSum.Merge): a go.mod requirement gets its go.sum
// hashes, and a go.sum module that go.mod does not name stays a dependency of
// go.sum's own (Go downloads its source for some build of the module).

// goMod reads go.mod: its require directives, rewritten by its replace
// directives into what is actually fetched.
type goMod struct{}

func (goMod) Type() string            { return "go" }
func (goMod) Format() string          { return "go.mod" }
func (goMod) Detect(path string) bool { return baseName(path) == "go.mod" }

type goRequire struct {
	path, version string
	line          int
}

type goReplacement struct {
	path, version string // version "" means a local directory
}

func (goMod) Parse(data []byte) (*Result, error) {
	if strings.IndexByte(string(data), 0) >= 0 {
		return nil, errors.New("go.mod contains a NUL byte")
	}
	res := &Result{}
	var requires []goRequire
	exact := map[string]goReplacement{} // "path@version" → replacement
	all := map[string]goReplacement{}   // "path" → replacement
	sawModule := false
	block := ""
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		tokens, err := goModTokens(raw)
		if err != nil {
			return nil, errors.New("go.mod line " + strconv.Itoa(lineNo) + ": " + err.Error())
		}
		if len(tokens) == 0 {
			continue
		}
		verb := block
		args := tokens
		if block == "" {
			verb, args = tokens[0], tokens[1:]
			if len(args) == 1 && args[0] == "(" {
				block = verb
				continue
			}
		} else if tokens[0] == ")" {
			block = ""
			continue
		}
		switch verb {
		case "module":
			sawModule = true
		case "require":
			if len(args) != 2 {
				res.warnf("line %d: a require directive without a module and a version", lineNo)
				continue
			}
			requires = append(requires, goRequire{path: args[0], version: args[1], line: lineNo})
		case "replace":
			arrow := -1
			for j, a := range args {
				if a == "=>" {
					arrow = j
				}
			}
			if arrow < 1 || arrow > 2 || len(args)-arrow-1 < 1 || len(args)-arrow-1 > 2 {
				res.warnf("line %d: a malformed replace directive", lineNo)
				continue
			}
			left, right := args[:arrow], args[arrow+1:]
			rep := goReplacement{path: right[0]}
			if len(right) == 2 {
				rep.version = right[1]
			}
			if len(left) == 2 {
				exact[left[0]+"@"+left[1]] = rep
			} else {
				all[left[0]] = rep
			}
		}
	}
	if block != "" {
		return nil, errors.New("go.mod: a " + block + " block is not closed")
	}
	if !sawModule && len(requires) == 0 {
		return nil, errors.New("not a go.mod: no module directive")
	}
	for _, r := range requires {
		path, version := r.path, r.version
		rep, ok := exact[path+"@"+version]
		if !ok {
			rep, ok = all[path]
		}
		if ok {
			if rep.version == "" {
				res.warnf("%s %s: replaced by a local directory, not fetched", path, version)
				continue
			}
			path, version = rep.path, rep.version
		}
		if !validGoModulePath(path) || !validVersion(version) {
			res.warnf("line %d: a requirement without a usable module path or version", r.line)
			continue
		}
		res.Dependencies = append(res.Dependencies, Dependency{Name: path, Version: version, Line: r.line})
	}
	return res, nil
}

// goModTokens splits a go.mod line into tokens: words, Go string literals,
// "(", ")" and "=>", with "//" comments dropped.
func goModTokens(line string) ([]string, error) {
	var out []string
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return out, nil
		case c == '(' || c == ')':
			out = append(out, string(c))
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
			out = append(out, s)
			i = end + 1
		default:
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '(' && line[i] != ')' &&
				!(line[i] == '/' && i+1 < len(line) && line[i+1] == '/') {
				i++
			}
			out = append(out, line[start:i])
		}
	}
	return out, nil
}

// validGoModulePath accepts what can be a module path: no blanks, no
// backslashes, not a relative or absolute file path.
func validGoModulePath(p string) bool {
	if !validPackageName(p) || strings.ContainsAny(p, "\\") {
		return false
	}
	return !strings.HasPrefix(p, ".") && !strings.HasPrefix(p, "/")
}

// goSum reads go.sum: "<module> <version>[/go.mod] h1:<hash>" lines.
type goSum struct{}

func (goSum) Type() string            { return "go" }
func (goSum) Format() string          { return "go.sum" }
func (goSum) Detect(path string) bool { return baseName(path) == "go.sum" }

func (goSum) Parse(data []byte) (*Result, error) {
	res := &Result{}
	modHashes := map[string]Digest{} // "path version" → hash of the go.mod
	index := map[string]int{}        // "path version" → dependency
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		f := strings.Fields(raw)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, errors.New("go.sum line " + strconv.Itoa(lineNo) + ": expected three fields")
		}
		path, version, hash := f[0], f[1], f[2]
		alg, value, ok := strings.Cut(hash, ":")
		if !ok || alg != "h1" {
			res.warnf("line %d: a hash that is not h1", lineNo)
			continue
		}
		// h1 is the base64 of a SHA-256; nothing else is kept from the line.
		sum, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(sum) != 32 {
			res.warnf("line %d: a malformed h1 hash", lineNo)
			continue
		}
		value = base64.StdEncoding.EncodeToString(sum)
		if !validGoModulePath(path) {
			res.warnf("line %d: not a module path", lineNo)
			continue
		}
		dg := Digest{Algorithm: "h1", Value: value}
		if v, isMod := strings.CutSuffix(version, "/go.mod"); isMod {
			dg.Of = "go.mod"
			key := path + " " + v
			modHashes[key] = dg
			if j, ok := index[key]; ok {
				res.Dependencies[j].Digests = append(res.Dependencies[j].Digests, dg)
			}
			continue
		}
		if !validVersion(version) {
			res.warnf("line %d: not a version", lineNo)
			continue
		}
		key := path + " " + version
		if _, dup := index[key]; dup {
			continue
		}
		d := Dependency{Name: path, Version: version, Digests: []Digest{dg}, Line: lineNo}
		if m, ok := modHashes[key]; ok {
			d.Digests = append(d.Digests, m)
		}
		index[key] = len(res.Dependencies)
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}

// Merge gives the requirements of the go.mod next to a go.sum the go.sum's
// hashes, and drops those modules from the go.sum's own list.
func (goSum) Merge(files []*File) {
	var mod, sum *File
	for _, f := range files {
		switch f.Format {
		case "go.mod":
			mod = f
		case "go.sum":
			sum = f
		}
	}
	if mod == nil || sum == nil || mod.Error != "" || sum.Error != "" {
		return
	}
	bySum := map[string]int{}
	for i, d := range sum.Dependencies {
		bySum[d.Name+" "+d.Version] = i
	}
	used := make([]bool, len(sum.Dependencies))
	for i := range mod.Dependencies {
		d := &mod.Dependencies[i]
		if j, ok := bySum[d.Name+" "+d.Version]; ok {
			d.Digests = mergeDigests(d.Digests, sum.Dependencies[j].Digests)
			used[j] = true
		}
	}
	kept := sum.Dependencies[:0]
	for j, d := range sum.Dependencies {
		if !used[j] {
			kept = append(kept, d)
		}
	}
	sum.Dependencies = kept
}
