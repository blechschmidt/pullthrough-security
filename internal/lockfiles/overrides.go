package lockfiles

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Readers of what makes a client build something other than what a lock file
// pins (Task 182). The repository maintenance updater moves a dependency to a
// version whose exact bytes the proxy vetted; files next to the lock file may
// have the client take that version from elsewhere — a Go replace directive or
// workspace, a Cargo [patch] or source replacement, an npm override, a package
// source of a requirements file whose pins carry no hash. Such a redirection
// may name the new version only, and lie dormant until the update lands: the
// updater does not update what one of these names.

// maxOverrideNames bounds what one file contributes.
const maxOverrideNames = 4096

// --- Go ------------------------------------------------------------------------

// goDirectives calls fn with every directive of a go.mod-syntax file (go.mod,
// go.work), the verb of a block repeated for each of its lines.
func goDirectives(data []byte, what string, fn func(verb string, args []string)) error {
	if strings.IndexByte(string(data), 0) >= 0 {
		return errors.New(what + " contains a NUL byte")
	}
	block := ""
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		tokens, err := goModTokens(raw)
		if err != nil {
			return errors.New(what + " line " + strconv.Itoa(lineNo) + ": " + err.Error())
		}
		if len(tokens) == 0 {
			continue
		}
		verb, args := block, tokens
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
		fn(verb, args)
	}
	if block != "" {
		return errors.New(what + ": a " + block + " block is not closed")
	}
	return nil
}

// replacedModule returns the module a replace directive's arguments replace
// (its left-hand side), or "".
func replacedModule(args []string) string {
	for i, a := range args {
		if a == "=>" {
			if i >= 1 && i <= 2 {
				return args[0]
			}
			return ""
		}
	}
	return ""
}

// GoWork reads a go.work file: the directories its use directives name, as
// written, and the modules its replace directives replace.
func GoWork(data []byte) (uses, replaced []string, err error) {
	err = goDirectives(data, "go.work", func(verb string, args []string) {
		switch verb {
		case "use":
			if len(args) >= 1 && len(uses) < maxOverrideNames {
				uses = append(uses, args[0])
			}
		case "replace":
			if m := replacedModule(args); m != "" && len(replaced) < maxOverrideNames {
				replaced = append(replaced, m)
			}
		}
	})
	return uses, replaced, err
}

// GoModReplaced reads a go.mod's module path and the modules its replace
// directives replace, whatever the version and the replacement.
func GoModReplaced(data []byte) (module string, replaced []string, err error) {
	err = goDirectives(data, "go.mod", func(verb string, args []string) {
		switch verb {
		case "module":
			if len(args) >= 1 && module == "" {
				module = args[0]
			}
		case "replace":
			if m := replacedModule(args); m != "" && len(replaced) < maxOverrideNames {
				replaced = append(replaced, m)
			}
		}
	})
	return module, replaced, err
}

// --- Cargo ---------------------------------------------------------------------

// cargoPatchNames adds the crates a [patch] table patches: its tables are
// per source ("crates-io", or a registry or repository URL), keyed by the
// dependency's name — and a renamed dependency's package key names the crate.
func cargoPatchNames(patch *tomlTable, add func(string)) {
	if patch == nil {
		return
	}
	for _, src := range patch.keys {
		t := patch.table(src)
		if t == nil {
			continue
		}
		for _, key := range t.keys {
			add(key)
			if dep := t.table(key); dep != nil {
				if p := strings.TrimSpace(dep.str("package")); p != "" {
					add(p)
				}
			}
		}
	}
}

// cargoSpecName returns the crate a package ID spec names: "foo",
// "foo:1.0.0", "foo@1.0.0", "https://…/crates.io-index#foo:1.0.0".
func cargoSpecName(spec string) string {
	if i := strings.LastIndexByte(spec, '#'); i >= 0 {
		spec = spec[i+1:]
	}
	if i := strings.IndexAny(spec, ":@"); i >= 0 {
		spec = spec[:i]
	}
	return strings.TrimSpace(spec)
}

// CargoPatched returns the crates a Cargo manifest patches ([patch.<source>])
// or replaces ([replace], keyed by package ID specs). Only the workspace's
// root manifest's count — Cargo ignores them in members' manifests — but any
// manifest's are returned.
func CargoPatched(data []byte) ([]string, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	names := newNameSet()
	cargoPatchNames(doc.table("patch"), names.add)
	if r := doc.table("replace"); r != nil {
		for _, spec := range r.keys {
			names.add(cargoSpecName(spec))
		}
	}
	return names.list(), nil
}

// CargoPatchUnused returns the crates a Cargo.lock lists in [[patch.unused]]:
// patches of the workspace that no locked version uses — yet. A patch that
// provides another version of a crate is unused until the lock file moves the
// crate to that version, and then it is what Cargo builds.
func CargoPatchUnused(data []byte) ([]string, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	names := newNameSet()
	if patch := doc.table("patch"); patch != nil {
		for _, t := range patch.tables("unused") {
			names.add(t.str("name"))
		}
	}
	return names.list(), nil
}

// CargoConfigRedirects reads a Cargo configuration file (.cargo/config.toml,
// or the older .cargo/config). redirect says what makes every registry crate
// come from elsewhere: a source replacement (a [source.<name>] with
// replace-with: vendored sources, a local registry, a mirror), path overrides
// (paths), another crates.io index (registry.index). patched are the crates
// its [patch] tables patch (Cargo reads [patch] from configuration too).
func CargoConfigRedirects(data []byte) (redirect string, patched []string, err error) {
	doc, err := parseTOML(data)
	if err != nil {
		return "", nil, err
	}
	if doc.get("paths") != nil {
		redirect = "path overrides (paths)"
	}
	if src := doc.table("source"); src != nil && redirect == "" {
		for _, name := range src.keys {
			if t := src.table(name); t != nil && t.get("replace-with") != nil {
				redirect = "a source replacement ([source." + name + "] replace-with)"
				break
			}
		}
	}
	if reg := doc.table("registry"); reg != nil && reg.get("index") != nil && redirect == "" {
		redirect = "another crates.io index (registry.index)"
	}
	names := newNameSet()
	cargoPatchNames(doc.table("patch"), names.add)
	return redirect, names.list(), nil
}

// --- npm -----------------------------------------------------------------------

// NPMOverrides returns the packages a package.json's "overrides" (npm 8.3 and
// later) names, at any depth: each key names a package ("name", or
// "name@<range>"), whose resolution npm replaces with the value; "." is the
// enclosing package itself.
func NPMOverrides(data []byte) ([]string, error) {
	var pkg struct {
		Overrides json.RawMessage `json:"overrides"`
	}
	if err := json.Unmarshal(trimBOM(data), &pkg); err != nil {
		return nil, err
	}
	if len(pkg.Overrides) == 0 || string(pkg.Overrides) == "null" {
		return nil, nil
	}
	var tree any
	if err := json.Unmarshal(pkg.Overrides, &tree); err != nil {
		return nil, err
	}
	names := newNameSet()
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		obj, ok := v.(map[string]any)
		if !ok || depth > 64 {
			return
		}
		for key, val := range obj {
			if key != "." {
				names.add(npmOverrideName(key))
			}
			walk(val, depth+1)
		}
	}
	walk(tree, 0)
	return names.list(), nil
}

// npmOverrideName returns the package an overrides key names: "name",
// "name@range", "@scope/name", "@scope/name@range".
func npmOverrideName(key string) string {
	key = strings.TrimSpace(key)
	start := 0
	if strings.HasPrefix(key, "@") {
		start = 1
	}
	if i := strings.IndexByte(key[start:], '@'); i >= 0 {
		return key[:start+i]
	}
	return key
}

// --- Python --------------------------------------------------------------------

// PythonSource is a package source a requirements file names: an index (-i,
// --index-url, --extra-index-url) or a page or directory of distribution files
// (-f, --find-links).
type PythonSource struct {
	Option string `json:"option"`
	Value  string `json:"value"`
}

// PythonSources returns the package sources a requirements file names, read
// as pip reads it: options anywhere on a line, a long option by any unique
// prefix ("--extra-i", "--find"), a short option's value attached or not
// ("-ihttps://…", "-f ./wheels"), "--opt=value".
func PythonSources(data []byte) []PythonSource {
	var out []PythonSource
	forEachLogicalLine(string(data), func(ll logicalLine) {
		fields := strings.Fields(stripReqComment(ll.text))
		for i := 0; i < len(fields) && len(out) < maxOverrideNames; i++ {
			f := fields[i]
			if !strings.HasPrefix(f, "-") {
				continue
			}
			next := ""
			if i+1 < len(fields) {
				next = fields[i+1]
			}
			opt, value, ok := pythonSourceOption(f, next)
			if !ok {
				continue
			}
			out = append(out, PythonSource{Option: opt, Value: strings.Trim(value, `"'`)})
		}
	})
	return out
}

// pythonSourceOption classifies one word of a requirements line (next is the
// word after it, a separate option value).
func pythonSourceOption(word, next string) (opt, value string, ok bool) {
	if strings.HasPrefix(word, "--") {
		name, val, attached := strings.Cut(word, "=")
		if !attached {
			val = next
		}
		for _, long := range []struct {
			full string
			min  int
		}{{"--index-url", 3}, {"--extra-index-url", 4}, {"--find-links", 3}} {
			if len(name) >= long.min && strings.HasPrefix(long.full, name) {
				return long.full, val, true
			}
		}
		return "", "", false
	}
	for _, short := range []struct{ flag, full string }{{"-i", "--index-url"}, {"-f", "--find-links"}} {
		if rest, found := strings.CutPrefix(word, short.flag); found {
			if rest == "" {
				rest = next
			}
			return short.full, strings.TrimPrefix(rest, "="), true
		}
	}
	return "", "", false
}

// --- helpers -------------------------------------------------------------------

// nameSet collects names, bounded, without repeats.
type nameSet struct{ m map[string]bool }

func newNameSet() *nameSet { return &nameSet{m: map[string]bool{}} }

func (s *nameSet) add(name string) {
	name = strings.TrimSpace(name)
	if name != "" && len(s.m) < maxOverrideNames {
		s.m[name] = true
	}
}

func (s *nameSet) list() []string {
	out := make([]string, 0, len(s.m))
	for n := range s.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func trimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		return data[3:]
	}
	return data
}
