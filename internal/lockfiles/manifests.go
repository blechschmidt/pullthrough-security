package lockfiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Readers of what a manifest declares (Task 182). The maintenance updater
// proposes a newer version of a dependency only within the constraint the
// project declares for it: the ranges of package.json and of every package
// that depends on it in package-lock.json, the requirements of Cargo.toml and
// of the crates that depend on it in Cargo.lock, the specifiers of a
// requirements.in or pyproject.toml. These readers return those declarations as
// written; evaluating them is internal/versions' business.

// --- npm ---------------------------------------------------------------------

// NPMRequirement is one range a package-lock.json entry (or the project's
// package.json) declares for a dependency, resolved to the position in
// node_modules that satisfies it.
type NPMRequirement struct {
	// Dependent is the install path of the package that declares the range
	// ("" for the project, "packages/a" for a workspace).
	Dependent string `json:"dependent"`
	// Name and Range are the dependency's name and the range declared ("npm:"
	// aliases already reduced to the aliased package's range).
	Name  string `json:"name"`
	Range string `json:"range"`
	// Kind is "", "dev", "optional" or "peer".
	Kind string `json:"kind,omitempty"`
	// Position is the install path the dependency resolves to from the
	// dependent (Node's lookup: the dependent's own node_modules, then each
	// ancestor's); Version the version installed there. Empty when nothing
	// in the lock file satisfies the lookup.
	Position string `json:"position,omitempty"`
	Version  string `json:"version,omitempty"`
	// Package is the real name of the package at the position (its alias
	// target, when the dependency is an alias).
	Package string `json:"package,omitempty"`
}

// npmEntry is what NPMRequirements reads of one installed package.
type npmEntry struct {
	version, name string
	link          bool
	deps          map[string]map[string]string // kind → name → range
}

// Bounds of NPMRequirements: the entries it reads, and the ranges they declare
// together. A package-lock.json is untrusted input, and its size bound counts
// bytes, not declarations: a 30 MiB root entry can declare millions of ranges,
// each of which would become a record.
const (
	maxNPMEntries = 200_000
	maxNPMRanges  = 400_000
)

// ErrTooManyRanges is returned by NPMRequirements for a lock file that
// declares more ranges than it reads.
var ErrTooManyRanges = errors.New("package-lock.json declares more dependency ranges than are read")

// NPMRequirements reads the ranges every package of a package-lock.json (or
// npm-shrinkwrap.json) declares for its dependencies, each resolved to the
// position that satisfies it. Versions 2 and 3 carry the project's own ranges
// in the root entry; for version 1 they come from packageJSON (nil when it is
// not available).
func NPMRequirements(lock, packageJSON []byte) ([]NPMRequirement, error) {
	budget := maxNPMRanges
	var top map[string]json.RawMessage
	if err := json.Unmarshal(lock, &top); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	entries := map[string]*npmEntry{}
	if raw, ok := top["packages"]; ok {
		var pkgs map[string]json.RawMessage
		if err := json.Unmarshal(raw, &pkgs); err != nil {
			return nil, fmt.Errorf("package-lock.json packages: %w", err)
		}
		if len(pkgs) > maxNPMEntries {
			return nil, fmt.Errorf("package-lock.json lists more than %d packages", maxNPMEntries)
		}
		for p, raw := range pkgs {
			e, err := readNPMEntry(raw, p == "" || !strings.Contains(p, "node_modules/"), &budget)
			if err != nil {
				return nil, fmt.Errorf("package-lock.json packages[%q]: %w", p, err)
			}
			entries[p] = e
		}
	} else if raw, ok := top["dependencies"]; ok {
		root := &npmEntry{deps: map[string]map[string]string{}}
		if packageJSON != nil {
			pj, err := readNPMEntry(packageJSON, true, &budget)
			if err != nil {
				return nil, fmt.Errorf("package.json: %w", err)
			}
			root = pj
		}
		entries[""] = root
		if err := readNPMv1(raw, "", entries, 0, &budget); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("package-lock.json has neither packages nor dependencies")
	}

	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []NPMRequirement
	for _, p := range paths {
		e := entries[p]
		if e.link {
			continue
		}
		for _, kind := range []string{"", "dev", "optional", "peer"} {
			deps := e.deps[kind]
			for _, name := range sortedStringKeys(deps) {
				if !npmInstallableName(name) {
					continue // nothing npm could install under that name
				}
				r := NPMRequirement{Dependent: p, Name: name, Range: deps[name], Kind: kind}
				if alias, rng, ok := npmAliasRange(r.Range); ok {
					r.Package, r.Range = alias, rng
				}
				if pos, ok := npmResolve(entries, p, name); ok {
					r.Position = pos
					r.Version = entries[pos].version
					if entries[pos].name != "" {
						r.Package = entries[pos].name
					} else if r.Package == "" {
						r.Package = name
					}
				}
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// readNPMEntry reads an installed package's (or a package.json's) version and
// declared dependencies. root says whether devDependencies count: npm installs
// them for the project and its workspaces only. budget is what is left of the
// ranges the whole read may hold.
func readNPMEntry(raw json.RawMessage, root bool, budget *int) (*npmEntry, error) {
	var f map[string]json.RawMessage
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	e := &npmEntry{deps: map[string]map[string]string{}}
	str := func(k string) string {
		var s string
		if v, ok := f[k]; ok {
			_ = json.Unmarshal(v, &s)
		}
		return s
	}
	e.version, e.name = str("version"), str("name")
	if v, ok := f["link"]; ok {
		_ = json.Unmarshal(v, &e.link)
	}
	fields := map[string]string{"dependencies": "", "optionalDependencies": "optional", "peerDependencies": "peer", "requires": ""}
	if root {
		fields["devDependencies"] = "dev"
	}
	for field, kind := range fields {
		raw, ok := f[field]
		if !ok {
			continue
		}
		if e.deps[kind] == nil {
			e.deps[kind] = map[string]string{}
		}
		if err := readRanges(raw, e.deps[kind], budget); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// readRanges streams a {"name": "range", …} object into into, counting the
// ranges against budget; a value that is not an object (v1's top-level
// "requires": true) holds none. Values that are not strings are left out.
func readRanges(raw json.RawMessage, into map[string]string, budget *int) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return err
		}
		if *budget <= 0 {
			return ErrTooManyRanges
		}
		*budget--
		var s string
		if json.Unmarshal(val, &s) == nil {
			into[key] = s
		}
	}
	return nil
}

// readNPMv1 reads version 1's nested "dependencies" tree into install paths.
func readNPMv1(raw json.RawMessage, parent string, entries map[string]*npmEntry, depth int, budget *int) error {
	if depth > 64 {
		return errors.New("package-lock.json: dependencies nested deeper than 64 levels")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("package-lock.json dependencies: %w", err)
	}
	for name, body := range m {
		if len(entries) >= maxNPMEntries {
			return fmt.Errorf("package-lock.json lists more than %d packages", maxNPMEntries)
		}
		if !npmInstallableName(name) {
			continue
		}
		p := "node_modules/" + name
		if parent != "" {
			p = parent + "/node_modules/" + name
		}
		e, err := readNPMEntry(body, false, budget)
		if err != nil {
			return fmt.Errorf("package-lock.json dependencies[%q]: %w", name, err)
		}
		// Version 1 spells an alias's version "npm:<real>@<version>".
		if alias, v, ok := npmAliasRange(e.version); ok {
			e.name, e.version = alias, v
		}
		entries[p] = e
		var f map[string]json.RawMessage
		if json.Unmarshal(body, &f) == nil {
			if nested, ok := f["dependencies"]; ok && len(bytes.TrimSpace(nested)) > 0 && bytes.TrimSpace(nested)[0] == '{' {
				if err := readNPMv1(nested, p, entries, depth+1, budget); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// npmResolve finds the position a dependency of the package at from resolves
// to: from's own node_modules, then each enclosing node_modules up to the root
// (Node's module resolution, which npm lays the tree out for).
func npmResolve(entries map[string]*npmEntry, from, name string) (string, bool) {
	dir := from
	for {
		cand := "node_modules/" + name
		if dir != "" {
			cand = dir + "/node_modules/" + name
		}
		if e, ok := entries[cand]; ok && !e.link {
			return cand, true
		} else if ok && e.link {
			return "", false
		}
		if dir == "" {
			return "", false
		}
		i := strings.LastIndex(dir, "/node_modules/")
		switch {
		case i >= 0:
			dir = dir[:i]
		case strings.HasPrefix(dir, "node_modules/"):
			dir = ""
		default:
			// A workspace folder: its node_modules, then the project's.
			dir = ""
		}
	}
}

// npmInstallableName reports whether name can name a directory npm installs
// into: "name" or "@scope/name", no empty or dot segment.
func npmInstallableName(name string) bool {
	segs := strings.Split(name, "/")
	if len(segs) > 2 || (len(segs) == 2 && !strings.HasPrefix(name, "@")) {
		return false
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || s == "@" || strings.ContainsAny(s, "\x00\\") {
			return false
		}
	}
	return true
}

// npmAliasRange reduces "npm:<name>@<range>" to the aliased name and range.
func npmAliasRange(spec string) (name, rng string, ok bool) {
	rest, found := strings.CutPrefix(spec, "npm:")
	if !found {
		return "", "", false
	}
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, "", true
	}
	return rest[:at], rest[at+1:], true
}

// --- Cargo -------------------------------------------------------------------

// CargoPackage is one [[package]] of a Cargo.lock with the dependencies it
// lists ("name", "name version" or "name version (source)").
type CargoPackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Source       string   `json:"source,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// CargoLockPackages reads the packages of a Cargo.lock with their dependency
// lists: the graph the requirements of each dependent are read along.
func CargoLockPackages(data []byte) ([]CargoPackage, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	var out []CargoPackage
	for _, pkg := range doc.tables("package") {
		out = append(out, CargoPackage{Name: pkg.str("name"), Version: pkg.str("version"), Source: pkg.str("source"),
			Dependencies: pkg.strings("dependencies")})
	}
	return out, nil
}

// CargoDependencyRef splits a Cargo.lock dependency reference ("name",
// "name version", "name version (source)").
func CargoDependencyRef(ref string) (name, version string) {
	f := strings.Fields(ref)
	switch len(f) {
	case 0:
		return "", ""
	case 1:
		return f[0], ""
	}
	return f[0], f[1]
}

// CargoRequirement is one dependency a Cargo.toml declares from a registry.
type CargoRequirement struct {
	// Name is the crate's name (the package of a renamed dependency).
	Name string `json:"name"`
	// Requirement is the version requirement ("1.2", "^0.4", "=1.0.3").
	Requirement string `json:"requirement"`
	// Table is where it is declared ("dependencies", "dev-dependencies",
	// "target.'cfg(unix)'.build-dependencies", "workspace.dependencies").
	Table string `json:"table"`
}

// CargoManifestRequirements reads the registry dependencies a Cargo.toml
// declares, with their version requirements, from every dependency table:
// [dependencies], [dev-dependencies], [build-dependencies], their
// [target.<cfg>.*] forms, and [workspace.dependencies]. A dependency inherited
// from the workspace ("x.workspace = true") is reported by the workspace's
// manifest; path and Git dependencies without a version are left out.
func CargoManifestRequirements(data []byte) ([]CargoRequirement, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	var out []CargoRequirement
	read := func(where string, t *tomlTable) {
		if t == nil {
			return
		}
		for _, key := range t.keys {
			v := t.get(key)
			if v == nil {
				continue
			}
			name, req := key, ""
			switch v.kind {
			case tkString:
				if req = strings.TrimSpace(v.str); req == "" {
					continue // no requirement to read
				}
			case tkTable:
				if v.tab.get("workspace") != nil {
					continue // inherited: the workspace's manifest declares it
				}
				req = strings.TrimSpace(v.tab.str("version"))
				if p := strings.TrimSpace(v.tab.str("package")); p != "" {
					name = p
				}
				if req == "" {
					continue // a path or Git dependency
				}
			default:
				continue
			}
			if strings.TrimSpace(name) == "" {
				continue
			}
			out = append(out, CargoRequirement{Name: name, Requirement: req, Table: where})
		}
	}
	for _, kind := range []string{"dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies"} {
		read(kind, doc.table(kind))
	}
	if targets := doc.table("target"); targets != nil {
		for _, cfg := range targets.keys {
			t := targets.table(cfg)
			if t == nil {
				continue
			}
			for _, kind := range []string{"dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies"} {
				read("target."+cfg+"."+kind, t.table(kind))
			}
		}
	}
	if ws := doc.table("workspace"); ws != nil {
		read("workspace.dependencies", ws.table("dependencies"))
	}
	return out, nil
}

// CargoManifestName returns the name of the package a Cargo.toml declares
// ([package] name), or "" for a virtual workspace manifest.
func CargoManifestName(data []byte) (string, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return "", err
	}
	if pkg := doc.table("package"); pkg != nil {
		return pkg.str("name"), nil
	}
	return "", nil
}

// PythonIncludes returns the files a requirements file includes with -r /
// --requirement and -c / --constraint, as written.
func PythonIncludes(data []byte) []string {
	var out []string
	forEachLogicalLine(string(data), func(ll logicalLine) {
		line := stripReqComment(ll.text)
		if !strings.HasPrefix(line, "-") {
			return
		}
		switch opt, value := reqOption(line); opt {
		case "-r", "--requirement", "-c", "--constraint":
			if value != "" && len(out) < 64 {
				out = append(out, value)
			}
		}
	})
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Python ------------------------------------------------------------------

// PythonRequirement is one requirement a Python manifest declares.
type PythonRequirement struct {
	// Name is PEP 503-normalised.
	Name string `json:"name"`
	// Specifier is the version specifier set as written (">=2.0,<3"); empty
	// for an unconstrained requirement. Markers and extras are dropped.
	Specifier string `json:"specifier,omitempty"`
	// Marker is the environment marker, when there is one: the requirement
	// may apply to some environments only.
	Marker string `json:"marker,omitempty"`
}

// PythonRequirementLine reads one PEP 508 requirement ("requests[socks]>=2.0,
// <3; python_version > '3.8'"). ok is false for a line that is not a
// requirement by name (an option, a URL, a local path, a direct reference).
func PythonRequirementLine(line string) (PythonRequirement, bool) {
	text := strings.TrimSpace(stripReqComment(line))
	if text == "" || strings.HasPrefix(text, "-") {
		return PythonRequirement{}, false
	}
	marker := ""
	if i := strings.IndexByte(text, ';'); i >= 0 {
		text, marker = strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
	}
	// Options after the requirement (a requirements file's --hash) end it.
	if i := strings.Index(text, " --"); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	m := reqLineRE.FindStringSubmatch(text)
	if m == nil || !pyNameRE.MatchString(m[1]) {
		return PythonRequirement{}, false
	}
	spec := strings.TrimSpace(m[3])
	if strings.HasPrefix(spec, "@") {
		return PythonRequirement{}, false // a direct reference: no version to update within
	}
	spec = strings.TrimSuffix(strings.TrimPrefix(spec, "("), ")") // the legacy "name (>=1.0)" form
	return PythonRequirement{Name: pyNormalize(m[1]), Specifier: strings.Join(strings.Fields(spec), ""), Marker: marker}, true
}

// PythonRequirementsIn reads a pip-tools input file (requirements.in): its
// requirement lines, continuations joined. -r/-c includes are not followed.
func PythonRequirementsIn(data []byte) []PythonRequirement {
	var out []PythonRequirement
	forEachLogicalLine(string(data), func(ll logicalLine) {
		if r, ok := PythonRequirementLine(ll.text); ok && len(out) < MaxDependenciesPerFile {
			out = append(out, r)
		}
	})
	return out
}

// PyProjectRequirements reads the requirements a pyproject.toml declares in
// [project] dependencies and optional-dependencies (PEP 621) and in
// [dependency-groups] (PEP 735).
func PyProjectRequirements(data []byte) ([]PythonRequirement, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	var out []PythonRequirement
	add := func(list []string) {
		for _, s := range list {
			if r, ok := PythonRequirementLine(s); ok {
				out = append(out, r)
			}
		}
	}
	if p := doc.table("project"); p != nil {
		add(p.strings("dependencies"))
		if opt := p.table("optional-dependencies"); opt != nil {
			for _, k := range opt.keys {
				add(opt.strings(k))
			}
		}
	}
	if g := doc.table("dependency-groups"); g != nil {
		for _, k := range g.keys {
			add(g.strings(k))
		}
	}
	return out, nil
}
