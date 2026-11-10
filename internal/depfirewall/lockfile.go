package depfirewall

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseLockfile parses lockfile content into a set of pinned rules — one rule
// per distinct (ecosystem, name), whose Pinned allowlist is the sorted set of
// versions the lockfile resolved for it. The format may be given explicitly
// ("package-lock.json", "requirements.txt", "go.sum", "Cargo.lock") or left
// empty/"auto" to detect it from the content. It returns the rules, the detected
// format label, and an error for an unrecognized or malformed lockfile.
func ParseLockfile(format string, content []byte) ([]Rule, string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" || f == "auto" {
		f = detectFormat(content)
	}
	var (
		eco, source string
		byName      map[string]map[string]struct{}
		err         error
	)
	switch f {
	case "package-lock.json", "npm", "package-lock":
		eco, source = "npm", "package-lock.json"
		byName, err = parsePackageLock(content)
	case "requirements.txt", "pip", "requirements":
		eco, source = "pip", "requirements.txt"
		byName, err = parseRequirements(content)
	case "go.sum", "go", "gosum":
		eco, source = "go", "go.sum"
		byName, err = parseGoSum(content)
	case "cargo.lock", "cargo":
		eco, source = "cargo", "Cargo.lock"
		byName, err = parseCargoLock(content)
	default:
		return nil, f, fmt.Errorf("unrecognized lockfile format %q (want package-lock.json, requirements.txt, go.sum, or Cargo.lock)", format)
	}
	return finalize(eco, source, byName, err)
}

// detectFormat sniffs the lockfile family from its content.
func detectFormat(content []byte) string {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if bytes.Contains(trimmed, []byte(`"lockfileVersion"`)) || bytes.Contains(trimmed, []byte(`"node_modules/`)) {
			return "package-lock.json"
		}
		return "package-lock.json"
	}
	if bytes.Contains(content, []byte("[[package]]")) {
		return "cargo.lock"
	}
	// go.sum lines contain "/go.mod " hashes or a "h1:" hash with a v-prefixed
	// version in the second field.
	if bytes.Contains(content, []byte(" h1:")) || bytes.Contains(content, []byte("/go.mod h1:")) {
		return "go.sum"
	}
	return "requirements.txt"
}

// finalize collapses a name->versionset map into sorted, deduplicated pinned
// rules. It propagates a parse error and rejects an empty result upstream.
func finalize(eco, source string, byName map[string]map[string]struct{}, perr error) ([]Rule, string, error) {
	if perr != nil {
		return nil, source, perr
	}
	rules := make([]Rule, 0, len(byName))
	for name, vers := range byName {
		list := make([]string, 0, len(vers))
		for v := range vers {
			list = append(list, v)
		}
		sort.Strings(list)
		rules = append(rules, Rule{
			Ecosystem: eco,
			Name:      name,
			Pinned:    list,
			Source:    "lockfile:" + source,
		})
	}
	sortRules(rules)
	return rules, source, nil
}

// --- package-lock.json (npm) ------------------------------------------------

// parsePackageLock parses the npm lockfile, supporting both the v1
// ("dependencies" tree) and v2/v3 ("packages" map) schemas.
func parsePackageLock(content []byte) (map[string]map[string]struct{}, error) {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"packages"`
		Dependencies map[string]packageLockDep `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	out := make(map[string]map[string]struct{})
	// v2/v3: the "packages" map keys are install paths ("node_modules/foo",
	// "node_modules/a/node_modules/b"); the package name is the segment after the
	// last "node_modules/". The root entry has an empty key and is skipped.
	for path, pkg := range doc.Packages {
		if path == "" || pkg.Version == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = npmNameFromPath(path)
		}
		if name == "" {
			continue
		}
		addVersion(out, name, pkg.Version)
	}
	// v1: walk the nested dependencies tree.
	for name, dep := range doc.Dependencies {
		walkPackageLockDep(out, name, dep)
	}
	return out, nil
}

type packageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]packageLockDep `json:"dependencies"`
}

func walkPackageLockDep(out map[string]map[string]struct{}, name string, dep packageLockDep) {
	if name != "" && dep.Version != "" {
		addVersion(out, name, dep.Version)
	}
	for child, cd := range dep.Dependencies {
		walkPackageLockDep(out, child, cd)
	}
}

// npmNameFromPath extracts the package name from a v2/v3 install path, honoring
// scoped names ("node_modules/@scope/pkg").
func npmNameFromPath(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(path[idx+len("node_modules/"):])
}

// --- requirements.txt (pip) -------------------------------------------------

// parseRequirements parses a pip requirements file, taking only exact "==" pins
// (the lockfile-grade constraint); other specifiers, comments, options, and
// includes are ignored.
func parseRequirements(content []byte) (map[string]map[string]struct{}, error) {
	out := make(map[string]map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip an inline comment and any environment markers / hashes.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.TrimSuffix(strings.TrimSpace(line), "\\")
		idx := strings.Index(line, "==")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		// Drop any extras: "package[extra]==1.0".
		if b := strings.IndexByte(name, '['); b >= 0 {
			name = strings.TrimSpace(name[:b])
		}
		ver := strings.TrimSpace(line[idx+2:])
		// A trailing ".*" in "==1.4.*" is a prefix match, not an exact pin: skip.
		if name == "" || ver == "" || strings.HasSuffix(ver, "*") {
			continue
		}
		addVersion(out, normalizePyName(name), ver)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse requirements.txt: %w", err)
	}
	return out, nil
}

// normalizePyName applies PEP 503 name normalization (lower-case, runs of
// -, _, . collapse to a single -) so the pin matches the coordinate the pip
// backend resolves.
func normalizePyName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	prevDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}

// --- go.sum (go modules) ----------------------------------------------------

// parseGoSum parses a go.sum file. Each line is "module version[/go.mod] hash";
// the version is taken from the lines (the "/go.mod" suffix is stripped). A
// pseudo-version or +incompatible suffix is kept verbatim, matching what the Go
// module proxy serves.
func parseGoSum(content []byte) (map[string]map[string]struct{}, error) {
	out := make(map[string]map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		module := fields[0]
		ver := fields[1]
		ver = strings.TrimSuffix(ver, "/go.mod")
		if module == "" || ver == "" || !strings.HasPrefix(ver, "v") {
			continue
		}
		addVersion(out, module, ver)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse go.sum: %w", err)
	}
	return out, nil
}

// --- Cargo.lock (cargo) -----------------------------------------------------

// parseCargoLock parses a Cargo.lock file's TOML "[[package]]" array. It uses a
// minimal line scanner rather than a full TOML parser (no external dependency):
// it tracks the current name/version within each [[package]] block.
func parseCargoLock(content []byte) (map[string]map[string]struct{}, error) {
	out := make(map[string]map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var name, ver string
	inPackage := false
	flush := func() {
		if inPackage && name != "" && ver != "" {
			addVersion(out, name, ver)
		}
		name, ver = "", ""
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
			inPackage = true
		case strings.HasPrefix(line, "[") && line != "[[package]]":
			// A different table ([metadata], [[patch...]], etc.) ends the block.
			flush()
			inPackage = false
		case inPackage && strings.HasPrefix(line, "name"):
			name = tomlString(line)
		case inPackage && strings.HasPrefix(line, "version"):
			ver = tomlString(line)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse Cargo.lock: %w", err)
	}
	return out, nil
}

// tomlString extracts the quoted value from a `key = "value"` TOML line.
func tomlString(line string) string {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return ""
	}
	val := strings.TrimSpace(line[idx+1:])
	val = strings.Trim(val, `"'`)
	return strings.TrimSpace(val)
}

// addVersion records (name, version) into the accumulator, creating the version
// set on first sight.
func addVersion(out map[string]map[string]struct{}, name, version string) {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return
	}
	set := out[name]
	if set == nil {
		set = make(map[string]struct{})
		out[name] = set
	}
	set[version] = struct{}{}
}
