package lockfiles

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// cabalFreeze reads cabal.project.freeze, which `cabal freeze` writes: a
// "constraints:" field pinning every package of the build plan with "==",
// qualified by where it is used ("any.aeson ==2.2.3.0", "setup.Cabal
// ==3.10.3.0"), next to flag settings ("aeson -ordered-keymap") and the
// "index-state" the plan was made against. It records no hashes: the
// index-state pins the package index, whose entries a client checks the
// tarballs against, but the file itself pins only versions. Boot packages
// (base, text, …) are pinned like the others; whether the build takes them
// from the compiler or from Hackage is not recorded.
type cabalFreeze struct{}

func (cabalFreeze) Type() string            { return "hackage" }
func (cabalFreeze) Format() string          { return "cabal.project.freeze" }
func (cabalFreeze) Detect(path string) bool { return baseName(path) == "cabal.project.freeze" }

// ghcInternal are package names a freeze file pins that are not on Hackage:
// they exist only inside the compiler.
var ghcInternal = map[string]bool{"rts": true, "system-cxx-std-lib": true}

func (cabalFreeze) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("cabal.project.freeze is not valid UTF-8")
	}
	res := &Result{}
	field, sawField := "", false
	seen := map[string]bool{}
	// pending accumulates the text of one constraint (constraints may span
	// lines only at commas, but a value may start on the next line).
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		value := trimmed
		if line[0] != ' ' && line[0] != '\t' {
			// "name:" — Cabal's lexer allows blanks between a field's name
			// and its colon ("constraints :").
			name, rest, ok := strings.Cut(trimmed, ":")
			name = strings.TrimRight(name, " \t")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				field = "" // a section header ("package foo") or something else
				continue
			}
			field, value, sawField = strings.ToLower(name), strings.TrimSpace(rest), true
		}
		if field != "constraints" {
			continue
		}
		for value != "" {
			c, rest, _ := strings.Cut(value, ",")
			value = rest
			d, ok := cabalConstraint(res, strings.TrimSpace(c), lineNo)
			if !ok {
				continue
			}
			// A package pinned for several qualifiers (any., setup.) is one
			// dependency.
			if key := d.Name + "\x00" + d.Version; !seen[key] {
				seen[key] = true
				res.add(d)
			}
		}
	}
	if !sawField {
		return nil, errNotFormat("cabal.project.freeze", "no fields")
	}
	return res, nil
}

// cabalConstraint reads one constraint: "[qualifier.]name ==version"; flag
// settings, "installed" and "source" constraints pin no version.
func cabalConstraint(res *Result, c string, line int) (Dependency, bool) {
	if c == "" {
		return Dependency{}, false
	}
	target, rest, _ := strings.Cut(c, " ")
	rest = strings.TrimSpace(rest)
	name := target[strings.LastIndexByte(target, '.')+1:]
	if !validHackageName(name) {
		res.warnf("line %d: not a constraint this parser understands", line)
		return Dependency{}, false
	}
	switch {
	case rest == "" || rest == "installed" || rest == "source" || strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-"):
		return Dependency{}, false
	case !strings.HasPrefix(rest, "=="):
		res.warnf("line %d: %s is constrained to a range, not pinned", line, name)
		return Dependency{}, false
	}
	version := strings.TrimSpace(strings.TrimPrefix(rest, "=="))
	if !validHackageVersion(version) {
		res.warnf("line %d: %s is not pinned to a single version", line, name)
		return Dependency{}, false
	}
	if ghcInternal[name] {
		return Dependency{}, false
	}
	return Dependency{Name: name, Version: version, Line: line}, true
}

// validHackageName: letters, digits and hyphens, at least one letter in each
// hyphen-separated part.
func validHackageName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, part := range strings.Split(s, "-") {
		if part == "" || strings.Trim(part, "0123456789") == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

// validHackageVersion: dot-separated numbers ("2.2.3.0").
func validHackageVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// stackLock reads Stack's stack.yaml.lock: for every extra dependency of
// stack.yaml the "original" reference and the "completed" one Stack resolved
// it to, and the same for the resolver snapshot. A Hackage package completes
// to "name-version@sha256:<hash>,<size>" — the hash of its .cabal file, which
// pins the revision of the package description — and every package to a
// "pantry-tree": the SHA-256 of Pantry's list of the package's files and
// their hashes, which pins its content. Git and archive packages record the
// commit, or the archive's own SHA-256.
//
// The packages of the snapshot are not in the file: the snapshot's own hash
// pins them, and they are reported as a warning, not as dependencies.
type stackLock struct{}

func (stackLock) Type() string            { return "hackage" }
func (stackLock) Format() string          { return "stack.yaml.lock" }
func (stackLock) Detect(path string) bool { return baseName(path) == "stack.yaml.lock" }

func (stackLock) Parse(data []byte) (*Result, error) {
	m, err := readYAMLLock(data, "stack.yaml.lock")
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if m == nil {
		return res, nil
	}
	packages := yamlGet(m, "packages")
	if packages == nil {
		packages = yamlGet(m, "dependencies") // Stack 2.1
	}
	snapshots := yamlGet(m, "snapshots")
	if packages == nil && snapshots == nil {
		return nil, errNotFormat("stack.yaml.lock", "no packages and no snapshots")
	}
	for _, entry := range yamlSeq(packages) {
		if d, ok := stackDependency(res, entry); ok {
			res.add(d)
		}
	}
	for _, s := range yamlSeq(snapshots) {
		name := yamlScalar(yamlGet(s, "original"))
		if name == "" {
			name = yamlScalar(yamlGet(yamlGet(s, "original"), "url"))
		}
		if name != "" {
			res.warnf("the snapshot %s pins the packages not listed here; the lock file pins the snapshot by its SHA-256", strings.TrimSpace(name))
		}
	}
	return res, nil
}

func stackDependency(res *Result, entry *yaml.Node) (Dependency, bool) {
	c := yamlGet(entry, "completed")
	if c == nil {
		return Dependency{}, false
	}
	line := c.Line
	d := Dependency{Line: line}
	if tree := yamlGet(c, "pantry-tree"); tree != nil {
		if dg, ok := hexDigest("sha256", yamlScalar(yamlGet(tree, "sha256")), "pantry-tree"); ok {
			d.Digests = append(d.Digests, dg)
		}
	}
	// Pantry reads a completed location in this order: a repository (git,
	// hg), an archive (url), a Hackage package, a GitHub shorthand. A key of
	// a later kind next to an earlier one is not what Stack fetches.
	switch {
	case yamlScalar(yamlGet(c, "git")) != "" || yamlScalar(yamlGet(c, "hg")) != "" || yamlScalar(yamlGet(c, "github")) != "":
		repo := yamlScalar(yamlGet(c, "git"))
		switch {
		case repo != "":
		case yamlScalar(yamlGet(c, "hg")) != "":
			repo = yamlScalar(yamlGet(c, "hg"))
		default:
			gh := yamlScalar(yamlGet(c, "github"))
			if owner, name, ok := strings.Cut(gh, "/"); !ok || !flakePart(owner) || !flakePart(name) {
				res.warnf("line %d: a GitHub repository that is not owner/name", line)
				return Dependency{}, false
			}
			repo = "https://github.com/" + gh
		}
		d.Name, d.Version = yamlScalar(yamlGet(c, "name")), yamlScalar(yamlGet(c, "version"))
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(repo)
		if commit := yamlScalar(yamlGet(c, "commit")); isCommitID(commit) {
			d.Revision = strings.ToLower(commit)
		}
		if yamlScalar(yamlGet(c, "hg")) != "" && yamlScalar(yamlGet(c, "git")) == "" {
			res.warnf("line %d: %s comes from a Mercurial repository", line, d.Name)
		}
	case yamlScalar(yamlGet(c, "url")) != "" || yamlScalar(yamlGet(c, "archive")) != "":
		u := yamlScalar(yamlGet(c, "url"))
		if u == "" {
			u = yamlScalar(yamlGet(c, "archive"))
		}
		d.Name, d.Version = yamlScalar(yamlGet(c, "name")), yamlScalar(yamlGet(c, "version"))
		d.Source, d.URL = SourceURL, cleanURL(u)
		if dg, ok := hexDigest("sha256", yamlScalar(yamlGet(c, "sha256")), ""); ok {
			d.Digests = append(d.Digests, dg)
		}
	case yamlScalar(yamlGet(c, "hackage")) != "":
		spec := yamlScalar(yamlGet(c, "hackage"))
		pkg, cabal, _ := strings.Cut(spec, "@")
		i := strings.LastIndexByte(pkg, '-')
		if i <= 0 {
			res.warnf("line %d: a Hackage reference without a version", line)
			return Dependency{}, false
		}
		d.Name, d.Version = pkg[:i], pkg[i+1:]
		if hash, ok := strings.CutPrefix(cabal, "sha256:"); ok {
			hash, _, _ = strings.Cut(hash, ",")
			if dg, ok := hexDigest("sha256", hash, "cabal-file"); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
	default:
		res.warnf("line %d: a completed package of a kind this parser does not read", line)
		return Dependency{}, false
	}
	if !validHackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: a package without a usable name or version", line)
		return Dependency{}, false
	}
	return d, true
}
