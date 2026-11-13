package lockfiles

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// gitmodules reads a repository's .gitmodules: the submodules it declares,
// each with the path it is checked out at and the URL of its repository. A
// submodule's commit is not in the file: it is the gitlink — a tree entry of
// mode 160000 — at the submodule's path. Parse records the declarations; the
// scan pins each to its gitlink (joinSubmodules) and only then is it a
// dependency: type "git", named by its path, its version and revision the
// commit, its registry the repository URL.
//
// Git reads .gitmodules only at the root of the tree, with its configuration
// syntax (git-config(1)): a file git cannot read (a bad line, an unknown
// escape) is an error here too. A key given twice for one submodule is read
// differently by different git commands — the first value from a commit, the
// last from a checkout — so such a submodule is left out with a warning
// rather than guessed at; so are the names, paths and URLs git itself ignores
// (a ".." name, a value starting with "-").
type gitmodules struct{}

// gitmodulesPath is where git reads .gitmodules: the root of the tree.
const gitmodulesPath = ".gitmodules"

func (gitmodules) Type() string            { return "git" }
func (gitmodules) Format() string          { return ".gitmodules" }
func (gitmodules) Detect(path string) bool { return path == gitmodulesPath }

// submoduleDecl is one submodule .gitmodules declares.
type submoduleDecl struct {
	name, path, url, branch string
	// line is the line of the submodule's first section header.
	line int
}

// maxSubmodules bounds the declarations read from one file: each costs a
// tree lookup when the scan pins it.
const maxSubmodules = 5000

func (gitmodules) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New(".gitmodules is not valid UTF-8")
	}
	entries, err := parseGitConfig(string(data))
	if err != nil {
		return nil, err
	}
	res := &Result{}
	type state struct {
		decl  submoduleDecl
		seen  map[string]bool
		twice string
	}
	var order []string
	byName := map[string]*state{}
	for _, e := range entries {
		if e.section != "submodule" || !e.hasSub {
			continue
		}
		st := byName[e.sub]
		if st == nil {
			if len(order) == maxSubmodules {
				res.warnf("more than %d submodules declared; the rest are not read", maxSubmodules)
				break
			}
			st = &state{decl: submoduleDecl{name: e.sub, line: e.headerLine}, seen: map[string]bool{}}
			byName[e.sub] = st
			order = append(order, e.sub)
		}
		switch e.key {
		case "path", "url", "branch":
		default:
			continue
		}
		if st.seen[e.key] && st.twice == "" {
			st.twice = e.key
		}
		st.seen[e.key] = true
		switch e.key {
		case "path":
			st.decl.path = e.value
		case "url":
			st.decl.url = e.value
		case "branch":
			st.decl.branch = e.value
		}
	}
	byPath := map[string]int{}
	for _, name := range order {
		st := byName[name]
		d := st.decl
		switch {
		case !validSubmoduleName(name):
			res.warnf("line %d: a submodule name git ignores as suspicious", d.line)
			continue
		case st.twice != "":
			res.warnf("submodule %q: %s is set twice, and git commands disagree on which value counts; left out", name, st.twice)
			continue
		case d.path == "" || d.url == "":
			res.warnf("submodule %q: no path or no URL", name)
			continue
		case strings.HasPrefix(d.path, "-") || strings.HasPrefix(d.url, "-"):
			res.warnf("submodule %q: a path or URL that looks like a command-line option, which git ignores", name)
			continue
		}
		clean, ok := cleanSubmodulePath(d.path)
		if !ok {
			res.warnf("submodule %q: its path is not a path inside the repository", name)
			continue
		}
		d.path = clean
		if why := submoduleURLProblem(d.url); why != "" {
			res.warnf("submodule %q: %s", name, why)
			continue
		}
		if i, dup := byPath[d.path]; dup {
			res.warnf("submodule %q: its path is also another submodule's; both are left out", name)
			if i >= 0 {
				res.submodules[i] = submoduleDecl{}
				byPath[d.path] = -1
			}
			continue
		}
		byPath[d.path] = len(res.submodules)
		res.submodules = append(res.submodules, d)
	}
	kept := res.submodules[:0]
	for _, d := range res.submodules {
		if d.path != "" {
			kept = append(kept, d)
		}
	}
	res.submodules = kept
	return res, nil
}

// validSubmoduleName applies git's check_submodule_name: not empty, and no
// ".." path component (the name becomes a directory under .git/modules).
func validSubmoduleName(name string) bool {
	if name == "" {
		return false
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return false
		}
	}
	return true
}

// cleanSubmodulePath checks a submodule path is one a gitlink can be named
// by: relative, slash-separated, without empty, "." or ".." components and
// without control characters. It is kept as written.
func cleanSubmodulePath(p string) (string, bool) {
	if p == "" || len(p) > 4096 || strings.ContainsAny(p, "\\\x00") {
		return "", false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	// Git maps a submodule to the gitlink at exactly this path: one with a
	// trailing slash, an empty, "." or ".." component maps to nothing.
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false
		}
	}
	return p, true
}

// submoduleURLProblem says why a submodule URL is not one the proxy could
// fetch through its Git upstream, or "" when it is: a network URL (https,
// http, ssh, git), an scp-like "host:path", or a URL relative to the
// superproject's remote ("../other.git").
func submoduleURLProblem(u string) string {
	if strings.ContainsAny(u, "\x00\n\r") {
		return "its URL holds a line break"
	}
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"),
		strings.HasPrefix(lower, "ssh://"), strings.HasPrefix(lower, "git://"),
		strings.HasPrefix(lower, "git+ssh://"), strings.HasPrefix(lower, "ssh+git://"):
		return ""
	case strings.HasPrefix(u, "./"), strings.HasPrefix(u, "../"):
		return ""
	case strings.HasPrefix(lower, "file:"), strings.HasPrefix(u, "/"):
		return "its URL is a local path, not fetched"
	case strings.Contains(u, "::"):
		return "its URL names a remote helper (transport::address), not fetched"
	case strings.Contains(u, "://"):
		return "its URL uses a transport the Git upstream does not serve"
	}
	// scp-like syntax: [user@]host:path, with no slash before the colon.
	if i := strings.IndexByte(u, ':'); i > 0 && !strings.Contains(u[:i], "/") {
		return ""
	}
	return "its URL is a local path, not fetched"
}

// submoduleWarnings bounds how many unpinned or undeclared submodules are
// named one by one.
const submoduleWarnings = 50

// joinSubmodules makes the submodules a .gitmodules file declares into
// dependencies, each pinned to the commit of the gitlink at its path, which
// gitlinkAt finds in the tree ("" when there is none). Only submodules under
// root ("" for the whole tree) are kept. links are the gitlinks the walk
// found; those no declaration names are returned, for the caller to report.
func joinSubmodules(f *File, gitlinkAt func(path string) (string, error), root string, links []Submodule) ([]Submodule, error) {
	declared := map[string]bool{}
	var unpinned []string
	for _, d := range f.submodules {
		if !underRoot(d.path, root) {
			continue
		}
		declared[d.path] = true
		commit, err := gitlinkAt(d.path)
		if err != nil {
			return nil, err
		}
		if commit == "" {
			unpinned = append(unpinned, d.name)
			continue
		}
		dep := Dependency{
			Type:     "git",
			Name:     d.path,
			Version:  commit,
			Source:   SourceGit,
			Registry: cleanGitRepoURL(d.url),
			Revision: strings.ToLower(commit),
			File:     f.Path,
			Line:     d.line,
		}
		if strings.HasPrefix(d.url, "./") || strings.HasPrefix(d.url, "../") {
			f.addWarning(fmt.Sprintf("submodule %q: its URL is relative to the superproject's own remote", d.name))
		}
		f.Dependencies = append(f.Dependencies, dep)
	}
	for i, name := range unpinned {
		if i == submoduleWarnings {
			f.addWarning(fmt.Sprintf("… and %d more submodules without a gitlink", len(unpinned)-i))
			break
		}
		f.addWarning(fmt.Sprintf("submodule %q: the tree has no gitlink at its path, so no commit pins it", name))
	}
	var undeclared []Submodule
	for _, l := range links {
		if !declared[l.Path] {
			undeclared = append(undeclared, l)
		}
	}
	return undeclared, nil
}

// underRoot reports whether p is root or inside it.
func underRoot(p, root string) bool {
	return root == "" || p == root || strings.HasPrefix(p, root+"/")
}
