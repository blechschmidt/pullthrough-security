package lockfiles

import (
	"sort"
	"strings"
)

// brewfileLock reads Brewfile.lock.json, which `brew bundle` wrote next to a
// Brewfile from 2019 until homebrew-bundle stopped writing it in November
// 2024 (Homebrew 4.4.8 was the last release that did); such files are still
// committed. "entries" holds an object per entry type:
//
//	brew    formula → {"version", "bottle": {"rebuild", "root_url",
//	        "files": {<tag>: {"cellar", "url", "sha256"}}}} — every
//	        platform's bottle, or "bottle": false for a formula built from
//	        source
//	cask    cask → {"version", "options"}            no hash
//	tap     tap → {"revision"}                       the tap's Git commit
//	mas, whalebrew, vscode                           not Homebrew packages
//
// A bottle's sha256 is the SHA-256 of the bottle tarball, which is also its
// blob digest on ghcr.io; each platform's bottle is one digest of the
// formula, Digest.Of naming the file
// ("<name>--<version>.<tag>.bottle[.<rebuild>].tar.gz").
type brewfileLock struct{}

func (brewfileLock) Type() string            { return "homebrew" }
func (brewfileLock) Format() string          { return "Brewfile.lock.json" }
func (brewfileLock) Detect(path string) bool { return baseName(path) == "Brewfile.lock.json" }

func (brewfileLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	sawEntries := false
	var deps []Dependency
	err := doc.object(func(key string, _ int) error {
		if key != "entries" || doc.peekKind() != '{' {
			return doc.skip()
		}
		sawEntries = true
		deps = nil // a repeated key keeps its last value
		return doc.object(func(kind string, _ int) error {
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			byName := map[string]int{}
			return doc.object(func(name string, line int) error {
				f, err := doc.fields()
				if err != nil {
					return err
				}
				d, ok := brewEntry(res, kind, name, f, line)
				if i, dup := byName[name]; dup {
					deps[i] = Dependency{} // superseded by this entry
				}
				if ok {
					byName[name] = len(deps)
					deps = append(deps, d)
				}
				return nil
			})
		})
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if !sawEntries {
		return nil, errNotFormat("Brewfile.lock.json", "no entries")
	}
	res.Dependencies = dropSuperseded(deps)
	return res, nil
}

func brewEntry(res *Result, kind, name string, f jsonFields, line int) (Dependency, bool) {
	switch kind {
	case "brew":
		d := Dependency{Name: name, Version: f.str("version"), Line: line}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a formula without a usable name or version", line)
			return Dependency{}, false
		}
		bottle := f.obj("bottle")
		if bottle == nil {
			d.UnverifiedReason = "Brewfile.lock.json records no bottle for this formula: it is built from source, and nothing pins the source archive"
			return d, true
		}
		rebuild := strings.TrimSpace(string(bottle["rebuild"]))
		files := bottle.obj("files")
		tags := make([]string, 0, len(files))
		for tag := range files {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			file := files.obj(tag)
			if file == nil || !brewTag(tag) {
				continue
			}
			of := name + "--" + d.Version + "." + tag + ".bottle"
			if rebuild != "" && rebuild != "0" && strings.Trim(rebuild, "0123456789") == "" {
				of += "." + rebuild
			}
			if dg, ok := hexDigest("sha256", file.str("sha256"), of+".tar.gz"); ok {
				d.Digests = append(d.Digests, dg)
			}
		}
		if u := bottle.str("root_url"); isHTTPURL(u) {
			d.Registry = cleanURL(u)
		}
		return d, true
	case "cask":
		d := Dependency{Name: name, Version: f.str("version"), Line: line,
			UnverifiedReason: "Brewfile.lock.json records no hash for a cask (the cask's definition has one, the lock file does not)"}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a cask without a usable name or version", line)
			return Dependency{}, false
		}
		return d, true
	case "tap":
		rev := strings.ToLower(f.str("revision"))
		user, repo, ok := strings.Cut(name, "/")
		if !ok || !flakePart(user) || !flakePart(repo) || strings.Contains(repo, "/") {
			res.warnf("line %d: a tap without a usable name", line)
			return Dependency{}, false
		}
		if !isCommitID(rev) {
			res.warnf("line %d: tap %s: no commit recorded", line, quoteName(name))
			return Dependency{}, false
		}
		// A tap "user/repo" is the repository github.com/user/homebrew-repo.
		return Dependency{Name: name, Version: rev, Source: SourceGit, Revision: rev, Line: line,
			Registry: "https://github.com/" + user + "/homebrew-" + strings.TrimPrefix(repo, "homebrew-")}, true
	}
	res.warnf("line %d: a %s entry, which is not a Homebrew package", line, kind)
	return Dependency{}, false
}

// brewTag reports whether s can be a bottle tag ("arm64_sonoma",
// "x86_64_linux", "all").
func brewTag(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
