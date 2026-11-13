package lockfiles

import (
	"encoding/json"
	"fmt"
	"strings"
)

// renvLock reads renv's renv.lock: the R version, the repositories
// ("R.Repositories", each a name and a URL) and a record per package —
// "Package", "Version", where it came from ("Source": Repository,
// Bioconductor, GitHub, GitLab, Bitbucket, git, URL, Local) and the remote
// fields of a package installed from a forge ("RemoteSha" is the commit).
//
// renv.lock records no hash of a package archive. The "Hash" field renv
// wrote before 1.1.0 (and still writes with RENV_LOCKFILE_VERSION=1) is its
// own MD5 over fields of the package's DESCRIPTION file — what renv compares
// installed packages by — and is not taken for a digest; since 1.1.0 a record
// carries the package's DESCRIPTION fields instead, and no Hash. A package
// from a repository is therefore unverified, one from a forge pinned by its
// commit. A record's "URL" is the DESCRIPTION's URL field, not a download.
//
// renv reads the file with an R JSON reader into named lists, where a name
// given twice is ambiguous (lookup finds the first, iteration both): a key
// repeated within an object is refused.
type renvLock struct{}

func (renvLock) Type() string            { return "cran" }
func (renvLock) Format() string          { return "renv.lock" }
func (renvLock) Detect(path string) bool { return baseName(path) == "renv.lock" }

func (renvLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	repos := map[string]string{}
	type record struct {
		key    string
		fields jsonFields
		line   int
	}
	var records []record
	sawPackages := false
	seenTop := map[string]bool{}
	err := doc.object(func(key string, _ int) error {
		if seenTop[key] {
			return fmt.Errorf("renv.lock: the key %q is repeated", key)
		}
		seenTop[key] = true
		switch key {
		case "R":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			// R looks a repository up by its name in a named list: a key or a
			// name given twice is refused, not read one way.
			return doc.object(func(k string, _ int) error {
				if k != "Repositories" || doc.peekKind() != '[' {
					return doc.skip()
				}
				return doc.array(func(_, line int) error {
					entry, err := strictFields(doc)
					if err != nil || entry == nil {
						return err
					}
					name, u := entry.str("Name"), entry.str("URL")
					if _, dup := repos[name]; dup {
						return fmt.Errorf("renv.lock line %d: the repository %q is named twice", line, name)
					}
					if name != "" && u != "" {
						repos[name] = u
					}
					return nil
				})
			})
		case "Packages":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawPackages = true
			seen := map[string]bool{}
			return doc.object(func(name string, line int) error {
				if seen[name] {
					return fmt.Errorf("renv.lock line %d: the package %q is repeated", line, name)
				}
				seen[name] = true
				f, err := strictFields(doc)
				if err != nil || f == nil {
					return err
				}
				records = append(records, record{key: name, fields: f, line: line})
				return nil
			})
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	if !sawPackages {
		return nil, errNotFormat("renv.lock", "no Packages")
	}
	unknownRepos := map[string][]string{}
	var unknownOrder []string
	for _, r := range records {
		d, ok := renvDependency(res, r.key, r.fields, repos, r.line)
		if !ok {
			continue
		}
		if repo := r.fields.str("Repository"); d.Source == SourceRegistry && d.Registry == "" && repo != "" {
			if _, seen := unknownRepos[repo]; !seen {
				unknownOrder = append(unknownOrder, repo)
			}
			unknownRepos[repo] = append(unknownRepos[repo], d.Name)
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	for _, repo := range unknownOrder {
		pkgs := unknownRepos[repo]
		more := ""
		if len(pkgs) > 5 {
			pkgs, more = pkgs[:5], ", …"
		}
		res.warnf("packages from the repository %s, whose URL R.Repositories does not give: %s%s", quoteName(repo), strings.Join(pkgs, ", "), more)
	}
	return res, nil
}

// renvForges are the hosts of the forges renv records packages from, keyed
// by "Source".
var renvForges = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}

func renvDependency(res *Result, key string, f jsonFields, repos map[string]string, line int) (Dependency, bool) {
	name := f.str("Package")
	if name == "" {
		name = key
	}
	d := Dependency{Name: name, Version: f.str("Version"), Line: line}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: %s: no usable name or version", line, key)
		return Dependency{}, false
	}
	// renv compares Source lower-cased; old lock files say "CRAN".
	source := strings.ToLower(f.str("Source"))
	switch {
	case source == "repository" || source == "cran":
		repo := f.str("Repository")
		if repo == "" && source == "cran" {
			repo = "CRAN"
		}
		if u := repos[repo]; u != "" {
			d.Registry = cleanURL(u)
		} else if isHTTPURL(repo) {
			d.Registry = cleanURL(repo)
		}
	case source == "bioconductor":
		d.Registry = "https://bioconductor.org"
	case renvForges[source] != "":
		host := renvForges[source]
		if raw := f.str("RemoteHost"); raw != "" {
			h := renvForgeHost(raw)
			if h == "" {
				// renv would download from that host; it is not one the
				// repository can be named on.
				res.warnf("%s: from %s through a host this parser cannot map to a repository", key, source)
				return Dependency{}, false
			}
			host = h
		}
		user, repo := f.str("RemoteUsername"), f.str("RemoteRepo")
		if user == "" || repo == "" || strings.ContainsAny(user+repo, "/@:") {
			res.warnf("%s: from %s without a usable repository", key, source)
			return Dependency{}, false
		}
		d.Source, d.Registry = SourceGit, "https://"+host+"/"+user+"/"+repo
		if sha := f.str("RemoteSha"); isCommitID(sha) {
			d.Revision = strings.ToLower(sha)
		}
	case source == "git" || f.str("RemoteType") == "git" || f.str("RemoteType") == "git2r":
		d.Source, d.Registry = SourceGit, cleanGitRepoURL(f.str("RemoteUrl"))
		if sha := f.str("RemoteSha"); isCommitID(sha) {
			d.Revision = strings.ToLower(sha)
		}
	case source == "url":
		d.Source, d.URL = SourceURL, cleanURL(f.str("RemoteUrl"))
	case source == "local":
		res.warnf("%s: installed from a local source, not fetched", key)
		return Dependency{}, false
	default:
		res.warnf("%s: from an unrecognised source %q", key, source)
		return Dependency{}, false
	}
	if d.Source != SourceGit {
		if f.str("Hash") != "" {
			d.UnverifiedReason = "renv.lock records no hash of the package archive (its Hash is renv's own hash of DESCRIPTION fields)"
		} else {
			d.UnverifiedReason = "renv.lock records no hash for this package"
		}
	}
	return d, true
}

// renvForgeHost returns the web host of the forge a RemoteHost names:
// "api.github.com" is github.com, "ghe.example.com/api/v3" a GitHub
// Enterprise server. It returns "" for a value that is not a host name.
func renvForgeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.Index(h, "/api/"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(h, "api.")
	if h == "" || len(h) > 253 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return ""
		}
	}
	return strings.ToLower(h)
}

// strictFields decodes the next value as an object's members, refusing a key
// that appears twice; anything but an object is skipped and yields nil.
func strictFields(doc *jsonDoc) (jsonFields, error) {
	if doc.peekKind() != '{' {
		return nil, doc.skip()
	}
	out := jsonFields{}
	err := doc.object(func(key string, line int) error {
		if _, dup := out[key]; dup {
			return fmt.Errorf("line %d: the key %q is repeated", line, key)
		}
		var v json.RawMessage
		if err := doc.value(&v); err != nil {
			return err
		}
		out[key] = v
		return nil
	})
	return out, err
}

// objs returns the member as an array of objects' members (non-objects
// dropped).
func (f jsonFields) objs(key string) []jsonFields {
	raw, ok := f[key]
	if !ok {
		return nil
	}
	var list []map[string]json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	out := make([]jsonFields, 0, len(list))
	for _, m := range list {
		if m != nil {
			out = append(out, m)
		}
	}
	return out
}
