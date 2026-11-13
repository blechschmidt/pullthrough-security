package update

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// npmUpdater rewrites package-lock.json and npm-shrinkwrap.json (the same
// format under the name npm publishes it with). Every entry of a changed
// package at the old version moves to the new one — in lockfileVersion 2 and
// 3 the "packages" entries, at any depth of node_modules; in versions 1 and 2
// the nested "dependencies" tree — and gets the new version's tarball URL and
// integrity. Version 2 carries both sections, for npm 6 and for npm 7 and
// later: both are rewritten, and must agree on how many entries move.
type npmUpdater struct{ file string }

func (u npmUpdater) Key() string { return "npm/" + u.file }

// npmChange is a change with what its entries get.
type npmChange struct {
	Change
	// integrity is the new tarball's Subresource Integrity; integrityErr says
	// why there is none, which fails an entry that records one.
	integrity    string
	integrityErr error
	// matched counts the entries moved in each section.
	inPackages, inLegacy int
	// registry is the registry the moved entries' tarballs come from: the
	// proxy vetted the package of one registry, and an entry from another
	// does not move under that vetting.
	registry string
}

func (u npmUpdater) Apply(lockPath string, files map[string][]byte, changes []Change) (map[string][]byte, error) {
	if path.Base(lockPath) != u.file {
		return nil, fmt.Errorf("%s is not a %s", lockPath, u.file)
	}
	data, ok := files[lockPath]
	if !ok {
		return nil, fmt.Errorf("%s is not among the files", lockPath)
	}
	if err := checkChanges("npm", changes, npmName, semverToken); err != nil {
		return nil, err
	}
	r := &npmRewrite{byName: map[string][]*npmChange{}}
	for _, c := range changes {
		nc := &npmChange{Change: c}
		nc.integrity, nc.integrityErr = npmIntegrity(c)
		r.byName[c.Name] = append(r.byName[c.Name], nc)
		r.changes = append(r.changes, nc)
	}
	if err := r.scan(data); err != nil {
		return nil, err
	}
	for _, c := range r.changes {
		switch {
		case r.hasPackages && r.hasLegacy && c.inPackages != c.inLegacy:
			return nil, fmt.Errorf("%s %s: the lock file's packages section has %d entries of it, its dependencies section %d",
				c.Name, c.From, c.inPackages, c.inLegacy)
		case c.inPackages+c.inLegacy == 0:
			return nil, fmt.Errorf("%s %s is not in the lock file", c.Name, c.From)
		}
	}
	out, err := splice(data, r.edits)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{lockPath: out}, nil
}

// npmName accepts the bytes of npm package names, scoped ones included.
func npmName(s string) bool { return tokenOf(s, "@/._~-") }

// npmIntegrity returns the integrity npm records for the change's tarball:
// "sha512-" and the base64 of its SHA-512.
func npmIntegrity(c Change) (string, error) {
	a, err := onlyArtifact(c, "package")
	if err != nil {
		return "", err
	}
	v, ok := hexDigest(a.SHA512, 64)
	if !ok {
		return "", fmt.Errorf("%s %s: the package artifact has no SHA-512", c.Name, c.To)
	}
	raw, _ := hex.DecodeString(v)
	return "sha512-" + base64.StdEncoding.EncodeToString(raw), nil
}

// npmRewrite collects the edits of one lock file.
type npmRewrite struct {
	changes []*npmChange
	byName  map[string][]*npmChange
	edits   []edit
	// hasPackages and hasLegacy record which sections the file has, as
	// objects: internal/lockfiles and npm read "packages" when it is there,
	// npm 6 the "dependencies" tree.
	hasPackages, hasLegacy bool
}

// npmEntry is what the rewrite reads of an entry of either section.
type npmEntry struct {
	version, resolved, integrity, name jsonField
	link, inBundle, bundled            jsonField
}

func (r *npmRewrite) scan(data []byte) error {
	s := &jsonScanner{data: data}
	// A byte order mark is not content (npm and internal/lockfiles drop it).
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		s.pos = 3
	}
	seen := map[string]bool{}
	err := s.object(func(key string) error {
		if key != "packages" && key != "dependencies" {
			return s.skip()
		}
		if seen[key] {
			return fmt.Errorf("the lock file has two %q sections", key)
		}
		seen[key] = true
		if s.peek() != '{' {
			return s.skip()
		}
		if key == "packages" {
			r.hasPackages = true
			return r.packages(s)
		}
		r.hasLegacy = true
		return r.legacy(s)
	})
	if err != nil {
		return err
	}
	if err := s.end(); err != nil {
		return err
	}
	if !r.hasPackages && !r.hasLegacy {
		return errors.New("not an npm lock file: no packages and no dependencies")
	}
	return nil
}

// packages reads the "packages" section: install paths and their entries.
func (r *npmRewrite) packages(s *jsonScanner) error {
	seen := map[string]bool{}
	return s.object(func(installPath string) error {
		if seen[installPath] {
			return fmt.Errorf("the lock file lists %q twice", installPath)
		}
		seen[installPath] = true
		if s.peek() != '{' {
			return s.skip()
		}
		var e npmEntry
		err := s.object(func(field string) error {
			switch field {
			case "version":
				return s.field(&e.version)
			case "resolved":
				return s.field(&e.resolved)
			case "integrity":
				return s.field(&e.integrity)
			case "name":
				return s.field(&e.name)
			case "link":
				return s.field(&e.link)
			case "inBundle":
				return s.field(&e.inBundle)
			}
			return s.skip()
		})
		if err != nil {
			return err
		}
		return r.packageEntry(installPath, &e)
	})
}

// packageEntry moves a "packages" entry if it is a changed package at its old
// version. As internal/lockfiles reads the section: the root ("") is the
// project, a path outside node_modules a workspace folder, a link points at
// one, a bundled package ships inside its parent; none of those is fetched.
// The package is the one the "name" member names (an alias's real package),
// else the one its path ends in.
func (r *npmRewrite) packageEntry(installPath string, e *npmEntry) error {
	if installPath == "" || e.link.isTrue || e.inBundle.isTrue {
		return nil
	}
	i := strings.LastIndex(installPath, "node_modules/")
	if i < 0 {
		return nil
	}
	name := installPath[i+len("node_modules/"):]
	if e.name.isString && e.name.value != "" {
		name = e.name.value
	}
	c := r.change(name, e.version)
	if c == nil {
		return nil
	}
	c.inPackages++
	return r.move(c, e, c.To)
}

// legacy reads a "dependencies" tree (lockfileVersion 1 and 2), recursing into
// the nested ones.
func (r *npmRewrite) legacy(s *jsonScanner) error {
	seen := map[string]bool{}
	return s.object(func(key string) error {
		if seen[key] {
			return fmt.Errorf("the lock file lists %q twice in one dependencies object", key)
		}
		seen[key] = true
		if s.peek() != '{' {
			return s.skip()
		}
		var e npmEntry
		nested := false
		err := s.object(func(field string) error {
			switch field {
			case "version":
				return s.field(&e.version)
			case "resolved":
				return s.field(&e.resolved)
			case "integrity":
				return s.field(&e.integrity)
			case "bundled":
				return s.field(&e.bundled)
			case "dependencies":
				if nested {
					return fmt.Errorf("an entry of %q has two dependencies objects", key)
				}
				nested = true
				if s.peek() != '{' {
					return s.skip()
				}
				return r.legacy(s)
			}
			return s.skip()
		})
		if err != nil {
			return err
		}
		return r.legacyEntry(key, &e)
	})
}

// legacyEntry moves an entry of the dependencies tree if it is a changed
// package at its old version. A bundled entry ships inside its parent's
// tarball and is not fetched. An alias names its real package in the version
// ("npm:string-width@4.2.3"), and keeps doing so.
func (r *npmRewrite) legacyEntry(key string, e *npmEntry) error {
	if e.bundled.isTrue || !e.version.isString {
		return nil
	}
	name, version, alias := key, e.version.value, false
	if rest, ok := strings.CutPrefix(version, "npm:"); ok {
		if i := strings.LastIndexByte(rest, '@'); i > 0 {
			name, version, alias = rest[:i], rest[i+1:], true
		}
	}
	c := r.change(name, jsonField{isString: true, value: version})
	if c == nil {
		return nil
	}
	c.inLegacy++
	to := c.To
	if alias {
		to = "npm:" + name + "@" + c.To
	}
	return r.move(c, e, to)
}

// change returns the change of the package at the entry's version, if any.
func (r *npmRewrite) change(name string, version jsonField) *npmChange {
	if !version.isString {
		return nil
	}
	for _, c := range r.byName[name] {
		if c.From == version.value {
			return c
		}
	}
	return nil
}

// move writes the edits that move an entry: its version, its tarball URL
// where it records one, and its integrity, which it must record — npm checks
// the bytes it installs against it, and an entry without one would take
// whatever its registry serves for the new version.
func (r *npmRewrite) move(c *npmChange, e *npmEntry, version string) error {
	if e.version.repeated || e.resolved.repeated || e.integrity.repeated || e.name.repeated {
		return fmt.Errorf("%s %s: an entry repeats a key", c.Name, c.From)
	}
	r.edits = append(r.edits, edit{e.version.at.start, e.version.at.end, jsonString(version)})
	if e.resolved.present {
		if !e.resolved.isString {
			return fmt.Errorf("%s %s: an entry's resolved is not a string", c.Name, c.From)
		}
		moved, registry, err := npmTarballURL(e.resolved.value, c.Change)
		if err != nil {
			return err
		}
		switch {
		case c.registry == "":
			c.registry = registry
		case c.registry != registry:
			return fmt.Errorf("%s %s comes from two registries (%s, %s)", c.Name, c.From, c.registry, registry)
		}
		r.edits = append(r.edits, edit{e.resolved.at.start, e.resolved.at.end, jsonString(moved)})
	}
	if !e.integrity.present {
		return fmt.Errorf("%s %s: an entry records no integrity, so nothing would check the bytes npm installs for %s", c.Name, c.From, c.To)
	}
	if !e.integrity.isString {
		return fmt.Errorf("%s %s: an entry's integrity is not a string", c.Name, c.From)
	}
	if !readableIntegrity(e.integrity.value) {
		return fmt.Errorf("%s %s: an entry's integrity is not one the updater reads", c.Name, c.From)
	}
	if c.integrityErr != nil {
		return c.integrityErr
	}
	r.edits = append(r.edits, edit{e.integrity.at.start, e.integrity.at.end, jsonString(c.integrity)})
	return nil
}

// npmTarballURL moves a registry tarball URL to the new version. A registry
// serves a package's tarballs as "<registry>/<name>/-/<base>-<version>.tgz",
// the base name being the name without its scope; internal/lockfiles takes
// the registry from what precedes "/<name>/-/" (npmRegistryBase), and so does
// this. Anything else — a Git repository, a local path, a tarball elsewhere,
// a URL with a query or a fragment — is not rewritten: the new version's
// digests would end up on an entry fetched from somewhere the proxy never
// fetched from.
//
// It also returns the registry: the URL before the package's name.
func npmTarballURL(resolved string, c Change) (moved, registry string, err error) {
	fail := fmt.Errorf("%s %s: the entry's resolved URL is not a registry tarball of that version", c.Name, c.From)
	lower := strings.ToLower(resolved)
	if (!strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://")) || strings.ContainsAny(resolved, "?#") {
		return "", "", fail
	}
	base := c.Name[strings.LastIndexByte(c.Name, '/')+1:]
	prefix, ok := strings.CutSuffix(resolved, "/-/"+base+"-"+c.From+".tgz")
	if !ok {
		return "", "", fail
	}
	registry, ok = npmRegistryOf(prefix, c.Name)
	if !ok {
		return "", "", fail
	}
	return prefix + "/-/" + base + "-" + c.To + ".tgz", registry, nil
}

// npmScopedEscape matches the escaped spellings of a scoped name's slash.
var npmScopedEscape = regexp.MustCompile(`(?i)%2f`)

// npmRegistryOf reports whether the path of a tarball URL before "/-/" ends
// in the package's name as internal/lockfiles recognises it — as written, with
// the scope's slash escaped, or escaped altogether ("%40scope%2fname") — and
// returns what precedes the name: the registry.
func npmRegistryOf(before, name string) (string, bool) {
	for _, spelled := range []string{name, strings.Replace(name, "/", "%2f", 1), strings.Replace(name, "/", "%2F", 1)} {
		if reg, ok := strings.CutSuffix(before, "/"+spelled); ok {
			return reg, true
		}
	}
	j := strings.LastIndex(before, "/")
	if j < 0 {
		return "", false
	}
	if u, err := url.PathUnescape(npmScopedEscape.ReplaceAllString(before[j+1:], "/")); err == nil && u == name {
		return before[:j], true
	}
	if k := strings.LastIndex(before[:j], "/"); k >= 0 && strings.HasPrefix(name, "@") {
		if u, err := url.PathUnescape(before[k+1:]); err == nil && u == name {
			return before[:k], true
		}
	}
	return "", false
}
