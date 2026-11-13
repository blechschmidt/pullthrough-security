package update

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// Verify holds a rewritten lock file to the changes it was rewritten for. It
// parses the lock file at lockPath — for Go, the go.mod and go.sum of its
// directory together, merged as a scan merges them — from before and after
// with internal/lockfiles, the reader every later stage trusts, and requires:
//
//   - The files read without error after as before, with the same format
//     versions and the same warnings (line numbers aside: a rewrite may
//     change the number of hash lines).
//   - Every changed package was pinned at its old version before, and no
//     entry of it at that version is left. (go.sum keeps the old version's
//     "/go.mod" hash on purpose; internal/lockfiles reads no dependency from
//     a module that has nothing else, so the rule holds as it stands.)
//   - Every entry of it at the old version became one at the new version
//     with the same identity (registry, source) and dev flag, and with
//     exactly the digests the change's artifacts give — npm: the SHA-512 of
//     the tarball; Cargo: the SHA-256 of the .crate; pip: the SHA-256 of each
//     file; Go: the h1 of the zip and of the go.mod — or none, where the old
//     entry recorded none. An entry of the new version the file already had
//     stays, and its digests must be among the new ones. No other entry of
//     the new version appears.
//   - Every other dependency is read exactly as before: same identity, same
//     digests, same URL and dev flag, none appearing or disappearing.
//
// An npm lock file is held to these rules entry by entry (verifyNPM): npm
// installs every entry for itself, and a reading that merges the entries of a
// package version, as a scan's does, would hide one entry's change behind
// another's. One with both sections (lockfileVersion 2) has its legacy
// "dependencies" tree, which npm 6 reads and internal/lockfiles passes over
// when "packages" is there, held to them on its own. For Go, go.sum must also
// hold the new version's "/go.mod" hash, which nothing reads as a dependency.
//
// before and after hold the files keyed by repository path; after is before
// with the rewrite's files replaced. The error names the first discrepancy.
func Verify(lockPath string, before, after map[string][]byte, changes []Change) error {
	if len(changes) == 0 {
		return errors.New("no changes to verify")
	}
	paths := []string{lockPath}
	base := path.Base(lockPath)
	if base == "package-lock.json" || base == "npm-shrinkwrap.json" {
		return verifyNPM(lockPath, before, after, changes)
	}
	if base == "go.mod" || base == "go.sum" {
		dir := lockPath[:len(lockPath)-len(base)]
		paths = nil
		for _, p := range []string{dir + "go.mod", dir + "go.sum"} {
			if _, ok := before[p]; ok {
				paths = append(paths, p)
			}
		}
	}
	b, a := map[string][]byte{}, map[string][]byte{}
	for _, p := range paths {
		var ok bool
		if b[p], ok = before[p]; !ok {
			return fmt.Errorf("%s is not among the files before the rewrite", p)
		}
		if a[p], ok = after[p]; !ok {
			return fmt.Errorf("%s is not among the files after the rewrite", p)
		}
	}
	bf, af := lockfiles.ParseFiles(nil, nil, b), lockfiles.ParseFiles(nil, nil, a)
	key := ""
	for _, f := range bf {
		if f.Path == lockPath {
			key = f.Type + "/" + f.Format
		}
	}
	if key == "" {
		return fmt.Errorf("%s is not a lock file", lockPath)
	}
	v := &verifier{key: key, changes: changes}
	if err := v.check(bf, af); err != nil {
		return err
	}
	if key == "go/go.mod" || key == "go/go.sum" {
		for _, p := range paths {
			if path.Base(p) == "go.sum" {
				if err := goModHashes(a[p], changes); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// verifyNPM holds an npm lock file to the changes entry by entry.
func verifyNPM(lockPath string, before, after map[string][]byte, changes []Change) error {
	b, ok := before[lockPath]
	if !ok {
		return fmt.Errorf("%s is not among the files before the rewrite", lockPath)
	}
	a, ok := after[lockPath]
	if !ok {
		return fmt.Errorf("%s is not among the files after the rewrite", lockPath)
	}
	v := &verifier{key: "npm/" + path.Base(lockPath), changes: changes}
	if err := v.consistent(); err != nil {
		return err
	}
	if err := v.entries(lockfiles.ParseEntries(nil, nil, lockPath, b), lockfiles.ParseEntries(nil, nil, lockPath, a)); err != nil {
		return err
	}
	lb, hasB, err := npmLegacyView(b)
	if err != nil {
		return err
	}
	la, hasA, err := npmLegacyView(a)
	if err != nil {
		return err
	}
	if hasB != hasA {
		return errors.New("the rewrite changed the lock file's sections")
	}
	if hasB {
		if err := v.entries(lockfiles.ParseEntries(nil, nil, lockPath, lb), lockfiles.ParseEntries(nil, nil, lockPath, la)); err != nil {
			return fmt.Errorf("the dependencies section: %w", err)
		}
	}
	return nil
}

// consistent checks that the changes name each old version once, of the
// format's type, and that none starts where another ends.
func (v *verifier) consistent() error {
	type nv struct{ name, version string }
	from, to := map[nv]bool{}, map[nv]bool{}
	for _, c := range v.changes {
		if lockfiles.CanonicalType(c.Type) != strings.SplitN(v.key, "/", 2)[0] {
			return fmt.Errorf("a %s change for a %s lock file", c.Type, v.key)
		}
		if c.From == c.To || from[nv{c.Name, c.From}] {
			return fmt.Errorf("the changes of %s %s contradict each other", c.Name, c.From)
		}
		from[nv{c.Name, c.From}] = true
		to[nv{c.Name, c.To}] = true
	}
	for _, c := range v.changes {
		if to[nv{c.Name, c.From}] {
			return fmt.Errorf("the changes of %s %s contradict each other", c.Name, c.From)
		}
	}
	return nil
}

// entries compares two entry-by-entry readings of an npm lock file
// (lockfiles.ParseEntries). The rewrite changes no line structure, so the
// entries pair up in order, on the same lines. An entry of a changed package
// at its old version must come out at the new version with the same identity,
// URL moved to the new version's tarball, dev flag kept, and exactly the
// digest of the bytes the proxy verified — and it must have recorded a digest
// (npm checks nothing for an entry without one). Every other entry reads
// exactly as before; one of a changed package at its new version, which the
// file had already, must be pinned with that digest only.
func (v *verifier) entries(bf, af *lockfiles.File) error {
	if bf == nil || af == nil {
		return errors.New("not an npm lock file")
	}
	if bf.Error != "" {
		return fmt.Errorf("%s could not be read before the rewrite: %s", bf.Path, bf.Error)
	}
	if af.Error != "" {
		return fmt.Errorf("%s cannot be read after the rewrite: %s", af.Path, af.Error)
	}
	if bf.FormatVersion != af.FormatVersion {
		return fmt.Errorf("%s: format version %q before the rewrite, %q after", af.Path, bf.FormatVersion, af.FormatVersion)
	}
	if err := sameWarnings(bf, af); err != nil {
		return err
	}
	if len(bf.Dependencies) != len(af.Dependencies) {
		return fmt.Errorf("%d entries before the rewrite, %d after", len(bf.Dependencies), len(af.Dependencies))
	}
	type nv struct{ name, version string }
	byFrom, byTo := map[nv]*Change{}, map[nv]*Change{}
	for i := range v.changes {
		c := &v.changes[i]
		byFrom[nv{c.Name, c.From}] = c
		byTo[nv{c.Name, c.To}] = c
	}
	moved := map[*Change]int{}
	for i := range bf.Dependencies {
		d0, d1 := bf.Dependencies[i], af.Dependencies[i]
		if d0.Line != d1.Line {
			return fmt.Errorf("%s %s on line %d is on line %d after the rewrite", d0.Name, d0.Version, d0.Line, d1.Line)
		}
		c := byFrom[nv{d0.Name, d0.Version}]
		if c == nil {
			if fingerprint(d0) != fingerprint(d1) {
				return fmt.Errorf("%s %s (%s line %d) is not read as before the rewrite", d0.Name, d0.Version, d0.File, d0.Line)
			}
			if pre := byTo[nv{d0.Name, d0.Version}]; pre != nil {
				ds, err := changeDigests(v.key, *pre)
				if err != nil {
					return err
				}
				for _, dg := range d0.Digests {
					if !containsDigest(ds, dg) {
						return fmt.Errorf("%s %s was already pinned with %s, which is not a digest of the bytes the proxy verified (line %d)", d0.Name, d0.Version, dg, d0.Line)
					}
				}
			}
			continue
		}
		if d0.Source != lockfiles.SourceRegistry {
			return fmt.Errorf("%s %s (line %d) is pinned from a %s source, which a native rewrite does not move", c.Name, c.From, d0.Line, d0.Source)
		}
		if len(d0.Digests) == 0 {
			return fmt.Errorf("%s %s (line %d) recorded no digest, so nothing would check the bytes installed for %s", c.Name, c.From, d0.Line, c.To)
		}
		want := d0
		want.Version = c.To
		ds, err := changeDigests(v.key, *c)
		if err != nil {
			return err
		}
		want.Digests = ds
		if want.URL, err = npmMovedURL(d0.URL, *c); err != nil {
			return err
		}
		switch {
		case d1.Name == c.Name && d1.Version == c.From:
			return fmt.Errorf("%s %s is still pinned after the rewrite (line %d)", c.Name, c.From, d0.Line)
		case d1.Key() != want.Key():
			return fmt.Errorf("%s %s comes from %s after the rewrite, not %s (line %d)", d1.Name, d1.Version, sourceOf(d1), sourceOf(want), d0.Line)
		case !sameDigests(digestSet(want.Digests), digestSet(d1.Digests)):
			return fmt.Errorf("%s %s is pinned with the digests %s after the rewrite, not %s (line %d)", c.Name, c.To,
				digestList(digestSet(d1.Digests)), digestList(digestSet(want.Digests)), d0.Line)
		case d1.Dev != want.Dev:
			return fmt.Errorf("%s %s: the rewrite changed whether it is development-only (line %d)", c.Name, c.To, d0.Line)
		case d1.URL != want.URL:
			return fmt.Errorf("%s %s is downloaded from another URL after the rewrite (line %d)", c.Name, c.To, d0.Line)
		case fingerprint(want) != fingerprint(d1):
			return fmt.Errorf("%s %s is not read as intended after the rewrite (line %d)", c.Name, c.To, d0.Line)
		}
		moved[c]++
	}
	for i := range v.changes {
		if moved[&v.changes[i]] == 0 {
			return fmt.Errorf("the lock file did not pin %s %s before the rewrite", v.changes[i].Name, v.changes[i].From)
		}
	}
	return nil
}

// npmMovedURL returns the download URL a moved npm entry is read with: the
// registry tarball URL of the new version ("" where the entry recorded none).
func npmMovedURL(u string, c Change) (string, error) {
	if u == "" {
		return "", nil
	}
	base := c.Name[strings.LastIndexByte(c.Name, '/')+1:]
	prefix, ok := strings.CutSuffix(u, "/-/"+base+"-"+c.From+".tgz")
	if !ok {
		return "", fmt.Errorf("%s %s: the entry's URL is not a registry tarball of that version", c.Name, c.From)
	}
	return prefix + "/-/" + base + "-" + c.To + ".tgz", nil
}

// verifier compares the reading of files before and after a rewrite.
type verifier struct {
	key     string // the format, "<type>/<format>"
	changes []Change
}

// lineNumber matches the line numbers warnings carry.
var lineNumber = regexp.MustCompile(`\bline \d+`)

func (v *verifier) check(bf, af []*lockfiles.File) error {
	if len(bf) != len(af) {
		return fmt.Errorf("%d lock files read before the rewrite, %d after", len(bf), len(af))
	}
	var bdeps, adeps []lockfiles.Dependency
	for i := range bf {
		b, a := bf[i], af[i]
		if b.Path != a.Path || b.Type != a.Type || b.Format != a.Format {
			return fmt.Errorf("%s was read as %s/%s before the rewrite and %s as %s/%s after", b.Path, b.Type, b.Format, a.Path, a.Type, a.Format)
		}
		if b.Error != "" {
			return fmt.Errorf("%s could not be read before the rewrite: %s", b.Path, b.Error)
		}
		if a.Error != "" {
			return fmt.Errorf("%s cannot be read after the rewrite: %s", a.Path, a.Error)
		}
		if b.FormatVersion != a.FormatVersion {
			return fmt.Errorf("%s: format version %q before the rewrite, %q after", a.Path, b.FormatVersion, a.FormatVersion)
		}
		if err := sameWarnings(b, a); err != nil {
			return err
		}
		bdeps = append(bdeps, b.Dependencies...)
		adeps = append(adeps, a.Dependencies...)
	}
	return v.dependencies(bdeps, adeps)
}

// sameWarnings compares the warnings of a file, line numbers aside.
func sameWarnings(b, a *lockfiles.File) error {
	count := map[string]int{}
	for _, w := range b.Warnings {
		count[lineNumber.ReplaceAllString(w, "line N")]++
	}
	for _, w := range a.Warnings {
		n := lineNumber.ReplaceAllString(w, "line N")
		if count[n] == 0 {
			return fmt.Errorf("%s: a new warning after the rewrite: %s", a.Path, w)
		}
		count[n]--
	}
	var gone []string
	for w, n := range count {
		if n > 0 {
			gone = append(gone, w)
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		return fmt.Errorf("%s: a warning is gone after the rewrite: %s", a.Path, gone[0])
	}
	return nil
}

// moved is what the entries of a changed package of one identity — from
// one registry or source — must come out as at the new version.
type moved struct {
	label string
	// fromDigests says an old entry recorded digests; pre holds the digests
	// of an entry of the new version the file had already, hasPre whether it
	// had one.
	fromDigests bool
	pre         map[lockfiles.Digest]bool
	hasPre      bool
	// dev: all the entries are development-only. url: the old entry's;
	// preURLs those of the entries of the new version the file had already.
	dev     bool
	url     string
	preURLs []string
}

// arrived is what the entries of one identity came out as.
type arrived struct {
	digests map[lockfiles.Digest]bool
	dev     bool
	url     string
}

// dependencies compares the dependencies of the files.
func (v *verifier) dependencies(bdeps, adeps []lockfiles.Dependency) error {
	type nv struct{ name, version string }
	from, to := map[nv]bool{}, map[nv]bool{}
	for _, c := range v.changes {
		if lockfiles.CanonicalType(c.Type) != strings.SplitN(v.key, "/", 2)[0] {
			return fmt.Errorf("a %s change for a %s lock file", c.Type, v.key)
		}
		if c.From == c.To || from[nv{c.Name, c.From}] {
			return fmt.Errorf("the changes of %s %s contradict each other", c.Name, c.From)
		}
		from[nv{c.Name, c.From}] = true
		to[nv{c.Name, c.To}] = true
	}
	for _, c := range v.changes {
		if to[nv{c.Name, c.From}] {
			return fmt.Errorf("the changes of %s %s contradict each other", c.Name, c.From)
		}
	}
	changed := func(d lockfiles.Dependency) bool {
		return from[nv{d.Name, d.Version}] || to[nv{d.Name, d.Version}]
	}

	// Every other dependency, exactly as before.
	others := map[string]int{}
	label := map[string]string{}
	for _, d := range bdeps {
		if !changed(d) {
			fp := fingerprint(d)
			others[fp]++
			label[fp] = d.Name + " " + d.Version
		}
	}
	for _, d := range adeps {
		if changed(d) {
			continue
		}
		fp := fingerprint(d)
		if others[fp] == 0 {
			return fmt.Errorf("%s %s (%s) is not read as before the rewrite", d.Name, d.Version, d.File)
		}
		others[fp]--
	}
	var gone []string
	for fp, n := range others {
		if n > 0 {
			gone = append(gone, label[fp])
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		return fmt.Errorf("%s is not read as before the rewrite", gone[0])
	}

	// The changed packages.
	for i := range v.changes {
		c := &v.changes[i]
		want := map[string]*moved{}
		var keys []string
		at := func(k string) *moved {
			m := want[k]
			if m == nil {
				m = &moved{label: c.Name + " " + c.To, pre: map[lockfiles.Digest]bool{}, dev: true}
				want[k] = m
				keys = append(keys, k)
			}
			return m
		}
		pinned := false
		for _, d := range bdeps {
			if d.Name != c.Name {
				continue
			}
			switch d.Version {
			case c.From:
				if d.Source != lockfiles.SourceRegistry {
					return fmt.Errorf("%s %s is pinned from a %s source (%s), which a native rewrite does not move", c.Name, c.From, d.Source, d.File)
				}
				pinned = true
				m := at(keyAt(d, c.To))
				m.fromDigests = m.fromDigests || len(d.Digests) > 0
				m.dev = m.dev && d.Dev
				if m.url == "" {
					m.url = d.URL
				}
			case c.To:
				m := at(d.Key())
				m.hasPre = true
				m.dev = m.dev && d.Dev
				m.preURLs = append(m.preURLs, d.URL)
				for _, dg := range d.Digests {
					m.pre[dg] = true
				}
			}
		}
		if !pinned {
			return fmt.Errorf("the lock file did not pin %s %s before the rewrite", c.Name, c.From)
		}
		got := map[string]*arrived{}
		for _, d := range adeps {
			if d.Name != c.Name {
				continue
			}
			switch d.Version {
			case c.From:
				return fmt.Errorf("%s %s is still pinned after the rewrite (%s)", c.Name, c.From, d.File)
			case c.To:
				k := d.Key()
				if want[k] == nil {
					return fmt.Errorf("%s %s appears from %s after the rewrite, where no entry of %s moved", c.Name, c.To, sourceOf(d), c.From)
				}
				g := got[k]
				if g == nil {
					g = &arrived{digests: map[lockfiles.Digest]bool{}, dev: true, url: d.URL}
					got[k] = g
				}
				g.dev = g.dev && d.Dev
				for _, dg := range d.Digests {
					g.digests[dg] = true
				}
			}
		}
		for _, k := range keys {
			m, g := want[k], got[k]
			if g == nil {
				return fmt.Errorf("%s is not pinned after the rewrite", m.label)
			}
			expected, err := v.expected(c, m)
			if err != nil {
				return err
			}
			if !sameDigests(expected, g.digests) {
				return fmt.Errorf("%s is pinned with the digests %s after the rewrite, not %s", m.label, digestList(g.digests), digestList(expected))
			}
			if g.dev != m.dev {
				return fmt.Errorf("%s: the rewrite changed whether it is development-only", m.label)
			}
			// The URL read for the identity is its first entry's: the moved
			// one's, or one the file had already.
			if g.url != replaceLast(m.url, c.From, c.To) && !containsString(m.preURLs, g.url) {
				return fmt.Errorf("%s is downloaded from another URL after the rewrite", m.label)
			}
		}
	}
	return nil
}

// expected returns the digests the entries of one identity must have after
// the rewrite: the change's, where the old entries recorded any, and those of
// an entry of the new version the file already had — which must be among the
// change's.
func (v *verifier) expected(c *Change, m *moved) (map[lockfiles.Digest]bool, error) {
	out := map[lockfiles.Digest]bool{}
	if !m.fromDigests && len(m.pre) == 0 {
		return out, nil
	}
	ds, err := changeDigests(v.key, *c)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		if m.fromDigests {
			out[d] = true
		}
	}
	for d := range m.pre {
		if !containsDigest(ds, d) {
			return nil, fmt.Errorf("%s was already pinned with %s, which is not a digest of the bytes the proxy verified", m.label, d)
		}
		out[d] = true
	}
	return out, nil
}

// changeDigests returns the digests a format records for a change's new
// version, as internal/lockfiles reports them.
func changeDigests(key string, c Change) ([]lockfiles.Digest, error) {
	switch key {
	case "npm/package-lock.json", "npm/npm-shrinkwrap.json":
		a, err := onlyArtifact(c, "package")
		if err != nil {
			return nil, err
		}
		v, ok := hexDigest(a.SHA512, 64)
		if !ok {
			return nil, fmt.Errorf("%s %s: the package artifact has no SHA-512", c.Name, c.To)
		}
		return []lockfiles.Digest{{Algorithm: "sha512", Value: v}}, nil
	case "cargo/Cargo.lock":
		a, err := onlyArtifact(c, "package")
		if err != nil {
			return nil, err
		}
		v, err := sha256Of(c, a)
		if err != nil {
			return nil, err
		}
		return []lockfiles.Digest{{Algorithm: "sha256", Value: v}}, nil
	case "pip/requirements.txt":
		hs, err := pipHashes(c)
		if err != nil {
			return nil, err
		}
		out := make([]lockfiles.Digest, len(hs))
		for i, h := range hs {
			out[i] = lockfiles.Digest{Algorithm: "sha256", Value: h}
		}
		return out, nil
	case "go/go.mod", "go/go.sum":
		var out []lockfiles.Digest
		for _, role := range []string{"package", "go.mod"} {
			h, err := goSumHash(c, role)
			if err != nil {
				return nil, err
			}
			d := lockfiles.Digest{Algorithm: "h1", Value: strings.TrimPrefix(h, "h1:")}
			if role == "go.mod" {
				d.Of = "go.mod"
			}
			out = append(out, d)
		}
		return out, nil
	}
	return nil, fmt.Errorf("Verify does not know the digests %s records", key)
}

// goModHashes checks that go.sum holds the new versions' go.mod hashes, which
// the go command needs to load the module graph and internal/lockfiles reads
// as no dependency.
func goModHashes(sum []byte, changes []Change) error {
	for _, c := range changes {
		want, err := goSumHash(c, "go.mod")
		if err != nil {
			return err
		}
		found := false
		for off := 0; off < len(sum); {
			l, _ := nextLine(sum, off)
			off = l.next
			f := strings.Fields(string(sum[l.start:l.end]))
			if len(f) == 3 && f[0] == c.Name && f[1] == c.To+"/go.mod" {
				if f[2] != want {
					return fmt.Errorf("go.sum holds another hash of the go.mod of %s %s", c.Name, c.To)
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("go.sum does not hold the hash of the go.mod of %s %s", c.Name, c.To)
		}
	}
	return nil
}

// npmLegacyView returns an npm lock file with its "packages" key renamed
// away, so that internal/lockfiles reads its "dependencies" tree instead —
// when it has both sections.
func npmLegacyView(data []byte) ([]byte, bool, error) {
	s := &jsonScanner{data: data}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		s.pos = 3
	}
	var packagesKey span
	hasPackages, hasLegacy := false, false
	err := s.object(func(key string) error {
		if s.peek() == '{' {
			switch key {
			case "packages":
				hasPackages, packagesKey = true, s.keyAt
			case "dependencies":
				hasLegacy = true
			}
		}
		return s.skip()
	})
	if err != nil {
		return nil, false, err
	}
	if !hasPackages || !hasLegacy {
		return nil, false, nil
	}
	out := append([]byte(nil), data...)
	// A key of the same length, which no reader knows.
	n := packagesKey.end - packagesKey.start
	copy(out[packagesKey.start:packagesKey.end], `"`+strings.Repeat("_", n-2)+`"`)
	return out, true, nil
}

// keyAt returns the identity of a dependency at another version.
func keyAt(d lockfiles.Dependency, version string) string {
	d.Version = version
	return d.Key()
}

// fingerprint is everything a reading says of a dependency but the line it is
// on, which a rewrite that changes the number of lines moves.
func fingerprint(d lockfiles.Dependency) string {
	ds := make([]string, len(d.Digests))
	for i, dg := range d.Digests {
		ds[i] = dg.String()
	}
	sort.Strings(ds)
	return strings.Join([]string{d.File, d.Key(), strings.Join(ds, " "), fmt.Sprint(d.Dev), d.URL, d.Upstream,
		fmt.Sprint(d.Unverified), d.UnverifiedReason}, "\x00")
}

func sourceOf(d lockfiles.Dependency) string {
	switch {
	case d.Registry != "":
		return d.Registry
	case d.Source != "":
		return d.Source
	}
	return "the default registry"
}

func digestSet(ds []lockfiles.Digest) map[lockfiles.Digest]bool {
	out := make(map[lockfiles.Digest]bool, len(ds))
	for _, d := range ds {
		out[d] = true
	}
	return out
}

func sameDigests(want, got map[lockfiles.Digest]bool) bool {
	if len(want) != len(got) {
		return false
	}
	for d := range want {
		if !got[d] {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsDigest(ds []lockfiles.Digest, d lockfiles.Digest) bool {
	for _, x := range ds {
		if x == d {
			return true
		}
	}
	return false
}

// digestList names digests for an error message, shortened.
func digestList(ds map[lockfiles.Digest]bool) string {
	if len(ds) == 0 {
		return "none"
	}
	var out []string
	for d := range ds {
		v := d.Value
		if _, err := hex.DecodeString(v); err == nil && len(v) > 16 {
			v = v[:16] + "…"
		}
		s := d.Algorithm + ":" + v
		if d.Of != "" {
			s += " (" + d.Of + ")"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// replaceLast replaces the last occurrence of old in s.
func replaceLast(s, old, new string) string {
	i := strings.LastIndex(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}
