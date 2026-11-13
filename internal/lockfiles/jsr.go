package lockfiles

import (
	"fmt"
	"strings"
)

// denoLock reads Deno's deno.lock, whose layout changed with its version:
//
//	none      Deno before 1.28: module URL → SHA-256, the whole file
//	"2"       "remote" modules; npm under "npm": {"specifiers", "packages"}
//	"3"       "packages": {"specifiers", "jsr", "npm"}, "remote", "workspace"
//	"4", "5"  "specifiers", "jsr", "npm", "remote", "workspace" at the top
//
// Three kinds of dependency come out of it:
//
//   - JSR packages ("@std/path@1.0.8"), with the SHA-256 of the version's
//     manifest on jsr.io (<scope>/<name>/<version>_meta.json), which lists the
//     SHA-256 of every file of the version — so it pins them;
//   - npm packages ("chalk@5.3.0", peer variants "x@1.0.0_peer@2.0.0" read as
//     x 1.0.0), with the registry's Subresource Integrity, of type npm;
//   - remote modules, each a URL with the SHA-256 of the file's bytes. They
//     come from no registry: each is a dependency of type generic (an
//     operator fronts such a host with a generic upstream), named by its URL
//     without the scheme, its version the content hash ("sha256:…") — the
//     URL alone can serve other bytes tomorrow.
//
// Deno reads the file with serde, by its version: a key repeated at the top
// is an error, a repeated package keeps its last entry, and a section of
// another version's layout is refused here — Deno would ignore it, or let
// it overwrite the section it does read.
type denoLock struct{}

func (denoLock) Type() string            { return "jsr" }
func (denoLock) Format() string          { return "deno.lock" }
func (denoLock) Detect(path string) bool { return baseName(path) == "deno.lock" }

// denoEntry is a package entry with the line it starts on: the fields of a
// package, or the hash of a remote module.
type denoEntry struct {
	key    string
	fields jsonFields
	hash   string
	line   int
}

// denoSections are the package maps of one lock file, each keyed by package
// ("@std/path@1.0.8"); a repeated key keeps its last entry.
type denoSections struct {
	jsr, npm []denoEntry
	remote   []denoEntry
}

func (denoLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	// Every section is kept as it is found; the version then picks the ones
	// Deno reads for it, and a section of another version's layout is
	// refused rather than read: Deno would ignore it, or overwrite with it.
	var (
		topJsr, topNpm, nestedNpm, pkgJsr, pkgNpm, remote, bareRemote []denoEntry
		sawTopJsr, sawTopNpm, sawNested, sawPackages, sawRemote       bool
	)
	seen := map[string]bool{}
	err := doc.object(func(key string, line int) error {
		if seen[key] {
			return fmt.Errorf("deno.lock line %d: the key %q is repeated", line, key)
		}
		seen[key] = true
		switch key {
		case "version":
			v, err := jsonScalar(doc)
			res.FormatVersion = v
			return err
		case "jsr":
			sawTopJsr = true
			var err error
			topJsr, err = denoPackages(doc)
			return err
		case "npm":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawTopNpm = true
			var flat []denoEntry
			err := doc.object(func(k string, l int) error {
				switch k {
				case "packages": // version 2: {"specifiers", "packages"}
					sawNested = true
					var err error
					nestedNpm, err = denoPackages(doc)
					return err
				case "specifiers":
					sawNested = true
					return doc.skip()
				}
				f, err := doc.fields()
				if err != nil {
					return err
				}
				flat = append(flat, denoEntry{key: k, fields: f, line: l})
				return nil
			})
			topNpm = lastEntries(flat)
			return err
		case "packages":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawPackages = true
			return doc.object(func(k string, _ int) error { // version 3
				var err error
				switch k {
				case "jsr":
					pkgJsr, err = denoPackages(doc)
				case "npm":
					pkgNpm, err = denoPackages(doc)
				default:
					err = doc.skip()
				}
				return err
			})
		case "remote":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawRemote = true
			var entries []denoEntry
			err := doc.object(func(u string, l int) error {
				hash, err := doc.stringValue()
				if err != nil {
					return err
				}
				entries = append(entries, denoEntry{key: u, hash: hash, line: l})
				return nil
			})
			remote = lastEntries(entries)
			return err
		}
		if isHTTPURL(key) && doc.peekKind() == '"' {
			// Version 1 (Deno before 1.28): a flat map of module URL to hash.
			hash, err := doc.stringValue()
			bareRemote = append(bareRemote, denoEntry{key: key, hash: hash, line: line})
			return err
		}
		return doc.skip()
	})
	if err != nil {
		return nil, err
	}
	if err := doc.end(); err != nil {
		return nil, err
	}
	var sec denoSections
	foreign := ""
	switch res.FormatVersion {
	case "":
		if len(bareRemote) == 0 || sawTopJsr || sawTopNpm || sawPackages || sawRemote {
			return nil, errNotFormat("deno.lock", "no version")
		}
		res.FormatVersion = "1"
		sec.remote = lastEntries(bareRemote)
	case "2":
		sec.npm, sec.remote = nestedNpm, remote
		if sawTopJsr || sawPackages || len(topNpm) > 0 {
			foreign = "a section of a later version's layout"
		}
	case "3":
		sec.jsr, sec.npm, sec.remote = pkgJsr, pkgNpm, remote
		if sawTopJsr || sawTopNpm {
			foreign = "a top-level jsr or npm section, which version 3 keeps under packages"
		}
	case "4", "5":
		sec.jsr, sec.npm, sec.remote = topJsr, topNpm, remote
		if sawPackages || sawNested {
			foreign = "a section of an earlier version's layout"
		}
	default:
		return nil, fmt.Errorf("deno.lock version %s, which Deno does not read", quoteName(res.FormatVersion))
	}
	if foreign != "" {
		return nil, fmt.Errorf("deno.lock version %s with %s", res.FormatVersion, foreign)
	}
	if len(bareRemote) > 0 && res.FormatVersion != "1" {
		return nil, fmt.Errorf("deno.lock version %s with module URLs at the top, as version 1 wrote them", res.FormatVersion)
	}
	for _, e := range sec.jsr {
		name, version, ok := splitNameAtLast(e.key)
		if !ok || !strings.HasPrefix(name, "@") || !validPackageName(name) || !validVersion(version) {
			res.warnf("line %d: a JSR package without a usable name or version", e.line)
			continue
		}
		d := Dependency{Type: "jsr", Name: name, Version: version, Line: e.line}
		if dg, ok := hexDigest("sha256", e.fields.str("integrity"), "jsr-manifest"); ok {
			d.Digests = append(d.Digests, dg)
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	for _, e := range sec.npm {
		name, version, ok := splitNameAt(e.key)
		if ok {
			version, _, _ = strings.Cut(version, "_") // a peer-dependency variant
		}
		if !ok || !validPackageName(name) || !validVersion(version) {
			res.warnf("line %d: an npm package without a usable name or version", e.line)
			continue
		}
		d := Dependency{Type: "npm", Name: name, Version: version, Line: e.line, Digests: sriDigests(e.fields.str("integrity"))}
		if t := e.fields.str("tarball"); t != "" {
			d.URL = cleanURL(t)
			if base, ok := npmRegistryBase(t, name); ok {
				d.Registry = base
			} else {
				d.Source = SourceURL
			}
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	for _, e := range sec.remote {
		dg, ok := hexDigest("sha256", e.hash, "")
		if !ok || !isHTTPURL(e.key) {
			res.warnf("line %d: a remote module without a URL or a SHA-256", e.line)
			continue
		}
		clean := cleanURL(e.key)
		name := clean[strings.Index(clean, "://")+3:]
		if !validPackageName(name) {
			res.warnf("line %d: a remote module whose URL is not usable", e.line)
			continue
		}
		res.Dependencies = append(res.Dependencies, Dependency{
			Type: "generic", Name: name, Version: "sha256:" + dg.Value, Source: SourceURL,
			URL: clean, Digests: []Digest{dg}, Line: e.line,
		})
	}
	return res, nil
}

// denoPackages reads a map of package entries; a repeated key keeps its last
// entry.
func denoPackages(doc *jsonDoc) ([]denoEntry, error) {
	if doc.peekKind() != '{' {
		return nil, doc.skip()
	}
	var entries []denoEntry
	err := doc.object(func(k string, l int) error {
		f, err := doc.fields()
		if err != nil {
			return err
		}
		entries = append(entries, denoEntry{key: k, fields: f, line: l})
		return nil
	})
	return lastEntries(entries), err
}

// lastEntries drops every entry a later one with the same key replaces.
func lastEntries(entries []denoEntry) []denoEntry {
	last := map[string]int{}
	for i, e := range entries {
		last[e.key] = i
	}
	out := entries[:0]
	for i, e := range entries {
		if last[e.key] == i {
			out = append(out, e)
		}
	}
	return out
}
