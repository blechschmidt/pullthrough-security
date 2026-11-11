// Package scancoverage is the catalog of how every upstream type's artifacts
// reach the LLM content scans: which request paths carry something a client
// installs or runs, in which format, and over which serve path — and which
// paths are documents the scan leaves alone.
//
// It is data, kept in one place for three readers:
//
//   - docs/llm-package-scan-coverage.md is generated from it
//     (`make llmscan-coverage-gen`), so the published coverage table is the
//     catalog and cannot drift from it;
//   - a test in cmd/pullthrough builds every backend the way the server does
//     and resolves each example path against it, so the catalog cannot drift
//     from what the backends actually classify;
//   - that same test fails when an upstream type the configuration accepts has
//     no entry here, so a backend added later cannot be left out of the scan —
//     or of this table — without someone deciding so.
//
// The package deliberately imports nothing from the backends or the gate: it is
// read by a documentation generator and must stay cheap to link.
package scancoverage

import (
	"fmt"
	"sort"
	"strings"
)

// Gates an upstream type's content is examined by.
const (
	// GatePackageScan is the LLM package-content scan (internal/llmpkgscan): the
	// model reviews the unpacked artifact before it is served.
	GatePackageScan = "llm-package-scan"
	// GateCommitScan is the LLM commit scan (internal/scan/commit): the model
	// reviews the commits of watched repositories and of the commits packages
	// were built from. It examines; it does not refuse a clone or fetch.
	GateCommitScan = "llm-commit-scan"
)

// Classes a backend gives a resolved request (backends.ArtifactClass).
const (
	ClassPayload      = "payload"
	ClassMetadata     = "metadata"
	ClassUnclassified = "unclassified"
)

// Kinds refining a class (backends.ArtifactKind).
const (
	KindArchive      = ""              // an ordinary artifact: an archive is expected
	KindFile         = "file"          // a payload that may be a single file
	KindIndexArchive = "index-archive" // metadata that is itself an archive of data files
	KindOCIManifest  = "oci-manifest"
	KindOCIBlob      = "oci-blob"
)

// Serve paths: how the bytes of a request reach the client, and with it where
// the gate sits.
const (
	// ServeCache: fetched into the content cache and served from the entry. The
	// gate runs on the entry before any byte is written, on a hit as on a miss.
	ServeCache = "cache"
	// ServeDirect: not cached; streamed from the upstream. The response is held
	// in a spool until the verdict exists, then served from the spool.
	ServeDirect = "direct"
	// ServeLFS: a Git LFS object, served by the Git backend from the content
	// cache. The gate is that backend's serve gate, consulted on every request.
	ServeLFS = "git-lfs"
	// ServeGit: Git smart-HTTP / SSH traffic, served by the Git backend itself,
	// with no admission gate. Its commits are the commit scan's to judge, not the
	// package scan's; a verdict there does not refuse the clone.
	ServeGit = "git"
)

// Path is one kind of request an upstream type answers.
type Path struct {
	// What names the resource in the ecosystem's own terms.
	What string
	// Example is a request path below /v1/<upstream>, as a client sends it.
	Example string
	// Class and Kind are what the backend states for it.
	Class string
	Kind  string
	// Format is the artifact format (for a payload): what the unpacker opens.
	Format string
	// Serve is the serve path.
	Serve string
}

// Entry describes one upstream type.
type Entry struct {
	// Type is the upstream type as configured; Aliases are its other accepted
	// names ("deb" for "apt").
	Type    string
	Aliases []string
	// Title is the ecosystem's display name.
	Title string
	// Gate is the LLM scan that examines this type's content.
	Gate string
	// Ecosystem is the key the type is scoped by in llmPackageScan.include /
	// exclude. Empty when the package scan does not apply to the type.
	Ecosystem string
	// Settings are the upstream settings the examples assume (see
	// config.UpstreamConfig.Settings); nil for none.
	Settings map[string]string
	// Routes are the routes of the declarative ("generic") backend the examples
	// assume. A generic upstream serves what its operator declares, so its
	// coverage is stated for a representative configuration.
	Routes []Route
	// Paths lists the type's request paths: every kind of payload, and the
	// documents served next to them.
	Paths []Path
	// Notes are caveats worth a sentence each.
	Notes []string
}

// Route is one route of a declarative backend's configuration
// (generic.RouteConfig), reduced to what decides coverage.
type Route struct {
	Name      string
	Match     string
	Cacheable bool
	Rewrite   bool
	Gates     []string
}

// Payloads returns the entry's payload paths.
func (e Entry) Payloads() []Path {
	var out []Path
	for _, p := range e.Paths {
		if p.Class == ClassPayload {
			out = append(out, p)
		}
	}
	return out
}

// Catalog returns the entries, sorted by type. The slice is a copy.
func Catalog() []Entry {
	out := append([]Entry(nil), catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Lookup returns the entry for an upstream type, by its name or an alias.
func Lookup(upstreamType string) (Entry, bool) {
	t := strings.ToLower(strings.TrimSpace(upstreamType))
	for _, e := range catalog {
		if e.Type == t {
			return e, true
		}
		for _, a := range e.Aliases {
			if a == t {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// Validate checks the catalog's own consistency: unique types and aliases,
// known enum values, and no entry that claims the package scan without naming a
// payload. It does not check the entries against the backends — the test in
// cmd/pullthrough does, with the real ones.
func Validate() error {
	seen := map[string]string{}
	claim := func(name, owner string) error {
		if prev, dup := seen[name]; dup {
			return fmt.Errorf("scancoverage: %q is claimed by both %q and %q", name, prev, owner)
		}
		seen[name] = owner
		return nil
	}
	for _, e := range catalog {
		if e.Type == "" || e.Title == "" {
			return fmt.Errorf("scancoverage: an entry has no type or title: %+v", e)
		}
		if err := claim(e.Type, e.Type); err != nil {
			return err
		}
		for _, a := range e.Aliases {
			if err := claim(a, e.Type); err != nil {
				return err
			}
		}
		switch e.Gate {
		case GatePackageScan:
			if e.Ecosystem == "" {
				return fmt.Errorf("scancoverage: %s is examined by the package scan but names no ecosystem key", e.Type)
			}
			if len(e.Payloads()) == 0 {
				return fmt.Errorf("scancoverage: %s is examined by the package scan but lists no payload path", e.Type)
			}
		case GateCommitScan:
		default:
			return fmt.Errorf("scancoverage: %s has unknown gate %q", e.Type, e.Gate)
		}
		for _, p := range e.Paths {
			if p.What == "" || p.Example == "" {
				return fmt.Errorf("scancoverage: %s has a path without a description or an example: %+v", e.Type, p)
			}
			switch p.Class {
			case ClassPayload:
				if p.Format == "" {
					return fmt.Errorf("scancoverage: %s payload %q names no format", e.Type, p.What)
				}
			case ClassMetadata, ClassUnclassified:
			default:
				return fmt.Errorf("scancoverage: %s path %q has unknown class %q", e.Type, p.What, p.Class)
			}
			switch p.Kind {
			case KindArchive, KindFile, KindIndexArchive, KindOCIManifest, KindOCIBlob:
			default:
				return fmt.Errorf("scancoverage: %s path %q has unknown kind %q", e.Type, p.What, p.Kind)
			}
			if p.Kind == KindIndexArchive && p.Class != ClassMetadata {
				return fmt.Errorf("scancoverage: %s path %q: only metadata is an index archive", e.Type, p.What)
			}
			switch p.Serve {
			case ServeCache, ServeDirect, ServeLFS, ServeGit:
			default:
				return fmt.Errorf("scancoverage: %s path %q has unknown serve path %q", e.Type, p.What, p.Serve)
			}
		}
	}
	return nil
}
