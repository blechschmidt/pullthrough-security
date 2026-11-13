package lockfiles

import (
	"encoding/json"
	"fmt"
	"strings"
)

// packageResolved reads SwiftPM's Package.resolved, in its three versions:
//
//	1   {"object": {"pins": [{"package", "repositoryURL", "state": {...}}]}, "version": 1}
//	2   {"pins": [{"identity", "kind", "location", "state": {...}}], "version": 2}
//	3   as 2, with the "originHash" of the manifests it was resolved from
//
// A pin's state names the commit ("revision") and, for a release, its
// "version"; a pin to a branch records the branch and the commit it was at.
// Source-control pins are Git dependencies pinned by commit. A registry pin
// (kind "registry", SE-0292) records only the version: SwiftPM keeps the
// checksum of a registry release in its own fingerprint storage, not in this
// file, so such a pin is unverified here. Local packages are not fetched.
type packageResolved struct{}

func (packageResolved) Type() string            { return "swift" }
func (packageResolved) Format() string          { return "Package.resolved" }
func (packageResolved) Detect(path string) bool { return baseName(path) == "Package.resolved" }

func (packageResolved) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	var version string
	// SwiftPM decodes the file by its version: version 1 reads only
	// "object"."pins", versions 2 and 3 only the top-level "pins". Both are
	// kept, and the version picks one.
	var pinsV1, pinsV2 []swiftPin
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "version":
			v, err := jsonScalar(doc)
			version = v
			return err
		case "pins":
			var err error
			pinsV2, err = readSwiftPins(doc) // a repeated key keeps its last value
			return err
		case "object":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			return doc.object(func(k string, _ int) error {
				if k != "pins" {
					return doc.skip()
				}
				var err error
				pinsV1, err = readSwiftPins(doc)
				return err
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
	res.FormatVersion = version
	var pins []swiftPin
	switch version {
	case "1":
		pins = pinsV1
	case "2", "3":
		pins = pinsV2
	case "":
		return nil, errNotFormat("Package.resolved", "no version")
	default:
		return nil, fmt.Errorf("Package.resolved version %s, which SwiftPM does not read", quoteName(version))
	}
	for _, pin := range pins {
		if d, ok := swiftDependency(res, pin); ok {
			res.add(d)
		}
	}
	return res, nil
}

// swiftPin is one pin, in either layout.
type swiftPin struct {
	fields, state jsonFields
	line          int
}

func readSwiftPins(doc *jsonDoc) ([]swiftPin, error) {
	if doc.peekKind() != '[' {
		return nil, doc.skip()
	}
	var pins []swiftPin
	err := doc.array(func(_, line int) error {
		f, err := doc.fields()
		if err != nil || f == nil {
			return err
		}
		pins = append(pins, swiftPin{fields: f, state: f.obj("state"), line: line})
		return nil
	})
	return pins, err
}

func swiftDependency(res *Result, pin swiftPin) (Dependency, bool) {
	f, state := pin.fields, pin.state
	identity, kind, location := f.str("identity"), f.str("kind"), f.str("location")
	if location == "" && f.str("repositoryURL") != "" { // version 1
		location, kind = f.str("repositoryURL"), "remoteSourceControl"
		identity = swiftIdentity(location)
		if identity == "" {
			identity = strings.ToLower(f.str("package"))
		}
	}
	revision, version, branch := state.str("revision"), state.str("version"), state.str("branch")
	label := identity
	if label == "" {
		label = "a pin"
	}
	switch kind {
	case "localSourceControl", "fileSystem":
		res.warnf("%s: a local package, not fetched", label)
		return Dependency{}, false
	case "registry":
		d := Dependency{Name: identity, Version: version, Line: pin.line}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a registry pin without a usable identity or version", pin.line)
			return Dependency{}, false
		}
		d.UnverifiedReason = "Package.resolved records no checksum for a registry release (SwiftPM keeps it in its fingerprint storage)"
		return d, true
	case "remoteSourceControl":
	default:
		res.warnf("%s: a pin of kind %q, which this parser does not read", label, kind)
		return Dependency{}, false
	}
	d := Dependency{Name: identity, Version: version, Source: SourceGit, Registry: cleanGitRepoURL(location), Line: pin.line}
	if isCommitID(revision) {
		d.Revision = strings.ToLower(revision)
	}
	if d.Version == "" {
		d.Version = d.Revision // a branch or revision pin
	}
	if d.Revision == "" && branch != "" {
		res.warnf("%s: pinned to branch %q without a commit", label, branch)
		return Dependency{}, false
	}
	if !validPackageName(d.Name) || !validVersion(d.Version) {
		res.warnf("line %d: a pin without a usable identity, version or revision", pin.line)
		return Dependency{}, false
	}
	return d, true
}

// swiftIdentity derives SwiftPM's identity of a source-control package from
// its URL: the last path component, lower-cased, without ".git".
func swiftIdentity(location string) string {
	u := strings.TrimRight(strings.TrimSpace(location), "/")
	if i := strings.LastIndexAny(u, "/:"); i >= 0 {
		u = u[i+1:]
	}
	return strings.ToLower(strings.TrimSuffix(u, ".git"))
}

// jsonScalar decodes the next value as a string or number's text ("" for
// anything else).
func jsonScalar(doc *jsonDoc) (string, error) {
	switch doc.peekKind() {
	case '"':
		return doc.stringValue()
	case '{', '[':
		return "", doc.skip()
	}
	var raw json.RawMessage
	if err := doc.value(&raw); err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(raw))
	if s == "null" || s == "true" || s == "false" {
		return "", nil
	}
	return s, nil
}
