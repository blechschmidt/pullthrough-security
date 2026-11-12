package lockfiles

import (
	"encoding/json"
	"strings"
)

// nugetLock reads NuGet's packages.lock.json: per target framework, every
// package with its resolved version and content hash. The same package
// version appears once per framework; it is one dependency.
//
// NuGet's contentHash is the SHA-512 of the package as NuGet hashes it —
// leaving a signed package's signature file out — so it does not equal the
// hash of the .nupkg bytes the registry serves (Digest.Of "nuget-content").
type nugetLock struct{}

func (nugetLock) Type() string   { return "nuget" }
func (nugetLock) Format() string { return "packages.lock.json" }

// Detect accepts packages.lock.json and the per-project spelling
// packages.<project>.lock.json (NuGetLockFilePath).
func (nugetLock) Detect(path string) bool {
	name := baseName(path)
	return name == "packages.lock.json" || (strings.HasPrefix(name, "packages.") && strings.HasSuffix(name, ".lock.json"))
}

type nugetEntry struct {
	Type        lenientString `json:"type"`
	Resolved    lenientString `json:"resolved"`
	ContentHash lenientString `json:"contentHash"`
}

func (nugetLock) Parse(data []byte) (*Result, error) {
	doc := newJSONDoc(data)
	res := &Result{}
	sawDeps := false
	err := doc.object(func(key string, _ int) error {
		switch key {
		case "version":
			var v json.RawMessage
			if err := doc.value(&v); err != nil {
				return err
			}
			res.FormatVersion = strings.Trim(string(v), `"`)
			return nil
		case "dependencies":
			if doc.peekKind() != '{' {
				return doc.skip()
			}
			sawDeps = true
			return doc.object(func(_ string, _ int) error { // target framework
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				return doc.object(func(id string, line int) error {
					if doc.peekKind() != '{' {
						return doc.skip()
					}
					var e nugetEntry
					if err := doc.value(&e); err != nil {
						return err
					}
					if strings.EqualFold(string(e.Type), "Project") {
						return nil // a project reference, built here
					}
					name := strings.ToLower(id)
					if !validPackageName(name) || !validVersion(string(e.Resolved)) {
						res.warnf("line %d: a package without a usable id or resolved version", line)
						return nil
					}
					d := Dependency{Name: name, Version: string(e.Resolved), Line: line}
					if dg, ok := base64Digest("sha512", string(e.ContentHash), "nuget-content"); ok {
						d.Digests = append(d.Digests, dg)
					}
					res.Dependencies = append(res.Dependencies, d)
					return nil
				})
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
	if !sawDeps && res.FormatVersion == "" {
		return nil, errNotFormat("packages.lock.json", "no version and no dependencies")
	}
	return res, nil
}

// errNotFormat says a file is not in the format its name promises.
func errNotFormat(format, why string) error {
	return &formatError{format: format, why: why}
}

type formatError struct{ format, why string }

func (e *formatError) Error() string { return "not a " + e.format + ": " + e.why }
