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
			res.Dependencies = nil                          // a repeated key keeps its last value
			return doc.object(func(_ string, _ int) error { // target framework
				if doc.peekKind() != '{' {
					return doc.skip()
				}
				byID := map[string]int{}
				first := len(res.Dependencies)
				err := doc.object(func(id string, line int) error {
					e, err := doc.fields()
					if err != nil || e == nil {
						return err
					}
					if i, dup := byID[id]; dup {
						res.Dependencies[i] = Dependency{} // superseded
					}
					if strings.EqualFold(e.str("type"), "Project") {
						return nil // a project reference, built here
					}
					name := strings.ToLower(id)
					if !validPackageName(name) || !validVersion(e.str("resolved")) {
						res.warnf("line %d: a package without a usable id or resolved version", line)
						return nil
					}
					d := Dependency{Name: name, Version: e.str("resolved"), Line: line}
					if dg, ok := base64Digest("sha512", e.str("contentHash"), "nuget-content"); ok {
						d.Digests = append(d.Digests, dg)
					}
					byID[id] = len(res.Dependencies)
					res.add(d)
					return nil
				})
				res.Dependencies = append(res.Dependencies[:first], dropSuperseded(res.Dependencies[first:])...)
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
