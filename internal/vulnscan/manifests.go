package vulnscan

import (
	"encoding/xml"
	"strings"
)

// goRequire is a single Go module require directive.
type goRequire struct {
	path    string
	version string
}

// parseGoRequires extracts require directives from a go.mod file. It handles both
// the single-line form ("require path version") and the block form
// ("require (\n  path version\n)"). Indirect-dependency comments are tolerated.
// It is a focused parser (not the full go.mod grammar) sufficient to enumerate
// dependency coordinates for SBOM/vulnerability purposes.
func parseGoRequires(gomod []byte) []goRequire {
	var out []goRequire
	inBlock := false
	for _, raw := range strings.Split(string(gomod), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip trailing line comments (e.g. "// indirect").
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case inBlock:
			if line == ")" {
				inBlock = false
				continue
			}
			if r, ok := parseRequireFields(line); ok {
				out = append(out, r)
			}
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case strings.HasPrefix(line, "require "):
			if r, ok := parseRequireFields(strings.TrimPrefix(line, "require ")); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// goRequireMeta is a require directive enriched with its direct/indirect
// classification (the "// indirect" marker), used by reachability analysis.
type goRequireMeta struct {
	path     string
	version  string
	indirect bool
}

// parseGoRequiresMeta extracts require directives along with each entry's
// direct/indirect classification. The "// indirect" marker is maintained by
// `go mod tidy` and authoritatively records that no package in the module
// imports the dependency directly, so it is the primary reachability signal. The
// parser mirrors parseGoRequires' block/line handling.
func parseGoRequiresMeta(gomod []byte) []goRequireMeta {
	var out []goRequireMeta
	inBlock := false
	for _, raw := range strings.Split(string(gomod), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		indirect := false
		if i := strings.Index(line, "//"); i >= 0 {
			indirect = strings.Contains(line[i:], "indirect")
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case inBlock:
			if line == ")" {
				inBlock = false
				continue
			}
			if r, ok := parseRequireFields(line); ok {
				out = append(out, goRequireMeta{path: r.path, version: r.version, indirect: indirect})
			}
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case strings.HasPrefix(line, "require "):
			if r, ok := parseRequireFields(strings.TrimPrefix(line, "require ")); ok {
				out = append(out, goRequireMeta{path: r.path, version: r.version, indirect: indirect})
			}
		}
	}
	return out
}

// parseRequireFields parses a "path version" pair, returning ok=false when the
// line is not a well-formed require entry.
func parseRequireFields(line string) (goRequire, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return goRequire{}, false
	}
	path, version := fields[0], fields[1]
	if path == "" || !strings.HasPrefix(version, "v") {
		return goRequire{}, false
	}
	return goRequire{path: path, version: version}, true
}

// nugetDependency is a single declared NuGet dependency.
type nugetDependency struct {
	id      string
	version string
}

// nuspecPackage models the subset of the .nuspec XML schema we read. The schema
// uses an xmlns that varies by version; ignoring the namespace (via the local
// element names below) keeps the parser version-agnostic.
type nuspecPackage struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		// License is the modern <license type="expression|file">value</license>
		// element; LicenseURL is the deprecated <licenseUrl> form.
		License struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"license"`
		LicenseURL   string `xml:"licenseUrl"`
		Dependencies struct {
			// Flat dependency list (older schema).
			Dependency []nuspecDep `xml:"dependency"`
			// Grouped by target framework (newer schema).
			Group []struct {
				Dependency []nuspecDep `xml:"dependency"`
			} `xml:"group"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

type nuspecDep struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// parseNuspecDependencies extracts declared dependencies from a .nuspec document,
// flattening both the ungrouped and framework-grouped forms and de-duplicating by
// id.
func parseNuspecDependencies(nuspec []byte) []nugetDependency {
	var pkg nuspecPackage
	if err := xml.Unmarshal(nuspec, &pkg); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []nugetDependency
	add := func(d nuspecDep) {
		id := strings.TrimSpace(d.ID)
		if id == "" || seen[strings.ToLower(id)] {
			return
		}
		seen[strings.ToLower(id)] = true
		out = append(out, nugetDependency{id: id, version: strings.TrimSpace(d.Version)})
	}
	for _, d := range pkg.Metadata.Dependencies.Dependency {
		add(d)
	}
	for _, g := range pkg.Metadata.Dependencies.Group {
		for _, d := range g.Dependency {
			add(d)
		}
	}
	return out
}

// parseNuspecLicense extracts a declarable SPDX license expression from a .nuspec
// document. Only the <license type="expression"> form yields a usable SPDX
// identifier; a license file reference or a bare <licenseUrl> cannot be mapped to
// an SPDX id deterministically and is left undeclared (NOASSERTION), which the
// compliance gate flags for review.
func parseNuspecLicense(nuspec []byte) string {
	var pkg nuspecPackage
	if err := xml.Unmarshal(nuspec, &pkg); err != nil {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(pkg.Metadata.License.Type), "expression") {
		return strings.TrimSpace(pkg.Metadata.License.Value)
	}
	return ""
}
