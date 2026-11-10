package maven

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// The POM (Project Object Model) is the canonical descriptor of a Maven
// artifact. Parsing it lets the proxy feed authoritative coordinates,
// dependencies, and license declarations into the existing supply-chain gates:
//
//   - The effective GAV (groupId:artifactId:version) is the artifact's identity
//     for nameguard, policy, provenance, vulnscan, and policyengine. A POM whose
//     declared coordinate disagrees with the path it was served from is a
//     supply-chain red flag (a repository serving foo's bytes at bar's path), so
//     the backend cross-checks them.
//
//   - Declared <licenses> feed the license-compliance gate for JVM artifacts
//     that ship no SBOM of their own.
//
//   - Declared <dependencies> populate the provenance/dependency graph.
//
// groupId and version may be inherited from the <parent> element rather than
// declared directly; the parser resolves that fallback. Full property
// interpolation and transitive parent resolution are out of scope (they require
// fetching the parent chain); the parser records the raw, possibly
// property-templated values when they cannot be resolved locally.

// POM is the parsed, partially-resolved form of a pom.xml.
type POM struct {
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string
	Parent     *POMParent
	Licenses   []POMLicense
	// Dependencies are the direct <dependencies> entries (compile-scope and
	// otherwise); test/provided scopes are retained with their Scope set so
	// callers can filter.
	Dependencies []POMDependency
}

// POMParent is the <parent> coordinate a POM may inherit groupId/version from.
type POMParent struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// POMLicense is one declared <license>.
type POMLicense struct {
	Name string
	URL  string
}

// POMDependency is one declared <dependency> coordinate.
type POMDependency struct {
	GroupID    string
	ArtifactID string
	Version    string
	Scope      string
	Optional   bool
}

// xmlPOM mirrors the subset of the POM schema the proxy consumes.
type xmlPOM struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Packaging  string   `xml:"packaging"`
	Parent     *struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	Licenses []struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	} `xml:"licenses>license"`
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
		Optional   string `xml:"optional"`
	} `xml:"dependencies>dependency"`
}

// maxPOMBytes bounds POM parsing memory. A POM is text and rarely exceeds a few
// hundred KiB even for large aggregator projects.
const maxPOMBytes = 8 << 20 // 8 MiB

// ParsePOM decodes a pom.xml document into a POM, resolving groupId/version
// inheritance from <parent> when they are not declared directly. A document that
// is not well-formed XML, or whose root is not <project>, is an error.
func ParsePOM(data []byte) (*POM, error) {
	if len(data) > maxPOMBytes {
		return nil, fmt.Errorf("maven: POM exceeds %d bytes", maxPOMBytes)
	}
	var x xmlPOM
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("maven: parsing pom.xml: %w", err)
	}
	if x.XMLName.Local != "project" {
		return nil, fmt.Errorf("maven: pom.xml root element is %q, want \"project\"", x.XMLName.Local)
	}

	p := &POM{
		GroupID:    strings.TrimSpace(x.GroupID),
		ArtifactID: strings.TrimSpace(x.ArtifactID),
		Version:    strings.TrimSpace(x.Version),
		Packaging:  strings.TrimSpace(x.Packaging),
	}
	if x.Parent != nil {
		p.Parent = &POMParent{
			GroupID:    strings.TrimSpace(x.Parent.GroupID),
			ArtifactID: strings.TrimSpace(x.Parent.ArtifactID),
			Version:    strings.TrimSpace(x.Parent.Version),
		}
		// groupId and version are inherited from the parent when omitted; artifactId
		// is always the child's own.
		if p.GroupID == "" {
			p.GroupID = p.Parent.GroupID
		}
		if p.Version == "" {
			p.Version = p.Parent.Version
		}
	}
	if p.Packaging == "" {
		p.Packaging = "jar" // Maven's default packaging.
	}
	for _, l := range x.Licenses {
		name := strings.TrimSpace(l.Name)
		url := strings.TrimSpace(l.URL)
		if name == "" && url == "" {
			continue
		}
		p.Licenses = append(p.Licenses, POMLicense{Name: name, URL: url})
	}
	for _, d := range x.Dependencies {
		dep := POMDependency{
			GroupID:    strings.TrimSpace(d.GroupID),
			ArtifactID: strings.TrimSpace(d.ArtifactID),
			Version:    strings.TrimSpace(d.Version),
			Scope:      strings.TrimSpace(d.Scope),
			Optional:   strings.EqualFold(strings.TrimSpace(d.Optional), "true"),
		}
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		p.Dependencies = append(p.Dependencies, dep)
	}
	return p, nil
}

// Coordinate returns the POM's GAV name ("groupId:artifactId"), or "" when
// either component is unresolved.
func (p *POM) Coordinate() string {
	if p.GroupID == "" || p.ArtifactID == "" {
		return ""
	}
	return p.GroupID + ":" + p.ArtifactID
}

// matchesPath reports whether the POM's declared coordinate agrees with the GAV
// derived from the path it was served at. A value templated with an unresolved
// property (e.g. "${revision}") is treated as agreeing, since it cannot be
// compared locally without the parent chain. It is used as a supply-chain
// integrity signal, not a hard gate (the path GAV remains authoritative for
// admission).
func (p *POM) matchesPath(groupID, artifactID, version string) bool {
	if p.ArtifactID != "" && p.ArtifactID != artifactID {
		return false
	}
	if p.GroupID != "" && !isUnresolvedProperty(p.GroupID) && p.GroupID != groupID {
		return false
	}
	if p.Version != "" && !isUnresolvedProperty(p.Version) && p.Version != version {
		return false
	}
	return true
}

// isUnresolvedProperty reports whether a POM field still contains a Maven
// property reference ("${...}") that the local parser cannot interpolate.
func isUnresolvedProperty(s string) bool {
	return strings.Contains(s, "${")
}
