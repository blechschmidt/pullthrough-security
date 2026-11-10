package sbomdiff

import (
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// SnapshotInput identifies the artifact a snapshot is being built for. The SBOM
// and vulnerability findings come from the vulnerability subsystem's already-
// computed report, so building a snapshot never re-reads artifact content or
// re-implements a manifest parser.
type SnapshotInput struct {
	Tenant     string
	Ecosystem  string
	Coordinate string
	Version    string
	Digest     string
	ObservedAt time.Time
}

// BuildSnapshot reduces a CycloneDX SBOM (and the vulnerabilities a scan found
// for the same artifact) to the Snapshot the diff and history store operate on.
// sbom may be nil (a metadata-only pull), in which case the snapshot carries no
// dependencies. vulns may be nil. The artifact's own primary component is
// excluded from the dependency set (it is the coordinate being diffed) but its
// declared license is captured as the snapshot's PrimaryLicense.
func BuildSnapshot(in SnapshotInput, sbom *vulnscan.SBOM, vulns []vulnscan.Vulnerability) Snapshot {
	s := Snapshot{
		Tenant:     in.Tenant,
		Ecosystem:  strings.ToLower(strings.TrimSpace(in.Ecosystem)),
		Coordinate: strings.TrimSpace(in.Coordinate),
		Version:    strings.TrimSpace(in.Version),
		Digest:     in.Digest,
		ObservedAt: in.ObservedAt,
	}

	var primaryRef string
	if sbom != nil {
		if sbom.Metadata != nil && sbom.Metadata.Component != nil {
			primary := sbom.Metadata.Component
			primaryRef = primary.BOMRef
			s.PrimaryLicense = primary.LicenseExpression()
		}
		for i := range sbom.Components {
			c := &sbom.Components[i]
			// Skip the primary component if it also appears in the components list.
			if primaryRef != "" && c.BOMRef == primaryRef {
				continue
			}
			s.Deps = append(s.Deps, Dep{
				Name:      componentName(c),
				Version:   c.Version,
				Namespace: componentNamespace(c),
				License:   c.LicenseExpression(),
				Scope:     c.Scope,
				PURL:      c.PURL,
			})
		}
	}

	for i := range vulns {
		v := vulns[i]
		if v.Withdrawn || v.Suppressed {
			continue
		}
		s.Vulns = append(s.Vulns, VulnRef{
			ID:       v.ID,
			Severity: string(v.Severity),
			Package:  v.Package,
			CVSS:     v.CVSS,
		})
	}

	s.normalize()
	return s
}

// componentName renders a component's fully-qualified name including its
// group/namespace when the ecosystem uses one (npm scope, Maven groupId, Go
// module path).
func componentName(c *vulnscan.Component) string {
	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

// componentNamespace derives the owning organisation/scope of a component: the
// CycloneDX group when present, else the namespace segment of the purl. This is
// the unit the maintainer/namespace diff keys on — a never-before-seen namespace
// is a strong dependency-confusion / hijack signal.
func componentNamespace(c *vulnscan.Component) string {
	if g := strings.TrimSpace(c.Group); g != "" {
		return g
	}
	return purlNamespace(c.PURL)
}

// purlNamespace extracts the namespace from a package URL of the form
// "pkg:type/namespace/name@version", returning "" when no namespace segment is
// present.
func purlNamespace(purl string) string {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	// Drop qualifiers/subpath and version.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		rest = rest[:i]
	}
	// rest is "type/namespace/name" or "type/name".
	parts := strings.Split(rest, "/")
	if len(parts) >= 3 {
		return strings.Join(parts[1:len(parts)-1], "/")
	}
	return ""
}
