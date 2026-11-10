package dossier

import (
	"strconv"
	"strings"
)

// ident is the normalized artifact identity a dossier pivots on. coord is the
// canonical "name@version" (or bare name when no version is known). When
// versioned is false the dossier aggregates every version of the named package.
type ident struct {
	eco       string
	name      string
	version   string
	coord     string
	versioned bool
}

// parseIdent normalizes a Query into an ident. The coordinate may be a bare
// name or "name@version"; an explicit Version field takes precedence over a
// version embedded in the coordinate. A leading "ecosystem/" qualifier on the
// coordinate is stripped so "npm/lodash@4.17.21" and "lodash@4.17.21" agree.
func parseIdent(q Query) ident {
	eco := strings.TrimSpace(q.Ecosystem)
	name, ver := splitCoordinate(eco, q.Coordinate)
	if v := strings.TrimSpace(q.Version); v != "" {
		ver = v
	}
	id := ident{eco: eco, name: name, version: ver}
	id.coord = canonicalCoord(name, ver)
	id.versioned = ver != "" && name != ""
	return id
}

// splitCoordinate parses "name@version" into its parts, tolerating scoped npm
// names (@scope/pkg@1.0.0) by splitting on the LAST '@', and stripping a leading
// "ecosystem/" qualifier.
func splitCoordinate(eco, coordinate string) (name, version string) {
	c := strings.TrimSpace(coordinate)
	if c == "" {
		return "", ""
	}
	if eco != "" {
		c = strings.TrimPrefix(c, eco+"/")
	}
	if i := strings.LastIndexByte(c, '@'); i > 0 { // i>0 keeps a leading '@scope' intact
		return strings.TrimSpace(c[:i]), strings.TrimSpace(c[i+1:])
	}
	return c, ""
}

// canonicalCoord renders the canonical join coordinate.
func canonicalCoord(name, version string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if v := strings.TrimSpace(version); v != "" {
		return name + "@" + v
	}
	return name
}

// matches reports whether a candidate artifact identity belongs to this
// dossier's coordinate. Ecosystem must agree when both sides specify one. When
// the query is versioned, the candidate version must match exactly; otherwise
// any version of the named package matches.
func (id ident) matches(eco, name, version, coordinate string) bool {
	if id.eco != "" && eco != "" && !strings.EqualFold(id.eco, eco) {
		return false
	}
	cname, cver := name, version
	if cname == "" {
		cname, cver = splitCoordinate(eco, coordinate)
		if version != "" {
			cver = version
		}
	}
	cname = strings.TrimSpace(cname)
	if cname == "" || !strings.EqualFold(cname, id.name) {
		return false
	}
	if id.versioned {
		return strings.EqualFold(strings.TrimSpace(cver), id.version)
	}
	return true
}

// pluralize renders "<n> <noun>" with a naive plural 's' suffix.
func pluralize(n int, noun string) string {
	s := strconv.Itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}

// trimFloat renders a float without a trailing ".0" for whole numbers.
func trimFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
}
