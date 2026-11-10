package vexexport

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// coordinate is a normalized artifact selector used to scope posture gathering
// and to render product references.
type coordinate struct {
	ecosystem string
	name      string
	version   string
	raw       string // original coordinate string / digest, used for findings lookup
}

// newCoordinate builds a coordinate, splitting a raw "ecosystem:name@version" or
// "name@version" string when the name is not supplied separately.
func newCoordinate(eco, name, version, raw string) coordinate {
	eco = strings.TrimSpace(eco)
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	raw = strings.TrimSpace(raw)
	if name == "" && raw != "" {
		e, n, v := splitCoordinate(raw)
		if eco == "" {
			eco = e
		}
		name = n
		version = v
	}
	return coordinate{ecosystem: eco, name: name, version: version, raw: raw}
}

// lookup returns the string a findings store is keyed by for this coordinate.
func (c coordinate) lookup() string {
	if c.raw != "" {
		return c.raw
	}
	if c.name != "" {
		if c.version != "" {
			return c.name + "@" + c.version
		}
		return c.name
	}
	return ""
}

// key is the dedup/sort key for a coordinate (case-insensitive).
func (c coordinate) key() string {
	if c.name != "" {
		return strings.ToLower(c.ecosystem + ":" + c.name + "@" + c.version)
	}
	return strings.ToLower(c.raw)
}

// purl renders the Package-URL for the coordinate, or "" when the name is
// unknown (digest-only selector).
func (c coordinate) purl() string {
	if c.name == "" {
		return ""
	}
	return vulnscan.PackageURL(c.ecosystem, c.name, c.version)
}

// productRef builds the product reference an exported statement uses for this
// coordinate: the purl when derivable, else the raw digest/identifier.
func (c coordinate) productRef() vulnscan.VEXProductRef {
	if p := c.purl(); p != "" {
		return vulnscan.VEXProductRef{ID: p, Name: c.lookup()}
	}
	return vulnscan.VEXProductRef{ID: c.raw}
}

// splitCoordinate decomposes an "ecosystem:name@version" or "name@version"
// string. A bare purl ("pkg:...") is left to the raw-identifier path (empty
// name/version returned).
func splitCoordinate(s string) (eco, name, version string) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(strings.ToLower(s), "pkg:") {
		return "", "", ""
	}
	rest := s
	// An "ecosystem:" prefix (no "@" or "/" in the candidate ecosystem segment).
	if i := strings.Index(s, ":"); i > 0 {
		head := s[:i]
		if !strings.ContainsAny(head, "@/") {
			eco = head
			rest = s[i+1:]
		}
	}
	name = rest
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name = rest[:i]
		version = rest[i+1:]
	}
	return eco, name, version
}

// coordinateSet dedups coordinates by their case-insensitive key.
type coordinateSet struct {
	m map[string]coordinate
}

func newCoordinateSet() *coordinateSet { return &coordinateSet{m: make(map[string]coordinate)} }

func (s *coordinateSet) add(c coordinate) {
	k := c.key()
	if k == "" {
		return
	}
	if _, ok := s.m[k]; !ok {
		s.m[k] = c
	}
}

func (s *coordinateSet) sorted() []coordinate {
	out := make([]coordinate, 0, len(s.m))
	for _, c := range s.m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func coordinatesFromEntries(entries []snapshot.Entry, tenant string) []coordinate {
	set := newCoordinateSet()
	for _, e := range entries {
		if !tenantMatches(tenant, e.Tenant) {
			continue
		}
		set.add(newCoordinate(e.Ecosystem, e.Name, e.Version, e.Coordinate))
	}
	return set.sorted()
}

// tenantMatches reports whether a (possibly empty) wanted tenant covers an
// entry's tenant. An empty wanted tenant matches everything; a public
// (tenant-independent) entry matches any wanted tenant.
func tenantMatches(want, have string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	have = strings.TrimSpace(have)
	if have == "" {
		return true
	}
	return strings.EqualFold(want, have)
}

// --- statement coverage / dedup / ordering ----------------------------------

// statementCovers reports whether a corpus statement applies to a coordinate,
// via a tolerant product-reference comparison (purl, bare name, or raw digest).
func statementCovers(st vulnscan.VEXStatement, c coordinate) bool {
	purl := c.purl()
	purlNoVer := stripPurlVersion(purl)
	for _, p := range st.Products {
		if productCovers(p, c, purl, purlNoVer) {
			return true
		}
		for _, sub := range p.Subcomponents {
			if productCovers(sub, c, purl, purlNoVer) {
				return true
			}
		}
	}
	return false
}

func productCovers(p vulnscan.VEXProductRef, c coordinate, purl, purlNoVer string) bool {
	id := strings.TrimSpace(p.ID)
	name := strings.TrimSpace(p.Name)
	if id != "" {
		if purl != "" && strings.EqualFold(id, purl) {
			return true
		}
		if purlNoVer != "" && strings.EqualFold(stripPurlVersion(id), purlNoVer) {
			return true
		}
		if c.raw != "" && strings.EqualFold(id, c.raw) {
			return true
		}
		if c.name != "" && strings.EqualFold(id, c.name) {
			return true
		}
	}
	if name != "" && c.name != "" && strings.EqualFold(name, c.name) {
		return true
	}
	return false
}

func stripPurlVersion(purl string) string {
	if purl == "" {
		return ""
	}
	if i := strings.LastIndex(purl, "@"); i > len("pkg:") {
		return purl[:i]
	}
	return purl
}

// statementKey is the dedup key for an exported statement: the advisory id plus
// the set of product identifiers. Status is intentionally excluded so a
// higher-priority source (the corpus) wins over a lower one for the same
// (vulnerability, product) pair.
func statementKey(st vulnscan.VEXStatement) string {
	ids := make([]string, 0, len(st.Products))
	for _, p := range st.Products {
		v := p.ID
		if v == "" {
			v = p.Name
		}
		ids = append(ids, strings.ToLower(strings.TrimSpace(v)))
	}
	sort.Strings(ids)
	return strings.ToLower(strings.TrimSpace(st.Vulnerability)) + "\x00" + strings.Join(ids, ",")
}

// sortStatements orders statements deterministically for reproducible output.
func sortStatements(stmts []vulnscan.VEXStatement) {
	sort.SliceStable(stmts, func(i, j int) bool {
		return statementKey(stmts[i]) < statementKey(stmts[j])
	})
}

// stampCorpus returns a corpus statement ready for export, stamping the format
// when the source omitted it.
func stampCorpus(st vulnscan.VEXStatement) vulnscan.VEXStatement {
	if st.Format == "" {
		st.Format = "openvex"
	}
	return st
}

// --- findings-derived suppressions ------------------------------------------

// findingSuppressions turns a findings document's VEX-adjudicated (suppressed)
// vulnerability findings into not_affected/fixed VEX statements.
func findingSuppressions(doc findings.Document) []vulnscan.VEXStatement {
	ref := artifactProductRef(doc.Artifact)
	var out []vulnscan.VEXStatement
	for _, f := range doc.Findings {
		if !f.Suppressed || f.Gate != findings.GateVEX {
			continue
		}
		id := strings.TrimSpace(f.Identifier)
		if id == "" {
			continue
		}
		status := vulnscan.VEXNotAffected
		if raw, ok := stringProp(f.Properties, "vexStatus"); ok {
			if ns, ok2 := vulnscan.NormalizeVEXStatus(raw); ok2 {
				status = ns
			}
		}
		just := ""
		if raw, ok := stringProp(f.Properties, "vexJustification"); ok {
			just = raw
		} else {
			just = strings.TrimSpace(f.Justification)
		}
		out = append(out, vulnscan.VEXStatement{
			Vulnerability:   id,
			Products:        []vulnscan.VEXProductRef{ref},
			Status:          status,
			Justification:   vulnscan.VEXJustification(just),
			ImpactStatement: strings.TrimSpace(f.Message),
			Timestamp:       doc.GeneratedAt,
			Source:          "findings:" + doc.Artifact.Coordinate,
			Format:          "openvex",
		})
	}
	return out
}

func artifactProductRef(a findings.Artifact) vulnscan.VEXProductRef {
	if a.Name != "" {
		return vulnscan.VEXProductRef{
			ID:   vulnscan.PackageURL(a.Ecosystem, a.Name, a.Version),
			Name: coalesce(a.Coordinate, a.Name),
		}
	}
	if a.Digest != "" {
		return vulnscan.VEXProductRef{ID: a.Digest, Name: a.Coordinate}
	}
	return vulnscan.VEXProductRef{Name: a.Coordinate}
}

func stringProp(props map[string]any, key string) (string, bool) {
	if props == nil {
		return "", false
	}
	if v, ok := props[key]; ok {
		if s, ok2 := v.(string); ok2 && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

func coalesce(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// --- break-glass grant helpers ----------------------------------------------

func grantProduct(g approvals.Request) vulnscan.VEXProductRef {
	coord := strings.TrimSpace(g.Coordinate)
	if strings.HasPrefix(strings.ToLower(coord), "pkg:") {
		return vulnscan.VEXProductRef{ID: coord}
	}
	eco, name, version := splitCoordinate(coord)
	if strings.TrimSpace(g.Ecosystem) != "" {
		eco = g.Ecosystem
	}
	if name != "" {
		return vulnscan.VEXProductRef{ID: vulnscan.PackageURL(eco, name, version), Name: coord}
	}
	return vulnscan.VEXProductRef{ID: coord, Name: coord}
}

func grantAction(g approvals.Request, now time.Time) string {
	approvers := make([]string, 0, len(g.Approvers))
	for _, a := range g.Approvers {
		if s := strings.TrimSpace(a.Subject); s != "" {
			approvers = append(approvers, s)
		}
	}
	by := strings.Join(approvers, ", ")
	if by == "" {
		by = strings.TrimSpace(g.DecidedBy)
	}
	msg := "Served under a time-boxed break-glass exception"
	if by != "" {
		msg += " approved by " + by
	}
	if !g.ExpiresAt.IsZero() {
		msg += fmt.Sprintf("; the exception expires %s", g.ExpiresAt.UTC().Format(time.RFC3339))
	}
	msg += "."
	return msg
}

func grantImpact(g approvals.Request) string {
	if j := strings.TrimSpace(g.Justification); j != "" {
		return j
	}
	return strings.TrimSpace(g.Reason)
}

func grantTimestamp(g approvals.Request) time.Time {
	if !g.GrantedAt.IsZero() {
		return g.GrantedAt
	}
	return g.UpdatedAt
}

func grantSyntheticID(g approvals.Request) string {
	gate := strings.TrimSpace(g.Gate)
	if gate == "" {
		gate = "exception"
	}
	return "break-glass/" + strings.ToLower(gate)
}

// filename derives a download filename for an export result.
func filename(format Format, req Request) string {
	base := "vex-posture"
	if name := strings.TrimSpace(req.Name); name != "" {
		base = sanitizeFilename(name)
		if v := strings.TrimSpace(req.Version); v != "" {
			base += "@" + sanitizeFilename(v)
		}
	} else if coord := strings.TrimSpace(req.Coordinate); coord != "" {
		base = sanitizeFilename(coord)
	} else if id := strings.TrimSpace(req.SnapshotID); id != "" {
		base = "vex-snapshot-" + sanitizeFilename(id)
	}
	ext := ".openvex.json"
	if format == FormatCycloneDX {
		ext = ".cdx.json"
	}
	return base + ext
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "vex"
	}
	return out
}
