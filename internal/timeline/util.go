package timeline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
)

// normalizeQuery trims and lower-cases the scalar selectors and normalizes the
// coordinate the same way events are normalized, so a query and an event join
// on the same canonical form.
func normalizeQuery(q Query) Query {
	q.Tenant = strings.TrimSpace(q.Tenant)
	q.Identity = strings.TrimSpace(q.Identity)
	q.IncidentID = strings.TrimSpace(q.IncidentID)
	q.Coordinate = normalizeCoordinate("", strings.TrimSpace(q.Coordinate))
	return q
}

// matcher applies the AND-combined query selectors to each event. It is
// pre-computed once per query for speed and to keep the per-event test cheap.
type matcher struct {
	tenant      string
	identity    string
	incidentID  string
	coordinate  string
	coordName   string // bare name half of a name@version coordinate query
	since       time.Time
	until       time.Time
	hasCoord    bool
	hasTenant   bool
	hasIdentity bool
	hasIncident bool
}

func newMatcher(q Query) matcher {
	m := matcher{
		tenant:      strings.ToLower(q.Tenant),
		identity:    strings.ToLower(q.Identity),
		incidentID:  strings.ToLower(q.IncidentID),
		coordinate:  strings.ToLower(q.Coordinate),
		since:       q.Since,
		until:       q.Until,
		hasCoord:    q.Coordinate != "",
		hasTenant:   q.Tenant != "",
		hasIdentity: q.Identity != "",
		hasIncident: q.IncidentID != "",
	}
	if i := strings.IndexByte(m.coordinate, '@'); i >= 0 {
		m.coordName = m.coordinate[:i]
	} else {
		m.coordName = m.coordinate
	}
	return m
}

func (m matcher) matches(ev Event) bool {
	if !m.since.IsZero() && ev.Time.Before(m.since) {
		return false
	}
	if !m.until.IsZero() && ev.Time.After(m.until) {
		return false
	}
	// Tenant scoping, consistent with the portal: an event attributed to a
	// *different* tenant is never returned under a tenant scope. Un-attributed
	// (organisation-wide) events remain visible.
	if m.hasTenant {
		if ev.Tenant != "" && !strings.EqualFold(ev.Tenant, m.tenant) {
			return false
		}
	}
	if m.hasIdentity {
		if !strings.EqualFold(ev.Actor, m.identity) {
			return false
		}
	}
	if m.hasIncident {
		if !strings.EqualFold(ev.IncidentID, m.incidentID) {
			return false
		}
	}
	if m.hasCoord {
		if !m.matchesCoordinate(ev.Coordinate) {
			return false
		}
	}
	return true
}

// matchesCoordinate accepts an exact normalized match, or a bare-name match
// (querying "lodash" returns every "lodash@<version>" event), so an incident
// responder can pivot on a package without knowing the exact version.
func (m matcher) matchesCoordinate(coord string) bool {
	c := strings.ToLower(coord)
	if c == "" {
		return false
	}
	if c == m.coordinate {
		return true
	}
	// Bare-name query matches any version of that name.
	name := c
	if i := strings.IndexByte(c, '@'); i >= 0 {
		name = c[:i]
	}
	return name == m.coordName && m.coordName != "" && !strings.Contains(m.coordinate, "@")
}

// --- normalization helpers --------------------------------------------------

// normalizeCoordinate produces the stable join key shared with the rest of the
// security model: name@version, with any leading "ecosystem/" qualifier and
// version-less query/path noise stripped. It mirrors queryapi's normalization so
// the two layers agree on coordinate identity.
func normalizeCoordinate(ecosystem, coordinate string) string {
	c := strings.TrimSpace(coordinate)
	if c == "" {
		return ""
	}
	// A trailing "@" with no version (e.g. from name+"@"+version when version is
	// empty) is meaningless; strip it.
	c = strings.TrimSuffix(c, "@")
	if eco := strings.TrimSpace(ecosystem); eco != "" {
		c = strings.TrimPrefix(c, eco+"/")
	}
	// Strip a generic leading "<segment>/" qualifier when it is not part of a
	// name@version (some resources arrive as "npm/lodash@4.17.21").
	if i := strings.IndexByte(c, '/'); i >= 0 && !strings.ContainsAny(c[:i], "@") {
		// Only strip when the remainder still looks like a coordinate; keeping the
		// path otherwise (e.g. a Docker blob path) is harmless because coordinate
		// queries then simply won't match it.
		rest := c[i+1:]
		if strings.Contains(rest, "@") || !strings.Contains(rest, "/") {
			c = rest
		}
	}
	return c
}

// tenantFromSubject extracts the tenant half of a secops subject, which is
// formatted as "tenant" or "tenant|identity". It returns "" when the subject is
// not tenant-scoped.
func tenantFromSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	if i := strings.IndexByte(subject, '|'); i >= 0 {
		return strings.TrimSpace(subject[:i])
	}
	return ""
}

// incidentFromDetail pulls an incident identifier out of an audit event's detail
// map under any of the conventional keys.
func incidentFromDetail(detail map[string]any) string {
	for _, k := range []string{"incidentId", "incidentID", "incident", "incident_id"} {
		if v, ok := detail[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// reasonHead returns the leading "verb" of a colon-delimited reason
// ("lockdown:engaged" -> "lockdown:engaged" stays; "policy:block:risk" -> the
// whole short reason). It is used only to give EventPolicy/EventSnapshot a more
// specific kind than the generic type name.
func reasonHead(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if len(reason) > 60 {
		return reason[:60]
	}
	return reason
}

// approverList renders the dual-control approver identities as a comma list.
func approverList(approvers []approvals.Approver) string {
	if len(approvers) == 0 {
		return ""
	}
	names := make([]string, 0, len(approvers))
	for _, a := range approvers {
		if s := strings.TrimSpace(a.Subject); s != "" {
			names = append(names, s)
		}
	}
	return strings.Join(names, ", ")
}

// --- value helpers ----------------------------------------------------------

func canonicalDecision(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "deny", "denied", "block", "blocked":
		return "block"
	case "allow", "allowed", "admit", "admitted", "observe":
		return "admit"
	case "warn", "warning":
		return "warn"
	case "error", "err":
		return "error"
	default:
		return strings.ToLower(strings.TrimSpace(d))
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func timeStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func copyStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// stringifyDetail flattens an audit detail map (map[string]any) into a
// string→string map for the uniform Event.Detail, dropping empty values.
func stringifyDetail(detail map[string]any) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	out := make(map[string]string, len(detail))
	for k, v := range detail {
		s := scalarString(v)
		if s == "" {
			continue
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case time.Time:
		return timeStr(t)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

func unionStringMaps(a, b map[string]string) map[string]string {
	if len(a) == 0 {
		return copyStringMap(b)
	}
	if len(b) == 0 {
		return a
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}
	return a
}

// mergeSorted unions two small string sets and returns them sorted.
func mergeSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// severity ordering for the findings roll-up.
var severityRank = map[string]int{
	"": 0, "none": 0, "unknown": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

func worseSeverity(cur, next string) string {
	cur = strings.ToLower(cur)
	next = strings.ToLower(next)
	if severityRank[next] > severityRank[cur] {
		return next
	}
	if cur == "" {
		return next
	}
	return cur
}
