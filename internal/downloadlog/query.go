package downloadlog

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/clientip"
)

// Limits on a query's page size.
const (
	// DefaultLimit is the page size when a query names none.
	DefaultLimit = 100
	// MaxLimit is the largest page a query may ask for.
	MaxLimit = 1000
)

// Query selects entries from the log. The zero Query matches everything. Every
// set field narrows the selection (fields are ANDed).
type Query struct {
	// ClientIP selects by client address: a single address ("10.0.0.7",
	// "2001:db8::1") or a CIDR prefix ("10.0.0.0/8").
	ClientIP string
	// Package selects by package, ignoring case: either the package name
	// ("left-pad", "@acme/widgets") or the coordinate "name@version"
	// ("left-pad@1.3.0"). A "*" matches any run of characters ("@acme/*",
	// "*crypto*", "left-pad@1.*"); without one the match is exact.
	//
	// Both readings are tried, because a name can itself contain an "@" —
	// Homebrew's "openssl@3" is a package, not version 3 of "openssl" — and
	// nothing in the text says which is meant.
	Package string
	// Version selects by exact version, ignoring case.
	Version string
	// Ecosystem and Upstream select by exact name, ignoring case.
	Ecosystem string
	Upstream  string
	// Outcome selects by result.
	Outcome Outcome
	// Kind selects by resource kind.
	Kind Kind
	// Subject selects by the identified client — the user a download is
	// attributed to. Without a "*" the match is exact; with one it is a pattern,
	// matched ignoring case ("*@example.com"). The value "-" selects the entries
	// nobody was identified for.
	Subject string
	// Tenant selects by the client's team, exactly.
	Tenant string
	// Link selects by the personal cache link a request came through, exactly.
	Link string
	// Search is a free-text filter: an entry matches when any of its textual
	// fields contains it, ignoring case.
	Search string
	// Since and Until bound the entry time (inclusive since, exclusive until).
	// The zero time leaves that side open.
	Since time.Time
	Until time.Time
	// Before, when non-zero, restricts the page to entries older than the entry
	// with this ID: the cursor returned as Result.NextBefore.
	Before uint64
	// Limit is the page size. Zero means DefaultLimit; it is capped at MaxLimit.
	// A negative Limit returns every match (exports).
	Limit int
}

// Result is one page of a query, newest entry first.
type Result struct {
	// Total is how many retained entries match the query, regardless of paging.
	Total int `json:"total"`
	// Entries is the page.
	Entries []Entry `json:"entries"`
	// NextBefore is the cursor for the next (older) page: pass it as
	// Query.Before. Zero means this page reached the end.
	NextBefore uint64 `json:"nextBefore,omitempty"`
}

// QueryFromValues builds a Query from URL query parameters, the form the admin
// API and the CLI use:
//
//	ip         client address or CIDR prefix
//	package    package name or name@version ("*" is a wildcard)
//	version    package version
//	ecosystem  ecosystem (cargo, go, npm, …)
//	upstream   upstream name
//	outcome    served | not_modified | blocked | not_found | error
//	kind       package | metadata | unclassified
//	subject    identified user ("*" is a wildcard; "-" selects unattributed entries)
//	tenant     tenant / team
//	link       personal cache link (its identifier)
//	q          free-text search
//	since      lower time bound: RFC 3339, unix seconds, or an age ("15m", "24h", "7d")
//	until      upper time bound, same forms
//	before     pagination cursor (an entry ID)
//	limit      page size
//
// An unparseable value is an error rather than being ignored: a filter that
// silently did not apply would answer a different question than the one asked.
func QueryFromValues(v url.Values, now time.Time) (Query, error) {
	q := Query{
		ClientIP:  strings.TrimSpace(v.Get("ip")),
		Package:   strings.TrimSpace(v.Get("package")),
		Version:   strings.TrimSpace(v.Get("version")),
		Ecosystem: strings.TrimSpace(v.Get("ecosystem")),
		Upstream:  strings.TrimSpace(v.Get("upstream")),
		Subject:   strings.TrimSpace(v.Get("subject")),
		Tenant:    strings.TrimSpace(v.Get("tenant")),
		Link:      strings.TrimSpace(v.Get("link")),
		Search:    strings.TrimSpace(v.Get("q")),
	}
	if q.ClientIP != "" {
		if _, err := parseIPFilter(q.ClientIP); err != nil {
			return Query{}, err
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(v.Get("outcome"))); raw != "" {
		q.Outcome = Outcome(raw)
		if !q.Outcome.valid() {
			return Query{}, fmt.Errorf("unknown outcome %q (want one of %s)", raw, joinOutcomes())
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(v.Get("kind"))); raw != "" {
		q.Kind = Kind(raw)
		if !q.Kind.valid() {
			return Query{}, fmt.Errorf("unknown kind %q (want package, metadata or unclassified)", raw)
		}
	}
	var err error
	if q.Since, err = parseTimeBound(v.Get("since"), now); err != nil {
		return Query{}, fmt.Errorf("invalid since: %w", err)
	}
	if q.Until, err = parseTimeBound(v.Get("until"), now); err != nil {
		return Query{}, fmt.Errorf("invalid until: %w", err)
	}
	if raw := strings.TrimSpace(v.Get("before")); raw != "" {
		if q.Before, err = strconv.ParseUint(raw, 10, 64); err != nil {
			return Query{}, fmt.Errorf("invalid before: %q is not an entry ID", raw)
		}
	}
	if raw := strings.TrimSpace(v.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return Query{}, fmt.Errorf("invalid limit: %q is not a non-negative integer", raw)
		}
		q.Limit = n
	}
	return q, nil
}

func joinOutcomes() string {
	names := make([]string, 0, len(Outcomes()))
	for _, o := range Outcomes() {
		names = append(names, string(o))
	}
	return strings.Join(names, ", ")
}

// parseTimeBound parses a time bound: empty (open), an age relative to now
// ("90s", "15m", "24h", "7d"), an RFC 3339 timestamp, or unix seconds.
func parseTimeBound(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if age, ok := parseAge(raw); ok {
		return now.Add(-age), nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if secs, err := strconv.ParseInt(raw, 10, 64); err == nil && secs >= 0 {
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("%q is not an age (15m, 24h, 7d), an RFC 3339 timestamp or unix seconds", raw)
}

// parseAge parses a positive duration with an optional day unit ("7d", "1d12h").
func parseAge(raw string) (time.Duration, bool) {
	var days time.Duration
	rest := raw
	if i := strings.IndexByte(raw, 'd'); i > 0 {
		n, err := strconv.Atoi(raw[:i])
		if err != nil || n < 0 || n > 36500 {
			return 0, false
		}
		days = time.Duration(n) * 24 * time.Hour
		rest = raw[i+1:]
		if rest == "" {
			return days, days > 0
		}
	}
	d, err := time.ParseDuration(rest)
	if err != nil || d < 0 {
		return 0, false
	}
	total := days + d
	return total, total > 0
}

// ipFilter matches client addresses against one address or one prefix.
type ipFilter struct {
	exact  string       // canonical address, for a single-address filter
	prefix netip.Prefix // valid for a CIDR filter
}

// parseIPFilter parses the ClientIP field of a query.
func parseIPFilter(raw string) (ipFilter, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		prefix, err := clientip.ParsePrefix(raw)
		if err != nil {
			return ipFilter{}, fmt.Errorf("invalid ip filter: %q is not a CIDR prefix", raw)
		}
		return ipFilter{prefix: prefix}, nil
	}
	canonical, ok := clientip.Canonical(raw)
	if !ok {
		return ipFilter{}, fmt.Errorf("invalid ip filter: %q is not an IP address or CIDR prefix", raw)
	}
	return ipFilter{exact: canonical}, nil
}

func (f ipFilter) match(clientIP string) bool {
	if f.exact != "" {
		// Stored addresses are canonical, so equal hosts are equal strings.
		return clientIP == f.exact
	}
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	return f.prefix.Contains(addr.Unmap())
}

// matcher is a compiled Query.
type matcher struct {
	q       Query
	ip      *ipFilter
	pkg     string // lower-cased package pattern
	pkgGlob bool
	// pkgCoordinate reports that the pattern can only match a "name@version"
	// coordinate if at all: it has an "@" that is not its first character (the
	// "@" an npm scope starts with separates nothing).
	pkgCoordinate bool
	search        string // lower-cased
	// subjectGlob is the lower-cased subject pattern, when the subject filter
	// contains a "*"; subjectNone reports the filter "-": no subject at all.
	subjectGlob string
	subjectNone bool
}

// compile prepares q for matching. It fails only on an unparseable ClientIP.
func compile(q Query) (*matcher, error) {
	m := &matcher{q: q, search: strings.ToLower(q.Search)}
	if q.ClientIP != "" {
		f, err := parseIPFilter(q.ClientIP)
		if err != nil {
			return nil, err
		}
		m.ip = &f
	}
	if q.Package != "" {
		m.pkg = strings.ToLower(q.Package)
		m.pkgGlob = strings.Contains(m.pkg, "*")
		m.pkgCoordinate = strings.LastIndexByte(m.pkg, '@') > 0
	}
	switch {
	case q.Subject == NoSubject:
		m.subjectNone = true
	case strings.Contains(q.Subject, "*"):
		m.subjectGlob = strings.ToLower(q.Subject)
	}
	return m, nil
}

// NoSubject is the Query.Subject value that selects the entries nobody was
// identified for: downloads known by their address only.
const NoSubject = "-"

// matchSubject reports whether the entry's subject satisfies the subject
// filter.
func (m *matcher) matchSubject(e *Entry) bool {
	switch {
	case m.subjectNone:
		return e.Subject == ""
	case m.subjectGlob != "":
		return e.Subject != "" && globMatch(m.subjectGlob, strings.ToLower(e.Subject))
	default:
		return e.Subject == m.q.Subject
	}
}

// matchPackage reports whether the entry's package — its name, or its
// "name@version" coordinate — matches the package pattern.
func (m *matcher) matchPackage(e *Entry) bool {
	name := strings.ToLower(e.Package)
	if m.matchName(name) {
		return true
	}
	if !m.pkgCoordinate || e.Version == "" {
		return false
	}
	return m.matchName(name + "@" + strings.ToLower(e.Version))
}

func (m *matcher) matchName(name string) bool {
	if m.pkgGlob {
		return globMatch(m.pkg, name)
	}
	return name == m.pkg
}

func (m *matcher) match(e *Entry) bool {
	q := &m.q
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !e.Time.Before(q.Until) {
		return false
	}
	if q.Outcome != "" && e.Outcome != q.Outcome {
		return false
	}
	if q.Kind != "" && e.Kind != q.Kind {
		return false
	}
	if m.ip != nil && !m.ip.match(e.ClientIP) {
		return false
	}
	if q.Ecosystem != "" && !strings.EqualFold(e.Ecosystem, q.Ecosystem) {
		return false
	}
	if q.Upstream != "" && !strings.EqualFold(e.Upstream, q.Upstream) {
		return false
	}
	if m.pkg != "" && !m.matchPackage(e) {
		return false
	}
	if q.Version != "" && !strings.EqualFold(e.Version, q.Version) {
		return false
	}
	if q.Subject != "" && !m.matchSubject(e) {
		return false
	}
	if q.Tenant != "" && e.Tenant != q.Tenant {
		return false
	}
	if q.Link != "" && e.Link != q.Link {
		return false
	}
	if m.search != "" && !m.searchMatch(e) {
		return false
	}
	return true
}

// searchMatch reports whether any textual field of e contains the search term.
func (m *matcher) searchMatch(e *Entry) bool {
	for _, field := range [...]string{
		e.ClientIP, e.Package, e.Version, e.Artifact, e.Path, e.Ecosystem, e.Upstream,
		e.Subject, e.Tenant, e.UserAgent, e.Gate, e.Code, e.Reason, e.ForwardedBy, e.Digest, e.Link,
	} {
		if field != "" && containsFold(field, m.search) {
			return true
		}
	}
	return false
}

// containsFold reports whether s contains the lower-case term, ignoring case.
func containsFold(s, lowerTerm string) bool {
	return strings.Contains(strings.ToLower(s), lowerTerm)
}

// globMatch reports whether name matches pattern, where "*" in the pattern
// matches any (possibly empty) run of characters. Both are already lower-case.
// It runs in O(len(pattern) * len(name)) worst case with no recursion, so a
// pattern made of many stars cannot be used to stall a query.
func globMatch(pattern, name string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case p < len(pattern) && pattern[p] == name[n]:
			p++
			n++
		case star >= 0:
			// Backtrack: let the last star swallow one more character.
			p = star + 1
			mark++
			n = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// Query returns the page of entries selected by q, newest first, together with
// the total number of matches. It fails only when q.ClientIP is not an address
// or a prefix.
func (l *Log) Query(q Query) (Result, error) {
	m, err := compile(q)
	if err != nil {
		return Result{}, err
	}
	res := Result{Entries: []Entry{}}
	if !l.Enabled() {
		return res, nil
	}
	limit := q.Limit
	switch {
	case limit == 0:
		limit = DefaultLimit
	case limit > MaxLimit:
		limit = MaxLimit
	}

	// The scan runs on a snapshot, without the log's lock: a query over a large
	// log must not hold up the downloads being recorded meanwhile.
	v := l.snapshotView()
	// Newest first. Every match counts toward Total; the page is the first
	// `limit` matches older than the cursor.
	more := false
	for i := v.count - 1; i >= 0; i-- {
		e := v.at(i)
		if !m.match(e) {
			continue
		}
		res.Total++
		if q.Before != 0 && e.ID >= q.Before {
			continue
		}
		if limit >= 0 && len(res.Entries) >= limit {
			more = true
			continue
		}
		res.Entries = append(res.Entries, *e)
	}
	if more && len(res.Entries) > 0 {
		res.NextBefore = res.Entries[len(res.Entries)-1].ID
	}
	return res, nil
}

// Selection is what a Query selects, frozen at one moment: a snapshot of the
// log together with the compiled filter. It exists for exports. Walking it
// neither holds the log's lock nor copies the entries, so writing out a log of
// millions of entries costs the downloads being recorded no pause and the
// process no second copy of the log — where Query, which returns its page as a
// slice, would have to build one.
//
// A Selection is not safe for concurrent use.
type Selection struct {
	v     view
	m     *matcher
	total int // -1 until counted
}

// Select freezes the entries q selects. q.Limit is ignored: the caller decides
// when to stop. It fails only when q.ClientIP is not an address or a prefix.
func (l *Log) Select(q Query) (*Selection, error) {
	m, err := compile(q)
	if err != nil {
		return nil, err
	}
	s := &Selection{m: m, total: -1}
	if l.Enabled() {
		s.v = l.snapshotView()
	}
	return s, nil
}

// Total returns how many entries the query matches, regardless of its Before
// cursor — the same number Query reports as Result.Total.
func (s *Selection) Total() int {
	if s.total < 0 {
		s.total = 0
		for i := 0; i < s.v.count; i++ {
			if s.m.match(s.v.at(i)) {
				s.total++
			}
		}
	}
	return s.total
}

// Each calls fn for every selected entry older than the query's Before cursor,
// newest first, until fn returns false. The entry belongs to the log: fn must
// not modify it.
func (s *Selection) Each(fn func(e *Entry) bool) {
	before := s.m.q.Before
	for i := s.v.count - 1; i >= 0; i-- {
		e := s.v.at(i)
		if !s.m.match(e) {
			continue
		}
		if before != 0 && e.ID >= before {
			continue
		}
		if !fn(e) {
			return
		}
	}
}
