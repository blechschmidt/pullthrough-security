package downloadlog

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixture records a small, varied set of downloads one minute apart and returns
// the log. Entry IDs are 1..8 in recording order.
//
//	1  10.0.0.5      cargo  cfg-if@1.0.0            served   alice/team-a
//	2  10.0.0.5      cargo  itoa@1.0.11             blocked  alice/team-a  gate=policy code=malicious
//	3  10.0.0.6      cargo  cfg-if@1.0.0            served   bob/team-b
//	4  10.0.1.7      go     rsc.io/quote@v1.5.2     served
//	5  10.0.1.7      go     rsc.io/sampler@v1.3.0   served
//	6  192.168.1.20  go     github.com/pkg/errors@v0.9.1  not_found
//	7  2001:db8::1   npm    @acme/widgets@2.0.0     served
//	8  2001:db8::2   npm    left-pad@1.3.0          error (502)
func fixture(t *testing.T) (*Log, *clock) {
	t.Helper()
	l, c := newLog(t, Config{})
	rec := func(e Entry) {
		l.Record(e)
		c.Advance(time.Minute)
	}

	e := entry("10.0.0.5", "cargo", "cfg-if", "1.0.0")
	e.Subject, e.Tenant, e.UserAgent, e.Artifact = "alice", "team-a", "cargo/1.84.0", "cfg-if-1.0.0.crate"
	rec(e)

	e = entry("10.0.0.5", "cargo", "itoa", "1.0.11")
	e.Subject, e.Tenant = "alice", "team-a"
	e.Outcome, e.Status, e.Gate, e.Code, e.Bytes = OutcomeBlocked, 403, "policy", "malicious", 0
	e.Reason = "source commit flagged malicious by the commit scanner"
	rec(e)

	e = entry("10.0.0.6", "cargo", "cfg-if", "1.0.0")
	e.Subject, e.Tenant, e.Cache = "bob", "team-b", "HIT"
	rec(e)

	rec(entry("10.0.1.7", "go", "rsc.io/quote", "v1.5.2"))
	rec(entry("10.0.1.7", "go", "rsc.io/sampler", "v1.3.0"))

	e = entry("192.168.1.20", "go", "github.com/pkg/errors", "v0.9.1")
	e.Outcome, e.Status, e.Bytes = OutcomeNotFound, 404, 0
	rec(e)

	e = entry("2001:db8::1", "npm", "@acme/widgets", "2.0.0")
	e.Upstream = "npm-internal"
	rec(e)

	e = entry("2001:db8::2", "npm", "left-pad", "1.3.0")
	e.Outcome, e.Status, e.Bytes = OutcomeError, 502, 0
	rec(e)
	return l, c
}

func queryIDs(t *testing.T, l *Log, q Query) []uint64 {
	t.Helper()
	q.Limit = -1
	got := ids(mustQuery(t, l, q).Entries)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	return got
}

func TestQueryFilters(t *testing.T) {
	l, c := fixture(t)
	start := c.Now().Add(-8 * time.Minute) // time of entry 1

	tests := []struct {
		name string
		q    Query
		want []uint64
	}{
		{"everything", Query{}, []uint64{1, 2, 3, 4, 5, 6, 7, 8}},

		// The question the log exists for, from the address side …
		{"one address", Query{ClientIP: "10.0.0.5"}, []uint64{1, 2}},
		{"an address spelled differently", Query{ClientIP: "::ffff:10.0.0.5"}, []uint64{1, 2}},
		{"an IPv6 address spelled out", Query{ClientIP: "2001:0db8:0000:0000:0000:0000:0000:0001"}, []uint64{7}},
		{"a /24", Query{ClientIP: "10.0.0.0/24"}, []uint64{1, 2, 3}},
		{"a /16", Query{ClientIP: "10.0.0.0/16"}, []uint64{1, 2, 3, 4, 5}},
		{"a prefix given by a host address", Query{ClientIP: "10.0.1.99/24"}, []uint64{4, 5}},
		{"an IPv6 prefix", Query{ClientIP: "2001:db8::/32"}, []uint64{7, 8}},
		{"everything IPv4", Query{ClientIP: "0.0.0.0/0"}, []uint64{1, 2, 3, 4, 5, 6}},
		{"an address nobody used", Query{ClientIP: "10.9.9.9"}, nil},

		// … and from the package side.
		{"one package", Query{Package: "cfg-if"}, []uint64{1, 3}},
		{"package names ignore case", Query{Package: "CFG-IF"}, []uint64{1, 3}},
		{"an exact name is not a substring match", Query{Package: "cfg"}, nil},
		{"a Go module path", Query{Package: "rsc.io/quote"}, []uint64{4}},
		{"prefix wildcard", Query{Package: "rsc.io/*"}, []uint64{4, 5}},
		{"scope wildcard", Query{Package: "@acme/*"}, []uint64{7}},
		{"infix wildcard", Query{Package: "*pkg*"}, []uint64{6}},
		{"lone wildcard matches named packages", Query{Package: "*"}, []uint64{1, 2, 3, 4, 5, 6, 7, 8}},
		{"package and version", Query{Package: "cfg-if", Version: "1.0.0"}, []uint64{1, 3}},
		{"version alone", Query{Version: "v1.5.2"}, []uint64{4}},
		{"a version nobody pulled", Query{Package: "cfg-if", Version: "0.1.0"}, nil},

		{"ecosystem", Query{Ecosystem: "go"}, []uint64{4, 5, 6}},
		{"ecosystem ignores case", Query{Ecosystem: "Cargo"}, []uint64{1, 2, 3}},
		{"upstream", Query{Upstream: "npm-internal"}, []uint64{7}},
		{"outcome blocked", Query{Outcome: OutcomeBlocked}, []uint64{2}},
		{"outcome served", Query{Outcome: OutcomeServed}, []uint64{1, 3, 4, 5, 7}},
		{"outcome not_found", Query{Outcome: OutcomeNotFound}, []uint64{6}},
		{"outcome error", Query{Outcome: OutcomeError}, []uint64{8}},
		{"kind package", Query{Kind: KindPackage}, []uint64{1, 2, 3, 4, 5, 6, 7, 8}},
		{"kind metadata", Query{Kind: KindMetadata}, nil},
		{"subject", Query{Subject: "alice"}, []uint64{1, 2}},
		{"subject is exact", Query{Subject: "Alice"}, nil},
		{"tenant", Query{Tenant: "team-b"}, []uint64{3}},

		{"search by package fragment", Query{Search: "quote"}, []uint64{4}},
		{"search ignores case", Query{Search: "ACME"}, []uint64{7}},
		{"search by address fragment", Query{Search: "192.168"}, []uint64{6}},
		{"search by user agent", Query{Search: "cargo/1.84"}, []uint64{1}},
		{"search by reason code", Query{Search: "malicious"}, []uint64{2}},
		{"search by artifact", Query{Search: ".crate"}, []uint64{1}},
		{"search with no match", Query{Search: "no-such-thing"}, nil},

		{"since is inclusive", Query{Since: start.Add(6 * time.Minute)}, []uint64{7, 8}},
		{"until is exclusive", Query{Until: start.Add(2 * time.Minute)}, []uint64{1, 2}},
		{"a window", Query{Since: start.Add(2 * time.Minute), Until: start.Add(5 * time.Minute)}, []uint64{3, 4, 5}},
		{"an empty window", Query{Since: start.Add(time.Hour)}, nil},

		{"filters are ANDed", Query{ClientIP: "10.0.0.0/24", Package: "cfg-if", Outcome: OutcomeServed, Tenant: "team-b"}, []uint64{3}},
		{"who was refused what", Query{ClientIP: "10.0.0.5", Outcome: OutcomeBlocked}, []uint64{2}},
		{"contradicting filters", Query{ClientIP: "10.0.0.6", Subject: "alice"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := queryIDs(t, l, tc.q)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("entries %v, want %v", got, tc.want)
			}
		})
	}
}

func TestQueryRejectsInvalidAddressFilter(t *testing.T) {
	l, _ := fixture(t)
	for _, bad := range []string{"not-an-ip", "10.0.0", "10.0.0.0/40", "10.0.0.5:8080", "example.com"} {
		if _, err := l.Query(Query{ClientIP: bad}); err == nil {
			t.Errorf("Query accepted the address filter %q", bad)
		}
		if _, err := l.Summarize(Query{ClientIP: bad}, 0); err == nil {
			t.Errorf("Summarize accepted the address filter %q", bad)
		}
	}
}

func TestQueryPaging(t *testing.T) {
	l, _ := fixture(t)

	// Default order is newest first; walk the whole log three entries at a time.
	var walked []uint64
	q := Query{Limit: 3}
	for page := 0; ; page++ {
		res := mustQuery(t, l, q)
		if res.Total != 8 {
			t.Fatalf("page %d: Total = %d, want 8 on every page", page, res.Total)
		}
		walked = append(walked, ids(res.Entries)...)
		if res.NextBefore == 0 {
			break
		}
		if page > 5 {
			t.Fatal("paging does not terminate")
		}
		q.Before = res.NextBefore
	}
	if want := []uint64{8, 7, 6, 5, 4, 3, 2, 1}; !reflect.DeepEqual(walked, want) {
		t.Fatalf("walked %v, want %v", walked, want)
	}

	// Paging composes with a filter: the cursor only moves within the matches.
	res := mustQuery(t, l, Query{Ecosystem: "cargo", Limit: 2})
	if got := ids(res.Entries); !reflect.DeepEqual(got, []uint64{3, 2}) || res.NextBefore != 2 || res.Total != 3 {
		t.Fatalf("first cargo page = %v next %d total %d", got, res.NextBefore, res.Total)
	}
	res = mustQuery(t, l, Query{Ecosystem: "cargo", Limit: 2, Before: res.NextBefore})
	if got := ids(res.Entries); !reflect.DeepEqual(got, []uint64{1}) || res.NextBefore != 0 || res.Total != 3 {
		t.Fatalf("second cargo page = %v next %d total %d", got, res.NextBefore, res.Total)
	}

	// A page that exactly exhausts the matches reports no further page.
	res = mustQuery(t, l, Query{Ecosystem: "cargo", Limit: 3})
	if len(res.Entries) != 3 || res.NextBefore != 0 {
		t.Fatalf("exact page: %d entries, next %d", len(res.Entries), res.NextBefore)
	}
}

func TestQueryLimitBounds(t *testing.T) {
	l, _ := newLog(t, Config{MaxEntries: 5000})
	for i := 0; i < MaxLimit+250; i++ {
		l.Record(entry("10.0.0.1", "npm", fmt.Sprintf("p%d", i), "1.0.0"))
	}
	if got := len(mustQuery(t, l, Query{}).Entries); got != DefaultLimit {
		t.Errorf("default page = %d entries, want %d", got, DefaultLimit)
	}
	if got := len(mustQuery(t, l, Query{Limit: MaxLimit * 10}).Entries); got != MaxLimit {
		t.Errorf("oversized page = %d entries, want it capped at %d", got, MaxLimit)
	}
	if got := len(mustQuery(t, l, Query{Limit: -1}).Entries); got != MaxLimit+250 {
		t.Errorf("unlimited page = %d entries, want all %d", got, MaxLimit+250)
	}
	if got := len(mustQuery(t, l, Query{Limit: 7}).Entries); got != 7 {
		t.Errorf("page of 7 = %d entries", got)
	}
}

func TestQueryFromValues(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	parse := func(raw string) (Query, error) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatalf("bad test query %q: %v", raw, err)
		}
		return QueryFromValues(v, now)
	}

	q, err := parse("ip=10.0.0.0%2F8&package=%40acme%2F*&version=2.0.0&ecosystem=npm&upstream=npm-internal" +
		"&outcome=BLOCKED&kind=Package&subject=alice&tenant=team-a&q=widgets&since=24h&until=2026-03-01T11:00:00Z&before=42&limit=25")
	if err != nil {
		t.Fatal(err)
	}
	want := Query{
		ClientIP: "10.0.0.0/8", Package: "@acme/*", Version: "2.0.0", Ecosystem: "npm", Upstream: "npm-internal",
		Outcome: OutcomeBlocked, Kind: KindPackage, Subject: "alice", Tenant: "team-a", Search: "widgets",
		Since: now.Add(-24 * time.Hour), Until: time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC),
		Before: 42, Limit: 25,
	}
	if !reflect.DeepEqual(q, want) {
		t.Fatalf("parsed\n %+v\nwant\n %+v", q, want)
	}

	if q, err := parse(""); err != nil || !reflect.DeepEqual(q, Query{}) {
		t.Fatalf("an empty query string = %+v, %v; want the zero Query", q, err)
	}
	if q, err := parse("ip=+10.0.0.5+&package=+cfg-if+"); err != nil || q.ClientIP != "10.0.0.5" || q.Package != "cfg-if" {
		t.Fatalf("values must be trimmed: %+v, %v", q, err)
	}

	ages := map[string]time.Duration{
		"90s": 90 * time.Second, "15m": 15 * time.Minute, "24h": 24 * time.Hour,
		"7d": 7 * 24 * time.Hour, "1d12h": 36 * time.Hour, "2d30m": 48*time.Hour + 30*time.Minute,
	}
	for raw, age := range ages {
		q, err := parse("since=" + raw)
		if err != nil || !q.Since.Equal(now.Add(-age)) {
			t.Errorf("since=%s → %v, %v; want %v", raw, q.Since, err, now.Add(-age))
		}
	}
	if q, err := parse("since=1772366400"); err != nil || !q.Since.Equal(time.Unix(1772366400, 0)) {
		t.Errorf("unix seconds: %v, %v", q.Since, err)
	}
	if q, err := parse("since=2026-03-01T13:00:00%2B02:00"); err != nil || !q.Since.Equal(time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("RFC 3339 with an offset: %v, %v", q.Since, err)
	}

	// A filter that cannot be applied is an error, not a filter that is skipped.
	for _, bad := range []string{
		"ip=nope", "ip=10.0.0.0%2F99", "outcome=pwned", "kind=binary",
		"since=yesterday", "since=-5m", "since=0s", "until=12%3A00", "since=d", "since=99999999d",
		"before=abc", "before=-1", "limit=abc", "limit=-1",
	} {
		if q, err := parse(bad); err == nil {
			t.Errorf("%q was accepted: %+v", bad, q)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"**", "anything", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "abcd", false},
		{"a*", "a", true},
		{"a*", "abc", true},
		{"a*", "ba", false},
		{"*c", "abc", true},
		{"*c", "abcd", false},
		{"a*c", "ac", true},
		{"a*c", "abbbc", true},
		{"a*c", "abcb", false},
		{"*b*", "abc", true},
		{"*b*", "acd", false},
		{"@acme/*", "@acme/widgets", true},
		{"@acme/*", "@acme2/widgets", false},
		{"a*b*c", "aXbXc", true},
		{"a*b*c", "aXcXb", false},
		{"a*b*c", "abcbc", true},
		{"", "", true},
		{"", "a", false},
	}
	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.name); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

// A pattern built to make a naive matcher backtrack exponentially must still be
// answered quickly: the filter is reachable with a read-only admin credential.
func TestGlobMatchIsNotExponential(t *testing.T) {
	pattern := strings.Repeat("a*", 60) + "b"
	name := strings.Repeat("a", 400)
	done := make(chan bool, 1)
	go func() { done <- globMatch(pattern, name) }()
	select {
	case got := <-done:
		if got {
			t.Fatal("the pattern must not match")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("globMatch did not finish: pathological backtracking")
	}
}

// selectIDs walks a selection and returns the IDs it visits, in order.
func selectIDs(t *testing.T, l *Log, q Query) (visited []uint64, total int) {
	t.Helper()
	sel, err := l.Select(q)
	if err != nil {
		t.Fatalf("Select(%+v): %v", q, err)
	}
	sel.Each(func(e *Entry) bool {
		visited = append(visited, e.ID)
		return true
	})
	return visited, sel.Total()
}

func TestSelectVisitsWhatQueryReturns(t *testing.T) {
	l, _ := fixture(t)
	for _, q := range []Query{
		{},
		{ClientIP: "10.0.0.0/24"},
		{Package: "cfg-if"},
		{Ecosystem: "go", Outcome: OutcomeServed},
		{Search: "malicious"},
		{Before: 5},
		{Ecosystem: "cargo", Before: 3},
		{Package: "no-such-package"},
	} {
		// The reference: the same query as one unbounded page.
		unbounded := q
		unbounded.Limit = -1
		want := mustQuery(t, l, unbounded)

		visited, total := selectIDs(t, l, q)
		if got := ids(want.Entries); !reflect.DeepEqual(visited, got) && (len(visited) > 0 || len(got) > 0) {
			t.Errorf("%+v: Each visited %v, Query returned %v", q, visited, got)
		}
		if total != want.Total {
			t.Errorf("%+v: Total = %d, Query reported %d", q, total, want.Total)
		}
	}

	// The page size is the caller's business: Select ignores Limit.
	if visited, _ := selectIDs(t, l, Query{Limit: 2}); len(visited) != 8 {
		t.Errorf("Limit: 2 visited %d entries, want all 8", len(visited))
	}
	// An address filter that cannot be parsed fails, as it does for Query.
	if _, err := l.Select(Query{ClientIP: "not-an-address"}); err == nil {
		t.Error("Select accepted an unparseable address filter")
	}
}

func TestSelectEachStopsWhenAsked(t *testing.T) {
	l, _ := fixture(t)
	sel, err := l.Select(Query{})
	if err != nil {
		t.Fatal(err)
	}
	var visited []uint64
	sel.Each(func(e *Entry) bool {
		visited = append(visited, e.ID)
		return len(visited) < 3
	})
	if want := []uint64{8, 7, 6}; !reflect.DeepEqual(visited, want) {
		t.Errorf("visited %v, want the three newest %v", visited, want)
	}
	// Stopping early does not change what the selection holds.
	if got := sel.Total(); got != 8 {
		t.Errorf("Total after an early stop = %d, want 8", got)
	}
}

// A selection is a snapshot: what is recorded — or evicted — after it was taken
// does not change what it visits. That is what lets an export run for as long
// as its client reads slowly, without holding the log's lock.
func TestSelectIsASnapshot(t *testing.T) {
	l, _ := newLog(t, Config{MaxEntries: 4})
	for i := 1; i <= 4; i++ {
		l.Record(entry("10.0.0.1", "cargo", fmt.Sprintf("p%d", i), "1.0.0"))
	}
	sel, err := l.Select(Query{})
	if err != nil {
		t.Fatal(err)
	}
	// Push every entry of the snapshot out of the log, twice over, across a
	// chunk boundary.
	for i := 5; i <= 4+2*chunkSize; i++ {
		l.Record(entry("10.0.0.2", "go", fmt.Sprintf("q%d", i), "v1.0.0"))
	}

	var names []string
	sel.Each(func(e *Entry) bool {
		names = append(names, e.Package)
		return true
	})
	if want := []string{"p4", "p3", "p2", "p1"}; !reflect.DeepEqual(names, want) {
		t.Errorf("the snapshot visited %v, want %v", names, want)
	}
	if got := sel.Total(); got != 4 {
		t.Errorf("Total = %d, want the 4 entries of the snapshot", got)
	}
	// The log itself has moved on.
	if res := mustQuery(t, l, Query{Package: "p*"}); res.Total != 0 {
		t.Errorf("the log still holds %d of the evicted entries", res.Total)
	}
}

func TestSelectOnNilAndDisabledLogs(t *testing.T) {
	disabled, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]*Log{"nil": nil, "disabled": disabled} {
		sel, err := l.Select(Query{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := sel.Total(); got != 0 {
			t.Errorf("%s: Total = %d", name, got)
		}
		sel.Each(func(*Entry) bool {
			t.Errorf("%s: Each visited an entry", name)
			return false
		})
	}
}

// The package filter takes what people type and paste: a name, or a
// name@version coordinate. A name can itself contain an "@" — Homebrew's
// "openssl@3" is a package, not version 3 of "openssl" — so both readings are
// tried, and splitting the text at its "@" is never left to the caller.
func TestQueryPackageMatchesNameOrCoordinate(t *testing.T) {
	l, _ := newLog(t, Config{})
	rec := func(ecosystem, name, version string) {
		l.Record(entry("10.0.0.5", ecosystem, name, version))
	}
	rec("homebrew", "openssl@3", "3.4.0")    // 1: the name contains an "@"
	rec("homebrew", "python@3.12", "3.12.8") // 2
	rec("npm", "left-pad", "1.3.0")          // 3
	rec("npm", "left-pad", "1.2.0")          // 4
	rec("npm", "@acme/widgets", "2.0.0")     // 5: an npm scope starts with "@"
	rec("git", "octocat/Hello-World", "")    // 6: no version at all
	rec("generic", "openssl", "3")           // 7: a package "openssl" at version "3"

	tests := []struct {
		pattern string
		want    []uint64
	}{
		{"openssl@3", []uint64{1, 7}}, // the Homebrew formula — and openssl at version 3
		{"python@3.12", []uint64{2}},
		{"openssl@3@3.4.0", []uint64{1}}, // name@version of a name with an "@"
		{"left-pad", []uint64{3, 4}},
		{"left-pad@1.3.0", []uint64{3}},
		{"LEFT-PAD@1.3.0", []uint64{3}},
		{"left-pad@1.*", []uint64{3, 4}},
		{"left-pad@2.0.0", nil},
		{"*@1.3.0", []uint64{3}},
		{"@acme/widgets", []uint64{5}},
		{"@acme/widgets@2.0.0", []uint64{5}},
		{"@acme/*", []uint64{5}},
		{"@acme/*@2.*", []uint64{5}},
		{"octocat/Hello-World", []uint64{6}},
		{"octocat/Hello-World@", nil}, // an entry without a version has no coordinate form
		{"openssl", []uint64{7}},
		{"openssl*", []uint64{1, 7}},
	}
	for _, tc := range tests {
		got := queryIDs(t, l, Query{Package: tc.pattern})
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("package=%q matched %v, want %v", tc.pattern, got, tc.want)
		}
	}

	// The version parameter still narrows, for callers that keep the two apart.
	if got := queryIDs(t, l, Query{Package: "left-pad", Version: "1.2.0"}); !reflect.DeepEqual(got, []uint64{4}) {
		t.Errorf("package=left-pad version=1.2.0 matched %v, want [4]", got)
	}
	// And the summary's "who pulled this" works for a name with an "@".
	sum, err := l.Summarize(Query{Package: "python@3.12"}, 0)
	if err != nil || sum.Total != 1 || len(sum.ByPackage) != 1 || sum.ByPackage[0].Package != "python@3.12" {
		t.Errorf("summary for python@3.12 = %+v, %v", sum, err)
	}
}
