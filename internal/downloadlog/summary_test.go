package downloadlog

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func mustSummarize(t *testing.T, l *Log, q Query, top int) Summary {
	t.Helper()
	sum, err := l.Summarize(q, top)
	if err != nil {
		t.Fatalf("Summarize(%+v): %v", q, err)
	}
	return sum
}

func TestSummarizeTotals(t *testing.T) {
	l, c := fixture(t)
	start := c.Now().Add(-8 * time.Minute)

	sum := mustSummarize(t, l, Query{}, 0)
	if sum.Total != 8 || sum.Served != 5 || sum.Blocked != 1 || sum.NotFound != 1 || sum.Errors != 1 || sum.NotModified != 0 {
		t.Fatalf("totals = %+v", sum)
	}
	if sum.Bytes != 500 {
		t.Errorf("Bytes = %d, want 500 (five served entries of 100 bytes)", sum.Bytes)
	}
	if sum.Clients != 6 {
		t.Errorf("Clients = %d, want 6 distinct addresses", sum.Clients)
	}
	if sum.Packages != 7 {
		t.Errorf("Packages = %d, want 7 distinct packages (cfg-if was pulled twice)", sum.Packages)
	}
	if sum.First == nil || !sum.First.Equal(start) || sum.Last == nil || !sum.Last.Equal(start.Add(7*time.Minute)) {
		t.Errorf("First/Last = %v / %v, want %v / %v", sum.First, sum.Last, start, start.Add(7*time.Minute))
	}
}

// "What did this address pull?"
func TestSummarizeByClient(t *testing.T) {
	l, c := fixture(t)
	start := c.Now().Add(-8 * time.Minute)
	sum := mustSummarize(t, l, Query{}, 0)

	// Two addresses made two requests each; the one seen most recently is first.
	if len(sum.ByClient) != 6 {
		t.Fatalf("%d clients listed, want 6", len(sum.ByClient))
	}
	first, second := sum.ByClient[0], sum.ByClient[1]
	if first.ClientIP != "10.0.1.7" || second.ClientIP != "10.0.0.5" {
		t.Fatalf("top clients = %s, %s; want 10.0.1.7 (seen later), 10.0.0.5", first.ClientIP, second.ClientIP)
	}
	want := ClientSummary{
		ClientIP: "10.0.0.5", Downloads: 2, Served: 1, Blocked: 1, Packages: 2, Bytes: 100,
		Identities: []string{"alice"}, FirstSeen: start, LastSeen: start.Add(time.Minute),
	}
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("10.0.0.5 summary\n %+v\nwant\n %+v", second, want)
	}
	if first.Downloads != 2 || first.Served != 2 || first.Blocked != 0 || first.Packages != 2 || len(first.Identities) != 0 {
		t.Fatalf("10.0.1.7 summary = %+v", first)
	}
	// The remaining addresses made one request each: newest first.
	var rest []string
	for _, cs := range sum.ByClient[2:] {
		rest = append(rest, cs.ClientIP)
	}
	if want := []string{"2001:db8::2", "2001:db8::1", "192.168.1.20", "10.0.0.6"}; !reflect.DeepEqual(rest, want) {
		t.Fatalf("remaining clients = %v, want %v", rest, want)
	}
}

// "Who pulled this package?"
func TestSummarizeByPackage(t *testing.T) {
	l, c := fixture(t)
	start := c.Now().Add(-8 * time.Minute)
	sum := mustSummarize(t, l, Query{}, 0)

	if len(sum.ByPackage) != 7 {
		t.Fatalf("%d packages listed, want 7", len(sum.ByPackage))
	}
	top := sum.ByPackage[0]
	want := PackageSummary{
		Ecosystem: "cargo", Package: "cfg-if", Downloads: 2, Served: 2, Clients: 2, Users: 2,
		Versions: []string{"1.0.0"}, Bytes: 200, LastSeen: start.Add(2 * time.Minute),
	}
	if !reflect.DeepEqual(top, want) {
		t.Fatalf("top package\n %+v\nwant\n %+v", top, want)
	}

	// Scoped to one package, the client list is exactly who pulled it.
	scoped := mustSummarize(t, l, Query{Package: "cfg-if"}, 0)
	if scoped.Total != 2 || scoped.Clients != 2 || scoped.Packages != 1 {
		t.Fatalf("scoped totals = %+v", scoped)
	}
	var who []string
	for _, cs := range scoped.ByClient {
		who = append(who, cs.ClientIP)
	}
	if want := []string{"10.0.0.6", "10.0.0.5"}; !reflect.DeepEqual(who, want) {
		t.Fatalf("cfg-if was pulled by %v, want %v", who, want)
	}

	// A refused attempt is attributed to the package as a block, not a download
	// that succeeded.
	blocked := mustSummarize(t, l, Query{Package: "itoa"}, 0)
	if len(blocked.ByPackage) != 1 || blocked.ByPackage[0].Blocked != 1 || blocked.ByPackage[0].Served != 0 || blocked.ByPackage[0].Bytes != 0 {
		t.Fatalf("itoa summary = %+v", blocked.ByPackage)
	}
}

func TestSummarizeByEcosystem(t *testing.T) {
	l, _ := fixture(t)
	sum := mustSummarize(t, l, Query{}, 0)
	want := []EcosystemSummary{
		{Ecosystem: "cargo", Downloads: 3, Served: 2, Blocked: 1, Bytes: 200},
		{Ecosystem: "go", Downloads: 3, Served: 2, Bytes: 200},
		{Ecosystem: "npm", Downloads: 2, Served: 1, Bytes: 100},
	}
	if !reflect.DeepEqual(sum.ByEcosystem, want) {
		t.Fatalf("ByEcosystem\n %+v\nwant\n %+v", sum.ByEcosystem, want)
	}
}

func TestSummarizeTopBounds(t *testing.T) {
	l, _ := newLog(t, Config{})
	for i := 0; i < MaxTop+20; i++ {
		// Every address pulls its own package: as many groups as entries.
		l.Record(entry(fmt.Sprintf("10.%d.%d.1", i/250, i%250), "npm", fmt.Sprintf("p%04d", i), "1.0.0"))
	}
	sum := mustSummarize(t, l, Query{}, 0)
	if len(sum.ByClient) != DefaultTop || len(sum.ByPackage) != DefaultTop {
		t.Errorf("default top = %d clients, %d packages; want %d", len(sum.ByClient), len(sum.ByPackage), DefaultTop)
	}
	// The totals count everything, however short the lists are cut.
	if sum.Clients != MaxTop+20 || sum.Packages != MaxTop+20 {
		t.Errorf("Clients/Packages = %d/%d, want %d", sum.Clients, sum.Packages, MaxTop+20)
	}
	if got := mustSummarize(t, l, Query{}, 3); len(got.ByClient) != 3 || len(got.ByPackage) != 3 {
		t.Errorf("top 3 = %d clients, %d packages", len(got.ByClient), len(got.ByPackage))
	}
	if got := mustSummarize(t, l, Query{}, MaxTop*4); len(got.ByClient) != MaxTop || len(got.ByPackage) != MaxTop {
		t.Errorf("oversized top = %d clients, %d packages; want it capped at %d", len(got.ByClient), len(got.ByPackage), MaxTop)
	}
}

// The per-group lists of identities and versions stay short however many there
// are, and requests without a package name count without forming a package.
func TestSummarizeBoundsDetailLists(t *testing.T) {
	l, _ := newLog(t, Config{})
	for i := 0; i < 40; i++ {
		e := entry("10.0.0.1", "npm", "lodash", fmt.Sprintf("4.17.%d", i))
		e.Subject = fmt.Sprintf("user-%02d", i)
		l.Record(e)
	}
	unnamed := entry("10.0.0.1", "npm", "", "")
	unnamed.Kind = KindUnclassified
	l.Record(unnamed)

	sum := mustSummarize(t, l, Query{}, 0)
	if sum.Total != 41 || sum.Packages != 1 || len(sum.ByPackage) != 1 {
		t.Fatalf("total %d, packages %d, listed %d; want 41, 1, 1", sum.Total, sum.Packages, len(sum.ByPackage))
	}
	if got := len(sum.ByPackage[0].Versions); got != maxSummaryVersions {
		t.Errorf("%d versions listed, want at most %d", got, maxSummaryVersions)
	}
	if got := len(sum.ByClient[0].Identities); got != maxSummaryIdentities {
		t.Errorf("%d identities listed, want at most %d", got, maxSummaryIdentities)
	}
	if sum.ByClient[0].Downloads != 41 || sum.ByClient[0].Packages != 1 {
		t.Errorf("client summary = %+v", sum.ByClient[0])
	}
}

func TestSummarizeAppliesTheQuery(t *testing.T) {
	l, _ := fixture(t)
	sum := mustSummarize(t, l, Query{ClientIP: "10.0.0.0/24"}, 0)
	if sum.Total != 3 || sum.Clients != 2 || sum.Packages != 2 || sum.Blocked != 1 {
		t.Fatalf("summary of 10.0.0.0/24 = %+v", sum)
	}
	if len(sum.ByEcosystem) != 1 || sum.ByEcosystem[0].Ecosystem != "cargo" {
		t.Fatalf("ByEcosystem = %+v", sum.ByEcosystem)
	}
	// Paging fields do not narrow a summary.
	paged := mustSummarize(t, l, Query{ClientIP: "10.0.0.0/24", Limit: 1, Before: 2}, 0)
	if paged.Total != 3 {
		t.Fatalf("a summary honoured the paging fields: total %d, want 3", paged.Total)
	}
	empty := mustSummarize(t, l, Query{Package: "nothing"}, 0)
	if empty.Total != 0 || empty.First != nil || empty.Last != nil || len(empty.ByClient) != 0 {
		t.Fatalf("empty summary = %+v", empty)
	}
}

// "What did this user pull?" and "who pulled this package?" — by name, where
// the log knows one (Task 177).
func TestSummarizeByUser(t *testing.T) {
	l, c := fixture(t)
	start := c.Now().Add(-8 * time.Minute)
	sum := mustSummarize(t, l, Query{}, 0)

	// Three of the eight entries carry an identity; the rest are known by their
	// address only.
	if sum.Users != 2 || sum.Unattributed != 5 {
		t.Fatalf("Users = %d, Unattributed = %d; want 2 and 5", sum.Users, sum.Unattributed)
	}
	if len(sum.ByUser) != 2 {
		t.Fatalf("%d users listed, want 2: %+v", len(sum.ByUser), sum.ByUser)
	}
	want := UserSummary{
		Subject: "alice", Tenant: "team-a", Downloads: 2, Served: 1, Blocked: 1, Packages: 2, Bytes: 100,
		Addresses: 1, ClientIPs: []string{"10.0.0.5"}, FirstSeen: start, LastSeen: start.Add(time.Minute),
	}
	if !reflect.DeepEqual(sum.ByUser[0], want) {
		t.Fatalf("busiest user\n %+v\nwant\n %+v", sum.ByUser[0], want)
	}
	if sum.ByUser[1].Subject != "bob" || sum.ByUser[1].Downloads != 1 {
		t.Fatalf("second user = %+v", sum.ByUser[1])
	}

	// Scoped to a package, the list is who pulled it.
	scoped := mustSummarize(t, l, Query{Package: "cfg-if"}, 0)
	var who []string
	for _, u := range scoped.ByUser {
		who = append(who, u.Subject)
	}
	if !reflect.DeepEqual(who, []string{"bob", "alice"}) || scoped.Users != 2 || scoped.Unattributed != 0 {
		t.Fatalf("who pulled cfg-if = %v (users %d, unattributed %d)", who, scoped.Users, scoped.Unattributed)
	}
	if scoped.ByPackage[0].Users != 2 {
		t.Fatalf("the package summary counts %d users, want 2", scoped.ByPackage[0].Users)
	}

	// Scoped to a user, it is what they pulled.
	mine := mustSummarize(t, l, Query{Subject: "alice"}, 0)
	if mine.Total != 2 || mine.Users != 1 || mine.Packages != 2 || mine.Clients != 1 || mine.Unattributed != 0 {
		t.Fatalf("alice's summary = %+v", mine)
	}

	// The list of users honours `top`, like the others.
	if got := mustSummarize(t, l, Query{}, 1); len(got.ByUser) != 1 || got.Users != 2 {
		t.Fatalf("top 1: %d users listed, total %d", len(got.ByUser), got.Users)
	}
}

// One user on several addresses — a laptop that moves, or a personal link that
// got out — and with several links: the summary shows both.
func TestSummarizeUserAddressesAndLinks(t *testing.T) {
	l, c := newLog(t, Config{})
	for i := 0; i < maxSummaryAddresses+3; i++ {
		e := entry(fmt.Sprintf("10.9.0.%d", i+1), "npm", "left-pad", "1.3.0")
		e.Subject, e.Tenant, e.AuthMethod = "carol@example.com", "team-c", "personal-link"
		e.Link = fmt.Sprintf("%016x", i%2+1)
		l.Record(e)
		c.Advance(time.Second)
	}
	// A user's team is the one of their most recent entry.
	e := entry("10.9.0.1", "npm", "left-pad", "1.3.0")
	e.Subject, e.Tenant = "carol@example.com", "team-d"
	l.Record(e)

	sum := mustSummarize(t, l, Query{}, 0)
	if len(sum.ByUser) != 1 {
		t.Fatalf("%d users, want 1", len(sum.ByUser))
	}
	u := sum.ByUser[0]
	if u.Addresses != maxSummaryAddresses+3 || len(u.ClientIPs) != maxSummaryAddresses {
		t.Fatalf("Addresses = %d with %d listed; want %d with %d listed", u.Addresses, len(u.ClientIPs), maxSummaryAddresses+3, maxSummaryAddresses)
	}
	if !reflect.DeepEqual(u.Links, []string{"0000000000000001", "0000000000000002"}) {
		t.Fatalf("Links = %v", u.Links)
	}
	if u.Tenant != "team-d" || u.Packages != 1 || u.Downloads != maxSummaryAddresses+4 {
		t.Fatalf("user summary = %+v", u)
	}

	// Filtering by link shows what came through that one link.
	one := mustSummarize(t, l, Query{Link: "0000000000000002"}, 0)
	if one.Total != (maxSummaryAddresses+3)/2 || one.Users != 1 {
		t.Fatalf("by link: %+v", one)
	}
}
