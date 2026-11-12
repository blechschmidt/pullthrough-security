package downloadlog

import (
	"sort"
	"time"
)

// Limits on how many groups a summary lists.
const (
	// DefaultTop is how many clients and packages a summary lists by default.
	DefaultTop = 10
	// MaxTop is the most a summary lists.
	MaxTop = 500
	// maxSummaryIdentities and maxSummaryVersions bound the per-group lists of
	// distinct identities / versions.
	maxSummaryIdentities = 5
	maxSummaryVersions   = 10
	// maxSummaryAddresses and maxSummaryLinks bound the per-user lists of
	// distinct client addresses / personal links.
	maxSummaryAddresses = 5
	maxSummaryLinks     = 5
)

// Summary aggregates the entries a query selects: totals, and the busiest
// client addresses, users and packages. It answers the questions the log exists
// for from either side — "what did this address pull", "what did this user
// pull" and "who pulled this package" — without paging through entries.
type Summary struct {
	// Total is the number of matching entries; the fields below break it down by
	// outcome.
	Total       int `json:"total"`
	Served      int `json:"served"`
	NotModified int `json:"notModified"`
	Blocked     int `json:"blocked"`
	NotFound    int `json:"notFound"`
	Errors      int `json:"errors"`
	// Bytes is the number of body bytes sent across all matching entries.
	Bytes int64 `json:"bytes"`
	// Clients is the number of distinct client addresses; Packages the number
	// of distinct packages (ecosystem + name).
	Clients  int `json:"clients"`
	Packages int `json:"packages"`
	// Users is the number of distinct identified users (subjects) among the
	// matching entries; Unattributed the number of entries nobody was
	// identified for — downloads known by their address only.
	Users        int `json:"users"`
	Unattributed int `json:"unattributed"`
	// First and Last are the times of the oldest and newest matching entry.
	First *time.Time `json:"first,omitempty"`
	Last  *time.Time `json:"last,omitempty"`

	// ByClient lists the client addresses with the most entries.
	ByClient []ClientSummary `json:"byClient"`
	// ByUser lists the identified users with the most entries (Task 177).
	ByUser []UserSummary `json:"byUser"`
	// ByPackage lists the packages with the most entries.
	ByPackage []PackageSummary `json:"byPackage"`
	// ByEcosystem breaks the entries down by ecosystem.
	ByEcosystem []EcosystemSummary `json:"byEcosystem"`
}

// ClientSummary is the activity of one client address.
type ClientSummary struct {
	ClientIP string `json:"clientIp"`
	// Downloads is the number of entries; Served and Blocked break out the two
	// outcomes that matter most.
	Downloads int `json:"downloads"`
	Served    int `json:"served"`
	Blocked   int `json:"blocked"`
	// Packages is the number of distinct packages the address requested.
	Packages int   `json:"packages"`
	Bytes    int64 `json:"bytes"`
	// Identities lists authenticated subjects seen from the address (a few).
	Identities []string  `json:"identities,omitempty"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
}

// UserSummary is the activity of one identified user: the subject of a personal
// cache link, a token, an OIDC identity, a workload certificate.
type UserSummary struct {
	Subject string `json:"subject"`
	// Tenant is the user's team, as of their most recent entry.
	Tenant string `json:"tenant,omitempty"`
	// Downloads is the number of entries; Served and Blocked break out the two
	// outcomes that matter most.
	Downloads int `json:"downloads"`
	Served    int `json:"served"`
	Blocked   int `json:"blocked"`
	// Packages is the number of distinct packages the user requested.
	Packages int   `json:"packages"`
	Bytes    int64 `json:"bytes"`
	// Addresses is the number of distinct client addresses the user's requests
	// came from; ClientIPs lists a few of them. One user on many addresses is a
	// laptop that moves — or a personal link that got out.
	Addresses int      `json:"addresses"`
	ClientIPs []string `json:"clientIps,omitempty"`
	// Links lists the personal cache links the user's requests came through (a
	// few).
	Links     []string  `json:"links,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// PackageSummary is the activity around one package.
type PackageSummary struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Downloads int    `json:"downloads"`
	Served    int    `json:"served"`
	Blocked   int    `json:"blocked"`
	// Clients is the number of distinct client addresses that requested it;
	// Users the number of distinct identified users.
	Clients int `json:"clients"`
	Users   int `json:"users"`
	// Versions lists the distinct versions requested (a few).
	Versions []string  `json:"versions,omitempty"`
	Bytes    int64     `json:"bytes"`
	LastSeen time.Time `json:"lastSeen"`
}

// EcosystemSummary is the activity in one ecosystem.
type EcosystemSummary struct {
	Ecosystem string `json:"ecosystem"`
	Downloads int    `json:"downloads"`
	Served    int    `json:"served"`
	Blocked   int    `json:"blocked"`
	Bytes     int64  `json:"bytes"`
}

type clientAgg struct {
	ClientSummary
	packages   map[pkgKey]struct{}
	identities map[string]struct{}
}

type userAgg struct {
	UserSummary
	packages  map[pkgKey]struct{}
	addresses map[string]struct{}
	links     map[string]struct{}
}

type packageAgg struct {
	PackageSummary
	clients  map[string]struct{}
	users    map[string]struct{}
	versions map[string]struct{}
}

type pkgKey struct{ ecosystem, name string }

// Summarize aggregates the entries selected by q (its paging fields are
// ignored) and lists the top clients and packages. top <= 0 means DefaultTop;
// it is capped at MaxTop. It fails only when q.ClientIP is unparseable.
func (l *Log) Summarize(q Query, top int) (Summary, error) {
	m, err := compile(q)
	if err != nil {
		return Summary{}, err
	}
	sum := Summary{ByClient: []ClientSummary{}, ByUser: []UserSummary{}, ByPackage: []PackageSummary{}, ByEcosystem: []EcosystemSummary{}}
	if !l.Enabled() {
		return sum, nil
	}
	switch {
	case top <= 0:
		top = DefaultTop
	case top > MaxTop:
		top = MaxTop
	}

	clients := map[string]*clientAgg{}
	users := map[string]*userAgg{}
	packages := map[pkgKey]*packageAgg{}
	ecosystems := map[string]*EcosystemSummary{}

	v := l.snapshotView()
	for i := 0; i < v.count; i++ {
		e := v.at(i)
		if !m.match(e) {
			continue
		}
		sum.Total++
		sum.Bytes += e.Bytes
		switch e.Outcome {
		case OutcomeServed:
			sum.Served++
		case OutcomeNotModified:
			sum.NotModified++
		case OutcomeBlocked:
			sum.Blocked++
		case OutcomeNotFound:
			sum.NotFound++
		default:
			sum.Errors++
		}
		if sum.First == nil {
			first := e.Time
			sum.First = &first
		}
		last := e.Time
		sum.Last = &last

		key := pkgKey{e.Ecosystem, e.Package}

		c := clients[e.ClientIP]
		if c == nil {
			c = &clientAgg{
				ClientSummary: ClientSummary{ClientIP: e.ClientIP, FirstSeen: e.Time},
				packages:      map[pkgKey]struct{}{},
				identities:    map[string]struct{}{},
			}
			clients[e.ClientIP] = c
		}
		c.Downloads++
		c.Bytes += e.Bytes
		c.LastSeen = e.Time
		if e.Package != "" {
			c.packages[key] = struct{}{}
		}
		if e.Subject != "" && len(c.identities) < maxSummaryIdentities {
			c.identities[e.Subject] = struct{}{}
		}

		// An entry nobody was identified for has no user to be grouped under.
		var u *userAgg
		if e.Subject == "" {
			sum.Unattributed++
		} else {
			u = users[e.Subject]
			if u == nil {
				u = &userAgg{
					UserSummary: UserSummary{Subject: e.Subject, FirstSeen: e.Time},
					packages:    map[pkgKey]struct{}{},
					addresses:   map[string]struct{}{},
					links:       map[string]struct{}{},
				}
				users[e.Subject] = u
			}
			u.Downloads++
			u.Bytes += e.Bytes
			u.LastSeen = e.Time
			u.Tenant = e.Tenant
			if e.Package != "" {
				u.packages[key] = struct{}{}
			}
			u.addresses[e.ClientIP] = struct{}{}
			if e.Link != "" && len(u.links) < maxSummaryLinks {
				u.links[e.Link] = struct{}{}
			}
		}

		eco := ecosystems[e.Ecosystem]
		if eco == nil {
			eco = &EcosystemSummary{Ecosystem: e.Ecosystem}
			ecosystems[e.Ecosystem] = eco
		}
		eco.Downloads++
		eco.Bytes += e.Bytes

		// A request that resolved to no package name (an unclassified path)
		// counts in the totals but has no package to be grouped under.
		var p *packageAgg
		if e.Package != "" {
			p = packages[key]
			if p == nil {
				p = &packageAgg{
					PackageSummary: PackageSummary{Ecosystem: e.Ecosystem, Package: e.Package},
					clients:        map[string]struct{}{},
					users:          map[string]struct{}{},
					versions:       map[string]struct{}{},
				}
				packages[key] = p
			}
			p.Downloads++
			p.Bytes += e.Bytes
			p.LastSeen = e.Time
			p.clients[e.ClientIP] = struct{}{}
			if e.Subject != "" {
				p.users[e.Subject] = struct{}{}
			}
			if e.Version != "" && len(p.versions) < maxSummaryVersions {
				p.versions[e.Version] = struct{}{}
			}
		}

		switch e.Outcome {
		case OutcomeServed:
			c.Served++
			eco.Served++
			if p != nil {
				p.Served++
			}
			if u != nil {
				u.Served++
			}
		case OutcomeBlocked:
			c.Blocked++
			eco.Blocked++
			if p != nil {
				p.Blocked++
			}
			if u != nil {
				u.Blocked++
			}
		}
	}

	sum.Clients = len(clients)
	sum.Packages = len(packages)
	sum.Users = len(users)

	for _, u := range users {
		u.Packages = len(u.packages)
		u.Addresses = len(u.addresses)
		u.ClientIPs = sortedKeys(u.addresses)
		if len(u.ClientIPs) > maxSummaryAddresses {
			u.ClientIPs = u.ClientIPs[:maxSummaryAddresses]
		}
		u.Links = sortedKeys(u.links)
		sum.ByUser = append(sum.ByUser, u.UserSummary)
	}
	sort.Slice(sum.ByUser, func(i, j int) bool {
		a, b := sum.ByUser[i], sum.ByUser[j]
		if a.Downloads != b.Downloads {
			return a.Downloads > b.Downloads
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.Subject < b.Subject
	})
	if len(sum.ByUser) > top {
		sum.ByUser = sum.ByUser[:top]
	}

	for _, c := range clients {
		c.Packages = len(c.packages)
		c.Identities = sortedKeys(c.identities)
		sum.ByClient = append(sum.ByClient, c.ClientSummary)
	}
	sort.Slice(sum.ByClient, func(i, j int) bool {
		a, b := sum.ByClient[i], sum.ByClient[j]
		if a.Downloads != b.Downloads {
			return a.Downloads > b.Downloads
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ClientIP < b.ClientIP
	})
	if len(sum.ByClient) > top {
		sum.ByClient = sum.ByClient[:top]
	}

	for _, p := range packages {
		p.Clients = len(p.clients)
		p.Users = len(p.users)
		p.Versions = sortedKeys(p.versions)
		sum.ByPackage = append(sum.ByPackage, p.PackageSummary)
	}
	sort.Slice(sum.ByPackage, func(i, j int) bool {
		a, b := sum.ByPackage[i], sum.ByPackage[j]
		if a.Downloads != b.Downloads {
			return a.Downloads > b.Downloads
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Package < b.Package
	})
	if len(sum.ByPackage) > top {
		sum.ByPackage = sum.ByPackage[:top]
	}

	for _, eco := range ecosystems {
		sum.ByEcosystem = append(sum.ByEcosystem, *eco)
	}
	sort.Slice(sum.ByEcosystem, func(i, j int) bool {
		a, b := sum.ByEcosystem[i], sum.ByEcosystem[j]
		if a.Downloads != b.Downloads {
			return a.Downloads > b.Downloads
		}
		return a.Ecosystem < b.Ecosystem
	})
	return sum, nil
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
