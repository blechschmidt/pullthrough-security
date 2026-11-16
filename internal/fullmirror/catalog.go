// Package fullmirror records, for every upstream type the proxy fronts, how a
// mirror can learn about new uploads before any client asks for them — the
// research full mirroring is built on.
//
// Pull-through serves what clients request: a version nobody has asked for yet
// has never passed the gates. A full mirror instead follows the registry and
// fetches (and scans) each new upload as it appears. Whether that is possible,
// and at what cost, differs per registry: npm and PyPI publish a change feed
// with a resumable cursor, APT and CRAN publish a complete index to poll and
// diff, Open VSX-style registries only offer listings, and Docker Hub cannot be
// enumerated at all. Catalog holds one Entry per upstream type with its Tier,
// the feeds it offers (endpoint template, cursor kind, semantics, the live
// check that confirmed it), rate and terms-of-use limits, the realistic size of
// a full mirror, how private and self-hosted upstreams differ, and sources.
//
// The catalog is data, not code that fetches anything. docs/full-mirroring.md
// is generated from it (GenerateReference, `make full-mirroring-reference-gen`)
// and CI fails when the page is stale; a test holds the catalog to
// config.UpstreamTypes so a new backend cannot arrive without an entry. Each
// entry's Status is the implementation-status column: the tasks that add the
// full-mirror engine and its feed adapters set it.
package fullmirror

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Tier says how a mirror can learn about new uploads ahead of any client
// request. Lower letters are cheaper and more complete to follow.
type Tier string

const (
	// TierFeed is an incremental change feed with a resumable cursor: the
	// follower asks for the changes since the cursor it stored and gets only
	// those (npm's _changes sequence, PyPI's serial, a Git-backed index's
	// commits, an append-only file's length).
	TierFeed Tier = "a"
	// TierIndex is a complete index the follower polls and diffs against its
	// previous copy (APT Packages, CRAN PACKAGES, Hex /versions). Some offer a
	// cheaper delta of the index (APT pdiffs, conda's sharded repodata).
	TierIndex Tier = "b"
	// TierListing is a registry that offers only paginated listings: the
	// follower pages until it reaches what it has already seen — or, when the
	// listing is not sorted by time, reads all of it.
	TierListing Tier = "c"
	// TierNone is a registry with no practical way to enumerate its content.
	// Only what clients request (or a partial feed: one channel, the
	// repositories one names) can be mirrored.
	TierNone Tier = "d"
)

// Tiers lists the tiers in order.
func Tiers() []Tier { return []Tier{TierFeed, TierIndex, TierListing, TierNone} }

// Title is the tier's heading.
func (t Tier) Title() string {
	switch t {
	case TierFeed:
		return "incremental change feed"
	case TierIndex:
		return "complete index to poll and diff"
	case TierListing:
		return "paginated listings only"
	case TierNone:
		return "no practical enumeration"
	}
	return "unknown tier"
}

// CursorKind is what a follower stores to resume where it stopped.
type CursorKind string

const (
	// CursorSequence is an integer the registry assigns to every change, in
	// order (npm's seq, PyPI's serial).
	CursorSequence CursorKind = "sequence"
	// CursorTimestamp is a time the registry stamps on every change, compared
	// against the registry's clock, never the follower's (the Go module
	// index, the NuGet catalog, Packagist, CPAN's RECENT files).
	CursorTimestamp CursorKind = "timestamp"
	// CursorCommit is a commit of the Git repository the registry is built
	// from; the follower fetches and diffs the trees.
	CursorCommit CursorKind = "commit"
	// CursorOffset is the length of an append-only file already read; the
	// follower fetches the rest with an HTTP Range request.
	CursorOffset CursorKind = "byte offset"
	// CursorValidator is the ETag, Last-Modified or digest of the copy of a
	// complete index the follower holds: a conditional request answers
	// "unchanged", otherwise the new index is diffed against the old one.
	CursorValidator CursorKind = "validator"
	// CursorPage is a position in a listing — a page number, an offset or an
	// opaque keyset cursor — together with the newest item already seen.
	CursorPage CursorKind = "page"
)

// cursorKinds is the closed set Validate accepts.
var cursorKinds = map[CursorKind]bool{
	CursorSequence: true, CursorTimestamp: true, CursorCommit: true,
	CursorOffset: true, CursorValidator: true, CursorPage: true,
}

// resumable reports whether a cursor of this kind names a point in a sequence
// of changes, so that "changes since the cursor" is an answerable question.
func (k CursorKind) resumable() bool {
	switch k {
	case CursorSequence, CursorTimestamp, CursorCommit, CursorOffset:
		return true
	}
	return false
}

// tier is the tier a complete feed with a cursor of this kind gives a
// registry: a resumable cursor is a change feed, a validator a complete index,
// a page a listing.
func (k CursorKind) tier() Tier {
	switch {
	case k.resumable():
		return TierFeed
	case k == CursorValidator:
		return TierIndex
	}
	return TierListing
}

// FeedSpec is one way to learn what a registry holds or what changed in it.
type FeedSpec struct {
	// Name is a short label ("replication feed", "complete index").
	Name string
	// URL is the endpoint as a template: {placeholders} stand for the cursor
	// or the parts of the path the follower fills in. A Git-backed feed names
	// the repository's clone URL.
	URL string
	// Cursor is what the follower stores between runs.
	Cursor CursorKind
	// Semantics says how the cursor works: ordering, page sizes, how long the
	// registry keeps the history, what one item carries and what the
	// follower has to fetch next.
	Semantics string
	// Partial marks a feed that covers only part of the registry (one channel,
	// the latest version of each package, package names without versions).
	Partial bool
	// Verified is the live request that confirmed the feed: when, what was
	// asked and what came back.
	Verified string
}

// Size is the realistic size of a full mirror.
type Size struct {
	// Figure is the size, as precise as the evidence allows, or what is
	// known instead (a package count).
	Figure string
	// Basis says where the figure comes from: a statistic the registry
	// publishes, a live count, or an estimate and how it was made.
	Basis string
}

// Source is a document an entry's claims rest on.
type Source struct {
	Title string
	URL   string
}

// State is how far the proxy implements full mirroring for a type.
type State string

const (
	// StateNotStarted: no feed adapter yet. Every entry starts here.
	StateNotStarted State = "not started"
	// StatePartial: some of the type's feeds, or some of a feed, is followed.
	StatePartial State = "partial"
	// StateImplemented: the proxy follows the type's recommended feed.
	StateImplemented State = "implemented"
	// StateNotApplicable: the registry offers nothing to follow.
	StateNotApplicable State = "not applicable"
)

var states = map[State]bool{StateNotStarted: true, StatePartial: true, StateImplemented: true, StateNotApplicable: true}

// ImplStatus is the implementation-status column of the generated page.
type ImplStatus struct {
	State State
	// Note says what is (or will be) implemented and where.
	Note string
}

// Entry describes how one upstream type's public registry can be followed.
type Entry struct {
	// Type is the upstream type as configured; Aliases are its other accepted
	// names ("deb" for "apt").
	Type    string
	Aliases []string
	// Title is the registry's display name.
	Title string
	// Registry is the public registry the entry describes — the upstream URL
	// the proxy's documentation uses for the type. Empty for a type that has
	// no public registry (generic).
	Registry string
	// Tier is how the registry can be followed, by its best feed.
	Tier Tier
	// Feeds are the ways to follow or enumerate the registry, the
	// recommended one first.
	Feeds []FeedSpec
	// RateLimits states the published (or observed) request limits.
	RateLimits string
	// Terms states what the registry's terms of use and mirroring policy say
	// about bulk downloads and mirrors.
	Terms string
	// Size is the realistic size of a full mirror.
	Size Size
	// Private says how private and self-hosted upstreams of the type
	// (Artifactory, Nexus, the ecosystem's own servers) differ.
	Private string
	// Notes are caveats worth a sentence each.
	Notes []string
	// Sources are the documents the entry rests on.
	Sources []Source
	// Status is how far the proxy implements it.
	Status ImplStatus
}

// Catalog returns the entries, sorted by type. The slice is a copy.
func Catalog() []Entry {
	out := make([]Entry, len(catalog))
	for i, e := range catalog {
		e.Aliases = append([]string(nil), e.Aliases...)
		e.Feeds = append([]FeedSpec(nil), e.Feeds...)
		e.Notes = append([]string(nil), e.Notes...)
		e.Sources = append([]Source(nil), e.Sources...)
		out[i] = e
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Lookup returns the entry for an upstream type, by its name or an alias.
func Lookup(upstreamType string) (Entry, bool) {
	t := strings.ToLower(strings.TrimSpace(upstreamType))
	for _, e := range Catalog() {
		if e.Type == t {
			return e, true
		}
		for _, a := range e.Aliases {
			if a == t {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// ByTier returns the entries of one tier, sorted by type.
func ByTier(t Tier) []Entry {
	var out []Entry
	for _, e := range Catalog() {
		if e.Tier == t {
			out = append(out, e)
		}
	}
	return out
}

// placeholder matches a {name} in a URL template.
var placeholder = regexp.MustCompile(`\{[A-Za-z][A-Za-z0-9_-]*\}`)

// datedCheck matches a live check that says when it was made.
var datedCheck = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}: \S`)

// Validate checks the catalog's own consistency: unique types and aliases,
// known tiers, cursor kinds and states, every field filled in, dated live
// checks, URLs that parse, and feeds that fit the tier — a tier-(a) entry
// leads with a resumable cursor, a tier-(b) entry with a complete index, a
// tier-(c) entry with a listing, a tier-(d) entry has at most partial feeds,
// and no complete feed is better than the entry's tier (the tier is the best
// feed's).
func Validate() error {
	seen := map[string]string{}
	claim := func(name, owner string) error {
		if name != strings.ToLower(strings.TrimSpace(name)) || name == "" {
			return fmt.Errorf("fullmirror: %q (of %q) is not a lower-case type name", name, owner)
		}
		if prev, dup := seen[name]; dup {
			return fmt.Errorf("fullmirror: %q is claimed by both %q and %q", name, prev, owner)
		}
		seen[name] = owner
		return nil
	}
	for _, e := range catalog {
		if err := claim(e.Type, e.Type); err != nil {
			return err
		}
		for _, a := range e.Aliases {
			if err := claim(a, e.Type); err != nil {
				return err
			}
		}
		if err := validateEntry(e); err != nil {
			return fmt.Errorf("fullmirror: %s: %w", e.Type, err)
		}
	}
	return nil
}

func validateEntry(e Entry) error {
	for name, v := range map[string]string{
		"title": e.Title, "rate limits": e.RateLimits, "terms": e.Terms,
		"size": e.Size.Figure, "size basis": e.Size.Basis, "private upstreams": e.Private,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("empty %s", name)
		}
	}
	switch {
	case e.Registry == "" && e.Tier != TierNone:
		return fmt.Errorf("no registry: only a tier-(d) type without a public registry may leave it empty")
	case e.Registry != "":
		if err := checkURL(e.Registry, false); err != nil {
			return fmt.Errorf("registry: %w", err)
		}
	}
	switch e.Tier {
	case TierFeed, TierIndex, TierListing, TierNone:
	default:
		return fmt.Errorf("unknown tier %q", e.Tier)
	}
	for i, f := range e.Feeds {
		if strings.TrimSpace(f.Name) == "" || strings.TrimSpace(f.Semantics) == "" || strings.TrimSpace(f.Verified) == "" {
			return fmt.Errorf("feed %d (%q) needs a name, semantics and the live check that verified it", i, f.Name)
		}
		if !datedCheck.MatchString(f.Verified) {
			return fmt.Errorf("feed %q: the live check must start with its date (\"2006-01-02: …\"): %q", f.Name, f.Verified)
		}
		if _, err := time.Parse("2006-01-02", f.Verified[:10]); err != nil {
			return fmt.Errorf("feed %q: the live check's date is not a date: %w", f.Name, err)
		}
		if !cursorKinds[f.Cursor] {
			return fmt.Errorf("feed %q: unknown cursor kind %q", f.Name, f.Cursor)
		}
		if err := checkURL(f.URL, true); err != nil {
			return fmt.Errorf("feed %q: %w", f.Name, err)
		}
	}
	var lead *FeedSpec
	if len(e.Feeds) > 0 {
		lead = &e.Feeds[0]
	}
	switch e.Tier {
	case TierFeed:
		if lead == nil || lead.Partial || !lead.Cursor.resumable() {
			return fmt.Errorf("a tier-(a) entry must lead with a complete feed with a resumable cursor")
		}
	case TierIndex:
		if lead == nil || lead.Partial || lead.Cursor != CursorValidator {
			return fmt.Errorf("a tier-(b) entry must lead with a complete index (cursor %q)", CursorValidator)
		}
	case TierListing:
		if lead == nil || lead.Partial || lead.Cursor != CursorPage {
			return fmt.Errorf("a tier-(c) entry must lead with a listing (cursor %q)", CursorPage)
		}
	case TierNone:
		for _, f := range e.Feeds {
			if !f.Partial {
				return fmt.Errorf("a tier-(d) entry can only have partial feeds; %q is complete", f.Name)
			}
		}
	}
	// The tier is the best complete feed's: a later feed may not outrank it.
	for _, f := range e.Feeds {
		if t := f.Cursor.tier(); !f.Partial && t < e.Tier {
			return fmt.Errorf("the complete feed %q (cursor %q) makes this a tier-(%s) entry, not (%s); mark the feed partial or raise the tier", f.Name, f.Cursor, t, e.Tier)
		}
	}
	if len(e.Sources) == 0 {
		return fmt.Errorf("no sources")
	}
	for _, s := range e.Sources {
		if strings.TrimSpace(s.Title) == "" {
			return fmt.Errorf("a source without a title: %s", s.URL)
		}
		if err := checkURL(s.URL, false); err != nil {
			return fmt.Errorf("source %q: %w", s.Title, err)
		}
	}
	if !states[e.Status.State] {
		return fmt.Errorf("unknown implementation state %q", e.Status.State)
	}
	if e.Tier == TierNone && e.Status.State == StateImplemented {
		return fmt.Errorf("a tier-(d) entry cannot be fully implemented")
	}
	return nil
}

// checkURL accepts an absolute https URL; with template set, {placeholders}
// may stand anywhere in it.
func checkURL(raw string, template bool) error {
	s := raw
	if template {
		s = placeholder.ReplaceAllString(raw, "x")
	}
	u, err := url.Parse(s)
	if err == nil && !strings.ContainsAny(s, "{} \t\n") && u.Scheme == "https" && u.Host != "" && u.User == nil {
		return nil
	}
	if template && strings.ContainsAny(raw, "{}") {
		return fmt.Errorf("%q is not an absolute https URL template (placeholders are {name})", raw)
	}
	return fmt.Errorf("%q is not an absolute https URL", raw)
}
