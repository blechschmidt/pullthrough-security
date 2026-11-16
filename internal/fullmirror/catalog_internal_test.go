package fullmirror

import (
	"strings"
	"testing"
)

// validEntry is a minimal entry Validate accepts; the cases below break one
// thing each.
func validEntry() Entry {
	return Entry{
		Type: "npm", Title: "npm", Registry: "https://registry.npmjs.org", Tier: TierFeed,
		Feeds: []FeedSpec{{
			Name: "changes", URL: "https://replicate.npmjs.com/_changes?since={seq}", Cursor: CursorSequence,
			Semantics: "ordered by seq", Verified: "2026-11-15: 200",
		}},
		RateLimits: "none", Terms: "allowed", Size: Size{Figure: "big", Basis: "count"}, Private: "none",
		Sources: []Source{{Title: "docs", URL: "https://docs.npmjs.com/"}},
		Status:  ImplStatus{State: StateNotStarted},
	}
}

func TestValidateRejectsBrokenEntries(t *testing.T) {
	saved := catalog
	t.Cleanup(func() { catalog = saved })

	catalog = []Entry{validEntry()}
	if err := Validate(); err != nil {
		t.Fatalf("the valid entry was refused: %v", err)
	}

	cases := []struct {
		name  string
		edit  func([]Entry) []Entry
		match string
	}{
		{"duplicate type", func(c []Entry) []Entry { return append(c, c[0]) }, "claimed by both"},
		{"alias of another type", func(c []Entry) []Entry {
			o := validEntry()
			o.Type, o.Aliases = "pip", []string{"npm"}
			return append(c, o)
		}, "claimed by both"},
		{"upper-case type", func(c []Entry) []Entry { c[0].Type = "NPM"; return c }, "lower-case"},
		{"no title", func(c []Entry) []Entry { c[0].Title = ""; return c }, "empty title"},
		{"no terms", func(c []Entry) []Entry { c[0].Terms = " "; return c }, "empty terms"},
		{"no size basis", func(c []Entry) []Entry { c[0].Size.Basis = ""; return c }, "empty size basis"},
		{"http registry", func(c []Entry) []Entry { c[0].Registry = "http://registry.npmjs.org"; return c }, "https"},
		{"no registry outside tier d", func(c []Entry) []Entry { c[0].Registry = ""; return c }, "no registry"},
		{"unknown tier", func(c []Entry) []Entry { c[0].Tier = "e"; return c }, "unknown tier"},
		{"undated check", func(c []Entry) []Entry { c[0].Feeds[0].Verified = "returned 200"; return c }, "start with its date"},
		{"impossible date", func(c []Entry) []Entry { c[0].Feeds[0].Verified = "2026-13-45: 200"; return c }, "not a date"},
		{"credentials in a URL", func(c []Entry) []Entry {
			c[0].Feeds[0].URL = "https://user:secret@replicate.npmjs.com/_changes"
			return c
		}, "https URL"},
		{"a later complete feed outranks tier b", func(c []Entry) []Entry {
			c[0].Tier = TierIndex
			c[0].Feeds = []FeedSpec{
				{Name: "index", URL: "https://x.example/index", Cursor: CursorValidator, Semantics: "s", Verified: "2026-11-15: 200"},
				{Name: "commits", URL: "https://x.example/git", Cursor: CursorCommit, Semantics: "s", Verified: "2026-11-15: 200"},
			}
			return c
		}, "makes this a tier-(a) entry"},
		{"a later complete index outranks tier c", func(c []Entry) []Entry {
			c[0].Tier = TierListing
			c[0].Feeds = []FeedSpec{
				{Name: "listing", URL: "https://x.example/list?page={page}", Cursor: CursorPage, Semantics: "s", Verified: "2026-11-15: 200"},
				{Name: "index", URL: "https://x.example/index", Cursor: CursorValidator, Semantics: "s", Verified: "2026-11-15: 200"},
			}
			return c
		}, "makes this a tier-(b) entry"},
		{"no semantics", func(c []Entry) []Entry { c[0].Feeds[0].Semantics = ""; return c }, "needs a name"},
		{"unknown cursor", func(c []Entry) []Entry { c[0].Feeds[0].Cursor = "vibes"; return c }, "unknown cursor"},
		{"relative feed URL", func(c []Entry) []Entry { c[0].Feeds[0].URL = "/_changes"; return c }, "https"},
		{"broken placeholder", func(c []Entry) []Entry { c[0].Feeds[0].URL = "https://x.example/{since"; return c }, "URL template"},
		{"tier a led by a partial feed", func(c []Entry) []Entry { c[0].Feeds[0].Partial = true; return c }, "tier-(a)"},
		{"tier a led by a listing", func(c []Entry) []Entry { c[0].Feeds[0].Cursor = CursorPage; return c }, "tier-(a)"},
		{"tier a without feeds", func(c []Entry) []Entry { c[0].Feeds = nil; return c }, "tier-(a)"},
		{"tier b led by a sequence", func(c []Entry) []Entry { c[0].Tier = TierIndex; return c }, "tier-(b)"},
		{"tier c led by a validator", func(c []Entry) []Entry {
			c[0].Tier, c[0].Feeds[0].Cursor = TierListing, CursorValidator
			return c
		}, "tier-(c)"},
		{"tier d with a complete feed", func(c []Entry) []Entry { c[0].Tier = TierNone; return c }, "tier-(d)"},
		{"tier d implemented", func(c []Entry) []Entry {
			c[0].Tier, c[0].Feeds[0].Partial, c[0].Status.State = TierNone, true, StateImplemented
			return c
		}, "cannot be fully implemented"},
		{"no sources", func(c []Entry) []Entry { c[0].Sources = nil; return c }, "no sources"},
		{"source without a title", func(c []Entry) []Entry { c[0].Sources[0].Title = ""; return c }, "without a title"},
		{"source that is not a URL", func(c []Entry) []Entry { c[0].Sources[0].URL = "npm docs"; return c }, "https"},
		{"unknown state", func(c []Entry) []Entry { c[0].Status.State = "done-ish"; return c }, "unknown implementation state"},
	}
	for _, tc := range cases {
		catalog = tc.edit([]Entry{validEntry()})
		err := Validate()
		if err == nil || !strings.Contains(err.Error(), tc.match) {
			t.Errorf("%s: Validate() = %v, want an error containing %q", tc.name, err, tc.match)
		}
	}

	// A partial feed may be better than the tier: it does not cover the registry.
	partial := validEntry()
	partial.Tier = TierListing
	partial.Feeds = []FeedSpec{
		{Name: "listing", URL: "https://x.example/list?page={page}", Cursor: CursorPage, Semantics: "s", Verified: "2026-11-15: 200"},
		{Name: "other registry", URL: "https://x.example/git", Cursor: CursorCommit, Partial: true, Semantics: "s", Verified: "2026-11-15: 200"},
	}
	catalog = []Entry{partial}
	if err := Validate(); err != nil {
		t.Errorf("a partial feed better than the tier was refused: %v", err)
	}

	// A tier-(d) type without a public registry and without feeds is fine.
	none := validEntry()
	none.Tier, none.Registry, none.Feeds, none.Status.State = TierNone, "", nil, StateNotApplicable
	catalog = []Entry{none}
	if err := Validate(); err != nil {
		t.Errorf("a tier-(d) entry without a registry was refused: %v", err)
	}
}

func TestCheckURLTemplates(t *testing.T) {
	for _, ok := range []string{
		"https://index.golang.org/index?since={timestamp}&limit=2000",
		"https://registry.terraform.io/v2/providers?page%5Bsize%5D=100&page%5Bnumber%5D={page}",
		"https://github.com/rust-lang/crates.io-index",
	} {
		if err := checkURL(ok, true); err != nil {
			t.Errorf("checkURL(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://example.com/", "ftp://example.com/", "https://", "https://x.example/{1bad}", "https://x.example/a b"} {
		if err := checkURL(bad, true); err == nil {
			t.Errorf("checkURL(%q) accepted it", bad)
		}
	}
	if err := checkURL("https://x.example/{seq}", false); err == nil {
		t.Error("a placeholder was accepted outside a template")
	}
}

func TestEveryTierAndCursorIsDescribed(t *testing.T) {
	for _, tier := range Tiers() {
		if tier.Title() == "unknown tier" || tier.Description() == "" {
			t.Errorf("tier %q has no title or description", tier)
		}
	}
	for k := range cursorKinds {
		if k.Description() == "" {
			t.Errorf("cursor kind %q has no description", k)
		}
	}
}
