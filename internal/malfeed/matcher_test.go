package malfeed

import "testing"

func buildFixtureMatcher(t *testing.T) *Matcher {
	t.Helper()
	entries, err := ParseOSVStream([]byte(fixtureFeed), "osv-malicious-packages")
	if err != nil {
		t.Fatalf("parse fixture feed: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries from fixture, got %d", len(entries))
	}
	return NewMatcher(entries)
}

func TestMatcher_WholePackageMatch(t *testing.T) {
	m := buildFixtureMatcher(t)

	// AllVersions: matches with or without a version, and across name spellings
	// (npm is case-insensitive).
	cases := []Coordinate{
		{Ecosystem: "npm", Name: "Evil-Stealer", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "evil-stealer", Version: ""},
		{Ecosystem: "node", Name: "EVIL-STEALER", Version: "9.9.9"},
	}
	for _, c := range cases {
		got := m.Match(c)
		if !got.Matched {
			t.Fatalf("expected match for %+v", c)
		}
		if got.Entry.ID != "MAL-2024-0001" {
			t.Fatalf("wrong entry for %+v: %s", c, got.Entry.ID)
		}
	}
}

func TestMatcher_ExplicitVersions(t *testing.T) {
	m := buildFixtureMatcher(t)

	// PyPI name is normalized (PEP 503): crypto_miner_pkg ≡ crypto-miner-pkg.
	if got := m.Match(Coordinate{Ecosystem: "pip", Name: "Crypto-Miner-Pkg", Version: "1.0.0"}); !got.Matched {
		t.Fatal("expected match for pinned version 1.0.0")
	}
	if got := m.Match(Coordinate{Ecosystem: "PyPI", Name: "crypto_miner_pkg", Version: "1.0.1"}); !got.Matched {
		t.Fatal("expected match for pinned version 1.0.1")
	}
	// A version not in the list is allowed.
	if got := m.Match(Coordinate{Ecosystem: "pip", Name: "crypto-miner-pkg", Version: "2.0.0"}); got.Matched {
		t.Fatal("did not expect match for unlisted version 2.0.0")
	}
	// A version-less lookup of a version-specific entry must NOT block.
	if got := m.Match(Coordinate{Ecosystem: "pip", Name: "crypto-miner-pkg"}); got.Matched {
		t.Fatal("version-less lookup of a version-specific entry must not match")
	}
}

func TestMatcher_RangeMembership(t *testing.T) {
	m := buildFixtureMatcher(t)

	inRange := []string{"1.2.0", "1.3.5", "1.4.99"}
	for _, v := range inRange {
		if got := m.Match(Coordinate{Ecosystem: "cargo", Name: "bad_crate", Version: v}); !got.Matched {
			t.Fatalf("expected %s in affected range", v)
		}
	}
	outOfRange := []string{"1.1.9", "1.5.0", "2.0.0"}
	for _, v := range outOfRange {
		if got := m.Match(Coordinate{Ecosystem: "cargo", Name: "bad-crate", Version: v}); got.Matched {
			t.Fatalf("did not expect %s in affected range", v)
		}
	}
}

func TestMatcher_PURLRecovery(t *testing.T) {
	m := buildFixtureMatcher(t)
	// Name recovered from the purl; NuGet is case-insensitive.
	if got := m.Match(Coordinate{Ecosystem: "nuget", Name: "contoso.evil", Version: "2.0.0"}); !got.Matched {
		t.Fatal("expected match for purl-recovered NuGet package")
	}
}

func TestMatcher_NoFalsePositive(t *testing.T) {
	m := buildFixtureMatcher(t)
	clean := []Coordinate{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: "pip", Name: "requests", Version: "2.31.0"},
		{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "", Version: "1.0.0"}, // nameless: never matches
	}
	for _, c := range clean {
		if got := m.Match(c); got.Matched {
			t.Fatalf("unexpected match for clean coordinate %+v", c)
		}
	}
}

func TestMatcher_CountsAndSearch(t *testing.T) {
	m := buildFixtureMatcher(t)
	if m.Len() != 4 {
		t.Fatalf("expected 4 entries, got %d", m.Len())
	}
	counts := m.CountsByEcosystem()
	for _, eco := range []string{"npm", "pip", "cargo", "nuget"} {
		if counts[eco] != 1 {
			t.Fatalf("expected 1 entry for %s, got %d", eco, counts[eco])
		}
	}

	// Search by category, id, and ecosystem filter.
	if got := m.Search("crypto-miner", "", 0); len(got) != 1 || got[0].ID != "MAL-2024-0002" {
		t.Fatalf("category search failed: %+v", got)
	}
	if got := m.Search("MAL-2024-0003", "", 0); len(got) != 1 || got[0].ID != "MAL-2024-0003" {
		t.Fatalf("id search failed: %+v", got)
	}
	if got := m.Search("", "npm", 0); len(got) != 1 {
		t.Fatalf("ecosystem filter failed: %+v", got)
	}
	if got := m.Search("", "", 2); len(got) != 2 {
		t.Fatalf("limit not honored: got %d", len(got))
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0-rc1", 1}, // release > pre-release
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0", "1.0.0", 0}, // missing segment treated as 0
	}
	for _, c := range cases {
		if got := compareVersions("", c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
