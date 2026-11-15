package fullmirror_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/scancoverage"
)

// TestEveryUpstreamTypeHasAnEntry holds the catalog to the configuration: every
// upstream type the proxy accepts (config.UpstreamTypes, aliases included) must
// have an entry, so a backend cannot be added without recording how its
// registry can be followed.
func TestEveryUpstreamTypeHasAnEntry(t *testing.T) {
	types := config.UpstreamTypes()
	if len(types) < 30 {
		t.Fatalf("config.UpstreamTypes() returned only %d types", len(types))
	}
	for _, typ := range types {
		if _, ok := fullmirror.Lookup(typ); !ok {
			t.Errorf("upstream type %q has no full-mirroring entry (internal/fullmirror/catalog_data.go)", typ)
		}
	}
}

// TestEntriesAreUpstreamTypes fails on an entry or alias the configuration does
// not accept — a stale entry for a removed type, or a typo.
func TestEntriesAreUpstreamTypes(t *testing.T) {
	known := map[string]bool{}
	for _, typ := range config.UpstreamTypes() {
		known[typ] = true
	}
	for _, e := range fullmirror.Catalog() {
		for _, name := range append([]string{e.Type}, e.Aliases...) {
			if !known[name] {
				t.Errorf("entry %q names %q, which is not an upstream type the configuration accepts", e.Type, name)
			}
		}
	}
}

// TestAliasesMatchTheBackendCatalog keeps the aliases in step with the
// scan-coverage catalog, which records each type's other names: "deb" must
// lead to the same entry as "apt" everywhere.
func TestAliasesMatchTheBackendCatalog(t *testing.T) {
	for _, sc := range scancoverage.Catalog() {
		e, ok := fullmirror.Lookup(sc.Type)
		if !ok {
			t.Errorf("no entry for %q", sc.Type)
			continue
		}
		if e.Type != sc.Type {
			t.Errorf("%q is an alias here but a type in the scan-coverage catalog", sc.Type)
		}
		got := append([]string(nil), e.Aliases...)
		want := append([]string(nil), sc.Aliases...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: aliases %v, the scan-coverage catalog has %v", sc.Type, got, want)
		}
	}
}

func TestCatalogIsConsistent(t *testing.T) {
	if err := fullmirror.Validate(); err != nil {
		t.Fatal(err)
	}
	cat := fullmirror.Catalog()
	for i := 1; i < len(cat); i++ {
		if cat[i-1].Type >= cat[i].Type {
			t.Errorf("Catalog() is not sorted by type: %q before %q", cat[i-1].Type, cat[i].Type)
		}
	}
	// Catalog returns a copy: a caller cannot alter the data.
	cat[0].Type = "tampered"
	cat[1].Feeds[0].Name = "tampered"
	again := fullmirror.Catalog()
	if again[0].Type == "tampered" || again[1].Feeds[0].Name == "tampered" {
		t.Error("Catalog() hands out the catalog itself")
	}
}

func TestLookupByTypeAndAlias(t *testing.T) {
	for _, e := range fullmirror.Catalog() {
		for _, name := range append([]string{e.Type}, e.Aliases...) {
			got, ok := fullmirror.Lookup("  " + strings.ToUpper(name) + " ")
			if !ok || got.Type != e.Type {
				t.Errorf("Lookup(%q) = %q, %v; want %q", name, got.Type, ok, e.Type)
			}
		}
	}
	for _, name := range []string{"", "cobol"} {
		if _, ok := fullmirror.Lookup(name); ok {
			t.Errorf("Lookup(%q) found an entry", name)
		}
	}
}

// TestTiers pins every type's tier. The tiers decide which adapter follows a
// registry, so moving a type is a decision that must show up in review — and
// several differ from what one would guess (PyPI's feed is deprecated-in-
// waiting yet still (a); Homebrew is (a) through homebrew-core's history; Open
// VSX publishes a complete sitemap; the Terraform registry can be listed, just
// not by time). The prose of docs/full-mirroring.md names examples per tier:
// update it with this table.
func TestTiers(t *testing.T) {
	want := map[fullmirror.Tier][]string{
		fullmirror.TierFeed:    {"bazel", "cargo", "composer", "conan", "cpan", "go", "hackage", "homebrew", "julia", "npm", "nuget", "pip", "rubygems"},
		fullmirror.TierIndex:   {"apt", "conda", "cran", "helm", "hex", "maven", "openvsx", "yum"},
		fullmirror.TierListing: {"ansible", "dart", "huggingface", "jsr", "puppet", "terraform"},
		fullmirror.TierNone:    {"docker", "generic", "git", "nix", "swift"},
	}
	total := 0
	for _, tier := range fullmirror.Tiers() {
		var got []string
		for _, e := range fullmirror.ByTier(tier) {
			got = append(got, e.Type)
		}
		total += len(got)
		if strings.Join(got, ",") != strings.Join(want[tier], ",") {
			t.Errorf("tier (%s): %v, want %v", tier, got, want[tier])
		}
	}
	if total != len(fullmirror.Catalog()) {
		t.Errorf("the tiers hold %d entries, the catalog %d", total, len(fullmirror.Catalog()))
	}
}

// TestClaimsThatChangeWhatAMirrorMayDo pins the findings an operator must not
// miss: terms that forbid or bound full mirroring, and a backend limitation
// the research turned up.
func TestClaimsThatChangeWhatAMirrorMayDo(t *testing.T) {
	for _, c := range []struct{ typ, field, want string }{
		{"maven", "terms", "Full mirroring is forbidden"},
		{"npm", "terms", "five million requests"},
		{"docker", "terms", "mirror or replicate content for an unauthorized commercial service"},
		{"composer", "feed", "kept for up to 24h"},
		{"rubygems", "feed", "recalculated at the start of each month"},
		{"yum", "notes", "serves RPMs unverified"},
	} {
		e, ok := fullmirror.Lookup(c.typ)
		if !ok {
			t.Fatalf("no entry for %s", c.typ)
		}
		var text string
		switch c.field {
		case "terms":
			text = e.Terms
		case "feed":
			text = e.Feeds[0].Semantics
		case "notes":
			text = strings.Join(e.Notes, " ")
		}
		if !strings.Contains(text, c.want) {
			t.Errorf("%s: the %s no longer say %q", c.typ, c.field, c.want)
		}
	}
}

func TestReferenceListsEveryType(t *testing.T) {
	ref := fullmirror.GenerateReference()
	if !strings.HasPrefix(ref, fullmirror.ReferenceBegin) || !strings.HasSuffix(ref, fullmirror.ReferenceEnd+"\n") {
		t.Fatal("the generated part does not start and end with its markers")
	}
	for _, e := range fullmirror.Catalog() {
		if !strings.Contains(ref, "\n### "+e.Type+"\n") {
			t.Errorf("no section for %s", e.Type)
		}
		if !strings.Contains(ref, "| [`"+e.Type+"`](#"+e.Type+")") {
			t.Errorf("no summary row for %s", e.Type)
		}
		for _, f := range e.Feeds {
			if !strings.Contains(ref, "`"+f.URL+"`") {
				t.Errorf("%s: the feed %q is not rendered", e.Type, f.Name)
			}
		}
	}
}

// TestProseQuantitiesComeFromTheCatalog keeps the hand-written part of
// docs/full-mirroring.md honest: every size and rate it quotes (a number with
// KB…PB, "N requests", "N API calls", "N per M hours") must appear, spelled
// the same way, in the generated part — so changing a figure in the catalog
// without the prose that repeats it fails here.
func TestProseQuantitiesComeFromTheCatalog(t *testing.T) {
	doc, err := os.ReadFile("../../docs/full-mirroring.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	i := strings.Index(text, fullmirror.ReferenceBegin)
	j := strings.Index(text, fullmirror.ReferenceEnd)
	if i < 0 || j < i {
		t.Fatal("docs/full-mirroring.md has no generated part")
	}
	prose := text[:i] + text[j+len(fullmirror.ReferenceEnd):]
	generated := fullmirror.GenerateReference()
	quantity := regexp.MustCompile(`\b\d[\d,]*(?:\.\d+)?\s?(?:KB|MB|GB|TB|PB|GiB)\b|\b\d[\d,]* (?:requests|API calls)\b|\b\d[\d,]* per \d+ (?:hours|minutes)\b`)
	found := quantity.FindAllString(prose, -1)
	if len(found) < 10 {
		t.Fatalf("only %d quantities found in the prose — has the page or the pattern changed? %v", len(found), found)
	}
	for _, q := range found {
		if !strings.Contains(generated, q) {
			t.Errorf("the prose quotes %q, which the catalog does not say (spelled this way)", q)
		}
	}
}

// TestReferenceIsCurrent fails when docs/full-mirroring.md no longer matches
// the catalog — the same check as `make full-mirroring-reference-check`, so
// `go test ./...` catches it too.
func TestReferenceIsCurrent(t *testing.T) {
	doc, err := os.ReadFile("../../docs/full-mirroring.md")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := fullmirror.SpliceReference(string(doc), fullmirror.GenerateReference())
	if err != nil {
		t.Fatal(err)
	}
	if updated != string(doc) {
		t.Error("docs/full-mirroring.md is stale; run `make full-mirroring-reference-gen` and commit the result")
	}
}

func TestSpliceReference(t *testing.T) {
	gen := fullmirror.ReferenceBegin + "\nnew\n" + fullmirror.ReferenceEnd + "\n"
	doc := "# Title\n\nprose before\n\n" + fullmirror.ReferenceBegin + "\nold\n" + fullmirror.ReferenceEnd + "\n\nprose after\n"
	got, err := fullmirror.SpliceReference(doc, gen)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Title\n\nprose before\n\n" + gen + "\nprose after\n"
	if got != want {
		t.Errorf("splice:\n%q\nwant\n%q", got, want)
	}
	if again, _ := fullmirror.SpliceReference(got, gen); again != got {
		t.Error("splicing the same part twice changed the document")
	}
	for name, bad := range map[string]string{
		"no markers":   "# Title\n",
		"no end":       fullmirror.ReferenceBegin + "\n",
		"out of order": fullmirror.ReferenceEnd + "\n" + fullmirror.ReferenceBegin + "\n",
		"two parts":    doc + doc,
	} {
		if _, err := fullmirror.SpliceReference(bad, gen); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
