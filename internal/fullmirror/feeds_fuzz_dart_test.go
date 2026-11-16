//go:build fuzz
// +build fuzz

// Fuzz targets for the dart feed's parsers (Task 191): pub.dev's Atom feed and
// what is cleaned of it before it is parsed, a page of its package listing,
// its name list, a package's document, the feed's tokens and the page
// boundaries its cursor keeps. None may panic; what they accept must be what
// the adapter can hand on — names the backend serves, versions a path
// carries, times that read.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzDartFeed$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/backends/dart"
)

// dartFuzzSeeds adds the recorded fixtures of the dart tests.
func dartFuzzSeeds(f *testing.F, pattern string) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "feeds", "dart", pattern))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
}

func FuzzDartFeed(f *testing.F) {
	dartFuzzSeeds(f, "*.atom")
	for _, s := range []string{``, `<feed/>`, `<feed><entry><title>v1.0.0 of a</title><updated>2026-01-01T00:00:00Z</updated></entry></feed>`,
		`<feed><entry><title>v of </title><updated>x</updated><link rel="alternate" title="b"/></entry></feed>`,
		`<!DOCTYPE feed [<!ENTITY a "aaaaaaaa">]><feed><entry><title>&a;</title></entry></feed>`,
		"<feed><entry><title>v1.0.0 of a</title><updated>2026-01-01T00:00:00Z</updated><content>\x1b[32m\xff</content></entry></feed>"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := dartParseFeed(data)
		if err != nil {
			return
		}
		if len(entries) > dartMaxFeedEntries {
			t.Fatalf("%d entries", len(entries))
		}
		for _, e := range entries {
			if !dart.ValidPackageName(e.name) || !dartValidVersion(e.version) || e.published.UnixNano() <= 0 {
				t.Fatalf("entry %+v", e)
			}
			if it := (listingItem{Name: e.name, Time: e.published, ID: e.name + "@" + e.version}); !it.valid() {
				t.Fatalf("item %+v the listing driver refuses", it)
			}
		}
	})
}

func FuzzDartListing(f *testing.F) {
	dartFuzzSeeds(f, "packages-page*.json")
	for _, s := range []string{``, `{"packages":[]}`, `{"packages":["https://pub.dev/packages/a.json","/packages/b.json","%zz","https://x/packages/A.json"],"next":7}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		names, count, _, err := dartParseListing(data)
		if err != nil {
			return
		}
		if len(names) > count {
			t.Fatalf("%d names of %d URLs", len(names), count)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if !dartListedName(n) || seen[n] {
				t.Fatalf("name %q", n)
			}
			seen[n] = true
		}
	})
}

func FuzzDartNames(f *testing.F) {
	dartFuzzSeeds(f, "package-names.json")
	for _, s := range []string{``, `{"packages":null}`, `{"packages":["b","a","a","A","1x",""]}`, `{"packages":[1]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := dartParseNames(bytes.NewReader(data))
		if err != nil {
			return
		}
		if !sort.StringsAreSorted(names) {
			t.Fatalf("not sorted: %v", names)
		}
		for i, n := range names {
			if !dart.ValidPackageName(n) || (i > 0 && names[i-1] == n) {
				t.Fatalf("name %q", n)
			}
		}
	})
}

func FuzzDartDocument(f *testing.F) {
	dartFuzzSeeds(f, "package-*.json")
	for _, s := range []string{``, `{"name":"a","versions":[]}`, `{"name":"a","versions":[{"version":"1.0.0","retracted":true,"published":"x"},{"version":"1.0.0"},{"version":"a"}]}`,
		`{"name":"a","versions":{"x":1}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := dartParseDocument(data)
		if err != nil {
			return
		}
		if doc.name == "" || len(doc.versions) > dartMaxVersions {
			t.Fatalf("%+v", doc)
		}
		seen := map[string]bool{}
		for _, v := range doc.versions {
			if !dartValidVersion(v.version) || seen[v.version] {
				t.Fatalf("version %+v", v)
			}
			seen[v.version] = true
		}
	})
}

func FuzzDartToken(f *testing.F) {
	for _, s := range []string{"", "p1@1763273071303297000", dartToken{page: 3, upper: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), since: time.Unix(1763276000, 0),
		before: []string{dartAnchor("a"), dartAnchor("b")}}.String(), "p2@5@1@", "p0@1", "p1@-1", "p01@5", "p2@5@1@aaaaaaaa.bbbbbbbb.cccccccc.dddddddd", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		tok, err := dartParseToken(token, dartGapPages)
		if err != nil {
			return
		}
		if tok.page < 1 || tok.page > dartGapPages+1 || tok.upper.UnixNano() <= 0 || len(tok.before) > dartAnchors || tok.String() != token {
			t.Fatalf("%q read as %+v", token, tok)
		}
		for _, a := range tok.before {
			if !dartValidAnchor(a) {
				t.Fatalf("%q read as %+v", token, tok)
			}
		}
	})
}

func FuzzDartGap(f *testing.F) {
	for _, s := range []string{"", dartGap{Page: 2, Since: 1763276000, Before: []string{dartAnchor("a")}, After: []string{dartAnchor("b"), dartAnchor("c")}}.String(),
		"2.1763276000.0:aaaaaaaa:bbbbbbbb", "400.1.12:aaaaaaaa,bbbbbbbb,cccccccc:dddddddd", "1.1.0:a:b", "2.1.0::", "2.1.0:aaaaaaaa:bbbbbbbb:cccccccc"} {
		f.Add(s)
	}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		g, err := dartParseGap(s, dartGapPages, now)
		if err != nil {
			return
		}
		if g.Page < 2 || g.Page > dartGapPages || g.Since <= 0 || g.Since > now.Add(listingSkew).Unix() || g.Rounds < 0 ||
			len(g.Before) == 0 || len(g.Before) > dartAnchors || len(g.After) == 0 || len(g.After) > dartAnchors || g.String() != s {
			t.Fatalf("%q read as %+v", s, g)
		}
	})
}

func FuzzDartXMLText(f *testing.F) {
	dartFuzzSeeds(f, "*.atom")
	for _, s := range []string{"", "a\x00b\tc\xc3\xa9\xed\xa0\x80\uFFFE\uFFFD", "\xff\xfe\xfd", "\x1b[0m"} {
		f.Add([]byte(s))
	}
	allowed := func(r rune) bool {
		return r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out := dartXMLText(data)
		if !utf8.Valid(out) || len(out) > 3*len(data) || !bytes.Equal(dartXMLText(out), out) {
			t.Fatalf("%q cleaned to %q", data, out)
		}
		clean := utf8.Valid(data)
		for _, r := range string(data) {
			clean = clean && allowed(r)
		}
		for _, r := range string(out) {
			if !allowed(r) {
				t.Fatalf("%q cleaned to %q, which holds %U", data, out, r)
			}
		}
		if clean != bytes.Equal(out, data) {
			t.Fatalf("%q (clean %v) cleaned to %q", data, clean, out)
		}
	})
}
