//go:build fuzz
// +build fuzz

// Fuzz targets for the puppet feed's parsers (Task 191): a page of the
// Forge's release listing and a module document. Neither may panic; what they
// accept must be what the adapter can hand on — modules and versions whose
// tarball paths the backend caches, times that read.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzPuppetListing$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/puppet"
)

// puppetFuzzSeeds adds the recorded fixtures of the puppet tests.
func puppetFuzzSeeds(f *testing.F, pattern string) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "feeds", "puppet", pattern))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
}

func FuzzPuppetListing(f *testing.F) {
	puppetFuzzSeeds(f, "releases-*.json")
	for _, s := range []string{``, `{}`, `{"pagination":{},"results":[]}`, `{"pagination":{"total":-3,"next":7},"results":[{}]}`,
		`{"pagination":{"next":"x"},"results":[{"slug":"a-b-1","module":{"slug":"a-b"},"version":"1","created_at":"2026-01-01 00:00:00 +0000"}]}`,
		`{"pagination":{"next":null},"results":[{"slug":"A-b-1","module":{"slug":"A-b"},"version":"1","created_at":"x"}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		lst, err := puppetParseListing(data)
		if err != nil {
			return
		}
		if len(lst.releases) > lst.count || lst.total < -1 {
			t.Fatalf("%d of %d releases, total %d", len(lst.releases), lst.count, lst.total)
		}
		for _, r := range lst.releases {
			if !puppet.ValidRelease(r.module, r.version) || r.slug != r.module+"-"+r.version || r.created.IsZero() {
				t.Fatalf("release %+v", r)
			}
			if it := (listingItem{Name: r.module, Time: r.created, ID: r.slug}); !it.valid() {
				t.Fatalf("item %+v the listing driver refuses", it)
			}
		}
	})
}

func FuzzPuppetModule(f *testing.F) {
	puppetFuzzSeeds(f, "module-*.json")
	for _, s := range []string{``, `[]`, `{"slug":"a-b"}`, `{"slug":"a-b","releases":{}}`, `{"slug":"a-b","releases":[{"version":"1.0.0"},{"version":"1.0.0"},{"version":"x/y"}]}`,
		`{"slug":"a-b","premium":"yes","releases":[]}`, `{"slug":"a-b","releases":[{"version":"1","deleted_at":{},"file_size":-5,"created_at":7}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		mod, err := puppetParseModule(data)
		if err != nil {
			return
		}
		if mod.slug == "" || len(mod.releases) > puppetMaxReleases {
			t.Fatalf("%+v", mod)
		}
		seen := map[string]bool{}
		for _, r := range mod.releases {
			if !puppet.ValidRelease(mod.slug, r.version) || seen[r.version] || r.size < 0 {
				t.Fatalf("release %+v", r)
			}
			seen[r.version] = true
		}
	})
}

func FuzzPuppetOffset(f *testing.F) {
	for _, s := range []string{"", "5", "0", "-1", "007", "99999999999", "1e3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		n, err := puppetOffset(token)
		if err != nil {
			return
		}
		if n < 0 || n > puppetMaxOffset || (token == "") != (n == 0) {
			t.Fatalf("%q read as offset %d", token, n)
		}
	})
}
