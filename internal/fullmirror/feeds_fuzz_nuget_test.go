//go:build fuzz
// +build fuzz

package fullmirror

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// Fuzz targets for the NuGet feed adapter's parsers (Task 190): the service
// index, the catalog index and pages, and the flat container's version list
// are registry input. None may panic, and what they return must be what the
// adapter can hand on: valid ids and versions, pages in commit order on the
// catalog's origin.

// nugetFuzzSeeds adds the recorded fixtures of the NuGet tests.
func nugetFuzzSeeds(f *testing.F, pattern string) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "feeds", "nuget", pattern))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
}

func FuzzNuGetServiceIndex(f *testing.F) {
	nugetFuzzSeeds(f, "service-index.json")
	f.Add([]byte(`{"resources":[{"@id":"x","@type":["Catalog/3.0.0",7]},{"@id":"","@type":"A"},{"@type":null}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := nugetParseServiceIndex(data)
		if err != nil {
			return
		}
		for _, r := range res {
			if r.ID == "" || len(r.Types) == 0 {
				t.Fatalf("resource %+v", r)
			}
		}
		_ = nugetResourceURL(res, nugetCatalogType)
	})
}

func FuzzNuGetCatalogIndex(f *testing.F) {
	nugetFuzzSeeds(f, "catalog-index.json")
	f.Add([]byte(`{"commitTimeStamp":"2026-11-16T02:14:09.8253348Z","items":[{"@id":"https://api.nuget.org/v3/catalog0/page2.json","commitTimeStamp":"2026-11-16T02:14:09Z"},{"@id":"https://api.nuget.org/v3/catalog0/page10.json","commitTimeStamp":"2026-11-16T02:14:09Z"}]}`))
	catalog, _ := url.Parse("https://api.nuget.org/v3/catalog0/index.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := nugetParseCatalogIndex(data, catalog)
		if err != nil {
			return
		}
		for i, p := range idx.Pages {
			if !nugetOnOrigin(catalog, p.URL) || p.TS.After(idx.TS) {
				t.Fatalf("page %+v of an index committed at %v", p, idx.TS)
			}
			if i > 0 && p.TS.Before(idx.Pages[i-1].TS) {
				t.Fatalf("pages out of commit order: %+v after %+v", p, idx.Pages[i-1])
			}
		}
	})
}

func FuzzNuGetCatalogPage(f *testing.F) {
	nugetFuzzSeeds(f, "page-*.json")
	f.Add([]byte(`{"items":[{"@type":["PackageDelete"],"nuget:id":"a.b","nuget:version":"1.0.0-RC+x","commitTimeStamp":"2026-11-16T00:00:00.1Z"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		leaves, err := nugetParseCatalogPage(data)
		if err != nil {
			return
		}
		for _, l := range leaves {
			if v, ok := nugetVersion(l.Version); !nugetValidID(l.ID) || !ok || v != l.Version || l.TS.IsZero() {
				t.Fatalf("leaf %+v", l)
			}
		}
		for _, c := range nugetCoordinates(leaves) {
			if err := validateBatch(Batch{Items: []Coordinate{c}, Next: "x"}); err != nil {
				t.Fatalf("coordinate %+v: %v", c, err)
			}
		}
	})
}

func FuzzNuGetVersionList(f *testing.F) {
	nugetFuzzSeeds(f, "flat-*.json")
	f.Add([]byte(`{"versions":["1.0.0","1.0.0","1.0.0-Beta+meta","v1"]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		versions, err := nugetParseVersionList(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, v := range versions {
			if n, ok := nugetVersion(v); !ok || n != v || seen[v] {
				t.Fatalf("version %q", v)
			}
			seen[v] = true
		}
	})
}
