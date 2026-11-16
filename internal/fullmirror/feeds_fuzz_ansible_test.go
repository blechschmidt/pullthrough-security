//go:build fuzz
// +build fuzz

// Fuzz targets for the ansible feed's parsers (Task 191): a page of Galaxy's
// collection-version search, of a repository's collection index and of a
// collection's versions list. None may panic; what they accept must be what
// the adapter can hand on — collections and versions whose artifact paths the
// backend caches.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzAnsibleSearch$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/ansible"
)

// ansibleFuzzSeeds adds the recorded fixtures of the ansible tests.
func ansibleFuzzSeeds(f *testing.F, pattern string) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "feeds", "ansible", pattern))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
}

func FuzzAnsibleSearch(f *testing.F) {
	ansibleFuzzSeeds(f, "search-*.json")
	for _, s := range []string{``, `{}`, `{"meta":{},"links":{},"data":[]}`, `{"meta":{"count":-1},"links":{"next":5},"data":[{}]}`,
		`{"meta":{"count":1},"links":{"next":"x"},"data":[{"repository":{"name":"published"},"collection_version":{"namespace":"a","name":"b","version":"1","pulp_created":"2026-01-01T00:00:00Z"}}]}`,
		`{"meta":{"count":1},"links":{"next":null},"data":[{"repository":{"name":"published"},"collection_version":{"namespace":"A","name":"b","version":"1 0","pulp_created":"x"}}]}`,
		`{"meta":{"count":2},"links":{"next":null},"data":[{"repository":{"name":"a"},"collection_version":{}},{"repository":{"name":"b"},"collection_version":{}}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pg, err := ansibleParseSearch(data)
		if err != nil {
			return
		}
		if len(pg.versions) > pg.count || pg.total < -1 {
			t.Fatalf("%d of %d versions, total %d", len(pg.versions), pg.count, pg.total)
		}
		for _, v := range pg.versions {
			if !ansible.ValidRelease(v.collection, v.version) || v.created.IsZero() {
				t.Fatalf("version %+v", v)
			}
			if it := (listingItem{Name: v.collection, Version: v.version, Time: v.created}); !it.valid() {
				t.Fatalf("item %+v the listing driver refuses", it)
			}
		}
	})
}

func FuzzAnsibleIndex(f *testing.F) {
	ansibleFuzzSeeds(f, "index-*.json")
	for _, s := range []string{``, `{"meta":{"count":1},"links":{},"data":[{"namespace":"a","name":"b"},{"namespace":"A.b","name":""}]}`, `{"data":null}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ansibleParseIndex(data)
		if err != nil {
			return
		}
		if len(idx.collections) > idx.count {
			t.Fatalf("%d of %d collections", len(idx.collections), idx.count)
		}
		for _, c := range idx.collections {
			if !ansible.ValidCollection(c) || !cleanName(c) {
				t.Fatalf("collection %q", c)
			}
		}
	})
}

func FuzzAnsibleVersions(f *testing.F) {
	ansibleFuzzSeeds(f, "versions-*.json")
	for _, s := range []string{``, `{"meta":{"count":2},"links":{"next":null},"data":[{"version":"1.0.0"},{"version":"../x","created_at":"2026-01-01T00:00:00Z"}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pg, err := ansibleParseVersions(data, "acme.tools")
		if err != nil {
			return
		}
		if len(pg.versions) > pg.count {
			t.Fatalf("%d of %d versions", len(pg.versions), pg.count)
		}
		for _, v := range pg.versions {
			if !ansible.ValidRelease("acme.tools", v.version) {
				t.Fatalf("version %+v", v)
			}
		}
	})
}

func FuzzAnsibleOffset(f *testing.F) {
	for _, s := range []string{"", "5", "0", "-1", "007", "99999999999", "1e3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		n, err := ansibleOffset(token)
		if err != nil {
			return
		}
		if n < 0 || n > ansibleMaxOffset || (token == "") != (n == 0) {
			t.Fatalf("%q read as offset %d", token, n)
		}
		if next := ansibleNextToken(n, 100, 5, true); next != "" {
			if m, err := ansibleOffset(next); err != nil || m <= n {
				t.Fatalf("the token after %d is %q (%v)", n, next, err)
			}
		}
	})
}
