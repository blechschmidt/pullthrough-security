//go:build fuzz
// +build fuzz

package fullmirror

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/composer"
)

// Fuzz targets for the Composer feed adapter's parsers (Task 190): Packagist's
// change log and package list are registry input. Neither may panic, and what
// they return must be what the adapter can hand on: names the backend routes,
// no dev-branch documents.

// composerFuzzSeeds adds the recorded fixtures of the Composer tests.
func composerFuzzSeeds(f *testing.F, names ...string) {
	for _, n := range names {
		if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "composer", n)); err == nil {
			f.Add(data)
		}
	}
}

func FuzzComposerChanges(f *testing.F) {
	composerFuzzSeeds(f, "changes.json", "changes-old.json", "nosince.json")
	f.Add([]byte(`{"actions":[{"type":"delete","package":"a\/b","time":2},{"type":"update","package":"a\/b","time":1},7],"timestamp":1.5}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		log, err := composerParseChanges(data)
		if err != nil {
			return
		}
		if log.Timestamp < 0 {
			t.Fatalf("timestamp %d", log.Timestamp)
		}
		feed := &composerFeed{maxItems: 3, times: map[string]int64{}}
		items, _ := feed.items(log.Actions, feed.maxItems)
		if len(items) > feed.maxItems {
			t.Fatalf("%d items past the limit", len(items))
		}
		seen := map[string]bool{}
		for _, c := range items {
			if _, _, ok := composer.SplitPackageName(c.Name); !ok || strings.HasSuffix(c.Name, "~dev") || c.Version != "" || seen[c.Name] {
				t.Fatalf("coordinate %+v", c)
			}
			seen[c.Name] = true
		}
	})
}

func FuzzComposerList(f *testing.F) {
	composerFuzzSeeds(f, "list.json")
	f.Add([]byte(`{"packageNames":["a/b","a/b","A/B","a","a/b/c",""]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := composerParseList(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, n := range names {
			if _, _, ok := composer.SplitPackageName(n); !ok || seen[n] || strings.Contains(n, "\n") {
				t.Fatalf("name %q", n)
			}
			seen[n] = true
		}
	})
}
