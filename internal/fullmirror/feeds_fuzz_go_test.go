//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// The Go feed reads the module index and version lists — untrusted input.
// These targets hold its parsers to never panic, to stay bounded, to move the
// cursor only forward, and to hand the engine only tagged versions of valid
// module paths.

// goIndexFuzzSeeds adds the recorded fixtures matching pattern as seeds, each
// cut to goIndexFuzzSeedMax bytes at a line end (the engine's minimization
// is quadratic in an input's length).
func goIndexFuzzSeeds(f *testing.F, pattern string) {
	f.Helper()
	paths, _ := filepath.Glob(filepath.Join("testdata", "feeds", "go", pattern))
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			if len(data) > goIndexFuzzSeedMax {
				data = data[:goIndexFuzzSeedMax]
				if i := bytes.LastIndexByte(data, '\n'); i > 0 {
					data = data[:i+1]
				}
			}
			f.Add(data)
		}
	}
}

// goIndexFuzzSeedMax bounds a seed: a few index records.
const goIndexFuzzSeedMax = 512

func FuzzGoIndexPage(f *testing.F) {
	goIndexFuzzSeeds(f, "*.jsonl")
	f.Add([]byte(`{"Path":"example.com/a","Version":"v1.0.0","Timestamp":"2026-11-16T02:40:00Z"}` + "\n" + `{"Path":"example.com/a","Version":"v1.0.0","Timestamp":"2026-11-16T02:40:00Z"}`))
	since := time.Date(2026, 11, 16, 2, 40, 0, 0, time.UTC)
	horizon := since.Add(24 * time.Hour)
	scheme, _ := versions.For("go")
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, lines, err := goIndexParsePage(body)
		if err != nil {
			return
		}
		if len(entries) > lines {
			t.Fatalf("%d records of %d lines", len(entries), lines)
		}
		seenKey := goIndexKey(goIndexEntry{path: "example.com/a", version: "v1.0.0"})
		for _, c := range []goIndexCursor{
			{Format: "go/1"},
			{Format: "go/1", Since: since.Format(time.RFC3339Nano), Seen: []string{seenKey}},
		} {
			at := time.Time{}
			if c.Since != "" {
				at = since
			}
			items, next, newest, err := goIndexAdvance(c, at, horizon, entries, lines >= 3)
			if err != nil {
				continue
			}
			if newest.Before(at) {
				t.Fatalf("newest %s before since %s", newest, at)
			}
			if next.Since != "" {
				ns, perr := time.Parse(time.RFC3339Nano, next.Since)
				if perr != nil || ns.Before(at) || ns.After(horizon.Add(time.Microsecond)) {
					t.Fatalf("next since %q goes back from %s or past %s", next.Since, at, horizon)
				}
			}
			if len(next.Seen) > goIndexMaxSeen || len(encodeCursor(&next)) > maxCursorBytes {
				t.Fatalf("cursor of %d remembered versions", len(next.Seen))
			}
			if err := validateBatch(Batch{Items: items, Next: "x"}); err != nil {
				t.Fatalf("the engine would refuse the batch: %v", err)
			}
			for _, it := range items {
				v, perr := scheme.Parse(it.Version)
				if perr != nil || versions.IsPseudoVersion(v) || !goIndexModulePath(it.Name) {
					t.Fatalf("change %+v", it)
				}
			}
		}
	})
}

func FuzzGoVersionList(f *testing.F) {
	goIndexFuzzSeeds(f, "list-*.txt")
	f.Add([]byte("v1.0.0\nv0.0.0-20190404164418-38d8ce5564a5\nv2.0.0+incompatible x\n"))
	scheme, _ := versions.For("go")
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := goIndexParseList(body)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, v := range got {
			parsed, perr := scheme.Parse(v)
			if perr != nil || versions.IsPseudoVersion(parsed) || seen[v] {
				t.Fatalf("version %q", v)
			}
			seen[v] = true
		}
	})
}

func FuzzGoCursor(f *testing.F) {
	f.Add(`{"format":"go/1","since":"2019-04-10T20:30:31.325463Z","seen":["3aaf709bd69dd0fe"],"replay":true}`)
	f.Add(`{"format":"go/1"}`)
	feed := &goIndexFeed{now: func() time.Time { return time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC) }}
	f.Fuzz(func(t *testing.T, cursor string) {
		c, since, err := feed.decode(cursor)
		if err != nil {
			return
		}
		if len(c.Seen) > goIndexMaxSeen || (c.Since == "" && (len(c.Seen) > 0 || !since.IsZero())) {
			t.Fatalf("cursor %+v accepted", c)
		}
	})
}
