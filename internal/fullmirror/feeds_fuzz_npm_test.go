//go:build fuzz
// +build fuzz

// Fuzz targets for the npm feed adapter's parsers (Task 190). The replication
// feed and the packuments come from the registry — untrusted input parsed
// before anything is fetched — so the parsers must never panic and must fail
// closed on malformed input.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzNPMChanges$' ./internal/fullmirror/
package fullmirror

import (
	"os"
	"testing"
)

func seedFiles(f *testing.F, typ string, names ...string) {
	for _, n := range names {
		if data, err := os.ReadFile("testdata/feeds/" + typ + "/" + n); err == nil {
			f.Add(data)
		}
	}
}

func FuzzNPMChanges(f *testing.F) {
	seedFiles(f, "npm", "changes.json", "changes-beyond-head.json")
	f.Add([]byte(`{"results":[{"seq":"1-abc","id":"x","deleted":true}],"last_seq":"9-g1AAAA"}`))
	f.Add([]byte(`{"results":[],"last_seq":-1}`))
	f.Add([]byte(`{"results":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		changes, last, err := parseNPMChanges(data)
		if err != nil {
			return
		}
		if len(last) > 4096 {
			t.Fatalf("an unbounded sequence: %d bytes", len(last))
		}
		for _, c := range changes {
			if isNPMPackageName(c.ID) && !cleanName(c.ID) {
				t.Fatalf("accepted name %q", c.ID)
			}
		}
	})
}

func FuzzNPMAllDocs(f *testing.F) {
	seedFiles(f, "npm", "all-docs-first.json", "all-docs-after-left-pad.json")
	f.Add([]byte(`{"rows":[{"id":"_design/x"},{"id":"@a/b"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseNPMAllDocs(data)
	})
}

func FuzzNPMPackument(f *testing.F) {
	seedFiles(f, "npm", "packument-left-pad.json", "packument-types-node.json")
	f.Add([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"http://x/v1/n/a/-/a-1.0.0.tgz"}},"../x":{"dist":{"tarball":"y"}}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := parseNPMPackument(data)
		if err != nil {
			return
		}
		for _, v := range vs {
			if !cleanName(v.Version) || v.Tarball == "" {
				t.Fatalf("accepted version %q (%q)", v.Version, v.Tarball)
			}
		}
	})
}
